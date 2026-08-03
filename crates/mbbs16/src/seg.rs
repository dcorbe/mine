//! Segments: memory below 4 GiB, and the LDT descriptors that name it.

use std::io;
use std::sync::atomic::{AtomicU32, Ordering};

/// `modify_ldt(2)` function code for writing an entry.
const LDT_WRITE: i32 = 1;

/// Segment contents, as `struct user_desc` encodes it.
const CONTENTS_DATA: u32 = 0;
const CONTENTS_CODE: u32 = 2;

/// `struct user_desc`, with the kernel's bitfield word spelled out.
#[repr(C)]
struct UserDesc {
    entry_number: u32,
    base_addr: u32,
    limit: u32,
    flags: u32,
}

/// Layout of `UserDesc::flags`, which is the kernel's bitfield word:
/// `seg_32bit:1, contents:2, read_exec_only:1, limit_in_pages:1,
/// seg_not_present:1, useable:1`.
const CONTENTS_SHIFT: u32 = 1;
const F_USEABLE: u32 = 1 << 6;

/// Hands out LDT slots. A process has exactly one LDT, so allocation has to be
/// process-wide even though a `Machine` feels local.
static NEXT_ENTRY: AtomicU32 = AtomicU32::new(0);

fn take_ldt_entry() -> u32 {
    NEXT_ENTRY.fetch_add(1, Ordering::Relaxed)
}

/// A mapping below 4 GiB with an LDT descriptor over it.
///
/// The 4 GiB limit is not a preference. A descriptor's base is a 32-bit field,
/// so anything higher cannot be named at all.
pub(crate) struct Segment {
    base: *mut u8,
    len: usize,
    entry: u32,
}

impl Segment {
    /// Map `len` bytes below 4 GiB and describe them as a 16-bit segment.
    ///
    /// `executable` picks between a readable code segment and a writable data
    /// segment; the latter is what `SS` requires.
    pub(crate) fn new(len: usize, executable: bool) -> io::Result<Self> {
        let mut prot = libc::PROT_READ | libc::PROT_WRITE;
        if executable {
            prot |= libc::PROT_EXEC;
        }

        // SAFETY: an ordinary anonymous mapping. MAP_32BIT is what keeps the
        // result addressable by a 32-bit descriptor base.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                prot,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_32BIT,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let base = base.cast::<u8>();

        let entry = take_ldt_entry();
        let contents = if executable { CONTENTS_CODE } else { CONTENTS_DATA };

        let desc = UserDesc {
            entry_number: entry,
            base_addr: base as usize as u32,
            limit: (len - 1) as u32,

            // Every other bit is deliberately zero. seg_32bit clear is the
            // whole point: for code it clears D, making the default operand and
            // address size 16-bit; for a stack segment the same field is B,
            // declaring the stack pointer to be SP rather than ESP.
            // read_exec_only clear leaves code readable and data writable,
            // limit_in_pages clear keeps the limit in bytes, and
            // seg_not_present clear makes the descriptor live.
            flags: (contents << CONTENTS_SHIFT) | F_USEABLE,
        };

        // SAFETY: `desc` is a correctly shaped user_desc living long enough for
        // the call, which copies it.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_modify_ldt,
                LDT_WRITE,
                std::ptr::from_ref(&desc),
                size_of::<UserDesc>(),
            )
        };
        if rc != 0 {
            // SAFETY: unmapping a mapping we just made and are abandoning.
            unsafe { libc::munmap(base.cast(), len) };
            return Err(io::Error::last_os_error());
        }

        Ok(Self { base, len, entry })
    }

    /// The selector naming this segment: index in bits 3..15, TI set to select
    /// the LDT rather than the GDT, RPL 3.
    pub(crate) fn selector(&self) -> u16 {
        ((self.entry as u16) << 3) | 0x7
    }

    /// The mapping's linear address, for the far-jump targets that need one.
    pub(crate) fn linear(&self, offset: usize) -> u32 {
        debug_assert!(offset < self.len);
        (self.base as usize + offset) as u32
    }

    /// Write `bytes` at `offset` within the segment.
    pub(crate) fn write(&mut self, offset: usize, bytes: &[u8]) -> io::Result<()> {
        if offset + bytes.len() > self.len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write past the end of the segment",
            ));
        }
        // SAFETY: bounds checked immediately above, and the mapping is writable.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.base.add(offset), bytes.len());
        }
        Ok(())
    }

    /// Read a little-endian `u16` at `offset`.
    pub(crate) fn read_u16(&self, offset: usize) -> u16 {
        assert!(offset + 2 <= self.len, "read past the end of the segment");
        // SAFETY: bounds checked, and the mapping is readable. `read_unaligned`
        // because 16-bit code has no alignment obligations whatsoever.
        unsafe { self.base.add(offset).cast::<u16>().read_unaligned() }
    }
}

impl Drop for Segment {
    fn drop(&mut self) {
        // SAFETY: our own mapping, dropped exactly once.
        unsafe { libc::munmap(self.base.cast(), self.len) };
    }
}
