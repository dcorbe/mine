//! Segments: memory below 4 GiB, and the LDT descriptors that name it.

use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, PoisonError};

/// `modify_ldt(2)` function code for writing an entry.
const LDT_WRITE: i32 = 1;

/// How many entries an LDT has. One module load takes 82 of them, so this is
/// not a limit only a pathological caller could reach.
const LDT_ENTRIES: u32 = 8192;

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
const F_READ_EXEC_ONLY: u32 = 1 << 3;
const F_SEG_NOT_PRESENT: u32 = 1 << 5;
const F_USEABLE: u32 = 1 << 6;

/// Slots never yet handed out. A process has exactly one LDT, so allocation has
/// to be process-wide even though a `Machine` feels local.
static NEXT_ENTRY: AtomicU32 = AtomicU32::new(0);

/// Slots handed back by a dropped segment. Reuse before the bump allocator,
/// because the LDT is a fixed 8192 entries and a module load takes 82 of them:
/// without this, loading and unloading the same module a hundred times runs the
/// table out.
static FREE_ENTRIES: Mutex<Vec<u32>> = Mutex::new(Vec::new());

fn free_entries() -> std::sync::MutexGuard<'static, Vec<u32>> {
    // Nothing inside the critical section can panic in a way that matters, and
    // failing an allocation because an unrelated thread died is worse than
    // carrying on with a list that is merely correct.
    FREE_ENTRIES.lock().unwrap_or_else(PoisonError::into_inner)
}

fn take_ldt_entry() -> io::Result<u32> {
    if let Some(entry) = free_entries().pop() {
        return Ok(entry);
    }

    let entry = NEXT_ENTRY.fetch_add(1, Ordering::Relaxed);
    if entry >= LDT_ENTRIES {
        // Recoverable, and deliberately not recovered here: dropping segments
        // refills the free list, so the counter running past the end is not
        // itself the end of anything.
        return Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            format!("the LDT's {LDT_ENTRIES} entries are all in use"),
        ));
    }
    Ok(entry)
}

/// Write `desc` into the LDT.
fn write_ldt(desc: &UserDesc) -> io::Result<()> {
    // SAFETY: `desc` is a correctly shaped user_desc living long enough for the
    // call, which copies it.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_modify_ldt,
            LDT_WRITE,
            std::ptr::from_ref(desc),
            size_of::<UserDesc>(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Make an LDT entry name nothing at all.
///
/// The exact shape matters: Linux clears an entry only for a descriptor its
/// `LDT_empty()` recognises, which is every field zero *except* a set
/// `read_exec_only` and `seg_not_present`. Anything else is written as an
/// ordinary descriptor, and a not-present descriptor over a freed mapping is
/// the very thing this exists to prevent.
fn clear_ldt_entry(entry: u32) -> io::Result<()> {
    write_ldt(&UserDesc {
        entry_number: entry,
        base_addr: 0,
        limit: 0,
        flags: F_READ_EXEC_ONLY | F_SEG_NOT_PRESENT,
    })
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

        let entry = match take_ldt_entry() {
            Ok(entry) => entry,
            Err(e) => {
                // SAFETY: unmapping a mapping we just made and are abandoning.
                unsafe { libc::munmap(base.cast(), len) };
                return Err(e);
            }
        };
        let contents = if executable {
            CONTENTS_CODE
        } else {
            CONTENTS_DATA
        };

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

        if let Err(e) = write_ldt(&desc) {
            // SAFETY: unmapping a mapping we just made and are abandoning.
            unsafe { libc::munmap(base.cast(), len) };
            free_entries().push(entry);
            return Err(e);
        }

        Ok(Self { base, len, entry })
    }

    /// The selector naming this segment: index in bits 3..15, TI set to select
    /// the LDT rather than the GDT, RPL 3.
    pub(crate) fn selector(&self) -> u16 {
        ((self.entry as u16) << 3) | 0x7
    }

    /// The LDT slot describing this segment.
    pub(crate) fn entry(&self) -> u32 {
        self.entry
    }

    /// The segment's length, which is also its bound.
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Borrow `len` bytes at `offset`.
    ///
    /// # Panics
    ///
    /// If the range leaves the segment. Callers bounds-check first and report
    /// that as an error; reaching the panic is a host bug, not a module one.
    pub(crate) fn slice(&self, offset: usize, len: usize) -> &[u8] {
        assert!(
            offset + len <= self.len,
            "slice past the end of the segment"
        );
        // SAFETY: bounds checked, and the mapping is readable for its whole
        // length and outlives the borrow.
        unsafe { std::slice::from_raw_parts(self.base.add(offset), len) }
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
        // Descriptor first, mapping second, and the slot last of all. The order
        // is the whole point: a present descriptor over unmapped address space
        // is a selector that names memory which no longer exists, which is
        // precisely what the far-pointer bounds checks cannot catch. And the
        // slot must not become reusable until it describes nothing, or the next
        // allocation's descriptor could be overwritten by this one's clear.
        //
        // A failed clear therefore leaks both, on purpose: the mapping stays
        // ours, so the stale descriptor names memory we still hold rather than
        // whatever the allocator hands out next. There is no entry number this
        // can fail for that `take_ldt_entry` could have produced, so reaching
        // here is a host bug and worth the abort.
        clear_ldt_entry(self.entry)
            .expect("could not clear an LDT entry; leaking its mapping rather than dangling it");

        // SAFETY: our own mapping, dropped exactly once.
        unsafe { libc::munmap(self.base.cast(), self.len) };

        free_entries().push(self.entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The LDT is process-wide, and so is the free list. These tests assert on
    /// *which* slot comes back, so they cannot run beside each other.
    static SERIALISE: Mutex<()> = Mutex::new(());

    /// `modify_ldt(2)` function code for reading the table back.
    const LDT_READ: i32 = 0;

    /// Bytes per LDT entry, as the CPU stores it -- not `user_desc`'s shape.
    const LDT_ENTRY_SIZE: usize = 8;

    /// The raw descriptor the kernel holds for `entry`.
    fn descriptor(entry: u32) -> [u8; LDT_ENTRY_SIZE] {
        let bytes = (entry as usize + 1) * LDT_ENTRY_SIZE;
        let mut table = vec![0u8; bytes];

        // SAFETY: the buffer is `bytes` long and the kernel is told so.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_modify_ldt,
                LDT_READ,
                table.as_mut_ptr(),
                bytes as libc::c_ulong,
            )
        };
        assert!(rc >= 0, "read_ldt: {}", io::Error::last_os_error());

        table[bytes - LDT_ENTRY_SIZE..].try_into().unwrap()
    }

    #[test]
    fn a_dropped_segment_leaves_no_live_descriptor() {
        let _guard = SERIALISE.lock().unwrap_or_else(PoisonError::into_inner);

        let segment = Segment::new(4096, false).expect("a segment");
        let entry = segment.entry();
        assert_ne!(
            descriptor(entry),
            [0u8; LDT_ENTRY_SIZE],
            "a live segment has a live descriptor"
        );

        drop(segment);

        assert_eq!(
            descriptor(entry),
            [0u8; LDT_ENTRY_SIZE],
            "the descriptor still names the memory that was just unmapped"
        );
    }

    #[test]
    fn an_ldt_slot_is_reused_once_its_segment_is_gone() {
        let _guard = SERIALISE.lock().unwrap_or_else(PoisonError::into_inner);

        let first = Segment::new(4096, false).expect("a segment");
        let entry = first.entry();
        drop(first);

        let second = Segment::new(4096, false).expect("another segment");
        assert_eq!(
            second.entry(),
            entry,
            "a freed slot should be handed out again before a fresh one"
        );
    }

    #[test]
    fn many_load_and_unload_cycles_do_not_exhaust_the_ldt() {
        let _guard = SERIALISE.lock().unwrap_or_else(PoisonError::into_inner);

        // Four times the whole table, in batches the size of a module load.
        // Without recycling this runs out on the hundredth batch.
        for _ in 0..400 {
            let batch: Vec<Segment> = (0..82)
                .map(|_| Segment::new(4096, false).expect("a segment"))
                .collect();
            drop(batch);
        }
    }
}
