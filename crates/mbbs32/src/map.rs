//! One anonymous mapping below 4 GiB.
//!
//! **Where this differs from `crates/mbbs16/src/seg.rs`, deliberately:** there
//! is no `modify_ldt` here, and no descriptor at all. A 16-bit module is
//! addressed through a segment:offset far pointer, so `mbbs16` needs an LDT
//! entry to *name* every window onto memory it hands the module -- `seg.rs`
//! (582 lines) and `farptr.rs` (144) exist for that. A 32-bit module is
//! addressed flat: an `Rva` is just an offset from this mapping's base, and an
//! ordinary pointer reaches it. There is exactly one exception to "no
//! descriptors ever" in this crate family, and it is not here -- Task 15 needs
//! one LDT entry for the Win32 TIB `FS` must point at, because the module
//! dereferences through `FS` before it does anything else. That single
//! descriptor is the whole of this crate's LDT footprint, against 3,576 for
//! one 16-bit MajorMUD instance.
//!
//! # `unsafe` starts here
//!
//! Part A (`pe.rs`) parses untrusted bytes into plain data with no allocation
//! and no `unsafe` at all. This module is where that stops: `mmap` and
//! `munmap` are inherently `unsafe` calls, and everything built on top of a
//! [`Mapping`] -- starting with `Image` in `image.rs` -- inherits that a
//! mapping's `base` pointer is only valid between `Mapping::new` succeeding
//! and the `Mapping` being dropped.

use std::io;

/// An anonymous, read/write/execute mapping placed below 4 GiB.
///
/// Below 4 GiB because every 32-bit address this crate ever computes --- a far
/// jump's offset field, a base relocation's fixed-up word, the module's own
/// `ImageBase` --- is a 32-bit quantity, and nothing above `0xffff_ffff` can be
/// named by one.
pub struct Mapping {
    base: *mut u8,
    len: usize,
}

impl Mapping {
    /// Map `len` bytes, private, anonymous, and read/write/execute, below
    /// 4 GiB.
    ///
    /// RWX rather than per-section protections: this crate does not yet parse
    /// section characteristics into page protections (Task 11 notes this
    /// explicitly; that is a later increment, not an oversight here).
    ///
    /// # Errors
    ///
    /// If the kernel refuses the mapping -- most likely `ENOMEM`, either
    /// ordinary memory pressure or (rarely) no space left below 4 GiB.
    pub fn new(len: usize) -> io::Result<Self> {
        // SAFETY: this is an ordinary anonymous mapping request -- no file
        // descriptor, no fixed address, so there is nothing here for the
        // kernel to interpret except `len`, and mmap itself validates that
        // (zero or absurd lengths simply fail rather than doing something
        // unsound). `MAP_32BIT` is what makes the returned base usable by the
        // rest of this crate: every 32-bit address a loaded module's own
        // relocations or far jumps compute must resolve inside this mapping.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_32BIT,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            base: base.cast::<u8>(),
            len,
        })
    }

    /// The mapping's base address.
    pub fn base(&self) -> *mut u8 {
        self.base
    }

    /// The mapping's length in bytes, as given to [`Mapping::new`].
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether this mapping covers zero bytes.
    ///
    /// Never true in practice -- `mmap(len = 0)` fails, so [`Mapping::new`]
    /// never returns one of these -- but `clippy::len_without_is_empty` wants
    /// it, and having it costs nothing.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The mapping's contents.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `base` and `len` describe exactly the region `mmap`
        // returned in `new` and this `Mapping` still owns (nothing else can
        // unmap it early: `munmap` only happens in `Drop`, which requires
        // consuming `self`). PROT_READ was requested for the whole region, so
        // every byte in range is readable, and the borrow's lifetime is tied
        // to `&self` so it cannot outlive the mapping.
        unsafe { std::slice::from_raw_parts(self.base, self.len) }
    }

    /// The mapping's contents, writable.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as `as_slice`, plus `&mut self` gives this the only live
        // reference to the mapping, so a `&mut [u8]` over it does not alias
        // anything else that could observe or race the writes.
        unsafe { std::slice::from_raw_parts_mut(self.base, self.len) }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: `base`/`len` are exactly the region `mmap` returned in
        // `new`. `Mapping` is not `Clone` and this is `Drop::drop`, which the
        // language runs at most once per value, so this `munmap` cannot race
        // or double-free the mapping.
        unsafe { libc::munmap(self.base.cast(), self.len) };
    }
}
