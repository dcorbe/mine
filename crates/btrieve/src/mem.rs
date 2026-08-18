//! What the Btrieve session needs from whoever owns the memory.
//!
//! `Btrieve` was `Btrieve<A: Abi>`, which read as though the engine were
//! entangled with module hosting. It is not: nothing it asks for is about
//! calling conventions, shims or the WGSERVER ABI. It was parameterised by
//! `Abi` only because `Abi` was the nearest type that happened to supply a
//! pointer, and `Abi` brings a machine, a CPU and a shim table along with it.
//!
//! # What it actually needs, measured
//!
//! The design document that preceded this counted seven items, from
//! `grep -c 'A::'` over the session. That undercounts, in two ways a reader
//! should know about before trusting the number:
//!
//! - **The pattern cannot match `Abi`.** `A::Ptr` matches; `impl<A: Abi>` does
//!   not, and neither does `<A as Abi>::Ptr`. `btrieve/ops.rs` has nine
//!   `impl<A: Abi> Block<A>` blocks and `btrieve/stat.rs` one, all invisible to
//!   that grep, which is why both files import `crate::abi::Abi` while
//!   reporting zero uses.
//! - **It cannot see methods called on pointer *values*.** `Abi::Ptr` is bound
//!   by `mbbs_machine::ptr::ModulePtr`, so `ptr.resolve(mem, len)` and
//!   `ptr.write(mem, bytes)` are ABI surface that never spells `A::` at all.
//!
//! And one dependency is not on `Abi` at all: `Btrieve::open` and
//! `Btrieve::close_at` take `&mut crate::Heap<A>`, because opening a file
//! allocates the module's block, name, record buffer and key buffer, and
//! closing frees them. A crate that depends on nothing but `std` can name
//! neither `ModulePtr` nor `Heap`, so both cross the seam here.
//!
//! Eleven items, then: [`Mem`] carries ten and [`Alloc`] the last two, split
//! because a caller that only reads a block should not have to supply an
//! allocator. Every one is a pointer, memory or allocation concern. That is
//! the whole of it, and it is what lets a DOS guest and a Win32 host satisfy
//! this without pretending to be a module ABI.

/// Which compiler laid out the file block a module is handed back.
///
/// `struct btvblk` (`BTVSTF.H:6-19`) and `struct dfablk` (`DFAAPI.H:103-145`)
/// are the *same* field sequence -- `posblk`, `filnam`, `reclen`, `key`,
/// `data`, `lastkn`, `keylns[SEGMAX]` -- and a host that assumed one byte
/// layout served both for as long as it only hosted 16-bit modules. It does
/// not generalise, and this enum is why.
///
/// A module reads these fields directly. `bb->data` is Galacticomm's
/// documented direct-access convention, not an implementation detail, so the
/// offsets are load-bearing: MajorMUD-NT's own module init does
/// `strcpy(dst, dfa->data)` off a `dfaOpen` return value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockAbi {
    /// The 16-bit compiler's layout: nothing is padded, because every field
    /// is two or four bytes and every offset is already even. `reclen` and
    /// `lastkn` are two bytes here whether the header spells them `INT`
    /// (`btvblk`) or `USHORT`/`SHORT` (`dfablk`) -- which is exactly why one
    /// layout could serve both families, and why that stopped being true at
    /// 32 bits.
    ///
    /// The tail is `GCDOSP`'s `realseg`/`keyseg` (`DFAAPI.H:140-143`), two
    /// real-mode segment numbers this host has no real mode to fill in.
    Packed16,

    /// `DFAAPI.H`'s `GCWINNT` branch (`:119-129`), the 32-bit Worldgroup
    /// layout: `reclen` is `USHORT`, so the compiler inserts **two bytes of
    /// padding** before `key` to put a pointer back on a four-byte boundary.
    /// Everything from `key` on therefore sits two bytes higher than
    /// [`Packed16`](BlockAbi::Packed16) puts it.
    ///
    /// The tail is `flddefList[SEGMAX]`/`unpackKeySiz[SEGMAX]`, the arrays
    /// that drive `cvtDataIP`'s field marshalling. This host does no such
    /// conversion and never fills them, but they are still counted in the
    /// block's size, because the size is what it allocates and a real
    /// `DFAFILE` is that big.
    ///
    /// The 32-bit `btvblk` is a third layout again (`INT reclen`/`INT
    /// lastkn`, four bytes each) that happens to agree with this one on
    /// `key` and `data` and diverges after them. It is not represented here:
    /// no 32-bit module in the surveyed corpus imports a single `btv*`
    /// symbol -- MajorMUD-NT imports seventeen `dfa*` and zero `btv*` -- so
    /// inventing its layout would be a guess with nothing to check it
    /// against.
    WinNt32,
}

/// A pointer-and-memory provider for the Btrieve session.
///
/// Implemented by whoever owns the memory a module's pointers address: this
/// host does it for both WGSERVER ABIs, and the offline-utility hosts will do
/// it for a DOS guest's real mode and a Win32 process's flat address space.
pub trait Mem {
    /// A pointer as this consumer's programs write one.
    type Ptr: Copy + Eq + std::hash::Hash + std::fmt::Debug;

    /// The memory those pointers address.
    type Memory;

    /// What resolving or writing through a pointer can fail with.
    ///
    /// Kept as an associated type rather than flattened to `String` so that a
    /// consumer's own fault type survives the crossing; the session only ever
    /// renders it with `to_string`.
    type Error: std::error::Error;

    /// The width of `Ptr` in bytes, as stored in a program's memory.
    const PTR_WIDTH: usize;

    /// Which `struct dfablk`/`struct btvblk` shape this consumer's compiler
    /// produced. See [`BlockAbi`] -- it is not the same on both, and getting
    /// it wrong hands a module a struct of plausible size with its pointers
    /// two bytes from where the module reads them.
    const BLOCK: BlockAbi;

    /// The pointer that addresses nothing.
    fn null_ptr() -> Self::Ptr;

    /// Encode a pointer as a program's own memory stores one.
    fn ptr_to_bytes(p: Self::Ptr) -> Vec<u8>;

    /// Decode a pointer from exactly [`PTR_WIDTH`](Mem::PTR_WIDTH) bytes.
    fn ptr_from_bytes(b: &[u8]) -> Self::Ptr;

    /// A pointer `delta` bytes past `base`.
    ///
    /// `delta` is a `u16` because every use is a field offset within one
    /// structure, and because a 16-bit far pointer cannot be advanced past a
    /// segment anyway.
    fn ptr_offset(base: Self::Ptr, delta: u16) -> Self::Ptr;

    /// Borrow `len` bytes of memory at `p`.
    ///
    /// # Errors
    ///
    /// If `p` does not address `len` readable bytes.
    fn resolve<'m>(
        p: Self::Ptr,
        memory: &'m Self::Memory,
        len: usize,
    ) -> Result<&'m [u8], Self::Error>;

    /// Write `bytes` to memory at `p`.
    ///
    /// # Errors
    ///
    /// If `p` does not address `bytes.len()` writable bytes.
    fn write(p: Self::Ptr, memory: &mut Self::Memory, bytes: &[u8]) -> Result<(), Self::Error>;
}

/// Where the session gets the memory a module sees its own Btrieve blocks in.
///
/// Separate from [`Mem`] because it is needed by exactly two operations --
/// opening a file and closing one -- while everything else in the session only
/// reads and writes through pointers it was handed. A consumer that never opens
/// a file on a module's behalf need not implement this at all.
///
/// Errors are `String` because that is what this host's heap already returns
/// and what the session already renders; there is no structure here worth
/// preserving across the seam.
pub trait Alloc<M: Mem + ?Sized> {
    /// Allocate `size` bytes and return a pointer a module can hold.
    ///
    /// # Errors
    ///
    /// If there is no room for `size` bytes in one piece.
    fn reserve(&mut self, memory: &mut M::Memory, size: u16) -> Result<M::Ptr, String>;

    /// Release an allocation made by [`reserve`](Alloc::reserve).
    ///
    /// # Errors
    ///
    /// If `at` was not allocated here, or was freed already.
    fn free(&mut self, at: M::Ptr) -> Result<(), String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Flat, FlatHeap, FlatMem, FlatPtr};

    #[test]
    fn a_non_abi_type_can_satisfy_the_seam() {
        assert_eq!(<Flat as Mem>::PTR_WIDTH, 4);
        assert_eq!(<Flat as Mem>::null_ptr(), FlatPtr::NULL);
        assert_eq!(<Flat as Mem>::ptr_offset(FlatPtr(16), 4), FlatPtr(20));
        let round = <Flat as Mem>::ptr_from_bytes(&<Flat as Mem>::ptr_to_bytes(FlatPtr(0xdead)));
        assert_eq!(
            round,
            FlatPtr(0xdead),
            "a pointer must survive the byte round trip"
        );
    }

    #[test]
    fn a_non_abi_type_can_resolve_and_write() {
        let mut mem = FlatMem::new(64);
        <Flat as Mem>::write(FlatPtr(8), &mut mem, b"BTRIEVE").expect("a write inside memory");
        let seen = <Flat as Mem>::resolve(FlatPtr(8), &mem, 7).expect("a read inside memory");
        assert_eq!(seen, b"BTRIEVE");

        <Flat as Mem>::write(FlatPtr(60), &mut mem, b"BTRIEVE")
            .expect_err("a write past the end must fail rather than grow the memory");
        <Flat as Mem>::resolve(FlatPtr(60), &mem, 7)
            .expect_err("a read past the end must fail rather than return short");
    }

    #[test]
    fn a_non_abi_allocator_can_satisfy_the_seam() {
        let mut mem = FlatMem::new(64);
        let mut heap = FlatHeap::new(0);
        let first = heap.reserve(&mut mem, 16).expect("room for 16 bytes");
        let second = heap.reserve(&mut mem, 16).expect("room for 16 more");
        assert_ne!(
            first, second,
            "two live allocations must not share an address"
        );
        heap.reserve(&mut mem, u16::MAX)
            .expect_err("an allocation larger than the memory must be refused");
        heap.free(first).expect("a free of a live allocation");
    }
}
