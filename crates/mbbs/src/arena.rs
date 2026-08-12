//! Memory the host hands a module a pointer into and then never moves.
//!
//! Two kinds of thing need this. Message text, which `stgopt` returns a `char *`
//! to and a module may hold across other calls; and the structs a module knows
//! by their address -- `msgblk`, `FILE` -- where the pointer *is* the handle and
//! has to stay unique for as long as the host might be asked about it.
//!
//! Append-only across a list of regions, because `WCCMMHLP.MSG` is 124 KB and
//! one 16-bit segment is 64. No allocator, and **no dependency on the module
//! heap** -- which is what let message files be implemented before the heap was,
//! and what keeps a `FILE` off the budget [`farcoreleft`] reports.
//!
//! # Generic over the ABI, concrete at every call site
//!
//! `Arena<A>` gets its backing regions from [`ModuleMem::alloc_region`]
//! rather than `mbbs16::Machine::alloc_segment` directly, and builds
//! placements inside one with [`Abi::ptr_offset`] rather than constructing a
//! `FarPtr` by hand -- so the packing algorithm below (first-fit within the
//! current region, a fresh region when nothing fits) is written once and
//! shared by any ABI, not duplicated per one. Only `Wg16` exists today, so
//! every actual caller still names a concrete `Arena` (the default type
//! parameter), and nothing about this task changes that -- see
//! `docs/plans/2026-08-11-abi-abstraction-implementation.md`'s Task 6.
//!
//! # Nothing here is ever reclaimed
//!
//! Not an oversight, and not the same tradeoff in both directions.
//!
//! For text it is a simple bound: `clsmsg` does not shrink the arena, three
//! message files is nothing, and a host that opened and closed them in a loop
//! would grow without end. Worth knowing rather than mechanising.
//!
//! For a handle it is the point. An address that came back into circulation
//! would make a use-after-close name whatever was opened next -- silently, and
//! writing into a real file. Retiring the address instead is what makes that a
//! refusal, and it is worth the bytes.
//!
//! [`farcoreleft`]: crate::heap::Heap::left

use std::io;

use mbbs_ptr::ModulePtr;

use crate::abi::{Abi, ModuleMem, Wg16};

/// Bytes in one of the arena's regions. One 16-bit segment is as much as a
/// 16-bit offset can address; other ABIs may allow more, but nothing this
/// crate places is anywhere near that large, so one bound serves every ABI
/// met so far.
const SEGMENT: usize = 64 * 1024;

/// `A` defaults to [`Wg16`] so every existing caller -- all of which predate
/// this generic parameter -- keeps naming this type as plain `Arena`. See the
/// module doc comment ("Generic over the ABI, concrete at every call site").
pub(crate) struct Arena<A: Abi = Wg16> {
    /// Each region and how much of it is spoken for.
    segments: Vec<(A::Ptr, usize)>,
}

impl<A: Abi> Default for Arena<A> {
    fn default() -> Self {
        Self {
            segments: Vec::new(),
        }
    }
}

impl<A: Abi> Arena<A>
where
    A::Ptr: ModulePtr<Memory = A::Mem>,
{
    /// Reserve `len` zeroed bytes somewhere stable, and say where.
    ///
    /// The zeroing is written rather than assumed. A fresh region arrives
    /// zeroed and nothing ever writes past `used`, so it would be true anyway --
    /// but a caller filling in two fields of a struct and trusting the other
    /// eighteen bytes deserves better than an invariant held somewhere else.
    ///
    /// # Errors
    ///
    /// If a region cannot be mapped, or `len` is too long for one.
    pub fn reserve(&mut self, mem: &mut A::Mem, len: usize) -> io::Result<A::Ptr> {
        let at = self.carve(mem, len)?;
        at.write(mem, &vec![0u8; len])
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(at)
    }

    /// Copy `bytes` and a terminator somewhere stable, and say where.
    ///
    /// # Errors
    ///
    /// If a region cannot be mapped, or `bytes` is too long for one.
    pub fn intern(&mut self, mem: &mut A::Mem, bytes: &[u8]) -> io::Result<A::Ptr> {
        let at = self.carve(mem, bytes.len() + 1)?;
        let mut out = bytes.to_vec();
        out.push(0);
        at.write(mem, &out)
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(at)
    }

    /// Set `need` bytes aside and say where they start.
    ///
    /// # Errors
    ///
    /// If a region cannot be mapped, or `need` is too long for one.
    fn carve(&mut self, mem: &mut A::Mem, need: usize) -> io::Result<A::Ptr> {
        if need == 0 || need > SEGMENT {
            // Nothing legitimate reaches either end. `OPTSIZE` -- the longest a
            // message may be -- is 16,384, and the structs are tens of bytes.
            return Err(io::Error::other(format!(
                "a {need}-byte reservation will not fit in a {SEGMENT}-byte segment"
            )));
        }

        // Something that does not fit in what is left starts a new region
        // rather than being split: a C string cannot cross a 16-bit selector
        // boundary, and neither can a struct a module indexes fields out of.
        let room = self
            .segments
            .last()
            .is_some_and(|(_, used)| SEGMENT - used >= need);
        if !room {
            self.segments.push((mem.alloc_region(SEGMENT)?, 0));
        }

        let (base, used) = self.segments.last_mut().expect("just ensured");
        let at = A::ptr_offset(*base, *used as u16);
        *used += need;
        Ok(at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mbbs16::Machine;

    fn machine() -> Machine {
        Machine::new().expect("machine")
    }

    #[test]
    fn a_reservation_is_zeroed() {
        let mut m = machine();
        let mut arena = Arena::<Wg16>::default();
        let at = arena.reserve(m.mem_mut(), 20).expect("reserve");
        assert_eq!(m.resolve(at, 20).expect("resolve"), &[0u8; 20]);
    }

    #[test]
    fn an_interned_string_is_terminated() {
        let mut m = machine();
        let mut arena = Arena::<Wg16>::default();
        let at = arena.intern(m.mem_mut(), b"hello").expect("intern");
        assert_eq!(m.resolve(at, 6).expect("resolve"), b"hello\0");
    }

    #[test]
    fn two_reservations_do_not_overlap() {
        let mut m = machine();
        let mut arena = Arena::<Wg16>::default();
        let first = arena.reserve(m.mem_mut(), 20).expect("reserve");
        let second = arena.reserve(m.mem_mut(), 20).expect("reserve");
        assert_ne!(first, second);

        // Writing through one must not be visible through the other, which is
        // the whole guarantee a handle rests on.
        m.write(first, &[0xff; 20]).expect("write");
        assert_eq!(m.resolve(second, 20).expect("resolve"), &[0u8; 20]);
    }

    #[test]
    fn a_reservation_never_straddles_a_selector() {
        let mut m = machine();
        let mut arena = Arena::<Wg16>::default();

        // Fill the first segment to within less than the next reservation.
        let big = SEGMENT - 8;
        let first = arena.reserve(m.mem_mut(), big).expect("reserve");
        let second = arena.reserve(m.mem_mut(), 20).expect("reserve");

        assert_ne!(
            first.selector, second.selector,
            "a reservation that would not fit starts a new segment"
        );
        assert_eq!(second.offset, 0, "and starts at the beginning of it");
        assert_eq!(m.resolve(second, 20).expect("resolve"), &[0u8; 20]);
    }

    #[test]
    fn nothing_larger_than_a_segment_is_reserved() {
        let mut m = machine();
        let mut arena = Arena::<Wg16>::default();
        // Refused rather than truncated or split: a 16-bit offset cannot
        // address past the end of one, so there is no honest answer.
        assert!(arena.reserve(m.mem_mut(), SEGMENT + 1).is_err());
        assert!(arena.reserve(m.mem_mut(), 0).is_err());
    }
}
