//! Memory the host hands a module a pointer into and then never moves.
//!
//! Two kinds of thing need this. Message text, which `stgopt` returns a `char *`
//! to and a module may hold across other calls; and the structs a module knows
//! by their address -- `msgblk`, `FILE` -- where the pointer *is* the handle and
//! has to stay unique for as long as the host might be asked about it.
//!
//! Append-only across a list of segments, because `WCCMMHLP.MSG` is 124 KB and
//! one 16-bit segment is 64. No allocator, and **no dependency on the module
//! heap** -- which is what let message files be implemented before the heap was,
//! and what keeps a `FILE` off the budget [`farcoreleft`] reports.
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

use mbbs16::{FarPtr, Machine};

/// Bytes in one of the arena's segments. One segment is as much as a 16-bit
/// offset can address.
const SEGMENT: usize = 64 * 1024;

#[derive(Default)]
pub(crate) struct Arena {
    /// Each segment and how much of it is spoken for.
    segments: Vec<(u16, usize)>,
}

impl Arena {
    /// Reserve `len` zeroed bytes somewhere stable, and say where.
    ///
    /// The zeroing is written rather than assumed. A fresh segment arrives
    /// zeroed and nothing ever writes past `used`, so it would be true anyway --
    /// but a caller filling in two fields of a struct and trusting the other
    /// eighteen bytes deserves better than an invariant held somewhere else.
    ///
    /// # Errors
    ///
    /// If a segment cannot be mapped, or `len` is too long for one.
    pub fn reserve(&mut self, machine: &mut Machine, len: usize) -> io::Result<FarPtr> {
        let at = self.carve(machine, len)?;
        machine
            .write(at, &vec![0u8; len])
            .map_err(io::Error::other)?;
        Ok(at)
    }

    /// Copy `bytes` and a terminator somewhere stable, and say where.
    ///
    /// # Errors
    ///
    /// If a segment cannot be mapped, or `bytes` is too long for one.
    pub fn intern(&mut self, machine: &mut Machine, bytes: &[u8]) -> io::Result<FarPtr> {
        let at = self.carve(machine, bytes.len() + 1)?;
        let mut out = bytes.to_vec();
        out.push(0);
        machine.write(at, &out).map_err(io::Error::other)?;
        Ok(at)
    }

    /// Set `need` bytes aside and say where they start.
    ///
    /// # Errors
    ///
    /// If a segment cannot be mapped, or `need` is too long for one.
    fn carve(&mut self, machine: &mut Machine, need: usize) -> io::Result<FarPtr> {
        if need == 0 || need > SEGMENT {
            // Nothing legitimate reaches either end. `OPTSIZE` -- the longest a
            // message may be -- is 16,384, and the structs are tens of bytes.
            return Err(io::Error::other(format!(
                "a {need}-byte reservation will not fit in a {SEGMENT}-byte segment"
            )));
        }

        // Something that does not fit in what is left starts a new segment
        // rather than being split: a C string cannot cross a selector boundary,
        // and neither can a struct a module indexes fields out of.
        let room = self
            .segments
            .last()
            .is_some_and(|(_, used)| SEGMENT - used >= need);
        if !room {
            self.segments.push((machine.alloc_segment(SEGMENT)?, 0));
        }

        let (selector, used) = self.segments.last_mut().expect("just ensured");
        let at = FarPtr {
            offset: *used as u16,
            selector: *selector,
        };
        *used += need;
        Ok(at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine() -> Machine {
        Machine::new().expect("machine")
    }

    #[test]
    fn a_reservation_is_zeroed() {
        let mut m = machine();
        let mut arena = Arena::default();
        let at = arena.reserve(&mut m, 20).expect("reserve");
        assert_eq!(m.resolve(at, 20).expect("resolve"), &[0u8; 20]);
    }

    #[test]
    fn an_interned_string_is_terminated() {
        let mut m = machine();
        let mut arena = Arena::default();
        let at = arena.intern(&mut m, b"hello").expect("intern");
        assert_eq!(m.resolve(at, 6).expect("resolve"), b"hello\0");
    }

    #[test]
    fn two_reservations_do_not_overlap() {
        let mut m = machine();
        let mut arena = Arena::default();
        let first = arena.reserve(&mut m, 20).expect("reserve");
        let second = arena.reserve(&mut m, 20).expect("reserve");
        assert_ne!(first, second);

        // Writing through one must not be visible through the other, which is
        // the whole guarantee a handle rests on.
        m.write(first, &[0xff; 20]).expect("write");
        assert_eq!(m.resolve(second, 20).expect("resolve"), &[0u8; 20]);
    }

    #[test]
    fn a_reservation_never_straddles_a_selector() {
        let mut m = machine();
        let mut arena = Arena::default();

        // Fill the first segment to within less than the next reservation.
        let big = SEGMENT - 8;
        let first = arena.reserve(&mut m, big).expect("reserve");
        let second = arena.reserve(&mut m, 20).expect("reserve");

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
        let mut arena = Arena::default();
        // Refused rather than truncated or split: a 16-bit offset cannot
        // address past the end of one, so there is no honest answer.
        assert!(arena.reserve(&mut m, SEGMENT + 1).is_err());
        assert!(arena.reserve(&mut m, 0).is_err());
    }
}
