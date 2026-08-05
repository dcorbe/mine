//! Memory: the heap, the tiles, and the four leaves that move bytes about.
//!
//! Every memory-related import `WCCMMUD.DLL` has, with call-site counts:
//!
//! ```text
//! galfree      90    alctile      12    memcpy       4
//! setmem       59    ptrtile      12    movmem       3
//! alczer       51    farcoreleft  11    alcmem       3
//!                                       memcmp       2
//! ```
//!
//! That is the whole surface. **No `alcrsz`, no `alcdup`, no `alcblok`, no
//! `malloc`**, so realloc, strdup and the block API are all out of scope and
//! stay unimplemented, poisoning by name.
//!
//! What backs the heap, and why the block sizes are kept out of the module's
//! reach, is [`crate::heap`].
//!
//! # Two argument orders that corrupt silently
//!
//! `GCOMM.H` defines two of these as macros over the C library, and both
//! reverse an order everyone has memorised:
//!
//!
//! Neither mistake fails; both write the wrong bytes and are noticed much
//! later, somewhere else. So their tests use a count and a fill value that
//! differ, and a source and destination that differ -- a test written
//! `setmem(p, 4, 4)` would pass either way.

use mbbs16::{FarPtr, Machine, Ret};

use crate::Host;
use crate::shims::ShimError;

/// `char *alcmem(unsigned size)` -- reserve memory the module will free.
///
/// A `size` of zero, or a heap with no room, is a refusal. The real host
/// returned null for both, and step 7's trace is what that costs: `alczer`
/// answered null at call 183 and the module dereferenced it eighteen calls
/// later, where the fault named module code rather than the lie.
pub fn alcmem(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let size = machine.arg_u16(0);
    let at = host
        .heap
        .alloc(machine, size)
        .map_err(|e| ShimError::Failed(format!("alcmem: {e}")))?;
    Ok(Ret::Far(at))
}

/// `char *alczer(unsigned size)` -- reserve memory, zeroed.
///
/// Zeroed here rather than assumed: reused space holds whatever the last owner
/// left, and a module that trusts `alczer` and gets `alcmem` finds out slowly.
pub fn alczer(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let size = machine.arg_u16(0);
    let at = host
        .heap
        .alloc(machine, size)
        .map_err(|e| ShimError::Failed(format!("alczer: {e}")))?;
    machine.write(at, &vec![0u8; usize::from(size)])?;
    Ok(Ret::Far(at))
}

/// `void galfree(void *ptr)` -- give memory back.
pub fn galfree(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let at = machine.arg_far(0);
    host.heap
        .free(at)
        .map_err(|e| ShimError::Failed(format!("galfree: {e}")))?;
    Ok(Ret::Void)
}

/// `unsigned long farcoreleft(void)` -- how much memory is left.
///
/// A policy, not a fact: modules size their caches off this. See
/// [`Config::heap`](crate::Config::heap) for what the number is and why.
pub fn farcoreleft(_: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let left = host.heap.left();
    Ok(Ret::U32(u32::try_from(left).unwrap_or(u32::MAX)))
}

/// `void *alctile(int qty, int size)` -- one region of `qty` tiles.
///
/// `PLSTUFF.C`: `bigptr = MK_FP(pltile(qty*(long)size, 0, size, size), 0)`. One
/// linear region, `qty` consecutive LDT descriptors across it, each a `size`
/// window. The module walks between tiles itself, so every descriptor has to
/// exist first -- see [`Machine::alloc_tiled`](mbbs16::Machine::alloc_tiled).
pub fn alctile(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let qty = machine.arg_u16(0);
    let size = machine.arg_u16(1);
    let at = host
        .heap
        .alloc_tiled(machine, qty, size)
        .map_err(|e| ShimError::Failed(format!("alctile({qty}, {size}): {e}")))?;
    Ok(Ret::Far(at))
}

/// `void *ptrtile(void *bigptr, int index)` -- the `index`th tile of a region.
///
///
/// A far pointer is a 32-bit value with the selector in the high word, so
/// `+ (index << 19)` is `+ index * 8` **on the selector** -- which is
/// [`SELECTOR_STEP`](mbbs16::SELECTOR_STEP), and the same shift `DOSCALLS.135`
/// hands the module to fold inline.
///
/// The module computes this itself at most of the twelve call sites and only
/// calls through here at some, so this must agree with the arithmetic exactly.
/// An index past the last tile is refused: without the region's shape the host
/// would hand back a selector belonging to something else entirely.
pub fn ptrtile(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let base = machine.arg_far(0);
    // Word 2: the far pointer before it is two words, not one.
    let index = machine.arg_u16(2);

    let region = host.heap.region(base.selector).ok_or_else(|| {
        ShimError::Failed(format!("ptrtile: {base:?} is not a tiled region"))
    })?;
    if index >= region.qty {
        return Err(ShimError::Failed(format!(
            "ptrtile: tile {index} of a {}-tile region",
            region.qty
        )));
    }

    Ok(Ret::Far(FarPtr {
        offset: base.offset,
        selector: base.selector + index * mbbs16::SELECTOR_STEP,
    }))
}

/// `void setmem(void *p, unsigned n, char c)` -- fill.
///
/// **Count then fill**, which is `memset`'s arguments the other way round.
pub fn setmem(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let at = machine.arg_far(0);
    let count = machine.arg_u16(2);
    // A `char` argument still arrives as a whole word; the fill is its low byte.
    let fill = machine.arg_u16(3) as u8;
    machine.write(at, &vec![fill; usize::from(count)])?;
    Ok(Ret::Void)
}

/// `void movmem(void *src, void *dst, unsigned n)` -- copy, overlapping allowed.
///
/// **Source first**, which is the opposite of `memcpy` immediately below.
pub fn movmem(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let src = machine.arg_far(0);
    let dst = machine.arg_far(2);
    let count = machine.arg_u16(4);
    let bytes = machine.resolve(src, usize::from(count))?.to_vec();
    machine.write(dst, &bytes)?;
    Ok(Ret::Void)
}

/// `void *memcpy(void *dst, void *src, unsigned n)` -- destination first.
pub fn memcpy(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let dst = machine.arg_far(0);
    let src = machine.arg_far(2);
    let count = machine.arg_u16(4);
    let bytes = machine.resolve(src, usize::from(count))?.to_vec();
    machine.write(dst, &bytes)?;
    Ok(Ret::Far(dst))
}

/// `int memcmp(void *a, void *b, unsigned n)`.
pub fn memcmp(machine: &mut Machine, _: &mut Host) -> Result<Ret, ShimError> {
    let a = machine.arg_far(0);
    let b = machine.arg_far(2);
    let count = usize::from(machine.arg_u16(4));

    let left = machine.resolve(a, count)?.to_vec();
    let right = machine.resolve(b, count)?;
    let answer = match left.as_slice().cmp(right) {
        std::cmp::Ordering::Less => -1i16,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    };
    Ok(Ret::U16(answer as u16))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;

    fn far(at: FarPtr) -> [u16; 2] {
        [at.offset, at.selector]
    }

    #[test]
    fn alcmem_hands_out_distinct_memory_that_galfree_takes_back() {
        let mut f = Fixture::new();
        let Ret::Far(a) = f.invoke(alcmem, &[256]).expect("a") else {
            panic!("alcmem returns a pointer")
        };
        let Ret::Far(b) = f.invoke(alcmem, &[256]).expect("b") else {
            panic!("alcmem returns a pointer")
        };
        assert_ne!(a, b);

        f.invoke(galfree, &far(a)).expect("freed");
        let Ret::Far(c) = f.invoke(alcmem, &[256]).expect("c") else {
            panic!("alcmem returns a pointer")
        };
        assert_eq!(a, c, "the freed space came back");
    }

    #[test]
    fn alczer_is_zeroed_even_in_space_that_was_used() {
        let mut f = Fixture::new();
        let Ret::Far(a) = f.invoke(alcmem, &[64]).expect("a") else {
            panic!("pointer")
        };
        f.machine.write(a, &[0xcc; 64]).expect("dirtied");
        f.invoke(galfree, &far(a)).expect("freed");

        let Ret::Far(b) = f.invoke(alczer, &[64]).expect("b") else {
            panic!("pointer")
        };
        assert_eq!(b, a, "the same space, so the test means something");
        assert_eq!(
            f.machine.resolve(b, 64).expect("readable"),
            &[0u8; 64],
            "alczer left what the last owner wrote"
        );
    }

    #[test]
    fn galfree_of_something_never_allocated_refuses_by_name() {
        let mut f = Fixture::new();
        let Ret::Far(a) = f.invoke(alcmem, &[64]).expect("a") else {
            panic!("pointer")
        };
        let stray = FarPtr {
            offset: a.offset + 8,
            selector: a.selector,
        };
        let e = f.invoke(galfree, &far(stray)).expect_err("not a block");
        assert!(e.to_string().contains("galfree"), "{e}");

        f.invoke(galfree, &far(a)).expect("this one is");
        assert!(f.invoke(galfree, &far(a)).is_err(), "but not twice");
    }

    #[test]
    fn the_heap_crosses_a_segment_and_still_works_from_16_bit_code() {
        let mut f = Fixture::new();
        let Ret::Far(a) = f.invoke(alcmem, &[40_000]).expect("a") else {
            panic!("pointer")
        };
        let Ret::Far(b) = f.invoke(alcmem, &[40_000]).expect("b") else {
            panic!("pointer")
        };
        assert_ne!(a.selector, b.selector, "two of these need two segments");

        // And both are memory a module can actually reach.
        f.machine.write(b, b"past the boundary\0").expect("writes");
        assert_eq!(f.read(b), "past the boundary");
    }

    #[test]
    fn farcoreleft_falls_by_what_was_taken_and_rises_when_it_is_given_back() {
        let mut f = Fixture::new();
        let Ret::U32(before) = f.invoke(farcoreleft, &[]).expect("asked") else {
            panic!("farcoreleft returns a long")
        };
        let Ret::Far(a) = f.invoke(alcmem, &[1000]).expect("a") else {
            panic!("pointer")
        };
        let Ret::U32(during) = f.invoke(farcoreleft, &[]).expect("asked") else {
            panic!("long")
        };
        assert_eq!(during, before - 1000);

        f.invoke(galfree, &far(a)).expect("freed");
        let Ret::U32(after) = f.invoke(farcoreleft, &[]).expect("asked") else {
            panic!("long")
        };
        assert_eq!(after, before);
    }

    #[test]
    fn ptrtile_agrees_with_the_arithmetic_the_module_does_itself() {
        // The invariant that ties this to step 7. `DOSCALLS.135` is the shift
        // the module folds into its own code, so a region walked by calling
        // `ptrtile` and one walked by shifting must land on the same tiles --
        // the module does both and they cannot disagree.
        let mut f = Fixture::new();
        let Ret::Far(base) = f.invoke(alctile, &[8, 4096]).expect("tiled") else {
            panic!("alctile returns a pointer")
        };

        let shift = mbbs16::SELECTOR_STEP.ilog2();
        for index in 0..8u16 {
            let Ret::Far(asked) = f.invoke(ptrtile, &[base.offset, base.selector, index])
                .expect("in range")
            else {
                panic!("pointer")
            };

            // What the module computes: the far pointer as one 32-bit value,
            // plus index << (16 + AHSHIFT).
            let flat = (u32::from(base.selector) << 16) | u32::from(base.offset);
            let computed = flat + (u32::from(index) << (16 + shift));
            assert_eq!(
                ((u32::from(asked.selector) << 16) | u32::from(asked.offset)),
                computed,
                "tile {index}"
            );
        }
    }

    #[test]
    fn each_tile_is_its_own_memory_and_16_bit_code_can_reach_it() {
        let mut f = Fixture::new();
        let Ret::Far(base) = f.invoke(alctile, &[4, 4096]).expect("tiled") else {
            panic!("pointer")
        };
        for index in 0..4u16 {
            let Ret::Far(tile) = f
                .invoke(ptrtile, &[base.offset, base.selector, index])
                .expect("in range")
            else {
                panic!("pointer")
            };
            f.machine.write(tile, &[index as u8; 32]).expect("writes");
        }
        // Written through four different selectors, read back through them.
        for index in 0..4u16 {
            let Ret::Far(tile) = f
                .invoke(ptrtile, &[base.offset, base.selector, index])
                .expect("in range")
            else {
                panic!("pointer")
            };
            assert_eq!(
                f.machine.resolve(tile, 1).expect("readable")[0],
                index as u8,
                "tile {index} does not hold what was written through it"
            );
        }
    }

    #[test]
    fn ptrtile_past_the_last_tile_refuses_rather_than_naming_someone_elses() {
        let mut f = Fixture::new();
        let Ret::Far(base) = f.invoke(alctile, &[3, 4096]).expect("tiled") else {
            panic!("pointer")
        };
        assert!(
            f.invoke(ptrtile, &[base.offset, base.selector, 3]).is_err(),
            "tile 3 of three"
        );

        // And a pointer that is not a region at all.
        let heap = f.invoke(alcmem, &[64]).expect("a");
        let Ret::Far(heap) = heap else { panic!("pointer") };
        assert!(f.invoke(ptrtile, &[heap.offset, heap.selector, 0]).is_err());
    }

    #[test]
    fn setmem_takes_the_count_before_the_fill() {
        // The count and the fill differ, so swapping them fails. Written
        // `setmem(p, 4, 4)` this test would pass either way round.
        let mut f = Fixture::new();
        let at = f.bytes(&[0xff; 16], false);
        f.invoke(setmem, &[at.offset, at.selector, 4, 0x41])
            .expect("filled");
        assert_eq!(
            f.machine.resolve(at, 6).expect("readable"),
            &[0x41, 0x41, 0x41, 0x41, 0xff, 0xff],
            "four bytes of 'A', not sixty-five bytes of 4"
        );
    }

    #[test]
    fn movmem_takes_the_source_before_the_destination() {
        let mut f = Fixture::new();
        let src = f.bytes(b"source", false);
        let dst = f.bytes(b"DEST!!", false);
        f.invoke(movmem, &[src.offset, src.selector, dst.offset, dst.selector, 6])
            .expect("moved");
        assert_eq!(
            f.machine.resolve(dst, 6).expect("readable"),
            b"source",
            "movmem copies src to dst, not the other way"
        );
        assert_eq!(f.machine.resolve(src, 6).expect("readable"), b"source");
    }

    #[test]
    fn memcpy_takes_the_destination_first_which_is_the_other_way_round() {
        let mut f = Fixture::new();
        let dst = f.bytes(b"DEST!!", false);
        let src = f.bytes(b"source", false);
        assert_eq!(
            f.invoke(memcpy, &[dst.offset, dst.selector, src.offset, src.selector, 6])
                .expect("copied"),
            Ret::Far(dst)
        );
        assert_eq!(f.machine.resolve(dst, 6).expect("readable"), b"source");
    }

    #[test]
    fn memcmp_orders_the_way_c_does() {
        let mut f = Fixture::new();
        let a = f.bytes(b"abc", false);
        let b = f.bytes(b"abd", false);
        let c = f.bytes(b"abc", false);

        let args = |x: FarPtr, y: FarPtr| [x.offset, x.selector, y.offset, y.selector, 3];
        assert_eq!(f.invoke(memcmp, &args(a, c)).expect("same"), Ret::U16(0));
        assert_eq!(
            f.invoke(memcmp, &args(a, b)).expect("less"),
            Ret::U16((-1i16) as u16)
        );
        assert_eq!(f.invoke(memcmp, &args(b, a)).expect("more"), Ret::U16(1));
    }
}
