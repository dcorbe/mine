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

use mbbs_machine::m16::FarPtr;
use mbbs_machine::ptr::ModulePtr;

use crate::Host;
use crate::abi::{self, Abi, Call, Wg16};
use crate::shims::ShimError;

/// `VOID *alcmem(UINT size)` -- `GCOMM.H:256-258` -- reserve memory the
/// module will free.
///
/// A `size` of zero, or a heap with no room, is a refusal. The real host
/// returned null for both, and step 7's trace is what that costs: `alczer`
/// answered null at call 183 and the module dereferenced it eighteen calls
/// later, where the fault named module code rather than the lie.
///
/// Generic (Task 5): [`Heap::reserve`](crate::heap::Heap::reserve) is
/// already `impl<A: Abi> Heap<A>` -- unlike the `Wg16`-only `alloc` facade
/// this used to call (deleted in Task 13 of
/// `docs/plans/2026-08-12-abi-border-implementation.md`, once nothing else
/// called it), it takes `&mut A::Mem` straight from [`Call::mem`] rather
/// than a whole `&mut Machine`.
pub fn alcmem<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let size = Into::<u32>::into(call.int()) as u16;
    let at = host
        .heap
        .reserve(call.mem(), size)
        .map_err(|e| ShimError::Failed(format!("alcmem: {e}")))?;
    Ok(abi::Ret::Ptr(at))
}

/// `VOID *alczer(UINT nbytes)` -- `GCOMM.H:274-276` -- reserve memory, zeroed.
///
/// Zeroed here rather than assumed: reused space holds whatever the last owner
/// left, and a module that trusts `alczer` and gets `alcmem` finds out slowly.
///
/// Generic (Task 5): same [`Heap::reserve`](crate::heap::Heap::reserve) core
/// as [`alcmem`], and the zero-fill writes through
/// [`mbbs_machine::ptr::ModulePtr::write`] on [`Call::mem`] rather than
/// `Machine::write`.
pub fn alczer<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let size = Into::<u32>::into(call.int()) as u16;
    let at = host
        .heap
        .reserve(call.mem(), size)
        .map_err(|e| ShimError::Failed(format!("alczer: {e}")))?;
    // `A::Ptr::Error` has no `From` into `ShimError` for an arbitrary `A` --
    // only `Wg16`'s `FarPtrError` does -- so this is `map_err`, not `?`,
    // unlike the `Wg16`-only original (`shims::user::haskey`'s own comment
    // has the same note).
    at.write(call.mem(), &vec![0u8; usize::from(size)])
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Ptr(at))
}

/// `VOID galfree(VOID *block)` -- `GCOMM.H:771-773` -- give memory back.
///
/// Generic (Task 5): [`Heap::free`](crate::heap::Heap::free) never touched a
/// `Machine`, so this was already `impl<A: Abi> Heap<A>` before this task.
pub fn galfree<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let at = call.ptr();
    host.heap
        .free(at)
        .map_err(|e| ShimError::Failed(format!("galfree: {e}")))?;
    Ok(abi::Ret::Void)
}

/// `LONG farcoreleft(VOID)` -- `GCOMM.H:147` -- how much memory is left.
///
/// A policy, not a fact: modules size their caches off this. See
/// [`Config::heap`](crate::Config::heap) for what the number is and why.
///
/// Generic (Task 5): [`Heap::left`](crate::heap::Heap::left) never touched a
/// `Machine` either, and reads no argument -- the `call` parameter is unused.
pub fn farcoreleft<A: Abi>(
    _call: &mut Call<A>,
    host: &mut Host<A>,
) -> Result<abi::Ret<A>, ShimError> {
    let left = host.heap.left();
    Ok(abi::Ret::Long(u32::try_from(left).unwrap_or(u32::MAX)))
}

/// `void *alctile(int qty, int size)` -- one region of `qty` tiles.
///
/// `PLSTUFF.C`: `bigptr = MK_FP(pltile(qty*(long)size, 0, size, size), 0)`. One
/// linear region, `qty` consecutive LDT descriptors across it, each a `size`
/// window. The module walks between tiles itself, so every descriptor has to
/// exist first -- see [`Machine::alloc_tiled`](mbbs_machine::m16::Machine::alloc_tiled).
pub fn alctile(
    call: &mut Call<Wg16>,
    host: &mut Host<Wg16>,
) -> Result<abi::Ret<Wg16>, ShimError> {
    // No vendor prototype: `alctile` is not declared anywhere in
    // re/wg33src/INC's 125 headers. It is genuinely 16-bit-only -- segment
    // tiling has no flat-memory counterpart -- and the 32-bit module imports
    // `alcblok`/`ptrblok` instead, which are among the 56 unimplemented
    // symbols and out of scope here.
    let qty = call.int();
    let size = call.int();
    let at = host
        .heap
        .alloc_tiled(call.cpu, qty, size)
        .map_err(|e| ShimError::Failed(format!("alctile({qty}, {size}): {e}")))?;
    Ok(abi::Ret::Ptr(at))
}

/// [`Heap::alloc_tiled`](crate::heap::Heap::alloc_tiled)'s `Wg16` facade --
/// `alctile`'s host half, kept beside its one production caller now that
/// [`Heap`](crate::heap::Heap) itself is generic top to bottom (Task 13 of
/// `docs/plans/2026-08-12-abi-border-implementation.md`; see that module's
/// doc comment). No generic core to delegate into: LDT tile chaining
/// (`Machine::alloc_tiled`) has no 32-bit counterpart -- `alcblok`/`ptrblok`
/// are a different mechanism entirely, out of scope here, the same reason
/// `alctile`/`ptrtile` above are concrete rather than `<A: Abi>`.
impl crate::heap::Heap<Wg16> {
    /// # Errors
    ///
    /// If the region cannot be mapped or the LDT has no run that long.
    pub fn alloc_tiled(
        &mut self,
        machine: &mut mbbs_machine::m16::Machine,
        qty: u16,
        size: u16,
    ) -> Result<mbbs_machine::m16::FarPtr, String> {
        let at = machine.alloc_tiled(qty, size).map_err(|e| e.to_string())?;
        self.push_tile(crate::heap::Region {
            selector: at.selector,
            qty,
            size,
        });
        Ok(at)
    }
}

/// `void *ptrtile(void *bigptr, int index)` -- the `index`th tile of a region.
///
///
/// A far pointer is a 32-bit value with the selector in the high word, so
/// `+ (index << 19)` is `+ index * 8` **on the selector** -- which is
/// [`SELECTOR_STEP`](mbbs_machine::m16::SELECTOR_STEP), and the same shift `DOSCALLS.135`
/// hands the module to fold inline.
///
/// The module computes this itself at most of the twelve call sites and only
/// calls through here at some, so this must agree with the arithmetic exactly.
/// An index past the last tile is refused: without the region's shape the host
/// would hand back a selector belonging to something else entirely.
pub fn ptrtile(
    call: &mut Call<Wg16>,
    host: &mut Host<Wg16>,
) -> Result<abi::Ret<Wg16>, ShimError> {
    // No vendor prototype either, for the same reason as `alctile` above.
    let base = call.ptr();
    let index = call.int();

    let region = host.heap.region(base.selector).ok_or_else(|| {
        ShimError::Failed(format!("ptrtile: {base:?} is not a tiled region"))
    })?;
    if index >= region.qty {
        return Err(ShimError::Failed(format!(
            "ptrtile: tile {index} of a {}-tile region",
            region.qty
        )));
    }

    Ok(abi::Ret::Ptr(FarPtr {
        offset: base.offset,
        selector: base.selector + index * mbbs_machine::m16::SELECTOR_STEP,
    }))
}

/// `#define setmem(p,n,c) memset(p,c,n)` -- `GCOMM.H:143` -- fill.
///
/// Not a function prototype -- `setmem` is a macro over the ANSI C runtime's
/// `memset`, and `memset` itself is declared nowhere in `re/wg33src/INC`. But
/// the macro is the vendor's own statement of the argument order, which is
/// this file's whole reason for existing: **count then fill**, `memset`'s
/// arguments the other way round.
///
/// Generic (Task 5): the fill and the write go through [`Call::mem`] and
/// [`mbbs_machine::ptr::ModulePtr::write`] rather than a whole `&mut Machine`.
pub fn setmem<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let at = call.ptr();
    let count = Into::<u32>::into(call.int()) as u16;
    // A `char` argument still arrives as a whole word; the fill is its low byte.
    let fill = Into::<u32>::into(call.int()) as u8;
    at.write(call.mem(), &vec![fill; usize::from(count)])
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Void)
}

/// `VOID galmovmem(VOID *src, VOID *dst, USHORT nbytes)` -- `GCOMM.H:163-164`,
/// behind `#define movmem(s,d,n) galmovmem(s,d,n)` (`:166`) -- copy,
/// overlapping allowed.
///
/// **Source first**, which is the opposite of `memcpy` immediately below.
///
/// Generic (Task 5): reads through [`mbbs_machine::ptr::ModulePtr::resolve`] and
/// writes through [`mbbs_machine::ptr::ModulePtr::write`], both against [`Call::mem`].
pub fn movmem<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let src = call.ptr();
    let dst = call.ptr();
    let count = Into::<u32>::into(call.int()) as u16;
    let bytes = src
        .resolve(call.mem(), usize::from(count))
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    dst.write(call.mem(), &bytes)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Void)
}

/// `void *memcpy(void *dst, const void *src, size_t n)` -- destination
/// first. Borland's; no Galacticomm header redeclares it (see this file's
/// commit message).
///
/// Generic (Task 5): same shape as [`movmem`], with `dst`/`src` read in the
/// other order.
pub fn memcpy<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let dst = call.ptr();
    let src = call.ptr();
    let count = Into::<u32>::into(call.int()) as u16;
    let bytes = src
        .resolve(call.mem(), usize::from(count))
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    dst.write(call.mem(), &bytes)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Ptr(dst))
}

/// `void *memmove(void *dst, const void *src, size_t n)` -- [`memcpy`], safe
/// when the two ranges overlap.
///
/// Borland's; no Galacticomm header redeclares it -- not to be confused with
/// `GCOMM.H`'s `movmem(s,d,n)` macro (this file's own module doc, "Two
/// argument orders that corrupt silently"), which expands to
/// `memmove(d,s,n)` and is [`movmem`] above, a *different* import with its
/// arguments in the other order. LunatiX imports `_memmove` directly --
/// Stage 3's Task 8 (`docs/plans/2026-08-14-stage3-channel-entry-implementation.md`)
/// -- so this is the plain, dst-first C library routine, not the macro.
///
/// # Overlap is handled for free
///
/// `src` is read whole into an owned `Vec` before anything is written to
/// `dst`, exactly as [`memcpy`] already does -- so there is no forward/
/// backward copy direction to get right for an overlapping range the way a
/// byte-at-a-time C implementation of `memmove` has to choose one. Reading
/// the whole source first is what makes the choice moot.
///
/// # Width, not `memcpy`/`memcmp`'s `as u16`
///
/// `count` is read at `A`'s own int width and used as a `usize` outright,
/// **not** narrowed with `as u16`. `memcpy` and `memcmp` above still do that
/// narrowing -- a pre-existing width trap this task did not introduce and is
/// out of scope to fix here (see `shims::mod`'s own width discipline, and
/// `outprf`'s note in the Stage 3 plan on the same trap) -- but there is no
/// reason for a *new* sibling landing today to copy a bug this crate has
/// already found and removed everywhere else it looked (`fread`, `fwrite`,
/// `toupper`).
pub fn memmove<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let dst = call.ptr();
    let src = call.ptr();
    let count = Into::<u32>::into(call.int()) as usize;
    let bytes = src
        .resolve(call.mem(), count)
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    dst.write(call.mem(), &bytes)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Ptr(dst))
}

/// `int memcmp(const void *a, const void *b, size_t n)`. Borland's; no
/// Galacticomm header redeclares it.
///
/// Generic (Task 5): both reads go through [`mbbs_machine::ptr::ModulePtr::resolve`]
/// on [`Call::mem`]; the answer is built through [`Abi::Int`]'s `From<u16>`
/// the same way [`shims::user::haskey`](crate::shims::user::haskey) builds
/// its boolean answer.
pub fn memcmp<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let a = call.ptr();
    let b = call.ptr();
    let count = usize::from(Into::<u32>::into(call.int()) as u16);

    let left = a
        .resolve(call.mem(), count)
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let right = b
        .resolve(call.mem(), count)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let answer = match left.as_slice().cmp(right) {
        std::cmp::Ordering::Less => -1i16,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    };
    Ok(abi::Ret::Int(A::Int::from(answer as u16)))
}

#[cfg(test)]
mod tests {
    use super::*;
    // Wg16-only, and used by these fixtures alone -- the
    // production code above reaches memory through the ABI.
    use mbbs_machine::m16::Ret;
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

        let shift = mbbs_machine::m16::SELECTOR_STEP.ilog2();
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
    fn memmove_takes_the_destination_first_same_as_memcpy() {
        let mut f = Fixture::new();
        let dst = f.bytes(b"DEST!!", false);
        let src = f.bytes(b"source", false);
        assert_eq!(
            f.invoke(memmove, &[dst.offset, dst.selector, src.offset, src.selector, 6])
                .expect("moved"),
            Ret::Far(dst)
        );
        assert_eq!(f.machine.resolve(dst, 6).expect("readable"), b"source");
    }

    #[test]
    fn memmove_is_correct_when_the_ranges_overlap() {
        // A byte-at-a-time forward copy corrupts this: by the time it reaches
        // the tail of `dst`, it would be reading bytes it had already
        // overwritten rather than the originals. Reading `src` whole before
        // writing anything -- this shim's own doc comment -- sidesteps the
        // question rather than answering it correctly by luck.
        let mut f = Fixture::new();
        let buf = f.bytes(b"abcdefgh", false);
        let dst = FarPtr {
            offset: buf.offset + 2,
            selector: buf.selector,
        };
        f.invoke(memmove, &[dst.offset, dst.selector, buf.offset, buf.selector, 6])
            .expect("moved");
        assert_eq!(f.machine.resolve(buf, 8).expect("readable"), b"ababcdef");
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
