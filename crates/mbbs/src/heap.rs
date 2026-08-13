//! Memory a module can address, and what the host remembers about it.
//!
//! `alcmem`, `alczer` and `galfree` are MajorBBS's general allocator. What backs
//! them here is a first-fit heap over host-owned 64 KiB segments.
//!
//! # Why not a segment per allocation
//!
//! `alczer` has 51 call sites in `WCCMMUD.DLL` and `galfree` 90. A game that
//! allocates per room or per monster would run the LDT's 8,192 entries out, and
//! a module load already takes 82 of them. `alcmem(unsigned size)` cannot ask
//! for more than 65,535 bytes, so **no allocation ever needs to span a
//! segment** -- which is exactly why `alctile` exists for the things that do.
//! One entry per 64 KiB of heap, not one per allocation.
//!
//! # Why the block sizes are not in the module's memory
//!
//! A C allocator keeps the size in a header word before the pointer it returns.
//! That word sits in module-writable memory, so a module overrunning a block by
//! one byte corrupts the allocator, and the crash lands somewhere else entirely
//! and much later.
//!
//! Here the sizes are on the Rust side, keyed by the pointer. A `galfree` of
//! something never allocated, or freed already, is then a *diagnosable refusal*
//! naming the pointer, rather than damage. That is a difference from the real
//! host -- which would have shrugged and carried on corrupting itself -- and it
//! is the intended one.
//!
//! # Generic core, 16-bit-only skin
//!
//! The algorithm above -- first-fit across regions already mapped, block
//! sizes kept host-side keyed by the pointer -- is written once, over
//! `A: Abi`, and grows a region at a time through
//! [`ModuleMem::alloc_region`](crate::abi::ModuleMem::alloc_region) rather
//! than `mbbs_machine::m16::Machine::alloc_segment` directly: see [`Heap::reserve`].
//!
//! What does **not** move onto that generic core is `alcmem`/`galfree`'s
//! actual public surface, or `alctile`. Every shim call site --
//! `shims/system.rs`, `users.rs`, `btrieve.rs`, and others -- was written
//! against `Heap::alloc(&mut Machine, ..)`, and this task's job is to change
//! what backs that call, not to touch the 114 shim bodies that make it.
//! [`Heap::alloc`] and [`Heap::alloc_tiled`] stay `impl Heap<Wg16>`-only
//! methods with their original `&mut Machine` signatures, each a one-line
//! reborrow into the generic core (`machine.mem_mut()`) -- the same
//! delegating-facade shape Task 1 gave `Machine` over `Segments`.
//! `alloc_tiled` in particular has no generic core to delegate deeper than
//! that: LDT tile chaining is `Wg16`-only forever (its 32-bit counterpart is
//! `alcblok`/`ptrblok`, an unrelated mechanism, out of scope here).
//!
//! `A` carries no default. It was `= Wg16`, which let every caller name this
//! type as plain `Heap`; Task 3 of
//! `docs/plans/2026-08-12-abi-border-implementation.md` struck that default
//! along with every other in this crate, so each caller spells its ABI.

use std::collections::HashMap;

use crate::abi::{Abi, ModuleMem, Wg16};

/// Bytes in one of the heap's regions, which is as much as one 16-bit segment
/// can address. Kept as the shared growth policy for now because only `Wg16`
/// exists to measure a different one against -- a 32-bit `Heap` may one day
/// want regions sized differently, at which point this stops being a bare
/// constant and becomes something the `Abi` states, the way
/// [`Abi::PTR_WIDTH`](crate::abi::Abi::PTR_WIDTH) already does for argument
/// widths.
const SEGMENT: u16 = u16::MAX;

/// How much memory a module may have, and how it is laid out.
///
/// A `Config` rather than constants because `farcoreleft` makes the total
/// *observable*: modules size their caches off it, so too large and a module
/// reserves what it cannot fill, too small and it refuses to start.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Bytes of module heap, across as many segments as it takes.
    ///
    /// Eight megabytes: 128 of the LDT's 8,192 entries, comfortably more than a
    /// board of the period had, and leaving the rest of the table for the
    /// module's own segments and for `alctile`'s runs.
    pub heap: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self { heap: 8 * 1024 * 1024 }
    }
}

/// One free or allocated run of bytes within a heap region.
#[derive(Debug, Clone, Copy)]
struct Span {
    at: u16,
    len: u16,
}

/// One region of heap, and what is free in it.
struct Arena<A: Abi> {
    base: A::Ptr,
    /// Free spans, in address order and never touching -- adjacent ones are
    /// merged on free, or a heap that had been used would stop being able to
    /// answer for its own capacity.
    free: Vec<Span>,
}

/// Where a live allocation sits: which region, how far into it, how long.
///
/// Kept host-side rather than reconstructed from the pointer, because a
/// generic `A::Ptr` cannot be decomposed back into "which region" and "how
/// far into it" the way a `FarPtr`'s `selector`/`offset` could be read
/// directly -- `mbbs_machine::ptr::ModulePtr` has no such operation, deliberately (see
/// its own doc comment). Recording the decomposition at allocation time, once,
/// is simpler than adding one.
struct Block {
    region: usize,
    at: u16,
    len: u16,
}

/// The module's heap and its tiled regions.
///
/// `A` carries no default; every caller spells its ABI -- see this module's
/// doc comment ("Generic core, 16-bit-only skin").
pub struct Heap<A: Abi> {
    config: Config,
    regions: Vec<Arena<A>>,

    /// How long each live allocation is, and where, by the pointer handed out
    /// for it.
    blocks: HashMap<A::Ptr, Block>,

    /// Every tiled region: the first tile's selector, how many tiles, how big.
    /// Needed because `ptrtile` is otherwise unanswerable -- the host cannot
    /// tell a tile index that is inside a region from one past its end.
    ///
    /// `Region` (the public, `alctile`-facing one -- not [`Arena`] above,
    /// which is this module's private per-region free list) stays keyed by a
    /// raw `u16` selector rather than `A::Ptr`: `alctile`'s tiling is
    /// `Wg16`-only regardless of `A` (see this module's doc comment), so
    /// there is no ABI to be generic over here.
    tiles: Vec<Region>,
}

/// One `alctile` region.
#[derive(Debug, Clone, Copy)]
pub struct Region {
    pub selector: u16,
    pub qty: u16,
    pub size: u16,
}

impl<A: Abi> Heap<A> {
    /// A heap that has not reserved anything yet.
    ///
    /// Regions are mapped as they are needed rather than up front: a module
    /// that allocates nothing should cost nothing, and eight megabytes of
    /// untouched mapping is eight megabytes.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            regions: Vec::new(),
            blocks: HashMap::new(),
            tiles: Vec::new(),
        }
    }

    /// How many bytes are left, as `farcoreleft` reports it.
    ///
    /// The genuine remaining capacity: what is free in the regions already
    /// mapped, plus what could still be mapped.
    ///
    /// "Could still be mapped" is whole regions and no remainder. A heap
    /// configured at eight megabytes holds 128 regions of 65,535 bytes and 128
    /// bytes over, and those 128 can never be handed to anybody -- counting
    /// them would make this number wrong by exactly the amount a module sizing
    /// a cache off it would then fail to get.
    pub fn left(&self) -> usize {
        let spare = (self.capacity() - self.regions.len()) * SEGMENT as usize;
        let free: usize = self
            .regions
            .iter()
            .flat_map(|a| &a.free)
            .map(|s| usize::from(s.len))
            .sum();
        free + spare
    }

    /// How many regions this heap may ever have.
    fn capacity(&self) -> usize {
        self.config.heap / SEGMENT as usize
    }

    /// Reserve `size` bytes, growing through
    /// [`ModuleMem::alloc_region`] if nothing already mapped has room.
    ///
    /// The generic core `alcmem`/`alczer` both back, through
    /// [`Heap::alloc`]'s `Wg16` facade -- see this module's doc comment for
    /// why the facade exists and why shim call sites still say `alloc`.
    ///
    /// # Errors
    ///
    /// If `size` is zero, or the heap has no room and may not grow.
    pub fn reserve(&mut self, mem: &mut A::Mem, size: u16) -> Result<A::Ptr, String> {
        if size == 0 {
            // `alcmem(0)` has no useful answer: a pointer to nothing that
            // `galfree` must still accept. The real host returned something;
            // this says so instead.
            return Err("an allocation of zero bytes".to_owned());
        }

        if let Some((region, at, ptr)) = self.take(size) {
            self.blocks.insert(ptr, Block { region, at, len: size });
            return Ok(ptr);
        }

        // Nothing had room. Grow, if the configured total allows it.
        if self.regions.len() == self.capacity() {
            return Err(format!(
                "{size} bytes, and the {}-byte heap has {} left",
                self.config.heap,
                self.left()
            ));
        }
        let base = mem
            .alloc_region(SEGMENT as usize)
            .map_err(|e| e.to_string())?;
        self.regions.push(Arena {
            base,
            free: vec![Span { at: 0, len: SEGMENT }],
        });

        let (region, at, ptr) = self.take(size).expect("a fresh region has room");
        self.blocks.insert(ptr, Block { region, at, len: size });
        Ok(ptr)
    }

    /// Give `at` back.
    ///
    /// # Errors
    ///
    /// If `at` was never allocated, or has already been freed. Both are module
    /// bugs the real host would have absorbed silently.
    pub fn free(&mut self, at: A::Ptr) -> Result<(), String> {
        let block = self
            .blocks
            .remove(&at)
            .ok_or_else(|| format!("{at:?} was not allocated, or was freed already"))?;

        let region = &mut self.regions[block.region];

        // Insert in address order, then merge with either neighbour it now
        // touches. Without the merge, allocating and freeing the same block
        // repeatedly would leave the heap unable to satisfy anything larger.
        let index = region.free.partition_point(|s| s.at < block.at);
        region.free.insert(
            index,
            Span {
                at: block.at,
                len: block.len,
            },
        );

        let mut merged: Vec<Span> = Vec::with_capacity(region.free.len());
        for span in region.free.drain(..) {
            match merged.last_mut() {
                Some(last) if last.at + last.len == span.at => last.len += span.len,
                _ => merged.push(span),
            }
        }
        region.free = merged;
        Ok(())
    }

    /// How long the block at `at` is, or `None` if nothing is.
    pub fn block(&self, at: A::Ptr) -> Option<u16> {
        self.blocks.get(&at).map(|b| b.len)
    }

    /// Which tiled region `selector` names the first tile of.
    pub fn region(&self, selector: u16) -> Option<Region> {
        self.tiles.iter().copied().find(|r| r.selector == selector)
    }

    /// Every tiled region, in the order they were made.
    pub fn regions(&self) -> &[Region] {
        &self.tiles
    }

    /// How many heap regions are mapped.
    pub fn segments(&self) -> usize {
        self.regions.len()
    }

    /// First fit across the regions already mapped: which region, how far
    /// into it, and the pointer that offset resolves to.
    fn take(&mut self, size: u16) -> Option<(usize, u16, A::Ptr)> {
        for (index, region) in self.regions.iter_mut().enumerate() {
            // `continue`, not `?`: a region with no room means try the next
            // one, not that the heap is full.
            let Some(found) = region.free.iter().position(|s| s.len >= size) else {
                continue;
            };
            let span = &mut region.free[found];
            let at = span.at;
            if span.len == size {
                region.free.remove(found);
            } else {
                span.at += size;
                span.len -= size;
            }
            let ptr = A::ptr_offset(region.base, at);
            return Some((index, at, ptr));
        }
        None
    }
}

/// The `Wg16` facade: `alcmem`/`galfree`'s and `alctile`'s original public
/// names and `&mut Machine` signatures, unchanged since before this task, so
/// every shim call site keeps compiling. See this module's doc comment
/// ("Generic core, 16-bit-only skin").
impl Heap<Wg16> {
    /// `alcmem`'s host half. A one-line reborrow into [`Heap::reserve`] --
    /// see `crates/mbbs/src/abi.rs`'s "Call holds one handle, not two" for why
    /// a reborrow through `Machine::mem_mut`, not a second stored borrow, is
    /// what makes a generic core reachable from a `&mut Machine` call site at
    /// all.
    ///
    /// # Errors
    ///
    /// If `size` is zero, or the heap has no room and may not grow.
    pub fn alloc(&mut self, machine: &mut mbbs_machine::m16::Machine, size: u16) -> Result<mbbs_machine::m16::FarPtr, String> {
        self.reserve(machine.mem_mut(), size)
    }

    /// `alctile`'s host half. Stays `Wg16`-only by construction: LDT tile
    /// chaining (`Machine::alloc_tiled`) has no 32-bit counterpart --
    /// `alcblok`/`ptrblok` are a different mechanism entirely, out of scope
    /// here (see the implementation plan's Task 6).
    ///
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
        self.tiles.push(Region {
            selector: at.selector,
            qty,
            size,
        });
        Ok(at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mbbs_machine::m16::{FarPtr, Machine};

    fn heap() -> (Machine, Heap<Wg16>) {
        (
            Machine::new().expect("machine"),
            Heap::new(Config::default()),
        )
    }

    #[test]
    fn allocations_do_not_overlap() {
        let (mut m, mut h) = heap();
        let a = h.alloc(&mut m, 100).expect("a");
        let b = h.alloc(&mut m, 100).expect("b");
        assert_ne!(a, b);
        assert!(
            a.offset + 100 <= b.offset || b.offset + 100 <= a.offset,
            "{a:?} and {b:?} overlap"
        );
    }

    #[test]
    fn freed_space_is_reusable() {
        let (mut m, mut h) = heap();
        let a = h.alloc(&mut m, 4096).expect("a");
        h.free(a).expect("freed");
        let b = h.alloc(&mut m, 4096).expect("b");
        assert_eq!(a, b, "the same space should come back");
    }

    #[test]
    fn adjacent_free_blocks_merge() {
        // Without merging, a heap that had been used could not satisfy anything
        // larger than the biggest single block ever freed -- and nothing would
        // say why.
        let (mut m, mut h) = heap();
        let a = h.alloc(&mut m, 20_000).expect("a");
        let b = h.alloc(&mut m, 20_000).expect("b");
        let c = h.alloc(&mut m, 20_000).expect("c");
        h.free(b).expect("freed");
        h.free(a).expect("freed");
        h.free(c).expect("freed");

        let big = h.alloc(&mut m, 60_000).expect("three merged into one");
        assert_eq!(big, a);
        assert_eq!(h.segments(), 1, "and it did not need a second segment");
    }

    #[test]
    fn a_free_of_something_never_allocated_refuses() {
        let (mut m, mut h) = heap();
        let a = h.alloc(&mut m, 64).expect("a");
        let stray = FarPtr {
            offset: a.offset + 8,
            selector: a.selector,
        };
        assert!(h.free(stray).is_err(), "a pointer into a block is not one");
    }

    #[test]
    fn a_double_free_refuses_rather_than_corrupting_the_heap() {
        let (mut m, mut h) = heap();
        let a = h.alloc(&mut m, 64).expect("a");
        h.free(a).expect("first");
        assert!(h.free(a).is_err(), "the second is a module bug");
    }

    #[test]
    fn the_heap_crosses_a_segment_boundary() {
        let (mut m, mut h) = heap();
        let first = h.alloc(&mut m, 40_000).expect("a");
        let second = h.alloc(&mut m, 40_000).expect("b");
        assert_ne!(
            first.selector, second.selector,
            "two of these do not fit in one 64 KiB segment"
        );
        assert_eq!(h.segments(), 2);
    }

    #[test]
    fn a_heap_that_may_not_grow_refuses_and_says_how_much_is_left() {
        let mut m = Machine::new().expect("machine");
        let mut h = Heap::new(Config {
            heap: SEGMENT as usize,
        });
        h.alloc(&mut m, 40_000).expect("fits");
        let e = h.alloc(&mut m, 40_000).expect_err("does not");
        assert!(e.contains("left"), "{e}");
    }

    #[test]
    fn farcoreleft_counts_what_is_free_and_what_could_still_be_mapped() {
        let (mut m, mut h) = heap();
        // Whole segments only: the configured total rounded down, because the
        // remainder is memory nothing could ever be given.
        let capacity = Config::default().heap / SEGMENT as usize * SEGMENT as usize;
        assert_eq!(h.left(), capacity, "nothing reserved yet");

        let a = h.alloc(&mut m, 1000).expect("a");
        assert_eq!(h.left(), capacity - 1000);
        h.free(a).expect("freed");
        assert_eq!(h.left(), capacity, "and it comes back");
    }

    #[test]
    fn a_heap_never_promises_a_remainder_it_cannot_hand_out() {
        // Two segments' worth and a bit: the bit is not capacity.
        let mut m = Machine::new().expect("machine");
        let mut h = Heap::new(Config {
            heap: 2 * SEGMENT as usize + 4096,
        });
        assert_eq!(h.left(), 2 * SEGMENT as usize);

        h.alloc(&mut m, 40_000).expect("first segment");
        h.alloc(&mut m, 40_000).expect("second segment");
        assert_eq!(h.segments(), 2);
        assert!(h.alloc(&mut m, 40_000).is_err(), "there is no third");
    }

    #[test]
    fn a_zero_byte_allocation_refuses() {
        let (mut m, mut h) = heap();
        assert!(h.alloc(&mut m, 0).is_err());
    }

    #[test]
    fn a_tiled_region_is_remembered_by_its_first_selector() {
        let (mut m, mut h) = heap();
        let at = h.alloc_tiled(&mut m, 4, 4096).expect("tiled");
        let region = h.region(at.selector).expect("remembered");
        assert_eq!((region.qty, region.size), (4, 4096));
        assert!(h.region(at.selector + 8).is_none(), "only the first tile");
    }
}
