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
//! # Generic top to bottom
//!
//! The algorithm above -- first-fit across regions already mapped, block
//! sizes kept host-side keyed by the pointer -- is written once, over
//! `A: Abi`, and grows a region at a time through
//! [`ModuleMem::alloc_region`](crate::abi::ModuleMem::alloc_region) rather
//! than `mbbs_machine::m16::Machine::alloc_segment` directly: see [`Heap::reserve`].
//!
//! This file used to keep a `Wg16`-only facade over that core --
//! `Heap::alloc(&mut Machine, ..)`, a one-line reborrow into
//! [`Heap::reserve`] -- because every shim call site was written against it.
//! By Task 13 of `docs/plans/2026-08-12-abi-border-implementation.md` every
//! production call site had already moved onto `reserve` itself (`alcmem`,
//! `alczer`, `Host::alcvda`, `TextVars::push_mem`, ...); `alloc`'s only
//! remaining callers were this file's own tests and one `btrieve.rs` test
//! helper, both of which call `reserve` directly now. So the facade is
//! deleted rather than converted -- there was nothing left calling it.
//!
//! [`Heap::alloc_tiled`] is not here for a different reason: LDT tile
//! chaining is `Wg16`-only forever (32-bit's `alcblok`/`ptrblok` are an
//! unrelated mechanism, out of scope here), so unlike `alloc` it never had a
//! generic core to converge onto. It moved to `crates/mbbs/src/shims/memory.rs`,
//! beside `alctile`, its one production caller -- see `Heap::push_tile`
//! (`pub(crate)`, so not linked from here) for the one piece of access it
//! still needs from this module.
//!
//! `A` carries no default. It was `= Wg16`, which let every caller name this
//! type as plain `Heap`; Task 3 of
//! `docs/plans/2026-08-12-abi-border-implementation.md` struck that default
//! along with every other in this crate, so each caller spells its ABI.

use std::collections::HashMap;

use crate::abi::{Abi, ModuleMem};

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
/// doc comment ("Generic top to bottom").
pub struct Heap<A: Abi> {
    config: Config,
    regions: Vec<Arena<A>>,

    /// How long each live allocation is, and where, by the pointer handed out
    /// for it.
    blocks: HashMap<A::Ptr, Block>,

    /// Live allocations [`Heap::reserve_large`] made, by the pointer handed
    /// out for each: a single allocation too big to pack into any
    /// [`SEGMENT`]-sized [`Arena`], so there is no `region`/`at` pair to
    /// record the way [`Block`] does -- only how long it is, so
    /// [`Heap::free`] knows to hand the whole thing back to nobody (see that
    /// method) rather than hunting for it in `regions`.
    large: HashMap<A::Ptr, usize>,

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
            large: HashMap::new(),
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
    /// The generic core `alcmem`/`alczer` both call directly -- see this
    /// module's doc comment for the `Wg16` `alloc` facade this used to be
    /// reached through, and why it is gone now.
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

    /// Reserve `size` bytes as a region entirely of its own, for a single
    /// allocation too large to pack into any of the [`SEGMENT`]-sized
    /// regions [`Heap::reserve`] shares among many callers.
    ///
    /// Goes straight to [`ModuleMem::alloc_region`] -- the same primitive
    /// [`Heap::reserve`] itself grows through when nothing already mapped
    /// has room -- and never joins `self.regions`' first-fit free list,
    /// because nothing else should ever be packed alongside a block this
    /// size. This is deliberately **not** `reserve` widened: `reserve`'s
    /// `u16` stays exactly as narrow as it was (see [`Abi::ptr_offset`]'s
    /// doc comment for why a wider type there would only let an
    /// out-of-range offset compile instead of refusing to build), and
    /// every one of `reserve`'s other 58 call sites is untouched by this
    /// method existing.
    ///
    /// `Wg32`'s `alloc_region` (`Memory::alloc`, a flat bump allocator over
    /// a fixed arena) has no ceiling of its own short of the arena's own
    /// size, so this is where a `Wg32` allocation past `u16::MAX` bytes
    /// actually lands -- MajorMUD-NT's module init asks `alcblok` for
    /// 2,317,552 of them; see `shims::memory::alcblok32`'s own doc comment.
    ///
    /// `Wg16`'s `alloc_region` is `Machine::alloc_segment`, which refuses
    /// anything past 64 KiB outright -- no far pointer can address across a
    /// segment boundary, and that refusal is correct, load-bearing
    /// behaviour, not a gap this method works around. In practice nothing
    /// on the `Wg16` side ever calls this with a `size` [`Heap::reserve`]
    /// could not already have answered -- `alcmem`/`alczer` branch into
    /// this only once `size` no longer fits `u16`, and `Wg16`'s own `Int`
    /// is `u16`, so a `Wg16` module can never produce such a `size` in the
    /// first place. If something ever does reach this on `Wg16`, it fails
    /// the same way growing `reserve` a fresh region would: cleanly, naming
    /// why, not by finding a way around a limit that exists on purpose.
    ///
    /// This block is invisible to [`Heap::left`]'s accounting: `left`
    /// counts `self.regions` and how many more of them the configured
    /// `heap` total could still map, and a large block is neither packed
    /// into one nor counted against that total. That is a real limitation
    /// of `farcoreleft`'s honesty once a module starts making large
    /// allocations, not an oversight this task's brief asked to fix.
    ///
    /// # Errors
    ///
    /// If `size` is zero, or `mem.alloc_region` refuses.
    pub fn reserve_large(&mut self, mem: &mut A::Mem, size: usize) -> Result<A::Ptr, String> {
        if size == 0 {
            return Err("an allocation of zero bytes".to_owned());
        }
        let ptr = mem.alloc_region(size).map_err(|e| e.to_string())?;
        self.large.insert(ptr, size);
        Ok(ptr)
    }

    /// Give `at` back.
    ///
    /// Checked against [`Heap::reserve_large`]'s own list first: a large
    /// block was never packed into any `Arena`'s free list, so the ordinary
    /// path below would never find it. Handing it back only forgets it --
    /// nothing here ever reclaims a `ModuleMem::alloc_region` mapping, the
    /// same as an ordinary region once grown (see [`Heap::reserve`]) -- but
    /// forgetting it is enough to make a second `free` of the same pointer
    /// fall through to the "was not allocated, or was freed already" refusal
    /// below, same as any other double free.
    ///
    /// # Errors
    ///
    /// If `at` was never allocated, or has already been freed. Both are module
    /// bugs the real host would have absorbed silently.
    pub fn free(&mut self, at: A::Ptr) -> Result<(), String> {
        if self.large.remove(&at).is_some() {
            return Ok(());
        }

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

    /// Record a newly tiled region.
    ///
    /// `pub(crate)`, not the tiling operation itself: building a [`Region`]
    /// needs the selector `mbbs_machine::m16::Machine::alloc_tiled` handed
    /// back, which only `Wg16`'s own `alloc_tiled` (`shims/memory.rs`,
    /// beside `alctile`, its one caller) can supply -- see this module's
    /// doc comment. This is the one piece of `tiles`' privacy that caller
    /// needs, so it gets a named method rather than a wider field.
    pub(crate) fn push_tile(&mut self, region: Region) {
        self.tiles.push(region);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{Wg16, Wg32};
    use mbbs_machine::m16::{FarPtr, Machine};
    use mbbs_machine::ptr::ModulePtr;

    fn heap() -> (Machine, Heap<Wg16>) {
        (
            Machine::new().expect("machine"),
            Heap::new(Config::default()),
        )
    }

    // # Wg32 fixtures build a `Memory` only, never a `Machine`
    //
    // `reserve_large` (like `reserve`) only ever touches `A::Mem`, never
    // `A::Cpu` -- so a `mbbs_machine::m32::Memory` on its own is everything
    // these tests need, and nothing here calls `mbbs_machine::m32::Machine::new`, which is
    // the call that registers with the process-wide fault arbiter
    // (`crates/mbbs/tests/wg32_abi.rs`'s own module doc comment explains why
    // any test that *does* build a `Wg32Cpu` stays out of this binary
    // entirely). Duplicated rather than shared, per this crate family's own
    // convention for this exact fixture -- see `mbbs_machine::m32::mem`'s and
    // `mbbs_machine::m32::flatptr`'s own test modules, and
    // `crates/mbbs/tests/wg32_abi.rs`'s `minimal_with_one_section`.
    const WG32_SIZE_OF_IMAGE: u32 = 0x0000_2000;

    fn wg32_minimal_with_one_section() -> Vec<u8> {
        let mut v = vec![0u8; 0x200];
        v[0..2].copy_from_slice(b"MZ");
        v[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        v[0x80..0x84].copy_from_slice(b"PE\0\0");
        v[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes());
        v[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        v[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes());
        v[0x96..0x98].copy_from_slice(&0x010eu16.to_le_bytes());
        v[0x98..0x9a].copy_from_slice(&0x010bu16.to_le_bytes());

        let opt = 0x98;
        v[opt + 16..opt + 20].copy_from_slice(&0x0000_1111u32.to_le_bytes());
        v[opt + 28..opt + 32].copy_from_slice(&0x2222_0000u32.to_le_bytes());
        v[opt + 32..opt + 36].copy_from_slice(&0x0000_1000u32.to_le_bytes());
        v[opt + 36..opt + 40].copy_from_slice(&0x0000_0400u32.to_le_bytes());
        v[opt + 56..opt + 60].copy_from_slice(&WG32_SIZE_OF_IMAGE.to_le_bytes());

        let sec = opt + 0xe0;
        v.resize(sec + 40 + 0x200, 0);
        v[sec..sec + 8].copy_from_slice(b"CODE\0\0\0\0");
        v[sec + 8..sec + 12].copy_from_slice(&0x100u32.to_le_bytes());
        v[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        v[sec + 16..sec + 20].copy_from_slice(&0x80u32.to_le_bytes());
        v[sec + 20..sec + 24].copy_from_slice(&((sec + 40) as u32).to_le_bytes());
        v[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        v
    }

    fn wg32_mem(arena_len: usize) -> mbbs_machine::m32::Memory {
        let file = wg32_minimal_with_one_section();
        let pe = mbbs_machine::m32::PeImage::parse(&file).expect("fixture parses");
        let image = mbbs_machine::m32::Image::load(&file, &pe).expect("fixture loads");
        mbbs_machine::m32::Memory::with_image(image, arena_len).expect("arena mapping")
    }

    /// The scenario this task exists for: MajorMUD-NT's module init calls
    /// `alcblok(1501, 1544)`, `1501 * 1544 + 8 = 2,317,552` bytes -- about
    /// 35x `Heap::reserve`'s packed-region ceiling
    /// (`shims::memory::alcblok32`'s own doc comment). A 4 MiB arena holds
    /// it three times over, so `reserve_large` must answer a real,
    /// end-to-end writable pointer, and `free` must take it back.
    #[test]
    fn reserve_large_is_writable_across_its_full_length_and_frees_on_wg32() {
        let mut mem = wg32_mem(4 * 1024 * 1024);
        let mut h = Heap::<Wg32>::new(Config::default());

        let size = 1501 * 1544 + 8;
        let ptr = h
            .reserve_large(&mut mem, size)
            .expect("a 4 MiB arena holds 2,317,552 bytes three times over");

        let full = vec![0xABu8; size];
        ptr.write(&mut mem, &full)
            .expect("the whole block must be writable, not merely its head");
        assert_eq!(
            ptr.resolve(&mem, size).expect("readable back"),
            &full[..],
            "every byte written must read back, end to end"
        );

        // A second allocation must start at or past the end of the first
        // one's full requested `size` -- not merely somewhere the first
        // write happened to succeed. `Memory::alloc` is a flat arena with no
        // per-allocation bounds check of its own, so a `reserve_large` that
        // silently asked `mem.alloc_region` for less than `size` (e.g.
        // clamped to one `SEGMENT`) would still let the write/read-back
        // above pass -- the bytes are still inside the arena mapping,
        // simply not inside what was actually reserved. Only a pointer that
        // overlaps the first allocation's own claimed length catches that.
        let second = h
            .reserve_large(&mut mem, 64)
            .expect("a second, small dedicated region");
        assert!(
            second.0 >= ptr.0 + size as u32,
            "the second reserve_large call must not land inside the first \
             one's own {size}-byte span -- overlap here means the first \
             call did not actually reserve its full requested size"
        );

        h.free(ptr).expect("free accepts a reserve_large pointer");
        assert!(
            h.free(ptr).is_err(),
            "a second free of the same large block is a double free, same as any other block"
        );
    }

    #[test]
    fn reserve_large_refuses_zero_bytes_on_wg32() {
        let mut mem = wg32_mem(4096);
        let mut h = Heap::<Wg32>::new(Config::default());
        assert!(h.reserve_large(&mut mem, 0).is_err());
    }

    /// `Wg16`'s `alloc_region` is `Machine::alloc_segment`, which refuses
    /// anything past 64 KiB outright -- correct, load-bearing behaviour
    /// (no far pointer can address across a segment boundary), not a gap
    /// `reserve_large` should paper over. Pinned so a future change cannot
    /// "fix" this refusal without the test naming exactly what it would
    /// break.
    #[test]
    fn reserve_large_refuses_cleanly_on_wg16_naming_why() {
        let (mut m, mut h) = heap();
        let e = h
            .reserve_large(m.mem_mut(), 100_000)
            .expect_err("no far pointer can address across a 64 KiB segment boundary");
        assert!(e.contains("100000"), "the refusal should name the size asked for: {e}");
        assert!(
            e.to_lowercase().contains("segment"),
            "the refusal should name why, not just that it failed: {e}"
        );
    }

    #[test]
    fn allocations_do_not_overlap() {
        let (mut m, mut h) = heap();
        let a = h.reserve(m.mem_mut(), 100).expect("a");
        let b = h.reserve(m.mem_mut(), 100).expect("b");
        assert_ne!(a, b);
        assert!(
            a.offset + 100 <= b.offset || b.offset + 100 <= a.offset,
            "{a:?} and {b:?} overlap"
        );
    }

    #[test]
    fn freed_space_is_reusable() {
        let (mut m, mut h) = heap();
        let a = h.reserve(m.mem_mut(), 4096).expect("a");
        h.free(a).expect("freed");
        let b = h.reserve(m.mem_mut(), 4096).expect("b");
        assert_eq!(a, b, "the same space should come back");
    }

    #[test]
    fn adjacent_free_blocks_merge() {
        // Without merging, a heap that had been used could not satisfy anything
        // larger than the biggest single block ever freed -- and nothing would
        // say why.
        let (mut m, mut h) = heap();
        let a = h.reserve(m.mem_mut(), 20_000).expect("a");
        let b = h.reserve(m.mem_mut(), 20_000).expect("b");
        let c = h.reserve(m.mem_mut(), 20_000).expect("c");
        h.free(b).expect("freed");
        h.free(a).expect("freed");
        h.free(c).expect("freed");

        let big = h.reserve(m.mem_mut(), 60_000).expect("three merged into one");
        assert_eq!(big, a);
        assert_eq!(h.segments(), 1, "and it did not need a second segment");
    }

    #[test]
    fn a_free_of_something_never_allocated_refuses() {
        let (mut m, mut h) = heap();
        let a = h.reserve(m.mem_mut(), 64).expect("a");
        let stray = FarPtr {
            offset: a.offset + 8,
            selector: a.selector,
        };
        assert!(h.free(stray).is_err(), "a pointer into a block is not one");
    }

    #[test]
    fn a_double_free_refuses_rather_than_corrupting_the_heap() {
        let (mut m, mut h) = heap();
        let a = h.reserve(m.mem_mut(), 64).expect("a");
        h.free(a).expect("first");
        assert!(h.free(a).is_err(), "the second is a module bug");
    }

    #[test]
    fn the_heap_crosses_a_segment_boundary() {
        let (mut m, mut h) = heap();
        let first = h.reserve(m.mem_mut(), 40_000).expect("a");
        let second = h.reserve(m.mem_mut(), 40_000).expect("b");
        assert_ne!(
            first.selector, second.selector,
            "two of these do not fit in one 64 KiB segment"
        );
        assert_eq!(h.segments(), 2);
    }

    #[test]
    fn a_heap_that_may_not_grow_refuses_and_says_how_much_is_left() {
        let mut m = Machine::new().expect("machine");
        let mut h = Heap::<Wg16>::new(Config {
            heap: SEGMENT as usize,
        });
        h.reserve(m.mem_mut(), 40_000).expect("fits");
        let e = h.reserve(m.mem_mut(), 40_000).expect_err("does not");
        assert!(e.contains("left"), "{e}");
    }

    #[test]
    fn farcoreleft_counts_what_is_free_and_what_could_still_be_mapped() {
        let (mut m, mut h) = heap();
        // Whole segments only: the configured total rounded down, because the
        // remainder is memory nothing could ever be given.
        let capacity = Config::default().heap / SEGMENT as usize * SEGMENT as usize;
        assert_eq!(h.left(), capacity, "nothing reserved yet");

        let a = h.reserve(m.mem_mut(), 1000).expect("a");
        assert_eq!(h.left(), capacity - 1000);
        h.free(a).expect("freed");
        assert_eq!(h.left(), capacity, "and it comes back");
    }

    #[test]
    fn a_heap_never_promises_a_remainder_it_cannot_hand_out() {
        // Two segments' worth and a bit: the bit is not capacity.
        let mut m = Machine::new().expect("machine");
        let mut h = Heap::<Wg16>::new(Config {
            heap: 2 * SEGMENT as usize + 4096,
        });
        assert_eq!(h.left(), 2 * SEGMENT as usize);

        h.reserve(m.mem_mut(), 40_000).expect("first segment");
        h.reserve(m.mem_mut(), 40_000).expect("second segment");
        assert_eq!(h.segments(), 2);
        assert!(h.reserve(m.mem_mut(), 40_000).is_err(), "there is no third");
    }

    #[test]
    fn a_zero_byte_allocation_refuses() {
        let (mut m, mut h) = heap();
        assert!(h.reserve(m.mem_mut(), 0).is_err());
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
