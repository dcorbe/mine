//! What a [`Flat32Ptr`] resolves against: a module's loaded [`Image`], plus a
//! second [`Mapping`] the host allocates fresh module-addressable memory out
//! of.
//!
//! **Why not fold this into `Image`.** `Image` is a fixed-size mapping made
//! once at load -- see its own module doc comment ("Section protections are
//! parsed but not applied") and `Image::load`'s signature, which takes the
//! whole file and produces exactly one mapping sized to `size_of_image`.
//! There is no "allocate more" operation on it, and there should not be one:
//! widening `Image` into an allocator would make every future reader of that
//! type ask whether a given region is part of the module's own sections or
//! something the host bolted on afterward, for no benefit -- nothing about
//! parsing or relocating a PE image needs to know that distinction.
//!
//! Precedent already exists in this crate for keeping the two apart:
//! `Machine`'s `tib` owns its own stack [`Mapping`], entirely separate from
//! whatever `Image` a caller happens to be executing against (`Machine`
//! does not own an `Image` at all -- see `mod.rs`'s `Machine::call` doc
//! comment). `Memory` is that same shape applied to the *other* side of the
//! crate: one struct owning the module's `Image` and a second `Mapping` for
//! host-allocated regions, so a pointer into either resolves the same way.
pub struct Memory {
    image: crate::m32::Image,
    arena: crate::m32::Mapping,
    /// Bytes of `arena` already handed out. A bump allocator, not a real
    /// free list -- see [`Memory::alloc`] for why nothing here needs to
    /// reclaim.
    arena_used: u32,
}

impl Memory {
    /// Take ownership of a loaded `image`, and reserve `arena_len` bytes of
    /// fresh mapping the host can hand the module regions out of.
    ///
    /// # Errors
    ///
    /// If the arena mapping cannot be made -- [`Mapping::new`]'s errors, most
    /// likely `ENOMEM`.
    pub fn new(image: crate::m32::Image, arena_len: usize) -> std::io::Result<Self> {
        Ok(Self {
            image,
            arena: crate::m32::Mapping::new(arena_len)?,
            arena_used: 0,
        })
    }

    /// The module's own loaded image.
    pub fn image(&self) -> &crate::m32::Image {
        &self.image
    }

    /// The module's own loaded image, mutably -- for relocation and import
    /// binding, which happen before any pointer into it is handed to a shim.
    pub fn image_mut(&mut self) -> &mut crate::m32::Image {
        &mut self.image
    }

    fn arena_base(&self) -> u32 {
        // Same non-lossy cast `Image::base` relies on: `Mapping::new` only
        // ever returns a base below 4 GiB (`MAP_32BIT`), so this narrows
        // nothing that does not already fit.
        self.arena.base() as usize as u32
    }

    /// Give the module `bytes` of fresh, zeroed, addressable memory, and say
    /// where it starts.
    ///
    /// A bump allocator, not first-fit: nothing here ever frees a region
    /// (that bookkeeping -- first-fit, sizes kept host-side keyed by pointer
    /// -- belongs one layer up, in `crates/mbbs`'s `Heap`/`Arena`, which call
    /// this once per region and never again for the same bytes; see
    /// `docs/plans/2026-08-11-abi-abstraction-design.md`, Part 3). This is
    /// the primitive they grow through, matching
    /// [`ModuleMem::alloc_region`](../../mbbs/src/abi.rs)'s contract: "give
    /// me N bytes of module-addressable memory and a pointer to it."
    ///
    /// # Errors
    ///
    /// If `bytes` does not fit in the arena `Memory::new` reserved.
    pub fn alloc(&mut self, bytes: usize) -> std::io::Result<crate::m32::Flat32Ptr> {
        let bytes_u32 = u32::try_from(bytes).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{bytes} bytes does not fit a 32-bit region length"),
            )
        })?;
        let end = self
            .arena_used
            .checked_add(bytes_u32)
            .filter(|&end| u64::from(end) <= self.arena.len() as u64)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::OutOfMemory,
                    format!(
                        "{bytes} bytes will not fit in the {}-byte arena, {} already used",
                        self.arena.len(),
                        self.arena_used
                    ),
                )
            })?;

        let ptr = crate::m32::Flat32Ptr(self.arena_base() + self.arena_used);
        self.arena_used = end;
        Ok(ptr)
    }

    /// `len` bytes at linear address `addr`, wherever they actually live --
    /// the image or the arena. `None` if `addr..addr+len` is not entirely
    /// inside either.
    pub(crate) fn read_at(&self, addr: u32, len: usize) -> Option<&[u8]> {
        let in_image = addr
            .checked_sub(self.image.base())
            .and_then(|off| self.image.read_at(off, len).ok());
        if let Some(bytes) = in_image {
            return Some(bytes);
        }
        let off = addr.checked_sub(self.arena_base())?;
        let off = usize::try_from(off).ok()?;
        let end = off.checked_add(len)?;
        self.arena.as_slice().get(off..end)
    }

    /// Write `bytes` at linear address `addr`. `None` (nothing written) if
    /// `addr..addr+bytes.len()` is not entirely inside the image or the
    /// arena.
    pub(crate) fn write_at(&mut self, addr: u32, bytes: &[u8]) -> Option<()> {
        let wrote_image = addr
            .checked_sub(self.image.base())
            .is_some_and(|off| self.image.write_at(off, bytes).is_ok());
        if wrote_image {
            return Some(());
        }
        let off = addr.checked_sub(self.arena_base())?;
        let off = usize::try_from(off).ok()?;
        let end = off.checked_add(bytes.len())?;
        let dst = self.arena.as_mut_slice().get_mut(off..end)?;
        dst.copy_from_slice(bytes);
        Some(())
    }

    /// Every byte from linear address `addr` to the end of whichever mapping
    /// -- image or arena -- contains it, for a NUL scan. `None` if `addr`
    /// names neither mapping, or sits exactly at the end of one (zero bytes
    /// available, the same "nothing to scan" refusal `Flat32Ptr::read_cstr`
    /// already drew against a bare `Image`).
    pub(crate) fn tail_from(&self, addr: u32) -> Option<&[u8]> {
        if let Some(off) = addr.checked_sub(self.image.base()) {
            let off = off as usize;
            let full = self.image.as_slice();
            if let Some(n) = full.len().checked_sub(off).filter(|n| *n > 0) {
                return Some(&full[off..off + n]);
            }
        }
        let off = addr.checked_sub(self.arena_base())?;
        let off = usize::try_from(off).ok()?;
        let full = self.arena.as_slice();
        let n = full.len().checked_sub(off).filter(|n| *n > 0)?;
        Some(&full[off..off + n])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m32::pe::PeImage;

    /// Mirrors `flatptr.rs`'s own fixture -- see that module's test
    /// constants for why this exact size.
    const SIZE_OF_IMAGE: u32 = 0x0000_2000;

    fn minimal_with_one_section() -> Vec<u8> {
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
        v[opt + 56..opt + 60].copy_from_slice(&SIZE_OF_IMAGE.to_le_bytes());

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

    fn load() -> crate::m32::Image {
        let file = minimal_with_one_section();
        let image = PeImage::parse(&file).expect("fixture parses");
        crate::m32::Image::load(&file, &image).expect("fixture loads")
    }

    /// A region `alloc` hands back must actually resolve -- through the
    /// *arena*, not the image, and at a distinct address from it. A mutation
    /// that made `alloc` return an address inside the image (or simply
    /// `Flat32Ptr(self.arena_used)`, forgetting the base) would still produce
    /// *a* pointer; only checking that it round-trips through `read_at`
    /// catches that.
    #[test]
    fn an_allocated_region_resolves_through_the_arena_and_starts_zeroed() {
        let mut mem = Memory::new(load(), 0x1000).expect("arena");
        let ptr = mem.alloc(16).expect("16 bytes fit");

        assert!(
            ptr.0.wrapping_sub(mem.image().base()) >= SIZE_OF_IMAGE,
            "an arena pointer must not land inside the image"
        );
        assert_eq!(
            mem.read_at(ptr.0, 16).expect("just allocated"),
            &[0u8; 16],
            "a fresh arena region is zeroed, same as a fresh mapping's own pages"
        );
    }

    /// Two `alloc` calls must not overlap -- the whole point of tracking
    /// `arena_used` rather than always answering the arena's base.
    #[test]
    fn two_allocations_do_not_overlap() {
        let mut mem = Memory::new(load(), 0x1000).expect("arena");
        let a = mem.alloc(10).expect("fits");
        let b = mem.alloc(10).expect("fits");
        assert_eq!(b.0, a.0 + 10, "the second allocation must start after the first");
    }

    /// An allocation larger than the arena is refused, not silently
    /// truncated or wrapped into an out-of-bounds pointer.
    #[test]
    fn an_allocation_past_the_arenas_capacity_is_refused() {
        let mut mem = Memory::new(load(), 16).expect("arena");
        assert!(mem.alloc(17).is_err());
    }

    /// `read_at`/`write_at` must find bytes in *either* mapping -- an
    /// address inside the image must not spuriously look like it is in the
    /// arena, and vice versa. Regression guard against a `locate` that only
    /// ever checked one of the two.
    #[test]
    fn read_and_write_reach_both_the_image_and_the_arena() {
        let mut mem = Memory::new(load(), 0x1000).expect("arena");

        // Image: rva 0x1010, inside the mapped CODE section.
        let image_addr = mem.image().base() + 0x1010;
        mem.write_at(image_addr, &[1, 2, 3, 4])
            .expect("address is inside the mapped image");
        assert_eq!(mem.read_at(image_addr, 4).unwrap(), &[1, 2, 3, 4]);

        // Arena: a freshly allocated region.
        let arena_ptr = mem.alloc(4).expect("fits");
        mem.write_at(arena_ptr.0, &[5, 6, 7, 8])
            .expect("address is inside the arena");
        assert_eq!(mem.read_at(arena_ptr.0, 4).unwrap(), &[5, 6, 7, 8]);
    }

    /// An address in neither mapping resolves to nothing, on both `read_at`
    /// and `write_at` -- not a panic, not a silent wrap into whichever
    /// mapping happened to be checked first.
    #[test]
    fn an_address_in_neither_mapping_is_refused() {
        let mut mem = Memory::new(load(), 0x1000).expect("arena");
        // Comfortably past both the image (0x2000 bytes) and the arena
        // (0x1000 bytes), and not `0` (which some future accidental
        // "unchecked" base could make look valid by coincidence).
        let nowhere = mem.image().base().max(mem.arena_base()) + 0x10_0000;
        assert!(mem.read_at(nowhere, 1).is_none());
        assert!(mem.write_at(nowhere, &[0]).is_none());
    }
}
