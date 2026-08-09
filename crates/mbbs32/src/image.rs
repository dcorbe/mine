//! A [`PeImage`] mapped into memory: one [`Mapping`], sections copied into
//! place, then rebased with [`Image::relocate`].
//!
//! Import binding (Task 13) is not applied here.
//!
//! **Section protections are parsed but not applied.** Every page of a
//! [`Mapping`] is `PROT_READ | PROT_WRITE | PROT_EXEC`, regardless of a
//! section's own characteristics (`CODE` not writable, `.reloc` not needed at
//! runtime at all, and so on). Tightening that is future work, not an
//! oversight: it needs page-granular `mprotect` calls keyed to each section's
//! *aligned* extent, which is a distinct piece of machinery from copying
//! bytes, and nothing through this task exercises it.

use std::io;

use crate::map::Mapping;
use crate::pe::{PeError, PeImage};

/// A [`PeImage`], mapped: one [`Mapping`] of `size_of_image` bytes, with each
/// section's raw bytes copied into place at its `rva`.
pub struct Image {
    mapping: Mapping,
}

impl Image {
    /// Map `image` and copy every section's raw bytes into place.
    ///
    /// For each section, exactly `raw_size` bytes are copied from
    /// `raw_offset` in `file` to `rva` in the mapping -- **never
    /// `virtual_size`**. Where `virtual_size > raw_size` (a section's BSS
    /// tail), those bytes are left exactly as the mapping's fresh anonymous
    /// pages already made them: zero.
    ///
    /// Copying `virtual_size` bytes instead would read past a section's own
    /// raw data and into whatever the file happens to place next -- not a
    /// hypothetical: in the real module this loader exists for, `DATA`'s
    /// raw data ends at file offset `0x78400 + 0x17c00 = 0x90000`, which is
    /// exactly where `.idata`'s raw data begins. `DATA`'s `virtual_size`
    /// exceeds its `raw_size` by `0xc400`, so copying `virtual_size` bytes
    /// for `DATA` would carry `.idata`'s first `0x1200` bytes (all of it)
    /// and part of `.edata`'s straight into `DATA`'s BSS tail.
    ///
    /// # Errors
    ///
    /// If the mapping cannot be made -- [`Mapping::new`]'s errors, most
    /// likely `ENOMEM`.
    pub fn load(file: &[u8], image: &PeImage) -> io::Result<Self> {
        let mut mapping = Mapping::new(image.size_of_image as usize)?;
        let dst = mapping.as_mut_slice();

        for section in &image.sections {
            let raw_offset = section.raw_offset as usize;
            let raw_size = section.raw_size as usize;
            let rva = section.rva as usize;

            // Both ranges indexed below are in-bounds by construction, not
            // merely by hope: `PeImage::parse` refuses (as
            // `PeError::SectionOutOfBounds`, in `pe.rs`) any section whose
            // `raw_offset + raw_size` exceeds `file.len()` (the "raw data"
            // arm) or whose `rva + raw_size` exceeds `size_of_image` (the
            // "raw data mapped into the image" arm, added specifically for
            // this call site -- see its comment for the case it closes:
            // `raw_size` is not bounded by `virtual_size`, so the
            // `rva + virtual_size <= size_of_image` check alone does not
            // cover this write). A `PeImage` this crate can construct at all
            // therefore cannot describe a section whose copy runs past
            // either `file` or `dst`.
            //
            // This is deliberately plain slice indexing, not
            // `unsafe { ptr::copy_nonoverlapping(..) }` against `Mapping`'s
            // raw base: if the invariant above is ever wrong -- weakened in
            // `pe.rs` without this call site being revisited, say -- the
            // failure here is a panic, not a silent out-of-bounds write.
            // `Mapping::as_mut_slice` already carries the one `unsafe` this
            // crate needs to reach the mapping's memory at all (see
            // `map.rs`); nothing is gained by duplicating it here under a
            // weaker guarantee.
            //
            // Two consequences of copying `raw_size` rather than Windows'
            // `min(raw_size, virtual_size)` were measured across the 188-file
            // PE32 corpus in `archive/_acquire/pools/full` rather than argued
            // about, because both are the kind of thing that is fine until the
            // one file where it is not:
            //
            //   - `SizeOfRawData > VirtualSize` is COMMON -- 205 of 985
            //     sections, 20.8% -- since raw data is padded up to
            //     `FileAlignment` while `VirtualSize` is not. So the
            //     `rva + raw_size <= size_of_image` check above is load-bearing
            //     on a fifth of all real sections, not an exotic case.
            //   - Despite that, ZERO of those 985 sections have
            //     `rva + raw_size > SizeOfImage`, and zero of the 797 adjacent
            //     section pairs have `rva + raw_size` reaching into the next
            //     section's `rva`. The padding always fits in the gap that
            //     `SectionAlignment` (0x1000, against a typical 0x200
            //     `FileAlignment`) leaves behind.
            //
            // So copying the full `raw_size` neither overruns the mapping nor
            // clobbers a neighbour on any real input measured. If a future file
            // trips the parse-time check, that is the case to re-read this
            // against -- the fix would be to copy `min(raw_size, virtual_size)`,
            // which is what Windows does, not to relax the bound.
            dst[rva..rva + raw_size].copy_from_slice(&file[raw_offset..raw_offset + raw_size]);
        }

        Ok(Self { mapping })
    }

    /// The mapped image's contents.
    pub fn as_slice(&self) -> &[u8] {
        self.mapping.as_slice()
    }

    /// The address this image is actually mapped at.
    ///
    /// [`Mapping::new`] never asks the kernel for a specific address, so this
    /// is almost never `image.image_base` -- which is exactly the property
    /// [`Image::relocate`]'s tests depend on to prove the rebase arithmetic
    /// rather than merely exercise a delta of zero.
    pub fn base(&self) -> u32 {
        // The cast cannot lose bits: `Mapping::new` only ever returns a base
        // below 4 GiB (`MAP_32BIT`; see map.rs, and
        // `base_is_non_null_below_4gib_and_page_aligned` in tests/map.rs),
        // so `base as usize` already fits in 32 bits before this narrows it.
        self.mapping.base() as usize as u32
    }

    /// Apply `image`'s base relocations against this mapping's actual load
    /// address.
    ///
    /// `delta = self.base() - image.image_base`, and every relocation site is
    /// `*(u32*)(base + rva) += delta`, wrapping. When `delta` is zero (the
    /// image happened to land at its own `ImageBase`) this is a no-op: there
    /// is nothing to fix up, and skipping the loop means a delta-zero load
    /// can never be mistaken for one that actually exercised the rebase
    /// arithmetic.
    ///
    /// # Errors
    ///
    /// [`PeError::RelocsStripped`] if `delta != 0` and `image` was linked
    /// without relocations (`image.rebasable()` is `false`, i.e.
    /// `IMAGE_FILE_RELOCS_STRIPPED` is set). Such an image has no relocation
    /// directory at all -- there is nothing to apply -- so loading it away
    /// from `ImageBase` would otherwise silently leave every absolute address
    /// it contains wrong, with zero fixups applied and nothing to report.
    /// This is refused rather than mapped: no bytes are written when this
    /// error is returned.
    pub fn relocate(&mut self, image: &PeImage) -> Result<(), PeError> {
        let delta = self.base().wrapping_sub(image.image_base);
        if delta == 0 {
            return Ok(());
        }
        if !image.rebasable() {
            return Err(PeError::RelocsStripped);
        }

        let dst = self.mapping.as_mut_slice();
        for reloc in &image.relocations {
            let rva = reloc.rva as usize;
            // In-bounds by construction: `PeImage::parse` refuses (as
            // `PeError::UnmappedRva` / `PeError::RvaSpansSectionEnd`) any
            // relocation whose 4-byte site is not entirely inside some
            // section's raw data -- see `Relocation`'s doc comment in
            // `pe.rs`. A `PeImage` this crate can construct at all therefore
            // cannot describe a site outside `dst` (raw data is itself
            // bounded to `size_of_image` by `SectionOutOfBounds`).
            let word = u32::from_le_bytes(dst[rva..rva + 4].try_into().expect("4 bytes"));
            dst[rva..rva + 4].copy_from_slice(&word.wrapping_add(delta).to_le_bytes());
        }
        Ok(())
    }
}
