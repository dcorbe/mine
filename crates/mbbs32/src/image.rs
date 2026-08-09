//! A [`PeImage`] mapped into memory: one [`Mapping`], sections copied into
//! place.
//!
//! Base relocations (Task 12) and import binding (Task 13) are not applied
//! here -- this is the shape of the image once its bytes are in place, before
//! either.
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
use crate::pe::PeImage;

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
            dst[rva..rva + raw_size].copy_from_slice(&file[raw_offset..raw_offset + raw_size]);
        }

        Ok(Self { mapping })
    }

    /// The mapped image's contents.
    pub fn as_slice(&self) -> &[u8] {
        self.mapping.as_slice()
    }
}
