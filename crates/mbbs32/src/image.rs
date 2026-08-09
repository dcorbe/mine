//! A [`PeImage`] mapped into memory: one [`Mapping`], sections copied into
//! place, rebased with [`Image::relocate`], imports bound with
//! [`Image::bind_imports`].
//!
//! **Section protections are parsed but not applied.** Every page of a
//! [`Mapping`] is `PROT_READ | PROT_WRITE | PROT_EXEC`, regardless of a
//! section's own characteristics (`CODE` not writable, `.reloc` not needed at
//! runtime at all, and so on). Tightening that is future work, not an
//! oversight: it needs page-granular `mprotect` calls keyed to each section's
//! *aligned* extent, which is a distinct piece of machinery from copying
//! bytes, and nothing through this task exercises it.

use std::collections::HashMap;
use std::io;

use crate::map::Mapping;
use crate::pe::{PeError, PeImage, Symbol};

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

    /// Read `len` bytes at linear-address-relative `rva`, bounds-checked
    /// against this image's own mapped length.
    ///
    /// **Not** `PeImage::rva_to_file`: that answers a file-layout question and
    /// refuses BSS addresses that are perfectly valid once mapped (zeroed by
    /// the mapping itself, never present in the file). This checks only
    /// against what is actually mapped.
    ///
    /// # Errors
    ///
    /// If `rva + len` runs past the end of the mapping.
    pub fn read_at(&self, rva: u32, len: usize) -> io::Result<&[u8]> {
        let start = rva as usize;
        let end = start.checked_add(len).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "rva + len overflows")
        })?;
        self.as_slice().get(start..end).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{len} bytes at rva {rva:#x} runs past the end of the image"),
            )
        })
    }

    /// Write `bytes` at linear-address-relative `rva`, bounds-checked the same
    /// way as [`Image::read_at`].
    ///
    /// # Errors
    ///
    /// If `rva + bytes.len()` runs past the end of the mapping.
    pub fn write_at(&mut self, rva: u32, bytes: &[u8]) -> io::Result<()> {
        let start = rva as usize;
        let end = start.checked_add(bytes.len()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "rva + len overflows")
        })?;
        let len = bytes.len();
        self.mapping
            .as_mut_slice()
            .get_mut(start..end)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{len} bytes at rva {rva:#x} runs past the end of the image"),
                )
            })?
            .copy_from_slice(bytes);
        Ok(())
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

    /// Bind every import: for each *distinct* `(library, symbol)` pair among
    /// `image.imports`, ask `resolver` once, and write the answer into every
    /// IAT slot naming that pair.
    ///
    /// **Once per symbol, not once per site, and this is not an
    /// optimisation.** `wccmmud.dll` names some symbols at only one site, but
    /// nothing about the format stops a module from naming the same host
    /// global at hundreds -- the sibling 16-bit loader's own module does
    /// exactly that (`usrnum`, 1,285 sites). A resolver that allocates
    /// storage for a global on first sight, asked once per site, would
    /// scatter that one global across every site that names it, and the
    /// module would read whichever fixup happened to run last. Caching the
    /// answer by `(library, symbol)` here, in the loader, makes that bug
    /// impossible regardless of how a resolver is implemented.
    ///
    /// [`Import32::Data`] writes its address directly. Anything else --
    /// [`Import32::Routine`], or `resolver.resolve` returning `None` for a
    /// symbol the host does not implement -- gets a dense thunk index instead
    /// (0, 1, 2, ... in first-encounter order across the whole import table),
    /// written into the IAT slot in place of a real address. No code lives at
    /// that index yet: nothing through this task builds thunks (that is a
    /// later increment; see `docs/plans/2026-08-08-mbbs32-implementation.md`,
    /// Task 16). What this task fixes, permanently, is *which* index every
    /// site sharing a symbol gets -- one, the same one, never reassigned.
    ///
    /// An unresolved symbol is given an index rather than skipped so that
    /// calling it later is a diagnosable event (which thunk index; look it up
    /// in the returned list) rather than a call through whatever happened to
    /// already be in that IAT slot's freshly-mapped, zeroed memory.
    ///
    /// Returns every distinct symbol that was given an index, in that same
    /// index order, so a later task can tell one thunk from the next without
    /// re-walking `image.imports` itself.
    pub fn bind_imports(
        &mut self,
        image: &PeImage,
        resolver: &dyn ImportResolver,
    ) -> Vec<ThunkSite> {
        let mut cache: HashMap<(&str, &Symbol), u32> = HashMap::new();
        let mut thunks: Vec<ThunkSite> = Vec::new();

        let dst = self.mapping.as_mut_slice();
        for import in &image.imports {
            let key = (import.library.as_str(), &import.symbol);
            let value = *cache.entry(key).or_insert_with(|| {
                let answer = resolver.resolve(&import.library, &import.symbol);
                match answer {
                    Some(Import32::Data(addr)) => addr,
                    other => {
                        // `other` is `Some(Import32::Routine)` or `None`;
                        // both get a thunk, see the doc comment above.
                        let index = thunks.len();
                        thunks.push(ThunkSite {
                            library: import.library.clone(),
                            symbol: import.symbol.clone(),
                            resolved: matches!(other, Some(Import32::Routine)),
                        });
                        index as u32
                    }
                }
            });

            let rva = import.iat_rva as usize;
            // In-bounds by construction: `PeImage::parse` refuses (as
            // `PeError::UnmappedRva` / `PeError::RvaSpansSectionEnd`) any
            // import whose IAT slot is not entirely inside some section's raw
            // data -- see `Import::iat_rva`'s doc comment in `pe.rs`. A
            // `PeImage` this crate can construct at all therefore cannot
            // describe a slot outside `dst`.
            dst[rva..rva + 4].copy_from_slice(&value.to_le_bytes());
        }

        thunks
    }

    /// After [`Image::bind_imports`], overwrite every IAT slot it gave a
    /// thunk index with a real address instead: `thunk_addr(index)`.
    ///
    /// `thunks` must be exactly what the matching `bind_imports` call
    /// returned. This does **not** call a resolver again -- a resolver may
    /// have side effects (the doc comment on [`Image::bind_imports`] already
    /// leans on that: an unresolved symbol gets a thunk rather than being
    /// skipped precisely so a *future*, side-effecting resolver has a
    /// diagnosable place to answer from), so asking it a second time for a
    /// symbol it already answered would be wrong, not merely redundant.
    /// Instead this rebuilds the `(library, symbol) -> index` map directly
    /// from `thunks`'s own order -- which [`Image::bind_imports`]'s own doc
    /// comment guarantees is "in that same index order" -- and walks
    /// `image.imports` once more to find every site naming one of those
    /// symbols. An import whose `(library, symbol)` is not a key in that map
    /// was resolved to [`Import32::Data`] and is left exactly as
    /// `bind_imports` already wrote it.
    pub fn patch_thunk_addresses(
        &mut self,
        image: &PeImage,
        thunks: &[ThunkSite],
        thunk_addr: impl Fn(u32) -> u32,
    ) {
        let index_of: HashMap<(&str, &Symbol), u32> = thunks
            .iter()
            .enumerate()
            .map(|(i, t)| ((t.library.as_str(), &t.symbol), i as u32))
            .collect();

        let dst = self.mapping.as_mut_slice();
        for import in &image.imports {
            let key = (import.library.as_str(), &import.symbol);
            if let Some(&index) = index_of.get(&key) {
                let rva = import.iat_rva as usize;
                // In-bounds by construction: see the identical comment on
                // `bind_imports`'s own write to this same slot above.
                dst[rva..rva + 4].copy_from_slice(&thunk_addr(index).to_le_bytes());
            }
        }
    }
}

/// How a host answers "what is `WGSERVER.EXE:_prfmsg`?".
///
/// Two arms, not the sibling 16-bit loader's three: a flat 32-bit ABI has no
/// segment:offset far pointers to carry, and nothing measured in
/// `wccmmud.dll`'s 210 imports needs [`Import`](crate::Import)-by-constant
/// (the 16-bit loader's `Absolute` arm, for `DOSCALLS.135`'s shift count) --
/// a fixup here writes a whole address-sized slot, never patches an
/// instruction's immediate field.
pub trait ImportResolver {
    /// `None` for a symbol the host does not implement. The loader still
    /// gives it a thunk, so that calling it is a diagnosable event rather
    /// than a jump into nothing.
    fn resolve(&self, library: &str, symbol: &Symbol) -> Option<Import32>;
}

impl<F: Fn(&str, &Symbol) -> Option<Import32>> ImportResolver for F {
    fn resolve(&self, library: &str, symbol: &Symbol) -> Option<Import32> {
        self(library, symbol)
    }
}

/// What a host answers `ImportResolver::resolve` with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Import32 {
    /// A host routine. Gets a thunk; calling it comes back as `Exit::Call`
    /// (a later increment -- see `Image::bind_imports`'s doc comment).
    Routine,
    /// A host global the module addresses directly. This address goes
    /// straight into the IAT slot, and the host is never told it was read.
    Data(u32),
}

/// One symbol [`Image::bind_imports`] gave a thunk index rather than a real
/// address -- every site in `image.imports` naming this exact
/// `(library, symbol)` pair got the same index, in the order these appear in
/// the `Vec` [`Image::bind_imports`] returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThunkSite {
    pub library: String,
    pub symbol: Symbol,
    /// `false` when `ImportResolver::resolve` answered `None` -- the host
    /// does not implement this symbol at all. The site still gets a thunk
    /// index (see [`Image::bind_imports`]'s doc comment for why), so this is
    /// the only place that distinction survives.
    pub resolved: bool,
}

#[cfg(test)]
mod read_write_tests {
    use super::*;
    use crate::pe::PeImage;

    /// `size_of_image` this fixture's optional header plants -- large enough
    /// that a one-section image maps comfortably inside it, with plenty of
    /// room past the section for "past the mapped length" tests to land in.
    const SIZE_OF_IMAGE: u32 = 0x0005_5000;

    /// Offset (within the file buffer this returns) of the one section's raw
    /// data. Mirrors `tests/pe.rs`'s `with_one_section()` layout exactly:
    /// section table starts at `opt + SizeOfOptionalHeader` (`0x98 + 0xe0`),
    /// one 40-byte section header, then raw data immediately after.
    const RAW_OFFSET: usize = 0x98 + 0xe0 + 40;

    /// The smallest file `PeImage::parse` accepts, plus one `CODE` section
    /// covering rva `0x1000..0x1100` (raw `0x1000..0x1080`).
    ///
    /// `image.rs` had no `#[cfg(test)]` module of its own before this task,
    /// so there is no existing helper in *this* crate's unit tests to reuse
    /// directly -- `tests/pe.rs`'s `minimal()`/`with_one_section()` live in
    /// the separate integration-test crate and are not visible from here.
    /// This is that same byte layout, inlined, so these tests build a
    /// `PeImage` + file buffer the same way every other test in this crate
    /// family does rather than inventing a new fixture shape.
    fn minimal_with_one_section() -> Vec<u8> {
        let mut v = vec![0u8; 0x200];
        v[0..2].copy_from_slice(b"MZ");
        v[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew
        v[0x80..0x84].copy_from_slice(b"PE\0\0");
        v[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes()); // machine = i386
        v[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        v[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes()); // SizeOfOptionalHeader
        v[0x96..0x98].copy_from_slice(&0x010eu16.to_le_bytes()); // characteristics
        v[0x98..0x9a].copy_from_slice(&0x010bu16.to_le_bytes()); // PE32 magic

        let opt = 0x98;
        v[opt + 16..opt + 20].copy_from_slice(&0x0000_1111u32.to_le_bytes()); // entry point
        v[opt + 28..opt + 32].copy_from_slice(&0x2222_0000u32.to_le_bytes()); // image base
        v[opt + 32..opt + 36].copy_from_slice(&0x0000_3000u32.to_le_bytes()); // section alignment
        v[opt + 36..opt + 40].copy_from_slice(&0x0000_0400u32.to_le_bytes()); // file alignment
        v[opt + 56..opt + 60].copy_from_slice(&SIZE_OF_IMAGE.to_le_bytes());

        let sec = opt + 0xe0;
        v.resize(sec + 40 + 0x200, 0);
        v[sec..sec + 8].copy_from_slice(b"CODE\0\0\0\0");
        v[sec + 8..sec + 12].copy_from_slice(&0x100u32.to_le_bytes()); // VirtualSize
        v[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        v[sec + 16..sec + 20].copy_from_slice(&0x80u32.to_le_bytes()); // SizeOfRawData
        v[sec + 20..sec + 24].copy_from_slice(&((sec + 40) as u32).to_le_bytes()); // PointerToRawData
        v[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        v
    }

    /// Parse `file` and load it, panicking on failure -- every test here
    /// starts from a fixture already proven to parse and load cleanly by
    /// `tests/pe.rs`/`tests/map.rs`, so a failure here is a bug in the
    /// fixture, not something under test.
    fn load(file: &[u8]) -> Image {
        let image = PeImage::parse(file).expect("fixture parses");
        Image::load(file, &image).expect("fixture loads")
    }

    #[test]
    fn read_at_returns_the_bytes_at_that_rva() {
        // Arrange: a known byte pattern at some offset inside the CODE
        // section's raw data, at file offset `RAW_OFFSET + 0x10` -- which
        // `PeImage::load` copies to rva `0x1000 + 0x10`.
        let mut file = minimal_with_one_section();
        file[RAW_OFFSET + 0x10..RAW_OFFSET + 0x14].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let image = load(&file);

        // Act + Assert: reading the matching rva returns the same bytes.
        assert_eq!(image.read_at(0x1010, 4).unwrap(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn read_at_past_the_mapped_length_is_refused() {
        let file = minimal_with_one_section();
        let image = load(&file);

        // Exactly at the end of the mapping: zero bytes available, one asked
        // for.
        assert!(image.read_at(SIZE_OF_IMAGE, 1).is_err());
        // One byte inside the mapping, two asked for: the range would run
        // one byte past the end.
        assert!(image.read_at(SIZE_OF_IMAGE - 1, 2).is_err());
    }

    #[test]
    fn write_at_is_visible_to_a_later_read_at() {
        let file = minimal_with_one_section();
        let mut image = load(&file);

        image.write_at(0x1020, &[1, 2, 3, 4]).unwrap();
        assert_eq!(image.read_at(0x1020, 4).unwrap(), &[1, 2, 3, 4]);
    }

    #[test]
    fn write_at_past_the_mapped_length_is_refused() {
        let file = minimal_with_one_section();
        let mut image = load(&file);

        assert!(image.write_at(SIZE_OF_IMAGE, &[0]).is_err());
        assert!(image.write_at(SIZE_OF_IMAGE - 1, &[0, 0]).is_err());
    }
}
