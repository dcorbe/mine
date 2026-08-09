//! The PE32 loader: a real module, in real sections.
//!
//! Everything about the format is from the PE/COFF specification. Everything
//! about what a *Worldgroup* module actually contains is measured from
//! `re/wg_nt_ref/WCCNT8PJ/out/wccmmud.dll` and recorded in
//! `docs/plans/2026-08-08-mbbs32-design.md`; `re/pefmt.py` reads the import half
//! of the same file and is the cross-check.
//!
//! # Parse, then map
//!
//! Nothing is allocated until the whole file has parsed, so a malformed module
//! is an error rather than a half-built machine.

use std::fmt;

/// Why a module could not be read.
///
/// Every variant is something a *file* can be, not something the host can do
/// wrong, so none of them is a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeError {
    /// No `MZ` at the front, or no `PE\0\0` where `e_lfanew` points.
    NotPe,

    /// Not a 32-bit x86 image: the COFF machine field is not `IMAGE_FILE_MACHINE_I386`.
    NotI386 { machine: u16 },

    /// The optional header is PE32+ (64-bit) rather than PE32.
    NotPe32 { magic: u16 },

    /// A structure the header points at runs past the end of the file.
    Truncated {
        what: &'static str,
        at: usize,
        need: usize,
        len: usize,
    },

    /// An RVA that no section covers.
    UnmappedRva { rva: u32 },

    /// The image says its relocations were stripped, so it cannot be rebased.
    RelocsStripped,

    /// `SizeOfOptionalHeader` is smaller than this parser trusts to place the
    /// section table.
    ///
    /// The section table sits at `opt + SizeOfOptionalHeader`. A value that
    /// is too small points that address back into the optional header's own
    /// data directories -- which still bounds-checks cleanly, so parsing
    /// would otherwise succeed with a `PeImage` whose sections describe the
    /// wrong bytes rather than failing. This is a floor, not the real
    /// module's exact `0xe0`: legitimate toolchains vary this field, and only
    /// a value that cannot even cover the fields already read from the
    /// header (out to `opt + 56`, i.e. the header must reach `opt + 0x60`) is
    /// rejected.
    BadOptionalHeaderSize { size: u16 },

    /// A base-relocation entry's type is neither `IMAGE_REL_BASED_HIGHLOW`
    /// (the only type this image contains) nor `IMAGE_REL_BASED_ABSOLUTE`
    /// (padding, dropped rather than applied). Refusing it is the whole
    /// reason this loader has a relocation model at all rather than an
    /// assumption: an unknown type is a fixup this loader does not know how
    /// to apply, and applying it wrong would corrupt the module silently.
    UnsupportedRelocation { kind: u16 },

    /// A section describes bytes outside the file, or outside the image the
    /// headers say to allocate. Either one would make the loader read or write
    /// out of bounds when the image is mapped, so it is refused at parse.
    SectionOutOfBounds {
        section: String,
        what: &'static str,
        end: u64,
        limit: u64,
    },

    /// A relocation block's header, or the entries its declared `size`
    /// claims, would run past the base-relocation directory's own declared
    /// end.
    ///
    /// This is deliberately not `Truncated`: that variant's `len` is the
    /// file's length, and a block can overrun its *directory* while sitting
    /// well inside the file -- a directory that claims 10 bytes but whose
    /// only block declares `size = 0x100` parses every byte it touches out of
    /// a file that is plenty long enough. `end` is the boundary that was
    /// actually violated, mirroring why `SectionOutOfBounds` carries its own
    /// `limit` rather than reusing `Truncated`.
    ///
    /// Also returned when the block chain does not land exactly on the
    /// directory's end: a directory that overstates the chain's true length
    /// would otherwise have its shortfall bytes reinterpreted as a fresh
    /// block header, parsing whatever follows in the file as relocations
    /// that were never declared.
    RelocBlockOutOfBounds {
        at: usize,
        need: usize,
        end: usize,
    },

    /// A relocation block's declared `size` is not `8 + 2*n` for an integer
    /// `n`: after the 8-byte header, entries are 2 bytes each, so any other
    /// size leaves a dangling byte inside the block. Accepting it would
    /// floor-divide `(size - 8) / 2`, silently dropping that byte while still
    /// advancing past the whole declared `size` -- shifting every later
    /// block's parse position by an attacker-chosen offset.
    MalformedRelocBlockSize { at: usize, size: usize },
}

impl fmt::Display for PeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPe => write!(f, "not a PE file"),
            Self::NotI386 { machine } => {
                write!(f, "machine {machine:#06x} is not i386")
            }
            Self::NotPe32 { magic } => {
                write!(f, "optional header magic {magic:#06x} is not PE32")
            }
            Self::Truncated {
                what,
                at,
                need,
                len,
            } => write!(
                f,
                "{what} needs {need} bytes at {at:#x}, but the file is {len} bytes"
            ),
            Self::UnmappedRva { rva } => {
                write!(f, "rva {rva:#x} is not inside any section")
            }
            Self::RelocsStripped => {
                write!(f, "the image has no relocations and cannot be rebased")
            }
            Self::BadOptionalHeaderSize { size } => write!(
                f,
                "optional header size {size:#x} is too small to place the section table"
            ),
            Self::UnsupportedRelocation { kind } => {
                write!(f, "relocation type {kind} is not one this loader applies")
            }
            Self::SectionOutOfBounds {
                section,
                what,
                end,
                limit,
            } => write!(
                f,
                "section {section:?} {what} ends at {end:#x}, past {limit:#x}"
            ),
            Self::RelocBlockOutOfBounds { at, need, end } => write!(
                f,
                "reloc block at {at:#x} needs {need} bytes, but its directory ends at {end:#x}"
            ),
            Self::MalformedRelocBlockSize { at, size } => write!(
                f,
                "reloc block at {at:#x} declares size {size}, which is not 8 + an even number of bytes"
            ),
        }
    }
}

impl std::error::Error for PeError {}

/// A cursor that cannot read off the end of the file.
///
/// Every field in this parser is read through one of these methods. The
/// alternative -- indexing the slice directly and trusting the header -- is how
/// a loader turns a malformed file into a panic, and a module is untrusted
/// input in exactly the same sense module memory is.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn slice(&self, what: &'static str, at: usize, len: usize) -> Result<&'a [u8], PeError> {
        self.bytes
            .get(at..at.checked_add(len).ok_or(PeError::Truncated {
                what,
                at,
                need: len,
                len: self.bytes.len(),
            })?)
            .ok_or(PeError::Truncated {
                what,
                at,
                need: len,
                len: self.bytes.len(),
            })
    }

    fn u16(&self, what: &'static str, at: usize) -> Result<u16, PeError> {
        let b = self.slice(what, at, 2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&self, what: &'static str, at: usize) -> Result<u32, PeError> {
        let b = self.slice(what, at, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
}

/// Where `e_lfanew` lives in the MZ header every PE file starts with.
const E_LFANEW: usize = 0x3c;

/// `IMAGE_FILE_MACHINE_I386`.
const MACHINE_I386: u16 = 0x014c;

/// `IMAGE_NT_OPTIONAL_HDR32_MAGIC`. The 64-bit form is `0x020b`, and the
/// difference is not cosmetic: PE32+ moves every field after `BaseOfCode`.
const PE32_MAGIC: u16 = 0x010b;

/// `IMAGE_FILE_RELOCS_STRIPPED` in the COFF characteristics word.
const RELOCS_STRIPPED: u16 = 0x0001;

/// The smallest `SizeOfOptionalHeader` this parser trusts.
///
/// Every optional-header field this parser reads -- through `SizeOfImage` at
/// `opt + 56` -- fits inside the first `0x60` bytes, which not coincidentally
/// is also where the real header's data directories begin (see `DIR_*`
/// below). A file reporting less than this cannot even cover the fields
/// already read out of it, which means the section table -- located at
/// `opt + SizeOfOptionalHeader` -- would be read from inside the optional
/// header rather than after it. This is a floor, not equality against the
/// real module's `0xe0`: legitimate toolchains vary this field, and the goal
/// is to catch a value that makes the section table land somewhere
/// impossible, not to reject every file that isn't a bit-for-bit match of the
/// one module this crate was measured against.
const MIN_OPTIONAL_HEADER_SIZE: u16 = 0x60;

/// Where the base-relocation directory sits among the optional header's data
/// directories, which begin at `opt + 96`.
const DIR_BASERELOC: usize = 5;

/// `IMAGE_REL_BASED_HIGHLOW`: add the load delta to the 32-bit word at the
/// site. The only type `wccmmud.dll` contains, and the only one implemented --
/// see "Base relocations: one type, and padding" in the design note.
const REL_HIGHLOW: u16 = 3;

/// `IMAGE_REL_BASED_ABSOLUTE`: padding to a 4-byte block boundary. Defined by
/// the format to mean nothing, and dropped at parse rather than at apply so it
/// can never be counted as work.
const REL_ABSOLUTE: u16 = 0;

/// One site to rebase once the image is mapped: `*(u32*)(image + rva) += delta`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relocation {
    pub rva: u32,
}

/// A parsed PE32 image. Plain data: nothing here is mapped or allocated.
#[derive(Debug, Clone)]
pub struct PeImage {
    pub image_base: u32,
    pub size_of_image: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub entry_point: u32,
    pub characteristics: u16,
    pub sections: Vec<Section>,
    pub relocations: Vec<Relocation>,
}

/// The file offset an RVA's bytes live at, given a section table.
///
/// A free function rather than a method: base relocations are parsed inside
/// `PeImage::parse`, before there is a `Self` to call a method on, and
/// `PeImage::rva_to_file` is defined in terms of this so there is exactly one
/// copy of the arithmetic. See `PeImage::rva_to_file` for why it is
/// subtraction-then-compare rather than addition.
///
/// # Errors
///
/// If no section covers the RVA.
fn rva_to_file_in(sections: &[Section], rva: u32) -> Result<usize, PeError> {
    for s in sections {
        if let Some(offset) = rva.checked_sub(s.rva)
            && offset < s.raw_size
        {
            return Ok(s.raw_offset as usize + offset as usize);
        }
    }
    Err(PeError::UnmappedRva { rva })
}

impl PeImage {
    /// Parse a PE32 image. Nothing is allocated beyond the returned structure.
    ///
    /// # Errors
    ///
    /// If the file is not a well-formed 32-bit x86 PE image.
    pub fn parse(file: &[u8]) -> Result<Self, PeError> {
        let r = Reader::new(file);

        // A short read here is "no MZ at the front" in exactly the same sense
        // a mismatched one is: either way, this is not a PE file, not a
        // truncated one. (A `?` here would report `Truncated` for a
        // zero-length file, which is not what "not a PE file" means.)
        match r.slice("mz signature", 0, 2) {
            Ok(b"MZ") => {}
            _ => return Err(PeError::NotPe),
        }
        let pe = r.u32("e_lfanew", E_LFANEW)? as usize;
        if r.slice("pe signature", pe, 4)? != b"PE\0\0" {
            return Err(PeError::NotPe);
        }

        let machine = r.u16("machine", pe + 4)?;
        if machine != MACHINE_I386 {
            return Err(PeError::NotI386 { machine });
        }
        let nsections = r.u16("section count", pe + 6)?;
        let optional_size = r.u16("optional header size", pe + 20)?;
        if optional_size < MIN_OPTIONAL_HEADER_SIZE {
            return Err(PeError::BadOptionalHeaderSize { size: optional_size });
        }
        let characteristics = r.u16("characteristics", pe + 22)?;

        let opt = pe + 24;
        let magic = r.u16("optional magic", opt)?;
        if magic != PE32_MAGIC {
            return Err(PeError::NotPe32 { magic });
        }

        let entry_point = r.u32("entry point", opt + 16)?;
        let image_base = r.u32("image base", opt + 28)?;
        let section_alignment = r.u32("section alignment", opt + 32)?;
        let file_alignment = r.u32("file alignment", opt + 36)?;
        let size_of_image = r.u32("size of image", opt + 56)?;

        let table = opt + usize::from(optional_size);
        let mut sections = Vec::with_capacity(usize::from(nsections));
        for i in 0..usize::from(nsections) {
            let at = table + i * 40;
            let raw = r.slice("section name", at, 8)?;
            let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            sections.push(Section {
                // Latin-1, not UTF-8: these are 1990s toolchain output and a
                // non-ASCII byte is a name, not a decoding error.
                name: raw[..end].iter().map(|&b| b as char).collect(),
                rva: r.u32("section rva", at + 12)?,
                virtual_size: r.u32("section virtual size", at + 8)?,
                raw_size: r.u32("section raw size", at + 16)?,
                raw_offset: r.u32("section raw offset", at + 20)?,
                characteristics: r.u32("section characteristics", at + 36)?,
            });

            // Both bounds below are u64 arithmetic over attacker-controlled
            // u32s specifically so the check itself cannot overflow: Part B
            // (Task 10-13) copies `raw_size` bytes from `raw_offset` in the
            // file to `rva` in a `size_of_image`-byte mapping, in `unsafe`
            // code, so a section describing bytes outside either one must be
            // refused here rather than trusted into an out-of-bounds read or
            // write.
            let s = sections.last().expect("just pushed");
            let raw_end = u64::from(s.raw_offset) + u64::from(s.raw_size);
            if raw_end > file.len() as u64 {
                return Err(PeError::SectionOutOfBounds {
                    section: s.name.clone(),
                    what: "raw data",
                    end: raw_end,
                    limit: file.len() as u64,
                });
            }
            let virtual_end = u64::from(s.rva) + u64::from(s.virtual_size);
            if virtual_end > u64::from(size_of_image) {
                return Err(PeError::SectionOutOfBounds {
                    section: s.name.clone(),
                    what: "virtual range",
                    end: virtual_end,
                    limit: u64::from(size_of_image),
                });
            }
        }

        // Data directories start at opt+96 (after the 8 preceding header
        // fields); each is an 8-byte {VirtualAddress, Size} pair. Base
        // relocations are parsed here, during `parse`, before there is a
        // `Self` to hang `rva_to_file` off of -- hence `rva_to_file_in`.
        let dirs = opt + 96;
        let reloc_rva = r.u32("basereloc rva", dirs + DIR_BASERELOC * 8)?;
        let reloc_size = r.u32("basereloc size", dirs + DIR_BASERELOC * 8 + 4)?;
        let mut relocations = Vec::new();
        if reloc_rva != 0 && reloc_size != 0 {
            let base = rva_to_file_in(&sections, reloc_rva)?;
            let end =
                base.checked_add(reloc_size as usize)
                    .ok_or(PeError::Truncated {
                        what: "basereloc directory",
                        at: base,
                        need: reloc_size as usize,
                        len: file.len(),
                    })?;
            let mut at = base;
            // The walk is required to land exactly on `end`, not merely stay
            // under it: a directory that overstates the block chain's true
            // length would otherwise have the shortfall bytes -- whatever
            // happens to follow in the file -- reinterpreted as a fresh block
            // header, so `at != end` with no room left for another header is
            // an error rather than a quiet stop.
            while at != end {
                at.checked_add(8)
                    .filter(|&next| next <= end)
                    .ok_or(PeError::RelocBlockOutOfBounds { at, need: 8, end })?;
                let page = r.u32("reloc block page", at)?;
                let size = r.u32("reloc block size", at + 4)? as usize;
                // A block size under 8 (the header alone) would not advance
                // `at`, and the loop would spin on a malformed file rather
                // than reject it.
                if size < 8 {
                    return Err(PeError::Truncated {
                        what: "reloc block",
                        at,
                        need: 8,
                        len: file.len(),
                    });
                }
                // Entries are 2 bytes each after the 8-byte header; a size
                // that isn't `8 + 2*n` leaves a dangling byte that floor
                // division would silently drop while still advancing `at` by
                // the whole declared `size`.
                if !(size - 8).is_multiple_of(2) {
                    return Err(PeError::MalformedRelocBlockSize { at, size });
                }
                // The block's own declared `size` must fit inside the
                // directory too, not just its 8-byte header: this is the
                // check whose absence let a block claim to be larger than
                // its directory and have the bytes past the directory's
                // declared end walked as relocation entries anyway.
                let next = at
                    .checked_add(size)
                    .filter(|&next| next <= end)
                    .ok_or(PeError::RelocBlockOutOfBounds { at, need: size, end })?;
                for i in 0..(size - 8) / 2 {
                    let entry = r.u16("reloc entry", at + 8 + i * 2)?;
                    let kind = entry >> 12;
                    if kind == REL_ABSOLUTE {
                        continue;
                    }
                    if kind != REL_HIGHLOW {
                        return Err(PeError::UnsupportedRelocation { kind });
                    }
                    relocations.push(Relocation {
                        rva: page + u32::from(entry & 0x0fff),
                    });
                }
                at = next;
            }
        }

        Ok(Self {
            image_base,
            size_of_image,
            section_alignment,
            file_alignment,
            entry_point,
            characteristics,
            sections,
            relocations,
        })
    }

    /// Whether the image can be loaded anywhere, or only at `image_base`.
    pub fn rebasable(&self) -> bool {
        self.characteristics & RELOCS_STRIPPED == 0
    }

    /// The file offset an RVA's bytes live at.
    ///
    /// Only defined where the section has file bytes: an RVA inside a
    /// section's BSS tail -- past `SizeOfRawData` but within `VirtualSize` --
    /// exists once the image is mapped and nowhere in the file. Answering
    /// with a plausible offset there would silently read the *next*
    /// section's bytes.
    ///
    /// The arithmetic here is deliberately subtraction-then-compare rather
    /// than `s.rva + s.raw_size`: both are attacker-controlled `u32`s read
    /// straight from the file, and a sum close to `u32::MAX` would overflow
    /// and panic in a debug build -- exactly the kind of malformed-file panic
    /// this parser exists to never produce.
    ///
    /// # Errors
    ///
    /// If no section covers the RVA.
    pub fn rva_to_file(&self, rva: u32) -> Result<usize, PeError> {
        rva_to_file_in(&self.sections, rva)
    }
}

/// One section of the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub rva: u32,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub raw_offset: u32,
    pub characteristics: u32,
}
