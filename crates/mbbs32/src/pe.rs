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
        }

        Ok(Self {
            image_base,
            size_of_image,
            section_alignment,
            file_alignment,
            entry_point,
            characteristics,
            sections,
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
        for s in &self.sections {
            if let Some(offset) = rva.checked_sub(s.rva)
                && offset < s.raw_size
            {
                return Ok(s.raw_offset as usize + offset as usize);
            }
        }
        Err(PeError::UnmappedRva { rva })
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
