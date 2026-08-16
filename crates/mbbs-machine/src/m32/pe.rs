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

pub use crate::module::Symbol;

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

    /// A read through an RVA needs more contiguous bytes than remain in the
    /// section that RVA falls inside.
    ///
    /// `rva_to_file` (and the bounded translation under it) only prove the
    /// *first* byte of a read is inside a section; nothing about a single
    /// starting offset stops a multi-byte read -- an import descriptor, a
    /// thunk entry, a name -- from starting one byte before a section's raw
    /// end and spilling into whatever the file happens to place next. This is
    /// the same failure `UnmappedRva` refuses for a BSS tail, generalized to
    /// reads wider than one byte: silently returning bytes from beyond the
    /// section that RVA was declared to belong to.
    RvaSpansSectionEnd {
        what: &'static str,
        rva: u32,
        need: usize,
        remaining: usize,
    },

    /// A NUL-terminated string had no NUL byte before the end of the section
    /// its start RVA falls inside.
    ///
    /// The search is bounded to that section deliberately: scanning past it
    /// would risk returning a "name" built from bytes the next section (or
    /// inter-section padding) happens to contain, which were never part of
    /// this string.
    UnterminatedString { what: &'static str, at: usize },

    /// Advancing an RVA by a fixed step (an import descriptor by 20 bytes, an
    /// import lookup/address table cursor by 4) would overflow `u32`.
    ///
    /// Nothing in a well-formed file reaches this: every section's virtual
    /// range is already checked to fit under `SizeOfImage`. But
    /// `SizeOfImage` is itself an attacker-controlled field with no upper
    /// bound enforced on it alone, so the overflow is reachable from a
    /// crafted file, and `checked_add` is this parser's rule for every
    /// file-supplied `u32` regardless of whether a real linker would ever
    /// produce the input that exercises it.
    RvaOverflow { what: &'static str, rva: u32 },

    /// A name's entry in `AddressOfNameOrdinals` indexes past the end of the
    /// `AddressOfFunctions` array this same export directory declares
    /// (`NumberOfFunctions`).
    ///
    /// This cannot be caught by a bounds-checked *read*: the two-byte
    /// ordinal itself is read from perfectly valid, in-bounds memory. It is
    /// a *data* inconsistency between two arrays this parser has already
    /// finished reading, not a truncated read, so it gets checked
    /// explicitly against `functions.len()` rather than being allowed to
    /// index off the end of the `Vec` already built from it.
    ExportOrdinalOutOfRange {
        name: String,
        ordinal: u16,
        functions: u32,
    },
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
            Self::RvaSpansSectionEnd {
                what,
                rva,
                need,
                remaining,
            } => write!(
                f,
                "{what} at rva {rva:#x} needs {need} bytes, but only {remaining} remain in its section"
            ),
            Self::UnterminatedString { what, at } => write!(
                f,
                "{what} at file offset {at:#x} has no NUL before the end of its section"
            ),
            Self::RvaOverflow { what, rva } => {
                write!(f, "{what}: advancing rva {rva:#x} would overflow u32")
            }
            Self::ExportOrdinalOutOfRange {
                name,
                ordinal,
                functions,
            } => write!(
                f,
                "export {name:?} names function ordinal {ordinal}, but the export \
                 directory declares only {functions} functions"
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
///
/// `rva` is guaranteed, by `PeImage::parse`, to have all 4 of its bytes
/// inside some section's raw data -- the block header's `page` field is
/// otherwise unbounded file input, so that membership is checked at parse
/// time (`RvaSpansSectionEnd` / `UnmappedRva` on failure) rather than trusted.
/// `Image::relocate` (`image.rs`) relies on exactly this invariant to index
/// the mapping without a second bounds check of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relocation {
    pub rva: u32,
}

/// Where the import directory sits among the optional header's data
/// directories, which begin at `opt + 96`.
const DIR_IMPORT: usize = 1;

/// The high bit of an import lookup/address table entry: when set, the low
/// 16 bits are an ordinal, not an RVA to a hint/name pair.
///
/// `wccmmud.dll` imports all 210 of its symbols by name -- zero by ordinal --
/// but the format allows either per entry, and other Worldgroup modules in
/// the Task 9 corpus use it.
const IMPORT_BY_ORDINAL: u32 = 0x8000_0000;

/// One symbol a module imports, and where its address must be written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    /// The DLL as the file spells it -- case is not normalised, because
    /// `WGSERVER.EXE` and `cw3220mt.DLL` appear exactly like that in the same
    /// file.
    pub library: String,
    pub symbol: Symbol,
    /// RVA of the IAT slot this import's resolved address must be written
    /// into. This is always read from the descriptor's `FirstThunk` array,
    /// walked in lockstep with the ILT -- never from the ILT's own address,
    /// even when `OriginalFirstThunk` was zero and the two walks share one
    /// array (see the fallback note on `PeImage::parse`).
    ///
    /// Guaranteed, by `PeImage::parse`, to have all 4 of its bytes inside
    /// some section's raw data -- checked explicitly, because (unlike the
    /// ILT cursor walked alongside it) nothing about reading this array ever
    /// dereferences it, so nothing would otherwise catch a `FirstThunk` that
    /// places it outside every section. `Image::bind_imports` (`image.rs`)
    /// relies on exactly this invariant to index the mapping without a
    /// second bounds check of its own -- mirroring `Relocation::rva`.
    pub iat_rva: u32,
}

/// Where the export directory sits among the optional header's data
/// directories, which begin at `opt + 96`.
const DIR_EXPORT: usize = 0;

/// Where an export points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportAddress {
    /// The ordinary case, and the only one `wccmmud.dll` contains: an RVA to
    /// the function's own code.
    Rva(u32),
    /// The function's entry in `AddressOfFunctions` fell inside the export
    /// directory's own `[VirtualAddress, VirtualAddress + Size)` range. That
    /// is the format's signal that this "address" is not code at all, but
    /// the RVA of a NUL-terminated `"DLL.Symbol"` string naming where the
    /// real export lives. A loader that read it as code would jump into the
    /// middle of a string; representing it as a distinct variant makes that
    /// mistake a type error instead. Following the forwarder into the named
    /// DLL is a Windows loader's job, not this crate's -- see the crate doc.
    Forwarded(String),
}

/// One exported symbol: a name, and where it points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    pub name: String,
    pub address: ExportAddress,
}

impl Export {
    /// `Some(target)` if this export forwards to another DLL's export under
    /// `"DLL.Symbol"`, `None` if it is an ordinary code address.
    #[must_use]
    pub fn forwarder(&self) -> Option<&str> {
        match &self.address {
            ExportAddress::Forwarded(target) => Some(target.as_str()),
            ExportAddress::Rva(_) => None,
        }
    }
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
    pub imports: Vec<Import>,
    /// Every *named* export. Functions exported by ordinal only
    /// (`NumberOfFunctions > NumberOfNames`) are silently absent -- there is
    /// no name to key them by, and nothing through Task 17 needs one. This
    /// is not hypothetical: measured against the two host binaries in this
    /// repo, `WGSERVER.EXE` has 1615 functions but only 1393 names (222
    /// ordinal-only), and `GALGSBL.DLL` has 109 functions but only 89 names
    /// (20 ordinal-only). `export_rva` returning `None` for such a symbol is
    /// indistinguishable from the symbol not existing at all. See the crate
    /// doc's "Two things this is not" for the scope decision.
    pub exports: Vec<Export>,
    /// Every function slot in `AddressOfFunctions`, 0-based -- unlike
    /// `exports`, this includes ordinal-only slots that have no name at all
    /// (see `m32::mod`'s module doc comment: `WGSERVER.EXE` has 222 such
    /// exports out of 1615 functions, `GALGSBL.DLL` 20 out of 109). Built
    /// once, directly from the raw address table, forwarder-detecting every
    /// slot the same way the named loop below does -- so a forwarder is
    /// represented identically whether or not a name ever pointed at it.
    ///
    /// This is a 0-based array index, exactly what `AddressOfNameOrdinals`
    /// entries already are and exactly what `export_base`'s own doc comment
    /// warns must never have `Base` subtracted from it a second time. A
    /// caller-supplied *public* ordinal (what `GetProcAddress`, and
    /// `export_rva_by_ordinal`, take) is `Base` higher than the index that
    /// finds it here -- see `export_rva_by_ordinal`.
    ///
    /// Empty when the image has no export directory.
    pub export_table: Vec<ExportAddress>,
    /// The export directory's `Base` field (`+16`): the value that would be
    /// added to a function's index in `AddressOfFunctions` to produce its
    /// public exported ordinal number.
    ///
    /// Deliberately unused by `export_rva`: a name resolves to a function by
    /// indexing `AddressOfFunctions` directly with
    /// `AddressOfNameOrdinals[i]`, which the format already defines as a
    /// plain 0-based array index, not a `Base`-relative ordinal. Subtracting
    /// `Base` from it -- a classic mistake, since ordinals handed to
    /// `GetProcAddress` *are* `Base`-relative -- indexes the wrong function
    /// whenever `Base != 0`. `None` when the image has no export directory.
    ///
    /// `export_rva_by_ordinal` is the later need this field was kept for: a
    /// *public* ordinal (Galacticomm's "ordinal 1" init-routine convention,
    /// carried from the 16-bit side -- see `crate::m16::ne::Module::entry`)
    /// genuinely is `Base`-relative, so that method subtracts `Base` from
    /// its argument before indexing `export_table` -- the opposite
    /// correction from the one this doc comment warns `export_rva` must not
    /// make, because the value being adjusted is a different kind of number.
    pub export_base: Option<u32>,
    /// The module's own name, as it recorded itself in its export
    /// directory's `Name` field (`+12`) at link time -- e.g. `lunatix.DLL`,
    /// `rcirose.DLL`. Measured, not assumed: both strings above are read
    /// straight off `LUNATIX.DLL` and `RCIROSE.DLL`'s own export
    /// directories.
    ///
    /// This field used to be described here as "deliberately never read":
    /// true until `Wg32::load` needed to resolve a module's init routine by
    /// *name* (`crate::m32::Module::init`'s doc comment -- exported ordinal
    /// 1 is a coincidence for `LUNATIX.DLL`, not Galacticomm's convention,
    /// and is flatly wrong for `RCIROSE.DLL`). That resolution needs the
    /// linked DLL name, and this field is the only place to get one:
    /// `Wg32::load` takes only `file: &[u8]` (`crates/mbbs/src/abi.rs`'s
    /// `Abi::load`), so no filesystem path is ever threaded down to
    /// `PeImage::parse` to read a stem from instead. The export directory's
    /// `Name` is the name the linker itself burned into the file, so it
    /// survives a renamed or copied DLL exactly where a filesystem path
    /// would not.
    ///
    /// `None` when the image has no export directory (mirroring
    /// `export_base`), or when it has one but the `Name` field does not
    /// resolve to a readable string -- e.g. RVA 0, which is what an
    /// otherwise-valid export directory that never set this field reads as.
    pub export_name: Option<String>,
}

/// The file offset an RVA's bytes live at, plus how many contiguous raw bytes
/// of the *same section* follow it, given a section table.
///
/// A free function rather than a method: base relocations and imports are
/// both parsed inside `PeImage::parse`, before there is a `Self` to call a
/// method on. `rva_to_file_in` and `PeImage::rva_to_file` are both defined in
/// terms of this so there is exactly one copy of the arithmetic. See
/// `PeImage::rva_to_file` for why it is subtraction-then-compare rather than
/// addition.
///
/// # Errors
///
/// If no section covers the RVA.
fn rva_to_file_bounded_in(sections: &[Section], rva: u32) -> Result<(usize, usize), PeError> {
    for s in sections {
        if let Some(offset) = rva.checked_sub(s.rva)
            && offset < s.raw_size
        {
            let remaining = (s.raw_size - offset) as usize;
            return Ok((s.raw_offset as usize + offset as usize, remaining));
        }
    }
    Err(PeError::UnmappedRva { rva })
}

/// The file offset an RVA's bytes live at, given a section table.
///
/// # Errors
///
/// If no section covers the RVA.
fn rva_to_file_in(sections: &[Section], rva: u32) -> Result<usize, PeError> {
    rva_to_file_bounded_in(sections, rva).map(|(offset, _)| offset)
}

/// Reads `len` contiguous bytes starting at `rva`, refusing a read that would
/// run past the end of the section `rva` falls inside -- see
/// `PeError::RvaSpansSectionEnd`.
///
/// # Errors
///
/// If no section covers `rva`, if fewer than `len` bytes remain in that
/// section, or if `len` bytes would run past the end of the file (which
/// should not be reachable once the former two checks pass, since a
/// section's raw range is validated against the file's length at parse time,
/// but `Reader::slice` is the single place that fact is enforced).
fn read_bytes_at_rva<'a>(
    sections: &[Section],
    r: &Reader<'a>,
    what: &'static str,
    rva: u32,
    len: usize,
) -> Result<&'a [u8], PeError> {
    let (file_off, remaining) = rva_to_file_bounded_in(sections, rva)?;
    if remaining < len {
        return Err(PeError::RvaSpansSectionEnd {
            what,
            rva,
            need: len,
            remaining,
        });
    }
    r.slice(what, file_off, len)
}

/// Reads a little-endian `u32` at `rva`, bounded to its own section.
///
/// # Errors
///
/// See `read_bytes_at_rva`.
fn u32_at_rva(
    sections: &[Section],
    r: &Reader<'_>,
    what: &'static str,
    rva: u32,
) -> Result<u32, PeError> {
    let b = read_bytes_at_rva(sections, r, what, rva, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Reads a little-endian `u16` at `rva`, bounded to its own section.
///
/// # Errors
///
/// See `read_bytes_at_rva`.
fn u16_at_rva(
    sections: &[Section],
    r: &Reader<'_>,
    what: &'static str,
    rva: u32,
) -> Result<u16, PeError> {
    let b = read_bytes_at_rva(sections, r, what, rva, 2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

/// Reads a NUL-terminated string starting at `rva`, without the NUL.
///
/// The search for the terminator is bounded to the section `rva` falls
/// inside -- see `PeError::UnterminatedString` for why reading further would
/// be wrong even when the file has more bytes to offer.
///
/// Decoded byte-for-byte as Latin-1, not UTF-8, matching `Section::name`:
/// these are 1990s toolchain outputs, and a non-ASCII byte is a name, not a
/// decoding error.
///
/// # Errors
///
/// If no section covers `rva`, or if no NUL byte appears before the end of
/// that section's raw data.
fn read_cstr_at_rva(
    sections: &[Section],
    r: &Reader<'_>,
    what: &'static str,
    rva: u32,
) -> Result<String, PeError> {
    let (file_off, remaining) = rva_to_file_bounded_in(sections, rva)?;
    let bytes = r.slice(what, file_off, remaining)?;
    let end = bytes
        .iter()
        .position(|&b| b == 0)
        .ok_or(PeError::UnterminatedString { what, at: file_off })?;
    Ok(bytes[..end].iter().map(|&b| b as char).collect())
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

            // All three bounds below are u64 arithmetic over
            // attacker-controlled u32s specifically so the check itself
            // cannot overflow: Part B (Task 10-13) copies `raw_size` bytes
            // from `raw_offset` in the file to `rva` in a
            // `size_of_image`-byte mapping, so a section describing bytes
            // outside any of the three must be refused here rather than
            // trusted into an out-of-bounds read or write.
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
            // Nothing above bounds `raw_size` against `virtual_size` (the
            // format does not forbid `SizeOfRawData > VirtualSize`, and
            // neither of the two checks above catches it: a small
            // `virtual_size` at a high `rva` can pass "virtual range" while a
            // much larger `raw_size` at that same `rva` still passes "raw
            // data" against the file). Task 11 (`image.rs`) copies exactly
            // `raw_size` bytes to `rva` in a `size_of_image`-byte mapping, so
            // that write is the thing this check exists to keep in-bounds —
            // check it directly rather than through `virtual_size` as a
            // proxy.
            let raw_into_image_end = u64::from(s.rva) + u64::from(s.raw_size);
            if raw_into_image_end > u64::from(size_of_image) {
                return Err(PeError::SectionOutOfBounds {
                    section: s.name.clone(),
                    what: "raw data mapped into the image",
                    end: raw_into_image_end,
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
                    // `page` is the block header's `VirtualAddress`, read
                    // straight from the file with no upper bound of its own,
                    // so adding the entry's 12-bit page offset can overflow a
                    // crafted file's `u32` even though no real linker output
                    // gets near it.
                    let rva = page.checked_add(u32::from(entry & 0x0fff)).ok_or(
                        PeError::RvaOverflow {
                            what: "relocation site",
                            rva: page,
                        },
                    )?;
                    // The block header's `page` places this fixup anywhere in
                    // a 32-bit address space; nothing above has checked it
                    // against the section table at all. Applying it unchecked
                    // at map time would let a crafted file's relocation
                    // directory write four bytes anywhere in the mapping (or,
                    // for a `rva` past `size_of_image` entirely, out of
                    // bounds of it) -- so this is the same bounded-membership
                    // check every other RVA-indexed read in this parser goes
                    // through, applied here to a site nothing yet reads or
                    // writes, only records for `Image::relocate` to trust
                    // later.
                    let (_, remaining) = rva_to_file_bounded_in(&sections, rva)?;
                    if remaining < 4 {
                        return Err(PeError::RvaSpansSectionEnd {
                            what: "relocation site",
                            rva,
                            need: 4,
                            remaining,
                        });
                    }
                    relocations.push(Relocation { rva });
                }
                at = next;
            }
        }

        // Import directory: an array of 20-byte descriptors, terminated by
        // one whose 20 bytes are all zero. Unlike the base-relocation
        // directory, the descriptor array has no independent count or length
        // to bound it by -- the `Size` field at `dirs + DIR_IMPORT*8 + 4`
        // does not divide evenly by 20 even in the real module
        // (4,308 / 20 = 215.4), so it describes the whole import section's
        // rough extent, not an exact descriptor count, and is not trusted as
        // one here. What *is* enforced is that no descriptor, and no thunk
        // entry read while walking one, is ever read from beyond the end of
        // the section its own RVA falls inside (`read_bytes_at_rva` /
        // `u32_at_rva`): the walk can only be stopped by an all-zero
        // descriptor or a zero ILT entry, or refused by running off a
        // section, never by silently continuing into whatever bytes the file
        // happens to place next.
        let import_rva = r.u32("import directory rva", dirs + DIR_IMPORT * 8)?;
        let import_size = r.u32("import directory size", dirs + DIR_IMPORT * 8 + 4)?;
        let mut imports = Vec::new();
        if import_rva != 0 && import_size != 0 {
            let mut desc_rva = import_rva;
            loop {
                let desc = read_bytes_at_rva(&sections, &r, "import descriptor", desc_rva, 20)?;
                let ilt_rva = u32::from_le_bytes(desc[0..4].try_into().expect("4 bytes"));
                let time_date_stamp = u32::from_le_bytes(desc[4..8].try_into().expect("4 bytes"));
                let forwarder_chain = u32::from_le_bytes(desc[8..12].try_into().expect("4 bytes"));
                let name_rva = u32::from_le_bytes(desc[12..16].try_into().expect("4 bytes"));
                let iat_rva = u32::from_le_bytes(desc[16..20].try_into().expect("4 bytes"));

                // The terminator is the whole 20-byte descriptor being zero,
                // not merely the fields this loader otherwise reads: a
                // descriptor with, say, a nonzero TimeDateStamp but zero
                // everything else is not the end of the array.
                if ilt_rva == 0
                    && time_date_stamp == 0
                    && forwarder_chain == 0
                    && name_rva == 0
                    && iat_rva == 0
                {
                    break;
                }

                let library = read_cstr_at_rva(&sections, &r, "import library name", name_rva)?;

                // Older linkers leave OriginalFirstThunk (the ILT) zero and
                // populate only FirstThunk (the IAT); the walk below then
                // reads the same array twice; see the doc comment on
                // `Import::iat_rva` for why `iat_cursor` is still always
                // taken from `iat_rva`, never from `thunk_rva`.
                let thunk_rva = if ilt_rva != 0 { ilt_rva } else { iat_rva };

                let mut ilt_cursor = thunk_rva;
                let mut iat_cursor = iat_rva;
                loop {
                    let entry = u32_at_rva(&sections, &r, "import lookup table entry", ilt_cursor)?;
                    if entry == 0 {
                        break;
                    }

                    let symbol = if entry & IMPORT_BY_ORDINAL != 0 {
                        Symbol::Ordinal((entry & 0xffff) as u16)
                    } else {
                        // The top bit is clear, so `entry` is itself the RVA
                        // of a 2-byte hint followed by the NUL-terminated
                        // name; the hint is not read, only skipped.
                        let name_rva = entry.checked_add(2).ok_or(PeError::RvaOverflow {
                            what: "import hint/name",
                            rva: entry,
                        })?;
                        Symbol::Name(read_cstr_at_rva(
                            &sections,
                            &r,
                            "import symbol name",
                            name_rva,
                        )?)
                    };

                    // `iat_cursor` is never read through a bounds-checked
                    // helper the way `ilt_cursor` is (`u32_at_rva`, every
                    // iteration, above): when the ILT and IAT are separate
                    // arrays -- the ordinary case, `ilt_rva != 0` -- nothing
                    // in this walk ever dereferences the IAT at all, only
                    // advances a cursor into it. So a crafted `FirstThunk`
                    // could otherwise place `Import::iat_rva` anywhere a
                    // `u32` can name, unbounded by any section, with only
                    // `checked_add` below guarding against overflowing past
                    // `u32::MAX` -- not against landing outside the image at
                    // all. This is the same site Task 13's `Image::bind_imports`
                    // (`image.rs`) indexes the mapping at, exactly as
                    // `Relocation::rva` is for `Image::relocate`, so it gets
                    // the same membership check.
                    let (_, remaining) = rva_to_file_bounded_in(&sections, iat_cursor)?;
                    if remaining < 4 {
                        return Err(PeError::RvaSpansSectionEnd {
                            what: "import address table slot",
                            rva: iat_cursor,
                            need: 4,
                            remaining,
                        });
                    }
                    imports.push(Import {
                        library: library.clone(),
                        symbol,
                        iat_rva: iat_cursor,
                    });

                    ilt_cursor = ilt_cursor.checked_add(4).ok_or(PeError::RvaOverflow {
                        what: "import lookup table cursor",
                        rva: ilt_cursor,
                    })?;
                    iat_cursor = iat_cursor.checked_add(4).ok_or(PeError::RvaOverflow {
                        what: "import address table cursor",
                        rva: iat_cursor,
                    })?;
                }

                desc_rva = desc_rva.checked_add(20).ok_or(PeError::RvaOverflow {
                    what: "import descriptor advance",
                    rva: desc_rva,
                })?;
            }
        }

        // Export directory: unlike imports (a null-terminated walk with no
        // length field at all) the export tables are true fixed-length
        // arrays -- NumberOfFunctions and NumberOfNames are straight counts
        // from the header. Neither is trusted by pre-allocating a `Vec` from
        // it (an attacker-chosen NumberOfFunctions near u32::MAX would be a
        // multi-gigabyte allocation before a single byte is read); every
        // element is read one at a time through a bounds-checked RVA, so a
        // header that overstates either count fails at the first read past
        // the covering section's raw end.
        //
        // `+12 Name` (the RVA of the module's own name string) used to go
        // unread here -- nothing in this crate's original scope (binding
        // imports by name, finding an export's address by name) needed the
        // exporting module's own name string. `PeImage::export_name` now
        // reads it: see that field's own doc comment for the caller that
        // needs it and why no other source will do.
        let export_dir_rva = r.u32("export directory rva", dirs + DIR_EXPORT * 8)?;
        let export_dir_size = r.u32("export directory size", dirs + DIR_EXPORT * 8 + 4)?;
        let mut exports = Vec::new();
        let mut export_table = Vec::new();
        let mut export_base = None;
        let mut export_name = None;
        if export_dir_rva != 0 && export_dir_size != 0 {
            let field = |offset: u32, what: &'static str| -> Result<u32, PeError> {
                let rva = export_dir_rva
                    .checked_add(offset)
                    .ok_or(PeError::RvaOverflow { what, rva: export_dir_rva })?;
                u32_at_rva(&sections, &r, what, rva)
            };
            let base = field(16, "export base")?;
            let number_of_functions = field(20, "export number of functions")?;
            let number_of_names = field(24, "export number of names")?;
            let addr_of_functions = field(28, "export address of functions")?;
            let addr_of_names = field(32, "export address of names")?;
            let addr_of_name_ordinals = field(36, "export address of name ordinals")?;
            export_base = Some(base);

            // The 4-byte `Name` field itself is read the same strict way as
            // every sibling field above (`base`, `number_of_functions`, ...)
            // -- a directory too short to hold it is exactly as malformed as
            // one too short to hold `Base`. What it *points to* is read
            // leniently: `.ok()`, not `?`. A well-formed PE's `Name` always
            // resolves, but plenty of this file's own synthetic export-table
            // fixtures build a directory that only ever populates the fields
            // `export_rva`/`export_rva_by_ordinal` need and leave `Name` at
            // its zeroed default -- RVA 0, unmapped in every one of them.
            // Hard-erroring on that would fail parsing for a field nothing
            // in those tests is exercising; `None` is the honest answer for
            // "this image has an export directory but no readable name",
            // and callers that need one (`init_rva`) already treat `None`
            // as "no name to build a candidate from," not as a load failure.
            let name_field_rva = field(12, "export directory name")?;
            export_name = read_cstr_at_rva(&sections, &r, "export directory name", name_field_rva).ok();

            // The end of the export directory's own byte range: a function
            // RVA landing inside [export_dir_rva, dir_end) is a forwarder
            // string, not code. Computed once, outside the loop below, so
            // an overflowing Size is refused up front rather than per entry.
            let dir_end = export_dir_rva
                .checked_add(export_dir_size)
                .ok_or(PeError::RvaOverflow {
                    what: "export directory range",
                    rva: export_dir_rva,
                })?;

            let mut functions = Vec::new();
            let mut cursor = addr_of_functions;
            for _ in 0..number_of_functions {
                let rva = u32_at_rva(&sections, &r, "export address table entry", cursor)?;
                functions.push(rva);
                cursor = cursor.checked_add(4).ok_or(PeError::RvaOverflow {
                    what: "export address table cursor",
                    rva: cursor,
                })?;
            }

            // The ordinal-indexed table: every slot in `functions`,
            // forwarder-detected once here rather than per name below, so
            // an ordinal-only export (no entry in the name loop at all)
            // gets exactly the same treatment as a named one. `exports`
            // still only grows for named entries -- this is a second,
            // complete view of the same data, not a replacement for it.
            for &func_rva in &functions {
                let address = if func_rva >= export_dir_rva && func_rva < dir_end {
                    ExportAddress::Forwarded(read_cstr_at_rva(
                        &sections,
                        &r,
                        "export forwarder string",
                        func_rva,
                    )?)
                } else {
                    ExportAddress::Rva(func_rva)
                };
                export_table.push(address);
            }

            let mut names_cursor = addr_of_names;
            let mut ordinals_cursor = addr_of_name_ordinals;
            for _ in 0..number_of_names {
                let name_rva =
                    u32_at_rva(&sections, &r, "export name pointer table entry", names_cursor)?;
                let name = read_cstr_at_rva(&sections, &r, "export name", name_rva)?;
                let ordinal =
                    u16_at_rva(&sections, &r, "export name ordinal table entry", ordinals_cursor)?;

                // `ordinal` is a plain 0-based index into `export_table` --
                // see `PeImage::export_base` for why it is never combined
                // with `Base` here. It was read from a perfectly valid
                // location, so an out-of-range value here is a data
                // inconsistency between two arrays this loader has already
                // finished reading, not a truncated read.
                let address = export_table.get(usize::from(ordinal)).cloned().ok_or(
                    PeError::ExportOrdinalOutOfRange {
                        name: name.clone(),
                        ordinal,
                        functions: number_of_functions,
                    },
                )?;

                exports.push(Export { name, address });

                names_cursor = names_cursor.checked_add(4).ok_or(PeError::RvaOverflow {
                    what: "export name pointer table cursor",
                    rva: names_cursor,
                })?;
                ordinals_cursor = ordinals_cursor.checked_add(2).ok_or(PeError::RvaOverflow {
                    what: "export name ordinal table cursor",
                    rva: ordinals_cursor,
                })?;
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
            imports,
            exports,
            export_table,
            export_base,
            export_name,
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

    /// The RVA of the function a name exports, by linear search over
    /// `exports`.
    ///
    /// `None` covers two different cases identically: no export has this
    /// name, or the export does exist but is a forwarder rather than code --
    /// there is no function RVA to hand back for one of those. Callers that
    /// need to tell the two apart, or that want a forwarder's target
    /// string, should search `exports` directly and match on
    /// `ExportAddress::Forwarded`.
    #[must_use]
    pub fn export_rva(&self, name: &str) -> Option<u32> {
        self.exports.iter().find_map(|e| {
            if e.name != name {
                return None;
            }
            match &e.address {
                ExportAddress::Rva(rva) => Some(*rva),
                ExportAddress::Forwarded(_) => None,
            }
        })
    }

    /// The same lookup as `export_rva`, ASCII case-insensitive.
    ///
    /// Exists for `_init__<dll>`, Galacticomm's init-routine convention
    /// carried over from the 16-bit side: NE modules spell it upper-case
    /// (`_INIT__WCCMMUD`), this PE format lower-cases it (`_init__lunatix`,
    /// `_init__rcirose` -- both measured, see `crate::m32::Module::init`'s
    /// doc comment). `export_rva` itself stays exact-case on purpose --
    /// every other caller (import binding, the `tests/pe.rs` fixtures) is
    /// matching a name it already knows the exact spelling of, and a
    /// case-blind default there would let a real spelling mismatch through
    /// silently. Only the init lookup has to survive two different
    /// toolchains' casing conventions, so only it gets the case-insensitive
    /// path.
    #[must_use]
    pub fn export_rva_ignore_ascii_case(&self, name: &str) -> Option<u32> {
        self.exports.iter().find_map(|e| {
            if !e.name.eq_ignore_ascii_case(name) {
                return None;
            }
            match &e.address {
                ExportAddress::Rva(rva) => Some(*rva),
                ExportAddress::Forwarded(_) => None,
            }
        })
    }

    /// The RVA of the function at *public* exported ordinal `ordinal`, by
    /// direct indexing into `export_table` -- O(1), unlike `export_rva`'s
    /// linear search by name.
    ///
    /// Unlike `export_rva`, this correctly serves an ordinal-only export
    /// (no entry in the name pointer table at all -- see `export_table`'s
    /// own doc comment for why those are not silently absent here the way
    /// they are from `exports`). Used by [`PeImage::init_rva`] as the last
    /// resort when no named `_init__<dll>` export exists -- see that
    /// method's own doc comment for why ordinal 1 is a fallback and not,
    /// as this crate believed until it was measured against `RCIROSE.DLL`,
    /// Galacticomm's actual convention.
    ///
    /// `Base` is subtracted here, deliberately the opposite of what
    /// `export_base`'s own doc comment warns `export_rva`'s internal lookup
    /// must never do: `ordinal` is a caller-supplied *public* ordinal (what
    /// `GetProcAddress` takes), and `export_table` is indexed 0-based, so
    /// the adjustment belongs here, not there. See `export_base`'s doc
    /// comment for the full contrast.
    ///
    /// `None` if the image has no export directory, if `ordinal < Base`, if
    /// the `Base`-adjusted index is past the end of `export_table`, or if
    /// the export at that ordinal is a forwarder rather than code --
    /// mirroring `export_rva`'s own `None` cases.
    #[must_use]
    pub fn export_rva_by_ordinal(&self, ordinal: u16) -> Option<u32> {
        let base = self.export_base?;
        let index = u32::from(ordinal).checked_sub(base)?;
        match self.export_table.get(index as usize)? {
            ExportAddress::Rva(rva) => Some(*rva),
            ExportAddress::Forwarded(_) => None,
        }
    }

    /// The module's real init routine -- Galacticomm's `register_module`
    /// caller -- resolved by **name** first, exported ordinal 1 only as a
    /// fallback.
    ///
    /// This crate used to say "exported ordinal 1" *was* the convention,
    /// on the strength of one module: `LUNATIX.DLL`'s ordinal 1 is
    /// `_init__lunatix`. Measured today against a second module,
    /// `RCIROSE.DLL` (935 exports), that agreement turned out to be
    /// coincidence, not convention: its ordinal 1 is `_his_mods`, gameplay
    /// code, while the real init routine, `_init__rcirose`, sits at
    /// ordinal 352. Two-for-two on modules that both happened to be linked
    /// with init first is not evidence of a rule -- it is evidence that
    /// nobody had yet linked one the other way. `_init__<dll>` **by name**
    /// is what both modules actually agree on: `LUNATIX.DLL` exports
    /// `_init__lunatix`, `RCIROSE.DLL` exports `_init__rcirose`, and both
    /// names are built from [`PeImage::export_name`] -- the module's own
    /// linked name (`lunatix.DLL`, `rcirose.DLL`), not a filesystem path
    /// (`Wg32::load` never receives one to begin with -- see
    /// `export_name`'s own doc comment). The `.dll`/`.DLL` suffix is
    /// stripped case-insensitively before building the candidate, and the
    /// candidate is matched against the export table case-insensitively
    /// too (`export_rva_ignore_ascii_case`) -- measured PE exports
    /// lower-case the whole name (`_init__lunatix`, `_init__rcirose`), but
    /// nothing about the format guarantees that.
    ///
    /// Ordinal 1 is tried only when the name lookup finds nothing --
    /// **never** preferred once a name resolves, even if ordinal 1 also
    /// happens to exist. That matters beyond `RCIROSE.DLL`'s PE build: its
    /// *NE* sibling's ordinal 1 is `BCC286_EXE`, Borland C++ 286's crt0
    /// startup stub, not an entry point at all (`m16::ne::Module::init`
    /// has the full measurement) -- a strong sign that "ordinal 1" was
    /// never a Worldgroup convention so much as where a C runtime's own
    /// startup code happens to land when nothing else claims the slot.
    ///
    /// `None` exactly when both the name lookup and the ordinal-1 fallback
    /// come up empty -- no export directory, no `_init__<dll>` export, and
    /// no export at ordinal 1 either.
    #[must_use]
    pub fn init_rva(&self) -> Option<u32> {
        if let Some(name) = &self.export_name {
            let stem = if name.len() >= 4 && name[name.len() - 4..].eq_ignore_ascii_case(".dll") {
                &name[..name.len() - 4]
            } else {
                name.as_str()
            };
            let candidate = format!("_init__{stem}");
            if let Some(rva) = self.export_rva_ignore_ascii_case(&candidate) {
                return Some(rva);
            }
        }
        self.export_rva_by_ordinal(1)
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
