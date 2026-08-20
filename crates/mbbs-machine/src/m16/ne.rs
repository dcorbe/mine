//! The NE (New Executable) loader: a real module, in real segments.
//!
//! This is the format Galacticomm modules ship in. Despite the "for MS Windows
//! 3.00" marker a server module is not a Windows binary -- it targets the Phar
//! Lap 286|DOS-Extender and imports an OS/2 1.x-style subset from
//! `DOSCALLS`/`PHAPI` -- but the container is unchanged, and so is everything
//! here.
//!
//! Everything about the format is from the spec in
//! `archive/tooling/reference-documents/Windows_3.0_16-bit_NE_Executable_Format.txt`.
//! Everything about what a *Galacticomm* module actually contains is measured
//! from `re/WCCMMUD.DLL` and recorded in `docs/plans/2026-08-04-ne-loader.md`;
//! `re/nefmt.py` reads the same structures out of the same file and is the
//! cross-check.
//!
//! # Three kinds of import
//!
//! The obvious model -- every import is a routine, so every import gets a thunk
//! -- is wrong, and wrong for a fifth of them. Of MajorMUD's 188 distinct
//! `MAJORBBS` ordinals, 38 are never far-called: they appear as `SEGMENT` and
//! additive `OFFSET` fixups, which is the module taking a host global's
//! `selector:offset` and reading or writing it directly. `usrnum` alone is
//! addressed at 1,285 sites and there is no call anywhere to intercept.
//!
//! So [`Import`] has three arms. A routine gets a thunk and comes back as
//! [`Exit::Call`](crate::m16::Exit::Call); a datum gets a far pointer into memory the
//! host owns, and the module reads and writes it with the host none the wiser;
//! and an absolute is not an address at all -- its value goes straight into an
//! instruction's immediate field, which is how `DOSCALLS.135` tells a module how
//! far to shift a 64 KiB count to reach the next selector.
//!
//! # Parse, then map
//!
//! Nothing is allocated until the whole file has parsed. A malformed module is
//! then an error rather than a half-built [`Machine`], which matters because a
//! `Machine` that is half a module is indistinguishable from one that is all of
//! a smaller module.

use std::collections::HashMap;
use std::fmt;
use std::io;

use crate::m16::seg::Segment;
use crate::m16::{FarPtr, MAX_THUNKS, Machine};
pub use crate::module::{ImportSite, Symbol};

/// A 16-bit segment's size when the field holding it reads zero. Both `length`
/// and `minalloc` spell 64 KiB this way, since the field is a word and 64 KiB
/// does not fit in one.
const SIXTY_FOUR_K: usize = 0x1_0000;

/// Where `e_lfanew` lives in the MZ header that every NE file starts with.
const E_LFANEW: usize = 0x3c;

/// Bytes of NE header, which every header field must fit inside.
const HEADER_BYTES: usize = 0x40;

/// Relocation source types, in the record's first byte.
const SRC_LOBYTE: u8 = 0;
const SRC_SEGMENT: u8 = 2;
const SRC_FAR_ADDR: u8 = 3;
const SRC_OFFSET: u8 = 5;

/// Relocation target types, in the low two bits of the record's flags byte.
const TGT_MASK: u8 = 0x03;
const TGT_INTERNALREF: u8 = 0;
const TGT_IMPORTORDINAL: u8 = 1;
const TGT_IMPORTNAME: u8 = 2;
const TGT_OSFIXUP: u8 = 3;

/// Flags bit meaning "this record names one site, not a chain".
const TGT_ADDITIVE: u8 = 0x04;

/// Segment table flag bits.
const SEG_DATA: u16 = 0x0001;
const SEG_MOVEABLE: u16 = 0x0010;
const SEG_RELOCINFO: u16 = 0x0100;

/// The `segment` byte of an INTERNALREF target, when the target is moveable.
const INTERNALREF_MOVEABLE: u8 = 0xff;

/// The entry-table bundle indicator for moveable entries.
const BUNDLE_MOVEABLE: u8 = 0xff;

/// `INT 3Fh`, little-endian, as it sits between a moveable entry's flags and
/// its segment number. The real loader patched over this to reach the segment
/// once it had been placed; this host places every segment at a fixed address
/// and never needs to, so it is read only as the format marker it also is.
const MOVEABLE_THUNK: u16 = 0x3fcd;

/// End of a relocation source chain.
const CHAIN_END: u16 = 0xffff;

/// Why a module could not be read or loaded.
///
/// Every variant is something a *file* can be, not something the host can do
/// wrong, so none of them is a panic. A module is untrusted input in the same
/// sense module memory already is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NeError {
    /// No `MZ` at the front, or no `NE` where `e_lfanew` points.
    NotNe,

    /// A structure the header points at runs past the end of the file.
    Truncated {
        what: &'static str,
        at: usize,
        need: usize,
        len: usize,
    },

    /// A segment's allocation is larger than a 16-bit segment can address.
    SegmentTooLarge { segment: u16, size: usize },

    /// A relocation names a segment number the segment table does not have.
    NoSuchSegment { segment: u16 },

    /// A module-reference index outside the module reference table.
    NoSuchModule { index: u16 },

    /// A relocation site is not inside the segment it belongs to.
    SiteOutOfBounds {
        segment: u16,
        offset: usize,
        size: usize,
    },

    /// A relocation source chain that does not end, or ends outside its
    /// segment. A file can be shaped this way; a loader that followed it would
    /// not stop.
    ChainRunsAway { segment: u16, offset: u16 },

    /// A structure whose bytes do not match the format.
    ///
    /// Replaces a `Moveable` variant that meant "this loader refuses moveable
    /// segments", which it no longer does. That variant's own doc said no
    /// Galacticomm module measured so far had one; 148 of the 254 module
    /// binaries under `archive/modules/dlls` do, and every one of them was
    /// unloadable because of it.
    Malformed {
        what: &'static str,
        why: String,
    },

    /// A relocation source type the format does not define.
    UnknownSource { source: u8 },

    /// This load's own distinct imports would need a thunk index the
    /// machine has none left of. `needed` is the machine-wide total --
    /// every thunk already spoken for by an earlier load into this same
    /// [`Machine`], plus this one's own -- not merely this module's own
    /// import count, since the index space this module is drawing from is
    /// the machine's, not its own (see [`Thunks`]'s own doc comment).
    TooManyImports { needed: usize, limit: u16 },

    /// The header names an automatic data segment that does not exist.
    NoAutoData { segment: u16 },

    /// The host resolved a symbol to an [`Import::Absolute`], and a fixup for
    /// it wants a selector. A constant has no selector, and writing one of its
    /// halves as an address would be a wrong address rather than an error.
    AbsoluteNeedsAnAddress { segment: u16, offset: u16 },

    /// A segment could not be mapped. The errno rather than the `io::Error`,
    /// because a parse result is worth comparing and an `io::Error` is not.
    Mapping { segment: u16, errno: i32 },
}

impl fmt::Display for NeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotNe => write!(f, "not an NE file"),
            Self::Truncated {
                what,
                at,
                need,
                len,
            } => write!(
                f,
                "{what} needs {need} bytes at {at:#x}, but the file is {len} bytes"
            ),
            Self::SegmentTooLarge { segment, size } => write!(
                f,
                "segment {segment} wants {size} bytes, more than a 16-bit segment can address"
            ),
            Self::NoSuchSegment { segment } => write!(f, "no segment {segment} in this module"),
            Self::NoSuchModule { index } => {
                write!(f, "no module reference {index} in this module")
            }
            Self::SiteOutOfBounds {
                segment,
                offset,
                size,
            } => write!(
                f,
                "a relocation site at {offset:#x} is outside segment {segment}, which is {size} bytes"
            ),
            Self::ChainRunsAway { segment, offset } => write!(
                f,
                "the relocation chain at {offset:#06x} in segment {segment} does not end"
            ),
            Self::Malformed { what, why } => write!(f, "{what}: {why}"),
            Self::UnknownSource { source } => {
                write!(
                    f,
                    "relocation source type {source} is not one the format defines"
                )
            }
            Self::TooManyImports { needed, limit } => write!(
                f,
                "this machine would need {needed} thunks across every module loaded into it, \
                 and it has {limit}"
            ),
            Self::NoAutoData { segment } => {
                write!(
                    f,
                    "the automatic data segment is {segment}, which does not exist"
                )
            }
            Self::AbsoluteNeedsAnAddress { segment, offset } => write!(
                f,
                "segment {segment}:{offset:#06x} wants an address, and the host \
                 resolved that symbol to a constant"
            ),
            Self::Mapping { segment, errno } => write!(
                f,
                "could not map segment {segment}: {}",
                io::Error::from_raw_os_error(*errno)
            ),
        }
    }
}

impl std::error::Error for NeError {}

impl From<NeError> for io::Error {
    fn from(e: NeError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }
}

/// Bounds-checked reads out of the file.
///
/// Every offset in an NE header is attacker-controlled in the same sense a
/// module's far pointers are, so there is no read here that is not checked.
struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn need(&self, what: &'static str, at: usize, need: usize) -> Result<&'a [u8], NeError> {
        let end = at.checked_add(need).ok_or(NeError::Truncated {
            what,
            at,
            need,
            len: self.data.len(),
        })?;
        self.data.get(at..end).ok_or(NeError::Truncated {
            what,
            at,
            need,
            len: self.data.len(),
        })
    }

    fn u8(&self, what: &'static str, at: usize) -> Result<u8, NeError> {
        Ok(self.need(what, at, 1)?[0])
    }

    fn u16(&self, what: &'static str, at: usize) -> Result<u16, NeError> {
        let b = self.need(what, at, 2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&self, what: &'static str, at: usize) -> Result<u32, NeError> {
        let b = self.need(what, at, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A length-prefixed, un-terminated, case-sensitive name string, and the
    /// number of bytes it occupied.
    ///
    /// Decoded as latin1 rather than UTF-8: these are 1990 DOS-toolchain
    /// strings, so a byte is a character and the decode cannot fail. Treating
    /// them as UTF-8 would introduce an error case that says nothing useful.
    fn pstring(&self, what: &'static str, at: usize) -> Result<(String, usize), NeError> {
        let len = usize::from(self.u8(what, at)?);
        let bytes = self.need(what, at + 1, len)?;
        Ok((bytes.iter().map(|&b| b as char).collect(), 1 + len))
    }
}

/// Where a relocation's value goes, and how wide it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// One byte: the low half of the offset.
    LoByte,
    /// One word: the selector.
    Segment,
    /// One word: the offset.
    Offset,
    /// Two words: the offset, then the selector.
    FarAddr,
}

impl Source {
    /// Bytes a site of this kind occupies.
    pub fn width(self) -> usize {
        match self {
            Self::LoByte => 1,
            Self::Segment | Self::Offset => 2,
            Self::FarAddr => 4,
        }
    }
}

/// What a relocation resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Another segment of this same module.
    Internal { segment: u8, offset: u16 },

    /// A symbol in another module, by ordinal or by name.
    Import { module: u16, symbol: Symbol },

    /// A floating-point emulator fixup, which this loader carries but does not
    /// apply.
    ///
    /// The linker has already written the emulator interrupt at the site; a real
    /// loader rewrites it to native 8087 instructions when a coprocessor is
    /// present. Leaving it alone keeps the emulator path, and the emulator is
    /// not implemented -- so a module that actually computes a float will fault
    /// on the interrupt and name itself, which is the answer. Refusing the file
    /// at load time instead costs 210 segments to avoid 50 sites:
    /// `MAJORBBS-mbbstd.EXE` has 50 of these among 10,234 relocations, kinds 4-6
    /// (`FIERQQ`/`FIDRQQ`/`FIWRQQ`), and none of the FSD or screen-library code
    /// touches them.
    OsFixup { kind: u16 },
}

/// One fixup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relocation {
    pub source: Source,
    pub target: Target,

    /// Set when the record names exactly one site rather than the head of a
    /// chain. That is what the flag *means*; whether the value is also *added*
    /// to what is already there depends on the source type, because adding to a
    /// selector is meaningless.
    pub additive: bool,

    /// Offset of the site, or of the head of the chain, within the segment.
    pub offset: u16,
}

/// One row of the segment table, plus the relocations that follow its data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentEntry {
    /// Where the segment's bytes are in the file. Empty when the segment has no
    /// file data at all, which is how a pure-BSS segment is spelled.
    pub file: std::ops::Range<usize>,
    pub flags: u16,
    /// Bytes to allocate, which is never less than the bytes in the file.
    pub alloc: usize,
    pub relocations: Vec<Relocation>,
}

impl SegmentEntry {
    /// Whether this segment holds data rather than code.
    pub fn is_data(&self) -> bool {
        self.flags & SEG_DATA != 0
    }
}

/// An exported entry point, as the entry table gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryPoint {
    /// 1-based segment number.
    pub segment: u8,
    pub offset: u16,
    pub exported: bool,
}

/// An NE file, parsed. Nothing here is mapped, and nothing here borrows the
/// file it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeImage {
    /// The header's flag word. `0x8000` is a library, `0x0001` single-data.
    pub flags: u16,
    /// Executable type, as the header reports it rather than as we assume.
    pub exetype: u8,
    /// 1-based segment number of `DGROUP`, or zero for `NOAUTODATA`.
    pub autodata: u16,
    /// Logical sector alignment, as a shift count.
    pub align: u16,
    pub segments: Vec<SegmentEntry>,
    /// Imported module names, indexed 1-based by relocation records.
    pub modules: Vec<String>,
    /// Entry points by ordinal: ordinal 1 is index 0. `None` where the linker
    /// skipped an ordinal.
    pub entries: Vec<Option<EntryPoint>>,
    /// This module's own declared name -- the resident name table's own
    /// first entry, which every other reader of this table drops (see this
    /// field's own construction site in [`NeImage::parse`]). What another
    /// module's import table names this one by.
    pub own_name: String,
    /// Exported names from both name tables, mapped to their ordinals.
    pub names: HashMap<String, u16>,
}

impl NeImage {
    /// Read an NE file.
    ///
    /// # Errors
    ///
    /// If it is not an NE file, or any structure it declares runs past the end
    /// of it.
    pub fn parse(data: &[u8]) -> Result<Self, NeError> {
        let r = Reader { data };

        if r.need("MZ header", 0, 2)? != b"MZ" {
            return Err(NeError::NotNe);
        }
        let ne = r.u32("e_lfanew", E_LFANEW)? as usize;
        if r.need("NE header", ne, HEADER_BYTES)?[..2] != *b"NE" {
            return Err(NeError::NotNe);
        }

        // Every header field is a fixed offset into the 0x40 bytes just checked,
        // so these reads cannot fail. Going through the reader anyway keeps one
        // rule rather than two.
        let flags = r.u16("flags", ne + 0x0c)?;
        let autodata = r.u16("autodata", ne + 0x0e)?;
        let segment_count = r.u16("segment count", ne + 0x1c)?;
        let module_count = r.u16("module count", ne + 0x1e)?;
        let segtab = ne + r.u16("segment table offset", ne + 0x22)? as usize;
        let restab = ne + r.u16("resident name table offset", ne + 0x26)? as usize;
        let modtab = ne + r.u16("module table offset", ne + 0x28)? as usize;
        let imptab = ne + r.u16("imported name table offset", ne + 0x2a)? as usize;
        // The one table offset that is relative to the file rather than to the
        // header. Reading it as header-relative lands 0x90 bytes into a string.
        let nrtab = r.u32("non-resident name table offset", ne + 0x2c)? as usize;
        let entrytab = ne + r.u16("entry table offset", ne + 0x04)? as usize;
        let align = match r.u16("sector alignment", ne + 0x32)? {
            0 => 9,
            n => n,
        };
        let exetype = r.u8("executable type", ne + 0x36)?;

        // Module references are offsets into the imported names table.
        let mut modules = Vec::with_capacity(usize::from(module_count));
        for i in 0..usize::from(module_count) {
            let rel = r.u16("module reference", modtab + i * 2)? as usize;
            modules.push(r.pstring("module name", imptab + rel)?.0);
        }

        // Before the segments, because a segment's relocations can name a
        // moveable target by entry-table ordinal and `parse_relocation`
        // resolves that here rather than deferring it -- which is what keeps
        // `Target` and every fixup below unchanged.
        let entries = parse_entry_table(&r, entrytab)?;

        let mut segments = Vec::with_capacity(usize::from(segment_count));
        for i in 0..usize::from(segment_count) {
            segments.push(parse_segment(
                &r,
                segtab + i * 8,
                align,
                imptab,
                (i + 1) as u16,
                &entries,
            )?);
        }

        // The resident name table's own first entry -- what `collect_names`
        // below drops as the "not an export" leading string, because that
        // reading is only true of the *export* map it is building. It is
        // also the one place this format ever states its own name: the
        // string another module's own import table has to match to reach
        // this one (`WCCMMPLS.DLL`'s own resident table leads with
        // `WCCMMPLS`, and `WCCMMUD.DLL`'s leads with `WCCMMUD` -- exactly the
        // spelling `WCCMMPLS.DLL`'s import records name it by; measured, not
        // assumed). Read here, once, rather than recovered from `collect_names`
        // after the fact, since that function's contract is "drop the first
        // entry of every table it is given" and has no reason to hand it back.
        let own_name = r.pstring("resident name table", restab)?.0;

        let mut names = HashMap::new();
        collect_names(&r, restab, &mut names)?;
        collect_names(&r, nrtab, &mut names)?;

        Ok(Self {
            flags,
            exetype,
            autodata,
            align,
            segments,
            modules,
            entries,
            own_name,
            names,
        })
    }

    /// The module reference index `n` names, 1-based as relocations give it.
    ///
    /// Public because a host reads the relocations too -- to work out which
    /// imports are data rather than routines -- and the 1-based indexing is not
    /// a thing to re-implement in two places.
    pub fn module_name(&self, n: u16) -> Result<&str, NeError> {
        self.modules
            .get(usize::from(n).wrapping_sub(1))
            .map(String::as_str)
            .ok_or(NeError::NoSuchModule { index: n })
    }
}

/// One segment table row, and the relocation records after its data.
fn parse_segment(
    r: &Reader<'_>,
    at: usize,
    align: u16,
    imptab: usize,
    number: u16,
    entries: &[Option<EntryPoint>],
) -> Result<SegmentEntry, NeError> {
    let sector = r.u16("segment table", at)? as usize;
    let length = r.u16("segment table", at + 2)?;
    let flags = r.u16("segment table", at + 4)?;
    let minalloc = r.u16("segment table", at + 6)?;

    // `SEG_MOVEABLE` is deliberately NOT refused. It told the real memory
    // manager that this segment could be relocated and reached through a
    // handle; this host maps every segment once, at a fixed address, with its
    // own LDT descriptor, and never moves it. So the flag describes a facility
    // that does not exist here rather than one this loader lacks, and a
    // moveable segment loads exactly as a fixed one does.
    //
    // What would break is a module that moves or discards a segment through
    // the handle-based memory API -- and it has no route to: the only way it
    // names a segment is a selector this loader wrote, which always describes
    // the same mapping.

    // A zero sector means the segment has no file data. Otherwise a zero length
    // means 64 KiB, because the field is a word and 64 KiB does not fit.
    let file_len = match (sector, length) {
        (0, _) => 0,
        (_, 0) => SIXTY_FOUR_K,
        (_, n) => usize::from(n),
    };
    let start = sector << align;
    let file = if file_len == 0 {
        0..0
    } else {
        r.need("segment data", start, file_len)?;
        start..start + file_len
    };

    let alloc = match minalloc {
        0 => SIXTY_FOUR_K,
        n => usize::from(n),
    }
    .max(file_len);
    if alloc > SIXTY_FOUR_K {
        return Err(NeError::SegmentTooLarge {
            segment: number,
            size: alloc,
        });
    }

    let mut relocations = Vec::new();
    if flags & SEG_RELOCINFO != 0 && file_len != 0 {
        let at = start + file_len;
        let count = r.u16("relocation count", at)?;
        relocations.reserve(usize::from(count));
        for i in 0..usize::from(count) {
            relocations.push(parse_relocation(r, at + 2 + i * 8, imptab, entries)?);
        }
    }

    Ok(SegmentEntry {
        file,
        flags,
        alloc,
        relocations,
    })
}

/// One 8-byte relocation record.
fn parse_relocation(
    r: &Reader<'_>,
    at: usize,
    imptab: usize,
    entries: &[Option<EntryPoint>],
) -> Result<Relocation, NeError> {
    let source = match r.u8("relocation", at)? {
        SRC_LOBYTE => Source::LoByte,
        SRC_SEGMENT => Source::Segment,
        SRC_FAR_ADDR => Source::FarAddr,
        SRC_OFFSET => Source::Offset,
        source => return Err(NeError::UnknownSource { source }),
    };
    let flags = r.u8("relocation", at + 1)?;
    let offset = r.u16("relocation", at + 2)?;
    let lo = r.u16("relocation", at + 4)?;
    let hi = r.u16("relocation", at + 6)?;

    let target = match flags & TGT_MASK {
        TGT_INTERNALREF => {
            // The low word is a segment number in its low byte; 0xFF there means
            // the target is moveable and `hi` is an entry-table ordinal instead.
            let segment = lo as u8;
            if segment == INTERNALREF_MOVEABLE {
                // `hi` is an entry-table ordinal, 1-based, not an offset. The
                // entry it names carries the segment and offset the real
                // loader would have patched in once it placed the segment, so
                // resolving it here yields an ordinary `Target::Internal` and
                // nothing downstream has to know the difference.
                //
                // **No module in `archive/modules/dlls` uses this form.**
                // Measured: 95,436 `TGT_INTERNALREF` records across 62 of the
                // 209 NE modules, and not one has `0xff` in the segment byte.
                // So unlike the moveable *segment* flag and the moveable
                // *entry bundle* -- which 148 modules each have, and which are
                // what actually unblocked them -- this path is exercised only
                // by `tests/ne.rs`'s synthetic module.
                //
                // Implemented anyway, because it is part of the format and
                // refusing it would leave the same wall standing for a module
                // outside this corpus. But said out loud, because the variant
                // this replaced carried a comment claiming no Galacticomm
                // module had moveable segments, and 148 of them do.
                let ordinal = hi;
                let entry = usize::from(ordinal)
                    .checked_sub(1)
                    .and_then(|i| entries.get(i))
                    .copied()
                    .flatten()
                    .ok_or_else(|| NeError::Malformed {
                        what: "moveable relocation",
                        why: format!(
                            "names entry-table ordinal {ordinal}, which this \
                             module's entry table does not define ({} ordinals)",
                            entries.len()
                        ),
                    })?;
                return Ok(Relocation {
                    source,
                    target: Target::Internal {
                        segment: entry.segment,
                        offset: entry.offset,
                    },
                    additive: flags & TGT_ADDITIVE != 0,
                    offset,
                });
            }
            Target::Internal {
                segment,
                offset: hi,
            }
        }
        TGT_IMPORTORDINAL => Target::Import {
            module: lo,
            symbol: Symbol::Ordinal(hi),
        },
        TGT_IMPORTNAME => Target::Import {
            module: lo,
            symbol: Symbol::Name(r.pstring("imported name", imptab + usize::from(hi))?.0),
        },
        TGT_OSFIXUP => Target::OsFixup { kind: lo },
        _ => unreachable!("TGT_MASK is two bits and all four are handled"),
    };

    Ok(Relocation {
        source,
        target,
        additive: flags & TGT_ADDITIVE != 0,
        offset,
    })
}

/// The entry table: bundles of entry points, indexed by ordinal from 1.
fn parse_entry_table(r: &Reader<'_>, at: usize) -> Result<Vec<Option<EntryPoint>>, NeError> {
    let mut entries = Vec::new();
    let mut at = at;

    loop {
        let count = usize::from(r.u8("entry table", at)?);
        if count == 0 {
            return Ok(entries);
        }
        let indicator = r.u8("entry table", at + 1)?;
        at += 2;

        match indicator {
            // The linker skipping ordinals. No entry data follows.
            0 => entries.extend(std::iter::repeat_n(None, count)),
            // A moveable bundle's entries are six bytes, not three: the
            // segment number is carried per entry rather than once in the
            // indicator, with the real loader's `INT 3Fh` thunk between.
            //
            // Measured on `ISVADV__Advbdynt/_SETUP.DLL`, whose first moveable
            // bundle reads `03 cd 3f 01 24 00` -- flags `03`, the two bytes
            // `cd 3f` (`INT 3Fh`), segment `01`, offset `0024`.
            //
            // The resulting `EntryPoint` is the same shape a fixed bundle
            // produces, which is the point: nothing downstream needs to know
            // which kind of bundle an ordinal came from.
            BUNDLE_MOVEABLE => {
                for _ in 0..count {
                    let flags = r.u8("entry table", at)?;
                    // Checked rather than skipped: these two bytes are the
                    // format's own marker, so a bundle without them is a
                    // malformed file and not a moveable one, and saying which
                    // is the difference between a useful refusal and a
                    // confusing one.
                    let thunk = r.u16("entry table", at + 1)?;
                    if thunk != MOVEABLE_THUNK {
                        return Err(NeError::Malformed {
                            what: "moveable entry bundle",
                            why: format!(
                                "expected the INT 3Fh thunk {MOVEABLE_THUNK:#06x} \
                                 between an entry's flags and its segment, found \
                                 {thunk:#06x}"
                            ),
                        });
                    }
                    let segment = r.u8("entry table", at + 3)?;
                    let offset = r.u16("entry table", at + 4)?;
                    at += 6;
                    entries.push(Some(EntryPoint {
                        segment,
                        offset,
                        exported: flags & 0x01 != 0,
                    }));
                }
            }
            segment => {
                for _ in 0..count {
                    let flags = r.u8("entry table", at)?;
                    let offset = r.u16("entry table", at + 1)?;
                    at += 3;
                    entries.push(Some(EntryPoint {
                        segment,
                        offset,
                        exported: flags & 0x01 != 0,
                    }));
                }
            }
        }
    }
}

/// Read a name table into `names`, dropping its first entry.
///
/// Both name tables lead with a string that is not an export -- the module name
/// in the resident table, the module description in the non-resident one -- and
/// whose ordinal field is meaningless.
fn collect_names(
    r: &Reader<'_>,
    at: usize,
    names: &mut HashMap<String, u16>,
) -> Result<(), NeError> {
    let mut at = at;
    let mut first = true;

    loop {
        let (name, used) = r.pstring("name table", at)?;
        if name.is_empty() {
            return Ok(());
        }
        let ordinal = r.u16("name table", at + used)?;
        at += used + 2;

        if first {
            first = false;
        } else {
            names.insert(name, ordinal);
        }
    }
}

/// What an imported symbol resolves to, in this format's own pointer type.
///
/// The distinction is not a convenience. A routine is reached by far call, so
/// the host can put a thunk in its place and be told when it is used. A datum
/// is reached by `mov`, and the host is never told anything -- so the address a
/// data import resolves to must be memory the host genuinely owns and can read
/// back later. An absolute needs no memory at all -- see
/// [`crate::module::Import`]'s own doc comment for the third arm, and for why
/// this is a type alias onto shared vocabulary now rather than a type local
/// to this format: `m32::image::Import32` used to be this enum's own
/// two-variant cousin, and the two are reconciled there, not here --
/// `docs/plans/2026-08-12-abi-border-design.md` §3.
pub type Import = crate::module::Import<FarPtr>;

/// How a host answers "what is `MAJORBBS.474`?", for this format's own
/// pointer type.
///
/// Re-exported rather than declared here: see [`crate::module::ImportResolver`]
/// for the shared trait (implemented for any suitable closure, which is what
/// tests and examples in this crate use throughout). A real host has a
/// table, keyed by host version -- ordinals move between versions (996 in
/// MBBS 6.25, 1210 in WG 1.01, 1233 in WG 2.0), so resolving against the
/// wrong one produces plausible wrong bindings rather than errors.
pub use crate::module::ImportResolver;

/// A module in memory: which selector each of its segments got, what its
/// exports are, and what sits behind each thunk.
#[derive(Debug, Clone)]
pub struct Module {
    /// Selector per NE segment number, indexed from zero for segment 1.
    selectors: Vec<u16>,
    autodata: u16,
    entries: Vec<Option<EntryPoint>>,
    /// This module's own declared name -- see [`NeImage::own_name`]. What a
    /// *different* module's own import table would have to say to reach
    /// this one; not to be confused with [`NeImage::modules`], which is the
    /// list of names *this* module imports from.
    own_name: String,
    names: HashMap<String, u16>,
    /// Where this module's own slice of the machine-wide thunk index space
    /// begins -- [`Machine::next_thunk`](crate::m16::Machine) when this
    /// module's [`Thunks`] started counting. `imports[0]`, if it exists, is
    /// always the import behind global index `base`; see [`Module::import`].
    base: u16,
    imports: Vec<ImportSite>,
    relocations: usize,
}

impl Module {
    /// This module's own declared name -- see [`NeImage::own_name`]'s own
    /// doc comment for where it comes from and what it is for
    /// (`crates/mbbs`'s cross-module import registry keys loaded modules by
    /// exactly this string).
    pub fn name(&self) -> &str {
        &self.own_name
    }

    /// The selector a 1-based NE segment number was given.
    pub fn segment_selector(&self, segment: u16) -> Option<u16> {
        self.selectors
            .get(usize::from(segment).wrapping_sub(1))
            .copied()
    }

    /// The 1-based NE segment a selector belongs to, if it is one of this
    /// module's.
    ///
    /// The reverse of [`Module::segment_selector`], and the piece that turns a
    /// runtime address back into a place in the file: a disassembler and
    /// `re/ne_arity.py` both speak segment-and-offset, and neither has ever
    /// heard of a selector.
    ///
    /// A linear scan. Modules have tens of segments, this runs once per
    /// refusal, and a reverse index would be a second thing to keep in step
    /// with the first.
    pub fn segment_at(&self, selector: u16) -> Option<u16> {
        let index = self.selectors.iter().position(|&s| s == selector)?;
        u16::try_from(index + 1).ok()
    }

    /// How many segments the module has.
    pub fn segment_count(&self) -> usize {
        self.selectors.len()
    }

    /// The module's `DGROUP`: the segment its globals live in, and the `DS` its
    /// entry points are called with.
    pub fn data_selector(&self) -> u16 {
        self.autodata
    }

    /// Where an exported ordinal points.
    pub fn entry(&self, ordinal: u16) -> Option<FarPtr> {
        let entry = (*self.entries.get(usize::from(ordinal).wrapping_sub(1))?)?;
        Some(FarPtr {
            offset: entry.offset,
            selector: self.segment_selector(u16::from(entry.segment))?,
        })
    }

    /// Where an exported name points. Both name tables are searched.
    pub fn entry_by_name(&self, name: &str) -> Option<FarPtr> {
        self.entry(*self.names.get(name)?)
    }

    /// The same lookup as [`Module::entry_by_name`], ASCII case-insensitive.
    ///
    /// A linear scan, unlike the exact-case lookup's `HashMap` hit --
    /// [`Module::init`] is the only caller, it runs once per load, and a
    /// second case-folded index would be a second table to keep in step
    /// with `names`.
    fn entry_by_name_ignore_ascii_case(&self, name: &str) -> Option<FarPtr> {
        let ordinal = self
            .names
            .iter()
            .find_map(|(n, &ordinal)| n.eq_ignore_ascii_case(name).then_some(ordinal))?;
        self.entry(ordinal)
    }

    /// The module's real init routine -- `register_module`'s caller --
    /// resolved by **name** first, exported ordinal 1 only as a fallback.
    ///
    /// **Not "exported ordinal 1."** That was believed to be Galacticomm's
    /// own convention on the strength of one module: `WCCMMUD.DLL`'s
    /// ordinal 1 is `_INIT__WCCMMUD`, its real init routine. Measured
    /// against a second module, `RCIROSE.DLL` (NE), that agreement turned
    /// out to be coincidence: its ordinal 1 is `BCC286_EXE` -- Borland C++
    /// 286's crt0 startup stub, not an entry point at all -- while its real
    /// init routine, `_INIT__RCIROSE`, sits at ordinal 403. A crt0-looking
    /// name at ordinal 1 is itself a signal that ordinal 1 is not an entry
    /// point; the name lookup below runs first for exactly that reason, and
    /// ordinal 1 is never preferred once a name resolves, even when both
    /// exist.
    ///
    /// The candidate name is `_INIT__` followed by [`Module::name`]
    /// (`WCCMMUD` -> `_INIT__WCCMMUD`, `RCIROSE` -> `_INIT__RCIROSE`, both
    /// measured) and matched case-insensitively -- both measured NE exports
    /// happen to upper-case the whole name, matching [`Module::name`]'s own
    /// case exactly, but nothing about the format guarantees that, and the
    /// PE side of this same convention (`m32::PeImage::init_rva`) lower-cases
    /// it instead.
    ///
    /// `None` when neither the name lookup nor ordinal 1 resolves -- the
    /// module has no export by that name and no ordinal 1 either. Mirrors
    /// `m32::PeImage::init_rva`'s own `None` case.
    pub fn init(&self) -> Option<FarPtr> {
        let candidate = format!("_INIT__{}", self.own_name);
        self.entry_by_name_ignore_ascii_case(&candidate)
            .or_else(|| self.entry(1))
    }

    /// What thunk `index` stands for, as [`Exit::Call`](crate::m16::Exit::Call)
    /// reports it. This is how an unimplemented import is named rather than
    /// merely counted.
    ///
    /// `index` is the machine-wide index `Exit::Call` reports, not a
    /// position in [`Module::imports`] -- the two only coincide for the
    /// first module loaded into a machine, whose `base` is zero. `index`
    /// below `base`, or `base + imports.len()` or beyond, answers `None`:
    /// both are "not this module's own import" (see this module's own doc
    /// comment on [`Thunks`], and `Host::run`'s doc comment in `crates/mbbs`
    /// for why a caller who gets `None` here must try *other* loaded
    /// modules before concluding the index names nothing at all).
    pub fn import(&self, index: u16) -> Option<&ImportSite> {
        let local = index.checked_sub(self.base)?;
        self.imports.get(usize::from(local))
    }

    /// Every import the module has, in thunk-index order.
    pub fn imports(&self) -> &[ImportSite] {
        &self.imports
    }

    /// How many relocations were applied. Every record in the file is applied
    /// or the load fails, so this is the file's total.
    pub fn relocations_applied(&self) -> usize {
        self.relocations
    }
}

/// Assigns thunk indices to imported routines, densely and in first-encounter
/// order, out of the **machine-wide** index space [`Machine::next_thunk`]
/// tracks.
///
/// Densely rather than by ordinal: `MAJORBBS` alone reaches ordinal 1,233, and
/// MajorMUD uses 188 of them.
///
/// Machine-wide, not per-load: the trampoline table a thunk index names is
/// one physical structure belonging to the [`Machine`], built once and
/// shared by every module that loads into it (`mbbs-server` boots more than
/// one, `1a67e7d`). A `Thunks` that counted from zero on every load handed
/// two modules the same physical slot for two different imports --
/// `Exit::Call` only ever reports the bare index, so nothing downstream
/// could tell which module's table it named. `base` is where *this* load's
/// slice of that shared space starts, seeded from the machine's own
/// high-water mark and never reused by a later load.
struct Thunks {
    base: u16,
    by_symbol: HashMap<(String, Symbol), u16>,
    sites: Vec<ImportSite>,
}

impl Thunks {
    /// `base`: the machine-wide index this load's own imports start
    /// counting from -- [`Machine::next_thunk`] at the moment this load
    /// began.
    fn new(base: u16) -> Self {
        Self {
            base,
            by_symbol: HashMap::new(),
            sites: Vec::new(),
        }
    }

    /// This load's own high-water mark, machine-wide: `base` plus every
    /// distinct import assigned so far. What [`Machine::next_thunk`] must
    /// become once this load finishes successfully, so the *next* load's
    /// `Thunks::new` starts past every slot this one just spoke for.
    fn next_index(&self) -> u16 {
        // `index_of` never lets `sites.len()` grow past what fit below
        // `MAX_THUNKS` once added to `base` (see the `filter` below), so
        // this cannot overflow back below `base`.
        self.base + self.sites.len() as u16
    }

    fn index_of(&mut self, module: &str, symbol: &Symbol, resolved: bool) -> Result<u16, NeError> {
        let key = (module.to_owned(), symbol.clone());
        if let Some(&index) = self.by_symbol.get(&key) {
            return Ok(index);
        }

        let index = u16::try_from(self.sites.len())
            .ok()
            .and_then(|n| self.base.checked_add(n))
            .filter(|n| *n < MAX_THUNKS)
            .ok_or(NeError::TooManyImports {
                // Machine-wide: how many thunks the *machine* would need to
                // give every module loaded into it its own slot, not merely
                // this one load's own count -- `limit` is now genuinely a
                // machine-wide ceiling (see `MAX_THUNKS`'s own doc comment),
                // so `needed` has to speak the same currency to mean
                // anything next to it.
                needed: usize::from(self.base) + self.sites.len() + 1,
                limit: MAX_THUNKS,
            })?;
        self.by_symbol.insert(key, index);
        self.sites.push(ImportSite {
            module: module.to_owned(),
            symbol: symbol.clone(),
            resolved,
        });
        Ok(index)
    }
}

impl Machine {
    /// Load an NE module: map its segments, apply its relocations, wire its
    /// imports.
    ///
    /// Afterwards the machine's [`data_selector`](Machine::data_selector) is the
    /// module's `DGROUP`, so entry points are called with the `DS` they expect,
    /// and [`Module::entry`] gives a far pointer [`Machine::call`] accepts.
    ///
    /// The scratch code and data segments [`Machine::new`] provides for
    /// [`Machine::load_code`] stay allocated and go unused. One module per
    /// machine; a real image does not fit in the scratch segment anyway.
    ///
    /// # Errors
    ///
    /// If the file is not a well-formed NE module, if it needs something this
    /// loader refuses (a moveable segment), or if a segment cannot be mapped. An
    /// OSFIXUP relocation is not one of these: it is carried, not applied, and
    /// costs the load nothing (see [`Target::OsFixup`]).
    pub fn load_ne(&mut self, file: &[u8], imports: &dyn ImportResolver<FarPtr>) -> io::Result<Module> {
        let image = NeImage::parse(file)?;
        self.map_ne(&image, file, imports).map_err(io::Error::from)
    }

    /// The half of [`Machine::load_ne`] that can fail with an [`NeError`].
    fn map_ne(
        &mut self,
        image: &NeImage,
        file: &[u8],
        imports: &dyn ImportResolver<FarPtr>,
    ) -> Result<Module, NeError> {
        // Allocate first, so that every relocation has every selector it could
        // possibly name. A forward reference between segments is the ordinary
        // case, not an exception.
        //
        // The mappings arrive zeroed -- they are fresh anonymous pages -- which
        // is what a segment whose `minalloc` exceeds its file length needs: the
        // tail is BSS, and leaving it as whatever was there before would be a
        // module reading uninitialised globals that looked initialised.
        let mut selectors = Vec::with_capacity(image.segments.len());
        let first = self.mem.segments.len();
        for (i, entry) in image.segments.iter().enumerate() {
            let mut segment =
                Segment::new(entry.alloc, !entry.is_data()).map_err(|e| NeError::Mapping {
                    segment: (i + 1) as u16,
                    errno: e.raw_os_error().unwrap_or(0),
                })?;
            segment
                .write(0, &file[entry.file.clone()])
                .expect("the segment is at least as large as its file data");
            selectors.push(segment.selector());
            self.mem.segments.push(segment);
        }

        // Seeded from the machine's own high-water mark, not zero -- see
        // `Thunks`'s own doc comment. Read before anything below can move
        // it, so this load's whole slice is contiguous.
        let mut thunks = Thunks::new(self.next_thunk);
        let mut applied = 0;

        // Every distinct symbol is resolved exactly once, and every fixup naming
        // it gets that same answer.
        //
        // This is not an optimisation, though it is also that: `usrnum` is
        // addressed at 1,285 sites, and a resolver asked 1,285 times is a
        // resolver that can answer differently 1,285 times. The natural way to
        // write one -- hand out a slot of host memory per global, allocating on
        // first sight -- would then scatter a single global across 1,285
        // addresses, of which the module would use whichever the last fixup
        // happened to name.
        let mut resolved: HashMap<(&str, &Symbol), Value> = HashMap::new();

        for (i, entry) in image.segments.iter().enumerate() {
            for reloc in &entry.relocations {
                let value = match &reloc.target {
                    Target::Internal { segment, offset } => Value::Address(FarPtr {
                        offset: *offset,
                        selector: *selectors.get(usize::from(*segment).wrapping_sub(1)).ok_or(
                            NeError::NoSuchSegment {
                                segment: u16::from(*segment),
                            },
                        )?,
                    }),
                    Target::Import { module, symbol } => {
                        let name = image.module_name(*module)?;
                        match resolved.get(&(name, symbol)) {
                            Some(&value) => value,
                            None => {
                                let value = match imports.resolve(name, symbol) {
                                    // A datum is addressed, never called: the
                                    // host's own memory goes into the fixup.
                                    Some(Import::Data(ptr)) => Value::Address(ptr),
                                    Some(Import::Absolute(n)) => Value::Absolute(n),
                                    answer => {
                                        let index = thunks.index_of(
                                            name,
                                            symbol,
                                            matches!(answer, Some(Import::Routine)),
                                        )?;
                                        Value::Address(self.thunk_slot(index))
                                    }
                                };
                                resolved.insert((name, symbol), value);
                                value
                            }
                        }
                    }

                    // Not applied, so not counted: `applied` is a count of sites
                    // this loader wrote, and claiming one it deliberately left
                    // alone would make the total disagree with the image.
                    Target::OsFixup { .. } => continue,
                };

                apply(&mut self.mem.segments[first + i], (i + 1) as u16, reloc, value)?;
                applied += 1;
            }
        }

        let autodata = *selectors
            .get(usize::from(image.autodata).wrapping_sub(1))
            .ok_or(NeError::NoAutoData {
                segment: image.autodata,
            })?;
        self.mem.data = autodata;

        // Only now, with the load fully successful: a failed load (the `?`s
        // above) must leave `next_thunk` exactly where it was, so a retried
        // or abandoned load never burns machine-wide indices it never ended
        // up using.
        self.next_thunk = thunks.next_index();

        Ok(Module {
            selectors,
            autodata,
            entries: image.entries.clone(),
            own_name: image.own_name.clone(),
            names: image.names.clone(),
            base: thunks.base,
            imports: thunks.sites,
            relocations: applied,
        })
    }
}

/// What a fixup writes: an address, or a constant that has none.
#[derive(Debug, Clone, Copy)]
enum Value {
    Address(FarPtr),
    Absolute(u16),
}

/// Write one relocation's value into its segment.
///
/// The ADDITIVE flag's real meaning is "this record names exactly one site, do
/// not walk the chain". Whether the value is also *added* to what is there
/// depends on the source type: adding to a selector is meaningless, so a
/// selector is written either way.
///
/// The additive-OFFSET case is the one that matters. 1,670 of `WCCMMUD.DLL`'s
/// additive OFFSET sites already hold a nonzero word -- `margv[-1]`, `sv.numact`
/// and their like -- so treating additive as a write would silently produce
/// 1,670 wrong addresses rather than any error at all.
///
/// The additive-SEGMENT case is where Wine and MBBSEmu disagree: Wine writes,
/// MBBSEmu does not handle it. All 2,069 additive SEGMENT sites in `WCCMMUD.DLL`
/// hold zero, so the two agree on this module and the question is unobservable.
/// Written, to match Wine.
fn apply(
    segment: &mut Segment,
    number: u16,
    reloc: &Relocation,
    value: Value,
) -> Result<(), NeError> {
    // A constant has no selector, so a fixup that wants one has nothing to be
    // given. Refused here rather than fudged: writing half a constant as an
    // address produces a wrong address and no complaint.
    let (offset, selector) = match value {
        Value::Address(ptr) => (ptr.offset, Some(ptr.selector)),
        Value::Absolute(n) => (n, None),
    };
    if selector.is_none() && matches!(reloc.source, Source::Segment | Source::FarAddr) {
        return Err(NeError::AbsoluteNeedsAnAddress {
            segment: number,
            offset: reloc.offset,
        });
    }
    let selector = selector.unwrap_or_default();

    // A site needs room for what is written into it, and -- when it is a link
    // in a chain -- room for the word holding the next offset. The two are the
    // same for every source but LOBYTE, which writes one byte and still carries
    // a word-sized link: the spec's chains are terminated by 0FFFFh, and no byte
    // is 0FFFFh.
    let width = reloc.source.width().max(if reloc.additive { 0 } else { 2 });
    let mut at = reloc.offset;

    // Walking a chain normally destroys it -- the fixup overwrites the very word
    // the next link lives in -- so a cycle usually breaks itself after a step or
    // two. A LOBYTE chain does not, because one byte of the link survives. A
    // chain cannot honestly revisit a site, and every link is a word, so no
    // well-formed chain needs more steps than this.
    let limit = segment.len() / 2 + 1;

    for _ in 0..limit {
        let site = usize::from(at);
        if site + width > segment.len() {
            return Err(NeError::SiteOutOfBounds {
                segment: number,
                offset: site,
                size: segment.len(),
            });
        }

        // Read before writing, twice over: the addend is what the site already
        // holds, and so is the chain's next link.
        let addend = match reloc.source {
            Source::LoByte => u16::from(segment.slice(site, 1)[0]),
            _ => segment.read_u16(site),
        };
        let next = if reloc.additive {
            CHAIN_END
        } else {
            segment.read_u16(site)
        };

        match reloc.source {
            Source::LoByte => {
                let byte = if reloc.additive {
                    (addend as u8).wrapping_add(offset as u8)
                } else {
                    offset as u8
                };
                segment.write(site, &[byte]).expect("bounds checked above");
            }
            Source::Segment => {
                segment
                    .write(site, &selector.to_le_bytes())
                    .expect("bounds checked above");
            }
            Source::Offset | Source::FarAddr => {
                let word = if reloc.additive {
                    // Wrapping, not saturating and not checked: `margv` is
                    // reached with an addend of 0xfffe, which is -2.
                    addend.wrapping_add(offset)
                } else {
                    offset
                };
                segment
                    .write(site, &word.to_le_bytes())
                    .expect("bounds checked above");
                if reloc.source == Source::FarAddr {
                    segment
                        .write(site + 2, &selector.to_le_bytes())
                        .expect("bounds checked above");
                }
            }
        }

        // A link pointing at its own site is where the chain stops. Wine reads
        // it the same way, and it is the only reading that terminates.
        if next == CHAIN_END || next == at {
            return Ok(());
        }
        at = next;
    }

    Err(NeError::ChainRunsAway {
        segment: number,
        offset: reloc.offset,
    })
}
