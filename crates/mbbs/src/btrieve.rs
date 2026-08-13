//! Btrieve files: the geometry in a file's first page, and the blocks a module
//! names them by.
//!
//! A MajorBBS module keeps everything that is not text in Btrieve: MajorMUD's
//! items, spells, monsters, rooms, shops and characters are eighteen files
//! shipped beside the module. `BTVSTF.H` is the interface it reaches them
//! through and `PLBTVSTF.C` is Galacticomm's own implementation of it, which
//! settles most of what this file has to reproduce.
//!
//! The on-disk format is not Galacticomm's -- it is Btrieve's, and the real
//! host reached it through `INT 0x7B` into a TSR nobody has. So the format is
//! read here directly, and only as far as a step needs.
//!
//! # Read directly, not converted
//!
//! MBBSEmu converts each file into a SQLite database on first open. That is a
//! reasonable choice for a long-running emulator and the wrong one here: it
//! writes a second file that has to be kept in step with the first, and it
//! makes "give me the next record in key order" go through a query planner to
//! answer what a B-tree already knows. The largest file MajorMUD ships is 77 MB
//! and opening one reads its first page.
//!
//! # What is read, and what is not
//!
//! Initialisation opens sixteen files, counts the records in one, and never
//! reads a record -- so this reads the file control record and stops. No key
//! definitions, no page walking, no records. Everything below is a field of the
//! FCR, verified against all eighteen files MajorMUD ships by
//! `crates/mbbs/tests/btrieve.rs`.

mod create;
pub mod keys;
mod ops;
pub mod pages;
pub mod records;
mod stat;
mod variable;
pub(crate) mod v6;

use std::fmt;
use std::path::{Path, PathBuf};

use mbbs_ptr::ModulePtr;

use crate::abi::Abi;

pub use create::{create, FileSpec, KeySpec, SegmentSpec};
pub use keys::Key;
pub use ops::{BlockId, Delivery, LockMode, LockTable, Op, OpError, Step};
pub use records::{Record, Records};
pub use stat::{deliver, Stat, StatKey};

/// How much of the first page this host reads.
///
/// The file control record *is* the first page, and the smallest page a Btrieve
/// file has is 512 bytes -- so every field read here is inside the first 512 of
/// any file, whatever its page length.
const FCR: usize = 512;

/// Where each field of the file control record lives.
///
/// Byte offsets rather than a `#[repr(C)]` struct: the record has hundreds of
/// bytes this host has no reading for, and a struct would have to name them all
/// to reach the eight that matter.
mod at {
    /// Page length, in bytes.
    pub const PAGE: usize = 0x08;
    /// How many keys the file is indexed by.
    pub const KEYS: usize = 0x14;
    /// Logical record length -- the bytes a module sees.
    pub const RECLEN: usize = 0x16;
    /// Physical record length -- the logical length plus Btrieve's own padding.
    pub const PHYSICAL: usize = 0x18;
    /// Record count, **high half**.
    pub const RECORDS_HIGH: usize = 0x1a;
    /// Record count, **low half**.
    pub const RECORDS_LOW: usize = 0x1c;
    /// `0xff` when the file holds variable-length records.
    pub const VARIABLE_MARK: usize = 0x38;
    /// User flags. Bit 0 is variable-length records, bit 3 is compression.
    pub const USRFLGS: usize = 0x106;

    /// Generation counter. Present in both the v6 control record's shadow
    /// copies and both the allocation table's; the higher one is live.
    pub const GENERATION: usize = 0x04;
}

/// Bits of [`at::USRFLGS`], and what each adds to a record's physical length.
///
/// The engine builds the physical length one flag at a time -- decompiled at
/// `re/btrieve_ghidra/exports/W32MKDE_decompiled.c:17798` (`FUN_0041e3f0`):
/// variable-length adds four bytes of fragment pointer, blank truncation adds
/// a trailing-blank count after it, and compression and v6 add more. **So the
/// fragment pointer is at the logical record length whichever other flags are
/// set**, and mislocating it by the two bytes of a blank count is the failure
/// this names rather than assumes away.
mod flag {
    /// The file holds variable-length records.
    pub const VARIABLE: u16 = 1 << 0;

    /// Trailing blanks are stripped from each record and counted instead.
    ///
    /// Two more bytes of physical record, after the fragment pointer, and a
    /// read has to put the blanks back. Nothing in `tmp/` sets it -- all 32
    /// files were checked -- so there is nothing to check an implementation
    /// against, and it is refused rather than ignored: ignoring it returns
    /// every record short by however many spaces it ended with.
    pub const BLANK_TRUNCATION: u16 = 1 << 1;

    /// The record data is compressed.
    ///
    /// No file MajorMUD ships sets it either, and this host has no
    /// decompressor. A file that set it would otherwise be read as a fragment
    /// chain over compressed bytes and hand the module plausible garbage.
    pub const COMPRESSED: u16 = 1 << 3;
}

/// Which Btrieve wrote the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// Btrieve 5.x: the first four bytes are zero and byte 7 is the version.
    /// Seventeen of the eighteen files MajorMUD ships.
    V5,

    /// Btrieve 6.x: the first two bytes are `FC`. Exactly one file --
    /// `NEWMP001.VIR`, the virgin map template, which the module never opens.
    ///
    /// Its file control record reads correctly at the v5 offsets, which is why
    /// it is accepted rather than refused. **That is only established for the
    /// fields below**; a v6 file's *pages* are not laid out like a v5 file's,
    /// so whatever walks pages later must not assume they are.
    V6,
}

/// A Btrieve file's shape, out of its file control record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    pub version: Version,

    /// Bytes per page. Always a multiple of 512.
    pub page: u16,

    /// How many keys the file is indexed by. The definitions themselves are not
    /// read yet -- see [`Block::key`].
    pub keys: u16,

    /// Logical record length: what a module's `struct` is meant to match.
    pub reclen: u16,

    /// Physical record length: the logical length plus Btrieve's padding, and
    /// what a page's records are actually spaced by.
    pub physical: u16,

    /// How many records the file holds.
    pub records: u32,

    /// How many pages the file is, which is its size divided by [`page`](Self::page).
    pub pages: u32,

    /// Whether records are variable-length. `WCCTEXT` is; the other seventeen
    /// are not.
    pub variable: bool,
}

/// A file the host will not read as Btrieve, and the reason.
///
/// One shape rather than a variant per check, because what a caller does with
/// it is the same in every case -- stop the module and say this sentence. The
/// file is named separately from the reason so that the name cannot be left out
/// of the message by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtvError {
    pub file: String,
    pub why: String,
}

impl fmt::Display for BtvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.file, self.why)
    }
}

impl std::error::Error for BtvError {}

/// Why [`Btrieve::begin`], [`Btrieve::end`] or [`Btrieve::abort`] refused.
///
/// Measured against genuine Btrieve 6.15 under Wine
/// (`tools/btrieve-oracle/xactprobe.c`), not designed from the vendor
/// header's `ASSERT`s alone: a nested `dfaBegTrans` is refused (status 37,
/// not silently accepted or stacked -- `nested: inner begin status=37`), and
/// `dfaEndTrans`/`dfaAbtTrans` with no transaction active are refused with
/// the same status the engine gives a *second* `dfaAbtTrans` right after a
/// first one that already closed the transaction (`end_no_begin: status=39`,
/// `abort_no_begin: status=39`, `nested: second abort status=39`) -- three
/// different routes to "no transaction is open" landing on one status is
/// itself the measurement, not a name read off a manual. This host does not
/// reproduce Btrieve's numeric status codes at the engine layer (Task 7's
/// marshalling does that); the two variants below are what `dfaBegTrans` and
/// `dfaEndTrans`/`dfaAbtTrans` each need to tell apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionError {
    /// [`Btrieve::begin`] while a transaction was already open.
    AlreadyActive,
    /// [`Btrieve::end`] or [`Btrieve::abort`] with none open.
    NoneActive,
}

impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyActive => write!(f, "a transaction is already open"),
            Self::NoneActive => write!(f, "no transaction is open"),
        }
    }
}

impl std::error::Error for TransactionError {}

impl Geometry {
    /// Read a file's geometry from its first page.
    ///
    /// `name` is what the module called the file, and is what any refusal is
    /// named by.
    ///
    /// # Errors
    ///
    /// If the file cannot be read, is not Btrieve, or describes a shape that
    /// contradicts itself. A file whose header is wrong is refused here rather
    /// than read: every field below sizes something, and a wrong page length
    /// silently turns record 400 into whatever bytes are at the wrong offset.
    pub fn read(name: &str, path: &Path) -> Result<Self, BtvError> {
        let fail = |why: String| BtvError {
            file: name.to_owned(),
            why,
        };

        let size = std::fs::metadata(path)
            .map_err(|e| fail(format!("{}: {e}", path.display())))?
            .len();
        // A v6 file's control record is shadowed across physical pages 0 and 1
        // -- generation counters, not position, say which is live (Evidence 1).
        // A v5 file has no second copy, so the version is established from the
        // first `FCR` bytes alone, and only a v6 file requires a further read.
        let head = read_head(path, FCR).map_err(|e| fail(format!("{}: {e}", path.display())))?;
        if head.len() < FCR {
            return Err(fail(format!(
                "{size} bytes, and a Btrieve file's first page is at least {FCR}"
            )));
        }

        let version = version(&head).ok_or_else(|| {
            fail(format!(
                "starts {:02x?}, which is neither a v5 file control record \
                 (four zero bytes) nor a v6 one (\"FC\")",
                &head[..4]
            ))
        })?;

        let bytes: Vec<u8> = if version == Version::V6 {
            // The second shadow copy lives on *physical page 1* -- byte offset
            // `page_size`, not the fixed `FCR` (512) offset an earlier version
            // of this function used. Those only coincide when `page_size ==
            // 512`; `DUPKEY30.DAT`'s 512-byte pages hid that, but a
            // 2048-byte-paged file compared padding against padding and never
            // reached page 1 at all (`PP2048.DAT` read 0 of its 50 records).
            //
            // `page_size` is read from the first half and trusted *before*
            // liveness is decided -- Evidence 1 measured it identical between
            // the two copies, so that trust is safe, but say so here because
            // it is the one field this function reads before it has chosen
            // which copy is live.
            let page_size = u32::from(u16::from_le_bytes([head[at::PAGE], head[at::PAGE + 1]]));
            let needed = u64::from(page_size) + FCR as u64;
            if size < needed {
                return Err(fail(format!(
                    "{size} bytes, too short to hold a second physical page: a \
                     {page_size}-byte page 0 plus a {FCR}-byte control-record copy \
                     starting page 1 needs at least {needed}"
                )));
            }
            // Read only the FCR-byte header of physical page 1, not the whole
            // page -- a page can be many kilobytes, and this file can be tens
            // of megabytes; nothing here may become a whole-file read.
            let second = read_at(path, page_size as usize, FCR)
                .map_err(|e| fail(format!("{}: {e}", path.display())))?;
            if second.len() < FCR {
                return Err(fail(format!(
                    "{size} bytes, too short to hold a second physical page: only \
                     {} bytes were readable starting at offset {page_size}",
                    second.len()
                )));
            }
            if &second[..2] != b"FC" {
                return Err(fail(format!(
                    "the bytes at offset {page_size} (physical page 1, by this \
                     file's own {page_size}-byte page size) are {:02x?}, not \
                     \"FC\" -- there is no second control-record shadow copy \
                     where this file's page size says one belongs",
                    &second[..2]
                )));
            }
            let generation = |half: &[u8]| {
                u16::from_le_bytes([half[at::GENERATION], half[at::GENERATION + 1]])
            };
            let first = generation(&head);
            let second_gen = generation(&second);
            match first.cmp(&second_gen) {
                std::cmp::Ordering::Greater => head,
                std::cmp::Ordering::Less => second,
                std::cmp::Ordering::Equal => {
                    return Err(fail(format!(
                        "both control-record copies claim generation {first}, and \
                         there is no rule measured for choosing between them"
                    )));
                }
            }
        } else {
            head
        };

        let word = |offset: usize| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let page = word(at::PAGE);
        let reclen = word(at::RECLEN);
        let physical = word(at::PHYSICAL);

        // Every check below is a *self*-consistency one: a number the file gives
        // twice, or gives once and can be checked against its own size. Nothing
        // is refused for being unusual, because a file none of the eighteen
        // resembles is not necessarily one this cannot read.
        if page < 512 || page % 512 != 0 {
            return Err(fail(format!(
                "a page length of {page}, which is not a multiple of 512"
            )));
        }
        if size % u64::from(page) != 0 {
            return Err(fail(format!(
                "{size} bytes, which is not a whole number of {page}-byte pages"
            )));
        }
        if reclen == 0 {
            return Err(fail("a record length of zero".to_owned()));
        }
        if physical < reclen {
            return Err(fail(format!(
                "a physical record length of {physical}, shorter than the \
                 {reclen}-byte record it holds"
            )));
        }
        if u32::from(physical) > u32::from(page) {
            return Err(fail(format!(
                "a {physical}-byte record in a {page}-byte page"
            )));
        }

        // Two independent witnesses to the same fact, and they are checked
        // against each other because either alone could be something else: bit
        // 0 of the user flags, and the `0xff` marker. All eighteen files agree,
        // and `WCCTEXT` is the one where both say yes.
        let usrflgs = word(at::USRFLGS);
        let variable = usrflgs & flag::VARIABLE != 0;
        if variable != (bytes[at::VARIABLE_MARK] == 0xff) {
            return Err(fail(format!(
                "user flags say variable-length records is {variable}, and the \
                 marker at {:#x} says {}",
                at::VARIABLE_MARK,
                !variable
            )));
        }

        // Compression is a separate encoding of the record body, on top of the
        // fragment chain, and nothing here can undo it. Refused rather than
        // read: the alternative is handing a module 2,000 bytes of compressed
        // stream that parses as text just well enough not to be noticed.
        if usrflgs & flag::COMPRESSED != 0 {
            return Err(fail(format!(
                "user flags {usrflgs:#06x} say the record data is compressed, and this \
                 host has no decompressor"
            )));
        }

        // Blank truncation is the other thing that lengthens a physical record,
        // and it lengthens it *after* the fragment pointer. Refused rather than
        // ignored: a record read without putting the blanks back is short by
        // however many spaces it ended with, silently.
        if usrflgs & flag::BLANK_TRUNCATION != 0 {
            return Err(fail(format!(
                "user flags {usrflgs:#06x} say trailing blanks are truncated and counted, \
                 and this host does not put them back -- every record would come out short \
                 by the spaces it ended with"
            )));
        }

        // Where a variable-length record's chain begins: the four bytes after
        // the logical record, inside the physical one. A file that says it has
        // variable-length records and leaves no room for the pointer is
        // describing something this cannot read.
        //
        // v6 needs six, not four: Evidence 1b's own two-byte slot marker sits
        // between the slot and the logical record on *every* v6 file, fixed
        // or variable, so the four-byte pointer `walk_v6` reads still comes
        // right after `reclen` bytes -- but out of a `physical - 2`-byte
        // content area, not a `physical`-byte one. Checking the v5 floor
        // against a v6 file would let through a shape that later panics
        // slicing four bytes out of the two or three actually left, rather
        // than refusing here the way this house style requires.
        let pointer_needs = match version {
            Version::V5 => 4,
            Version::V6 => 4 + 2,
        };
        if variable && physical - reclen < pointer_needs {
            return Err(fail(format!(
                "variable-length records whose {physical}-byte slot leaves only {} bytes \
                 after the {reclen}-byte record, and {version:?}'s fragment pointer needs \
                 {pointer_needs}",
                physical - reclen
            )));
        }

        Ok(Self {
            version,
            page,
            keys: word(at::KEYS),
            reclen,
            physical,
            // RECORDS_HIGH and RECORDS_LOW are two separate fields (see
            // `pages::write_record`'s doc comment on why `to_long` cannot
            // write them in one store), but they sit adjacent, so the range
            // between them is the same four-byte, high-word-first quantity
            // `pages::long` decodes everywhere else.
            records: pages::long(&bytes[at::RECORDS_HIGH..at::RECORDS_LOW + 2]),
            pages: (size / u64::from(page)) as u32,
            variable,
        })
    }
}

/// Which Btrieve wrote this, or `None` if nothing did.
fn version(bytes: &[u8]) -> Option<Version> {
    if &bytes[..2] == b"FC" {
        return Some(Version::V6);
    }
    // A v5 file control record opens with four zero bytes and carries its
    // version in byte 7 -- 4 in every file MajorMUD ships. 3, 4 and 5 are the
    // codes MBBSEmu accepts, which is the only independent transcription there
    // is; a file outside them is refused rather than read on the assumption
    // that the fields did not move.
    if bytes[..4] == [0, 0, 0, 0] && bytes[6] == 0 && (3..=5).contains(&bytes[7]) {
        return Some(Version::V5);
    }
    None
}

/// The first `len` bytes of a file, or fewer if it is shorter.
///
/// `WCCUPDAT.DAT` is 77 MB and `WCCMP001.VIR` 43. Reading a header is reading a
/// header.
fn read_head(path: &Path, len: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;

    let mut out = vec![0u8; len];
    let mut file = std::fs::File::open(path)?;
    let mut got = 0;
    while got < len {
        match file.read(&mut out[got..])? {
            0 => break,
            n => got += n,
        }
    }
    out.truncate(got);
    Ok(out)
}

/// The `len` bytes of a file starting at `offset`, or fewer if it is shorter.
///
/// Seeks rather than reading from the start, for the same reason
/// [`read_head`] does not read the whole file: a v6 file's second
/// control-record copy can start many kilobytes in, and this file can be
/// tens of megabytes.
fn read_at(path: &Path, offset: usize, len: usize) -> std::io::Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = std::fs::File::open(path)?;
    file.seek(SeekFrom::Start(offset as u64))?;
    let mut out = vec![0u8; len];
    let mut got = 0;
    while got < len {
        match file.read(&mut out[got..])? {
            0 => break,
            n => got += n,
        }
    }
    out.truncate(got);
    Ok(out)
}

/// Bytes of `struct btvblk`, and where each field of it sits.
///
/// `BTVSTF.H:17`, with the `PHARLAP` fields -- which `WCCMMUD.DLL` is built
/// for, because a server module targets the 286|DOS-Extender rather than DOS:
///
/// Each field is written as the one before it plus that one's width, so the
/// struct's total size cannot drift from the offsets inside it. The absolute
/// numbers are pinned by [`tests::the_block_is_laid_out_the_way_btvstf_h_declares_it`].
mod field {
    use super::SEGMAX;

    /// Btrieve's own 128-byte position block. Opaque to everybody, including
    /// the real host, which only ever handed its address to the TSR.
    pub const POSBLK: u16 = 0;
    pub const FILNAM: u16 = POSBLK + 128;
    pub const RECLEN: u16 = FILNAM + 4;
    pub const KEY: u16 = RECLEN + 2;
    pub const DATA: u16 = KEY + 4;
    pub const LASTKN: u16 = DATA + 4;
    pub const KEYLNS: u16 = LASTKN + 2;
    /// Real-mode segment of the block, for the DOS extender. Nothing here has a
    /// real mode to have a segment in, so it stays zero.
    pub const REALSEG: u16 = KEYLNS + SEGMAX * 2;
    /// Real-mode segment of the key buffer. Zero, for the same reason.
    pub const KEYSEG: u16 = REALSEG + 2;
    /// The whole struct.
    pub const SIZE: u16 = KEYSEG + 2;
}

/// `BTVSTF.H:13` -- key segments per file, which sizes `keylns`.
const SEGMAX: u16 = 24;

/// `BTVSTF.H:14` -- how deep `setbtv`'s stack is.
const BBSTSZ: usize = 10;

/// Where a file is positioned: the cursor Btrieve keeps in its position block.
///
/// Not in the module's memory. Btrieve kept it in `posblk`, which is 128 opaque
/// bytes the real host only ever handed back to the TSR -- so a module cannot
/// read it, cannot corrupt it, and has no way to notice that this host keeps it
/// somewhere else entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cursor {
    /// Nothing has positioned the file yet, and `absbtv` has nothing to report.
    Nowhere,

    /// At a place in a key's order: what the query and acquire families leave
    /// behind, and what `qnxbtv` steps along.
    Ordered { key: u16, at: usize },

    /// At a place in physical order: what the step family leaves behind.
    Physical { at: usize },
}

/// One open Btrieve file.
///
/// # Generic (over `A: Abi`), as of this task
///
/// `block`/`data`/`key` are `A::Ptr` rather than `mbbs16::FarPtr` -- they are
/// module-memory addresses the host handed a module, and the module's own
/// ABI decides their shape. `A` defaults to [`Wg16`] so every existing caller
/// keeps naming this type as plain `Block`, the same convention
/// [`crate::heap::Heap`] and [`crate::msg::Messages`] already use. Every
/// method that never resolved a pointer against module memory -- `query`,
/// `get`, `step`, `insert`, `update`, `delete`, `reindex`, and the getters
/// below -- has no `A`-dependent behaviour and lives on `impl<A: Abi>
/// Block<A>` unchanged; only the three fields below and their own getters
/// name `A::Ptr`.
pub struct Block<A: Abi> {
    /// This block's identity for [`ops::LockTable`] -- see [`ops::BlockId`]'s
    /// own doc comment for why it is not the module's `struct btvblk *`.
    id: ops::BlockId,

    /// What the module named it, for error messages.
    name: String,

    /// Where it is on disk, so records can be read without opening it again.
    path: PathBuf,

    /// The file's own shape.
    geometry: Geometry,

    /// What the file is indexed by.
    keys: Vec<Key>,

    /// The `struct btvblk` the module was handed. Also this block's identity:
    /// `setbtv`, `cntrbtv` and `clsbtv` name it and nothing else does.
    block: A::Ptr,

    /// What the module said its records are -- `opnbtv`'s `maxlen`, which sizes
    /// `data` and is what `bb->reclen` holds. **Not** the file's record length:
    /// `PLBTVSTF.C:150` stores the module's number, and the two disagreeing is
    /// a thing worth being able to see rather than to silence.
    maxlen: u16,

    /// The record buffer, `maxlen` bytes of the module's heap.
    data: A::Ptr,

    /// The key buffer, `clckln()` bytes of the module's heap. What a search
    /// value is copied into, and what a `Get Key` operation leaves the found
    /// key in.
    key: A::Ptr,

    /// The records, read the first time something asks for one.
    ///
    /// **Lazily**, because `opnbtv` is not a read: initialisation opens fifteen
    /// files totalling 55 MB and then queries one of them. Loading at open time
    /// would make every module pay for every file it merely holds a handle to.
    records: Option<Records>,

    /// Where the file is positioned.
    cursor: Cursor,

    /// Whether a write has happened since the index pages last agreed with the
    /// data. Set by [`Self::insert`] and [`Self::update`], cleared by
    /// [`Self::reindex`].
    ///
    /// The host never reads an index page -- `records()` page-walks and sorts
    /// -- so nothing *needs* this flag to answer a module correctly. It exists
    /// for the file itself: a real Btrieve or MBBSEmu could open it later, and
    /// `clsbtv` calls `reindex` exactly when this is true so that a file
    /// leaving this host's reach never leaves with a stale index behind it.
    dirty: bool,

    /// Whether a transaction [`Btrieve::begin`] started is still open and
    /// covers this block.
    ///
    /// Set on every currently-open block by [`Btrieve::begin`] and on every
    /// block opened while one is in progress by [`Btrieve::open`], cleared by
    /// [`Btrieve::end`] and [`Btrieve::abort`]. `Block::insert`/`Block::update`
    /// read this rather than taking a parameter, because `dinsbtv`/`dupdbtv`
    /// call them directly (`shims/btrieve.rs:455,579`) and that call site is
    /// frozen for this task -- see this module's top-of-file note. A `bool`
    /// here is what lets the transaction reach a write it cannot be told
    /// about through its own argument list.
    txn_active: bool,

    /// This block's pre-image for the transaction in progress, if a write
    /// has reached it since [`Self::txn_active`] went true.
    ///
    /// `None` until the *first* write inside the transaction -- capturing one
    /// for every open block at `begin` would mean reading every file the
    /// module happens to have open, most of which a transaction never
    /// touches, and the largest MajorMUD ships is 77 MB. Captured just once:
    /// [`Self::insert`] and [`Self::update`] only take it if it is still
    /// `None`, so a second write to the same block in the same transaction
    /// leaves the *pre-transaction* image standing, not the first write's
    /// result.
    pre_image: Option<PreImage>,
}

/// One block's state as it was the moment a transaction first wrote to it --
/// enough to put both the disk and the in-memory model back exactly where
/// they were on [`Btrieve::abort`].
///
/// Genuine Pervasive Btrieve keeps this as a page-level pre-image file
/// (`docs/plans/2026-08-12-btrieve-finish.md` Task 6, and `DFAAPI.C`'s
/// `PRIMBV`/"normal pre-image `dfaMode()`" -- see `at::` in this file's
/// module doc comment). This host keeps the whole file's bytes instead of
/// only the pages a write touched: `Block::insert`/`Block::update` write
/// through several places (a data page, and on `insert` sometimes the
/// allocation table) and re-deriving exactly which bytes moved would have to
/// track every one of them precisely, where "the file as it was" cannot be
/// wrong by construction. The cost is one extra copy of the file, taken
/// once per transaction per block actually written -- not per write, and not
/// for a block a transaction never touches.
#[derive(Debug)]
struct PreImage {
    /// The file's bytes before this transaction's first write to it.
    bytes: Vec<u8>,
    /// The in-memory model at the same instant, so a restore does not need a
    /// re-read to agree with the bytes it just wrote back.
    records: Option<Records>,
    /// The block's record/page counts at the same instant.
    geometry: Geometry,
    /// Whether the block was dirty at the same instant.
    dirty: bool,
}

/// Make `bytes` exactly `reclen` long: padded with zero if shorter, cut off
/// if longer.
///
/// `records::walk` always stores exactly `geometry.reclen` bytes for a
/// record, because that is all it reads out of a slot. A model that kept a
/// caller's buffer at whatever length the caller handed over -- `dinsbtv`
/// passes `bb->reclen`, [`Block::maxlen`], the *module's* own idea of the
/// record length, which is allowed to differ from the file's -- would hold a
/// record of a different length than a re-read of the same file produces,
/// and `Key::extract`/`Key::compare` would then see different bytes before
/// and after the cache is dropped. [`Block::insert`] calls this on its way
/// into both the write and the model, which is the one place both have to
/// agree.
fn normalized(bytes: &[u8], reclen: u16) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out.resize(usize::from(reclen), 0);
    out
}

impl<A: Abi> Block<A> {
    /// What the module named this file.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The file's shape.
    pub fn geometry(&self) -> &Geometry {
        &self.geometry
    }

    /// What the file is indexed by.
    pub fn keys(&self) -> &[Key] {
        &self.keys
    }

    /// A record's bytes, padded so a key's own `offset` lands where it was
    /// measured from -- see [`records::keyed`].
    ///
    /// On the `Block` because the shim layer reads key bytes off a record it
    /// reached through one, and has no other route to the file's version.
    pub(crate) fn keyed<'a>(&self, bytes: &'a [u8]) -> std::borrow::Cow<'a, [u8]> {
        let shift = self.records.as_ref().map_or(0, Records::key_shift);
        records::keyed(shift, bytes)
    }

    /// Whether this host will write to the file at all.
    ///
    /// # Errors
    ///
    /// If the file is v6. Reading one is Tasks 1-6 of
    /// `docs/plans/2026-08-11-btrieve-v6-page-addressing.md`; **writing one is
    /// deliberately out of that plan's scope**, and needs the allocation-table
    /// maintenance, shadow-copy flipping and generation bumping the engine
    /// does.
    ///
    /// This exists because removing the blanket v6 refusal from
    /// `Records::read` (Task 2, lifted in Task 5) silently un-guarded the
    /// write path, which had never been v6-safe and was only unreachable
    /// because every v6 read failed first. A v6 record's `position` carries a
    /// **logical** page id (Evidence 1c), and `pages::write_record` seeks to a
    /// position as a literal byte offset -- so an insert or update would have
    /// landed on whatever physical page happened to sit at the logical id's
    /// arithmetic, or past the end of the file, while the in-memory model
    /// recorded a success. Silent corruption, so: refuse.
    fn writable(&self) -> Result<(), BtvError> {
        if self.geometry.version != Version::V5 {
            return Err(BtvError {
                file: self.name.clone(),
                why: format!(
                    "is a {:?} file, and this host reads those but does not write \
                     them -- a v6 record's position names a logical page, and \
                     writing one needs the allocation-table maintenance that is \
                     deliberately out of the read plan's scope",
                    self.geometry.version
                ),
            });
        }
        Ok(())
    }

    /// If a transaction covers this block and has not yet written to it,
    /// capture its pre-image. A no-op otherwise -- both when no transaction
    /// is active ([`Self::txn_active`] false) and when this transaction has
    /// already captured one, so every call site can call this unconditionally
    /// right before it is about to change the file.
    ///
    /// **Called at the last point before a write, not at the top of
    /// `insert`/`update`.** Both callers reach this only after every refusal
    /// ahead of them (`writable`, the variable-length checks, the length and
    /// position checks) has already passed, so a call that returns `Err`
    /// never captures one -- there is nothing to roll back for a write that
    /// never happened, and capturing anyway would cost a full read of the
    /// file for every refused call, not just every real write.
    ///
    /// # Errors
    ///
    /// If the file cannot be read back for the snapshot.
    fn capture_for_journal(&mut self) -> Result<(), BtvError> {
        if !self.txn_active || self.pre_image.is_some() {
            return Ok(());
        }
        let bytes = std::fs::read(&self.path).map_err(|e| BtvError {
            file: self.name.clone(),
            why: format!("{}: reading a transaction pre-image: {e}", self.path.display()),
        })?;
        self.pre_image = Some(PreImage {
            bytes,
            records: self.records.clone(),
            geometry: self.geometry,
            dirty: self.dirty,
        });
        Ok(())
    }

    /// The `struct btvblk` the module holds.
    pub fn block(&self) -> A::Ptr {
        self.block
    }

    /// The record length the module declared.
    pub fn maxlen(&self) -> u16 {
        self.maxlen
    }

    /// The record buffer the module may read into.
    pub fn data(&self) -> A::Ptr {
        self.data
    }

    /// The key buffer a search value is copied into.
    ///
    /// `PLBTVSTF.C:166` sizes it with `clckln()`, which is the longest key plus
    /// one. The buffer exists whether or not the module ever searches by key,
    /// because the real host allocated it in `opnbtv` and a module is entitled
    /// to find a pointer there.
    pub fn key(&self) -> A::Ptr {
        self.key
    }

    /// Where the file is positioned.
    pub fn cursor(&self) -> Cursor {
        self.cursor
    }

    /// Move the file to a new position.
    pub fn seek_to(&mut self, cursor: Cursor) {
        self.cursor = cursor;
    }

    /// The file's records, reading them if this is the first time.
    ///
    /// Both v5 and v6 files reach [`Records::read`](Records::read) the same
    /// way -- it dispatches on `geometry.version` internally
    /// (`docs/plans/2026-08-11-btrieve-v6-page-addressing.md`, Task 5).
    ///
    /// # Errors
    ///
    /// If the file cannot be read, holds a different number of records from
    /// the number its header claims, or -- v6 only -- its allocation table
    /// cannot be resolved (any refusal of [`v6::Map::read`]).
    pub fn records(&mut self) -> Result<&Records, BtvError> {
        if self.records.is_none() {
            self.records = Some(Records::read(
                &self.name,
                &self.path,
                &self.geometry,
                &self.keys,
            )?);
        }
        Ok(self.records.as_ref().expect("just read"))
    }

    /// The file's records, if they have been read.
    pub fn loaded(&self) -> Option<&Records> {
        self.records.as_ref()
    }

    /// Whether a write has happened since the index pages were last rebuilt.
    pub fn dirty(&self) -> bool {
        self.dirty
    }

    /// The record the cursor names, if it names one.
    pub fn current(&self) -> Option<&Record> {
        let records = self.records.as_ref()?;
        match self.cursor {
            Cursor::Nowhere => None,
            Cursor::Ordered { key, at } => records.ordered(key, at),
            Cursor::Physical { at } => records.physical(at),
        }
    }

    /// Add a record, choosing its slot and writing it.
    ///
    /// Returns the file position it went to, which is what `absbtv` would
    /// answer for it.
    ///
    /// In order: load the model, choose a slot from the model's own positions
    /// plus what is on disk, write the record to disk with the record count
    /// **after** the insert, then -- only once the write has succeeded -- add
    /// it to the model. A write that fails partway leaves the model agreeing
    /// with whatever is actually on disk, never with a slot nothing wrote.
    ///
    /// `bytes` is normalised to `self.geometry.reclen` before either of those
    /// happens -- see [`normalized`]. `dinsbtv` passes `bb->reclen`
    /// (`Self::maxlen`), the *module's* number, which is allowed to differ
    /// from the file's own `reclen`; without this, the model would hold the
    /// caller's buffer verbatim while `records::walk` always stores exactly
    /// `geometry.reclen` bytes, and the two would disagree the moment the
    /// cache is dropped and the file is read again.
    ///
    /// **Variable-length files refuse instead.** Normalising is right when
    /// `reclen` really is the length of every record; on a variable-length
    /// file it is not, and cutting a real record down to it is the same
    /// silent truncation [`Self::update`] already refuses for exactly this
    /// reason. See [`Self::update`]'s doc comment.
    ///
    /// `self.geometry` is updated last: `records` always grows by one, and
    /// `pages` grows by one only when the slot was a new page. Both fields are
    /// `Copy` and are what the next `Records::read` bounds its walk by, so
    /// leaving either stale here would make a later re-read of this same file
    /// -- after the cache is dropped -- silently wrong rather than merely
    /// inconvenient. See `a_block_that_writes_is_readable_after_its_cache_is_dropped`.
    ///
    /// # Errors
    ///
    /// If the records cannot be read, the file holds variable-length
    /// records, or the file cannot be written.
    pub fn insert(&mut self, bytes: &[u8]) -> Result<u32, BtvError> {
        self.records()?;
        self.writable()?;
        let name = self.name.clone();

        if self.geometry.variable {
            return Err(BtvError {
                file: name,
                why: format!(
                    "holds variable-length records up to {} bytes, and this host does \
                     not write them -- inserting this {}-byte buffer would silently \
                     truncate it to fit the file's own reclen, the same wrong answer \
                     update already refuses to give",
                    self.geometry.reclen,
                    bytes.len()
                ),
            });
        }

        let bytes = normalized(bytes, self.geometry.reclen);

        let layout = pages::Layout {
            page: self.geometry.page,
            physical: self.geometry.physical,
            pages: self.geometry.pages,
        };

        let (positions, count) = {
            let records = self.records.as_ref().expect("just loaded");
            (records.positions(), records.len() as u32 + 1)
        };
        let free = pages::free_head(&self.path).map_err(|why| BtvError {
            file: name.clone(),
            why,
        })?;
        let data = pages::data_pages(&self.path, layout).map_err(|why| BtvError {
            file: name.clone(),
            why,
        })?;
        let slot = layout.next_slot(&positions, free, &data);

        // The last point before this write actually changes anything -- see
        // `Self::capture_for_journal`'s doc comment for why it is taken here
        // rather than at the top of the function.
        self.capture_for_journal()?;

        pages::write_record(&self.path, layout, slot, &bytes, count).map_err(|why| BtvError {
            file: name.clone(),
            why,
        })?;

        let position = slot.position();
        self.records
            .as_mut()
            .expect("just loaded")
            .insert(&self.keys, position, bytes)
            .map_err(|why| BtvError {
                file: name.clone(),
                why,
            })?;

        self.geometry.records = count;
        if matches!(slot, pages::Slot::NewPage { .. }) {
            self.geometry.pages += 1;
        }
        self.dirty = true;

        Ok(position)
    }

    /// Replace the record at `position`.
    ///
    /// An update is in place: it neither adds a slot nor a page, so
    /// `self.geometry` is untouched. Existence is checked against the model
    /// **before** anything is written, because `position` is a module's word
    /// for a file offset and not a slot this layer chose -- writing to it
    /// unconditionally would let a module scribble over whatever bytes happen
    /// to be there, free-list link or otherwise.
    ///
    /// `bytes` must be exactly `self.geometry.reclen` long, refused rather
    /// than padded. [`Self::insert`] pads a short buffer with zero because
    /// there is nothing at a fresh slot to lose; an update writes over a
    /// record that already exists, and `pages::write_record` pads to
    /// `physical` unconditionally, so a short buffer here would silently
    /// zero-fill the tail of whatever was there. That is a live data-loss
    /// path once `dupdbtv` calls this.
    ///
    /// **Variable-length files refuse, whatever the buffer's length.** The
    /// four bytes between `reclen` and `physical` in such a file's slot are
    /// Btrieve's pointer to the record's first variable fragment, and
    /// `write_record` pads to `physical`, so any write here unlinks them. An
    /// earlier version refused only a buffer that was not `reclen` long, which
    /// misses the case that actually occurs: `Records::read` yields the fixed
    /// part alone, exactly `reclen` bytes, so a caller that reads a record and
    /// writes it back went straight through. Genuine Btrieve 6.15 then refused
    /// the whole of `WCCTEXT.VIR` with status 54 -- see
    /// [`an_update_of_a_variable_length_file_is_refused_rather_than_unlinking_its_fragments`].
    ///
    /// # Errors
    ///
    /// If the file holds variable-length records, `bytes` is not exactly
    /// `reclen` long, the records cannot be read, `position` holds no record,
    /// or the file cannot be written.
    pub fn update(&mut self, position: u32, bytes: &[u8]) -> Result<(), BtvError> {
        self.records()?;
        self.writable()?;
        let name = self.name.clone();

        if self.geometry.variable {
            let reclen = usize::from(self.geometry.reclen);

            // The one shape this host rewrites: a buffer with a body beyond
            // `reclen` (nothing to rewrite in place otherwise), at a position
            // the model already holds a record at. Everything else -- no
            // body, an unknown position, or a body
            // `variable::rewrite_fragment_in_place` itself refuses because the
            // page it names is not shaped for an in-place rewrite -- keeps
            // this host's refusal rather than guessing.
            let has_body = bytes.len().checked_sub(reclen).is_some_and(|n| n > 0);
            if has_body {
                let known = self
                    .records
                    .as_ref()
                    .expect("just loaded")
                    .find_physical(position)
                    .is_some();
                if known {
                    self.capture_for_journal()?;
                    return match self.rewrite_variable(position, bytes) {
                        Ok(()) => {
                            self.records
                                .as_mut()
                                .expect("just loaded")
                                .update(&self.keys, position, bytes.to_vec())
                                .map_err(|why| BtvError { file: name, why })?;
                            self.dirty = true;
                            Ok(())
                        }
                        Err(why) => Err(BtvError { file: name, why }),
                    };
                }
            }

            return Err(BtvError {
                file: name,
                why: format!(
                    "holds variable-length records up to {} bytes, and this host does \
                     not write them -- writing this {}-byte buffer would pad the slot \
                     out to its {} physical bytes and zero the pointer to the record's \
                     variable part, unlinking the fragment chain the rest of the file \
                     is threaded on",
                    self.geometry.reclen,
                    bytes.len(),
                    self.geometry.physical
                ),
            });
        }

        if bytes.len() != usize::from(self.geometry.reclen) {
            return Err(BtvError {
                file: name,
                why: format!(
                    "a {}-byte record for a {}-byte slot -- update refuses rather than \
                     zero-fill the tail of whatever was there",
                    bytes.len(),
                    self.geometry.reclen
                ),
            });
        }

        let records = self.records.as_ref().expect("just loaded");
        if records.find_physical(position).is_none() {
            return Err(BtvError {
                file: name,
                why: format!("position {position} holds no record"),
            });
        }
        let count = records.len() as u32;

        let layout = pages::Layout {
            page: self.geometry.page,
            physical: self.geometry.physical,
            pages: self.geometry.pages,
        };
        self.capture_for_journal()?;
        pages::write_record(&self.path, layout, pages::Slot::Existing(position), bytes, count)
            .map_err(|why| BtvError {
                file: name.clone(),
                why,
            })?;

        self.records
            .as_mut()
            .expect("just loaded")
            .update(&self.keys, position, bytes.to_vec())
            .map_err(|why| BtvError { file: name, why })?;

        self.dirty = true;

        Ok(())
    }

    /// Rewrite a variable-length record's fragment in place, and its fixed
    /// part alongside it, in that order.
    ///
    /// The fragment first: [`variable::rewrite_fragment_in_place`] does its
    /// own validation before it writes a byte, so if the file's shape does
    /// not match, this returns before the data page's slot has been touched
    /// at all. The fixed part is written from `bytes[..reclen]`; the four
    /// bytes of pointer behind it, and anything past those up to `physical`,
    /// are read off disk and written straight back -- this can never be the
    /// write that zeros the pointer [`Self::update`]'s blanket refusal exists
    /// to prevent, because it never puts anything there but what was already
    /// there.
    ///
    /// `bytes` is assumed to be at least `reclen + 1` long and `position` to
    /// already hold a record -- both are the caller's job, checked in
    /// [`Self::update`] before this is reached.
    ///
    /// # Errors
    ///
    /// If the slot cannot be read, [`variable::rewrite_fragment_in_place`]
    /// refuses the fragment's shape, or the slot cannot be written back.
    fn rewrite_variable(&self, position: u32, bytes: &[u8]) -> Result<(), String> {
        use std::io::{Read, Seek, SeekFrom};

        let reclen = usize::from(self.geometry.reclen);
        let physical = usize::from(self.geometry.physical);

        let mut slot = vec![0u8; physical];
        {
            let mut file = std::fs::File::open(&self.path)
                .map_err(|e| format!("{}: {e}", self.path.display()))?;
            file.seek(SeekFrom::Start(u64::from(position)))
                .and_then(|_| file.read_exact(&mut slot))
                .map_err(|e| {
                    format!("{}: reading position {position}: {e}", self.path.display())
                })?;
        }

        let pointer =
            variable::Pointer::decode([slot[reclen], slot[reclen + 1], slot[reclen + 2], slot[reclen + 3]]);

        let mut pages = variable::FilePages::new(&self.path, self.geometry.page, self.geometry.pages);
        variable::rewrite_fragment_in_place(
            &mut pages,
            self.geometry.version,
            pointer,
            &bytes[reclen..],
        )?;

        slot[..reclen].copy_from_slice(&bytes[..reclen]);

        let layout = pages::Layout {
            page: self.geometry.page,
            physical: self.geometry.physical,
            pages: self.geometry.pages,
        };
        let count = self
            .records
            .as_ref()
            .expect("checked by Self::update before this is called")
            .len() as u32;
        pages::write_record(&self.path, layout, pages::Slot::Existing(position), &slot, count)
    }

    /// Remove the record at `position`, as `delbtv` (Btrieve operation 4)
    /// does: take it out of the in-memory model and splice its slot onto the
    /// head of the file's own free list on disk.
    ///
    /// Existence is checked against the model **before** anything is
    /// written, the same reason [`Self::update`] checks first: `position` is
    /// a module's word for a file offset, not a slot this layer chose, and
    /// deleting whatever happens to sit at an unverified offset would erase
    /// bytes that were never a record at all.
    ///
    /// **Variable-length files refuse, for the same reason [`Self::update`]
    /// already refuses to write one.** A variable-length record's fragment
    /// lives on a separate page, reached through the four-byte pointer
    /// between `reclen` and `physical` in its slot (see [`Self::update`]'s
    /// doc comment and [`Self::rewrite_variable`]). Deleting the slot without
    /// also freeing that fragment page would leak it forever; deleting the
    /// fragment page too is a real feature this host has not measured or
    /// implemented. Measured (`tools/btrieve-oracle/delprobe.c`,
    /// `docs/delete-oracle-answer.md`): a genuine delete of a variable-length
    /// record succeeds at the API level (status 0) on the real engine, but
    /// what it does to the fragment chain was not traced byte-for-byte, so
    /// this host refuses rather than guess -- the identical precedent
    /// [`Self::update`]'s own doc comment sets for the same shape of file.
    ///
    /// Measured against the real engine, on a copy of the real, shipped
    /// `WCCCLASS.DAT` (fixed-length, no confounding shadow-paged or
    /// freshly-`B_CREATE`d artifacts -- see `docs/delete-oracle-answer.md`
    /// for why that file was chosen over a synthetic fixture): deleting the
    /// record at file offset 3843 left the file control record's free-list
    /// head ([`pages::fcr::FREE`]) holding exactly 3843, the deleted slot's
    /// own first four bytes holding `0x16ce` -- the free-list head's value
    /// **before** this delete, now a forwarding link -- and every byte behind
    /// that zero. The record count dropped by one and both changes persisted
    /// across a close and reopen. A later insert was measured to land back
    /// at offset 3843, reusing the freed slot, with the free-list head
    /// advancing to `0x16ce` -- confirming [`pages::Layout::next_slot`]'s
    /// `Slot::Free` reuse from the write side, not only the read side it
    /// already assumed. See [`pages::delete_record`] for the on-disk half.
    ///
    /// Also measured: a second `B_DELETE` with no repositioning in between,
    /// and a `B_DELETE` with no position established at all, both gave
    /// status 8 ("invalid positioning") -- the same status either way,
    /// because a delete consumes the position exactly as fully as never
    /// having one. This host gives the equivalent refusal by requiring
    /// `position` to still name a record in the model; nothing here tracks
    /// "the position a delete just consumed" as a distinct state, because the
    /// model already stops naming that position the moment this call
    /// succeeds -- a caller that calls `delete` again with the same
    /// `position` hits the "holds no record" refusal below, the same
    /// observable the real engine's status 8 gives.
    ///
    /// # Errors
    ///
    /// If the records cannot be read, the file holds variable-length
    /// records, `position` holds no record, or the file cannot be written.
    pub fn delete(&mut self, position: u32) -> Result<(), BtvError> {
        self.records()?;
        self.writable()?;
        let name = self.name.clone();

        if self.geometry.variable {
            return Err(BtvError {
                file: name,
                why: format!(
                    "holds variable-length records up to {} bytes, and this host does \
                     not delete them -- a variable-length record's fragment lives on a \
                     separate page reached through the pointer behind its fixed part, \
                     and this host has not measured or implemented freeing that page, \
                     the same reasoning `Self::update` already gives for refusing to \
                     write this shape of file",
                    self.geometry.reclen
                ),
            });
        }

        let records = self.records.as_ref().expect("just loaded");
        if records.find_physical(position).is_none() {
            return Err(BtvError {
                file: name,
                why: format!("position {position} holds no record"),
            });
        }
        let count = records.len() as u32 - 1;

        let layout = pages::Layout {
            page: self.geometry.page,
            physical: self.geometry.physical,
            pages: self.geometry.pages,
        };

        // The last point before this write actually changes anything -- see
        // `Self::capture_for_journal`'s doc comment for why it is taken here
        // rather than at the top of the function.
        self.capture_for_journal()?;

        pages::delete_record(&self.path, layout, position, count).map_err(|why| BtvError {
            file: name.clone(),
            why,
        })?;

        self.records
            .as_mut()
            .expect("just loaded")
            .delete(&self.keys, position)
            .map_err(|why| BtvError { file: name, why })?;

        self.geometry.records = count;
        self.dirty = true;

        Ok(())
    }

    /// Rebuild every key's leaf index page from the records already in memory,
    /// in that key's order, and update the file control record's per-key
    /// record count to match.
    ///
    /// The host never reads these pages back -- `records()` page-walks and
    /// sorts, which is [`keys`]'s whole design. But a file this host wrote is
    /// a file a real Btrieve, or MBBSEmu, could later open, and an index that
    /// disagrees with the data behind it is exactly the silent corruption this
    /// crate refuses to produce anywhere else. `clsbtv` calls this when
    /// [`Self::dirty`] is set, which is the flush point the design names.
    ///
    /// # Errors
    ///
    /// If the records have never been loaded, a key's root page is `0` or
    /// outside the file (see [`Key::definition`]), a key's tree cannot be
    /// walked, or no entry fits a page, or the file cannot be written.
    pub fn reindex(&mut self) -> Result<(), BtvError> {
        let name = self.name.clone();
        let fail = |why: String| BtvError {
            file: name.clone(),
            why,
        };

        let records = self.records.as_ref().ok_or_else(|| {
            fail("reindex called before the records were loaded".to_owned())
        })?;

        // A key's `offset` is measured from the physical slot, and a v6
        // record's bytes start two bytes into it -- so every key read below
        // has to be padded the same way `Records`' own sort does. Taken once
        // here rather than through `Records::keyed`, which this loop cannot
        // reach: `records` is borrowed immutably for its whole body.
        let shift = records.key_shift();

        let layout = pages::Layout {
            page: self.geometry.page,
            physical: self.geometry.physical,
            pages: self.geometry.pages,
        };

        // Just the first page: every field this touches -- the key
        // definitions and their record counts -- lives well inside it (see
        // `fcr::KEYS`), and reading the whole file to reindex an 80 MB one
        // would defeat the point of writing one page at a time.
        let mut fcr = read_head(&self.path, usize::from(self.geometry.page)).map_err(|e| {
            fail(format!("{}: {e}", self.path.display()))
        })?;

        // The file may grow while reindexing, and every page number written
        // below is checked against how big it is *now*.
        let mut total = self.geometry.pages;

        for key in &self.keys {
            // `unwrap_or(0)` would treat a key number `Records` was never
            // built with the same as a key with no records, and write an
            // empty leaf over its root instead of saying it does not know
            // the key. This crate refuses to guess; refuse here too.
            let len = records.ordered_len(key.number).ok_or_else(|| {
                fail(format!(
                    "key {}: not among the keys the loaded records were ordered by",
                    key.number
                ))
            })?;
            // One entry per distinct key value, and for a key that permits
            // duplicates that is fewer than `len`. Grouped with `key.compare`
            // -- the same comparator `Records::reindex` sorted by, so the
            // group boundaries cannot disagree with the order they fall in --
            // rather than by comparing the extracted key bytes, which would
            // split a group whenever a key folds two spellings of a value onto
            // one (an alternate collating sequence, or a case-insensitive
            // name). Btrieve's own index holds one entry per *value*, and two
            // entries a binary search cannot tell apart is a tree that reads
            // back in a plausible wrong order.
            let mut entries: Vec<pages::Entry> = Vec::new();
            let mut groups: Vec<Vec<u32>> = Vec::new();
            for n in 0..len {
                let record = records.ordered(key.number, n).expect("in range");
                let joins = n > 0
                    && key.compare(
                        &records::keyed(
                            shift,
                            &records.ordered(key.number, n - 1).expect("in range").bytes,
                        ),
                        &records::keyed(shift, &record.bytes),
                    ) == std::cmp::Ordering::Equal;
                if joins && key.duplicates {
                    let last = entries.last_mut().expect("a group to join");
                    last.tail = record.position;
                    groups.last_mut().expect("a group to join").push(record.position);
                } else {
                    entries.push(pages::Entry::unique(
                        key.extract(&records::keyed(shift, &record.bytes)),
                        record.position,
                    ));
                    groups.push(vec![record.position]);
                }
            }

            // The chain that joins each group, written into the records
            // themselves. Every record of a duplicate-permitting key carries
            // one, including a value only one record holds: its pair is
            // `[NOWHERE, NOWHERE]`, and leaving it as the zeros
            // `write_record` pads a fresh slot with would name page 0 -- the
            // file control record -- as the next record in the chain.
            if key.duplicates {
                let offset = usize::from(key.chain.ok_or_else(|| {
                    fail(format!(
                        "key {}: permits duplicates and its definition names no \
                         chain offset, so there is nowhere to write one",
                        key.number
                    ))
                })?);
                for group in &groups {
                    for (at, position) in group.iter().enumerate() {
                        let chain = [
                            if at == 0 { pages::NOWHERE } else { group[at - 1] },
                            if at + 1 == group.len() {
                                pages::NOWHERE
                            } else {
                                group[at + 1]
                            },
                        ];
                        pages::write_chain(&self.path, layout, *position, offset, chain)
                            .map_err(|why| fail(format!("key {}: {why}", key.number)))?;
                    }
                }
            }

            // `key.definition`, not `key.number`: a multi-segment key's root
            // and record count live at its *first* definition, and the two
            // indices only coincide when no earlier key has more than one
            // segment. See [`Key::definition`].
            let definition = pages::fcr::KEYS + usize::from(key.definition) * pages::fcr::KEY_WIDTH;
            let root_at = definition + pages::fcr::KEY_ROOT;
            let root = pages::long(&fcr[root_at..root_at + 4]);

            // Page 0 is the file control record, never a key's root, and a
            // root has to name a page the file actually has. Refused
            // regardless of whether `key.definition` above is right: this is
            // the guard that stands even if it is subtly wrong, and it is
            // what stops a continuation definition's meaningless root field
            // (measured as `0` off the shipped files) from writing a page
            // over the file control record.
            if root == 0 || root >= total {
                return Err(fail(format!(
                    "key {}: root page {root} is not inside a {total}-page file",
                    key.number
                )));
            }

            let layout = pages::Layout { pages: total, ..layout };
            let shape = key.shape();

            // What the key's index occupies now. Rebuilding into these same
            // numbers is what keeps a file from growing by a whole index every
            // time it is closed, and it keeps `KEY_ROOT` correct without
            // rewriting it -- `number_pages` puts the root on `owned[0]`.
            let owned = pages::walk(&self.path, layout, root, shape)
                .map_err(|why| fail(format!("key {}: {why}", key.number)))?
                .pages;

            let built = pages::build_index(layout, &entries, shape)
                .map_err(|why| fail(format!("key {}: {why}", key.number)))?;

            // Grow only if the new tree needs more pages than the old one had.
            // Surplus pages are left where they are: there is no sample of page
            // reclamation in any shipped file, and inventing one would write a
            // structure a real Btrieve reads and this host guessed at. See
            // `docs/plans/2026-08-07-btrieve-interior-pages-design.md`.
            let grown_before = total;
            let mut numbers = owned;
            while numbers.len() < built.nodes.len() {
                let number = pages::append_page(&self.path, pages::Layout { pages: total, ..layout })
                    .map_err(|why| fail(format!("key {}: {why}", key.number)))?;
                numbers.push(number);
                total += 1;
            }
            let layout = pages::Layout { pages: total, ..layout };

            for (number, mut image) in pages::number_pages(&built, &numbers)
                .map_err(|why| fail(format!("key {}: {why}", key.number)))?
            {
                // `Header::stamp`'s doc comment says the stamp is preserved
                // rather than interpreted, and preserving it means reading it
                // before it is gone. A page this reindex just appended has no
                // stamp to preserve, and reading it back would cost a seek to
                // learn zero -- `grown_before` is the boundary between the two.
                if number < grown_before {
                    let existing = pages::page_header(&self.path, layout, number)
                        .map_err(|why| fail(format!("key {}: {why}", key.number)))?;
                    let mut header = pages::Header::decode(&image[..6]);
                    header.stamp = existing.stamp;
                    image[..6].copy_from_slice(&header.encode());
                }

                pages::write_page(&self.path, layout, number, &image)
                    .map_err(|why| fail(format!("key {}: {why}", key.number)))?;
            }

            let count = u32::try_from(entries.len())
                .map_err(|_| fail(format!("key {}: more than four billion entries", key.number)))?;
            let records_at = definition + pages::fcr::KEY_RECORDS;
            fcr[records_at..records_at + 4].copy_from_slice(&pages::to_long(count));
        }

        // The page count, if this reindex grew the file. `HIGHEST` is the
        // highest page number, one less than the count -- the same relation
        // `Layout::stamp` maintains when a data page is appended.
        if total != self.geometry.pages {
            fcr[pages::fcr::PAGES..pages::fcr::PAGES + 4].copy_from_slice(&pages::to_long(total));
            let highest = u16::try_from(total - 1)
                .map_err(|_| fail("a file of more than 65,535 pages".to_owned()))?;
            fcr[pages::fcr::HIGHEST..pages::fcr::HIGHEST + 2]
                .copy_from_slice(&highest.to_le_bytes());
            self.geometry.pages = total;
        }

        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&self.path)
            .map_err(|e| fail(format!("{}: {e}", self.path.display())))?;
        file.seek(SeekFrom::Start(0))
            .and_then(|_| file.write_all(&fcr))
            .map_err(|e| {
                fail(format!(
                    "{}: writing the file control record: {e}",
                    self.path.display()
                ))
            })?;

        self.dirty = false;
        Ok(())
    }
}

/// Every Btrieve file the host has open, and the stack of which is current.
///
/// The current file is **not** here. It is `bb`, a host global living in module
/// memory (`BTVSTF.H:36`), read back out of there every time -- the same rule
/// `curmbk` and `prfptr` are under. What is here is the stack behind it, which
/// `PLBTVSTF.C` keeps in a `static` the module cannot see either.
///
/// # Generic (over `A: Abi`), as of this task
///
/// `open: Vec<Block<A>>` and `stack: [A::Ptr; BBSTSZ]` -- every pointer this
/// type keeps is a module address, and the module's own ABI decides its
/// shape. `A` defaults to [`Wg16`], the same convention every other generic
/// type in this crate uses, so every existing caller keeps naming this type
/// as plain `Btrieve`. `crate::lib::Host<A>::btrieve` still names it without
/// `<A>` (bare `btrieve::Btrieve`, i.e. `Btrieve<Wg16>` through that default)
/// -- widening it to `Btrieve<A>` is the one remaining step, and it is in
/// `crates/mbbs/src/lib.rs`, a file this task does not own; see this crate's
/// own worklog for the exact edit.
pub struct Btrieve<A: Abi> {
    open: Vec<Block<A>>,

    /// `bbstk`: what `rstbtv` will restore, nearest first. Fixed at ten and
    /// **shifting**, which is not an implementation detail -- see [`Self::set`].
    stack: [A::Ptr; BBSTSZ],

    /// `bbomode`: the mode the next `opnbtv` opens in. `PRIMBV`, which is zero,
    /// until `omdbtv` says otherwise.
    mode: i16,

    /// Whether a transaction begun by [`Self::begin`] is in progress.
    ///
    /// Btrieve ops 19/20/21 (`dfaBegTrans`/`dfaEndTrans`/`dfaAbtTrans`) take
    /// no file argument at all -- `DFAAPI.C:206,214,222` calls
    /// `btvu(19+loktyp,NULL,NULL,0,0)`, `btvu(21,NULL,NULL,0,0)` and
    /// `btvu(20,NULL,NULL,0,0)` -- so the transaction is a property of the
    /// whole session, not of any one [`Block`], and belongs on `Btrieve`
    /// rather than on a `Block`. Each `Block` additionally carries its own
    /// `txn_active`/`pre_image` (see [`Block`]'s doc comments) because the
    /// frozen shim call sites reach a block's `insert`/`update` directly, with
    /// no way to pass this flag through -- this field is what tells
    /// [`Self::begin`]/[`Self::open`] to set that per-block flag, and
    /// [`Self::end`]/[`Self::abort`] to clear it everywhere.
    transaction: bool,

    /// This session's Btrieve locks -- see [`ops::LockTable`]'s own doc
    /// comment for why this lives here (on the session) rather than on any
    /// one [`Block`].
    locks: ops::LockTable,
}

impl<A: Abi> Default for Btrieve<A> {
    /// Nothing open, nothing stacked, and `PRIMBV`.
    ///
    /// Ten null pointers rather than an empty vector, because that is what
    /// `static struct btvblk *bbstk[BBSTSZ]` is and what makes `rstbtv` past
    /// the bottom yield null instead of nothing.
    ///
    /// Not `#[derive(Default)]`: the derive macro bounds `A: Default` on the
    /// generated impl, which the bare marker struct [`Wg16`] does not satisfy
    /// -- the same problem `crates/mbbs/src/abi.rs`'s `Ret<A>` and
    /// `crates/mbbs/src/msg.rs`'s `Messages<A>` hit, and the same fix.
    fn default() -> Self {
        Self {
            open: Vec::new(),
            stack: [A::null_ptr(); BBSTSZ],
            mode: 0,
            transaction: false,
            locks: ops::LockTable::default(),
        }
    }
}

impl<A: Abi> Btrieve<A> {
    /// Open a file, and give the module a `struct btvblk` to name it by.
    ///
    /// The block is real memory from the module's own heap, laid out as
    /// `BTVSTF.H` declares it, with the fields the host knows filled in and the
    /// rest -- Btrieve's position block above all -- zeroed. A module that reads
    /// `bb->reclen` gets its record length; one that reads the position block
    /// gets zeros rather than a fault.
    ///
    /// This does **not** make the file current. `opnbtv` does that, separately
    /// and for a reason that is worth reading in
    /// [`shims::btrieve::opnbtv`](crate::shims::btrieve::opnbtv).
    ///
    /// Takes `mem: &mut A::Mem` rather than a whole machine -- the same
    /// generic-core shape [`crate::heap::Heap::reserve`] and
    /// [`crate::msg::Messages::open_mem`] already use. `heap` allocates
    /// through [`Heap::reserve`](crate::heap::Heap::reserve), the generic
    /// core behind [`Heap::alloc`](crate::heap::Heap::alloc)'s `Wg16` facade,
    /// so this needs no facade of its own.
    ///
    /// # Errors
    ///
    /// If the file's key definitions cannot be read, or the heap has no room
    /// for the block, its name, its record buffer or its key buffer.
    pub fn open(
        &mut self,
        mem: &mut A::Mem,
        heap: &mut crate::Heap<A>,
        name: &str,
        path: &Path,
        geometry: Geometry,
        maxlen: u16,
    ) -> Result<A::Ptr, String> {
        // The key definitions come out of the same first page the geometry did,
        // and they are read at open time rather than with the records because
        // `clckln()` -- which sizes the key buffer below -- is part of what
        // `opnbtv` does. A file whose keys cannot be read is refused here, not
        // at whatever much later moment something first searches by one.
        let fcr = read_head(path, FCR).map_err(|e| format!("{}: {e}", path.display()))?;
        let parsed = keys::parse(name, &fcr, geometry.keys).map_err(|e| e.why)?;

        // `PLBTVSTF.C:148` -- `bb->filnam=alcmem(strlen(filnam)+1)`. The
        // module's, not the host's: `clsbtv` frees it.
        let bytes = name.as_bytes();
        let filnam = heap.reserve(mem, bytes.len() as u16 + 1)?;
        let mut terminated = bytes.to_vec();
        terminated.push(0);
        filnam.write(mem, &terminated).map_err(|e| e.to_string())?;

        let data = heap.reserve(mem, maxlen)?;
        data.write(mem, &vec![0u8; usize::from(maxlen)])
            .map_err(|e| e.to_string())?;

        // `clckln()` returns the longest key plus one, and that is what the
        // real host allocated. Plus one because a Btrieve key buffer for a
        // string key holds a terminator the key length does not count.
        let longest = parsed.iter().map(Key::length).max().unwrap_or(0);
        let key = heap.reserve(mem, longest + 1)?;
        key.write(mem, &vec![0u8; usize::from(longest) + 1])
            .map_err(|e| e.to_string())?;

        let block = heap.reserve(mem, field::SIZE)?;
        let mut image = vec![0u8; usize::from(field::SIZE)];
        let put = |image: &mut Vec<u8>, offset: u16, bytes: &[u8]| {
            let at = usize::from(offset);
            image[at..at + bytes.len()].copy_from_slice(bytes);
        };
        put(&mut image, field::FILNAM, &A::ptr_to_bytes(filnam));
        put(&mut image, field::RECLEN, &maxlen.to_le_bytes());
        put(&mut image, field::DATA, &A::ptr_to_bytes(data));
        put(&mut image, field::KEY, &A::ptr_to_bytes(key));

        // `bb->keylns[n]`, which `clckln()` fills in and which `qrybtv` and the
        // acquire family read to know how many bytes of the module's buffer are
        // the key. Every one this host knows is written; the rest stay zero.
        for definition in &parsed {
            let at = field::KEYLNS + definition.number * 2;
            if at + 2 <= field::REALSEG {
                put(&mut image, at, &definition.length().to_le_bytes());
            }
        }
        block.write(mem, &image).map_err(|e| e.to_string())?;

        self.open.push(Block {
            id: ops::BlockId::fresh(),
            name: name.to_owned(),
            path: path.to_owned(),
            geometry,
            keys: parsed,
            block,
            maxlen,
            data,
            key,
            records: None,
            cursor: Cursor::Nowhere,
            dirty: false,
            // A file opened while a transaction is in progress is covered by
            // it too -- `dfaBegTrans` has no per-file scope (see this
            // module's `Btrieve::begin` doc comment), so a module that opens
            // a new file mid-transaction and writes to it gets that write
            // rolled back on abort the same as one opened before `begin`.
            txn_active: self.transaction,
            pre_image: None,
        });
        Ok(block)
    }

    /// Push what is current and make `block` current, as `setbtv` does.
    ///
    /// `PLBTVSTF.C:227`, and every word of it is load-bearing:
    ///
    ///
    /// A **shifting** stack ten deep, not an indexed one. So an eleventh nested
    /// `setbtv` does not overflow -- it silently drops the *oldest* entry, and
    /// the module never finds out. That is reproduced here rather than refused,
    /// because the real host's behaviour is defined and modules were built
    /// against it; `rstbtv` has 176 call sites in `WCCMMUD.DLL` against
    /// `setbtv`'s 148, and a host that refused where the original did not would
    /// stop a module that was working as designed.
    ///
    /// What is different is that the dropped entry is *reported*. Returns the
    /// name of the file that fell off the bottom, if one did.
    ///
    /// Only the stack is touched. `bb` itself is written by the caller, because
    /// `bb` is in module memory and this type deliberately keeps no copy of it.
    pub fn set(&mut self, current: A::Ptr) -> Option<String> {
        let dropped = self.stack[BBSTSZ - 1];
        self.stack.copy_within(0..BBSTSZ - 1, 1);
        self.stack[0] = current;
        if dropped == A::null_ptr() {
            return None;
        }
        Some(match self.find(dropped) {
            Ok(at) => self.open[at].name.clone(),
            Err(_) => format!("{dropped:?}"),
        })
    }

    /// What was current before the last `setbtv`, as `rstbtv` restores it.
    ///
    /// `PLBTVSTF.C:236`:
    ///
    ///
    /// **An empty stack is not an error.** It restores `bbstk[0]`, which starts
    /// null, and every routine in `PLBTVSTF.C` opens by checking `bb == NULL`
    /// and returning quietly -- so a module that unbalances its `rstbtv` calls
    /// was designed to get null, not a refusal. `rstmbk` refuses on underflow
    /// and the module never hit it; here the gap between the call-site counts
    /// is 28 and the original's answer is documented, so the original's answer
    /// is what this gives.
    ///
    /// Returns what to put in `bb`, and whether the stack was empty.
    pub fn restore(&mut self) -> (A::Ptr, bool) {
        let restored = self.stack[0];
        self.stack.copy_within(1..BBSTSZ, 0);
        (restored, restored == A::null_ptr())
    }

    /// The null `struct btvblk *`.
    pub fn null() -> A::Ptr {
        A::null_ptr()
    }

    /// The mode the next `opnbtv` will use.
    pub fn mode(&self) -> i16 {
        self.mode
    }

    /// Set the mode the next `opnbtv` will use, as `omdbtv` does.
    pub fn set_mode(&mut self, mode: i16) {
        self.mode = mode;
    }

    /// Begin a transaction, as `dfaBegTrans` (Btrieve op `19+loktyp`) does.
    ///
    /// `loktyp` (`WAITBV`/`NOWTBV`, `DFAAPI.H:36-37`) is not a parameter
    /// here: measured against the real engine with a single client
    /// (`tools/btrieve-oracle/xactprobe.c`'s `loktyp` scenario), `begin` then
    /// `end` with each value in turn gave `status=0` both times, with no
    /// observable difference -- unsurprising, since a wait-or-not bias only
    /// has anything to wait *for* when a second client is holding a
    /// conflicting lock, and this host is single-process and
    /// single-threaded by construction. Task 7's marshalling can take the
    /// argument and drop it, with this comment as the record of why.
    ///
    /// Every write made through [`Block::insert`]/[`Block::update`] after
    /// this call, on any file open now or opened later while it is still in
    /// progress, is covered: [`Self::abort`] can undo it, [`Self::end`]
    /// keeps it. Writes already made **before** this call are not covered --
    /// there is nothing before `begin` for a pre-image to be *of*.
    ///
    /// # Errors
    ///
    /// [`TransactionError::AlreadyActive`] if a transaction is already open.
    /// Measured, not assumed: `xactprobe`'s `nested` scenario opens one,
    /// begins a second without ending the first, and the real engine
    /// refuses it (`nested: inner begin status=37`) rather than accepting it
    /// silently or stacking it -- the first transaction's own single
    /// `abort` closes it (`nested: abort status=0`), and a *second* abort
    /// right after finds nothing open (`nested: second abort status=39`,
    /// the same status [`Self::end`]/[`Self::abort`] give with no `begin` at
    /// all). So Btrieve transactions do not nest, and this does not either.
    pub fn begin(&mut self) -> Result<(), TransactionError> {
        if self.transaction {
            return Err(TransactionError::AlreadyActive);
        }
        self.transaction = true;
        for block in &mut self.open {
            block.txn_active = true;
            block.pre_image = None;
        }
        Ok(())
    }

    /// End a transaction, as `dfaEndTrans` (Btrieve op 20) does: keep every
    /// write made since [`Self::begin`], and discard the pre-images that
    /// would have undone them.
    ///
    /// **Writes are already visible before this is called.** Measured
    /// (`xactprobe`'s `visibility` scenario): a `GET_EQUAL` for a record
    /// inserted earlier in the same transaction found it, tag and all,
    /// before `dfaEndTrans` was ever reached (`get-inside-txn status=0 (OK)
    /// tag=aa`), and it was still there after a close and reopen
    /// (`get-after-close-reopen status=0 (OK) tag=aa`). So this host's
    /// `Block::insert`/`Block::update` already write straight through, live,
    /// the same as the real engine -- there is no buffered write for `end`
    /// to flush. All it does is stop tracking pre-images, which matches: a
    /// failing op inside a transaction does not implicitly end or abort it
    /// either (`xactprobe`'s `fail_inside`: a duplicate-key insert returned
    /// status 5, and every op after it -- including the eventual `end` --
    /// still succeeded, and both the surviving insert and the one after the
    /// failure were there on reopen).
    ///
    /// # Errors
    ///
    /// [`TransactionError::NoneActive`] if no transaction is open. Measured:
    /// `xactprobe`'s `end_no_begin` scenario calls `dfaEndTrans` on a freshly
    /// opened file with no `dfaBegTrans` first, and the real engine refuses
    /// it (`end_no_begin: status=39`) rather than treating it as a no-op.
    pub fn end(&mut self) -> Result<(), TransactionError> {
        if !self.transaction {
            return Err(TransactionError::NoneActive);
        }
        self.transaction = false;
        for block in &mut self.open {
            block.txn_active = false;
            block.pre_image = None;
        }
        Ok(())
    }

    /// Abort a transaction, as `dfaAbtTrans` (Btrieve op 21) does: undo
    /// every write made since [`Self::begin`], on every file that has one.
    ///
    /// Measured against the real engine (`xactprobe`'s `abort_insert`,
    /// `abort_update` and `abort_delete` scenarios), an insert, an update and
    /// a delete made inside a transaction are all rolled back by abort, both
    /// within the same session (`get-after-abort-same-session`) and after a
    /// close and reopen (`get-after-close-reopen`) -- so this restores the
    /// file to disk, not only the in-memory model.
    ///
    /// A block with no [`Block::pre_image`] (nothing was written to it this
    /// transaction) is untouched -- there is nothing to undo, and reading it
    /// back off disk to overwrite it with itself would be pointless I/O for
    /// every file a module merely holds open. A block whose pre-image
    /// belongs to a file that has since been closed cannot be restored --
    /// [`Self::close`] refuses to close a block with one outstanding rather
    /// than let this silently happen; see its doc comment.
    ///
    /// # Errors
    ///
    /// [`TransactionError::NoneActive`] if no transaction is open. Measured
    /// the same way [`Self::end`]'s is: `xactprobe`'s `abort_no_begin`
    /// scenario gives `abort_no_begin: status=39`, the same status as
    /// `end_no_begin` and as a second `dfaAbtTrans` right after a first one
    /// already closed the transaction.
    ///
    /// If a pre-image cannot be written back to disk, the block it belongs to
    /// is left with that pre-image still attached rather than half-restored
    /// -- a later retry can still find it -- and every other block's restore
    /// still runs; one file's disk error should not strand every other
    /// file's rollback.
    pub fn abort(&mut self) -> Result<(), TransactionError> {
        if !self.transaction {
            return Err(TransactionError::NoneActive);
        }
        self.transaction = false;
        for block in &mut self.open {
            block.txn_active = false;
            let Some(pre) = block.pre_image.take() else {
                continue;
            };
            if std::fs::write(&block.path, &pre.bytes).is_err() {
                // Restoring the model without the disk write succeeding
                // would make the two disagree in a way a fresh read could
                // not even detect, since the next read of this file would
                // see the *unrestored* disk bytes. Leave both, and the
                // pre-image, exactly as they were so nothing here claims a
                // rollback that did not happen.
                block.pre_image = Some(pre);
                continue;
            }
            block.records = pre.records;
            block.geometry = pre.geometry;
            block.dirty = pre.dirty;
        }
        Ok(())
    }

    /// The block a module's pointer names.
    ///
    /// # Errors
    ///
    /// If it names no open file.
    pub fn block(&self, at: A::Ptr) -> Result<&Block<A>, String> {
        Ok(&self.open[self.find(at)?])
    }

    /// The block a module's pointer names, to be read from or positioned.
    ///
    /// # Errors
    ///
    /// If it names no open file.
    pub fn block_mut(&mut self, at: A::Ptr) -> Result<&mut Block<A>, String> {
        let index = self.find(at)?;
        Ok(&mut self.open[index])
    }

    /// How many files are open.
    pub fn len(&self) -> usize {
        self.open.len()
    }

    /// Whether no file is open.
    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }

    /// Every open file, in the order they were opened.
    pub fn files(&self) -> &[Block<A>] {
        &self.open
    }

    /// Close `at`, as everything in `PLBTVSTF.C:632` *after* `bb=bbp` does.
    ///
    ///
    /// `bb=bbp` is [`shims::btrieve::clsbtv`](crate::shims::btrieve::clsbtv)'s
    /// job, not this one's -- `bb` is a module global this type does not
    /// touch, and it has to be written whether or not anything below finds a
    /// file to close. What is here is the guard and everything behind it.
    ///
    /// Returns whether `at` named an open file. `false` is not an error: it
    /// is what a second `clsbtv` of the same block answers, and what a
    /// pointer that was never opened answers too -- `PLBTVSTF.C` could not
    /// tell those two apart either.
    ///
    /// # The guard is `at` in [`Self::open`], not `bb->filnam` in module memory
    ///
    /// `PLBTVSTF.C` measures `bb->filnam != NULL`, and an earlier version of
    /// this measured it the same way: four bytes at `at`'s own
    /// `field::FILNAM`, on the theory that the first close nulls them before
    /// it frees anything and a second read of the same address would still
    /// find them null. That theory holds only until something else
    /// allocates over the span -- [`Heap::free`](crate::Heap::free) never
    /// clears what it frees (see its own doc comment), so those four bytes
    /// are only reliably null until a later, unrelated `alcmem` reuses that
    /// memory for something with a non-null value in the same position, at
    /// which point a *second* close of an already-closed block reads
    /// garbage that looks like an open file and fails looking it up in
    /// [`Self::open`] -- a module bug in disguise, not a refusal this crate
    /// intends. `self.open` is the authoritative record of what is actually
    /// open, and asking it directly cannot be fooled by whatever the heap
    /// has done with the memory since. `PLBTVSTF.C` could not tell a closed
    /// block from one never opened either way, so this is at least as
    /// faithful as reading `bb->filnam` was, and it does not share that
    /// method's failure mode.
    ///
    /// # Errors
    ///
    /// If the block is dirty and [`Block::reindex`] fails: this is the flush
    /// point the whole design rests on, and a file going out of this host's
    /// reach with an index that disagrees with its data is exactly what
    /// `reindex` exists to prevent. Or if any of the four allocations cannot
    /// be freed. Or if the block has an outstanding transaction pre-image --
    /// see the note below.
    ///
    /// # A block with an outstanding pre-image refuses to close
    ///
    /// [`Btrieve::abort`] restores a block from its [`Block::pre_image`],
    /// which lives on the `Block` and leaves with it if the block is
    /// removed from [`Self::open`] here. Closing a block a transaction has
    /// already written to would make that write unreachable to a later
    /// `abort` -- the write stays on disk and in whatever the module did
    /// with the closed handle, and the transaction's own guarantee (measured
    /// against the real engine: an aborted insert, update or delete does not
    /// survive, even across a close and reopen -- see [`Btrieve::abort`]'s
    /// doc comment) silently stops applying to this one file. This case is
    /// not in `xactprobe`'s scenarios -- closing a file mid-transaction was
    /// never run against the real engine -- so rather than guess what real
    /// Btrieve does with it, this refuses it outright: a compile-time-checked
    /// `Result` a caller must handle, not a rollback guarantee that quietly
    /// stops holding for one file and nothing says so.
    pub fn close(
        &mut self,
        mem: &mut A::Mem,
        heap: &mut crate::Heap<A>,
        at: A::Ptr,
    ) -> Result<bool, BtvError> {
        if at == A::null_ptr() {
            // `goodptr(bb=bbp)` is false for a null `bbp`.
            return Ok(false);
        }

        // Either a second close of a block already closed, or a pointer
        // that never named one. `self.open` cannot tell those two apart
        // either, and does not need to -- both answer `false` here, exactly
        // as `bb->filnam != NULL` being false answered for both in
        // `PLBTVSTF.C`.
        let Ok(index) = self.find(at) else {
            return Ok(false);
        };
        let name = self.open[index].name.clone();
        let fail = |why: String| BtvError {
            file: name.clone(),
            why,
        };

        if self.open[index].pre_image.is_some() {
            return Err(fail(
                "has been written to inside a transaction that has not yet ended or \
                 aborted -- closing it now would take its rollback out of a later abort's \
                 reach, so this refuses rather than let that happen silently"
                    .to_owned(),
            ));
        }

        let filnam_at = A::ptr_offset(at, field::FILNAM);
        let bytes = filnam_at
            .resolve(mem, A::PTR_WIDTH)
            .map_err(|e| fail(e.to_string()))?;
        let filnam = A::ptr_from_bytes(bytes);

        // `bb->filnam=NULL` -- still written, and still before anything is
        // freed, exactly where `PLBTVSTF.C:639` writes it. A module that
        // reads its own `bb->filnam` after this call sees what the original
        // left there; this host just no longer *relies* on reading it back
        // to decide whether there was a file to close.
        filnam_at
            .write(mem, &A::ptr_to_bytes(A::null_ptr()))
            .map_err(|e| fail(e.to_string()))?;

        // The flush point. A block that was never written is never
        // reindexed -- which is not merely tidy, it is load-bearing:
        // `pages::index_pages` refuses any key needing more than one leaf
        // page, and nine of MajorMUD's eleven files with records need one.
        // Reindexing every close rather than only a dirty one would stop the
        // module on the first `WCCITEMS` or `WCCTEXT` it closed.
        if self.open[index].dirty {
            self.open[index].reindex()?;
        }

        let block = self.open.remove(index);
        // Measured (`docs/lock-oracle-answer.md`): "closing a file releases
        // every lock it held, immediately." Every lock this session took
        // while this block was current names it by `BlockId`, and that id
        // dies with `block` -- release explicitly rather than let the
        // entries become unreachable, so a later `Block` that happens to
        // reuse the same name never has to wonder whether a stale entry
        // could apply to it (it cannot: `BlockId`s never repeat, but a lock
        // this close forgot to release would sit in the table forever
        // regardless).
        self.locks.release_all_for(block.id());
        heap.free(block.key).map_err(fail)?;
        heap.free(block.data).map_err(fail)?;
        heap.free(filnam).map_err(fail)?;
        heap.free(block.block).map_err(fail)?;

        Ok(true)
    }

    /// Take `lock` at `at`'s current position, once a positioning call has
    /// already found one there. `lock == 0` is always `Ok(())`. The session
    /// half of [`ops::Block::take_lock`] -- callers only have `at`, a module
    /// pointer, not a `&mut Block` and a `&mut ops::LockTable` at once, so
    /// this resolves both from `self` and hands them to the `Block` method
    /// that knows what to do with them.
    ///
    /// # Errors
    /// If `at` names no open file, or [`ops::OpError`] (mode mixing, or the
    /// defensive not-positioned case -- see [`ops::Block::take_lock`]).
    pub fn take_lock(&mut self, at: A::Ptr, lock: i16) -> Result<(), String> {
        let index = self.find(at)?;
        self.open[index]
            .take_lock(lock, &mut self.locks)
            .map_err(|e| e.to_string())
    }

    /// The raw lock type this session holds at `at`'s current position, if
    /// any -- test/inspection surface for [`Self::take_lock`].
    ///
    /// # Errors
    /// If `at` names no open file.
    pub fn lock_at_current(&self, at: A::Ptr) -> Result<Option<i16>, String> {
        let index = self.find(at)?;
        Ok(self.open[index].lock_at_current(&self.locks))
    }

    /// Release the lock this session holds at `at`'s current position --
    /// Btrieve op 27, Unlock, with `keynum = 0` and no data. Always
    /// succeeds; see [`ops::Block::unlock`].
    ///
    /// # Errors
    /// If `at` names no open file.
    pub fn unlock_current(&mut self, at: A::Ptr) -> Result<(), String> {
        let index = self.find(at)?;
        self.open[index].unlock(&mut self.locks);
        Ok(())
    }

    fn find(&self, at: A::Ptr) -> Result<usize, String> {
        self.open
            .iter()
            .position(|b| b.block == at)
            .ok_or_else(|| format!("{at:?} is not an open Btrieve file"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::Wg16;
    use mbbs16::{FarPtr, Machine};

    /// A file control record with a page length, a record length and a count,
    /// and enough pages behind it to match.
    fn file(page: u16, reclen: u16, physical: u16, records: u32, pages: u32) -> Vec<u8> {
        let mut out = vec![0u8; (usize::from(page)) * pages as usize];
        out[at::PAGE..at::PAGE + 2].copy_from_slice(&page.to_le_bytes());
        out[6] = 0;
        out[7] = 4;
        out[at::KEYS..at::KEYS + 2].copy_from_slice(&1u16.to_le_bytes());
        out[at::RECLEN..at::RECLEN + 2].copy_from_slice(&reclen.to_le_bytes());
        out[at::PHYSICAL..at::PHYSICAL + 2].copy_from_slice(&physical.to_le_bytes());
        out[at::RECORDS_HIGH..at::RECORDS_HIGH + 2]
            .copy_from_slice(&((records >> 16) as u16).to_le_bytes());
        out[at::RECORDS_LOW..at::RECORDS_LOW + 2].copy_from_slice(&(records as u16).to_le_bytes());
        out
    }

    /// Mark the first `FCR`-byte half of a synthetic v6 file as the live
    /// control-record copy, by giving it the higher generation. Every v6 test
    /// below built by [`file`] carries its actual field values in that first
    /// half, so anything else would make [`Geometry::read`]'s shadow-copy
    /// comparison pick a copy of all zeroes.
    ///
    /// The second copy lives at byte offset `page_size` -- read from the
    /// fixture's own `at::PAGE` field, not passed in, so this cannot drift
    /// from what [`Geometry::read`] itself derives it from -- **not** at a
    /// fixed `FCR` offset. An earlier version of this helper wrote the second
    /// generation at `FCR + at::GENERATION`, which for a `file(4096, ...)`
    /// fixture lands *inside physical page 0*, sixteen bytes past the first
    /// generation it had just written. That fixture was shaped to match the
    /// bug `Geometry::read` had at the time, which is exactly why the suite
    /// could not see it. [`Geometry::read`] also now refuses a second
    /// physical page that does not start with `"FC"`, so this stamps that
    /// magic too.
    fn mark_first_half_live(bytes: &mut [u8]) {
        let page_size = usize::from(u16::from_le_bytes([bytes[at::PAGE], bytes[at::PAGE + 1]]));
        bytes[at::GENERATION..at::GENERATION + 2].copy_from_slice(&2u16.to_le_bytes());
        bytes[page_size..page_size + 2].copy_from_slice(b"FC");
        bytes[page_size + at::GENERATION..page_size + at::GENERATION + 2]
            .copy_from_slice(&1u16.to_le_bytes());
    }

    /// Read a header out of bytes, by way of a real file.
    ///
    /// A directory per file rather than one shared: tests run in parallel, and
    /// a scratch directory is emptied when it is asked for.
    fn read(name: &str, bytes: &[u8]) -> Result<Geometry, BtvError> {
        let dir = crate::testing::scratch(&format!("btv-{name}"));
        let path = dir.join(name);
        std::fs::write(&path, bytes).expect("written");
        Geometry::read(name, &path)
    }

    #[test]
    fn the_block_is_laid_out_the_way_btvstf_h_declares_it() {
        // A 16-bit compiler pads none of this -- every field is two or four
        // bytes and every offset is even -- so these are the byte offsets a
        // module's own `bb->reclen` compiles to, and a host that placed them
        // anywhere else would be handing back a struct of the right size with
        // everything in the wrong place.
        assert_eq!(field::POSBLK, 0);
        assert_eq!(field::FILNAM, 128);
        assert_eq!(field::RECLEN, 132);
        assert_eq!(field::KEY, 134);
        assert_eq!(field::DATA, 138);
        assert_eq!(field::LASTKN, 142);
        assert_eq!(field::KEYLNS, 144);
        assert_eq!(field::REALSEG, 192, "the first of the two PHARLAP fields");
        assert_eq!(field::KEYSEG, 194);
        assert_eq!(field::SIZE, 196);
    }

    #[test]
    fn a_file_control_record_gives_the_files_shape() {
        let geometry = read("SHAPE.DAT", &file(512, 100, 104, 7, 3)).expect("reads");
        assert_eq!(geometry.version, Version::V5);
        assert_eq!(geometry.page, 512);
        assert_eq!(geometry.keys, 1);
        assert_eq!(geometry.reclen, 100);
        assert_eq!(geometry.physical, 104);
        assert_eq!(geometry.records, 7);
        assert_eq!(geometry.pages, 3);
        assert!(!geometry.variable);
    }

    #[test]
    fn the_record_count_is_two_halves_and_the_high_one_comes_first() {
        // The one field in the record that is not simply little-endian: the
        // count is a `long` stored as two words, high word first. Every file
        // MajorMUD ships has a zero high word, so nothing in the corpus can
        // tell the two readings apart -- which is exactly why it is pinned
        // here, where a file with more than 65,535 records can be made.
        let geometry = read("BIG.DAT", &file(512, 100, 100, 70_000, 2)).expect("reads");
        assert_eq!(geometry.records, 70_000);

        let bytes = file(512, 100, 100, 70_000, 2);
        assert_eq!(&bytes[at::RECORDS_HIGH..at::RECORDS_HIGH + 2], &[1, 0]);
        assert_eq!(&bytes[at::RECORDS_LOW..at::RECORDS_LOW + 2], &[0x70, 0x11]);
    }

    #[test]
    fn a_v6_file_is_read_at_the_same_offsets() {
        let mut bytes = file(4096, 1544, 1546, 0, 6);
        bytes[..2].copy_from_slice(b"FC");
        bytes[7] = 0;
        mark_first_half_live(&mut bytes);
        let geometry = read("NEWMP001.VIR", &bytes).expect("reads");
        assert_eq!(geometry.version, Version::V6);
        assert_eq!(geometry.reclen, 1544);
    }

    /// A v6 file's control record is shadowed across physical pages 0 and 1,
    /// and page 0 can be the stale copy: `DUPKEY30.DAT`'s page 0 says the file
    /// holds no records and its page 1 says thirty. Reading page 0
    /// unconditionally -- which is what `read_head(path, FCR)` did -- reported
    /// a populated file as empty, and reported it *without an error*, because
    /// the two copies agree on every field the self-consistency checks look
    /// at. Only the counts drift.
    #[test]
    fn a_v6_control_record_is_read_from_the_live_shadow_copy() {
        // `CARGO_MANIFEST_DIR`-relative, not workspace-root-relative -- the
        // convention `pages.rs`'s `dupkey30()` already uses, because a test
        // binary's working directory is the crate root, not wherever `cargo
        // test` was invoked from.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/btrieve-oracle/fixtures/DUPKEY30.DAT");
        let geometry = Geometry::read("DUPKEY30.DAT", &path).expect("reads");
        assert_eq!(geometry.version, Version::V6);
        assert_eq!(geometry.records, 30, "page 1 is live and says thirty");
    }

    /// Task 2 made reading records from a v6 file refuse and name the
    /// version rather than hand back an empty vector -- before that, `walk`
    /// applied v5's `page * number` arithmetic to `DUPKEY30.DAT` regardless
    /// of its version and returned *something*, wrong, silently. Task 5
    /// replaces that refusal with the real path: `DUPKEY30.DAT` is still the
    /// fixture that catches a regression here, for the same reason it caught
    /// the original bug -- its 30 records make "found nothing" (or "found
    /// the wrong thing that happens to count to 30") impossible to pass by
    /// accident. `crates/mbbs/tests/btrieve.rs`'s
    /// `dupkey30_reads_byte_for_byte_through_records_read` is the byte-level
    /// check against the genuine engine's own dump; this one pins the
    /// higher-level shape -- a v6 file reads through the same `Records::read`
    /// every v5 file does, with no special-casing at this entry point.
    #[test]
    fn a_v6_files_records_are_read_correctly_not_refused() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/btrieve-oracle/fixtures/DUPKEY30.DAT");
        let geometry = Geometry::read("DUPKEY30.DAT", &path).expect("reads");
        let fcr = std::fs::read(&path).expect("readable");
        let parsed = keys::parse("DUPKEY30.DAT", &fcr, geometry.keys).expect("keys");

        let records = Records::read("DUPKEY30.DAT", &path, &geometry, &parsed)
            .expect("v6 addressing is resolved as of Task 5");
        assert_eq!(records.len(), 30, "page 1's live count, walked for real");
    }

    /// A v6 record's key is two bytes further along than the body it is read
    /// out of, because a key's `offset` is measured from the physical slot
    /// and [`Record::bytes`] starts past the slot's two-byte marker
    /// (Evidence 1b).
    ///
    /// `DUPKEY30.DAT`'s only key is four bytes at slot offset 2 -- so the key
    /// of the record whose body begins `09000000 1b000000` is `09000000`, the
    /// body's own first four bytes, reached by padding rather than by reading
    /// the body at offset 2 and getting `1b000000`, its *second* field.
    ///
    /// The byte-for-byte fixture tests cannot see this: they compare record
    /// bodies, which are right either way. Only something that reads a key
    /// notices, which is why this exists separately.
    #[test]
    fn a_v6_records_key_is_padded_past_the_slot_marker() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/btrieve-oracle/fixtures/DUPKEY30.DAT");
        let geometry = Geometry::read("DUPKEY30.DAT", &path).expect("reads");
        let fcr = std::fs::read(&path).expect("readable");
        let parsed = keys::parse("DUPKEY30.DAT", &fcr, geometry.keys).expect("keys");
        let records = Records::read("DUPKEY30.DAT", &path, &geometry, &parsed).expect("records");

        let key = &parsed[0];
        for at in 0..records.len() {
            let record = records.physical(at).expect("in range");
            let padded = key.extract(&records.keyed(&record.bytes));
            assert_eq!(
                padded,
                record.bytes[..4].to_vec(),
                "a v6 key is the body's own first four bytes"
            );
        }
    }

    /// Every other v6 test in this file has its live copy on physical page 1
    /// -- which alone cannot tell a correct generation comparison apart from
    /// code that just always prefers the second half. `DUPKEY30SWAPPED.DAT`
    /// is `DUPKEY30.DAT` with its two shadow-copy halves exchanged by hand --
    /// byte-for-byte swap of `[0..512)` and `[512..1024)`, nothing else
    /// touched (see `tools/btrieve-oracle/fixtures/V6CORPUS.txt`) -- so its
    /// live copy (generation 2, 30 records) is back on physical page 0. This
    /// is a hand-built fixture, not one the oracle wrote, so the "we write,
    /// the oracle reads back" rule does not apply to it.
    #[test]
    fn the_live_copy_is_found_by_generation_not_by_position() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/btrieve-oracle/fixtures/DUPKEY30SWAPPED.DAT");
        let geometry = Geometry::read("DUPKEY30SWAPPED.DAT", &path).expect("reads");
        assert_eq!(geometry.version, Version::V6);
        assert_eq!(geometry.records, 30, "page 0 is live here and says thirty");
    }

    /// The shadow copy is not at byte offset `FCR` (512) -- it is at byte
    /// offset `page_size`, and the two only coincide when `page_size == 512`.
    /// `DUPKEY30.DAT` (above) has `page_size == 512`, so it cannot catch this:
    /// the wrong-offset read and the right one land on the same bytes there.
    /// `PP2048.DAT` has `page_size == 2048`; before this fix its stale copy
    /// (page 0, generation 1, 0 records) sits at both offset 0 *and* offset
    /// 512, so a `read_head(path, FCR)`-style implementation comparing
    /// `[0..512)` against `[512..1024)` compares padding against padding --
    /// still inside physical page 0 -- and never reaches physical page 1
    /// (offset 2048, generation 2, 50 records) at all.
    #[test]
    fn a_v6_shadow_copy_is_found_at_page_size_not_at_fcr() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/btrieve-oracle/fixtures/PP2048.DAT");
        let geometry = Geometry::read("PP2048.DAT", &path).expect("reads");
        assert_eq!(geometry.version, Version::V6);
        assert_eq!(geometry.page, 2048);
        assert_eq!(
            geometry.records, 50,
            "physical page 1, at byte offset 2048, is live and says fifty"
        );

        // `FRAG1024.DAT` also has a non-`FCR` page size (1024), and it is a
        // *variable-length* v6 file -- Task 6 taught this host to read those,
        // so it no longer refuses. Its live copy's raw record count is 1.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/btrieve-oracle/fixtures/FRAG1024.DAT");
        let geometry = Geometry::read("FRAG1024.DAT", &path).expect("reads, as of Task 6");
        assert_eq!(geometry.version, Version::V6);
        assert_eq!(geometry.page, 1024);
        assert!(geometry.variable);
        assert_eq!(geometry.records, 1, "physical page 1 is live and says one");
    }

    #[test]
    fn something_that_is_not_btrieve_is_refused_by_name() {
        let mut bytes = vec![0u8; FCR];
        bytes[..4].copy_from_slice(b"MZ\x90\x00");
        let e = read("PKUNZIP.EXE", &bytes).expect_err("not a Btrieve file");
        assert_eq!(e.file, "PKUNZIP.EXE");
        assert!(e.to_string().contains("PKUNZIP.EXE"), "{e}");
    }

    #[test]
    fn a_v5_record_with_a_version_nobody_wrote_is_refused() {
        // The four zero bytes alone are not enough: a file of zeros has them.
        let mut bytes = file(512, 100, 100, 0, 2);
        bytes[7] = 9;
        assert!(read("FUTURE.DAT", &bytes).is_err());
    }

    #[test]
    fn a_page_length_that_is_not_a_multiple_of_512_is_refused() {
        let bytes = file(1000, 100, 100, 0, 2);
        let e = read("ODD.DAT", &bytes).expect_err("1000 is not a page length");
        assert!(e.why.contains("1000"), "{e}");
    }

    #[test]
    fn a_page_length_of_zero_is_refused_rather_than_dividing_by_it() {
        let mut bytes = file(512, 100, 100, 0, 2);
        bytes[at::PAGE..at::PAGE + 2].copy_from_slice(&0u16.to_le_bytes());
        assert!(read("ZERO.DAT", &bytes).is_err());
    }

    #[test]
    fn a_file_that_is_not_a_whole_number_of_pages_is_refused() {
        let mut bytes = file(512, 100, 100, 0, 2);
        bytes.truncate(900);
        let e = read("RAGGED.DAT", &bytes).expect_err("900 is not two pages");
        assert!(e.why.contains("900"), "{e}");
    }

    #[test]
    fn a_record_longer_than_a_page_is_refused() {
        let bytes = file(512, 600, 600, 0, 2);
        assert!(read("FAT.DAT", &bytes).is_err());
    }

    #[test]
    fn a_physical_record_shorter_than_the_logical_one_is_refused() {
        // Padding cannot be negative, and the two fields swapped would size
        // every read wrongly.
        let bytes = file(512, 104, 100, 0, 2);
        assert!(read("SWAPPED.DAT", &bytes).is_err());
    }

    #[test]
    fn a_file_shorter_than_one_page_is_refused_rather_than_read_past() {
        assert!(read("STUB.DAT", &[0u8; 64]).is_err());
    }

    /// A file laid out like virgin `WCCUSERS.DAT` but small enough to read at a
    /// glance: 64-byte pages holding two 20-byte records each, five pages, one
    /// of which (page 4) is a data page. Mirrors `pages::tests::seed`.
    fn seed(dir: &Path) -> PathBuf {
        let (page, physical, pages) = (64usize, 20usize, 5usize);
        let mut bytes = vec![0u8; page * pages];
        bytes[0x08..0x0a].copy_from_slice(&(page as u16).to_le_bytes());
        bytes[0x10..0x14].copy_from_slice(&pages::to_long(pages::NOWHERE));
        bytes[0x14..0x16].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x16..0x18].copy_from_slice(&16u16.to_le_bytes());
        bytes[0x18..0x1a].copy_from_slice(&(physical as u16).to_le_bytes());
        bytes[0x1e..0x20].copy_from_slice(&4u16.to_le_bytes());
        bytes[0x26..0x2a].copy_from_slice(&pages::to_long(pages as u32));
        // Page 4 is the data page; 1..4 are index pages.
        for number in 1..pages {
            let header = pages::Header {
                number: number as u32,
                data: number == 4,
                stamp: 0,
            };
            bytes[number * page..number * page + 6].copy_from_slice(&header.encode());
        }
        let path = dir.join("SCRATCH.DAT");
        std::fs::write(&path, &bytes).expect("scratch file");
        path
    }

    /// A `Block` over `seed`'s file, built directly rather than through
    /// `Btrieve::open` -- this test has no module and no heap, only the file
    /// and the geometry a real `opnbtv` would have read out of it.
    fn block(path: PathBuf) -> Block<Wg16> {
        let geometry = Geometry {
            version: Version::V5,
            page: 64,
            keys: 1,
            reclen: 16,
            physical: 20,
            records: 0,
            pages: 5,
            variable: false,
        };
        let keys = vec![Key {
            number: 0,
            definition: 0,
            segments: vec![keys::Segment {
                offset: 0,
                length: 2,
                kind: keys::Kind::Signed,
                descending: false,
            }],
            duplicates: false,
            chain: None,
        }];
        Block {
            id: ops::BlockId::fresh(),
            name: "SCRATCH.DAT".to_owned(),
            path,
            geometry,
            keys,
            block: FarPtr::NULL,
            maxlen: 16,
            data: FarPtr::NULL,
            key: FarPtr::NULL,
            records: None,
            cursor: Cursor::Nowhere,
            dirty: false,
            txn_active: false,
            pre_image: None,
        }
    }

    /// A 16-byte record whose two-byte key is `n`.
    fn record(n: u16) -> Vec<u8> {
        let mut bytes = vec![0u8; 16];
        bytes[..2].copy_from_slice(&n.to_le_bytes());
        bytes
    }

    /// Writing a v6 file is refused, and the refusal is load-bearing.
    ///
    /// Until Task 5 the write path was v6-safe only by accident:
    /// `Records::read` refused every v6 file, and `insert`/`update` call it
    /// before doing anything, so neither could get started. Task 5 lifted
    /// that refusal for reads and un-guarded the writes behind it -- and
    /// `pages::write_record` seeks to a record's `position` as a literal byte
    /// offset, while a v6 position carries a **logical** page id (Evidence
    /// 1c). On `DUPKEY30.DAT` logical 2 is physical 10, so an update would
    /// have written over a different page entirely and reported success.
    ///
    /// Found by Task 5's code review, not by any test: every v6 test in this
    /// crate reads.
    #[test]
    fn a_v6_file_is_read_but_never_written() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/btrieve-oracle/fixtures/DUPKEY30.DAT");
        let mut block = block(path.clone());
        block.name = "DUPKEY30.DAT".to_owned();
        block.geometry = Geometry::read("DUPKEY30.DAT", &path).expect("reads");
        let fcr = std::fs::read(&path).expect("readable");
        block.keys = keys::parse("DUPKEY30.DAT", &fcr, block.geometry.keys).expect("keys");
        block.maxlen = block.geometry.reclen;

        // Reading it works -- that is Tasks 1-5, and the point of the refusal
        // being on the write path alone.
        assert_eq!(block.records().expect("v6 reads").len(), 30);

        let bytes = vec![0u8; usize::from(block.geometry.reclen)];
        let e = block.insert(&bytes).expect_err("v6 inserts are refused");
        assert!(e.why.contains("does not write"), "{e}");
        let at = block
            .records()
            .expect("read")
            .physical(0)
            .expect("a record")
            .position;
        let e = block.update(at, &bytes).expect_err("v6 updates are refused");
        assert!(e.why.contains("does not write"), "{e}");
        let e = block.delete(at).expect_err("v6 deletes are refused");
        assert!(e.why.contains("does not write"), "{e}");

        // And the file on disk is untouched.
        assert_eq!(std::fs::read(&path).expect("readable"), fcr, "not one byte written");
    }

    /// The trap the plan names: `geometry` is a `Copy` struct held by value on
    /// `Block`, and `walk()` reads `geometry.records` and `geometry.pages` on
    /// the next `Records::read`. A `Block` that writes without updating its own
    /// copy would re-read the file wrongly the moment something drops the
    /// cache -- so this drops the cache and reads again, rather than trusting
    /// the in-memory model to agree with itself.
    ///
    /// Three inserts rather than one: page 4 holds two slots, so the third has
    /// nowhere to go but a fresh page, which is the other half of the trap --
    /// `geometry.pages` has to grow too, or the re-read never looks at page 5
    /// at all.
    #[test]
    fn a_block_that_writes_is_readable_after_its_cache_is_dropped() {
        let dir = crate::testing::scratch("block-write-persists");
        let path = seed(&dir);
        let mut block = block(path);

        let first = block.insert(&record(1)).expect("first insert");
        let second = block.insert(&record(2)).expect("second insert");
        let third = block.insert(&record(3)).expect("third insert");

        assert_eq!(block.geometry.records, 3, "the model's count is not stale");
        assert_eq!(block.geometry.pages, 6, "the third insert grew the file by a page");

        block.records = None;
        let reread = block.records().expect("a fresh read from disk");
        assert_eq!(reread.len(), 3, "all three records survive a fresh read");
        for position in [first, second, third] {
            assert!(reread.find_physical(position).is_some());
        }
    }

    /// I2: variable-length files must refuse `insert`, not truncate into it.
    /// `normalized` (below) exists for the fixed-length case -- see
    /// [`insert_normalizes_to_the_files_own_reclen_not_the_callers_buffer`] --
    /// where `reclen` really is every record's length and padding or cutting
    /// to it is correct. On a variable-length file `reclen` is not that; it
    /// is the same number `Block::update` already refuses to write over for
    /// exactly this reason (see its doc comment). Before this fix,
    /// `dinsbtv` on `WCCTEXT.DAT` would silently cut a 2,022-byte buffer down
    /// to a 22-byte `reclen` and answer 1, success -- the next task writes
    /// `WCCTEXT`, and that is not a plausible answer to give it.
    #[test]
    fn insert_refuses_a_variable_length_file_rather_than_truncate() {
        let dir = crate::testing::scratch("block-insert-refuses-variable-length");
        let path = seed(&dir);
        let mut block = block(path);
        block.geometry.variable = true;

        let long = vec![7u8; 2022];
        let e = block
            .insert(&long)
            .expect_err("a variable-length file refuses insert, the same as update");
        assert!(e.why.contains("variable-length"), "{e}");

        // The refusal did not touch the model, the count, or the file.
        assert_eq!(block.geometry.records, 0, "the refused insert did not count");
        block.records = None;
        let reread = block.records().expect("a fresh read from disk");
        assert_eq!(reread.len(), 0, "nothing was written");
    }

    /// I3: `dinsbtv` passes `bb->reclen` -- `Block::maxlen`, the module's own
    /// idea of the record length -- which the plan says is allowed to differ
    /// from the file's own `reclen`. `Block::insert` used to store the
    /// caller's buffer verbatim while `records::walk` always stores exactly
    /// `geometry.reclen` bytes, so the in-memory record and the on-disk one
    /// would have different lengths and `Key::extract`/`Key::compare` would
    /// see different bytes before and after the cache is dropped.
    ///
    /// This is the fixed-length case -- see
    /// [`insert_refuses_a_variable_length_file_rather_than_truncate`] for why
    /// the same normalising is wrong on a variable-length file.
    #[test]
    fn insert_normalizes_to_the_files_own_reclen_not_the_callers_buffer() {
        let dir = crate::testing::scratch("block-insert-normalizes-to-reclen");
        let path = seed(&dir);
        let mut block = block(path);

        // 20 bytes: the slot's physical length, standing in for a module
        // whose own `bb->reclen` is wider than the file's 16-byte `reclen`.
        // Bytes 16..20 are past the file's own record and must not survive
        // into the model.
        let mut bytes = vec![0u8; 20];
        bytes[..2].copy_from_slice(&7u16.to_le_bytes());
        bytes[16..20].copy_from_slice(&[0xaa; 4]);

        let position = block.insert(&bytes).expect("inserts");

        let stored = block
            .loaded()
            .and_then(|records| records.physical(0))
            .expect("in memory")
            .bytes
            .clone();
        assert_eq!(stored.len(), 16, "normalized to the file's reclen, not the caller's 20");

        block.records = None;
        let reread = block.records().expect("a fresh read from disk");
        let reread_record = reread
            .find_physical(position)
            .and_then(|at| reread.physical(at))
            .expect("still there");
        assert_eq!(
            reread_record.bytes, stored,
            "the model matches exactly what a re-read produces"
        );
    }

    /// C1: reproduces the reviewer's probe. Two records written into a
    /// scratch file, the second one all zero, used to leave
    /// `Records::read` answering `"the header says 2 records and walking
    /// the pages found 0"` -- `walk` reads the all-zero record as an empty
    /// slot, `break`s the page, and both records vanish, because a slot on
    /// a real free list is skipped rather than ending the page and a
    /// live-but-empty-looking slot is not on the free list. `Block::insert`
    /// must refuse the second record outright rather than write a file its
    /// own reader then refuses to read.
    #[test]
    fn insert_refuses_a_record_that_would_make_its_own_reader_fail() {
        let dir = crate::testing::scratch("block-insert-refuses-empty-lookalike");
        let path = seed(&dir);
        let mut block = block(path);

        let first = block.insert(&record(1)).expect("a live record");

        let e = block
            .insert(&[0u8; 16])
            .expect_err("an all-zero record decodes as an empty slot");
        assert!(e.why.contains("empty"), "{e}");

        // The refusal did not touch the model or the count.
        assert_eq!(block.geometry.records, 1, "the refused insert did not count");

        // And the file itself is still exactly what the reviewer's probe
        // checked: `Records::read` finds the one live record, not zero.
        block.records = None;
        let reread = block.records().expect("a fresh read from disk");
        assert_eq!(reread.len(), 1, "the file was never corrupted");
        assert!(reread.find_physical(first).is_some());
    }

    #[test]
    fn an_update_keeps_the_position_and_the_records_count() {
        let dir = crate::testing::scratch("block-update-persists");
        let path = seed(&dir);
        let mut block = block(path);
        let position = block.insert(&record(1)).expect("insert");

        block.update(position, &record(9)).expect("update");
        assert_eq!(block.geometry.records, 1, "an update changes no count");
        assert_eq!(block.geometry.pages, 5, "and grows no page");

        block.records = None;
        let reread = block.records().expect("a fresh read from disk");
        assert_eq!(reread.len(), 1);
        assert_eq!(
            reread
                .find_physical(position)
                .and_then(|at| reread.physical(at))
                .expect("still there")
                .bytes[0],
            9,
            "the new bytes, not the old, come back off disk"
        );
    }

    #[test]
    fn updating_a_position_that_holds_no_record_is_refused_by_the_block() {
        let dir = crate::testing::scratch("block-update-refused");
        let path = seed(&dir);
        let mut block = block(path);

        let e = block.update(999, &record(1)).expect_err("nothing is there");
        assert_eq!(e.file, "SCRATCH.DAT");
        assert!(e.why.contains("999"), "{e}");
    }

    /// I4: `write_record` pads to `physical` unconditionally, so an update
    /// with fewer bytes than the file's own `reclen` used to zero-fill the
    /// tail of whatever record was already there, silently. `dupdbtv` always
    /// calls `Block::update` with a fixed-length buffer, but the refusal
    /// belongs at this boundary rather than trusted to every future caller.
    #[test]
    fn an_update_shorter_than_reclen_is_refused_rather_than_zero_filling_the_tail() {
        let dir = crate::testing::scratch("block-update-refuses-short-buffer");
        let path = seed(&dir);
        let mut block = block(path);
        let position = block.insert(&record(1)).expect("insert");

        // `record` is 16 bytes, the file's own reclen; 10 is short.
        let short = vec![9u8; 10];
        let e = block
            .update(position, &short)
            .expect_err("10 bytes for a 16-byte record");
        assert!(e.why.contains("10") && e.why.contains("16"), "{e}");

        // Refusing left the original record intact, on disk as well as in
        // the model.
        block.records = None;
        let reread = block.records().expect("a fresh read from disk");
        let record = reread
            .find_physical(position)
            .and_then(|at| reread.physical(at))
            .expect("still there");
        assert_eq!(record.bytes[0], 1, "not overwritten by the refused update");
    }

    /// A variable-length file's slot is `physical` bytes wide and only `reclen`
    /// of them are the record; the four behind them are Btrieve's pointer to
    /// the record's first variable fragment. An update must not write over
    /// them, and the only way not to is to refuse the file.
    ///
    /// **Found by the real Btrieve 6.15 engine, not by reasoning.** The wash in
    /// `docs/plans/2026-08-08-oracle-wash.md` had this host update one record
    /// of `WCCTEXT.VIR` -- the one variable-length file of the eighteen -- and
    /// close it, then handed the result to the engine, which refused the whole
    /// file at the very first `GET_FIRST`: status 54, *variable page error*.
    /// Not the one record; every record, because the fragment chain the file's
    /// variable pages are threaded on had a link zeroed. A byte diff against
    /// the same file merely reindexed confirms it: two bytes changed, the one
    /// the test meant to flip and one of the four behind the record.
    ///
    /// The refusal that already existed did not catch it. `Block::update`
    /// refuses a variable-length file whose buffer is not `reclen` long, which
    /// anticipates a module passing a whole variable-length record. That leaves
    /// the buffer that *is* `reclen` long going straight through into
    /// `write_record`, which pads to `physical`. When the bug was found the
    /// gap was wide open, because `Records::read` yielded the fixed part alone
    /// and so read-then-write-back always hit it; [`variable::Chain`] has since
    /// narrowed it -- a read now returns the reassembled record, which the
    /// length check does catch -- but narrowing is not closing. **A record
    /// whose chain is empty still reads back as exactly `reclen` bytes**, which
    /// is the case below, and any caller that builds a `reclen` buffer of its
    /// own never had a length to be checked. The guard has to be the file's
    /// shape, not the buffer's length, the same as [`Block::insert`]'s.
    #[test]
    fn an_update_of_a_variable_length_file_is_refused_rather_than_unlinking_its_fragments() {
        let dir = crate::testing::scratch("block-update-refuses-variable-length");
        let path = seed(&dir);
        let mut block = block(path.clone());

        // Written while the file is still fixed-length, because that is the
        // only way this fixture can get a record onto a page; what makes it a
        // variable-length record is the four bytes behind it, written next.
        let position = block.insert(&record(1)).expect("insert");

        // The fragment pointer, in the padding between `reclen` (16) and
        // `physical` (20). Literals, not values derived from the geometry under
        // test: 16 and 20 are what `seed` and `block` chose, and a check
        // computed from `block.geometry` would move whenever they did.
        //
        // `ff ff ff ff` is the end-of-chain pointer -- `variable::END_PAGE` and
        // `END_FRAGMENT` -- so this record has no fragments and reads back as
        // its 16 fixed bytes. That is deliberately the *hardest* case for the
        // guard: it is the one a length check cannot distinguish from a
        // fixed-length record. Zeroing it does not merely lose a link, it makes
        // the pointer name page 0 fragment 0, and page 0 is the file control
        // record.
        let pointer = [0xffu8; 4];
        let tail = position as usize + 16;
        let mut bytes = std::fs::read(&path).expect("read");
        bytes[tail..tail + 4].copy_from_slice(&pointer);
        std::fs::write(&path, &bytes).expect("write the fragment pointer");

        // Now it is the file WCCTEXT is: the same slots, four of whose bytes
        // belong to Btrieve rather than to the record.
        block.geometry.variable = true;
        block.records = None;

        let whole = block
            .records()
            .expect("reads")
            .find_physical(position)
            .and_then(|at| block.records.as_ref().expect("loaded").physical(at))
            .expect("still there")
            .bytes
            .clone();
        assert_eq!(
            whole.len(),
            16,
            "a record with an empty chain reads back as exactly reclen, which is \
             what makes the length check unable to catch this one"
        );

        let e = block
            .update(position, &whole)
            .expect_err("a variable-length file refuses update, the same as insert");
        assert!(e.why.contains("variable-length"), "{e}");

        // The harm, not just the verdict: the four bytes behind the record are
        // what the engine follows to the record's variable part, and a refusal
        // that still wrote them would be no refusal at all.
        let after = std::fs::read(&path).expect("read back");
        assert_eq!(
            &after[tail..tail + 4],
            &pointer,
            "the fragment pointer was overwritten"
        );
    }

    /// One variable page holding one un-continued fragment, laid out the way
    /// [`variable`] documents: its own number, no free successor, a fragment
    /// count of one, the body from `0x0c`, and the two-entry array (fragment
    /// 0's start and the offset that ends it) at the end of the page.
    fn variable_page(number: u32, page_len: usize, body: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; page_len];
        out[0..2].copy_from_slice(&((number >> 16) as u16).to_le_bytes());
        out[2..4].copy_from_slice(&(number as u16).to_le_bytes());
        out[0x06..0x0a].copy_from_slice(&[0xff; 4]);
        out[0x0a..0x0c].copy_from_slice(&1u16.to_le_bytes());
        out[0x0c..0x0c + body.len()].copy_from_slice(body);
        let end = 0x0c + body.len();
        out[page_len - 2] = 0x0c;
        out[page_len - 1] = 0x00;
        out[page_len - 4] = (end & 0xff) as u8;
        out[page_len - 3] = (end >> 8) as u8;
        out
    }

    /// A variable-length file shaped the way `WCCTEXT` measures: one 8-byte
    /// fixed part, a 4-byte fragment pointer behind it (`physical` - `reclen`
    /// == 4, nothing else), one record on page 1 whose pointer names page 2,
    /// fragment 0 -- a single, un-continued fragment holding the record's
    /// 20-byte variable body.
    fn seed_variable(dir: &Path) -> PathBuf {
        let (page, reclen, physical, pages) = (64usize, 8u16, 12u16, 3usize);
        let mut bytes = vec![0u8; page * pages];
        bytes[at::PAGE..at::PAGE + 2].copy_from_slice(&(page as u16).to_le_bytes());
        bytes[0x10..0x14].copy_from_slice(&pages::to_long(pages::NOWHERE));
        bytes[6] = 0;
        bytes[7] = 4;
        bytes[at::KEYS..at::KEYS + 2].copy_from_slice(&1u16.to_le_bytes());
        bytes[at::RECLEN..at::RECLEN + 2].copy_from_slice(&reclen.to_le_bytes());
        bytes[at::PHYSICAL..at::PHYSICAL + 2].copy_from_slice(&physical.to_le_bytes());
        bytes[at::RECORDS_HIGH..at::RECORDS_HIGH + 2].copy_from_slice(&0u16.to_le_bytes());
        bytes[at::RECORDS_LOW..at::RECORDS_LOW + 2].copy_from_slice(&1u16.to_le_bytes());
        // `at::VARIABLE_MARK` and `at::USRFLGS` are not written: this fixture
        // is a file `Block::update` reads directly off `self.geometry`,
        // never through `Geometry::read`, which is the only reader of
        // either -- and both sit past a page this small (`block()`'s fixed-
        // length fixture leaves them unwritten for the same reason).

        // Page 1: one data page, one record: a 2-byte key, six bytes of
        // fixed-part padding, then the pointer to page 2, fragment 0.
        let header = pages::Header {
            number: 1,
            data: true,
            stamp: 0,
        };
        bytes[page..page + 6].copy_from_slice(&header.encode());
        let record_at = page + 6;
        bytes[record_at..record_at + 2].copy_from_slice(&1u16.to_le_bytes());
        bytes[record_at + 8..record_at + 12].copy_from_slice(&[0x00, 0x02, 0x00, 0x00]);

        // Page 2: the fragment.
        let body: Vec<u8> = (0..20u8).collect();
        let fragment_page = variable_page(2, page, &body);
        bytes[2 * page..3 * page].copy_from_slice(&fragment_page);

        let path = dir.join("VARIABLE.DAT");
        std::fs::write(&path, &bytes).expect("scratch file");
        path
    }

    /// A `Block` over [`seed_variable`]'s file, built directly the same way
    /// [`block`] is.
    fn block_variable(path: PathBuf) -> Block<Wg16> {
        let geometry = Geometry {
            version: Version::V5,
            page: 64,
            keys: 1,
            reclen: 8,
            physical: 12,
            records: 1,
            pages: 3,
            variable: true,
        };
        let keys = vec![Key {
            number: 0,
            definition: 0,
            segments: vec![keys::Segment {
                offset: 0,
                length: 2,
                kind: keys::Kind::Signed,
                descending: false,
            }],
            duplicates: false,
            chain: None,
        }];
        Block {
            id: ops::BlockId::fresh(),
            name: "VARIABLE.DAT".to_owned(),
            path,
            geometry,
            keys,
            block: FarPtr::NULL,
            maxlen: 28,
            data: FarPtr::NULL,
            key: FarPtr::NULL,
            records: None,
            cursor: Cursor::Nowhere,
            dirty: false,
            txn_active: false,
            pre_image: None,
        }
    }

    /// The one shape this host rewrites: an equal-length, single-fragment,
    /// non-continued body. `Block::update` reaches
    /// [`variable::rewrite_fragment_in_place`] for it rather than refusing.
    #[test]
    fn update_rewrites_a_matching_variable_length_fragment_in_place() {
        let dir = crate::testing::scratch("block-update-rewrites-variable-length");
        let path = seed_variable(&dir);
        let mut block = block_variable(path.clone());

        let before = std::fs::read(&path).expect("read the fixture");

        // A new key and a new body, the same length as the old one (20
        // bytes) so the shape matches.
        let mut new_value = vec![0u8; 8];
        new_value[..2].copy_from_slice(&9u16.to_le_bytes());
        new_value.extend((100..120u8).collect::<Vec<u8>>());

        block.update(70, &new_value).expect("an equal-length rewrite is handled");

        // The model agrees immediately.
        let current = block.records().expect("reads").find_physical(70).and_then(|at| {
            block.records.as_ref().expect("loaded").physical(at)
        }).expect("still there");
        assert_eq!(current.bytes, new_value, "the model holds the new value");

        // And so does a fresh read from disk, after the cache is dropped.
        block.records = None;
        let reread = block.records().expect("reads from disk");
        let record = reread.find_physical(70).and_then(|at| reread.physical(at)).expect("still there");
        assert_eq!(record.bytes, new_value, "a fresh read agrees with the model");

        // Byte-identical everywhere except the fixed part (8 bytes at
        // position 70) and the fragment's payload (20 bytes at page 2 offset
        // 0x0c). Not the pointer behind the fixed part, not the fragment
        // page's header or its entry array, not page 0's other fields.
        let after = std::fs::read(&path).expect("read back");
        let fixed_range = 70..70 + 8;
        let payload_range = 2 * 64 + 0x0c..2 * 64 + 0x0c + 20;
        for i in 0..after.len() {
            if fixed_range.contains(&i) || payload_range.contains(&i) {
                continue;
            }
            assert_eq!(after[i], before[i], "byte {i}, outside the fixed part and the payload, changed");
        }
        assert_eq!(&after[fixed_range.clone()], &new_value[..8], "the fixed part changed");
        assert_eq!(&after[payload_range.clone()], &new_value[8..], "the payload changed");
    }

    /// A body a different length from the fragment it would replace needs a
    /// second page or the free chain, neither of which this host has yet, so
    /// it refuses -- the same house style as the length check
    /// [`variable::rewrite_fragment_in_place`] runs on its own account, named
    /// distinguishably from the blanket variable-length refusal.
    #[test]
    fn update_refuses_a_variable_length_body_of_a_different_length() {
        let dir = crate::testing::scratch("block-update-refuses-grown-variable-length");
        let path = seed_variable(&dir);
        let mut block = block_variable(path.clone());

        let before = std::fs::read(&path).expect("read the fixture");

        let mut new_value = vec![0u8; 8];
        new_value[..2].copy_from_slice(&9u16.to_le_bytes());
        new_value.extend((0..21u8).collect::<Vec<u8>>()); // 21, not 20

        let e = block
            .update(70, &new_value)
            .expect_err("21 bytes does not match the existing 20-byte fragment");
        assert!(
            e.why.contains("an in-place rewrite only handles a replacement of the same length"),
            "{e}"
        );

        let after = std::fs::read(&path).expect("read back");
        assert_eq!(after, before, "a refused rewrite must not touch the file");
    }

    /// A position the model has no record at is refused before
    /// [`Block::rewrite_variable`] ever reads a byte from it, whatever the
    /// buffer's shape -- otherwise `position` is a module-supplied file
    /// offset that would be read as a record slot with nothing having
    /// checked it lands on one. The buffer's shape matches (20 bytes of
    /// body, the same length the fixture's fragment holds), so a check that
    /// forgot to gate on the model would attempt the rewrite anyway.
    #[test]
    fn update_refuses_a_variable_length_write_to_an_unknown_position() {
        let dir = crate::testing::scratch("block-update-refuses-unknown-position-variable");
        let path = seed_variable(&dir);
        let mut block = block_variable(path.clone());

        let before = std::fs::read(&path).expect("read the fixture");

        let mut new_value = vec![0u8; 8];
        new_value[..2].copy_from_slice(&9u16.to_le_bytes());
        new_value.extend((100..120u8).collect::<Vec<u8>>());

        let e = block
            .update(9999, &new_value)
            .expect_err("9999 holds no record, matching shape or not");
        assert!(e.why.contains("variable-length"), "{e}");

        let after = std::fs::read(&path).expect("read back");
        assert_eq!(after, before, "a refused rewrite must not touch the file");
    }

    /// Every fixture above sets `physical - reclen` to exactly four -- the
    /// pointer and nothing past it. This one does not: two more bytes sit
    /// behind the pointer, a sentinel this rewrite is never told about and
    /// must still carry through untouched, the same as the pointer itself.
    /// [`Block::rewrite_variable`] reads the whole physical slot off disk and
    /// only ever overwrites its first `reclen` bytes, so this is true by
    /// construction -- this test is what makes that true by measurement too.
    fn seed_variable_with_padding_behind_the_pointer(dir: &Path) -> PathBuf {
        let (page, reclen, physical, pages) = (64usize, 8u16, 14u16, 3usize);
        let mut bytes = vec![0u8; page * pages];
        bytes[at::PAGE..at::PAGE + 2].copy_from_slice(&(page as u16).to_le_bytes());
        bytes[0x10..0x14].copy_from_slice(&pages::to_long(pages::NOWHERE));
        bytes[6] = 0;
        bytes[7] = 4;
        bytes[at::KEYS..at::KEYS + 2].copy_from_slice(&1u16.to_le_bytes());
        bytes[at::RECLEN..at::RECLEN + 2].copy_from_slice(&reclen.to_le_bytes());
        bytes[at::PHYSICAL..at::PHYSICAL + 2].copy_from_slice(&physical.to_le_bytes());
        bytes[at::RECORDS_HIGH..at::RECORDS_HIGH + 2].copy_from_slice(&0u16.to_le_bytes());
        bytes[at::RECORDS_LOW..at::RECORDS_LOW + 2].copy_from_slice(&1u16.to_le_bytes());

        let header = pages::Header {
            number: 1,
            data: true,
            stamp: 0,
        };
        bytes[page..page + 6].copy_from_slice(&header.encode());
        let record_at = page + 6;
        bytes[record_at..record_at + 2].copy_from_slice(&1u16.to_le_bytes());
        bytes[record_at + 8..record_at + 12].copy_from_slice(&[0x00, 0x02, 0x00, 0x00]);
        // The two bytes past the pointer: not the record, not the pointer,
        // and named nowhere in this format -- a rewrite has no business
        // touching them.
        bytes[record_at + 12..record_at + 14].copy_from_slice(&[0xab, 0xcd]);

        let body: Vec<u8> = (0..20u8).collect();
        let fragment_page = variable_page(2, page, &body);
        bytes[2 * page..3 * page].copy_from_slice(&fragment_page);

        let path = dir.join("PADDED.DAT");
        std::fs::write(&path, &bytes).expect("scratch file");
        path
    }

    #[test]
    fn update_leaves_bytes_behind_the_pointer_untouched_when_physical_exceeds_reclen_plus_four() {
        let dir = crate::testing::scratch("block-update-variable-length-padding-survives");
        let path = seed_variable_with_padding_behind_the_pointer(&dir);
        let mut block = block_variable(path.clone());
        block.geometry.physical = 14;

        let mut new_value = vec![0u8; 8];
        new_value[..2].copy_from_slice(&9u16.to_le_bytes());
        new_value.extend((100..120u8).collect::<Vec<u8>>());

        block.update(70, &new_value).expect("an equal-length rewrite is handled");

        let after = std::fs::read(&path).expect("read back");
        assert_eq!(
            &after[70 + 8..70 + 12],
            &[0x00, 0x02, 0x00, 0x00],
            "the fragment pointer survived a physical slot wider than reclen + 4"
        );
        assert_eq!(
            &after[70 + 12..70 + 14],
            &[0xab, 0xcd],
            "the two bytes behind the pointer, which this format names nowhere, survived too"
        );
    }

    /// A file shaped like `seed`'s but at a real page size -- 512 bytes, the
    /// minimum an actual Btrieve file uses (`Geometry::read` refuses smaller).
    /// `seed`'s 64-byte pages are for the write tests above, which never touch
    /// a key definition; `reindex` does, and a key definition at `0x110`
    /// needs a page with room for one. Key 0 is given a root: page 1, one of
    /// the three index pages below the one data page.
    fn seed_indexed(dir: &Path) -> PathBuf {
        let (page, physical, pages) = (512usize, 20usize, 5usize);
        let mut bytes = vec![0u8; page * pages];
        bytes[0x08..0x0a].copy_from_slice(&(page as u16).to_le_bytes());
        bytes[0x10..0x14].copy_from_slice(&pages::to_long(pages::NOWHERE));
        bytes[0x14..0x16].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x16..0x18].copy_from_slice(&16u16.to_le_bytes());
        bytes[0x18..0x1a].copy_from_slice(&(physical as u16).to_le_bytes());
        bytes[0x1e..0x20].copy_from_slice(&4u16.to_le_bytes());
        bytes[0x26..0x2a].copy_from_slice(&pages::to_long(pages as u32));
        for number in 1..pages {
            let header = pages::Header {
                number: number as u32,
                data: number == 4,
                stamp: 0,
            };
            bytes[number * page..number * page + 6].copy_from_slice(&header.encode());
        }
        bytes[0x110..0x114].copy_from_slice(&pages::to_long(1));
        let path = dir.join("INDEXED.DAT");
        std::fs::write(&path, &bytes).expect("scratch file");
        path
    }

    /// A `Block` over `seed_indexed`'s file.
    fn block_indexed(path: PathBuf) -> Block<Wg16> {
        let geometry = Geometry {
            version: Version::V5,
            page: 512,
            keys: 1,
            reclen: 16,
            physical: 20,
            records: 0,
            pages: 5,
            variable: false,
        };
        let keys = vec![Key {
            number: 0,
            definition: 0,
            segments: vec![keys::Segment {
                offset: 0,
                length: 2,
                kind: keys::Kind::Signed,
                descending: false,
            }],
            duplicates: false,
            chain: None,
        }];
        Block {
            id: ops::BlockId::fresh(),
            name: "INDEXED.DAT".to_owned(),
            path,
            geometry,
            keys,
            block: FarPtr::NULL,
            maxlen: 16,
            data: FarPtr::NULL,
            key: FarPtr::NULL,
            records: None,
            cursor: Cursor::Nowhere,
            dirty: false,
            txn_active: false,
            pre_image: None,
        }
    }

    /// `seed_indexed`'s file, with its one key permitting duplicates.
    ///
    /// Eight more bytes of physical record than logical -- the `[prev][next]`
    /// pair -- which is the delta every one of MajorMUD's own duplicate-key
    /// files carries (`WCCUSERS` 1998 -> 2006, `WCCBANKS` 72 -> 80). The chain
    /// offset is `reclen`: it is measured from the physical slot, and in a
    /// version 5 file the slot and the record start at the same byte. See
    /// [`pages::chain_pair`].
    fn seed_duplicated(dir: &Path) -> PathBuf {
        let (page, physical, pages) = (512usize, 24usize, 5usize);
        let mut bytes = vec![0u8; page * pages];
        bytes[0x08..0x0a].copy_from_slice(&(page as u16).to_le_bytes());
        bytes[0x10..0x14].copy_from_slice(&pages::to_long(pages::NOWHERE));
        bytes[0x14..0x16].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x16..0x18].copy_from_slice(&16u16.to_le_bytes());
        bytes[0x18..0x1a].copy_from_slice(&(physical as u16).to_le_bytes());
        bytes[0x1e..0x20].copy_from_slice(&4u16.to_le_bytes());
        bytes[0x26..0x2a].copy_from_slice(&pages::to_long(pages as u32));
        for number in 1..pages {
            let header = pages::Header {
                number: number as u32,
                data: number == 4,
                stamp: 0,
            };
            bytes[number * page..number * page + 6].copy_from_slice(&header.encode());
        }
        bytes[0x110..0x114].copy_from_slice(&pages::to_long(1));
        let path = dir.join("DUPLICATE.DAT");
        std::fs::write(&path, &bytes).expect("scratch file");
        path
    }

    /// A `Block` over [`seed_duplicated`]'s file.
    fn block_duplicated(path: PathBuf) -> Block<Wg16> {
        let mut block = block_indexed(path);
        block.name = "DUPLICATE.DAT".to_owned();
        block.geometry.physical = 24;
        block.keys[0].duplicates = true;
        block.keys[0].chain = Some(16);
        block
    }

    /// A record of [`seed_duplicated`]'s shape: `value` is its key, `tag` is
    /// what tells two records sharing a value apart.
    ///
    /// `tag` sits at offset 4 rather than anywhere earlier because a record
    /// whose bytes past the first four are all zero reads back as a free slot
    /// -- `records::looks_empty` -- so a record of key 0 needs something in it
    /// that is not the key -- so callers pass a `tag` of 1 or more. Key 0 is
    /// exactly the case this file exists to exercise: every new MajorMUD
    /// character has zero experience, and `WCCUSERS` key 2 is experience. A
    /// real character record is never all zero either; it carries a name.
    fn duplicated_record(value: u16, tag: u16) -> Vec<u8> {
        let mut bytes = vec![0u8; 16];
        bytes[..2].copy_from_slice(&value.to_le_bytes());
        bytes[4..6].copy_from_slice(&tag.to_le_bytes());
        bytes
    }

    /// A `Block` over `seed_indexed`'s file holding `n` records, inserted out
    /// of key order.
    ///
    /// `seed_indexed`'s key is a two-byte signed integer over a 512-byte page,
    /// so a page holds `(512 - 16) / (2 + 8) = 49` entries and 400 records need
    /// nine leaves under a root — two levels, and eight page numbers this file
    /// does not have yet. That is the growth path as well as the tree path.
    ///
    /// Out of order on purpose, and deterministically so: odd keys ascending,
    /// then even. A builder that preserved insertion order rather than key
    /// order would pass against a file seeded in order.
    fn block_with_many_records(dir: &Path, n: u16) -> Block<Wg16> {
        let path = seed_indexed(dir);
        let mut block = block_indexed(path);
        let odd = (1..=n).filter(|k| k % 2 == 1);
        let even = (1..=n).filter(|k| k % 2 == 0);
        for key in odd.chain(even) {
            block.insert(&record(key)).expect("insert");
        }
        block
    }

    /// **The wall this whole plan is about.**
    ///
    /// More entries than one page holds used to be a refusal out of
    /// `index_pages` that propagated through `clsbtv`. Now it is a tree, and
    /// walking it back gives the same order the records went in.
    #[test]
    fn reindex_writes_a_tree_when_the_entries_do_not_fit_one_page() {
        let dir = crate::testing::scratch("block-reindex-multi-page");
        let mut block = block_with_many_records(&dir, 400);

        block.reindex().expect("reindexes into a tree");

        let layout = pages::Layout {
            page: block.geometry.page,
            physical: block.geometry.physical,
            pages: block.geometry.pages,
        };
        let key = &block.keys[0];
        let fcr = read_head(&block.path, usize::from(block.geometry.page)).expect("reads");
        let root_at = pages::fcr::KEYS
            + usize::from(key.definition) * pages::fcr::KEY_WIDTH
            + pages::fcr::KEY_ROOT;
        let root = pages::long(&fcr[root_at..root_at + 4]);

        let walk = pages::walk(&block.path, layout, root, key.shape())
            .expect("the tree this host just wrote is walkable");
        assert_eq!(walk.entries.len(), 400, "every record is in the tree once");
        assert!(walk.pages.len() > 1, "400 records do not fit one page");

        let records = block.records.as_ref().expect("loaded");
        for (n, entry) in walk.entries.iter().enumerate() {
            let record = records.ordered(key.number, n).expect("in range");
            assert_eq!(entry.head, record.position, "entry {n} names the wrong record");
            assert_eq!(entry.key, key.extract(&record.bytes), "entry {n} holds the wrong key");
        }
    }

    /// **Stage D2.** A duplicate-permitting key with records in it: one index
    /// entry per distinct value, and a chain through the records that share
    /// one.
    ///
    /// Twelve records over four values, inserted round-robin so that no
    /// group's records are neighbours on the page -- a chain that merely
    /// stepped to the next slot would pass on a file seeded value by value,
    /// and would be wrong here.
    ///
    /// Every claim is checked against the **file**, not against the model that
    /// wrote it: the tree is walked back off disk, and each chain link is read
    /// with [`pages::chain_pair`] out of the bytes on the page.
    #[test]
    fn reindex_writes_one_entry_per_value_and_chains_the_records_sharing_it() {
        const VALUES: u16 = 4;
        const PER_VALUE: u16 = 3;

        let dir = crate::testing::scratch("block-reindex-duplicates");
        let mut block = block_duplicated(seed_duplicated(&dir));
        for tag in 0..VALUES * PER_VALUE {
            block
                .insert(&duplicated_record(tag % VALUES, tag + 1))
                .expect("insert");
        }
        block.reindex().expect("reindexes a duplicate key");

        let layout = pages::Layout {
            page: block.geometry.page,
            physical: block.geometry.physical,
            pages: block.geometry.pages,
        };
        let key = &block.keys[0];

        // What the model says each group is: the positions carrying each
        // value, in the order the key orders them.
        let records = block.records.as_ref().expect("loaded");
        let mut groups: Vec<Vec<u32>> = vec![Vec::new(); VALUES as usize];
        for n in 0..records.len() {
            let record = records.ordered(0, n).expect("in range");
            let value = u16::from_le_bytes([record.bytes[0], record.bytes[1]]);
            groups[usize::from(value)].push(record.position);
        }
        for group in &groups {
            assert_eq!(group.len(), usize::from(PER_VALUE), "three records a value");
        }

        // One entry per value, naming the ends of that value's group.
        let walk = pages::walk(&block.path, layout, 1, key.shape()).expect("walks");
        assert_eq!(
            walk.entries.len(),
            usize::from(VALUES),
            "one entry per distinct value, not one per record"
        );
        for (value, entry) in walk.entries.iter().enumerate() {
            let group = &groups[value];
            assert_eq!(entry.key, (value as u16).to_le_bytes().to_vec(), "entry {value}");
            assert_eq!(entry.head, group[0], "value {value}'s head");
            assert_eq!(entry.tail, group[PER_VALUE as usize - 1], "value {value}'s tail");
        }

        // And the chain that joins them, read back off the pages.
        let file = std::fs::read(&block.path).expect("readable");
        let offset = usize::from(key.chain.expect("a duplicate key has a chain offset"));
        for group in &groups {
            for (at, position) in group.iter().enumerate() {
                let slot = *position as usize;
                let bytes = &file[slot..slot + usize::from(layout.physical)];
                assert_eq!(
                    pages::chain_pair(bytes, offset),
                    Some([
                        if at == 0 { pages::NOWHERE } else { group[at - 1] },
                        if at + 1 == group.len() {
                            pages::NOWHERE
                        } else {
                            group[at + 1]
                        },
                    ]),
                    "the record at {position}, {} of its group",
                    at + 1
                );
            }
        }

        // The per-key count in the file control record is the number of
        // entries, not the number of records -- measured on `DUPKEY30.DAT`,
        // whose file control record reads 10 for a file of 30 records.
        let fcr = std::fs::read(&block.path).expect("readable");
        let at = pages::fcr::KEYS + pages::fcr::KEY_RECORDS;
        assert_eq!(
            pages::long(&fcr[at..at + 4]),
            u32::from(VALUES),
            "the key's record count is its distinct values"
        );

        // And it is still a no-op the second time, chains included.
        let once = std::fs::read(&block.path).expect("readable");
        block.reindex().expect("second");
        assert_eq!(once, std::fs::read(&block.path).expect("readable"));
    }

    /// Rebuilding a file this host already indexed changes nothing.
    ///
    /// This is the invariant that reuse buys and an allocator could not: page
    /// numbers are stable, so a second reindex over unchanged records is a
    /// byte-for-byte no-op. It is **not** a claim that this host reproduces
    /// Btrieve's own splits -- it does not, and does not need to.
    ///
    /// Almost any mistake in the builder, the numbering or the walk breaks it,
    /// which is why it is here rather than a page-count assertion.
    #[test]
    fn reindexing_twice_over_the_same_records_writes_the_same_bytes() {
        let dir = crate::testing::scratch("block-reindex-idempotent");
        let mut block = block_with_many_records(&dir, 400);

        block.reindex().expect("first");
        let once = std::fs::read(&block.path).expect("readable");
        block.reindex().expect("second");
        let twice = std::fs::read(&block.path).expect("readable");

        assert_eq!(once, twice, "a rebuild of unchanged records is a no-op");
    }

    /// Bytes this process has read at the syscall level, from `/proc/self/io`'s
    /// `rchar` -- counted whether or not the bytes came off disk, which is
    /// exactly what distinguishes "read the first page" from "read the whole
    /// file and throw most of it away".
    fn bytes_read_by_this_process() -> u64 {
        let stat = std::fs::read_to_string("/proc/self/io").expect("/proc/self/io");
        stat.lines()
            .find_map(|line| line.strip_prefix("rchar:"))
            .expect("an rchar line")
            .trim()
            .parse()
            .expect("rchar is a number")
    }

    /// I1: `reindex` touches only the file control record, and must cost the
    /// same whether the file behind it is 2.5 KB or 80 MB -- `WCCUPDAT.DAT`
    /// is real at 80 MB, and a `reindex` that read the whole thing before
    /// truncating to one page would defeat the point of writing one page at
    /// a time.
    ///
    /// Grows `seed_indexed`'s file to a **sparse** 64 MiB with `set_len` --
    /// free on any filesystem that supports holes, since nothing is written
    /// to the new range -- then measures how many bytes `reindex` itself
    /// reads via `/proc/self/io`, which counts a sparse hole's zeroed bytes
    /// the same as any other: a whole-file read shows up as tens of millions
    /// of bytes; reading a handful of pages does not. A wall-clock budget
    /// would have worked too, but on this host reading a sparse gigabyte
    /// measured at barely half a second either way -- not a reliable
    /// tripwire under a parallel test run -- while the byte count is exact.
    ///
    /// The bound is now a function of the *old* index's shape, not just the
    /// control record: `reindex` walks the key's existing tree before
    /// rebuilding it, so the cost here is one page per node of that old tree
    /// plus the control record -- for this test's single inserted record, one
    /// 512-byte root plus the 512-byte control record, nowhere near the
    /// threshold below.
    #[test]
    fn reindex_does_not_read_the_whole_file_to_rebuild_one_page() {
        let dir = crate::testing::scratch("block-reindex-sparse-file");
        let path = seed_indexed(&dir);
        let mut block = block_indexed(path.clone());
        block.insert(&record(1)).expect("insert");

        let grown = 64 * 1024 * 1024;
        let big = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open to grow");
        big.set_len(grown).expect("grow the file sparsely");
        drop(big);

        let before = bytes_read_by_this_process();
        block.reindex().expect("reindexes without reading the sparse tail");
        let read = bytes_read_by_this_process().saturating_sub(before);

        assert!(
            read < 1024 * 1024,
            "reindex read {read} bytes off a {grown}-byte file -- it read more \
             than the first page"
        );
    }

    #[test]
    fn an_insert_leaves_the_block_dirty_and_reindex_clears_it() {
        let dir = crate::testing::scratch("block-reindex-dirty-flag");
        let path = seed_indexed(&dir);
        let mut block = block_indexed(path);
        assert!(!block.dirty(), "nothing written yet");

        block.insert(&record(1)).expect("insert");
        assert!(block.dirty(), "an insert leaves the index stale");

        block.reindex().expect("reindexes");
        assert!(!block.dirty(), "reindex brings the index back in step");
    }

    #[test]
    fn reindex_before_the_records_are_loaded_is_refused() {
        let dir = crate::testing::scratch("block-reindex-unloaded");
        let path = seed_indexed(&dir);
        let mut block = block_indexed(path);

        let e = block.reindex().expect_err("nothing has been read yet");
        assert!(e.why.contains("loaded"), "{e}");
    }

    /// The rebuild survives a fresh read of the *file*, not just the
    /// in-memory model -- reindex's whole point is that the bytes on disk
    /// agree with the records, and only reading them back proves that.
    #[test]
    fn reindex_writes_a_leaf_page_that_decodes_to_the_records_key_order() {
        let dir = crate::testing::scratch("block-reindex-leaf-page");
        let path = seed_indexed(&dir);
        let mut block = block_indexed(path.clone());

        // Out of key order on purpose: 3, 1, 2. Key order is 1, 2, 3.
        let first = block.insert(&record(3)).expect("insert");
        let second = block.insert(&record(1)).expect("insert");
        let third = block.insert(&record(2)).expect("insert");

        block.reindex().expect("reindexes");

        let bytes = std::fs::read(&path).expect("read back");

        // The file control record's key-0 record count, at `fcr::KEY_RECORDS`
        // within the key-0 definition.
        let definition = pages::fcr::KEYS;
        let count_at = definition + pages::fcr::KEY_RECORDS;
        assert_eq!(
            pages::long(&bytes[count_at..count_at + 4]),
            3,
            "the key's record count follows the rebuild, not the file's old one"
        );

        // Page 1 is a 512-byte leaf: 16 bytes of header, then three 10-byte
        // entries (a 2-byte key plus 8 bytes of pointers) in key order.
        let page = &bytes[512..1024];
        assert!(!pages::Header::decode(&page[..6]).data, "still an index page");
        assert_eq!(u16::from_le_bytes([page[6], page[7]]), 3, "three entries");

        let entry = |n: usize| {
            let at = 16 + n * 10;
            let key = u16::from_le_bytes([page[at], page[at + 1]]);
            let position = pages::long(&page[at + 2..at + 6]);
            (key, position)
        };
        assert_eq!(entry(0), (1, second), "1 sorts first");
        assert_eq!(entry(1), (2, third), "2 sorts second");
        assert_eq!(entry(2), (3, first), "3 sorts last");
    }

    /// C3: `Header::stamp`'s doc comment says the stamp is preserved rather
    /// than interpreted, and `seed_indexed` gives every page a stamp of
    /// zero -- which a bug that always writes zero cannot be told apart
    /// from the right answer. This seeds key 0's root with a nonzero stamp
    /// first, so a rebuild that clobbers it has something to be caught by.
    #[test]
    fn reindex_carries_the_roots_stamp_forward_rather_than_zeroing_it() {
        let dir = crate::testing::scratch("block-reindex-preserves-stamp");
        let path = seed_indexed(&dir);

        let mut bytes = std::fs::read(&path).expect("read");
        let mut header = pages::Header::decode(&bytes[512..518]);
        header.stamp = 141;
        bytes[512..518].copy_from_slice(&header.encode());
        std::fs::write(&path, &bytes).expect("seed a nonzero stamp on key 0's root");

        let mut block = block_indexed(path.clone());
        block.insert(&record(1)).expect("insert");
        block.reindex().expect("reindexes");

        let after = std::fs::read(&path).expect("read back");
        let header = pages::Header::decode(&after[512..518]);
        assert_eq!(header.stamp, 141, "the root's stamp must survive a rebuild");
        assert_eq!(header.number, 1, "and still names itself page 1");
        assert!(!header.data, "still an index page");
    }

    /// I7, part 1: a file like `seed_indexed`'s but with **two** keys, where
    /// key 0 has two segments (`ANOSEG`, definitions 0 and 1) and key 1 is a
    /// single segment -- `WCCITOWN.DAT`'s shape with the segmented key moved
    /// **first** instead of last, which is the order no shipped file uses and
    /// the one `reindex` got wrong.
    ///
    /// Definition 0 is key 0's real root, page 1. Definition 1 is key 0's
    /// continuation segment; measured off the shipped files, a continuation
    /// definition's own root field is `0`, so that is what this puts there.
    /// Definition 2 is key 1's real root, page 2 -- **not** page 1, which is
    /// `key.number * KEY_WIDTH` (`1 * 30`) would have landed on by reading
    /// definition 1 instead.
    fn seed_two_keys_segmented_first(dir: &Path) -> PathBuf {
        let (page, physical, pages) = (512usize, 20usize, 5usize);
        let mut bytes = vec![0u8; page * pages];
        bytes[0x08..0x0a].copy_from_slice(&(page as u16).to_le_bytes());
        bytes[0x10..0x14].copy_from_slice(&pages::to_long(pages::NOWHERE));
        bytes[0x14..0x16].copy_from_slice(&2u16.to_le_bytes());
        bytes[0x16..0x18].copy_from_slice(&16u16.to_le_bytes());
        bytes[0x18..0x1a].copy_from_slice(&(physical as u16).to_le_bytes());
        bytes[0x1e..0x20].copy_from_slice(&4u16.to_le_bytes());
        bytes[0x26..0x2a].copy_from_slice(&pages::to_long(pages as u32));
        for number in 1..pages {
            let header = pages::Header {
                number: number as u32,
                data: number == 4,
                stamp: 0,
            };
            bytes[number * page..number * page + 6].copy_from_slice(&header.encode());
        }
        bytes[0x110..0x114].copy_from_slice(&pages::to_long(1));
        let def1 = 0x110 + pages::fcr::KEY_WIDTH;
        bytes[def1..def1 + 4].copy_from_slice(&pages::to_long(0));
        let def2 = 0x110 + 2 * pages::fcr::KEY_WIDTH;
        bytes[def2..def2 + 4].copy_from_slice(&pages::to_long(2));
        let path = dir.join("TWOKEY.DAT");
        std::fs::write(&path, &bytes).expect("scratch file");
        path
    }

    /// A `Block` over `seed_two_keys_segmented_first`'s file: key 0 has two
    /// segments and `definition: 0`; key 1 has one segment, `number: 1` but
    /// `definition: 2`.
    fn block_two_keys(path: PathBuf) -> Block<Wg16> {
        let geometry = Geometry {
            version: Version::V5,
            page: 512,
            keys: 2,
            reclen: 16,
            physical: 20,
            records: 0,
            pages: 5,
            variable: false,
        };
        let segment = |offset| keys::Segment {
            offset,
            length: 2,
            kind: keys::Kind::Signed,
            descending: false,
        };
        let keys = vec![
            Key {
                number: 0,
                definition: 0,
                segments: vec![segment(0), segment(2)],
                duplicates: false,
                chain: None,
            },
            Key {
                number: 1,
                definition: 2,
                segments: vec![segment(4)],
                duplicates: false,
                chain: None,
            },
        ];
        Block {
            id: ops::BlockId::fresh(),
            name: "TWOKEY.DAT".to_owned(),
            path,
            geometry,
            keys,
            block: FarPtr::NULL,
            maxlen: 16,
            data: FarPtr::NULL,
            key: FarPtr::NULL,
            records: None,
            cursor: Cursor::Nowhere,
            dirty: false,
            txn_active: false,
            pre_image: None,
        }
    }

    #[test]
    fn reindex_uses_a_keys_own_definition_not_its_number_for_the_root() {
        let dir = crate::testing::scratch("block-reindex-definition-not-number");
        let path = seed_two_keys_segmented_first(&dir);
        let mut block = block_two_keys(path.clone());

        block.records().expect("reads -- no records yet");
        block.reindex().expect("reindexes both keys at their own roots");

        let bytes = std::fs::read(&path).expect("read back");

        // Key 1's leaf landed on its own root, page 2 -- not page 1, which
        // reading `key.number` (1) instead of `key.definition` (2) would
        // have targeted, clobbering key 0's own root.
        let page2 = &bytes[2 * 512..3 * 512];
        let header2 = pages::Header::decode(&page2[..6]);
        assert_eq!(header2.number, 2);
        assert!(!header2.data, "still an index page");

        // And key 0's own root, page 1, is untouched by key 1's rebuild.
        let page1 = &bytes[512..1024];
        let header1 = pages::Header::decode(&page1[..6]);
        assert_eq!(header1.number, 1);

        // The file control record itself was not clobbered.
        assert_eq!(&bytes[..4], &[0, 0, 0, 0], "still a v5 marker, not a page header");
        assert_eq!(u16::from_le_bytes([bytes[0x16], bytes[0x17]]), 16, "reclen untouched");
    }

    /// I7, part 2: the guard that holds even if `key.definition` were
    /// somehow still wrong. A root of `0` names the file control record
    /// itself, and `reindex` must refuse it outright rather than write a
    /// leaf over it.
    #[test]
    fn reindex_refuses_a_root_of_zero_rather_than_write_over_the_file_control_record() {
        let dir = crate::testing::scratch("block-reindex-root-zero");
        let path = seed_indexed(&dir);
        let mut bytes = std::fs::read(&path).expect("read");
        bytes[0x110..0x114].copy_from_slice(&pages::to_long(0));
        std::fs::write(&path, &bytes).expect("corrupt the root to page 0");

        let mut block = block_indexed(path.clone());
        block.records().expect("reads");
        let e = block.reindex().expect_err("a root of page 0 is refused");
        assert!(e.why.contains("0"), "{e}");

        let after = std::fs::read(&path).expect("read back");
        assert_eq!(after, bytes, "a refused reindex touches nothing");
    }

    /// The other half of the same guard: a root naming a page the file does
    /// not have at all.
    #[test]
    fn reindex_refuses_a_root_past_the_end_of_the_file() {
        let dir = crate::testing::scratch("block-reindex-root-out-of-range");
        let path = seed_indexed(&dir);
        let mut bytes = std::fs::read(&path).expect("read");
        bytes[0x110..0x114].copy_from_slice(&pages::to_long(99));
        std::fs::write(&path, &bytes).expect("corrupt the root past the end");

        let mut block = block_indexed(path.clone());
        block.records().expect("reads");
        let e = block.reindex().expect_err("page 99 does not exist in a 5-page file");
        assert!(e.why.contains("99"), "{e}");
    }

    /// The record count stored in key 0's own definition -- `fcr::KEY_RECORDS`
    /// at `0x110 + 0x04`. Only [`Block::reindex`] ever writes it; an ordinary
    /// insert or update does not, which is what makes it a witness to whether
    /// a close actually rebuilt the index rather than merely not erroring.
    fn key_records(path: &Path) -> u32 {
        let bytes = std::fs::read(path).expect("read the file back");
        pages::long(&bytes[0x114..0x118])
    }

    /// Register `seed_indexed`'s block as a real open file: allocate its four
    /// module-memory pieces on a real heap and write `field::FILNAM` the way
    /// [`Btrieve::open`] does, then push it directly rather than going
    /// through `keys::parse` -- `seed_indexed`'s key definition has no real
    /// attributes, only a root, and `block_indexed`'s hand-built [`Key`]
    /// already describes it correctly. Returns the pointer a module's `bb`
    /// would hold.
    fn open_indexed(
        machine: &mut Machine,
        heap: &mut crate::Heap<Wg16>,
        btrieve: &mut Btrieve<Wg16>,
        path: PathBuf,
    ) -> FarPtr {
        let mut block = block_indexed(path);

        let filnam = heap.alloc(machine, 12).expect("alloc filnam");
        machine.write(filnam, b"INDEXED.DAT\0").expect("write filnam");

        let data = heap.alloc(machine, block.maxlen).expect("alloc data");
        machine
            .write(data, &vec![0u8; usize::from(block.maxlen)])
            .expect("write data");

        let key = heap.alloc(machine, 3).expect("alloc key");
        machine.write(key, &[0u8; 3]).expect("write key");

        let at = heap.alloc(machine, field::SIZE).expect("alloc block");
        let mut image = vec![0u8; usize::from(field::SIZE)];
        let put = |image: &mut Vec<u8>, offset: u16, bytes: &[u8]| {
            let start = usize::from(offset);
            image[start..start + bytes.len()].copy_from_slice(bytes);
        };
        put(&mut image, field::FILNAM, &filnam.to_bytes());
        put(&mut image, field::DATA, &data.to_bytes());
        put(&mut image, field::KEY, &key.to_bytes());
        machine.write(at, &image).expect("write block");

        block.block = at;
        block.data = data;
        block.key = key;
        btrieve.open.push(block);
        at
    }

    /// I4: `close` must call `reindex` exactly when the block is dirty, and
    /// not otherwise -- `pages::index_pages` refuses any key needing more
    /// than one leaf page, which is nine of MajorMUD's eleven files with
    /// records, and the `dirty` flag is the only thing standing between a
    /// clean close of one of those and that refusal.
    #[test]
    fn close_reindexes_a_dirty_block_but_never_a_clean_one() {
        let mut machine = Machine::new().expect("a 16-bit machine");
        let mut heap = crate::Heap::new(crate::Config::default());
        let mut btrieve = Btrieve::default();

        // Dirty: an insert alone never touches a key's own record count --
        // only `reindex` does. That field moving from 0 to 1 is proof the
        // rebuild ran, not merely that the close did not error.
        let dirty_path = seed_indexed(&crate::testing::scratch("btrieve-close-reindex-dirty"));
        let dirty = open_indexed(&mut machine, &mut heap, &mut btrieve, dirty_path.clone());
        btrieve
            .block_mut(dirty)
            .expect("open")
            .insert(&record(1))
            .expect("insert");
        assert_eq!(
            key_records(&dirty_path),
            0,
            "an insert alone leaves the key's own count alone"
        );

        btrieve
            .close(machine.mem_mut(), &mut heap, dirty)
            .expect("closes, and reindexes on the way");
        assert_eq!(
            key_records(&dirty_path),
            1,
            "closing a dirty block rebuilds the index"
        );

        // Clean: a second file with the same shape and the same real index
        // root, never written to. If `close` reindexed regardless of
        // `dirty`, this would still succeed -- the fixture's one entry fits
        // on one leaf page -- but its bytes would change, because
        // `index_pages` does not promise to reproduce Btrieve's own byte
        // layout (see `pages::index_pages`'s doc comment). Byte-for-byte
        // identical is only possible if `reindex` was never called.
        let clean_path = seed_indexed(&crate::testing::scratch("btrieve-close-reindex-clean"));
        let before = std::fs::read(&clean_path).expect("read before");
        let clean = open_indexed(&mut machine, &mut heap, &mut btrieve, clean_path.clone());
        btrieve
            .close(machine.mem_mut(), &mut heap, clean)
            .expect("closes without ever asking to reindex");
        let after = std::fs::read(&clean_path).expect("read after");
        assert_eq!(before, after, "a clean close never touches the file");
    }

    /// C5: the re-entrancy guard used to be `bb->filnam != NULL`, read out of
    /// module memory the first close already freed. [`crate::Heap::free`]
    /// never clears what it frees (see its own doc comment), so that read
    /// stayed reliably null only until something else allocated over the
    /// same span -- reproduced here with eight `Heap::alloc(256)` calls, the
    /// same shape `alcmem` makes, run after the first close. Before the fix
    /// the second close found garbage where `bb->filnam` used to be null,
    /// tried to look up a block already removed from [`Self::open`], and
    /// stopped the module with "is not an open Btrieve file" -- a module
    /// bug in disguise -- instead of the quiet no-op a real double close is.
    #[test]
    fn close_is_a_quiet_no_op_the_second_time_even_after_the_heap_reuses_its_span() {
        let mut machine = Machine::new().expect("a 16-bit machine");
        let mut heap = crate::Heap::new(crate::Config::default());
        let mut btrieve = Btrieve::default();

        let path = seed_indexed(&crate::testing::scratch(
            "btrieve-close-reentrancy-heap-reuse",
        ));
        let at = open_indexed(&mut machine, &mut heap, &mut btrieve, path);

        assert!(
            btrieve.close(machine.mem_mut(), &mut heap, at).expect("closes"),
            "the first close finds an open file"
        );

        // The same shape of traffic `alcmem` makes, and enough of it to land
        // on the span the closed block's own `struct btvblk` used to occupy
        // -- and, critically, written into, the way a module actually uses
        // memory it was just handed. `Heap::alloc` alone only reserves
        // address space; it is the write that leaves non-null garbage where
        // `bb->filnam` used to read as null.
        for _ in 0..8 {
            let block = heap.alloc(&mut machine, 256).expect("alcmem-shaped traffic");
            machine
                .write(block, &[0xaau8; 256])
                .expect("a module writes into what it was just given");
        }

        let second = btrieve
            .close(machine.mem_mut(), &mut heap, at)
            .expect("a second close of the same pointer must be a quiet no-op");
        assert!(!second, "nothing was open the second time");
    }

    /// Measured (`docs/lock-oracle-answer.md`): "closing a file releases
    /// every lock it held, immediately." Goes through the real `open`/
    /// `close`/`take_lock` methods rather than poking `LockTable` directly,
    /// so a mutation that closed a file without releasing its locks is
    /// caught even though `close`'s own return value does not change.
    #[test]
    fn closing_a_file_releases_every_lock_it_held() {
        let mut machine = Machine::new().expect("a 16-bit machine");
        let mut heap = crate::Heap::new(crate::Config::default());
        let mut btrieve = Btrieve::default();

        let path = seed_indexed(&crate::testing::scratch("btrieve-close-releases-locks"));
        let at = open_indexed(&mut machine, &mut heap, &mut btrieve, path);
        btrieve
            .block_mut(at)
            .expect("open")
            .insert(&record(1))
            .expect("insert");
        assert!(
            btrieve
                .block_mut(at)
                .expect("open")
                .query(0, Op::Equal, &1u16.to_le_bytes())
                .expect("queries"),
            "positions on the record just inserted"
        );
        btrieve.take_lock(at, 100).expect("takes a single lock");

        let id = btrieve.block(at).expect("open").id();
        let position = btrieve.block(at).expect("open").current().expect("positioned").position;
        assert_eq!(
            btrieve.locks.get(id, position),
            Some(100),
            "held before close"
        );

        btrieve
            .close(machine.mem_mut(), &mut heap, at)
            .expect("closes");
        assert_eq!(
            btrieve.locks.get(id, position),
            None,
            "released the moment the file closed"
        );
        assert!(btrieve.locks.is_empty(), "and nothing else was left behind");
    }

    #[test]
    fn the_two_witnesses_to_variable_length_records_must_agree() {
        // 104 rather than 100: a variable-length file's physical slot has to
        // leave room for the four-byte pointer to the first fragment, which is
        // checked below in its own right.
        let mut bytes = file(512, 100, 104, 0, 2);
        bytes[at::USRFLGS] = 1;
        assert!(read("HALF.DAT", &bytes).is_err(), "flag set, marker not");

        bytes[at::VARIABLE_MARK] = 0xff;
        assert!(read("BOTH.DAT", &bytes).expect("reads").variable);
    }

    /// The four bytes after the logical record are where a variable-length
    /// record's chain begins. A file with fewer has nowhere to put one, and
    /// reading it would decode a pointer out of the padding of the next field.
    #[test]
    fn a_variable_length_file_with_no_room_for_a_fragment_pointer_is_refused() {
        for physical in [100u16, 101, 102, 103] {
            let mut bytes = file(512, 100, physical, 0, 2);
            bytes[at::USRFLGS] = 1;
            bytes[at::VARIABLE_MARK] = 0xff;
            let e = read("NOROOM.DAT", &bytes)
                .expect_err("there is no room for a fragment pointer");
            assert!(e.why.contains("needs 4"), "{e}");
        }

        // And four is enough, which is exactly what `WCCTEXT` has spare.
        let mut bytes = file(512, 100, 104, 0, 2);
        bytes[at::USRFLGS] = 1;
        bytes[at::VARIABLE_MARK] = 0xff;
        assert!(read("ROOM.DAT", &bytes).expect("reads").variable);
    }

    /// Compressed record data is a second encoding this host cannot undo, and
    /// no file MajorMUD ships sets the bit. Refusing is the difference between
    /// stopping the module and handing it 2,000 bytes of compression stream.
    #[test]
    fn a_file_whose_records_are_compressed_is_refused_rather_than_read() {
        let mut bytes = file(512, 100, 100, 0, 2);
        bytes[at::USRFLGS] = 0x08;
        let e = read("PACKED.DAT", &bytes).expect_err("nothing here decompresses");
        assert!(e.why.contains("compressed"), "{e}");

        // Bit 3 alone, not "any flag at all": bit 2 is somebody else's and is
        // read as before.
        let mut ordinary = file(512, 100, 100, 0, 2);
        ordinary[at::USRFLGS] = 0x04;
        assert!(!read("PLAIN.DAT", &ordinary).expect("reads").variable);
    }

    /// Blank truncation lengthens the physical record *after* the fragment
    /// pointer (`W32MKDE_decompiled.c:17798`), and a read has to put the
    /// stripped spaces back. Nothing here does, so every record would come out
    /// short with nothing saying so.
    #[test]
    fn a_file_whose_trailing_blanks_are_truncated_is_refused_rather_than_read() {
        let mut bytes = file(512, 100, 102, 0, 2);
        bytes[at::USRFLGS] = 0x02;
        let e = read("BLANKS.DAT", &bytes).expect_err("the blanks are not put back");
        assert!(e.why.contains("trailing blanks"), "{e}");
    }

    /// Before Task 6, a v6 file's fragments were refused outright -- `Version`
    /// had been parsed and never consulted anywhere, which is exactly how the
    /// v5 rule would have been applied to a v6 file silently. Task 6 taught
    /// `variable::Chain::follow` to read a v6 chain, so `Geometry::read` no
    /// longer refuses by version alone; this asserts that directly, alongside
    /// the fixed-length case that was always read.
    #[test]
    fn a_btrieve_6_file_of_variable_length_records_is_read_not_refused_by_version_alone() {
        // `physical - reclen == 6`: Evidence 1b's two-byte slot marker plus
        // the four-byte fragment pointer, the v6 floor this task adds.
        let mut bytes = file(512, 100, 106, 0, 2);
        bytes[..2].copy_from_slice(b"FC");
        bytes[at::USRFLGS] = 0x01;
        bytes[at::VARIABLE_MARK] = 0xff;
        mark_first_half_live(&mut bytes);
        let geometry = read("SIX.DAT", &bytes).expect("Task 6 reads a v6 variable-length file");
        assert_eq!(geometry.version, Version::V6);
        assert!(geometry.variable);

        // And a v6 file of *fixed*-length records is still read, which is what
        // `NEWMP001.VIR` is.
        let mut fixed = file(512, 100, 100, 0, 2);
        fixed[..2].copy_from_slice(b"FC");
        mark_first_half_live(&mut fixed);
        assert_eq!(read("SIXFIXED.DAT", &fixed).expect("reads").version, Version::V6);
    }

    /// The v6-specific half of the room check Task 6 adds: a v6 slot needs
    /// six spare bytes after `reclen`, not v5's four, because Evidence 1b's
    /// two-byte marker sits in front of the pointer too. Four or five bytes
    /// of room would let `Geometry::read` succeed and then panic inside
    /// `records::walk_v6` slicing a four-byte pointer out of a two- or
    /// three-byte remainder; refusing here is what this house style prefers
    /// to that crash.
    #[test]
    fn a_v6_variable_length_file_needs_six_spare_bytes_not_four() {
        for physical in [104u16, 105] {
            let mut bytes = file(512, 100, physical, 0, 2);
            bytes[..2].copy_from_slice(b"FC");
            bytes[at::USRFLGS] = 0x01;
            bytes[at::VARIABLE_MARK] = 0xff;
            mark_first_half_live(&mut bytes);
            let e = read("V6NOROOM.DAT", &bytes)
                .expect_err("a v6 slot marker leaves no room for the pointer at this gap");
            assert!(e.why.contains("V6") && e.why.contains("needs 6"), "{e}");
        }

        let mut bytes = file(512, 100, 106, 0, 2);
        bytes[..2].copy_from_slice(b"FC");
        bytes[at::USRFLGS] = 0x01;
        bytes[at::VARIABLE_MARK] = 0xff;
        mark_first_half_live(&mut bytes);
        assert!(read("V6ROOM.DAT", &bytes).expect("six is enough").variable);
    }

    // `Block::delete` (Btrieve operation 4, `delbtv`). Semantics measured
    // against genuine Btrieve 6.15 with `tools/btrieve-oracle/delprobe.c`;
    // see `Block::delete`'s and `pages::delete_record`'s doc comments for the
    // raw probe output each test below is reproducing.

    #[test]
    fn delete_refuses_a_variable_length_file() {
        let dir = crate::testing::scratch("block-delete-refuses-variable-length");
        let path = seed_variable(&dir);
        let mut block = block_variable(path.clone());
        let before = std::fs::read(&path).expect("read the fixture");

        let e = block
            .delete(64 + 6)
            .expect_err("a variable-length file refuses delete, the same as insert and update");
        assert!(e.why.contains("variable-length"), "{e}");

        let after = std::fs::read(&path).expect("read back");
        assert_eq!(after, before, "a refused delete must not touch the file");
    }

    /// `position` is a module's word for a file offset, not a slot this layer
    /// chose -- deleting at one the model does not recognise must refuse
    /// rather than clear whatever bytes happen to be there.
    #[test]
    fn delete_refuses_a_position_that_holds_no_record() {
        let dir = crate::testing::scratch("block-delete-refuses-unknown-position");
        let path = seed(&dir);
        let mut block = block(path.clone());
        block.insert(&record(1)).expect("seed a record");
        let before = std::fs::read(&path).expect("read the fixture");

        let e = block.delete(9999).expect_err("9999 holds no record");
        assert!(e.why.contains("9999"), "{e}");

        let after = std::fs::read(&path).expect("read back");
        assert_eq!(after, before, "a refused delete must not touch the file");
    }

    /// The measured shape end to end at the `Block` level: the record leaves
    /// the in-memory model, the file control record's free-list head becomes
    /// the deleted position, the deleted slot's own bytes hold the forwarding
    /// link `pages::delete_record`'s doc comment describes, and the record
    /// count drops by one -- all four surviving a dropped cache and a fresh
    /// read off disk, the same check
    /// [`a_block_that_writes_is_readable_after_its_cache_is_dropped`] makes
    /// for insert.
    #[test]
    fn delete_removes_the_record_from_the_model_and_updates_the_free_list_on_disk() {
        let dir = crate::testing::scratch("block-delete-updates-free-list");
        let path = seed(&dir);
        let mut block = block(path.clone());
        let first = block.insert(&record(1)).expect("first insert");
        let second = block.insert(&record(2)).expect("second insert");

        block.delete(first).expect("delete");

        assert!(
            block.records().expect("reads").find_physical(first).is_none(),
            "gone from the in-memory model"
        );
        assert!(
            block.records().expect("reads").find_physical(second).is_some(),
            "the other record is untouched"
        );
        assert_eq!(block.geometry.records, 1, "the model's own count dropped by one");

        let bytes = std::fs::read(&path).expect("read back");
        assert_eq!(
            pages::long(&bytes[pages::fcr::FREE..pages::fcr::FREE + 4]),
            first,
            "the free-list head is the deleted position"
        );
        assert_eq!(
            pages::long(&bytes[first as usize..first as usize + 4]),
            pages::NOWHERE,
            "the deleted slot's own forwarding link -- nothing was free before this delete"
        );
        assert_eq!(
            pages::long(&bytes[pages::fcr::RECORDS_HIGH..pages::fcr::RECORDS_HIGH + 4]),
            1,
            "the on-disk record count dropped by one"
        );

        // Cache dropped, fresh read off disk: the deletion reached the file,
        // not only the `Records` cache.
        block.records = None;
        let reread = block.records().expect("a fresh read from disk");
        assert_eq!(reread.len(), 1, "disk has only the surviving record");
        assert!(reread.find_physical(second).is_some());
        assert!(reread.find_physical(first).is_none());
    }

    /// Closes the loop `pages::delete_record`'s doc comment describes from
    /// the write side: a slot freed by `Block::delete` is the slot the very
    /// next `Block::insert` reuses, at the `Block` level rather than
    /// `pages::Layout::next_slot`'s own unit tests. A mutation that deleted
    /// the record everywhere BUT forgot to update the on-disk free-list head
    /// would still pass every assertion in the test above that only reads
    /// `fcr::FREE` once -- this one only passes if a REAL subsequent write
    /// consults it.
    #[test]
    fn a_slot_freed_by_delete_is_reused_by_the_next_insert() {
        let dir = crate::testing::scratch("block-delete-slot-is-reused");
        let path = seed(&dir);
        let mut block = block(path);
        let first = block.insert(&record(1)).expect("first insert");
        block.insert(&record(2)).expect("second insert");

        block.delete(first).expect("delete the first");
        let reused = block.insert(&record(3)).expect("third insert");

        assert_eq!(reused, first, "the freed slot came back, not a fresh one");
        assert_eq!(block.geometry.pages, 5, "no new page was needed");
    }

    /// The two-entry case: `pages::delete_record`'s doc comment on
    /// `Layout::next_slot`'s pop-from-head reuse only has one entry to prove
    /// itself against in the test above. Deleting a SECOND record must link
    /// it ahead of the first, not overwrite the list's only entry -- a
    /// mutation that always wrote `NOWHERE` as the forwarding link (ignoring
    /// whatever the free-list head already was) would pass the single-delete
    /// test above but strand the first deletion's slot here, unreachable
    /// from the head.
    #[test]
    fn two_deletes_leave_a_two_entry_free_list_in_lifo_order() {
        let dir = crate::testing::scratch("block-delete-two-entry-free-list");
        let path = seed(&dir);
        let mut block = block(path);
        let first = block.insert(&record(1)).expect("first insert");
        let second = block.insert(&record(2)).expect("second insert");
        block.insert(&record(3)).expect("third insert");

        block.delete(first).expect("delete the first");
        block.delete(second).expect("delete the second");

        // LIFO: the most recently deleted slot comes back first.
        let reused_second = block.insert(&record(4)).expect("fourth insert");
        assert_eq!(reused_second, second, "the second deletion's slot is reused first");
        let reused_first = block.insert(&record(5)).expect("fifth insert");
        assert_eq!(reused_first, first, "the first deletion's slot comes back second");
    }

    // Task 6: transactions. Ops 19/20/21 (`dfaBegTrans`/`dfaEndTrans`/
    // `dfaAbtTrans`) as ABI-independent `Btrieve` methods -- semantics only,
    // no shim registration (that is Task 7's marshalling, blocked on the
    // `abi` branch's `Abi` trait landing on `main`). Every behaviour here was
    // measured against genuine Btrieve 6.15 first with
    // `tools/btrieve-oracle/xactprobe.c`; see `Btrieve::begin`/`end`/`abort`'s
    // doc comments for the raw probe output each test is reproducing.

    /// A `Btrieve` over a set of already-open blocks, built directly rather
    /// than through [`Btrieve::open`] -- these tests are about the
    /// transaction bookkeeping in [`Btrieve::begin`]/[`Btrieve::end`]/
    /// [`Btrieve::abort`], not about opening a file, and every field here is
    /// visible to `mod tests` as a descendant of the module that declares
    /// them private.
    fn btrieve_with(open: Vec<Block<Wg16>>) -> Btrieve<Wg16> {
        Btrieve {
            open,
            stack: [FarPtr::NULL; BBSTSZ],
            mode: 0,
            transaction: false,
            locks: ops::LockTable::default(),
        }
    }

    #[test]
    fn beginning_a_transaction_when_one_is_already_open_is_refused() {
        let mut btrieve = btrieve_with(vec![]);
        btrieve.begin().expect("the first begin opens one");
        let e = btrieve.begin().expect_err("nested begin is refused, not stacked");
        assert_eq!(e, TransactionError::AlreadyActive);
    }

    #[test]
    fn ending_a_transaction_with_none_open_is_refused() {
        let mut btrieve = btrieve_with(vec![]);
        let e = btrieve.end().expect_err("nothing was begun");
        assert_eq!(e, TransactionError::NoneActive);
    }

    #[test]
    fn aborting_a_transaction_with_none_open_is_refused() {
        let mut btrieve = btrieve_with(vec![]);
        let e = btrieve.abort().expect_err("nothing was begun");
        assert_eq!(e, TransactionError::NoneActive);
    }

    /// Reproduces `xactprobe`'s `nested` scenario past its first `abort`:
    /// `nested: abort status=0 (OK)` then `nested: second abort status=39
    /// (?)` -- the same status `end_no_begin`/`abort_no_begin` give with no
    /// `begin` at all. One `abort` closes the transaction completely; there
    /// is no outer transaction left standing for a second `abort` to find.
    #[test]
    fn a_second_abort_right_after_the_first_finds_nothing_open() {
        let mut btrieve = btrieve_with(vec![]);
        btrieve.begin().expect("begin");
        btrieve.abort().expect("first abort closes it");
        let e = btrieve.abort().expect_err("nothing is open a second time");
        assert_eq!(e, TransactionError::NoneActive);
    }

    #[test]
    fn begin_marks_every_currently_open_block_as_covered() {
        let dir = crate::testing::scratch("txn-begin-marks-open-blocks");
        let path = seed(&dir);
        let mut btrieve = btrieve_with(vec![block(path)]);

        assert!(!btrieve.open[0].txn_active, "not covered before begin");
        btrieve.begin().expect("begin");
        assert!(btrieve.open[0].txn_active, "covered the moment begin returns");
    }

    /// `Btrieve::open` (the real one, not the test helper `block()`) is where
    /// a file that did not exist yet when `begin` ran picks up coverage --
    /// exercised through the genuine method, with a real `Machine` and
    /// `Heap`, because that propagation lives in `open` itself and a
    /// hand-built `Block` pushed straight into `open` (as `open_indexed`
    /// does for other tests here) would skip the code path this test is for.
    #[test]
    fn a_file_opened_after_begin_is_covered_too() {
        let mut machine = Machine::new().expect("a 16-bit machine");
        // Explicit `<Wg16>`, unlike every other `Heap::new` in this module:
        // this is the first test to call the real `Btrieve::open` directly
        // rather than through `open_indexed` (whose own signature is
        // concrete and pins the type there) -- with nothing else in this
        // test naming a concrete `A::Mem`/`A::Ptr`, `A` has nothing to
        // infer from until `open`'s own call below, and Rust does not solve
        // an associated-type equation backwards from an argument's concrete
        // type to find which `A` produces it.
        let mut heap = crate::Heap::<Wg16>::new(crate::Config::default());
        let mut btrieve = Btrieve::default();

        btrieve.begin().expect("begin before anything is open");

        // `SAMPLE.DAT`: a real, committed fixture with a genuine key
        // definition (`crates/mbbs/tests/data/SAMPLE.DAT`, what
        // `shims::btrieve`'s own `opnbtv` tests open) -- unlike this file's
        // hand-built `seed`/`seed_indexed` fixtures, which only ever back a
        // hand-rolled `Geometry`/`Key` and have no real key bytes at `0x110`
        // for `keys::parse` to read. This is the first test in this module to
        // drive the real `Btrieve::open`, so it needs a fixture that survives
        // both `Geometry::read` and `keys::parse`, not just one.
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/SAMPLE.DAT");
        let geometry = Geometry::read("SAMPLE.DAT", &path).expect("reads");
        let at = btrieve
            .open(machine.mem_mut(), &mut heap, "SAMPLE.DAT", &path, geometry, 64)
            .expect("opens");

        assert!(
            btrieve.block(at).expect("open").txn_active,
            "a file opened mid-transaction is covered by it, matching real \
             Btrieve: dfaBegTrans has no per-file scope"
        );
    }

    /// Reproduces `xactprobe`'s `visibility` scenario: `insert status=0
    /// (OK)`, then `get-inside-txn status=0 (OK) tag=aa` -- the write is
    /// visible to a read on the same client before `end`, because this
    /// host's `insert` already writes straight through rather than buffering
    /// until commit.
    #[test]
    fn an_insert_made_after_begin_is_visible_before_end() {
        let dir = crate::testing::scratch("txn-insert-visible-before-end");
        let path = seed(&dir);
        let mut btrieve = btrieve_with(vec![block(path)]);
        btrieve.begin().expect("begin");

        let position = btrieve.open[0].insert(&record(1)).expect("insert");

        let seen = btrieve.open[0]
            .records()
            .expect("reads")
            .find_physical(position)
            .is_some();
        assert!(seen, "visible before end, same as the real engine");
    }

    /// Reproduces `xactprobe`'s `abort_insert` scenario: after `abort`, a
    /// `GET_EQUAL` for the inserted key found nothing, both
    /// `get-after-abort-same-session` and `get-after-close-reopen` -- so this
    /// checks both the in-memory model (no re-read) and a fresh read off
    /// disk (cache dropped), the same distinction
    /// `a_block_that_writes_is_readable_after_its_cache_is_dropped` draws for
    /// an ordinary insert.
    #[test]
    fn abort_undoes_an_insert_both_in_memory_and_on_disk() {
        let dir = crate::testing::scratch("txn-abort-undoes-insert");
        let path = seed(&dir);
        let mut btrieve = btrieve_with(vec![block(path.clone())]);
        // A record from before the transaction, so this test can also see
        // that abort does not touch it -- see the companion test below for
        // the write made *after* begin being the only one undone.
        let baseline = btrieve.open[0].insert(&record(1)).expect("baseline insert");

        btrieve.begin().expect("begin");
        let inserted = btrieve.open[0].insert(&record(2)).expect("insert inside the transaction");
        assert!(
            btrieve.open[0].records().expect("reads").find_physical(inserted).is_some(),
            "visible before abort"
        );

        btrieve.abort().expect("abort");

        assert!(!btrieve.open[0].txn_active, "the block is no longer covered");
        assert!(btrieve.open[0].pre_image.is_none(), "the pre-image is discarded, not kept");
        assert_eq!(btrieve.open[0].geometry.records, 1, "the count reverts too");

        let model = btrieve.open[0].records().expect("in-memory model after abort");
        assert!(model.find_physical(baseline).is_some(), "the baseline survives");
        assert!(model.find_physical(inserted).is_none(), "the transaction's insert does not");

        // And a fresh read off disk, cache dropped, agrees with the model --
        // the rollback reached the file, not only the `Records` cache.
        btrieve.open[0].records = None;
        let reread = btrieve.open[0].records().expect("a fresh read from disk");
        assert_eq!(reread.len(), 1, "disk has only the baseline record");
        assert!(reread.find_physical(baseline).is_some());
    }

    /// Reproduces `xactprobe`'s `abort_update` scenario: `get-inside-txn`
    /// showed the new tag (`22`), and after `abort`,
    /// `get-after-abort-same-session` and `get-after-close-reopen` both
    /// showed the old one (`11`) again.
    #[test]
    fn abort_undoes_an_update_both_in_memory_and_on_disk() {
        let dir = crate::testing::scratch("txn-abort-undoes-update");
        let path = seed(&dir);
        let mut btrieve = btrieve_with(vec![block(path)]);
        let position = btrieve.open[0].insert(&record(1)).expect("baseline insert");

        btrieve.begin().expect("begin");
        btrieve.open[0].update(position, &record(9)).expect("update inside the transaction");
        assert_eq!(
            btrieve.open[0]
                .records()
                .expect("reads")
                .find_physical(position)
                .and_then(|at| btrieve.open[0].records.as_ref().expect("loaded").physical(at))
                .expect("still there")
                .bytes[0],
            9,
            "the new value is visible before abort"
        );

        btrieve.abort().expect("abort");

        btrieve.open[0].records = None;
        let reread = btrieve.open[0].records().expect("a fresh read from disk");
        assert_eq!(
            reread
                .find_physical(position)
                .and_then(|at| reread.physical(at))
                .expect("still there")
                .bytes[0],
            1,
            "the pre-transaction value, not the update, survives on disk"
        );
    }

    /// Reproduces `xactprobe`'s `abort_delete` scenario: `delete status=0
    /// (OK)`, then `get-inside-txn status=4 (key value not found)`, and after
    /// `abort`, `get-after-abort-same-session status=0 (OK) tag=33` and
    /// `get-after-close-reopen status=0 (OK) tag=33` -- the record comes back
    /// both in the same session and after a fresh read off disk.
    #[test]
    fn abort_undoes_a_delete_both_in_memory_and_on_disk() {
        let dir = crate::testing::scratch("txn-abort-undoes-delete");
        let path = seed(&dir);
        let mut btrieve = btrieve_with(vec![block(path)]);
        // A second record from before the transaction, so this test can also
        // see that abort's restore does not disturb it -- the same shape
        // `abort_undoes_an_insert_both_in_memory_and_on_disk` uses a baseline
        // for.
        let survivor = btrieve.open[0].insert(&record(1)).expect("survivor insert");
        let position = btrieve.open[0].insert(&record(9)).expect("baseline insert");

        btrieve.begin().expect("begin");
        btrieve.open[0].delete(position).expect("delete inside the transaction");
        assert!(
            btrieve.open[0].records().expect("reads").find_physical(position).is_none(),
            "gone before abort, matching xactprobe's get-inside-txn status 4"
        );

        btrieve.abort().expect("abort");

        assert!(!btrieve.open[0].txn_active, "the block is no longer covered");
        assert!(btrieve.open[0].pre_image.is_none(), "the pre-image is discarded, not kept");
        assert_eq!(btrieve.open[0].geometry.records, 2, "the count reverts too");

        let model = btrieve.open[0].records().expect("in-memory model after abort");
        assert!(model.find_physical(position).is_some(), "the deleted record comes back");
        assert!(model.find_physical(survivor).is_some(), "the survivor is undisturbed");

        // And a fresh read off disk, cache dropped, agrees with the model --
        // the rollback reached the file, not only the `Records` cache.
        btrieve.open[0].records = None;
        let reread = btrieve.open[0].records().expect("a fresh read from disk");
        assert_eq!(reread.len(), 2, "disk has both records again");
        assert!(reread.find_physical(position).is_some());
        assert!(reread.find_physical(survivor).is_some());
    }

    /// `Self::capture_for_journal`'s doc comment says a call that returns
    /// `Err` never captures one -- checked here for `delete` specifically,
    /// the same way its placement is checked for insert and update by every
    /// refusal test in this module running outside a transaction (where a
    /// stray capture is invisible: nothing ever reads `pre_image` if
    /// `txn_active` is false). Moving the call to the top of `delete`, ahead
    /// of the "holds no record" refusal, passed every other test in this
    /// module -- capturing a pre-image is idempotent and no bytes change
    /// between "top of function" and "just before the write" on a call that
    /// is about to fail anyway, so a snapshot taken early is byte-identical
    /// to one taken late. The only thing that mutation changes is whether
    /// `pre_image` becomes `Some` on a call that never wrote anything, and
    /// that is what this test pins.
    #[test]
    fn a_refused_delete_inside_a_transaction_does_not_capture_a_pre_image() {
        let dir = crate::testing::scratch("txn-refused-delete-no-pre-image");
        let path = seed(&dir);
        let mut btrieve = btrieve_with(vec![block(path)]);
        btrieve.open[0].insert(&record(1)).expect("seed a record");

        btrieve.begin().expect("begin");
        btrieve.open[0].delete(9999).expect_err("9999 holds no record");

        assert!(
            btrieve.open[0].pre_image.is_none(),
            "a refused delete wrote nothing, so there is nothing to have captured"
        );
    }

    /// The variable-length in-place rewrite path
    /// ([`Block::update`]'s `has_body`/`known` branch, which reaches
    /// [`Block::rewrite_variable`] instead of the fixed-length write below
    /// it) is a **second, separate** call to `capture_for_journal` --
    /// `update`'s doc comment on why variable-length files take a different
    /// path than fixed-length ones applies here too. A mutation that removed
    /// only this call site (leaving the fixed-length one intact) passed
    /// every other test in this module, including
    /// [`abort_undoes_an_update_both_in_memory_and_on_disk`], because that
    /// test's block is fixed-length and never reaches this branch. This test
    /// is what closes that gap: same fixture and position as
    /// [`update_rewrites_a_matching_variable_length_fragment_in_place`], now
    /// inside a transaction that gets aborted instead of kept.
    #[test]
    fn abort_undoes_a_variable_length_in_place_rewrite() {
        let dir = crate::testing::scratch("txn-abort-undoes-variable-rewrite");
        let path = seed_variable(&dir);
        let mut btrieve = btrieve_with(vec![block_variable(path.clone())]);

        let original = btrieve.open[0]
            .records()
            .expect("reads")
            .find_physical(70)
            .and_then(|at| btrieve.open[0].records.as_ref().expect("loaded").physical(at))
            .expect("the fixture's one record")
            .bytes
            .clone();

        btrieve.begin().expect("begin");
        let mut new_value = vec![0u8; 8];
        new_value[..2].copy_from_slice(&9u16.to_le_bytes());
        new_value.extend((100..120u8).collect::<Vec<u8>>());
        btrieve.open[0]
            .update(70, &new_value)
            .expect("an equal-length rewrite is handled");
        assert_ne!(
            btrieve.open[0]
                .records()
                .expect("reads")
                .find_physical(70)
                .and_then(|at| btrieve.open[0].records.as_ref().expect("loaded").physical(at))
                .expect("still there")
                .bytes,
            original,
            "the rewrite is visible before abort"
        );

        btrieve.abort().expect("abort");

        let model = btrieve.open[0].records().expect("in-memory model after abort");
        let restored = model.find_physical(70).and_then(|at| model.physical(at)).expect("still there");
        assert_eq!(restored.bytes, original, "the in-memory model reverts to the original fragment");

        btrieve.open[0].records = None;
        let reread = btrieve.open[0].records().expect("a fresh read from disk");
        let reread_record = reread.find_physical(70).and_then(|at| reread.physical(at)).expect("still there");
        assert_eq!(reread_record.bytes, original, "and so does a fresh read off disk");
    }

    /// Reproduces `xactprobe`'s `fail_inside` scenario indirectly: `end`
    /// keeps the write rather than rolling it back, matching real Btrieve
    /// where every op after a failed one (including the eventual `end`)
    /// still succeeded and both records were there on reopen. This host has
    /// no buffered-write path for `end` to flush -- see [`Btrieve::end`]'s
    /// doc comment -- so what `end` actually has to get right is *not*
    /// undoing anything, and discarding the now-useless pre-image.
    #[test]
    fn ending_a_transaction_keeps_the_write_and_discards_the_pre_image() {
        let dir = crate::testing::scratch("txn-end-keeps-write");
        let path = seed(&dir);
        let mut btrieve = btrieve_with(vec![block(path)]);

        btrieve.begin().expect("begin");
        let inserted = btrieve.open[0].insert(&record(1)).expect("insert");
        assert!(btrieve.open[0].pre_image.is_some(), "captured on the first write");

        btrieve.end().expect("end");

        assert!(!btrieve.open[0].txn_active, "no longer covered");
        assert!(btrieve.open[0].pre_image.is_none(), "the pre-image is discarded");

        btrieve.open[0].records = None;
        let reread = btrieve.open[0].records().expect("a fresh read from disk");
        assert!(reread.find_physical(inserted).is_some(), "the write survives end");
    }

    /// Scope check: a write made **before** `begin` is not what a later
    /// `abort` undoes -- there is no pre-image of it to restore, because
    /// [`Block::capture_for_journal`] only ever runs once `txn_active` is
    /// true. Without this, a test that only ever inserts *after* begin
    /// cannot tell "abort undoes this transaction's writes" from "abort
    /// undoes every write this block has ever seen" -- see this test's
    /// mutation-table entry.
    #[test]
    fn a_write_before_begin_is_untouched_by_a_later_abort() {
        let dir = crate::testing::scratch("txn-write-before-begin-survives-abort");
        let path = seed(&dir);
        let mut btrieve = btrieve_with(vec![block(path)]);
        let before = btrieve.open[0].insert(&record(1)).expect("before begin");

        btrieve.begin().expect("begin");
        btrieve.abort().expect("abort with nothing written since begin");

        let model = btrieve.open[0].records().expect("reads");
        assert!(model.find_physical(before).is_some(), "a pre-begin write survives an abort");
    }

    /// The pre-image is captured **once**, at the first write since `begin`
    /// -- not refreshed on every write. If it were refreshed, the second
    /// write's "before" state (which already includes the first write) would
    /// be what abort restores to, and the first write inside the transaction
    /// would survive an abort that is supposed to undo the whole
    /// transaction. Both inserts made after `begin` must be gone after
    /// `abort`, not just the second.
    #[test]
    fn a_second_write_in_the_same_transaction_does_not_reset_the_pre_image() {
        let dir = crate::testing::scratch("txn-second-write-keeps-first-pre-image");
        let path = seed(&dir);
        let mut btrieve = btrieve_with(vec![block(path)]);

        btrieve.begin().expect("begin");
        let first = btrieve.open[0].insert(&record(1)).expect("first insert this transaction");
        let second = btrieve.open[0].insert(&record(2)).expect("second insert this transaction");

        btrieve.abort().expect("abort");

        let model = btrieve.open[0].records().expect("reads");
        assert!(model.find_physical(first).is_none(), "the first write is undone too");
        assert!(model.find_physical(second).is_none(), "and the second");
        assert_eq!(model.len(), 0, "back to nothing, the state before begin");
    }

    /// [`Btrieve::close`]'s new refusal: closing a block a transaction has
    /// already written to would take its rollback out of a later abort's
    /// reach (see `close`'s doc comment), so this refuses rather than let
    /// that happen silently.
    #[test]
    fn closing_a_block_with_an_outstanding_pre_image_is_refused() {
        let mut machine = Machine::new().expect("a 16-bit machine");
        let mut heap = crate::Heap::new(crate::Config::default());
        let mut btrieve = Btrieve::default();

        let path = seed_indexed(&crate::testing::scratch("txn-close-refuses-outstanding-pre-image"));
        let at = open_indexed(&mut machine, &mut heap, &mut btrieve, path);

        btrieve.begin().expect("begin");
        btrieve
            .block_mut(at)
            .expect("open")
            .insert(&record(1))
            .expect("insert, which captures a pre-image");

        let e = btrieve
            .close(machine.mem_mut(), &mut heap, at)
            .expect_err("a write from this transaction has nowhere to go on abort otherwise");
        assert!(e.why.contains("transaction"), "{e}");

        // Still open, and still covered -- the refusal did not half-close it.
        assert!(btrieve.block(at).is_ok(), "still open after the refusal");
        btrieve.abort().expect("abort still works after the refused close");
        let model = btrieve.block(at).expect("still open").loaded();
        assert!(
            model.is_none_or(|records| records.is_empty()),
            "the insert this test never got to keep was rolled back"
        );
    }
}
