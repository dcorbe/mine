//! A Btrieve 6.15 engine, and the session that holds open files.
//!
//! Depends on nothing but `std` at runtime, deliberately, and
//! `tests/independence.rs` is a mechanical guard that it stays that way. The
//! one exception is test-only and named, not silent: `[dev-dependencies]`
//! carries exactly `btrieve-oracle`, and only
//! `crates/btrieve/tests/differential.rs` (Task 12's replay of genuine
//! Pervasive Btrieve 6.15's own recorded fixtures) is allowed to name it --
//! `independence.rs` checks both the manifest section and the source scan
//! for that exact shape, not just that `src/` is clean. Three consumers need
//! this engine and no two of them agree on anything
//! else: the MajorBBS/Worldgroup host serves it to 16- and 32-bit modules, a
//! DOS guest reaches it through an interrupt, and a Win32 host reaches it
//! through `wbtrv32.dll!BTRCALL`. Those last two are what the vendor's offline
//! maintenance utilities need -- see
//! `docs/plans/2026-08-17-offline-utilities-design.md`.
//!
//! What the session needs from whoever owns the memory is [`mem::Mem`], plus
//! [`mem::Alloc`] for the two operations that allocate. Eleven items, all
//! pointer, memory or allocation concerns, and nothing about calling
//! conventions or module hosting. [`testing::Flat`] satisfies them in about
//! forty lines, which is the measure of how narrow the seam is.
//!
//! # Btrieve files: the geometry in a file's first page
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

pub mod acs;
pub mod btrcall;
mod cache;
pub mod canvas;
pub mod corpus;
pub mod census;
mod create;
pub mod emit;
pub mod format;
pub mod keys;
pub mod mem;
pub mod model;
mod nav;
mod order;
mod ops;
pub mod pages;
pub mod read;
pub mod records;
mod stat;
pub mod testing;
pub mod verify;
mod variable;
pub(crate) mod v6;

use std::fmt;
use std::path::{Path, PathBuf};

use crate::mem::{Alloc, BlockAbi, Mem};

pub use crate::create::{create, FileSpec, KeySpec, SegmentSpec};
pub use crate::keys::Key;
pub use crate::ops::{BlockId, Delivery, LockMode, LockTable, Op, OpError, Step};
pub use crate::records::{Record, Records};
use crate::records::V6_SLOT_MARKER;
pub use crate::stat::{deliver, Stat, StatKey};

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

/// Where a v6 record physically is, and the page store it was found in.
///
/// [`Block::v6_slot`]'s answer: every v6 write needs all four of these and
/// none of them should be re-derived from another. `store` rides along
/// because opening it is the first thing each of them does anyway and
/// opening a second one would let the two disagree about what is dirty.
struct V6Slot {
    /// The file's pages, read lazily from here on -- not the whole file.
    store: v6::Store,
    /// The record's logical page -- what its position names.
    logical: u32,
    /// The physical page currently holding that logical page.
    physical: u32,
    /// The slot's byte offset within a page, marker included.
    within: usize,
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
/// marshalling does that); the first two variants below are what
/// `dfaBegTrans` and `dfaEndTrans`/`dfaAbtTrans` each need to tell apart.
///
/// [`Self::CommitFailed`] is Task 7's own addition, unmeasured against the
/// real engine (`xactprobe` has no disk-full scenario): [`Btrieve::end`]'s
/// deferred commit is the first point a transaction's own flush can fail
/// after the fact rather than at the failing op itself -- every op inside a
/// transaction that defers now only *stages* into a cache, which cannot
/// fail the way a real disk write can, so a genuine `ENOSPC`/`EIO` surfaces
/// here instead. No longer `Copy` because of it -- carrying the failure's
/// own message needs an owned `String`; every other derive is unaffected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionError {
    /// [`Btrieve::begin`] while a transaction was already open.
    AlreadyActive,
    /// [`Btrieve::end`] or [`Btrieve::abort`] with none open.
    NoneActive,
    /// [`Btrieve::end`]'s deferred flush failed for at least one covered
    /// block -- the first such failure's own message. Every other covered
    /// block still has its transaction bookkeeping closed out (see
    /// [`Btrieve::end`]'s own doc comment for why one block's disk error
    /// must not strand every other block's commit); the block that failed
    /// is left with its cache invalidated, matching
    /// [`Block::write_changed_pages`]'s existing failure handling.
    CommitFailed(String),
}

impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyActive => write!(f, "a transaction is already open"),
            Self::NoneActive => write!(f, "no transaction is open"),
            Self::CommitFailed(why) => write!(f, "committing a transaction failed: {why}"),
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
    // A v5-family file control record opens with four zero bytes and carries
    // its version in byte 7. Measured 2026-08-15 (Track B Task 8), replacing a
    // comment whose only authority was MBBSEmu's transcription of the same
    // range:
    //
    // - **Byte 7 really is the version.** Genuine Btrieve 6.15's own `stat`
    //   returns an index word whose high nibble is the file version -- `0x3001`
    //   for a byte-7 == 3 file, `0x4001` for a byte-7 == 4 one, `0x6001` for a
    //   v6 file. That arrives through the Btrieve API, not out of this header,
    //   so it is a second agreeing source rather than the same byte read twice.
    // - **3 is not theoretical.** A census of 849 `.DAT`/`.VIR` files across
    //   this repository found 191 at byte 7 == 4 and six distinct files at
    //   byte 7 == 3 -- and those six are MajorBBS's own core host files
    //   (`USRACC.DAT`, `EMAIL.DAT`, `CLASSADS.DAT`, `CLASSRSP.DAT`,
    //   `AUDITRAI.DAT`, `SYSVBL.DAT`). They read correctly at these offsets;
    //   `a_v3_file_reads_with_the_geometry_the_genuine_engine_reports` pins
    //   three of them against the engine's own numbers.
    // - **5 was never observed.** Not one file in the census carries byte
    //   7 == 5. It stays accepted because Btrieve 5.x existed and a 5 here
    //   would mean the version this family is named for -- but it is accepted
    //   on that reasoning, untested, and this comment is the disclosure. Every
    //   v5-family file this host has actually read is a 3 or a 4.
    //
    // A file outside the range is refused rather than read on the assumption
    // that the fields did not move.
    if bytes[..4] == [0, 0, 0, 0] && bytes[6] == 0 && (3..=5).contains(&bytes[7]) {
        return Some(Version::V5);
    }
    None
}

/// How many times this process has opened a file to serve a Btrieve read,
/// since the last [`testing::reset_file_opens`].
///
/// This crate's own choke-point count, not a kernel one: `/proc/self/io`'s
/// `syscr` counts `read(2)`, and a page cached by [`v6::Store`] is read at
/// most once regardless of how many times something asks for it, so `syscr`
/// alone cannot see an open-per-page caller collapse to an open-per-operation
/// one -- only the open count moves. Linux exposes no per-process `open(2)`
/// counter of its own (that needs ptrace or an audit rule, both out of reach
/// for a std-only crate), so this is counted here instead.
///
/// **Reads only.** [`open_for_read`] and [`read_whole`] are the only two
/// places in this crate's non-test code allowed to call
/// `std::fs::File::open`/`std::fs::read` directly --
/// `tests/file_opens_guard.rs` fails the build if a third one appears
/// outside a `#[cfg(test)]` module. A write open (`std::fs::OpenOptions`, in
/// [`pages`], [`variable`] and this file) is a separate question this
/// counter does not answer: the live defect this counter was built to catch
/// was a read-per-page pattern, a write already touches exactly the pages it
/// changes by construction, and folding writes in here would make a bound
/// written against reads silently start describing something else.
pub(crate) static FILE_OPENS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many times this process has read a page from disk into a
/// [`cache::PageCache`], since the last [`testing::reset_page_fetches`].
///
/// The same reasoning as [`FILE_OPENS`], one level down: Linux exposes no
/// per-process counter for "how many distinct pages did a cache actually go
/// to disk for" either, and a page cache's whole job is keeping that number
/// from scaling with how many times something asks for the same page --
/// [`cache::PageCache::page`]'s own doc comment names the one call site
/// this is incremented from.
pub(crate) static PAGE_FETCHES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many times this process has run [`order::OrderIndex::build`] (a
/// full walk of one key's tree, positions only) since the last
/// [`testing::reset_order_builds`].
///
/// [`PAGE_FETCHES`] cannot tell a real rebuild apart from a cheap reuse
/// once every page either would touch is already resident in the same
/// [`cache::PageCache`] -- a `Block`'s cache never evicts, so a key's whole
/// tree stays warm for the rest of that block's open lifetime after the
/// first walk, and a *second* walk over the same warm pages costs zero new
/// fetches too, even though it re-does the same O(records) work. This
/// counts the walk itself, at its one call site
/// ([`Block::v6_build_order`]), so a test proving `Self::v6_invalidate_
/// keys`'s per-key selectivity has something that actually discriminates
/// "rebuilt" from "reused".
pub(crate) static ORDER_BUILDS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Open `path` for reading, counting the open in [`FILE_OPENS`].
///
/// The only place in this crate's non-test code allowed to call
/// `std::fs::File::open` -- every other read-serving site opens through
/// this function, or through [`read_whole`], so the count in [`FILE_OPENS`]
/// can never miss one. `tests/file_opens_guard.rs` enforces that mechanically.
///
/// # Errors
///
/// Whatever `std::fs::File::open` returns.
pub(crate) fn open_for_read(path: &Path) -> std::io::Result<std::fs::File> {
    let file = std::fs::File::open(path)?;
    FILE_OPENS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(file)
}

/// The whole contents of `path`, counting the open in [`FILE_OPENS`].
///
/// Built on [`open_for_read`] rather than `std::fs::read` directly, so the
/// crate has exactly one place that calls `std::fs::File::open` and none
/// that calls `std::fs::read` -- the second half of what
/// `tests/file_opens_guard.rs` checks.
///
/// # Errors
///
/// Whatever [`open_for_read`] or the read itself returns.
pub(crate) fn read_whole(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;

    let mut file = open_for_read(path)?;
    let mut out = Vec::new();
    file.read_to_end(&mut out)?;
    Ok(out)
}

/// The first `len` bytes of a file, or fewer if it is shorter.
///
/// `WCCUPDAT.DAT` is 77 MB and `WCCMP001.VIR` 43. Reading a header is reading a
/// header.
///
/// Opens `path` itself -- for the one-shot callers this exists for (a file
/// scanned once, at open/census/stat time). A caller reading many times from
/// the same file within one operation should hold its own `File` and call
/// [`read_head_open`] instead; see that function's own doc comment for why.
fn read_head(path: &Path, len: usize) -> std::io::Result<Vec<u8>> {
    let mut file = open_for_read(path)?;
    read_head_open(&mut file, len)
}

/// [`read_head`]'s body, through a handle the caller already has open rather
/// than one this function opens itself -- no [`FILE_OPENS`] count of its own,
/// because it opens nothing.
fn read_head_open(file: &mut std::fs::File, len: usize) -> std::io::Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};

    file.seek(SeekFrom::Start(0))?;
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

/// The `len` bytes of a file starting at `offset`, or fewer if it is shorter.
///
/// Seeks rather than reading from the start, for the same reason
/// [`read_head`] does not read the whole file: a v6 file's second
/// control-record copy can start many kilobytes in, and this file can be
/// tens of megabytes.
///
/// Opens `path` itself, same one-shot caveat as [`read_head`]: a caller that
/// reads many times from the same file within one operation should hold its
/// own `File` and call [`read_at_open`] instead. [`v6::Store`] is the reason
/// this distinction exists at all -- it used to reach here once per page,
/// which measured as 35,860 `openat`s in three seconds against a live
/// board's `WCCMP002.DAT` (`docs/2026-08-24-btrieve-write-cost-baseline.md`'s
/// follow-up); it now opens once per operation and calls [`read_at_open`].
pub(crate) fn read_at(path: &Path, offset: usize, len: usize) -> std::io::Result<Vec<u8>> {
    let mut file = open_for_read(path)?;
    read_at_open(&mut file, offset, len)
}

/// [`read_at`]'s body, through a handle the caller already has open rather
/// than one this function opens itself -- no [`FILE_OPENS`] count of its own,
/// because it opens nothing.
pub(crate) fn read_at_open(file: &mut std::fs::File, offset: usize, len: usize) -> std::io::Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};

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

/// Every alternate collating sequence `path` carries, in page order.
///
/// Empty when no key of the file declares one, which is the overwhelmingly
/// common case and costs no I/O to establish -- the gate is a walk of the key
/// definitions already in `fcr`, not a read.
///
/// One function rather than two so that [`Btrieve::open`] and
/// [`census::verdict`] cannot drift: the census exists to predict what `open`
/// will do, and a second copy of this search is a second thing to be wrong.
///
/// # Errors
///
/// If a page cannot be read, or a v6 page tagged as holding a block does not
/// hold one.
fn acs_tables(
    path: &Path,
    geometry: &Geometry,
    fcr: &[u8],
) -> Result<Vec<acs::Table>, String> {
    if !keys::declares_alt_collating(fcr, geometry.keys) {
        return Ok(Vec::new());
    }

    let page = usize::from(geometry.page);
    let mut found = Vec::new();
    match geometry.version {
        // A v6 key names its table by **logical** page, so the tables have to be
        // found by logical page -- and the allocation table is the only thing
        // that says which physical page a logical id is on.
        //
        // Deliberately not a scan for `'A'`-typed pages taking each page's own
        // header id: a page's self-stamp is stale bytes nothing should trust
        // (see [`v6`]'s header), and a freed former-ACS page that kept its type
        // tag and a stale id would shadow the live table. Going through the
        // allocation table sees only allocated slots, which is what the engine
        // does -- it hands the key's page number straight to the same page
        // resolver every other page goes through
        // (`W32MKDE_decompiled.c:15381`).
        Version::V6 => {
            // Open-time only, not `Block::update()`'s hot path -- reads the
            // whole file, same as before, wrapped in a `Store` only so
            // `v6::Map::read` stays one implementation.
            let whole = read_whole(path).map_err(|e| format!("{}: {e}", path.display()))?;
            let mut store = v6::Store::from_bytes(&whole, geometry.page)?;
            let map = v6::Map::read(&mut store, geometry.page)?;
            let mut resolved: Vec<(u32, u32)> = map.entries().collect();
            resolved.sort_unstable();
            for (logical, physical) in resolved {
                let at = physical as usize * page;
                let Some(bytes) = whole.get(at..at + page) else {
                    continue;
                };
                if acs::is_acs_page(bytes) {
                    found.push(acs::Table {
                        page: logical,
                        acs: std::sync::Arc::new(acs::decode(bytes)?),
                    });
                }
            }
        }
        // A v5 page carries no type byte, so there is nothing to scan for and
        // the block is at a fixed page instead. A page that does not decode
        // leaves `found` empty and `keys::parse` refuses the file, which is the
        // right answer for a file that declares a sequence it does not hold.
        //
        // Registered under page **zero**, which is what a v5 key definition
        // holds: that version has exactly one table and the engine takes it
        // from `FCR+0x10a` rather than per key
        // (`W32MKDE_decompiled.c:15364-15367`).
        Version::V5 => {
            let at = acs::V5_PAGE as usize * page;
            let bytes =
                read_at(path, at, page).map_err(|e| format!("{}: {e}", path.display()))?;
            if let Ok(table) = acs::decode(&bytes) {
                found.push(acs::Table {
                    page: 0,
                    acs: std::sync::Arc::new(table),
                });
            }
        }
    }
    Ok(found)
}

/// Bytes of `struct btvblk`, and where each field of it sits.
///
/// `BTVSTF.H:17`, with the `PHARLAP` fields -- which `WCCMMUD.DLL` is built
/// for, because a server module targets the 286|DOS-Extender rather than DOS:
///
/// Each field is written as the one before it plus that one's width, so the
/// struct's total size cannot drift from the offsets inside it. The absolute
/// numbers are pinned by [`tests::the_block_is_laid_out_the_way_btvstf_h_declares_it`].
/// Where each field of a module's file block sits, for one [`BlockAbi`].
///
/// This used to be a `mod field` of plain constants, which was correct for
/// exactly as long as this host ran only 16-bit modules. It is not one layout
/// -- see [`BlockAbi`] -- and the difference is not cosmetic: a module reads
/// `bb->data`/`dfa->data` itself, so two bytes of compiler padding this host
/// does not reproduce hand it a pointer field it will read straight through.
///
/// Every offset is derived from the field sequence rather than written down
/// twice, so the two layouts cannot drift apart; [`Layout::of`]'s own tests
/// pin both against the vendor headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    /// Btrieve's own 128-byte position block. Opaque to everybody, including
    /// the real host, which only ever handed its address to the TSR.
    pub posblk: u16,
    pub filnam: u16,
    pub reclen: u16,
    pub key: u16,
    pub data: u16,
    pub lastkn: u16,
    pub keylns: u16,
    /// One past the last `keylns` entry -- the bound a key-length write must
    /// stay inside. Under [`BlockAbi::Packed16`] this is also where
    /// `realseg`/`keyseg` begin.
    pub keylns_end: u16,
    /// The whole struct, which is what gets allocated.
    pub size: u16,
}

impl Layout {
    /// The layout `M`'s own compiler produced.
    pub fn of<M: Mem>() -> Self {
        Self::new(M::PTR_WIDTH as u16, M::BLOCK)
    }

    fn new(ptr_width: u16, abi: BlockAbi) -> Self {
        let posblk = 0;
        let filnam = posblk + 128;
        let reclen = filnam + ptr_width;
        // The whole difference between the two layouts, in one line. A
        // 16-bit compiler puts `key` straight after `reclen`'s two bytes; a
        // 32-bit one aligns a pointer to four, so `key` -- and `data`, and
        // everything after -- moves up by two.
        let key = match abi {
            BlockAbi::Packed16 => reclen + 2,
            BlockAbi::WinNt32 => (reclen + 2).next_multiple_of(4),
        };
        let data = key + ptr_width;
        let lastkn = data + ptr_width;
        // `lastkn` is `INT` in `btvblk` and `SHORT` in `dfablk`; both are two
        // bytes under `Packed16`, and under `WinNt32` this host lays out
        // `dfablk` (see `BlockAbi::WinNt32` for why `btvblk` is not
        // represented), where it is two.
        let keylns = lastkn + 2;
        let keylns_end = keylns + SEGMAX * 2;
        let size = match abi {
            // `realseg` then `keyseg`.
            BlockAbi::Packed16 => keylns_end + 4,
            // `flddefList[SEGMAX]`, a pointer array and so realigned to four,
            // then `unpackKeySiz[SEGMAX]`.
            BlockAbi::WinNt32 => {
                keylns_end.next_multiple_of(4) + SEGMAX * ptr_width + SEGMAX * 2
            }
        };
        Self {
            posblk,
            filnam,
            reclen,
            key,
            data,
            lastkn,
            keylns,
            keylns_end,
            size,
        }
    }
}

/// `BTVSTF.H:13` -- key segments per file, which sizes `keylns`.
const SEGMAX: u16 = 24;

/// `BTVSTF.H:14` -- how deep `setbtv`'s stack is.
const BBSTSZ: usize = 10;

/// `DFAAPI.H:24` -- how deep `dfaSetBlk`/`dfaRstBlk`'s stack is. Numerically
/// the same ten as [`BBSTSZ`], but a separate constant because it is a
/// separate stack behind a separate pointer -- see [`Btrieve::dfa_set`]'s own
/// doc comment for why `dfa`/`dfastk` are never aliases of `bb`/`bbstk`.
const DFSTSZ: usize = 10;

/// The five `opnbtv`/`dfaOpen` modes, `DFAAPI.H:29-33` (`BTVSTF.H:41-45`
/// names the identical five values for `omdbtv`). What each does to a
/// [`Block`] opened under it is Task 8's own subject -- see [`Btrieve::open`]
/// for where `mode` is captured onto the block, [`Block::insert`]/
/// [`Block::update`]/[`Block::delete`] for [`RONLBV`], the block's own
/// `verify_writes` field for [`VERFBV`], [`Btrieve::open`] again for
/// [`EXCLBV`], and [`Block::write_changed_pages_attempt`] for [`ACCLBV`].
/// A mode outside these five (`dfaMode` stores one unchecked, unlike
/// `omdbtv`) matches none of the checks below and behaves as [`PRIMBV`].
const PRIMBV: i16 = 0;
const ACCLBV: i16 = -1;
const RONLBV: i16 = -2;
const VERFBV: i16 = -3;
const EXCLBV: i16 = -4;

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
/// `block`/`data`/`key` are `M::Ptr` rather than `mbbs_machine::m16::FarPtr` -- they are
/// module-memory addresses the host handed a module, and the module's own
/// ABI decides their shape. `A` carries no default; every caller spells its
/// ABI, the same convention `mbbs`'s `Heap` and
/// `mbbs`'s `Messages` follow since Task 3 of
/// `docs/plans/2026-08-12-abi-border-implementation.md`. Every
/// method that never resolved a pointer against module memory -- `query`,
/// `get`, `step`, `insert`, `update`, `delete`, `reindex`, and the getters
/// below -- has no `A`-dependent behaviour and lives on `impl<M: Mem>
/// Block<M>` unchanged; only the three fields below and their own getters
/// name `M::Ptr`.
pub struct Block<M: Mem> {
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
    block: M::Ptr,

    /// What the module said its records are -- `opnbtv`'s `maxlen`, which sizes
    /// `data` and is what `bb->reclen` holds. **Not** the file's record length:
    /// `PLBTVSTF.C:150` stores the module's number, and the two disagreeing is
    /// a thing worth being able to see rather than to silence.
    maxlen: u16,

    /// The record buffer, `maxlen` bytes of the module's heap.
    data: M::Ptr,

    /// The key buffer, `clckln()` bytes of the module's heap. What a search
    /// value is copied into, and what a `Get Key` operation leaves the found
    /// key in.
    key: M::Ptr,

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

    /// Whether [`Self::insert`], [`Self::update`] and [`Self::delete`]
    /// should run [`Self::verify_write`] after a successful write.
    ///
    /// Explicit opt-in, not a blanket `#[cfg(debug_assertions)]`, and
    /// deliberately so: this crate's own unit tests build `Block` directly,
    /// bypassing [`Self::open`], with synthetic geometries far smaller than
    /// [`crate::format::generation::FCR_MIN`] -- real enough to exercise one
    /// piece of write-path logic (a free-list splice, a reindex) in
    /// isolation, but not shaped like a file [`crate::read::file`] was ever
    /// meant to parse. Measured directly: gating verification on
    /// `debug_assertions` alone, with no opt-in, turned 37 of those tests
    /// red -- every one of them a `NotBtrieve` refusal of a fixture that was
    /// never trying to be a complete file. [`Self::open`] -- the one path a
    /// real module's `opnbtv` reaches -- sets this to `cfg!(debug_assertions)
    /// || mode == VERFBV` (Task 8): the debug default is unchanged, and a
    /// block opened under `VERFBV` (`-3`, read-after-write) gets the same
    /// check even in a release build, because that mode is the caller
    /// asking for it by name. Every test-only `Block` literal in this crate
    /// leaves it `false` unless a test is deliberately exercising
    /// verification itself.
    verify_writes: bool,

    /// The mode this block was opened under -- `opnbtv`/`dfaOpen`'s
    /// `Btrieve::mode()` at the moment [`Self::open`] pushed it, one of the
    /// five `DFAAPI.H:29-33` constants (`PRIMBV`/`ACCLBV`/`RONLBV`/`VERFBV`/
    /// `EXCLBV`) or, since neither `omdbtv` nor `dfaMode` can be trusted to
    /// have refused an out-of-range value first (`dfaMode` stores one
    /// unchecked), anything else at all -- which then matches none of the
    /// five checks below and behaves as `PRIMBV`.
    ///
    /// Captured once, at open, not read live off `Btrieve::mode()` on every
    /// write: the real engine's mode governs the *open*, not calls made
    /// against an already-open file after a later `omdbtv`/`dfaMode`
    /// changed what the *next* open will use -- a file opened read-only
    /// stays read-only for its own lifetime regardless of what the module
    /// tells the next `opnbtv` to do.
    mode: i16,

    /// A v6 file's page cache, attached for this block's whole open
    /// lifetime -- `None` for a v5 file (no allocation table to re-walk)
    /// and for every test-built `Block` that skips [`Self::open`].
    ///
    /// `RefCell`, not a plain field: [`Self::v6_resolve_logical`] is a
    /// read-serving method other `Block` methods call with only `&self`,
    /// and it has to mutate this cache (fault a page in) without demanding
    /// `&mut self`. The host is single-threaded by construction, so the
    /// interior mutability this buys is never contended -- it exists for
    /// the borrow checker, not for concurrency.
    ///
    /// `Rc`, not a bare `&RefCell`: [`v6::Store::attach`] needs its own
    /// handle to the same cache for the length of one write
    /// (`insert_v6`/`update_v6`/`delete_v6`), and those functions still
    /// have to mutate *other* fields of `self` after building that `Store`
    /// -- `Self::capture_for_journal`, `self.dirty = true`, and the rest of
    /// each function's tail. A plain borrowed reference would tie the
    /// `Store`'s lifetime to a borrow of the whole `Block`, and the
    /// borrow checker cannot see that only `cache` is aliased -- it refuses
    /// the later `&mut self` outright (measured: `cannot borrow `*self` as
    /// mutable because it is also borrowed as immutable`, from a minimal
    /// reproduction of exactly this shape). `Rc::clone` hands `Store` an
    /// independent, reference-counted handle instead, with no lifetime tied
    /// to `self` at all.
    cache: Option<std::rc::Rc<std::cell::RefCell<cache::PageCache>>>,

    /// Each key's [`order::OrderIndex`] this block currently has cached,
    /// keyed by key number -- `RefCell` for the same reason [`Self::cache`]
    /// is one: [`Self::v6_ensure_order`]/[`Self::current`] read (and lazily
    /// build) through this from `&self`. Empty for a v5 block, a
    /// variable-length v6 one, or any block that has not yet answered a
    /// keyed v6 read -- see [`Self::v6_fast_reads`].
    ///
    /// Invalidated **per key**, not wholesale: [`Self::v6_invalidate_keys`]
    /// drops only the keys whose own extracted value actually changed (or
    /// whose [`keys::Key::excluded`] status flipped) -- an update that
    /// touches no key at all (the majority of live write traffic --
    /// health, gold, position) leaves every key's cached order exactly as
    /// it was, so the next keyed read after it costs nothing extra. See
    /// `docs/2026-08-24-btrieve-write-cost-baseline.md`'s own measurement
    /// of what whole-map invalidation used to cost such an update.
    v6_order: std::cell::RefCell<std::collections::HashMap<u16, order::OrderIndex>>,

    /// Every claimed, live position in this file, ascending -- the
    /// physical-order counterpart to [`Self::v6_order`], answering what
    /// [`records::Records::physical`]/[`records::Records::find_physical`]
    /// answer for `Cursor::Physical`/[`ops::Step`] without a single
    /// record's bytes. `None` until the first physical read since the last
    /// insert or delete invalidated it ([`Self::v6_invalidate_physical`]);
    /// an update never invalidates this -- it changes a record's bytes,
    /// never which positions exist.
    v6_physical: std::cell::RefCell<Option<order::OrderIndex>>,
}

/// One block's state as it was the moment a transaction first wrote to it --
/// enough to put both the disk and the in-memory model back exactly where
/// they were on [`Btrieve::abort`].
///
/// Genuine Pervasive Btrieve keeps this as a page-level pre-image file
/// (`docs/plans/2026-08-12-btrieve-finish.md` Task 6, and `DFAAPI.C`'s
/// `PRIMBV`/"normal pre-image `dfaMode()`" -- see `at::` in this file's
/// module doc comment). This host keeps the whole file's bytes instead of
/// only the pages a write touched -- for a v5 block, or a v6 one with no
/// page cache to defer into (see [`Block::write_changed_pages`]'s own
/// fallback for that second case): `Block::insert`/`Block::update` write
/// through several places (a data page, and on `insert` sometimes the
/// allocation table) and re-deriving exactly which bytes moved would have to
/// track every one of them precisely, where "the file as it was" cannot be
/// wrong by construction.
///
/// # `bytes` is `None` for a deferred (v6, cached) block -- Task 7
///
/// A v6 block with a cache attached defers every in-transaction write to
/// that cache instead of writing through immediately (`Block::
/// stage_changed_pages`), so disk is never touched for it between `begin`
/// and whichever of `end`/`abort` closes the transaction. There is nothing
/// on disk for a whole-file snapshot to be a pre-image *of* -- disk already
/// **is** the pre-image, for as long as the transaction lasts. Reading and
/// holding 55 MB of bytes that will never be written back would cost real
/// memory for a restore [`Btrieve::abort`] can instead get for free
/// ([`cache::PageCache::drop_dirty`]), so [`Block::capture_for_journal`]
/// skips the disk read entirely for such a block and leaves this `None`;
/// [`Btrieve::abort`] takes `None` here as "nothing to restore on disk",
/// not "nothing was captured" -- the in-memory fields below are still taken
/// unconditionally, because those are mutated directly regardless of
/// deferral and still need restoring.
#[derive(Debug)]
struct PreImage {
    /// The file's bytes before this transaction's first write to it, or
    /// `None` for a v6 block whose writes this transaction defers -- see
    /// this struct's own doc comment.
    bytes: Option<Vec<u8>>,
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

/// One key's index entries over `records`, in that key's order, plus the
/// record positions grouped under each entry.
///
/// **One entry per distinct key value**, and for a key that permits duplicates
/// that is fewer than `len`. Grouped with `key.compare` -- the same comparator
/// `Records::reindex` sorted by, so the group boundaries cannot disagree with
/// the order they fall in -- rather than by comparing the extracted key bytes,
/// which would split a group whenever a key folds two spellings of a value
/// onto one (an alternate collating sequence, or a case-insensitive name).
/// Btrieve's own index holds one entry per *value*, and two entries a binary
/// search cannot tell apart is a tree that reads back in a plausible wrong
/// order.
///
/// `len` is the caller's already-checked `records.ordered_len(key.number)`:
/// this function is reached from two places that report a key the records were
/// not ordered by differently, and neither wants that refusal duplicated here.
///
/// # Why this is a shared function rather than one loop
///
/// [`Btrieve::reindex`] needs the entries to build the tree and the groups to
/// write the duplicate chains; [`Btrieve::key_record_counts`] needs only how
/// many entries there are. That count is what genuine Btrieve stores as a
/// key's `approx_count` -- *distinct entries*, measured, not records; see
/// `stat.rs`'s own "`approx_count` is a stored field" section, where three
/// records sharing one key value read back 1. A second loop computing "the
/// same" count independently is exactly how the number a `B_STAT` reports and
/// the tree a close writes would come to disagree.
fn index_entries(
    records: &records::Records,
    key: &keys::Key,
    shift: usize,
    len: usize,
) -> (Vec<pages::Entry>, Vec<Vec<u32>>) {
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
    (entries, groups)
}

/// The phase boundaries of a v6 commit, where a test can stand in for a crash.
///
/// [`Block::write_changed_pages`] promises that the file on disk always reads
/// as either its old self or its new self, whatever moment it is interrupted
/// at. A promise about crashes is worth what can be checked, and a SIGKILL
/// cannot be staged from a test -- so the interruption is staged at the
/// boundaries the promise is actually made about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::enum_variant_names,
    reason = "the shared prefix is the meaning: each names a moment *after* a               phase, which is where an interruption is staged"
)]
pub(crate) enum Stop {
    /// Content pages are down and flushed; nothing live points at them.
    AfterContent = 1,
    /// Structural bodies are down, still carrying losing generations.
    AfterBodies = 2,
    /// The control record has flipped and the allocation table has not --
    /// the one window the design does not close, kept pointing the safe way.
    AfterFirstFlip = 3,
}

/// Which sibling an underflowing v6 B-tree node redistributes with or
/// merges into -- `docs/2026-08-25-btree-split-rules.md` §6's right-first
/// predicate (`Block::v6_tree_delete`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Left,
    Right,
}

/// One shadow pair's canonicalised write, computed by [`diff_changed_pages`]
/// and consumed by [`Block::write_changed_pages_attempt`] (writes it to
/// disk, held-back then flipped) and [`Block::stage_changed_pages`] (stages
/// it straight into the cache, generation already final -- a deferred write
/// has no disk crash to be safe against, only "does the cache end up
/// holding what N real flushes would have left").
struct Flip {
    page: usize,
    image: Vec<u8>,
    generation: u16,
}

/// The read-only diff every v6 commit path needs: which of `store`'s dirty
/// pages are plain content, and which shadow pairs (if any) need the
/// held-back-then-flip canonicalisation, and with what final bytes/
/// generation. Pulled out of [`Block::write_changed_pages_attempt`] so that
/// function's disk-writing tail and [`Block::stage_changed_pages`]'s
/// cache-only tail can share the one computation neither of them should
/// re-derive differently -- see [`Block::write_changed_pages_attempt`]'s own
/// doc comment for the shadow-paging design this computes.
fn diff_changed_pages(store: &v6::Store) -> (Vec<usize>, Vec<Flip>) {
    let old_pages = store.original_pages();

    let generation = |image: &[u8]| -> u16 {
        u16::from_le_bytes([image[at::GENERATION], image[at::GENERATION + 1]])
    };

    // The shadow pairs a write actually touched, control record first --
    // the order phase 3 flips them in. `structural_pairs()` is already
    // sorted ascending, and physical 0/1 (the control record, always
    // noted by `v6::write_fcr`) sorts first by construction.
    let pairs = store.structural_pairs();

    // A pair the file grew into is not a flip at all: neither half
    // existed before, so nothing of it is live and phase 1 puts both
    // halves down with everything else new.
    let flip_pairs: Vec<(usize, usize)> =
        pairs.iter().copied().filter(|&(_, second)| second < old_pages).collect();

    let mut flips: Vec<Flip> = Vec::new();

    for &(first, second) in &flip_pairs {
        let before_first = store.original(first).expect("noted structural pairs are read before written");
        let before_second = store.original(second).expect("noted structural pairs are read before written");
        let after_first = store.current(first);
        let after_second = store.current(second);

        // A pair neither half of which moved is not part of this write at
        // all. Without this the canonicalisation below "flips" every
        // untouched allocation-table block to its other half with a
        // bumped generation -- the same content, written for nothing. On
        // `WCCMP002.DAT`, whose table runs to fourteen blocks, that was
        // 13 spurious page writes out of 16.
        if before_first == after_first && before_second == after_second {
            continue;
        }
        let (live_before, stale_before) = if generation(before_first) > generation(before_second) {
            (first, second)
        } else {
            (second, first)
        };
        let live_after = if generation(after_first) > generation(after_second) {
            first
        } else {
            second
        };

        let wanted = if live_after == stale_before {
            // One flip, or an odd number of them: the winning image is
            // already on the half that was stale, and its own generation
            // already beats the half that was live.
            generation(store.current(live_after))
        } else {
            // An even number of flips landed the winner back on the half
            // that started live. Move it across and give it the smallest
            // generation that still wins, so the live half is never
            // written.
            generation(store.original(live_before).expect("read above")).wrapping_add(1)
        };

        let mut image = store.current(live_after).to_vec();
        image[at::GENERATION..at::GENERATION + 2].copy_from_slice(&wanted.to_le_bytes());
        let stale_before_bytes = store.original(stale_before).expect("read above");
        if image == stale_before_bytes {
            continue;
        }
        flips.push(Flip {
            page: stale_before,
            image,
            generation: wanted,
        });
    }

    // Everything else that changed. **Both** halves of every flip-
    // covered pair are excluded, not just the halves phase 2 writes:
    // canonicalising a double flip deliberately leaves the old live half
    // alone, so its bytes still differ from `original` and it must not
    // be mistaken for content. Leaving it is the point -- it becomes the
    // pair's stale copy, which is exactly what a stale copy is for. A
    // pair the file grew into (`second >= old_pages`, excluded from
    // `flip_pairs` above) is *not* excluded here -- it never went
    // through canonicalisation, so both its halves fall through to
    // ordinary content below, exactly like the old tail write handled
    // them.
    let flip_covered: std::collections::HashSet<usize> =
        flip_pairs.iter().flat_map(|&(first, second)| [first, second]).collect();
    let content: Vec<usize> = store
        .dirty_pages()
        .into_iter()
        .filter(|n| !flip_covered.contains(n))
        .filter(|&n| match store.original(n) {
            None => true, // appended this operation -- always new content
            Some(before) => before != store.current(n),
        })
        .collect();

    (content, flips)
}

#[cfg(test)]
thread_local! {
    /// Which [`Stop`] to fail at, or `None` for the only value production has.
    ///
    /// Thread-local, not a global: `cargo test` runs this crate's tests in
    /// parallel inside one process, and a staged interruption that leaked
    /// across threads failed four unrelated v6 writes the first time this
    /// was a `static`.
    pub(crate) static STOP_AT: std::cell::Cell<Option<Stop>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
thread_local! {
    /// Bytes [`Block::write_changed_pages`] has put on the disk.
    ///
    /// Thread-local rather than read out of `/proc/self/io`, which is
    /// process-wide: `cargo test` runs the suite in parallel, so the kernel's
    /// counters include every other test's I/O and the measurement test
    /// failed whenever it was not run alone.
    pub(crate) static WROTE: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };

    /// `sync_all` calls [`Block::write_changed_pages_attempt`] or
    /// [`Block::write_changed_pages_single_phase`] has made -- Task 8's own
    /// evidence that `ACCLBV` flushes once where every other mode flushes
    /// up to three times. Thread-local for the identical reason [`WROTE`] is.
    pub(crate) static FLUSHES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn stop_here(at: Stop) -> Result<(), String> {
    if STOP_AT.with(std::cell::Cell::get) == Some(at) {
        return Err(format!("{at:?}: a staged interruption, standing in for a crash"));
    }
    Ok(())
}

#[cfg(not(test))]
#[expect(clippy::unnecessary_wraps, reason = "the test build of this can fail")]
fn stop_here(_at: Stop) -> Result<(), String> {
    Ok(())
}

impl<M: Mem> Block<M> {
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

    /// The mode this block was opened under, captured once by
    /// [`Btrieve::open`] -- see the `mode` field's own doc comment.
    /// `btrcall::insert`/`update`/`delete` read this to answer `RONLBV`'s
    /// status 46 as a typed [`crate::btrcall::Status`] rather than routing
    /// it through [`Self::insert`]/[`Self::update`]/[`Self::delete`]'s own
    /// [`BtvError`] refusal, which this dispatcher has no way to tell apart
    /// from any other write refusal -- the same reason
    /// [`Self::would_change_unmodifiable_key`] exists as its own check
    /// rather than being inferred from `update`'s error string.
    pub fn mode(&self) -> i16 {
        self.mode
    }

    /// A record's bytes, padded so a key's own `offset` lands where it was
    /// measured from -- see [`records::keyed`].
    ///
    /// On the `Block` because the shim layer reads key bytes off a record it
    /// reached through one, and has no other route to the file's version.
    ///
    /// `pub` rather than `pub(crate)` only because that shim layer is now a
    /// different crate. Nothing else about it changed, and its own paragraph
    /// above already names the caller this widening is for.
    pub fn keyed<'a>(&self, bytes: &'a [u8]) -> std::borrow::Cow<'a, [u8]> {
        let shift = self.records.as_ref().map_or(0, Records::key_shift);
        records::keyed(shift, bytes)
    }

    /// Whether this host will write to the file the v5 way: seeking a
    /// position as a literal byte offset.
    ///
    /// **No longer the v6 gate at all.** [`Self::insert`], [`Self::update`]
    /// and [`Self::delete`] each now have their own v6 path
    /// ([`Self::insert_v6`]/[`Self::update_v6`]/[`Self::delete_v6`]),
    /// called before this could ever see a v6 file -- `pages::write_record`/
    /// `pages::delete_record`'s literal-byte-offset arithmetic, which this
    /// exists to guard, is simply never reached for one. This is called
    /// only on the v5 branch of each of the three, to catch the one case a
    /// version check alone would not: a v5-declared file whose geometry is
    /// otherwise malformed. See each caller's own doc comment for what its
    /// v6 path still refuses -- none of it is "v6 at all."
    ///
    /// # Errors
    ///
    /// If the file is not v5.
    fn writable(&self) -> Result<(), BtvError> {
        if self.geometry.version != Version::V5 {
            return Err(BtvError {
                file: self.name.clone(),
                why: format!(
                    "is a {:?} file, and this is the v5-only write path -- \
                     `pages::write_record`/`pages::delete_record` seek to a \
                     position as a literal byte offset, which is only ever \
                     correct for v5. A v6 file never reaches this: \
                     `Self::insert_v6`/`Self::update_v6`/`Self::delete_v6` \
                     handle it instead",
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
        // Task 7: a v6 block with a cache defers every in-transaction write
        // to that cache (`Self::stage_changed_pages`) rather than writing
        // through immediately, so disk is never touched for it until
        // `Btrieve::end`/`Btrieve::abort` closes the transaction -- there is
        // nothing for a whole-file snapshot to restore that disk does not
        // already hold. Skipping the read saves exactly the cost this
        // struct's own doc comment describes (up to the whole file, once per
        // transaction per block written) for the one case where it can never
        // be used. A v5 block, or a v6 block with no cache (only a hand-built
        // test `Block` reaches this), still writes straight through even
        // inside a transaction, so it still needs the real snapshot.
        let bytes = if self.cache.is_some() {
            None
        } else {
            Some(read_whole(&self.path).map_err(|e| BtvError {
                file: self.name.clone(),
                why: format!("{}: reading a transaction pre-image: {e}", self.path.display()),
            })?)
        };
        self.capture_pre_image(bytes);
        Ok(())
    }

    /// Build the pre-image. One authority, one way in.
    ///
    /// A v6 write used to hold the whole file in memory already (read once,
    /// mutated into a copy) and had a second entry point,
    /// `capture_for_journal_from`, that took a pre-image from those bytes
    /// rather than reading the file a second time. Now that a v6 write
    /// reads pages lazily through [`v6::Store`] and never holds the whole
    /// file, that shortcut no longer has anything cheap to shortcut --
    /// [`Self::capture_for_journal`]'s own disk read (or its Task 7 skip,
    /// for a deferred block -- see [`PreImage`]'s own doc comment) is the
    /// only way to get a transaction's pre-image.
    fn capture_pre_image(&mut self, bytes: Option<Vec<u8>>) {
        self.pre_image = Some(PreImage {
            bytes,
            records: self.records.clone(),
            geometry: self.geometry,
            dirty: self.dirty,
        });
    }

    /// Replace this block's cache with a fresh one read straight off disk
    /// -- or drop it to `None` if even that fails -- because whatever is
    /// currently resident may no longer agree with what disk holds. Also
    /// clears [`Self::v6_order`] and [`Self::v6_physical`], for the
    /// identical reason: both are built from whatever the page cache holds
    /// *at the moment a read asks for them*, so a rank or position either
    /// one has already cached can reflect exactly the same now-stale,
    /// pre-invalidation content this function exists to throw away.
    ///
    /// Two callers, one problem: [`Btrieve::abort`] just overwrote the
    /// whole file with a pre-image, and any page a rolled-back
    /// transaction's own write had pushed into the cache
    /// (`Self::write_changed_pages`'s write-through) is now stale --
    /// resident with *post*-transaction bytes while disk holds
    /// *pre*-transaction ones. [`Self::write_changed_pages`] itself calls
    /// this on any error: a genuine mid-flush I/O failure (`ENOSPC`,
    /// `EIO`) can leave disk holding whatever an earlier phase already
    /// wrote for real while the cache still holds what was resident before
    /// the attempt, and nothing else reconciles that on the `Err` path.
    /// [`Self::commit_deferred`]'s own failure path calls this too, for
    /// the same reason -- `Btrieve::end` failing to flush a covered block
    /// leaves that block in exactly the same "resident content may not
    /// agree with disk" state a failed autocommit write does.
    ///
    /// Missed until a re-review of Task 7's own round 3: every existing
    /// `abort_invalidates_the_v6_cache_*` test asserted on
    /// `Block::v6_resolve_logical`/`records()`, never on a keyed or
    /// physical read through `v6_order`/`v6_physical` themselves, so
    /// nothing caught that this function cleared the page cache those two
    /// indexes are built *from* without also clearing what they had
    /// already cached from it.
    ///
    /// [`cache::PageCache`] has no "forget everything" primitive (Task 2's
    /// interface, consumed as declared); a fresh one, opened over the file
    /// exactly as [`Btrieve::open`] would, is the equivalent -- nothing
    /// stays resident to answer wrong. Reopening itself failing is treated
    /// the same way `None` already is everywhere else in this crate: no
    /// cache is always safe, since every v6 read path falls back to
    /// reading disk directly when `Self::cache` is `None`.
    ///
    /// A no-op for a v5 block, or any block that never had one -- clearing
    /// `v6_order`/`v6_physical` costs nothing extra either way, since both
    /// only ever hold entries for a v6 block with a cache in the first
    /// place.
    fn invalidate_cache(&mut self) {
        let mut clear = false;
        if let Some(cache) = &self.cache {
            match cache::PageCache::open(&self.path, self.geometry.page) {
                Ok(fresh) => *cache.borrow_mut() = fresh,
                Err(_) => clear = true,
            }
        }
        if clear {
            self.cache = None;
        }
        self.v6_order.borrow_mut().clear();
        *self.v6_physical.borrow_mut() = None;
    }

    /// The `struct btvblk` the module holds.
    pub fn block(&self) -> M::Ptr {
        self.block
    }

    /// The record length the module declared.
    pub fn maxlen(&self) -> u16 {
        self.maxlen
    }

    /// The record buffer the module may read into.
    pub fn data(&self) -> M::Ptr {
        self.data
    }

    /// The key buffer a search value is copied into.
    ///
    /// `PLBTVSTF.C:166` sizes it with `clckln()`, which is the longest key plus
    /// one. The buffer exists whether or not the module ever searches by key,
    /// because the real host allocated it in `opnbtv` and a module is entitled
    /// to find a pointer there.
    pub fn key(&self) -> M::Ptr {
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
    ///
    /// **Owned, not borrowed, since Task 7's ops cutover.** A v6 fixed-
    /// length block's `Cursor::Ordered` case (`Self::v6_fast_reads`) fetches
    /// bytes fresh through the page cache rather than indexing into a
    /// resident [`Records`] -- there is no long-lived `&Record` for such a
    /// fetch to hand back. Every existing caller only ever reads a returned
    /// record's own fields (`.position`, `.bytes`), which compiles
    /// identically whether the value is owned or borrowed, so this is not a
    /// call-site-breaking change despite the signature moving.
    ///
    /// A genuine error partway through the v6 fast path (a resolve or page-
    /// cache failure, not "this key does not index this record") answers
    /// `None` here, the same as every other reason this method has always
    /// been able to silently answer "nothing" for -- this method carries no
    /// error channel of its own, and by the time a real caller reaches it
    /// the position/key it names has normally already been validated by
    /// whatever positioned the cursor in the first place.
    pub fn current(&self) -> Option<Record> {
        match self.cursor {
            Cursor::Nowhere => None,
            Cursor::Ordered { key, at } if self.v6_fast_reads() => {
                let position = self.v6_position_at(key, at).ok().flatten()?;
                let bytes = self.v6_record_bytes_at(position).ok().flatten()?;
                Some(Record { position, bytes })
            }
            Cursor::Physical { at } if self.v6_fast_reads() => {
                let position = self.v6_physical_at(at).ok().flatten()?;
                let bytes = self.v6_record_bytes_at(position).ok().flatten()?;
                Some(Record { position, bytes })
            }
            Cursor::Ordered { key, at } => self.records.as_ref()?.ordered(key, at).cloned(),
            Cursor::Physical { at } => self.records.as_ref()?.physical(at).cloned(),
        }
    }

    /// Write the pages a v6 write changed, and nothing else.
    ///
    /// # Why this is not a whole-file write
    ///
    /// It used to be. Every v6 write reads the file into memory, mutates that
    /// copy, and hands the result here; this replaced the file wholesale
    /// through a flushed temporary and a rename. On `WCCMP002.DAT` -- 53 MB,
    /// 13,713 pages, which MajorMUD-NT updates on every kick sweep -- one
    /// record update changes **three** of those pages and rewrote all 53 MB
    /// anyway, `sync_all`ing the lot before the rename. About 4,500x more
    /// I/O than the change needed, and the measurement is kept honest by
    /// `tests::v6_update_writes_only_the_pages_it_changed` and written up in
    /// `docs/2026-08-18-v6-write-amplification.md`.
    ///
    /// # What the rename was protecting, and how this keeps it
    ///
    /// A plain `std::fs::write` truncates its target and then refills it, so
    /// for as long as that takes there is no complete file on disk. That is
    /// not hypothetical: killing `mbbs-server` mid-write left 7,168 pages
    /// under a control record still claiming 13,572, and the next open
    /// refused the file outright. The rename made the switch atomic.
    ///
    /// Writing pages in place cannot borrow that trick, so it has to earn the
    /// same property from the format. A v6 file is shadow-paged: the file
    /// control record lives in **both** physical pages 0 and 1, each
    /// allocation-table block lives in both halves of its own pair, and in
    /// each case the copy with the higher generation counter at
    /// [`at::GENERATION`] is the live one. Everything else -- data pages,
    /// index pages -- is reached only *through* the allocation table, so a
    /// page the live table does not name cannot be seen at all.
    ///
    /// That gives three phases, and the invariant that the file on disk
    /// always reads as either its old self or its new self:
    ///
    /// 1. **Content.** Every changed data and index page, plus any pages the
    ///    file grew by. All of them are pages the live table does not name
    ///    yet, so writing them changes nothing a reader can see.
    /// 2. **Structure, with the generations held down.** The new control
    ///    record and allocation-table images, written to the halves that are
    ///    *stale* in `before`, each carrying that half's own old generation
    ///    rather than its new one. Still invisible: the halves that were live
    ///    stay live, and are never written at all.
    /// 3. **The flip.** Two bytes per page -- the generation words, control
    ///    record first, then the allocation table.
    ///
    /// Each phase is flushed before the next begins.
    ///
    /// ## Why the generations are held back
    ///
    /// Without phase 3 a structural page would go down complete, generation
    /// and all, in one write. A torn write of that page makes a half-written
    /// image live, which is worse than anything the whole-file rename could
    /// do. Holding the generation means every structural body is durable
    /// before any of them counts, and the only writes that can decide
    /// anything are two bytes wide.
    ///
    /// ## Why one flip per pair, never two
    ///
    /// A single write can relocate the same page more than once -- the first
    /// update of a freshly opened `WCCMP002.DAT` performs 107 relocations --
    /// and each relocation flips a shadow pair. Replaying those flips one for
    /// one would write the half that is live in `before`, destroying the old
    /// state that phases 1 and 2 exist to preserve. So a pair that ended up
    /// back on the half it started on is **canonicalised**: the final image
    /// is written to the half that was stale in `before`, with a generation
    /// one above the half that was live. The end state is identical and it
    /// takes one flip to get there.
    ///
    /// The finished file never shows the difference, which is why
    /// `tests::a_v6_write_that_flips_a_pair_twice_is_still_undone_by_an_interruption`
    /// stops one of those writes half way and reopens it.
    ///
    /// ## The window in phase 3, and which way it fails
    ///
    /// The control record and the allocation table are separate shadow pairs
    /// and cannot flip as one, so a crash between them is possible. This is
    /// the one window the design does not close, and the order is chosen for
    /// how it fails rather than for tidiness.
    ///
    /// **Control record first.** What survives is a file whose header claims
    /// one more record than its pages hold, and `records::read` refuses it by
    /// name:
    ///
    /// ```text
    /// the header says 121 records and walking the pages found 120
    /// ```
    ///
    /// That is a refusal, not a repair -- the file needs one, exactly as it
    /// would after any interrupted write. It is nonetheless the better of the
    /// two failures, because the other one is silent: with the table flipped
    /// first the pages would hold 121 records under a header still saying
    /// 120, `records::walk_v6` stops after `geometry.records` of them, and
    /// the count then *matches*, so nothing refuses anything and one record
    /// -- whichever falls last in logical order, not necessarily the new one
    /// -- is simply gone.
    ///
    /// Note what this window is not. The whole-file rename it replaces had a
    /// window too, and a far wider one: 53 MB of writing and flushing, some
    /// six hundred milliseconds per update, during which a kill left a file
    /// that also refused to open. This window is the gap between two
    /// two-byte writes.
    ///
    /// # Errors
    ///
    /// If either image is not a whole number of pages, if the file shrank
    /// (v6 writes only ever grow it), or if any page cannot be written or
    /// flushed.
    ///
    /// # What changed from a `before`/`after` diff
    ///
    /// This used to take two whole-file images (`before: &[u8]`,
    /// `after: &[u8]`) and diff them page by page to work out both the
    /// structural pairs and which content pages changed. `store` already
    /// knows both: [`v6::Store::dirty_pages`] is every page a write actually
    /// touched, already known rather than rediscovered, and
    /// [`v6::Store::structural_pairs`] is exactly the shadow pairs a write
    /// touched -- named by [`v6::Map::claim`], [`v6::Map::relocate`],
    /// [`v6::Map::unclaim`] and [`v6::write_fcr`] themselves, never
    /// inferred by scanning for `"PP"` magic. The canonicalisation logic
    /// below -- one flip per pair, live/stale by generation, a double flip
    /// collapsed to nothing -- is unchanged; only where the before/after
    /// bytes come from is.
    ///
    /// # Coherence with `store`'s attached cache
    ///
    /// `store` takes `&mut` now, not `&`: after every phase below has
    /// actually flushed, this pushes the final bytes of every page it just
    /// wrote into whatever cache `store` is attached to
    /// ([`v6::Store::cache_put`], then one [`v6::Store::cache_mark_clean`])
    /// -- a no-op when there is none. Without this, the cache would go on
    /// answering a later operation's reads with the bytes this write just
    /// made stale, which is worse than not caching at all. Both calls are
    /// no-ops for a `Store` built with [`v6::Store::open`] or
    /// [`v6::Store::from_bytes`] rather than [`v6::Store::attach`].
    ///
    /// # A failed attempt invalidates the cache too
    ///
    /// This is a thin wrapper around [`Self::write_changed_pages_attempt`],
    /// which is everything below. On any `Err` -- a genuine mid-flush I/O
    /// failure (`ENOSPC`, `EIO`) partway through phase 1, 2 or 3 -- an
    /// earlier phase may already have written real bytes to disk that the
    /// cache never saw (the write-through above only runs after every
    /// phase succeeds), so whatever is resident can no longer be trusted
    /// either way: it might be stale relative to what *did* land, or it
    /// might simply predate an attempt that changed nothing. Either way,
    /// [`Block::invalidate_cache`] -- same primitive [`Btrieve::abort`]
    /// uses for the same reason -- nukes and refetches rather than trying
    /// to reason about exactly how far the failed write got.
    ///
    /// # Autocommit versus a transaction in progress (Task 7)
    ///
    /// Outside a transaction (`!self.txn_active`), this is unchanged: the
    /// write lands on disk before this returns, exactly as every task before
    /// this one built it. Inside one, with a cache actually attached to
    /// defer into, this instead calls [`Self::stage_changed_pages`] -- the
    /// same canonicalised bytes, staged into the cache and left dirty,
    /// nothing touching disk. `Btrieve::end` is what turns every covered
    /// block's staged pages into a real flush (one combined
    /// [`v6::Store::for_commit`] pass, not one per op); `Btrieve::abort` is
    /// what throws them away (`PageCache::drop_dirty`). A `txn_active` block
    /// with no cache (only reachable for a hand-built test `Block` that
    /// skipped `Self::open` yet still got pushed through `Btrieve::begin` --
    /// never a real `opnbtv`) has nowhere to defer *to*, so it falls back to
    /// this same immediate path rather than silently discarding the write.
    fn write_changed_pages(&mut self, store: &mut v6::Store) -> Result<(), BtvError> {
        if self.txn_active && self.cache.is_some() {
            self.stage_changed_pages(store);
            return Ok(());
        }
        let result = self.write_changed_pages_attempt(store);
        if result.is_err() {
            self.invalidate_cache();
        }
        result
    }

    /// The deferred half of [`Self::write_changed_pages`]: compute the same
    /// diff [`Self::write_changed_pages_attempt`] would, but push it into
    /// the attached cache only -- left dirty, not [`v6::Store::
    /// cache_mark_clean`]ed, because nothing has actually reached disk yet.
    ///
    /// This is *not* "skip the flip ceremony because nothing is written to
    /// disk yet". [`Map::claim`]/[`Map::relocate`]/[`write_fcr`] and friends
    /// decide which physical half of a shadow pair to write by reading the
    /// *current* generation through this same `store` -- which, for an op
    /// inside a transaction, means through the cache, which means through
    /// whatever an *earlier* op in the same transaction staged here. So the
    /// cache has to end up holding exactly the bytes a real flush would have
    /// left (final winning image, final generation, on the physical page a
    /// real flush would have put it on) or the next op's own read of "what
    /// is currently live" would disagree with what a real, undeferred
    /// sequence of the same ops would have produced. Only the *disk* half of
    /// the ceremony (held-back generation in phase 2, the single flipping
    /// write in phase 3) is something an in-memory cache has no crash to be
    /// unsafe about, so that part alone is skipped.
    fn stage_changed_pages(&mut self, store: &mut v6::Store) {
        let (content, flips) = diff_changed_pages(store);
        for &number in &content {
            let bytes = store.current(number).to_vec();
            store.cache_put(number, bytes);
        }
        for flip in &flips {
            store.cache_put(flip.page, flip.image.clone());
        }
        // Deliberately no `cache_mark_clean()` here -- these pages are
        // staged, not durable. `Btrieve::end`'s commit flush is what marks
        // them clean; `Btrieve::abort`'s `PageCache::drop_dirty` is what
        // discards them if the transaction never reaches `end`.
    }

    /// [`Btrieve::end`]'s own half of Task 7's deferral: turn everything
    /// this block's cache holds staged-but-undurable into one real,
    /// flushed disk write, covering every op the just-ending transaction
    /// ran against this block, not one flush per op.
    ///
    /// A no-op for a v5 block (`self.cache` is `None`) or a v6 block whose
    /// cache holds nothing dirty -- no write happened this transaction, or
    /// none of them were deferred (a `txn_active` block with no cache falls
    /// back to writing straight through immediately, see
    /// [`Self::write_changed_pages`]'s own doc comment, so it never leaves
    /// anything for this to find either).
    ///
    /// # Errors
    ///
    /// If [`v6::Store::for_commit`] cannot read the file's true (untouched)
    /// disk bytes, or the flush itself fails -- the same disk errors
    /// [`Self::write_changed_pages_attempt`] can already return, since this
    /// calls that same function. On failure, this block's cache is
    /// invalidated, the same handling an autocommit flush already gets from
    /// [`Self::write_changed_pages`].
    fn commit_deferred(&mut self) -> Result<(), BtvError> {
        let Some(cache) = self.cache.clone() else {
            return Ok(());
        };
        if cache.borrow().dirty_pages().is_empty() {
            return Ok(());
        }
        let mut store = v6::Store::for_commit(&cache, &self.path, self.geometry.page).map_err(|why| BtvError {
            file: self.name.clone(),
            why,
        })?;
        let result = self.write_changed_pages_attempt(&mut store);
        if result.is_err() {
            self.invalidate_cache();
        }
        result
    }

    /// Everything [`Self::write_changed_pages`] does except invalidating
    /// the cache on failure -- split out only so that wrapper can run
    /// after this one returns, success or not. See that function's own
    /// doc comment for the shadow-paging design this actually implements.
    fn write_changed_pages_attempt(&self, store: &mut v6::Store) -> Result<(), BtvError> {
        use std::io::{Seek, SeekFrom, Write};

        // `ACCLBV` (Task 8): the caller has asked to waive crash
        // consistency in exchange for fewer writes and one flush instead
        // of three -- see [`Self::write_changed_pages_single_phase`]'s own
        // doc comment for exactly what that gives up. Every other mode
        // (including `PRIMBV`, what the differential/replay suite runs
        // under) takes the three-phase path below, unchanged.
        if self.mode == ACCLBV {
            return self.write_changed_pages_single_phase(store);
        }

        let fail = |why: String| BtvError {
            file: self.name.clone(),
            why,
        };
        let page = usize::from(self.geometry.page);

        let generation = |image: &[u8]| -> u16 {
            u16::from_le_bytes([image[at::GENERATION], image[at::GENERATION + 1]])
        };

        let (content, flips) = diff_changed_pages(store);

        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .open(&self.path)
            .map_err(|e| fail(format!("{}: {e}", self.path.display())))?;

        let put = |out: &mut std::fs::File, at: u64, bytes: &[u8]| -> Result<(), BtvError> {
            #[cfg(test)]
            WROTE.with(|wrote| wrote.set(wrote.get() + bytes.len()));
            out.seek(SeekFrom::Start(at))
                .and_then(|_| out.write_all(bytes))
                .map_err(|e| fail(format!("{}: writing at {at}: {e}", self.path.display())))
        };
        let flush = |out: &std::fs::File| -> Result<(), BtvError> {
            #[cfg(test)]
            FLUSHES.with(|flushes| flushes.set(flushes.get() + 1));
            out.sync_all()
                .map_err(|e| fail(format!("{}: flushing: {e}", self.path.display())))
        };

        // Phase 1 -- content, pre-existing or newly appended alike: every
        // dirty page not covered by a flip goes down whole, unconditionally.
        for &number in &content {
            put(&mut out, (number * page) as u64, store.current(number))?;
        }
        flush(&out)?;
        stop_here(Stop::AfterContent).map_err(&fail)?;

        // Phase 2 -- structural bodies, each still carrying the generation
        // that loses to the half currently live.
        for flip in &flips {
            let mut held = flip.image.clone();
            let losing = generation(store.original(flip.page).expect("read above"));
            held[at::GENERATION..at::GENERATION + 2].copy_from_slice(&losing.to_le_bytes());
            put(&mut out, (flip.page * page) as u64, &held)?;
        }
        flush(&out)?;
        stop_here(Stop::AfterBodies).map_err(&fail)?;

        // Phase 3 -- the flip. Control record first; see the doc comment.
        for (done, flip) in flips.iter().enumerate() {
            put(
                &mut out,
                (flip.page * page + at::GENERATION) as u64,
                &flip.generation.to_le_bytes(),
            )?;
            if done == 0 {
                flush(&out)?;
                stop_here(Stop::AfterFirstFlip).map_err(&fail)?;
            }
        }
        flush(&out)?;

        // Every page this call just wrote, live on disk from here on --
        // pushed into `store`'s attached cache (a no-op if it has none) so
        // the next operation on this same `Block` sees the final bytes
        // without a fresh disk read. Content pages first (their final
        // bytes are just `store.current`), then flips: `flip.image` already
        // carries `flip.generation`, the *live* value phase 3 just made
        // real, not the held-back one phase 2 wrote to disk -- see the
        // `Flip` struct above. One `cache_mark_clean` at the end, not one
        // per `cache_put`: see that method's own doc comment for why
        // clearing dirty state cache-wide is still correct here.
        for &number in &content {
            let bytes = store.current(number).to_vec();
            store.cache_put(number, bytes);
        }
        for flip in &flips {
            store.cache_put(flip.page, flip.image.clone());
        }
        store.cache_mark_clean();

        Ok(())
    }

    /// `ACCLBV`'s write: every changed page -- content and structural alike
    /// -- goes down with its final, live bytes in one pass, then one flush.
    /// No held-back generation, no separate flip pass.
    ///
    /// # What this gives up
    ///
    /// [`Self::write_changed_pages_attempt`]'s own doc comment explains why
    /// the three-phase path holds a shadow pair's generation back and
    /// flips it only after its body is durable: so a crash mid-write can
    /// only ever leave the file reading as its old self or its new self,
    /// never a mix. Writing `flip.image` -- which already carries the
    /// *final* generation, [`Flip`]'s own field -- in the same pass as
    /// every content page removes exactly that guarantee: an interruption
    /// here can land a shadow pair's generation and a still-incomplete
    /// body in the same write, or land some flips and not others, with no
    /// phase boundary to recover from. `ACCLBV` -- Btrieve's own
    /// "accelerated" mode, `DFAAPI.H:30` -- is documented as the caller
    /// asking for exactly that trade, so this reproduces the trade rather
    /// than the crash. `PRIMBV`, the default every other mode and the
    /// differential/replay suite runs under, never reaches this function.
    ///
    /// # What is measurably different
    ///
    /// One `sync_all` instead of up to three, and -- for any write that
    /// touches at least one shadow pair, which every v6 write does (the
    /// file control record's own pair, at minimum) -- two fewer bytes
    /// written per pair: the three-phase path's phase 3 re-writes each
    /// flip's two generation bytes a second time after phase 2's held-back
    /// write; this writes them once. Both are visible to this module's own
    /// `#[cfg(test)]` counters, `WROTE` (bytes) and `FLUSHES` (`sync_all`
    /// calls) -- see
    /// `tests::acclbv_commits_in_a_single_phase_with_fewer_writes_and_one_flush`.
    fn write_changed_pages_single_phase(&self, store: &mut v6::Store) -> Result<(), BtvError> {
        use std::io::{Seek, SeekFrom, Write};

        let fail = |why: String| BtvError {
            file: self.name.clone(),
            why,
        };
        let page = usize::from(self.geometry.page);
        let (content, flips) = diff_changed_pages(store);

        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .open(&self.path)
            .map_err(|e| fail(format!("{}: {e}", self.path.display())))?;

        let put = |out: &mut std::fs::File, at: u64, bytes: &[u8]| -> Result<(), BtvError> {
            #[cfg(test)]
            WROTE.with(|wrote| wrote.set(wrote.get() + bytes.len()));
            out.seek(SeekFrom::Start(at))
                .and_then(|_| out.write_all(bytes))
                .map_err(|e| fail(format!("{}: writing at {at}: {e}", self.path.display())))
        };

        // Content, then every shadow pair's FINAL image -- `flip.image`
        // already carries `flip.generation`, the live value, unlike the
        // three-phase path's `held` copy. One combined pass, no ordering
        // between the two loops to preserve: neither can be observed by a
        // reader until the flush below lands.
        for &number in &content {
            put(&mut out, (number * page) as u64, store.current(number))?;
        }
        for flip in &flips {
            put(&mut out, (flip.page * page) as u64, &flip.image)?;
        }

        #[cfg(test)]
        FLUSHES.with(|flushes| flushes.set(flushes.get() + 1));
        out.sync_all()
            .map_err(|e| fail(format!("{}: flushing: {e}", self.path.display())))?;

        // Same cache write-through as the three-phase path -- see that
        // function's own tail comment for why.
        for &number in &content {
            let bytes = store.current(number).to_vec();
            store.cache_put(number, bytes);
        }
        for flip in &flips {
            store.cache_put(flip.page, flip.image.clone());
        }
        store.cache_mark_clean();

        Ok(())
    }

    /// Insert a record into a v6 file.
    ///
    /// The v5 half of [`Self::insert`] seeks a physical offset and writes one
    /// slot; this reads the whole file into memory, mutates that copy through
    /// [`v6::Map::claim`], [`v6::Map::relocate`] and [`v6::write_fcr`], and
    /// writes it back once -- the same shape those three functions already
    /// use internally, because every one of them is itself a
    /// read-modify-append-elsewhere-and-flip-the-shadow-pair operation, not
    /// an in-place edit.
    ///
    /// # Scope
    ///
    /// None of the three restrictions this doc used to state here still
    /// hold: [`Self::v6_reindex`] writes a duplicate-permitting key's chain
    /// itself ([`Self::v6_write_chains`]), [`v6::Map::claim`] scans every
    /// existing `"PP"` allocation-table block rather than only the first
    /// (`v6.rs`'s own `claiming_works_on_a_file_that_has_a_second_block`),
    /// and an index that outgrows one page claims new interior-node pages on
    /// demand, the same way any other page is claimed. What is still
    /// checked, for every key, before anything is written: the key's root
    /// must carry the v6 marker bit (see Errors below) -- a refusal there
    /// never leaves some keys' indexes updated and others not.
    ///
    /// # Where the record goes
    ///
    /// The free list decides, exactly as it does for v5 and exactly as it
    /// does in the real engine: [`Self::v6_pop_free`] when the head names a
    /// free slot, [`Self::v6_claim_threaded_page`] when the list is empty.
    /// **So records pack**, several to a page, and a fresh page is claimed
    /// only when there is genuinely no room -- which is also what makes this
    /// the other half of [`Self::delete_v6`]: the slot a delete frees is the
    /// slot the next insert takes.
    ///
    /// This used to claim a whole page per record and never touch the head,
    /// which was format-valid and cost 2 KB a record while quietly leaking
    /// every slot a delete freed.
    ///
    /// # What is measured, not invented
    ///
    /// Every mechanism below -- claiming the record's own page, threading a
    /// newly claimed page's slots onto the free list, popping the head,
    /// relocating each key's root rather than editing it in place, which byte
    /// offsets of the file control record change and which (`fcr::PAGES`)
    /// does not -- was measured against genuine Btrieve 6.15 running under
    /// Wine (`crtprobe.exe` and `delprobe.exe`, `tools/btrieve-oracle/`,
    /// 2026-08-15 and 2026-08-16), not assumed from the v5 shape. See
    /// [`v6::Map::relocate`]'s doc comment for the measurement that found
    /// relocation-on-every-write, [`v6::write_fcr`]'s for the
    /// file-control-record fields, and
    /// `docs/2026-08-16-v6-update-delete-oracle.md` for the free list.
    ///
    /// A v6 key's root, read from [`pages::fcr::KEY_ROOT`], is not a bare
    /// page number the way a v5 key's is: bit 31 is set and the low 31 bits
    /// are the root's **logical** id, resolved through [`v6::Map`] exactly
    /// like a record's own position is. Measured on every key this host has
    /// seen; a root without that bit is refused rather than assumed to be
    /// something else.
    ///
    /// # Errors
    ///
    /// If the record does not fit the physical slot once the two-byte v6
    /// slot marker is counted, if any key's root does not carry the v6
    /// marker bit, or if the file cannot be read or written.
    fn insert_v6(&mut self, bytes: Vec<u8>) -> Result<u32, BtvError> {
        let name = self.name.clone();
        let fail = |why: String| BtvError {
            file: name.clone(),
            why,
        };

        let page_size = self.geometry.page;
        let physical = usize::from(self.geometry.physical);
        let reclen = usize::from(self.geometry.reclen);
        // The two-byte v6 slot marker (Evidence 1b, `records.rs`'s
        // `V6_SLOT_MARKER`) plus the record body must fit the physical slot
        // this file declares -- the same shape `records::walk_v6` already
        // refuses to read, checked again here because writing a record that
        // could never be read back is the identical silent corruption
        // `writable`'s old blanket refusal existed to prevent.
        if physical < reclen + 2 {
            return Err(fail(format!(
                "a {reclen}-byte record does not fit a {physical}-byte v6 \
                 physical slot once the two-byte slot marker is counted"
            )));
        }

        // `Store::open`/`Store::attach` read only the file's length (or, for
        // `attach`, the attached cache's own page count) -- every page this
        // write actually touches is read lazily, once, the first time
        // something below asks for it. See `Store`'s own doc comment for
        // what this replaced (a `std::fs::read` of the whole file, plus a
        // full clone of it for `write_changed_pages` to diff against).
        // `attach`, when this block has a cache (`Self::cache`'s own doc
        // comment), is what lets a page an earlier operation already
        // fetched or wrote answer from memory here instead.
        let mut store = match &self.cache {
            Some(cache) => v6::Store::attach(cache, &self.path, page_size).map_err(&fail)?,
            None => v6::Store::open(&self.path, page_size).map_err(&fail)?,
        };

        let layout = pages::Layout {
            page: page_size,
            physical: self.geometry.physical,
            pages: self.geometry.pages,
        };

        let fcr = self.v6_live_fcr(&mut store).map_err(&fail)?;
        let head = pages::long(&fcr[pages::fcr::FREE_V6..pages::fcr::FREE_V6 + 4]);

        // A variable-length record's body goes down **first**, on a variable
        // page, and what lands in the data-page slot is the fixed part plus
        // four bytes of pointer to it.
        //
        // Body first because the two writes cannot be made atomic: if placing
        // the body fails there is nothing to unwind, whereas a slot written
        // first and then orphaned leaves a record pointing at fragments that
        // were never allocated. Note nothing below is written to disk until
        // the very end, so a failure past this point discards the fragment
        // with everything else -- still true now that `store` holds pages
        // one at a time rather than the whole file.
        let (slot, variable_head) = if self.geometry.variable {
            let reclen = usize::from(self.geometry.reclen);
            let was = variable::head_of(&fcr);
            let mut source =
                variable::V6Pages::new(&mut store, page_size).map_err(&fail)?;
            let mut space = variable::Space::new(&mut source, Version::V6, was);
            let at = space.place(&bytes[reclen..]).map_err(|why| {
                fail(format!(
                    "placing the {}-byte body of a {}-byte record: {why}",
                    bytes.len() - reclen,
                    bytes.len()
                ))
            })?;
            let now = space.head();

            let mut slot = bytes[..reclen].to_vec();
            slot.extend_from_slice(&at.encode());
            (slot, Some(now))
        } else {
            (bytes.clone(), None)
        };

        // Where the record goes, and what the free-list head becomes: pop the
        // head if it names a free slot, and claim a whole new pre-threaded
        // page if the list is empty. Both are what genuine 6.15 does; see
        // `Self::v6_pop_free` and `Self::v6_claim_threaded_page`.
        let (new_position, new_head) = if head == records::NOWHERE {
            self.v6_claim_threaded_page(&mut store, layout, &slot).map_err(&fail)?
        } else {
            self.v6_pop_free(&mut store, layout, head, &slot).map_err(&fail)?
        };

        // The model, updated on a copy first -- **except for Task 7's own
        // fast path** (`Self::v6_fast_reads`): a fixed-length v6 block with
        // a page cache never builds `records_clone` at all, because
        // nothing downstream of this point needs it any more. What used to
        // come from it: `shift` is a pure function of the version (v6 is
        // always 2, `Records::read`'s own rule); each key's post-write
        // count is the *live FCR's own pre-write count* (already in `fcr`,
        // read once above) plus one, unless this key excludes the new
        // record (`Key::excluded`) from its index entirely; the total
        // record count is `self.geometry.records` (still the pre-write
        // count at this point) plus one. Every one of those is exactly
        // what `records_clone` would have answered, computed without
        // reading a single other record's bytes.
        //
        // A write that fails partway still leaves the model exactly where
        // a fresh read of the untouched file would put it either way: the
        // slow path never stores `records_clone` back until the whole
        // operation succeeds (see the tail of this function), and the fast
        // path never touches `self.records` at all -- there is nothing to
        // roll back.
        let fast = self.v6_fast_reads();
        let mut records_clone = if fast {
            None
        } else {
            let mut rc = self
                .records
                .as_ref()
                .expect("Self::insert calls Self::records() before this")
                .clone();
            rc.insert(&self.keys, new_position, bytes.clone())
                .map_err(|why| fail(format!("adding the new record to the model: {why}")))?;
            Some(rc)
        };
        let shift = if fast {
            2
        } else {
            records_clone.as_ref().expect("just built").key_shift()
        };

        // Task 6: every key's own B-tree, edited incrementally -- locate,
        // insert (extending a duplicate group's tail, or splitting a full
        // leaf and cascading upward per the rules doc) -- never a full
        // `v6_reindex` rebuild. `index_free_head` threads the B-tree page
        // free list's own running head across every key in this one op, so
        // a page one key's split reclaims is gone by the time the next
        // key's split looks for one.
        let cache_rc = self.v6_tree_cache().map_err(&fail)?;
        let mut key_record_counts: Vec<(usize, u32)> = Vec::with_capacity(self.keys.len());
        let mut key_roots: Vec<(usize, u32)> = Vec::new();
        // Every key this insert actually gave a new index entry to -- fed
        // to `Self::v6_invalidate_keys` below so a key this record excludes
        // (`Key::excluded`) keeps its cached `OrderIndex`, not just every
        // key that changed count.
        let mut changed_keys: Vec<u16> = Vec::new();
        let mut index_free_head =
            pages::long(&fcr[pages::fcr::INDEX_FREE_V6..pages::fcr::INDEX_FREE_V6 + 4]);
        for key in &self.keys {
            let definition = pages::fcr::KEYS + usize::from(key.definition) * pages::fcr::KEY_WIDTH;
            let keyed_bytes = records::keyed(shift, &bytes);
            let len = if fast {
                let at = definition + pages::fcr::KEY_RECORDS;
                let before = pages::long(&fcr[at..at + 4]);
                if key.excluded(&keyed_bytes) {
                    before
                } else {
                    changed_keys.push(key.number);
                    before.saturating_add(1)
                }
            } else {
                u32::try_from(
                    records_clone
                        .as_ref()
                        .expect("just built")
                        .ordered_len(key.number)
                        .ok_or_else(|| {
                            fail(format!(
                                "key {}: not among the keys the loaded records were ordered by",
                                key.number
                            ))
                        })?,
                )
                .expect("far fewer records than u32::MAX")
            };
            key_record_counts.push((definition + pages::fcr::KEY_RECORDS, len));

            let value = key.extract(&keyed_bytes);
            let (new_root, next_free_head) = self.v6_tree_insert(
                &mut store,
                &cache_rc,
                layout,
                key,
                &fcr,
                &value,
                new_position,
                index_free_head,
            )?;
            index_free_head = next_free_head;
            if let Some(root) = new_root {
                key_roots.push((definition + pages::fcr::KEY_ROOT, root));
            }
        }

        let total_records = if fast {
            self.geometry.records.saturating_add(1)
        } else {
            u32::try_from(records_clone.as_ref().expect("just built").len())
                .expect("far fewer records than u32::MAX")
        };
        v6::write_fcr(
            &mut store,
            page_size,
            total_records,
            &key_record_counts,
            Some(new_head),
            variable_head,
            Some(index_free_head),
            &key_roots,
        )
        .map_err(|why| fail(format!("updating the file control record: {why}")))?;

        // The last point before this write actually changes anything on
        // disk -- see `Self::capture_for_journal`'s doc comment for why it
        // is taken here rather than at the top of the function. Reads the
        // pristine file fresh from disk when a transaction actually needs
        // it (`Self::capture_for_journal`'s own no-op-unless-active guard);
        // nothing below this point has written anything yet, so the file on
        // disk is still exactly the pre-image a rollback would want.
        self.capture_for_journal()?;

        self.write_changed_pages(&mut store)?;

        if fast {
            self.v6_invalidate_keys(&changed_keys);
            self.v6_invalidate_physical();
        } else {
            self.records = records_clone.take();
        }
        self.geometry.records = total_records;
        self.geometry.pages =
            u32::try_from(store.total_pages()).expect("a Btrieve file under four gigabytes of pages");
        self.dirty = true;

        Ok(new_position)
    }

    /// The number of a key that does not declare itself modifiable and whose
    /// value this update would change, if there is one.
    ///
    /// # Why this is a refusal and not a shrug
    ///
    /// A key definition's attribute bit 1 ([`keys::flag::MODIFIABLE`]) says
    /// whether an update may change that key's value. Without it, genuine
    /// Btrieve 6.15 answers **status 10** and writes nothing -- measured by
    /// creating one file with attributes `0x0100` and another with `0x0102`
    /// and running the same key-changing update against both
    /// (`tools/btrieve-oracle/delprobe.c`).
    ///
    /// The module never sees the number 10. `PLBTVSTF.C`'s wrappers turn it
    /// into a catastrophic error: `upvbtv` (`:531-547`) sends **any** nonzero
    /// status to `btverrptr("UPDATE")`, and `dupdbtv` (`:550-570`) carves out
    /// exactly one status -- `case 5`, the duplicate key -- and sends
    /// everything else, 10 included, to the same `btverrptr`. So the faithful
    /// behaviour is to stop, which is what returning an error from here does,
    /// and it is why this is not modelled as a quiet failure answer the way
    /// `shims::btrieve::duplicate_key`'s status 5 is.
    ///
    /// # Where it lives, and why not in the four callers
    ///
    /// [`Self::update`] has four callers -- `dupdbtv`, `upvbtv`,
    /// `dfa.rs`'s update, and `ops.rs`'s chunked update -- and the rule is a
    /// property of the file format, not of any one wrapper's calling
    /// convention. Put here once, all four inherit it; put in the shims, the
    /// engine's own `ops` path would silently keep the old behaviour.
    ///
    /// # By value, not by bytes
    ///
    /// The comparison is [`Key::compare`], which is segment-by-segment and
    /// type-aware, **not** a byte comparison of the key field. Measured: a
    /// `Zstring` key holding `AB\0` followed by five `0xAA`, on a
    /// non-modifiable key, updated so that only those five trailing bytes
    /// change -- genuine 6.15 answers status 0 and commits the new bytes. The
    /// value did not change; the bytes did. A byte comparison here would
    /// refuse a write the real engine performs.
    ///
    /// Equally measured: rewriting a non-modifiable key with the value it
    /// already holds is status 0. The engine refuses a *change*, not a touch.
    ///
    /// `existing` and `bytes` are both whole records, and both go through
    /// [`records::keyed`] first, because a v6 key's offset is measured from
    /// the physical slot and [`Record::bytes`] does not carry the two-byte
    /// marker that slot opens with.
    fn unmodifiable_key_changed(&self, existing: &[u8], bytes: &[u8]) -> Option<u16> {
        let shift = self.records.as_ref().map_or(0, Records::key_shift);
        let before = records::keyed(shift, existing);
        let after = records::keyed(shift, bytes);
        self.keys
            .iter()
            .find(|key| {
                !key.modifiable && key.compare(&before, &after) != std::cmp::Ordering::Equal
            })
            .map(|key| key.number)
    }

    /// Whether calling [`Self::update`] with `bytes` at `position` would
    /// refuse because it changes a key that does not declare itself
    /// modifiable, without writing anything.
    ///
    /// A read-only mirror of the check [`Self::update`] runs internally
    /// (`:2096`), exposed so a caller that must answer with a *status* --
    /// `btrcall`'s op 3, which real Btrieve answers with status 10 rather
    /// than a driver-level error -- can consult the same predicate before
    /// calling `update`, instead of parsing [`BtvError::why`]'s prose. Kept
    /// as a thin wrapper rather than a change to `update`'s return type: see
    /// the task 7b brief for why a typed [`BtvError`] would ripple into
    /// `mbbs`'s six-thousand-line BTVSTF shims.
    ///
    /// Answers `None` -- not a refusal -- when `position` names no known
    /// record. `update` itself is what turns that into status 8 or a "holds
    /// no record" gap; this predicate only ever answers the one question its
    /// name asks.
    ///
    /// # Errors
    ///
    /// If the file's records cannot be loaded.
    pub fn would_change_unmodifiable_key(
        &mut self,
        position: u32,
        bytes: &[u8],
    ) -> Result<Option<u16>, BtvError> {
        self.records()?;
        let records = self.records.as_ref().expect("just loaded");
        let Some(at) = records.find_physical(position) else {
            return Ok(None);
        };
        let existing = records.physical(at).expect("just found").bytes.clone();
        Ok(self.unmodifiable_key_changed(&existing, bytes))
    }

    /// Put `bytes` in the slot the free list's head names, and answer with
    /// that slot's position and the list's new head.
    ///
    /// The head names a slot; that slot's own first four bytes name the next
    /// one. Popping is reading the link out before overwriting the slot, and
    /// nothing more -- the identical discipline v5 has always had, at a
    /// different offset ([`pages::fcr::FREE_V6`]) and through the allocation
    /// table rather than straight into the file.
    ///
    /// The head is *verified*, not trusted: it must be on a slot boundary, on
    /// a page the allocation table claims, and the slot it names must
    /// actually be free (marker zero). A head that fails any of those is a
    /// broken file, and writing a record over whatever it names would turn a
    /// broken free list into lost data.
    ///
    /// # Errors
    ///
    /// If the head does not name a free slot of a claimed page, or the page
    /// cannot be relocated.
    fn v6_pop_free(
        &self,
        store: &mut v6::Store,
        layout: pages::Layout,
        head: u32,
        bytes: &[u8],
    ) -> Result<(u32, u32), String> {
        let page_size = self.geometry.page;

        let (logical, slot) = layout.slot_of(head).ok_or_else(|| {
            format!("the free-list head is {head}, which is not on a slot boundary")
        })?;
        let physical = v6::Map::read(store, page_size)?.physical(logical).ok_or_else(|| {
            format!(
                "the free-list head is {head}, on logical page {logical}, which the \
                 allocation table claims no physical page for"
            )
        })?;

        let mut content = store.page(physical as usize).map_err(|why| {
            format!(
                "the free-list head is {head}, on logical page {logical}, which \
                 resolves to physical page {physical}: {why}"
            )
        })?.to_vec();

        let within = layout.position(0, slot) as usize;
        let marker = u16::from_le_bytes([content[within], content[within + 1]]);
        if marker != 0 {
            return Err(format!(
                "the free-list head is {head}, whose slot carries marker \
                 {marker} -- a live record, not a free slot"
            ));
        }

        let body = within + V6_SLOT_MARKER;
        let next = pages::long(&content[body..body + 4]);

        content[within..within + 2].copy_from_slice(&1u16.to_le_bytes());
        content[body..body + usize::from(self.geometry.physical) - V6_SLOT_MARKER].fill(0);
        content[body..body + bytes.len()].copy_from_slice(bytes);

        v6::Map::relocate(store, page_size, logical, &content, [0x00, 0x44])
            .map_err(|why| format!("relocating the page the free slot is on: {why}"))?;

        Ok((head, next))
    }

    /// Claim a fresh page for `bytes`, threaded the way a newly claimed page
    /// arrives from genuine Btrieve, and answer with the record's position
    /// and the free list's new head.
    ///
    /// Measured (`docs/2026-08-16-v6-update-delete-oracle.md`): a page the
    /// engine claims comes with **every** slot free and linked to the next --
    /// marker zero, the next slot's position in the body's first four bytes,
    /// the last one ending the chain at `0xffffffff`. The record then takes
    /// slot 0 and the head moves to slot 1.
    ///
    /// This is reached only when the list is already empty, which is why the
    /// chain built here ends rather than continuing into whatever the head
    /// was: there was nothing there to continue into.
    ///
    /// # Errors
    ///
    /// If the page cannot be claimed.
    fn v6_claim_threaded_page(
        &self,
        store: &mut v6::Store,
        layout: pages::Layout,
        bytes: &[u8],
    ) -> Result<(u32, u32), String> {
        let page_size = self.geometry.page;
        let per_page = layout.per_page();
        if per_page == 0 {
            return Err(format!(
                "a {}-byte physical slot leaves no room for a record in a \
                 {page_size}-byte page",
                self.geometry.physical
            ));
        }

        let mut content = vec![0u8; usize::from(page_size)];
        // Data bit set, stamp 1 -- `Header`'s own encoding, applied by hand
        // because `content`'s first four bytes (tag, logical id) are
        // `v6::Map::claim`'s to fill in, not this function's; see its doc
        // comment on `content`.
        content[4..6].copy_from_slice(&0x8001u16.to_le_bytes());

        // `claim` decides the logical id, and the thread's links are
        // positions that depend on it -- so the page is threaded *after* the
        // claim, in the file, rather than before it in this buffer.
        let logical = v6::Map::claim(store, page_size, &content, [0x00, 0x44])
            .map_err(|why| format!("claiming a page for the new record: {why}"))?;

        let physical = v6::Map::read(store, page_size)?
            .physical(logical)
            .ok_or_else(|| format!("logical page {logical} was just claimed and is not claimed"))?
            as usize;

        for slot in 0..per_page {
            let body = layout.position(0, slot) as usize + V6_SLOT_MARKER;
            let next = if slot + 1 < per_page {
                layout.position(logical, slot + 1)
            } else {
                records::NOWHERE
            };
            store.page_mut(physical)?[body..body + 4].copy_from_slice(&pages::to_long(next));
        }

        // Slot 0 takes the record, so the head is slot 1 -- or nothing, on a
        // page with room for exactly one.
        let record_at = layout.position(0, 0) as usize;
        let page_bytes = store.page_mut(physical)?;
        page_bytes[record_at..record_at + 2].copy_from_slice(&1u16.to_le_bytes());
        let body = record_at + V6_SLOT_MARKER;
        page_bytes[body..body + usize::from(self.geometry.physical) - V6_SLOT_MARKER].fill(0);
        page_bytes[body..body + bytes.len()].copy_from_slice(bytes);

        let head = if per_page > 1 {
            layout.position(logical, 1)
        } else {
            records::NOWHERE
        };
        Ok((layout.position(logical, 0), head))
    }

    /// Which physical page currently holds logical page `logical`, read by
    /// formula rather than by loading the file.
    ///
    /// [`format::alloc::block_of`] finds which allocation-table block
    /// answers for `logical`, and [`format::alloc::pair_position`] finds
    /// that block's own shadow pair the same way -- the identical formula
    /// [`v6::Map::read`] uses internally, except that function walks *every*
    /// block in the file to build a complete lookup and this reads only the
    /// one block a caller actually wants resolved. On `WCCMP002.DAT`
    /// (fourteen blocks) that is two pages instead of twenty-eight, and none
    /// of the file's other 13,579 pages are touched at all.
    ///
    /// This is what [`Self::v6_slot`] used to spend its whole-file read
    /// resolving; see that function's own doc comment for why it still reads
    /// the whole file afterward, for an unrelated reason.
    ///
    /// # Errors
    ///
    /// If either shadow page cannot be read in full (short reads past the
    /// end of the file are refused, not silently truncated), if neither
    /// carries the `"PP"` allocation-table magic, if one does but disagrees
    /// about which block it is, if both do and their generations tie, if the
    /// resolved entry's marker says never-claimed, or if the physical page it
    /// names is the file control record's own shadow pair or past
    /// [`Self::geometry`]'s own page count.
    fn v6_resolve_logical(&self, logical: u32) -> Result<u32, String> {
        let page_size = usize::from(self.geometry.page);
        let (block, entry) = format::alloc::block_of(logical, page_size)?;
        let (first, second) = format::alloc::pair_position(page_size, block);

        // Read through this block's attached cache when it has one (every
        // v6 `Block` a real `opnbtv` reaches -- see `Self::cache`'s own doc
        // comment), so a later resolution against the same allocation-table
        // block answers from memory instead of disk -- this is the "same
        // offsets re-read up to 36x" traffic a fresh `Store` per operation
        // used to cost. Each borrow is scoped to one page: the bytes are
        // copied out before it ends.
        //
        // Only a test-built `Block` that skips `Self::open` ever has no
        // cache; that fallback keeps the one-handle-for-both-shadow-halves
        // discipline this used to be the whole of -- two `openat`s per
        // record write for a resolution that needs exactly two `read`s and
        // no more.
        let mut file = None;
        let mut page_at = |physical: usize| -> Result<Vec<u8>, String> {
            if let Some(cache) = &self.cache {
                let physical_u32 = u32::try_from(physical)
                    .map_err(|_| format!("physical page {physical} does not fit a u32"))?;
                let mut guard = cache.borrow_mut();
                return Ok(guard.page(physical_u32)?.to_vec());
            }
            if file.is_none() {
                file = Some(
                    open_for_read(&self.path).map_err(|e| format!("{}: {e}", self.path.display()))?,
                );
            }
            let page = read_at_open(file.as_mut().expect("just opened"), physical * page_size, page_size)
                .map_err(|e| format!("{}: {e}", self.path.display()))?;
            if page.len() != page_size {
                return Err(format!(
                    "physical page {physical} is only {} of {page_size} bytes \
                     -- past the end of the file",
                    page.len()
                ));
            }
            Ok(page)
        };
        let first_page = page_at(first)?;
        let second_page = page_at(second)?;

        let has_magic = |page: &[u8]| page[..2] == *format::alloc::MAGIC;
        let generation = |page: &[u8]| {
            let at = format::alloc::at::GENERATION;
            u16::from_le_bytes([page[at], page[at + 1]])
        };
        let block_index = |page: &[u8]| {
            let at = format::alloc::at::BLOCK;
            u16::from_le_bytes([page[at], page[at + 1]])
        };

        let candidates: Vec<(usize, &[u8])> =
            [(first, first_page.as_slice()), (second, second_page.as_slice())]
                .into_iter()
                .filter(|&(_, page)| has_magic(page))
                .collect();
        if candidates.is_empty() {
            return Err(format!(
                "neither physical page {first} nor {second} carries the \"PP\" \
                 allocation-table magic -- there is no block {block} where this \
                 logical id's own arithmetic says one must be"
            ));
        }
        for &(page_number, page) in &candidates {
            let stored = block_index(page);
            if usize::from(stored) != block {
                return Err(format!(
                    "physical page {page_number} is where allocation-table \
                     block {block} lives, but it calls itself block {stored}"
                ));
            }
        }

        let top_generation = candidates.iter().map(|&(_, page)| generation(page)).max().unwrap_or(0);
        let live: Vec<&[u8]> = candidates
            .iter()
            .filter(|&&(_, page)| generation(page) == top_generation)
            .map(|&(_, page)| page)
            .collect();
        if live.len() > 1 {
            return Err(format!(
                "allocation-table block {block} has {} copies all claiming \
                 generation {top_generation}, and there is no rule measured \
                 for choosing between them",
                live.len()
            ));
        }
        let live = live[0];

        let at = format::alloc::at::ENTRIES + entry * format::alloc::ENTRY_WIDTH;
        let marker = u16::from_le_bytes([live[at], live[at + 1]]);
        let claimed_page = u16::from_le_bytes([live[at + 2], live[at + 3]]);

        if marker >> 8 == 0 {
            return Err(format!(
                "the allocation table claims no physical page for logical page \
                 {logical}, which is where its record's position says it is"
            ));
        }
        if claimed_page <= 1 {
            return Err(format!(
                "allocation-table block {block} claims physical page \
                 {claimed_page}, which is the file control record's own \
                 shadow pair and cannot hold a logical page"
            ));
        }
        if u32::from(claimed_page) >= self.geometry.pages {
            return Err(format!(
                "allocation-table block {block} claims physical page \
                 {claimed_page}, and the file has only {} pages",
                self.geometry.pages
            ));
        }

        Ok(u32::from(claimed_page))
    }

    /// Everything [`nav::TreeCursor::seek`] needs for `key`'s tree: the FCR
    /// root (still tag-decorated, see [`nav::root_of`]), the key's shape,
    /// what a duplicate-permitting key's chain walk needs (`None` for a
    /// unique key), this block's own page cache, and a resolver bound to it.
    ///
    /// `None` when `key` currently has no tree at all -- a virgin file, or
    /// (per `format::fcr::key_descriptor`'s own doc) an `ANOSEG` continuation
    /// definition; both read a bare `0` at [`pages::fcr::KEY_ROOT`].
    ///
    /// Called from [`Self::v6_build_order`] (Task 7's own ops cutover) as
    /// well as `nav.rs`'s differential test -- both need the same five
    /// things to drive a [`nav::TreeCursor`] against this key's real tree.
    ///
    /// # Errors
    ///
    /// If `key` names no key this block has, this block has no v6 page cache
    /// attached (a v5 file, or a test-built `Block` that skipped
    /// [`Self::open`]), the live file control record cannot be read, the
    /// stored root does not carry the v6 marker bit
    /// ([`pages::fcr::ROOT_PAGE`]'s doc comment), or the key permits
    /// duplicates but names no chain offset.
    fn nav_root(
        &self,
        key: u16,
    ) -> Result<
        Option<(
            u32,
            pages::Shape,
            Option<nav::Duplicates>,
            &std::cell::RefCell<cache::PageCache>,
            Box<dyn FnMut(u32) -> Result<u32, String> + '_>,
        )>,
        String,
    > {
        let found = self
            .keys
            .iter()
            .find(|k| k.number == key)
            .ok_or_else(|| format!("{}: no such key: {key}", self.name))?;
        let cache = self.cache.as_ref().ok_or_else(|| {
            format!(
                "{}: no v6 page cache attached -- not a v6 file, or a test build \
                 that skipped Self::open",
                self.name
            )
        })?;
        let mut store = v6::Store::attach(cache, &self.path, self.geometry.page)?;
        let fcr = self.v6_live_fcr(&mut store)?;
        let Some(root) = nav::root_of(&fcr, usize::from(found.definition), found.number)? else {
            return Ok(None);
        };
        let shape = found.shape();
        let dup = if found.duplicates {
            let offset = usize::from(found.chain.ok_or_else(|| {
                format!(
                    "{}: key {key} permits duplicates but names no chain offset",
                    self.name
                )
            })?);
            Some(nav::Duplicates {
                layout: pages::Layout {
                    page: self.geometry.page,
                    physical: self.geometry.physical,
                    pages: self.geometry.pages,
                },
                offset,
            })
        } else {
            None
        };
        let resolve: Box<dyn FnMut(u32) -> Result<u32, String> + '_> =
            Box::new(move |logical: u32| self.v6_resolve_logical(logical));
        Ok(Some((root, shape, dup, &**cache, resolve)))
    }

    /// Whether this block's v6 read ops can serve a key's order from
    /// [`Self::v6_order`] instead of a full [`Records`] walk.
    ///
    /// **Fixed-length v6 only.** A variable-length v6 file stays on the old
    /// `Self::records()`-based path: [`Self::v6_record_bytes_at`] reads a
    /// slot's fixed part straight off its data page, and a variable-length
    /// record's own body lives on a *separate* fragment chain
    /// (`variable::Chain`) this fast path does not follow -- reading one
    /// would need the same chain-following `records::walk_v6` already does,
    /// which is a materially different (and already-proven) mechanism this
    /// task did not have budget to duplicate for a shape none of MajorMUD's
    /// own eighteen files use for a *keyed* file (`WCCTEXT`, this crate's
    /// one variable-length v6 fixture, has no key at all). A narrower,
    /// explicit exception, the same shape as this method's own v5 exclusion.
    fn v6_fast_reads(&self) -> bool {
        self.geometry.version == Version::V6 && !self.geometry.variable && self.cache.is_some()
    }

    /// This key's [`order::OrderIndex`], built if it is not already cached.
    ///
    /// Built **lazily**, one [`nav::TreeCursor`] walk (`Self::v6_build_
    /// order`) the first time a read asks for this key since the last
    /// write invalidated [`Self::v6_order`] wholesale (`Self::
    /// v6_invalidate_order`) -- so an ordinary session pays one walk of one
    /// key's *positions*, never a walk of the whole file's records, and
    /// never more than once between writes.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::v6_build_order`] refuses.
    fn v6_ensure_order(&self, key: u16) -> Result<(), String> {
        if self.v6_order.borrow().contains_key(&key) {
            return Ok(());
        }
        let index = self.v6_build_order(key)?;
        self.v6_order.borrow_mut().insert(key, index);
        Ok(())
    }

    /// Build `key`'s [`order::OrderIndex`] fresh -- see [`Self::v6_ensure_
    /// order`] for the caching this feeds.
    ///
    /// # Errors
    ///
    /// If `key` names no key this block has, or whatever [`Self::nav_root`]/
    /// [`order::OrderIndex::build`] refuse.
    fn v6_build_order(&self, key: u16) -> Result<order::OrderIndex, String> {
        ORDER_BUILDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let Some((root, shape, dup, cache, mut resolve)) = self.nav_root(key)? else {
            return Ok(order::OrderIndex::empty());
        };
        let definition = self
            .keys
            .iter()
            .find(|k| k.number == key)
            .ok_or_else(|| format!("{}: no such key: {key}", self.name))?;
        let cmp = |a: &[u8], b: &[u8]| definition.compare_extracted(a, b);
        order::OrderIndex::build(cache, &mut resolve, root, shape, dup, &cmp)
    }

    /// How many records `key` currently indexes -- [`Self::v6_ensure_
    /// order`], then its length.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::v6_ensure_order`] refuses.
    fn v6_order_len(&self, key: u16) -> Result<usize, BtvError> {
        self.v6_ensure_order(key).map_err(|why| BtvError {
            file: self.name.clone(),
            why,
        })?;
        Ok(self.v6_order.borrow().get(&key).expect("just ensured").len())
    }

    /// The rank a fresh [`nav::TreeCursor`] seek (`bias`, `target`) lands
    /// on, translated through `key`'s cached [`order::OrderIndex`] --
    /// [`ops::Op::Equal`]/`AtLeast`/`Greater`/`Less`/`AtMost`'s own v6 fast
    /// path.
    ///
    /// The seek itself answers a *position*; `nav::TreeCursor` has no rank
    /// concept of its own (this module's doc comment on why a fresh
    /// `TreeCursor` per op, not a cached one, is the only shape that works
    /// at all). The rank a caller needs to store back into `ops::Cursor::
    /// Ordered` comes from the *cached* index instead -- built in the same
    /// order this same seek's own walk would produce (both drive the
    /// identical `nav::TreeCursor`), so the two never disagree.
    ///
    /// # Errors
    ///
    /// If `key` names no key this block has, or whatever [`Self::v6_ensure_
    /// order`]/[`nav::TreeCursor::seek`] refuse.
    fn v6_seek_rank(&self, key: u16, bias: nav::Bias, target: &[u8]) -> Result<Option<usize>, BtvError> {
        let fail = |why: String| BtvError {
            file: self.name.clone(),
            why,
        };
        self.v6_ensure_order(key).map_err(&fail)?;
        let Some((root, shape, dup, cache, mut resolve)) = self.nav_root(key).map_err(&fail)? else {
            return Ok(None);
        };
        let definition = self
            .keys
            .iter()
            .find(|k| k.number == key)
            .ok_or_else(|| fail(format!("no such key: {key}")))?;
        let cmp = |a: &[u8], b: &[u8]| definition.compare_extracted(a, b);
        let (_, found) =
            nav::TreeCursor::seek(cache, &mut resolve, root, shape, Some(target), bias, dup, &cmp)
                .map_err(&fail)?;
        let Some(position) = found else {
            return Ok(None);
        };
        let order = self.v6_order.borrow();
        Ok(order.get(&key).expect("just ensured").rank_of(position))
    }

    /// The position at rank `at` in `key`'s order -- [`ops::Block::
    /// current`]'s own v6 fast path for a [`Cursor::Ordered`] position, and
    /// [`ops::physical_of`]'s v6 equivalent.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::v6_ensure_order`] refuses.
    fn v6_position_at(&self, key: u16, at: usize) -> Result<Option<u32>, BtvError> {
        self.v6_ensure_order(key).map_err(|why| BtvError {
            file: self.name.clone(),
            why,
        })?;
        Ok(self.v6_order.borrow().get(&key).expect("just ensured").position_at(at))
    }

    /// `position`'s own rank in `key`'s order, if this key indexes it --
    /// [`ops::Block::insert_extended`]'s own v6 currency-establishing tail,
    /// and [`ops::Block::acquire_absolute`]'s v6 fast path.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::v6_ensure_order`] refuses.
    fn v6_rank_of(&self, key: u16, position: u32) -> Result<Option<usize>, BtvError> {
        self.v6_ensure_order(key).map_err(|why| BtvError {
            file: self.name.clone(),
            why,
        })?;
        Ok(self.v6_order.borrow().get(&key).expect("just ensured").rank_of(position))
    }

    /// Throw away every key's cached [`order::OrderIndex`], and drop
    /// `self.records` too -- called after any successful v6 fixed-length
    /// write.
    ///
    /// `self.records` normally just stays `None` forever on the fast path
    /// (nothing on it ever populates it), but it is not guaranteed to
    /// still be `None` by the time a write reaches this: a straggler
    /// caller with no fast path of its own yet (`Block::update_chunks`
    /// unconditionally primes `self.records()` before calling
    /// `Self::current`) can leave it `Some` from *before* this write, and
    /// leaving it there would answer a later `self.records()` call with a
    /// pre-write snapshot -- exactly the staleness bug this task's own
    /// report records finding (`insert_inner`/`update_inner`/
    /// `delete_inner`'s own unconditional priming, fixed the same way).
    /// Clearing it here, unconditionally, is what makes that impossible
    /// regardless of which caller left it populated.
    ///
    /// Drop the cached [`order::OrderIndex`] for exactly the keys in
    /// `changed`, and `self.records` unconditionally.
    ///
    /// **Per key, not whole-map**: a write's own caller already knows
    /// which keys' *values* actually changed (`Self::insert_v6`/`Self::
    /// update_v6`/`Self::delete_v6` each compute this from `Key::excluded`
    /// or `Key::compare` before this is called) -- an update that touches
    /// no key at all (health, gold, position: the majority of live write
    /// traffic) passes an empty `changed` and leaves every key's cached
    /// order exactly as it was, so the next keyed read after it costs
    /// nothing extra. A splice-on-write (insert at the rank the tree
    /// insert determined, remove on delete) would save even the *touched*
    /// keys' next read a rebuild, but a wrong splice is a wrong *rank*
    /// silently handed back to a module, where a stale-then-rebuilt index
    /// is merely a cost the next read after a write pays once -- simplicity
    /// first for the keys that do change, per this task's own ruling. See
    /// `docs/2026-08-24-btrieve-write-cost-baseline.md` for the measured
    /// cost this replaces (whole-map invalidation on every write,
    /// regardless of which keys changed).
    ///
    /// `self.records` clears regardless of `changed`: it is not guarded by
    /// [`Self::v6_fast_reads`] anywhere a write reaches this, and a
    /// straggler caller with no fast path of its own yet (`Block::
    /// update_chunks`'s old, now-removed unconditional prime; a rare
    /// `Key::excluded` fallback in `ops::Block::acquire_absolute`/
    /// `ops::Block::insert_extended`) can still leave it `Some` from
    /// *before* this write -- leaving it there would answer a later
    /// `self.records()` call with a pre-write snapshot, exactly the
    /// staleness bug this task's own report records finding. The clear
    /// itself is a plain `Option` write, not a cost worth gating.
    fn v6_invalidate_keys(&mut self, changed: &[u16]) {
        if !changed.is_empty() {
            let mut order = self.v6_order.borrow_mut();
            for &key in changed {
                order.remove(&key);
            }
        }
        self.records = None;
    }

    /// Drop the cached physical-order index -- called only when the
    /// position *set* changes (insert claims a new position, delete frees
    /// one). An update never calls this: it changes a record's bytes,
    /// never which positions exist, so [`Self::v6_physical`] stays valid
    /// across it.
    fn v6_invalidate_physical(&mut self) {
        *self.v6_physical.borrow_mut() = None;
    }

    /// This file's [`order::OrderIndex`] over every claimed, live position,
    /// built if it is not already cached -- the physical-order counterpart
    /// to [`Self::v6_ensure_order`].
    ///
    /// # Errors
    ///
    /// Whatever [`Self::v6_build_physical_index`] refuses.
    fn v6_ensure_physical(&self) -> Result<(), String> {
        if self.v6_physical.borrow().is_some() {
            return Ok(());
        }
        let index = self.v6_build_physical_index()?;
        *self.v6_physical.borrow_mut() = Some(index);
        Ok(())
    }

    /// Build the physical-order index fresh: every claimed (logical,
    /// physical) pair the allocation table names ([`v6::Map::read`],
    /// bounded by allocation-table blocks, not by record count), sorted by
    /// logical id -- [`pages::Layout::position`]'s own formula is
    /// monotonic in `(logical, slot)`, so this ascending walk produces
    /// ascending *position* order directly, the identical order
    /// [`records::walk_v6`] already produces and [`records::Records::
    /// physical`] already answers from. Each claimed page is fetched once
    /// through the page cache; a page whose own tag is not "record data"
    /// (a B-tree index node, also claimed through the same allocation
    /// table) is skipped, and within a data page, each slot's own
    /// two-byte marker says whether it holds a live record -- the same
    /// checks [`Self::v6_record_bytes_at`] makes for one slot, run here
    /// for every slot on every claimed data page.
    ///
    /// # Errors
    ///
    /// If this block has no v6 page cache attached, whatever
    /// [`v6::Map::read`] refuses, or the number of live positions found
    /// does not match [`Self::geometry`]'s own record count (the same
    /// acceptance check [`records::Records::read`] makes).
    fn v6_build_physical_index(&self) -> Result<order::OrderIndex, String> {
        let cache = self.cache.as_ref().ok_or_else(|| {
            format!(
                "{}: no v6 page cache attached -- not a v6 file, or a test build                  that skipped Self::open",
                self.name
            )
        })?;
        let page_size = self.geometry.page;
        let mut store = v6::Store::attach(cache, &self.path, page_size)?;
        let map = v6::Map::read(&mut store, page_size)?;
        drop(store);

        let layout = pages::Layout {
            page: page_size,
            physical: self.geometry.physical,
            pages: self.geometry.pages,
        };
        let per_page = layout.per_page();

        let mut claimed: Vec<(u32, u32)> = map.entries().collect();
        claimed.sort_unstable_by_key(|&(logical, _)| logical);

        let mut positions = Vec::with_capacity(self.geometry.records as usize);
        for (logical, physical_page) in claimed {
            let buffer = {
                let mut guard = cache.borrow_mut();
                guard.page(physical_page)?.to_vec()
            };
            if buffer.len() < 2 || buffer[1] != 0x44 || !pages::Header::decode(&buffer).data {
                continue;
            }
            for slot in 0..per_page {
                let marker_at = layout.position(0, slot) as usize;
                if marker_at + 2 > buffer.len() {
                    continue;
                }
                if u16::from_le_bytes([buffer[marker_at], buffer[marker_at + 1]]) == 0 {
                    continue;
                }
                positions.push(layout.position(logical, slot));
            }
        }

        if positions.len() as u32 != self.geometry.records {
            return Err(format!(
                "{}: the header says {} records and walking the claimed pages found {}",
                self.name,
                self.geometry.records,
                positions.len()
            ));
        }

        Ok(order::OrderIndex::from_positions(positions))
    }

    /// How many records this file holds in physical order -- always
    /// [`Self::geometry`]'s own record count, but resolved through
    /// [`Self::v6_ensure_physical`] so a caller that also wants a position
    /// pays for the walk at most once.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::v6_ensure_physical`] refuses.
    fn v6_physical_len(&self) -> Result<usize, BtvError> {
        self.v6_ensure_physical().map_err(|why| BtvError {
            file: self.name.clone(),
            why,
        })?;
        Ok(self.v6_physical.borrow().as_ref().expect("just ensured").len())
    }

    /// The position at physical rank `at`, or `None` past the end.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::v6_ensure_physical`] refuses.
    fn v6_physical_at(&self, at: usize) -> Result<Option<u32>, BtvError> {
        self.v6_ensure_physical().map_err(|why| BtvError {
            file: self.name.clone(),
            why,
        })?;
        Ok(self.v6_physical.borrow().as_ref().expect("just ensured").position_at(at))
    }

    /// `position`'s own rank in physical order, or `None` if it names no
    /// live record.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::v6_ensure_physical`] refuses.
    fn v6_physical_rank_of(&self, position: u32) -> Result<Option<usize>, BtvError> {
        self.v6_ensure_physical().map_err(|why| BtvError {
            file: self.name.clone(),
            why,
        })?;
        Ok(self.v6_physical.borrow().as_ref().expect("just ensured").rank_of(position))
    }

    /// A v6 fixed-length record's own bytes, fetched through the block-
    /// lifetime page cache by its position -- the read counterpart to
    /// [`Self::v6_slot`]'s write-side resolution, and to [`records::
    /// walk_v6`]'s own per-slot extraction (the identical marker-check-
    /// then-slice logic, for one slot instead of every slot on every
    /// claimed page).
    ///
    /// `Ok(None)` if the slot's own two-byte marker reads zero -- free, not
    /// a record -- the same "nothing here, not an error" every other v6
    /// read in this crate answers a free slot with.
    ///
    /// **Fixed-length only** -- see [`Self::v6_fast_reads`]'s own doc
    /// comment for why a variable-length record's body (a separate
    /// fragment chain) is out of scope for this fast path.
    ///
    /// # Errors
    ///
    /// If `position` is not on a slot boundary, the allocation table cannot
    /// resolve its logical page or the page it names lies past the end of
    /// the file, this block has no v6 page cache attached, or the physical
    /// page's own tag does not say "record data".
    fn v6_record_bytes_at(&self, position: u32) -> Result<Option<Vec<u8>>, String> {
        let layout = pages::Layout {
            page: self.geometry.page,
            physical: self.geometry.physical,
            pages: self.geometry.pages,
        };
        let (logical, slot) = layout.slot_of(position).ok_or_else(|| {
            format!("position {position} is not on a slot boundary of this file's layout")
        })?;
        let physical_page = self.v6_resolve_logical(logical)?;
        let cache = self.cache.as_ref().ok_or_else(|| {
            format!(
                "{}: no v6 page cache attached -- not a v6 file, or a test build \
                 that skipped Self::open",
                self.name
            )
        })?;
        let buffer = {
            let mut guard = cache.borrow_mut();
            guard.page(physical_page)?.to_vec()
        };
        if buffer.len() < 2 || buffer[1] != 0x44 || !pages::Header::decode(&buffer).data {
            return Err(format!(
                "physical page {physical_page} (logical {logical}) does not carry the \
                 record-data tag this position's own slot expects"
            ));
        }
        let marker_at = layout.position(0, slot) as usize;
        if marker_at + records::V6_SLOT_MARKER > buffer.len() {
            return Err(format!(
                "slot {slot} at logical page {logical} runs past its own {}-byte page",
                buffer.len()
            ));
        }
        if u16::from_le_bytes([buffer[marker_at], buffer[marker_at + 1]]) == 0 {
            return Ok(None);
        }
        let start = marker_at + records::V6_SLOT_MARKER;
        let content_len = usize::from(self.geometry.physical) - records::V6_SLOT_MARKER;
        let reclen = usize::from(self.geometry.reclen);
        if start + content_len > buffer.len() {
            return Err(format!(
                "slot {slot} at logical page {logical} runs past its own {}-byte page",
                buffer.len()
            ));
        }
        Ok(Some(buffer[start..start + content_len][..reclen].to_vec()))
    }

    /// A v6 record's page, and where its slot starts inside that page.
    ///
    /// The four quantities every v6 write below needs and none of them should
    /// re-derive: the record's logical page, the physical page currently
    /// holding it, the slot's byte offset within a page, and a page store to
    /// do the rest of the write through. The first three are resolved by
    /// [`Self::v6_resolve_logical`] and pure arithmetic, without loading the
    /// file -- see that function's own doc comment. [`v6::Store::open`]
    /// below reads nothing yet either; it only checks the file's length
    /// against `page_size`, and every page [`Self::update_v6`] or
    /// [`Self::delete_v6`] actually needs -- this one included -- is read
    /// lazily as they ask for it, once, from here on.
    ///
    /// # Errors
    ///
    /// If the file's metadata cannot be read or its length is not a whole
    /// number of pages, `position` is not on a slot boundary, the allocation
    /// table cannot be resolved or does not claim the record's logical page,
    /// or the page it names lies past the end of the file.
    fn v6_slot(&self, position: u32, layout: pages::Layout) -> Result<V6Slot, String> {
        let (logical, slot) = layout.slot_of(position).ok_or_else(|| {
            format!("position {position} is not on a slot boundary of this file's layout")
        })?;

        let physical = self.v6_resolve_logical(logical)?;

        let mut store = match &self.cache {
            Some(cache) => v6::Store::attach(cache, &self.path, self.geometry.page)?,
            None => v6::Store::open(&self.path, self.geometry.page)?,
        };
        // Touch the page now, not lazily on first write: a `physical` the
        // allocation table named but that does not actually exist in the
        // file is exactly the "past the end" refusal this used to raise
        // itself, and `Store::page` already raises the same one.
        store.page(physical as usize).map_err(|why| {
            format!("logical page {logical} resolves to physical page {physical}: {why}")
        })?;

        // Within a page, a slot's offset is the same whichever page it is on,
        // so `position(0, slot)` asks exactly that -- the same reasoning
        // `records::walk_v6` gives at length for the same expression.
        Ok(V6Slot {
            store,
            logical,
            physical,
            within: layout.position(0, slot) as usize,
        })
    }

    /// Replace the record at `position` in a v6 file.
    ///
    /// # What genuine Btrieve does, which this follows
    ///
    /// Measured 2026-08-16 (`docs/2026-08-16-v6-update-delete-oracle.md`):
    ///
    /// - the record is rewritten **in its own slot**, so its position never
    ///   changes -- not when the body changes, and not even when the key value
    ///   does;
    /// - the slot's two-byte marker is incremented (`1` on a fresh record, `2`
    ///   after its first update, and so on);
    /// - the data page is relocated;
    /// - the index is touched **only if a key's value changed** -- an update
    ///   that leaves every key alone leaves every index page byte-identical.
    ///   [`Self::v6_reindex`] is what implements that last part, by comparing
    ///   before relocating.
    /// - the record count does not change, and neither does the free list.
    ///
    /// # A key that does not declare itself modifiable
    ///
    /// Refused before this is reached -- see
    /// [`Self::unmodifiable_key_changed`], called from [`Self::update`] ahead
    /// of the version split, because the rule is the file format's and not
    /// v6's. An earlier version of this comment said the bit had never been
    /// measured and so could not be acted on; it had been measured, in the
    /// same session, by creating one file with key attributes `0x0100` and
    /// another with `0x0102` and running the same update against both.
    ///
    /// # Variable-length records (Task 6)
    ///
    /// When `self.geometry.variable`, `bytes` is `reclen` fixed bytes
    /// followed by the record's whole body -- [`Self::update_inner`] only
    /// reaches this function once it has confirmed there is one (its
    /// `has_body` check). The slot's own four-byte pointer, between `reclen`
    /// and `physical`, is never in `bytes` at all, and must not be
    /// overwritten by copying `bytes` straight into the slot the way the
    /// fixed-length case does -- that is the exact corruption
    /// [`Self::update`]'s own doc comment warns a blanket write here would
    /// cause. Instead: the pointer is read off the *pre-write* page,
    /// [`variable::rewrite_fragment_in_place_v6`] rewrites the fragment it
    /// names (refusing rather than guessing at a chain or a resize -- see
    /// its own doc comment), the page is re-read fresh because that call
    /// went through `store` directly, and only then are the marker and the
    /// `reclen` fixed bytes written -- the pointer itself is never touched,
    /// because the fragment did not move.
    ///
    /// # Errors
    ///
    /// If the file cannot be read or written, `position` does not resolve to a
    /// claimed slot, [`Self::v6_reindex`] refuses any key, or (variable-length
    /// only) the fragment is chained onto another page, is not exactly one
    /// fragment, or is not the same length as the replacement.
    fn update_v6(&mut self, position: u32, bytes: &[u8], layout: pages::Layout) -> Result<(), BtvError> {
        let name = self.name.clone();
        let fail = |why: String| BtvError {
            file: name.clone(),
            why,
        };

        let page_size = self.geometry.page;
        let V6Slot {
            mut store,
            logical,
            physical,
            within,
        } = self.v6_slot(position, layout).map_err(&fail)?;

        // Task 7's ops cutover: a fixed-length v6 block with a page cache
        // never builds `records_clone` -- see `Self::insert_v6`'s own doc
        // comment on the identical fast path there for the full reasoning.
        // `old_record`, below, already comes from the page itself, not from
        // any in-memory model, so the fast path costs nothing extra to
        // reach it.
        let fast = self.v6_fast_reads();
        let mut records_clone = if fast {
            None
        } else {
            let mut rc = self
                .records
                .as_ref()
                .expect("Self::update calls Self::records() before this")
                .clone();
            rc.update(&self.keys, position, bytes.to_vec())
                .map_err(|why| fail(format!("updating the record in the model: {why}")))?;
            Some(rc)
        };

        let mut content = store.page(physical as usize).map_err(&fail)?.to_vec();
        let body = within + V6_SLOT_MARKER;
        let reclen = usize::from(self.geometry.reclen);
        let old_record = content[body..body + reclen].to_vec();

        // Variable-length records: rewrite the fragment first, on the
        // pre-write pointer, then re-read the slot's own page fresh -- see
        // this function's own doc comment for why. `fixed_len` is `reclen`
        // here (the pointer bytes past it are left exactly as they already
        // are) and `bytes.len()` for a fixed-length record, where there is
        // no pointer to disturb.
        let fixed_len = if self.geometry.variable {
            let pointer_at = body + reclen;
            let pointer = variable::Pointer::decode([
                content[pointer_at],
                content[pointer_at + 1],
                content[pointer_at + 2],
                content[pointer_at + 3],
            ]);
            {
                let mut fragments = variable::V6Pages::new(&mut store, page_size).map_err(&fail)?;
                variable::rewrite_fragment_in_place_v6(&mut fragments, pointer, &bytes[reclen..])
                    .map_err(&fail)?;
            }
            content = store.page(physical as usize).map_err(&fail)?.to_vec();
            reclen
        } else {
            bytes.len()
        };

        // The marker counts updates, and zero means free -- so it must never
        // land back on zero. Genuine Btrieve's behaviour at the sixty-five
        // thousandth update of one record was not measured; wrapping to `1`
        // is this host's own choice, taken because the alternative readings
        // (wrap to `0`, or refuse the write) are respectively corruption and
        // a refusal no module could act on.
        let marker = u16::from_le_bytes([content[within], content[within + 1]]);
        let marker = marker.checked_add(1).filter(|&m| m != 0).unwrap_or(1);
        content[within..within + 2].copy_from_slice(&marker.to_le_bytes());

        content[body..body + fixed_len].copy_from_slice(&bytes[..fixed_len]);

        let fcr = self.v6_live_fcr(&mut store).map_err(&fail)?;

        v6::Map::relocate(&mut store, page_size, logical, &content, [0x00, 0x44])
            .map_err(|why| fail(format!("relocating the record's page: {why}")))?;

        // Task 6: only a key whose own VALUE changed is touched at all
        // (measured -- see this function's own doc comment); an unchanged
        // key's tree is not even read, let alone rewritten. A changed key
        // is a delete of its old value followed by an insert of its new
        // one -- both already incremental, and this composition is sound
        // even though no oracle recording exercises a key-changing update
        // specifically (the replay corpus's own `ReplayOp` has no `Update`
        // variant at all).
        let shift = if fast {
            2
        } else {
            records_clone.as_ref().expect("just built").key_shift()
        };
        let cache_rc = self.v6_tree_cache().map_err(&fail)?;
        let mut key_record_counts: Vec<(usize, u32)> = Vec::with_capacity(self.keys.len());
        let mut key_roots: Vec<(usize, u32)> = Vec::new();
        // Every key whose own extracted value actually changed (or whose
        // `Key::excluded` status flipped) -- fed to `Self::v6_invalidate_
        // keys` below. A key this update never touches keeps its cached
        // `OrderIndex`, which is the whole point for the majority of live
        // write traffic (health, gold, position) that changes no key at
        // all.
        let mut changed_keys: Vec<u16> = Vec::new();
        let mut index_free_head =
            pages::long(&fcr[pages::fcr::INDEX_FREE_V6..pages::fcr::INDEX_FREE_V6 + 4]);
        for key in &self.keys {
            let definition = pages::fcr::KEYS + usize::from(key.definition) * pages::fcr::KEY_WIDTH;
            let len = if fast {
                // An update changes the *total* record count for a key
                // only when the value's own excluded-ness flips (`Key::
                // excluded`, the same predicate `records.rs` filters
                // `order[key]` by) -- an ordinary value change, key or not,
                // leaves the count exactly where the live FCR already has
                // it.
                let at = definition + pages::fcr::KEY_RECORDS;
                let before_count = pages::long(&fcr[at..at + 4]);
                let was_excluded = key.excluded(&records::keyed(shift, &old_record));
                let now_excluded = key.excluded(&records::keyed(shift, bytes));
                match (was_excluded, now_excluded) {
                    (false, true) => before_count.saturating_sub(1),
                    (true, false) => before_count.saturating_add(1),
                    _ => before_count,
                }
            } else {
                u32::try_from(
                    records_clone
                        .as_ref()
                        .expect("just built")
                        .ordered_len(key.number)
                        .ok_or_else(|| {
                            fail(format!(
                                "key {}: not among the keys the loaded records were ordered by",
                                key.number
                            ))
                        })?,
                )
                .expect("far fewer records than u32::MAX")
            };
            key_record_counts.push((definition + pages::fcr::KEY_RECORDS, len));

            let before = records::keyed(shift, &old_record);
            let after = records::keyed(shift, bytes);
            if key.compare(&before, &after) == std::cmp::Ordering::Equal {
                continue;
            }
            changed_keys.push(key.number);
            let old_value = key.extract(&before);
            let new_value = key.extract(&after);

            // The fast path first: old and new value on the same leaf is a
            // same-count swap, one relocate, nothing above it touched or
            // even read. Only when that does not apply does this fall back
            // to the general delete-then-insert composition below.
            if self
                .v6_tree_update_key_same_leaf(&mut store, &cache_rc, layout, key, &fcr, &old_value, &new_value, position)?
                .is_some()
            {
                continue;
            }

            let (root_after_delete, free_head_after_delete) = self.v6_tree_delete(
                &mut store,
                &cache_rc,
                layout,
                key,
                &fcr,
                &old_value,
                position,
                index_free_head,
                None,
            )?;
            index_free_head = free_head_after_delete;
            if let Some(root) = root_after_delete {
                key_roots.push((definition + pages::fcr::KEY_ROOT, root));
            }

            // The FCR this second call reads a root from must reflect the
            // delete's own root move, if any -- the live `fcr` bytes this
            // function read at the top of `update_v6` are a snapshot, so a
            // key whose delete just grew or shrank its own tree gets its
            // updated root spliced in before the matching insert looks for
            // it, exactly as `v6_reindex`'s own single-pass loop kept every
            // key's view consistent across its own writes.
            let mut fcr_for_insert = fcr.clone();
            if let Some(root) = root_after_delete {
                let root_at = definition + pages::fcr::KEY_ROOT;
                fcr_for_insert[root_at..root_at + 4].copy_from_slice(&pages::to_long(root));
            }
            let (root_after_insert, free_head_after_insert) = self.v6_tree_insert(
                &mut store,
                &cache_rc,
                layout,
                key,
                &fcr_for_insert,
                &new_value,
                position,
                index_free_head,
            )?;
            index_free_head = free_head_after_insert;
            if let Some(root) = root_after_insert {
                key_roots.retain(|&(offset, _)| offset != definition + pages::fcr::KEY_ROOT);
                key_roots.push((definition + pages::fcr::KEY_ROOT, root));
            }
        }

        // An update never changes how many records the file holds, fast
        // path or slow.
        let total_records = if fast {
            self.geometry.records
        } else {
            u32::try_from(records_clone.as_ref().expect("just built").len())
                .expect("far fewer records than u32::MAX")
        };
        v6::write_fcr(
            &mut store,
            page_size,
            total_records,
            &key_record_counts,
            None,
            None,
            Some(index_free_head),
            &key_roots,
        )
        .map_err(|why| fail(format!("updating the file control record: {why}")))?;

        self.capture_for_journal()?;
        self.write_changed_pages(&mut store)?;

        if fast {
            self.v6_invalidate_keys(&changed_keys);
        } else {
            self.records = records_clone.take();
        }
        self.geometry.pages =
            u32::try_from(store.total_pages()).expect("a Btrieve file under four gigabytes of pages");
        self.dirty = true;

        Ok(())
    }

    /// Take the record at `position` out of a v6 file.
    ///
    /// # What genuine Btrieve does, which this follows
    ///
    /// Measured 2026-08-16 (`docs/2026-08-16-v6-update-delete-oracle.md`):
    ///
    /// - the slot's marker goes to zero, and the first four bytes of its body
    ///   become the free list's previous head, with everything behind that
    ///   zeroed -- the same forwarding-link shape v5 uses, at the same place
    ///   in the slot;
    /// - the file control record's free-list head becomes this slot's own
    ///   position. **`pages::fcr::FREE_V6`, not `pages::fcr::FREE`** -- the v5
    ///   offset reads `0xffffffff` on every v6 file and never moves;
    /// - the record count and the touched keys' record counts each drop by
    ///   one, and the index is rebuilt without the entry;
    /// - the page **keeps its claim in the allocation table**, whether or not
    ///   other records share it, and *even when the deleted record was the
    ///   only one on it*. Scenario B of the measurement is exactly that case.
    ///   Nothing here unclaims a page, and that is the measured behaviour
    ///   rather than a simplification.
    ///
    /// That whole ladder was measured against a **fixed-length** file
    /// (`reclen 32`, no variable flag) and this function applies it
    /// unchanged to a variable-length slot's own bytes -- the forwarding
    /// link and the fragment pointer never collide (the link goes at the
    /// slot's first four body bytes; the pointer sits `reclen` bytes in, and
    /// `reclen` is never zero), so zeroing "everything behind" the link is
    /// the same write either way.
    ///
    /// # Variable-length records (Task 7)
    ///
    /// When `self.geometry.variable`, the record's own fragment is freed
    /// **before** any byte of the slot is touched -- the same ordering
    /// [`Self::update_v6`] uses and for the same reason: a shape refusal
    /// there must leave nothing written anywhere. The pointer is read off
    /// the *pre-write* page (between `reclen` and `physical` in the slot,
    /// same as [`Self::update_v6`]), [`variable::free_fragment_v6`] frees
    /// the fragment it names (refusing a chained fragment, or one an oracle
    /// recording has not settled -- see its own doc comment), and the page
    /// is re-read fresh afterward because that call went through `store`
    /// directly and may have relocated an unrelated page. Only then does
    /// the slot itself get zeroed and linked, exactly as the fixed-length
    /// case above.
    ///
    /// # The freed slot is reused, not leaked
    ///
    /// The freed slot goes on the free list, and [`Self::insert_v6`] pops
    /// exactly that head before ever claiming a fresh page -- see
    /// [`Self::v6_pop_free`]. A delete-then-insert pair reuses the freed
    /// slot rather than costing a page, the other half of the same
    /// mechanism this function's own doc describes:
    /// [`a_v6_insert_reuses_the_slot_a_delete_freed`] is the test. An
    /// earlier version of this host claimed a whole fresh page per insert
    /// and never touched the head, which this section used to describe as
    /// a standing leak; that has since been fixed.
    ///
    /// # A freed fragment page rejoins the write-side free-space chain
    ///
    /// **Corrected during review**: an earlier version of this comment
    /// claimed rejoining the chain was safe to defer because "no v6 insert
    /// consults it." That was false -- `Self::insert_v6` has called
    /// [`variable::head_of`] and [`variable::Space::place`] for every v6
    /// variable-length insert since before this task
    /// (`insert_writes_a_variable_length_record_into_a_file_the_engine_made`).
    /// Deferring the rejoin would have made a page `free_fragment_v6` just
    /// gave real room to permanently unreachable to that exact insert path
    /// -- a claimed-but-unreachable leak of the same class Task 3b already
    /// fixed once for index pages, this time for fragment pages.
    ///
    /// [`variable::free_fragment_v6`] now threads the chain's head the same
    /// way [`Self::insert_v6`] does (`was`/`now`): read
    /// [`variable::head_of`] off the live file control record before the
    /// free, pass it in, and write back whatever comes out through
    /// `write_fcr`'s `variable_head` (doubly optional, same as insert's own
    /// call). A page already reachable from the chain is left exactly where
    /// it is -- see the function's own doc comment for why moving it is out
    /// of scope, the same restriction `Space::reoffer` holds itself to.
    ///
    /// # Errors
    ///
    /// If the file cannot be read or written, `position` does not resolve to a
    /// claimed slot, [`Self::v6_reindex`] refuses any key, or (variable-length
    /// only) the record's fragment is chained onto another page, is the only
    /// fragment on its page, or [`variable::free_fragment_v6`] refuses it for
    /// any other reason -- see that function's own doc comment.
    fn delete_v6(&mut self, position: u32, layout: pages::Layout) -> Result<(), BtvError> {
        let name = self.name.clone();
        let fail = |why: String| BtvError {
            file: name.clone(),
            why,
        };

        let page_size = self.geometry.page;
        let V6Slot {
            mut store,
            logical,
            physical,
            within,
        } = self.v6_slot(position, layout).map_err(&fail)?;

        // Task 7's ops cutover: a fixed-length v6 block with a page cache
        // never builds `records_clone`, and fetches the about-to-be-
        // deleted record's own bytes straight through the page cache by
        // position rather than through an in-memory model -- see
        // `Self::insert_v6`'s own doc comment on the identical fast path
        // there.
        let fast = self.v6_fast_reads();
        let shift = if fast {
            2
        } else {
            self.records.as_ref().map_or(0, Records::key_shift)
        };
        let old_record = if fast {
            self.v6_record_bytes_at(position)
                .map_err(&fail)?
                .ok_or_else(|| fail(format!("position {position} does not name a live record")))?
        } else {
            let records = self
                .records
                .as_ref()
                .expect("Self::delete calls Self::records() before this");
            let at = records.find_physical(position).ok_or_else(|| {
                fail(format!("position {position} does not name a live record in the model"))
            })?;
            records.physical(at).expect("just found").bytes.clone()
        };

        let mut records_clone = if fast {
            None
        } else {
            let mut rc = self
                .records
                .as_ref()
                .expect("Self::delete calls Self::records() before this")
                .clone();
            rc.delete(&self.keys, position)
                .map_err(|why| fail(format!("removing the record from the model: {why}")))?;
            Some(rc)
        };

        let fcr = self.v6_live_fcr(&mut store).map_err(&fail)?;
        let free_head = pages::long(&fcr[pages::fcr::FREE_V6..pages::fcr::FREE_V6 + 4]);

        // Variable-length records: free the fragment first, on the
        // pre-write pointer, before a byte of the slot itself is touched --
        // see this function's own doc comment for why. `Self::v6_slot`'s
        // `within` already accounts for the marker.
        //
        // `variable_head` threads the write-side free-space chain's head
        // exactly the way `Self::insert_v6` threads it (`was`/`now` there):
        // `None` here means "this delete never touched the chain" (a fixed-
        // length file, or nothing to rejoin), and
        // `Some(new_head)` -- even when `new_head == was` -- says "checked,
        // write it back," matching `v6::write_fcr`'s own doubly-optional
        // contract for this field.
        let mut variable_head: Option<Option<u32>> = None;
        if self.geometry.variable {
            let reclen = usize::from(self.geometry.reclen);
            let pre_write = store.page(physical as usize).map_err(&fail)?.to_vec();
            let pointer_at = within + V6_SLOT_MARKER + reclen;
            let pointer = variable::Pointer::decode([
                pre_write[pointer_at],
                pre_write[pointer_at + 1],
                pre_write[pointer_at + 2],
                pre_write[pointer_at + 3],
            ]);
            let was = variable::head_of(&fcr);
            let mut fragments = variable::V6Pages::new(&mut store, page_size).map_err(&fail)?;
            let now = variable::free_fragment_v6(&mut fragments, pointer, was).map_err(&fail)?;
            variable_head = Some(now);
        }

        let mut content = store.page(physical as usize).map_err(&fail)?.to_vec();

        // Every duplicate-permitting key's own `[prev][next]` pair for this
        // exact slot, read *before* the zero-fill below erases it. The
        // B-tree loop further down needs `position`'s own chain neighbours
        // to splice a partial-chain delete around, and by the time it runs
        // this slot has already been wiped and relocated -- `v6_tree_delete`
        // reading it fresh at that point would only find zeros.
        let own_chain_pairs: Vec<Option<(u32, u32)>> = self
            .keys
            .iter()
            .map(|k| {
                k.chain.map(|offset| {
                    let at = within + usize::from(offset);
                    (pages::long(&content[at..at + 4]), pages::long(&content[at + 4..at + 8]))
                })
            })
            .collect();

        // Zero the whole slot -- marker included -- and then write the
        // forwarding link over the front of the body. Zeroing first rather
        // than only writing the link is what leaves the measured shape: the
        // freed slot's own record bytes do not survive the delete.
        let slot_end = within + usize::from(self.geometry.physical);
        content[within..slot_end].fill(0);
        let body = within + V6_SLOT_MARKER;
        content[body..body + 4].copy_from_slice(&pages::to_long(free_head));

        v6::Map::relocate(&mut store, page_size, logical, &content, [0x00, 0x44])
            .map_err(|why| fail(format!("relocating the record's page: {why}")))?;

        // Task 6: every key's own B-tree, edited incrementally -- locate
        // the deleted record's own entry, remove it, redistribute or merge
        // an underflow per the rules doc, cascading upward at most to the
        // root -- never a full `v6_reindex` rebuild.
        let cache_rc = self.v6_tree_cache().map_err(&fail)?;
        let mut key_record_counts: Vec<(usize, u32)> = Vec::with_capacity(self.keys.len());
        let mut key_roots: Vec<(usize, u32)> = Vec::new();
        // Every key the deleted record was actually indexed under -- fed
        // to `Self::v6_invalidate_keys` below, so a key that excluded this
        // record (`Key::excluded`) keeps its cached `OrderIndex`.
        let mut changed_keys: Vec<u16> = Vec::new();
        let mut index_free_head =
            pages::long(&fcr[pages::fcr::INDEX_FREE_V6..pages::fcr::INDEX_FREE_V6 + 4]);
        for (key_index, key) in self.keys.iter().enumerate() {
            let definition = pages::fcr::KEYS + usize::from(key.definition) * pages::fcr::KEY_WIDTH;
            let len = if fast {
                // The deleted record's own excluded-ness under this key
                // says whether its removal drops this key's count at all
                // (`Key::excluded`, the same predicate `records.rs` filters
                // `order[key]` by).
                let at = definition + pages::fcr::KEY_RECORDS;
                let before_count = pages::long(&fcr[at..at + 4]);
                if key.excluded(&records::keyed(shift, &old_record)) {
                    before_count
                } else {
                    changed_keys.push(key.number);
                    before_count.saturating_sub(1)
                }
            } else {
                u32::try_from(
                    records_clone
                        .as_ref()
                        .expect("just built")
                        .ordered_len(key.number)
                        .ok_or_else(|| {
                            fail(format!(
                                "key {}: not among the keys the loaded records were ordered by",
                                key.number
                            ))
                        })?,
                )
                .expect("far fewer records than u32::MAX")
            };
            key_record_counts.push((definition + pages::fcr::KEY_RECORDS, len));

            let value = key.extract(&records::keyed(shift, &old_record));
            let (new_root, next_free_head) = self.v6_tree_delete(
                &mut store,
                &cache_rc,
                layout,
                key,
                &fcr,
                &value,
                position,
                index_free_head,
                own_chain_pairs[key_index],
            )?;
            index_free_head = next_free_head;
            if let Some(root) = new_root {
                key_roots.push((definition + pages::fcr::KEY_ROOT, root));
            }
        }

        let total_records = if fast {
            self.geometry.records.saturating_sub(1)
        } else {
            u32::try_from(records_clone.as_ref().expect("just built").len())
                .expect("far fewer records than u32::MAX")
        };
        v6::write_fcr(
            &mut store,
            page_size,
            total_records,
            &key_record_counts,
            Some(position),
            variable_head,
            Some(index_free_head),
            &key_roots,
        )
        .map_err(|why| fail(format!("updating the file control record: {why}")))?;

        self.capture_for_journal()?;
        self.write_changed_pages(&mut store)?;

        if fast {
            self.v6_invalidate_keys(&changed_keys);
            self.v6_invalidate_physical();
        } else {
            self.records = records_clone.take();
        }
        self.geometry.records = total_records;
        self.geometry.pages =
            u32::try_from(store.total_pages()).expect("a Btrieve file under four gigabytes of pages");
        self.dirty = true;

        Ok(())
    }

    /// The live half of a v6 file's file-control-record shadow pair.
    ///
    /// Physical pages 0 and 1 both carry a control record; the one with the
    /// higher generation is the current one. A tie is refused rather than
    /// broken, because no rule for breaking it has been measured -- the same
    /// refusal [`v6::write_fcr`] and [`v6::Map::relocate`] each make about
    /// their own pair.
    ///
    /// # Errors
    ///
    /// If the file does not hold two whole pages, or the two generations tie.
    fn v6_live_fcr(&self, store: &mut v6::Store) -> Result<Vec<u8>, String> {
        let page_size = usize::from(self.geometry.page);
        if store.total_pages() < 2 {
            return Err(format!(
                "{} bytes does not hold two whole {page_size}-byte pages for the \
                 file control record's shadow pair",
                store.total_pages() * page_size
            ));
        }
        let generation = |store: &mut v6::Store, page: usize| -> Result<u16, String> {
            let header = store.header(page)?;
            Ok(u16::from_le_bytes([header[at::GENERATION], header[at::GENERATION + 1]]))
        };
        let live = match generation(store, 0)?.cmp(&generation(store, 1)?) {
            std::cmp::Ordering::Greater => 0usize,
            std::cmp::Ordering::Less => 1usize,
            std::cmp::Ordering::Equal => {
                return Err(format!(
                    "both file-control-record copies claim generation {}, and \
                     there is no rule measured for choosing between them",
                    generation(store, 0)?
                ));
            }
        };
        Ok(store.page(live)?.to_vec())
    }

    /// Rebuild every key's index from `records`, and relocate each key's root
    /// page whose content the rebuild actually changed.
    ///
    /// Shared by [`Self::insert_v6`], [`Self::update_v6`] and
    /// [`Self::delete_v6`], which differ in what they do to a *record* and
    /// agree completely on what that obliges them to do to the *indexes*.
    /// Written once so they cannot drift: three copies of "build every key,
    /// check every key fits, then write" is three places for a refusal to be
    /// checked in the wrong order.
    ///
    /// # Every key is built before any key is written
    ///
    /// A refusal must never leave some keys' indexes updated and others not,
    /// so the whole `built` vector is assembled -- and every scope check made
    /// -- before the first [`v6::Map::relocate`] call. This is the property
    /// [`Self::insert_v6`]'s doc comment states and the reason this is one
    /// pass followed by another rather than a single loop.
    ///
    /// # A key whose index did not change is not relocated
    ///
    /// Measured (`docs/2026-08-16-v6-update-delete-oracle.md`): an update that
    /// leaves every key's *value* alone leaves the index pages untouched --
    /// not rewritten in place, not relocated, byte-identical. Only an update
    /// that reorders a key moves its root. So the rebuilt image is compared
    /// against what the file already holds, past the six-byte header whose
    /// stamp and logical id are [`v6::Map::relocate`]'s to write, and an
    /// unchanged key is skipped.
    ///
    /// That is not an optimisation for its own sake: [`v6::Map::relocate`]
    /// **appends** the relocated page to the file, so a needless relocation
    /// costs a page of growth per call, forever.
    ///
    /// `fcr` is the live half of the file control record's shadow pair, which
    /// the caller has already chosen; `records` is the model **after** the
    /// caller's own change, since that is what the indexes have to describe.
    ///
    /// # Errors
    ///
    /// If any key is not among the orders the loaded records carry, has a
    /// root without the v6 marker bit, or if claiming or releasing an index
    /// page, or a relocation, fails. A duplicate-permitting key is handled,
    /// not refused -- see [`Self::v6_write_chains`] -- and an index that
    /// outgrows one page claims the extra pages it needs rather than
    /// refusing.
    /// Write the `[prev][next]` pairs that join records sharing a key value,
    /// into the records themselves, **v6-aware**.
    ///
    /// # Why `pages::write_chain` cannot be used
    ///
    /// It seeks `position + offset` as a literal file offset
    /// (`pages.rs:613`), which is right for v5 and wrong for v6: a v6
    /// record's position embeds the page's **logical** id, not its physical
    /// one (`records.rs:798-813`). On `DUPKEY30.DAT` logical 2 is physical
    /// 10, so seeking a v6 position writes over an entirely different page
    /// and reports success -- the silent corruption this crate exists to
    /// refuse. Here the logical id is resolved through the allocation table
    /// first.
    ///
    /// # Why whole pages, and why relocation
    ///
    /// A v6 page is never written in place; it is rewritten to the other half
    /// of its shadow pair with the allocation table repointed
    /// (`v6::Map::relocate`). So the pairs are grouped by the page they land
    /// on and each page is relocated exactly once, however many records on it
    /// need chaining.
    ///
    /// # What it writes
    ///
    /// Eight bytes per record: `[prev][next]`, each a
    /// [`pages::to_long`], and [`pages::NOWHERE`] at either end of a group. A
    /// record whose value is unique gets `NOWHERE` in both, which is what
    /// genuine 6.15 writes -- zeros would name page 0, the control record, as
    /// the next record in the chain
    /// (`docs/2026-08-17-v6-duplicate-key-oracle.md`).
    ///
    /// Unreferenced now that [`Self::insert_v6`]/[`Self::update_v6`]/
    /// [`Self::delete_v6`] no longer call [`Self::v6_reindex`] (Task 6) --
    /// kept, not deleted, for the same reason that function is: a future
    /// create/repair path that still wants a from-scratch tree.
    #[allow(dead_code)]
    fn v6_write_chains(
        &self,
        store: &mut v6::Store,
        layout: pages::Layout,
        chains: &[(usize, Vec<Vec<u32>>)],
    ) -> Result<(), String> {
        let page_size = self.geometry.page;
        let page_size_usize = usize::from(page_size);

        // Every eight-byte write this call owes, keyed by the logical page it
        // lands on: (offset within the page, the pair).
        let mut per_page: std::collections::BTreeMap<u32, Vec<(usize, [u32; 2])>> =
            std::collections::BTreeMap::new();

        for (offset, groups) in chains {
            for group in groups {
                for (at, position) in group.iter().enumerate() {
                    let pair = [
                        if at == 0 { pages::NOWHERE } else { group[at - 1] },
                        if at + 1 == group.len() {
                            pages::NOWHERE
                        } else {
                            group[at + 1]
                        },
                    ];
                    let (logical, slot) = layout.slot_of(*position).ok_or_else(|| {
                        format!("record position {position} is not on a slot boundary")
                    })?;
                    let within = layout.position(0, slot) as usize + offset;
                    if within + 8 > page_size_usize {
                        return Err(format!(
                            "a chain offset of {offset} puts its eight bytes at {within} of \
                             a {page_size}-byte page, past its end"
                        ));
                    }
                    per_page.entry(logical).or_default().push((within, pair));
                }
            }
        }

        // Read once and refreshed only after a relocation actually moves
        // something -- the same reason [`Self::v6_reindex`]'s loop does:
        // a relocation does rewrite the allocation table, but most passes
        // through this loop no longer relocate at all.
        let mut map = v6::Map::read(store, page_size)?;
        let mut map_is_stale = false;

        for (logical, writes) in per_page {
            if map_is_stale {
                map = v6::Map::read(store, page_size)?;
                map_is_stale = false;
            }
            let physical = map
                .physical(logical)
                .ok_or_else(|| {
                    format!(
                        "a record lives on logical page {logical}, which the allocation \
                         table claims no physical page for"
                    )
                })?;
            let mut content = store
                .page(physical as usize)
                .map_err(|why| {
                    format!("logical page {logical} resolves to physical {physical}: {why}")
                })?
                .to_vec();

            for (within, [prev, next]) in writes {
                content[within..within + 4].copy_from_slice(&pages::to_long(prev));
                content[within + 4..within + 8].copy_from_slice(&pages::to_long(next));
            }

            // The diff [`Self::v6_reindex`]'s index loop has always had, and
            // this one did not: a write that leaves a duplicate key's groups
            // exactly where they were still recomputed every chain pair, and
            // relocated every data page holding one, for bytes identical to
            // the ones already there. The pages are *data* pages, so each
            // needless relocation also claimed or consumed a shadow twin.
            if content.as_slice() == store.page(physical as usize).map_err(|why| why.to_string())? {
                continue;
            }

            v6::Map::relocate(store, page_size, logical, &content, [0x00, 0x44])?;
            map_is_stale = true;
        }

        Ok(())
    }

    // ---- Task 6: incremental v6 B-tree maintenance -------------------------
    //
    // Everything below replaces the per-op call to `Self::v6_reindex` in
    // `insert_v6`/`update_v6`/`delete_v6` with leaf-local edits per
    // `docs/2026-08-25-btree-split-rules.md`: locate the touched entry with
    // `nav::descend_for_write`, edit only the pages a split/merge/
    // redistribute actually needs, and relocate/claim/retire/reclaim
    // exactly those. `v6_reindex` itself is untouched -- it still exists
    // for create/repair/close-time rebuild of a v5-style caller.

    /// The page cache a v6 tree edit reads through: this block's own `Rc`
    /// when it has one (every `Block` a real `Self::open` produced), or a
    /// fresh cache scoped to this one call when it does not -- a test-built
    /// `Block` that skipped `Self::open`, the same graceful fallback
    /// [`Self::v6_slot`]/[`Self::v6_resolve_logical`] already use so this
    /// incremental path works the same way against either kind of `Block`.
    ///
    /// # Errors
    ///
    /// If a fresh cache cannot be opened (this block has no attached one).
    fn v6_tree_cache(&self) -> Result<std::rc::Rc<std::cell::RefCell<cache::PageCache>>, String> {
        match &self.cache {
            Some(rc) => Ok(std::rc::Rc::clone(rc)),
            None => Ok(std::rc::Rc::new(std::cell::RefCell::new(cache::PageCache::open(
                &self.path,
                self.geometry.page,
            )?))),
        }
    }

    /// `key`'s current root (still tag-decorated) and shape, off `fcr` --
    /// the non-cache half of what [`Self::nav_root`] bundles, split out
    /// because a tree write already carries its own cache handle
    /// ([`Self::v6_tree_cache`]) alongside.
    ///
    /// `None` when `key` has no tree yet (a virgin file) -- Task 6's
    /// incremental path only maintains an existing tree; a key's very
    /// first index page is [`Self::v6_reindex`]'s job (reached only from
    /// create/repair), never this one's.
    fn v6_key_root(&self, key: &keys::Key, fcr: &[u8]) -> Result<Option<(u32, pages::Shape)>, String> {
        let Some(root) = nav::root_of(fcr, usize::from(key.definition), key.number)? else {
            return Ok(None);
        };
        Ok(Some((root, key.shape())))
    }

    /// A logical id as `key`'s own index pages tag it -- `0x80 + key.number`
    /// in the high byte, `0x00` in the low one, matching
    /// [`Self::v6_decorate`]/[`Self::v6_reindex`]'s identical computation.
    fn v6_key_tag_bytes(key: &keys::Key) -> Result<[u8; 2], BtvError> {
        let fail = |why: String| BtvError { file: String::new(), why };
        let high = 0x80u8
            .checked_add(u8::try_from(key.number).map_err(|_| {
                fail(format!("key {}: does not fit a page tag's low byte", key.number))
            })?)
            .ok_or_else(|| {
                fail(format!(
                    "key {}: a page tag's high byte is 0x80 plus the key's own \
                     number, and this key's number does not fit",
                    key.number
                ))
            })?;
        Ok([0x00, high])
    }

    /// Reconstruct [`pages::Entry`] values from a decoded [`pages::IndexPage`]'s
    /// own `entries`/`tails` arrays -- [`pages::encode_v6_index_page`]'s
    /// input shape, needed because `IndexPage` keeps a duplicate-permitting
    /// key's tail in a parallel array rather than alongside `head`.
    fn entries_from_page(page: &pages::IndexPage, tails: &[u32]) -> Vec<pages::Entry> {
        page.entries
            .iter()
            .enumerate()
            .map(|(n, (key, head, _child))| pages::Entry {
                key: key.clone(),
                head: *head,
                tail: tails.get(n).copied().unwrap_or(*head),
            })
            .collect()
    }

    /// Split a full node's already-merged entry sequence (`max_entries + 1`
    /// entries, sorted) per split rules §2/§3: left = the first
    /// `ceil_half`, the next entry promoted (removed from both sides),
    /// right = the remainder. `children`, non-empty only for an interior
    /// node, is one longer than `entries` and splits at the identical
    /// point (`ceil_half + 1` left, the rest right) -- see
    /// [`nav::children_of`]'s own convention.
    ///
    /// Returns `(left entries, left children, promoted, right entries,
    /// right children)`.
    ///
    /// # Panics
    ///
    /// If `entries.len() <= ceil_half` -- the caller only calls this on a
    /// node that has just overflowed past `ceil_half`.
    fn split_merged(
        ceil_half: usize,
        mut entries: Vec<pages::Entry>,
        mut children: Vec<u32>,
    ) -> (Vec<pages::Entry>, Vec<u32>, pages::Entry, Vec<pages::Entry>, Vec<u32>) {
        let right_entries = entries.split_off(ceil_half + 1);
        let promoted = entries.pop().expect("caller only splits an overflowed node");
        let left_entries = entries;
        let (left_children, right_children) = if children.is_empty() {
            (Vec::new(), Vec::new())
        } else {
            let right_children = children.split_off(ceil_half + 1);
            (children, right_children)
        };
        (left_entries, left_children, promoted, right_entries, right_children)
    }

    /// Claim a fresh logical id for `image`, reclaiming the B-tree page
    /// free list's own head first when it is non-empty rather than growing
    /// the file -- this crate's own resolution of the split rules' open
    /// "preference among multiple simultaneously-vacated candidates"
    /// question (§8): LIFO, the most-recently-retired page reclaimed
    /// first, per the `retired-page-reclaim-order` recording (two
    /// retirements, chain `12 -> 10`, reclaimed back in that same order --
    /// see `docs/btrieve-unproven.md` §6.1.3). Three or more candidates on
    /// the list at once, and a reclaim separated from its own retirement
    /// by intervening writes, are still unrecorded; this stack-shaped
    /// implementation is indifferent to either, but that is extrapolation,
    /// not measurement -- named in the same place. Falls back to
    /// [`v6::Map::claim`] (mechanism 1, marker-zero) only once the free
    /// list is empty.
    ///
    /// Returns `(the id claimed or reclaimed, the free list's head as this
    /// call leaves it)`.
    ///
    /// # Errors
    ///
    /// If the free list's head names a page the allocation table does not
    /// claim, or if the underlying claim/reclaim fails.
    fn v6_claim_or_reclaim(
        &self,
        store: &mut v6::Store,
        page_size: u16,
        image: &[u8],
        tag: [u8; 2],
        free_head: u32,
    ) -> Result<(u32, u32), String> {
        if free_head == pages::NOWHERE {
            let logical = v6::Map::claim(store, page_size, image, tag)?;
            return Ok((logical, free_head));
        }
        let next = {
            let physical = v6::Map::read(store, page_size)?.physical(free_head).ok_or_else(|| {
                format!(
                    "the B-tree free list names logical {free_head}, which the \
                     allocation table claims no physical page for"
                )
            })?;
            let body = store.page(physical as usize)?;
            pages::long(&body[8..12])
        };
        v6::Map::reclaim(store, page_size, free_head, image, tag)?;
        Ok((free_head, next))
    }

    /// Commit one split's two halves and answer with what the level above
    /// must absorb: RIGHT always keeps `old_logical`'s own identity, LEFT
    /// always claims (or reclaims) a fresh one -- split rules §2, "the
    /// opposite of the naive 'left keeps identity' default".
    ///
    /// Returns `(the promoted entry, left's own decorated pointer, the
    /// free list's head as this call leaves it)`.
    ///
    /// # Errors
    ///
    /// If claiming, reclaiming or relocating either half fails.
    #[allow(clippy::too_many_arguments)]
    fn v6_place_split(
        &self,
        store: &mut v6::Store,
        layout: pages::Layout,
        shape: pages::Shape,
        tag: [u8; 2],
        ceil_half: usize,
        entries: Vec<pages::Entry>,
        children: Vec<u32>,
        old_logical: u32,
        old_stamp: u16,
        free_head: u32,
    ) -> Result<(pages::Entry, u32, u32), String> {
        let page_size = self.geometry.page;
        let (left_entries, left_children, promoted, right_entries, right_children) =
            Self::split_merged(ceil_half, entries, children);

        // A newly-claimed (or reclaimed) id starts its stamp at 0 --
        // split rules §10.
        let left_image = pages::encode_v6_index_page(layout, shape, 0, &left_entries, &left_children);
        let (left_logical, new_free_head) =
            self.v6_claim_or_reclaim(store, page_size, &left_image, tag, free_head)?;

        let right_image =
            pages::encode_v6_index_page(layout, shape, old_stamp.wrapping_add(1), &right_entries, &right_children);
        v6::Map::relocate(store, page_size, old_logical, &right_image, tag)?;

        Ok((promoted, Self::v6_decorate(left_logical, tag), new_free_head))
    }

    /// Apply one or more `[prev][next]` duplicate-chain field edits to
    /// member records' own slots -- shared by every place this engine's
    /// insert/delete paths thread a chain link, batched by logical page so
    /// two edits landing on the same physical page cost one relocate, not
    /// two.
    ///
    /// Each edit is `(position, new_prev, new_next)`; `None` leaves that
    /// half of the pair exactly as it already reads (a middle-of-chain
    /// relink only ever touches one half of each of its two neighbours).
    ///
    /// Resolves every logical page through `store` itself (`v6::Map::
    /// read(store, ...)`, not [`Self::v6_resolve_logical`]): a record this
    /// same op already relocated earlier (a new insert's own data page, or
    /// this same key's own leaf) has only been seen by `store` so far --
    /// [`Self::cache`] is not written through until the whole operation
    /// commits.
    ///
    /// # Errors
    ///
    /// If any position is not on a slot boundary, or its logical page is
    /// claimed by nothing.
    fn v6_write_chain_edits(
        &self,
        store: &mut v6::Store,
        layout: pages::Layout,
        offset: usize,
        edits: &[(u32, Option<u32>, Option<u32>)],
    ) -> Result<(), String> {
        let page_size = self.geometry.page;
        let mut per_logical: std::collections::BTreeMap<u32, Vec<(usize, Option<u32>, Option<u32>)>> =
            std::collections::BTreeMap::new();
        for &(position, prev, next) in edits {
            let (logical, slot) = layout
                .slot_of(position)
                .ok_or_else(|| format!("record position {position} is not on a slot boundary"))?;
            let within = layout.position(0, slot) as usize + offset;
            per_logical.entry(logical).or_default().push((within, prev, next));
        }
        for (logical, writes) in per_logical {
            let physical = v6::Map::read(store, page_size)?
                .physical(logical)
                .ok_or_else(|| format!("logical page {logical} is claimed by nothing"))?;
            let mut content = store.page(physical as usize)?.to_vec();
            for (within, prev, next) in writes {
                if let Some(p) = prev {
                    content[within..within + 4].copy_from_slice(&pages::to_long(p));
                }
                if let Some(n) = next {
                    content[within + 4..within + 8].copy_from_slice(&pages::to_long(n));
                }
            }
            v6::Map::relocate(store, page_size, logical, &content, [0x00, 0x44])?;
        }
        Ok(())
    }

    /// Thread a newly-inserted record onto an existing duplicate-value
    /// group's chain: the new record's own `[prev][next]` pair becomes
    /// `[old_tail, NOWHERE]`, and the old tail's own `next` half now names
    /// the new record. `head` never moves (`docs/2026-08-25-btree-split-
    /// rules.md` §1/§9) -- only these two records' own slots change, never
    /// the index.
    ///
    /// # Errors
    ///
    /// See [`Self::v6_write_chain_edits`].
    fn v6_write_dup_chain_extend(
        &self,
        store: &mut v6::Store,
        layout: pages::Layout,
        offset: usize,
        old_tail: u32,
        new_position: u32,
    ) -> Result<(), String> {
        self.v6_write_chain_edits(
            store,
            layout,
            offset,
            &[(new_position, Some(old_tail), Some(pages::NOWHERE)), (old_tail, None, Some(new_position))],
        )
    }

    /// Read one duplicate-chain member's own `[prev][next]` pair off its
    /// slot, resolved through `store` itself the same way
    /// [`Self::v6_write_chain_edits`] writes it.
    ///
    /// # Errors
    ///
    /// If `position` is not on a slot boundary, or its logical page is
    /// claimed by nothing.
    fn v6_read_chain_pair(
        &self,
        store: &mut v6::Store,
        layout: pages::Layout,
        offset: usize,
        position: u32,
    ) -> Result<(u32, u32), String> {
        let (logical, slot) = layout
            .slot_of(position)
            .ok_or_else(|| format!("record position {position} is not on a slot boundary"))?;
        let physical = v6::Map::read(store, self.geometry.page)?
            .physical(logical)
            .ok_or_else(|| format!("logical page {logical} is claimed by nothing"))?;
        let within = layout.position(0, slot) as usize + offset;
        let content = store.page(physical as usize)?;
        Ok((pages::long(&content[within..within + 4]), pages::long(&content[within + 4..within + 8])))
    }

    /// Insert `position` under `key`'s own extracted `value`, maintaining
    /// `key`'s B-tree incrementally instead of rebuilding it --
    /// `docs/2026-08-25-btree-split-rules.md` §1-§3. `free_head` is this
    /// whole op's own running B-tree free-list head, threaded across every
    /// key so a page one key's split reclaims is visible to the next key's
    /// own split in the same insert.
    ///
    /// # Returns
    ///
    /// `(key's new root if this write changed it, the free list's head as
    /// this call leaves it)`.
    ///
    /// # Errors
    ///
    /// If `key` has no tree yet, the descent or any relocate/claim/reclaim
    /// fails, or an exact match is found on a key whose shape carries no
    /// duplicate-chain tail (a genuinely new value should never exact-match
    /// at all).
    fn v6_tree_insert(
        &self,
        store: &mut v6::Store,
        cache: &std::cell::RefCell<cache::PageCache>,
        layout: pages::Layout,
        key: &keys::Key,
        fcr: &[u8],
        value: &[u8],
        position: u32,
        free_head: u32,
    ) -> Result<(Option<u32>, u32), BtvError> {
        let name = self.name.clone();
        let fail = |why: String| BtvError { file: name.clone(), why };
        let page_size = self.geometry.page;

        let Some((root, shape)) = self.v6_key_root(key, fcr).map_err(&fail)? else {
            return Err(fail(format!(
                "key {}: has no tree yet -- Task 6's incremental path only \
                 maintains an existing one",
                key.number
            )));
        };
        let tag = Self::v6_key_tag_bytes(key)?;
        let cmp = |a: &[u8], b: &[u8]| key.compare_extracted(a, b);
        let mut resolve = |logical: u32| self.v6_resolve_logical(logical);
        let located =
            nav::descend_for_write(cache, &mut resolve, root, shape, value, &cmp).map_err(&fail)?;

        if located.exact {
            // A duplicate-permitting key's already-present value: only the
            // tail advances (§1); head, and every other entry, untouched.
            let frame = located.path.last().expect("descend_for_write always returns at least one frame");
            if frame.page.tails.is_empty() {
                return Err(fail(format!(
                    "key {}: value already present in the tree, but this key's \
                     own shape carries no duplicate-chain tail column -- a \
                     genuinely new value should never exact-match",
                    key.number
                )));
            }
            let old_tail = frame.page.tails[located.at];
            let mut tails = frame.page.tails.clone();
            tails[located.at] = position;
            let entries = Self::entries_from_page(&frame.page, &tails);
            let children = nav::children_of(&frame.page);
            let stamp = frame.page.stamp.wrapping_add(1);
            let image = pages::encode_v6_index_page(layout, shape, stamp, &entries, &children);
            v6::Map::relocate(store, page_size, frame.logical, &image, tag).map_err(&fail)?;

            // The chain itself lives in the records, not the index (§0/§9):
            // the new record's own `[prev][next]` names the old tail and
            // `NOWHERE`, and the old tail's own `next` half now names the
            // new record. `head` never moves once a chain exists.
            let chain_offset = usize::from(key.chain.ok_or_else(|| {
                fail(format!(
                    "key {}: permits duplicates but names no chain offset",
                    key.number
                ))
            })?);
            self.v6_write_dup_chain_extend(store, layout, chain_offset, old_tail, position)
                .map_err(&fail)?;

            return Ok((None, free_head));
        }

        // Not an exact match: the last frame IS the leaf, `located.at` is
        // where the new entry belongs (positional, in the merged sorted
        // sequence -- §2's own "not an append fast path" finding).
        let leaf_idx = located.path.len() - 1;
        let leaf_logical = located.path[leaf_idx].logical;
        let leaf_stamp = located.path[leaf_idx].page.stamp;
        let mut entries =
            Self::entries_from_page(&located.path[leaf_idx].page, &located.path[leaf_idx].page.tails);
        entries.insert(located.at, pages::Entry { key: value.to_vec(), head: position, tail: position });

        let max_entries = shape.capacity(page_size);
        if entries.len() <= max_entries {
            // Leaf insert, no split (§1): this leaf's own stamp advances,
            // nothing above it is touched.
            let stamp = leaf_stamp.wrapping_add(1);
            let image = pages::encode_v6_index_page(layout, shape, stamp, &entries, &[]);
            v6::Map::relocate(store, page_size, leaf_logical, &image, tag).map_err(&fail)?;
            return Ok((None, free_head));
        }

        // Leaf split (§2), and possibly cascading interior splits (§3).
        let ceil_half = max_entries.div_ceil(2);
        let (mut promoted, mut left_decorated, mut free_head) = self
            .v6_place_split(store, layout, shape, tag, ceil_half, entries, Vec::new(), leaf_logical, leaf_stamp, free_head)
            .map_err(&fail)?;

        let mut carried_past_root = true;
        for level in (0..leaf_idx).rev() {
            let frame_logical = located.path[level].logical;
            let frame_stamp = located.path[level].page.stamp;
            let child_idx = located.path[level].descended_via;
            let mut entries =
                Self::entries_from_page(&located.path[level].page, &located.path[level].page.tails);
            let mut children = nav::children_of(&located.path[level].page);
            entries.insert(child_idx, promoted.clone());
            children.insert(child_idx, left_decorated);

            if entries.len() <= max_entries {
                let stamp = frame_stamp.wrapping_add(1);
                let image = pages::encode_v6_index_page(layout, shape, stamp, &entries, &children);
                v6::Map::relocate(store, page_size, frame_logical, &image, tag).map_err(&fail)?;
                carried_past_root = false;
                break;
            }

            let (p, l, f) = self
                .v6_place_split(store, layout, shape, tag, ceil_half, entries, children, frame_logical, frame_stamp, free_head)
                .map_err(&fail)?;
            promoted = p;
            left_decorated = l;
            free_head = f;
        }

        if !carried_past_root {
            return Ok((None, free_head));
        }

        // The split cascaded all the way up: a new root, one entry, the
        // old root demoted to an ordinary (right-hand) child -- §3.
        let root_entries = vec![promoted];
        let root_children = vec![left_decorated, root];
        let new_root_image = pages::encode_v6_index_page(layout, shape, 0, &root_entries, &root_children);
        let (new_root_logical, free_head) =
            self.v6_claim_or_reclaim(store, page_size, &new_root_image, tag, free_head).map_err(&fail)?;
        Ok((Some(Self::v6_decorate(new_root_logical, tag)), free_head))
    }

    /// Delete a key whose value lives only as a promoted interior separator
    /// -- `docs/2026-08-25-btree-split-rules.md`'s own open item, settled by
    /// the `interior-separator-delete` recording: replaced with its
    /// in-order PREDECESSOR (the left subtree's own maximum, pulled up
    /// from the leaf that held it), wholesale (key, head, and tail all
    /// move together, the same "genuine B-tree, never recomputed" fact §0
    /// already establishes for a promotion or a redistribute). The
    /// deleted separator's own record is freed by the ordinary data-page
    /// free-list code that already ran before `Block::delete_v6` reached
    /// this, unconditionally of B-tree shape -- nothing more to do for it
    /// here.
    ///
    /// Scoped to the recorded case: the predecessor's own leaf must not
    /// underflow when its maximum entry is removed (`>= half_entries`
    /// afterward, the only shape any recording exercises -- the fixture's
    /// own left leaf goes `21 -> 20`, landing exactly at `half_entries`,
    /// not under it). If it would underflow, this refuses by name rather
    /// than extending the merge/redistribute cascade into an interaction
    /// nothing measures: the cascade's own right-sibling-first check could
    /// reach the very separator being replaced (its right subtree is
    /// exactly the predecessor's own path's right sibling one level up),
    /// consuming it in a merge before this function gets to overwrite it.
    /// Successor preference (the right subtree's own minimum) under a
    /// missing/empty left subtree is equally unrecorded, named the same
    /// way per the coordinator's own phase-2 ruling -- this engine never
    /// builds an interior entry with no left child at all, so that shape
    /// cannot arise from this engine's own writes, only conceivably from a
    /// foreign file.
    ///
    /// # Errors
    ///
    /// If the predecessor's own removal would underflow its leaf, or the
    /// left-subtree descent/relocate itself fails.
    #[allow(clippy::too_many_arguments)]
    fn v6_delete_interior_separator(
        &self,
        store: &mut v6::Store,
        cache: &std::cell::RefCell<cache::PageCache>,
        layout: pages::Layout,
        key: &keys::Key,
        shape: pages::Shape,
        tag: [u8; 2],
        key_tag_byte: u8,
        located: &nav::Located,
        free_head: u32,
    ) -> Result<(Option<u32>, u32), BtvError> {
        let name = self.name.clone();
        let fail = |why: String| BtvError { file: name.clone(), why };
        let page_size = self.geometry.page;
        let max_entries = shape.capacity(page_size);
        let half_entries = max_entries / 2;

        let sep_level = located.path.len() - 1;
        let sep_frame = &located.path[sep_level];
        let mut resolve = |logical: u32| self.v6_resolve_logical(logical);

        // Rightmost descent from the separator's own left child -- the
        // left subtree's own maximum, wherever it bottoms out.
        let mut pending = nav::children_of(&sep_frame.page)[located.at];
        let (pred_logical, pred_page) = loop {
            let page = nav::fetch_one(cache, &mut resolve, shape, key_tag_byte, pending).map_err(&fail)?;
            let logical = pending & pages::fcr::ROOT_PAGE;
            if page.leaf() {
                break (logical, page);
            }
            pending = page.rightmost;
        };

        let mut pred_entries = Self::entries_from_page(&pred_page, &pred_page.tails);
        let predecessor = pred_entries
            .pop()
            .expect("a real B-tree leaf on the predecessor path has at least one entry");
        if pred_entries.len() < half_entries {
            return Err(fail(format!(
                "key {}: the in-order predecessor's own leaf would underflow \
                 ({} entries, half_entries {half_entries}) if its maximum entry \
                 is removed -- no recording exercises an interior-separator \
                 delete whose predecessor removal cascades, so this refuses \
                 rather than guessing how the cascade interacts with the \
                 separator being replaced",
                key.number,
                pred_entries.len()
            )));
        }
        let pred_stamp = pred_page.stamp.wrapping_add(1);
        let pred_image = pages::encode_v6_index_page(layout, shape, pred_stamp, &pred_entries, &[]);
        v6::Map::relocate(store, page_size, pred_logical, &pred_image, tag).map_err(&fail)?;

        let mut sep_entries = Self::entries_from_page(&sep_frame.page, &sep_frame.page.tails);
        sep_entries[located.at] = predecessor;
        let sep_children = nav::children_of(&sep_frame.page);
        let sep_stamp = sep_frame.page.stamp.wrapping_add(1);
        let sep_image = pages::encode_v6_index_page(layout, shape, sep_stamp, &sep_entries, &sep_children);
        v6::Map::relocate(store, page_size, sep_frame.logical, &sep_image, tag).map_err(&fail)?;

        Ok((None, free_head))
    }

    /// Delete `position` (whose value under `key` is `value`) from `key`'s
    /// B-tree incrementally, per `docs/2026-08-25-btree-split-rules.md`
    /// §4-§8: no underflow leaves the touched leaf's own stamp advanced and
    /// nothing else touched; an underflow redistributes with or merges
    /// into a sibling (donor-slack is the sole discriminator, §6), possibly
    /// cascading into the parent (never past the root -- see Errors).
    /// A value found only as an interior separator delegates to
    /// [`Self::v6_delete_interior_separator`]; one member of an active
    /// duplicate-value group is pure chain surgery (see the `head != tail`
    /// branch below), never touching the B-tree at all except when the
    /// removed member is the group's own head or tail.
    ///
    /// `own_chain` is `position`'s own `[prev][next]` pair, read *before*
    /// a caller that already zeroed and relocated `position`'s slot did so
    /// ([`Self::delete_v6`]'s unconditional pre-write free -- by the time
    /// this runs, [`Self::v6_read_chain_pair`] would read back zeros, not
    /// the chain this delete needs to splice around). `None` says the slot
    /// is still intact and this reads it fresh instead ([`Self::update_v6`]'s
    /// delete-then-insert composition never touches the chain bytes, only
    /// the record body ahead of them, so its own call always passes `None`).
    ///
    /// # Returns
    ///
    /// `(key's new root if this write changed it, the free list's head as
    /// this call leaves it)`.
    ///
    /// # Errors
    ///
    /// Refusals this task's own rulings require, named with their
    /// predicate rather than silently guessed at: **a node with neither a
    /// left nor a right sibling** at its own level (an unexpected tree
    /// shape -- a well-formed tree never reaches this, so this is a
    /// foreign file's own problem, not this engine's); and **an underflow
    /// deeper than `half_entries - 1`** (every recorded crossing lands
    /// exactly there). Multi-level root collapse (an interior root losing
    /// its own last entry to a cascade, the surviving child becoming the
    /// new root) is no longer refused -- round 5's own recording measured
    /// it, see the `level == 0` branch below. Also if `key` has no tree,
    /// the value is not
    /// found at all (a model/tree disagreement), or any relocate/retire/
    /// reclaim fails.
    #[allow(clippy::too_many_lines)]
    fn v6_tree_delete(
        &self,
        store: &mut v6::Store,
        cache: &std::cell::RefCell<cache::PageCache>,
        layout: pages::Layout,
        key: &keys::Key,
        fcr: &[u8],
        value: &[u8],
        position: u32,
        free_head: u32,
        own_chain: Option<(u32, u32)>,
    ) -> Result<(Option<u32>, u32), BtvError> {
        let name = self.name.clone();
        let fail = |why: String| BtvError { file: name.clone(), why };
        let page_size = self.geometry.page;

        let Some((root, shape)) = self.v6_key_root(key, fcr).map_err(&fail)? else {
            return Err(fail(format!("key {}: has no tree to delete from", key.number)));
        };
        let key_tag_byte = (root >> 24) as u8;
        let tag = Self::v6_key_tag_bytes(key)?;
        let cmp = |a: &[u8], b: &[u8]| key.compare_extracted(a, b);
        let mut resolve = |logical: u32| self.v6_resolve_logical(logical);
        let located =
            nav::descend_for_write(cache, &mut resolve, root, shape, value, &cmp).map_err(&fail)?;

        if !located.exact {
            return Err(fail(format!(
                "key {}: value not found in the tree at all -- the in-memory \
                 model and the on-disk tree disagree",
                key.number
            )));
        }
        let leaf_idx = located.path.len() - 1;
        let frame = &located.path[leaf_idx];
        if !frame.page.leaf() {
            return self.v6_delete_interior_separator(
                store,
                cache,
                layout,
                key,
                shape,
                tag,
                key_tag_byte,
                &located,
                free_head,
            );
        }
        let head = frame.page.entries[located.at].1;
        let tail = frame.page.tails.get(located.at).copied().unwrap_or(head);
        if head != tail {
            // An active 2+-member duplicate chain: pure chain surgery
            // (`dup-chain-partial-delete`, recorded round 2). The deleted
            // member's own (still-live-at-this-point) `[prev][next]` names
            // its neighbours; only the head or tail deletion ever touches
            // the leaf entry at all, and only its own head/tail field --
            // no split, no underflow, both unreachable since the entry
            // count never changes. A middle deletion touches no index
            // page whatsoever, only its two neighbours' own chain fields.
            let chain_offset = usize::from(key.chain.ok_or_else(|| {
                fail(format!("key {}: permits duplicates but names no chain offset", key.number))
            })?);
            let (prev, next) = match own_chain {
                Some(pair) => pair,
                None => {
                    self.v6_read_chain_pair(store, layout, chain_offset, position).map_err(&fail)?
                }
            };

            if position == head {
                let mut entries = Self::entries_from_page(&frame.page, &frame.page.tails);
                entries[located.at].head = next;
                let children = nav::children_of(&frame.page);
                let stamp = frame.page.stamp.wrapping_add(1);
                let image = pages::encode_v6_index_page(layout, shape, stamp, &entries, &children);
                v6::Map::relocate(store, page_size, frame.logical, &image, tag).map_err(&fail)?;
                self.v6_write_chain_edits(store, layout, chain_offset, &[(next, Some(pages::NOWHERE), None)])
                    .map_err(&fail)?;
                return Ok((None, free_head));
            }
            if position == tail {
                let mut entries = Self::entries_from_page(&frame.page, &frame.page.tails);
                entries[located.at].tail = prev;
                let children = nav::children_of(&frame.page);
                let stamp = frame.page.stamp.wrapping_add(1);
                let image = pages::encode_v6_index_page(layout, shape, stamp, &entries, &children);
                v6::Map::relocate(store, page_size, frame.logical, &image, tag).map_err(&fail)?;
                self.v6_write_chain_edits(store, layout, chain_offset, &[(prev, None, Some(pages::NOWHERE))])
                    .map_err(&fail)?;
                return Ok((None, free_head));
            }
            // A middle member: relink the two neighbours directly, the
            // leaf entry itself untouched.
            self.v6_write_chain_edits(
                store,
                layout,
                chain_offset,
                &[(prev, None, Some(next)), (next, Some(prev), None)],
            )
            .map_err(&fail)?;
            return Ok((None, free_head));
        }
        if head != position {
            return Err(fail(format!(
                "key {}: the located entry's own record ({head}) does not match \
                 the position being deleted ({position})",
                key.number
            )));
        }

        let max_entries = shape.capacity(page_size);
        let half_entries = max_entries / 2;

        let mut cur_entries = Self::entries_from_page(&frame.page, &frame.page.tails);
        cur_entries.remove(located.at);
        let mut cur_children: Vec<u32> = Vec::new();
        let mut cur_logical = frame.logical;
        let mut cur_stamp = frame.page.stamp;
        let mut free_head = free_head;

        let mut level = leaf_idx;
        loop {
            // The root is never subject to the half_entries floor at all --
            // it has no sibling to redistribute or merge with, which is
            // exactly why genuine Btrieve's own underflow trigger (§5) is
            // never observed to fire there.
            if level == 0 {
                if cur_entries.is_empty() {
                    if cur_children.is_empty() {
                        // Deleting a key's last remaining record (the root
                        // IS the leaf, no children at all) -- genuine
                        // Btrieve allows this (status OK,
                        // `delete-to-empty/manifest.txt`): the emptied root
                        // reverts to the exact virgin-file shape, not a
                        // distinct "emptied" state -- `leftmost = 0`
                        // (**not** NOWHERE, the one field
                        // `encode_v6_index_page`'s ordinary leaf case does
                        // not produce), `rightmost = NOWHERE`, `entries =
                        // 0`. Same logical id, same stamp-then-relocate
                        // discipline as any other rewrite; nothing retires
                        // and nothing new claims.
                        let stamp = cur_stamp.wrapping_add(1);
                        let mut image =
                            pages::encode_v6_index_page(layout, shape, stamp, &cur_entries, &cur_children);
                        image[12..16].copy_from_slice(&pages::to_long(0));
                        v6::Map::relocate(store, page_size, cur_logical, &image, tag).map_err(&fail)?;
                        return Ok((None, free_head));
                    }
                    // An interior root (children.len() > 1 before this)
                    // that lost its own last entry to a merge cascading
                    // from below -- the tree drops a level. Round 5's own
                    // recording (`root-level-collapse`): the ONE surviving
                    // child (an interior node has exactly `entries.len() +
                    // 1` children, so exactly one remains once `entries` is
                    // empty) becomes the new root DIRECTLY -- the FCR's own
                    // root pointer moves to that child's own decorated
                    // logical id, never a content copy into the old root's
                    // id. `cur_children[0]` is already that decorated
                    // pointer (read straight off the surviving page's own
                    // `leftmost`/`rightmost` field, the same convention
                    // every other sibling lookup in this cascade uses), so
                    // it is returned as-is. The vacated root retires into
                    // the same `0x4500` free list a leaf uses, chained
                    // after whatever this same delete already retired --
                    // this op's own last retiree becomes the list's new
                    // head, exactly the LIFO discipline every other retire
                    // in this engine follows.
                    let new_root = cur_children[0];
                    v6::Map::retire(store, page_size, cur_logical, free_head).map_err(&fail)?;
                    free_head = cur_logical;
                    return Ok((Some(new_root), free_head));
                }
                let stamp = cur_stamp.wrapping_add(1);
                let image = pages::encode_v6_index_page(layout, shape, stamp, &cur_entries, &cur_children);
                v6::Map::relocate(store, page_size, cur_logical, &image, tag).map_err(&fail)?;
                return Ok((None, free_head));
            }

            if cur_entries.len() >= half_entries {
                let stamp = cur_stamp.wrapping_add(1);
                let image = pages::encode_v6_index_page(layout, shape, stamp, &cur_entries, &cur_children);
                v6::Map::relocate(store, page_size, cur_logical, &image, tag).map_err(&fail)?;
                return Ok((None, free_head));
            }

            // Every recorded underflow crosses at exactly `half_entries - 1`,
            // the first-crossing value (split rules §5's own citation); a
            // node found already deeper than that -- more than one entry
            // below `half_entries` -- was never measured, "sub-half_entries
            // underflow depth paired with a large donor" in the rules doc's
            // own "out of scope" list. This engine's own writes never
            // produce that shape (every merge/redistribute here lands
            // exactly at the first crossing too), but a file this engine did
            // not build -- a foreign real-Btrieve file, which owes this
            // engine's own invariants nothing -- can arrive already in it,
            // and extrapolating the redistribute/merge predicate onto a
            // depth nothing observed would be exactly the guess this task's
            // rulings forbid.
            let first_crossing = half_entries.saturating_sub(1);
            if cur_entries.len() < first_crossing {
                return Err(fail(format!(
                    "key {}: this node has {} entries, more than one below \
                     half_entries ({half_entries}) -- every recorded underflow \
                     crossed at exactly half_entries - 1 ({first_crossing}), and \
                     a deeper one was never measured (docs/2026-08-25-btree-\
                     split-rules.md's own 'out of scope' list) -- refusing \
                     rather than guessing at the redistribute/merge predicate \
                     for a depth nothing observed",
                    key.number,
                    cur_entries.len()
                )));
            }

            let parent_level = level - 1;
            let child_idx = located.path[parent_level].descended_via;
            let mut parent_entries =
                Self::entries_from_page(&located.path[parent_level].page, &located.path[parent_level].page.tails);
            let mut parent_children = nav::children_of(&located.path[parent_level].page);

            let has_right = child_idx + 1 < parent_children.len();
            let has_left = child_idx > 0;

            let (side, sibling_decorated, separator_idx) = if has_right {
                (Side::Right, parent_children[child_idx + 1], child_idx)
            } else if has_left {
                (Side::Left, parent_children[child_idx - 1], child_idx - 1)
            } else {
                return Err(fail(format!(
                    "key {}: the node at tree level {level} has neither a left \
                     nor a right sibling to redistribute or merge with -- an \
                     unexpected tree shape",
                    key.number
                )));
            };

            let sibling_page =
                nav::fetch_one(cache, &mut resolve, shape, key_tag_byte, sibling_decorated).map_err(&fail)?;
            let sibling_logical = sibling_decorated & pages::fcr::ROOT_PAGE;
            let mut sibling_entries = Self::entries_from_page(&sibling_page, &sibling_page.tails);
            let mut sibling_children = nav::children_of(&sibling_page);

            if sibling_entries.len() > half_entries {
                // REDISTRIBUTE (§7): the parent's separator moves down as
                // this node's new extreme entry; the donor's own nearest
                // extreme entry moves up, wholesale, to replace it. The
                // parent's own entry COUNT is unchanged, so this cannot
                // cascade any further -- write all three and stop.
                let old_separator = parent_entries[separator_idx].clone();
                let new_separator = match side {
                    Side::Right => {
                        let donor_first = sibling_entries.remove(0);
                        let moved = (!sibling_children.is_empty()).then(|| sibling_children.remove(0));
                        cur_entries.push(old_separator);
                        if let Some(child) = moved {
                            cur_children.push(child);
                        }
                        donor_first
                    }
                    Side::Left => {
                        let donor_last = sibling_entries.pop().expect("more than half_entries entries");
                        let moved = if sibling_children.is_empty() {
                            None
                        } else {
                            Some(sibling_children.pop().expect("children.len() == entries.len() + 1"))
                        };
                        cur_entries.insert(0, old_separator);
                        if let Some(child) = moved {
                            cur_children.insert(0, child);
                        }
                        donor_last
                    }
                };
                parent_entries[separator_idx] = new_separator;

                let cur_stamp_new = cur_stamp.wrapping_add(1);
                let cur_image = pages::encode_v6_index_page(layout, shape, cur_stamp_new, &cur_entries, &cur_children);
                v6::Map::relocate(store, page_size, cur_logical, &cur_image, tag).map_err(&fail)?;

                let sibling_stamp_new = sibling_page.stamp.wrapping_add(1);
                let sibling_image =
                    pages::encode_v6_index_page(layout, shape, sibling_stamp_new, &sibling_entries, &sibling_children);
                v6::Map::relocate(store, page_size, sibling_logical, &sibling_image, tag).map_err(&fail)?;

                let parent_stamp_new = located.path[parent_level].page.stamp.wrapping_add(1);
                let parent_image =
                    pages::encode_v6_index_page(layout, shape, parent_stamp_new, &parent_entries, &parent_children);
                v6::Map::relocate(store, page_size, located.path[parent_level].logical, &parent_image, tag)
                    .map_err(&fail)?;

                return Ok((None, free_head));
            }

            // MERGE (§6): the underflowing node's surviving entries, the
            // separator pulled down as a real entry (§0/§6), and the
            // sibling's own entries -- concatenated in key order, whichever
            // side survives keeps its OWN id, the other retires.
            let separator = parent_entries.remove(separator_idx);
            parent_children.remove(child_idx);

            let (survivor_logical, survivor_stamp, retired_logical, new_entries, new_children) = match side {
                Side::Right => {
                    let mut entries = std::mem::take(&mut cur_entries);
                    entries.push(separator);
                    entries.extend(sibling_entries);
                    let mut children = std::mem::take(&mut cur_children);
                    children.extend(sibling_children);
                    (sibling_logical, sibling_page.stamp, cur_logical, entries, children)
                }
                Side::Left => {
                    let mut entries = sibling_entries;
                    entries.push(separator);
                    entries.extend(std::mem::take(&mut cur_entries));
                    let mut children = sibling_children;
                    children.extend(std::mem::take(&mut cur_children));
                    (sibling_logical, sibling_page.stamp, cur_logical, entries, children)
                }
            };

            let survivor_image = pages::encode_v6_index_page(
                layout,
                shape,
                survivor_stamp.wrapping_add(1),
                &new_entries,
                &new_children,
            );
            v6::Map::relocate(store, page_size, survivor_logical, &survivor_image, tag).map_err(&fail)?;
            v6::Map::retire(store, page_size, retired_logical, free_head).map_err(&fail)?;
            free_head = retired_logical;

            // The parent just lost one entry and one child -- continue the
            // loop one level up, checking whether IT now underflows.
            cur_entries = parent_entries;
            cur_children = parent_children;
            cur_logical = located.path[parent_level].logical;
            cur_stamp = located.path[parent_level].page.stamp;
            level = parent_level;
        }
    }

    /// A key-changing update's fast path: when the old and new values both
    /// belong to the SAME leaf, swapping one entry for another leaves the
    /// entry count unchanged -- no split, no underflow, nothing above the
    /// leaf touched, one relocate. `None` when they do not, so the caller
    /// falls back to [`Self::v6_tree_delete`] + [`Self::v6_tree_insert`]'s
    /// general composition.
    ///
    /// Both descents run against the tree as this call found it -- neither
    /// touches a page before the other completes -- so "same leaf" here is
    /// exactly "these two entries could be swapped in place", not an
    /// approximation.
    ///
    /// # Returns
    ///
    /// `Some((None, free_head))` if the fast path applied (a same-count
    /// swap never moves a root); `Ok(None)` to mean "try the general path
    /// instead", not a written no-op.
    ///
    /// # Errors
    ///
    /// If `key` has no tree, or the descent/relocate fails once this
    /// function has already committed to the fast path.
    fn v6_tree_update_key_same_leaf(
        &self,
        store: &mut v6::Store,
        cache: &std::cell::RefCell<cache::PageCache>,
        layout: pages::Layout,
        key: &keys::Key,
        fcr: &[u8],
        old_value: &[u8],
        new_value: &[u8],
        position: u32,
    ) -> Result<Option<()>, BtvError> {
        let name = self.name.clone();
        let fail = |why: String| BtvError { file: name.clone(), why };
        let page_size = self.geometry.page;

        let Some((root, shape)) = self.v6_key_root(key, fcr).map_err(&fail)? else {
            return Ok(None);
        };
        let tag = Self::v6_key_tag_bytes(key)?;
        let cmp = |a: &[u8], b: &[u8]| key.compare_extracted(a, b);
        let mut resolve = |logical: u32| self.v6_resolve_logical(logical);

        let old_located =
            nav::descend_for_write(cache, &mut resolve, root, shape, old_value, &cmp).map_err(&fail)?;
        if !old_located.exact {
            return Ok(None);
        }
        let old_frame = old_located.path.last().expect("descend_for_write always returns at least one frame");
        if !old_frame.page.leaf() {
            return Ok(None);
        }
        let head = old_frame.page.entries[old_located.at].1;
        let tail = old_frame.page.tails.get(old_located.at).copied().unwrap_or(head);
        if head != tail || head != position {
            return Ok(None);
        }

        let new_located =
            nav::descend_for_write(cache, &mut resolve, root, shape, new_value, &cmp).map_err(&fail)?;
        let new_frame = new_located.path.last().expect("descend_for_write always returns at least one frame");
        if new_frame.logical != old_frame.logical || new_located.exact {
            // A different leaf, or the new value already has an entry of
            // its own (a duplicate group to extend, or a collision on a
            // unique key) -- either way, not this fast path's job.
            return Ok(None);
        }

        let mut entries = Self::entries_from_page(&old_frame.page, &old_frame.page.tails);
        entries.remove(old_located.at);
        // Re-found within the now-one-shorter list rather than adjusted
        // arithmetically from `new_located.at` (computed against the
        // pre-removal page) -- simpler, and just as cheap on one page.
        let insert_at = entries.partition_point(|e| cmp(&e.key, new_value) == std::cmp::Ordering::Less);
        entries.insert(insert_at, pages::Entry { key: new_value.to_vec(), head: position, tail: position });

        let stamp = old_frame.page.stamp.wrapping_add(1);
        let image = pages::encode_v6_index_page(layout, shape, stamp, &entries, &[]);
        v6::Map::relocate(store, page_size, old_frame.logical, &image, tag).map_err(&fail)?;

        Ok(Some(()))
    }

    /// A logical id as a v6 index page names it: the key's own tag byte in
    /// the top eight bits, the id in the low twenty-four.
    ///
    /// Measured against genuine Btrieve 6.15 (`crtprobe.exe`, 2026-08-17) on a
    /// two-key file: key 1's root page reads `0x8100000b` in its own header
    /// and every child pointer inside it reads `0x81......`. Key 0's read
    /// `0x80......`. The same encoding the file control record's `KEY_ROOT`
    /// field uses ([`pages::fcr::ROOT_PAGE`]), which is why the mask is 24
    /// bits and not 31.
    fn v6_decorate(logical: u32, tag: [u8; 2]) -> u32 {
        (u32::from(tag[1]) << 24) | (logical & pages::fcr::ROOT_PAGE)
    }

    /// The logical ids a key's index tree occupies today, **root first**, in
    /// the order [`pages::number_pages`] hands page numbers out.
    ///
    /// v6's counterpart to the `pages::walk` call v5's [`Self::reindex`] makes,
    /// and deliberately the *same traversal*: [`pages::walk_with`] does the
    /// walking and this supplies only the one thing that differs, which is what
    /// a child slot's number means. A v5 slot names a physical page; a v6 slot
    /// names a logical id with the key's tag byte on top, resolved through the
    /// `"PP"` allocation table. Writing a second traversal here would be one
    /// more thing that could fall out of step with `number_pages`, and the
    /// symptom of that is a rebuild silently moving every node to a different
    /// page instead of being a no-op.
    ///
    /// # Errors
    ///
    /// If the allocation table cannot be read, if a child slot carries some
    /// other key's tag byte, if an id the tree names is claimed by nothing, or
    /// if any page of the tree does not decode.
    ///
    /// Unreferenced now that the per-op write path no longer calls
    /// [`Self::v6_reindex`] (Task 6) -- kept for the same reason that
    /// function is.
    #[allow(dead_code)]
    fn v6_index_logicals(
        store: &mut v6::Store,
        page_size: u16,
        root: u32,
        tag: [u8; 2],
        shape: pages::Shape,
    ) -> Result<Vec<u32>, String> {
        let map = v6::Map::read(store, page_size)?;
        let walked = pages::walk_with(Self::v6_decorate(root, tag), shape, |number| {
            let top = (number >> 24) as u8;
            if top != tag[1] {
                return Err(format!(
                    "a child slot reads {number:#010x}, whose top byte {top:#04x} is                      not this key's {:#04x} -- the page it names belongs to another                      key's tree",
                    tag[1]
                ));
            }
            let logical = number & pages::fcr::ROOT_PAGE;
            let physical = map.physical(logical).ok_or_else(|| {
                format!("logical page {logical} is claimed by nothing")
            })? as usize;
            store
                .page(physical)
                .map(<[u8]>::to_vec)
                .map_err(|why| format!("logical page {logical} resolves to physical {physical}: {why}"))
        })?;
        Ok(walked
            .pages
            .into_iter()
            .map(|number| number & pages::fcr::ROOT_PAGE)
            .collect())
    }

    /// Unreferenced by any per-op write path now that [`Self::insert_v6`]/
    /// [`Self::update_v6`]/[`Self::delete_v6`] maintain each key's B-tree
    /// incrementally instead (Task 6) -- kept, not deleted, for a future
    /// create/repair/close-time caller that still wants a from-scratch
    /// rebuild, per this task's own brief.
    #[allow(dead_code)]
    fn v6_reindex(
        &self,
        store: &mut v6::Store,
        records: &Records,
        fcr: &[u8],
        layout: pages::Layout,
    ) -> Result<Vec<(usize, u32)>, String> {
        let page_size = self.geometry.page;
        let shift = records.key_shift();

        struct Rebuilt {
            root: u32,
            /// The rebuilt tree, still unplaced: [`pages::number_pages`] turns
            /// it into images once every node has a logical id.
            index: pages::Built,
            /// The logical ids the key's tree occupies **today**, root first,
            /// in exactly the order [`pages::number_pages`] hands numbers out.
            ///
            /// Reused rather than re-claimed, for the same reason v5's
            /// `Block::reindex` feeds `pages::walk`'s output back in: a rebuild
            /// that claimed fresh ids would leak one allocation-table slot per
            /// node per write, and a file whose index is a hundred pages would
            /// exhaust the table in a few hundred inserts.
            existing: Vec<u32>,
            count_at: usize,
            count: u32,
            /// The two-byte page type an index page of *this* key carries:
            /// `0x8000` for key 0, `0x8100` for key 1, and so on.
            ///
            /// Measured against genuine Btrieve 6.15 (`crtprobe.exe`,
            /// 2026-08-17): a two-key v6 file with 120 records gives key 1 a
            /// root whose page opens `00 81`, and every child pointer inside
            /// it reads `0x81......`. The key's number is in the top byte of
            /// the pointer *and* in the page's own tag -- the same byte
            /// `pages::fcr::ROOT_PAGE`'s doc comment already establishes for
            /// the file control record's `KEY_ROOT` field.
            ///
            /// This used to be a hardcoded `[0x00, 0x80]`, which tagged every
            /// key's index pages as key 0's. It went unnoticed because
            /// `v6::Map::relocate` rewrites only the *page number* half of an
            /// allocation-table entry and leaves the marker alone, so the
            /// table kept saying `0x8100` while the page it named said
            /// `0x8000`. Measured on `WGSGEN2.DAT` after one boot: key 1's
            /// root page carried `0x8000` where the virgin file the engine
            /// wrote carries `0x8100`.
            tag: [u8; 2],
        }
        let mut built: Vec<Rebuilt> = Vec::with_capacity(self.keys.len());

        // Every duplicate-permitting key's chain offset and its groups,
        // collected while the indexes are built and written once at the end.
        // Written last because each write relocates a *data* page, and doing
        // that while the index roots are still being placed would interleave
        // two page-relocation sequences for no reason.
        let mut chains: Vec<(usize, Vec<Vec<u32>>)> = Vec::new();

        for key in &self.keys {
            let len = records.ordered_len(key.number).ok_or_else(|| {
                format!(
                    "key {}: not among the keys the loaded records were ordered by",
                    key.number
                )
            })?;
            // One entry per distinct *value*, not per record: records sharing
            // a value join the entry before them and move its `tail`, which
            // is the four extra bytes `Key::shape` reserves for a
            // duplicate-permitting key. Genuine 6.15 writes exactly this --
            // three records under key 7 produced one entry reading head 1030,
            // tail 1102 (`docs/2026-08-17-v6-duplicate-key-oracle.md`).
            //
            // The same shape as `Self::reindex`'s v5 loop, deliberately: the
            // grouping is a property of the format, and the two differ only
            // in how the chain is then written to disk.
            let mut entries: Vec<pages::Entry> = Vec::with_capacity(len);
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
                    entries.last_mut().expect("a group to join").tail = record.position;
                    groups.last_mut().expect("a group to join").push(record.position);
                } else {
                    entries.push(pages::Entry::unique(
                        key.extract(&records::keyed(shift, &record.bytes)),
                        record.position,
                    ));
                    groups.push(vec![record.position]);
                }
            }
            if key.duplicates {
                let offset = usize::from(key.chain.ok_or_else(|| {
                    format!(
                        "key {}: permits duplicate values but names no chain offset, \
                         so it repeats its key in the index instead (attribute \
                         1<<7) -- this host reads such a file and does not write \
                         one, because there is no in-record pair to maintain and \
                         writing one at offset 0 would land on the record itself",
                        key.number
                    )
                })?);
                chains.push((offset, groups));
            }

            let index = pages::build_index(layout, &entries, key.shape())
                .map_err(|why| format!("key {}: {why}", key.number))?;

            let definition = pages::fcr::KEYS + usize::from(key.definition) * pages::fcr::KEY_WIDTH;
            let root_at = definition + pages::fcr::KEY_ROOT;
            let raw_root = pages::long(&fcr[root_at..root_at + 4]);
            if raw_root & 0x8000_0000 == 0 {
                return Err(format!(
                    "key {}: root {raw_root:#x} does not carry the v6 marker \
                     bit (0x80000000) this host's own measurement found on \
                     every v6 key it has seen -- refusing rather than \
                     guessing at a shape nothing has measured",
                    key.number
                ));
            }

            let tag_high = 0x80u8
                .checked_add(u8::try_from(key.number).map_err(|_| {
                    format!("key {}: does not fit a page tag's low byte", key.number)
                })?)
                .ok_or_else(|| {
                    format!(
                        "key {}: a page tag's high byte is 0x80 plus the key's \
                         own number, and this key's number does not fit",
                        key.number
                    )
                })?;
            let root = raw_root & pages::fcr::ROOT_PAGE;
            let tag = [0x00, tag_high];
            let existing = Self::v6_index_logicals(store, page_size, root, tag, key.shape())
                .map_err(|why| format!("key {}: walking its current index: {why}", key.number))?;
            built.push(Rebuilt {
                root,
                index,
                existing,
                count_at: definition + pages::fcr::KEY_RECORDS,
                count: u32::try_from(len).expect("far fewer records than u32::MAX"),
                tag,
            });
        }

        // Every key's index built. Now, and only now, anything is written.
        //
        // Claiming a page is itself a write, so it happens here rather than in
        // the loop above: a key that cannot be indexed at all must refuse
        // before the file has been touched, not after two of its siblings have
        // already been placed.
        // [`v6::Map::read`] walks every allocation-table block in the file,
        // and this loop used to ask for one per index node -- 109 walks for a
        // single-record update on a 13,713-page `WCCMP002.DAT`, almost all of
        // them answering a question nothing had changed since. The map only
        // goes stale when a page actually moves, so it is re-read after a
        // `claim` or a `relocate` and not otherwise. Lazily, at the point of
        // use, so the last relocate of a write does not pay for a walk whose
        // answer is then thrown away.
        let mut map = v6::Map::read(store, page_size)?;
        let mut map_is_stale = false;

        let mut counts = Vec::with_capacity(built.len());
        for rebuilt in &built {
            counts.push((rebuilt.count_at, rebuilt.count));

            // The tree's own page numbers, root first and decorated with this
            // key's number the way every v6 child pointer is. `existing` covers
            // the nodes the tree already had; anything beyond that is a node
            // this rebuild added and needs an allocation-table slot of its own.
            let mut numbers: Vec<u32> = rebuilt
                .existing
                .iter()
                .map(|&logical| Self::v6_decorate(logical, rebuilt.tag))
                .collect();
            let blank = vec![0u8; usize::from(page_size)];
            while numbers.len() < rebuilt.index.nodes.len() {
                let logical = v6::Map::claim(store, page_size, &blank, rebuilt.tag)
                    .map_err(|why| format!("claiming an index page: {why}"))?;
                map_is_stale = true;
                numbers.push(Self::v6_decorate(logical, rebuilt.tag));
            }

            // A tree that *shrank* no longer needs every page `existing`
            // named -- this crate packs a fresh rebuild denser than genuine
            // Btrieve 6.15 ever wrote (measured 50-77% full,
            // `v6::Map`'s own module doc), so an ordinary insert or update
            // can leave a key's tree smaller than it was. `number_pages`
            // below only consumes the first `rebuilt.index.nodes.len()`
            // entries of `numbers`; anything past that must be released
            // here, or the allocation table keeps a claim on a page no
            // key's walk reaches any more -- exactly what `read::file`
            // refuses as "claimed but attributed to no key's B-tree".
            // Measured, not assumed: a real `IDXPROBE.DAT` insert shrinks
            // *both* of its keys' trees (6 nodes to 4), and a real
            // `WCCMP002.DAT` update shrinks its one key's tree (208 nodes to
            // 106) -- one mechanism, not two (`task-3b-report.md`'s
            // census). `v6::Map::unclaim` only forgets the claim; the
            // abandoned physical page is left as ordinary litter, the same
            // shape `v6::Map::relocate`'s own doc comment already
            // establishes for a page a move leaves behind.
            for decorated in numbers.split_off(rebuilt.index.nodes.len()) {
                let logical = decorated & pages::fcr::ROOT_PAGE;
                v6::Map::unclaim(store, page_size, logical).map_err(|why| {
                    format!(
                        "releasing logical page {logical}, which the rebuilt tree \
                         no longer needs: {why}"
                    )
                })?;
                map_is_stale = true;
            }

            let placed = pages::number_pages(&rebuilt.index, &numbers)?;
            for (number, image) in placed {
                let logical = number & pages::fcr::ROOT_PAGE;

                // Every claim and every relocation rewrites the allocation
                // table, so a map read from before one of those would answer
                // about the file as it was two nodes ago.
                if map_is_stale {
                    map = v6::Map::read(store, page_size)?;
                    map_is_stale = false;
                }
                let body = usize::from(pages::HEADER);
                if let Some(physical) = map.physical(logical) {
                    let current = store.page(physical as usize).map_err(|why| {
                        format!("logical page {logical} resolves to physical {physical}: {why}")
                    })?;
                    if current[body..] == image[body..] {
                        continue;
                    }
                }

                v6::Map::relocate(store, page_size, logical, &image, rebuilt.tag)
                    .map_err(|why| {
                        format!("relocating an index page at logical {logical}: {why}")
                    })?;
                map_is_stale = true;
            }
        }

        // Last, and after every index root has been placed: the chains join
        // records on *data* pages, and relocating those is a separate
        // sequence that should not be interleaved with the index's.
        self.v6_write_chains(store, layout, &chains)?;

        Ok(counts)
    }

    /// Check a write's own output by rebuilding it and comparing, but only
    /// when [`Self::verify_writes`] says to, and never at all in a release
    /// build.
    ///
    /// # LOAD-BEARING NAME -- do not rename or remove this hook
    ///
    /// `verify_write` is Plan 3 Task 1's net, and every later task in that
    /// plan is written against its presence. Stage B (tasks 4 and 5)
    /// rewrites `insert_v6`/`update_v6`/`delete_v6` and `write_changed_pages`
    /// underneath the three callers below -- that rewrite must still leave
    /// every successful call to [`Self::insert`], [`Self::update`] and
    /// [`Self::delete`] passing back through this function before it returns
    /// to its caller. Those tasks' own reviews check for this by name.
    ///
    /// **Plan 3 Task 2's cost measurement must be taken with this hook
    /// off** -- either build `--release` (which strips the mechanism
    /// entirely, see below) or open the block under test with
    /// [`Self::verify_writes`] left `false`, or the numbers measured are
    /// this function's read and re-emit, not the write being measured.
    ///
    /// # What this actually does
    ///
    /// If `result` is `Err`, it is returned unchanged -- a write that never
    /// happened has nothing on disk to check. Otherwise, only when compiled
    /// with `debug_assertions` (never in `--release`) **and** only when
    /// `self.verify_writes` is `true`, [`verify::written`] is run against
    /// `self.path`; its failure replaces `result` with an `Err` naming the
    /// offset and field it found wrong, exactly as [`verify::written`]'s own
    /// doc comment describes.
    ///
    /// Two gates, not one, because they answer different questions. Whether
    /// `crate::verify::written` runs *at all* costs nothing to check --
    /// `self.verify_writes` is a plain bool read -- but doing the check is
    /// a full read plus a full re-emit, see [`verify::written`]'s doc
    /// comment, and that cost is what `self.verify_writes` gates. It is
    /// `cfg!(debug_assertions)` by default -- so a normal release board
    /// pays nothing beyond the one bool read, same as when this was a
    /// compile-time `#[cfg(debug_assertions)]` -- **except** when
    /// [`Self::open`] captured `VERFBV` (Task 8): then it is `true`
    /// regardless of the build, because that mode is the caller asking for
    /// read-after-write verification by name, and a compile-time gate could
    /// not have honoured that in a release build no matter what the module
    /// asked for. See [`Self::verify_writes`]'s own doc comment for the 37
    /// tests that went red the one time the check ran with no opt-in at
    /// all.
    fn verify_write<T>(&self, result: Result<T, BtvError>) -> Result<T, BtvError> {
        let value = result?;
        if self.verify_writes {
            if let Err(why) = crate::verify::written(&self.path) {
                return Err(BtvError {
                    file: self.name.clone(),
                    why,
                });
            }
        }
        Ok(value)
    }

    /// `RONLBV` (Task 8): refuse a write outright on a block opened
    /// read-only, before either the write itself or [`Self::verify_write`]
    /// ever runs.
    ///
    /// Measured against genuine Btrieve 6.15 under Wine: a file opened
    /// `RONLBV` (-2) and then written to (insert, update or delete alike)
    /// answers status 46, "Access To File Denied" --
    /// `docs/mirrors/github-syntax53-Nightmare-Redux/modBtrieve.bas:183-184`.
    /// See task-8-report.md for the probe transcript.
    fn refuse_if_read_only(&self) -> Result<(), BtvError> {
        if self.mode == RONLBV {
            return Err(BtvError {
                file: self.name.clone(),
                why: "refused -- this file is open read-only (RONLBV), and a write to it \
                      is status 46, Access To File Denied, measured against genuine \
                      Btrieve 6.15 under Wine"
                    .to_owned(),
            });
        }
        Ok(())
    }

    /// Add a record, choosing its slot and writing it. See
    /// [`Self::insert_inner`] for the algorithm; this wrapper only adds the
    /// read-only refusal ([`Self::refuse_if_read_only`]) and the post-write
    /// verification described on [`Self::verify_write`].
    ///
    /// # Errors
    ///
    /// If this block is open `RONLBV` (status 46, see
    /// [`Self::refuse_if_read_only`]), the records cannot be read, the file
    /// holds variable-length records and `bytes` is shorter than the fixed
    /// part every record has, the file holds variable-length records and is
    /// version 5 (see [`Self::insert_v6`]'s own doc comment for what a
    /// version 6 variable-length file still refuses), the file cannot be
    /// written, or [`Self::verify_write`] finds the write did not do what
    /// it claims.
    pub fn insert(&mut self, bytes: &[u8]) -> Result<u32, BtvError> {
        self.refuse_if_read_only()?;
        let result = self.insert_inner(bytes);
        self.verify_write(result)
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
    /// **A variable-length file is not normalised, and a version 5 one
    /// still refuses outright.** Normalising is right when `reclen` really
    /// is the length of every record; on a variable-length file it is not,
    /// and cutting a real record down to it is the same silent truncation
    /// [`Self::update`] already refuses for exactly this reason. A version
    /// 6 variable-length file does not refuse -- it diverges to
    /// [`Self::insert_v6`] below, which places the body on a variable page;
    /// only a version 5 one still has no proven write-side allocator for
    /// this shape and refuses (see the refusal a few lines down). See
    /// [`Self::update`]'s doc comment for the normalising rule this
    /// mirrors.
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
    /// records and `bytes` is shorter than the fixed part every record has,
    /// the file holds variable-length records and is version 5, or the file
    /// cannot be written.
    fn insert_inner(&mut self, bytes: &[u8]) -> Result<u32, BtvError> {
        // A fixed-length v6 block with a page cache diverges to
        // `Self::insert_v6` below before anything past this point ever
        // touches `self.records` -- and `insert_v6`'s own fast path
        // (`Self::v6_fast_reads`) never populates it either, so priming it
        // here would be pure waste: exactly the whole-file walk Task 7's
        // ops cutover exists to stop paying on every write. Every other
        // shape (v5, or a variable-length v6 file) still needs it, same as
        // always.
        if !self.v6_fast_reads() {
            self.records()?;
        }
        let name = self.name.clone();

        // A variable-length record is **not** normalised. `reclen` is the
        // length of its fixed part, not of the record, and cutting the buffer
        // down to it is exactly the silent truncation this used to refuse the
        // whole write to avoid. What is past `reclen` is the record's body,
        // and `Self::insert_v6` puts it on a variable page.
        let bytes = if self.geometry.variable {
            let reclen = usize::from(self.geometry.reclen);
            if bytes.len() < reclen {
                return Err(BtvError {
                    file: name,
                    why: format!(
                        "a {}-byte buffer is shorter than the {reclen}-byte fixed part \
                         every record of this file has",
                        bytes.len()
                    ),
                });
            }
            bytes.to_vec()
        } else {
            normalized(bytes, self.geometry.reclen)
        };

        // v6 diverges completely below this point -- a record's position
        // names a *logical* page, not a byte offset, so every remaining line
        // of this function (`pages::Layout::next_slot`, `pages::write_record`
        // seeking to a literal offset) is v5-only. `Self::insert_v6` is the
        // v6 equivalent, with its own narrower scope; see its doc comment.
        if self.geometry.version == Version::V6 {
            return self.insert_v6(bytes);
        }

        // v5 variable-length files still refuse: `variable::Space` has a v6
        // page source and no v5 one, and v5 takes a physical page off the
        // file's own free chain rather than claiming a logical id through an
        // allocation table. Refusing here rather than in `Space` keeps the
        // v5 arithmetic below reachable only for the shape it was written
        // for.
        if self.geometry.variable {
            return Err(BtvError {
                file: name,
                why: format!(
                    "is a version 5 file holding variable-length records up to {} bytes, \
                     and this host writes them only to version 6 files so far -- v5 takes \
                     a fresh variable page off the file's own free chain, which has not \
                     been measured",
                    self.geometry.reclen
                ),
            });
        }

        // Reached only for v5 now, but kept explicit rather than deleted:
        // `writable` is what refuses a version this match does not
        // recognise, and a future third version should hit that refusal
        // here rather than fall through to v5's own arithmetic.
        self.writable()?;

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

        // After the model, never before it: the count is read off the model,
        // so taking it any earlier would store the number this insert was
        // about to make wrong. See `Self::write_key_record_counts`.
        self.write_key_record_counts().map_err(|why| BtvError {
            file: name,
            why,
        })?;

        Ok(position)
    }

    /// Replace the record at `position`. See [`Self::update_inner`] for the
    /// algorithm; this wrapper only adds the read-only refusal
    /// ([`Self::refuse_if_read_only`]) and the post-write verification
    /// described on [`Self::verify_write`].
    ///
    /// # Errors
    ///
    /// If this block is open `RONLBV` (status 46, see
    /// [`Self::refuse_if_read_only`]), the file holds fixed-length records
    /// and `bytes` is not exactly `reclen` long, the file holds
    /// variable-length records and the write is not an in-place,
    /// same-length, single-fragment rewrite (see [`Self::update_inner`]'s
    /// own doc comment), the records cannot be read, `position` holds no
    /// record, the file cannot be written, or [`Self::verify_write`] finds
    /// the write did not do what it claims.
    pub fn update(&mut self, position: u32, bytes: &[u8]) -> Result<(), BtvError> {
        self.refuse_if_read_only()?;
        let result = self.update_inner(position, bytes);
        self.verify_write(result)
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
    /// **Variable-length files rewrite in place, or refuse.** The four bytes
    /// between `reclen` and `physical` in such a file's slot are Btrieve's
    /// pointer to the record's first variable fragment, and
    /// `pages::write_record`/`v6::Map::relocate` both write the *whole*
    /// slot, so a buffer that does not already carry the right pointer bytes
    /// in the right place would corrupt or unlink the fragment chain if
    /// written unconditionally. What actually happens is only ever a call to
    /// [`Self::rewrite_variable`] (v5) or [`Self::update_v6`]'s
    /// variable-length branch (v6, Task 6): both read the *existing* pointer
    /// off disk, rewrite only the fragment content it names, and leave the
    /// pointer itself untouched -- see their own doc comments for the exact
    /// shape each one handles (v5: one whole unfragmented fragment, same
    /// length; v6: the same, decided by the fragment's own leading pointer
    /// rather than its entry bit) and refuses otherwise. An earlier version
    /// refused every variable-length update outright, on every version; that
    /// refusal is what genuine Btrieve 6.15 gave for the one shape this host
    /// still cannot do -- see
    /// [`an_update_of_a_variable_length_file_is_refused_rather_than_unlinking_its_fragments`]
    /// for the case (a buffer with no body past `reclen` at all) this host
    /// still refuses exactly the same way.
    ///
    /// # Errors
    ///
    /// If the file holds fixed-length records and `bytes` is not exactly
    /// `reclen` long, the file holds variable-length records and the write
    /// is not an in-place, same-length, single-fragment rewrite, the records
    /// cannot be read, `position` holds no record, or the file cannot be
    /// written.
    fn update_inner(&mut self, position: u32, bytes: &[u8]) -> Result<(), BtvError> {
        let fast = self.v6_fast_reads();
        if !fast {
            self.records()?;
        }
        let name = self.name.clone();

        if self.geometry.version != Version::V6 {
            self.writable()?;
        }

        if self.geometry.variable {
            let reclen = usize::from(self.geometry.reclen);

            // The one shape this host rewrites: a buffer with a body beyond
            // `reclen` (nothing to rewrite in place otherwise), at a position
            // the model already holds a record at. Everything else -- no
            // body, an unknown position, or a body the version-specific
            // rewrite itself refuses because the page it names is not shaped
            // for an in-place rewrite -- keeps this host's refusal rather
            // than guessing.
            let has_body = bytes.len().checked_sub(reclen).is_some_and(|n| n > 0);
            if has_body {
                let known = self
                    .records
                    .as_ref()
                    .expect("just loaded")
                    .find_physical(position)
                    .is_some();
                if known {
                    if self.geometry.version == Version::V6 {
                        let layout = pages::Layout {
                            page: self.geometry.page,
                            physical: self.geometry.physical,
                            pages: self.geometry.pages,
                        };
                        return self.update_v6(position, bytes, layout);
                    }
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
                    "holds variable-length records up to {} bytes, and this write has no \
                     body past reclen (or names a position with no known record) -- \
                     writing this {}-byte buffer would pad the slot out to its {} \
                     physical bytes and zero the pointer to the record's variable part, \
                     unlinking the fragment chain the rest of the file is threaded on",
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

        // The existing record's own bytes, needed only for
        // `Self::unmodifiable_key_changed`'s before/after comparison below.
        // The fast path fetches them straight through the page cache by
        // position (`Self::v6_record_bytes_at`, the same "does this
        // position hold a live record" check `Records::find_physical`
        // answers on the old path) rather than needing `self.records`
        // populated at all.
        let existing = if fast {
            self.v6_record_bytes_at(position)
                .map_err(|why| BtvError {
                    file: name.clone(),
                    why,
                })?
                .ok_or_else(|| BtvError {
                    file: name.clone(),
                    why: format!("position {position} holds no record"),
                })?
        } else {
            let records = self.records.as_ref().expect("just loaded");
            let Some(at) = records.find_physical(position) else {
                return Err(BtvError {
                    file: name,
                    why: format!("position {position} holds no record"),
                });
            };
            records.physical(at).expect("just found").bytes.clone()
        };

        // Genuine Btrieve refuses this write outright, and so does this. See
        // `Self::unmodifiable_key_changed` for the measurement and for why the
        // refusal lives here rather than in each of the four callers.
        if let Some(key) = self.unmodifiable_key_changed(&existing, bytes) {
            return Err(BtvError {
                file: name,
                why: format!(
                    "key {key} does not declare itself modifiable, and this \
                     update changes its value -- genuine Btrieve answers status \
                     10 and writes nothing"
                ),
            });
        }

        let layout = pages::Layout {
            page: self.geometry.page,
            physical: self.geometry.physical,
            pages: self.geometry.pages,
        };

        // v6 diverges completely from here, the same way `Self::insert` does
        // and for the same reason: `pages::write_record` seeks `position` as
        // a literal byte offset, and a v6 position names a logical page.
        if self.geometry.version == Version::V6 {
            return self.update_v6(position, bytes, layout);
        }

        // v5-only from here -- `fast` is always false (`Self::v6_fast_reads`
        // implies `Version::V6`), so `self.records` is always populated.
        let records = self.records.as_ref().expect("just loaded");
        let count = records.len() as u32;

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
            .map_err(|why| BtvError {
                file: name.clone(),
                why,
            })?;

        self.dirty = true;

        // An update can change a key's value, and a changed value can join or
        // leave a duplicate group -- so the entry count moves even though the
        // record count does not. See `Self::write_key_record_counts`.
        self.write_key_record_counts().map_err(|why| BtvError {
            file: name,
            why,
        })?;

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
            let mut file = open_for_read(&self.path)
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

    /// Remove the record at `position`. See [`Self::delete_inner`] for the
    /// algorithm; this wrapper only adds the read-only refusal
    /// ([`Self::refuse_if_read_only`]) and the post-write verification
    /// described on [`Self::verify_write`].
    ///
    /// # Errors
    ///
    /// If this block is open `RONLBV` (status 46, see
    /// [`Self::refuse_if_read_only`]), the records cannot be read, the file
    /// holds variable-length records and is version 5 (see
    /// [`Self::delete_v6`]'s own doc comment for what a version 6
    /// variable-length file still refuses), `position` holds no record, the
    /// file cannot be written, or [`Self::verify_write`] finds the write
    /// did not do what it claims.
    pub fn delete(&mut self, position: u32) -> Result<(), BtvError> {
        self.refuse_if_read_only()?;
        let result = self.delete_inner(position);
        self.verify_write(result)
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
    /// **v5 variable-length files still refuse.** A variable-length record's
    /// fragment lives on a separate page, reached through the four-byte
    /// pointer between `reclen` and `physical` in its slot (see
    /// [`Self::update`]'s doc comment and [`Self::rewrite_variable`]).
    /// Measured (`tools/btrieve-oracle/delprobe.c`,
    /// `docs/delete-oracle-answer.md`): a genuine delete of a variable-length
    /// record succeeds at the API level (status 0) on the real engine, but
    /// what it does to a v5 fragment chain was not traced byte-for-byte, and
    /// v5's own write-side allocator (`variable::Space`) has only ever been
    /// proven for insert, not a delete-side free -- so this host refuses v5
    /// rather than guess.
    ///
    /// **v6 variable-length files delete** (Task 7): see
    /// [`Self::delete_v6`]'s own doc comment for the shape this closes and
    /// [`variable::free_fragment_v6`] for what is refused within that.
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
    /// records and is version 5, `position` holds no record, or the file
    /// cannot be written.
    fn delete_inner(&mut self, position: u32) -> Result<(), BtvError> {
        let fast = self.v6_fast_reads();
        if !fast {
            self.records()?;
        }
        if self.geometry.version != Version::V6 {
            self.writable()?;
        }
        let name = self.name.clone();

        if self.geometry.variable && self.geometry.version != Version::V6 {
            return Err(BtvError {
                file: name,
                why: format!(
                    "holds variable-length records up to {} bytes, and this host does \
                     not delete them for Btrieve 5 -- a variable-length record's \
                     fragment lives on a separate page reached through the pointer \
                     behind its fixed part, and the write-side allocator this needs \
                     (`variable::Space`) has only ever been proven for insert, not a \
                     delete-side free, for v5 (v6 deletes -- see `Self::delete_v6`)",
                    self.geometry.reclen
                ),
            });
        }

        // Existence check -- the fast path asks the page cache directly by
        // position (`Self::v6_record_bytes_at`) rather than needing
        // `self.records` populated at all; see `Self::update_inner`'s
        // identical reasoning.
        if fast {
            if self
                .v6_record_bytes_at(position)
                .map_err(|why| BtvError {
                    file: name.clone(),
                    why,
                })?
                .is_none()
            {
                return Err(BtvError {
                    file: name,
                    why: format!("position {position} holds no record"),
                });
            }
        } else {
            let records = self.records.as_ref().expect("just loaded");
            if records.find_physical(position).is_none() {
                return Err(BtvError {
                    file: name,
                    why: format!("position {position} holds no record"),
                });
            }
        }

        let layout = pages::Layout {
            page: self.geometry.page,
            physical: self.geometry.physical,
            pages: self.geometry.pages,
        };

        // v6 diverges completely from here, the same way `Self::insert` and
        // `Self::update` do: `pages::delete_record` seeks `position` as a
        // literal byte offset and splices the v5 free list at
        // `pages::fcr::FREE`, and a v6 file has neither.
        if self.geometry.version == Version::V6 {
            return self.delete_v6(position, layout);
        }

        // v5-only from here -- `fast` is always false (`Self::
        // v6_fast_reads` implies `Version::V6`), so `self.records` is
        // always populated.
        let records = self.records.as_ref().expect("just loaded");
        let count = records.len() as u32 - 1;

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
            .map_err(|why| BtvError {
                file: name.clone(),
                why,
            })?;

        self.geometry.records = count;
        self.dirty = true;

        // Measured on the genuine engine: a delete takes the key's own count
        // down with the file's (`docs/2026-08-16-v6-update-delete-oracle.md`,
        // "per-key record count | 3 -> 2"). See
        // `Self::write_key_record_counts`.
        self.write_key_record_counts().map_err(|why| BtvError {
            file: name,
            why,
        })?;

        Ok(())
    }

    /// Every key's stored `approx_count`, paired with the offset in the file
    /// control record that holds it -- the `(offset, count)` shape
    /// [`v6::write_fcr`] already takes, so the two versions describe the same
    /// thing the same way.
    ///
    /// The count is the number of index entries, not the number of records:
    /// see [`index_entries`], and `stat.rs`'s own "`approx_count` is a stored
    /// field" section for the measurement behind that distinction.
    ///
    /// # Errors
    ///
    /// If the records have never been loaded, or a key is not one they were
    /// ordered by.
    fn key_record_counts(&self) -> Result<Vec<(usize, u32)>, String> {
        let records = self
            .records
            .as_ref()
            .ok_or_else(|| "the key counts were asked for before the records were loaded".to_owned())?;
        let shift = records.key_shift();
        let mut counts = Vec::with_capacity(self.keys.len());
        for key in &self.keys {
            let len = records.ordered_len(key.number).ok_or_else(|| {
                format!(
                    "key {}: not among the keys the loaded records were ordered by",
                    key.number
                )
            })?;
            let (entries, _) = index_entries(records, key, shift, len);
            let definition =
                pages::fcr::KEYS + usize::from(key.definition) * pages::fcr::KEY_WIDTH;
            let count = u32::try_from(entries.len())
                .map_err(|_| format!("key {}: more than four billion entries", key.number))?;
            counts.push((definition + pages::fcr::KEY_RECORDS, count));
        }
        Ok(counts)
    }

    /// Bring every key's stored `approx_count` on disk up to date with the
    /// model, touching no other byte of the file control record.
    ///
    /// v5 only, and called by every v5 write. Genuine Btrieve keeps this field
    /// live per operation -- `docs/2026-08-16-v6-update-delete-oracle.md:120`
    /// measured a delete taking a key's count from 3 to 2 -- while this
    /// engine's v5 write path rebuilt the *index* lazily at close
    /// ([`Self::reindex`]) and let the count ride along with it. That is a
    /// defensible place to defer a whole B-tree to. It is not a defensible
    /// place to defer a four-byte counter to: a `B_STAT` between an insert and
    /// the close answered a number that was true before the write, and it was
    /// this engine's own replay of a genuine transcript that caught it --
    /// three inserts, then a stat, where genuine Btrieve answered 3 and this
    /// engine answered 0 (`crates/btrieve/tests/differential.rs`, and
    /// follow-up 3 of `docs/2026-08-17-btrcall-facade-landed.md`).
    ///
    /// The index stays deferred. This writes the count alone, so a file left
    /// unclosed by a crash now holds a count that agrees with its records
    /// rather than one that trails them -- the same direction the file-level
    /// record count already goes, which `pages::write_record` has always
    /// written on the spot.
    ///
    /// # Four bytes at a time, not a page
    ///
    /// [`Self::reindex`] reads the file control record as
    /// `geometry.page` bytes, patches its counts in memory and writes the
    /// whole thing back. That is safe for it -- it is rewriting the head
    /// wholesale anyway -- but it is wrong here twice over: the key
    /// definitions start at [`pages::fcr::KEYS`] (`0x110`), which lies past a
    /// page smaller than 276 bytes, and writing a whole page back would put
    /// this function in the business of preserving every other field in it.
    /// Keys are parsed from the first [`FCR`] bytes regardless of page size
    /// ([`Self::open`]), so this seeks to each count and writes its four bytes,
    /// touching nothing else. The test fixtures' 64-byte pages are what made
    /// the difference visible.
    ///
    /// # Errors
    ///
    /// If [`Self::key_record_counts`] cannot be taken, a count lies past the
    /// file control record, or the file cannot be written.
    fn write_key_record_counts(&self) -> Result<(), String> {
        let counts = self.key_record_counts()?;
        if counts.is_empty() {
            return Ok(());
        }

        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&self.path)
            .map_err(|e| format!("{}: {e}", self.path.display()))?;
        for (at, count) in counts {
            if at + 4 > FCR {
                return Err(format!(
                    "{}: a key's record count at {at:#x} lies past the \
                     {FCR}-byte file control record",
                    self.path.display()
                ));
            }
            file.seek(SeekFrom::Start(at as u64))
                .and_then(|_| file.write_all(&pages::to_long(count)))
                .map_err(|e| {
                    format!(
                        "{}: writing a key's record count at {at:#x}: {e}",
                        self.path.display()
                    )
                })?;
        }
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

        // A v6 file has nothing deferred to rebuild here, and running this
        // function's v5 arithmetic over one would corrupt it.
        //
        // [`Self::insert_v6`] maintains the index **inline**: it rebuilds the
        // key's tree, relocates the root through the `"PP"` allocation table
        // and rewrites the file control record's shadow pair, all before it
        // returns. That is not an optimisation, it is forced -- every v6 write
        // relocates the page it touches, so there is no way to write a record
        // now and fix its index later.
        //
        // Everything below this point assumes v5, in three separate places:
        // `KEY_ROOT` is read as a page number (a v6 root is
        // `0x8000_0000 | logical_id`), `pages::walk`/`pages::write_page`
        // address pages physically (a v6 page number is a logical id resolved
        // through the allocation table), and `pages::append_page` grows the
        // file without claiming the new page in that table.
        //
        // The bounds check further down is what stopped the first of those
        // from doing damage -- it refused `0x8000_0001` as "not inside an
        // 8-page file" rather than letting `pages::walk` follow it into a real
        // page and write a rebuilt index over whatever lived there. That
        // refusal is how this was found: it stopped The Rose 3.0NT's boot in
        // `dfaclose`, after the module had otherwise finished init.
        //
        // So this early return is a genuine no-op, not a gap papered over --
        // and it stays one now that `update`/`delete` also write v6 files
        // ([`Self::update_v6`], [`Self::delete_v6`]): both call
        // [`Self::v6_reindex`] inline, the same discipline `insert_v6`
        // established, so there is still nothing deferred to close time for
        // this function to catch up on. If a future v6 write path ever
        // defers index work to close time instead, this has to become a
        // real v6 reindex.
        if self.geometry.version == Version::V6 {
            self.dirty = false;
            return Ok(());
        }

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
            let (mut entries, groups) = index_entries(records, key, shift, len);

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
/// `open: Vec<Block<M>>` and `stack: [M::Ptr; BBSTSZ]` -- every pointer this
/// type keeps is a module address, and the module's own ABI decides its
/// shape. `A` carries no default; every caller spells its ABI, the same
/// convention every other generic type in this crate follows.
///
/// This paragraph used to say that `Host<A>::btrieve` "still names it without
/// `<A>` ... widening it to `Btrieve<A>` is the one remaining step". Both
/// halves are done and have been for a while: commit 42d212e made the field
/// `btrieve::Btrieve<A>` -- the elision had been silently pinning the whole
/// subsystem to one ABI, which is the bug that comment was describing as
/// future work -- and Task 3 of
/// `docs/plans/2026-08-12-abi-border-implementation.md` removed the `= Wg16`
/// default that made the elision compile. Left in place rather than deleted
/// because a comment that outlived its fact by long enough to be quoted back
/// as a live blocker is the failure this crate keeps paying for.
pub struct Btrieve<M: Mem> {
    open: Vec<Block<M>>,

    /// `bbstk`: what `rstbtv` will restore, nearest first. Fixed at ten and
    /// **shifting**, which is not an implementation detail -- see [`Self::set`].
    stack: [M::Ptr; BBSTSZ],

    /// `bbomode`: the mode the next `opnbtv` opens in. `PRIMBV`, which is zero,
    /// until `omdbtv` says otherwise. Consumed by [`Self::open`] (Task 8),
    /// which captures it onto the [`Block`] being pushed.
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

    /// `dfa`: DFAAPI.C's own current-file pointer, the `dfa*` family's
    /// counterpart to `bb` above and entirely independent of it -- opening a
    /// file with `dfaOpen` never changes what `opnbtv` left current, and vice
    /// versa. `WCCMMUD.DLL` (16-bit, the one module this host has run
    /// end-to-end) never calls a `dfa*` routine at all; the family is what
    /// the 32-bit modules in the corpus survey import instead.
    ///
    /// **Kept here, not in module memory.** `BTVSTF.H:36` declares
    /// `extern struct btvblk *bb;`, which is what lets [`crate::globals`]
    /// place `bb` somewhere a module's own fixups can address directly (see
    /// `mbbs`'s `shims::btrieve::current`'s own doc comment).
    /// `DFAAPI.H` declares no such extern for `dfa` -- it is a plain
    /// file-scope `static` inside `DFAAPI.C`, invisible outside the object
    /// file that provides `dfaOpen`/`dfaSetBlk`/etc. So unlike `bb`, this
    /// type is the only place `dfa`'s value exists at all, and every dfa*
    /// shim reads and writes it here rather than through module memory.
    dfa_current: M::Ptr,

    /// `dfastk`: the ten-deep stack behind [`Self::dfa_current`],
    /// `DFAAPI.H:24`. See [`Self::dfa_set`] for why its shift rule is not
    /// [`Self::set`]'s.
    dfa_stack: [M::Ptr; DFSTSZ],

    /// `dfaomode`: the mode the next `dfaOpen` opens in, `DFAAPI.C:26`.
    /// `PRIMBV` (zero) until `dfaMode` says otherwise -- the `dfa*` family's
    /// own counterpart to [`Self::mode`], and independent of it for the
    /// identical reason `dfa`/`bb` are.
    dfa_mode: i16,

    /// `lastlen`: `DFAAPI.C:27`, `dfaLastLen`'s own answer. Updated only by
    /// `shims::dfa`'s own read/positioning routines (`dfaQueryNP`,
    /// `dfaGetLock`, `dfaAcqLock`, `dfaAcqNPLock`, `dfaGetAbsLock`,
    /// `dfaAcqAbsLock`, `dfaStepLock`) -- **a simplification**, noted here
    /// rather than left silent: the real `btvu()` (`:948`, and the two
    /// platform branches beside it) echoes back Btrieve's own `dbflen` after
    /// *every* call, writes included, where this host updates it only after
    /// a record is actually delivered into a buffer. No `dfa*` symbol in
    /// `re/wg33src/LIB/WGSERVER.DEF` reaches `dfaLastLen` in the surveyed
    /// corpus (it is exported, but zero import count), so this is scoped to
    /// the one shape worth reproducing rather than every call site.
    dfa_last_len: u16,

    /// `lastlen`: `PLBTVSTF.C:34` (MajorBBS 6.25 -- `llnbtv` has a body
    /// there, `:352-356`), `llnbtv`'s own answer -- the BTVSTF
    /// family's counterpart to [`Self::dfa_last_len`], and independent of it
    /// for the identical reason `dfa_last_len` gives for why it is
    /// independent of `dfa`/`bb`: `PLBTVSTF.C` and `DFAAPI.C` are two
    /// different translation units, each with its own file-scope `static int
    /// lastlen`, both fed by their own low-level call into the same
    /// underlying `INT 0x7B` -- not the same variable.
    ///
    /// Updated in exactly one place, [`shims::btrieve::deliver`]
    /// (`crate::shims::btrieve`) -- the chokepoint every read routine in that
    /// file already funnels a successful positioning through
    /// (`locate`/`absolute`/`stpbtvl`'s own direct calls) -- with the same
    /// scoping [`Self::dfa_last_len`]'s own doc comment already applies to
    /// its family: the real `btvu()` (`:812`, `lastlen=btvdatptr->dbflen`)
    /// echoes back Btrieve's own `dbflen` after *every* call, including a
    /// query that delivers nothing and a write; this host updates it only
    /// where a record is actually copied into module memory. `llnbtv` has no
    /// import anywhere in `WCCMMUD.DLL`'s own seventeen-symbol survey (this
    /// file's own module doc comment), so -- exactly as for `dfa_last_len`
    /// -- this is scoped to the one shape worth reproducing rather than
    /// instrumented at every call site on no evidence any of them matters.
    lastlen: u16,

    /// The length `sttbtv` last stored, for a future `llnbtv`... no,
    /// `rlenbtv`... **no consumer has been found for this at all.**
    ///
    /// `sttbtv(int len)` is declared at `BTVSTF.H:169` (Worldgroup-era
    /// numbering) and has **no body in any of the three recovered
    /// `PLBTVSTF.C` generations** -- MajorBBS 6.25, Worldgroup 1.0 or
    /// Worldgroup 2.0 (Task 1's own finding) -- and no macro in `BTVSTF.H`
    /// and no call site anywhere in `archive/` or `re/` references it either
    /// (checked: `grep -a -rn sttbtv archive/ re/`, zero hits outside the two
    /// header declarations). So this field's very existence is inferred, not
    /// measured: `sttbtv` sits in `BTVSTF.H`'s list immediately after the
    /// insert/update family, which is the only reason to guess "set the
    /// length for the next variable write" over any other reading of `int
    /// len`, and `rlenbtv`'s own real body (`PLBTVSTF.C:696-710`, both
    /// generations agree) does **not** read anything like it back -- it
    /// queries the file's own fixed `reclen` off a Btrieve `STAT` (op 15),
    /// unrelated to whatever a module last told `sttbtv`. Nothing in this
    /// crate reads this field back through any other shim either: it is
    /// stored, and stored only, on the standing instruction that a real
    /// Btrieve feature is implemented even where the one surveyed module
    /// never reaches it (`take_lock`'s own doc comment) -- but "implemented"
    /// here can only mean "the argument is read at the right width and
    /// remembered", because inventing which write path consumes it would be
    /// inventing behaviour with zero evidence behind it, the one thing this
    /// project's "no plausible zeros" rule forbids outright. [`Self::stt_length`]
    /// exists so a test can observe the argument landed correctly; nothing
    /// downstream of it exists yet.
    stt_length: u16,
}

impl<M: Mem> Default for Btrieve<M> {
    /// Nothing open, nothing stacked, and `PRIMBV`.
    ///
    /// Ten null pointers rather than an empty vector, because that is what
    /// `static struct btvblk *bbstk[BBSTSZ]` is and what makes `rstbtv` past
    /// the bottom yield null instead of nothing.
    ///
    /// Not `#[derive(Default)]`: the derive macro bounds `M: Default` on the
    /// generated impl, which a bare marker struct like `mbbs`'s `Wg16` does
    /// not satisfy -- the same problem `crates/mbbs/src/abi.rs`'s `Ret<A>`
    /// and `crates/mbbs/src/msg.rs`'s `Messages<A>` hit, and the same fix.
    fn default() -> Self {
        Self {
            open: Vec::new(),
            stack: [M::null_ptr(); BBSTSZ],
            mode: PRIMBV,
            transaction: false,
            locks: ops::LockTable::default(),
            dfa_current: M::null_ptr(),
            dfa_stack: [M::null_ptr(); DFSTSZ],
            dfa_mode: 0,
            dfa_last_len: 0,
            lastlen: 0,
            stt_length: 0,
        }
    }
}

impl<M: Mem> Btrieve<M> {
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
    /// `mbbs`'s `shims::btrieve::opnbtv`.
    ///
    /// Takes `mem: &mut M::Memory` rather than a whole machine -- the same
    /// generic-core shape `mbbs`'s `Heap::reserve` and
    /// `mbbs`'s `Messages::open_mem` already use. `heap` allocates
    /// through `mbbs`'s `Heap::reserve` directly, so
    /// this needs no `Wg16` facade of its own.
    ///
    /// # Errors
    ///
    /// If the file's key definitions cannot be read, or the heap has no room
    /// for the block, its name, its record buffer or its key buffer.
    pub fn open(
        &mut self,
        mem: &mut M::Memory,
        heap: &mut impl Alloc<M>,
        name: &str,
        path: &Path,
        geometry: Geometry,
        maxlen: u16,
    ) -> Result<M::Ptr, String> {
        // `EXCLBV` (Task 8): refused before any of the work below, the same
        // way a real conflict is refused before the engine has read anything
        // -- measured against genuine Btrieve 6.15 under Wine, two separate
        // `wine btrvprobe.exe serve` clients against one shared
        // `W32MKDE.EXE` (the same setup `docs/lock-oracle-answer.md` used):
        // an exclusive open against a path any block already has open, in
        // EITHER direction (the exclusive open arrives first and something
        // else opens next, or something else is already open and an
        // exclusive open arrives), answers status 88 -- "Incompatible Mode
        // Error", `docs/mirrors/github-syntax53-Nightmare-Redux/modBtrieve.bas:233`
        // -- both directions, read-only or normal on the other side, closing
        // the first opener releases it. `DFAAPI.C:153-164`'s own `dfaOpen`
        // expects status 85 here and *loops* on it rather than refusing --
        // that is a different, older status this project has no live
        // engine old enough to reproduce; 88 is what the engine this host
        // is measured against actually answers, and looping forever on a
        // single-threaded host would hang the board rather than open a
        // file, so this refuses instead. See task-8-report.md for the full
        // probe transcript.
        let mode = self.mode;
        if self.open.iter().any(|b| {
            b.path == path && (mode == EXCLBV || b.mode == EXCLBV)
        }) {
            return Err(format!(
                "{name}: refused -- {} is already open under an incompatible mode \
                 (status 88, Incompatible Mode Error): an exclusive open excludes \
                 every other open of the same path, and an exclusive open is itself \
                 excluded by any other open already in progress",
                path.display()
            ));
        }

        // The key definitions come out of the same first page the geometry did,
        // and they are read at open time rather than with the records because
        // `clckln()` -- which sizes the key buffer below -- is part of what
        // `opnbtv` does. A file whose keys cannot be read is refused here, not
        // at whatever much later moment something first searches by one.
        let fcr = read_head(path, FCR).map_err(|e| format!("{}: {e}", path.display()))?;
        // The control record says only *that* a key collates through an
        // alternate sequence; the table is on another page, so a file that uses
        // one costs a second read here. Files that do not -- 425 of the 470 the
        // census swept -- pay nothing for this.
        let tables = acs_tables(path, &geometry, &fcr)?;
        let parsed = keys::parse(name, &fcr, geometry.keys, &tables).map_err(|e| e.why)?;

        // `PLBTVSTF.C:148` -- `bb->filnam=alcmem(strlen(filnam)+1)`. The
        // module's, not the host's: `clsbtv` frees it.
        let bytes = name.as_bytes();
        let filnam = heap.reserve(mem, bytes.len() as u16 + 1)?;
        let mut terminated = bytes.to_vec();
        terminated.push(0);
        M::write(filnam, mem, &terminated).map_err(|e| e.to_string())?;

        let data = heap.reserve(mem, maxlen)?;
        M::write(data, mem, &vec![0u8; usize::from(maxlen)]).map_err(|e| e.to_string())?;

        // `clckln()` returns the longest key plus one, and that is what the
        // real host allocated. Plus one because a Btrieve key buffer for a
        // string key holds a terminator the key length does not count.
        let longest = parsed.iter().map(Key::length).max().unwrap_or(0);
        let key = heap.reserve(mem, longest + 1)?;
        M::write(key, mem, &vec![0u8; usize::from(longest) + 1])
            .map_err(|e| e.to_string())?;

        let field = Layout::of::<M>();
        let block = heap.reserve(mem, field.size)?;
        let mut image = vec![0u8; usize::from(field.size)];
        let put = |image: &mut Vec<u8>, offset: u16, bytes: &[u8]| {
            let at = usize::from(offset);
            image[at..at + bytes.len()].copy_from_slice(bytes);
        };
        put(&mut image, field.filnam, &M::ptr_to_bytes(filnam));
        put(&mut image, field.reclen, &maxlen.to_le_bytes());
        put(&mut image, field.data, &M::ptr_to_bytes(data));
        put(&mut image, field.key, &M::ptr_to_bytes(key));

        // `bb->keylns[n]`, which `clckln()` fills in and which `qrybtv` and the
        // acquire family read to know how many bytes of the module's buffer are
        // the key. Every one this host knows is written; the rest stay zero.
        for definition in &parsed {
            let at = field.keylns + definition.number * 2;
            if at + 2 <= field.keylns_end {
                put(&mut image, at, &definition.length().to_le_bytes());
            }
        }
        M::write(block, mem, &image).map_err(|e| e.to_string())?;

        // A v6 file gets a page cache for its whole time open, so its
        // second operation stops re-walking the allocation table from
        // disk (`Block::cache`'s own doc comment). A v5 file has no such
        // table, so it gets none. `PageCache::open` propagates its error
        // as-is -- already `path`-prefixed -- rather than wrapping it
        // again.
        let cache = if geometry.version == Version::V6 {
            Some(std::rc::Rc::new(std::cell::RefCell::new(cache::PageCache::open(
                path,
                geometry.page,
            )?)))
        } else {
            None
        };

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
            // A real module's `opnbtv` reached this constructor -- the only
            // one that did -- so this is the one place verification is worth
            // its cost, in a debug build by default, and unconditionally
            // when the module asked for `VERFBV` -- see `Self::verify_write`.
            verify_writes: cfg!(debug_assertions) || mode == VERFBV,
            mode,
            cache,
            v6_order: std::cell::RefCell::new(std::collections::HashMap::new()),
            v6_physical: std::cell::RefCell::new(None),
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
    pub fn set(&mut self, current: M::Ptr) -> Option<String> {
        let dropped = self.stack[BBSTSZ - 1];
        self.stack.copy_within(0..BBSTSZ - 1, 1);
        self.stack[0] = current;
        if dropped == M::null_ptr() {
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
    pub fn restore(&mut self) -> (M::Ptr, bool) {
        let restored = self.stack[0];
        self.stack.copy_within(1..BBSTSZ, 0);
        (restored, restored == M::null_ptr())
    }

    /// The null `struct btvblk *`.
    pub fn null() -> M::Ptr {
        M::null_ptr()
    }

    /// `dfa` -- the file `dfa*` routines currently work on. See
    /// [`Self::dfa_current`]'s sibling field doc comment for why this is
    /// read from `self` rather than from module memory.
    pub fn dfa_current(&self) -> M::Ptr {
        self.dfa_current
    }

    /// Overwrite `dfa` with no other effect -- not [`Self::dfa_set`], which
    /// also pushes the stack.
    ///
    /// `dfaClose`'s own `goodptr(dfa=dfap)` (`DFAAPI.C:661`) is exactly this:
    /// an unconditional assignment to `dfa` that runs whether or not the
    /// guard it is part of then finds a file to close, and the ten-deep
    /// stack behind `dfa` is untouched either way -- the same "the stack is
    /// not purged on close" shape `mbbs`'s `shims::btrieve::clsbtv`'s
    /// own doc comment already describes for `bb`/`bbstk`.
    pub fn dfa_set_current(&mut self, at: M::Ptr) {
        self.dfa_current = at;
    }

    /// The mode the next `dfaOpen` will use.
    ///
    /// Task 8 made [`Self::open`] consume [`Self::mode`] -- the `omdbtv`/
    /// `opnbtv` field this one is deliberately independent of, see this
    /// field's own doc comment -- for `RONLBV`/`VERFBV`/`EXCLBV`/`ACCLBV`.
    /// `dfaOpen` still calls that same [`Self::open`], and still passes it
    /// no mode of its own, so this value is stored and reported here but
    /// not yet consumed by anything: a module that reaches its Btrieve
    /// files through `dfa*` rather than `btv*` does not get mode
    /// enforcement from this task. `WCCMMUD.DLL`, the one 16-bit module
    /// this host runs end-to-end, never calls a `dfa*` routine at all (see
    /// [`Self::dfa_current`]'s own doc comment), so this gap has no
    /// currently-live caller; closing it is future work, not a silent
    /// omission.
    pub fn dfa_mode(&self) -> i16 {
        self.dfa_mode
    }

    /// Set the mode the next `dfaOpen` will use, as `dfaMode` does.
    pub fn dfa_set_mode(&mut self, mode: i16) {
        self.dfa_mode = mode;
    }

    /// `dfaLastLen`'s own answer -- see the `dfa_last_len` field's own doc
    /// comment for what updates it and what does not.
    pub fn dfa_last_len(&self) -> u16 {
        self.dfa_last_len
    }

    /// Record what a `dfa*` read just delivered, for [`Self::dfa_last_len`]
    /// to answer later.
    pub fn dfa_set_last_len(&mut self, len: u16) {
        self.dfa_last_len = len;
    }

    /// `llnbtv`'s own answer -- see the `lastlen` field's own doc comment for
    /// what updates it and what does not.
    pub fn lastlen(&self) -> u16 {
        self.lastlen
    }

    /// Record what a BTVSTF-family read just delivered, for [`Self::lastlen`]
    /// to answer later. Called from exactly one place,
    /// `mbbs`'s `shims::btrieve::deliver` -- see the
    /// `lastlen` field's own doc comment for why that one chokepoint is
    /// enough.
    pub fn set_lastlen(&mut self, len: u16) {
        self.lastlen = len;
    }

    /// What `sttbtv` last stored -- see the `stt_length` field's own doc
    /// comment for the honest account of what this is (and is not yet) for.
    pub fn stt_length(&self) -> u16 {
        self.stt_length
    }

    /// Record what `sttbtv` was just given.
    pub fn set_stt_length(&mut self, len: u16) {
        self.stt_length = len;
    }

    /// `dfaSetBlk` -- `DFAAPI.C:186-192`, quoted in full because the one
    /// line that matters is easy to misread:
    ///
    ///
    /// # Not [`Self::set`], and not an oversight
    ///
    /// `setbtv`'s equivalent line is `*bbstk=bb;` -- it reads `bb`'s value
    /// *before* this call overwrites it, so what lands in `bbstk[0]` is
    /// whatever was current a moment ago. `dfaSetBlk`'s line is
    /// `*dfastk=dfa=dfaptr;`, a chained C assignment, which evaluates its
    /// right-hand side first: `dfa=dfaptr` runs, and the *value of that
    /// expression* -- `dfaptr` itself, the new pointer -- is what `*dfastk`
    /// then receives. So `dfaSetBlk` pushes the pointer it was just handed,
    /// never the one it is replacing, and whatever `dfa` held a moment
    /// before this call is not saved anywhere: it is gone the instant this
    /// returns, with no `dfaRstBlk` able to reach it again.
    ///
    /// A concrete trace: opening `A` then `B` (each open ends with its own
    /// `dfaSetBlk(dfa)` at `DFAAPI.C:175`, `dfa` already reassigned to the
    /// freshly allocated block by then) leaves `dfa_stack == [B, A, ...]`,
    /// and one [`Self::dfa_restore`] returns to `A` -- **that much reads the
    /// same as `setbtv`'s "open pushes itself" shape**, because two
    /// *different* pointers went in. Where the two families diverge is a
    /// call that is not immediately paired with a restore: calling this
    /// twice in a row on the same pointer (`dfa_set(B); dfa_set(B);`, which
    /// nothing here forbids and nothing in `DFAAPI.C` guards against
    /// either) leaves `dfa_stack` holding two copies of `B`, with whatever
    /// was current before the *first* call unrecoverable by any number of
    /// restores. `Self::set` given the same two calls would have pushed the
    /// true previous value exactly once.
    ///
    /// Returns the name of the file that fell off the bottom, if the shift
    /// dropped one -- the same shape [`Self::set`] returns, for the same
    /// reason: an eleventh entry is not refused, because `DFAAPI.C`'s own
    /// shift does not refuse it either.
    pub fn dfa_set(&mut self, new: M::Ptr) -> Option<String> {
        let dropped = self.dfa_stack[DFSTSZ - 1];
        self.dfa_stack.copy_within(0..DFSTSZ - 1, 1);
        self.dfa_stack[0] = new;
        self.dfa_current = new;
        if dropped == M::null_ptr() {
            return None;
        }
        Some(match self.find(dropped) {
            Ok(at) => self.open[at].name.clone(),
            Err(_) => format!("{dropped:?}"),
        })
    }

    /// `dfaRstBlk` -- `DFAAPI.C:194-199`, and this one *is* the same shape
    /// as [`Self::restore`]:
    ///
    ///
    /// An empty stack is not an error, for the same reason [`Self::restore`]'s
    /// is not: `dfastk` starts as ten null pointers, and every `dfa*`
    /// routine this host implements that guards on `dfa == NULL` at all does
    /// so before touching anything else -- so a module that unbalances its
    /// own `dfaRstBlk` calls was written to get null back, not a refusal.
    ///
    /// Returns what to put in `dfa`, and whether the stack was empty.
    pub fn dfa_restore(&mut self) -> (M::Ptr, bool) {
        let restored = self.dfa_stack[0];
        self.dfa_stack.copy_within(1..DFSTSZ, 0);
        self.dfa_current = restored;
        (restored, restored == M::null_ptr())
    }

    /// The mode the next `opnbtv` will use.
    ///
    /// Task 8: [`Self::open`] now captures this onto the new [`Block`] it
    /// pushes, and `RONLBV`/`VERFBV`/`EXCLBV`/`ACCLBV` each change that
    /// block's behaviour from there -- see [`Block`]'s own `mode` field.
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
    /// **Writes are already visible before this is called**, in the sense
    /// that matters to a module. Measured (`xactprobe`'s `visibility`
    /// scenario): a `GET_EQUAL` for a record inserted earlier in the same
    /// transaction found it, tag and all, before `dfaEndTrans` was ever
    /// reached (`get-inside-txn status=0 (OK) tag=aa`), and it was still
    /// there after a close and reopen (`get-after-close-reopen status=0 (OK)
    /// tag=aa`). A v5 block, or a v6 one with no cache, still keeps that
    /// guarantee the same way it always has: `Block::insert`/`Block::update`
    /// write straight through, live, so there is nothing for `end` to flush
    /// for it.
    ///
    /// # A deferred (v6, cached) block *does* have something to flush -- Task 7
    ///
    /// Such a block's in-transaction writes only ever staged into its cache
    /// (`Block::stage_changed_pages`), never touching disk, so this is the
    /// point disk actually catches up: [`Block::commit_deferred`] runs one
    /// combined [`v6::Store::for_commit`] pass per covered block, flushing
    /// every page any op in the transaction touched through the same
    /// shadow-pair-aware three-phase write [`Block::write_changed_pages_
    /// attempt`] always uses, not one flush per op. "Visible before `end`"
    /// still holds for a module -- every read this host serves for such a
    /// block answers from the same cache the writes staged into, or from
    /// `self.records`, which every v6 write updates directly regardless of
    /// deferral -- it is only *disk* (a different process reading the file,
    /// or this one after a close and reopen) that was not caught up until
    /// now.
    ///
    /// # Errors
    ///
    /// [`TransactionError::NoneActive`] if no transaction is open. Measured:
    /// `xactprobe`'s `end_no_begin` scenario calls `dfaEndTrans` on a freshly
    /// opened file with no `dfaBegTrans` first, and the real engine refuses
    /// it (`end_no_begin: status=39`) rather than treating it as a no-op.
    ///
    /// [`TransactionError::CommitFailed`] if [`Block::commit_deferred`]
    /// fails for at least one covered block -- unmeasured against the real
    /// engine (no `xactprobe` scenario forces a disk error at `end` itself);
    /// this end's own doc comment on that variant states this call's
    /// policy. Every block still gets its transaction bookkeeping closed out
    /// regardless: one file's disk error should not strand every other
    /// file's commit, the same principle [`Self::abort`] already follows.
    pub fn end(&mut self) -> Result<(), TransactionError> {
        if !self.transaction {
            return Err(TransactionError::NoneActive);
        }
        self.transaction = false;
        let mut failure: Option<String> = None;
        for block in &mut self.open {
            block.txn_active = false;
            block.pre_image = None;
            if let Err(e) = block.commit_deferred() {
                failure.get_or_insert_with(|| e.to_string());
            }
        }
        match failure {
            Some(why) => Err(TransactionError::CommitFailed(why)),
            None => Ok(()),
        }
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
    ///
    /// A block's attached cache (v6 only) is invalidated whenever its disk
    /// write actually lands -- [`Block::invalidate_cache`] -- because
    /// whatever the aborted transaction's own write left resident there no
    /// longer agrees with the file this just put back. Missed until Task
    /// 3's own review: every existing `abort_undoes_*` test uses a v5
    /// fixture, which never attaches a cache, so nothing caught this until
    /// `abort_invalidates_the_v6_cache_not_just_disk_and_the_model` did.
    ///
    /// # A deferred (v6, cached) block never touched disk -- Task 7
    ///
    /// [`PreImage::bytes`] is `None` for such a block ([`PreImage`]'s own
    /// doc comment): every in-transaction write went to its cache only
    /// (`Block::stage_changed_pages`), so disk already **is** the
    /// pre-image and there is nothing to write back. Discarding what this
    /// transaction staged is [`cache::PageCache::drop_dirty`] -- cheaper
    /// than [`Block::invalidate_cache`]'s full reopen because every already-
    /// durable, pre-transaction page already resident stays resident; only
    /// the pages this transaction's own writes left dirty (never marked
    /// clean, because nothing ever flushed them) are thrown away. The
    /// in-memory model (`records`/`geometry`/`dirty`) is restored from
    /// `pre` exactly as it is for the disk-writing branch, because those
    /// fields are mutated directly by every v6 write regardless of
    /// deferral and still need putting back.
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
            match &pre.bytes {
                Some(bytes) => {
                    if std::fs::write(&block.path, bytes).is_err() {
                        // Restoring the model without the disk write
                        // succeeding would make the two disagree in a way a
                        // fresh read could not even detect, since the next
                        // read of this file would see the *unrestored* disk
                        // bytes. Leave both, and the pre-image, exactly as
                        // they were so nothing here claims a rollback that
                        // did not happen.
                        block.pre_image = Some(pre);
                        continue;
                    }
                    block.records = pre.records;
                    block.geometry = pre.geometry;
                    block.dirty = pre.dirty;
                    // The disk write above just put pre-transaction bytes
                    // back -- any page the transaction's own write had
                    // pushed into this block's cache is now stale. See
                    // `Block::invalidate_cache`'s own doc comment.
                    block.invalidate_cache();
                }
                None => {
                    // Task 7: nothing was ever written to disk for this
                    // block -- see this method's own doc comment.
                    if let Some(cache) = &block.cache {
                        cache.borrow_mut().drop_dirty();
                    }
                    // Same reason `Block::invalidate_cache` clears these
                    // on its own two callers' behalf: a keyed or physical
                    // read made inside the transaction (this crate's own
                    // read-your-own-writes contract) could have cached a
                    // rank or position built from exactly the dirty pages
                    // `drop_dirty` just discarded above. This branch never
                    // goes through `invalidate_cache` -- there is no page
                    // cache reopen to do, disk was never touched -- so it
                    // clears them directly instead.
                    block.v6_order.borrow_mut().clear();
                    *block.v6_physical.borrow_mut() = None;
                    block.records = pre.records;
                    block.geometry = pre.geometry;
                    block.dirty = pre.dirty;
                }
            }
        }
        Ok(())
    }

    /// The block a module's pointer names.
    ///
    /// # Errors
    ///
    /// If it names no open file.
    pub fn block(&self, at: M::Ptr) -> Result<&Block<M>, String> {
        Ok(&self.open[self.find(at)?])
    }

    /// The block a module's pointer names, to be read from or positioned.
    ///
    /// # Errors
    ///
    /// If it names no open file.
    pub fn block_mut(&mut self, at: M::Ptr) -> Result<&mut Block<M>, String> {
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
    pub fn files(&self) -> &[Block<M>] {
        &self.open
    }

    /// Close `at`, as everything in `PLBTVSTF.C:632` *after* `bb=bbp` does.
    ///
    ///
    /// `bb=bbp` is `mbbs`'s `shims::btrieve::clsbtv`'s
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
    /// allocates over the span -- `mbbs`'s `Heap::free` never
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
        mem: &mut M::Memory,
        heap: &mut impl Alloc<M>,
        at: M::Ptr,
    ) -> Result<bool, BtvError> {
        if at == M::null_ptr() {
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

        let filnam_at = M::ptr_offset(at, Layout::of::<M>().filnam);
        let bytes = M::resolve(filnam_at, mem, M::PTR_WIDTH)
            .map_err(|e| fail(e.to_string()))?;
        let filnam = M::ptr_from_bytes(bytes);

        // The file-side half: refuse on an outstanding pre-image, reindex
        // if dirty, drop the `Block`. Shared with `close_all_files` so
        // there is one reindex-on-dirty implementation, not two.
        let block = self.close_file(index)?;

        // `bb->filnam=NULL` -- still written, and still before anything is
        // freed, exactly where `PLBTVSTF.C:639` writes it. A module that
        // reads its own `bb->filnam` after this call sees what the original
        // left there; this host just no longer *relies* on reading it back
        // to decide whether there was a file to close.
        M::write(filnam_at, mem, &M::ptr_to_bytes(M::null_ptr()))
            .map_err(|e| fail(e.to_string()))?;

        heap.free(block.key).map_err(fail)?;
        heap.free(block.data).map_err(fail)?;
        heap.free(filnam).map_err(fail)?;
        heap.free(block.block).map_err(fail)?;

        Ok(true)
    }

    /// The file-side half of closing the block at `self.open[index]`:
    /// refuse if a transaction pre-image is outstanding, reindex it if
    /// [`Block::dirty`], then drop it from [`Self::open`] and release every
    /// lock it held. Returns the removed `Block` so a caller that also owns
    /// module memory (`close`) can free what this half never touches.
    ///
    /// Shared by [`Self::close`] and [`Self::close_all_files`] so the
    /// reindex-on-dirty rule -- and the pre-image refusal ahead of it --
    /// exist in exactly one place.
    ///
    /// # Errors
    /// If the block has an outstanding transaction pre-image (see
    /// [`Self::close`]'s doc comment), or if a dirty block's
    /// [`Block::reindex`] fails. Either way, `index` is left in
    /// [`Self::open`] rather than removed -- [`Self::close_all_files`]
    /// relies on this to retry a failing block later without having
    /// silently dropped it.
    fn close_file(&mut self, index: usize) -> Result<Block<M>, BtvError> {
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
        Ok(block)
    }

    /// Close every open file the way host shutdown needs to: the file-side
    /// half of [`Self::close`] (flush/reindex-if-dirty, drop the `Block`)
    /// for each entry in [`Self::open`], with no `mem`/`heap` parameters --
    /// the machine is being torn down, so the module memory `close` would
    /// otherwise reach into (the `bb->filnam` write, the four heap frees)
    /// is going away with it and there is nothing left to free it into.
    ///
    /// **Best-effort, not fail-fast.** At shutdown, maximum data settled
    /// wins over stopping at the first problem: every block still in
    /// [`Self::open`] is attempted, even after an earlier one in the same
    /// sweep failed, so one stuck file never keeps the rest of the board's
    /// data from reaching disk. A block that closes successfully always
    /// leaves [`Self::open`]; a block [`Self::close_file`] refuses or fails
    /// to reindex is left *in* [`Self::open`] (never dropped on failure --
    /// see [`Self::close_file`]'s own doc comment) so a later call --
    /// another `close_all_files`, or a direct [`Self::close`] once whatever
    /// blocked it clears -- can retry exactly that file and no others.
    ///
    /// Returns how many files closed successfully. Idempotent on the
    /// all-clear path: called again with nothing left open, it returns
    /// `Ok(0)`.
    ///
    /// # Errors
    /// If any block in the sweep refused to close or failed to reindex,
    /// this returns the *first* such error -- after every other block has
    /// already been attempted, not instead of attempting them.
    pub fn close_all_files(&mut self) -> Result<usize, BtvError> {
        let mut closed = 0;
        let mut first_err: Option<BtvError> = None;
        let mut index = 0;
        while index < self.open.len() {
            match self.close_file(index) {
                // Closed and removed from `self.open` -- the next block has
                // shifted into this same index, so stay here rather than
                // advance past it.
                Ok(_) => closed += 1,
                // `close_file` leaves a failing block in place, so advance
                // past it explicitly -- otherwise the same refusal would
                // repeat forever and the sweep would never reach anything
                // after it.
                Err(e) => {
                    first_err.get_or_insert(e);
                    index += 1;
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(closed),
        }
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
    pub fn take_lock(&mut self, at: M::Ptr, lock: i16) -> Result<(), String> {
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
    pub fn lock_at_current(&self, at: M::Ptr) -> Result<Option<i16>, String> {
        let index = self.find(at)?;
        Ok(self.open[index].lock_at_current(&self.locks))
    }

    /// Release the lock this session holds at `at`'s current position --
    /// Btrieve op 27, Unlock, with `keynum = 0` and no data. Always
    /// succeeds; see [`ops::Block::unlock`].
    ///
    /// # Errors
    /// If `at` names no open file.
    pub fn unlock_current(&mut self, at: M::Ptr) -> Result<(), String> {
        let index = self.find(at)?;
        self.open[index].unlock(&mut self.locks);
        Ok(())
    }

    /// Release the lock this session holds at an explicit file position --
    /// Btrieve op 27 with `keynum = -1`, `unlbtv`'s `ulmbtv`/`ulobtv`
    /// flavour (`BTVSTF.H:126-127`: `unlbtv(absbtv(),-1)` /
    /// `unlbtv((f),-1)`). Always succeeds, for the identical reason
    /// [`Self::unlock_current`] does: releasing a position that was never
    /// locked is a no-op, not an error.
    ///
    /// # Errors
    /// If `at` names no open file.
    pub fn unlock_at(&mut self, at: M::Ptr, position: u32) -> Result<(), String> {
        let index = self.find(at)?;
        self.locks.release_at(self.open[index].id(), position);
        Ok(())
    }

    /// Release every lock this session holds on `at` -- Btrieve op 27 with
    /// `keynum = -2`, `unlbtv`'s `ulabtv` flavour (`BTVSTF.H:128`:
    /// `unlbtv(NULL,-2)`). The same operation [`Self::close`] already
    /// performs on every file it closes; this is the module-callable form of
    /// it, on a file that stays open.
    ///
    /// # Errors
    /// If `at` names no open file.
    pub fn unlock_all(&mut self, at: M::Ptr) -> Result<(), String> {
        let index = self.find(at)?;
        self.locks.release_all_for(self.open[index].id());
        Ok(())
    }

    fn find(&self, at: M::Ptr) -> Result<usize, String> {
        self.open
            .iter()
            .position(|b| b.block == at)
            .ok_or_else(|| format!("{at:?} is not an open Btrieve file"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Flat, FlatHeap, FlatMem, FlatPtr};

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
        let f = Layout::new(4, BlockAbi::Packed16);
        assert_eq!(f.posblk, 0);
        assert_eq!(f.filnam, 128);
        assert_eq!(f.reclen, 132);
        assert_eq!(f.key, 134);
        assert_eq!(f.data, 138);
        assert_eq!(f.lastkn, 142);
        assert_eq!(f.keylns, 144);
        assert_eq!(f.keylns_end, 192, "the first of the two PHARLAP fields");
        assert_eq!(f.size, 196);
    }

    /// `DFAAPI.H:119-129`, the `GCWINNT` branch -- the layout MajorMUD-NT is
    /// compiled against, and the one this host got wrong until the boot
    /// described below.
    ///
    ///
    /// `reclen` is `USHORT`, so a 32-bit compiler pads two bytes before
    /// `key` to put the pointer back on a four-byte boundary. **Every offset
    /// from `key` on is therefore two higher than the 16-bit layout above**,
    /// and `data` -- the field modules read directly -- lands at `0x8c`.
    ///
    /// # Measured, not derived
    ///
    /// Serving the packed layout to a 32-bit module stopped MajorMUD-NT's
    /// init at `wccmmud.dll` RVA `0x60336`, which is
    /// `strcpy(dst, dfa->data)` against the `DFAFILE *` global at
    /// `ds:0x47914c`. Reading a dword at `0x8c` of a block whose `data` sits
    /// at `0x8a` returns the *high half* of that pointer with `lastkn`'s two
    /// zero bytes above it -- a 32-bit heap pointer of `0x40809b8e` reads
    /// back as `0x00004080`:
    ///
    /// ```text
    /// cw3220mt.DLL.strcpy refused: 1 bytes at 0x00004080 runs past the end
    /// of the image
    /// ```
    ///
    /// The low half changed every run with the arena's base and the high
    /// half did not, which is what identified it as a pointer read two bytes
    /// off rather than a corrupt one.
    #[test]
    fn the_32_bit_block_is_laid_out_the_way_dfaapi_hs_gcwinnt_branch_declares_it() {
        let f = Layout::new(4, BlockAbi::WinNt32);
        assert_eq!(f.posblk, 0x00);
        assert_eq!(f.filnam, 0x80);
        assert_eq!(f.reclen, 0x84);
        assert_eq!(f.key, 0x88, "two bytes of padding sit between these");
        assert_eq!(f.data, 0x8c, "the offset MajorMUD-NT reads directly");
        assert_eq!(f.lastkn, 0x90);
        assert_eq!(f.keylns, 0x92);
        assert_eq!(f.keylns_end, 0xc2);
        // flddefList realigns to 0xc4, runs 24*4 to 0x124, then
        // unpackKeySiz runs 24*2 to 0x154.
        assert_eq!(f.size, 0x154);
    }

    /// The two layouts agree on everything up to `reclen` and on nothing
    /// after it. Stated as its own assertion because the whole defect was
    /// the assumption that they agreed throughout -- a reader who changes
    /// one of the two tests above should be made to notice the other.
    #[test]
    fn the_two_layouts_diverge_at_key_and_not_before() {
        let packed = Layout::new(4, BlockAbi::Packed16);
        let winnt = Layout::new(4, BlockAbi::WinNt32);

        assert_eq!(packed.posblk, winnt.posblk);
        assert_eq!(packed.filnam, winnt.filnam);
        assert_eq!(packed.reclen, winnt.reclen);

        assert_eq!(winnt.key - packed.key, 2);
        assert_eq!(winnt.data - packed.data, 2);
        assert_eq!(winnt.lastkn - packed.lastkn, 2);
        assert_ne!(packed.size, winnt.size);
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
        let parsed = keys::parse("DUPKEY30.DAT", &fcr, geometry.keys, &[]).expect("keys");

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
        let parsed = keys::parse("DUPKEY30.DAT", &fcr, geometry.keys, &[]).expect("keys");
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
    /// Closing a v6 file this host inserted into must not run a v5-shaped
    /// reindex over it.
    ///
    /// Found by booting The Rose 3.0NT (PE32), which got all the way through
    /// init and then stopped on:
    ///
    /// ```text
    /// dfaclose: rci_univ.dat: key 0: root page 2147483649 is not inside a 8-page file
    /// ```
    ///
    /// `2147483649` is `0x8000_0001` — a v6 key root, which encodes
    /// `0x8000_0000 | logical_id` rather than a page number ([`Block::insert_v6`]
    /// strips exactly that bit). `Btrieve::close` reindexes any block whose
    /// `dirty` flag is set, `insert_v6` sets it, and [`Block::reindex`] read
    /// that root as a literal page and bounds-checked it against the file —
    /// a check no v6 file can ever pass.
    ///
    /// **The refusal was the good outcome.** Had the bounds check not been
    /// there, `pages::walk` would have followed `0x8000_0001` as a physical
    /// page number into a file that has eight, and the rebuilt index would
    /// have been written over whatever it landed on. This is the same shape
    /// as the trap `docs/2026-08-15-btrieve-v5-v6-divergence.md` closes with:
    /// a v5 rule applied to a v6 file addresses a real page and produces a
    /// plausible wrong answer.
    #[test]
    fn a_v6_insert_survives_the_close_that_would_reindex_a_v5_file() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/btrieve-oracle/fixtures/V6EMPTY1KEY.DAT");
        let dir = crate::testing::scratch("btv-v6-reindex");
        let path = dir.join("V6EMPTY1KEY.DAT");
        std::fs::copy(&fixture, &path).expect("copy fixture");

        let mut block = block(path.clone());
        block.name = "V6EMPTY1KEY.DAT".to_owned();
        block.geometry = Geometry::read("V6EMPTY1KEY.DAT", &path).expect("reads");
        let fcr = std::fs::read(&path).expect("readable");
        block.keys = keys::parse("V6EMPTY1KEY.DAT", &fcr, block.geometry.keys, &[]).expect("keys");
        block.maxlen = block.geometry.reclen;

        let mut bytes = vec![0u8; usize::from(block.geometry.reclen)];
        bytes[..4].copy_from_slice(b"ABCD");
        let position = block.insert(&bytes).expect("a v6 insert");
        assert!(block.dirty(), "the insert wrote, so the block is dirty");

        // This is what `Btrieve::close` does with a dirty block, and what The
        // Rose's boot died on.
        block.reindex().expect("closing a v6 file must not run a v5 reindex over it");
        assert!(!block.dirty(), "reindex clears the flag either way");

        // And the index `insert_v6` built has to still be there afterwards --
        // a `reindex` that "succeeded" by doing something destructive would
        // pass the line above and fail here.
        let file = std::fs::read(&path).expect("readable");
        let page_size = block.geometry.page;
        let map = v6::Map::read(&mut v6::Store::from_bytes(&file, page_size).expect("test fixture"), page_size).expect("the allocation table");
        let key = &block.keys[0];
        let definition = pages::fcr::KEYS + usize::from(key.definition) * pages::fcr::KEY_WIDTH;
        let root_at = definition + pages::fcr::KEY_ROOT;
        let raw_root = pages::long(&file[root_at..root_at + 4]);
        assert_eq!(
            raw_root & 0x8000_0000,
            0x8000_0000,
            "the v6 marker bit must survive the close"
        );
        let root_physical = map
            .physical(raw_root & pages::fcr::ROOT_PAGE)
            .expect("the root is a claimed logical page");
        let start = root_physical as usize * usize::from(page_size);
        let index = pages::decode_index_page(&file[start..start + usize::from(page_size)], key.shape())
            .expect("the root index page");
        assert!(
            index.entries.iter().any(|(_, head, _)| *head == position),
            "the index must still point at the record after the close"
        );
    }

    /// Task 8 of `docs/plans/2026-08-15-host-api-surface-track-b.md`: is
    /// `version()`'s `3..=5` range real, or is v3 read with v5 rules?
    ///
    /// It was the one range in this file whose only authority was a
    /// transcription — [`version`]'s own comment conceded it was copied from
    /// MBBSEmu, "the only independent transcription there is". That is now
    /// measured instead, and the answer is that **v3 is not theoretical**:
    /// six distinct files carry byte 7 == 3, and they are MajorBBS's own core
    /// host files (`USRACC.DAT` is the user accounts file). A census of 849
    /// `.DAT`/`.VIR` files across the whole repository found 564 v6, 191 with
    /// byte 7 == 4, these 6 with byte 7 == 3 (each present twice, under
    /// `archive/modules/majorbbs` and `archive/galacticomm/hosts/majorbbs`),
    /// and **not one with byte 7 == 5**.
    ///
    /// The engine confirms byte 7 is the version, independently of the byte:
    /// genuine Btrieve 6.15's own `stat` returns an index word whose high
    /// nibble is the file version — `0x3001` for these, `0x4001` for a
    /// byte-7 == 4 file, `0x6001` for a v6 one. That comes back through the
    /// Btrieve API rather than from the header, so it is a second, agreeing
    /// source rather than the same byte read twice.
    ///
    /// The numbers asserted below are the genuine engine's, taken from
    /// `btrvprobe.exe stat` (and `walk 0` for `USRACC.DAT`, which reports
    /// WALK OK over 2 records). So this is a cross-version acceptance test,
    /// not a self-consistency one.
    ///
    /// `archive/` is gitignored, so this degrades to a skip rather than a
    /// failure in a checkout without it — the same shape
    /// `crates/mbbs-machine/tests/m16_rose.rs` uses. The files are copied to
    /// scratch before being opened: this crate's rule is that no engine of
    /// ours writes to a shipped `.DAT`, and the cheapest way to keep it is to
    /// never hand the shipped path to anything.
    #[test]
    fn a_v3_file_reads_with_the_geometry_the_genuine_engine_reports() {
        let from = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../archive/galacticomm/hosts/majorbbs");
        if !from.exists() {
            eprintln!("skipped: archive/galacticomm/hosts/majorbbs is not in this checkout");
            return;
        }
        let dir = crate::testing::scratch("btv-v3-geometry");

        // (file, reclen, page size, keys, records, key descriptors parse) --
        // every number from `btrvprobe.exe stat` against genuine Btrieve 6.15.
        //
        // **Two of the three refuse at the key descriptors, and not for a
        // version reason** -- pinned rather than skipped, because the
        // distinction is the whole point. `EMAIL.DAT` and `CLASSADS.DAT` each
        // declare a key with a **numbered alternate collating sequence**,
        // which this host refuses outright ("changes what its index holds and
        // is not reproduced by sorting the records") rather than guessing at a
        // collation it does not have. Their geometry decodes perfectly; the
        // refusal would fire identically on a v5 file declaring an ACS.
        //
        // That is a real gap in its own right, and worth knowing where it
        // bites: ACS is not an exotic corner, it is what MajorBBS's own core
        // host files use. It is a *collation* gap, not a *version* gap, and
        // nothing about supporting v3 would move it.
        for (name, reclen, page, keys, records, parses) in [
            ("USRACC.DAT", 252u16, 512u16, 1u16, 2usize, true),
            ("EMAIL.DAT", 1000, 1024, 3, 0, false),
            ("CLASSADS.DAT", 402, 512, 2, 0, false),
        ] {
            let path = dir.join(name);
            std::fs::copy(from.join(name), &path).expect("copy the fixture out of archive/");

            let geometry = Geometry::read(name, &path).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(geometry.version, Version::V5, "{name}: byte 7 == 3 is the v5 family");
            assert_eq!(geometry.reclen, reclen, "{name}: record length");
            assert_eq!(geometry.page, page, "{name}: page size");
            assert_eq!(geometry.keys, keys, "{name}: key count");
            assert_eq!(geometry.records, records as u32, "{name}: record count");

            // Read the records too, not just the header -- a header that
            // decodes at the right offsets proves nothing about whether the
            // data pages are laid out where this host expects them.
            let fcr = std::fs::read(&path).expect("readable");
            let parsed = keys::parse(name, &fcr, geometry.keys, &[]);
            if !parses {
                let why = parsed.expect_err("EMAIL.DAT's ACS key must refuse").why;
                assert!(
                    why.contains("alternate collating sequence"),
                    "{name}: must refuse for the ACS, not something else: {why}"
                );
                continue;
            }

            let mut block = block(path.clone());
            block.name = name.to_owned();
            block.geometry = geometry;
            block.keys = parsed.unwrap_or_else(|e| panic!("{name}: {e}"));
            block.maxlen = geometry.reclen;
            assert_eq!(
                block.records().unwrap_or_else(|e| panic!("{name}: {e}")).len(),
                records,
                "{name}: records read back"
            );
        }
    }

    fn block(path: PathBuf) -> Block<Flat> {
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
            modifiable: true,
            chain: None,
                    acs: None,
                    null: None,
}];
        Block {
            id: ops::BlockId::fresh(),
            name: "SCRATCH.DAT".to_owned(),
            path,
            geometry,
            keys,
            block: FlatPtr::NULL,
            maxlen: 16,
            data: FlatPtr::NULL,
            key: FlatPtr::NULL,
            records: None,
            cursor: Cursor::Nowhere,
            dirty: false,
            txn_active: false,
            pre_image: None,
            // A test-only fixture, not `Self::open` -- see
            // `Self::verify_writes`'s doc comment for why this stays off.
            verify_writes: false,
            // Same reasoning: a test-only fixture never goes through
            // `Self::open`, the only place that captures a mode at all.
            mode: PRIMBV,
            // Same reasoning: a test-only fixture never goes through
            // `Self::open`, the only place that builds one.
            cache: None,
            v6_order: std::cell::RefCell::new(std::collections::HashMap::new()),
            v6_physical: std::cell::RefCell::new(None),
        }
    }

    /// A 16-byte record whose two-byte key is `n`.
    fn record(n: u16) -> Vec<u8> {
        let mut bytes = vec![0u8; 16];
        bytes[..2].copy_from_slice(&n.to_le_bytes());
        bytes
    }

    /// Updating a v6 file whose key permits duplicates succeeds, and an
    /// update that moves no record between duplicate groups writes no chain
    /// pages.
    ///
    /// **This used to assert the opposite: that every write to such a file
    /// was refused, insert, update and delete alike.** It is not, and has
    /// not been since duplicate chains were made v6-aware --
    /// [`Block::v6_reindex`]/[`Block::v6_write_chains`] build them, shared
    /// by [`Block::insert_v6`], [`Block::update_v6`] and
    /// [`Block::delete_v6`] alike (see `insert_v6`'s own doc comment), and
    /// none of the three refuses a duplicate-permitting key any more. This
    /// comment said otherwise for longer than it should have: the test
    /// body beneath it has asserted a *successful* update
    /// (`.expect("an update off the key")`) the whole time, and its sibling
    /// below, [`insert_extends_a_v6_duplicate_keys_chain_rather_than_
    /// refusing`], says as much by name. What this test actually checks is
    /// a cost bound, not a refusal: an update that does not move a record
    /// between duplicate groups should not pay for a chain-page relocation
    /// it did not need.
    ///
    /// The history worth keeping: until Task 5 the write path was v6-safe
    /// only by accident, because `Records::read` refused every v6 file and
    /// every write calls it first. Task 5 lifted that for reads and left the
    /// writes behind it un-guarded, while `pages::write_record` seeks a
    /// record's `position` as a literal byte offset and a v6 position carries
    /// a **logical** page id. On `DUPKEY30.DAT` logical 2 is physical 10, so
    /// an update would have written over a different page entirely and
    /// reported success. That is what the v6 paths exist to prevent.
    ///
    /// `Block::v6_write_chains` recomputes every duplicate-permitting key's
    /// `[prev][next]` pairs on every write, which is cheap, and then relocated
    /// every data page holding one, which is not: those are data pages, so
    /// each needless relocation spends a shadow twin as well as a page write.
    /// `Block::v6_reindex`'s index loop has always skipped a node whose image
    /// already matches; this is the same skip, one loop further on.
    ///
    /// `DUPKEY30.DAT` is genuine Btrieve 6.15's own -- 30 records, 10 values,
    /// three records per value, 512-byte pages -- so an update that changes a
    /// non-key byte moves no record between groups and every chain pair it
    /// computes is already on the disk.
    #[test]
    fn an_update_that_moves_no_duplicate_writes_no_chain_pages() {
        let dir = crate::testing::scratch("v6-duplicate-chain-diff");
        let path = dir.join("DUPKEY30.DAT");
        std::fs::copy(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tools/btrieve-oracle/fixtures/DUPKEY30.DAT"),
            &path,
        )
        .expect("the fixture copies into a scratch directory");

        let mut block = block_from_file(path, "DUPKEY30.DAT");
        assert!(block.keys.iter().any(|k| k.duplicates), "its key permits duplicates");
        let page = usize::from(block.geometry.page);

        let found = block
            .records()
            .expect("v6 reads")
            .physical(0)
            .expect("a first record");
        let (position, mut bytes) = (found.position, found.bytes.to_vec());
        let last = bytes.len() - 1;
        bytes[last] = 0x5c;

        // One warm-up, so the shadow twins this file needs already exist and
        // what is measured is the steady state a running board writes.
        block.update(position, &bytes).expect("a warm-up update");
        bytes[last] = 0x5d;

        WROTE.with(|wrote| wrote.set(0));
        block.update(position, &bytes).expect("an update off the key");
        let wrote = WROTE.with(std::cell::Cell::get);

        // The record's own data page, the allocation-table half that names
        // it, the control record half, and the two-byte generation words. A
        // chain page relocated for nothing would be one more page than that.
        assert!(
            wrote <= 3 * page + 4,
            "an update that moved no duplicate wrote {wrote} bytes, which is \
             more than the three pages and two generation words it needs"
        );
    }

    /// A record inserted into a v6 file whose key permits duplicates, joining
    /// a value that already has records under it.
    ///
    /// **This test used to assert the opposite**, and drove its writes at
    /// `tools/btrieve-oracle/fixtures/DUPKEY30.DAT` *in place* -- safe only
    /// for as long as every one of those writes refused. The moment insert
    /// started working it rewrote a committed fixture and took an unrelated
    /// `v6::tests` case down with it. It works on a scratch copy now, and no
    /// test should ever again point a write at a path under `fixtures/`.
    ///
    /// `DUPKEY30.DAT` is genuine Btrieve 6.15's own: 30 records, 10 distinct
    /// values, three records per value. Inserting a 31st under an existing
    /// value has to extend that value's chain and move its index entry's
    /// tail, without disturbing the other nine groups.
    #[test]
    fn insert_extends_a_v6_duplicate_keys_chain_rather_than_refusing() {
        let dir = crate::testing::scratch("v6-duplicate-insert");
        let path = dir.join("DUPKEY30.DAT");
        std::fs::copy(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tools/btrieve-oracle/fixtures/DUPKEY30.DAT"),
            &path,
        )
        .expect("the fixture copies into a scratch directory");

        let mut block = block_from_file(path.clone(), "DUPKEY30.DAT");
        assert!(block.keys.iter().any(|k| k.duplicates), "its key permits duplicates");
        assert_eq!(block.records().expect("v6 reads").len(), 30);

        // A record carrying the same key bytes as the file's first record, so
        // it must join that value's existing group rather than start one.
        let first = block.records().expect("read").physical(0).expect("a record").bytes.clone();
        let mut bytes = first.clone();
        // Leave the key alone; change a byte that is not part of it so the
        // record is distinguishable.
        let last = bytes.len() - 1;
        bytes[last] = 0x5b;

        block.insert(&bytes).expect("a duplicate value is a chain to extend, not a refusal");

        let dup = block
            .keys
            .iter()
            .find(|k| k.duplicates)
            .expect("this file has a duplicate-permitting key")
            .clone();
        let number = dup.number;
        let offset = usize::from(dup.chain.expect("the key names its chain offset"));

        let geometry = block.geometry;
        block.records = None;
        let after = block.records().expect("a fresh read from disk");
        assert_eq!(after.len(), 31, "the record went in");

        let shift = after.key_shift();

        // The chain lives on the page, not in the model -- `Record::bytes`
        // carries `reclen` bytes and the pair sits past them -- so this reads
        // the slots back off the disk, resolving each record's LOGICAL page
        // through the allocation table exactly as the writer had to.
        let whole = std::fs::read(&path).expect("the file reads");
        let page_size = geometry.page;
        let map = v6::Map::read(&mut v6::Store::from_bytes(&whole, page_size).expect("test fixture"), page_size).expect("its allocation table reads");
        let layout = pages::Layout {
            page: page_size,
            physical: geometry.physical,
            pages: geometry.pages,
        };
        let pair_at = |position: u32| -> [u32; 2] {
            let (logical, slot) = layout.slot_of(position).expect("a slot boundary");
            let physical = map.physical(logical).expect("a live page");
            let at = usize::from(page_size) * physical as usize
                + layout.position(0, slot) as usize
                + offset;
            [
                pages::long(&whole[at..at + 4]),
                pages::long(&whole[at + 4..at + 8]),
            ]
        };

        // The groups the chain is supposed to describe, in the order this
        // key puts the records in -- which is the order the writer walked
        // when it built them.
        let mut groups: Vec<Vec<u32>> = Vec::new();
        for n in 0..after.ordered_len(number).expect("ordered by this key") {
            let record = after.ordered(number, n).expect("in range");
            let joins = n > 0
                && dup.compare(
                    &records::keyed(shift, &after.ordered(number, n - 1).expect("in range").bytes),
                    &records::keyed(shift, &record.bytes),
                ) == std::cmp::Ordering::Equal;
            if joins {
                groups.last_mut().expect("a group").push(record.position);
            } else {
                groups.push(vec![record.position]);
            }
        }
        assert!(
            groups.iter().any(|g| g.len() > 1),
            "a file of 31 records over 10 values has groups to chain"
        );

        // Walking `next` from each group's head must reproduce the group, in
        // order. Checking only that the links agree with each other is not
        // enough: swapping `prev` and `next` everywhere gives a consistently
        // mirrored list that satisfies any symmetric check, and did.
        for group in &groups {
            let [prev, _] = pair_at(group[0]);
            assert_eq!(
                prev,
                pages::NOWHERE,
                "the first record of a group has nothing before it"
            );
            let mut walked = vec![group[0]];
            let mut at = group[0];
            while walked.len() <= group.len() {
                let [_, next] = pair_at(at);
                if next == pages::NOWHERE {
                    break;
                }
                assert!(
                    after.find_physical(next).is_some(),
                    "record at {at} names {next}, which is not a record"
                );
                walked.push(next);
                at = next;
            }
            assert_eq!(
                walked, *group,
                "following `next` must reproduce the group in key order"
            );

            // And every member points back at the one before it. Checking
            // only the head's `prev` and then walking forward leaves a writer
            // that puts NOWHERE in every `prev` indistinguishable from a
            // correct one -- genuine 6.15 writes real back-links, measured in
            // `docs/2026-08-17-v6-duplicate-key-oracle.md`.
            for (at, position) in group.iter().enumerate() {
                let [prev, _] = pair_at(*position);
                let expected = if at == 0 { pages::NOWHERE } else { group[at - 1] };
                assert_eq!(
                    prev, expected,
                    "record {at} of a group of {} must name the one before it",
                    group.len()
                );
            }
        }
    }

    /// A v6 `Block` over a scratch copy of `V6EMPTY1KEY.DAT` -- genuine
    /// Btrieve 6.15's own empty one-key file (`crtprobe.exe create`) -- with
    /// `records` already loaded. `reclen` is 20, `physical` 22, page 512.
    fn v6_scratch(scratch: &str) -> (Block<Flat>, std::path::PathBuf) {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/btrieve-oracle/fixtures/V6EMPTY1KEY.DAT");
        let dir = crate::testing::scratch(scratch);
        let path = dir.join("V6EMPTY1KEY.DAT");
        std::fs::copy(&fixture, &path).expect("copy fixture");

        let mut block = block(path.clone());
        block.name = "V6EMPTY1KEY.DAT".to_owned();
        block.geometry = Geometry::read("V6EMPTY1KEY.DAT", &path).expect("reads");
        let fcr = std::fs::read(&path).expect("readable");
        block.keys = keys::parse("V6EMPTY1KEY.DAT", &fcr, block.geometry.keys, &[]).expect("keys");
        block.maxlen = block.geometry.reclen;
        block.records().expect("v6 reads");
        (block, path)
    }

    /// The record at a file position, or `None` if nothing is there.
    ///
    /// `Records::find_physical` answers with an *index into physical order*,
    /// not a record; every caller below wants the record.
    fn at_position(records: &Records, position: u32) -> Option<&Record> {
        records.physical(records.find_physical(position)?)
    }

    /// A 20-byte record whose first four bytes -- the key -- are `key`, and
    /// whose remaining sixteen are `0xEE`.
    ///
    /// **The filler is not decoration.** With a zero tail, a delete that only
    /// zeroed the slot's marker and wrote the forwarding link -- leaving the
    /// record's own bytes behind it intact -- passed
    /// `a_v6_delete_threads_the_freed_slot_onto_the_free_list` unchanged,
    /// because the bytes it failed to clear were zero already. Measured, by
    /// mutation. A byte that is never anything but zero cannot tell "cleared"
    /// from "never written".
    fn v6_record(key: &[u8; 4]) -> Vec<u8> {
        let mut bytes = vec![0xEEu8; 20];
        bytes[..4].copy_from_slice(key);
        bytes
    }

    /// Which physical page holds a key's root index, resolved the way the
    /// engine does: the file control record's `KEY_ROOT`, v6 marker bit
    /// stripped, through the `"PP"` allocation table.
    fn v6_root_physical(block: &Block<Flat>, file: &[u8]) -> u32 {
        let key = &block.keys[0];
        let definition = pages::fcr::KEYS + usize::from(key.definition) * pages::fcr::KEY_WIDTH;
        let raw_root = pages::long(&file[definition + pages::fcr::KEY_ROOT..][..4]);
        let mut store = v6::Store::from_bytes(file, block.geometry.page).expect("test fixture");
        let map = v6::Map::read(&mut store, block.geometry.page).expect("the allocation table");
        map.physical(raw_root & pages::fcr::ROOT_PAGE)
            .expect("the key's root is a claimed logical page")
    }

    /// The live half of the file control record's shadow pair.
    fn v6_fcr(block: &Block<Flat>, file: &[u8]) -> Vec<u8> {
        let mut store = v6::Store::from_bytes(file, block.geometry.page).expect("test fixture");
        block.v6_live_fcr(&mut store).expect("a live control record")
    }

    /// An update that changes the value of a key the file declares
    /// non-modifiable is refused, and writes nothing.
    ///
    /// Genuine Btrieve 6.15 answers status 10 to this and writes nothing --
    /// measured by creating the same file twice, once with key attributes
    /// `0x0100` and once with `0x0102`, and running the same key-changing
    /// update against both (`delprobe create` vs `create_mod`). Forty-three of
    /// the seventy-six key definitions in this repository's real files are
    /// non-modifiable, `WCCUSERS.DAT` key 0 among them.
    #[test]
    fn an_update_that_changes_a_non_modifiable_keys_value_is_refused() {
        let dir = crate::testing::scratch("block-unmodifiable-key");
        let path = seed(&dir);
        let mut block = block(path.clone());

        let position = block.insert(&record(1)).expect("insert");
        block.keys[0].modifiable = false;
        let before = std::fs::read(&path).expect("readable");

        let e = block
            .update(position, &record(9))
            .expect_err("changing a non-modifiable key is refused");
        assert!(e.why.contains("does not declare itself modifiable"), "{e}");
        assert!(e.why.contains("status 10"), "the refusal names what Btrieve answers: {e}");

        assert_eq!(
            std::fs::read(&path).expect("readable"),
            before,
            "a refused update writes nothing"
        );
        assert_eq!(
            at_position(block.records().expect("loaded"), position)
                .expect("still there")
                .bytes,
            record(1),
            "and leaves the model alone too"
        );
    }

    /// The same key, the same file, an update that leaves the key's value
    /// where it was: allowed.
    ///
    /// Measured (`delprobe modsame`): rewriting a non-modifiable key with the
    /// value it already holds answers status 0. Btrieve refuses a *change*,
    /// not a touch -- and a host that refused every update to a file with a
    /// non-modifiable key would break almost every write MajorMUD makes.
    #[test]
    fn an_update_that_leaves_a_non_modifiable_keys_value_alone_is_written() {
        let dir = crate::testing::scratch("block-unmodifiable-key-untouched");
        let path = seed(&dir);
        let mut block = block(path);

        let position = block.insert(&record(1)).expect("insert");
        block.keys[0].modifiable = false;

        let mut changed = record(1);
        changed[8..12].copy_from_slice(b"body");
        block.update(position, &changed).expect("the key did not move");

        block.records = None;
        assert_eq!(
            at_position(block.records().expect("re-reads"), position)
                .expect("still there")
                .bytes,
            changed
        );
    }

    /// A text key's bytes past its NUL terminator are not part of its value,
    /// so changing them is not a change.
    ///
    /// Measured, and the reason the check is [`Key::compare`] rather than a
    /// byte comparison of the key field: a `Zstring` key holding `AB\0` and
    /// five `0xAA`, on a **non-modifiable** key, updated so only those five
    /// trailing bytes move -- genuine 6.15 answers status 0 and commits the
    /// new bytes (`delprobe modtail`). A byte comparison here would refuse a
    /// write the real engine performs, on a file MajorMUD ships: every one of
    /// its text keys is a `Zstring` inside a fixed-width field.
    #[test]
    fn a_text_keys_bytes_past_its_terminator_are_not_part_of_its_value() {
        let dir = crate::testing::scratch("block-unmodifiable-text-key");
        let path = seed(&dir);
        let mut block = block(path);
        block.keys = vec![Key {
            number: 0,
            definition: 0,
            segments: vec![keys::Segment {
                offset: 0,
                length: 8,
                kind: keys::Kind::Text,
                descending: false,
            }],
            duplicates: false,
            modifiable: false,
            chain: None,
                    acs: None,
                    null: None,
}];

        let mut before = vec![0u8; 16];
        before[..3].copy_from_slice(b"AB\0");
        before[3..8].fill(0xAA);

        let mut tail = before.clone();
        tail[3..8].fill(0xBB);
        assert_eq!(
            block.unmodifiable_key_changed(&before, &tail),
            None,
            "the bytes after the terminator are not the value"
        );

        let mut value = before.clone();
        value[1] = b'C';
        assert_eq!(
            block.unmodifiable_key_changed(&before, &value),
            Some(0),
            "and the bytes before it are"
        );
    }

    /// v6 inserts pack: consecutive records land in consecutive slots of one
    /// page, and the file does not grow a page per record.
    ///
    /// `V6EMPTY1KEY.DAT` is 512-byte pages of 22-byte slots, so 23 records
    /// fit one page. Before this, each insert claimed its own page and the
    /// file grew by 512 bytes every time -- format-valid, and 23 times the
    /// size the engine would have written.
    #[test]
    fn v6_inserts_pack_into_one_page_rather_than_a_page_each() {
        let (mut block, path) = v6_scratch("btv-v6-pack");
        let before = std::fs::metadata(&path).expect("readable").len();

        let layout = pages::Layout {
            page: block.geometry.page,
            physical: block.geometry.physical,
            pages: block.geometry.pages,
        };
        let keys: [&[u8; 4]; 4] = [b"AAAA", b"BBBB", b"CCCC", b"DDDD"];
        let placed: Vec<(u32, u32)> = keys
            .iter()
            .map(|key| {
                let at = block.insert(&v6_record(key)).expect("insert");
                layout.slot_of(at).expect("a slot boundary")
            })
            .collect();

        let page = placed[0].0;
        assert!(
            placed.iter().all(|&(logical, _)| logical == page),
            "four records, one page: {placed:?}"
        );
        assert_eq!(
            placed.iter().map(|&(_, slot)| slot).collect::<Vec<_>>(),
            vec![0, 1, 2, 3],
            "and consecutive slots of it"
        );

        // Two pages, whatever the record count: one shadow twin for the data
        // page and one for the index root, both claimed on the first write
        // that relocates them and reused by every write after.
        let after = std::fs::metadata(&path).expect("readable").len();
        assert_eq!(
            after - before,
            u64::from(block.geometry.page) * 2,
            "four records cost two pages of twins, not a page each"
        );

        // And the next four cost nothing at all. This is the assertion that
        // fails if `v6::Map::relocate` goes back to appending: it grew by a
        // page per relocation, which is two per record, forever.
        for key in [b"EEEE", b"FFFF", b"GGGG", b"HHHH"] {
            block.insert(&v6_record(key)).expect("insert");
        }
        assert_eq!(
            std::fs::metadata(&path).expect("readable").len(),
            after,
            "a record that fits an already-claimed page grows the file by nothing"
        );

        block.records = None;
        assert_eq!(block.records().expect("re-reads").len(), 8);
    }

    /// Filling a page past its capacity claims a second one, threads it, and
    /// keeps inserting into it.
    ///
    /// **This is the only test that reaches
    /// [`Block::v6_claim_threaded_page`] at all.** `V6EMPTY1KEY.DAT` arrives
    /// from genuine Btrieve with a free list already covering its one data
    /// page's 23 slots, so every insert up to the 23rd pops that list and the
    /// claim path is never entered. Found by mutation: gutting the threading
    /// loop entirely left the whole suite green.
    ///
    /// The 24th record is the first that has to claim. The **26th** is what
    /// proves the claimed page was *threaded*: the 25th is placed at slot 1,
    /// which `v6_claim_threaded_page` also computes arithmetically when it
    /// sets the new head, so a claim that threads nothing still gets that far
    /// -- measured, by mutation, on the version of this test that stopped at
    /// 25 records. Only slot 2 has to come out of a link written on disk.
    #[test]
    fn a_v6_insert_past_a_full_page_claims_and_threads_another() {
        let (mut block, _path) = v6_scratch("btv-v6-second-page");
        let layout = pages::Layout {
            page: block.geometry.page,
            physical: block.geometry.physical,
            pages: block.geometry.pages,
        };
        let per_page = layout.per_page();
        assert_eq!(per_page, 23, "this fixture's page holds 23 slots");

        let mut placed = Vec::new();
        for n in 0..per_page + 3 {
            let key = [
                b'A' + (n / 26) as u8,
                b'A' + (n % 26) as u8,
                b'0',
                b'0',
            ];
            let at = block.insert(&v6_record(&key)).expect("insert");
            placed.push(layout.slot_of(at).expect("a slot boundary"));
        }

        let first_page = placed[0].0;
        assert!(
            placed[..per_page as usize].iter().all(|&(page, _)| page == first_page),
            "the first {per_page} records fill one page: {placed:?}"
        );
        let second_page = placed[per_page as usize].0;
        assert_ne!(second_page, first_page, "the 24th record needs a new page");
        assert_eq!(
            placed[per_page as usize],
            (second_page, 0),
            "and lands in its first slot"
        );
        assert_eq!(
            placed[per_page as usize + 1],
            (second_page, 1),
            "the 25th follows it"
        );
        assert_eq!(
            placed[per_page as usize + 2],
            (second_page, 2),
            "and the 26th is the one that proves the claimed page was THREADED: \
             slot 1's own body is the only place the position of slot 2 is \
             written down, so a claim that placed slot 1 by arithmetic and \
             threaded nothing gets here with a free-list head of zero"
        );

        block.records = None;
        assert_eq!(
            block.records().expect("re-reads both pages").len(),
            (per_page + 3) as usize
        );
    }

    /// The slot a delete frees is the slot the next insert takes.
    ///
    /// The two halves of one mechanism, which is the whole reason the free
    /// list is maintained at all rather than merely written. Until insert
    /// popped the head, a delete's freed slot was leaked forever and this
    /// test's second record would have landed somewhere else entirely.
    #[test]
    fn a_v6_insert_reuses_the_slot_a_delete_freed() {
        let (mut block, _path) = v6_scratch("btv-v6-reuse");

        block.insert(&v6_record(b"AAAA")).expect("first insert");
        let freed = block.insert(&v6_record(b"BBBB")).expect("second insert");
        block.delete(freed).expect("delete the second");

        let reused = block.insert(&v6_record(b"CCCC")).expect("insert after the delete");
        assert_eq!(reused, freed, "the freed slot is where the next record goes");

        block.records = None;
        let reread = block.records().expect("re-reads");
        assert_eq!(reread.len(), 2);
        assert_eq!(at_position(reread, reused).expect("reused").bytes, v6_record(b"CCCC"));
    }

    /// An update of a v6 record rewrites it **in its own slot**, leaving its
    /// position alone, and -- because no key value changed -- does not touch
    /// the index at all.
    ///
    /// Both halves are measured behaviour, not preference
    /// (`docs/2026-08-16-v6-update-delete-oracle.md`). The index half is the
    /// one worth a test: `Self::v6_reindex` decides it by comparing the
    /// rebuilt image against what the file holds, and getting that comparison
    /// wrong costs a page of file growth on every update forever, while every
    /// read-back assertion stays green.
    #[test]
    fn a_v6_update_keeps_the_record_where_it_was_and_leaves_the_index_alone() {
        let (mut block, path) = v6_scratch("btv-v6-update");

        let first = block.insert(&v6_record(b"AAAA")).expect("first insert");
        let second = block.insert(&v6_record(b"BBBB")).expect("second insert");

        let before = std::fs::read(&path).expect("readable");
        let root_before = v6_root_physical(&block, &before);
        let count_before = pages::long(&v6_fcr(&block, &before)[pages::fcr::RECORDS_HIGH..][..4]);

        let mut changed = v6_record(b"BBBB");
        changed[4..8].copy_from_slice(b"body");
        block.update(second, &changed).expect("a v6 update");

        assert_eq!(
            at_position(block.records().expect("loaded"), second).map(|r| r.bytes.clone()),
            Some(changed.clone()),
            "the model holds the new bytes at the same position"
        );

        // The read that matters: a fresh `Records::read` off disk, with
        // nothing carried over in memory.
        block.records = None;
        let reread = block.records().expect("re-reads after the update");
        assert_eq!(reread.len(), 2);
        assert_eq!(at_position(reread, second).expect("still there").bytes, changed);
        assert_eq!(at_position(reread, first).expect("untouched").bytes, v6_record(b"AAAA"));

        let after = std::fs::read(&path).expect("readable");

        // The slot's marker counts updates: 1 when the record was inserted,
        // 2 after this. Zero would mean *free*, which is why it is the one
        // value the increment must never reach.
        let layout = pages::Layout {
            page: block.geometry.page,
            physical: block.geometry.physical,
            pages: block.geometry.pages,
        };
        let (logical, slot) = layout.slot_of(second).expect("a slot boundary");
        let physical = v6::Map::read(&mut v6::Store::from_bytes(&after, block.geometry.page).expect("test fixture"), block.geometry.page)
            .expect("table")
            .physical(logical)
            .expect("claimed");
        let at =
            physical as usize * usize::from(block.geometry.page) + layout.position(0, slot) as usize;
        assert_eq!(
            u16::from_le_bytes([after[at], after[at + 1]]),
            2,
            "the marker counts this record's updates"
        );

        assert_eq!(
            v6_root_physical(&block, &after),
            root_before,
            "no key value changed, so the index root must not have moved"
        );
        assert_eq!(
            pages::long(&v6_fcr(&block, &after)[pages::fcr::RECORDS_HIGH..][..4]),
            count_before,
            "an update does not change the record count"
        );
    }

    /// An update that reorders a key **does** move that key's index root, and
    /// the record still does not move.
    ///
    /// The companion to the test above, and the reason that one is not enough
    /// on its own: a `v6_reindex` that never relocated anything would pass
    /// it. This one fails unless the comparison can also come out *unequal*.
    #[test]
    fn a_v6_update_that_reorders_a_key_relocates_that_keys_root() {
        let (mut block, path) = v6_scratch("btv-v6-update-key");
        // The fixture's key is not modifiable, and `Block::update` refuses a
        // key-changing update on one -- that rule has its own test below. The
        // subject here is index relocation, so the scratch copy is made
        // modifiable and the block re-opened over it.
        crate::testing::make_keys_modifiable(&path);
        block.keys = keys::parse(
            "V6EMPTY1KEY.DAT",
            &std::fs::read(&path).expect("readable"),
            block.geometry.keys,
            &[],
        )
        .expect("keys");

        block.insert(&v6_record(b"AAAA")).expect("first insert");
        let second = block.insert(&v6_record(b"BBBB")).expect("second insert");

        let before = std::fs::read(&path).expect("readable");
        let root_before = v6_root_physical(&block, &before);

        // "BBBB" -> "ZZZZ" keeps this record last; "0000" makes it first.
        block.update(second, &v6_record(b"0000")).expect("a key-changing v6 update");

        let after = std::fs::read(&path).expect("readable");
        assert_ne!(
            v6_root_physical(&block, &after),
            root_before,
            "the key order changed, so the index root must have been rewritten"
        );

        block.records = None;
        let reread = block.records().expect("re-reads");
        assert_eq!(reread.len(), 2);
        assert_eq!(
            at_position(reread, second).expect("same position").bytes,
            v6_record(b"0000"),
            "a v6 update never moves the record, whatever it does to the key"
        );
        assert_eq!(
            reread.ordered(0, 0).expect("first in key order").bytes,
            v6_record(b"0000"),
            "and the model's key order followed the new value"
        );
    }

    /// A v6 delete empties the slot, threads it onto the file's own free list
    /// at `pages::fcr::FREE_V6`, drops the record count, and leaves the page
    /// claimed.
    ///
    /// Every number asserted here was measured against genuine 6.15
    /// (`docs/2026-08-16-v6-update-delete-oracle.md`): the zero marker, the
    /// forwarding link in the freed body, the head moving to the freed slot's
    /// own position, and `pages::fcr::FREE` -- the *v5* offset -- never
    /// moving off `0xffffffff`.
    #[test]
    fn a_v6_delete_threads_the_freed_slot_onto_the_free_list() {
        let (mut block, path) = v6_scratch("btv-v6-delete");

        let first = block.insert(&v6_record(b"AAAA")).expect("first insert");
        let second = block.insert(&v6_record(b"BBBB")).expect("second insert");

        let before = std::fs::read(&path).expect("readable");
        let head_before = pages::long(&v6_fcr(&block, &before)[pages::fcr::FREE_V6..][..4]);
        let claims_before = v6::Map::read(&mut v6::Store::from_bytes(&before, block.geometry.page).expect("test fixture"), block.geometry.page)
            .expect("table")
            .entries()
            .count();

        block.delete(second).expect("a v6 delete");

        let after = std::fs::read(&path).expect("readable");
        let fcr = v6_fcr(&block, &after);

        assert_eq!(
            pages::long(&fcr[pages::fcr::FREE_V6..][..4]),
            second,
            "the free-list head becomes the freed slot's own position"
        );
        assert_eq!(
            pages::long(&fcr[pages::fcr::RECORDS_HIGH..][..4]),
            1,
            "the record count drops by one"
        );
        assert_eq!(
            pages::long(&fcr[pages::fcr::FREE..][..4]),
            0xffff_ffff,
            "the v5 free-list offset is not where a v6 file keeps its head, \
             and writing it would be writing over a field this format uses \
             for something else"
        );
        assert_eq!(
            v6::Map::read(&mut v6::Store::from_bytes(&after, block.geometry.page).expect("test fixture"), block.geometry.page).expect("table").entries().count(),
            claims_before,
            "a v6 delete never unclaims a page, even one it just emptied"
        );

        // The freed slot itself: marker zero, then the previous head as a
        // forwarding link, then nothing.
        let layout = pages::Layout {
            page: block.geometry.page,
            physical: block.geometry.physical,
            pages: block.geometry.pages,
        };
        let (logical, slot) = layout.slot_of(second).expect("a slot boundary");
        let physical = v6::Map::read(&mut v6::Store::from_bytes(&after, block.geometry.page).expect("test fixture"), block.geometry.page)
            .expect("table")
            .physical(logical)
            .expect("still claimed");
        let at = physical as usize * usize::from(block.geometry.page)
            + layout.position(0, slot) as usize;
        assert_eq!(&after[at..at + 2], &[0, 0], "the slot's marker says free");
        assert_eq!(
            pages::long(&after[at + 2..at + 6]),
            head_before,
            "the freed body's first four bytes forward to the previous head"
        );
        assert!(
            after[at + 6..at + usize::from(block.geometry.physical)].iter().all(|&b| b == 0),
            "and everything behind the link is zeroed"
        );

        // And the file still reads as one record, from disk, with the
        // survivor intact -- the freed slot is not mistaken for a record.
        block.records = None;
        let reread = block.records().expect("re-reads after the delete");
        assert_eq!(reread.len(), 1);
        assert_eq!(at_position(reread, first).expect("survivor").bytes, v6_record(b"AAAA"));
        assert!(at_position(reread, second).is_none(), "the deleted record is gone");
    }

    /// Deleting a record from the *middle* of a page leaves the records
    /// behind it readable.
    ///
    /// This is the whole reason `records::walk_v6` had to learn the slot
    /// marker, and it is asserted here as well as there because this is the
    /// path that creates the hole. Without the marker check the walk stops at
    /// the freed slot and the third record silently vanishes.
    ///
    /// It needs three records on **one** page, which `insert_v6` does not
    /// produce -- it claims a fresh page per record -- so the records are
    /// placed by hand into a page this host's own insert claimed, and the
    /// control record's count corrected to match, before the delete runs.
    #[test]
    fn a_v6_delete_from_the_middle_of_a_page_leaves_the_rest_readable() {
        let (mut block, path) = v6_scratch("btv-v6-delete-middle");

        let first = block.insert(&v6_record(b"AAAA")).expect("insert");
        let layout = pages::Layout {
            page: block.geometry.page,
            physical: block.geometry.physical,
            pages: block.geometry.pages,
        };
        let (logical, _) = layout.slot_of(first).expect("a slot boundary");

        // Two more records into slots 1 and 2 of that same page, written
        // straight into the file: marker 1, then the record.
        let mut file = std::fs::read(&path).expect("readable");
        let page_size = usize::from(block.geometry.page);
        let physical = v6::Map::read(&mut v6::Store::from_bytes(&file, block.geometry.page).expect("test fixture"), block.geometry.page)
            .expect("table")
            .physical(logical)
            .expect("claimed") as usize;
        let (second, third) = (layout.position(logical, 1), layout.position(logical, 2));
        for (slot, key) in [(1u32, b"BBBB"), (2u32, b"CCCC")] {
            let slot_at = physical * page_size + layout.position(0, slot) as usize;
            file[slot_at..slot_at + 2].copy_from_slice(&1u16.to_le_bytes());
            file[slot_at + 2..slot_at + 2 + 20].copy_from_slice(&v6_record(key));
        }
        // The control record's own count has to agree, or `Records::read`
        // refuses the file before the delete is ever reached. Write it into
        // whichever half of the shadow pair is live.
        let generation = |page: usize| -> u16 {
            u16::from_le_bytes([
                file[page * page_size + at::GENERATION],
                file[page * page_size + at::GENERATION + 1],
            ])
        };
        let live = if generation(0) > generation(1) { 0 } else { page_size };
        file[live + pages::fcr::RECORDS_HIGH..][..4].copy_from_slice(&pages::to_long(3));
        let definition = pages::fcr::KEYS + usize::from(block.keys[0].definition) * pages::fcr::KEY_WIDTH;
        file[live + definition + pages::fcr::KEY_RECORDS..][..4]
            .copy_from_slice(&pages::to_long(3));

        // Task 6: the delete this test drives now locates its target
        // through the on-disk B-tree (`nav::descend_for_write`), not a
        // rebuild from the model -- so "BBBB"/"CCCC", injected straight
        // into the data page above, also need entries of their own, or the
        // delete below finds only "AAAA"'s and refuses ("value not found in
        // the tree"). Both go into the same one-entry leaf `insert_v6`
        // already built for "AAAA", re-encoded with three entries instead
        // of one; this file's key is a 4-byte unique STRING, so ordinary
        // byte order already sorts AAAA < BBBB < CCCC.
        let key = &block.keys[0];
        let shape = key.shape();
        let root_raw = pages::long(&file[live + definition + pages::fcr::KEY_ROOT..][..4]);
        let root_logical = root_raw & pages::fcr::ROOT_PAGE;
        let root_physical = v6::Map::read(
            &mut v6::Store::from_bytes(&file, block.geometry.page).expect("test fixture"),
            block.geometry.page,
        )
        .expect("table")
        .physical(root_logical)
        .expect("the root is claimed") as usize;
        let leaf_start = root_physical * page_size;
        let leaf_before = pages::decode_index_page(&file[leaf_start..leaf_start + page_size], shape)
            .expect("insert_v6 already built a decodable one-entry leaf");
        assert_eq!(leaf_before.entries.len(), 1, "only AAAA is indexed before this patch");
        let entries = vec![
            pages::Entry::unique(b"AAAA".to_vec(), first),
            pages::Entry::unique(b"BBBB".to_vec(), second),
            pages::Entry::unique(b"CCCC".to_vec(), third),
        ];
        let mut leaf_image = pages::encode_v6_index_page(layout, shape, leaf_before.stamp, &entries, &[]);
        // `encode_v6_index_page` leaves the header's own tag/logical bytes
        // zero (its caller is always `v6::Map::claim`/`relocate`, which fill
        // them in) -- copied from the page this patches in place instead.
        leaf_image[..4].copy_from_slice(&file[leaf_start..leaf_start + 4]);
        file[leaf_start..leaf_start + page_size].copy_from_slice(&leaf_image);

        std::fs::write(&path, &file).expect("written");

        block.geometry = Geometry::read("V6EMPTY1KEY.DAT", &path).expect("re-reads the shape");
        block.records = None;
        assert_eq!(block.records().expect("three records on one page").len(), 3);

        block.delete(second).expect("delete the middle record");

        block.records = None;
        let reread = block.records().expect("re-reads across the hole");
        assert_eq!(reread.len(), 2, "the hole is skipped, not treated as the end");
        assert_eq!(at_position(reread, first).expect("before the hole").bytes, v6_record(b"AAAA"));
        assert_eq!(
            at_position(reread, third).expect("behind the hole").bytes,
            v6_record(b"CCCC"),
            "the record behind the freed slot is still there"
        );
    }

    /// `Self::insert_v6`'s narrow scope actually works: a fresh, virgin,
    /// one-key v6 file (`V6EMPTY1KEY.DAT`, minted by genuine Btrieve 6.15
    /// itself -- `crtprobe.exe create`, no records inserted) takes one
    /// record, and a *fresh* `Block` over the same file -- cache dropped,
    /// nothing carried over in memory -- reads it back correctly. That
    /// second read is the whole point: `Self::records`'s v6 path
    /// (`records::walk_v6`) resolves everything through
    /// [`v6::Map::read`], built from what is on disk, not from anything
    /// this test's own `Block` remembers writing.
    #[test]
    fn a_v6_insert_lands_on_a_fresh_single_key_file() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/btrieve-oracle/fixtures/V6EMPTY1KEY.DAT");
        let dir = crate::testing::scratch("btv-v6-insert");
        let path = dir.join("V6EMPTY1KEY.DAT");
        std::fs::copy(&fixture, &path).expect("copy fixture");

        let mut block = block(path.clone());
        block.name = "V6EMPTY1KEY.DAT".to_owned();
        block.geometry = Geometry::read("V6EMPTY1KEY.DAT", &path).expect("reads");
        let fcr = std::fs::read(&path).expect("readable");
        block.keys = keys::parse("V6EMPTY1KEY.DAT", &fcr, block.geometry.keys, &[]).expect("keys");
        block.maxlen = block.geometry.reclen;

        assert_eq!(block.records().expect("v6 reads").len(), 0);

        let mut bytes = vec![0u8; usize::from(block.geometry.reclen)];
        bytes[..4].copy_from_slice(b"ABCD");
        let position = block
            .insert(&bytes)
            .expect("a single unique-keyed, single-block, single-page-index v6 insert");

        assert_eq!(block.records().expect("still loaded").len(), 1);
        let record = block.records().expect("loaded").physical(0).expect("the record");
        assert_eq!(record.position, position);
        assert_eq!(record.bytes, bytes);

        // The trap `a_block_that_writes_is_readable_after_its_cache_is_dropped`
        // names for v5, exercised here for v6: a fresh `Records::read` of the
        // file this just wrote to has to find the record through the
        // allocation table and the file control record's own count, not
        // through anything this `Block` still remembers.
        block.records = None;
        let reread = block.records().expect("re-reads after writing");
        assert_eq!(reread.len(), 1);
        let record = reread.physical(0).expect("the record, from a fresh read");
        assert_eq!(record.position, position);
        assert_eq!(record.bytes, bytes);

        // Everything above reads the file back through `Records::read`, which
        // finds records by walking *data* pages. It never consults the key
        // index -- so every assertion above passes just as happily on a file
        // whose B-tree is garbage, and the index is half of what `insert_v6`
        // writes.
        //
        // Measured, not argued: mutating the index entries this insert builds
        // to carry `record.position ^ 0xDEAD` leaves every assertion above
        // green, while genuine Btrieve 6.15 rejects the resulting file
        // outright -- `walk 0` reports "walked 0 (stopped early)" and
        // `descend 0` reports DESCEND MISMATCH with "collect end 2 (I/O
        // error)". That is a silently-corrupt file this suite called correct.
        //
        // So this reaches the index the way the engine does and asserts it
        // points at the record: resolve key 0's root through the file control
        // record's own `KEY_ROOT` (v6 marker bit stripped), map that *logical*
        // id to a physical page through the `"PP"` allocation table, and decode
        // the page. Independent of the entry construction it is checking --
        // `position` here is the value `insert` returned and the data-page read
        // above already confirmed.
        let file = std::fs::read(&path).expect("readable after the insert");
        let page_size = block.geometry.page;
        let map = v6::Map::read(&mut v6::Store::from_bytes(&file, page_size).expect("test fixture"), page_size).expect("the allocation table");
        let key = &block.keys[0];
        let definition = pages::fcr::KEYS + usize::from(key.definition) * pages::fcr::KEY_WIDTH;
        let root_at = definition + pages::fcr::KEY_ROOT;
        let raw_root = pages::long(&file[root_at..root_at + 4]);
        let root_logical = raw_root & pages::fcr::ROOT_PAGE;
        let root_physical = map
            .physical(root_logical)
            .expect("the key's root is a claimed logical page");
        let start = root_physical as usize * usize::from(page_size);
        let page = &file[start..start + usize::from(page_size)];
        let index = pages::decode_index_page(page, key.shape()).expect("the root index page");
        assert!(
            index.entries.iter().any(|(_, head, _)| *head == position),
            "the key index must point at the record the insert wrote \
             (position {position}), but the root page's entries are {:?}",
            index.entries.iter().map(|(_, head, _)| *head).collect::<Vec<_>>()
        );
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
    /// A key's index root is the low **24** bits of its root field, not the
    /// low 31.
    ///
    /// `WGSGEN2.VIR` is the file that found this: genuine Worldgroup's own
    /// generic user database, two keys, and the second one's root reads
    /// `0x81000003`. Masking with `0x7fffffff` leaves the key number in the
    /// top byte and turns logical page 3 into 16,777,219, which
    /// `v6::Map::relocate` then refuses as not fitting a `u16` -- the error
    /// that stopped MajorMUD's boot once duplicate keys worked.
    ///
    /// **A single-key file cannot catch this**, because its only root has a
    /// top byte of exactly `0x80` and the two masks agree. Every other
    /// fixture here is single-key, which is why this test needs a file of its
    /// own rather than an assertion added to an existing one.
    #[test]
    fn a_keys_root_is_its_low_twenty_four_bits_even_on_a_second_key() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/variable/WGSGEN2.VIR");
        let geometry = Geometry::read("WGSGEN2.VIR", &path).expect("a genuine v6 file");
        assert_eq!(geometry.keys, 2, "the point of this fixture is its second key");

        let whole = std::fs::read(&path).expect("the file reads");
        let page = usize::from(geometry.page);
        let generation = |at: usize| u16::from_le_bytes([whole[at + 4], whole[at + 5]]);
        let live = if generation(0) > generation(page) { 0 } else { page };
        let fcr = &whole[live..live + FCR];
        let tables = acs_tables(&path, &geometry, fcr).expect("its collating tables load");
        let keys = keys::parse("WGSGEN2.VIR", fcr, geometry.keys, &tables).expect("its keys parse");

        let root_of = |key: &Key| {
            let at = pages::fcr::KEYS
                + usize::from(key.definition) * pages::fcr::KEY_WIDTH
                + pages::fcr::KEY_ROOT;
            pages::long(&fcr[at..at + 4])
        };

        let first = root_of(&keys[0]);
        let second = root_of(&keys[1]);
        assert_eq!(first, 0x8000_0002, "key 0's root, as the vendor shipped it");
        assert_eq!(second, 0x8100_0003, "key 1's root carries its own number too");

        // Both must resolve to a page the file actually has.
        let map = v6::Map::read(&mut v6::Store::from_bytes(&whole, geometry.page).expect("test fixture"), geometry.page).expect("its allocation table reads");
        for (key, raw) in [(&keys[0], first), (&keys[1], second)] {
            let logical = raw & pages::fcr::ROOT_PAGE;
            assert!(
                logical < geometry.pages,
                "key {}: root {raw:#010x} masks to logical {logical}, and the file has \
                 {} pages",
                key.number,
                geometry.pages
            );
            assert!(
                map.physical(logical).is_some(),
                "key {}: logical {logical} is claimed in the allocation table",
                key.number
            );
        }

        // The mask this replaced agreed on the first key and not the second.
        assert_eq!(first & 0x7fff_ffff, first & pages::fcr::ROOT_PAGE);
        assert_ne!(second & 0x7fff_ffff, second & pages::fcr::ROOT_PAGE);
    }

    /// A `Block` over a real file, with the geometry and keys the file itself
    /// declares rather than invented ones.
    ///
    /// `block` above hand-builds both, which is right for a scratch fixture
    /// it also hand-builds. A test whose whole point is that a *genuine*
    /// engine's file is handled correctly must not get to choose what that
    /// file says about itself.
    fn block_from_file(path: PathBuf, name: &str) -> Block<Flat> {
        let geometry = Geometry::read(name, &path).expect("a readable Btrieve file");
        let whole = std::fs::read(&path).expect("the file reads");
        let page = usize::from(geometry.page);

        // A v6 control record is shadowed across pages 0 and 1 and the higher
        // generation is live; a v5 file has only the one copy.
        let fcr = match geometry.version {
            Version::V5 => whole[..FCR].to_vec(),
            Version::V6 => {
                let generation = |at: usize| {
                    u16::from_le_bytes([
                        whole[at + at::GENERATION],
                        whole[at + at::GENERATION + 1],
                    ])
                };
                let live = if generation(0) > generation(page) { 0 } else { page };
                whole[live..live + FCR].to_vec()
            }
        };
        let tables = acs_tables(&path, &geometry, &fcr).expect("its collating tables load");
        let keys = keys::parse(name, &fcr, geometry.keys, &tables).expect("its keys parse");

        Block {
            id: ops::BlockId::fresh(),
            name: name.to_owned(),
            path,
            maxlen: geometry.reclen,
            geometry,
            keys,
            block: FlatPtr::NULL,
            data: FlatPtr::NULL,
            key: FlatPtr::NULL,
            records: None,
            cursor: Cursor::Nowhere,
            dirty: false,
            txn_active: false,
            pre_image: None,
            // A test-only fixture, not `Self::open` -- see
            // `Self::verify_writes`'s doc comment for why this stays off.
            verify_writes: false,
            // Same reasoning: a test-only fixture never goes through
            // `Self::open`, the only place that captures a mode at all.
            mode: PRIMBV,
            // Same reasoning: a test-only fixture never goes through
            // `Self::open`, the only place that builds one.
            cache: None,
            v6_order: std::cell::RefCell::new(std::collections::HashMap::new()),
            v6_physical: std::cell::RefCell::new(None),
        }
    }

    /// A run of real writes against a real 53 MB file still reads back.
    ///
    /// The small committed fixtures exercise the ordinary path -- one flip
    /// per shadow pair -- against files of a few pages. This runs updates and
    /// inserts against a file genuine Btrieve built, reopening it from disk
    /// every round rather than trusting the model the write just updated,
    /// because the model is the half a bad write would leave looking right.
    ///
    /// Ignored: needs a real `WCCMP002.DAT`, named by `$WCCMP002`.
    #[test]
    #[ignore = "needs a real WCCMP002.DAT, named by $WCCMP002"]
    fn a_run_of_v6_writes_on_a_real_file_reads_back_every_time() {
        let Ok(source) = std::env::var("WCCMP002") else {
            eprintln!("set WCCMP002=/path/to/WCCMP002.DAT to run this");
            return;
        };
        let dir = crate::testing::scratch("v6-real-write-run");
        let path = dir.join("WCCMP002.DAT");
        std::fs::copy(&source, &path).expect("the file copies into scratch");

        let mut block = block_from_file(path.clone(), "WCCMP002.DAT");
        let mut expected = block.records().expect("the records read").len();
        let reclen = usize::from(block.geometry.reclen);

        for round in 0..6u8 {
            // The record's *own* bytes with a trailing byte changed: key 0 is
            // not modifiable on this file, so an update carrying some other
            // record's key is refused before it ever reaches the writer this
            // is testing.
            let (target, mut bytes) = {
                let records = block.records().expect("the records read");
                let found = records
                    .physical(usize::from(round) % 8)
                    .expect("a record in the first few");
                (found.position, found.bytes.to_vec())
            };
            bytes.resize(reclen, 0);
            let last = bytes.len() - 1;
            bytes[last] = round;
            block.update(target, &bytes).expect("an update");

            let mut record = vec![0u8; reclen];
            record[..4].copy_from_slice(&(900_000u32 + u32::from(round)).to_le_bytes());
            block.insert(&record).expect("an insert");
            expected += 1;

            // Reopened from disk every round: a write that corrupted the file
            // and left the model intact would otherwise sail through.
            let mut fresh = block_from_file(path.clone(), "WCCMP002.DAT");
            let count = fresh
                .records()
                .unwrap_or_else(|e| panic!("round {round}: the file no longer reads: {e}"))
                .len();
            assert_eq!(count, expected, "round {round}: record count on disk");
        }
    }

    /// The identical run [`a_run_of_v6_writes_on_a_real_file_reads_back_
    /// every_time`] makes, but through a real [`Self::open`] (a page cache
    /// attached, `Self::v6_fast_reads` true) rather than [`block_from_file`]
    /// -- review Important 1: every other real-`$WCCMP002` test builds a
    /// hand-`Block` with `cache: None`, which cannot exercise a single line
    /// of this task's own fast path (`Self::v6_fast_reads` requires
    /// `cache.is_some()`), so nothing proved the incremental FCR-count
    /// arithmetic (`saturating_add`/`saturating_sub` gated on `Key::
    /// excluded` transitions) over a sustained sequence of writes against a
    /// large file.
    ///
    /// Same shape as the sibling: six rounds of update-then-insert, each
    /// round finding its own target record and verifying the new count
    /// through an *independent, freshly reopened* `Btrieve` -- never
    /// trusting the model (or the fast path's own cached indexes) the write
    /// just updated, since that is exactly the half a bad write would leave
    /// looking right.
    ///
    /// Ignored: needs a real `WCCMP002.DAT`, named by `$WCCMP002`.
    #[test]
    #[ignore = "needs a real WCCMP002.DAT, named by $WCCMP002"]
    fn a_run_of_v6_writes_on_a_real_file_through_the_fast_path_reads_back_every_time() {
        let Ok(source) = std::env::var("WCCMP002") else {
            eprintln!("set WCCMP002=/path/to/WCCMP002.DAT to run this");
            return;
        };
        let dir = crate::testing::scratch("v6-real-write-run-fast-path");
        let path = dir.join("WCCMP002.DAT");
        std::fs::copy(&source, &path).expect("the file copies into scratch");

        // A fresh `Btrieve`, `Self::open`ed on `path` -- a real page cache,
        // never a hand-built fixture. `mem`/`heap` are scoped to this
        // function only: nothing after `open` returns ever resolves a
        // module-memory pointer, so they do not need to outlive it.
        fn open_fresh(path: &Path) -> (Btrieve<Flat>, FlatPtr) {
            let mut mem = FlatMem::new(64 * 1024);
            let mut heap = FlatHeap::new(0x100);
            let mut btrieve = Btrieve::<Flat>::default();
            let geometry = Geometry::read("WCCMP002.DAT", path).expect("reads");
            let maxlen = geometry.reclen;
            let at = btrieve
                .open(&mut mem, &mut heap, "WCCMP002.DAT", path, geometry, maxlen)
                .expect("opens");
            (btrieve, at)
        }

        let (mut btrieve, at) = open_fresh(&path);
        assert!(
            btrieve.block(at).expect("open").cache.is_some(),
            "a real Self::open attaches a cache -- this test is meaningless without one"
        );
        assert!(
            btrieve.block(at).expect("open").v6_fast_reads(),
            "WCCMP002.DAT is fixed-length v6 -- this test is meaningless if it is not              actually driving Self::v6_fast_reads"
        );
        let reclen = usize::from(btrieve.block(at).expect("open").geometry.reclen);
        let mut expected = btrieve.block(at).expect("open").v6_physical_len().expect("physical count");

        for round in 0..6u8 {
            // A record "in the first few", found through the fast physical
            // index itself rather than `self.records()` -- key 0 is not
            // modifiable on this file, so an update carrying some other
            // record's key is refused before it ever reaches the writer
            // this is testing, same as the sibling test's own reasoning.
            let (target, mut bytes) = {
                let block = btrieve.block_mut(at).expect("open");
                let position = block
                    .v6_physical_at(usize::from(round) % 8)
                    .expect("physical lookup")
                    .expect("a record in the first few");
                let bytes = block
                    .v6_record_bytes_at(position)
                    .expect("fetch")
                    .expect("still live");
                (position, bytes)
            };
            bytes.resize(reclen, 0);
            let last = bytes.len() - 1;
            bytes[last] = round;
            btrieve.block_mut(at).expect("open").update(target, &bytes).expect("an update");

            let mut record = vec![0u8; reclen];
            record[..4].copy_from_slice(&(900_000u32 + u32::from(round)).to_le_bytes());
            btrieve.block_mut(at).expect("open").insert(&record).expect("an insert");
            expected += 1;

            // Reopened from disk every round, a brand new `Btrieve` and
            // page cache: a write that corrupted the file and left the
            // fast path's own cached indexes intact would otherwise sail
            // through.
            let (fresh, fresh_at) = open_fresh(&path);
            let count = fresh
                .block(fresh_at)
                .unwrap_or_else(|e| panic!("round {round}: the file no longer opens: {e}"))
                .v6_physical_len()
                .unwrap_or_else(|e| panic!("round {round}: the file no longer reads: {e}"));
            assert_eq!(count, expected, "round {round}: record count on disk");
        }
    }

    /// Review Important 4: whole-map `OrderIndex` invalidation on an
    /// update that touches no key at all -- health, gold, position, the
    /// majority of live write traffic -- used to force the next keyed read
    /// to pay a full rebuild it had no reason to. `Self::v6_invalidate_
    /// keys` fixes this by invalidating only the keys a write's own
    /// `Key::compare`/`Key::excluded` check found actually changed; this
    /// measures the before/after directly, on the real `WCCMP002.DAT` this
    /// task's own cost baseline is judged against, where a rebuild is
    /// large enough to be worth measuring at all.
    ///
    /// Ignored: needs a real `WCCMP002.DAT`, named by `$WCCMP002`.
    #[test]
    #[ignore = "needs a real WCCMP002.DAT, named by $WCCMP002"]
    fn a_non_key_update_leaves_the_order_index_cached_a_key_changing_one_does_not() {
        let Ok(source) = std::env::var("WCCMP002") else {
            eprintln!("set WCCMP002=/path/to/WCCMP002.DAT to run this");
            return;
        };
        let dir = crate::testing::scratch("v6-selective-order-invalidation");
        let path = dir.join("WCCMP002.DAT");
        std::fs::copy(&source, &path).expect("the file copies into scratch");
        crate::testing::make_keys_modifiable(&path);

        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut btrieve = Btrieve::<Flat>::default();
        let geometry = Geometry::read("WCCMP002.DAT", &path).expect("reads");
        let maxlen = geometry.reclen;
        let at = btrieve
            .open(&mut mem, &mut heap, "WCCMP002.DAT", &path, geometry, maxlen)
            .expect("opens");
        assert!(btrieve.block(at).expect("open").v6_fast_reads(), "meaningless without the fast path");

        let reclen = usize::from(maxlen);
        let (position, original) = {
            let block = btrieve.block_mut(at).expect("open");
            let position = block.v6_physical_at(0).expect("physical lookup").expect("a first record");
            let bytes = block.v6_record_bytes_at(position).expect("fetch").expect("still live");
            (position, bytes)
        };

        // Prime key 0's `OrderIndex` -- a `Get Equal` for the record's own
        // (unmodified) key value, first read since open, so this pays
        // whatever a full rebuild costs. `WCCMP002.DAT`'s one key lives at
        // byte 0 of each record (`write_cost.rs`'s own `bytes[0] ^= 0xff`
        // targets it for the identical reason). `page_fetches` here (a
        // cold cache -- nothing has read this file yet this session) is
        // the genuine cost one full `OrderIndex` rebuild pays, reported in
        // `docs/2026-08-24-btrieve-write-cost-baseline.md`'s own
        // measurement of what selective invalidation now avoids.
        crate::testing::reset_page_fetches();
        let mut locks = LockTable::default();
        assert!(
            btrieve.block_mut(at).expect("open").get(0, Op::Equal, &original[..8], 0, &mut locks, maxlen)
                .expect("get")
                .is_some(),
            "the record's own original key value must still be found"
        );

        let cold_build_fetches = crate::testing::page_fetches();

        // A non-key update: only the record's *last* byte changes.
        // `key.compare` on an unchanged first four bytes must find no
        // change at all, so `Self::v6_invalidate_keys` receives an empty
        // `changed_keys` and key 0's cached order survives.
        let mut non_key_bytes = original.clone();
        non_key_bytes[reclen - 1] ^= 0xff;
        btrieve.block_mut(at).expect("open").update(position, &non_key_bytes).expect("a non-key update");

        crate::testing::reset_order_builds();
        assert!(
            btrieve.block_mut(at).expect("open").get(0, Op::Equal, &original[..8], 0, &mut locks, maxlen)
                .expect("get")
                .is_some(),
            "the key value is unchanged, so it must still be found"
        );
        let reuse_builds = crate::testing::order_builds();

        // Contrast: a key-changing update on a *different* record (so the
        // value this test keeps searching for stays findable) invalidates
        // key 0's cached order for real.
        let (other_position, mut other_bytes) = {
            let block = btrieve.block_mut(at).expect("open");
            let position = block.v6_physical_at(1).expect("physical lookup").expect("a second record");
            let bytes = block.v6_record_bytes_at(position).expect("fetch").expect("still live");
            (position, bytes)
        };
        other_bytes[0] ^= 0xff;
        btrieve.block_mut(at).expect("open").update(other_position, &other_bytes).expect("a key-changing update");

        crate::testing::reset_order_builds();
        assert!(
            btrieve.block_mut(at).expect("open").get(0, Op::Equal, &original[..8], 0, &mut locks, maxlen)
                .expect("get")
                .is_some(),
            "still found -- this update touched a different record's key, not this one"
        );
        let rebuild_builds = crate::testing::order_builds();

        eprintln!(
            "a_non_key_update_leaves_the_order_index_cached: cold_build_fetches={cold_build_fetches} \
             reuse_builds={reuse_builds} rebuild_builds={rebuild_builds}"
        );
        assert_eq!(
            reuse_builds, 0,
            "a non-key update must leave key 0's cached OrderIndex untouched -- the next \
             read rebuilt it {reuse_builds} time(s) instead of reusing what was already there"
        );
        assert_eq!(
            rebuild_builds, 1,
            "a key-changing update must actually invalidate key 0's cached OrderIndex -- \
             the next read rebuilt it {rebuild_builds} time(s), not exactly once"
        );
    }

    /// The healthy path: insert, update and delete against a real,
    /// committed, single-key v6 fixture (`V6DUP.DAT`), opened with
    /// [`Block::verify_writes`] turned on, all succeed and leave a file
    /// [`crate::verify::written`] accepts.
    ///
    /// This is the baseline
    /// [`a_shrinking_v6_reindex_releases_its_surplus_pages_on_insert`] is
    /// contrasted against: `verify_writes` does not fail a write that is
    /// actually sound.
    #[test]
    fn verify_writes_passes_on_the_healthy_path() {
        let dir = crate::testing::scratch("verify-writes-v6dup");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/variable/V6DUP.DAT");
        let path = dir.join("V6DUP.DAT");
        std::fs::copy(&source, &path).expect("the fixture copies into scratch");

        let mut block = block_from_file(path.clone(), "V6DUP.DAT");
        block.verify_writes = true;
        let reclen = usize::from(block.geometry.reclen);

        // `V6DUP.DAT` holds variable-length records. Delete still refuses
        // unconditionally for a v6 variable-length file (`Self::delete_inner`,
        // out of this task's scope); update now rewrites an in-place,
        // same-length, single-fragment record (Task 6,
        // `a_v6_variable_length_record_rewrites_a_single_fragment_in_place`
        // exercises it directly) but this fixture's own record shapes are not
        // chosen for that, so insert alone is what this test uses to show the
        // healthy case through the real v6 write path verification wires into.
        let mut record = vec![0u8; reclen];
        record[..4].copy_from_slice(&999_999u32.to_le_bytes());
        block.insert(&record).expect("a verified insert");

        assert_eq!(crate::verify::written(&path), Ok(()));
    }

    /// Task 8: `VERFBV` forces [`Block::verify_writes`] on for the block it
    /// opens -- and, unlike before this task, that check is no longer
    /// wrapped in `#[cfg(debug_assertions)]` at all, so nothing about a
    /// `--release` build can compile it away. This test cannot flip
    /// `cfg!(debug_assertions)` itself (`cargo test` always builds with it
    /// on), so it proves the release-shaped claim the only way a single
    /// test binary can: by showing `Self::verify_write`'s *runtime* gate is
    /// `self.verify_writes` alone, with nothing else standing between it
    /// and [`crate::verify::written`] -- exactly the gate a `--release`
    /// build still evaluates. (This test's own name was additionally
    /// confirmed under a real `--release` build for task-8-report.md; see
    /// that report for the transcript.)
    #[test]
    fn a_verify_mode_open_reaches_verify_written_in_release_shape() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut btrieve = Btrieve::<Flat>::default();
        let (name, path) = create_scratch_v5("verfbv-forces-verification");
        let geometry = Geometry::read(&name, &path).expect("reads");
        let maxlen = geometry.reclen;

        btrieve.set_mode(VERFBV);
        let at = btrieve
            .open(&mut mem, &mut heap, &name, &path, geometry, maxlen)
            .expect("opens");
        {
            let block = btrieve.block(at).expect("open");
            assert_eq!(block.mode(), VERFBV);
            assert!(
                block.verify_writes,
                "VERFBV must force verify_writes on for this block, in any build"
            );
        }

        // Corrupt the file behind the block's back -- one appended byte, so
        // `crate::verify::written`'s own first check (rebuilt length versus
        // on-disk length) is what catches it, rather than depending on
        // which byte ranges this model treats as opaque. Then call
        // `Block::verify_write` directly with an already-successful inner
        // result and confirm it still turns that `Ok` into an `Err`: proof
        // this runs, not merely that the flag reads `true`.
        let mut corrupted = std::fs::read(&path).expect("read the file back");
        corrupted.push(0xff);
        std::fs::write(&path, &corrupted).expect("corrupt the file on disk");

        let block = btrieve.block(at).expect("open");
        let result: Result<(), BtvError> = block.verify_write(Ok(()));
        assert!(
            result.is_err(),
            "a VERFBV block's verify_write must catch the corruption -- no compile-time \
             debug_assertions gate stands between self.verify_writes and \
             crate::verify::written any more"
        );
    }

    /// Task 8: `ACCLBV` writes every changed page -- content and structural
    /// alike -- in one pass, with the shadow pair's FINAL generation
    /// already baked in, and flushes once. Every other mode, `PRIMBV`
    /// included, holds a shadow pair's generation back, writes its body
    /// separately, and flips it in a third pass -- three flushes, and two
    /// extra bytes per pair (the generation, written twice: held-back, then
    /// final).
    ///
    /// Two fresh copies of the same fixture, the identical insert against
    /// each -- one block left at the open default (`PRIMBV`), the other's
    /// `mode` set to `ACCLBV` directly (this test is about
    /// `write_changed_pages_attempt`'s own branch, not about `Self::open`,
    /// which Task 8's other tests already cover) -- isolate exactly the
    /// write-path difference, with nothing else able to explain it: same
    /// file, same bytes in, same bytes the model produces.
    #[test]
    fn acclbv_commits_in_a_single_phase_with_fewer_writes_and_one_flush() {
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/variable/V6DUP.DAT");

        let run = |tag: &str, mode: i16| -> (usize, usize) {
            let dir = crate::testing::scratch(tag);
            let path = dir.join("V6DUP.DAT");
            std::fs::copy(&source, &path).expect("the fixture copies into scratch");

            let mut block = block_from_file(path.clone(), "V6DUP.DAT");
            block.mode = mode;
            let reclen = usize::from(block.geometry.reclen);
            let mut record = vec![0u8; reclen];
            record[..4].copy_from_slice(&999_999u32.to_le_bytes());

            WROTE.with(|wrote| wrote.set(0));
            FLUSHES.with(|flushes| flushes.set(0));
            block.insert(&record).expect("an insert, either mode");

            (
                WROTE.with(std::cell::Cell::get),
                FLUSHES.with(std::cell::Cell::get),
            )
        };

        let (primbv_bytes, primbv_flushes) = run("acclbv-evidence-primbv", PRIMBV);
        let (acclbv_bytes, acclbv_flushes) = run("acclbv-evidence-acclbv", ACCLBV);

        // Phase 1 and phase 2 each flush once, unconditionally; phase 3
        // flushes once after its first flip (this fixture's insert always
        // relocates at least the file control record's own pair -- v6
        // relocates a written key's root, and the FCR, on every write) and
        // once more at the end -- four, not three, once there is any flip
        // at all to trigger the first.
        assert_eq!(primbv_flushes, 4, "PRIMBV's three-phase commit flushes four times here");
        assert_eq!(acclbv_flushes, 1, "ACCLBV's single-phase commit flushes once");
        assert!(
            acclbv_bytes < primbv_bytes,
            "ACCLBV should write fewer bytes than PRIMBV for the identical insert -- \
             PRIMBV wrote {primbv_bytes}, ACCLBV wrote {acclbv_bytes}"
        );
        assert_eq!(
            primbv_bytes - acclbv_bytes,
            4,
            "the only byte-count difference should be phase 3's two-byte-per-flip \
             re-write, which the single-phase path never does at all -- measured at \
             two flips for this fixture's insert (the file control record's own pair, \
             plus its one key's root, relocated on every v6 write), 2 bytes each"
        );
    }

    /// **A v6 variable-length record can be updated.** Task 6: closes the
    /// refusal `Self::update_inner` used to give unconditionally for every
    /// v6 file holding variable-length records -- the refusal the design
    /// doc named as what "crashes a live board", reachable today on
    /// MajorMUD-NT's own `WCCTEXT2.VIR` (`tmp/plan-3-update-survey.md`
    /// SS0.B/SS5: any `dfaUpdateDup`/`upvbtv` write to it stopped the
    /// session outright, `ShimError` being terminal).
    ///
    /// # Why this copy, not the 3,467-record one the task brief names
    ///
    /// `wccnt8pj`'s copy of `wcctext2.vir` is the 3,467-record file the task
    /// brief describes, and it is genuinely v6 and genuinely variable -- but
    /// measured directly (every one of its 3,467 fragment pointers decodes
    /// to the end-of-chain sentinel, zero real continuations), it carries no
    /// multi-hop fragment chain at all. Step 6's required mutation --
    /// emitting the fragment pointer without its byte-order scramble -- is
    /// only visible on a *real* page number; `0xffffffff`, the sentinel, is
    /// the one pointer value every byte permutation encodes identically.
    /// `verify::written` re-emits the *whole* file after this test's update,
    /// so the mutation is only caught if some record left untouched by this
    /// update still carries a real chain. `wccnt7pw`'s copy of the same
    /// file (same MajorMUD text database, a different build snapshot) does:
    /// measured directly, 170 of its 1,940 records' fragment pointers name a
    /// real next page rather than the sentinel.
    ///
    /// # Why this loop, not one hardcoded position
    ///
    /// `Self::update_v6`'s variable-length branch only rewrites a record
    /// whose own fragment is the whole record on one page -- refusing a
    /// chain that continues onto another is deliberate scope (see
    /// `variable::rewrite_fragment_in_place_v6`'s own doc comment: growing
    /// or splicing a chain needs the allocator and entry-array edits this
    /// host has not measured against genuine Btrieve 6.15 for v6). Roughly
    /// 9 in 10 of this file's records are the single-fragment shape (170 of
    /// 1,940 measured with a real continuation), so this tries records in
    /// the order the model lists them until one succeeds, rather than
    /// asserting a specific position that would make this test fragile
    /// against which record happens to be which shape.
    #[test]
    fn a_v6_variable_length_record_rewrites_a_single_fragment_in_place() {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../archive/modules/majormud-nt/wccnt7pw/out/wcctext2.vir");
        if !source.exists() {
            eprintln!("{}: not present in this checkout, skipping", source.display());
            return;
        }
        let dir = crate::testing::scratch("v6-variable-update-wcctext2");
        let path = dir.join("wcctext2.vir");
        std::fs::copy(&source, &path).expect("the corpus file copies into scratch");

        let mut block = block_from_file(path.clone(), "WCCTEXT2.VIR");
        block.verify_writes = true;
        assert_eq!(block.geometry.version, Version::V6);
        assert!(
            block.geometry.variable,
            "wcctext2.vir is supposed to hold variable-length records"
        );

        let positions = block.records().expect("the records read").positions();
        let mut updated = None;
        for position in positions {
            let mut bytes = {
                let records = block.records().expect("still loaded");
                let at = records.find_physical(position).expect("just listed");
                records.physical(at).expect("just found").bytes.clone()
            };
            // The body's own last byte -- never a fixed-part byte a key
            // might be defined over, so this can never trip the
            // unmodifiable-key rule even where that rule applied here.
            let last = bytes.len() - 1;
            bytes[last] = bytes[last].wrapping_add(1);
            if block.update(position, &bytes).is_ok() {
                updated = Some((position, bytes));
                break;
            }
        }
        let (position, bytes) = updated.expect(
            "wcctext2.vir has at least one single-fragment, unchained variable-length record",
        );

        assert_eq!(crate::verify::written(&path), Ok(()));

        // Reopened from disk, not trusted from the model the write just
        // updated -- the same discipline the real-file WCCMP002 tests use.
        let mut fresh = block_from_file(path.clone(), "WCCTEXT2.VIR");
        let reread = {
            let records = fresh.records().expect("the file still reads");
            let at = records.find_physical(position).expect("record still there");
            records.physical(at).expect("record").bytes.clone()
        };
        assert_eq!(reread, bytes, "the update is visible after a fresh read");
    }

    /// **A v6 variable-length record can be deleted.** Task 7: closes the
    /// refusal `Self::delete_inner` used to give unconditionally for every
    /// v6 file holding variable-length records.
    ///
    /// # Why this fixture, and this loop
    ///
    /// Same reasoning as
    /// [`a_v6_variable_length_record_rewrites_a_single_fragment_in_place`]
    /// (Task 6), and the same fixture: `wccnt7pw`'s copy of `wcctext2.vir`
    /// carries 170 real multi-hop fragment pointers among 1,940 records,
    /// measured directly, so a delete that corrupted the entry array in a
    /// way only visible on a real chain has something to be caught by --
    /// the task brief's own named fixture (`wccnt8pj`'s copy, 3,467
    /// records) carries none. `Self::delete_v6`'s variable branch refuses a
    /// chained fragment and the only fragment on a page (see
    /// [`variable::free_fragment_v6`]'s doc comment), so this tries
    /// positions in the order the model lists them until one deletes,
    /// rather than asserting a specific one.
    ///
    /// # What "the freed fragments are accounted for" means here
    ///
    /// [`crate::verify::written`] re-reads the whole file back into a fresh
    /// model and re-emits it, byte for byte, from that model -- so it does
    /// not merely check that the deleted record is gone, it also re-derives
    /// and re-checks every *other* record still on the touched fragment
    /// page. `Self::delete_v6`'s interior-compaction path physically moves
    /// those neighbours' bytes; if that shift or the entry rebase behind it
    /// were wrong, a neighbour's own fragment would decode to the wrong
    /// span or the wrong content, and this assertion is what would catch
    /// that, not a targeted check on the deleted record alone.
    #[test]
    fn a_v6_variable_length_record_deletes_a_single_fragment() {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../archive/modules/majormud-nt/wccnt7pw/out/wcctext2.vir");
        if !source.exists() {
            eprintln!("{}: not present in this checkout, skipping", source.display());
            return;
        }
        let dir = crate::testing::scratch("v6-variable-delete-wcctext2");
        let path = dir.join("wcctext2.vir");
        std::fs::copy(&source, &path).expect("the corpus file copies into scratch");

        let mut block = block_from_file(path.clone(), "WCCTEXT2.VIR");
        block.verify_writes = true;
        assert_eq!(block.geometry.version, Version::V6);
        assert!(
            block.geometry.variable,
            "wcctext2.vir is supposed to hold variable-length records"
        );

        let before_count = block.records().expect("the records read").len();
        let positions = block.records().expect("still loaded").positions();
        let mut deleted = None;
        for position in positions {
            if block.delete(position).is_ok() {
                deleted = Some(position);
                break;
            }
        }
        let position = deleted.expect(
            "wcctext2.vir has at least one deletable record -- an unchained fragment \
             whose page is not that fragment's only one",
        );

        assert_eq!(crate::verify::written(&path), Ok(()));

        // Reopened from disk, not trusted from the model the delete just
        // changed -- the same discipline the update test above uses.
        let mut fresh = block_from_file(path.clone(), "WCCTEXT2.VIR");
        let records = fresh.records().expect("the file still reads");
        assert!(records.find_physical(position).is_none(), "gone after a fresh read too");
        assert_eq!(records.len(), before_count - 1, "the record count dropped by exactly one");
    }

    /// **A v6 tree that shrinks on rebuild no longer leaks a claimed page.**
    ///
    /// Formerly `verify_writes_catches_a_real_defect_in_multi_key_v6_reindex`,
    /// which asserted the opposite of what this now checks -- a defect this
    /// test itself once demonstrated has since been fixed
    /// (`v6::Map::unclaim`, wired into `Block::v6_reindex`), and a test
    /// still named "catches a real defect" would be a lie sitting in the
    /// suite once it started asserting the defect's *absence*. Renamed to
    /// describe the property it guards instead -- and dropped "multi_key"
    /// specifically: the census in `task-3b-report.md` proved key count is
    /// irrelevant to the mechanism, so a name built around it would invite
    /// the exact misreading Task 1's own original inference made. This
    /// test's own fixture happens to be multi-key; its sibling,
    /// [`a_shrinking_v6_reindex_releases_its_surplus_pages_on_delete`],
    /// hits the identical mechanism on a single-key file -- the suffix
    /// names the *operation* that triggers the shrink, which is the
    /// property that actually varies between them.
    ///
    /// The scenario is unchanged: `IDXPROBE.DAT` (2 keys, 120 records) is
    /// the smallest committed multi-key v6 fixture this crate has, and one
    /// ordinary `insert` on it is what originally surfaced the leak --
    /// rebuilding both keys' trees from scratch needs only 4 nodes each
    /// where the file's own (genuine-Btrieve-packed) trees occupy 6, and the
    /// 2 surplus logical pages per key used to stay claimed in the
    /// allocation table with no key's walk reaching them any more, which
    /// `read::file` refused as "claimed but attributed to no key's B-tree".
    /// Now `v6_reindex` releases exactly those surplus pages before it
    /// returns, so the write -- and `verify::written` on the result -- both
    /// succeed, in either build profile.
    #[test]
    fn a_shrinking_v6_reindex_releases_its_surplus_pages_on_insert() {
        let dir = crate::testing::scratch("verify-writes-idxprobe-shrink");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/variable/IDXPROBE.DAT");
        let path = dir.join("IDXPROBE.DAT");
        std::fs::copy(&source, &path).expect("the fixture copies into scratch");
        assert_eq!(
            crate::verify::written(&path),
            Ok(()),
            "the untouched fixture must round-trip, or this test would be \
             blaming the write for a defect the fixture already had"
        );

        let mut block = block_from_file(path.clone(), "IDXPROBE.DAT");
        block.verify_writes = true;
        let reclen = usize::from(block.geometry.reclen);
        let mut record = vec![0u8; reclen];
        record[..4].copy_from_slice(&999_999u32.to_le_bytes());

        // `Self::verify_write` runs in a debug build and is compiled out in
        // `--release` (`verify::written`'s own doc comment for why), so the
        // insert's own success is the only assertion that holds in both
        // profiles; the explicit `verify::written` call after it is what
        // still proves the file is sound in `--release`, where `insert`
        // alone would not have checked.
        block.insert(&record).expect(
            "a multi-key v6 tree that shrinks on rebuild must still leave a file this crate \
             can read back",
        );
        assert_eq!(
            crate::verify::written(&path),
            Ok(()),
            "the write must leave a file read::file accepts, independent of whether \
             verify_writes caught anything already"
        );
    }

    /// **Task 3b blast-radius census (throwaway, not the plan's pinned test)** --
    /// drives one real, verified write (insert for a variable-length file,
    /// update for a fixed-length one, both through the real `Block::insert`/
    /// `Block::update` and real `verify::written`) against every v6 file this
    /// box's `archive/` corpus holds, and counts how many hit the exact
    /// "claimed by the allocation table but attributed to no key's B-tree"
    /// refusal. Run once to answer Step 1 of the task-3b brief and left in as
    /// `#[ignore]`d evidence rather than a scratch script that leaves nothing
    /// behind.
    /// **The single-key shape, default-running -- the dominant real-world
    /// failure mode, not just the fixture that happened to find it.**
    ///
    /// `a_shrinking_v6_reindex_releases_its_surplus_pages_on_insert`'s own
    /// fixture is multi-key, and the task-3b census found the census's own
    /// blast radius runs the other way: of 170 real writes driven across the
    /// `archive/` corpus, 93 hit this defect and every one of them was a
    /// single-key file (0 of the 2 populated multi-key files ever did). A
    /// default `cargo test -p btrieve` exercised none of that -- the census
    /// itself is `#[ignore]`d and the real single-key witness
    /// (`WCCMP002.DAT`) is env-gated behind `$WCCMP002`. This is a small,
    /// committed, always-running fixture closing that gap.
    ///
    /// `V6SHRINK.DAT`: a genuine v6 file, its empty shell built by the real
    /// oracle (`tools/btrieve-oracle/crtprobe.exe create`, Pervasive Btrieve
    /// 6.15 under Wine -- not hand-crafted bytes), one key (STRING, 48
    /// bytes, unique), reclen 48, page 512. `Shape::capacity` gives this key
    /// 8 entries per index page ((512-12)/(48+8)), and the committed
    /// fixture's 9 records split 4-and-4 under one root separator.
    ///
    /// **Re-expressed for Task 6, per that task's own ruling, then again
    /// for round 5's own recording.** Before incremental maintenance
    /// landed, `v6_reindex`'s full rebuild packed this same 9-record tree
    /// into fewer nodes than the genuine-Btrieve-built file it started
    /// from, and this test proved the surplus was released rather than
    /// left as a dangling allocation-table claim. That mechanism
    /// (`v6_reindex`, `v6::Map::unclaim`) is unreferenced by any per-op
    /// write path now -- deleting **any** one of these 9 records
    /// underflows a leaf whose sibling sits at exactly `half_entries` (4
    /// and 4, never `> half_entries`), which per split rules §6 merges
    /// rather than redistributes, pulling the root's own one separator
    /// down and collapsing it to zero entries. Task 6's own rulings
    /// refused this (never recorded); round 5's own recording
    /// (`root-level-collapse`, `docs/btrieve-unproven.md` §6.1.4) measured
    /// it: status OK, the tree drops a level, the surviving leaf becomes
    /// the new root under its OWN logical id, and the vacated root retires
    /// onto the same free list a leaf does. This test's original *intent*
    /// -- a shrink must never silently leak a claimed page -- still holds,
    /// now satisfied the way the measured rule actually works: nothing is
    /// leaked because the vacated root is retired, not orphaned or
    /// dropped, and the allocation table still claims it (as `0x4500`,
    /// reusable) rather than losing track of it.
    #[test]
    fn a_shrinking_v6_reindex_releases_its_surplus_pages_on_delete() {
        let dir = crate::testing::scratch("verify-writes-v6shrink-delete");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/variable/V6SHRINK.DAT");
        let path = dir.join("V6SHRINK.DAT");
        std::fs::copy(&source, &path).expect("the fixture copies into scratch");
        assert_eq!(
            crate::verify::written(&path),
            Ok(()),
            "the untouched fixture must round-trip, or this test would be \
             blaming the write for a defect the fixture already had"
        );
        let before_bytes = std::fs::read(&path).expect("the untouched fixture reads");
        let before = crate::read::file(&before_bytes).expect("the untouched fixture decodes");
        let old_root = before.key_descriptors[0].root_page;
        let root_page_before = before
            .v6_pages
            .iter()
            .find(|p| u32::from(p.logical) == old_root)
            .expect("the root's own page is present");
        let idx_before = root_page_before.index.as_ref().expect("this fixture's own committed interior root");
        assert_eq!(idx_before.entries.len(), 1, "one separator between two leaves, the fixture's own 4-and-4 split");
        let leftmost = idx_before.leftmost & pages::fcr::ROOT_PAGE;
        let rightmost = idx_before.rightmost & pages::fcr::ROOT_PAGE;

        let mut block = block_from_file(path.clone(), "V6SHRINK.DAT");
        block.verify_writes = true;
        let records = block.records().expect("the fixture's records load");
        assert_eq!(records.len(), 9, "the fixture's own committed record count");
        let first = records.physical(0).expect("9 records, so index 0 exists").clone();
        let free_head_before = pages::long(
            &v6_fcr(&block, &before_bytes)[pages::fcr::INDEX_FREE_V6..pages::fcr::INDEX_FREE_V6 + 4],
        );
        assert_eq!(free_head_before, pages::NOWHERE, "a fresh oracle-built fixture retires nothing yet");

        block
            .delete(first.position)
            .expect("round 5's own recording: this collapse is status OK, not refused");

        let after_bytes = std::fs::read(&path).expect("the file still reads");
        let after = crate::read::file(&after_bytes).expect("the written file decodes");
        let new_root = after.key_descriptors[0].root_page;
        assert_ne!(new_root, old_root, "the old root did not survive its own collapse");
        assert!(
            new_root == leftmost || new_root == rightmost,
            "the new root is one of the two original leaves (the survivor), not a freshly claimed page"
        );
        let retired_leaf = if new_root == leftmost { rightmost } else { leftmost };

        let new_root_page = after
            .v6_pages
            .iter()
            .find(|p| u32::from(p.logical) == new_root)
            .expect("the new root's own page");
        let idx_after = new_root_page.index.as_ref().expect("still a real index page");
        assert_eq!(idx_after.leftmost, pages::NOWHERE, "a genuine populated leaf now, not an interior node");
        assert_eq!(idx_after.rightmost, pages::NOWHERE);
        assert_eq!(idx_after.entries.len(), 8, "3 survivors + the pulled-down separator + 4 donor entries");

        // Both pages this collapse retires -- the vacated root AND the
        // underflowing leaf -- are chained onto the SAME free list a leaf
        // alone would use, root last (LIFO: this op's own last retiree is
        // the list's new head).
        let old_root_page = after
            .v6_pages
            .iter()
            .find(|p| u32::from(p.logical) == old_root)
            .expect("the old root's own page still exists, now retired");
        assert!(old_root_page.retired.is_some(), "the vacated interior root is retired, not orphaned");
        let retired_leaf_page = after
            .v6_pages
            .iter()
            .find(|p| u32::from(p.logical) == retired_leaf)
            .expect("the underflowing leaf's own page still exists, now retired");
        assert!(retired_leaf_page.retired.is_some(), "the underflowing leaf retires exactly like any ordinary merge");

        let free_head_after = pages::long(
            &v6_fcr(&block, &after_bytes)[pages::fcr::INDEX_FREE_V6..pages::fcr::INDEX_FREE_V6 + 4],
        );
        assert_eq!(free_head_after, old_root, "the just-retired root becomes the free list's new head");
        let next_link = |page: &crate::model::V6Page| pages::long(&page.retired.as_ref().expect("retired")[2..6]);
        assert_eq!(
            next_link(old_root_page),
            retired_leaf,
            "the root's own link names the other page retired within this same operation"
        );
        assert_eq!(
            next_link(retired_leaf_page),
            pages::NOWHERE,
            "nothing was retired before this op, so the chain ends here"
        );

        assert_eq!(
            crate::verify::written(&path),
            Ok(()),
            "the written file must still round-trip after the collapse"
        );
    }

    #[test]
    #[ignore = "drives real writes across every v6 file in archive/; slow, opt-in, needs the archive"]
    fn task3b_v6_shrink_census() {
        let Some(_root) = crate::corpus::root() else {
            eprintln!("census: no archive/ on this box, nothing measured");
            return;
        };
        let entries = crate::corpus::walk();
        let mut total_v6 = 0usize;
        let mut single_key_v6 = 0usize;
        let mut multi_key_v6 = 0usize;
        let mut clean_before = 0usize;
        let mut attempted = 0usize;
        let mut attempted_multi_key = 0usize;
        let mut hit_defect = 0usize;
        let mut hit_defect_single_key = 0usize;
        let mut hit_defect_multi_key = 0usize;
        let mut other_failure = 0usize;
        let mut hit_names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

        for (n, entry) in entries.iter().enumerate() {
            if !entry.id.generation.is_v6() {
                continue;
            }
            total_v6 += 1;
            let Ok(geometry) = Geometry::read("census", &entry.path) else {
                continue;
            };
            if geometry.keys >= 2 {
                multi_key_v6 += 1;
            } else {
                single_key_v6 += 1;
            }

            let dir = crate::testing::scratch(&format!("task3b-census-{n}"));
            let name = entry
                .path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| format!("FILE{n}.DAT"));
            let dest = dir.join(&name);
            if std::fs::copy(&entry.path, &dest).is_err() {
                continue;
            }

            // Only files that round-trip clean *before* any write touches
            // them count -- a refusal on an already-broken fixture would be
            // blaming this task's write for a defect the file already had.
            if crate::verify::written(&dest).is_err() {
                continue;
            }
            clean_before += 1;

            let mut block = block_from_file(dest.clone(), &name);
            block.verify_writes = true;

            let result = if geometry.variable {
                let reclen = usize::from(block.geometry.reclen);
                if block.geometry.physical < reclen as u16 + 2 {
                    continue;
                }
                let mut record = vec![0u8; reclen];
                if reclen >= 4 {
                    record[..4].copy_from_slice(&999_999u32.to_le_bytes());
                }
                block.insert(&record).map(|_| ())
            } else {
                let Ok(records) = block.records() else {
                    continue;
                };
                if records.is_empty() {
                    continue;
                }
                let rec = records.physical(0).expect("just checked non-empty").clone();
                // Flip whichever byte does not change a non-modifiable key's
                // value -- byte 0 lands inside a leading key field on many
                // real files, which reports "status 10" and never reaches
                // `v6_reindex` at all, undercounting real exposure. Try a
                // few candidate offsets rather than always the front.
                let candidates = [
                    rec.bytes.len().saturating_sub(1),
                    rec.bytes.len() / 2,
                    rec.bytes.len().saturating_sub(2),
                    0,
                ];
                let mut chosen = None;
                for &at in &candidates {
                    if at >= rec.bytes.len() {
                        continue;
                    }
                    let mut bytes = rec.bytes.clone();
                    bytes[at] ^= 0xff;
                    if block.would_change_unmodifiable_key(rec.position, &bytes).ok().flatten().is_none() {
                        chosen = Some(bytes);
                        break;
                    }
                }
                let Some(bytes) = chosen else {
                    continue;
                };
                block.update(rec.position, &bytes)
            };
            attempted += 1;
            if geometry.keys >= 2 {
                attempted_multi_key += 1;
            }

            match result {
                Ok(()) => {}
                Err(e)
                    if e.why.contains(
                        "claimed by the allocation table but attributed to no key's B-tree",
                    ) =>
                {
                    hit_defect += 1;
                    hit_names.insert(name.clone());
                    if geometry.keys >= 2 {
                        hit_defect_multi_key += 1;
                    } else {
                        hit_defect_single_key += 1;
                    }
                }
                Err(_) => other_failure += 1,
            }
        }

        eprintln!(
            "TASK3B CENSUS: {total_v6} v6 corpus files ({single_key_v6} single-key, \
             {multi_key_v6} multi-key); {clean_before} round-tripped clean before any write; \
             {attempted} real writes attempted ({attempted_multi_key} of them multi-key); \
             {hit_defect} hit the shrink-leak defect \
             ({hit_defect_single_key} single-key, {hit_defect_multi_key} multi-key); \
             {other_failure} other failures; distinct hit filenames: {hit_names:?}"
        );
    }

    /// A write that relocates the same pair twice, interrupted, is still the
    /// old file.
    ///
    /// This is the case canonicalisation exists for, and the only one that
    /// can catch its absence. A shadow pair flipped an even number of times
    /// ends up back on the half it started on, so replaying those flips would
    /// write the half that is still live -- destroying the old state that
    /// phases 1 and 2 are supposed to preserve, in a way the *finished* file
    /// never shows, because by the end both halves are correct.
    ///
    /// `WCCMP002.DAT`'s first update after opening performs 107 relocations,
    /// so it is the fixture that has the shape.
    ///
    /// Ignored: needs a real `WCCMP002.DAT`, named by `$WCCMP002`.
    #[test]
    #[ignore = "needs a real WCCMP002.DAT, named by $WCCMP002"]
    fn a_v6_write_that_flips_a_pair_twice_is_still_undone_by_an_interruption() {
        let Ok(source) = std::env::var("WCCMP002") else {
            eprintln!("set WCCMP002=/path/to/WCCMP002.DAT to run this");
            return;
        };
        let dir = crate::testing::scratch("v6-double-flip-stop");
        let path = dir.join("WCCMP002.DAT");
        std::fs::copy(&source, &path).expect("the file copies into scratch");

        let mut block = block_from_file(path.clone(), "WCCMP002.DAT");
        // Every record's bytes, not just how many: an *update* leaves the
        // count alone, so a count is not enough to tell a preserved file from
        // a half-committed one. This is why the write below is an insert and
        // the comparison is over the records themselves.
        let was: Vec<(u32, Vec<u8>)> = {
            let records = block.records().expect("the records read");
            (0..records.len())
                .map(|at| {
                    let found = records.physical(at).expect("in range");
                    (found.position, found.bytes.to_vec())
                })
                .collect()
        };

        let mut record = vec![0u8; usize::from(block.geometry.reclen)];
        record[..4].copy_from_slice(&987_654u32.to_le_bytes());

        // The *first* write against a freshly opened file, which is the one
        // that relocates in bulk and so flips pairs more than once.
        STOP_AT.with(|at| at.set(Some(Stop::AfterBodies)));
        let refused = block.insert(&record);
        STOP_AT.with(|at| at.set(None));
        assert!(refused.is_err(), "the write could not have succeeded");

        let mut fresh = block_from_file(path.clone(), "WCCMP002.DAT");
        let now: Vec<(u32, Vec<u8>)> = {
            let records = fresh
                .records()
                .expect("an interrupted write left the file readable");
            (0..records.len())
                .map(|at| {
                    let found = records.physical(at).expect("in range");
                    (found.position, found.bytes.to_vec())
                })
                .collect()
        };
        assert_eq!(now.len(), was.len(), "the record count changed");
        assert_eq!(now, was, "the file no longer holds what it did");

        // The invariant itself, asserted rather than inferred. Reading the
        // records back is too weak to catch this: a half-committed table can
        // still walk to the same answer, because `walk_v6` stops after
        // `geometry.records` records and the record the write was adding
        // sorts last. What canonicalisation actually promises is narrower and
        // exact -- **the live half of every shadow pair is never written** --
        // and that is checkable byte for byte.
        let original = std::fs::read(&source).expect("the source reads");
        let interrupted = std::fs::read(&path).expect("the scratch copy reads");
        let page = usize::from(block.geometry.page);
        let mut pairs = vec![(0usize, 1usize)];
        let table = v6::Map::table_pages(&original, block.geometry.page);
        pairs.extend(table.chunks_exact(2).map(|pair| (pair[0], pair[1])));

        let generation = |image: &[u8], number: usize| -> u16 {
            let at = number * page + at::GENERATION;
            u16::from_le_bytes([image[at], image[at + 1]])
        };
        for (first, second) in pairs {
            let live = if generation(&original, first) > generation(&original, second) {
                first
            } else {
                second
            };
            assert_eq!(
                &original[live * page..][..page],
                &interrupted[live * page..][..page],
                "physical page {live} was live before the write and was \
                 written anyway"
            );
        }
    }

    /// What one v6 record update costs on a real 53 MB file.
    ///
    /// Measured on `WCCMP002.DAT` (4096-byte pages, 13,713 pages, 26,720
    /// records), release build, warm page cache:
    ///
    /// ```text
    /// one update: 135ms, read 53 MB, wrote 0 MB (file is 53 MB)
    /// 3 of 13713 pages differ: [1, 3, 8]
    /// wrote 12292 bytes; allocation map walked 4 times
    /// ```
    ///
    /// Three pages change and **12,292 bytes are written** -- the three pages
    /// themselves plus the two two-byte generation words that flip them. The
    /// three are the stale half of the file control record's shadow pair
    /// (0/1, tagged `"FC"`), the stale half of the owning allocation-table
    /// block's (2/3, tagged `"PP"`), and the data page the record lives on.
    ///
    /// It used to write all 53 MB and `sync_all` the lot: 617 ms, and a write
    /// amplification of about 4,500x. See
    /// `docs/2026-08-18-v6-write-amplification.md`, and
    /// [`Block::write_changed_pages`] for why writing three pages is as safe
    /// as replacing the file was.
    ///
    /// The 53 MB still *read* is the remaining half, and a separate decision:
    /// removing it means caching the page image on the `Block`, which costs
    /// 53 MB of memory per open file.
    ///
    /// The first update of a freshly opened file is not representative -- it
    /// claims 106 shadow twins that every later update then reuses -- so this
    /// warms up once and measures the second.
    ///
    /// Ignored because it needs a `WCCMP002.DAT`, which is not in the repo.
    /// Run it with:
    ///
    /// ```text
    /// WCCMP002=/path/to/WCCMP002.DAT \\
    ///   cargo test --release -p btrieve --lib -- --ignored --nocapture \\
    ///   v6_update_writes_only_the_pages_it_changed
    /// ```
    #[test]
    #[ignore = "needs a real WCCMP002.DAT, named by $WCCMP002"]
    fn v6_update_writes_only_the_pages_it_changed() {
        let Ok(source) = std::env::var("WCCMP002") else {
            eprintln!("set WCCMP002=/path/to/WCCMP002.DAT to run this");
            return;
        };
        let dir = crate::testing::scratch("v6-update-io-cost");
        let path = dir.join("WCCMP002.DAT");
        std::fs::copy(&source, &path).expect("the file copies into scratch");

        // `/proc/self/io` rather than `perf`, which produced zero samples on
        // this box twice; the counters are bytes this process asked the kernel
        // for, which is exactly the question.
        let io = || -> (u64, u64) {
            let text = std::fs::read_to_string("/proc/self/io").unwrap_or_default();
            let field = |name: &str| {
                text.lines()
                    .find_map(|l| l.strip_prefix(name))
                    .and_then(|v| v.trim().parse::<u64>().ok())
                    .unwrap_or(0)
            };
            (field("rchar:"), field("wchar:"))
        };

        let mut block = block_from_file(path, "WCCMP002.DAT");
        assert_eq!(block.geometry.version, Version::V6);
        let page = usize::from(block.geometry.page);

        let found = block
            .records()
            .expect("the records read")
            .physical(0)
            .expect("a first record");
        let (position, bytes) = (found.position, found.bytes.to_vec());

        block.update(position, &bytes).expect("a warm-up update");

        let before = std::fs::read(&block.path).expect("the file reads");
        crate::v6::READS.with(|reads| reads.set(0));
        WROTE.with(|wrote| wrote.set(0));
        let (read_before, wrote_before) = io();
        let start = std::time::Instant::now();
        block.update(position, &bytes).expect("a no-op update of record 0");
        let took = start.elapsed();
        let (read_after, wrote_after) = io();
        let map_reads = crate::v6::READS.with(std::cell::Cell::get);
        let wrote = WROTE.with(std::cell::Cell::get);

        let after = std::fs::read(&block.path).expect("the file reads back");
        let common = before.len().min(after.len()) / page;
        let differing: Vec<usize> = (0..common)
            .filter(|n| before[n * page..(n + 1) * page] != after[n * page..(n + 1) * page])
            .collect();

        // `/proc/self/io` is process-wide and only used for the printout;
        // every assertion below is on this write path's own counter.
        let (read, kernel_wrote) = (read_after - read_before, wrote_after - wrote_before);
        eprintln!(
            "one update: {took:?}, read {} MB, this write put down {wrote} bytes \
             (the process wrote {kernel_wrote}; the file is {} MB)",
            read / 1_048_576,
            before.len() / 1_048_576
        );
        eprintln!("{} of {common} pages differ: {differing:?}", differing.len());
        eprintln!("wrote {wrote} bytes; allocation map walked {map_reads} times");

        assert!(
            differing.len() * page < before.len() / 100,
            "an update changed {} pages of {common} -- more than 1% of the \\
             file, so writing only the changed pages has stopped being the \\
             thing worth doing",
            differing.len()
        );

        // The bound that matters: what reaches the disk is the pages that
        // changed, plus the two-byte generation word that flips each shadow
        // pair. Anything materially above that is the whole-file write coming
        // back.
        let expected = differing.len() * page;
        assert!(
            wrote <= expected + page,
            "wrote {wrote} bytes to change {expected}"
        );

        // Walking the allocation table is O(the file), and `v6_reindex` used
        // to do it once per index node. Nothing about the resulting file
        // records that cost, so this counter is the only thing that can hold
        // it down.
        assert!(
            map_reads < 20,
            "the allocation table was walked {map_reads} times for one update"
        );

        // `read` itself is deliberately not asserted on here: `/proc/self/io`
        // is process-wide, and this test file has no lock serialising it
        // against every other `--ignored` test in the same binary the way
        // `crates/btrieve/tests/write_cost.rs`'s `MEASURE_LOCK` does -- the
        // `eprintln!` above is honest best-effort reporting, not a gate.
        // `write_cost.rs`'s `wccmp002_update_cost_today` and `_cold` are
        // Plan 3 Task 5's actual bound tests for this number, and they do
        // serialise.
    }

    /// Task 6's own deferred measurement: **an insert's B-tree maintenance
    /// touches a bounded number of pages -- tree depth, not tree size** --
    /// closing the twin-search cost question Task 3 of the incremental-
    /// updates plan left open ("your rewritten write path should either
    /// eliminate it naturally ... or explicitly re-defer with a
    /// measurement in the report").
    ///
    /// Before Task 6, every insert called `Block::v6_reindex`, which
    /// rebuilds and relocates every node of every key's tree -- on
    /// `WCCMP002.DAT` (thousands of index pages) that was thousands of
    /// `Map::relocate` calls, each paying its own twin-search scan, for a
    /// single record. This task's incremental path instead descends to one
    /// leaf per key and edits its own path back to the root: at most `tree
    /// depth` pages touched, never the whole tree.
    ///
    /// Ignored because it needs a `WCCMP002.DAT`, which is not in the repo.
    #[test]
    #[ignore = "needs a real WCCMP002.DAT, named by $WCCMP002"]
    fn v6_insert_touches_a_bounded_number_of_pages_not_the_whole_tree() {
        let Ok(source) = std::env::var("WCCMP002") else {
            eprintln!("set WCCMP002=/path/to/WCCMP002.DAT to run this");
            return;
        };
        let dir = crate::testing::scratch("v6-insert-bounded-cost");
        let path = dir.join("WCCMP002.DAT");
        std::fs::copy(&source, &path).expect("the file copies into scratch");

        let mut block = block_from_file(path, "WCCMP002.DAT");
        assert_eq!(block.geometry.version, Version::V6);
        let page = usize::from(block.geometry.page);
        let reclen = usize::from(block.geometry.reclen);

        let before = std::fs::read(&block.path).expect("the file reads");
        crate::v6::READS.with(|reads| reads.set(0));
        WROTE.with(|wrote| wrote.set(0));

        let mut record = vec![0u8; reclen];
        record[..4].copy_from_slice(&999_999_001u32.to_le_bytes());
        block.insert(&record).expect("a fresh record inserts");

        let map_reads = crate::v6::READS.with(std::cell::Cell::get);
        let wrote = WROTE.with(std::cell::Cell::get);

        let after = std::fs::read(&block.path).expect("the file reads back");
        let common = before.len().min(after.len()) / page;
        let differing = (0..common)
            .filter(|n| before[n * page..(n + 1) * page] != after[n * page..(n + 1) * page])
            .count();
        let appended = (after.len() - before.len()) / page;

        eprintln!(
            "one insert: wrote {wrote} bytes, {differing} of {common} existing pages \
             differ, {appended} pages appended, allocation map walked {map_reads} times"
        );

        // The bound that matters: a handful of pages (this record's own
        // data page plus each touched key's own root-to-leaf path), never
        // the thousands a full-tree rebuild would touch.
        assert!(
            differing + appended < 20,
            "an insert touched {differing} existing pages and appended {appended} -- \
             far more than one key's own tree depth, so this is rebuilding the \
             whole tree again"
        );
        assert!(
            map_reads < 20,
            "the allocation table was walked {map_reads} times for one insert"
        );
    }

    /// Task 6's own retire/reclaim cycle, driven entirely through
    /// `Block::insert`/`Block::delete` -- not the oracle replay's own
    /// fixtures -- ends with no net growth in the file: retiring a page (a
    /// merge) and later reclaiming it (a split needing a fresh left id)
    /// nets to zero pages, the whole point of threading the B-tree free
    /// list at all rather than growing the file on every split.
    ///
    /// `V6EMPTY1KEY.DAT`'s key is 4 bytes, unique, on a 512-byte page --
    /// `Shape::capacity` gives it the identical `max_entries = 41` the
    /// split rules doc's own `append512u` fixtures measure, asserted here
    /// rather than assumed, so a change to that geometry fails loudly
    /// instead of silently changing what this test drives.
    ///
    /// The sequence, all ascending keys so every insert lands on the
    /// current rightmost leaf: 64 inserts force two leaf splits, leaving
    /// the root with 2 entries / 3 children -- deliberately more than the
    /// 2-child, 1-entry root a single split leaves, because merging the
    /// *middle* child's own pair of siblings must not put the root at risk
    /// of collapsing to zero entries the way merging one of only two
    /// children would (that scenario is `a_shrinking_v6_reindex_releases_
    /// its_surplus_pages_on_delete`'s own subject, a refusal, not this
    /// test's). Deleting the middle child's own lowest two entries
    /// underflows it (21->20, no underflow; 20->19, underflows) and its
    /// right sibling's own entries are not `> half_entries`, so §6 merges
    /// rather than redistributes, retiring the middle child's own
    /// (freshly-claimed, second-split) id -- the root drops from 2 to 1
    /// entries, still healthy. Two more inserts push the merged survivor
    /// past `max_entries` again, needing a new left id, which the split
    /// must reclaim from the free list rather than grow the file for.
    #[test]
    fn a_retire_then_reclaim_cycle_through_ordinary_inserts_and_deletes_nets_no_growth() {
        let (mut block, path) = v6_scratch("btv-v6-retire-reclaim-cycle");
        let max_entries = block.keys[0].shape().capacity(block.geometry.page);
        assert_eq!(max_entries, 41, "this test's own arithmetic assumes append512u's geometry");

        let key_at = |n: u32| -> [u8; 4] {
            format!("{n:04}").into_bytes().try_into().expect("4 ASCII digits")
        };

        // 64 ascending inserts: the first split lands at n=41 (root gains
        // 1 entry, 2 children); continuing to insert onto the new
        // rightmost leaf lands the second split at n=63 (root gains a
        // second entry, 3 children) -- both split points established by
        // this same arithmetic (`ceil(41/2)=21` left, 20 right) as the
        // oracle-recorded `append512u_leaf_split` fixture, just carried
        // one level further here.
        let mut positions = Vec::with_capacity(64);
        for n in 0..64u32 {
            positions.push(block.insert(&v6_record(&key_at(n))).expect("insert"));
        }

        // The middle child (the second split's own new left leaf) holds
        // keys 22..=42 -- its own lowest two.
        block.delete(positions[22]).expect("first delete off the middle child (21->20, no underflow)");
        block.delete(positions[23]).expect("second delete triggers the middle child's own merge");

        let after_merge = std::fs::read(&path).expect("reads");
        let free_head_after_merge = pages::long(
            &v6_fcr(&block, &after_merge)[pages::fcr::INDEX_FREE_V6..pages::fcr::INDEX_FREE_V6 + 4],
        );
        assert_ne!(
            free_head_after_merge,
            pages::NOWHERE,
            "the merge must have retired a page onto the B-tree free list"
        );
        let size_with_retired_page = after_merge.len();

        block.insert(&v6_record(&key_at(64))).expect("push the merged survivor to max_entries");
        block.insert(&v6_record(&key_at(65))).expect("push it past max_entries, forcing another split");

        let after_reclaim = std::fs::read(&path).expect("reads");
        let free_head_after_reclaim = pages::long(
            &v6_fcr(&block, &after_reclaim)[pages::fcr::INDEX_FREE_V6..pages::fcr::INDEX_FREE_V6 + 4],
        );
        assert_eq!(
            free_head_after_reclaim,
            pages::NOWHERE,
            "the next split needing a fresh left id must reclaim the retired page, not \
             leave it on the free list and claim a new one instead"
        );
        assert_eq!(
            after_reclaim.len(),
            size_with_retired_page,
            "a retire-then-reclaim cycle must not grow the file: the reclaim reused the \
             retired page's own physical slot rather than appending a fresh one"
        );
    }

    /// Task 4 of the incremental-updates plan: locating a v6 record's
    /// physical page must read a small, fixed number of pages, never the
    /// whole file.
    ///
    /// `v6_slot` used to spend one `std::fs::read(&self.path)` -- the entire
    /// 55,734,272-byte `WCCMP002.DAT` -- resolving a single logical id.
    /// `Self::v6_resolve_logical` is the fix: it reads only the one
    /// allocation-table block that answers for the logical id in question
    /// (two pages, found by [`format::alloc::block_of`] and
    /// [`format::alloc::pair_position`], never a scan), and nothing else.
    /// This calls it directly -- the same private function `v6_slot` itself
    /// calls, not a reimplementation -- so a regression that put the
    /// whole-file read back would fail this test even if every other
    /// assertion in this file kept passing.
    ///
    /// Bounded at eight pages rather than exactly two: generous enough that a
    /// small, deliberate change to how many blocks get consulted would not
    /// make this flap, tight enough that a whole-file read (13,607 pages on
    /// this file) cannot sneak through unnoticed.
    ///
    /// Ignored: needs a real `WCCMP002.DAT`, named by `$WCCMP002`.
    #[test]
    #[ignore = "needs a real WCCMP002.DAT, named by $WCCMP002"]
    fn locating_a_v6_slot_reads_pages_not_the_file() {
        let Ok(source) = std::env::var("WCCMP002") else {
            eprintln!("set WCCMP002=/path/to/WCCMP002.DAT to run this");
            return;
        };
        let dir = crate::testing::scratch("v6-locate-io-cost");
        let path = dir.join("WCCMP002.DAT");
        std::fs::copy(&source, &path).expect("the file copies into scratch");
        let file_len = std::fs::metadata(&path).expect("metadata").len();

        let io = || -> u64 {
            let text = std::fs::read_to_string("/proc/self/io").unwrap_or_default();
            text.lines()
                .find_map(|l| l.strip_prefix("rchar:"))
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(0)
        };

        let mut block = block_from_file(path, "WCCMP002.DAT");
        assert_eq!(block.geometry.version, Version::V6);
        let page = u64::from(block.geometry.page);

        let position = block
            .records()
            .expect("the records read")
            .physical(0)
            .expect("a first record")
            .position;
        let layout = pages::Layout {
            page: block.geometry.page,
            physical: block.geometry.physical,
            pages: block.geometry.pages,
        };
        let (logical, _slot) = layout.slot_of(position).expect("a slot-aligned position");

        let before = io();
        let physical = block.v6_resolve_logical(logical).expect("the logical page resolves");
        let after = io();
        let read = after - before;

        eprintln!(
            "locating logical page {logical} (-> physical {physical}) in a {} MB file read \
             {read} bytes ({} pages of {page})",
            file_len / 1_048_576,
            read / page.max(1)
        );

        assert!(
            read <= 8 * page,
            "locating one slot read {read} bytes of a {page}-byte page -- expected a small \
             multiple of the page size, not something that scales with the file's \
             {file_len} bytes"
        );
    }

    /// What one `obtbtvl` costs on the board's largest v5 file.
    ///
    /// `_UPDATE_POLLING_ROUTINE` (`re/exports/WCCMMUD_named.c:57538`) is
    /// MajorMUD's database update. `_BEGIN_UPDATING` (`:57678`) opens a file,
    /// proves it is not empty with option 13 (`Op::Highest`), and installs the
    /// worker through `begin_polling`; the worker then walks the file one
    /// record per poll dispatch with `obtbtvl(rec, key, 0, 8, 0)` -- option 8
    /// is `Op::Greater` -- and `stop_polling`s itself when the walk runs out.
    ///
    /// Every one of those dispatches spends one unit of `Host::cycle`'s
    /// per-second poll grant, which is the same grant that serves player
    /// channels. So what one step costs is what the grant buys, and the last
    /// line printed here is the share of every second the update takes at the
    /// shipped `--polls-per-second 512`.
    ///
    /// Ignored because it needs a real `WCCUPDAT.DAT`, which is not in the
    /// repo. Run it with:
    ///
    /// ```text
    /// WCCUPDAT=~/peepeebbs/WCCUPDAT.DAT \\
    ///   cargo test --release -p btrieve --lib -- --ignored --nocapture \\
    ///   v5_keyed_walk_cost_per_obtbtvl
    /// ```
    #[test]
    #[ignore = "needs a real WCCUPDAT.DAT, named by $WCCUPDAT"]
    fn v5_keyed_walk_cost_per_obtbtvl() {
        let Ok(source) = std::env::var("WCCUPDAT") else {
            eprintln!("set WCCUPDAT=/path/to/WCCUPDAT.DAT to run this");
            return;
        };
        let dir = crate::testing::scratch("v5-keyed-walk-cost");
        let path = dir.join("WCCUPDAT.DAT");
        std::fs::copy(&source, &path).expect("the file copies into scratch");
        let size = std::fs::metadata(&path).expect("the copy stats").len();

        // `/proc/self/io`'s `rchar`, the same counter the v6 write-cost test
        // uses: bytes this process asked the kernel for, which is the question
        // "does a step go back to the disk?".
        let rchar = || -> u64 {
            let text = std::fs::read_to_string("/proc/self/io").unwrap_or_default();
            text.lines()
                .find_map(|l| l.strip_prefix("rchar:"))
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(0)
        };

        let read_at_open = rchar();
        let opening = std::time::Instant::now();
        let mut block = block_from_file(path, "WCCUPDAT.DAT");
        let open_took = opening.elapsed();
        assert_eq!(block.geometry.version, Version::V5);
        let reclen = block.geometry.reclen;
        let page = block.geometry.page;

        let loading = std::time::Instant::now();
        let count = block.records().expect("the records read").len();
        let load_took = loading.elapsed();
        let read_after_load = rchar();

        let mut locks = LockTable::default();
        let first = block
            .get(0, Op::Lowest, &[], 0, &mut locks, reclen)
            .expect("the lowest key reads")
            .expect("a first record");
        let mut key = first.key.expect("a keyed read carries its key");

        let steps = 2000.min(count.saturating_sub(1));
        let read_before_walk = rchar();
        let walking = std::time::Instant::now();
        let mut worst = std::time::Duration::ZERO;
        let mut done = 0usize;
        for _ in 0..steps {
            let one = std::time::Instant::now();
            let found = block
                .get(0, Op::Greater, &key, 0, &mut locks, reclen)
                .expect("a keyed walk step");
            let took = one.elapsed();
            let Some(next) = found else { break };
            if took > worst {
                worst = took;
            }
            key = next.key.expect("a keyed read carries its key");
            done += 1;
        }
        let walk_took = walking.elapsed();
        let read_after_walk = rchar();

        let each = walk_took / u32::try_from(done.max(1)).unwrap_or(1);
        eprintln!(
            "WCCUPDAT.DAT: {} MB, {count} records, v5, {page}-byte pages, reclen {reclen}",
            size / 1_048_576
        );
        eprintln!(
            "open: {open_took:?}; records() model build: {load_took:?}; together they read {} MB",
            (read_after_load - read_at_open) / 1_048_576
        );
        eprintln!(
            "{done} keyed Greater steps: {walk_took:?} total, {each:?} each, worst {worst:?}"
        );
        eprintln!(
            "the walk read {} bytes from the kernel -- ~0 means the model is in memory \
             and a step is pure CPU",
            read_after_walk - read_before_walk
        );
        eprintln!(
            "at the shipped 512 polls/s that is {:.0} ms of every second spent in obtbtvl",
            each.as_secs_f64() * 512.0 * 1000.0
        );
    }

    /// A record this host inserts into a file **genuine Btrieve 6.15 wrote**,
    /// read back whole from disk.
    ///
    /// `tests/data/variable/V6VAR.DAT` was created and filled by
    /// `tools/btrieve-oracle/varfree.c` running against the real engine under
    /// Wine: 512-byte pages, reclen 22, one unique key, and six records whose
    /// bodies are already fragments spread over two variable pages. The
    /// engine's own free-space chain is live in it. See
    /// `docs/2026-08-17-variable-write-oracle.md`.
    ///
    /// The body here is 300 bytes -- larger than the room left on the page
    /// the chain offers, so this exercises claiming a page as well as
    /// placing on one.
    #[test]
    fn insert_writes_a_variable_length_record_into_a_file_the_engine_made() {
        let dir = crate::testing::scratch("v6-variable-insert-real");
        let path = dir.join("V6VAR.DAT");
        std::fs::copy(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/variable/V6VAR.DAT"),
            &path,
        )
        .expect("the fixture copies into a scratch directory");

        let mut block = block_from_file(path, "V6VAR.DAT");
        assert!(block.geometry.variable, "the fixture holds variable-length records");
        assert_eq!(block.geometry.version, Version::V6);

        let before = block.records().expect("the engine's own records read").len();
        assert!(before > 0, "the fixture is not empty: {before} records");

        let reclen = usize::from(block.geometry.reclen);
        let mut record = vec![0xeeu8; reclen];
        record[..4].copy_from_slice(&99u32.to_le_bytes());
        record.extend_from_slice(&[0x5a; 300]);

        block.insert(&record).expect("a 322-byte record over a 22-byte reclen");

        // Dropped, so this is a fresh walk of what actually reached the disk
        // rather than the model that was just updated in memory.
        block.records = None;
        let after = block.records().expect("a fresh read from disk");
        assert_eq!(after.len(), before + 1, "the record went in");

        let mine = (0..after.len())
            .filter_map(|at| after.physical(at))
            .find(|r| r.bytes.starts_with(&99u32.to_le_bytes()))
            .expect("the new record is found by its key");
        assert_eq!(
            mine.bytes.len(),
            record.len(),
            "all 322 bytes come back, not the 22-byte fixed part"
        );
        assert_eq!(mine.bytes, record, "byte for byte");
    }


    /// A v6 write interrupted before its flip leaves every record readable.
    ///
    /// This is the property [`Block::write_changed_pages`] replaced the
    /// whole-file rename with. The rename made the switch atomic by never
    /// touching the original until the new file was complete; writing pages
    /// in place has to get the same result out of the format's own shadow
    /// paging, by putting every page down before anything makes it live.
    ///
    /// Both boundaries before the flip are checked, because they hold for
    /// different reasons: after phase 1 the new content is on the disk but
    /// unreferenced, and after phase 2 the new control record and allocation
    /// table are on the disk too, still carrying generations that lose to the
    /// halves they will replace. Neither may be visible.
    ///
    /// A SIGKILL cannot be staged from a test, so [`STOP_AT`] stages the
    /// interruption instead -- see [`Stop`].
    #[test]
    fn a_v6_write_stopped_before_the_flip_leaves_every_record_readable() {
        for stop in [Stop::AfterContent, Stop::AfterBodies] {
            let dir = crate::testing::scratch(&format!("v6-stop-{stop:?}"));
            let path = dir.join("IDXPROBE.DAT");
            std::fs::copy(
                concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/variable/IDXPROBE.DAT"),
                &path,
            )
            .expect("the engine-built fixture copies into a scratch directory");

            let mut block = block_from_file(path.clone(), "IDXPROBE.DAT");
            let was: Vec<Vec<u8>> = {
                let records = block.records().expect("records read");
                (0..records.len())
                    .map(|at| records.physical(at).expect("in range").bytes.to_vec())
                    .collect()
            };

            let mut record = vec![0u8; usize::from(block.geometry.reclen)];
            record[..4].copy_from_slice(&777u32.to_le_bytes());
            record[4..8].copy_from_slice(&777u32.to_le_bytes());

            STOP_AT.with(|at| at.set(Some(stop)));
            let refused = block.insert(&record);
            STOP_AT.with(|at| at.set(None));
            assert!(refused.is_err(), "{stop:?}: the write could not have succeeded");

            // Re-read from disk, not from the model: the model is what a
            // crash would have thrown away.
            let mut fresh = block_from_file(path, "IDXPROBE.DAT");
            let now: Vec<Vec<u8>> = {
                let records = fresh
                    .records()
                    .unwrap_or_else(|e| panic!("{stop:?}: the file still opens and reads: {e}"));
                (0..records.len())
                    .map(|at| records.physical(at).expect("in range").bytes.to_vec())
                    .collect()
            };
            assert_eq!(now, was, "{stop:?}: the file no longer reads as it did");
        }
    }

    /// The one window the design leaves open refuses loudly rather than
    /// dropping a record quietly.
    ///
    /// A crash between the two flips leaves the new record count committed and
    /// the allocation table still naming the old pages, so the header and the
    /// pages disagree by one and `records::read` says so and stops. The file
    /// needs a repair, which is the honest outcome of an interrupted write.
    ///
    /// The reverse order is what this test exists to prevent. With the table
    /// flipped first the pages would hold the new record under a header still
    /// carrying the old count, `records::walk_v6` stops after
    /// `geometry.records` records, the count then matches, and one record --
    /// whichever falls last in logical order -- is silently gone. A refusal
    /// that names the problem beats a file that quietly reads short, so if
    /// someone reorders those two loops, this fails.
    #[test]
    fn a_v6_write_stopped_between_the_two_flips_refuses_rather_than_losing_one() {
        let dir = crate::testing::scratch("v6-stop-between-flips");
        let path = dir.join("IDXPROBE.DAT");
        std::fs::copy(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/variable/IDXPROBE.DAT"),
            &path,
        )
        .expect("the engine-built fixture copies into a scratch directory");

        let mut block = block_from_file(path.clone(), "IDXPROBE.DAT");
        let was = block.records().expect("records read").len();

        let mut record = vec![0u8; usize::from(block.geometry.reclen)];
        record[..4].copy_from_slice(&778u32.to_le_bytes());
        record[4..8].copy_from_slice(&778u32.to_le_bytes());

        STOP_AT.with(|at| at.set(Some(Stop::AfterFirstFlip)));
        let refused = block.insert(&record);
        STOP_AT.with(|at| at.set(None));
        assert!(refused.is_err(), "the write could not have succeeded");

        let mut fresh = block_from_file(path, "IDXPROBE.DAT");
        let why = fresh
            .records()
            .expect_err("the header and the pages disagree, so this must refuse")
            .why;
        assert_eq!(
            why,
            format!(
                "the header says {} records and walking the pages found {was}",
                was + 1
            ),
            "the refusal did not name the count the interrupted write committed"
        );
    }

    /// A v6 key whose index spans more than one page is maintained, not
    /// refused -- and the tree the engine built is *reused*, not replaced.
    ///
    /// `IDXPROBE.DAT` was created and filled by genuine Btrieve 6.15 under
    /// Wine (`tools/btrieve-oracle/crtprobe.exe`, 2026-08-17): 512-byte pages,
    /// `reclen` 16, two unique four-byte keys whose orders are deliberately
    /// opposite (key 0 ascending 1..120, key 1 descending), and 120 records.
    /// A four-byte unique key's entry is twelve bytes, so one 512-byte page
    /// holds forty-one of them and 120 records cannot fit in one: the engine
    /// gave **both** keys a two-level tree, a root over several leaves.
    ///
    /// That is the wall MajorMUD-NT's boot hit next, on a file that needs a
    /// hundred index pages rather than five:
    ///
    /// ```text
    /// WGSERVER.EXE.dfaupdatedup refused: WCCMP002.DAT: key 0: 26720 records
    /// need 106 index pages, and this host only maintains a v6 key whose
    /// whole index fits one
    /// ```
    ///
    /// # Verified against the engine itself, not only against this crate
    ///
    /// The file this test writes was handed back to genuine Btrieve 6.15 under
    /// Wine (`tools/btrieve-oracle/btrvprobe.exe`, 2026-08-17). All of its
    /// checks pass on our output:
    ///
    /// ```text
    /// stat      records 121, key 0 approx=121, key 1 approx=121
    /// walk      walked 121, stat says 121, regressions 0   -> WALK OK
    /// descend 0 descents 121, failures 0, wrong rec 0      -> DESCEND OK
    /// descend 1 descents 121, failures 0, wrong rec 0      -> DESCEND OK
    /// ```
    ///
    /// `descend` is the one that matters: it does a `GET_EQUAL` for every key
    /// value, which forces the engine down its own root-to-leaf traversal of
    /// the tree this host wrote -- through the interior node and into the right
    /// leaf, 121 times per key. A tree with a wrong child pointer, a wrongly
    /// tagged page or a mis-split node does not survive that.
    ///
    /// The reuse half is what this asserts hardest. `Self::v6_index_logicals`
    /// walks the tree the file already has and hands those ids back to
    /// `pages::number_pages`, so a rebuild lands on the pages it already
    /// occupied. Claiming fresh ids instead would still produce a valid file
    /// and pass every other assertion here -- while leaking one
    /// allocation-table slot per node per write, which on a hundred-page index
    /// exhausts the table in a few hundred inserts. The claim count is
    /// therefore checked directly.
    #[test]
    fn a_v6_key_whose_index_needs_several_pages_is_maintained() {
        let dir = crate::testing::scratch("v6-multi-page-index");
        let path = dir.join("IDXPROBE.DAT");
        std::fs::copy(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/variable/IDXPROBE.DAT"),
            &path,
        )
        .expect("the engine-built fixture copies into a scratch directory");

        let mut block = block_from_file(path.clone(), "IDXPROBE.DAT");
        assert_eq!(block.geometry.version, Version::V6);
        assert_eq!(block.keys.len(), 2, "the engine built it with two keys");
        let before = block.records().expect("the engine's own records read").len();
        assert_eq!(before, 120);

        // Both keys really do need more than one page -- otherwise this test
        // would pass without ever leaving the single-page path.
        let whole = std::fs::read(&path).expect("reads");
        for key in &block.keys {
            let definition =
                pages::fcr::KEYS + usize::from(key.definition) * pages::fcr::KEY_WIDTH;
            let mut store = v6::Store::from_bytes(&whole, block.geometry.page).expect("test fixture");
            let live = block.v6_live_fcr(&mut store).expect("a live control record");
            let raw = pages::long(&live[definition..definition + 4]);
            let tag = [0x00, 0x80 | key.number as u8];
            let nodes = Block::<Flat>::v6_index_logicals(
                &mut store,
                block.geometry.page,
                raw & pages::fcr::ROOT_PAGE,
                tag,
                key.shape(),
            )
            .expect("the engine's own tree walks");
            assert!(
                nodes.len() > 1,
                "key {}'s index is {} page(s); this fixture exists to exercise more \
                 than one",
                key.number,
                nodes.len()
            );
        }

        let claimed_before = v6::Map::read(&mut v6::Store::from_bytes(&whole, block.geometry.page).expect("test fixture"), block.geometry.page)
            .expect("resolves")
            .entries()
            .count();

        let mut record = vec![0u8; usize::from(block.geometry.reclen)];
        record[..4].copy_from_slice(&500u32.to_le_bytes());
        record[4..8].copy_from_slice(&500u32.to_le_bytes());
        block.insert(&record).expect("an insert into a multi-page index");

        // Re-read from disk rather than trusting the in-memory model.
        block.records = None;
        let after = block.records().expect("a fresh read from disk");
        assert_eq!(after.len(), before + 1, "the record went in");

        let whole = std::fs::read(&path).expect("reads");
        let claimed_after = v6::Map::read(&mut v6::Store::from_bytes(&whole, block.geometry.page).expect("test fixture"), block.geometry.page)
            .expect("resolves")
            .entries()
            .count();
        assert!(
            claimed_after <= claimed_before + 2,
            "one insert claimed {} new pages: the existing index tree is meant to be \
             walked and reused, not re-claimed node by node",
            claimed_after - claimed_before
        );

        // Every key's tree still walks, still belongs to that key, and still
        // holds one entry per record.
        for key in &block.keys {
            let definition =
                pages::fcr::KEYS + usize::from(key.definition) * pages::fcr::KEY_WIDTH;
            let mut store = v6::Store::from_bytes(&whole, block.geometry.page).expect("test fixture");
            let live = block.v6_live_fcr(&mut store).expect("a live control record");
            let raw = pages::long(&live[definition..definition + 4]);
            let tag = [0x00, 0x80 | key.number as u8];
            let nodes = Block::<Flat>::v6_index_logicals(
                &mut store,
                block.geometry.page,
                raw & pages::fcr::ROOT_PAGE,
                tag,
                key.shape(),
            )
            .unwrap_or_else(|e| panic!("key {}: the rebuilt tree walks: {e}", key.number));
            assert!(nodes.len() > 1, "key {} still spans several pages", key.number);

            let map = v6::Map::read(&mut store, block.geometry.page).expect("resolves");
            let page = usize::from(block.geometry.page);
            for logical in &nodes {
                let physical = map.physical(*logical).expect("claimed") as usize;
                let tag_read =
                    u16::from_le_bytes([whole[physical * page], whole[physical * page + 1]]);
                assert_eq!(
                    tag_read,
                    0x8000 | (key.number << 8),
                    "logical {logical} is in key {}'s tree and must carry its tag",
                    key.number
                );
            }
        }
    }

    /// Key **1**'s index pages are tagged `0x8100`, not key 0's `0x8000`.
    ///
    /// A v6 index page's type tag carries the key's own number in its high
    /// byte -- `0x8000` for key 0, `0x8100` for key 1 -- exactly as the file
    /// control record's `KEY_ROOT` field does
    /// ([`pages::fcr::ROOT_PAGE`]'s doc comment). Measured against genuine
    /// Btrieve 6.15 (`crtprobe.exe`, 2026-08-17): a two-key v6 file built and
    /// filled with 120 records by the engine gives key 1 a root page opening
    /// `00 81`, with every child pointer in it reading `0x81......`, against
    /// key 0's `00 80` and `0x80......`.
    ///
    /// `WGSGEN2.VIR` is the same shape and says the same thing before anything
    /// has been written to it: key 0's root is logical 2 on a page tagged
    /// `0x8000`, key 1's is logical 3 on a page tagged `0x8100`.
    ///
    /// This host wrote `0x8000` for both. The mistake survived because
    /// [`v6::Map::relocate`] rewrites only the page-number half of an
    /// allocation-table entry and leaves the marker untouched, so the table
    /// went on saying `0x8100` while the page it pointed at said `0x8000` --
    /// a disagreement no reader in this crate consults and every one of its
    /// tests was blind to.
    #[test]
    fn each_keys_index_pages_are_tagged_with_that_keys_own_number() {
        let dir = crate::testing::scratch("wgsgen2-index-page-tags");
        let path = dir.join("WGSGEN2.DAT");
        std::fs::copy(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/variable/WGSGEN2.VIR"),
            &path,
        )
        .expect("the virgin fixture copies into a scratch directory");

        let mut block = block_from_file(path.clone(), "WGSGEN2.DAT");
        let reclen = usize::from(block.geometry.reclen);
        let mut record = vec![0u8; reclen];
        record[..4].copy_from_slice(&1u32.to_le_bytes());
        record.extend_from_slice(&[0xa5u8; 7]);
        block.insert(&record).expect("one record goes in");

        // Read the roots back off the file exactly as `v6_reindex` found them.
        let whole = std::fs::read(&path).expect("the file reads");
        let page = usize::from(block.geometry.page);
        let mut store = v6::Store::from_bytes(&whole, block.geometry.page).expect("test fixture");
        let live = block.v6_live_fcr(&mut store).expect("a live control record");
        let map = v6::Map::read(&mut store, block.geometry.page).expect("resolves");

        for key in &block.keys {
            let definition =
                pages::fcr::KEYS + usize::from(key.definition) * pages::fcr::KEY_WIDTH;
            let raw = pages::long(&live[definition..definition + 4]);
            let logical = raw & pages::fcr::ROOT_PAGE;
            let physical = map.physical(logical).expect("the root is claimed") as usize;
            let tag = u16::from_le_bytes([whole[physical * page], whole[physical * page + 1]]);

            let want = 0x8000u16 | (key.number << 8);
            assert_eq!(
                tag, want,
                "key {}'s index root (logical {logical}, physical {physical}) is tagged \
                 {tag:#06x}, and this key's pages are {want:#06x}",
                key.number
            );
            assert_eq!(
                (raw >> 24) as u16,
                0x80 | key.number,
                "and the control record's own root field agrees"
            );
        }
    }

    /// The wall MajorMUD-NT's boot used to hit: three successive
    /// variable-length inserts into `WGSGEN2.DAT` left the header's record
    /// count and the page walk disagreeing.
    ///
    /// ```text
    /// WGSERVER.EXE.dfaacqlock refused: WGSGEN2.DAT: the header says 3
    /// records and walking the pages found 2
    /// ```
    ///
    /// The module inserts one demo-clock record per boot and re-reads the
    /// file afterwards, so this was not an exotic path -- it was the second
    /// and third time anything was written to a file this host created.
    ///
    /// # The cause, and why it took three inserts to show
    ///
    /// `WGSGEN2.DAT`'s key 0 is a **segmented duplicate key**, and `keys.rs`
    /// read every key's in-record chain offset off its *last* definition. A
    /// segmented key carries that offset in its *first* one, so key 0's chain
    /// offset came back as 0 -- not a chain at all, but the front of the slot.
    /// [`Self::v6_reindex`] then wrote each duplicate pair at `slot + 0`, and
    /// because [`pages::to_long`] stores a long word-swapped, a `prev` of
    /// position 16390 (`0x4006`) laid down `00 00 06 40`, clearing the
    /// two-byte marker of the very slot it was describing.
    ///
    /// Three inserts, because a chain pair is only non-`NOWHERE` once a record
    /// has a neighbour on both sides. The first two inserts wrote
    /// `ff ff ff ff` over their markers, which reads as occupied and so did no
    /// visible harm; the third gave the middle record a real `prev`, whose
    /// swapped high word is zero, and the marker read free. The slot markers
    /// after each insert:
    ///
    /// ```text
    /// insert 0   [ffff,    0,    0]
    /// insert 1   [ffff, ffff,    0]
    /// insert 2   [ffff,    0, ffff]     <- slot 1 now reads free
    /// ```
    ///
    /// See `keys.rs`'s
    /// `a_segmented_duplicate_key_reads_its_chain_offset_from_its_first_segment`
    /// for the fixture's own key descriptors and the fix.
    ///
    /// # Two things an earlier reading recorded as suspects, both wrong
    ///
    /// Kept because they cost a session and would cost another. Neither is a
    /// divergence from genuine 6.15:
    ///
    /// 1. **"Physical pages 7 and 10 both carry logical id 4, and this host
    ///    never advances their generation word."** They are logical 4's shadow
    ///    *twin pair*, which is exactly what [`v6::Map::relocate`] measured the
    ///    engine doing -- a page alternates between two physical homes on
    ///    successive writes. Nothing needs to distinguish them by a stamp of
    ///    their own: the allocation table says which one is live, and a data
    ///    page's `[0x04]` is a modification stamp, not the generation counter
    ///    an allocation-table or control-record page carries.
    /// 2. **"The two allocation-table copies disagree about pages already
    ///    claimed, so a claim is being lost."** Traced entry by entry across
    ///    all three inserts, the live table is correct at every step and never
    ///    loses a claim. What alternates is which *physical* page each logical
    ///    id resolves to -- twin flipping again -- and which of physical 2 and
    ///    3 is live, which is what copy-on-write means.
    ///
    /// Both readings were taken from snapshots of the file between inserts.
    /// The defect was never in the allocation table; it was eight bytes
    /// written at the wrong offset inside a record.
    #[test]
    fn repeated_variable_inserts_keep_the_header_count_and_the_walk_agreeing() {
        let dir = crate::testing::scratch("wgsgen2-repeated-variable-insert");
        let path = dir.join("WGSGEN2.DAT");
        std::fs::copy(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/variable/WGSGEN2.VIR"),
            &path,
        )
        .expect("the virgin fixture copies into a scratch directory");

        let mut block = block_from_file(path.clone(), "WGSGEN2.DAT");
        assert!(block.geometry.variable);
        let reclen = usize::from(block.geometry.reclen);

        for n in 0..3u32 {
            let mut record = vec![0u8; reclen];
            record[..4].copy_from_slice(&(n + 1).to_le_bytes());
            // The module's own record runs past `reclen` -- 62 bytes over a
            // 55-byte fixed part -- which is what makes it variable at all.
            record.extend_from_slice(&[0xa5u8; 7]);
            block.insert(&record).unwrap_or_else(|e| panic!("insert {n}: {e:?}"));

            block.records = None;
            let seen = block
                .records()
                .unwrap_or_else(|e| panic!("re-read after insert {n}: {e:?}"))
                .len();
            assert_eq!(
                seen,
                n as usize + 1,
                "after insert {n} the walk must find every record the header counts"
            );
        }
    }


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
    fn block_variable(path: PathBuf) -> Block<Flat> {
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
            modifiable: true,
            chain: None,
                    acs: None,
                    null: None,
}];
        Block {
            id: ops::BlockId::fresh(),
            name: "VARIABLE.DAT".to_owned(),
            path,
            geometry,
            keys,
            block: FlatPtr::NULL,
            maxlen: 28,
            data: FlatPtr::NULL,
            key: FlatPtr::NULL,
            records: None,
            cursor: Cursor::Nowhere,
            dirty: false,
            txn_active: false,
            pre_image: None,
            // A test-only fixture, not `Self::open` -- see
            // `Self::verify_writes`'s doc comment for why this stays off.
            verify_writes: false,
            // Same reasoning: a test-only fixture never goes through
            // `Self::open`, the only place that captures a mode at all.
            mode: PRIMBV,
            // Same reasoning: a test-only fixture never goes through
            // `Self::open`, the only place that builds one.
            cache: None,
            v6_order: std::cell::RefCell::new(std::collections::HashMap::new()),
            v6_physical: std::cell::RefCell::new(None),
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
    fn block_indexed(path: PathBuf) -> Block<Flat> {
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
            modifiable: true,
            chain: None,
                    acs: None,
                    null: None,
}];
        Block {
            id: ops::BlockId::fresh(),
            name: "INDEXED.DAT".to_owned(),
            path,
            geometry,
            keys,
            block: FlatPtr::NULL,
            maxlen: 16,
            data: FlatPtr::NULL,
            key: FlatPtr::NULL,
            records: None,
            cursor: Cursor::Nowhere,
            dirty: false,
            txn_active: false,
            pre_image: None,
            // A test-only fixture, not `Self::open` -- see
            // `Self::verify_writes`'s doc comment for why this stays off.
            verify_writes: false,
            // Same reasoning: a test-only fixture never goes through
            // `Self::open`, the only place that captures a mode at all.
            mode: PRIMBV,
            // Same reasoning: a test-only fixture never goes through
            // `Self::open`, the only place that builds one.
            cache: None,
            v6_order: std::cell::RefCell::new(std::collections::HashMap::new()),
            v6_physical: std::cell::RefCell::new(None),
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
    fn block_duplicated(path: PathBuf) -> Block<Flat> {
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
    fn block_with_many_records(dir: &Path, n: u16) -> Block<Flat> {
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
    fn block_two_keys(path: PathBuf) -> Block<Flat> {
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
                modifiable: true,
                chain: None,
                            acs: None,
                            null: None,
},
            Key {
                number: 1,
                definition: 2,
                segments: vec![segment(4)],
                duplicates: false,
                modifiable: true,
                chain: None,
                            acs: None,
                            null: None,
},
        ];
        Block {
            id: ops::BlockId::fresh(),
            name: "TWOKEY.DAT".to_owned(),
            path,
            geometry,
            keys,
            block: FlatPtr::NULL,
            maxlen: 16,
            data: FlatPtr::NULL,
            key: FlatPtr::NULL,
            records: None,
            cursor: Cursor::Nowhere,
            dirty: false,
            txn_active: false,
            pre_image: None,
            // A test-only fixture, not `Self::open` -- see
            // `Self::verify_writes`'s doc comment for why this stays off.
            verify_writes: false,
            // Same reasoning: a test-only fixture never goes through
            // `Self::open`, the only place that captures a mode at all.
            mode: PRIMBV,
            // Same reasoning: a test-only fixture never goes through
            // `Self::open`, the only place that builds one.
            cache: None,
            v6_order: std::cell::RefCell::new(std::collections::HashMap::new()),
            v6_physical: std::cell::RefCell::new(None),
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

    /// `seed_indexed`'s key names page 1 as its root (`0x110`, [`pages::fcr`]'s
    /// `KEY_ROOT`), and that page starts out empty behind its header. Only
    /// [`Btrieve::reindex`] ever writes it.
    fn root_page(path: &Path) -> Vec<u8> {
        let bytes = std::fs::read(path).expect("read the file back");
        bytes[512..1024].to_vec()
    }

    /// Every v5 write keeps the key's stored count live, not just insert.
    ///
    /// This test exists because a mutation found its absence: disabling
    /// [`Btrieve::write_key_record_counts`] in `delete` alone left the whole
    /// suite green, so `delete`'s half of the fix was covered by nothing. A
    /// fix watched failing in one caller and not the others is one third of
    /// a fix.
    #[test]
    fn a_delete_takes_the_keys_stored_count_down_with_it() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut btrieve = Btrieve::default();

        let path = seed_indexed(&crate::testing::scratch("btrieve-delete-key-count"));
        let at = open_indexed(&mut mem, &mut heap, &mut btrieve, path.clone());

        let first = btrieve.block_mut(at).expect("open").insert(&record(1)).expect("insert");
        btrieve.block_mut(at).expect("open").insert(&record(2)).expect("insert");
        assert_eq!(key_records(&path), 2, "two records, two distinct key values");

        btrieve.block_mut(at).expect("open").delete(first).expect("delete");
        assert_eq!(key_records(&path), 1, "a delete lowers the key's own stored count");
    }

    /// Register `seed_indexed`'s block as a real open file: allocate its four
    /// module-memory pieces on a real heap and write `field::FILNAM` the way
    /// [`Btrieve::open`] does, then push it directly rather than going
    /// through `keys::parse` -- `seed_indexed`'s key definition has no real
    /// attributes, only a root, and `block_indexed`'s hand-built [`Key`]
    /// already describes it correctly. Returns the pointer a module's `bb`
    /// would hold.
    fn open_indexed(
        mem: &mut FlatMem,
        heap: &mut FlatHeap,
        btrieve: &mut Btrieve<Flat>,
        path: PathBuf,
    ) -> FlatPtr {
        let mut block = block_indexed(path);

        let filnam = heap.reserve(mem, 12).expect("alloc filnam");
        Flat::write(filnam, mem, b"INDEXED.DAT\0").expect("write filnam");

        let data = heap.reserve(mem, block.maxlen).expect("alloc data");
        Flat::write(data, mem, &vec![0u8; usize::from(block.maxlen)]).expect("write data");

        let key = heap.reserve(mem, 3).expect("alloc key");
        Flat::write(key, mem, &[0u8; 3]).expect("write key");

        let field = Layout::of::<Flat>();
        let at = heap.reserve(mem, field.size).expect("alloc block");
        let mut image = vec![0u8; usize::from(field.size)];
        let put = |image: &mut Vec<u8>, offset: u16, bytes: &[u8]| {
            let start = usize::from(offset);
            image[start..start + bytes.len()].copy_from_slice(bytes);
        };
        put(&mut image, field.filnam, &Flat::ptr_to_bytes(filnam));
        put(&mut image, field.data, &Flat::ptr_to_bytes(data));
        put(&mut image, field.key, &Flat::ptr_to_bytes(key));
        Flat::write(at, mem, &image).expect("write block");

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
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut btrieve = Btrieve::default();

        // Dirty: the observable is the key's own index page -- page 1, which
        // `seed_indexed` names as the key's root and leaves empty. An insert
        // writes the record and keeps the key's stored count live (see
        // `Btrieve::write_key_record_counts`) but never rebuilds the tree;
        // only `reindex` does, and it is the only thing that can put an entry
        // on that page. This test used to read the *count* instead, asserting
        // it was still 0 after the insert -- which pinned a real defect as if
        // it were the design, and stopped being a signal the moment the
        // defect was fixed.
        let dirty_path = seed_indexed(&crate::testing::scratch("btrieve-close-reindex-dirty"));
        let dirty = open_indexed(&mut mem, &mut heap, &mut btrieve, dirty_path.clone());
        btrieve
            .block_mut(dirty)
            .expect("open")
            .insert(&record(1))
            .expect("insert");
        let root_after_insert = root_page(&dirty_path);
        assert!(
            root_after_insert[usize::from(pages::HEADER)..].iter().all(|b| *b == 0),
            "an insert alone leaves the key's index page alone"
        );
        assert_eq!(
            key_records(&dirty_path),
            1,
            "an insert does keep the key's own stored count live"
        );

        btrieve
            .close(&mut mem, &mut heap, dirty)
            .expect("closes, and reindexes on the way");
        assert_ne!(
            root_page(&dirty_path),
            root_after_insert,
            "closing a dirty block rebuilds the index"
        );
        assert_eq!(
            key_records(&dirty_path),
            1,
            "and the rebuild agrees with the count the insert already wrote"
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
        let clean = open_indexed(&mut mem, &mut heap, &mut btrieve, clean_path.clone());
        btrieve
            .close(&mut mem, &mut heap, clean)
            .expect("closes without ever asking to reindex");
        let after = std::fs::read(&clean_path).expect("read after");
        assert_eq!(before, after, "a clean close never touches the file");
    }

    /// Task 1: host shutdown must close every block still in `self.open`,
    /// not just the one a module happens to hand `close`. Same fixture
    /// shape as `close_reindexes_a_dirty_block_but_never_a_clean_one` -- one
    /// dirty block, one clean one alongside it -- through
    /// `close_all_files`, which takes no `mem`/`heap`: the machine tearing
    /// down owns that memory, so there is nothing left to write `bb->filnam`
    /// into or free the four allocations back to.
    #[test]
    fn close_all_files_settles_every_dirty_block_and_empties_the_open_list() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut btrieve = Btrieve::default();

        let dirty_path = seed_indexed(&crate::testing::scratch("btrieve-close-all-dirty"));
        let dirty = open_indexed(&mut mem, &mut heap, &mut btrieve, dirty_path.clone());
        btrieve
            .block_mut(dirty)
            .expect("open")
            .insert(&record(1))
            .expect("insert");
        // Same observable as `close_reindexes_a_dirty_block_but_never_a_clean_one`:
        // an insert alone never touches the key's index page -- only
        // `reindex` does -- so the root page changing is what proves the
        // dirty block was flushed on the way out, not merely dropped.
        let root_before_close = root_page(&dirty_path);

        let clean_path = seed_indexed(&crate::testing::scratch("btrieve-close-all-clean"));
        open_indexed(&mut mem, &mut heap, &mut btrieve, clean_path);

        let closed = btrieve.close_all_files().expect("closes");
        assert_eq!(closed, 2);
        assert!(btrieve.is_empty(), "every block left self.open");
        assert_ne!(
            root_page(&dirty_path),
            root_before_close,
            "the dirty block was reindexed on the way out, same as a direct close"
        );
        assert_eq!(btrieve.close_all_files().expect("idempotent"), 0);
    }

    /// Controller ruling 2026-08-25: shutdown's close sweep is best-effort,
    /// not fail-fast -- maximum data settled wins over stopping at the
    /// first problem. A block with an outstanding transaction pre-image
    /// refuses to close
    /// (`closing_a_block_with_an_outstanding_pre_image_is_refused`), and
    /// that refusal must not stop the sweep from reaching every block
    /// after it, nor from reindexing what it can.
    #[test]
    fn close_all_files_still_settles_later_blocks_after_an_earlier_one_refuses() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut btrieve = Btrieve::default();

        // First-opened, and left mid-transaction, so `close_file` refuses
        // it -- deterministic, no filesystem-permission dance needed to
        // make a real write fail.
        let stuck_path = seed_indexed(&crate::testing::scratch("btrieve-close-all-stuck"));
        let stuck = open_indexed(&mut mem, &mut heap, &mut btrieve, stuck_path);
        btrieve.begin().expect("begin");
        btrieve
            .block_mut(stuck)
            .expect("open")
            .insert(&record(1))
            .expect("insert, which captures a pre-image");

        // Second-opened, dirty, and otherwise unremarkable -- the block
        // this test needs to see settle even though the sweep hit a
        // refusal first.
        let dirty_path =
            seed_indexed(&crate::testing::scratch("btrieve-close-all-dirty-after-stuck"));
        let dirty = open_indexed(&mut mem, &mut heap, &mut btrieve, dirty_path.clone());
        btrieve
            .block_mut(dirty)
            .expect("open")
            .insert(&record(2))
            .expect("insert");
        let root_before_close = root_page(&dirty_path);

        let err = btrieve
            .close_all_files()
            .expect_err("the stuck block's refusal is reported");
        assert!(err.why.contains("transaction"), "{err}");

        assert_ne!(
            root_page(&dirty_path),
            root_before_close,
            "the second block still reindexed on the way out, despite the first one refusing"
        );
        assert_eq!(
            btrieve.len(),
            1,
            "the settled block left self.open; the stuck one stays"
        );
        assert!(btrieve.block(stuck).is_ok(), "the refusing block is still open, for a retry");
        assert!(btrieve.block(dirty).is_err(), "the settled block is gone");

        // Retry: once the transaction ends, a second sweep finishes the job.
        btrieve.end().expect("end");
        assert_eq!(btrieve.close_all_files().expect("retry succeeds"), 1);
        assert!(btrieve.is_empty());
    }

    /// C5: the re-entrancy guard used to be `bb->filnam != NULL`, read out of
    /// module memory the first close already freed. `mbbs`'s `Heap::free`
    /// never clears what it frees (see its own doc comment), so that read
    /// stayed reliably null only until something else allocated over the
    /// same span -- reproduced here with eight `Heap::reserve(.., 256)`
    /// calls, the same shape `alcmem` makes, run after the first close. Before the fix
    /// the second close found garbage where `bb->filnam` used to be null,
    /// tried to look up a block already removed from [`Self::open`], and
    /// stopped the module with "is not an open Btrieve file" -- a module
    /// bug in disguise -- instead of the quiet no-op a real double close is.
    #[test]
    fn close_is_a_quiet_no_op_the_second_time_even_after_the_heap_reuses_its_span() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut btrieve = Btrieve::default();

        let path = seed_indexed(&crate::testing::scratch(
            "btrieve-close-reentrancy-heap-reuse",
        ));
        let at = open_indexed(&mut mem, &mut heap, &mut btrieve, path);

        assert!(
            btrieve.close(&mut mem, &mut heap, at).expect("closes"),
            "the first close finds an open file"
        );

        // Garbage written straight over the span the closed block's own
        // `struct btvblk` occupied, which is the state this test is about.
        //
        // It used to get there indirectly: eight `Heap::reserve(.., 256)`
        // calls, the shape `alcmem` makes, run until one happened to land on
        // the freed span. That worked because the host's heap reuses what it
        // frees and never clears it -- properties of `mbbs`'s `Heap`, which
        // this crate cannot name and whose own tests still cover it there.
        // Writing the garbage directly says the same thing deterministically
        // rather than relying on an allocator landing where the test needs it,
        // and it keeps the subject where it belongs: the re-entrancy guard,
        // not the allocator that happened to expose it.
        Flat::write(at, &mut mem, &vec![0xaau8; usize::from(Layout::of::<Flat>().size)])
            .expect("a module writes into what it was just given");

        let second = btrieve
            .close(&mut mem, &mut heap, at)
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
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut btrieve = Btrieve::default();

        let path = seed_indexed(&crate::testing::scratch("btrieve-close-releases-locks"));
        let at = open_indexed(&mut mem, &mut heap, &mut btrieve, path);
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
            .close(&mut mem, &mut heap, at)
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
    fn btrieve_with(open: Vec<Block<Flat>>) -> Btrieve<Flat> {
        Btrieve {
            open,
            stack: [FlatPtr::NULL; BBSTSZ],
            mode: 0,
            transaction: false,
            locks: ops::LockTable::default(),
            // The dfa facade's own current-block and stack, empty here: these
            // tests are about `begin`/`end`/`abort`, and a hand-written struct
            // literal is exactly what stops compiling when the struct grows,
            // which is how these two arrived.
            dfa_current: FlatPtr::NULL,
            dfa_stack: [FlatPtr::NULL; DFSTSZ],
            dfa_mode: 0,
            dfa_last_len: 0,
            lastlen: 0,
            stt_length: 0,
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

    // Task 8: `EXCLBV`. `open_indexed`'s own shortcut hand-builds a `Block`
    // and pushes it directly onto `self.open`, which never runs
    // `Self::open`'s own body at all -- so it cannot exercise a check that
    // lives there. These tests go through `Self::open` for real, over a
    // fresh v5 file [`create`] builds, exactly the way `btrcall.rs`'s own
    // `scratch_file` does.

    /// A fresh, valid, single-key v5 file `Self::open` can actually open --
    /// see this section's own header comment for why `open_indexed` cannot
    /// stand in here.
    fn create_scratch_v5(tag: &str) -> (String, PathBuf) {
        let name = "SCRATCH.DAT".to_owned();
        let path = crate::testing::scratch(tag).join(&name);
        let spec = FileSpec {
            record_length: 8,
            page_size: 512,
            keys: vec![KeySpec {
                segments: vec![SegmentSpec {
                    offset: 0,
                    length: 4,
                    kind: 0x0e, // DFAST_UNSIGNED_BINARY
                    descending: false,
                }],
                duplicates: false,
                modifiable: false,
            }],
        };
        create(&path, &spec).expect("creates a scratch Btrieve file");
        (name, path)
    }

    /// Measured against genuine Btrieve 6.15 under Wine: an exclusive open
    /// (-4) holding a path, and a second open of the same path arriving
    /// while it is held, answers status 88, "Incompatible Mode Error" --
    /// task-8-report.md carries the probe transcript.
    #[test]
    fn an_exclusive_open_refuses_a_second_open_with_status_88() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut btrieve = Btrieve::<Flat>::default();
        let (name, path) = create_scratch_v5("exclbv-refuses-second-open");
        let geometry = Geometry::read(&name, &path).expect("reads");
        let maxlen = geometry.reclen;

        btrieve.set_mode(EXCLBV);
        btrieve
            .open(&mut mem, &mut heap, &name, &path, geometry, maxlen)
            .expect("the exclusive open itself succeeds");

        btrieve.set_mode(PRIMBV);
        let err = btrieve
            .open(&mut mem, &mut heap, &name, &path, geometry, maxlen)
            .expect_err("a second open while the first is exclusive is refused");
        assert!(err.contains("88"), "expected status 88 named in the refusal: {err}");
    }

    /// The other direction of the same rule: an exclusive open ARRIVING
    /// second, while any other open of the path already exists (normal
    /// mode here), is refused too -- not just the reverse order. Measured
    /// the same way, same status.
    #[test]
    fn an_exclusive_open_is_itself_refused_while_any_other_open_of_the_path_exists() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut btrieve = Btrieve::<Flat>::default();
        let (name, path) = create_scratch_v5("exclbv-refuses-arriving-second");
        let geometry = Geometry::read(&name, &path).expect("reads");
        let maxlen = geometry.reclen;

        btrieve.set_mode(PRIMBV);
        btrieve
            .open(&mut mem, &mut heap, &name, &path, geometry, maxlen)
            .expect("a normal open succeeds");

        btrieve.set_mode(EXCLBV);
        let err = btrieve
            .open(&mut mem, &mut heap, &name, &path, geometry, maxlen)
            .expect_err("an exclusive open arriving second is refused too");
        assert!(err.contains("88"), "expected status 88 named in the refusal: {err}");
    }

    /// Guards against an over-broad check that refuses on `mode == EXCLBV`
    /// alone, regardless of path: `EXCLBV` excludes conflicting opens of
    /// the SAME path, not every other open in the session.
    #[test]
    fn an_exclusive_open_does_not_refuse_a_different_path() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut btrieve = Btrieve::<Flat>::default();
        let (name_a, path_a) = create_scratch_v5("exclbv-independent-a");
        let (name_b, path_b) = create_scratch_v5("exclbv-independent-b");
        let geometry_a = Geometry::read(&name_a, &path_a).expect("reads");
        let geometry_b = Geometry::read(&name_b, &path_b).expect("reads");

        btrieve.set_mode(EXCLBV);
        btrieve
            .open(&mut mem, &mut heap, &name_a, &path_a, geometry_a, geometry_a.reclen)
            .expect("first file opens exclusive");
        btrieve
            .open(&mut mem, &mut heap, &name_b, &path_b, geometry_b, geometry_b.reclen)
            .expect("a second, DIFFERENT file still opens exclusive -- EXCLBV is per-path");
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
    /// exercised through the genuine method, because that propagation lives
    /// in `open` itself and a hand-built `Block` pushed straight into `open`
    /// (as `open_indexed` does for other tests here) would skip the code path
    /// this test is for.
    #[test]
    fn a_file_opened_after_begin_is_covered_too() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
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
        //
        // Reached across to `mbbs` rather than copied in: it is a binary
        // fixture shared with that crate's own `opnbtv` tests, and two copies
        // of a Btrieve file that must stay byte-identical is a worse problem
        // than one relative path.
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../mbbs/tests/data/SAMPLE.DAT");
        let geometry = Geometry::read("SAMPLE.DAT", &path).expect("reads");
        let at = btrieve
            .open(&mut mem, &mut heap, "SAMPLE.DAT", &path, geometry, 64)
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

    /// Task 3's own review, Critical 1: `Btrieve::abort` restores disk (a
    /// whole-file `std::fs::write`) and the in-memory model, but never
    /// touched a v6 block's attached cache -- so a page the aborted
    /// transaction's own write pushed into the cache
    /// (`Block::write_changed_pages`'s write-through) stayed resident with
    /// *post*-transaction bytes even after disk went back to its
    /// *pre*-transaction state. The next resolution through that same
    /// cache silently answered with the wrong page -- not a crash, not a
    /// refusal, just wrong.
    ///
    /// Only a real v6 `Block` can exhibit this: `block()`/`block_from_file`
    /// (this file's own test helpers) never attach a cache, so every
    /// existing `abort_undoes_*` test above is structurally blind to it.
    /// This one goes through the genuine `Btrieve::open`, on
    /// `V6EMPTY1KEY.DAT` (`v6_scratch`'s own fixture) with two records
    /// inserted -- **not** `V6SHRINK.DAT` (this test's own fixture before
    /// Task 6): that file's 9 records split 4-and-4 under one root
    /// separator, so *any* single delete underflows a leaf whose sibling
    /// sits at exactly `half_entries`, which per §6 merges rather than
    /// redistributes and collapses the root -- the root-level tree-shrink
    /// this task's own rulings refuse rather than guess at (see
    /// `a_shrinking_v6_reindex_releases_its_surplus_pages_on_delete`,
    /// which now asserts that refusal directly). A key-changing update is
    /// a delete-then-insert (`Block::update_v6`'s own doc comment), so it
    /// hit the identical refusal here -- unrelated to what this test is
    /// actually about (cache invalidation on abort), so it moved to a
    /// fixture with only two records, nowhere near any split or underflow
    /// boundary.
    #[test]
    fn abort_invalidates_the_v6_cache_not_just_disk_and_the_model() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut btrieve = Btrieve::<Flat>::default();

        let dir = crate::testing::scratch("txn-abort-invalidates-cache");
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/btrieve-oracle/fixtures/V6EMPTY1KEY.DAT");
        let path = dir.join("V6EMPTY1KEY.DAT");
        std::fs::copy(&source, &path).expect("the fixture copies into scratch");
        // This fixture's one key is not modifiable by default -- the same
        // reason `a_v6_update_that_reorders_a_key_relocates_that_keys_root`
        // calls this helper.
        crate::testing::make_keys_modifiable(&path);

        let geometry = Geometry::read("V6EMPTY1KEY.DAT", &path).expect("reads");
        let maxlen = geometry.reclen;
        let at = btrieve
            .open(&mut mem, &mut heap, "V6EMPTY1KEY.DAT", &path, geometry, maxlen)
            .expect("opens");
        assert!(
            btrieve.block(at).expect("open").cache.is_some(),
            "a real v6 open attaches a cache -- this test is meaningless without one"
        );
        btrieve.block_mut(at).expect("open").insert(&v6_record(b"AAAA")).expect("first insert");
        let position = btrieve.block_mut(at).expect("open").insert(&v6_record(b"BBBB")).expect("second insert");

        let layout = {
            let block = btrieve.block(at).expect("open");
            pages::Layout { page: block.geometry.page, physical: block.geometry.physical, pages: block.geometry.pages }
        };
        let (logical, _slot) = layout.slot_of(position).expect("a slot-aligned position");
        let physical_before = btrieve
            .block(at)
            .expect("open")
            .v6_resolve_logical(logical)
            .expect("resolves before the transaction");

        btrieve.begin().expect("begin");
        let bytes = v6_record(b"ABRT");
        btrieve
            .block_mut(at)
            .expect("open")
            .update(position, &bytes)
            .expect("update inside the transaction");

        let physical_after_update = btrieve
            .block(at)
            .expect("open")
            .v6_resolve_logical(logical)
            .expect("resolves after the in-transaction update");
        assert_ne!(
            physical_after_update, physical_before,
            "v6 always relocates a record's data page on update (Map::relocate's own \
             doc comment) -- if this ever ties, the rest of this test cannot tell \
             abort's cache bug apart from an update that happened to land back where \
             it started"
        );

        btrieve.abort().expect("abort");

        // The bug, made directly observable: resolve the same logical id
        // again, through the same `Block`'s attached cache. Before the fix,
        // the allocation-table page the aborted update's own write pushed
        // into the cache is still resident, so this still answers
        // `physical_after_update` -- the aborted transaction's own
        // relocation -- even though disk has been rolled all the way back.
        // After the fix, the cache was rebuilt from the restored file, so
        // this answers `physical_before` again, agreeing with disk truth.
        let physical_after_abort = btrieve
            .block(at)
            .expect("open")
            .v6_resolve_logical(logical)
            .expect("resolves after abort");
        assert_eq!(
            physical_after_abort, physical_before,
            "abort restored disk but not the cache -- v6_resolve_logical answered with \
             the aborted transaction's own relocation instead of the rolled-back \
             file's real allocation-table entry"
        );

        // And the record's own bytes, read straight off disk (`records`
        // dropped and reloaded, never through the page cache), confirm
        // what "disk truth" actually is here -- so a coincidental
        // page-number match could not paper over a content mismatch the
        // other way.
        btrieve.block_mut(at).expect("open").records = None;
        let reread = btrieve.block_mut(at).expect("open").records().expect("a fresh read from disk");
        let restored = at_position(&reread, position).expect("still there, at its own unmoved position");
        assert_ne!(
            restored.bytes[..4],
            *b"ABRT",
            "the aborted update's bytes must not survive on disk"
        );
    }

    /// Re-review of round 3, Important 1: `Btrieve::abort` restores disk
    /// and the in-memory model (the test above), but neither abort branch
    /// -- the disk-rewrite path (`Block::invalidate_cache`) or the
    /// deferred, disk-never-touched path (`PageCache::drop_dirty`) --
    /// clears `Block::v6_order`/`Block::v6_physical`. Both caches are
    /// built from whatever the block's page cache holds *at the moment a
    /// read asks for them*, which inside a transaction is the in-flight,
    /// not-yet-committed state (`ending_a_transaction_flushes_every_
    /// deferred_v6_write_to_disk`'s own "visible before end" contract
    /// relies on exactly this). Concretely reachable: `begin`, insert
    /// (invalidates the affected key's cached order and the physical
    /// index -- `Self::v6_invalidate_keys`/`Self::v6_invalidate_physical`),
    /// a keyed or physical read *inside* the transaction (rebuilds and
    /// caches an index reflecting the uncommitted insert), `abort` (cache
    /// and disk both roll back, but the two indexes do not) -- the next
    /// `Get`/`Step` then silently serves the rolled-back insert's rank or
    /// position.
    #[test]
    fn abort_invalidates_the_v6_order_and_physical_indexes_not_just_disk_and_the_model() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut btrieve = Btrieve::<Flat>::default();

        let dir = crate::testing::scratch("txn-abort-invalidates-order-and-physical");
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/btrieve-oracle/fixtures/V6EMPTY1KEY.DAT");
        let path = dir.join("V6EMPTY1KEY.DAT");
        std::fs::copy(&source, &path).expect("the fixture copies into scratch");
        crate::testing::make_keys_modifiable(&path);

        let geometry = Geometry::read("V6EMPTY1KEY.DAT", &path).expect("reads");
        let maxlen = geometry.reclen;
        let at = btrieve
            .open(&mut mem, &mut heap, "V6EMPTY1KEY.DAT", &path, geometry, maxlen)
            .expect("opens");
        assert!(
            btrieve.block(at).expect("open").cache.is_some(),
            "a real v6 open attaches a cache -- this test is meaningless without one"
        );

        // One baseline record, written the ordinary autocommit way, before
        // the transaction even starts.
        btrieve.block_mut(at).expect("open").insert(&v6_record(b"AAAA")).expect("baseline");

        btrieve.begin().expect("begin");
        btrieve.block_mut(at).expect("open").insert(&v6_record(b"BBBB")).expect("in-transaction insert");

        // A keyed read and a physical read, both *inside* the transaction
        // -- each builds and caches an index (`v6_order[0]`, `v6_physical`)
        // that reflects the uncommitted insert, exactly the read-your-own-
        // writes contract this crate's own deferred-transaction tests
        // already rely on.
        let mut locks = LockTable::default();
        assert!(
            btrieve
                .block_mut(at)
                .expect("open")
                .query(0, Op::Equal, b"BBBB")
                .expect("query"),
            "the in-transaction insert must be visible to a keyed read before abort"
        );
        let last_in_txn = btrieve
            .block_mut(at)
            .expect("open")
            .step(Step::Last, 0, &mut locks, maxlen)
            .expect("step")
            .expect("a last record exists");
        assert_eq!(
            &last_in_txn.bytes[..4],
            b"BBBB",
            "the in-transaction insert must be visible to a physical read before abort too"
        );

        btrieve.abort().expect("abort");

        // The bug, made directly observable: a keyed read for the aborted
        // insert's own value, through the same `Block`'s cached order.
        // Before the fix, `v6_order[0]` still holds the two-record order
        // the in-transaction read built and cached, so this still finds
        // "BBBB" even though the insert was rolled back. After the fix,
        // the cache was cleared and the next read rebuilds it from the
        // restored file, so this correctly finds nothing.
        let found_after_abort = btrieve
            .block_mut(at)
            .expect("open")
            .query(0, Op::Equal, b"BBBB")
            .expect("query");
        assert!(
            !found_after_abort,
            "abort restored disk but not the cached key order -- a keyed read still found \
             the rolled-back insert"
        );

        // Same bug, the physical side: before the fix, `v6_physical` still
        // holds the two-position physical order the in-transaction read
        // built and cached, so Step::Last still lands on "BBBB". After the
        // fix, it lands back on the one record abort actually left.
        let last_after_abort = btrieve
            .block_mut(at)
            .expect("open")
            .step(Step::Last, 0, &mut locks, maxlen)
            .expect("step")
            .expect("a last record exists");
        assert_eq!(
            &last_after_abort.bytes[..4],
            b"AAAA",
            "abort restored disk but not the cached physical order -- Step::Last still \
             landed on the rolled-back insert"
        );

        // And both must agree with a fresh, independent open of the same
        // file -- nothing this `Block` has cached, resident or otherwise,
        // may disagree with what a brand new reader of the same bytes
        // sees.
        let mut fresh_mem = FlatMem::new(64 * 1024);
        let mut fresh_heap = FlatHeap::new(0x100);
        let mut fresh = Btrieve::<Flat>::default();
        let fresh_geometry = Geometry::read("V6EMPTY1KEY.DAT", &path).expect("reads");
        let fresh_at = fresh
            .open(&mut fresh_mem, &mut fresh_heap, "V6EMPTY1KEY.DAT", &path, fresh_geometry, maxlen)
            .expect("opens");
        let mut fresh_locks = LockTable::default();
        assert!(
            !fresh
                .block_mut(fresh_at)
                .expect("open")
                .query(0, Op::Equal, b"BBBB")
                .expect("query"),
            "a fresh independent open must not find the aborted insert either"
        );
        let fresh_last = fresh
            .block_mut(fresh_at)
            .expect("open")
            .step(Step::Last, 0, &mut fresh_locks, maxlen)
            .expect("step")
            .expect("a last record exists");
        assert_eq!(
            &fresh_last.bytes[..4],
            b"AAAA",
            "a fresh independent open's own Step::Last must agree with the aborted block's"
        );
    }

    /// Task 3's own review, Critical 2: `write_changed_pages` only pushed
    /// pages into the attached cache after every phase of a flush
    /// succeeded, so a genuine mid-flush I/O failure (`ENOSPC`, `EIO`)
    /// could leave an earlier phase's real disk write disagreeing with
    /// whatever the cache already had resident for that same page, and
    /// nothing on the `Err` path reconciled it. [`STOP_AT`] stages exactly
    /// this -- a phase 1 content write that really lands on disk, followed
    /// by a staged failure standing in for a crash before write-through
    /// ever runs -- the same instrument
    /// `a_v6_write_stopped_before_the_flip_leaves_every_record_readable`
    /// already uses for the disk-only half of this promise.
    #[test]
    fn a_failed_flush_invalidates_the_v6_cache_not_just_leaves_disk_torn() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut btrieve = Btrieve::<Flat>::default();

        let dir = crate::testing::scratch("v6-stop-invalidates-cache");
        // `V6EMPTY1KEY.DAT` with two inserted records, not `V6SHRINK.DAT`
        // (this test's own fixture before Task 6) -- see
        // `abort_invalidates_the_v6_cache_not_just_disk_and_the_model`'s own
        // doc comment for why a key-changing update against that 9-record,
        // 4-and-4-split file now refuses (root-level tree-shrink) rather
        // than succeeding, and that refusal is correct, not a regression.
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/btrieve-oracle/fixtures/V6EMPTY1KEY.DAT");
        let path = dir.join("V6EMPTY1KEY.DAT");
        std::fs::copy(&source, &path).expect("the fixture copies into scratch");
        crate::testing::make_keys_modifiable(&path);

        let geometry = Geometry::read("V6EMPTY1KEY.DAT", &path).expect("reads");
        let maxlen = geometry.reclen;
        let page_size = usize::from(geometry.page);
        let at = btrieve
            .open(&mut mem, &mut heap, "V6EMPTY1KEY.DAT", &path, geometry, maxlen)
            .expect("opens");
        assert!(
            btrieve.block(at).expect("open").cache.is_some(),
            "a real v6 open attaches a cache -- this test is meaningless without one"
        );
        btrieve.block_mut(at).expect("open").insert(&v6_record(b"AAAA")).expect("first insert");
        let position = btrieve.block_mut(at).expect("open").insert(&v6_record(b"BBBB")).expect("second insert");

        let layout = {
            let block = btrieve.block(at).expect("open");
            pages::Layout { page: block.geometry.page, physical: block.geometry.physical, pages: block.geometry.pages }
        };
        let (logical, _slot) = layout.slot_of(position).expect("a slot-aligned position");
        let physical_original = btrieve
            .block(at)
            .expect("open")
            .v6_resolve_logical(logical)
            .expect("resolves before any write");

        // A successful update relocates the record away from
        // `physical_original` -- v6 always relocates on write -- and
        // `Block::v6_slot`'s own eager touch already read
        // `physical_original` in full through the attached cache before the
        // record moved off it, so that page stays resident there as a
        // stale twin.
        let first_bytes = v6_record(b"1111");
        btrieve
            .block_mut(at)
            .expect("open")
            .update(position, &first_bytes)
            .expect("the first update succeeds");
        let physical_after_first = btrieve
            .block(at)
            .expect("open")
            .v6_resolve_logical(logical)
            .expect("resolves after the first update");
        assert_ne!(physical_after_first, physical_original, "v6 always relocates on update");

        // A snapshot of `physical_original`'s bytes, straight off disk,
        // before the second write touches it again -- what the still
        // resident (now stale-twin) cache entry for this page currently
        // agrees with.
        let disk_before: Vec<u8> = {
            let whole = std::fs::read(&path).expect("reads the file");
            whole[physical_original as usize * page_size..][..page_size].to_vec()
        };

        // The second update relocates back onto `physical_original` -- the
        // same alternation `v6::Map::relocate`'s own doc comment measures
        // (a data page running 6, 5, 6, 5, ...) -- but this time phase 1's
        // real disk write is followed by a staged failure standing in for
        // a crash before write-through ever runs.
        let mut second_bytes = vec![0x22u8; usize::from(maxlen)];
        second_bytes[..4].copy_from_slice(b"FAIL");
        STOP_AT.with(|at| at.set(Some(Stop::AfterContent)));
        let refused = btrieve.block_mut(at).expect("open").update(position, &second_bytes);
        STOP_AT.with(|at| at.set(None));
        assert!(refused.is_err(), "the staged interruption must fail the write");

        let disk_after: Vec<u8> = {
            let whole = std::fs::read(&path).expect("reads the file");
            whole[physical_original as usize * page_size..][..page_size].to_vec()
        };
        assert_ne!(
            disk_after, disk_before,
            "phase 1 must have really written the second update's content to \
             physical_original before the staged interruption fired, or this test \
             cannot tell a stale cache apart from one that was never touched"
        );

        // The bug, made directly observable: read the same physical page
        // through the block's attached cache. Before the fix, the entry
        // `Store::page`'s earlier eager touch left resident is untouched
        // by the failed write (write-through never ran), so this still
        // answers `disk_before` -- stale, and silently wrong -- even
        // though disk now holds `disk_after`. After the fix, the failed
        // `write_changed_pages` call invalidated the cache, so this
        // re-fetches from disk and agrees with whatever is actually there.
        let through_cache = {
            let block = btrieve.block(at).expect("open");
            let cache = block.cache.as_ref().expect("still attached");
            cache.borrow_mut().page(physical_original).expect("reads").to_vec()
        };
        assert_eq!(
            through_cache, disk_after,
            "a failed write_changed_pages left the cache disagreeing with disk -- it \
             answered with the page's pre-write bytes instead of what phase 1 actually \
             wrote before the staged interruption"
        );
    }

    /// Task 7's own headline behaviour, proven directly: a v6 block's
    /// writes inside a transaction do not reach disk one at a time -- they
    /// stage into the cache and stay there until `Btrieve::end` runs one
    /// combined flush. Two inserts and an update, all inside one
    /// transaction: `WROTE` (every byte a real disk write has put down,
    /// `Block::write_changed_pages_attempt`'s own counter) stays zero
    /// through every one of them, and only moves once `end` is called.
    /// Disk agreeing with the model afterward (read fresh, cache dropped,
    /// the same technique every `abort_undoes_*` test already uses) is what
    /// tells this apart from "happened to look deferred because nothing
    /// checked yet".
    #[test]
    fn ending_a_transaction_flushes_every_deferred_v6_write_to_disk() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut btrieve = Btrieve::<Flat>::default();

        let dir = crate::testing::scratch("txn-end-flushes-deferred-v6");
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/btrieve-oracle/fixtures/V6EMPTY1KEY.DAT");
        let path = dir.join("V6EMPTY1KEY.DAT");
        std::fs::copy(&source, &path).expect("the fixture copies into scratch");
        crate::testing::make_keys_modifiable(&path);

        let geometry = Geometry::read("V6EMPTY1KEY.DAT", &path).expect("reads");
        let maxlen = geometry.reclen;
        let at = btrieve
            .open(&mut mem, &mut heap, "V6EMPTY1KEY.DAT", &path, geometry, maxlen)
            .expect("opens");
        assert!(
            btrieve.block(at).expect("open").cache.is_some(),
            "a real v6 open attaches a cache -- this test is meaningless without one"
        );

        // A baseline record before the transaction, written (and flushed)
        // the ordinary autocommit way, so this test can also see that
        // `end`'s commit does not disturb what was already durable.
        let baseline = btrieve.block_mut(at).expect("open").insert(&v6_record(b"BASE")).expect("baseline");

        btrieve.begin().expect("begin");
        WROTE.with(|wrote| wrote.set(0));

        let first = btrieve.block_mut(at).expect("open").insert(&v6_record(b"AAAA")).expect("first insert");
        assert_eq!(WROTE.with(std::cell::Cell::get), 0, "a deferred insert must not touch disk");

        let second = btrieve.block_mut(at).expect("open").insert(&v6_record(b"BBBB")).expect("second insert");
        assert_eq!(WROTE.with(std::cell::Cell::get), 0, "a second deferred insert must not touch disk either");

        btrieve
            .block_mut(at)
            .expect("open")
            .update(first, &v6_record(b"CCCC"))
            .expect("a deferred update");
        assert_eq!(WROTE.with(std::cell::Cell::get), 0, "a deferred update must not touch disk");

        // Visible in-session before `end`, the same contract
        // `an_insert_made_after_begin_is_visible_before_end` pins for v5 --
        // through `Block::acquire_absolute` (Task 7's own v6 fast path,
        // `Block::v6_record_bytes_at`/`Block::v6_rank_of`), not
        // `self.records()`: a fixed-length v6 block never populates that
        // any more (`Block::v6_fast_reads`), and calling it here would do
        // exactly what this test is about to prove does not have to happen
        // -- a whole-file disk read that, mid-transaction, would only see
        // the pre-transaction baseline (`records::walk_v6` reads straight
        // off disk, bypassing the cache these deferred writes are staged
        // in). Reading through the same cache the writes staged into is
        // the point.
        let mut locks = LockTable::default();
        {
            let block = btrieve.block_mut(at).expect("open");
            assert!(
                block.acquire_absolute(first, 0, 0, &mut locks, maxlen).expect("resolves").is_some(),
                "the first deferred insert is visible before end"
            );
            assert!(
                block.acquire_absolute(second, 0, 0, &mut locks, maxlen).expect("resolves").is_some(),
                "the second deferred insert is visible before end"
            );
            let delivered = block
                .acquire_absolute(first, 0, 0, &mut locks, maxlen)
                .expect("resolves")
                .expect("still there");
            assert_eq!(
                &delivered.bytes[..4],
                b"CCCC",
                "the deferred update's own value is visible before end too"
            );
        }

        btrieve.end().expect("end");
        assert!(
            WROTE.with(std::cell::Cell::get) > 0,
            "end's own combined flush must be what finally reaches disk"
        );
        assert!(!btrieve.block(at).expect("open").txn_active, "no longer covered");
        assert!(btrieve.block(at).expect("open").pre_image.is_none(), "pre-image discarded");

        // A fresh read straight off disk -- `records` dropped, so this walks
        // the file directly rather than answering from the in-memory model
        // (or the cache) that already agreed before `end` ran.
        btrieve.block_mut(at).expect("open").records = None;
        let reread = btrieve.block_mut(at).expect("open").records().expect("a fresh read from disk");
        assert!(reread.find_physical(baseline).is_some(), "the pre-transaction baseline is untouched");
        assert!(reread.find_physical(first).is_some(), "the first deferred insert reached disk");
        assert!(reread.find_physical(second).is_some(), "the second deferred insert reached disk");
        let updated = at_position(&reread, first).expect("still there");
        assert_eq!(&updated.bytes[..4], b"CCCC", "the deferred update's own value reached disk");
    }

    /// Review Important 3: `Store::for_commit`'s positional shadow-pair
    /// reconstruction, exercised on a file with *two* allocation-table
    /// blocks rather than one -- `PP2BLOCK.DAT`, whose block 1 (pair at
    /// physical 2/3) is already full (126 of 126 entries, confirmed by a
    /// throwaway probe against this fixture) and whose block 2 (pair at
    /// 130/131) has 114 free.
    ///
    /// A brand new *third* block is not something this test can force: v6
    /// insert always lands in "the first allocation-table block that has a
    /// free entry" ([`v6::Map::claim`]'s own doc comment), so with block 1
    /// full every insert here lands in block 2 -- and claiming a block past
    /// the last one that exists is a refusal this crate states outright,
    /// "growing a new block is not implemented" (`Map::claim`'s own error
    /// text). That is a scope boundary Task 7 did not introduce and this
    /// test does not attempt to lift.
    ///
    /// What this fixture *does* give, for free: block 1's own pair turns
    /// out not to be a bystander here. Every insert and the update both
    /// relocate key 0's B-tree node (`Map::relocate`'s "twin" alternation,
    /// measured against genuine 6.15 in that function's own doc comment --
    /// a written page's *index* alternates physical homes on every touch,
    /// not only on a split), and that node's own logical id resolves into
    /// block 1. So a transaction of five inserts (each claiming a new
    /// entry in block 2) plus one update (which claims nothing new, but
    /// still relocates the key 0 node) dirties **both** existing blocks'
    /// shadow pairs -- confirmed below by generation, not assumed.
    ///
    /// The proof is what a naive "accumulate every per-op flip and replay
    /// them" model would get wrong and `for_commit`'s positional
    /// reconstruction gets right: six independent per-op commits (the
    /// `deferred: false` reference run below) flip each touched pair once
    /// *per op*, so on an even number of touches both physical halves end
    /// up rewritten; one batched commit (the `deferred: true` run) still
    /// only has to reach the same *final* live content, and collapses to a
    /// single flip -- exactly one physical half of every touched pair
    /// stays byte-identical to the original file. That collapse is checked
    /// directly, plus the total bytes an actual `write(2)` put down
    /// (`WROTE`), plus that both runs land at the same logical result
    /// (record count, every new record's bytes present and correct at its
    /// own physical position, the update's value in place) despite the
    /// different bytes.
    ///
    /// Logical equality is checked by physical position
    /// ([`Block::v6_physical_at`]/[`Block::v6_record_bytes_at`]), not by
    /// `Block::get(Op::Equal, ...)`: chasing this test down, `get`/`query`
    /// with `Op::Equal` turned out unable to find *any* record in
    /// `PP2BLOCK.DAT` by its key -- not the five new ones, not the lowest
    /// or highest pre-existing key, and not even with zero writes at all,
    /// on both this crate's fast (`Btrieve::open`) and slow
    /// (`block_from_file`) paths alike. The identical failure on both
    /// paths against an untouched file rules out anything Task 7 added;
    /// the same check against a local `WCCMP002.DAT` (also real, also
    /// multi-block, an 8-byte key rather than `PP2BLOCK.DAT`'s 4-byte one)
    /// finds both its lowest and highest key correctly, which rules out
    /// "any multi-block file" as the trigger. This is a pre-existing,
    /// unreported defect in equal-seek, `Op::Equal`-shaped and possibly
    /// key-width-shaped, outside this task's scope to fix -- see the
    /// fix report for the reproduction and why it does not block Task 7.
    #[test]
    fn deferred_writes_across_two_allocation_table_blocks_collapse_to_one_flip_each() {
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/btrieve-oracle/fixtures/PP2BLOCK.DAT");
        let original = std::fs::read(&source).expect("reads the committed fixture");

        let deferred_dir = crate::testing::scratch("v6-multi-block-deferred");
        let deferred_path = deferred_dir.join("PP2BLOCK.DAT");
        std::fs::copy(&source, &deferred_path).expect("copies");

        let reference_dir = crate::testing::scratch("v6-multi-block-reference");
        let reference_path = reference_dir.join("PP2BLOCK.DAT");
        std::fs::copy(&source, &reference_path).expect("copies");

        // Five new key values, all landing in block 2 (block 1's own 126
        // entries are already full), plus one update to a pre-existing
        // record. `PP2BLOCK.DAT`'s only key is a 4-byte unsigned value at
        // record offset 2 with no duplicates -- these are far above
        // anything 1,500 sequential records already hold.
        let new_keys: [u32; 5] = [90_000_001, 90_000_002, 90_000_003, 90_000_004, 90_000_005];

        fn open_it(path: &Path) -> (Btrieve<Flat>, FlatPtr, FlatMem, FlatHeap) {
            let mut mem = FlatMem::new(64 * 1024);
            let mut heap = FlatHeap::new(0x100);
            let mut btrieve = Btrieve::<Flat>::default();
            let geometry = Geometry::read("PP2BLOCK.DAT", path).expect("reads");
            let maxlen = geometry.reclen;
            let at = btrieve
                .open(&mut mem, &mut heap, "PP2BLOCK.DAT", path, geometry, maxlen)
                .expect("opens");
            (btrieve, at, mem, heap)
        }

        fn make_record(reclen: usize, key: u32) -> Vec<u8> {
            let mut record = vec![0u8; reclen];
            record[2..6].copy_from_slice(&key.to_le_bytes());
            record
        }

        // Runs the same five inserts, then one update, either inside one
        // deferred transaction or as six ordinary autocommit writes.
        // Returns the updated record's position and the total bytes a real
        // `write(2)` put down for the whole sequence.
        fn run(path: &Path, new_keys: &[u32], deferred: bool) -> (u32, usize) {
            let (mut btrieve, at, _mem, _heap) = open_it(path);
            assert!(
                btrieve.block(at).expect("open").v6_fast_reads(),
                "PP2BLOCK.DAT is fixed-length v6 -- meaningless if this is not the fast path"
            );
            let reclen = usize::from(btrieve.block(at).expect("open").geometry.reclen);

            let target = btrieve
                .block_mut(at)
                .expect("open")
                .v6_physical_at(0)
                .expect("physical lookup")
                .expect("a first record exists");

            WROTE.with(|wrote| wrote.set(0));
            if deferred {
                btrieve.begin().expect("begin");
            }

            for &key in new_keys {
                btrieve.block_mut(at).expect("open").insert(&make_record(reclen, key)).expect("insert");
            }
            let mut updated = btrieve
                .block_mut(at)
                .expect("open")
                .v6_record_bytes_at(target)
                .expect("fetch")
                .expect("still live");
            updated.resize(reclen, 0);
            let last = updated.len() - 1;
            updated[last] = 0xAB;
            btrieve.block_mut(at).expect("open").update(target, &updated).expect("update");

            if deferred {
                btrieve.end().expect("end");
            }
            (target, WROTE.with(std::cell::Cell::get))
        }

        let (deferred_target, deferred_wrote) = run(&deferred_path, &new_keys, true);
        let (reference_target, reference_wrote) = run(&reference_path, &new_keys, false);
        assert_eq!(deferred_target, reference_target, "both runs update the same physical record");

        let deferred_bytes = std::fs::read(&deferred_path).expect("reads");
        let reference_bytes = std::fs::read(&reference_path).expect("reads");
        assert_eq!(
            deferred_bytes.len(),
            reference_bytes.len(),
            "deferred and undeferred runs must grow the file by the same amount"
        );

        // The collapse: for every structural pair either run actually
        // touched (the control record, block 1, block 2), the deferred
        // transaction's single combined commit leaves one physical half
        // byte-identical to the original file -- it was never written even
        // once -- while the reference run's six independent commits wrote
        // both halves at least once each, so neither survives untouched.
        const PAGE: usize = 512;
        let unchanged_halves = |bytes: &[u8], first: usize, second: usize| -> usize {
            let mut count = 0;
            for page in [first, second] {
                if bytes[page * PAGE..(page + 1) * PAGE] == original[page * PAGE..(page + 1) * PAGE] {
                    count += 1;
                }
            }
            count
        };
        for &(first, second, label) in &[(0usize, 1usize, "the control record"), (2, 3, "block 1"), (130, 131, "block 2")]
        {
            assert_eq!(
                unchanged_halves(&deferred_bytes, first, second),
                1,
                "{label}: a batched transaction must leave exactly one physical half                  untouched by never having to write it"
            );
            assert_eq!(
                unchanged_halves(&reference_bytes, first, second),
                0,
                "{label}: six independent commits must have written both physical halves                  at least once between them -- this is the baseline the batched commit                  improves on, not a bug in the reference run"
            );
        }

        // The same collapse, measured directly in bytes actually put down
        // by `write(2)`, not inferred from which pages moved.
        assert!(
            deferred_wrote < reference_wrote,
            "one combined commit across two allocation-table blocks must write fewer bytes              than six independent ones -- deferred {deferred_wrote}, reference {reference_wrote}"
        );

        // Both runs must still agree on what the file *means*, despite
        // disagreeing on its bytes: same record count, every new key
        // readable, the update's value in place.
        let (mut fresh_deferred, fresh_deferred_at, _mem, _heap) = open_it(&deferred_path);
        let (mut fresh_reference, fresh_reference_at, _mem2, _heap2) = open_it(&reference_path);
        let deferred_count = fresh_deferred.block_mut(fresh_deferred_at).expect("open").v6_physical_len().expect("count");
        let reference_count =
            fresh_reference.block_mut(fresh_reference_at).expect("open").v6_physical_len().expect("count");
        assert_eq!(deferred_count, 1_505, "1,500 original records plus five new ones");
        assert_eq!(deferred_count, reference_count, "both runs must agree on the final record count");

        for (btrieve, at) in [(&mut fresh_deferred, fresh_deferred_at), (&mut fresh_reference, fresh_reference_at)] {
            let block = btrieve.block_mut(at).expect("open");
            let physical_len = block.v6_physical_len().expect("count");
            let mut found: Vec<u32> = Vec::new();
            for i in 0..physical_len {
                let position = block.v6_physical_at(i).expect("lookup").expect("within range");
                if let Some(bytes) = block.v6_record_bytes_at(position).expect("fetch") {
                    let k = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
                    if new_keys.contains(&k) {
                        found.push(k);
                    }
                }
            }
            found.sort_unstable();
            let mut expected = new_keys.to_vec();
            expected.sort_unstable();
            assert_eq!(found, expected, "every new record's own key is present and correct somewhere in the file");

            let reread_target = block.v6_record_bytes_at(deferred_target).expect("fetch").expect("still live");
            assert_eq!(*reread_target.last().expect("nonempty"), 0xAB, "the update reached disk");
        }
    }

    /// Repro for the `Op::Equal` defect found while building Task 7's
    /// multi-block `for_commit` test (the one above): registered in
    /// `docs/btrieve-unproven.md`'s own "known defect" section, not just
    /// described in prose there, so a follow-up owner starts from a
    /// running test.
    ///
    /// Minimal: zero writes. `PP2BLOCK.DAT` is opened exactly as it ships,
    /// its own lowest key found through `query(Lowest)` (already proven
    /// correct -- a full ascending walk reaches every record), then looked
    /// up by that same value through `get(Op::Equal, ...)`. Genuine
    /// Btrieve behaviour for `B_GET_EQUAL` on a key value the tree
    /// demonstrably holds is "found" -- there is nothing else it could
    /// mean. This currently fails: `get` reports "not found" for a key
    /// this same file's own ascending walk just delivered.
    ///
    /// Reproduces identically on the slow path too (`block_from_file`,
    /// `cache: None`, forcing the pre-Task-7 `Records`-backed `get`) --
    /// see the fix report for that cross-check; not repeated here, so this
    /// one test stays the single thing a follow-up runs to see the bug.
    #[test]
    #[ignore = "pre-existing keyed-lookup defect on PP2BLOCK.DAT-shaped files; see docs/btrieve-unproven.md"]
    fn get_equal_finds_pp2blocks_own_lowest_key() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut btrieve = Btrieve::<Flat>::default();

        let dir = crate::testing::scratch("pp2block-op-equal-repro");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/btrieve-oracle/fixtures/PP2BLOCK.DAT");
        let path = dir.join("PP2BLOCK.DAT");
        std::fs::copy(&source, &path).expect("copies");

        let geometry = Geometry::read("PP2BLOCK.DAT", &path).expect("reads");
        let maxlen = geometry.reclen;
        let at = btrieve
            .open(&mut mem, &mut heap, "PP2BLOCK.DAT", &path, geometry, maxlen)
            .expect("opens");
        let block = btrieve.block_mut(at).expect("open");

        assert!(block.query(0, Op::Lowest, &[]).expect("query"), "the file has at least one record");
        let lowest_key = block.current().expect("positioned").bytes[2..6].to_vec();

        let mut locks = LockTable::default();
        let found = block
            .get(0, Op::Equal, &lowest_key, 0, &mut locks, maxlen)
            .expect("get must not error, only find or not find");
        assert!(
            found.is_some(),
            "Op::Equal must find a key value this same file's own ascending walk just \
             delivered -- key {lowest_key:?} is demonstrably present"
        );
    }

    /// Task 7's ops cutover, exercised through a *real* cache-backed v6
    /// `Block` (`Btrieve::open`, not a hand-built fixture) rather than only
    /// through the corpus differential (`order::tests::order_index_and_
    /// byte_fetch_match_records_over_the_v6_corpus`, which proves the
    /// position/rank/byte machinery agrees with `Records` but never calls
    /// `Block::query`/`Block::get` at all): five records, five key values,
    /// every keyed `Op` this crate's own ops test suite pins by literal
    /// rank for v5 -- `Cursor::Ordered { key, at }`'s `at` staying a stable,
    /// literal rank is the whole point of Task 7's controller ruling
    /// ("keep the rank model, kill the bytes"), so this checks the exact
    /// same literal values a v5 fixture of this shape would produce.
    #[test]
    fn v6_fast_path_query_and_get_match_the_v5_rank_contract() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut btrieve = Btrieve::<Flat>::default();

        let dir = crate::testing::scratch("v6-fast-path-query-and-get");
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/btrieve-oracle/fixtures/V6EMPTY1KEY.DAT");
        let path = dir.join("V6EMPTY1KEY.DAT");
        std::fs::copy(&source, &path).expect("the fixture copies into scratch");
        crate::testing::make_keys_modifiable(&path);

        let geometry = Geometry::read("V6EMPTY1KEY.DAT", &path).expect("reads");
        let maxlen = geometry.reclen;
        let at = btrieve
            .open(&mut mem, &mut heap, "V6EMPTY1KEY.DAT", &path, geometry, maxlen)
            .expect("opens");
        assert!(
            btrieve.block(at).expect("open").cache.is_some(),
            "a real v6 open attaches a cache -- this test is meaningless without one"
        );

        // Inserted out of key order on purpose -- `AAAA/BBBB/CCCC/DDDD/EEEE`
        // sort ascending by value, not by insertion order, so a rank that
        // happened to just track insertion order would not be caught.
        for tag in [b"CCCC", b"AAAA", b"EEEE", b"BBBB", b"DDDD"] {
            btrieve.block_mut(at).expect("open").insert(&v6_record(tag)).expect("insert");
        }

        let mut locks = LockTable::default();
        let block = btrieve.block_mut(at).expect("open");

        assert!(block.query(0, Op::Lowest, &[]).expect("query"));
        assert_eq!(block.cursor(), Cursor::Ordered { key: 0, at: 0 });
        assert_eq!(&block.current().expect("positioned").bytes[..4], b"AAAA");

        assert!(block.query(0, Op::Highest, &[]).expect("query"));
        assert_eq!(block.cursor(), Cursor::Ordered { key: 0, at: 4 });
        assert_eq!(&block.current().expect("positioned").bytes[..4], b"EEEE");

        assert!(block.query(0, Op::Equal, b"CCCC").expect("query"));
        assert_eq!(block.cursor(), Cursor::Ordered { key: 0, at: 2 });

        assert!(block.query(0, Op::Next, &[]).expect("query"));
        assert_eq!(block.cursor(), Cursor::Ordered { key: 0, at: 3 });
        assert_eq!(&block.current().expect("positioned").bytes[..4], b"DDDD");

        assert!(block.query(0, Op::Previous, &[]).expect("query"));
        assert_eq!(block.cursor(), Cursor::Ordered { key: 0, at: 2 });
        assert_eq!(&block.current().expect("positioned").bytes[..4], b"CCCC");

        assert!(block.query(0, Op::Greater, b"CCCC").expect("query"));
        assert_eq!(block.cursor(), Cursor::Ordered { key: 0, at: 3 });

        assert!(block.query(0, Op::AtLeast, b"CCCC").expect("query"));
        assert_eq!(block.cursor(), Cursor::Ordered { key: 0, at: 2 });

        assert!(block.query(0, Op::Less, b"CCCC").expect("query"));
        assert_eq!(block.cursor(), Cursor::Ordered { key: 0, at: 1 });

        assert!(block.query(0, Op::AtMost, b"CCCC").expect("query"));
        assert_eq!(block.cursor(), Cursor::Ordered { key: 0, at: 2 });

        let miss = block.query(0, Op::Equal, b"ZZZZ").expect("query, not found");
        assert!(!miss, "a value nothing holds is not found, not an error");

        let delivery = block
            .get(0, Op::Equal, b"BBBB", 0, &mut locks, maxlen)
            .expect("get")
            .expect("found");
        assert_eq!(&delivery.bytes[..4], b"BBBB");

        assert_eq!(
            block.get_by_percentage(ops::PercentageBasis::Key(0), 5_000, 0, &mut locks, maxlen).unwrap().bytes[..4],
            *b"CCCC",
            "50% of 5 records lands on the middle one"
        );
        assert_eq!(
            block
                .find_percentage(&ops::FindBasis::Key { key: 0, value: b"CCCC".to_vec() })
                .expect("find percentage"),
            4_000,
            "CCCC sits at rank 2 of 5 -- 2/5 = 40.00%"
        );
    }

    /// Reproduces `xactprobe`'s `fail_inside` scenario indirectly: `end`
    /// keeps the write rather than rolling it back, matching real Btrieve
    /// where every op after a failed one (including the eventual `end`)
    /// still succeeded and both records were there on reopen. This is a v5
    /// fixture, which still writes straight through with nothing buffered
    /// for `end` to flush -- see [`Btrieve::end`]'s own doc comment for the
    /// v6 case (Task 7), where there *is* something to flush and this
    /// assertion (the write survives `end`) is exactly what
    /// `ending_a_transaction_flushes_every_deferred_v6_write_to_disk` checks
    /// for that path instead. What `end` has to get right here is *not*
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
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut btrieve = Btrieve::default();

        let path = seed_indexed(&crate::testing::scratch("txn-close-refuses-outstanding-pre-image"));
        let at = open_indexed(&mut mem, &mut heap, &mut btrieve, path);

        btrieve.begin().expect("begin");
        btrieve
            .block_mut(at)
            .expect("open")
            .insert(&record(1))
            .expect("insert, which captures a pre-image");

        let e = btrieve
            .close(&mut mem, &mut heap, at)
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

    /// A corpus file, or `None` when `archive/` is not populated here.
    fn corpus(relative: &str) -> Option<std::path::PathBuf> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative);
        path.exists().then_some(path)
    }

    /// The case B1 exists to close, end to end on a real **v6** file: one
    /// table, found by page type, reaching the key that declares it.
    #[test]
    fn a_v6_file_with_one_table_opens_and_its_key_carries_it() {
        let Some(path) = corpus("archive/tooling/wbtrv32/assets/WGSMENU2.DAT") else {
            eprintln!("skipped: archive/ not populated in this checkout");
            return;
        };
        let geometry = Geometry::read("WGSMENU2.DAT", &path).expect("a v6 header");
        assert_eq!(geometry.version, Version::V6);
        let fcr = read_head(&path, FCR).expect("a control record");
        assert!(
            keys::declares_alt_collating(&fcr, geometry.keys),
            "this file has an ACS-flagged key"
        );

        let tables = acs_tables(&path, &geometry, &fcr).expect("a locatable table");
        assert_eq!(tables.len(), 1, "WGSMENU2.DAT carries one table, GALCAPS");
        assert_eq!(&tables[0].acs.name, b"GALCAPS ");
        assert_eq!(tables[0].page, 1, "its logical page, which the key names it by");

        let parsed =
            keys::parse("WGSMENU2.DAT", &fcr, geometry.keys, &tables).expect("one table binds");
        assert!(
            parsed.iter().any(|k| k.acs.is_some()),
            "the table must reach the key, not merely be read"
        );
    }

    /// The same, on a real **v5** file -- which has no `'A'`-typed page to scan
    /// for and reads zero at `FCR+0x10a`. A search gated on the engine's own v6
    /// predicate would find nothing here, and 13 of the 45 corpus files that
    /// declare a sequence are v5.
    #[test]
    fn a_v5_file_holds_its_table_on_page_one_and_still_opens() {
        let Some(path) = corpus("archive/galacticomm/hosts/majorbbs/CLASSADS.DAT") else {
            eprintln!("skipped: archive/ not populated in this checkout");
            return;
        };
        let geometry = Geometry::read("CLASSADS.DAT", &path).expect("a v5 header");
        assert_eq!(geometry.version, Version::V5);
        let fcr = read_head(&path, FCR).expect("a control record");
        assert!(
            !acs::declared(&fcr),
            "the v6 pointer reads zero here -- gating on it would miss this file"
        );

        let tables = acs_tables(&path, &geometry, &fcr).expect("page 1 holds the block");
        assert_eq!(tables.len(), 1, "CLASSADS.DAT carries UPPER on page 1");
        assert_eq!(&tables[0].acs.name, b"UPPER   ");
        assert_eq!(tables[0].acs.fold(b'a'), b'A');
        assert_eq!(tables[0].page, 0, "v5 leaves the per-key page unset, so page zero");

        let parsed =
            keys::parse("CLASSADS.DAT", &fcr, geometry.keys, &tables).expect("one table binds");
        assert!(
            parsed.iter().any(|k| k.acs.is_some()),
            "the table must reach the key"
        );
    }

    /// The last file in the corpus that could not be read, end to end on the
    /// real bytes: two tables, and each key bound to the one it names by logical
    /// page.
    ///
    /// `ALLCAPS` is on logical 1 and folds `a` to `A`; `LOWER` is on logical 2
    /// and folds `A` to `a`. The two are opposites, so a binding that swapped
    /// them would not merely be untidy -- every lookup on both keys would answer
    /// wrongly, which is why this asserts the fold rather than the name.
    #[test]
    fn a_multi_table_file_binds_each_key_to_the_table_it_names() {
        let Some(path) = corpus("archive/tooling/wbtrv32/assets/MULTIACS.DAT") else {
            eprintln!("skipped: archive/ not populated in this checkout");
            return;
        };
        let geometry = Geometry::read("MULTIACS.DAT", &path).expect("a v6 header");
        let fcr = read_head(&path, FCR).expect("a control record");

        let tables = acs_tables(&path, &geometry, &fcr).expect("two locatable tables");
        assert_eq!(tables.len(), 2, "MULTIACS.DAT carries ALLCAPS and LOWER");
        assert_ne!(
            tables[0].acs.table, tables[1].acs.table,
            "they are different sequences, not one block read twice"
        );
        assert_eq!(
            (tables[0].page, tables[1].page),
            (1, 2),
            "found through the allocation table, so these are logical pages"
        );

        // Two gaps stood behind each other here. The alternate sequence was
        // closed first; key 1's second segment being a `float` (type 0x02)
        // was what surfaced next, and is closed now that the engine's own
        // float ordering has been measured
        // (`docs/2026-08-17-float-key-oracle.md`). This test used to assert
        // that refusal and now asserts its absence: the real definitions
        // parse, unpatched.
        let parsed = keys::parse("MULTIACS.DAT", &fcr, geometry.keys, &tables)
            .expect("nothing about this file is refused any more");
        assert_eq!(parsed.len(), 3);
        assert!(
            parsed[1].segments.iter().any(|s| s.kind == keys::Kind::Float),
            "key 1's second segment is the float that used to stop this file"
        );

        let folded = |key: &Key, b: u8| key.acs.as_ref().map(|acs| acs.fold(b));
        assert_eq!(
            folded(&parsed[0], b'a'),
            Some(b'A'),
            "key 0 names page 1, which is ALLCAPS"
        );
        assert_eq!(
            folded(&parsed[2], b'A'),
            Some(b'a'),
            "key 2 names page 2, which is LOWER"
        );
        assert!(
            parsed[1].acs.is_none(),
            "key 1 declares no sequence and must stay on raw byte order"
        );
    }

    /// A file no key of which declares a sequence must cost no page reads at
    /// all -- the gate is the point, since the v6 search is a whole-file scan.
    #[test]
    fn a_file_without_an_alternate_key_locates_nothing() {
        let Some(path) = corpus("archive/tooling/wbtrv32/assets/GALTELA.DAT") else {
            eprintln!("skipped: archive/ not populated in this checkout");
            return;
        };
        let geometry = Geometry::read("GALTELA.DAT", &path).expect("a header");
        // GALTELA.DAT *does* declare one, so the inverse is what needs showing:
        // a control record whose key definitions are blank declares nothing, and
        // must short-circuit before a single page is read.
        let plain = vec![0u8; FCR];
        assert!(!keys::declares_alt_collating(&plain, geometry.keys));
        assert!(
            acs_tables(&path, &geometry, &plain)
                .expect("no search happens")
                .is_empty(),
            "an unflagged file must locate nothing"
        );
    }
}

