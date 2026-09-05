//! Btrieve operation 14, Create: build a new file's control record, key
//! descriptors and root pages from scratch and write them to disk.
//!
//! # The request is measured from the vendor source; the result is measured
//! from real files
//!
//! `re/wg33src/INC/DFAAPI.H` (`struct dfaKeySpec`, `struct dfaSegSpec`) and
//! `re/wg33src/SRC/api/gcommlib/DFAAPI.C:674-750` (`dfaCreateSpec`) say what
//! a caller hands Btrieve to create a file: a fixed record length, a page
//! size, and a list of keys, each a list of segments with a position,
//! length, type and flags. That is what [`FileSpec`]/[`KeySpec`]/
//! [`SegmentSpec`] below carry, in the same shape `tools/btrieve-oracle/
//! btrvprobe.c`'s `cmd_create` and `crates/btrieve-oracle`'s
//! `create_file_spec()` already build for the real engine, and what
//! `tools/btrieve-oracle/crtprobe.c` (this task's own probe) generalised to
//! any shape and confirmed live: a unique ascending key, a duplicate
//! descending one, and a two-segment key all created and STAT'd back with
//! the fields this module expects (`crtprobe create` usage in that file's
//! own header comment).
//!
//! But the vendor source describes the *request*, not the bytes Btrieve
//! *writes* in response, and this machine's only working oracle -- genuine
//! Pervasive Btrieve 6.15 under Wine -- cannot be asked to produce that
//! answer directly: every file it creates opens `"FC"`, the v6 marker
//! [`super::version`] checks for (confirmed by hex-dumping `tools/
//! btrieve-oracle/fixtures/DUPKEY30.DAT`, which this same engine built, and
//! by a fresh `crtprobe create` run during this module's own development --
//! see the crate's test suite and this file's own doc comments below for
//! both). This module still only ever builds v5 files: `create()` (Btrieve
//! op 14) never writes a v6 control record from scratch, even though v6
//! *write* against an existing file is now implemented elsewhere in this
//! crate ([`super::Block::insert_v6`]/[`super::Block::update_v6`]/
//! [`super::Block::delete_v6`]) -- so a `create` built on what this oracle
//! writes would produce files nothing else in this crate could then insert
//! into.
//!
//! **This module writes the v5 format instead** -- four zero bytes at the
//! start, the format all seventeen of MajorMUD's real fixed-length files use,
//! and the one [`super::Block::insert`]/[`super::Block::reindex`] already
//! know how to write into. Its layout is measured off five real, *virgin*
//! (zero-record) v5 files this repo already ships in `tmp/`:
//! `WCCACMSR.VIR` (one key, one segment), `WCCBANKS.VIR` (one key, two
//! segments, duplicates permitted), `WCCGANGS.VIR` and `WCCITOWN.VIR` (two
//! keys each), and `WCCUSERS.VIR` (three keys, one of them duplicate-
//! permitting) -- hex-dumped byte for byte, field by field, cross-checked
//! against every offset this crate's *read* side already trusts
//! ([`super::at`], [`super::pages::fcr`], `keys.rs`'s own `BASE`/`WIDTH`/
//! `at` module) and against `pages.rs`'s own
//! `a_virgin_root_reads_as_a_leaf_even_though_its_slots_disagree` test,
//! which independently pins the empty-leaf shape this module writes. Every
//! field below that is not already documented on the read side is measured
//! against at least two of those five files; where a field's meaning is
//! still unmeasured, the doc comment says so and this module writes zero.
//!
//! # What create actually builds
//!
//! `keys + 2` pages: the file control record (page 0), one empty leaf index
//! page per **key** -- not per segment; `WCCBANKS.VIR`'s one duplicate-
//! permitting key has two segments and exactly one root -- at pages `1..=
//! keys`, and one pre-allocated, empty data page at `keys + 1`. That last
//! page is not cosmetic: [`super::pages::Layout::next_slot`] finds it by
//! scanning for a data page with room, so the very first
//! [`super::Block::insert`] into a file this module created lands there
//! without growing the file, exactly as it would on a virgin `WCCUSERS.DAT`.
//!
//! One page more when the file declares an alternate collating sequence: the
//! block goes on physical page 1 ([`super::acs::V5_PAGE`], the only place a
//! v5 reader looks for it), and everything after it moves down one, so the
//! roots are at `2..=keys + 1` and the data page at `keys + 2`.
//!
//! # What this module refuses
//!
//! - More than one duplicate-permitting key. Every real file measured here
//!   has at most one; a second would need its own `[prev][next]` chain
//!   region in the physical record, and nothing on hand says where a second
//!   one goes relative to the first's `physical - 8` -- see
//!   [`super::keys::at::CHAIN`]'s doc comment on why even *one* key's chain
//!   offset varies between `WCCUSERS.DAT` and `WCCUSERS.VIR`. Refused rather
//!   than guessed.
//! - Compression, blank truncation and key-only files. None of
//!   `DFACF_COMPRESS`, `DFACF_BLANKTRUNC` or `DFACF_KEYONLY` has a measured
//!   *create-time* byte layout here -- [`super::at::USRFLGS`]'s bits are
//!   read-side only, from files this crate never built -- so [`FileSpec`] has
//!   no field for any of them, and asking for one is not a call this module's
//!   signature can even express.
//! - Variable-length records ([`FileSpec::variable`], `DFACF_VARIABLE`) are
//!   now written -- measured off the MajorBBS 6 kit's `BBSK.DAT`, a virgin
//!   copy of which carries `variable_tag` (`0xff`), `variable_subflag`
//!   (`0xff`) and `variable_highest` (`0xffff`), [`fcr::USRFLGS_VARIABLE`]
//!   set, and a physical record four bytes wider than its logical one -- the
//!   fragment pointer every variable-length insert (Task 4) will place a
//!   record's body through. What this module does *not* do: pre-allocate a
//!   variable page, or let [`super::Block::insert`] write into a file it
//!   created this way -- both are refused today (`lib.rs`'s own `insert`
//!   doc comment) until a later task gives them a measured layout.
//! - An alternate collating sequence is now written rather than refused --
//!   [`FileSpec::acs`] and [`KeySpec::acs`] -- measured off the MajorBBS 6
//!   kit's own `BBSUSR.DAT`, which is a v5 file carrying `ALLCAPS` on
//!   physical page 1. See [`build_fcr`] for the three fields the control
//!   record gains and [`create`] for the page.
//! - A key segment whose type this crate's own reader
//!   ([`super::keys::Kind::of`]) has no ordering for. Writing one would
//!   build a file this crate could create but never read back -- the same
//!   failure `keys::parse` itself refuses on the read side, checked here
//!   before a byte is written rather than after.
//! - Overwriting an existing file. Real Btrieve's `dfaCreate` takes a
//!   `keyno` of 0 ("fail if it exists") or -1 ("overwrite"); this always
//!   behaves as 0, because a `create` call that silently replaced a file
//!   already in use is a worse failure mode than refusing to run at all.

use std::path::Path;

use super::keys::{Kind, SEGMAX};
use super::pages::{self, Header, Shape};
use super::BtvError;

/// Where each field of a key definition lives, within the `0x1e`-byte
/// definition -- extending `keys.rs`'s own `at` module (`ATTRIBUTES`,
/// `CHAIN`, `OFFSET`, `LENGTH`, `EXTENDED`) with the fields only a *writer*
/// needs, because a reader never has to reproduce them.
///
/// `keys::parse` never reads any of these back -- `ROOT`/`RECORDS` are
/// re-derived by [`super::pages`]'s own `KEY_ROOT`/`KEY_RECORDS` constants
/// when a *write* needs them, and `KEY_LENGTH`/`ENTRY_SIZE`/`MAX_ENTRIES`/
/// `HALF_ENTRIES` are all values `keys::Key::length`/`pages::Shape` already
/// recompute from the segments on every read. Real Btrieve stores them
/// anyway -- every one of the ten key definitions measured across the five
/// `.VIR` files below carries a value here, and it agrees with what this
/// crate would compute independently in every case -- so this module writes
/// the same numbers, both to match the real file byte for byte and because
/// nothing says a future reader will always recompute rather than trust
/// disk.
mod at {
    /// Root index page. A [`super::pages::long`]. Same field as
    /// [`super::super::pages::fcr::KEY_ROOT`]; named again here because this
    /// module writes it at file-creation time rather than through a
    /// `Block::reindex`.
    pub const ROOT: usize = 0x00;
    /// How many records this key indexes. Zero at creation.
    pub const RECORDS: usize = 0x04;
    /// Attribute flags -- see [`super::attrs`].
    pub const ATTRIBUTES: usize = 0x08;
    /// The key's total width in bytes, every segment summed --
    /// [`super::super::keys::Key::length`]. Measured at this offset on all
    /// five `.VIR` files: `WCCBANKS.VIR` reads `0x22` (34, its 30-byte name
    /// plus 4-byte number) here, `WCCUSERS.VIR`'s three keys read `0x1e`
    /// (30), `0x0b` (11) and `0x04` (4).
    pub const KEY_LENGTH: usize = 0x0a;
    /// Bytes of one index entry -- [`Shape::entry_size`]. Already read-side
    /// documented at `pages.rs`'s [`super::super::pages::Shape::entry_size`].
    pub const ENTRY_SIZE: usize = 0x0c;
    /// Index entries that fit one page -- [`Shape::capacity`]. Already
    /// documented at [`super::super::pages::Shape::capacity`].
    pub const MAX_ENTRIES: usize = 0x0e;
    /// `MAX_ENTRIES / 2`, integer division. Not read anywhere in this crate;
    /// measured directly against all ten definitions across the five `.VIR`
    /// files (`WCCBANKS.VIR` 10 -> 5, `WCCACMSR.VIR` 127 -> 63,
    /// `WCCGANGS.VIR` 17 -> 8 and 31 -> 15, `WCCITOWN.VIR` 127 -> 63 and
    /// 89 -> 44, `WCCUSERS.VIR` 53 -> 26, 107 -> 53 and 127 -> 63): every one
    /// is exactly `MAX_ENTRIES >> 1`, which reads as a cached "half full"
    /// split threshold for whatever B-tree balancing the real engine does --
    /// never consumed by anything this crate reads, written only so a byte
    /// comparison against a real file has nothing left unaccounted for.
    pub const HALF_ENTRIES: usize = 0x10;
    /// Duplicate chain offset. Same field as
    /// [`super::super::keys::at::CHAIN`].
    pub const CHAIN: usize = 0x12;
    /// Segment offset within the record. Same field as
    /// [`super::super::keys::at::OFFSET`].
    pub const OFFSET: usize = 0x14;
    /// Segment length. Same field as [`super::super::keys::at::LENGTH`].
    pub const LENGTH: usize = 0x16;
    /// Extended data type. Same field as
    /// [`super::super::keys::at::EXTENDED`].
    pub const EXTENDED: usize = 0x1c;
}

/// Attribute bits this module writes -- the same bit numbering `keys.rs`'s
/// own `flag` module reads, kept as a second, `create`-only copy rather than
/// exported from there because a reader's flags and a writer's are read in
/// opposite directions and conflating them invites writing a bit a reader
/// happens to ignore and calling that "supported".
mod attrs {
    pub const DUPLICATES: u16 = 1 << 0;
    /// `DFAKF_MODIFYABLE` (`DFAAPI.H:97`). Genuinely per-key and not
    /// derivable from anything else measured here: across the ten key
    /// definitions in the five `.VIR` files this module is measured
    /// against, this bit is set on some duplicate-permitting keys and not
    /// others (`WCCBANKS.VIR`, `WCCGANGS.VIR`'s key 1: yes;
    /// `WCCITOWN.VIR`'s key 1: no) and on some unique keys and not others
    /// (`WCCUSERS.VIR`'s key 1: yes; its key 0, and every key `WCCACMSR.VIR`/
    /// `WCCGANGS.VIR`/`WCCITOWN.VIR` have that permits no duplicates: no) --
    /// so [`KeySpec::modifiable`] is the caller's choice, exactly as
    /// `DFAAPI.C:734`'s own `ks.flags|=(keys[iKey].flags&DFASF_KEYVALID)`
    /// leaves it to the caller of `dfaCreateSpec`.
    pub const MODIFIABLE: u16 = 1 << 1;
    pub const ANOSEG: u16 = 1 << 4;
    /// `DFASF_ALTCOLLATE` -- the same bit [`super::super::keys::flag`] calls
    /// `ALT_COLLATING`, read back off the kit's `BBSUSR.DAT` key 0, whose
    /// attribute word is `0x0120`: this bit and [`EXTENDED`].
    pub const ALT_COLLATING: u16 = 1 << 5;
    pub const DESCENDING: u16 = 1 << 6;
    pub const EXTENDED: u16 = 1 << 8;
    /// **Not caller-controlled.** Set automatically whenever a segment's
    /// type is `0x0e` (unsigned binary) -- measured on `WCCGANGS.VIR`'s key
    /// 1, `WCCITOWN.VIR`'s key 1 and `WCCUSERS.VIR`'s key 2, all three
    /// `0x0e`, all three carrying this bit, against `WCCBANKS.VIR`'s
    /// duplicate key (type `0x0b`, zstring) and every other measured
    /// segment of any other type, none of which carries it. Confirmed live,
    /// not just from the five `.VIR` files: a real `B_CREATE` issued by this
    /// task's own `tools/btrieve-oracle/crtprobe.c` with `ext_type=14`
    /// (`0x0e`) and a request that did **not** set this bit came back from a
    /// `B_STAT` reporting it set anyway (`flags=0x0145` where the request
    /// asked for `0x0141`) -- the real engine adds it itself for this one
    /// type, so this module does too, rather than exposing a flag a caller
    /// could get wrong.
    pub const OLD_BINARY: u16 = 1 << 2;
}

/// Smallest legal page length. Same rule [`super::Geometry::read`] checks a
/// file against on the way in.
const MIN_PAGE: u16 = 512;

/// Largest page length this writes. Version 5's own maximum, and every page
/// size measured anywhere in this repository is one of the four multiples of
/// 512 up to it: 512 (`DUPKEY30.DAT`), 1024 (the kit's `BBSK.DAT` and
/// `BBSUSR.DAT`, and `FRAG1024.DAT`), 2048 (`PP2048.DAT`) and 4096
/// (`WCCMP002.DAT`).
///
/// It is a refusal rather than a clamp because of what one byte of the file
/// control record can hold: [`fcr::VARIABLE_PAGE_CAPACITY`] is a single byte
/// carrying `page_size / 20`, which is 204 at 4,096 and overflows a `u8`
/// somewhere past 5,100. Refusing here is what makes that `as u8` lossless
/// rather than a silent truncation on a file nobody could read back.
const MAX_PAGE: u16 = 4096;

/// Bytes of file control record this module fills in below `KEYS_BASE`.
/// Same offsets as [`super::at`]/[`super::pages::fcr`]; re-stated locally so
/// this module's byte-builder reads as one self-contained table rather than
/// three modules' worth of imports.
mod fcr {
    /// Version marker byte. Zero everywhere else in the first four bytes;
    /// `4` here is what all seventeen of MajorMUD's own v5 files carry, and
    /// what [`super::super::version`] accepts.
    pub const VERSION_BYTE: usize = 0x07;
    pub const VERSION: u8 = 4;
    pub const PAGE_SIZE: usize = 0x08;
    /// A second [`super::pages::long`] that reads [`super::pages::NOWHERE`]
    /// on every one of the five `.VIR` files measured, immediately before
    /// [`FREE`] -- caught only because the first version of this module's
    /// byte-for-byte comparison test against a real file failed at exactly
    /// this offset, having jumped from the version byte at 0x07 straight to
    /// `PAGE_SIZE` at 0x08 and never accounted for 0x0c-0x0f at all. What it
    /// means is not measured -- a second free list (data pages and index
    /// pages kept apart) is one guess, a pre-image/abort pointer another --
    /// only that it is `NOWHERE` on every virgin file on hand, which is what
    /// this module writes.
    pub const UNKNOWN_0C: usize = 0x0c;
    pub const FREE: usize = 0x10;
    pub const KEYS: usize = 0x14;
    pub const RECLEN: usize = 0x16;
    pub const PHYSICAL: usize = 0x18;
    /// Highest page number in use -- `0` on every one of the five `.VIR`
    /// files measured, even though each has key roots on pages `1..=keys`.
    /// **Unmeasured beyond "always zero on a virgin file"**: nothing here
    /// says what a populated file's value would be, or reconciles this with
    /// `pages.rs`'s own `fcr::HIGHEST` doc comment, which describes a
    /// non-zero value at this same offset for `WCCTEXT.DAT`. That file's
    /// value, measured directly during this module's own investigation,
    /// actually sits four bytes later, at [`ALLOCATED`] below -- so either
    /// `pages.rs`'s constant is one word off, or it means something this
    /// module has not measured. Left exactly as read-side code already
    /// treats it (untouched) rather than "corrected" on a guess; this
    /// module writes zero here because that is what every virgin file does.
    pub const HIGHEST: usize = 0x1e;
    /// `keys + 1` on every `.VIR` file measured -- the pre-allocated data
    /// page's own page number, which is also `PAGES - 1`. Not consumed by
    /// anything this crate reads; written to match the real file.
    pub const ALLOCATED: usize = 0x20;
    /// A [`super::pages::long`] that reads `1` on all five files measured,
    /// every one of which has exactly one pre-allocated data page. Whether
    /// it counts data pages or is some other constant a virgin file always
    /// carries is not distinguishable from five samples that all have
    /// exactly one; this module always creates exactly one pre-allocated
    /// data page too, so writing the measured `1` is exact either way.
    pub const DATA_PAGE_COUNT: usize = 0x22;
    pub const PAGES: usize = 0x26;
    /// `page_size - HEADER` on all five files measured -- the usable bytes
    /// of a freshly allocated page, `512 - 6 = 506` for a 512-byte page up
    /// to `2048 - 6 = 2042` for `WCCUSERS.VIR`'s. Not consumed by anything
    /// this crate reads.
    pub const PAGE_USABLE: usize = 0x2a;
    /// `0xff` when the file holds variable-length records, `0x00` otherwise.
    /// Same offset [`super::super::at::VARIABLE_MARK`] already reads and
    /// checks against [`USRFLGS_VARIABLE`] on open (`Geometry::read`
    /// refuses the two disagreeing). The kit's `BBSK.DAT` -- a populated
    /// file -- still carries `0xff` here (`format::fcr::at::VARIABLE_TAG`'s
    /// doc comment); only [`VARIABLE_SUBFLAG`] and [`VARIABLE_HIGHEST`]
    /// change once records exist.
    pub const VARIABLE_TAG: usize = 0x38;
    /// `0xff` on a virgin (zero-record) variable file, `0x00` once the file
    /// has ever held a record. `format::fcr::at::VARIABLE_SUBFLAG`'s doc
    /// comment measures both across the corpus; a freshly created file is
    /// always virgin, so this module always writes `0xff`.
    pub const VARIABLE_SUBFLAG: usize = 0x39;
    /// A [`u16`], `0xffff` (sentinel) on a virgin variable file --
    /// `format::fcr::at::VARIABLE_HIGHEST`'s doc comment. The kit's
    /// `BBSK.DAT` (populated) reads `0x0004` here instead; this module never
    /// writes that value because it never pre-allocates a variable page
    /// (Task 4's job).
    pub const VARIABLE_HIGHEST: usize = 0x3a;
    /// The alternate collating sequence's 8-byte name. Same offset the read
    /// side already knows (`acs.rs`'s own `NAME_IN_FCR`); the engine's
    /// `Create` writes this, [`ACS_PAGE_POINTER`] and `0x40` together
    /// (`W32MKDE_decompiled.c:18430`). `ALLCAPS ` on the kit's `BBSUSR.DAT`.
    pub const ACS_NAME: usize = 0x3c;
    /// The first block's **logical** page, as a [`super::pages::long`]
    /// (word-swapped, high half first). `acs.rs`'s own `PAGE_IN_FCR`.
    ///
    /// The kit's `BBSUSR.DAT` holds `00 00 01 00` here, which is logical page
    /// 1 -- the same page the v5 block sits on physically, because a fresh
    /// file's logical and physical page numbers have not yet diverged.
    /// Written even though a v5 *reader* must not trust it (`CLASSADS.DAT`
    /// and `EMAIL.DAT` read zero here while holding a real block): matching
    /// the file the kit itself writes costs nothing, and the engine's own
    /// "has an ACS" predicate reads it.
    pub const ACS_PAGE_POINTER: usize = 0x10a;
    pub const KEYS_BASE: usize = 0x110;
    pub const KEY_WIDTH: usize = 0x1e;

    /// User flags word. Same offset [`super::super::at::USRFLGS`] already
    /// reads. This module only ever sets [`USRFLGS_VARIABLE`]; every other
    /// bit stays clear, which is what every one of the five `.VIR` files
    /// (none variable) and the kit's `BBSK.DAT` (variable, and no other bit
    /// set) carries.
    pub const USRFLGS: usize = 0x106;
    /// Bit 0 of [`USRFLGS`]: the file holds variable-length records. Same
    /// bit `format::fcr::usrflgs::VARIABLE` names on the read side.
    pub const USRFLGS_VARIABLE: u16 = 1 << 0;
    /// One byte, `page_size / 20` on a variable file, `0x00` otherwise --
    /// `format::fcr::at::VARIABLE_PAGE_CAPACITY`'s doc comment. The kit's
    /// `BBSK.DAT` is a 1024-byte-page file and reads `0x33` (51) here:
    /// `1024 / 20 = 51.2`, truncated.
    pub const VARIABLE_PAGE_CAPACITY: usize = 0x108;
}

/// One segment of a key to create: a field of the record, and how Btrieve
/// should compare it. `re/wg33src/INC/DFAAPI.H`'s `struct dfaSegSpec`, minus
/// `nullChar` (the null-key flags are unsupported on the read side --
/// [`super::keys`]'s `UNSUPPORTED` table -- so there is nothing here for one
/// to configure). `DFASF_ALTCOLLATE` is per *key* here ([`KeySpec::acs`])
/// rather than per segment: [`super::keys::parse`] binds one table to a whole
/// key and refuses a key whose segments name two, so a per-segment field
/// could express nothing this crate could read back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentSpec {
    /// Byte offset of this segment within the record, **0-based** -- the
    /// same convention [`super::keys::Segment::offset`] already uses, and
    /// *not* the 1-based `position` the wire's own `KeySpec.position`
    /// carries (`re/wg33src/SRC/api/gcommlib/DFAAPI.C:734`:
    /// `ks.position=(USHORT)(keys[iKey].segs[iSeg].position+1)` -- the `+1`
    /// happens once, when the request is built for the wire; the FCR this
    /// module writes stores the 0-based offset directly, matching every
    /// value measured at [`at::OFFSET`]).
    pub offset: u16,
    /// Length of this segment, in bytes.
    pub length: u16,
    /// Btrieve's extended data type code -- `DFAST_ZSTRING` (0x0b),
    /// `DFAST_UNSIGNED_BINARY`/`DFAST_BINARY` (0x0e), `DFAST_INTEGER` (0x01),
    /// `DFAST_AUTOINC` (0x0f), and so on. Checked against
    /// [`super::keys::Kind::of`] before anything is written: a type this
    /// crate's own reader cannot order is refused here rather than written
    /// and discovered later.
    pub kind: u8,
    /// Whether this segment sorts backwards.
    pub descending: bool,
}

/// One key to create: one or more segments, compared in order, and whether
/// more than one record may carry the same value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySpec {
    pub segments: Vec<SegmentSpec>,
    pub duplicates: bool,
    /// `DFAKF_MODIFYABLE` -- see [`attrs::MODIFIABLE`]'s doc comment. Has no
    /// effect on anything this crate reads (`keys::parse` never looks at
    /// this bit), so a caller with no reason to match a specific real file's
    /// value can simply pass `false`.
    pub modifiable: bool,
    /// `DFASF_ALTCOLLATE`: order this key through the file's alternate
    /// collating sequence rather than by raw byte value. Requires
    /// [`FileSpec::acs`] -- a key that collates through a table the file does
    /// not carry is a file [`super::keys::parse`] refuses to open, so
    /// [`validate`] refuses to write one.
    ///
    /// Sets [`attrs::ALT_COLLATING`] on every one of the key's segment words,
    /// which is what the kit's `BBSUSR.DAT` carries on its single key
    /// (attributes `0x0120`: extended type, alternate collating).
    pub acs: bool,
}

/// A new file's shape: fixed record length, page size, and its keys.
///
/// No `flags` field -- see this module's own doc comment for the create-time
/// options ([`super`]'s `DFACF_*` family) this does not have a measured
/// layout for and therefore does not accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSpec {
    /// The logical record length every record in this file will be padded or
    /// checked against -- [`super::Geometry::reclen`].
    pub record_length: u16,
    /// Bytes per page. Must be a multiple of 512, the same rule
    /// [`super::Geometry::read`] checks an opened file against.
    pub page_size: u16,
    pub keys: Vec<KeySpec>,
    /// The one alternate collating sequence this file's ACS-flagged keys
    /// order through, or `None` for a file that orders by raw byte value.
    ///
    /// One table, not a list: a v5 file holds its block at a fixed page
    /// ([`super::acs::V5_PAGE`]) and its keys carry no page number of their
    /// own, so v5 has exactly one -- see `acs.rs`'s own header on why the two
    /// versions are found differently. [`super::acs::allcaps`] is the one
    /// MajorBBS itself uses.
    pub acs: Option<super::acs::Acs>,
    /// `DFACF_VARIABLE`: the file holds variable-length records. Widens the
    /// physical record by four bytes for the fragment pointer -- see this
    /// module's doc comment and [`validate`]. Does **not** by itself let
    /// [`super::Block::insert`] write into the file: inserting into a
    /// variable-length file is Task 4's job, and refuses today regardless of
    /// how the file was created.
    pub variable: bool,
}

/// Create a new, empty Btrieve file at `path`.
///
/// Writes the v5 file control record, one empty leaf index page per key, and
/// one pre-allocated empty data page -- see this module's doc comment for
/// what that shape is measured against and why it is v5 rather than the v6
/// this machine's oracle itself writes.
///
/// # Errors
///
/// If `path` already exists (this never overwrites -- see the module doc
/// comment), if `spec` describes something this module has no measured
/// layout for (zero keys, a key with no segments, more than
/// [`SEGMAX`] segments in total, a page size that is not a multiple of 512,
/// a record that does not fit its own page, more than one duplicate-
/// permitting key, a segment whose type [`Kind::of`] cannot order, a key
/// whose index entry does not fit one page, a key collating through an ACS
/// the file does not carry, or an ACS on a segment that is not text), or if
/// the file cannot be created or written.
pub fn create(path: &Path, spec: &FileSpec) -> Result<(), BtvError> {
    let name = path.display().to_string();
    let fail = |why: String| BtvError {
        file: name.clone(),
        why,
    };

    if path.exists() {
        return Err(fail(
            "already exists, and create never overwrites -- remove it first \
             if that is really what is wanted"
                .to_owned(),
        ));
    }

    let (physical, usable) = validate(spec).map_err(fail)?;

    let nkeys = u16::try_from(spec.keys.len()).expect("validate bounds key count under SEGMAX");
    let first_root = first_root(spec);
    let pages = u32::from(nkeys) + first_root + 1;
    let file_size = u64::from(pages) * u64::from(spec.page_size);

    let mut bytes = vec![0u8; file_size as usize];
    bytes[..usize::from(spec.page_size)]
        .copy_from_slice(&build_fcr(spec, physical, usable, nkeys, pages));

    if let Some(acs) = &spec.acs {
        let page = build_acs_page(super::acs::V5_PAGE, spec.page_size, acs);
        let at = usize::from(spec.page_size) * super::acs::V5_PAGE as usize;
        bytes[at..at + usize::from(spec.page_size)].copy_from_slice(&page);
    }

    for (n, key) in spec.keys.iter().enumerate() {
        let number = n as u32 + first_root;
        let page = build_root_page(number, spec.page_size);
        let at = usize::from(spec.page_size) * number as usize;
        bytes[at..at + usize::from(spec.page_size)].copy_from_slice(&page);
        let _ = key; // the root page's own bytes carry no key-specific content
    }

    let data_number = u32::from(nkeys) + first_root;
    let data_page = build_data_page(data_number, spec.page_size);
    let at = usize::from(spec.page_size) * data_number as usize;
    bytes[at..at + usize::from(spec.page_size)].copy_from_slice(&data_page);

    std::fs::write(path, &bytes).map_err(|e| fail(format!("{e}")))
}

/// Physical page the first key's root goes on: page 1 normally, page 2 when
/// an ACS block took page 1 ahead of it -- the ACS block's page is fixed at
/// [`super::acs::V5_PAGE`] and everything else shifts around it, rather than
/// the other way around, because a v5 reader has nothing to search by and
/// looks only there.
///
/// One function so [`create`]'s page assembly and [`build_fcr`]'s `ROOT`
/// fields cannot disagree about where a root went.
fn first_root(spec: &FileSpec) -> u32 {
    if spec.acs.is_some() {
        super::acs::V5_PAGE + 1
    } else {
        1
    }
}

/// Check `spec` against every limit this module's doc comment names, and
/// return the physical (padded) record length and the page's usable byte
/// count on success -- both values every other computation in [`create`]
/// needs and that validation itself already has to derive to check the
/// record fits the page.
fn validate(spec: &FileSpec) -> Result<(u16, u16), String> {
    if spec.record_length == 0 {
        return Err("a record length of zero".to_owned());
    }
    if spec.page_size < MIN_PAGE || !spec.page_size.is_multiple_of(MIN_PAGE) {
        return Err(format!(
            "a page length of {}, which is not a multiple of {MIN_PAGE}",
            spec.page_size
        ));
    }
    if spec.page_size > MAX_PAGE {
        return Err(format!(
            "a page length of {}, more than the {MAX_PAGE} a version 5 file may have -- \
             see MAX_PAGE for the measured sizes and for the one control-record byte \
             that cannot hold a larger page's own capacity",
            spec.page_size
        ));
    }
    if spec.keys.is_empty() {
        return Err("no keys -- a file with no index is not a shape this module has \
                     measured"
            .to_owned());
    }
    if spec.keys.len() > SEGMAX {
        return Err(format!(
            "{} keys, more than the {SEGMAX} segments a file may have in total \
             (BTVSTF.H:13) before counting a single segment of any of them",
            spec.keys.len()
        ));
    }

    let mut total_segments = 0usize;
    let mut duplicate_keys = 0usize;
    for (kn, key) in spec.keys.iter().enumerate() {
        if key.segments.is_empty() {
            return Err(format!("key {kn} has no segments"));
        }
        total_segments += key.segments.len();
        if key.duplicates {
            duplicate_keys += 1;
        }
        // A key that collates through a table the file does not carry is a
        // file `keys::parse` refuses to open -- it looks page 1 up, finds no
        // block, and rejects the whole file. Refused before a byte is
        // written rather than discovered on the next open.
        if key.acs && spec.acs.is_none() {
            return Err(format!(
                "key {kn} collates through an ACS but the file declares none"
            ));
        }
        for (sn, segment) in key.segments.iter().enumerate() {
            if segment.length == 0 {
                return Err(format!("key {kn} segment {sn} has a length of zero"));
            }
            let end = u32::from(segment.offset) + u32::from(segment.length);
            if end > u32::from(spec.record_length) {
                return Err(format!(
                    "key {kn} segment {sn} covers bytes {}..{end} of the record, past \
                     its {}-byte length",
                    segment.offset, spec.record_length
                ));
            }
            let Some(kind) = Kind::of(segment.kind) else {
                return Err(format!(
                    "key {kn} segment {sn} has type {:#04x}, which this host's own \
                     reader has no ordering for -- writing it would build a file \
                     this crate could create but never read back",
                    segment.kind
                ));
            };
            // The table maps a byte to the byte it compares as, which is only
            // meaningful where the comparison is byte by byte. `keys::order`
            // folds a text segment through it and compares every other kind
            // as the number it is, so an ACS on a number would be a flag the
            // file carried and nothing honoured.
            if key.acs && kind != Kind::Text {
                return Err(format!(
                    "key {kn} segment {sn} has type {:#04x}, which is not text, and an \
                     alternate collating sequence folds text only",
                    segment.kind
                ));
            }
        }
    }
    if total_segments > SEGMAX {
        return Err(format!(
            "{total_segments} segments in total, more than the {SEGMAX} a file may \
             have (BTVSTF.H:13)"
        ));
    }
    if duplicate_keys > 1 {
        return Err(format!(
            "{duplicate_keys} duplicate-permitting keys -- this module has a measured \
             chain layout for at most one (see this module's own doc comment on why a \
             second key's chain offset is not something this repo has on hand to \
             measure)"
        ));
    }
    // Same refusal, one clause down: a duplicate-permitting key on a
    // variable-length file would need both the eight-byte `[prev][next]`
    // chain and the four-byte fragment pointer in the same physical record,
    // and nothing measured here says how the two combine -- no file in
    // `tmp/` carries both. Guessed at additivity once and caught in review
    // (this module's own doc comment on why even *one* combination beyond
    // what is measured is refused rather than assumed).
    if spec.variable && duplicate_keys > 0 {
        return Err(format!(
            "a variable-length file with {duplicate_keys} duplicate-permitting key(s) -- \
             this module has no measured layout for how the eight-byte duplicate chain and \
             the four-byte fragment pointer combine in the same physical record"
        ));
    }

    // The physical record is the logical one plus eight bytes of
    // `[prev][next]` duplicate chain when any key permits duplicates --
    // `WCCBANKS.VIR` 72 -> 80, `WCCGANGS.VIR` 253 -> 261, `WCCITOWN.VIR`
    // 65 -> 73, `WCCUSERS.VIR` 1998 -> 2006, all eight bytes, all measured
    // the same. `keys.rs`'s own `at::CHAIN` doc comment: "physical - 8 is
    // therefore the general rule." A variable-length file adds four more --
    // the kit's `BBSK.DAT` reads reclen 31, physical 35 -- the fragment
    // pointer `Block::insert_v6`/`variable::Pointer` already expect to find
    // at the logical record length (`lib.rs::flag`'s own doc comment: "the
    // fragment pointer is at the logical record length whichever other flags
    // are set"). The two additions never both apply -- the refusal above
    // rules out a duplicate-permitting key on a variable-length file -- so
    // this is not really "additive", just written as the sum of two
    // mutually exclusive terms.
    let physical = u32::from(spec.record_length)
        + if duplicate_keys > 0 { 8 } else { 0 }
        + if spec.variable { 4 } else { 0 };
    let physical =
        u16::try_from(physical).map_err(|_| format!("a physical record length of {physical}"))?;
    // The record has to fit in what a page has left over after its own
    // 6-byte header (`pages::HEADER`, the same subtraction `build_fcr` makes
    // to write `fcr::PAGE_USABLE`) -- not the whole page. A record that
    // exactly fills `page_size` still leaves no room for the header, which
    // is how a spec once passed here and then produced a file this crate's
    // own opener rejected as not a whole number of pages.
    let usable = spec.page_size - pages::HEADER;
    if physical > usable {
        return Err(format!(
            "a {physical}-byte record in a {}-byte page, which has only {usable} bytes \
             usable after its {}-byte header",
            spec.page_size,
            pages::HEADER
        ));
    }

    // Every key's index entry has to fit one page -- `Shape::capacity`
    // returns 0 rather than erroring, the same contract `pages::build_index`
    // already refuses on.
    for (kn, key) in spec.keys.iter().enumerate() {
        let length: u16 = key.segments.iter().map(|s| s.length).sum();
        let shape = Shape {
            length: usize::from(length),
            duplicates: key.duplicates,
        };
        if shape.capacity(spec.page_size) == 0 {
            return Err(format!(
                "key {kn}'s {}-byte index entry does not fit a {}-byte page",
                shape.entry_size(),
                spec.page_size
            ));
        }
    }

    Ok((physical, usable))
}

/// Build the file control record: page 0, exactly `page_size` bytes.
fn build_fcr(spec: &FileSpec, physical: u16, usable: u16, nkeys: u16, pages: u32) -> Vec<u8> {
    let mut fcr = vec![0u8; usize::from(spec.page_size)];

    fcr[fcr::VERSION_BYTE] = fcr::VERSION;
    fcr[fcr::PAGE_SIZE..fcr::PAGE_SIZE + 2].copy_from_slice(&spec.page_size.to_le_bytes());
    fcr[fcr::UNKNOWN_0C..fcr::UNKNOWN_0C + 4].copy_from_slice(&pages::to_long(pages::NOWHERE));
    fcr[fcr::FREE..fcr::FREE + 4].copy_from_slice(&pages::to_long(pages::NOWHERE));
    fcr[fcr::KEYS..fcr::KEYS + 2].copy_from_slice(&nkeys.to_le_bytes());
    fcr[fcr::RECLEN..fcr::RECLEN + 2].copy_from_slice(&spec.record_length.to_le_bytes());
    fcr[fcr::PHYSICAL..fcr::PHYSICAL + 2].copy_from_slice(&physical.to_le_bytes());
    // Zero on every virgin file measured -- see fcr::HIGHEST's own doc
    // comment. Written explicitly, even though `fcr` starts zeroed, so this
    // function accounts for every byte its own doc comment names.
    fcr[fcr::HIGHEST..fcr::HIGHEST + 2].copy_from_slice(&0u16.to_le_bytes());
    // `keys + 1` on every `.VIR` file measured, which is `pages - 1` -- the
    // pre-allocated data page's own number. Written as `pages - 1` so an ACS
    // block's extra page carries it along.
    let allocated = u16::try_from(pages - 1).expect("validate bounds the page count");
    fcr[fcr::ALLOCATED..fcr::ALLOCATED + 2].copy_from_slice(&allocated.to_le_bytes());
    fcr[fcr::DATA_PAGE_COUNT..fcr::DATA_PAGE_COUNT + 4].copy_from_slice(&pages::to_long(1));
    fcr[fcr::PAGES..fcr::PAGES + 4].copy_from_slice(&pages::to_long(pages));
    fcr[fcr::PAGE_USABLE..fcr::PAGE_USABLE + 2].copy_from_slice(&usable.to_le_bytes());

    if spec.variable {
        fcr[fcr::VARIABLE_TAG] = 0xff;
        // A freshly created file is always virgin -- see VARIABLE_SUBFLAG
        // and VARIABLE_HIGHEST's own doc comments for what changes once a
        // record has been inserted (not this module's job).
        fcr[fcr::VARIABLE_SUBFLAG] = 0xff;
        fcr[fcr::VARIABLE_HIGHEST..fcr::VARIABLE_HIGHEST + 2].copy_from_slice(&0xffffu16.to_le_bytes());
        let usrflgs = u16::from_le_bytes([fcr[fcr::USRFLGS], fcr[fcr::USRFLGS + 1]]) | fcr::USRFLGS_VARIABLE;
        fcr[fcr::USRFLGS..fcr::USRFLGS + 2].copy_from_slice(&usrflgs.to_le_bytes());
        fcr[fcr::VARIABLE_PAGE_CAPACITY] = (spec.page_size / 20) as u8;
    }

    if let Some(acs) = &spec.acs {
        fcr[fcr::ACS_NAME..fcr::ACS_NAME + acs.name.len()].copy_from_slice(&acs.name);
        fcr[fcr::ACS_PAGE_POINTER..fcr::ACS_PAGE_POINTER + 4]
            .copy_from_slice(&pages::to_long(super::acs::V5_PAGE));
    }

    let first_root = first_root(spec);
    let mut at = fcr::KEYS_BASE;
    for (n, key) in spec.keys.iter().enumerate() {
        let root = n as u32 + first_root;
        let length: u16 = key.segments.iter().map(|s| s.length).sum();
        let shape = Shape {
            length: usize::from(length),
            duplicates: key.duplicates,
        };
        let entry_size = u16::try_from(shape.entry_size()).expect("validated to fit a page");
        let max_entries = u16::try_from(shape.capacity(spec.page_size)).expect(
            "an index this small does not approach u16::MAX entries on any page size this \
             module accepts",
        );
        let chain = if key.duplicates { physical - 8 } else { 0 };

        for (sn, segment) in key.segments.iter().enumerate() {
            let def = &mut fcr[at..at + fcr::KEY_WIDTH];

            if sn == 0 {
                def[at::ROOT..at::ROOT + 4].copy_from_slice(&pages::to_long(root));
                // No records yet. Written explicitly for the same reason
                // fcr::HIGHEST is above: `def` starts zeroed either way.
                def[at::RECORDS..at::RECORDS + 4].copy_from_slice(&pages::to_long(0));
                def[at::KEY_LENGTH..at::KEY_LENGTH + 2].copy_from_slice(&length.to_le_bytes());
                def[at::ENTRY_SIZE..at::ENTRY_SIZE + 2]
                    .copy_from_slice(&entry_size.to_le_bytes());
                def[at::MAX_ENTRIES..at::MAX_ENTRIES + 2]
                    .copy_from_slice(&max_entries.to_le_bytes());
                def[at::HALF_ENTRIES..at::HALF_ENTRIES + 2]
                    .copy_from_slice(&(max_entries / 2).to_le_bytes());
                def[at::CHAIN..at::CHAIN + 2].copy_from_slice(&chain.to_le_bytes());
            }

            let mut word = attrs::EXTENDED;
            if key.duplicates {
                word |= attrs::DUPLICATES;
            }
            if key.modifiable {
                word |= attrs::MODIFIABLE;
            }
            if key.acs {
                word |= attrs::ALT_COLLATING;
            }
            if sn + 1 < key.segments.len() {
                word |= attrs::ANOSEG;
            }
            if segment.descending {
                word |= attrs::DESCENDING;
            }
            if segment.kind == 0x0e {
                word |= attrs::OLD_BINARY;
            }
            def[at::ATTRIBUTES..at::ATTRIBUTES + 2].copy_from_slice(&word.to_le_bytes());
            def[at::OFFSET..at::OFFSET + 2].copy_from_slice(&segment.offset.to_le_bytes());
            def[at::LENGTH..at::LENGTH + 2].copy_from_slice(&segment.length.to_le_bytes());
            def[at::EXTENDED] = segment.kind;

            at += fcr::KEY_WIDTH;
        }
    }

    fcr
}

/// Build one key's root page: an empty leaf, exactly `page_size` bytes.
///
/// **`rightmost` is [`pages::NOWHERE`] and `leftmost` is `0` -- not both
/// `NOWHERE`.** Measured off `WCCUSERS.VIR` pages 1-3 and `WCCGANGS.VIR`
/// pages 1-2, byte for byte, and independently pinned by `pages.rs`'s own
/// `a_virgin_root_reads_as_a_leaf_even_though_its_slots_disagree` test:
/// "This is the shape every file this host writes starts in." That is a
/// different shape from what [`pages::build_index`] produces for an *empty*
/// tree (`NOWHERE` at both slots) -- [`IndexPage::leaf`](pages::IndexPage::leaf)
/// treats the two as equivalent when reading, which is exactly why
/// `build_index`'s shape was never wrong for anything that read it back, but
/// this writes the one the real engine itself produces at create time rather
/// than reuse `build_index`'s: a fresh file is not a rebuild of an existing
/// tree, and there is no reason to diverge from the measured byte for byte
/// answer when it is sitting right there.
fn build_root_page(number: u32, page_size: u16) -> Vec<u8> {
    let mut page = vec![0u8; usize::from(page_size)];
    page[..usize::from(pages::HEADER)].copy_from_slice(
        &Header {
            number,
            data: false,
            stamp: 0,
        }
        .encode(),
    );
    // Bytes 6-7 (entry count) are already zero.
    page[8..12].copy_from_slice(&pages::to_long(pages::NOWHERE)); // rightmost
    page[12..16].copy_from_slice(&pages::to_long(0)); // leftmost -- see doc comment
    page
}

/// Build the page holding the alternate collating sequence: an ordinary
/// six-byte page header, then the 265-byte block, then zeros.
///
/// Measured off the MajorBBS 6 kit's `BBSUSR.DAT` page 1, which reads
/// `00 00 01 00 00 00 ac 41 4c 4c 43 41 50 53 20` and then the table: the
/// page's own number as a [`pages::long`], a zero flags word (**not** a data
/// page, and no stamp), then the tag byte, the 8-byte name and the 256 table
/// bytes. Everything past the block is zero on that file, and is here.
///
/// The tag is [`super::acs::TAGS`]`[0]`, `0xac`. The engine accepts `0xad`
/// too, but nothing on hand says what distinguishes them, so this writes the
/// one the file it is measured against carries.
fn build_acs_page(number: u32, page_size: u16, acs: &super::acs::Acs) -> Vec<u8> {
    let mut page = vec![0u8; usize::from(page_size)];
    page[..usize::from(pages::HEADER)].copy_from_slice(
        &Header {
            number,
            data: false,
            stamp: 0,
        }
        .encode(),
    );
    let mut at = usize::from(pages::HEADER);
    page[at] = super::acs::TAGS[0];
    at += 1;
    page[at..at + acs.name.len()].copy_from_slice(&acs.name);
    at += acs.name.len();
    page[at..at + acs.table.len()].copy_from_slice(&acs.table);
    page
}

/// Build the pre-allocated, empty data page: a six-byte header with the data
/// bit set, then all zero -- measured off `WCCBANKS.VIR` page 2,
/// `WCCGANGS.VIR` page 3, `WCCITOWN.VIR` page 3, and `WCCUSERS.VIR` page 4
/// (every `.VIR` file's own last page). See this module's doc comment for
/// why a virgin file has one at all.
fn build_data_page(number: u32, page_size: u16) -> Vec<u8> {
    let mut page = vec![0u8; usize::from(page_size)];
    page[..usize::from(pages::HEADER)].copy_from_slice(
        &Header {
            number,
            data: true,
            stamp: 0,
        }
        .encode(),
    );
    page
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A path this test may create a file at, under `target/` rather than
    /// the system temporary directory -- [`crate::testing::scratch`], the
    /// convention `pages.rs`'s own write-path tests already use. `name` also
    /// names the scratch directory, one per caller, so two tests running in
    /// parallel never wipe a directory the other is still using -- the same
    /// reason every `crate::testing::scratch` call in `pages.rs` passes a
    /// distinct name.
    fn scratch(name: &str) -> std::path::PathBuf {
        crate::testing::scratch(name).join("file.dat")
    }

    fn single_key_spec(record_length: u16, page_size: u16, duplicates: bool) -> FileSpec {
        FileSpec {
            record_length,
            page_size,
            keys: vec![KeySpec {
                segments: vec![SegmentSpec {
                    offset: 0,
                    length: 4,
                    kind: 0x0e, // unsigned binary
                    descending: false,
                }],
                duplicates,
                modifiable: false,
                acs: false,
            }],
            acs: None,
            variable: false,
        }
    }

    #[test]
    fn a_single_key_file_is_keys_plus_two_pages() {
        let path = scratch("single-key.dat");
        let spec = single_key_spec(12, 512, false);
        create(&path, &spec).expect("creates");

        let bytes = std::fs::read(&path).expect("reads back");
        assert_eq!(bytes.len(), 3 * 512, "FCR + 1 root + 1 data page");

        assert_eq!(bytes[..4], [0, 0, 0, 0], "v5's zero-byte version prefix");
        assert_eq!(bytes[fcr::VERSION_BYTE], fcr::VERSION);
        assert_eq!(u16::from_le_bytes([bytes[8], bytes[9]]), 512, "page size");
        assert_eq!(
            &bytes[fcr::FREE..fcr::FREE + 4],
            &pages::to_long(pages::NOWHERE)[..],
            "an empty free list"
        );
        assert_eq!(u16::from_le_bytes([bytes[0x14], bytes[0x15]]), 1, "one key");
        assert_eq!(u16::from_le_bytes([bytes[0x16], bytes[0x17]]), 12, "reclen");
        assert_eq!(
            u16::from_le_bytes([bytes[0x18], bytes[0x19]]),
            12,
            "physical == reclen, no duplicate key to widen it"
        );
        assert_eq!(pages::long(&bytes[0x1a..0x1e]), 0, "no records yet");
        assert_eq!(u16::from_le_bytes([bytes[0x20], bytes[0x21]]), 2, "keys + 1");
        assert_eq!(pages::long(&bytes[0x22..0x26]), 1, "one pre-allocated data page");
        assert_eq!(pages::long(&bytes[0x26..0x2a]), 3, "3 pages total");
        assert_eq!(
            u16::from_le_bytes([bytes[0x2a], bytes[0x2b]]),
            512 - 6,
            "page usable bytes"
        );

        let def = &bytes[0x110..0x110 + 0x1e];
        assert_eq!(pages::long(&def[0x00..0x04]), 1, "key roots at page 1");
        assert_eq!(pages::long(&def[0x04..0x08]), 0);
        let attrs = u16::from_le_bytes([def[0x08], def[0x09]]);
        assert_eq!(
            attrs,
            attrs::EXTENDED | attrs::OLD_BINARY,
            "unique, ascending, extended type -- OLD_BINARY auto-set for type 0x0e"
        );
        assert_eq!(u16::from_le_bytes([def[0x0a], def[0x0b]]), 4, "key length");
        assert_eq!(u16::from_le_bytes([def[0x0c], def[0x0d]]), 4 + 8, "entry size, unique");
        let max_entries = (512 - 12) / (4 + 8);
        assert_eq!(u16::from_le_bytes([def[0x0e], def[0x0f]]), max_entries as u16);
        assert_eq!(
            u16::from_le_bytes([def[0x10], def[0x11]]),
            (max_entries / 2) as u16
        );
        assert_eq!(u16::from_le_bytes([def[0x12], def[0x13]]), 0, "no chain, unique key");
        assert_eq!(u16::from_le_bytes([def[0x14], def[0x15]]), 0, "segment offset");
        assert_eq!(u16::from_le_bytes([def[0x16], def[0x17]]), 4, "segment length");
        assert_eq!(def[0x1c], 0x0e, "extended type byte");

        // Page 1: the key's empty root.
        let root = &bytes[512..1024];
        assert_eq!(pages::long(&root[..4]), 1, "page number");
        assert_eq!(&root[4..6], &[0, 0], "not a data page, no stamp");
        assert_eq!(&root[6..8], &[0, 0], "no entries");
        assert_eq!(&root[8..12], &pages::to_long(pages::NOWHERE)[..], "no rightmost child");
        assert_eq!(&root[12..16], &pages::to_long(0)[..], "leftmost child is 0, not NOWHERE");
        assert!(root[16..].iter().all(|&b| b == 0), "nothing past the header");

        // Page 2: the pre-allocated, empty data page.
        let data = &bytes[1024..1536];
        assert_eq!(pages::long(&data[..4]), 2, "page number");
        assert_eq!(&data[4..6], &[0x00, 0x80], "the data-page bit");
        assert!(data[6..].iter().all(|&b| b == 0), "no record on it yet");
    }

    #[test]
    fn a_duplicate_key_widens_the_physical_record_by_eight() {
        let path = scratch("dup-key.dat");
        let spec = single_key_spec(12, 512, true);
        create(&path, &spec).expect("creates");
        let bytes = std::fs::read(&path).expect("reads back");

        assert_eq!(u16::from_le_bytes([bytes[0x16], bytes[0x17]]), 12, "reclen unchanged");
        assert_eq!(
            u16::from_le_bytes([bytes[0x18], bytes[0x19]]),
            20,
            "physical = reclen + 8, the chain pair"
        );
        let def = &bytes[0x110..0x110 + 0x1e];
        let attrs = u16::from_le_bytes([def[0x08], def[0x09]]);
        assert_eq!(attrs, attrs::EXTENDED | attrs::DUPLICATES | attrs::OLD_BINARY);
        assert_eq!(
            u16::from_le_bytes([def[0x12], def[0x13]]),
            20 - 8,
            "chain offset is physical - 8"
        );
    }

    #[test]
    fn a_multi_segment_key_gets_one_root_but_two_definitions() {
        let path = scratch("multi-seg.dat");
        let spec = FileSpec {
            record_length: 34,
            page_size: 512,
            keys: vec![KeySpec {
                segments: vec![
                    SegmentSpec { offset: 0, length: 30, kind: 0x0b, descending: false },
                    SegmentSpec { offset: 30, length: 4, kind: 0x01, descending: false },
                ],
                duplicates: false,
                modifiable: false,
                acs: false,
            }],
            acs: None,
            variable: false,
        };
        create(&path, &spec).expect("creates");
        let bytes = std::fs::read(&path).expect("reads back");

        assert_eq!(u16::from_le_bytes([bytes[0x14], bytes[0x15]]), 1, "one key");
        assert_eq!(bytes.len(), 3 * 512, "still keys(1) + 2 pages -- one root, not two");

        let def0 = &bytes[0x110..0x110 + 0x1e];
        let attrs0 = u16::from_le_bytes([def0[0x08], def0[0x09]]);
        assert_eq!(attrs0, attrs::EXTENDED | attrs::ANOSEG, "more segments follow");
        assert_eq!(pages::long(&def0[0x00..0x04]), 1, "the key's one root");
        assert_eq!(u16::from_le_bytes([def0[0x0a], def0[0x0b]]), 34, "34 = 30 + 4");

        let def1 = &bytes[0x110 + 0x1e..0x110 + 2 * 0x1e];
        let attrs1 = u16::from_le_bytes([def1[0x08], def1[0x09]]);
        assert_eq!(attrs1, attrs::EXTENDED, "last segment, no ANOSEG");
        assert_eq!(pages::long(&def1[0x00..0x04]), 0, "a continuation carries no root");
        assert_eq!(u16::from_le_bytes([def1[0x0a], def1[0x0b]]), 0, "nor a key length");
        assert_eq!(u16::from_le_bytes([def1[0x14], def1[0x15]]), 30, "its own segment offset");
        assert_eq!(u16::from_le_bytes([def1[0x16], def1[0x17]]), 4, "its own segment length");
    }

    #[test]
    fn two_keys_root_at_pages_one_and_two() {
        let path = scratch("two-keys.dat");
        let spec = FileSpec {
            record_length: 8,
            page_size: 512,
            keys: vec![
                KeySpec {
                    segments: vec![SegmentSpec { offset: 0, length: 4, kind: 0x0e, descending: false }],
                    duplicates: false,
                    modifiable: false,
                    acs: false,
                },
                KeySpec {
                    segments: vec![SegmentSpec { offset: 4, length: 4, kind: 0x0e, descending: true }],
                    duplicates: false,
                    modifiable: false,
                    acs: false,
                },
            ],
            acs: None,
            variable: false,
        };
        create(&path, &spec).expect("creates");
        let bytes = std::fs::read(&path).expect("reads back");

        assert_eq!(bytes.len(), 4 * 512, "keys(2) + 2 pages");
        let def0 = &bytes[0x110..0x110 + 0x1e];
        let def1 = &bytes[0x110 + 0x1e..0x110 + 2 * 0x1e];
        assert_eq!(pages::long(&def0[0x00..0x04]), 1);
        assert_eq!(pages::long(&def1[0x00..0x04]), 2);
        let attrs1 = u16::from_le_bytes([def1[0x08], def1[0x09]]);
        assert_eq!(attrs1, attrs::EXTENDED | attrs::DESCENDING | attrs::OLD_BINARY);

        // pages 1 and 2 are both roots, page 3 is the pre-allocated data page.
        let page1 = &bytes[512..1024];
        let page2 = &bytes[1024..1536];
        let page3 = &bytes[1536..2048];
        assert_eq!(pages::long(&page1[..4]), 1);
        assert_eq!(&page1[4..6], &[0, 0]);
        assert_eq!(pages::long(&page2[..4]), 2);
        assert_eq!(&page2[4..6], &[0, 0]);
        assert_eq!(pages::long(&page3[..4]), 3);
        assert_eq!(&page3[4..6], &[0x00, 0x80], "the third page is the data page");
    }

    #[test]
    fn create_refuses_to_overwrite_an_existing_file() {
        let path = scratch("exists.dat");
        std::fs::write(&path, b"already here").expect("seed a file");
        let err = create(&path, &single_key_spec(12, 512, false)).expect_err("refuses");
        assert!(err.why.contains("already exists"), "{}", err.why);
        assert_eq!(
            std::fs::read(&path).expect("still there"),
            b"already here",
            "the existing file must be untouched"
        );
    }

    #[test]
    fn create_refuses_zero_keys() {
        let path = scratch("zero-keys.dat");
        let spec = FileSpec { record_length: 12, page_size: 512, keys: vec![], acs: None, variable: false };
        let err = create(&path, &spec).expect_err("refuses");
        assert!(err.why.contains("no keys"), "{}", err.why);
        assert!(!path.exists(), "nothing should have been written");
    }

    /// 4,096 is version 5's largest page, and the one control-record byte
    /// that carries a variable file's page capacity (`page_size / 20`) can
    /// hold nothing bigger. Both ends of the boundary, because a check
    /// written with the wrong comparison passes one of them.
    #[test]
    fn create_refuses_a_page_larger_than_version_5_allows() {
        let path = scratch("page-too-big.dat");
        let err = create(&path, &single_key_spec(12, 4608, false)).expect_err("refuses");
        assert!(err.why.contains("more than the 4096"), "{}", err.why);
        assert!(!path.exists(), "nothing should have been written");

        let ok = scratch("page-at-the-limit.dat");
        create(&ok, &single_key_spec(12, MAX_PAGE, false)).expect("4096 is legal");
        let bytes = std::fs::read(&ok).expect("reads back");
        assert_eq!(u16::from_le_bytes([bytes[8], bytes[9]]), MAX_PAGE, "page size");
    }

    /// The variable-page capacity byte at the largest page this writes: 204,
    /// which is `4096 / 20` and fits a `u8` -- what the [`MAX_PAGE`] refusal
    /// above is what makes true.
    #[test]
    fn the_variable_page_capacity_byte_fits_at_the_largest_page() {
        let path = scratch("variable-capacity-at-max.dat");
        let mut spec = single_key_spec(12, MAX_PAGE, false);
        spec.variable = true;
        create(&path, &spec).expect("creates");
        let bytes = std::fs::read(&path).expect("reads back");
        assert_eq!(bytes[fcr::VARIABLE_PAGE_CAPACITY], 204, "4096 / 20, not truncated");
    }

    #[test]
    fn create_refuses_a_segment_past_the_record() {
        let path = scratch("past-record.dat");
        let spec = FileSpec {
            record_length: 4,
            page_size: 512,
            keys: vec![KeySpec {
                segments: vec![SegmentSpec { offset: 2, length: 4, kind: 0x0e, descending: false }],
                duplicates: false,
                modifiable: false,
                acs: false,
            }],
            acs: None,
            variable: false,
        };
        let err = create(&path, &spec).expect_err("refuses");
        assert!(err.why.contains("past its"), "{}", err.why);
    }

    #[test]
    fn create_refuses_an_unreadable_key_type() {
        let path = scratch("bad-type.dat");
        let spec = FileSpec {
            record_length: 8,
            page_size: 512,
            keys: vec![KeySpec {
                // `decimal` (0x05), packed BCD. Both `float` (0x02) and
                // `bfloat` (0x09) used to serve as this test's example of a
                // type with no ordering, and each stopped being one as the
                // engine's own order for it was measured.
                segments: vec![SegmentSpec { offset: 0, length: 8, kind: 0x05, descending: false }],
                duplicates: false,
                modifiable: false,
                acs: false,
            }],
            acs: None,
            variable: false,
        };
        let err = create(&path, &spec).expect_err("refuses");
        assert!(err.why.contains("no ordering"), "{}", err.why);
    }

    #[test]
    fn create_refuses_more_than_one_duplicate_key() {
        let path = scratch("two-dup-keys.dat");
        let seg = |offset| SegmentSpec { offset, length: 4, kind: 0x0e, descending: false };
        let spec = FileSpec {
            record_length: 8,
            page_size: 512,
            keys: vec![
                KeySpec { segments: vec![seg(0)], duplicates: true, modifiable: false, acs: false },
                KeySpec { segments: vec![seg(4)], duplicates: true, modifiable: false, acs: false },
            ],
            acs: None,
            variable: false,
        };
        let err = create(&path, &spec).expect_err("refuses");
        assert!(err.why.contains("duplicate-permitting"), "{}", err.why);
    }

    /// A duplicate-permitting key on a variable-length file needs the
    /// eight-byte chain and the four-byte fragment pointer in the same
    /// physical record, and nothing measured here says how the two combine --
    /// refused rather than guessed, the same shape as
    /// `create_refuses_more_than_one_duplicate_key` above.
    #[test]
    fn create_refuses_a_duplicate_key_on_a_variable_file() {
        let path = scratch("dup-key-variable.dat");
        let mut spec = single_key_spec(12, 512, true);
        spec.variable = true;
        let err = create(&path, &spec).expect_err("refuses");
        assert!(err.why.contains("duplicate-permitting"), "{}", err.why);
        assert!(err.why.contains("variable-length"), "{}", err.why);
    }

    /// Mutation testing gap, closed: nothing exercised the `SEGMAX` (24)
    /// total-segment ceiling before this test existed, so a version of
    /// [`validate`] with that check deleted passed every other test in this
    /// module. `keys::SEGMAX` is `BTVSTF.H:13`'s limit on segments across the
    /// *whole file*, not per key, so this builds one key with 25
    /// single-byte segments rather than 25 keys.
    #[test]
    fn create_refuses_more_than_segmax_segments_in_total() {
        let path = scratch("too-many-segments.dat");
        let segments: Vec<SegmentSpec> = (0..25)
            .map(|n| SegmentSpec { offset: n, length: 1, kind: 0x0e, descending: false })
            .collect();
        let spec = FileSpec {
            record_length: 25,
            page_size: 512,
            keys: vec![KeySpec { segments, duplicates: false, modifiable: false, acs: false }],
            acs: None,
            variable: false,
        };
        let err = create(&path, &spec).expect_err("refuses");
        assert!(err.why.contains("25 segments"), "{}", err.why);
        assert!(!path.exists(), "nothing should have been written");
    }

    #[test]
    fn create_refuses_a_page_length_that_is_not_a_multiple_of_512() {
        let path = scratch("bad-page.dat");
        let err = create(&path, &single_key_spec(12, 500, false)).expect_err("refuses");
        assert!(err.why.contains("512"), "{}", err.why);
    }

    #[test]
    fn create_refuses_a_record_wider_than_its_page() {
        let path = scratch("record-too-wide.dat");
        let spec = single_key_spec(600, 512, false);
        let err = create(&path, &spec).expect_err("refuses");
        assert!(err.why.contains("512-byte page"), "{}", err.why);
    }

    /// The escaped case: a physical record exactly the size of the *whole*
    /// page still leaves no room for the 6-byte page header
    /// (`pages::HEADER`), so it has to be refused too -- not just a record
    /// past `page_size`. This is the shape that produced a real
    /// `WGSGEN2.DAT` this same crate's own opener then rejected as not a
    /// whole number of pages. The message has to name all three numbers --
    /// physical, page size, and usable -- because the whole failure mode
    /// here was a six-byte discrepancy the old message never showed.
    #[test]
    fn create_refuses_a_record_exactly_the_page_size() {
        let path = scratch("record-equals-page.dat");
        let spec = single_key_spec(512, 512, false);
        let err = create(&path, &spec).expect_err("refuses");
        assert!(err.why.contains("512"), "{}", err.why);
        assert!(err.why.contains("506"), "must name the usable byte count: {}", err.why);
    }

    /// The boundary in the other direction: a physical record of exactly
    /// `page_size - HEADER` (506 for a 512-byte page) is the *largest* one
    /// that fits, and must still be accepted -- one byte more (507) is the
    /// smallest this module refuses. Confirms the fix does not over-reject.
    #[test]
    fn create_accepts_a_record_that_exactly_fills_the_usable_bytes() {
        let path = scratch("record-fills-usable.dat");
        let spec = single_key_spec(512 - pages::HEADER, 512, false);
        create(&path, &spec).expect("506 usable bytes hold a 506-byte record");
    }

    /// A duplicate-permitting key widens the physical record by 8 bytes for
    /// the `[prev][next]` chain before that comparison happens -- so the
    /// check has to be made against the *widened* physical record, not the
    /// caller's `record_length`. `record_length` 500 alone would fit
    /// (500 <= 506), but the chain pushes physical to 508, past the
    /// 506-byte usable ceiling: the old buggy comparison (`> page_size`,
    /// 508 <= 512) would have let this through.
    #[test]
    fn create_refuses_a_duplicate_key_whose_widened_record_overflows_usable() {
        let path = scratch("dup-key-overflows-usable.dat");
        let spec = single_key_spec(500, 512, true);
        let err = create(&path, &spec).expect_err("508-byte physical record, 506 usable");
        assert!(err.why.contains("508"), "{}", err.why);
        assert!(err.why.contains("506"), "must name the usable byte count: {}", err.why);
    }

    #[test]
    fn creating_twice_writes_the_same_bytes() {
        let a = scratch("repeat-a.dat");
        let b = scratch("repeat-b.dat");
        let spec = FileSpec {
            record_length: 1998,
            page_size: 2048,
            keys: vec![
                KeySpec {
                    segments: vec![SegmentSpec { offset: 0, length: 30, kind: 0x0b, descending: false }],
                    duplicates: false,
                    modifiable: false,
                    acs: false,
                },
                KeySpec {
                    segments: vec![SegmentSpec { offset: 30, length: 11, kind: 0x0b, descending: false }],
                    duplicates: false,
                    modifiable: true,
                    acs: false,
                },
                KeySpec {
                    segments: vec![SegmentSpec { offset: 60, length: 4, kind: 0x0e, descending: true }],
                    duplicates: true,
                    modifiable: true,
                    acs: false,
                },
            ],
            acs: None,
            variable: false,
        };
        create(&a, &spec).expect("creates");
        create(&b, &spec).expect("creates");
        assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
    }

    /// The kit's account file, if the operator has it. Third-party data:
    /// never committed, so this skips rather than fails without it.
    fn kit(name: &str) -> Option<Vec<u8>> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tmp/bbsv6")
            .join(name);
        match std::fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(_) => {
                eprintln!("skipped: no {name} under tmp/bbsv6");
                None
            }
        }
    }

    /// The shape of the kit's `BBSUSR.DAT`, read straight off its own control
    /// record: a 338-byte record (`fcr::RECLEN`), 1024-byte pages, one unique
    /// zstring key over the first 30 bytes, collating through `ALLCAPS`.
    fn usracc_spec() -> FileSpec {
        FileSpec {
            record_length: 338,
            page_size: 1024,
            keys: vec![KeySpec {
                segments: vec![SegmentSpec { offset: 0, length: 30, kind: 0x0b, descending: false }],
                duplicates: false,
                modifiable: false,
                acs: true,
            }],
            acs: Some(crate::acs::allcaps()),
            variable: false,
        }
    }

    #[test]
    fn an_acs_file_matches_the_kits_account_file_where_records_do_not_matter() {
        let Some(oracle) = kit("BBSUSR.DAT") else { return };
        let path = scratch("acs-usracc");
        create(&path, &usracc_spec()).expect("created");
        let ours = std::fs::read(&path).expect("read back");

        // Page 0: every field that is not a record or page count. The kit's
        // own copy holds four records on two data pages, so its page counts
        // (`fcr::ALLOCATED`, `fcr::PAGES`), its high-water marks and its key
        // 0 record count (`at::RECORDS`, the 0x114..0x118 hole below) all
        // moved off what a virgin file writes and say nothing about create.
        for (lo, hi, what) in [
            (0x06usize, 0x0a, "version and page size"),
            (0x14, 0x18, "key count and record length"),
            (0x38, 0x44, "variable tag, name of the ACS"),
            (0x106, 0x110, "user flags, variable capacity, ACS page pointer"),
            (0x110, 0x114, "key 0's root"),
            (0x118, 0x110 + 0x1e, "the rest of key 0's definition"),
        ] {
            assert_eq!(&ours[lo..hi], &oracle[lo..hi], "{what} at {lo:#x}..{hi:#x}");
        }
        // Key 0's root page moves down one because the ACS block took page 1.
        assert_eq!(pages::long(&ours[0x110..0x114]), 2, "root of key 0 is physical page 2");

        // Page 1: the whole ACS block, byte for byte.
        assert_eq!(&ours[1024..1024 + 6 + 265], &oracle[1024..1024 + 6 + 265], "ACS page");
        // And the rest of page 1 is zero in both.
        assert!(ours[1024 + 271..2048].iter().all(|&b| b == 0));
        assert!(oracle[1024 + 271..2048].iter().all(|&b| b == 0));
    }

    #[test]
    fn an_acs_file_opens_and_folds_case_on_the_key() {
        let path = scratch("acs-opens");
        create(&path, &usracc_spec()).expect("created");
        let geometry = crate::Geometry::read("USR", &path).expect("readable");
        let mut engine: crate::Btrieve<crate::testing::Flat> = crate::Btrieve::default();
        let mut mem = crate::testing::FlatMem::new(1 << 20);
        let mut heap = crate::testing::FlatHeap::new(0x1000);
        let block = engine
            .open(&mut mem, &mut heap, "USR", &path, geometry, 338)
            .expect("opens");
        let file = engine.block_mut(block).expect("block");

        // One record per letter the table folds, rather than `Sysop` alone.
        // `Sysop` exercises five of the twenty-six mappings and leaves the
        // other twenty-one free to be wrong: a table with `a` mapped to
        // itself still finds it. Every letter here is load-bearing --
        // `Aysop`'s key differs from `Bysop`'s in exactly the byte the fold
        // has to get right.
        for initial in b'A'..=b'Z' {
            let mut record = vec![0u8; 338];
            record[..5].copy_from_slice(b"Sysop");
            record[0] = initial;
            file.insert(&record).expect("inserted");
        }
        for initial in b'a'..=b'z' {
            let mut key = vec![0u8; 30];
            key[..5].copy_from_slice(b"sysop");
            key[0] = initial;
            assert!(
                file.query(0, crate::Op::Equal, &key).expect("query"),
                "lowercase {} finds {}ysop through ALLCAPS",
                char::from(initial),
                char::from(initial - 0x20)
            );
        }
    }

    #[test]
    fn a_key_collating_through_a_sequence_the_file_does_not_carry_is_refused() {
        let mut spec = usracc_spec();
        spec.acs = None;
        let err = create(&scratch("acs-missing"), &spec).expect_err("refused");
        assert!(
            err.why.contains("collates through an ACS but the file declares none"),
            "{}",
            err.why
        );
    }

    #[test]
    fn a_non_text_segment_may_not_collate_through_a_sequence() {
        let mut spec = usracc_spec();
        spec.keys[0].segments[0].kind = 0x0e; // unsigned binary
        let err = create(&scratch("acs-binary"), &spec).expect_err("refused");
        assert!(err.why.contains("folds text"), "{}", err.why);
    }

    /// The shape of the kit's `BBSK.DAT`, read straight off its own control
    /// record: a 31-byte record (`fcr::RECLEN`), 1024-byte pages, one unique
    /// zstring key over the first 30 bytes, collating through `ALLCAPS`, and
    /// variable-length records.
    fn keyrec_spec() -> FileSpec {
        FileSpec {
            record_length: 31,
            page_size: 1024,
            keys: vec![KeySpec {
                segments: vec![SegmentSpec { offset: 0, length: 30, kind: 0x0b, descending: false }],
                duplicates: false,
                modifiable: false,
                acs: true,
            }],
            acs: Some(crate::acs::allcaps()),
            variable: true,
        }
    }

    #[test]
    fn a_variable_file_matches_the_kits_key_file_where_records_do_not_matter() {
        let Some(oracle) = kit("BBSK.DAT") else { return };
        let path = scratch("variable-keyrec");
        create(&path, &keyrec_spec()).expect("created");
        let ours = std::fs::read(&path).expect("read back");
        for (lo, hi, what) in [
            (0x06usize, 0x0a, "version and page size"),
            (0x14, 0x1a, "key count, record length, physical length"),
            (0x38, 0x39, "variable tag"),
            (0x3c, 0x44, "ACS name"),
            (0x106, 0x110, "user flags, variable capacity, ACS pointer"),
            (0x110 + 0x08, 0x110 + 0x1e, "key 0 definition past its root"),
        ] {
            assert_eq!(&ours[lo..hi], &oracle[lo..hi], "{what} at {lo:#x}..{hi:#x}");
        }
        // Virgin-file sentinels the populated oracle no longer carries.
        assert_eq!(ours[0x39], 0xff, "variable subflag on a virgin file");
        assert_eq!(&ours[0x3a..0x3c], &[0xff, 0xff], "variable highest on a virgin file");
        let geometry = crate::Geometry::read("K", &path).expect("readable");
        assert!(geometry.variable);
        assert_eq!(geometry.physical, 35);
    }
}
