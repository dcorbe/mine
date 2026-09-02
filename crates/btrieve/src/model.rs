//! What a Btrieve file *is*, in this crate's terms.
//!
//! Grown by later plans. Today it holds what [`crate::read::file`] can
//! establish with certainty: the generation and page size (via
//! [`Identified`]), the v5 control record's fixed portion (via
//! [`ControlRecord`]), its key/segment definitions ([`KeyDescriptor`]),
//! every page's header and what the page graph says it is ([`PageKind`]), a
//! `Data`/`Free` page's slots and slack ([`DataPage`]), an `Index` page's
//! entry array ([`IndexPage`]/[`IndexEntry`]), a v5 file's alternate
//! collating sequence block ([`AcsBlock`]), a variable-length file's
//! fragment/overflow page ([`FragmentPage`]/[`FragmentSlot`]), and the
//! file's length. An `IndexChild` page's own owning key -- which of the
//! file's keys' B-trees it belongs to -- is resolved by walking every key's
//! tree from its root (`read::resolve_pages`'s `walk_index_trees`, Task
//! 11b), so its entry array is described the same way an `Index` root's is;
//! a page no walk reaches, and that is not otherwise claimed, is a genuinely
//! abandoned page ([`PageKind::Orphan`], Task 13 -- v5 has no page-level
//! free list, harvest 3 SS4, so an unreachable page is the format's own
//! expected outcome, not a parsing gap). A v6 file has the same outcome for
//! a different mechanism: every v6 write relocates (harvest 3 SS3,
//! "Relocation on write"), abandoning the physical page the allocation
//! table used to point at, and whether that physical page is ever reclaimed
//! is not established (harvest 3 SS4's own "single largest open question"),
//! so [`read::file`] makes no claim about reclaim and stores such a page's
//! body verbatim instead of guessing ([`V6Page::orphan`], Task 21).
//!
//! # The rule this type exists to enforce
//!
//! No opaque byte ranges. This model will never gain a field holding bytes
//! nobody has described -- an undescribed range is a fault to be fixed, not
//! data to be carried.
//!
//! This is not violated by a region this crate positively knows is unused
//! and carries verbatim rather than decodes further -- `DataPage::slack`,
//! `IndexPage::padding`, `AcsBlock::padding`, `File::page_zero_tail`, and
//! (Task 13) `Page::orphan` are each a *described* fact ("this is unused
//! space / an abandoned page, evidenced thus") stored whole because there is
//! no further structure to decode, not an undescribed range nobody has
//! looked at.

use crate::format::generation::Identified;
use crate::format::variable::Pointer;

/// The v5 control record's fixed portion (`0x00..0x110`), one field per row
/// of harvest 1's field table -- see `format::fcr::v5_fixed`.
///
/// `lead`, `version` and `page_size` are not duplicated here: they are
/// exactly what [`Identified`] already establishes, and storing the same
/// three bytes under two names is precisely the shape of error harvest 0
/// ruling 5 found in `HIGHEST`/`ALLOCATED` -- two names for one value,
/// looking independently plausible until one of them is wrong.
///
/// Every field is the value read off disk, never recomputed. `page_usable`
/// is the harvest's worked example of why that matters: it looks exactly
/// like `page_size - 6` on a near-virgin file and is wrong for every
/// populated one, so this crate stores what a file actually says rather than
/// a formula that happens to fit the easy cases.
///
/// A v6 file's shadowed control record is [`V6ControlRecord`], not this
/// struct -- Task 15 (harvest 2's field table) found the two families
/// genuinely diverge past `0x20`, not just in what a field *means* but in
/// how many bytes it occupies (`HIGHEST` is one 4-byte long for v5, a plain
/// 2-byte field for v6; `RESERVED_44` is 36 bytes for v5, 6 for v6, with
/// v6's own `VERSION` and five real usage-counter fields living in the rest
/// of that range) -- so one struct at one set of offsets cannot honestly
/// describe both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlRecord {
    /// `0x04`: for a v5 file, the ordinary per-page modification counter,
    /// applied to page 0 like any other page. For a v6 file, this is the
    /// shadow pair's own generation counter -- the value `read::file`
    /// compares between physical pages 0 and 1 to decide which copy is
    /// live (harvest 2 "FCR shadowing", ruling 7). Highly variable across
    /// the corpus either way.
    pub page_gen: u16,
    /// `0x0a`: companion/pre-image file selector byte. Always 0 across the
    /// corpus; what a nonzero value selects is unexercised.
    pub companion_selector: u8,
    /// `0x0b`: transaction/lock flag, bit `0x40`. Always 0 across the
    /// corpus.
    pub lock_flag: u8,
    /// `0x0c`: `NOWHERE` on 110 of 112 corpus files; true meaning unknown.
    pub unknown_0c: u32,
    /// `0x10`: v5 free-list head, a record position or `NOWHERE`.
    pub free: u32,
    /// `0x14`: count of keys, not of on-disk key/segment definitions.
    pub keys: u16,
    /// `0x16`: logical record length.
    pub reclen: u16,
    /// `0x18`: physical record length.
    pub physical: u16,
    /// `0x1a..0x1e`: record count, one 4-byte high-word-first long -- the
    /// old crate split this into `RECORDS_HIGH`/`RECORDS_LOW`.
    pub records: u32,
    /// `0x1e..0x22`: one 4-byte high-word-first long -- the old crate split
    /// this into `HIGHEST`'s always-(in this corpus)-zero high half and
    /// `ALLOCATED`'s low half. See harvest 0 ruling 5.
    pub highest: u32,
    /// `0x22`: reads exactly 1 on all 112 corpus files, up to 19,606 pages;
    /// not a data-page count despite the name the old crate gave it.
    pub data_page_count: u32,
    /// `0x26`: total pages in the file.
    pub pages: u32,
    /// `0x2a`: live remaining space on the currently active insertion page.
    /// Dynamic, not `page_size - 6` -- see harvest 1.
    pub page_usable: u16,
    /// `0x2c`: lock/transaction field, unconditionally zeroed by the
    /// engine. Always 0 across the corpus.
    pub lock_transaction: u16,
    /// `0x2e`: read only when the version word at offset 6 uses the
    /// negative encoding, which no corpus file does.
    pub negative_version_a: u32,
    /// `0x32`: same gate as `negative_version_a`.
    pub negative_version_b: u32,
    /// `0x36`: same gate.
    pub negative_version_c: u8,
    /// `0x37`: same gate.
    pub negative_version_d: u8,
    /// `0x38`: `0xff` for a variable-length-record file, `0x00` otherwise.
    pub variable_tag: u8,
    /// `0x39`: `0xff` on a virgin variable file, `0x00` on every
    /// non-variable file and every populated variable file measured.
    pub variable_subflag: u8,
    /// `0x3a`: variable highest/free-chain value; `0xffff` when virgin.
    pub variable_highest: u16,
    /// `0x3c`: space/NUL-padded alternate collating sequence name.
    pub acs_name: [u8; 8],
    /// `0x44`: always zero across the corpus; no decompile hit found for
    /// this range.
    pub reserved_44: [u8; 36],
    /// `0x68`: zero on 107 of 112 corpus files; nonzero only on the 5
    /// `majormud-nt` files.
    pub write_counter_68: u16,
    /// `0x6a`: always zero across the corpus.
    pub reserved_6a: [u8; 156],
    /// `0x106`: user flags; bit 0 is variable-length records.
    pub usrflgs: u16,
    /// `0x108`: `page_size / 20` for a variable file, 0 otherwise.
    pub variable_page_capacity: u8,
    /// `0x109`: always zero; plausibly the unused high byte of a value that
    /// never exceeds 255.
    pub reserved_109: u8,
    /// `0x10a`: ACS logical page pointer, word-swapped; unreliable on v5 (2
    /// of 13 ACS-bearing files read zero here regardless).
    pub acs_page_pointer: u32,
    /// `0x10e`: always zero; no lead.
    pub reserved_10e: [u8; 2],
}

/// A v6 control record's fixed portion (`0x00..0x110`), one field per row of
/// harvest 2's field table (Task 15) -- see `format::fcr::v6_fixed`. One
/// copy of [`Control::Shadowed`]'s `live`/`stale` pair.
///
/// `lead`, `version` and `page_size` are excluded for the same reason
/// [`ControlRecord`] excludes them: [`Identified`] already establishes all
/// three, and duplicating them under a second name is the exact shape of
/// error harvest 0 ruling 5 found.
///
/// Every field is the value read off disk, never recomputed -- `pages` is
/// this struct's own worked example of why that matters: it is the file's
/// **logical** page count (harvest 2 "PAGES, worked"; `wccmp002.vir` reads
/// 13,572 here against 13,607 physical pages), and a reader that quietly
/// substituted a computed physical count instead would produce a plausible
/// wrong number for every v6 file, not an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V6ControlRecord {
    /// `0x04`: the shadow pair's own generation counter -- `read::file`
    /// compares this between physical pages 0 and 1 to decide which copy is
    /// live (harvest 2 "FCR shadowing", ruling 7). The same byte offset v5
    /// calls `page_gen`, a different role.
    pub generation: u16,
    /// `0x06`: constant `0x0000` on all 226 live copies measured; no known
    /// role.
    pub reserved_06: [u8; 2],
    /// `0x0a`: constant `0x0000` on all 226 live copies; an earlier,
    /// page-0-only survey saw this vary before the live/stale correction
    /// (harvest 2 "Zero" section).
    pub reserved_0a: [u8; 2],
    /// `0x0c`: constant `0xffffffff` on all 226 live copies.
    pub reserved_0c: u32,
    /// `0x10`: v5's free-list-head slot; v6 always reads `0xffffffff` here
    /// ("no free slots", forever).
    pub free: u32,
    /// `0x14`: count of distinct keys, not of on-disk key/segment
    /// definitions -- a segmented key still counts once (`MULTIACS.DAT`:
    /// `KEYS`=3, 4 definitions).
    pub keys: u16,
    /// `0x16`: logical record length.
    pub reclen: u16,
    /// `0x18`: physical (on-disk) record slot length.
    pub physical: u16,
    /// `0x1a..0x1e`: record count, one 4-byte high-word-first long; 0 on
    /// virgin files, 26,720 on `wccmp002.vir`'s live copy.
    pub records: u32,
    /// `0x1e`: v5 semantics (highest page number in use); v6 behaviour on a
    /// populated file is unmeasured -- every sampled live copy, including
    /// `wccmp002.vir`, reads 0 (harvest 2 GAP 8). A plain 2-byte field here,
    /// unlike v5's 4-byte long at the same offset -- the other half of that
    /// range is `reserved_20`, a separate field for v6.
    pub highest: u16,
    /// `0x20`: constant `0x0000` on all 226 live copies. v5's `ALLOCATED`
    /// (`keys+1`) is not reused here -- v6's index-page-count-shaped field
    /// lives at `0x4e` (`index_alloc_4e`) instead.
    pub reserved_20: u16,
    /// `0x22`: constant `0xffff` on all 226 live copies (harvest 2 GAP 1).
    pub sentinel_22: u16,
    /// `0x24`: constant on all 226 live copies; the raw bytes are `01 00`,
    /// so read little-endian (this crate's own convention) the value is
    /// `0x0001` -- see `format::fcr::v6_fixed`'s `sentinel_24` citation for
    /// why this is not the harvest prose's own `0x0100`/256 gloss.
    pub sentinel_24: u16,
    /// `0x26..0x2a`: **logical** page count (the control record itself
    /// counts as logical page 0), one 4-byte high-word-first long -- NOT the
    /// physical page count. See this struct's own doc comment.
    pub pages: u32,
    /// `0x2a`: constant `0x0000` on all 226 live copies; v5's `PAGE_USABLE`
    /// lived here but v6 does not appear to reuse it.
    pub reserved_2a: u16,
    /// `0x2c`: constant all-zero on all 226 live copies; the 12 bytes v5
    /// splits into `lock_transaction`/`negative_version_a`/`b`/`c`/`d`.
    pub reserved_2c: [u8; 12],
    /// `0x38`: `0x00000000` for a fixed-length-record file, `0xffffffff`
    /// for a variable-length one.
    pub variable_mark: u32,
    /// `0x3c`: name of the file's (first) alternate collating sequence,
    /// space/NUL-padded; all-zero when the file declares none.
    pub acs_name: [u8; 8],
    /// `0x44`: constant all-zero on all 226 live copies.
    pub reserved_44: [u8; 6],
    /// `0x4a`: this copy's own version word (`W32MKDE FUN_00435970`: `abs(i16
    /// at 0x4a)` is `0x600`, `0x610` or `0x620`), decoded and stored **per
    /// copy** -- corrected from Task 15/16's own stated design (`format::
    /// fcr`'s module doc used to read "read through `Identified`, not
    /// duplicated in `model::V6ControlRecord`"), which assumed live and
    /// stale always agree. Task 20's own `MULTIACS.DAT` round trip disproved
    /// that: its stale copy's own bytes at page-relative `0x4a` are `10 06`
    /// (`0x0610`, matching `Identified.generation`, since page 0 happens to
    /// be live), while its stale copy (physical page 1) reads `00 06`
    /// (`0x0600`) -- the file was upgraded from V600 to V610 (harvest 4
    /// SS6c's own ACS census explains why) and the stale copy still carries
    /// the pre-upgrade version. Writing both copies from `Identified.
    /// generation` alone reproduced the live copy correctly and corrupted
    /// the stale one; this field, decoded independently for `live` and
    /// `stale` alike, is the fix.
    pub version: u16,
    /// `0x4c`: always equals `mirror_50` (226/226); `1` on every virgin file
    /// regardless of key count, grows with real usage (up to 14 observed).
    /// Exact meaning (candidate: index-tree depth) unresolved -- harvest 2
    /// GAP 2.
    pub usage_4c: u16,
    /// `0x4e`: on a virgin file, `8*(nkeys+1)`; grows with usage (up to 188
    /// observed). Plausibly index pages allocated for the file's key
    /// structures, unconfirmed -- harvest 2 GAP 2.
    pub index_alloc_4e: u16,
    /// `0x50`: identical to `usage_4c` in all 226 samples.
    pub mirror_50: u16,
    /// `0x52`: on a virgin file, `2*nkeys+1`; grows with usage -- harvest 2
    /// GAP 2.
    pub usage_52: u16,
    /// `0x54`: constant `0x0000` on all 226 live copies.
    pub reserved_54: u16,
    /// `0x56`: high entropy, 86 distinct leading bytes across 226 files; not
    /// a DOS packed date/time (decodes to implausible years). Probably a
    /// creation stamp or per-file unique value -- harvest 2 GAP 3.
    pub stamp_56: [u8; 4],
    /// `0x5a`: constant `0xffffffffffff` on all 226 live copies.
    pub reserved_5a: [u8; 6],
    /// `0x60`: constant `ff ff 00 ff ff ff 00 00` on all 226 live copies.
    pub reserved_60: [u8; 8],
    /// `0x68`: a modification/write counter, constant on virgin files, grows
    /// with real activity (87 distinct values across 226 live copies).
    pub write_counter: u16,
    /// `0x6a`: `0x00` in the overwhelming majority; rare nonzero,
    /// uncorrelated with anything else measured -- harvest 2 GAP 4.
    pub reserved_6a: [u8; 8],
    /// `0x72`: mostly zero, small nonzero variations uncorrelated with key
    /// count, reclen, ACS or variable-length -- harvest 2 GAP 4.
    pub reserved_72: [u8; 10],
    /// `0x7c`: constant all-zero on all 226 live copies.
    pub reserved_7c: [u8; 20],
    /// `0x90`: constant `00`x8 then `ffffffff` on all 226 live copies.
    pub reserved_90: [u8; 12],
    /// `0x9c`: free-list head, a record *position* (logical page * page
    /// length + slot offset), not a `NOWHERE`-style sentinel; `0` on a
    /// virgin file's single page, real positions on populated ones.
    pub free_v6: u32,
    /// `0xa0`: head of the variable free-space chain; `0xff00ffff`
    /// (`NO_VARIABLE_HEAD`) when none.
    pub variable_head: u32,
    /// `0xa4`: constant on all 226 live copies regardless of page size, key
    /// count, ACS or variable-length -- a fixed 48-byte template; role
    /// beyond that unconfirmed (harvest 2 GAP 6).
    pub reserved_a4: [u8; 48],
    /// `0xd4`: constant all-zero on 224/226; 2 files read `0x11` at relative
    /// byte 4 instead, unexplained (harvest 2 GAP 7).
    pub reserved_d4: [u8; 44],
    /// `0x100`: constant all-zero on all 226 live copies.
    pub reserved_100: [u8; 6],
    /// `0x106`: `0x00000000` on 207/226; four other exact values on 19
    /// files, uncorrelated with ACS presence, key count or page size --
    /// harvest 2 GAP 5.
    pub reserved_106: [u8; 4],
    /// `0x10a`: ACS logical page, word-swapped long; `0` when none declared.
    /// V6-only predicate -- unreliable on v5.
    pub acs_page: u32,
    /// `0x10e`: constant all-zero on all 226 live copies.
    pub reserved_10e: [u8; 2],
}

/// One 30-byte key/segment definition -- one segment of one key. A key with
/// more than one segment consumes more than one of these, chained by the
/// `ANOSEG` bit on every definition but the last of the key. See harvest 4
/// SS1a-SS3 and `format::fcr::key_descriptor`.
///
/// `KEYS` (`ControlRecord::keys`) counts keys, not definitions: the reader
/// walks this array until that many ANOSEG-terminated runs have been seen,
/// which is why `File::key_descriptors` is a `Vec` sized by the walk rather
/// than by `keys` directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDescriptor {
    /// Top byte of the on-disk `ROOT` long: `0x80|keynum` per harvest 4 SS2,
    /// `0` on a continuation definition. Unexercised on real v5 data -- all
    /// 307 definitions across the 145 v5 corpus files this task measured
    /// read 0 here. Modeled anyway because harvest 4 states the rule
    /// generally and masking is a no-op when the byte is already 0; `emit`
    /// reassembles `ROOT` from this and `root_page` rather than storing the
    /// raw word.
    pub key_number: u8,
    /// Low 24 bits of the on-disk `ROOT` long: the root index page for this
    /// key (segment-0 definition only; 0 on a continuation).
    pub root_page: u32,
    /// How many records this key indexes (segment-0 only; meaningless on a
    /// continuation definition).
    pub records: u32,
    /// Flag word -- duplicates/modifiable/binary/ANOSEG/alt-collating/
    /// descending/extended-type/null-handling bits. See harvest 4 SS1b.
    pub attributes: u16,
    /// This key's total width, every segment summed (0 on a continuation).
    pub key_length: u16,
    /// Bytes of one index-page entry for this key.
    pub entry_size: u16,
    /// Index entries of this key that fit one page.
    pub max_entries: u16,
    /// `max_entries / 2`, integer division.
    pub half_entries: u16,
    /// Byte offset, within the record's physical slot, of the duplicate
    /// `[prev][next]` chain pair; 0 when duplicates are not permitted.
    pub chain: u16,
    /// This segment's byte offset within the logical record.
    pub offset: u16,
    /// This segment's length in bytes.
    pub length: u16,
    /// Relative `0x18`: unclaimed by any v5 corpus file measured -- always 0
    /// across all 307 definitions this task scanned. Harvest 2 names the
    /// same byte `SELF_TAG` (`0x80|keynum`) on v6 data; see
    /// `format::fcr::key_descriptor::fields`'s citation for the
    /// reconciliation.
    pub self_tag: u8,
    /// ACS page, high byte. v6 only; 0 on v5.
    pub acs_page_high: u8,
    /// ACS page, low byte. v6 only; 0 on v5.
    pub acs_page_low: u8,
    /// ACS page, mid byte. v6 only; 0 on v5.
    pub acs_page_mid: u8,
    /// The segment's data-type code, when `attributes` bit 8 (`EXTENDED`) is
    /// set.
    pub extended: u8,
    /// The byte value this key's null-omission rule tests against, when a
    /// null-handling attribute bit is set.
    pub null_value: u8,
}

/// Everything in a v6 physical page (page 0 or its shadow twin, page 1)
/// past the key/segment definition array (Task 16).
///
/// The definition-offset trailer's own `u16` values are deliberately *not*
/// stored here: harvest 2 "Definition-offset trailer, worked" plus this
/// task's own census of all 493 corpus v6 files whose page size exceeds 512
/// (0 exceptions, measured against the rule actually shipped -- see
/// `format::fcr::trailer::expected_entries`) established that the whole
/// array is a pure function of the key/segment definitions already sitting
/// in `File::key_descriptors`: each independent segment's own offset,
/// packed into the next free slot in definition order (NOT into the slot
/// at its own definition index -- a continuation contributes no slot at
/// all, so a later independent segment compacts one slot earlier than its
/// index), zero-padded thereafter -- storing it a second time would be
/// redundant data this crate would have to keep in sync with itself for no
/// reason.
/// `read::v6_page_tail` derives the expected array and refuses if the file's
/// own bytes disagree; `emit::write_v6_page_tail` regenerates it from the
/// same descriptors. See `format::fcr::trailer`'s own module doc for the
/// position rule and the correction this task made to the harvest's
/// worked-example transcription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V6PageTail {
    /// Bytes between the last key/segment definition and the trailer's own
    /// fixed position (`format::fcr::trailer::position`) -- zero in all 493
    /// corpus files whose page size carries a measured trailer position,
    /// but carried verbatim rather than asserted, the same caution
    /// `page_zero_tail` earned from its own two exceptions. Empty when
    /// `page_size` has no trailer at all (512).
    pub gap: Vec<u8>,
    /// Bytes after the trailer's own `key_descriptors.len()` `u16` slots,
    /// out to `page_size` -- zero in all 493 samples measured (harvest 2
    /// GAP 9: whether the trailer reserves more capacity than the file's
    /// own definitions need is unresolved; this region cannot tell the
    /// difference either way, since unused capacity and ordinary
    /// end-of-page padding are both zero). Empty when `page_size` has no
    /// trailer at all (512) -- see `gap` for that case, which then holds
    /// the whole remaining region instead.
    pub padding: Vec<u8>,
}

/// One 4-byte slot of a v6 allocation-table ("PP") block's entry array
/// (harvest 3 SS3): a claim marker plus the physical page it names.
///
/// The engine's own allocated/never-allocated test is the marker's high
/// byte, not the whole 4 bytes -- `0x4400`/`0x8000` (a claimed data/index or
/// template page) versus `0x0000` (never allocated); see
/// `read::v6_allocation_table`'s own resolution logic for where this is
/// consulted rather than merely stored. Plain little-endian, unlike the
/// high-word-first `long` convention `ControlRecord`'s own fields use --
/// `format::alloc`'s module doc names this divergence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V6AllocationEntry {
    /// High byte: the claimed page's own type tag (`0` when never
    /// allocated). Low byte unexplained -- carried verbatim rather than
    /// masked away, since nothing establishes it is always zero.
    pub marker: u16,
    /// The physical page this slot claims when `marker`'s high byte is
    /// nonzero; `read::v6_allocation_table` refuses rather than trusting
    /// this at face value when it names physical page 0, 1 (the file
    /// control record's own shadow pair) or a page past the file's own
    /// length. Meaningless (but still stored, to round-trip) when the slot
    /// was never allocated.
    pub physical_page: u16,
}

/// One physical page's worth of allocation-table content: the `"PP"` magic
/// is implicit (checked before this is built, not stored -- the same
/// exclusion `Identified` earns for the file control record's own `"FC"`
/// lead), `block`/`generation` are this copy's own header fields, and
/// `entries` is its full slot array.
///
/// One of [`V6AllocationBlock`]'s two shadow copies -- see that type's own
/// doc comment for why both must be kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V6AllocationBlockCopy {
    /// `0x02`: 1-based block index, shared by both shadow copies of one
    /// block (harvest 3 SS3's field table) -- `read::v6_allocation_table`
    /// checks this agrees with the position the formula predicts for it,
    /// the same check `resolve_shadow`'s sibling makes for the file control
    /// record's own shadow pair.
    pub block: u16,
    /// `0x04`: file-global generation counter, meaningful only *within*
    /// this block's own pair -- the higher of the two copies is live
    /// (harvest 3 SS5, the identical rule `resolve_shadow` already
    /// enforces for the file control record).
    pub generation: u16,
    /// `0x06`: unexplained 2-byte gap, measured `0x0000` on physical page 2
    /// of all 500 v6 corpus files (harvest 3 SS3) -- carried verbatim
    /// rather than asserted zero, `page_zero_tail`'s own discipline.
    pub reserved_06: [u8; 2],
    /// `0x08..`: `(page_size - 8) / 4` entries, indexed by slot -- slot `n`
    /// of block `b` answers for logical id `(b - 1) * entries_per_block +
    /// n + 1` (harvest 3 SS3's resolution direction, `n = logical - 1`
    /// inverted).
    pub entries: Vec<V6AllocationEntry>,
}

/// One v6 allocation-table block, kept as both shadow copies -- the same
/// shape [`Control::Shadowed`] keeps for the file control record's own pair,
/// and for the identical reason: the vendor's copy-on-write-plus-bump update
/// strategy means a block caught mid-flip has a genuinely stale copy whose
/// exact bytes this crate must still reproduce, not merely a redundant
/// backup it can discard.
///
/// Where this pair physically lives is a formula of the block's own 1-based
/// index and the file's `page_size` (`format::alloc::pair_position`), not
/// stored here -- the same reasoning that keeps `Control::Shadowed` from
/// storing "physical page 0" and "physical page 1" a second time under new
/// names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V6AllocationBlock {
    /// The copy whose generation counter is higher -- current geometry.
    pub live: V6AllocationBlockCopy,
    /// The copy whose generation counter is lower -- superseded, but its
    /// exact bytes must still round-trip.
    pub stale: V6AllocationBlockCopy,
    /// `true` when `live` occupies the pair's first formula position
    /// (`format::alloc::pair_position`'s first element), `false` when it
    /// occupies the second -- the same role `Control::Shadowed`'s
    /// `live_is_page` plays for the file control record's own pair.
    pub live_is_first: bool,
}

/// What the control record's own pointers say a page is. Never itself an
/// on-disk byte range -- v5 carries no page-type tag (`format::page`'s
/// module doc) -- so this is metadata `read::resolve_pages` derives once and
/// `emit` never writes; it exists so a later task can decode a page's
/// content without re-deriving the graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageKind {
    /// Named by some key descriptor's `root_page` (harvest 3 SS3, harvest 4
    /// SS1a `ROOT`). Its own header's `data_bit` must be clear (a B-tree
    /// node, not records) -- measured 281/281 agree across the v5 corpus,
    /// enforced by `read::resolve_pages` as a real check, not a formality.
    Index,
    /// The file's alternate collating sequence block. Always physical page
    /// 1 once any key descriptor sets `ALT_COLLATING`, regardless of what
    /// FCR `0x10a` says (harvest 4 SS6a: measured on all 13 v5 corpus files
    /// that declare a sequence, no exceptions; `0x10a` itself reads zero on
    /// 2 of those 13 despite the block being genuinely present). Its own
    /// header's `data_bit` must be clear too -- measured 15/15 agree.
    Acs,
    /// Reachable by walking the record-slot free chain from FCR `0x10`.
    /// v5 has no *page-level* free list (harvest 3 SS4 -- "nothing reclaims
    /// a whole v5 page once allocated"); this bucket means "at least one
    /// freed record slot lives on this page." Its own header's `data_bit`
    /// must be set (it is a record-holding page, just with a freed slot on
    /// it) -- measured 22/22 agree across the v5 corpus.
    Free,
    /// A B-tree node no key's root names -- claimed by no pointer, and its
    /// own header's `data_bit` is clear. Never a residual: `data_bit` clear
    /// alone only says "this is a B-tree node, not a data page" (9,058 pages
    /// across 39 of the 145 v5 corpus files are exactly this, a
    /// controller-run measurement that corrected this crate's original
    /// brief). *Which* key's tree it belongs to is established by actually
    /// walking that key's own child pointers down from its root
    /// (`read::resolve_pages`'s `walk_index_trees`, Task 11b) -- a page no
    /// walk reaches is classified [`PageKind::Orphan`] instead (Task 13),
    /// never guessed at as `IndexChild` anyway.
    IndexChild,
    /// Claimed by no pointer, and its own header's `data_bit` is set: a
    /// page that genuinely holds records.
    Data,
    /// A variable-length file's fragment/overflow page (harvest 5 SS3.3):
    /// claimed by no pointer, `data_bit` clear (like `IndexChild`), but
    /// distinguished from a real B-tree node by its own *content* matching
    /// the engine's own invariants for this shape -- `read::resolve_pages`
    /// only ever attempts this when the file's own `usrflgs` bit 0 is set
    /// (harvest 5 SS3.1), and only classifies a page this way when both
    /// checks the engine itself performs pass: its fragment count (`0x0a`)
    /// is `1..=256`, and the first live (non-`0xffff`) entry of its array
    /// names offset exactly `0x0c`
    /// (`format::variable`, `W32MKDE_decompiled.c:19029-19060`). Measured
    /// against all four real corpus files this task was dispatched
    /// against: every page that passes is reachable by some record's
    /// fragment chain (`wcctext.nu1`: exactly 2,541 pages pass, matching
    /// its own 2,541-record count exactly), and every unclaimed
    /// data-bit-clear page that fails is a genuine `IndexChild` whose bytes
    /// merely overlap this shape's field positions by coincidence
    /// (`FW_QSQDB.DAT` page 8: a plausible fragment count, but its first
    /// live entry names offset 0 -- inside the page's own header -- and it
    /// holds real index key text, not fragment bytes). A page that fails
    /// both this shape's checks and is not otherwise claimed still falls
    /// through to `IndexChild` if some key's walk reaches it, or
    /// [`PageKind::Orphan`] (Task 13) if none does.
    Variable,
    /// Claimed by no pointer, unreached by any key's own B-tree walk, its
    /// own header's `data_bit` clear, and (on a variable-length file) not
    /// shaped like a fragment page either -- what `read::resolve_pages`
    /// refused by name before Task 13, and now accepts as a genuinely
    /// abandoned page rather than a parsing failure.
    ///
    /// This is not the residual guess Task 7 shipped (defaulting an
    /// unclassified page to `IndexChild`, which mislabelled 9,058 pages):
    /// `Orphan` asserts no structure at all, only that no positive claim
    /// exists for this page. The positive evidence that such a page is
    /// litter rather than a bug this crate failed to parse:
    ///
    /// - Harvest 3 SS4: v5 has no *page-level* free list. Once a B-tree
    ///   restructuring detaches a subtree, nothing in the format ever
    ///   reclaims the page -- an orphan is the format's own expected
    ///   long-run outcome for a heavily-modified file, not an anomaly.
    /// - A from-scratch, independent walk (this task's controller, in
    ///   Python, from every key's own root) agrees exactly with this
    ///   crate's own walk on which pages go unreached -- ruling out "the
    ///   walk missed something."
    ///
    /// A follow-up review pointed out that none of this was checked at
    /// runtime -- the round trip cannot tell a genuinely abandoned page
    /// from a live one a future walk bug silently under-visits, since both
    /// would still reproduce byte-identically. `read::resolve_pages` (its
    /// `orphan_header_shape` helper) now corroborates every `Orphan`
    /// against the page's own bytes before accepting it, using the shapes
    /// the corpus itself has demonstrated:
    ///
    /// - **Zeroed**: the engine zeroed the whole 6-byte header outright
    ///   (`number == 0 && counter == 0`) -- `wccitem2.vir` page 593
    ///   (`wccnt7pz`), `wccupda2.dat`'s pages 17564/19606.
    /// - **Leaf-shaped**: the header survives and the page still reads as
    ///   a genuine B-tree leaf -- `rightmost` `NOWHERE`, `leftmost`
    ///   `NOWHERE` or literal `0` (both valid on a leaf, see
    ///   [`IndexPage::leftmost`]) -- `TTIHORSS.DAT`/`.VIR` page 251,
    ///   `wccitem2.vir` page 592 (`wccnt7py`): a *structurally
    ///   self-consistent* index leaf that simply no walk reaches.
    /// - **Extends a corroborated anchor**: enforcing the two shapes above
    ///   against the full corpus turned up a *third* real shape neither
    ///   this task nor its first reviewer had seen: `wccitem2.vir`/
    ///   `wccITEM2.nu1` page 594 (`wccnt7pz`) and `wccupda2.dat` page 17565
    ///   (`wccnt7py`) are unclaimed, `data_bit` clear, and hold *nothing
    ///   but* leftover prose starting at byte 0 -- overwriting what would
    ///   be the header too. Neither zeroed nor leaf-shaped; `data_bit`
    ///   reads clear only because printable ASCII never sets the high bit,
    ///   a coincidence of the encoding, not a structural signal.
    ///
    ///   A first fix for this shape accepted a page if *either* neighbour
    ///   looked right and checked "is the neighbour already `Orphan`"
    ///   rather than "does the neighbour self-corroborate" -- a second
    ///   review caught that this bootstraps without bound: one
    ///   self-corroborating page lets every page after it become `Orphan`
    ///   in turn, forever, each one carried verbatim and every test green.
    ///   The rule actually enforced now requires *both* neighbours,
    ///   independently: the immediately preceding page must itself be
    ///   unclaimed, `data_bit` clear, and pass `orphan_header_shape` on its
    ///   own raw bytes (never merely "is `Orphan`"), and the immediately
    ///   following page's own `data_bit` must be set -- a genuine
    ///   record-holding page, which is what actually terminates both real
    ///   instances (595, 17566). Because only a self-corroborating page can
    ///   ever serve as the anchor, a page accepted this way can never in
    ///   turn anchor a third: the chain this rule accepts is always exactly
    ///   one page long.
    ///
    /// The corpus's known orphan bodies (past whichever of these shapes
    /// justified the classification) fit under one honest description
    /// without deciding between them: attributing the leaf-shaped case's
    /// bytes to a specific key's entries without a walk's own evidence
    /// would be exactly Task 7's mistake repeated, so this crate does not.
    /// `Orphan` stores the *whole* page body, past the 6-byte header, as
    /// one opaque `Vec<u8>` regardless of which shape justified it -- see
    /// [`Page::orphan`].
    Orphan,
}

/// One record slot of a `Data`/`Free` page, `physical` bytes wide: either a
/// live record, or -- once `read::resolve_pages`'s walk of the free chain
/// from FCR `0x10` reaches this slot's own file position (harvest 5 SS2.1)
/// -- the forwarding link and zero fill a delete left in its place.
///
/// A live slot's *content* remains the calling module's own business, not
/// this crate's, exactly as before this task (harvest 5's own framing) --
/// only a free slot's shape is this crate's to describe, because nothing
/// about it belongs to any record format: `format::free_slot` names both of
/// its fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordSlot {
    /// A live record's `physical` bytes, verbatim.
    Live(Vec<u8>),
    /// A member of the free chain: decoded, not left as an opaque blob a
    /// round trip merely happens to reproduce (this task's whole point --
    /// see this crate's `RecordSlot::Free` test coverage for the model-level
    /// assertion a byte-identical round trip alone cannot make).
    Free {
        /// The first 4 bytes, decoded as a high-word-first `long`
        /// (`format::free_slot::at::LINK`): the free-list head *before* the
        /// delete that produced this slot, or `NOWHERE` (`0xffff_ffff`) if
        /// this slot was the chain's own head at the time. This crate's
        /// clean witness, `wccnt7py`/`wccnt7pz`'s byte-identical
        /// `wccitem2.vir` (harvest 5 SS6.2, page 591 slot 2): `next` reads
        /// `NOWHERE`, because this file's one deletion was also its first.
        next: u32,
        /// The remaining `physical - 4` bytes, verbatim. Oracle-measured all
        /// zero on a fresh delete against genuine Btrieve 6.15 (harvest 5
        /// SS2.1) and confirmed zero on every free slot this crate's own
        /// corpus can currently read -- but stored rather than assumed,
        /// `DataPage::slack`'s own discipline: 5 real pages disagree with
        /// "trailing bytes are always zero," so nothing here re-derives a
        /// byte the file might one day disagree with either.
        fill: Vec<u8>,
    },
}

/// A v5 data/free page's fixed-length-record content: every slot, indexed
/// by record number within the page, plus what the engine leaves between
/// the last slot and the end of the page.
///
/// The slot count is a closed-form count, not read off disk -- harvest 5
/// SS1.1: `per_page = (page_size - 6) / physical`, `physical` being the FCR's
/// own `PHYSICAL` field (`ControlRecord::physical`), flag-additive over
/// `RECLEN` when any key permits duplicates. `USRACC.DAT`'s anchor case
/// confirms the arithmetic independently: `PAGE_USABLE` (FCR `0x2a`) reads 2
/// on a 512-byte page of two 252-byte records, and `512 - 6 - (2*252) == 2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPage {
    /// One entry per slot, `physical` bytes accounted for either way --
    /// live (`RecordSlot::Live`) or on the free chain (`RecordSlot::Free`,
    /// harvest 5 SS2.1). What this crate owns is *where* a slot sits, how
    /// many there are, and whether it is live or free; a live record's own
    /// content past that is still the calling module's business, never
    /// this crate's.
    pub slots: Vec<RecordSlot>,
    /// Bytes from the end of the last slot to the end of the page,
    /// verbatim -- never assumed zero. Measured across every v5 corpus file
    /// this crate can currently read (143 files, 42,571 data/free pages
    /// whose geometry leaves a nonzero-length slack region): all zero
    /// except 5 pages across 3 files under `archive/modules/majormud-nt`
    /// (`wccnt7pz/out/wccitem2.vir` and its byte-identical sibling
    /// `wccITEM2.nu1`, plus `wccnt7py/out/wccupda2.dat`), which carry
    /// genuine leftover, non-zero bytes past the last live/free slot. Stored
    /// verbatim for exactly that reason -- see this task's report for the
    /// full measurement.
    pub slack: Vec<u8>,
}

/// v6's own per-slot content (harvest 5 SS1.2, SS2.2) -- the analogue of
/// [`RecordSlot`], but not the same type: a v6 slot decides its own
/// liveness from its own 2-byte marker, never from free-chain membership
/// the way v5's does (harvest 5 SS2.3's `walk_v6` reads the marker
/// directly, `continue`ing past a `0` rather than `break`ing so a hole does
/// not hide the live records behind it). Merging this into `RecordSlot`
/// would let one family's assumption -- "liveness comes from outside the
/// slot" vs "liveness is the slot's own first two bytes" -- silently leak
/// into the other's.
///
/// **A v6 file's free list being non-empty is not deletion evidence** the
/// way it is for v5 (harvest 5 SS2.2): every claimed v6 page arrives with
/// every slot already threaded onto it, ending at `0xffff_ffff`. All 500
/// v6-family corpus files show a non-empty free-list head; a hole walk
/// (marker `0` followed, later on the same page, by a live marker) found
/// zero genuine deletions across all of them. This crate does not attempt
/// to tell "genuinely deleted" apart from "never used" -- both are simply
/// `Free`, decoded the same way, because the on-disk shape is identical
/// either way and nothing about which case produced it survives on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V6RecordSlot {
    /// A live record: the marker itself (nonzero; harvest 5 SS1.2 -- `1` on
    /// first insert, incremented -- wrapping past `0` back to `1`, never
    /// landing on `0` -- on each update) plus the `physical - 2` bytes of
    /// record body, verbatim. What a specific nonzero marker value means
    /// beyond "live" is not established by this corpus (harvest 5 SS1.2's
    /// own gap: every slot this crate has read fresh off a file it created
    /// holds `01 00`, and the corpus supplies no file with a genuine
    /// update history to measure further), so this crate stores it, never
    /// interprets it further.
    Live {
        /// The raw marker value.
        marker: u16,
        /// The record body, `physical - 2` bytes, verbatim.
        body: Vec<u8>,
    },
    /// A free slot: the marker is always literally `0` -- not stored here,
    /// since `0` is what "free" *means*, never a fact this crate
    /// reconstructs from context -- a forwarding link (the free-list head
    /// before the delete that produced this slot, or `NOWHERE`), and
    /// `physical - 6` bytes of zero fill, oracle-measured (harvest 5 SS2.2)
    /// but stored verbatim rather than asserted, `DataPage::slack`'s own
    /// discipline carried here too.
    Free {
        /// The forwarding link, decoded the same high-word-first `long`
        /// encoding v5's free slot uses (`format::free_slot::decode_link`).
        next: u32,
        /// The remaining `physical - 6` bytes, verbatim.
        fill: Vec<u8>,
    },
}

/// A v6 data page's fixed-length-record content (harvest 5 SS1.2): the same
/// shape as v5's [`DataPage`], every slot offset by its own 2-byte marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V6DataPage {
    /// One entry per slot, in slot order.
    pub slots: Vec<V6RecordSlot>,
    /// Bytes from the end of the last slot to the end of the page,
    /// verbatim -- never assumed zero, [`DataPage::slack`]'s own caution
    /// carried to v6.
    pub slack: Vec<u8>,
}

/// One ordinary v6 physical page (harvest 3 SS2), past the fixed control
/// record and the "PP" allocation table (`format::alloc`) -- a page some
/// allocation-table entry's `physical_page` resolves to.
///
/// Exactly one of `content`/`index`/`acs`/`fragment`/`orphan`/`retired` is `Some` --
/// so a `V6Page` that exists in a `File` always describes all of its own
/// content, one way or another. The first four are a positive
/// classification; `orphan` (Task 21) is the deliberate absence of one, for
/// a physical page no allocation-table entry currently resolves to at all
/// (not merely unattributed by a key's walk, the way an unclaimed `content`/
/// `index` candidate is) -- see its own doc comment for the evidence this
/// is abandoned content rather than a parsing gap. All five `None` at once
/// never happens: `read::file` refuses the whole file over a physical page
/// it cannot place in any of these five buckets (a page some
/// allocation-table entry claims but whose tag is `TAG_TEMPLATE`, or a tag
/// this crate does not recognize at all, unclaimed by any key's walk)
/// rather than build one.
///
/// - `content`: `Some` when the page is a genuine data page -- `tag ==
///   TAG_DATA` **and** no key's own B-tree walk
///   (`read::v6_walk_index_trees`) attributed it to a tree. Populated the
///   same way whether or not the file holds variable-length records
///   (`live.variable_mark`, Task 20): harvest 5 SS1.1's slot layout does not
///   change shape when a live record's tail holds a fragment pointer
///   instead of ordinary data, the identical reasoning `Page::content`'s own
///   v5 doc comment already states -- so `read_v6_data_page` needs no
///   `variable_mark` gate of its own, and had none even before this task
///   removed the one `read::file`'s classification loop used to impose.
/// - `index`: `Some` when some key's walk attributed this physical page to
///   its tree, root or descendant alike (harvest 4 SS2/SS4/SS4a) -- the same
///   `IndexPage`/`IndexEntry` shape v5 uses, since the entry-array layout
///   past the 6-byte header is identical in both families (harvest 4 SS4's
///   own framing: nothing here distinguishes v5 from v6).
/// - `acs`: `Some` when the page's own tag is `TAG_ACS`, found by scanning
///   every claimed page for that tag (harvest 4 SS6a -- v6 has no fixed
///   block page the way v5 does) -- the same `AcsBlock` shape v5 uses
///   (harvest 4 SS6: "same layout in both families").
/// - `fragment`: `Some` when the page's own tag is `TAG_VARIABLE` (Task 20,
///   harvest 5 SS3.3/SS3.4) -- the same [`FragmentPage`]/[`FragmentSlot`]
///   shape v5's untagged fragment pages use, since the header past the
///   6-byte tag/logical/stamp triple is identical in both families
///   (harvest 3 SS4's own measured table: "same field, same encoding, same
///   three states"). Believed unwitnessed in this project's corpus at the
///   time Task 20 shipped it -- Task 21 found that belief rested on an
///   unrelated refusal (`V6Page::orphan`'s own gap) hiding the evidence;
///   see `FragmentPage`'s own doc comment and
///   `the_v6_fragment_path_is_now_corpus_witnessed` in
///   `crates/btrieve/tests/roundtrip.rs`.
///
/// Before Task 19, `read::file` refused any v6 file declaring `keys > 0`
/// rather than guess which `TAG_DATA` pages were genuine data versus index
/// descendants (see this crate's own git history) -- this struct's `content`/
/// `index`/`acs` fields are what let that gate come off: each page's kind is
/// established by the walk, not by its tag alone (`format::page::v6::
/// TAG_DATA`'s own doc comment explains why the tag alone cannot tell the
/// two apart for key 0 specifically). Before Task 20, `read::file` refused a
/// `TAG_DATA` page on any file whose `variable_mark` was set and a
/// `TAG_VARIABLE` page outright, whatever file it was on -- `fragment` and
/// the `variable_mark` gate's removal are what closed those two off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V6Page {
    /// Which physical page this is. v6 pages are not laid out positionally
    /// the way v5's `pages` vec is -- the allocation table's own blocks are
    /// interleaved among them at arbitrary physical positions (harvest 3
    /// SS3) -- so each entry names its own physical page explicitly rather
    /// than relying on its position in a `Vec`.
    pub physical_page: u32,
    /// `0x00`: page kind tag -- `TAG_DATA`, `TAG_ACS`, or a key's own
    /// `0x80|keynum` tag (root or descendant alike). Stored verbatim
    /// regardless of which.
    pub tag: u16,
    /// `0x02`: the page's own self-reported logical id -- decorative
    /// (harvest 3 SS3: resolution never consults it), stored only so it
    /// round-trips.
    pub logical: u16,
    /// `0x04`: modification stamp/generation for an ordinary page.
    pub stamp: u16,
    /// This page's fixed-length-record content -- `Some` only for a
    /// genuine data page (see this struct's own doc comment); `None`
    /// otherwise.
    pub content: Option<V6DataPage>,
    /// This page's B-tree entry array -- `Some` for a page some key's walk
    /// attributed to its tree (root or descendant); `None` otherwise.
    pub index: Option<IndexPage>,
    /// This page's alternate collating sequence block -- `Some` for a page
    /// tagged `TAG_ACS`; `None` otherwise.
    pub acs: Option<AcsBlock>,
    /// This page's fragment/overflow content (harvest 5 SS3.3/SS3.4, Task
    /// 20) -- `Some` for a page tagged `TAG_VARIABLE`; `None` otherwise. The
    /// same [`FragmentPage`] shape v5's untagged fragment pages use; see
    /// this struct's own doc comment and [`FragmentPage`]'s for why nothing
    /// in the corpus can confirm this field is ever populated correctly.
    pub fragment: Option<FragmentPage>,
    /// This physical page's whole body, past its 6-byte header, verbatim --
    /// `Some` only when no allocation-table entry currently resolves to this
    /// physical page at all (Task 21); `None` for every page that is (the
    /// FCR's own shadow pair and the allocation-table pages themselves are
    /// never wrapped in a `V6Page` to begin with).
    ///
    /// **Why this is abandoned content, not a parsing failure:** harvest 3
    /// SS3 ("Relocation on write") measured directly against genuine
    /// Btrieve 6.15 that every v6 write relocates -- the old physical page
    /// is abandoned, a fresh or reused physical page is written, and the
    /// allocation-table entry (or the FCR's own shadow slot) is repointed.
    /// A page therefore has at most two physical homes once ever rewritten,
    /// and this crate's own corpus-wide census (Task 21) independently
    /// corroborates the mechanism harvest 3 already named: every one of
    /// this corpus's 157 previously-refused v6 files fails on exactly one
    /// unclaimed physical page, and the pages themselves carry the tags a
    /// once-live page would have left behind -- `TAG_DATA` (0x4400),
    /// `TAG_ACS`/`TAG_VARIABLE`, a key's own `0x80|keynum` tag, a stale
    /// allocation-table block's own `"PP"` magic (harvest 3 SS3 already
    /// named this exact shape: "abandoned pages that still hold \"PP\", a
    /// stale block index, and a higher generation than the live pair"), an
    /// all-zero header, or leftover printable prose -- never a shape this
    /// crate has reason to think is a live structure its own walks failed
    /// to reach. Whether the v6 engine ever reclaims this space is still
    /// not established (harvest 3 SS4's "single largest open question"),
    /// so this field makes no claim about that either way -- it only
    /// preserves what is there.
    ///
    /// Every physical page the allocation table's walk (`v6_allocation_table`,
    /// exhaustive over every block and every slot) and every key's own
    /// B-tree walk (`v6_walk_index_trees`) together fail to name is
    /// unclaimed by definition, not by a residual default -- see
    /// [`PageKind::Orphan`]'s own doc comment for why the v5 analogue of
    /// this same distinction matters, and this struct's own doc comment for
    /// why `orphan` is mutually exclusive with the other four fields.
    pub orphan: Option<Vec<u8>>,
    /// This physical page's whole body, past its 6-byte header, verbatim --
    /// `Some` only for a page tagged `TAG_RETIRED` (`0x4500`, Task 6): an
    /// underflow merge/redistribute retired it from a key's own B-tree, but
    /// the allocation table still claims it (an in-place marker change, not
    /// a relocation -- `docs/2026-08-25-btree-split-rules.md` section 8), so it is
    /// not an `orphan` either. Its own repurposed `rightmost` field (offset
    /// `0x08`) is the free list's next hop; this crate makes no claim about
    /// the rest of its body beyond storing it verbatim so the file still
    /// round-trips, the same discipline `orphan` already uses for content
    /// nothing walks any more.
    pub retired: Option<Vec<u8>>,
}

/// One entry in an index page's entry array (harvest 4 SS4/SS4a): a real
/// record's key, the record(s) it points at, and the child page this entry
/// bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    /// This entry's key value, `key_length` bytes, verbatim -- a real
    /// record's key. An interior entry names a record just as a leaf entry
    /// does (harvest 4 SS4a), so this crate does not distinguish the two;
    /// what the bytes mean past "this is a key value" is a later task's
    /// business, the same way a data page's slot contents are.
    pub key: Vec<u8>,
    /// For a unique key: the one record carrying this value, a file byte
    /// position. For a duplicate-permitting key: the **first**-inserted
    /// record of this value's chain.
    pub head: u32,
    /// Duplicate-permitting keys only: the **last**-inserted record of this
    /// value's chain. `None` when the key does not permit duplicates --
    /// never a magic value standing in for "not applicable."
    pub tail: Option<u32>,
    /// The child holding keys between this entry and the next -- `NOWHERE`
    /// on a leaf. Read and stored **verbatim**, never derived: the last
    /// entry of a page reads literal zero here (a placeholder, not a
    /// pointer to page 0 -- harvest 4 SS4), and this crate stores exactly
    /// that zero rather than assuming `NOWHERE` because the page happens to
    /// be a leaf. `None` only when the page genuinely has no room left for
    /// these 4 bytes at all (harvest 4 SS4's `WCCSPELS.VIR` case: a full
    /// page whose last entry's trailing 4 bytes are entirely absent from
    /// the file) -- not to be confused with a present value of zero.
    pub child: Option<u32>,
}

/// The alternate collating sequence block (harvest 4 SS6): a page's content
/// past its 6-byte header, when that page is the file's ACS block --
/// physical page 1 on every v5 file this crate reads (`PageKind::Acs`,
/// harvest 4 SS6a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcsBlock {
    /// `0xac` or `0xad` -- both accepted by the engine, only one meaning
    /// established (harvest 4 SS6).
    pub tag: u8,
    /// The sequence's name, 8 bytes, space/NUL-padded, verbatim -- never
    /// normalised or re-padded. Three names appear across the corpus for
    /// what are really two distinct tables (`UPPER`/`GALCAPS` name the same
    /// uppercase fold; `ALLCAPS`/`LOWER`, v6-only, are `MULTIACS.DAT`'s own
    /// pair) -- this crate stores whatever name the file actually carries,
    /// never the table it happens to match. Shared with the control
    /// record's own `acs_name` at `0x3c`, which agrees with this field on
    /// every v5 file this task measured.
    pub name: [u8; 8],
    /// Indexed by the raw byte; yields the byte its key collates as.
    pub table: [u8; 256],
    /// Bytes from the end of `table` to the end of the page, verbatim --
    /// like `DataPage::slack`/`IndexPage::padding`, never assumed zero even
    /// though every one of the 15 v5 corpus files this task measured
    /// happens to leave it so.
    pub padding: Vec<u8>,
}

/// An index page's content past its 6-byte header (harvest 4 SS4): the
/// entry count (implicit in `entries.len()`) and the two boundary pointers,
/// every entry in file order, plus whatever bytes remain after the last
/// entry to the end of the page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexPage {
    /// The child holding keys greater than the last entry's, or `NOWHERE`
    /// on a leaf.
    pub rightmost: u32,
    /// The child holding keys less than the first entry's; `NOWHERE` or `0`
    /// on a leaf.
    pub leftmost: u32,
    /// Every entry, in key order (the order the file itself stores them
    /// in).
    pub entries: Vec<IndexEntry>,
    /// Bytes from the end of the last entry to the end of the page,
    /// verbatim -- like `DataPage::slack`, never assumed zero.
    pub padding: Vec<u8>,
}

/// One fragment slot of a [`FragmentPage`]'s entry array (harvest 5 SS3.3):
/// either a live fragment or a freed one, indexed `0..fragment_count` --
/// entry `fragment_count` itself (the array's one extra, boundary-only
/// member) is not one of these; see [`FragmentPage::free_space_entry`].
///
/// Shared between v5's untagged fragment pages ([`PageKind::Variable`]) and
/// v6's `TAG_VARIABLE`-tagged ones (`V6Page::fragment`, Task 20): the array
/// shape, tiling rules and pointer encoding are identical in both families
/// (harvest 3 SS4, harvest 5 SS3.3) -- only how a live fragment's leading
/// pointer is *decided to be present* differs, see [`Live`](Self::Live)'s
/// own doc comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FragmentSlot {
    /// `0xffff` on disk: freed, no body of its own. Whatever bytes occupy
    /// its former span are not tracked separately -- they belong to the
    /// live fragment before it, whose own span the entry array's tiling
    /// extends across this one (harvest 5 SS3.3: both the "where does
    /// fragment 0 start" and "where does fragment N end" scans step over a
    /// freed entry the same way).
    Freed,
    /// A live fragment: continues onto another page's fragment (`Some`) or
    /// ends the record's chain here (`None`), plus its own body, verbatim,
    /// **after** the leading 4-byte continuation pointer when one is
    /// present.
    ///
    /// **v5**: `Some` iff the entry's own continuation bit (`0x8000`) is
    /// set (harvest 5 SS3.4's version-gated bit, `W32MKDE_decompiled.c:
    /// 19045`) -- a real, load-bearing on-disk fact, and this task's
    /// predecessor's own required mutation target (`Pointer::decode`'s
    /// scrambled byte order, harvest 5 SS3.2).
    ///
    /// **v6**: always `Some` -- every v6 fragment carries the leading
    /// pointer whether or not it continues (harvest 5 SS3.4: "every
    /// fragment carries the 4-byte pointer, continued or not"), so
    /// `read::read_fragment_page`'s `is_v6` branch never even reads the
    /// entry's own continuation bit to decide this. That bit is measured
    /// **always clear** -- originally from four oracle-written v6 fixtures
    /// (`variable.rs:340-353`: 165/165 entries, none with it set), and
    /// (Task 21) now independently confirmed against every real v6
    /// fragment page this corpus actually has: 35,442 live entries across
    /// 19,231 pages in 17 files, 0 with the bit set
    /// (`the_v6_fragment_path_is_now_corpus_witnessed`, `crates/btrieve/
    /// tests/roundtrip.rs`; see [`FragmentPage`]'s own doc comment for how
    /// that evidence stayed hidden until this task) -- so this crate never
    /// sets it on emit either, rather than deriving a bit from
    /// `next.is_some()` the way the v5 write path does.
    Live {
        /// The chain's next fragment. See this variant's own doc comment
        /// for when this is populated on each of the two families.
        next: Option<Pointer>,
        /// This fragment's own bytes, verbatim, past the leading pointer
        /// when `next` is `Some`.
        body: Vec<u8>,
    },
}

/// A variable-length file's fragment/overflow page (harvest 5 SS3.3): the
/// content past the ordinary 6-byte page header (`format::page`), when this
/// page is [`PageKind::Variable`] (v5, untagged, found structurally) or
/// tagged `TAG_VARIABLE` (v6, `V6Page::fragment`, Task 20 -- harvest 3 SS4
/// measured the header past the tag identical in both families).
///
/// **Witnessed on both families.** Three real, populated v5 files exercise
/// this shape extensively (harvest 5 SS3.5: `archive/tooling/wbtrv32/assets/
/// VARIABLE.DAT`, `FW_QSQDB.DAT`, `JABTTQST.DAT`). Harvest 5 SS4.3 measured
/// every v6-family file flagged variable-length at zero records and zero
/// fragment pages **at the time** -- true only because every one of them
/// also carried a physical page this crate's own "unclaimed physical page"
/// gate refused before `read::file` could reach that far. Task 21 closed
/// that unrelated gate (`V6Page::orphan`) and the v6 evidence turned out to
/// be there all along: 17 v6-family files (16 `wcctext2.vir`/`.nu1` copies
/// plus `WGSMENU2.DAT`) combine populated records with variable-length
/// data, carrying 19,231 genuine `TAG_VARIABLE` pages and 35,442 live
/// fragment entries between them, every one of which reads the
/// continuation bit clear and round-trips byte-identically
/// (`the_v6_fragment_path_is_now_corpus_witnessed`,
/// `crates/btrieve/tests/roundtrip.rs` -- the test this same doc comment
/// used to point at as a tripwire for exactly this happening). The v6 half
/// of this type -- and of [`FragmentSlot::Live`]'s `next` field
/// specifically -- was originally established by `W32MKDE_decompiled.c` and
/// by the oracle recordings this project's own `variable.rs` module cites
/// (`variable.rs:340-353,493-501`) rather than by the corpus; it is now
/// independently confirmed by the corpus too, at a scale (35,442 real
/// entries) that dwarfs the four oracle fixtures it was originally checked
/// against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentPage {
    /// `0x06`: the write-side free-space chain link -- which variable page
    /// with room follows this one (harvest 5 SS3.6's three-state field:
    /// `0xffff_ffff` "off the chain", `0x00ff_ffff` "on the chain, last",
    /// or a real page number "on the chain, this one follows"). Stored raw
    /// rather than decoded into an enum: this crate does not implement the
    /// write-side allocator that maintains it (SS3.6's own scope, a later
    /// task), so there is nothing to recompute from a decoded form and a
    /// raw high-word-first long round-trips losslessly on its own.
    pub free_chain: u32,
    /// Every fragment slot this page's own header (`fragment_count` at
    /// `0x0a`) says it holds, in entry order `0..fragment_count`.
    pub fragments: Vec<FragmentSlot>,
    /// The entry array's one extra member (index `fragment_count`), raw:
    /// no fragment corresponds to it, it only marks where free space
    /// begins past the last live fragment's tiling. Stored as the literal
    /// on-disk two bytes -- the high bit the engine would read as a
    /// "continued" flag on every other entry marks nothing here, and is
    /// preserved rather than interpreted.
    pub free_space_entry: u16,
    /// Bytes between where the last live fragment's tiling says free space
    /// starts and where the entry array itself begins -- never assumed
    /// zero. Task 8's `DataPage::slack` lesson, re-measured for this task:
    /// checked non-zero anywhere it occurs across the four real corpus
    /// files this task was dispatched against, and reported in this task's
    /// own report either way.
    pub trailing: Vec<u8>,
}

/// One physical page beyond the control record (page 0), read whole: its
/// six-byte header (`format::page`), split into the two things it actually
/// carries, plus what the page graph resolved it to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// `0x00`: the page's own physical page number, a high-word-first
    /// `long`. Measured to agree with the page's actual position in the
    /// file on every page this task checked (`USRACC.DAT`'s pages 1 and 2);
    /// stored rather than assumed, so a page that disagreed would surface
    /// as a stored fact rather than a silently "corrected" one. **Not**
    /// always the page's own physical position -- a real `majormud-nt` data
    /// page this task read (`wccitem2.vir` page 592) stores a value with no
    /// resemblance to 592 here, and it is carried verbatim regardless, the
    /// same way `page_usable`'s doc warns against trusting a plausible
    /// formula over what a file actually says.
    pub number: u32,
    /// Bit 15 of the counter word: set iff the page holds records rather
    /// than a B-tree node. Stored, not consulted -- `kind` is what this
    /// crate trusts to describe a page's role; see `PageKind`'s own
    /// documentation.
    pub data_bit: bool,
    /// The low 15 bits of the counter word: a modification/usage counter,
    /// preserved not interpreted.
    pub stamp: u16,
    /// What the control record's own pointers say this page is.
    pub kind: PageKind,
    /// This page's fixed-length record content: `Some` for a `Data`/`Free`
    /// page (`data_bit` set) whose `physical` is nonzero. `None` for an
    /// `Index`/`IndexChild`/`Acs`/`Variable` page. A variable-length file's
    /// `Data`/`Free` pages get this the same way any other file's do --
    /// harvest 5 SS1.1's slot layout does not change shape when a live
    /// record's tail holds a fragment pointer instead of zero padding, and
    /// `RecordSlot::Live` stores that whole slot verbatim regardless, so
    /// nothing here needs to know a pointer is inside one. Only the file's
    /// *fragment* pages (`PageKind::Variable`, a wholly different structure
    /// -- harvest 5 SS3.3) are `None` here; see
    /// [`Page::fragments`].
    pub content: Option<DataPage>,
    /// This page's index content: `Some` for an `Index` page (a key's own
    /// root) **and** for an `IndexChild` page (a genuine descendant that key's
    /// own walk reached, Task 11b) -- either way its owning key's
    /// `key_length`/`entry_size`/`attributes` are known (directly for a
    /// root, from the walk's own attribution for a child), so both decode
    /// the same way. `None` only for a `Data`/`Free`/`Acs` page, which never
    /// carry index content at all.
    pub index: Option<IndexPage>,
    /// This page's alternate collating sequence content, `Some` for an
    /// `Acs` page and `None` for every other kind.
    pub acs: Option<AcsBlock>,
    /// This page's fragment/overflow content (harvest 5 SS3.3), `Some` for
    /// a `Variable` page and `None` for every other kind.
    pub fragments: Option<FragmentPage>,
    /// An orphan page's entire body, past its 6-byte header, verbatim --
    /// `Some` only for [`PageKind::Orphan`], `None` for every other kind.
    /// Stored whole and uninterpreted rather than as slots/entries: this
    /// crate has no walk-based attribution for an orphan (that is exactly
    /// what makes it an orphan), so it makes no claim about what, if
    /// anything, inside this body is still meaningful -- see
    /// `PageKind::Orphan`'s own documentation for the evidence that this is
    /// abandoned content rather than a parsing gap.
    pub orphan: Option<Vec<u8>>,
}

/// A v5 file has one control record. A v6 file has two, physical pages 0
/// and 1, and one of them is stale -- see harvest 2 "FCR shadowing" and
/// harvest 0 ruling 7. Both are kept in full, because the vendor's own
/// update strategy is copy-on-write-plus-bump: copy the live page over the
/// stale one, mutate the stale copy, bump its generation past the live
/// one's -- so the two copies swap roles on every write, and 157 of 507
/// corpus v6 files are sitting mid-flip. A model that discards the stale
/// copy's exact bytes cannot reproduce a file caught in that state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Control {
    /// A v5 file: one control record, physical page 0.
    Single(ControlRecord),
    /// A v6 file: both shadow copies, plus which physical page (`0` or `1`)
    /// is the live one -- decided by comparing the generation counter at
    /// page-relative `0x04` in each, higher wins (`read::file` refuses a
    /// tie rather than guessing; no corpus file has ever tied).
    Shadowed {
        /// The copy whose generation counter is higher -- current geometry.
        live: V6ControlRecord,
        /// The copy whose generation counter is lower -- superseded, but
        /// its exact bytes must still round-trip.
        stale: V6ControlRecord,
        /// Which physical page (`0` or `1`) `live` came from.
        live_is_page: usize,
    },
}

/// One Btrieve file, described completely enough to reproduce it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    /// Generation and page size, from the control record.
    pub id: Identified,
    /// The control record: one copy for a v5 file, two (one live, one
    /// stale) for a v6 file -- see [`Control`]. `read::file` builds a
    /// `Control::Shadowed` `File` for every v6 file it can read at all
    /// (Task 18 first, for a file declaring no keys; Task 19 widened that
    /// to every v6 file whose pages this crate can fully classify), so
    /// `self.control` is `Control::Single` only for a v5 `File` -- a caller
    /// that might see either generation must match on `self.control`
    /// directly (see `File::live_control`'s own doc comment).
    pub control: Control,
    /// The key/segment definition array, `0x110` onward: one entry per
    /// on-disk definition, in file order. Its length is the walk's own
    /// result, not `control.keys` -- a segmented key contributes more than
    /// one entry for one key.
    pub key_descriptors: Vec<KeyDescriptor>,
    /// Whatever bytes remain in page 0 after the last key/segment
    /// definition, up to `page_size` -- verbatim, never assumed zero.
    ///
    /// Harvest 1's `tail_check.py` measured this zero on 112 of 112 v5
    /// corpus files, and Task 5 turned that measurement into an assertion:
    /// `read::file` refused any v5 file where this region was not all zero.
    /// Task 13 found the assertion's only two counterexamples --
    /// `wccitems.nu1` and its byte-identical sibling under `wccnt7pz` -- and
    /// they are not corrupt: byte 0x12e..0x600 holds readable MajorMUD prose
    /// (`"er teeth like spears, and the ... intelligence"`), leftover record
    /// text sitting in page 0's unused tail rather than a resurfacing
    /// structure. This is `DataPage::slack`'s exact lesson (Task 8: 42,566
    /// zero pages, 5 genuinely not) applied to page 0 -- the region is
    /// unused space that retains whatever the engine last wrote there, not
    /// an invariant the format enforces. So this field carries it verbatim
    /// and `read::file` no longer refuses a nonzero byte here; the zero
    /// measurement (143 of 145 v5 corpus files) stays true and useful, it is
    /// just no longer treated as a guarantee.
    pub page_zero_tail: Vec<u8>,
    /// Every physical page from 1 to the file's last page, in order --
    /// `pages[0]` is physical page 1, `pages[1]` is physical page 2, and so
    /// on. Each page's header is fully described; records, every index
    /// page's entries (root **and** child, Task 11b), the ACS table, and a
    /// variable-length file's fragment pages are all described too.
    ///
    /// v5 only -- empty for a v6 `File` (see the `v6_*` fields below, which
    /// carry v6's own geometry instead).
    pub pages: Vec<Page>,
    /// v6 only: the stale copy's own key/segment definitions, read
    /// independently off the stale physical page -- never assumed equal to
    /// `key_descriptors` (the live copy's own array), because a page caught
    /// mid-flip is a genuine snapshot of the file's schema before whatever
    /// mutation produced the live copy's own generation bump. Empty for a
    /// v5 `File`.
    pub v6_stale_key_descriptors: Vec<KeyDescriptor>,
    /// v6 only: the live copy's definition-offset trailer and surrounding
    /// padding (Task 16), past `key_descriptors`. `None` for a v5 `File`.
    pub v6_page_tail: Option<V6PageTail>,
    /// v6 only: the stale copy's own trailer and padding, read independently
    /// off `v6_stale_key_descriptors` for the identical reason that field
    /// exists. `None` for a v5 `File`.
    pub v6_stale_page_tail: Option<V6PageTail>,
    /// v6 only: every "PP" allocation-table block this file has (Task 17),
    /// both shadow copies of each, in block-index order (element `n` is
    /// block `n + 1`). Empty for a v5 `File`.
    pub v6_allocation_blocks: Vec<V6AllocationBlock>,
    /// v6 only: every physical page the allocation table resolves --
    /// `read::file` populates this for every v6 `File` it can read at all,
    /// keys or none: a genuine data page (Task 18), an index page some
    /// key's own walk attributed to its tree, root or descendant alike
    /// (Task 19), or the ACS block (Task 19) -- see [`V6Page`]'s own doc
    /// comment for which of its three content fields is `Some` for which
    /// case. Empty for a v5 `File`.
    pub v6_pages: Vec<V6Page>,
    /// The file's length in bytes.
    pub len: u64,
}

impl File {
    /// The v5 control record whose geometry is current. `read::file` does
    /// build a `Control::Shadowed` `File` now (Task 18 for a v6 file
    /// declaring no keys at all; Task 19 widened that to every v6 file
    /// this crate can read at all -- see [`Control::Shadowed`]'s own doc
    /// comment and `read::file`'s), so `self.control` is no longer always
    /// `Control::Single`; the `Shadowed` arm below still panics, because
    /// this accessor's whole contract is "the v5-shaped control record,"
    /// and a v6 `File`'s current geometry is `Control::Shadowed`'s own
    /// `live` field (a different type, `V6ControlRecord`) -- a caller that
    /// might see either generation must match on `self.control` directly
    /// rather than call this.
    #[must_use]
    pub fn live_control(&self) -> &ControlRecord {
        match &self.control {
            Control::Single(one) => one,
            Control::Shadowed { .. } => unreachable!(
                "live_control() is v5-only -- a v6 File's current geometry is \
                 Control::Shadowed's own `live` field (V6ControlRecord), not a \
                 ControlRecord this accessor could return; match on \
                 self.control directly for a caller that might see either"
            ),
        }
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    /// The first 512 bytes of `archive/galacticomm/hosts/majorbbs/USRACC.DAT`
    /// (V5R3, 3 pages of 512 bytes each), hand-copied via `xxd` when this
    /// task was dispatched. The controller measured these same values
    /// independently before dispatching the task, from the raw bytes:
    /// `page_size` 512, `KEYS` 1, `RECLEN` 0xfc, `PHYSICAL` 0xfc, `RECORDS`
    /// 2, `HIGHEST` 2, `PAGES` 3, `USRFLGS` 0. Bytes past `0x2c` are zero in
    /// the real file up to `0x110`, where a real key/segment definition
    /// begins -- see [`usracc_first_page`] for that definition's own bytes.
    ///
    /// Shared by `read`'s and `emit`'s own tests so both check against the
    /// same measured bytes rather than two independently-typed copies.
    pub(crate) fn usracc_fixed_portion() -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[0x04..0x06].copy_from_slice(&[0x06, 0x00]); // page_gen = 6
        b[0x06..0x08].copy_from_slice(&[0x00, 0x03]); // version -> V5R3
        b[0x08..0x0a].copy_from_slice(&[0x00, 0x02]); // page_size = 512
        b[0x0c..0x10].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]); // unknown_0c = NOWHERE
        b[0x10..0x14].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]); // free = NOWHERE
        b[0x14..0x16].copy_from_slice(&[0x01, 0x00]); // keys = 1
        b[0x16..0x18].copy_from_slice(&[0xfc, 0x00]); // reclen = 252
        b[0x18..0x1a].copy_from_slice(&[0xfc, 0x00]); // physical = 252
        b[0x1a..0x1e].copy_from_slice(&[0x00, 0x00, 0x02, 0x00]); // records = 2
        b[0x1e..0x22].copy_from_slice(&[0x00, 0x00, 0x02, 0x00]); // highest = 2
        b[0x22..0x26].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]); // data_page_count = 1
        b[0x26..0x2a].copy_from_slice(&[0x00, 0x00, 0x03, 0x00]); // pages = 3
        b[0x2a..0x2c].copy_from_slice(&[0x02, 0x00]); // page_usable = 2
        b
    }

    /// [`usracc_fixed_portion`] plus `USRACC.DAT`'s one real key/segment
    /// definition at `0x110`, read directly off
    /// `archive/galacticomm/hosts/majorbbs/USRACC.DAT` when this task was
    /// dispatched: `root` 1, `records` 2, `attributes` 0, `key_length` 10,
    /// `entry_size` 18 (`key_length + 8`, no duplicates), `max_entries` 27,
    /// `half_entries` 13 (`27 / 2`), `chain` 0, `offset` 0, `length` 10;
    /// every byte from `0x18` (self_tag) onward, and every byte from the end
    /// of this one definition (`0x12e`) to `512`, reads 0 in the real file.
    pub(crate) fn usracc_first_page() -> Vec<u8> {
        let mut b = usracc_fixed_portion();
        let base = 0x110;
        b[base + 0x02..base + 0x04].copy_from_slice(&[0x01, 0x00]); // root = 1
        b[base + 0x06..base + 0x08].copy_from_slice(&[0x02, 0x00]); // records = 2
        b[base + 0x0a..base + 0x0c].copy_from_slice(&[0x0a, 0x00]); // key_length = 10
        b[base + 0x0c..base + 0x0e].copy_from_slice(&[0x12, 0x00]); // entry_size = 18
        b[base + 0x0e..base + 0x10].copy_from_slice(&[0x1b, 0x00]); // max_entries = 27
        b[base + 0x10..base + 0x12].copy_from_slice(&[0x0d, 0x00]); // half_entries = 13
        b[base + 0x16..base + 0x18].copy_from_slice(&[0x0a, 0x00]); // length = 10
        b
    }

    /// A synthetic two-key v5 control record, styled after `MULTIACS.DAT`'s
    /// own (v6) key definitions but built here to exercise the same 24-bit
    /// root mask on v5 -- no real v5 corpus file carries a nonzero `ROOT`
    /// top byte (this task's own scan found 0 of 307 v5 definitions do), so
    /// nothing in the corpus can catch a mask that reads 31 bits instead of
    /// 24. Key 0: `ROOT` bytes `00 80 03 00` -> key_number 0x80, root_page 3.
    /// Key 1: `ROOT` bytes `00 81 04 00` -> key_number 0x81, root_page 4.
    /// Masking with `0x7fffffff` instead of `0x00ffffff` reads key 1's root
    /// as `0x01000004` (harvest 4 SS2's own worked example, reproduced here
    /// on v5-shaped bytes) -- see `read`'s
    /// `masking_the_wrong_width_corrupts_a_multi_key_roots_page` mutation
    /// test.
    pub(crate) fn two_key_fixed_portion() -> Vec<u8> {
        let mut b = usracc_fixed_portion();
        b[0x14..0x16].copy_from_slice(&[0x02, 0x00]); // keys = 2
        let def0 = 0x110;
        b[def0..def0 + 4].copy_from_slice(&[0x00, 0x80, 0x03, 0x00]); // root = 0x80000003
        let def1 = def0 + 0x1e;
        b[def1..def1 + 4].copy_from_slice(&[0x00, 0x81, 0x04, 0x00]); // root = 0x81000004
        b
    }

    /// Decode a hex string into bytes. Test-only convenience so real corpus
    /// bytes can be transcribed literally (via `xxd`/`hex()`) rather than
    /// re-typed byte by byte.
    fn from_hex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    /// A synthetic v5 file whose one key's root page is completely full:
    /// 50 entries of a 10-byte (`key_length` 2, `entry_size` 10, no
    /// duplicates) key in a 512-byte page -- the exact shape harvest 4 SS4
    /// cites (`WCCSPELS.VIR` page 1: "fifty 10-byte entries in a 512-byte
    /// page ... four bytes more than fits"), reconstructed here because
    /// that file could not be relocated in the current archive snapshot
    /// (harvest 4 SS8's own gap). `16 + 49*10 + 6 == 512` exactly: the
    /// last entry's trailing 4-byte `child` field has no room at all, so
    /// this is the shape that exercises the last-entry **omission**
    /// branch -- as opposed to a *present* literal zero, which
    /// `USRACC.DAT` already covers. No corpus file witnesses this: the
    /// fullest of the 102 passing index roots this task measured
    /// (`entry_size * count` against `page_size`) is 42%; this fixture is
    /// the only thing at 100%.
    pub(crate) fn full_index_page_with_an_omitted_last_child() -> Vec<u8> {
        fn put_long(b: &mut [u8], at: usize, v: u32) {
            let high = (v >> 16) as u16;
            let low = v as u16;
            b[at..at + 2].copy_from_slice(&high.to_le_bytes());
            b[at + 2..at + 4].copy_from_slice(&low.to_le_bytes());
        }

        let mut b = usracc_fixed_portion();
        b[0x14..0x16].copy_from_slice(&1u16.to_le_bytes()); // keys = 1
        put_long(&mut b, 0x1a, 50); // records = 50
        put_long(&mut b, 0x1e, 50); // highest = 50
        put_long(&mut b, 0x22, 0); // data_page_count -- no data page here
        put_long(&mut b, 0x26, 2); // pages = 2 (page 0 plus the index page)

        let def0 = 0x110;
        put_long(&mut b, def0, 1); // root = 1
        put_long(&mut b, def0 + 0x04, 50); // records = 50
        b[def0 + 0x0a..def0 + 0x0c].copy_from_slice(&2u16.to_le_bytes()); // key_length
        b[def0 + 0x0c..def0 + 0x0e].copy_from_slice(&10u16.to_le_bytes()); // entry_size
        b[def0 + 0x0e..def0 + 0x10].copy_from_slice(&49u16.to_le_bytes()); // max_entries
        b[def0 + 0x10..def0 + 0x12].copy_from_slice(&24u16.to_le_bytes()); // half_entries
        b[def0 + 0x16..def0 + 0x18].copy_from_slice(&2u16.to_le_bytes()); // length

        b.resize(1024, 0); // page 0 plus page 1 (the full index page)
        let page1 = 512usize;
        b[page1..page1 + 4].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]); // number = 1
        b[page1 + 4..page1 + 6].copy_from_slice(&5u16.to_le_bytes()); // stamp 5, data_bit clear
        b[page1 + 6..page1 + 8].copy_from_slice(&50u16.to_le_bytes()); // count = 50
        b[page1 + 8..page1 + 12].copy_from_slice(&[0xff; 4]); // rightmost = NOWHERE
        b[page1 + 12..page1 + 16].copy_from_slice(&[0xff; 4]); // leftmost = NOWHERE

        let mut offset = page1 + 16;
        for n in 0u32..50 {
            let is_last = n == 49;
            b[offset..offset + 2].copy_from_slice(&(n as u16).to_le_bytes()); // key
            put_long(&mut b, offset + 2, 0x1000 + n); // head
            if is_last {
                // No room at all for the trailing 4-byte child field --
                // the WCCSPELS.VIR omission (harvest 4 SS4).
                offset += 6;
            } else {
                put_long(&mut b, offset + 6, 0xffff_ffff); // child: NOWHERE, a leaf
                offset += 10;
            }
        }
        assert_eq!(offset, 1024, "the crafted page tiles exactly, no leftover byte");
        b
    }

    /// Physical page 15 of `archive/tooling/wbtrv32/assets/VARIABLE.DAT`,
    /// transcribed in full (via `xxd`/`hex()`) when this task was
    /// dispatched -- the harvest's own named best fixture for a multi-hop
    /// fragment chain (harvest 5 SS3.5: 72% of the file's checked fragments
    /// continue onto another page). Measured directly off this exact page:
    /// `number` 15, `data_bit` clear, `free_chain` `0xffff_ffff` ("off the
    /// chain"), `fragment_count` 8. Entry 0 alone continues (offset 12,
    /// continuation bit set) -- its leading 4 bytes `00 0d 00 08` decode via
    /// `Pointer::decode` to page 13, fragment 8, and its 33-byte body is a
    /// literal `0x00..=0x20` sequence (this asset's own synthetic filler,
    /// not real prose -- `VARIABLE.DAT` is a test tool's fixture, not a
    /// shipped module's data). Entries 1-7 each end the chain where they
    /// are, with bodies of increasing length built from the same `0x00..`
    /// filler pattern. No freed slots, and the boundary entry (index 8)
    /// names offset 494 -- exactly where the entry array itself begins
    /// (`512 - 2*(8+1) = 494`), so `trailing` is empty on this page: every
    /// byte from `0x0c` to the array is a live fragment's own body.
    pub(crate) fn variable_dat_page_15() -> Vec<u8> {
        from_hex(
            "00000f008900ffffffff0800000d0008000102030405060708090a0b0c0d0e0f1011\
             12131415161718191a1b1c1d1e1f20000102030405060708090a0b0c0d0e0f101112\
             131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334\
             35363738393a3b3c3d000102030405060708090a0b0c0d0e0f101112131415161718\
             191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a\
             3b3c3d3e000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d\
             1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
             000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021\
             22232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40000102\
             030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324\
             25262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40410001020304\
             05060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526\
             2728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041420a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031\
             32333435363738393a3b3c3d3e3f40414243ee01b40171012f01ee00ae006f003100\
             0c80",
        )
    }

    /// A synthetic v5 file wrapping [`variable_dat_page_15`] as physical
    /// page 1: zero keys (so nothing claims the page, and the fragment-page
    /// shape check is the only thing that can classify it), `usrflgs` bit 0
    /// set (harvest 5 SS3.1's own trigger, the gate `read::resolve_pages`
    /// requires before it ever attempts the shape check at all). Page 0's
    /// own key/segment definition array is empty, so this is exactly two
    /// pages, both fully described once fragment pages are.
    pub(crate) fn variable_length_file_with_a_real_fragment_page() -> Vec<u8> {
        let mut b = usracc_fixed_portion();
        b[0x14..0x16].copy_from_slice(&0u16.to_le_bytes()); // keys = 0
        b[0x26..0x2a].copy_from_slice(&[0x00, 0x00, 0x02, 0x00]); // pages = 2
        b[0x106..0x108].copy_from_slice(&1u16.to_le_bytes()); // usrflgs bit 0
        b.resize(1024, 0);
        b[512..1024].copy_from_slice(&variable_dat_page_15());
        b
    }
}
