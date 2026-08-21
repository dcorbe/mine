//! The file control record, described.
//!
//! Page 0 of every Btrieve file. This is the first structure given a complete
//! [`Layout`], and it establishes the pattern every later one follows: named
//! ranges, each cited, tiling the structure with no gaps.
//!
//! # Honest state of this description
//!
//! The control record is `page_size` bytes -- the whole of page 0, not a
//! fixed 512 -- see harvest 1's "How many bytes the FCR occupies". Its fixed
//! portion, `0x00` through `0x110`, is now fully harvested: every field in
//! that range is transcribed from harvest 1's field table, cited, and tiles
//! completely.
//!
//! Past `0x110`, v5 now describes the key/segment definition array too: one
//! [`key_descriptor_fields`] group of named, cited fields per definition,
//! `index: Some(n)` so a fault names which repetition. The array's length is
//! not `KEYS` (`0x14`) -- a segmented key consumes one definition per
//! segment, so the count comes from walking the file (`read::file`), not
//! from a formula. Whatever page bytes remain after the last definition, up
//! to `page_size`, are `page_zero_tail`: harvest 1's `tail_check.py` measured
//! this zero on 112 of 112 v5 corpus files, re-measured for Task 13 on all
//! 145 currently-identified v5 corpus files (143 of 145 confirmed; the 2
//! exceptions -- `wccitems.nu1` and its sibling -- carry genuine leftover
//! record prose here, not corruption, so `read` carries the region verbatim
//! rather than asserting it zero -- see `model::File::page_zero_tail`).
//!
//! # v6's fixed portion (Task 15)
//!
//! Harvest 2 (`docs/superpowers/harvest/2026-08-20-btrieve-harvest-2-fcr-v6.md`)
//! transcribed here as [`v6`]/[`v6_fixed`]: 43 named fields tiling
//! `0x00..0x110` exactly -- harvest 2's field table has 42 offset-addressed
//! rows there, and this crate splits its one two-value row (`0x22`,
//! "constant `0xffff` then `0x0100`") into `sentinel_22`/`sentinel_24`,
//! since a [`Field`] carries one value, not two. `PAGE_SIZE` and `VERSION`
//! are read through [`super::generation::Identified`], not duplicated in
//! `model::V6ControlRecord` -- the same exclusion v5's `at` module makes for
//! `lead`/`page_gen`/`page_size` in `model::ControlRecord`. Eighteen of the
//! remaining forty are fully understood and
//! cited to a decompile line or a clean corpus-measured formula; nineteen are
//! constant and fully reproducible but of unresolved semantic meaning
//! (named `reserved`/`sentinel`, each carrying the corpus count that pins its
//! value rather than a guess at its purpose); three (`0x4c`, `0x4e`/`0x50`/
//! `0x52`, `0x56`) are usage-dependent counters with a virgin-file baseline
//! formula but no confirmed live-growth rule -- see the harvest's own GAPS
//! section, quoted in each field's citation rather than upgraded into an
//! explanation this crate cannot back.
//!
//! Two corrections this harvest made to the old crate's understanding, both
//! load-bearing: `SELF_TAG` (key/segment definition relative `0x18`) is
//! `0x80|keynum` on an independent segment, `0` on an `ANOSEG` continuation
//! -- present in 199 of 201 sampled v6 definitions and unnamed anywhere
//! before this harvest (v5's own 307 definitions all read 0 there, so v5
//! models the same byte as an always-zero plain field, not a tag -- see
//! `key_descriptor::fields`'s `self_tag` citation). And `PAGES` (`0x26`) is
//! a **logical** page count, not physical: `wccmp002.vir` reads 13,572
//! against 13,607 physical pages, the difference being the fixed shadow
//! (control record + allocation table) overhead -- see the harvest's
//! "PAGES, worked" section.
//!
//! Past `0x110`, v6's key/segment definitions are the *same* 30-byte,
//! `ANOSEG`-chained structure v5 uses -- [`key_descriptor`] is shared, not
//! duplicated, because harvest 2's own field table (`ROOT` through
//! `NULL_VALUE`) transcribes to identical offsets and widths; `KEYS` (`0x14`)
//! counts *keys*, not definitions, exactly as it does for v5 (harvest 2's
//! `MULTIACS.DAT` worked example: 3 keys, 4 definitions, the second key's
//! two segments chained by `ANOSEG`). Whatever remains after the last
//! definition -- the definition-offset trailer (one `u16` per definition,
//! its own absolute byte offset, at a page-size-dependent fixed position)
//! plus trailing zero padding -- is `page_tail`, still `NOT YET HARVESTED`:
//! harvest 2 measured its position and content but not its exact capacity
//! (GAP 9), and decomposing it is the next task's job, not this one's.

use super::generation::Generation;
use super::{Field, Layout};

/// Byte offsets of the v5 control record's fixed-portion fields, `0x00`
/// through `0x110`. One name per harvest-1 field-table row, transcribed
/// directly so `v5_fixed`, `read` and `emit` share a single set of offsets
/// rather than three copies of the same magic numbers.
pub mod at {
    pub const LEAD: usize = 0x00;
    pub const PAGE_GEN: usize = 0x04;
    pub const VERSION: usize = 0x06;
    pub const PAGE_SIZE: usize = 0x08;
    pub const COMPANION_SELECTOR: usize = 0x0a;
    pub const LOCK_FLAG: usize = 0x0b;
    pub const UNKNOWN_0C: usize = 0x0c;
    pub const FREE: usize = 0x10;
    pub const KEYS: usize = 0x14;
    pub const RECLEN: usize = 0x16;
    pub const PHYSICAL: usize = 0x18;
    pub const RECORDS: usize = 0x1a;
    pub const HIGHEST: usize = 0x1e;
    pub const DATA_PAGE_COUNT: usize = 0x22;
    pub const PAGES: usize = 0x26;
    pub const PAGE_USABLE: usize = 0x2a;
    pub const LOCK_TRANSACTION: usize = 0x2c;
    pub const NEGATIVE_VERSION_A: usize = 0x2e;
    pub const NEGATIVE_VERSION_B: usize = 0x32;
    pub const NEGATIVE_VERSION_C: usize = 0x36;
    pub const NEGATIVE_VERSION_D: usize = 0x37;
    pub const VARIABLE_TAG: usize = 0x38;
    pub const VARIABLE_SUBFLAG: usize = 0x39;
    pub const VARIABLE_HIGHEST: usize = 0x3a;
    pub const ACS_NAME: usize = 0x3c;
    pub const ACS_NAME_LEN: usize = 8;
    pub const RESERVED_44: usize = 0x44;
    pub const RESERVED_44_LEN: usize = 36;
    pub const WRITE_COUNTER_68: usize = 0x68;
    pub const RESERVED_6A: usize = 0x6a;
    pub const RESERVED_6A_LEN: usize = 156;
    pub const USRFLGS: usize = 0x106;
    pub const VARIABLE_PAGE_CAPACITY: usize = 0x108;
    pub const RESERVED_109: usize = 0x109;
    pub const ACS_PAGE_POINTER: usize = 0x10a;
    pub const RESERVED_10E: usize = 0x10e;
    pub const RESERVED_10E_LEN: usize = 2;

    /// End of the harvested fixed portion: `0x00..FIXED_LEN` tiles
    /// completely, every byte cited.
    pub const FIXED_LEN: usize = 0x110;
}

/// Bits of `USRFLGS` (`at::USRFLGS`) this crate currently names.
pub mod usrflgs {
    /// Bit 0: the file holds variable-length records (harvest 5 SS3.1,
    /// corroborated there by `physical - reclen >= 4` and byte `0x38 ==
    /// 0xff`, measured with 0 mismatches across all 612 corpus files).
    /// `read::resolve_pages`'s fixed-length data-page description (this
    /// task) is gated on this bit being clear -- a variable-length file's
    /// data-bit-set pages are `'V'`-tagged fragment pages (harvest 5 SS3.3),
    /// a different structure entirely and a later task's job.
    pub const VARIABLE: u16 = 0b1;
}

/// One 30-byte key/segment definition, repeating at `at::FIXED_LEN + n*WIDTH`
/// -- the first structure in the format whose repetition count is read from
/// the file rather than known at compile time. See harvest 4 SS1a for the
/// field table this transcribes, and harvest 1's "Field table: the
/// key/segment definition" section for how the array sits inside the
/// control record.
///
/// # `KEYS` counts keys, not definitions
///
/// A key with `N` segments consumes `N` consecutive definitions, chained by
/// [`ANOSEG`] on every definition but the last of the key. The array is
/// walked definition by definition until [`super::at::KEYS`] *keys* -- not
/// definitions -- have been assembled (`read::file` does the walking; this
/// module only describes one definition's byte layout).
pub mod key_descriptor {
    use super::Field;

    /// Bytes of one key/segment definition.
    pub const WIDTH: usize = 0x1e;

    /// `BTVSTF.H:13` -- the most segments (and so the most definitions in a
    /// row before a key must close) a file may have.
    pub const SEGMAX: usize = 24;

    /// Bit 0 of `ATTRIBUTES`: more than one record may carry this key's
    /// value. Harvest 4 SS1b (`keys.rs:78`, `flag::DUPLICATES`). This is
    /// what `read::read_index_page` trusts to decide whether an index
    /// entry carries a trailing `tail` field -- cross-checked, not assumed,
    /// against the key descriptor's own stored `ENTRY_SIZE`
    /// (`key_length+8` unique, `key_length+12` duplicate): a descriptor
    /// whose `ENTRY_SIZE` agrees with neither is refused rather than
    /// silently guessed at.
    pub const DUPLICATES: u16 = 1 << 0;

    /// Bit 4 of `ATTRIBUTES`: another segment of *this same key* follows in
    /// the next definition. `BTVSTF.H:59`'s `ANOSEG 0x10`.
    pub const ANOSEG: u16 = 1 << 4;

    /// Bit 5 of `ATTRIBUTES`: this key is indexed through an alternate
    /// collating sequence rather than raw byte order. `keys.rs:98`
    /// (`flag::ALT_COLLATING`). `read::resolve_pages` gates the v5 ACS
    /// page's *presence* on this bit rather than on FCR `0x10a` alone --
    /// harvest 4 SS6a measured `0x10a` unreliable on 2 of 13 v5 files that
    /// declare a sequence.
    pub const ALT_COLLATING: u16 = 1 << 5;

    /// Byte offsets of one key/segment definition's fields, relative to the
    /// definition's own start.
    pub mod at {
        pub const ROOT: usize = 0x00;
        pub const RECORDS: usize = 0x04;
        pub const ATTRIBUTES: usize = 0x08;
        pub const KEY_LENGTH: usize = 0x0a;
        pub const ENTRY_SIZE: usize = 0x0c;
        pub const MAX_ENTRIES: usize = 0x0e;
        pub const HALF_ENTRIES: usize = 0x10;
        pub const CHAIN: usize = 0x12;
        pub const OFFSET: usize = 0x14;
        pub const LENGTH: usize = 0x16;
        pub const SELF_TAG: usize = 0x18;
        pub const ACS_PAGE_HIGH: usize = 0x19;
        pub const ACS_PAGE_LOW: usize = 0x1a;
        pub const ACS_PAGE_MID: usize = 0x1b;
        pub const EXTENDED: usize = 0x1c;
        pub const NULL_VALUE: usize = 0x1d;
    }

    /// Absolute offset, within the control record, of definition `n`'s own
    /// start.
    #[must_use]
    pub fn base(n: usize) -> usize {
        super::at::FIXED_LEN + n * WIDTH
    }

    /// Every named field of definition `n`, cited and carrying
    /// `index: Some(n)` so a tiling fault names `root[3]` rather than
    /// `root` -- see `format::Field::label`.
    #[must_use]
    pub fn fields(n: usize) -> Vec<Field> {
        let base = base(n);
        vec![
            Field {
                name: "root",
                index: Some(n),
                at: base + at::ROOT,
                len: 4,
                cite: "harvest 4 SS1a (create.rs:117-118 at::ROOT; pages.rs:57-74 \
                       ROOT_PAGE mask) and SS2 -- high-word-first long; top byte \
                       0x80|keynum, low 24 bits the root index page, 0 on a \
                       continuation. Reconciled with harvest 1's v5-specific \
                       claim ('a plain page number, no top-byte tag ... no \
                       masking needed'): not a real conflict in effect -- this \
                       task's own scan of all 307 v5 corpus definitions (145 \
                       files) found the top byte reads 0 in every one, so \
                       masking to 24 bits is a no-op on every v5 file measured. \
                       Modeled as key_number+root_page per harvest 4's general \
                       rule anyway, since harvest 4 SS2's 0x7fffffff-vs-0x00ffffff \
                       worked example (MULTIACS.DAT) is v6, not v5, and is the \
                       reason the mask is written at all",
            },
            Field {
                name: "records",
                index: Some(n),
                at: base + at::RECORDS,
                len: 4,
                cite: "harvest 4 SS1a (v6.rs:907-908, pages.rs KEY_RECORDS); \
                       harvest 1 (create.rs::at::RECORDS, stat.rs) -- how many \
                       records this key indexes; meaningless on a continuation",
            },
            Field {
                name: "attributes",
                index: Some(n),
                at: base + at::ATTRIBUTES,
                len: 2,
                cite: "harvest 4 SS1b (keys.rs::flag module) -- the flag word; \
                       see ANOSEG above for the bit this array's own walk reads",
            },
            Field {
                name: "key_length",
                index: Some(n),
                at: base + at::KEY_LENGTH,
                len: 2,
                cite: "harvest 4 SS1a (create.rs::at::KEY_LENGTH); harvest 1 -- \
                       total width of the key, every segment summed; 0 on a \
                       continuation",
            },
            Field {
                name: "entry_size",
                index: Some(n),
                at: base + at::ENTRY_SIZE,
                len: 2,
                cite: "harvest 4 SS1a (pages.rs:788-797 Shape::entry_size, \
                       W32MKDE_decompiled.c:18398-18410) -- key_length+8, or +12 \
                       if the key permits duplicates",
            },
            Field {
                name: "max_entries",
                index: Some(n),
                at: base + at::MAX_ENTRIES,
                len: 2,
                cite: "harvest 4 SS1a (pages.rs:799-806 Shape::capacity) -- index \
                       entries of this key that fit one page",
            },
            Field {
                name: "half_entries",
                index: Some(n),
                at: base + at::HALF_ENTRIES,
                len: 2,
                cite: "harvest 4 SS1a (create.rs::at::HALF_ENTRIES); harvest 1 -- \
                       max_entries/2 exactly, confirmed on all 229 definitions \
                       measured there",
            },
            Field {
                name: "chain",
                index: Some(n),
                at: base + at::CHAIN,
                len: 2,
                cite: "harvest 4 SS1a (keys.rs:43-73 at::CHAIN) -- byte offset, \
                       within the record's physical slot, of the duplicate \
                       [prev][next] chain pair; physical-8 when duplicates are \
                       permitted, else 0",
            },
            Field {
                name: "offset",
                index: Some(n),
                at: base + at::OFFSET,
                len: 2,
                cite: "harvest 4 SS1a (keys.rs:58 at::OFFSET) -- this segment's \
                       byte offset within the logical record",
            },
            Field {
                name: "length",
                index: Some(n),
                at: base + at::LENGTH,
                len: 2,
                cite: "harvest 4 SS1a (keys.rs:60 at::LENGTH) -- this segment's \
                       length in bytes",
            },
            Field {
                name: "self_tag",
                index: Some(n),
                at: base + at::SELF_TAG,
                len: 1,
                cite: "harvest 4 SS1a/SS8 flags this byte as an unclaimed GAP -- \
                       no field in keys.rs or create.rs reads it, and its only \
                       nonzero measurement there is MULTIACS.DAT (v6.10, out of \
                       this task's v5-only scope). Harvest 2 (the v6 FCR \
                       harvest) independently names the same byte SELF_TAG = \
                       0x80|keynum on an independent segment's first \
                       definition, 0 on an ANOSEG continuation -- a v6 finding. \
                       This task's own scan of all 307 v5 corpus definitions \
                       (145 files) found this byte reads 0 in every one \
                       (matching harvest 1's key18.py, 229/229 on an older \
                       corpus snapshot), so it is modeled here as a plain byte \
                       that is always zero on every v5 file measured, not as a \
                       self-tag: v5 never exercises whatever mechanism sets it \
                       in v6",
            },
            Field {
                name: "acs_page_high",
                index: Some(n),
                at: base + at::ACS_PAGE_HIGH,
                len: 1,
                cite: "harvest 4 SS1a (acs.rs::PAGE_HIGH_IN_KEY) -- v6-only; \
                       always 0 on the 16 v5 ACS-flagged keys measured there",
            },
            Field {
                name: "acs_page_low",
                index: Some(n),
                at: base + at::ACS_PAGE_LOW,
                len: 1,
                cite: "harvest 4 SS1a (acs.rs::PAGE_LOW_IN_KEY) -- v6-only; \
                       always 0 on v5",
            },
            Field {
                name: "acs_page_mid",
                index: Some(n),
                at: base + at::ACS_PAGE_MID,
                len: 1,
                cite: "harvest 4 SS1a (acs.rs::PAGE_MID_IN_KEY) -- v6-only; \
                       always 0 on v5; the three bytes assemble discontiguously \
                       as byte@0x19<<16 | byte@0x1b<<8 | byte@0x1a, not a u16 \
                       at 0x1a",
            },
            Field {
                name: "extended",
                index: Some(n),
                at: base + at::EXTENDED,
                len: 1,
                cite: "harvest 4 SS1a/SS1c (keys.rs:61-62 at::EXTENDED) -- the \
                       segment's data-type code, when ATTRIBUTES bit 8 \
                       (EXTENDED) is set",
            },
            Field {
                name: "null_value",
                index: Some(n),
                at: base + at::NULL_VALUE,
                len: 1,
                cite: "harvest 4 SS1a (keys.rs:63-72 at::NULL_VALUE) -- the byte \
                       value this key's null-omission rule tests against, \
                       located by an oracle A/B test (null 0x00 vs 0xaa) that \
                       also incidentally moved FCR offset 0x68",
            },
        ]
    }
}

/// The pre-v6 family's fixed-portion fields, `0x00` through [`at::FIXED_LEN`]
/// (`0x110`). Transcribed from harvest 1's field table; do not re-derive an
/// offset from anything else, and do not add a field the table does not
/// list.
fn v5_fixed() -> Vec<Field> {
    vec![
        Field {
            name: "lead",
            index: None,
            at: at::LEAD,
            len: 4,
            cite: "generation.rs::identify; W32MKDE_decompiled.c:33906-33917 \
                   -- zero for the whole v5 family",
        },
        Field {
            name: "page_gen",
            index: None,
            at: at::PAGE_GEN,
            len: 2,
            cite: "W32MKDE_decompiled.c:33532; pages.rs:23-27; corpus \
                   (measure_gaps.py, joined.py) -- the ordinary per-page \
                   modification counter every page carries, applied to page \
                   0 like any other; 27 distinct values across 112 files, no \
                   correlation to record/page/key count",
        },
        Field {
            name: "version",
            index: None,
            at: at::VERSION,
            len: 2,
            cite: "W32MKDE_decompiled.c:33914-33920; generation.rs -- \
                   abs(i16) is 0x300/0x400/0x500; no corpus file uses the \
                   negative encoding (negcheck.py: 0/112)",
        },
        Field {
            name: "page_size",
            index: None,
            at: at::PAGE_SIZE,
            len: 2,
            cite: "W32MKDE_decompiled.c:33928-33934; lib.rs::at::PAGE",
        },
        Field {
            name: "companion_selector",
            index: None,
            at: at::COMPANION_SELECTOR,
            len: 1,
            cite: "W32MKDE_decompiled.c:33505-33506,38038-38118; corpus -- \
                   Btrieve's pre-image/companion-file selector byte, 0 on \
                   every one of the 112 corpus files",
        },
        Field {
            name: "lock_flag",
            index: None,
            at: at::LOCK_FLAG,
            len: 1,
            cite: "W32MKDE_decompiled.c:34201-34210; corpus -- bit 0x40 \
                   transaction/lock flag, always 0 across the corpus",
        },
        Field {
            name: "unknown_0c",
            index: None,
            at: at::UNKNOWN_0C,
            len: 4,
            cite: "create.rs::fcr::UNKNOWN_0C; corpus (measure_gaps.py, \
                   joined.py) -- NOWHERE (0xffffffff) on 110 of 112 corpus \
                   files, 251 (as a long) on the byte-identical TTIHORSS \
                   pair; true meaning unknown",
        },
        Field {
            name: "free",
            index: None,
            at: at::FREE,
            len: 4,
            cite: "pages.rs::fcr::FREE -- v5 free-list head, a record \
                   position or NOWHERE when the list is empty",
        },
        Field {
            name: "keys",
            index: None,
            at: at::KEYS,
            len: 2,
            cite: "lib.rs::at::KEYS; keys.rs:640-654,701-733 -- count of \
                   keys, not of on-disk key/segment definitions",
        },
        Field {
            name: "reclen",
            index: None,
            at: at::RECLEN,
            len: 2,
            cite: "lib.rs::at::RECLEN -- logical record length, what a \
                   module's struct matches",
        },
        Field {
            name: "physical",
            index: None,
            at: at::PHYSICAL,
            len: 2,
            cite: "lib.rs::at::PHYSICAL; keys.rs::at::CHAIN doc; create.rs \
                   -- physical record length: logical + 8 when any key \
                   permits duplicates, else equal to reclen",
        },
        Field {
            name: "records",
            index: None,
            at: at::RECORDS,
            len: 4,
            cite: "lib.rs::at::RECORDS_HIGH; lib.rs::at::RECORDS_LOW -- one \
                   4-byte high-word-first long, not two separate 2-byte \
                   halves; the same correction harvest 0 ruling 5 applied \
                   to HIGHEST/ALLOCATED",
        },
        Field {
            name: "highest",
            index: None,
            at: at::HIGHEST,
            len: 4,
            cite: "harvest 0 ruling 5 -- one 4-byte high-word-first long \
                   spanning 0x1e..0x22; pages.rs::fcr::HIGHEST declared only \
                   its always-zero (in this corpus) high half and \
                   create.rs::fcr::ALLOCATED separately named its low half",
        },
        Field {
            name: "data_page_count",
            index: None,
            at: at::DATA_PAGE_COUNT,
            len: 4,
            cite: "create.rs::fcr::DATA_PAGE_COUNT; corpus -- reads exactly \
                   1 on all 112 corpus files without exception, up to a \
                   19,606-page file; not a live data-page count",
        },
        Field {
            name: "pages",
            index: None,
            at: at::PAGES,
            len: 4,
            cite: "pages.rs::fcr::PAGES; W32MKDE_decompiled.c:33531 -- total \
                   pages in the file, equals file size / page_size in every \
                   corpus file measured",
        },
        Field {
            name: "page_usable",
            index: None,
            at: at::PAGE_USABLE,
            len: 2,
            cite: "create.rs::fcr::PAGE_USABLE; corpus (usable_detail.py) -- \
                   live remaining space on the currently active insertion \
                   page, not the constant page_size - 6 create.rs assumed; \
                   stored as read, never recomputed",
        },
        Field {
            name: "lock_transaction",
            index: None,
            at: at::LOCK_TRANSACTION,
            len: 2,
            cite: "W32MKDE_decompiled.c:33532-33533,34201-34210; corpus -- \
                   unconditionally zeroed by the engine for v5; always 0 \
                   across the corpus",
        },
        Field {
            name: "negative_version_a",
            index: None,
            at: at::NEGATIVE_VERSION_A,
            len: 4,
            cite: "W32MKDE_decompiled.c:33566-33571 -- read only when the \
                   version word at offset 6 uses the negative encoding; no \
                   corpus file does (negcheck.py: 0/112), so this field is \
                   completely untested by round trip",
        },
        Field {
            name: "negative_version_b",
            index: None,
            at: at::NEGATIVE_VERSION_B,
            len: 4,
            cite: "W32MKDE_decompiled.c:33566-33571 -- same gate as \
                   negative_version_a",
        },
        Field {
            name: "negative_version_c",
            index: None,
            at: at::NEGATIVE_VERSION_C,
            len: 1,
            cite: "W32MKDE_decompiled.c:33566-33571 -- same gate",
        },
        Field {
            name: "negative_version_d",
            index: None,
            at: at::NEGATIVE_VERSION_D,
            len: 1,
            cite: "W32MKDE_decompiled.c:33566-33571 -- same gate; together \
                   with lock_transaction and negative_version_a/b this tiles \
                   the entire 0x2c-0x38 range this crate previously called \
                   one opaque gap",
        },
        Field {
            name: "variable_tag",
            index: None,
            at: at::VARIABLE_TAG,
            len: 1,
            cite: "W32MKDE_decompiled.c:18134-18139; acs.rs (corpus \
                   confirmation) -- 0xff for a variable-length-record file, \
                   0x00 otherwise; lib.rs::at::VARIABLE_MARK modeled this as \
                   a single byte, which happens to read the right yes/no \
                   answer but not the field's true 4-byte width",
        },
        Field {
            name: "variable_subflag",
            index: None,
            at: at::VARIABLE_SUBFLAG,
            len: 1,
            cite: "corpus (variable_dump.py, measure_gaps.py) -- 0xff on \
                   every virgin (0-record) variable file, 0x00 on every \
                   non-variable file and every populated variable file \
                   measured; the flip's meaning is not identified",
        },
        Field {
            name: "variable_highest",
            index: None,
            at: at::VARIABLE_HIGHEST,
            len: 2,
            cite: "corpus (variable_dump.py) -- 0xffff (sentinel) on virgin \
                   variable files, close to pages-1 on populated ones; the \
                   v5 analogue of v6's pages::fcr::VARIABLE_HEAD",
        },
        Field {
            name: "acs_name",
            index: None,
            at: at::ACS_NAME,
            len: at::ACS_NAME_LEN,
            cite: "acs.rs::NAME_IN_FCR; corpus -- space/NUL-padded alternate \
                   collating sequence name, zero when the file declares \
                   none",
        },
        Field {
            name: "reserved_44",
            index: None,
            at: at::RESERVED_44,
            len: at::RESERVED_44_LEN,
            cite: "corpus (big_gap.py); decompile: nothing found -- always \
                   zero across all 112 corpus files",
        },
        Field {
            name: "write_counter_68",
            index: None,
            at: at::WRITE_COUNTER_68,
            len: 2,
            cite: "create.rs::keys::at::NULL_VALUE doc; corpus (x68.py, \
                   big_gap.py) -- zero on 107 of 112 files, nonzero only on \
                   the 5 majormud-nt (32-bit NT) files",
        },
        Field {
            name: "reserved_6a",
            index: None,
            at: at::RESERVED_6A,
            len: at::RESERVED_6A_LEN,
            cite: "corpus (big_gap.py) -- always zero across all 112 corpus \
                   files",
        },
        Field {
            name: "usrflgs",
            index: None,
            at: at::USRFLGS,
            len: 2,
            cite: "lib.rs::at::USRFLGS; W32MKDE_decompiled.c:18104-18122; \
                   corpus -- bit 0 is variable-length records; bits 0x0020, \
                   0x0400, 0x0800 are forced off when the engine builds a \
                   v5 file",
        },
        Field {
            name: "variable_page_capacity",
            index: None,
            at: at::VARIABLE_PAGE_CAPACITY,
            len: 1,
            cite: "W32MKDE_decompiled.c:18116-18117; corpus \
                   (variable_dump.py) -- page_size / 20 for a variable file, \
                   zero for every non-variable file",
        },
        Field {
            name: "reserved_109",
            index: None,
            at: at::RESERVED_109,
            len: 1,
            cite: "corpus -- always zero; plausibly the unused high byte of \
                   a value that never exceeds 255 (page_size <= 4096)",
        },
        Field {
            name: "acs_page_pointer",
            index: None,
            at: at::ACS_PAGE_POINTER,
            len: 4,
            cite: "acs.rs::PAGE_IN_FCR; corpus -- ACS logical page pointer, \
                   word-swapped; unreliable on v5 (CLASSADS.DAT and \
                   EMAIL.DAT read zero here while genuinely holding an ACS \
                   block)",
        },
        Field {
            name: "reserved_10e",
            index: None,
            at: at::RESERVED_10E,
            len: at::RESERVED_10E_LEN,
            cite: "corpus (measure_gaps.py) -- always zero across the \
                   corpus",
        },
    ]
}

/// Byte offsets of the v6 control record's fixed-portion fields, `0x00`
/// through `0x110` -- harvest 2's field table, transcribed directly (one
/// name per row) so `v6_fixed`, `read::v6_control_record` and
/// `emit::write_v6_fixed_portion` share this one set of offsets rather than
/// three copies of the same magic numbers. `PAGE_SIZE` and `VERSION` are
/// listed for [`v6_fixed`]'s own tiling, but the runtime side of this crate
/// reads them through [`super::generation::Identified`], not through
/// `model::V6ControlRecord` -- the same exclusion v5's `at` module makes for
/// `lead`/`version`/`page_size`.
pub mod v6 {
    pub const GENERATION: usize = 0x04;
    pub const RESERVED_06: usize = 0x06;
    pub const PAGE_SIZE: usize = 0x08;
    pub const RESERVED_0A: usize = 0x0a;
    pub const RESERVED_0C: usize = 0x0c;
    pub const FREE: usize = 0x10;
    pub const KEYS: usize = 0x14;
    pub const RECLEN: usize = 0x16;
    pub const PHYSICAL: usize = 0x18;
    pub const RECORDS: usize = 0x1a;
    pub const HIGHEST: usize = 0x1e;
    pub const RESERVED_20: usize = 0x20;
    pub const SENTINEL_22: usize = 0x22;
    pub const SENTINEL_24: usize = 0x24;
    pub const PAGES: usize = 0x26;
    pub const RESERVED_2A: usize = 0x2a;
    pub const RESERVED_2C: usize = 0x2c;
    pub const RESERVED_2C_LEN: usize = 12;
    pub const VARIABLE_MARK: usize = 0x38;
    pub const ACS_NAME: usize = 0x3c;
    pub const ACS_NAME_LEN: usize = 8;
    pub const RESERVED_44: usize = 0x44;
    pub const RESERVED_44_LEN: usize = 6;
    pub const VERSION: usize = 0x4a;
    pub const USAGE_4C: usize = 0x4c;
    pub const INDEX_ALLOC_4E: usize = 0x4e;
    pub const MIRROR_50: usize = 0x50;
    pub const USAGE_52: usize = 0x52;
    pub const RESERVED_54: usize = 0x54;
    pub const STAMP_56: usize = 0x56;
    pub const STAMP_56_LEN: usize = 4;
    pub const RESERVED_5A: usize = 0x5a;
    pub const RESERVED_5A_LEN: usize = 6;
    pub const RESERVED_60: usize = 0x60;
    pub const RESERVED_60_LEN: usize = 8;
    pub const WRITE_COUNTER: usize = 0x68;
    pub const RESERVED_6A: usize = 0x6a;
    pub const RESERVED_6A_LEN: usize = 8;
    pub const RESERVED_72: usize = 0x72;
    pub const RESERVED_72_LEN: usize = 10;
    pub const RESERVED_7C: usize = 0x7c;
    pub const RESERVED_7C_LEN: usize = 20;
    pub const RESERVED_90: usize = 0x90;
    pub const RESERVED_90_LEN: usize = 12;
    pub const FREE_V6: usize = 0x9c;
    pub const VARIABLE_HEAD: usize = 0xa0;
    pub const RESERVED_A4: usize = 0xa4;
    pub const RESERVED_A4_LEN: usize = 48;
    pub const RESERVED_D4: usize = 0xd4;
    pub const RESERVED_D4_LEN: usize = 44;
    pub const RESERVED_100: usize = 0x100;
    pub const RESERVED_100_LEN: usize = 6;
    pub const RESERVED_106: usize = 0x106;
    pub const RESERVED_106_LEN: usize = 4;
    pub const ACS_PAGE: usize = 0x10a;
    pub const RESERVED_10E: usize = 0x10e;
    pub const RESERVED_10E_LEN: usize = 2;

    /// End of the harvested fixed portion: `0x00..FIXED_LEN` tiles
    /// completely, every byte cited, and this is where the (shared, see
    /// `super::key_descriptor`) key/segment definition array begins.
    pub const FIXED_LEN: usize = 0x110;
}

/// The v6 family's fixed fields, `0x00` through [`v6::FIXED_LEN`] (`0x110`).
/// Transcribed from harvest 2's field table (Task 15); do not re-derive an
/// offset from anything else, and do not add a field the table does not
/// list. 43 fields (harvest 2's 42 rows, with `0x22` split in two), tiling
/// exactly -- 18 fully understood and cited, 19
/// constant and reproducible but of unresolved semantic meaning, 3
/// (`USAGE_4C`, the `INDEX_ALLOC_4E`/`MIRROR_50`/`USAGE_52` group and
/// `STAMP_56`) usage-dependent with a virgin-file baseline but no confirmed
/// live-growth formula -- see this module's own doc comment.
fn v6_fixed() -> Vec<Field> {
    vec![
        Field {
            name: "lead",
            index: None,
            at: 0,
            len: 4,
            cite: "W32MKDE FUN_00435970: `*param_1 == 0x4346` (\"FC\") selects v6",
        },
        Field {
            name: "generation",
            index: None,
            at: v6::GENERATION,
            len: 2,
            cite: "harvest 2 'FCR shadowing' -- the shadow pair's own generation \
                   counter, page-relative 0x04 on both physical pages 0 and 1; \
                   higher wins, a tie is refused (0 of 500 corpus files have \
                   ever tied). Same byte offset v5 calls page_gen, a different \
                   role.",
        },
        Field {
            name: "reserved_06",
            index: None,
            at: v6::RESERVED_06,
            len: 2,
            cite: "harvest 2 field table (0x06) -- constant 0x0000 on all 226 \
                   unique live copies measured",
        },
        Field {
            name: "page_size",
            index: None,
            at: v6::PAGE_SIZE,
            len: 2,
            cite: "W32MKDE FUN_00435970: u16 at 8, non-zero, <= 0x1000, multiple \
                   of 0x200",
        },
        Field {
            name: "reserved_0a",
            index: None,
            at: v6::RESERVED_0A,
            len: 2,
            cite: "harvest 2 field table (0x0a) -- constant 0x0000 on all 226 \
                   live copies; earlier drafts of the harvest measured this \
                   varying 0x0000/0x4000 from reading stale page-0 copies of \
                   files whose live copy is page 1 -- against the live copy \
                   it is constant (harvest 2 'Zero' section)",
        },
        Field {
            name: "reserved_0c",
            index: None,
            at: v6::RESERVED_0C,
            len: 4,
            cite: "harvest 2 field table (0x0c) -- constant 0xffffffff on all \
                   226 live copies",
        },
        Field {
            name: "free",
            index: None,
            at: v6::FREE,
            len: 4,
            cite: "harvest 2 field table (0x10) -- v5's free-list-head slot; v6 \
                   always reads 0xffffffff here ('no free slots', forever), \
                   226/226",
        },
        Field {
            name: "keys",
            index: None,
            at: v6::KEYS,
            len: 2,
            cite: "harvest 2 field table (0x14) -- count of distinct keys, not \
                   of on-disk key/segment definitions; a segmented key still \
                   counts once (MULTIACS.DAT: KEYS=3, 4 definitions)",
        },
        Field {
            name: "reclen",
            index: None,
            at: v6::RECLEN,
            len: 2,
            cite: "harvest 2 field table (0x16) -- logical record length",
        },
        Field {
            name: "physical",
            index: None,
            at: v6::PHYSICAL,
            len: 2,
            cite: "harvest 2 field table (0x18) -- physical (on-disk) record \
                   slot length",
        },
        Field {
            name: "records",
            index: None,
            at: v6::RECORDS,
            len: 4,
            cite: "harvest 2 field table (0x1a) -- record count, one 4-byte \
                   high-word-first long; 0 on virgin files, 26720 on \
                   wccmp002.vir's live copy",
        },
        Field {
            name: "highest",
            index: None,
            at: v6::HIGHEST,
            len: 2,
            cite: "harvest 2 field table (0x1e) -- v5 semantics (highest page \
                   number in use); v6 behaviour on a populated file is \
                   unmeasured -- every sampled live copy, including the \
                   26,720-record wccmp002.vir, reads 0 (GAP 8). Unlike v5, \
                   this is a plain 2-byte u16 here, not half of a 4-byte long \
                   -- the other half is reserved_20, a separate field",
        },
        Field {
            name: "reserved_20",
            index: None,
            at: v6::RESERVED_20,
            len: 2,
            cite: "harvest 2 field table (0x20) -- constant 0x0000 on all 226 \
                   live copies; v5's analogous position (ALLOCATED, 'keys+1') \
                   is not reused here -- v6's index-page-count-shaped field \
                   lives at 0x4e instead (CONTRADICTIONS item 2)",
        },
        Field {
            name: "sentinel_22",
            index: None,
            at: v6::SENTINEL_22,
            len: 2,
            cite: "harvest 2 field table (0x22) / GAP 1 -- constant 0xffff on \
                   all 226 live copies",
        },
        Field {
            name: "sentinel_24",
            index: None,
            at: v6::SENTINEL_24,
            len: 2,
            cite: "harvest 2 field table (0x22) / GAP 1 -- constant on all 226 \
                   live copies; the raw bytes are `01 00`, so read little- \
                   endian (this crate's own convention for a plain u16 -- see \
                   canvas.rs's module doc) the value is 0x0001, not the \
                   harvest prose's own 0x0100/256 gloss, which reads the two \
                   bytes in file order rather than swapping them. Transcribed \
                   as the measured bytes, not the harvest's arithmetic on \
                   them; the field's meaning is unresolved either way",
        },
        Field {
            name: "pages",
            index: None,
            at: v6::PAGES,
            len: 4,
            cite: "harvest 2 'PAGES, worked' -- LOGICAL page count (the control \
                   record itself counts as logical page 0), NOT the physical \
                   page count: wccmp002.vir reads 13,572 here against 13,607 \
                   physical pages, the difference being the fixed control- \
                   record + allocation-table shadow overhead. One 4-byte \
                   high-word-first long, like v5's PAGES",
        },
        Field {
            name: "reserved_2a",
            index: None,
            at: v6::RESERVED_2A,
            len: 2,
            cite: "harvest 2 field table (0x2a) -- constant 0x0000 on all 226 \
                   live copies; v5's PAGE_USABLE lived here but v6 does not \
                   appear to reuse it",
        },
        Field {
            name: "reserved_2c",
            index: None,
            at: v6::RESERVED_2C,
            len: v6::RESERVED_2C_LEN,
            cite: "harvest 2 field table (0x2c) -- constant all-zero on all \
                   226 live copies; the 12 bytes v5 splits into \
                   lock_transaction/negative_version_a/b/c/d",
        },
        Field {
            name: "variable_mark",
            index: None,
            at: v6::VARIABLE_MARK,
            len: 4,
            cite: "harvest 2 field table (0x38); acs.rs -- 0x00000000 for a \
                   fixed-length file, 0xffffffff for a variable-length one",
        },
        Field {
            name: "acs_name",
            index: None,
            at: v6::ACS_NAME,
            len: v6::ACS_NAME_LEN,
            cite: "harvest 2 field table (0x3c); acs.rs -- name of the file's \
                   (first) alternate collating sequence, space/NUL-padded, \
                   all-zero when none declared",
        },
        Field {
            name: "reserved_44",
            index: None,
            at: v6::RESERVED_44,
            len: v6::RESERVED_44_LEN,
            cite: "harvest 2 field table (0x44) -- constant all-zero on all \
                   226 live copies",
        },
        Field {
            name: "version",
            index: None,
            at: v6::VERSION,
            len: 2,
            cite: "W32MKDE FUN_00435970: abs(i16 at 0x4a) is 0x600, 0x610 or \
                   0x620",
        },
        Field {
            name: "usage_4c",
            index: None,
            at: v6::USAGE_4C,
            len: 2,
            cite: "harvest 2 field table (0x4c) / GAP 2 -- always equals the \
                   field at 0x50 (226/226); 1 on every virgin file regardless \
                   of key count, grows with real usage (up to 14 observed); \
                   exact meaning (candidate: index-tree depth) unresolved",
        },
        Field {
            name: "index_alloc_4e",
            index: None,
            at: v6::INDEX_ALLOC_4E,
            len: 2,
            cite: "harvest 2 field table (0x4e) / GAP 2 -- on a virgin file, \
                   8*(nkeys+1) (16 for 1 key, 24 for 2, 32 for 3); grows with \
                   usage (up to 188 observed); plausibly index pages \
                   allocated for the file's key structures, unconfirmed",
        },
        Field {
            name: "mirror_50",
            index: None,
            at: v6::MIRROR_50,
            len: 2,
            cite: "harvest 2 field table (0x50) / GAP 2 -- identical to \
                   usage_4c in all 226 samples",
        },
        Field {
            name: "usage_52",
            index: None,
            at: v6::USAGE_52,
            len: 2,
            cite: "harvest 2 field table (0x52) / GAP 2 -- on a virgin file, \
                   2*nkeys+1 (3 for 1 key, 5 for 2, 7 for 3); grows with usage",
        },
        Field {
            name: "reserved_54",
            index: None,
            at: v6::RESERVED_54,
            len: 2,
            cite: "harvest 2 field table (0x54) -- constant 0x0000 on all 226 \
                   live copies",
        },
        Field {
            name: "stamp_56",
            index: None,
            at: v6::STAMP_56,
            len: v6::STAMP_56_LEN,
            cite: "harvest 2 field table (0x56) / GAP 3 -- high entropy, 86 \
                   distinct leading bytes across 226 files; not a DOS packed \
                   date/time (decodes to implausible years, e.g. 2045); \
                   probably a creation stamp or per-file unique value, \
                   unresolved",
        },
        Field {
            name: "reserved_5a",
            index: None,
            at: v6::RESERVED_5A,
            len: v6::RESERVED_5A_LEN,
            cite: "harvest 2 field table (0x5a) -- constant 0xffffffffffff \
                   on all 226 live copies",
        },
        Field {
            name: "reserved_60",
            index: None,
            at: v6::RESERVED_60,
            len: v6::RESERVED_60_LEN,
            cite: "harvest 2 field table (0x60) -- constant \
                   ff ff 00 ff ff ff 00 00 on all 226 live copies",
        },
        Field {
            name: "write_counter",
            index: None,
            at: v6::WRITE_COUNTER,
            len: 2,
            cite: "harvest 2 field table (0x68); keys.rs:63-72 doc -- a \
                   modification/write counter, constant on virgin files, \
                   grows with real activity (87 distinct values across 226 \
                   live copies)",
        },
        Field {
            name: "reserved_6a",
            index: None,
            at: v6::RESERVED_6A,
            len: v6::RESERVED_6A_LEN,
            cite: "harvest 2 field table (0x6a) / GAP 4 -- 0x00 in the \
                   overwhelming majority; rare nonzero, uncorrelated with \
                   anything else measured",
        },
        Field {
            name: "reserved_72",
            index: None,
            at: v6::RESERVED_72,
            len: v6::RESERVED_72_LEN,
            cite: "harvest 2 field table (0x72) / GAP 4 -- mostly zero, small \
                   nonzero variations uncorrelated with key count, reclen, \
                   ACS or variable-length",
        },
        Field {
            name: "reserved_7c",
            index: None,
            at: v6::RESERVED_7C,
            len: v6::RESERVED_7C_LEN,
            cite: "harvest 2 field table (0x7c) -- constant all-zero on all \
                   226 live copies",
        },
        Field {
            name: "reserved_90",
            index: None,
            at: v6::RESERVED_90,
            len: v6::RESERVED_90_LEN,
            cite: "harvest 2 field table (0x90) -- constant 00 x8 then \
                   ffffffff on all 226 live copies",
        },
        Field {
            name: "free_v6",
            index: None,
            at: v6::FREE_V6,
            len: 4,
            cite: "harvest 2 field table (0x9c); pages.rs::fcr::FREE_V6 -- \
                   free-list head, a record position (logical page * page \
                   length + slot offset), not a NOWHERE-style sentinel; 0 on \
                   a virgin file's single page, real positions on populated \
                   ones",
        },
        Field {
            name: "variable_head",
            index: None,
            at: v6::VARIABLE_HEAD,
            len: 4,
            cite: "harvest 2 field table (0xa0); pages.rs::fcr::VARIABLE_HEAD \
                   -- head of the variable free-space chain; 0xff00ffff \
                   (NO_VARIABLE_HEAD) when none",
        },
        Field {
            name: "reserved_a4",
            index: None,
            at: v6::RESERVED_A4,
            len: v6::RESERVED_A4_LEN,
            cite: "harvest 2 field table (0xa4) / GAP 6 -- constant on all \
                   226 live copies regardless of page size, key count, ACS or \
                   variable-length: the 12-byte unit \
                   00 ff ff ff ff ff ff ff ff ff ff ff repeated 4 times; role \
                   beyond a fixed template unconfirmed",
        },
        Field {
            name: "reserved_d4",
            index: None,
            at: v6::RESERVED_D4,
            len: v6::RESERVED_D4_LEN,
            cite: "harvest 2 field table (0xd4) / GAP 7 -- constant all-zero \
                   on 224/226; 2 files (ELWDIPCV.DAT's sibling pair, byte \
                   0xd8 specifically) read 0x11 instead of 0x00, unexplained",
        },
        Field {
            name: "reserved_100",
            index: None,
            at: v6::RESERVED_100,
            len: v6::RESERVED_100_LEN,
            cite: "harvest 2 field table (0x100) -- constant all-zero on all \
                   226 live copies",
        },
        Field {
            name: "reserved_106",
            index: None,
            at: v6::RESERVED_106,
            len: v6::RESERVED_106_LEN,
            cite: "harvest 2 field table (0x106) / GAP 5 -- 0x00000000 on \
                   207/226; four other exact values on 19 files, uncorrelated \
                   with ACS presence, key count or page size",
        },
        Field {
            name: "acs_page",
            index: None,
            at: v6::ACS_PAGE,
            len: 4,
            cite: "harvest 2 field table (0x10a); acs.rs::PAGE_IN_FCR -- \
                   logical page of the file's (first) ACS table, \
                   word-swapped long, 0 when none declared; v6-only \
                   predicate, unreliable on v5",
        },
        Field {
            name: "reserved_10e",
            index: None,
            at: v6::RESERVED_10E,
            len: v6::RESERVED_10E_LEN,
            cite: "harvest 2 field table (0x10e) -- constant all-zero on all \
                   226 live copies",
        },
    ]
}

/// The control record is the whole of page 0. The engine reads only its
/// first 512 bytes before it knows anything (`W32MKDE_decompiled.c:33874`),
/// but that is a minimum readable header, not the record's length: page_size
/// is a field *inside* this record, the crate's own writer has always
/// allocated page_size bytes for it, and the format's 24-segment ceiling
/// needs 0x3e0 bytes of key definitions. See harvest 1.
///
/// `key_descriptors` is how many key/segment definitions this particular
/// file's array actually holds -- data-dependent, read from the file by
/// walking `KEYS` ANOSEG-terminated runs (`read::file` does the walking; see
/// `format::fcr::key_descriptor`'s module doc for why the count cannot be a
/// formula). Ignored for a v6 file, whose key array this task does not
/// describe.
#[must_use]
pub fn layout(generation: Generation, page_size: usize, key_descriptors: usize) -> Layout {
    let mut fields = if generation.is_v6() { v6_fixed() } else { v5_fixed() };

    // Both families now describe the same shape past their fixed portion
    // (`at::FIXED_LEN` / `v6::FIXED_LEN`, both `0x110`): one
    // `key_descriptor::fields(n)` group per on-disk definition -- the same
    // 30-byte, `ANOSEG`-chained structure for both, per harvest 2's own
    // field table -- then whatever bytes remain, up to `page_size`, as one
    // named tail field.
    for n in 0..key_descriptors {
        fields.extend(key_descriptor::fields(n));
    }
    let after_definitions = key_descriptor::base(key_descriptors);
    if page_size > after_definitions {
        fields.push(Field {
            name: if generation.is_v6() { "page_tail" } else { "page_zero_tail" },
            index: None,
            at: after_definitions,
            len: page_size - after_definitions,
            cite: if generation.is_v6() {
                "harvest 2 'Definition-offset trailer, worked' + GAP 9 -- this \
                 region is a fixed-position array of little-endian u16s, one \
                 per consumed definition, each holding that definition's own \
                 absolute byte offset, followed by trailing zero padding; its \
                 exact capacity (whether it reserves SEGMAX=24 entries always \
                 or only as many as the file's key count needs) is not \
                 determined by this harvest (GAP 9) -- decomposing it into \
                 named fields is the next task's job, not this one's"
            } else {
                "harvest 1 tail_check.py (112/112 v5 corpus files: every \
                 byte from the end of the last actual key/segment \
                 definition to the end of the page is zero); re-measured \
                 for Task 13 across all 145 currently-identified v5 \
                 corpus files (143/145 confirmed; the 2 exceptions -- \
                 wccitems.nu1 and its sibling -- hold genuine leftover \
                 record prose here (Task 13), so this region is unused \
                 space carried verbatim, not an invariant this crate \
                 enforces -- see model::File::page_zero_tail)"
            },
        });
    }

    Layout {
        what: if generation.is_v6() {
            "v6 file control record"
        } else {
            "pre-v6 file control record"
        },
        len: page_size,
        fields,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every generation's control record must be described completely. This is
    /// the assertion that makes "no opaque bytes" real: a byte nobody has
    /// described fails here, whether or not a corpus file exercises it.
    #[test]
    fn every_generation_describes_its_whole_control_record() {
        for generation in [
            Generation::V5R3,
            Generation::V5R4,
            Generation::V5R5,
            Generation::V600,
            Generation::V610,
            Generation::V620,
        ] {
            let layout = layout(generation, 512, 0);
            assert_eq!(
                layout.tiling_fault(),
                None,
                "{generation:?}'s control record has an undescribed or \
                 overlapping range"
            );
        }
    }

    /// Every field carries the evidence that established it. A field nobody
    /// can cite is a guess, and this is what makes guesses visible.
    #[test]
    fn every_field_is_cited() {
        for generation in [Generation::V5R4, Generation::V600] {
            for field in &layout(generation, 512, 0).fields {
                assert!(
                    !field.cite.trim().is_empty(),
                    "{generation:?} field {} has no citation",
                    field.name
                );
            }
        }
    }

    /// The fields the engine's own open path reads must be present and at the
    /// offsets it reads them from -- see W32MKDE FUN_00435970.
    #[test]
    fn the_fields_the_engine_checks_are_where_it_checks_them() {
        let v5 = layout(Generation::V5R4, 512, 0);
        let version = v5
            .fields
            .iter()
            .find(|f| f.name == "version")
            .expect("v5 describes its version field");
        assert_eq!((version.at, version.len), (6, 2));

        let v6 = layout(Generation::V600, 512, 0);
        let version = v6
            .fields
            .iter()
            .find(|f| f.name == "version")
            .expect("v6 describes its version field");
        assert_eq!((version.at, version.len), (0x4a, 2));

        for generation in [Generation::V5R4, Generation::V600] {
            let l = layout(generation, 512, 0);
            let page = l
                .fields
                .iter()
                .find(|f| f.name == "page_size")
                .expect("page size is described");
            assert_eq!((page.at, page.len), (8, 2), "{generation:?}");
        }
    }

    /// A layout function that ignores its generation would pass every tiling
    /// test ever written, because both families tile. This is the assertion
    /// that can tell them apart: the engine reads the version word at 6 for
    /// one family and at 0x4a for the other, so the descriptions must differ.
    #[test]
    fn the_two_families_do_not_share_a_layout() {
        let v5 = layout(Generation::V5R4, 512, 0);
        let v6 = layout(Generation::V600, 512, 0);
        let at = |l: &Layout, name: &str| {
            l.fields.iter().find(|f| f.name == name).map(|f| f.at)
        };
        assert_eq!(at(&v5, "version"), Some(6));
        assert_eq!(at(&v6, "version"), Some(0x4a));
        assert_ne!(
            at(&v5, "version"),
            at(&v6, "version"),
            "the families must not share one description"
        );
    }

    /// The control record is the whole of page 0, so its description is as
    /// long as the file says its pages are -- not a constant 512.
    #[test]
    fn the_control_record_is_as_long_as_a_page() {
        for page_size in [512usize, 1024, 1536, 2048, 4096] {
            let l = layout(Generation::V5R4, page_size, 0);
            assert_eq!(l.len, page_size, "page_size {page_size}");
            assert_eq!(
                l.tiling_fault(),
                None,
                "a {page_size}-byte control record must still tile"
            );
        }
    }

    /// The fixed portion (`0x00..0x110`) must be fully described for v5 --
    /// no field in that range may carry a "NOT YET HARVESTED" citation. Past
    /// `0x110`, key/segment definitions and (conditionally) `page_zero_tail`
    /// are now harvested too, but this test only concerns the fixed portion.
    #[test]
    fn the_v5_fixed_portion_has_no_not_yet_harvested_fields() {
        let l = layout(Generation::V5R4, 512, 0);
        for field in &l.fields {
            if field.at < at::FIXED_LEN {
                assert!(
                    !field.cite.contains("NOT YET HARVESTED"),
                    "{} at {:#x} is inside the fixed portion and must be \
                     harvested: {}",
                    field.name,
                    field.at,
                    field.cite
                );
            }
        }
    }

    /// Task 15: the v6 fixed portion (`0x00..0x110`) must be fully described
    /// too -- no field in that range may carry a "NOT YET HARVESTED"
    /// citation. `page_tail` (past `0x110`) is explicitly excepted: the
    /// definition-offset trailer it covers is the next task's work.
    #[test]
    fn the_v6_fixed_portion_has_no_not_yet_harvested_fields() {
        for generation in [Generation::V600, Generation::V610, Generation::V620] {
            let l = layout(generation, 512, 0);
            for field in &l.fields {
                if field.at < v6::FIXED_LEN {
                    assert!(
                        !field.cite.contains("NOT YET HARVESTED"),
                        "{generation:?} field {} at {:#x} is inside the v6 \
                         fixed portion and must be harvested: {}",
                        field.name,
                        field.at,
                        field.cite
                    );
                }
            }
        }
    }

    /// `v6_fixed` is exactly 43 fields tiling `0x00..0x110` -- harvest 2's
    /// own field table has 42 offset-addressed rows there, and this crate
    /// splits its one two-value row (`0x22`, "constant `0xffff` then
    /// `0x0100`") into `sentinel_22`/`sentinel_24`, two named fields instead
    /// of one, since a `Field` has no way to say "two values live here." A
    /// regression here (a merged or split field) would still tile if the
    /// merge happened to preserve total width, so this pins the row count
    /// independently of the tiling check. Tested against `v6_fixed` itself,
    /// not `layout`, so `page_tail` (added only when `page_size` leaves
    /// room for it) cannot be confused with a 44th fixed-portion field.
    #[test]
    fn the_v6_fixed_portion_is_forty_three_fields() {
        assert_eq!(v6_fixed().len(), 43, "harvest 2's 42-row field table, with 0x22 split in two");
    }

    /// MULTIACS.DAT's real shape (harvest 2's own worked example): 3 keys,
    /// realized as 4 key/segment definitions because the second key has two
    /// segments chained by ANOSEG. The v6 layout with exactly that many
    /// definitions must still tile -- proof that v6 reuses
    /// `key_descriptor::fields` rather than needing its own copy.
    #[test]
    fn a_v6_layout_shaped_like_multiacs_dat_tiles_completely() {
        let l = layout(Generation::V610, 4096, 4);
        assert_eq!(
            l.tiling_fault(),
            None,
            "the v6 fixed portion plus MULTIACS.DAT's four key/segment \
             definitions plus page_tail must tile a 4096-byte control record \
             exactly"
        );
    }

    /// A v6 layout with several key descriptors must tile for a range of
    /// counts, not just the one MULTIACS.DAT happens to need.
    #[test]
    fn a_v6_layout_with_several_key_descriptors_tiles_completely() {
        for n in [0, 1, 2, 4] {
            let l = layout(Generation::V600, 4096, n);
            assert_eq!(l.tiling_fault(), None, "{n} definitions must tile");
        }
    }

    /// `records` and `highest` are each one 4-byte high-word-first long, not
    /// two 2-byte halves -- the exact correction harvest 0 ruling 5 made.
    /// (v5 only -- v6's `highest` is a plain 2-byte field, a real
    /// difference from v5 this harvest found, not an oversight.)
    #[test]
    fn records_and_highest_are_each_one_long_not_two_halves() {
        let l = layout(Generation::V5R4, 512, 0);
        for name in ["records", "highest"] {
            let matches: Vec<&Field> = l.fields.iter().filter(|f| f.name == name).collect();
            assert_eq!(matches.len(), 1, "{name} must be exactly one field");
            assert_eq!(matches[0].len, 4, "{name} must be 4 bytes wide");
        }
    }

    /// USRACC.DAT's real shape: 1 key, 1 definition. The layout with exactly
    /// that one definition must tile completely -- fixed portion, one
    /// definition's worth of fields, then page_zero_tail out to 512.
    #[test]
    fn a_layout_with_one_key_descriptor_tiles_completely() {
        let l = layout(Generation::V5R3, 512, 1);
        assert_eq!(
            l.tiling_fault(),
            None,
            "the fixed portion plus one key descriptor plus page_zero_tail must \
             tile a 512-byte control record exactly"
        );
    }

    /// A layout with more than one definition must still tile -- this is
    /// what a segmented key or a multi-key file needs, and 94 of 145 v5
    /// corpus files have more than one definition (this task's own
    /// measurement).
    #[test]
    fn a_layout_with_several_key_descriptors_tiles_completely() {
        for n in [0, 1, 2, 4] {
            let l = layout(Generation::V5R4, 512, n);
            assert_eq!(l.tiling_fault(), None, "{n} definitions must tile");
        }
    }

    /// Every field of key_descriptor::fields(n) must carry index Some(n) --
    /// this is what lets a tiling fault name `root[3]` instead of `root`.
    /// Mutation: setting `index: None` on any of these fields must turn this
    /// test red.
    #[test]
    fn key_descriptor_fields_carry_their_repetition_index() {
        for n in [0usize, 1, 3, 23] {
            let fields = key_descriptor::fields(n);
            assert_eq!(fields.len(), 16, "one entry per named sub-field of a 30-byte definition");
            for field in &fields {
                assert_eq!(
                    field.index,
                    Some(n),
                    "{} must carry index Some({n}), not {:?}",
                    field.name,
                    field.index
                );
            }
        }
    }

    /// `key_descriptor::fields` must tile its own 30 bytes exactly, in
    /// isolation from the rest of the control record -- this is the
    /// per-definition version of the whole-structure tiling check.
    #[test]
    fn one_key_descriptor_tiles_its_own_thirty_bytes() {
        let base = key_descriptor::base(2);
        let layout = Layout { what: "key descriptor", len: base + key_descriptor::WIDTH, fields: {
            let mut f = vec![Field { name: "prefix", index: None, at: 0, len: base, cite: "test" }];
            f.extend(key_descriptor::fields(2));
            f
        }};
        assert_eq!(layout.tiling_fault(), None);
    }
}
