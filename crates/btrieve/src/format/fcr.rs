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
//! Past `0x110`, v5 still has two ranges this crate does not describe:
//! `key_area` (`0x110` up to the historical 512-byte control record) is the
//! key/segment definition table, a later task's work, and genuinely not
//! zero for a populated file -- `read` does not inspect it. Beyond that,
//! when `page_size > 512`, `zero_padding` is measured zero on 94 of 96
//! corpus files with headroom that large, and `read` asserts it. v6's fixed
//! portion is untouched by this task and still has three undescribed
//! ranges (`undescribed_4`, `undescribed_a`, `undescribed_b`); a later task
//! owns it.

use super::generation::{Generation, FCR_MIN};
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

/// The v6 family's fixed fields, up to a fixed 512. Untouched by this task
/// -- a later task rebuilds this into its own full field table.
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
            name: "undescribed_4",
            index: None,
            at: 4,
            len: 4,
            cite: "NOT YET HARVESTED -- between the lead and the page size",
        },
        Field {
            name: "page_size",
            index: None,
            at: 8,
            len: 2,
            cite: "W32MKDE FUN_00435970: u16 at 8, non-zero, <= 0x1000, multiple of 0x200",
        },
        Field {
            name: "undescribed_a",
            index: None,
            at: 10,
            len: 0x4a - 10,
            cite: "NOT YET HARVESTED",
        },
        Field {
            name: "version",
            index: None,
            at: 0x4a,
            len: 2,
            cite: "W32MKDE FUN_00435970: abs(i16 at 0x4a) is 0x600, 0x610 or 0x620",
        },
        Field {
            name: "undescribed_b",
            index: None,
            at: 0x4c,
            len: FCR_MIN - 0x4c,
            cite: "NOT YET HARVESTED -- this range shrinks to nothing before the \
                   round-trip pin can reach 612",
        },
    ]
}

/// The control record is the whole of page 0. The engine reads only its
/// first 512 bytes before it knows anything (`W32MKDE_decompiled.c:33874`),
/// but that is a minimum readable header, not the record's length: page_size
/// is a field *inside* this record, the crate's own writer has always
/// allocated page_size bytes for it, and the format's 24-segment ceiling
/// needs 0x3e0 bytes of key definitions. See harvest 1.
#[must_use]
pub fn layout(generation: Generation, page_size: usize) -> Layout {
    let mut fields = if generation.is_v6() { v6_fixed() } else { v5_fixed() };
    let described = fields.iter().map(|f| f.at + f.len).max().unwrap_or(0);

    if generation.is_v6() {
        // v6's trailing placeholder is untouched by this task -- a later
        // task owns it.
        if page_size > described {
            fields.push(Field {
                name: "page_tail",
                index: None,
                at: described,
                len: page_size - described,
                cite: "NOT YET HARVESTED -- the remainder of page 0. \
                       Unexplained content for 493 of 493 large-page v6 \
                       files; see harvest 0 ruling 6",
            });
        }
    } else {
        // v5: `described` is now at::FIXED_LEN (0x110) -- the fully
        // harvested fixed portion. What historically fit in the first 512
        // bytes past that is the key/segment definition table: not yet
        // harvested (a later task's work), and genuinely non-zero for any
        // populated file, so it is named but not asserted. Only past that
        // 512-byte boundary, when page_size is larger still, is the
        // remainder measured zero (harvest 1's tail_check.py, 94 of 96
        // corpus files with that much headroom) -- that range alone is
        // what `read` asserts.
        let key_area_end = FCR_MIN.min(page_size).max(described);
        if key_area_end > described {
            fields.push(Field {
                name: "key_area",
                index: None,
                at: described,
                len: key_area_end - described,
                cite: "NOT YET HARVESTED -- key/segment definitions (and any \
                       trailing free space up to the historical 512-byte \
                       control record); a later task's work. Genuinely \
                       non-zero for a populated file, so read does not \
                       assert anything about it",
            });
        }
        if page_size > key_area_end {
            fields.push(Field {
                name: "zero_padding",
                index: None,
                at: key_area_end,
                len: page_size - key_area_end,
                cite: "harvest 1 tail_check.py -- zero on 94 of 96 v5 corpus \
                       files with page_size > 512; the 2 exceptions \
                       (wccitems.nu1 and its sibling) are refused by read's \
                       assertion, not accommodated",
            });
        }
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
            let layout = layout(generation, 512);
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
            for field in &layout(generation, 512).fields {
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
        let v5 = layout(Generation::V5R4, 512);
        let version = v5
            .fields
            .iter()
            .find(|f| f.name == "version")
            .expect("v5 describes its version field");
        assert_eq!((version.at, version.len), (6, 2));

        let v6 = layout(Generation::V600, 512);
        let version = v6
            .fields
            .iter()
            .find(|f| f.name == "version")
            .expect("v6 describes its version field");
        assert_eq!((version.at, version.len), (0x4a, 2));

        for generation in [Generation::V5R4, Generation::V600] {
            let l = layout(generation, 512);
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
        let v5 = layout(Generation::V5R4, 512);
        let v6 = layout(Generation::V600, 512);
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
            let l = layout(Generation::V5R4, page_size);
            assert_eq!(l.len, page_size, "page_size {page_size}");
            assert_eq!(
                l.tiling_fault(),
                None,
                "a {page_size}-byte control record must still tile"
            );
        }
    }

    /// The fixed portion (`0x00..0x110`) must be fully described for v5 --
    /// no field in that range may carry a "NOT YET HARVESTED" citation.
    /// What remains undescribed is `key_area` and (conditionally)
    /// `zero_padding`, both past `0x110`.
    #[test]
    fn the_v5_fixed_portion_has_no_not_yet_harvested_fields() {
        let l = layout(Generation::V5R4, 512);
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

    /// `records` and `highest` are each one 4-byte high-word-first long, not
    /// two 2-byte halves -- the exact correction harvest 0 ruling 5 made.
    #[test]
    fn records_and_highest_are_each_one_long_not_two_halves() {
        let l = layout(Generation::V5R4, 512);
        for name in ["records", "highest"] {
            let matches: Vec<&Field> = l.fields.iter().filter(|f| f.name == name).collect();
            assert_eq!(matches.len(), 1, "{name} must be exactly one field");
            assert_eq!(matches[0].len, 4, "{name} must be 4 bytes wide");
        }
    }
}
