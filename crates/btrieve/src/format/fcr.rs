//! The file control record, described.
//!
//! Page 0 of every Btrieve file. This is the first structure given a complete
//! [`Layout`], and it establishes the pattern every later one follows: named
//! ranges, each cited, tiling the structure with no gaps.
//!
//! # Honest state of this description
//!
//! Only three fields are established by primary evidence today -- the family
//! lead, the version word, and the page size, all read by the engine's own
//! open path at `W32MKDE_decompiled.c:33906-33941`. Everything else in the
//! 512-byte record is described here as a single `undescribed` range so that
//! the layout tiles and the *size* of what remains unknown is visible and
//! shrinking. That range is not an opaque blob in the model's sense: nothing
//! reads or writes it, and `read::file` refuses any file while it exists.
//! Harvesting the remaining fields is the next plan's work, and this range
//! shrinks to nothing as that lands.

use super::generation::Generation;
use super::{Field, Layout};

/// `W32MKDE_decompiled.c:33874` reads page 0 as `0x200` bytes before checking
/// anything -- a minimum readable header, not the record's length. It is,
/// however, as far as any field is harvested today, so it is where the fixed
/// portion below ends and the generic trailing range picks up.
const FIXED_LEN: usize = 512;

/// The pre-v6 family's fixed fields, up to [`FIXED_LEN`]. Task 5 rebuilds this
/// into the full `0x00..0x110` field table from harvest 1; today it is
/// exactly what the crate already knew.
fn v5_fixed() -> Vec<Field> {
    vec![
        Field {
            name: "lead",
            index: None,
            at: 0,
            len: 4,
            cite: "W32MKDE FUN_00435970: `*param_1 == 0` selects the pre-v6 family",
        },
        Field {
            name: "undescribed_4",
            index: None,
            at: 4,
            len: 2,
            cite: "NOT YET HARVESTED -- between the lead and the version word",
        },
        Field {
            name: "version",
            index: None,
            at: 6,
            len: 2,
            cite: "W32MKDE FUN_00435970: abs(i16 at 6) is 0x300, 0x400 or 0x500",
        },
        Field {
            name: "page_size",
            index: None,
            at: 8,
            len: 2,
            cite: "W32MKDE FUN_00435970: u16 at 8, non-zero, <= 0x1000, multiple of 0x200",
        },
        Field {
            name: "undescribed",
            index: None,
            at: 10,
            len: FIXED_LEN - 10,
            cite: "NOT YET HARVESTED -- this range shrinks to nothing before the \
                   round-trip pin can reach 612",
        },
    ]
}

/// The v6 family's fixed fields, up to [`FIXED_LEN`]. Task 5 rebuilds this
/// into the full `0x00..0x110` field table from harvest 1; today it is
/// exactly what the crate already knew.
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
            len: FIXED_LEN - 0x4c,
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
    if page_size > described {
        fields.push(Field {
            name: "page_tail",
            index: None,
            at: described,
            len: page_size - described,
            cite: "NOT YET HARVESTED -- the remainder of page 0. Zero padding \
                   for 94 of 96 large-page v5 files and unexplained content \
                   for 493 of 493 large-page v6 files; see harvest 0 ruling 6",
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
}
