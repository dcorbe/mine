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
/// anything, so the control record is 512 bytes whatever the file's page size.
const FCR_LEN: usize = 512;

static V5_FIELDS: &[Field] = &[
    Field {
        name: "lead",
        at: 0,
        len: 4,
        cite: "W32MKDE FUN_00435970: `*param_1 == 0` selects the pre-v6 family",
    },
    Field {
        name: "undescribed_4",
        at: 4,
        len: 2,
        cite: "NOT YET HARVESTED -- between the lead and the version word",
    },
    Field {
        name: "version",
        at: 6,
        len: 2,
        cite: "W32MKDE FUN_00435970: abs(i16 at 6) is 0x300, 0x400 or 0x500",
    },
    Field {
        name: "page_size",
        at: 8,
        len: 2,
        cite: "W32MKDE FUN_00435970: u16 at 8, non-zero, <= 0x1000, multiple of 0x200",
    },
    Field {
        name: "undescribed",
        at: 10,
        len: FCR_LEN - 10,
        cite: "NOT YET HARVESTED -- this range shrinks to nothing before the \
               round-trip pin can reach 612",
    },
];

static V6_FIELDS: &[Field] = &[
    Field {
        name: "lead",
        at: 0,
        len: 4,
        cite: "W32MKDE FUN_00435970: `*param_1 == 0x4346` (\"FC\") selects v6",
    },
    Field {
        name: "undescribed_4",
        at: 4,
        len: 4,
        cite: "NOT YET HARVESTED -- between the lead and the page size",
    },
    Field {
        name: "page_size",
        at: 8,
        len: 2,
        cite: "W32MKDE FUN_00435970: u16 at 8, non-zero, <= 0x1000, multiple of 0x200",
    },
    Field {
        name: "undescribed_a",
        at: 10,
        len: 0x4a - 10,
        cite: "NOT YET HARVESTED",
    },
    Field {
        name: "version",
        at: 0x4a,
        len: 2,
        cite: "W32MKDE FUN_00435970: abs(i16 at 0x4a) is 0x600, 0x610 or 0x620",
    },
    Field {
        name: "undescribed_b",
        at: 0x4c,
        len: FCR_LEN - 0x4c,
        cite: "NOT YET HARVESTED -- this range shrinks to nothing before the \
               round-trip pin can reach 612",
    },
];

static V5_LAYOUT: Layout = Layout {
    what: "pre-v6 file control record",
    len: FCR_LEN,
    fields: V5_FIELDS,
};

static V6_LAYOUT: Layout = Layout {
    what: "v6 file control record",
    len: FCR_LEN,
    fields: V6_FIELDS,
};

/// The control-record layout for a generation.
///
/// The three v5-family generations share one layout and the three v6 ones
/// share another, because no evidence yet distinguishes the records within a
/// family. When evidence appears -- a v6.1 file's variable-tail allocation
/// table, for instance -- this function is where the split lands, and the
/// signature already takes the specific generation so that split costs no
/// caller a change.
#[must_use]
pub fn layout(generation: Generation) -> &'static Layout {
    if generation.is_v6() {
        &V6_LAYOUT
    } else {
        &V5_LAYOUT
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
            let layout = layout(generation);
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
            for field in layout(generation).fields {
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
        let v5 = layout(Generation::V5R4);
        let version = v5
            .fields
            .iter()
            .find(|f| f.name == "version")
            .expect("v5 describes its version field");
        assert_eq!((version.at, version.len), (6, 2));

        let v6 = layout(Generation::V600);
        let version = v6
            .fields
            .iter()
            .find(|f| f.name == "version")
            .expect("v6 describes its version field");
        assert_eq!((version.at, version.len), (0x4a, 2));

        for generation in [Generation::V5R4, Generation::V600] {
            let page = layout(generation)
                .fields
                .iter()
                .find(|f| f.name == "page_size")
                .expect("page size is described");
            assert_eq!((page.at, page.len), (8, 2), "{generation:?}");
        }
    }
}
