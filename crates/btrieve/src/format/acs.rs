//! The alternate collating sequence block (harvest 4 SS6): a 265-byte
//! structure -- a tag byte, an 8-byte name, and a 256-byte translation
//! table -- sitting at byte offset 6 within its page, immediately past the
//! ordinary 6-byte page header (`format::page`). Same layout in both
//! families (harvest 4 SS6, confirmed on `MULTIACS.DAT`'s two v6 blocks and
//! 15 further v5 corpus files this task measured).
//!
//! This module's own content layout (`fields`, [`LEN`]) is shared by both
//! families (`read::read_acs_block` reads a v6 block through the exact
//! same offsets, Task 19) -- what differs is how each family *finds* its
//! block, which this module deliberately does not own:
//!
//! v5 finds its one block a different way than v6 does: not by scanning for
//! a page-type tag (v5 pages carry none), but at a **fixed** physical page,
//! [`V5_PAGE`] -- measured on all 15 v5 corpus files this task found
//! declaring a sequence (harvest 4 SS6a's 13, plus 2 further `.VIR` copies
//! of files harvest 4 already names), same `page_size*1 + 6` offset in every
//! case, no exceptions. `crate::read::resolve_pages` (task 7) already
//! classifies that page as [`crate::model::PageKind::Acs`] by content -- a
//! key descriptor's own `ALT_COLLATING` bit, not the control record's
//! `0x10a` pointer, which harvest 4 SS6a measured unreliable on 2 of those
//! 15 files (`CLASSADS.DAT`, `EMAIL.DAT`, both `V5R3`, both copies): this
//! module only describes the block's *content*, once that page is found.
//!
//! v6 finds its block (or blocks -- `MULTIACS.DAT` has two) by scanning
//! every claimed page for `format::page::v6::TAG_ACS` instead (harvest 4
//! SS6a: v6 pages carry a type tag, so there is no fixed page to trust the
//! way v5's is), which `read::file`'s own v6 branch does directly -- see
//! that function's own doc comment, not this module, for the v6 finding
//! rule.

use super::Field;

/// Byte offsets of the block's fields, **from the start of the page**
/// (i.e. including the 6-byte header `format::page` owns) -- the same
/// convention `format::index::at` uses for an index page's fixed portion,
/// so `read`/`emit` add nothing further to reach them.
pub mod at {
    /// `0xac` or `0xad`, immediately after the ordinary 6-byte page header.
    pub const TAG: usize = 0x06;
    /// The sequence's name, space/NUL-padded.
    pub const NAME: usize = 0x07;
    pub const NAME_LEN: usize = 8;
    /// The 256-byte translation table.
    pub const TABLE: usize = 0x0f;
    pub const TABLE_LEN: usize = 256;
}

/// Total bytes in the block: `tag` (1) + `name` (8) + `table` (256) = 265
/// (harvest 4 SS6).
pub const LEN: usize = 1 + at::NAME_LEN + at::TABLE_LEN;

/// Both tag bytes the engine accepts -- a decoder admitting only `0xac`
/// would refuse a file the engine reads (harvest 4 SS6, decompile
/// `W32MKDE_decompiled.c:18003-18004`, `(char)*puVar20 != -0x54` /
/// `!= -0x53`, i.e. `0xac`/`0xad` as signed bytes). Only one meaning is
/// established.
pub const TAGS: [u8; 2] = [0xac, 0xad];

/// Physical page holding a **v5** file's one block. v5 pages carry no
/// type byte to scan for (unlike v6's `'A'`-tagged pages), so the position
/// is fixed instead -- harvest 4 SS6a, measured on every v5 corpus file
/// this task found declaring a sequence, no exceptions.
pub const V5_PAGE: u32 = 1;

/// The block's three fields, cited to harvest 4 SS6's own table -- offsets
/// relative to the page (see [`at`]'s own doc), so `len` here is measured
/// from `at::TAG`, not from 0.
#[must_use]
pub fn fields() -> Vec<Field> {
    vec![
        Field {
            name: "tag",
            index: None,
            at: at::TAG,
            len: 1,
            cite: "harvest 4 SS6 -- 0xac or 0xad, both accepted, only one \
                   meaning established; decompile \
                   W32MKDE_decompiled.c:18003-18004",
        },
        Field {
            name: "name",
            index: None,
            at: at::NAME,
            len: at::NAME_LEN,
            cite: "harvest 4 SS6 -- space/NUL-padded sequence name, shared \
                   with the control record's own name at FCR 0x3c",
        },
        Field {
            name: "table",
            index: None,
            at: at::TABLE,
            len: at::TABLE_LEN,
            cite: "harvest 4 SS6 -- indexed by raw byte, yields the byte it \
                   collates as",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::Layout;

    /// The block's three fields tile the 265 bytes from `at::TAG` to the
    /// end of `table` exactly -- shifted so `Layout` (which measures from
    /// 0) can check it in isolation from the 6-byte page header, the same
    /// way `format::index`'s own test isolates its fixed portion.
    #[test]
    fn the_block_tiles_completely() {
        let shifted: Vec<Field> =
            fields().into_iter().map(|f| Field { at: f.at - at::TAG, ..f }).collect();
        let layout = Layout { what: "acs_block", len: LEN, fields: shifted };
        assert_eq!(layout.tiling_fault(), None);
    }

    /// Every field carries the evidence that established it.
    #[test]
    fn every_field_is_cited() {
        for field in fields() {
            assert!(!field.cite.trim().is_empty(), "{} has no citation", field.name);
        }
    }
}
