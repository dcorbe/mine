//! A variable-length file's fragment/overflow page (harvest 5 SS3.3): the
//! bytes past the ordinary 6-byte page header (`format::page`), on the
//! physical pages a record's continuation chain (SS3.2/SS3.4) actually
//! points at -- distinct from the fixed-length record pages SS1.1 describes,
//! which need nothing new: a record's trailing fragment pointer lives inside
//! the slot bytes `crate::model::DataPage` already stores verbatim.
//!
//! # Which unclaimed, data-bit-clear page is this, versus an `IndexChild`
//!
//! v5 carries no page-type tag (`format::page`'s own module doc), so a page
//! this crate cannot otherwise place is decided by its *content* matching
//! this format's own invariants -- exactly the discipline `read::resolve_pages`
//! already uses for the ACS block. The engine's own read routine
//! (`W32MKDE_decompiled.c:19029-19060`, `FUN_00420850`) checks two things
//! before it will treat a page as this shape at all: the fragment count at
//! `0x0a` is `1..=256`, and the first live entry of the array (skipping any
//! freed, `0xffff` slots) names offset exactly `0x0c` -- anything else is the
//! engine's own status 54, "variable page error". Measured directly against
//! four real corpus files this task was dispatched against
//! (`archive/tooling/wbtrv32/assets/VARIABLE.DAT`, `FW_QSQDB.DAT`,
//! `JABTTQST.DAT`, `wccnt7py/out/wcctext.nu1`): every unclaimed, data-bit-clear
//! page that passes both checks is reachable by following some record's
//! fragment chain (confirmed for `wcctext.nu1`: exactly 2,541 pages pass,
//! matching its own control record's 2,541-record count exactly); every one
//! that fails is a genuine `IndexChild` B-tree node whose own bytes merely
//! overlap this shape's field positions by coincidence (`FW_QSQDB.DAT` page
//! 8: fragment count 3, a plausible value, but its first live entry reads
//! offset 0 -- inside the page's own header -- and it turns out to hold real
//! index key text, "WESTERNS", not fragment bytes). `read::resolve_pages`
//! therefore only ever classifies a page this way when the file's own
//! `usrflgs` bit 0 (`fcr::usrflgs::VARIABLE`) is set -- on a non-variable
//! file every unclaimed data-bit-clear page stays `IndexChild`, unchanged
//! from before this task.

use super::Field;

/// Byte offsets of this page's own two named fields, **from the start of the
/// page** (i.e. including the 6-byte header `format::page` owns) -- the same
/// convention `format::acs::at`/`format::index::at` use.
pub mod at {
    /// The write-side free-space chain link: which variable page with room
    /// left follows this one. Harvest 5 SS3.6's three-state field -- see
    /// [`super::super::model::FragmentPage::free_chain`] for why it is
    /// carried raw rather than decoded into an enum.
    pub const FREE_CHAIN: usize = 0x06;
    /// How many fragments this page holds, `1..=`[`MAX_FRAGMENTS`].
    pub const FRAGMENT_COUNT: usize = 0x0a;
    /// Where fragment 0 always starts, and the whole of this page's own
    /// header -- the engine's own check (`W32MKDE_decompiled.c:19035`): the
    /// first live entry of the array must name exactly this offset, or the
    /// file is refused (status 54, "variable page error").
    pub const FRAGMENTS: usize = 0x0c;
}

/// The most fragments a page can hold (`W32MKDE_decompiled.c:19489`).
pub const MAX_FRAGMENTS: u16 = 256;

/// The entry value marking a freed fragment slot -- skipped by both the
/// "where does fragment 0 start" and "where does fragment N end" scans
/// (harvest 5 SS3.3).
pub const UNUSED_ENTRY: u16 = 0xffff;

/// Bit 15 of a live entry: whether the fragment leads with a 4-byte
/// continuation pointer. **v5 only** -- harvest 5 SS3.4's version gate
/// (`W32MKDE_decompiled.c:19045`): below version `0x600` this bit decides,
/// and this crate does not yet describe a v6 control record at all
/// (`read::file` refuses every v6 file today), so the v6 branch (every
/// fragment carries the pointer unconditionally) is not implemented here.
pub const CONTINUED_BIT: u16 = 0x8000;

/// The low 15 bits of an entry: the fragment's start offset within the page.
pub const OFFSET_MASK: u16 = 0x7fff;

/// Bytes of a continuation pointer, leading a fragment that continues
/// (harvest 5 SS3.2).
pub const POINTER_LEN: usize = 4;

/// Where entry `which` of a page holding `fragment_count` fragments sits --
/// the array grows down from the end of the page, one more entry than there
/// are fragments (harvest 5 SS3.3: entry `fragment_count` itself marks only
/// where free space starts, corresponding to no fragment).
///
/// `None` when `which` is so large the entry would start before byte 0 --
/// a page too small (or a bogus fragment count) to hold it, refused by the
/// caller rather than panicking on the underflow.
#[must_use]
pub fn entry_at(page_size: usize, which: usize) -> Option<usize> {
    page_size.checked_sub(2 * (which + 1))
}

/// A record's fragment pointer: which page, and which fragment on it, a
/// chain continues to (harvest 5 SS3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pointer {
    /// The physical page (v5; this crate reads no v6 control record yet).
    pub page: u32,
    /// The fragment index on that page.
    pub fragment: u8,
}

impl Pointer {
    /// Decode the four bytes that follow a variable-length file's logical
    /// record, or lead a continued fragment: a 24-bit page number,
    /// **scrambled**, and a fragment index.
    ///
    /// # The scramble, and why it is not a plain 24-bit little-endian number
    ///
    /// On-disk byte order is `[page bits 16-23][page bits 0-7][page bits
    /// 8-15][fragment]` -- **not** `[low][mid][high][fragment]`, the order a
    /// plain little-endian 24-bit read would assume. Settled two ways
    /// (harvest 5 SS3.2): the decompiled engine's own unpack,
    /// `FUN_00421c20` at `W32MKDE_decompiled.c:19951`, whose first statement
    /// is `*param_2 = param_1._3_1_` -- the fragment index out of byte 3,
    /// exactly as here; and a real chain continued onto logical page 3 under
    /// genuine Btrieve 6.15 writes, `00 03 00 00`, matching
    /// `Pointer { page: 3, fragment: 0 }.encode()` exactly. A reader that
    /// assumed the unscrambled order would still decode a *plausible* page
    /// number for any file whose page count fits in the low byte -- this is
    /// the single most likely defect harvest 5 warns this task about, and
    /// the one its required mutation targets.
    #[must_use]
    pub fn decode(bytes: [u8; POINTER_LEN]) -> Self {
        Self {
            page: u32::from(bytes[0]) << 16 | u32::from(bytes[1]) | u32::from(bytes[2]) << 8,
            fragment: bytes[3],
        }
    }

    /// The inverse of [`Self::decode`]: `[high][low][mid][fragment]`.
    #[must_use]
    pub fn encode(self) -> [u8; POINTER_LEN] {
        [
            (self.page >> 16) as u8,
            self.page as u8,
            (self.page >> 8) as u8,
            self.fragment,
        ]
    }
}

/// This page's two named fields, cited -- the entry array and fragment
/// bytes past them are not here, the same way `format::index`'s
/// runtime-sized entry array is not in its own `fields()`: `read`/`emit`
/// describe them field by field instead (see `model::FragmentPage`).
#[must_use]
pub fn fields() -> Vec<Field> {
    vec![
        Field {
            name: "free_chain",
            index: None,
            at: at::FREE_CHAIN,
            len: 4,
            cite: "harvest 5 SS3.3/SS3.6 (variable.rs:78-86,242-272) -- \
                   high-word-first long; the write-side free-space chain's \
                   next member, or one of two \"not offered\" sentinels",
        },
        Field {
            name: "fragment_count",
            index: None,
            at: at::FRAGMENT_COUNT,
            len: 2,
            cite: "harvest 5 SS3.3 (variable.rs:101,111; \
                   W32MKDE_decompiled.c:19489) -- LE u16, 1..=256",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::Layout;

    /// The two named fields tile the ten bytes between the ordinary page
    /// header and where fragment 0 begins -- shifted so `Layout` (which
    /// measures from 0) can check it in isolation, the same way
    /// `format::index`'s own test does.
    #[test]
    fn the_named_fields_tile_the_bytes_before_fragment_zero() {
        let shifted: Vec<Field> =
            fields().into_iter().map(|f| Field { at: f.at - at::FREE_CHAIN, ..f }).collect();
        let layout = Layout {
            what: "v5 variable page header (past the ordinary 6-byte header)",
            len: at::FRAGMENTS - at::FREE_CHAIN,
            fields: shifted,
        };
        assert_eq!(layout.tiling_fault(), None);
    }

    /// Every field carries the evidence that established it.
    #[test]
    fn every_field_is_cited() {
        for field in fields() {
            assert!(!field.cite.trim().is_empty(), "{} has no citation", field.name);
        }
    }

    /// The scramble is confirmed two ways in the harvest: the decompile's
    /// own unpack, and a real chain continued onto logical page 3 under
    /// genuine Btrieve 6.15 writes -- `00 03 00 00`.
    #[test]
    fn decode_matches_the_genuine_6_15_continuation_onto_page_3() {
        let p = Pointer::decode([0x00, 0x03, 0x00, 0x00]);
        assert_eq!(p, Pointer { page: 3, fragment: 0 });
        assert_eq!(p.encode(), [0x00, 0x03, 0x00, 0x00]);
    }

    /// The scramble is not symmetric: a page number whose three bytes are
    /// not all equal roundtrips correctly only through the scrambled order.
    /// This is the exact shape an unscrambled `[low][mid][high][fragment]`
    /// reading gets wrong -- it would decode a *different*, still plausible,
    /// page number from the same four bytes.
    #[test]
    fn decode_unscrambles_a_page_number_whose_bytes_are_not_all_equal() {
        // page 0x123456, fragment 7: byte 0 = bits 16-23 (0x12), byte 1 =
        // bits 0-7 (0x56), byte 2 = bits 8-15 (0x34) -- the scrambled order.
        let bytes = [0x12, 0x56, 0x34, 0x07];
        let p = Pointer::decode(bytes);
        assert_eq!(p, Pointer { page: 0x0012_3456, fragment: 7 });
        assert_eq!(p.encode(), bytes);
    }
}
