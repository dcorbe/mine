//! A v5 record slot that a delete has walked onto the file's own free chain
//! (harvest 5 SS2.1): the forwarding link a delete leaves, and the zero fill
//! after it. Distinct from `format::variable`'s fragment slots -- this is
//! what an *ordinary*, fixed-length record's own slot becomes once its
//! record is deleted, on any v5 file, not only a variable-length one; and
//! distinct from v6's analogous shape (harvest 5 SS2.2), which this crate
//! does not yet read at all.
//!
//! # What a delete leaves, measured against genuine Pervasive Btrieve 6.15
//!
//! Deleting the record at file offset 3843 in a copy of the real, shipped
//! `WCCCLASS.DAT` (15 records, no prior deletes) left FCR `FREE` (`0x10`)
//! holding exactly 3843, and the 4 bytes *at* offset 3843 held `0x16ce` --
//! the file's own free-list head *before* this delete, high-word-first, the
//! same `long` encoding every other record pointer in this format uses.
//! Every byte of the slot from offset 4 to its end was zero. Confirmed
//! round-trip: a later insert landed back at 3843, and the free-list head
//! advanced to `0x16ce` -- reading the very link this delete wrote
//! (`pages.rs:469-481`, tool `tools/btrieve-oracle/delprobe.c`).
//!
//! This crate's own corpus witness is simpler still: `wccnt7py`/`wccnt7pz`'s
//! byte-identical `wccitem2.vir` copies hold 1,736 live records and exactly
//! one free slot (harvest 5 SS6.2) -- page 591, slot 2 (physical position
//! `0x24f866`), whose forwarding link reads `NOWHERE` because this file's
//! one deletion was also its first. See `crate::model::RecordSlot::Free`
//! for how this crate stores the shape once decoded, and `crate::read`'s
//! own `wccitem2_vir_...` tests for the measurement re-derived directly off
//! the corpus file.

use super::Field;

/// Byte offsets within a freed slot itself (not the page it sits on --
/// `at::LINK` is relative to the slot's own first byte).
pub mod at {
    /// The forwarding link: the free-list head before this delete, or
    /// `NOWHERE` (`0xffff_ffff`) if this slot was the head.
    pub const LINK: usize = 0x00;
    /// Width of the link field. A physical record shorter than this cannot
    /// hold a free-list pointer at all and so cannot appear on the free
    /// chain -- `crate::read`'s own `read_data_page` refuses by name rather
    /// than reading past a slot too short to hold one.
    pub const LINK_LEN: usize = 4;
}

/// Decode a freed slot's forwarding link: the same high-word-first `long`
/// encoding every other record pointer in this format uses (harvest 5
/// SS2.1) -- two little-endian `u16` halves, high half first. **Not** a
/// plain little-endian `u32`, which reads a *different*, still plausible
/// position from the same four bytes with no error to flag it (harvest 1's
/// own "Endianness convention" warning, which this crate's `read::get_long`
/// doc repeats: this exact confusion has cost this project three separate
/// defects already). A dedicated pair here, rather than reusing
/// `read::get_long`/`Canvas::put_long` directly, so this task's own
/// structural claim -- that a free slot's link is *decoded*, not merely
/// copied through -- has one isolated place to be wrong, and one isolated
/// place a mutation can target (see `crate::read`'s own
/// `ttihorbt_dat_free_chain_decodes_to_the_measured_positions` test).
#[must_use]
pub fn decode_link(bytes: [u8; at::LINK_LEN]) -> u32 {
    let high = u16::from_le_bytes([bytes[0], bytes[1]]);
    let low = u16::from_le_bytes([bytes[2], bytes[3]]);
    (u32::from(high) << 16) | u32::from(low)
}

/// The inverse of [`decode_link`]: `[high][low]`, each a little-endian
/// `u16`.
#[must_use]
pub fn encode_link(value: u32) -> [u8; at::LINK_LEN] {
    let mut out = [0u8; at::LINK_LEN];
    out[0..2].copy_from_slice(&((value >> 16) as u16).to_le_bytes());
    out[2..4].copy_from_slice(&(value as u16).to_le_bytes());
    out
}

/// A freed slot's fields, cited -- the `link`, plus whatever remains of the
/// slot's `physical` bytes as zero fill. `physical` is a per-file quantity
/// (`ControlRecord::physical`), not a compile-time constant, so this
/// function -- like `format::variable`'s per-fragment body, or
/// `format::acs`'s trailing `padding` -- takes it as a parameter rather than
/// hardcoding a width; unlike those, a freed slot's *whole* content (both
/// fields) is exactly this module's business, since nothing about a free
/// slot is the calling module's own record format.
#[must_use]
pub fn fields(physical: usize) -> Vec<Field> {
    vec![
        Field {
            name: "link",
            index: None,
            at: at::LINK,
            len: at::LINK_LEN,
            cite: "harvest 5 SS2.1 (pages.rs:469-481, oracle tools/btrieve-oracle/delprobe.c) \
                   -- high-word-first long, the free-list head before this \
                   delete, or NOWHERE",
        },
        Field {
            name: "fill",
            index: None,
            at: at::LINK_LEN,
            len: physical.saturating_sub(at::LINK_LEN),
            cite: "harvest 5 SS2.1 -- oracle-measured all zero on a fresh \
                   delete against genuine Btrieve 6.15; stored verbatim by \
                   this crate rather than assumed, the same discipline \
                   DataPage::slack already applies",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::Layout;

    /// The two fields tile a whole slot exactly, for the corpus witness's
    /// own 1,072-byte physical record (`wccitem2.vir`).
    #[test]
    fn the_named_fields_tile_a_whole_slot() {
        let layout =
            Layout { what: "free_slot", len: 1072, fields: fields(1072) };
        assert_eq!(layout.tiling_fault(), None);
    }

    /// Every field carries the evidence that established it.
    #[test]
    fn every_field_is_cited() {
        for field in fields(1072) {
            assert!(!field.cite.trim().is_empty(), "{} has no citation", field.name);
        }
    }

    /// The oracle's own measurement (harvest 5 SS2.1): deleting the record
    /// at offset 3843 of a real `WCCCLASS.DAT` left `0x16ce` at the freed
    /// slot's own first 4 bytes, high-word-first. Chosen specifically
    /// because it is not byte-order-symmetric: a plain little-endian
    /// misread of the same four bytes (`0x00, 0x00, 0xce, 0x16`) gives
    /// `0x16ce0000`, a different, still-plausible-looking number -- exactly
    /// the failure mode harvest 1 warns about and this task's mutation
    /// targets.
    #[test]
    fn decode_link_matches_the_oracles_wcclass_dat_measurement() {
        let bytes = [0x00, 0x00, 0xce, 0x16];
        assert_eq!(decode_link(bytes), 0x16ce);
        assert_eq!(encode_link(0x16ce), bytes);
        assert_ne!(
            u32::from_le_bytes(bytes),
            0x16ce,
            "a plain little-endian misread must disagree, or this test could \
             not distinguish the two and the mutation below would be vacuous"
        );
    }
}
