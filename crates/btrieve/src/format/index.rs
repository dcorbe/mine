//! An index page's content past its 6-byte header (`format::page`): the
//! entry array harvest 4 SS4/SS4a describes.
//!
//! The fixed portion -- `count`, `rightmost`, `leftmost` -- is three named
//! fields at fixed offsets, described the same way `format::page`'s header
//! is. The entry array past it repeats a runtime-determined number of times
//! (like `format::fcr::key_descriptor`'s definition array), so it has no
//! static `Field` list of its own: `read::read_index_page` and
//! `emit::write_index_pages` describe it field by field, one `Canvas::put`/
//! `put_long` call per field, the same way `DataPage`'s slots are described
//! directly rather than through a `Layout`.

use super::Field;

/// Byte offsets, from the start of the page (i.e. including the 6-byte
/// header `format::page` owns), of the fixed portion past that header.
pub mod at {
    /// Number of entries this node holds.
    pub const COUNT: usize = 0x06;
    /// The child holding keys greater than the last entry's, or `NOWHERE`
    /// on a leaf -- a high-word-first long.
    pub const RIGHTMOST: usize = 0x08;
    /// The child holding keys less than the first entry's; `NOWHERE` or `0`
    /// on a leaf -- a high-word-first long.
    pub const LEFTMOST: usize = 0x0c;
    /// Where the entry array itself begins.
    pub const ENTRIES: usize = 0x10;
}

/// One entry's total byte width: `key_length + 8`, or `+12` when the key
/// permits duplicates (harvest 4 SS4) -- the same value the key descriptor
/// itself stores at its own `ENTRY_SIZE`
/// (`format::fcr::key_descriptor::at::ENTRY_SIZE`), confirmed to agree in
/// every case measured.
#[must_use]
pub fn entry_width(key_length: usize, duplicates: bool) -> usize {
    key_length + if duplicates { 12 } else { 8 }
}

/// The fixed portion's three named fields, cited. Measured directly against
/// `USRACC.DAT`'s own page 1 when this task was dispatched: `count` 2,
/// `rightmost` `NOWHERE`, `leftmost` `NOWHERE`.
#[must_use]
pub fn fields() -> Vec<Field> {
    vec![
        Field {
            name: "count",
            index: None,
            at: at::COUNT,
            len: 2,
            cite: "harvest 4 SS4 (pages.rs:721, decode_index_page) -- LE u16, \
                   number of entries this node holds; USRACC.DAT page 1 reads \
                   2, matching its 2 real records",
        },
        Field {
            name: "rightmost",
            index: None,
            at: at::RIGHTMOST,
            len: 4,
            cite: "harvest 4 SS4 (pages.rs:679-688, INDEX_HEADER doc) -- \
                   high-word-first long; the child holding keys greater than \
                   the last entry's, or NOWHERE on a leaf",
        },
        Field {
            name: "leftmost",
            index: None,
            at: at::LEFTMOST,
            len: 4,
            cite: "harvest 4 SS4 (pages.rs:688; pages.rs:905-911, \
                   IndexPage::leaf; create.rs:579-591, build_root_page) -- \
                   high-word-first long; the child holding keys less than \
                   the first entry's; NOWHERE or 0 on a leaf, and a virgin \
                   file writes 0 here specifically, never NOWHERE",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::Layout;

    /// The fixed portion (`count`/`rightmost`/`leftmost`) tiles exactly the
    /// ten bytes between the page header and the entry array -- shifted so
    /// `Layout` (which measures from 0) can check it in isolation from the
    /// 6-byte header `format::page` owns.
    #[test]
    fn the_fixed_portion_tiles_the_ten_bytes_before_the_entry_array() {
        let shifted: Vec<Field> =
            fields().into_iter().map(|f| Field { at: f.at - at::COUNT, ..f }).collect();
        let layout = Layout {
            what: "v5 index page fixed portion",
            len: at::ENTRIES - at::COUNT,
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

    /// `entry_width` matches harvest 4 SS4's own formula -- and USRACC.DAT's
    /// own measured `entry_size` (18, `key_length` 10, no duplicates).
    #[test]
    fn entry_width_matches_the_key_descriptors_own_entry_size() {
        assert_eq!(entry_width(10, false), 18, "USRACC.DAT's own key");
        assert_eq!(entry_width(10, true), 22, "the same key, if it permitted duplicates");
    }
}
