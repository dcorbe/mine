//! The ordinary v5 page header: six bytes, on every page of the file except
//! page 0 (the control record, described by [`super::fcr`] instead).
//!
//! # There is no page-type tag
//!
//! Both format families carry a tag-free header at this offset in one sense
//! or another, but v6 at least stamps a 2-byte type (`0x4400` data/index,
//! `0x5600` variable, `0x8000` template) at offset 0 (harvest 3 SS2). v5 has
//! **nothing** -- the six bytes are a page number and a counter, full stop.
//! A page's kind is therefore never read off the page itself; it is *derived*
//! from the control record's own pointers (which key's `ROOT` names it, the
//! ACS pointer, the free chain) -- `read::resolve_pages` does that
//! resolution, and this module only describes the six bytes every page
//! actually carries.
//!
//! # The counter word is one field, not two
//!
//! Harvest 3 SS2 names bit 15 `data` and the low 15 bits `stamp`, but they
//! share one on-disk `u16` -- there is no byte boundary between them, so
//! [`Layout`]/[`Field`], which describe byte ranges, can only own the whole
//! two bytes as one field (named `counter` here, echoing the vendor's own
//! "a page number and a counter" framing). `crate::model::Page` is what
//! actually splits it into `data_bit` and `stamp`, the same way
//! `KeyDescriptor` splits one 4-byte `root` field into `key_number` and
//! `root_page` -- see `format::fcr::key_descriptor::fields`'s `root` entry
//! for the precedent this follows.

use super::Field;

/// Byte offsets of the two fields in an ordinary v5 page header.
pub mod at {
    /// The page's own physical number, a high-word-first `long`.
    pub const NUMBER: usize = 0x00;
    /// The `data` bit (15) plus the `stamp` counter (low 15 bits), one
    /// plain little-endian `u16`.
    pub const COUNTER: usize = 0x04;
}

/// Total bytes in the header.
pub const LEN: usize = 6;

/// Bit 15 of the counter word: set iff the page holds records rather than a
/// B-tree node (harvest 3 SS2). `crate::model::Page::kind` is what this
/// crate actually trusts to describe a page's role -- see that type's own
/// documentation for why a page can, in principle, disagree with its own
/// `data_bit` without either being wrong (nothing in the corpus is known to
/// do so; this task did not find or need such a file).
pub const DATA_BIT: u16 = 0x8000;

/// Every named field of the six-byte header, cited.
#[must_use]
pub fn fields() -> Vec<Field> {
    vec![
        Field {
            name: "number",
            index: None,
            at: at::NUMBER,
            len: 4,
            cite: "harvest 3 SS2 (pages.rs:149-181, Header::decode/encode) -- \
                   high-word-first long, the page's own physical page number; \
                   measured against USRACC.DAT's own three pages when this \
                   task was dispatched (page 1 reads 1, page 2 reads 2)",
        },
        Field {
            name: "counter",
            index: None,
            at: at::COUNTER,
            len: 2,
            cite: "harvest 3 SS2 -- one LE u16 carrying two things: bit 15 \
                   `data` (set iff the page holds records rather than a \
                   B-tree node) and the low 15 bits `stamp` (a modification/ \
                   usage counter, preserved not interpreted); pages.rs:152-157, \
                   170-171",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::Layout;

    /// The six-byte header must tile completely -- the whole point of this
    /// module existing at all, rather than reading `number`/`counter`
    /// straight off two magic offsets the way the crate this replaces did.
    #[test]
    fn the_six_byte_header_tiles_completely() {
        let layout = Layout { what: "v5 page header", len: LEN, fields: fields() };
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
