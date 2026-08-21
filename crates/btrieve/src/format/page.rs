//! The ordinary v5 page header: six bytes, on every page of the file except
//! page 0 (the control record, described by [`super::fcr`] instead).
//!
//! # There is no page-*kind* tag, but there is one bit of real signal
//!
//! v6 stamps a 2-byte type (`0x4400` data/index, `0x5600` variable, `0x8000`
//! template) at offset 0 (harvest 3 SS2). v5 has no such tag -- no byte here
//! says "this is an index page" versus "the ACS block" versus "free." An
//! earlier version of this crate's brief over-read that as "the header
//! carries no signal at all" and built `read::resolve_pages` to trust only
//! the control record's own pointers (which key's `ROOT` names a page, the
//! ACS pointer, the free chain), defaulting anything unclaimed to `Data`.
//! That was wrong: bit 15 of the counter word (`DATA_BIT`, below) *is* a
//! real signal -- records versus B-tree node -- and a controller-run
//! measurement found 9,058 v5 pages across 39 corpus files where it is the
//! only thing that says a page is a B-tree node no key root names.
//! `read::resolve_pages` now classifies every page from both the pointers
//! and this bit, and requires them to agree wherever a pointer speaks.
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
/// B-tree node (harvest 3 SS2). This is a real, load-bearing signal, not a
/// decoration -- an earlier version of this crate's brief claimed v5 had no
/// page-type signal at all and treated this bit as something `read` could
/// ignore in favour of the control record's pointers; a controller-run
/// measurement against all 145 v5 corpus files disproved that directly:
/// 9,058 pages across 39 files hold a B-tree node no key root names, and
/// only this bit says so. `crate::model::Page::kind` (`read::resolve_pages`)
/// now classifies every page from *both* this bit and the pointers, and
/// requires them to agree wherever a pointer speaks -- measured 281/281
/// index roots, 15/15 ACS pages, and 22/22 free-chain pages agree with their
/// own `data_bit`, so the agreement check has never yet fired a refusal on
/// real data, but it is enforced, not assumed.
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
