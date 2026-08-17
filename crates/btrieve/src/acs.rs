//! Alternate collating sequences: the 256-byte translation table a key may
//! be indexed through instead of raw byte order.
//!
//! Forty-five of the 470 files the capability census swept declare one, and
//! were refused outright before this module existed. The layout here is read
//! off the genuine engine's decompile
//! (`re/btrieve_ghidra/exports/W32MKDE_decompiled.c`) and then confirmed
//! against every one of those 45 files.
//!
//! # The block
//!
//! A block is 265 bytes: a tag byte, an 8-byte name, then the 256-byte table.
//! It sits at offset 6 within its page, after the ordinary 6-byte
//! page header -- so the table itself begins 15 bytes in. The engine confirms
//! that base independently by indexing its own cached copy at `+0xf`
//! (`:15461-15473`), and `6 + 1 + 8 == 15`.
//!
//! Two tag bytes are accepted, `0xac` and `0xad` (`:18000`). A decoder
//! admitting only `0xac` would refuse a file the engine reads.
//!
//! # Finding it differs by version, and this is not a style choice
//!
//! **v6** tags the page: an ACS page carries the type byte `'A'` in byte 1 of
//! its header, which is what the engine allocates it with (`:18430`) and
//! fetches it by (`:15381`). Scanning for that type needs no page arithmetic
//! and no allocation-table resolution, and it finds *all* the blocks -- which
//! matters, because a file may carry **more than one**. `MULTIACS.DAT` holds
//! `ALLCAPS` on physical page 4 and `LOWER` on 5, one per ACS-flagged key, and
//! `Create` validates *N* blocks at a stride of `0x109` (265) bytes
//! (`:17993-18020`).
//!
//! **v5** cannot be scanned that way: its pages carry no type byte at all.
//! The block is at a fixed position instead -- physical page [`V5_PAGE`] (1),
//! same `+6` offset within it. Measured on all 13 v5 files in the corpus that
//! declare a sequence, with no exceptions: `CLASSADS.DAT` and `HVSXPLAY.VIR`
//! at 518 (512-byte pages), `EMAIL.DAT` and `TTIHORSS.DAT` at 1030 (1024),
//! `INFCTMAP.DAT` at 1542 (1536). An exhaustive independent byte scan of all
//! 45 files for a tag-plus-name-plus-table shape found no genuine block that
//! these two rules miss.
//!
//! The two rules cannot collide: a v6 file holds unrelated bytes at page 1
//! offset 6 (tag `0x00` on `ELWEROT.DAT` and `GALTELA.DAT`), and a v5 file has
//! no `'A'`-typed page to find.
//!
//! # [`declared`] is a v6 predicate, and must not gate the search
//!
//! `FCR+0x10a` holds the first block's *logical* page, word-swapped, and is the
//! engine's own "this file has one" test (`:12417`). It is reliable on v6, and
//! it is **not** reliable on v5: `CLASSADS.DAT` and `EMAIL.DAT` both read zero
//! there while genuinely holding a block on page 1. Gate the search on a key
//! actually declaring `flag::ALT_COLLATING` instead, and use this only as
//! corroboration.
//!
//! `FCR+0x3b` is *not* an ACS tag, though an earlier reading of this format
//! said so. `0x38`-`0x3b` is the variable-record mark region: `00000000` on
//! non-variable `CLASSADS.DAT`, `ffffffff` on variable `MULTIACS.DAT`. The
//! 8-byte name at `0x3c` is real -- `Create` writes `0x3c`, `0x40` and `0x10a`
//! together (`:18430`) and clears all three together (`:21294-21309`).

/// A file's alternate collating sequence: a name and the 256-byte map from a
/// raw byte to the byte its key is actually ordered by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acs {
    /// The sequence's name, space- or NUL-padded. Only two distinct tables
    /// appear across the whole corpus, under three names: `UPPER`, `GALCAPS`
    /// and `ALLCAPS` all name the same uppercase fold.
    pub name: [u8; 8],
    /// Indexed by the raw byte; yields the byte to compare in its place.
    pub table: [u8; 256],
}

impl Acs {
    /// The byte `b` collates as.
    #[must_use]
    pub const fn fold(&self, b: u8) -> u8 {
        self.table[b as usize]
    }
}

/// Both tag bytes the engine accepts (`W32MKDE_decompiled.c:18000`).
pub const TAGS: [u8; 2] = [0xac, 0xad];

/// The page type byte a v6 ACS page carries, in byte 1 of its header.
pub const PAGE_TYPE: u8 = b'A';

/// Physical page holding a **v5** file's block. v5 pages carry no type byte,
/// so there is nothing to scan for and the position is fixed instead.
pub const V5_PAGE: u32 = 1;

/// Byte offset, within a page, of the block -- past the 6-byte page header.
const BLOCK: usize = 6;

/// Byte offset, within a page header, of the page type byte.
const TYPE: usize = 1;

/// Length of a block: tag, 8-byte name, 256-byte table. The stride `Create`
/// validates successive blocks at (`:17993-18020`).
pub const LEN: usize = 1 + 8 + 256;

/// Byte offset, within the control record, of the sequence's name.
const NAME_IN_FCR: usize = 0x3c;

/// Byte offset, within the control record, of the first block's logical page,
/// stored word-swapped. Also the engine's own "has an ACS" predicate.
const PAGE_IN_FCR: usize = 0x10a;

/// Whether `page` is a v6 ACS page, by the only thing that says so: its type.
///
/// Always false for a v5 page, which carries no type byte -- see this module's
/// header for why that is a fact about the format rather than a limitation.
#[must_use]
pub fn is_acs_page(page: &[u8]) -> bool {
    page.get(TYPE) == Some(&PAGE_TYPE)
}

/// Decode the block at offset 6 within `page`, whatever found it.
///
/// The same layout serves both versions, so the v5 page-1 read and the v6
/// type scan share this one decoder.
pub fn decode(page: &[u8]) -> Result<Acs, String> {
    let block = page
        .get(BLOCK..BLOCK + LEN)
        .ok_or_else(|| format!("a {}-byte page cannot hold an ACS block", page.len()))?;

    let tag = block[0];
    if !TAGS.contains(&tag) {
        return Err(format!(
            "{tag:#04x} is not an ACS tag byte; the engine accepts 0xac and 0xad"
        ));
    }

    let mut name = [0u8; 8];
    name.copy_from_slice(&block[1..9]);
    let mut table = [0u8; 256];
    table.copy_from_slice(&block[9..9 + 256]);
    Ok(Acs { name, table })
}

/// The first block's logical page, as the control record stores it: a
/// word-swapped `u32`, high half first.
///
/// `MULTIACS.DAT` holds `00 00 01 00` here, which is logical page 1 -- read as
/// a plain little-endian `u32` it would be 65536.
#[must_use]
pub fn logical_page(fcr: &[u8]) -> u32 {
    let Some(bytes) = fcr.get(PAGE_IN_FCR..PAGE_IN_FCR + 4) else {
        return 0;
    };
    let high = u32::from(u16::from_le_bytes([bytes[0], bytes[1]]));
    let low = u32::from(u16::from_le_bytes([bytes[2], bytes[3]]));
    high << 16 | low
}

/// Whether the control record points at a block.
///
/// **v6 only.** Reliable there; not on v5, where `CLASSADS.DAT` and
/// `EMAIL.DAT` read zero while holding a real block. Never gate the search on
/// this -- see this module's header.
#[must_use]
pub fn declared(fcr: &[u8]) -> bool {
    logical_page(fcr) != 0
}

/// Byte offset, within a 30-byte key definition, of the low byte of the
/// logical page holding that key's table.
pub const PAGE_LOW_IN_KEY: usize = 0x1a;

/// Byte offset of the middle byte of that page number.
pub const PAGE_MID_IN_KEY: usize = 0x1b;

/// Byte offset of the high byte of that page number.
///
/// Out of order on purpose -- see [`page_in_key`].
pub const PAGE_HIGH_IN_KEY: usize = 0x19;

/// The logical page of the table a **v6** key collates through, read out of its
/// key definition.
///
/// This is what tells one of a file's tables from another, and it is a page
/// number rather than an index into the file's blocks. The engine assembles it
/// from three *discontiguous* bytes of the definition
/// (`W32MKDE_decompiled.c:15369-15371`):
///
/// ```text
/// local_4 = CONCAT13(byte@0x1b, CONCAT12(byte@0x1a, byte@0x19))
/// ```
///
/// and hands that straight to the same generic page-resolve routine every
/// ordinary data and index page goes through, with page type `'A'` (`:15381`).
/// Working that routine's word-swap (`:14276`) back through gives the page as
/// `byte@0x19 << 16 | byte@0x1b << 8 | byte@0x1a` -- so the *low* byte is at
/// `0x1a` and the *high* byte at `0x19`, with `0x1b` in the middle. `Create`
/// writes the same three bytes in the same order (`:18392-18394`).
///
/// **Not an ordinal.** Every table in this repository's corpus sits at logical
/// page 1 or 2, in the same order the pages appear, so an index into the block
/// list would fit the bytes equally well. The decompile settles it: an ACS page
/// comes from the *generic* page allocator (`:18442`, the same one `'D'`, `'E'`
/// and `'V'` pages use), so tables are only ever at small consecutive pages
/// because a fresh file allocates them first. On any file where that is not
/// true, an ordinal would bind the wrong table.
///
/// Zero for v5, whose key definitions leave all three bytes unset -- the engine
/// takes that version's single table from `FCR+0x10a` instead and never looks
/// here (`:15364-15367`). Measured: all 16 v5 ACS-flagged keys in the corpus
/// read zero, and all 23 v6 ones read nonzero.
#[must_use]
pub fn page_in_key(definition: &[u8]) -> u32 {
    let byte = |at: usize| definition.get(at).copied().map_or(0, u32::from);
    byte(PAGE_HIGH_IN_KEY) << 16 | byte(PAGE_MID_IN_KEY) << 8 | byte(PAGE_LOW_IN_KEY)
}

/// One of a file's tables, and the logical page a key names it by.
#[derive(Debug, Clone)]
pub struct Table {
    /// The logical page the block was found on, which is what a v6 key
    /// definition stores. **Zero for v5**, whose definitions leave that field
    /// unset and whose files carry exactly one table -- so registering it under
    /// zero makes one matching rule serve both versions instead of two.
    pub page: u32,
    /// The table itself.
    pub acs: std::sync::Arc<Acs>,
}

/// The sequence's name as the control record records it, if there is one.
#[must_use]
pub fn named_in(fcr: &[u8]) -> Option<[u8; 8]> {
    let bytes = fcr.get(NAME_IN_FCR..NAME_IN_FCR + 8)?;
    let mut name = [0u8; 8];
    name.copy_from_slice(bytes);
    Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case_fold() -> [u8; 256] {
        let mut t = [0u8; 256];
        for (i, s) in t.iter_mut().enumerate() {
            *s = i as u8;
        }
        for c in b'a'..=b'z' {
            t[c as usize] = c - 32;
        }
        t
    }

    /// An ACS page as every measured file lays one out: type `'A'` in byte 1
    /// of the page header, then the block at byte 6.
    fn acs_page(tag: u8, name: &[u8; 8], table: &[u8; 256]) -> Vec<u8> {
        let mut page = vec![0u8; 512];
        page[1] = PAGE_TYPE;
        page[6] = tag;
        page[7..15].copy_from_slice(name);
        page[15..271].copy_from_slice(table);
        page
    }

    #[test]
    fn an_acs_page_is_recognised_by_its_type_byte() {
        let page = acs_page(0xac, b"GALCAPS ", &case_fold());
        assert!(is_acs_page(&page));

        let mut other = page.clone();
        other[1] = b'D';
        assert!(!is_acs_page(&other), "a data page is not an ACS page");
    }

    #[test]
    fn the_table_starts_fifteen_bytes_into_the_page() {
        let page = acs_page(0xac, b"GALCAPS ", &case_fold());
        let acs = decode(&page).expect("a well-formed block");
        assert_eq!(&acs.name, b"GALCAPS ");
        assert_eq!(acs.fold(b'a'), b'A');
        assert_eq!(acs.fold(b'A'), b'A');
        assert_eq!(acs.fold(b'0'), b'0');
    }

    /// The engine accepts two tag bytes. Admitting only `0xac` would refuse a
    /// file it reads -- `W32MKDE_decompiled.c:18000`.
    ///
    /// The two bytes are written out literally rather than iterated from
    /// [`TAGS`]. Looping over the constant under test is no test at all:
    /// shrinking `TAGS` to `[0xac]` shrinks the loop with it and the assertion
    /// still passes. Measured -- that mutation survived the first draft of this
    /// test.
    #[test]
    fn both_tag_bytes_the_engine_accepts_are_accepted() {
        for tag in [0xac_u8, 0xad_u8] {
            let page = acs_page(tag, b"ALLCAPS\0", &case_fold());
            decode(&page).unwrap_or_else(|e| panic!("tag {tag:#04x}: {e}"));
        }
    }

    #[test]
    fn a_page_without_a_known_tag_is_refused() {
        let page = acs_page(0x00, b"GALCAPS ", &case_fold());
        let e = decode(&page).expect_err("no recognised tag");
        assert!(e.contains("0xac") || e.contains("tag"), "{e}");
    }

    #[test]
    fn a_short_page_is_refused_rather_than_panicking() {
        for len in [0usize, 6, 14, 270] {
            decode(&vec![0u8; len]).expect_err("too short to hold a block");
        }
    }

    /// `0x38`-`0x3b` is the variable-record mark, not an ACS tag. The name at
    /// `0x3c` is real, and `FCR+0x10a` is the engine's own predicate.
    #[test]
    fn the_control_record_declares_an_acs_by_its_page_pointer() {
        let mut fcr = vec![0u8; 512];
        fcr[0x3c..0x44].copy_from_slice(b"ALLCAPS\0");
        assert!(!declared(&fcr), "a name alone does not declare one");

        // Stored word-swapped, like every page pointer in this format.
        fcr[0x10c..0x10e].copy_from_slice(&1u16.to_le_bytes());
        assert!(declared(&fcr), "a non-zero page pointer does");
        assert_eq!(named_in(&fcr), Some(*b"ALLCAPS\0"));
    }

    /// The variable-record mark must not be mistaken for a declaration:
    /// `MULTIACS.DAT` carries `ffffffff` there and `CLASSADS.DAT` zeros.
    #[test]
    fn the_variable_record_mark_does_not_declare_an_acs() {
        let mut fcr = vec![0u8; 512];
        fcr[0x38..0x3c].copy_from_slice(&[0xff; 4]);
        assert!(!declared(&fcr), "0x38-0x3b is the variable mark");
    }

    /// The pointer is word-swapped, so the *high* half at `0x10a` counts too.
    /// A decoder reading only `0x10c` would miss a file whose first ACS sits
    /// past logical page 65535 -- and one reading a plain little-endian `u32`
    /// would read `MULTIACS.DAT`'s `00 00 01 00` as 65536 rather than 1.
    #[test]
    fn the_page_pointer_is_word_swapped() {
        let mut fcr = vec![0u8; 512];
        // MULTIACS.DAT's actual bytes: logical page 1.
        fcr[0x10a..0x10e].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]);
        assert_eq!(logical_page(&fcr), 1, "word-swapped, so this is 1");
        assert!(declared(&fcr));
    }

    /// A v5 file keeps its block on physical page 1 and its pages carry no
    /// type byte at all, so [`is_acs_page`] cannot find it and must not claim
    /// to. Measured on `CLASSADS.DAT`: tag `0xac` at 518 with 512-byte pages.
    #[test]
    fn a_v5_page_carries_no_type_byte_yet_still_decodes() {
        let mut page = vec![0u8; 512];
        page[6] = 0xac;
        page[7..15].copy_from_slice(b"UPPER   ");
        page[15..271].copy_from_slice(&case_fold());

        assert!(
            !is_acs_page(&page),
            "a v5 page has no type byte, so the v6 scan cannot see it"
        );
        let acs = decode(&page).expect("the block itself is laid out identically");
        assert_eq!(&acs.name, b"UPPER   ");
        assert_eq!(acs.fold(b'a'), b'A');
    }

    /// The block sits at the same in-page offset in both versions -- measured
    /// across all 45 corpus files that declare a sequence, v5 and v6 alike:
    /// `offset mod page_size` was 6 in all 39 genuine occurrences.
    #[test]
    fn the_block_offset_within_a_page_is_the_same_for_both_versions() {
        assert_eq!(BLOCK, 6);
    }

    /// Two of the thirteen v5 files that declare a sequence -- `CLASSADS.DAT`
    /// and `EMAIL.DAT` -- read **zero** at `FCR+0x10a` while genuinely holding
    /// a block on page 1. So [`declared`] is a v6 predicate and must never be
    /// what gates the search; see this module's header.
    ///
    /// The page number is assembled from three *discontiguous* bytes, with the
    /// low byte at `0x1a` and the high byte at `0x19`. Every real file has zero
    /// in `0x19` and `0x1b`, so a decoder that just read the `u16` at `0x1a`
    /// would pass the whole corpus and still be wrong.
    #[test]
    fn a_keys_acs_page_is_three_bytes_and_not_the_u16_at_0x1a() {
        let mut definition = vec![0u8; 0x1e];
        definition[PAGE_HIGH_IN_KEY] = 0x01;
        definition[PAGE_LOW_IN_KEY] = 0x02;
        definition[PAGE_MID_IN_KEY] = 0x03;
        assert_eq!(page_in_key(&definition), 0x01_03_02);

        // The naive reading -- a plain little-endian u16 at 0x1a -- gives this
        // instead, and the two must not be confused.
        assert_ne!(page_in_key(&definition), 0x03_02);
    }

    /// A definition too short to hold the field reads zero rather than panicking.
    #[test]
    fn a_short_key_definition_yields_no_acs_page() {
        for len in [0usize, 0x19, 0x1a, 0x1b] {
            assert_eq!(page_in_key(&vec![0u8; len]), 0);
        }
    }

    #[test]
    fn a_v5_file_may_hold_a_block_while_declaring_nothing_at_the_pointer() {
        let fcr = vec![0u8; 512];
        assert!(
            !declared(&fcr),
            "CLASSADS.DAT and EMAIL.DAT both read 0 here, yet both have an ACS"
        );
    }
}
