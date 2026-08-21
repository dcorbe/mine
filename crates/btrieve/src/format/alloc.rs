//! The v6 allocation ("PP") table: how a logical page id resolves to a
//! physical one.
//!
//! v5 has no indirection at all -- a page number *is* its physical byte
//! offset (`pages::Layout`). v6 breaks that: the only record of where a
//! logical id currently lives is this table, itself shadowed in pairs by
//! the identical generation rule `format::fcr`'s own control-record pair
//! uses (harvest 3 "Generation counters and shadow-copy resolution").
//!
//! # Resolution runs backwards from how a page names itself
//!
//! The engine takes the logical id it wants, computes `n = logical - 1`,
//! and fetches block `n / entries_per_block + 1` slot `n % entries_per_block`
//! -- the 4-byte entry stored there *is* the answer
//! (`W32MKDE_decompiled.c:14276-14286`, harvest 3 "v6: logical id resolved
//! through the allocation table"). It never reads a page's own header to
//! learn what logical id that page holds, so this module's whole job is
//! inverting that arithmetic, never scanning page headers for it.
//!
//! # Where a block's shadow pair lives is a formula, never a scan
//!
//! Block `k` sits at physical `2 + (k - 1) * (entries_per_block + 2)` and
//! the page after it (harvest 3 SS3; confirmed against every multi-block
//! corpus file in `crates/btrieve/src/v6.rs`'s own prior measurement, no
//! exceptions). Real files carry *abandoned* pages that still hold the
//! `"PP"` magic, a stale block index and a higher generation than the live
//! table -- scanning for the magic finds them and picks the wrong one;
//! `read::v6_allocation_table` walks this formula instead, exactly as the
//! engine itself does by fetching a block by number.
//!
//! # One page's layout
//!
//! | offset | width | name | meaning | citation |
//! |---:|---:|---|---|---|
//! | `0x00` | 2 | `magic` | `"PP"`, identifies an allocation-table page | harvest 3 SS3 |
//! | `0x02` | 2 | `block` | 1-based block index, shared by both shadow copies | harvest 3 SS3 |
//! | `0x04` | 2 | `generation` | file-global counter, meaningful only within one block's own pair | harvest 3 SS3/SS5 |
//! | `0x06` | 2 | `reserved_06` | unexplained gap, measured `0x0000` on physical page 2 of all 500 v6 corpus files | harvest 3 SS3 -- **GAP** |
//! | `0x08..` | 4/entry | `entry[n]` | `u16` marker + `u16` physical page, plain (not word-swapped) little-endian | harvest 3 SS3 |
//!
//! Every page size this corpus uses (512, 1024, 1536, 2048, 3584, 4096) is a
//! multiple of 8, so `page_size - 0x08` is always an exact multiple of 4
//! and the entry array tiles the page with no remainder; [`layout`] still
//! adds a trailing field defensively if a page size this corpus has never
//! shown ever leaves one, rather than let [`super::Layout::tiling_fault`]
//! discover a silent gap on some future file.

use super::{Field, Layout};

/// Byte offsets within one allocation-table page.
pub mod at {
    /// `"PP"`, 2 bytes -- identifies this page as allocation-table content.
    pub const MAGIC: usize = 0x00;
    /// 1-based block index, shared by both shadow copies of one block.
    pub const BLOCK: usize = 0x02;
    /// File-global generation counter; meaningful only within one block's
    /// own shadow pair.
    pub const GENERATION: usize = 0x04;
    /// Unexplained 2-byte gap -- measured `0x0000` on all 500 v6 corpus
    /// files at physical page 2 (harvest 3 SS3). **GAP**.
    pub const RESERVED_06: usize = 0x06;
    /// Start of the entry array.
    pub const ENTRIES: usize = 0x08;
}

/// The `"PP"` magic bytes that open an allocation-table page.
pub const MAGIC: &[u8; 2] = b"PP";

/// Bytes per entry: a `u16` marker and a `u16` physical page, both plain
/// little-endian -- not the high-word-first convention `format::fcr`'s own
/// `long` fields use.
pub const ENTRY_WIDTH: usize = 4;

/// How many regular entries one allocation-table block holds.
///
/// One number, one place, shared by [`layout`], `read::v6_allocation_table`
/// and `emit`'s own writer -- two copies of this arithmetic that disagreed
/// would put an entry in a slot the other could not find (the exact defect
/// `crates/btrieve/src/v6.rs`'s own `entries_per_block` doc comment records
/// having happened once already, at a different offset).
#[must_use]
pub fn entries_per_block(page_size: usize) -> usize {
    (page_size - at::ENTRIES) / ENTRY_WIDTH
}

/// Where allocation-table block `index` (1-based) keeps its shadow pair, as
/// physical page numbers -- position only, with no claim that a block is
/// actually there. See this module's own doc comment for the formula and
/// its citation.
#[must_use]
pub fn pair_position(page_size: usize, index: usize) -> (usize, usize) {
    let stride = entries_per_block(page_size) + 2;
    let first = 2 + (index - 1) * stride;
    (first, first + 1)
}

/// The (block, slot) an already-claimed or about-to-be-claimed logical id
/// belongs to, both 1-based and 0-based respectively.
///
/// The engine's own arithmetic: `n = logical - 1`, block
/// `n / entries_per_block + 1`, slot `n % entries_per_block`
/// (`W32MKDE_decompiled.c:14276-14278`). `logical` must be at least 1 --
/// logical id 0 is the control record itself (harvest 2 "PAGES, worked"),
/// never an allocation-table entry.
///
/// # Errors
///
/// If `logical` is 0.
pub fn block_of(logical: u32, page_size: usize) -> Result<(usize, usize), String> {
    if logical == 0 {
        return Err("logical ids are numbered from 1 -- 0 is the control \
                     record itself, never an allocation-table entry"
            .to_owned());
    }
    let entries = entries_per_block(page_size);
    let n = (logical - 1) as usize;
    Ok((n / entries + 1, n % entries))
}

/// Describe one allocation-table page's whole content -- one shadow copy,
/// `page_size` bytes, tiling completely.
#[must_use]
pub fn layout(page_size: usize) -> Layout {
    let entries = entries_per_block(page_size);
    let mut fields = vec![
        Field {
            name: "magic",
            index: None,
            at: at::MAGIC,
            len: 2,
            cite: "harvest 3 SS3 field table -- identifies an allocation-\
                   table page",
        },
        Field {
            name: "block",
            index: None,
            at: at::BLOCK,
            len: 2,
            cite: "harvest 3 SS3 field table -- 1-based block index, shared \
                   by both shadow copies",
        },
        Field {
            name: "generation",
            index: None,
            at: at::GENERATION,
            len: 2,
            cite: "harvest 3 SS3/SS5 -- file-global counter, meaningful only \
                   within one block's own pair",
        },
        Field {
            name: "reserved_06",
            index: None,
            at: at::RESERVED_06,
            len: 2,
            cite: "harvest 3 SS3 -- measured 0x0000 on physical page 2 of \
                   all 500 v6 corpus files; carried verbatim, not asserted \
                   -- GAP",
        },
    ];
    for n in 0..entries {
        fields.push(Field {
            name: "entry",
            index: Some(n),
            at: at::ENTRIES + n * ENTRY_WIDTH,
            len: ENTRY_WIDTH,
            cite: "harvest 3 SS3 -- a u16 marker (high byte the claimed \
                   page's own type tag, 0 = never allocated) plus a u16 \
                   physical page number, both plain little-endian; the \
                   engine's own off-by-one correction this crate's prior \
                   `v6.rs` documents (entries start at 0x08, not 0x0c) is \
                   folded directly into `at::ENTRIES`",
        });
    }
    let after = at::ENTRIES + entries * ENTRY_WIDTH;
    if page_size > after {
        fields.push(Field {
            name: "entries_tail",
            index: None,
            at: after,
            len: page_size - after,
            cite: "defensive: every page size this corpus uses (512, 1024, \
                   1536, 2048, 3584, 4096) is a multiple of 8, so \
                   page_size - 0x08 is always an exact multiple of 4 and \
                   this field is never nonempty on a real corpus file -- \
                   present so an unforeseen page size fails a tiling \
                   assertion rather than emitting a silent gap",
        });
    }

    Layout { what: "v6 allocation-table block", len: page_size, fields }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every page size the corpus actually uses must describe completely,
    /// with no leftover byte -- the whole point of routing this through
    /// `Layout` rather than four magic offsets.
    #[test]
    fn every_corpus_page_size_tiles_completely() {
        for page_size in [512, 1024, 1536, 2048, 3584, 4096] {
            let fault = layout(page_size).tiling_fault();
            assert_eq!(fault, None, "page_size {page_size}: {fault:?}");
        }
    }

    /// Every field carries the evidence that established it.
    #[test]
    fn every_field_is_cited() {
        for field in layout(4096).fields {
            assert!(!field.cite.trim().is_empty(), "{} has no citation", field.name);
        }
    }

    /// Harvest 3's own worked measurement: 4096-byte pages put blocks 1
    /// through 14 at physical 2, 1026, 2050 ... 13314
    /// (`wccnt8pj/wccmp002.vir`).
    #[test]
    fn pair_position_matches_the_harvests_own_worked_measurement() {
        assert_eq!(entries_per_block(4096), 1022);
        assert_eq!(pair_position(4096, 1), (2, 3));
        assert_eq!(pair_position(4096, 2), (1026, 1027));
        assert_eq!(pair_position(4096, 14), (13314, 13315));
    }

    /// `block_of` inverts `pair_position`'s own arithmetic: slot 0 of block
    /// 2 is logical `entries_per_block + 1`, not `entries_per_block`.
    #[test]
    fn block_of_inverts_the_engines_own_arithmetic() {
        let entries = entries_per_block(4096);
        assert_eq!(block_of(1, 4096).unwrap(), (1, 0));
        assert_eq!(block_of(entries as u32, 4096).unwrap(), (1, entries - 1));
        assert_eq!(block_of(entries as u32 + 1, 4096).unwrap(), (2, 0));
    }

    /// Logical id 0 is the control record itself, never a table entry.
    #[test]
    fn block_of_refuses_logical_zero() {
        assert!(block_of(0, 4096).is_err());
    }
}
