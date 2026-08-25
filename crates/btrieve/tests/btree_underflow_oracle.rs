//! Closes the three gaps `docs/2026-08-25-btree-split-oracle.md` named:
//! the exact underflow threshold, merge-vs-redistribute (and sibling
//! preference), and whether a page a merge emptied is ever reclaimed.
//! Replays the "Round 2" section of that doc against the fixtures in
//! `tests/data/btree-split-oracle/underflow-*`, the same way
//! `btree_split_oracle.rs` replays round 1.
//!
//! # Two decoders, on purpose
//!
//! A merge retags the emptied page `0x4500`, which `read::file` correctly
//! refuses to decode (an unrecognised tag) -- see round 1's
//! `the_reader_refuses_a_file_with_an_emptied_leaf_pending_tag_0x4500_support`.
//! Tests over a fixture that HAS such a page ([`threshold_512`],
//! [`threshold_4096`], [`reclaimed_page_reuses_the_freed_logical_id`]) read
//! the handful of raw bytes they need directly, with the small helpers
//! below -- the same tolerant, from-scratch approach
//! `tools/btrieve-oracle/rawscan.py` uses for exactly this reason, kept
//! deliberately minimal rather than pulled into the crate's own reader.
//! Tests over a fixture where every page still decodes normally (the
//! redistribution cases -- redistributing never eliminates a page) use
//! `btrieve::read::file` directly, like round 1's tests.

use std::fs;
use std::path::{Path, PathBuf};

use btrieve::model::{File, IndexEntry, V6Page};

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/btree-split-oracle").join(rel)
}

fn read_bytes(rel: &str) -> Vec<u8> {
    fs::read(fixture(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn read(rel: &str) -> File {
    let bytes = read_bytes(rel);
    btrieve::read::file(&bytes).unwrap_or_else(|e| panic!("{rel}: not readable: {}", e.why))
}

fn root_logical(file: &File) -> u32 {
    file.key_descriptors[0].root_page
}

fn index_page(file: &File, logical: u32) -> &V6Page {
    file.v6_pages
        .iter()
        .find(|p| u32::from(p.logical) == logical && p.index.is_some())
        .unwrap_or_else(|| panic!("no index page with logical id {logical}"))
}

fn key_int(e: &IndexEntry) -> u32 {
    assert_eq!(e.key.len(), 4);
    u32::from_le_bytes([e.key[0], e.key[1], e.key[2], e.key[3]])
}

fn keys(page: &V6Page) -> Vec<u32> {
    page.index.as_ref().expect("an index page").entries.iter().map(key_int).collect()
}

fn root_keys(file: &File) -> Vec<u32> {
    keys(index_page(file, root_logical(file)))
}

// --- Manual, tolerant reads for fixtures read::file refuses -----------

/// Plain little-endian u16.
fn getu16(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([data[at], data[at + 1]])
}

/// A "long": two little-endian u16 halves, high half first -- the whole
/// format's own convention (harvest 1's "Endianness convention"; mirrors
/// `crates/btrieve/src/read.rs`'s private `get_long`, reimplemented here
/// because that function is not `pub` and this file must not become a
/// second consumer of the crate's internals to reach three raw fields).
fn getlong(data: &[u8], at: usize) -> u32 {
    let hi = getu16(data, at) as u32;
    let lo = getu16(data, at + 2) as u32;
    (hi << 16) | lo
}

fn guess_page_size(data: &[u8]) -> usize {
    for candidate in [512usize, 1024, 1536, 2048, 3584, 4096] {
        if data.len() < candidate * 3 {
            continue;
        }
        let off = candidate * 2;
        if data[off] == b'P' && data[off + 1] == b'P' {
            return candidate;
        }
    }
    panic!("could not guess page size: no 'PP' allocation-table magic found");
}

fn live_alloc_page(data: &[u8], page_size: usize) -> usize {
    let g2 = getu16(data, 2 * page_size + 4);
    let g3 = getu16(data, 3 * page_size + 4);
    if g2 > g3 { 2 } else { 3 }
}

/// `(marker, physical_page)` for one logical id, read straight out of the
/// live allocation-table block -- `format::alloc`'s own module doc gives
/// the layout (`0x08 + (logical-1)*4`, a u16 marker then a u16 physical
/// page, both plain little-endian).
fn alloc_entry(data: &[u8], page_size: usize, logical: u32) -> (u16, u16) {
    let live = live_alloc_page(data, page_size);
    let off = live * page_size + 8 + (logical as usize - 1) * 4;
    (getu16(data, off), getu16(data, off + 2))
}

/// Every logical id with a nonzero allocation-table marker, in ascending
/// order -- used to confirm reclamation reuses an EXISTING id rather than
/// minting a new one, without hardcoding how many ids a fixture has.
fn claimed_logical_ids(data: &[u8], page_size: usize) -> Vec<u32> {
    let live = live_alloc_page(data, page_size);
    let entries_per_block = (page_size - 8) / 4;
    let mut out = Vec::new();
    for n in 0..entries_per_block {
        let off = live * page_size + 8 + n * 4;
        if getu16(data, off) != 0 {
            out.push(n as u32 + 1);
        }
    }
    out
}

/// One index page's entry count and key list, read manually (no tag
/// check at all -- deliberately: this is used on pages the crate's own
/// reader refuses to touch because ITS tag is unrecognised, but the entry
/// array past the header is the same shape regardless of the tag byte).
fn manual_index_keys(data: &[u8], page_size: usize, logical: u32) -> Vec<u32> {
    let (_, physical) = alloc_entry(data, page_size, logical);
    let off = physical as usize * page_size;
    let count = getu16(data, off + 6) as usize;
    (0..count)
        .map(|i| {
            let e = off + 16 + i * 12;
            u32::from_le_bytes([data[e], data[e + 1], data[e + 2], data[e + 3]])
        })
        .collect()
}

fn manual_root_entries(data: &[u8], page_size: usize) -> (u32, Vec<(u32, u32)>) {
    let fcr_live = if getu16(data, 4) > getu16(data, page_size + 4) { 0 } else { 1 };
    let root_raw = getlong(data, fcr_live * page_size + 0x110);
    let root_logical = root_raw & 0x00FF_FFFF;
    let (_, physical) = alloc_entry(data, page_size, root_logical);
    let off = physical as usize * page_size;
    let count = getu16(data, off + 6) as usize;
    let entries = (0..count)
        .map(|i| {
            let e = off + 16 + i * 12;
            let key = u32::from_le_bytes([data[e], data[e + 1], data[e + 2], data[e + 3]]);
            let child = getlong(data, e + 8) & 0x00FF_FFFF;
            (key, child)
        })
        .collect();
    (root_logical, entries)
}

// --- Gap 1: the exact underflow threshold ------------------------------

/// **Odd `max_entries` (41, `half_entries` 20):** the post-split middle
/// leaf starts at `ceil(41/2) = 21` entries -- one MORE than
/// `half_entries` -- so it takes two deletes to cross below it: the first
/// (21 -> 20 == `half_entries`) changes nothing; the second (20 -> 19 <
/// `half_entries`) merges the leaf into its right sibling.
#[test]
fn threshold_512_fires_when_entries_drop_below_half_entries() {
    let pristine = read("underflow-lifecycle-512/1-pristine.dat");
    let middle = index_page(&pristine, 4);
    assert_eq!(keys(middle).len(), 21, "ceil(41/2) = 21, one more than half_entries (20)");
    assert_eq!(root_keys(&pristine).len(), 2, "three leaves, two entries in the root");

    let at_threshold = read("underflow-lifecycle-512/2-at-threshold.dat");
    let middle = index_page(&at_threshold, 4);
    assert_eq!(keys(middle).len(), 20, "== half_entries: at the boundary, not below it");
    assert_eq!(root_keys(&at_threshold).len(), 2, "no merge yet at exactly half_entries");

    let data = read_bytes("underflow-lifecycle-512/3-merged.dat");
    let ps = guess_page_size(&data);
    let (_, root_entries) = manual_root_entries(&data, ps);
    assert_eq!(root_entries.len(), 1, "one delete below half_entries (19 < 20): the leaf is gone");
    let (marker, _) = alloc_entry(&data, ps, 4);
    assert_eq!(marker, 0x4500, "the vacated logical id 4 is retagged, not zeroed");
}

/// **Even `max_entries` (340, `half_entries` 170):** `ceil(340/2) ==
/// half_entries` exactly, so the post-split middle leaf starts AT the
/// threshold and the very FIRST delete already crosses it -- unlike the
/// odd case above, which needs two. Both geometries agree on the same
/// predicate (`entries < half_entries`); they only differ in how many
/// deletes it takes to reach it, which `ceil` vs `half_entries` explains
/// and a fixed fraction would not.
#[test]
fn threshold_4096_fires_on_the_first_delete_because_it_starts_at_half_entries() {
    let pristine = read("underflow-lifecycle-4096/1-pristine.dat");
    let middle = index_page(&pristine, 4);
    assert_eq!(keys(middle).len(), 170, "ceil(340/2) == half_entries (340 is even)");

    let data = read_bytes("underflow-lifecycle-4096/2-merged.dat");
    let ps = guess_page_size(&data);
    let (_, root_entries) = manual_root_entries(&data, ps);
    assert_eq!(root_entries.len(), 1, "one delete (170 -> 169 < 170) already merges");
    let (marker, _) = alloc_entry(&data, ps, 4);
    assert_eq!(marker, 0x4500);
}

// --- Gap 2: merge vs. redistribute, and sibling preference -------------

/// When both siblings have room, the underflowing MIDDLE leaf is merged
/// into its RIGHT sibling (which keeps its own logical id and grows); the
/// left sibling is untouched. The root's own entry count drops from 2 to
/// 1 -- not just a leaf's record count -- which is what tells a merge
/// apart from a redistribution (see the next three tests, none of which
/// change the root's entry count).
#[test]
fn merge_prefers_the_right_sibling_over_the_left() {
    let data = read_bytes("underflow-lifecycle-512/3-merged.dat");
    let ps = guess_page_size(&data);
    let left = manual_index_keys(&data, ps, 6);
    assert_eq!(left, (1..=21).collect::<Vec<_>>(), "left sibling untouched");
    let right = manual_index_keys(&data, ps, 1);
    // right started at 45..64 (20), gained the promoted separator (44) and
    // the middle leaf's surviving 25..43 (19 entries): 1 + 19 + 20 = 40.
    let mut expected: Vec<u32> = (25..=64).collect();
    expected.retain(|k| *k != 23 && *k != 24); // the two keys this fixture deleted
    assert_eq!(right, expected, "right sibling absorbed the promoted key and the survivors");
}

/// The RIGHTMOST leaf has no right sibling: underflowing, it redistributes
/// with its LEFT neighbour instead -- one entry rotates through the
/// parent (old separator down, neighbour's highest up), and BOTH leaves
/// survive. The root's entry count is unchanged; only one separator key
/// changed (44 -> 43).
#[test]
fn rightmost_leaf_redistributes_left_instead_of_merging() {
    let before = read("underflow-edge-rightmost/1-pristine.dat");
    assert_eq!(root_keys(&before), vec![22, 44]);

    let after = read("underflow-edge-rightmost/2-redistributed.dat");
    assert_eq!(root_keys(&after), vec![22, 43], "separator moved down from 44 to 43");

    let middle = index_page(&after, 4);
    assert_eq!(keys(middle), (23..=42).collect::<Vec<_>>(), "lost its own highest key (43)");
    let rightmost = index_page(&after, 1);
    let mut expected: Vec<u32> = (44..=64).collect();
    expected.retain(|k| *k != 45); // the deleted key
    assert_eq!(keys(rightmost), expected, "gained the old separator (44) at its low end");
}

/// The LEFTMOST leaf has no left sibling: underflowing, it redistributes
/// with its RIGHT neighbour -- the mirror image of the rightmost case.
#[test]
fn leftmost_leaf_redistributes_right_instead_of_merging() {
    let before = read("underflow-edge-leftmost/1-pristine.dat");
    assert_eq!(root_keys(&before), vec![22, 44]);

    let after = read("underflow-edge-leftmost/2-redistributed.dat");
    assert_eq!(root_keys(&after), vec![23, 44], "separator moved up from 22 to 23");

    let leftmost = index_page(&after, 6);
    let mut expected: Vec<u32> = (1..=22).collect();
    expected.retain(|k| *k != 1 && *k != 2); // the two deleted keys
    assert_eq!(keys(leftmost), expected, "gained the old separator (22) at its high end");
    let middle = index_page(&after, 4);
    assert_eq!(keys(middle), (24..=43).collect::<Vec<_>>(), "lost its own lowest key (23)");
}

/// **The right sibling is topped up near capacity first** (40 of 41
/// entries), so a full merge with an underflowing middle leaf (19 more)
/// would need 59 entries -- over `max_entries`. Btrieve does NOT fall
/// back to the left sibling (which has room): it redistributes with the
/// SAME right sibling anyway. The right-sibling preference from
/// [`merge_prefers_the_right_sibling_over_the_left`] holds even when a
/// full merge is impossible.
#[test]
fn when_the_right_sibling_has_no_room_it_redistributes_rather_than_switching_sides() {
    let before = read("underflow-no-room-redistribute/1-topped-up.dat");
    assert_eq!(root_keys(&before), vec![22, 44]);
    let right_before = index_page(&before, 1);
    assert_eq!(keys(right_before).len(), 40, "topped up to one below its own split trigger");

    let after = read("underflow-no-room-redistribute/2-redistributed.dat");
    assert_eq!(root_keys(&after), vec![22, 45], "separator moved from 44 to 45, not eliminated");
    let left = index_page(&after, 6);
    assert_eq!(keys(left), (1..=21).collect::<Vec<_>>(), "left sibling still untouched");
    let right_after = index_page(&after, 1);
    assert_eq!(keys(right_after).len(), 39, "gave up its own lowest entry (45), not absorbed");
}

// --- Gap 3: is a merge-vacated page ever reclaimed? --------------------

/// After the merge in `underflow-lifecycle-512` retags logical id 4's page
/// `0x4500`, two more inserts force the right sibling to split again --
/// and that split's LEFT child (a brand new logical page, per round 1's
/// own split rule) reuses logical id 4 rather than minting a new one: its
/// allocation-table marker flips back from `0x4500` to `0x8000`, its
/// physical page relocates (ordinary shadow-pair discipline), and the set
/// of CLAIMED logical ids is identical before and after -- nothing new
/// was added to reach it.
#[test]
fn a_merge_vacated_page_is_reclaimed_by_a_later_split_not_left_behind() {
    let before = read_bytes("underflow-lifecycle-512/3-merged.dat");
    let ps = guess_page_size(&before);
    let (marker_before, _) = alloc_entry(&before, ps, 4);
    assert_eq!(marker_before, 0x4500);
    let claimed_before = claimed_logical_ids(&before, ps);

    let after = read_bytes("underflow-lifecycle-512/4-reclaimed.dat");
    let (marker_after, _) = alloc_entry(&after, ps, 4);
    assert_eq!(marker_after, 0x8000, "logical id 4 is an ordinary index page again");
    let claimed_after = claimed_logical_ids(&after, ps);
    assert_eq!(claimed_before, claimed_after, "no new logical id was minted to hold the split");

    let reclaimed_keys = manual_index_keys(&after, ps, 4);
    assert_eq!(
        reclaimed_keys,
        (25..=45).collect::<Vec<_>>(),
        "the reclaimed page holds the LEFT half of the right sibling's own re-split \
         (ceil(41/2) = 21 entries), the same split rule round 1 recorded"
    );
}
