//! Pins the B-tree split/underflow facts measured against genuine Btrieve
//! 6.15 in `docs/2026-08-25-btree-split-oracle.md`, replayed through this
//! crate's own `read::file` so a later change cannot silently disagree with
//! the recording without a test noticing.
//!
//! **Not an implementation test.** `crates/btrieve` has no B-tree split code
//! -- `Block::update_v6` still rebuilds the whole index on every write
//! (`v6_reindex`). This only proves two things: the committed fixtures are
//! legible to the crate's existing (read-only) decoder, and the exact
//! entry-distribution facts the doc states are what that decoder actually
//! sees, not a transcription slip between the recording session and the doc.
//!
//! Fixtures: `tests/data/btree-split-oracle/`, each a `before.dat`/`after.dat`
//! pair bracketing one operation against a file `tools/btrieve-oracle/
//! split_oracle.py` built and grew one insert/delete at a time. See that
//! directory's own `README.txt` for how they were produced.

use std::fs;
use std::path::{Path, PathBuf};

use btrieve::model::{Control, File, IndexEntry, V6Page};

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/btree-split-oracle").join(rel)
}

fn read(rel: &str) -> File {
    let bytes = fs::read(fixture(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
    btrieve::read::file(&bytes).unwrap_or_else(|e| panic!("{rel}: not readable: {}", e.why))
}

/// The live control record's own `records` count -- the simplest possible
/// cross-check that a fixture is what its manifest row claims it is.
fn live_records(file: &File) -> u32 {
    let Control::Shadowed { live, .. } = &file.control else {
        panic!("every fixture here is v6");
    };
    live.records
}

fn root_logical(file: &File) -> u32 {
    file.key_descriptors[0].root_page
}

/// The one page whose self-reported logical id matches and which decoded as
/// an index page -- `V6Page::logical` is "decorative" per that field's own
/// doc comment (resolution never consults it), but for a fixture this small
/// (one allocation-table block, no relocated duplicates) it is unambiguous,
/// and asserting index-ness alongside it catches the one case it would not
/// be: a page that merely reused a stale logical id's number.
fn index_page(file: &File, logical: u32) -> &V6Page {
    file.v6_pages
        .iter()
        .find(|p| u32::from(p.logical) == logical && p.index.is_some())
        .unwrap_or_else(|| panic!("no index page with logical id {logical}"))
}

fn key_int(e: &IndexEntry) -> u32 {
    assert_eq!(e.key.len(), 4, "this oracle's rig always uses a 4-byte key");
    u32::from_le_bytes([e.key[0], e.key[1], e.key[2], e.key[3]])
}

fn keys(page: &V6Page) -> Vec<u32> {
    page.index.as_ref().expect("an index page").entries.iter().map(key_int).collect()
}

/// **Leaf split, `docs/2026-08-25-btree-split-oracle.md` "The split rule":**
/// a 41-entry leaf (`max_entries` 41, odd) receiving its 42nd key splits
/// into `ceil(41/2) = 21` left, one promoted, `41 - 21 = 20` right (the
/// 20th being the new record) -- and the tree grows from depth 1 (the leaf
/// is its own root) to depth 2 (a brand new root page, never reused from
/// anywhere).
#[test]
fn leaf_split_distributes_ceil_half_left_and_moves_the_root() {
    let before = read("append512u/leaf-split/before.dat");
    let after = read("append512u/leaf-split/after.dat");

    assert_eq!(live_records(&before), 41);
    assert_eq!(root_logical(&before), 1, "before the split the leaf IS the root");
    let leaf = index_page(&before, 1);
    assert_eq!(keys(leaf), (1..=41).collect::<Vec<_>>());

    assert_eq!(live_records(&after), 42);
    let new_root = root_logical(&after);
    assert_ne!(new_root, 1, "the root moved to a brand new logical page");
    let root = index_page(&after, new_root);
    assert_eq!(keys(root), vec![22], "the median of the 42 is promoted alone");

    let left = index_page(&after, 6);
    assert_eq!(keys(left), (1..=21).collect::<Vec<_>>(), "left = ceil(41/2) = 21 entries");
    let right = index_page(&after, 1);
    assert_eq!(
        keys(right),
        (23..=42).collect::<Vec<_>>(),
        "right keeps its OLD logical id (1) and gets the new record (42)"
    );
}

/// **Interior split, same doc, "Interior split (root grows a second time)":**
/// the same 21/1/20 arithmetic one level up, on the interior root that the
/// leaf split above created -- confirming the rule is level-independent.
#[test]
fn interior_split_grows_the_tree_a_second_level_with_the_same_ratio() {
    let before = read("append512u/interior-split/before.dat");
    let after = read("append512u/interior-split/after.dat");

    let old_root = root_logical(&before);
    let old = index_page(&before, old_root);
    assert_eq!(old.index.as_ref().unwrap().entries.len(), 41, "the interior root was full");

    let new_root = root_logical(&after);
    assert_ne!(new_root, old_root, "the root moved to a brand new logical page again");
    let root = index_page(&after, new_root);
    assert_eq!(root.index.as_ref().unwrap().entries.len(), 1);

    let right = index_page(&after, old_root);
    assert_eq!(
        right.index.as_ref().unwrap().entries.len(),
        20,
        "the OLD interior keeps its logical id and becomes the right child, \
         same as a leaf split"
    );
}

/// **A different page size and an even `max_entries`,** same doc's "the
/// geometry that disproved a `half_entries`-based guess": pagesize 4096
/// gives `max_entries` 340 (even), so `ceil(340/2) == 340/2 == half_entries`
/// -- unlike the 512-byte, odd-`max_entries` case above, where left is
/// `half_entries + 1`. A rule stated only in terms of `half_entries` would
/// have been right for one of these fixtures and wrong for the other.
#[test]
fn leaf_split_ratio_is_ceil_half_not_half_entries_at_a_different_page_size() {
    let before = read("append4096u/leaf-split/before.dat");
    let after = read("append4096u/leaf-split/after.dat");

    let leaf = index_page(&before, root_logical(&before));
    let entries = &leaf.index.as_ref().unwrap().entries;
    assert_eq!(entries.len(), 340);

    let new_root = root_logical(&after);
    let root = index_page(&after, new_root);
    assert_eq!(keys(root), vec![171], "ceil(340/2) = 170, so entry 170 (key 171) is promoted");

    let left = index_page(&after, 6);
    assert_eq!(keys(left).len(), 170, "left = ceil(340/2) = 170, not half_entries+1");
    let right = index_page(&after, 1);
    assert_eq!(keys(right).len(), 170, "right = 340 - 170 - 1 = 169, plus the new record");
}

/// **Middle insert, same doc's "Right-edge append vs. middle insert":** the
/// record that triggers the split (20500) lands inside the existing range,
/// not at either edge. The split point is still `ceil(max_entries/2)` of
/// the 42-entry MERGED sorted sequence, not of the original 41 -- so the
/// new record can end up on the left side, as it does here, rather than
/// always on the side an append-optimised engine would favour.
#[test]
fn middle_insert_splits_by_position_in_the_merged_sequence_not_by_side() {
    let after = read("middle512u/leaf-split/after.dat");
    let new_root = root_logical(&after);
    let root = index_page(&after, new_root);
    assert_eq!(keys(root), vec![21000], "promoted key is the 21st-smallest of the merged 42");

    let left = index_page(&after, 6);
    let mut left_keys: Vec<u32> = (1..=20).map(|n| n * 1000).collect();
    left_keys.push(20_500);
    assert_eq!(keys(left), left_keys, "the NEW record (20500) landed on the left, not the right");

    let right = index_page(&after, 1);
    assert_eq!(keys(right), (22..=41).map(|n| n * 1000).collect::<Vec<_>>());
}

/// **Duplicate-permitting key, same split ratio:** wider index entries
/// (`key_length + 12`, not `+8`) give `max_entries` 31, `ceil(31/2) = 16`.
#[test]
fn duplicate_key_leaf_split_uses_the_same_ceil_half_ratio() {
    let after = read("dup512/leaf-split/after.dat");
    let new_root = root_logical(&after);
    let root = index_page(&after, new_root);
    assert_eq!(keys(root), vec![17]);

    let left = index_page(&after, 6);
    assert_eq!(keys(left), (1..=16).collect::<Vec<_>>(), "ceil(31/2) = 16");
    let right = index_page(&after, 1);
    assert_eq!(keys(right), (18..=32).collect::<Vec<_>>());
}

/// **Duplicate chain:** five more records sharing one already-split key's
/// value extend that ONE entry's `head`/`tail`, rather than adding entries --
/// a duplicate group can never straddle a split, because splitting operates
/// on distinct-key entries and a duplicate group is exactly one entry.
#[test]
fn a_duplicate_group_extends_one_entrys_head_tail_chain() {
    let before = read("dup512/duplicate-chain/before.dat");
    let after = read("dup512/duplicate-chain/after.dat");

    // Key 40 lives in the RIGHT leaf (logical 1, per this experiment's own
    // split -- `duplicate_key_leaf_split_uses_the_same_ceil_half_ratio`
    // above), not the root: by this point the root holds only the one
    // promoted entry (key 17).
    let before_entry = index_page(&before, 1)
        .index
        .as_ref()
        .unwrap()
        .entries
        .iter()
        .find(|e| key_int(e) == 40)
        .expect("key 40 present before the duplicates");
    assert_eq!(before_entry.head, before_entry.tail.unwrap(), "one record: head == tail");

    let after_entry = index_page(&after, 1)
        .index
        .as_ref()
        .unwrap()
        .entries
        .iter()
        .find(|e| key_int(e) == 40)
        .expect("key 40 present after the duplicates");
    assert_ne!(
        after_entry.head,
        after_entry.tail.unwrap(),
        "six records sharing one key: head is the first, tail the last"
    );
    assert_eq!(after_entry.head, before_entry.head, "head never moves once a chain exists");
}

/// **Delete/underflow, same doc's "Delete does rebalance":** deleting the
/// top half of a 4-leaf tree's keys empties two leaves outright and drives
/// a third below `half_entries`, and that third leaf's SURVIVING entries
/// are merged into a sibling rather than left sparse -- the root's own
/// entry count drops from 4 to 1, not just the leaves' record counts.
///
/// The BEFORE fixture reads cleanly. The AFTER one does not -- see the next
/// test, which is the other half of this fact.
#[test]
fn delete_merges_an_underflowing_leaf_rather_than_leaving_it_sparse() {
    let before = read("underflow512u/merge-on-delete/before.dat");

    assert_eq!(live_records(&before), 120);
    let root_before = index_page(&before, root_logical(&before));
    assert_eq!(
        root_before.index.as_ref().unwrap().entries.len(),
        4,
        "four leaves under the root before any delete"
    );
}

/// **Tag `0x4500` support (Task 6), replacing the refusal this test used to
/// pin:** the AFTER file decodes now -- the root shrinks from four leaves
/// to one (the other half of `delete_merges_an_underflowing_leaf_rather_
/// than_leaving_it_sparse`'s fact), and the three emptied leaves are retired
/// into exactly the free list `docs/2026-08-25-btree-split-rules.md` §8
/// measured directly against this same fixture: `FCR+152 -> logical 10 ->
/// logical 8 -> logical 1 -> NOWHERE`.
#[test]
fn a_retired_page_decodes_into_the_measured_free_list_chain() {
    let bytes = fs::read(fixture("underflow512u/merge-on-delete/after.dat")).unwrap();
    let after = btrieve::read::file(&bytes)
        .unwrap_or_else(|e| panic!("the reader must accept tag 0x4500 now: {}", e.why));

    let root = index_page(&after, root_logical(&after));
    assert_eq!(
        root.index.as_ref().unwrap().entries.len(),
        1,
        "the merge collapses the root from four leaves to one"
    );

    let page_size = after.id.page_size as usize;
    let Control::Shadowed { live_is_page, .. } = &after.control else {
        panic!("every fixture here is v6");
    };
    let live_start = live_is_page * page_size;
    let head_at = live_start + btrieve::pages::fcr::INDEX_FREE_V6;
    let head = btrieve::pages::long(&bytes[head_at..head_at + 4]);

    let retired: Vec<&V6Page> = after.v6_pages.iter().filter(|p| p.retired.is_some()).collect();
    assert_eq!(retired.len(), 3, "three leaves were merged away");

    let mut chain: Vec<Option<u16>> = Vec::new();
    let mut next = head;
    loop {
        if next == 0xffff_ffff {
            chain.push(None);
            break;
        }
        let logical = u16::try_from(next).expect("a logical id fits a u16 on this fixture");
        chain.push(Some(logical));
        let page = retired
            .iter()
            .find(|p| p.logical == logical)
            .unwrap_or_else(|| panic!("free list names logical {logical}, no retired page carries it"));
        let body = page.retired.as_ref().expect("filtered on retired.is_some()");
        next = btrieve::pages::long(&body[2..6]);
    }
    assert_eq!(chain, vec![Some(10), Some(8), Some(1), None]);
}
