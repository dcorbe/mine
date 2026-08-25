//! Four more operations genuine Btrieve 6.15 performs, recorded because the
//! incremental engine `crates/btrieve` is growing currently refuses them and
//! a refusal halts the board: deleting one member out of a duplicate chain,
//! deleting a key that lives only as an interior separator, deleting a
//! key's last remaining record, and choosing among more than one retired
//! (`0x4500`) page when a split needs a new one.
//!
//! Written after `V6Page::retired` and `pages::fcr::INDEX_FREE_V6` landed
//! (Task 6, commit 97d673cf and after) -- every fixture here decodes
//! cleanly through `read::file`, no manual byte-parsing fallback needed.

use std::fs;
use std::path::{Path, PathBuf};

use btrieve::model::{Control, File, IndexEntry, V6Page, V6RecordSlot};

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

fn entry_for<'a>(page: &'a V6Page, key: u32) -> &'a IndexEntry {
    page.index
        .as_ref()
        .unwrap()
        .entries
        .iter()
        .find(|e| key_int(e) == key)
        .unwrap_or_else(|| panic!("key {key} not present"))
}

/// A duplicate record's own `[prev][next]` chain pair.
///
/// **A record `position` (as `head`/`tail` store it) is `logical_page *
/// page_size + offset_within_page`, using the record's own data page's
/// LOGICAL id -- the same convention `format::fcr`'s own `FREE_V6` field
/// doc states ("a record position (logical page * page length + slot
/// offset)") and generalises here to every other record-position field in
/// v6, not just that one. It is NOT a physical byte offset -- indexing
/// straight into the raw file with it lands in whatever unrelated physical
/// page happens to occupy that byte range, which is what this helper's
/// first version did and got caught by its own assertions immediately.**
/// So: resolve `position`'s page via its LOGICAL id against `file.v6_pages`
/// (already resolved through the allocation table by `read::file`, however
/// the shadow-pair discipline currently has it placed), find the slot
/// inside it, and read the already-decoded body -- no raw byte arithmetic
/// of our own past that point. The chain pair sits at body offset 12 (this
/// rig's reclen), 8 bytes, `[prev][next]`, word-swapped longs like
/// everything else in this format.
fn chain_at(file: &File, position: u32) -> (u32, u32) {
    let page_size = file.id.page_size as usize;
    let logical = position as usize / page_size;
    let offset_in_page = position as usize % page_size;
    let Control::Shadowed { live, .. } = &file.control else { panic!("v6 only") };
    let physical_slot_len = live.physical as usize;
    let slot_index = (offset_in_page - 6) / physical_slot_len; // 6 = format::page::LEN
    let page = file
        .v6_pages
        .iter()
        .find(|p| usize::from(p.logical) == logical && p.content.is_some())
        .unwrap_or_else(|| panic!("no data page with logical id {logical}"));
    match &page.content.as_ref().unwrap().slots[slot_index] {
        V6RecordSlot::Live { body, .. } => {
            (btrieve::pages::long(&body[12..16]), btrieve::pages::long(&body[16..20]))
        }
        V6RecordSlot::Free { .. } => panic!("position {position:#x} names a free slot"),
    }
}

const NOWHERE: u32 = 0xffff_ffff;

// --- (i) Partial duplicate-chain deletion ------------------------------

#[test]
fn deleting_the_head_of_a_duplicate_group_advances_head_and_clears_prev() {
    let before = read("dup-chain-partial-delete/00-baseline-all-groups.dat");
    let root = root_logical(&before);
    let leaf = index_page(&before, root);
    let e = entry_for(leaf, 100);
    let head_before = e.head;
    let (prev, next) = chain_at(&before, head_before);
    assert_eq!(prev, NOWHERE, "the chain's own head record has no predecessor");

    let after = read("dup-chain-partial-delete/01-head-deleted-group100.dat");
    let leaf = index_page(&after, root);
    let e = entry_for(leaf, 100);
    assert_eq!(e.head, next, "the entry's head now points at the second-inserted record");
    assert_ne!(e.head, head_before, "not the same record -- the deleted one is gone");
    let (new_prev, _) = chain_at(&after, e.head);
    assert_eq!(new_prev, NOWHERE, "the new head's own prev link was cleared");
}

#[test]
fn deleting_the_middle_of_a_duplicate_group_only_relinks_its_neighbours() {
    let before = read("dup-chain-partial-delete/01-head-deleted-group100.dat");
    let after = read("dup-chain-partial-delete/02-middle-deleted-group200.dat");
    let root = root_logical(&before);

    let e_before = entry_for(index_page(&before, root), 200);
    let e_after = entry_for(index_page(&after, root), 200);
    assert_eq!(e_after.head, e_before.head, "head unchanged -- the middle member left, not the head");
    assert_eq!(e_after.tail, e_before.tail, "tail unchanged either");

    let (_, head_next) = chain_at(&after, e_after.head);
    assert_eq!(head_next, e_after.tail.unwrap(), "head now links directly to tail, skipping the deleted middle");
    let (tail_prev, _) = chain_at(&after, e_after.tail.unwrap());
    assert_eq!(tail_prev, e_after.head, "tail links directly back to head");
}

#[test]
fn deleting_the_tail_of_a_duplicate_group_retreats_tail_and_clears_next() {
    let before = read("dup-chain-partial-delete/02-middle-deleted-group200.dat");
    let after = read("dup-chain-partial-delete/03-tail-deleted-group300.dat");
    let root = root_logical(&before);

    let e_before = entry_for(index_page(&before, root), 300);
    let e_after = entry_for(index_page(&after, root), 300);
    assert_eq!(e_after.head, e_before.head, "head untouched -- the tail left, not the head");
    assert_ne!(e_after.tail, e_before.tail, "a new, earlier record is now the tail");

    let (_, new_tail_next) = chain_at(&after, e_after.tail.unwrap());
    assert_eq!(new_tail_next, NOWHERE, "the new tail's own next link was cleared");
}

#[test]
fn draining_a_duplicate_group_to_solo_then_deleting_it_removes_the_entry_entirely() {
    let root = root_logical(&read("dup-chain-partial-delete/03-tail-deleted-group300.dat"));

    let three_to_two = read("dup-chain-partial-delete/04-group400-3-to-2.dat");
    let e = entry_for(index_page(&three_to_two, root), 400);
    assert_ne!(e.head, e.tail.unwrap(), "still two distinct records");

    let solo = read("dup-chain-partial-delete/05-group400-2-to-1-solo.dat");
    let e = entry_for(index_page(&solo, root), 400);
    assert_eq!(e.head, e.tail.unwrap(), "one record left: head and tail are the same position");

    let eliminated = read("dup-chain-partial-delete/06-group400-eliminated.dat");
    let leaf = index_page(&eliminated, root);
    assert!(
        leaf.index.as_ref().unwrap().entries.iter().all(|e| key_int(e) != 400),
        "deleting the solo survivor removes the WHOLE entry, same as any unique key's last record"
    );
}

// --- (ii) Interior-separator delete -------------------------------------

/// The classic B-tree interior-delete question, settled: Btrieve replaces
/// a deleted interior key with its in-order PREDECESSOR (the left
/// subtree's own maximum), pulled up from the leaf that held it.
#[test]
fn deleting_an_interior_separator_pulls_up_the_in_order_predecessor() {
    let before = read("interior-separator-delete/before.dat");
    let root_log = root_logical(&before);
    let root = index_page(&before, root_log);
    assert_eq!(key_int(&root.index.as_ref().unwrap().entries[0]), 22);

    let left = index_page(&before, 6);
    assert_eq!(
        key_int(left.index.as_ref().unwrap().entries.last().unwrap()),
        21,
        "the predecessor is the left subtree's own highest key"
    );
    let left_count_before = left.index.as_ref().unwrap().entries.len();

    let after = read("interior-separator-delete/after.dat");
    let root = index_page(&after, root_logical(&after));
    assert_eq!(
        key_int(&root.index.as_ref().unwrap().entries[0]),
        21,
        "the separator became the predecessor's own key, not left blank or successor-based"
    );
    let left = index_page(&after, 6);
    assert_eq!(
        left.index.as_ref().unwrap().entries.len(),
        left_count_before - 1,
        "the predecessor's own leaf entry was removed from the left subtree"
    );
    assert!(
        left.index.as_ref().unwrap().entries.iter().all(|e| key_int(e) != 21),
        "key 21 no longer lives in the leaf at all -- only in the interior root now"
    );
}

// --- (iii) Delete-to-empty ----------------------------------------------

/// Genuine Btrieve allows deleting a key's last record -- reproduces the
/// bug this experiment exists to fix (the incremental engine currently
/// refuses it). The emptied root reverts to the exact virgin-file shape,
/// not a distinct "emptied" state.
#[test]
fn deleting_the_last_record_empties_the_root_to_the_virgin_shape() {
    let one = read("delete-to-empty/1-one-record.dat");
    let root_log = root_logical(&one);
    assert_eq!(index_page(&one, root_log).index.as_ref().unwrap().entries.len(), 1);

    let emptied = read("delete-to-empty/2-emptied.dat");
    assert_eq!(root_logical(&emptied), root_log, "the FCR's root pointer is unchanged");
    let Control::Shadowed { live, .. } = &emptied.control else { panic!("v6 only") };
    assert_eq!(live.records, 0);
    let root = index_page(&emptied, root_log);
    let idx = root.index.as_ref().unwrap();
    assert_eq!(idx.entries.len(), 0);
    assert_eq!(idx.leftmost, 0, "virgin shape: leftmost is zero, not NOWHERE");
    assert_eq!(idx.rightmost, 0xffff_ffff, "virgin shape: rightmost is NOWHERE");

    let reinserted = read("delete-to-empty/3-reinserted.dat");
    assert_eq!(root_logical(&reinserted), root_log, "re-insertion reuses the same logical root id");
    let root = index_page(&reinserted, root_log);
    assert_eq!(root.index.as_ref().unwrap().entries.len(), 1);
}

// --- (iv) Multi-candidate reclaim preference ----------------------------

fn index_free_head(bytes: &[u8], file: &File) -> u32 {
    let Control::Shadowed { live_is_page, .. } = &file.control else { panic!("v6 only") };
    let at = live_is_page * file.id.page_size as usize + btrieve::pages::fcr::INDEX_FREE_V6;
    btrieve::pages::long(&bytes[at..at + 4])
}

fn retired_next(page: &V6Page) -> u32 {
    let body = page.retired.as_ref().expect("a retired page");
    btrieve::pages::long(&body[2..6])
}

fn by_logical(file: &File, logical: u32) -> &V6Page {
    file.v6_pages
        .iter()
        .find(|p| u32::from(p.logical) == logical)
        .unwrap_or_else(|| panic!("no page with logical id {logical}"))
}

/// Two independent retirements build a genuine LIFO chain: the free-list
/// head always names the MOST recently retired page, and that page's own
/// stored `next` link names whichever was retired before it.
#[test]
fn two_retirements_form_a_lifo_chain_at_the_free_list_head() {
    let bytes = read_bytes("retired-page-reclaim-order/2-leaf10-retired.dat");
    let file = read("retired-page-reclaim-order/2-leaf10-retired.dat");
    assert_eq!(index_free_head(&bytes, &file), 10);

    let bytes = read_bytes("retired-page-reclaim-order/4-both-retired.dat");
    let file = read("retired-page-reclaim-order/4-both-retired.dat");
    assert_eq!(index_free_head(&bytes, &file), 12, "the SECOND retirement becomes the new head");
    assert_eq!(retired_next(by_logical(&file, 12)), 10, "12's own link names the previous head");
    assert_eq!(retired_next(by_logical(&file, 10)), NOWHERE, "10 was first, so its link is NOWHERE");
}

/// Reclamation pulls from the free list's HEAD (the most recently retired
/// page) -- not the tail, and not the lowest logical id (12 > 10, and 12
/// is reclaimed first).
#[test]
fn a_split_reclaims_the_most_recently_retired_page_first() {
    let bytes = read_bytes("retired-page-reclaim-order/5-before-first-reclaim.dat");
    let file = read("retired-page-reclaim-order/5-before-first-reclaim.dat");
    assert_eq!(index_free_head(&bytes, &file), 12);

    let bytes = read_bytes("retired-page-reclaim-order/6-leaf12-reclaimed-first.dat");
    let file = read("retired-page-reclaim-order/6-leaf12-reclaimed-first.dat");
    assert!(by_logical(&file, 12).retired.is_none(), "logical 12 is reclaimed -- no longer retired");
    assert!(index_page(&file, 12).index.is_some(), "it is back to being an ordinary index page");
    assert_eq!(index_free_head(&bytes, &file), 10, "the chain's remaining link becomes the new head");

    let bytes = read_bytes("retired-page-reclaim-order/7-before-second-reclaim.dat");
    let file = read("retired-page-reclaim-order/7-before-second-reclaim.dat");
    assert_eq!(index_free_head(&bytes, &file), 10);

    let bytes = read_bytes("retired-page-reclaim-order/8-leaf10-reclaimed-second.dat");
    let file = read("retired-page-reclaim-order/8-leaf10-reclaimed-second.dat");
    assert!(by_logical(&file, 10).retired.is_none(), "logical 10 is reclaimed too");
    assert_eq!(index_free_head(&bytes, &file), NOWHERE, "the free list is empty again");
}
