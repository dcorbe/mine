//! The last reachable gap: what happens when an interior ROOT's own last
//! two children merge into one. Recorded by draining the exact 5-leaf,
//! depth-2 tree rounds 1 and 3 built (insert 1..120) all the way to empty,
//! not just the top half round 3 stopped at.
//!
//! Every fixture here decodes through plain `read::file` -- same as round
//! 4, no manual byte-parsing fallback needed.

use std::fs;
use std::path::{Path, PathBuf};

use btrieve::model::{Control, File, V6Page};

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

fn by_logical(file: &File, logical: u32) -> &V6Page {
    file.v6_pages
        .iter()
        .find(|p| u32::from(p.logical) == logical)
        .unwrap_or_else(|| panic!("no page with logical id {logical}"))
}

fn records(file: &File) -> u32 {
    let Control::Shadowed { live, .. } = &file.control else { panic!("v6 only") };
    live.records
}

fn index_free_head(bytes: &[u8], file: &File) -> u32 {
    let Control::Shadowed { live_is_page, .. } = &file.control else { panic!("v6 only") };
    let at = live_is_page * file.id.page_size as usize + btrieve::pages::fcr::INDEX_FREE_V6;
    btrieve::pages::long(&bytes[at..at + 4])
}

fn retired_next(page: &V6Page) -> u32 {
    let body = page.retired.as_ref().expect("a retired page");
    btrieve::pages::long(&body[2..6])
}

const NOWHERE: u32 = 0xffff_ffff;

/// **The core finding:** when an interior root's last entry disappears (its
/// two children merge), the tree drops a level. The SURVIVING CHILD becomes
/// the new root directly -- the FCR's `root_page` pointer moves to the
/// child's own logical id -- rather than the child's content being copied
/// into the old root's logical id. The vacated interior root is retired
/// into the exact same `0x4500` free list a retired LEAF uses, joining the
/// chain at its head like any other retirement.
#[test]
fn the_last_two_children_of_an_interior_root_collapse_the_tree_a_level() {
    let before_bytes = read_bytes("root-level-collapse/1-interior-root-one-entry.dat");
    let before = read("root-level-collapse/1-interior-root-one-entry.dat");
    let old_root = root_logical(&before);
    let root_page = by_logical(&before, old_root);
    let idx = root_page.index.as_ref().expect("an interior root");
    assert_eq!(idx.entries.len(), 1, "one entry left: two children, about to underflow");
    let left_child = idx.leftmost & 0x00ff_ffff;
    assert_ne!(idx.leftmost, 0, "a genuine interior node, not a virgin leaf");
    assert_eq!(records(&before), 41);
    assert_eq!(index_free_head(&before_bytes, &before), 10, "logical 10, retired earlier in this same cascade, is still the chain's head");

    let after_bytes = read_bytes("root-level-collapse/2-collapsed-to-single-level.dat");
    let after = read("root-level-collapse/2-collapsed-to-single-level.dat");
    let new_root = root_logical(&after);
    assert_eq!(new_root, left_child, "the FCR root pointer moved to the surviving child's own id");
    assert_ne!(new_root, old_root, "not the old root's id -- nothing was copied into it");
    let new_root_page = by_logical(&after, new_root);
    let idx = new_root_page.index.as_ref().expect("still a real index page");
    assert_eq!(idx.leftmost, NOWHERE, "a genuine (populated) leaf now, not an interior node");
    assert_eq!(idx.rightmost, NOWHERE);
    assert_eq!(idx.entries.len(), 40, "absorbed the other child's survivors AND the root's own key");
    assert_eq!(records(&after), 40);

    // The underflowing LEAF (logical 4, absorbed into 6) is retired too --
    // in the SAME operation as the interior root, not a separate step.
    let vacated_leaf = by_logical(&after, 4);
    assert!(vacated_leaf.retired.is_some(), "the absorbed leaf is retired, same as any ordinary merge");

    let old_root_page = by_logical(&after, old_root);
    assert!(old_root_page.retired.is_some(), "the vacated interior root is RETIRED, not orphaned or special-cased");
    assert_eq!(
        index_free_head(&after_bytes, &after),
        old_root,
        "the just-retired interior root becomes the free list's new head"
    );
    assert_eq!(
        retired_next(old_root_page),
        4,
        "the root's own link names the OTHER page retired in this same operation -- the absorbed leaf"
    );
    assert_eq!(
        retired_next(vacated_leaf),
        10,
        "the absorbed leaf's own link continues into the chain that existed before this operation"
    );
}

/// Continuing the drain past the collapse behaves like an ordinary
/// single-level tree -- nothing about having recently dropped a level
/// leaves a mark on later operations.
#[test]
fn the_collapsed_tree_keeps_draining_as_an_ordinary_single_level_tree() {
    let one_left = read("root-level-collapse/3-single-level-one-record.dat");
    assert_eq!(records(&one_left), 1);
    let root = by_logical(&one_left, root_logical(&one_left));
    let idx = root.index.as_ref().unwrap();
    assert_eq!(idx.entries.len(), 1);
    assert_eq!(idx.leftmost, NOWHERE, "a populated leaf: NOWHERE, not the virgin (zero-record) shape's zero");
    assert_eq!(idx.rightmost, NOWHERE);
}

/// The eventual empty state matches `delete-to-empty`'s own virgin shape
/// exactly -- SHAPE, not IDENTITY: the root's logical id here (6) is not
/// the file's original root id (1, at creation), because the collapse
/// changed which id holds the root role partway through the drain.
#[test]
fn draining_all_the_way_reaches_the_same_virgin_shape_as_delete_to_empty() {
    let emptied = read("root-level-collapse/4-drained-to-empty.dat");
    assert_eq!(records(&emptied), 0);
    let root_log = root_logical(&emptied);
    assert_ne!(root_log, 1, "the root's IDENTITY changed at the collapse -- it is no longer the original id 1");
    let root = by_logical(&emptied, root_log);
    let idx = root.index.as_ref().expect("still a real (if empty) index page");
    assert_eq!(idx.entries.len(), 0);
    assert_eq!(idx.leftmost, 0, "virgin shape: leftmost is zero");
    assert_eq!(idx.rightmost, NOWHERE, "virgin shape: rightmost is NOWHERE");
}
