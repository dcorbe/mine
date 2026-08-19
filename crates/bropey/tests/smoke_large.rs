//! Production-constant tests.
//!
//! Everything under `src/` runs at the tiny `cfg(test)` constants so that
//! unit tests build deep trees out of a few dozen bytes. This file is an
//! integration test precisely so it does *not* get those: it links the library
//! as a dependency, at `MAX_BYTES = 1024`, and is the only coverage of the
//! shape the crate actually ships with.

use bropey::{ByteSource, Rope};

fn seq(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

const MB: usize = 1024 * 1024;

#[test]
fn ten_megabytes_round_trip() {
    let bytes = seq(10 * MB);
    let rope = Rope::from_bytes(&bytes);
    assert_eq!(rope.len(), bytes.len());
    assert_eq!(rope.to_vec(), bytes);
}

#[test]
fn interior_edits_on_a_ten_megabyte_rope() {
    let bytes = seq(10 * MB);
    let mut rope = Rope::from_bytes(&bytes);
    let mut model = bytes.clone();

    for step in 0..64 {
        let at = (step * 149_837) % model.len();
        rope.insert(at, b"needle");
        model.splice(at..at, b"needle".iter().copied());
    }
    assert_eq!(rope.len(), model.len());
    assert_eq!(rope.to_vec(), model);
}

#[test]
fn a_multi_megabyte_splice_shares_structure() {
    let base = seq(5 * MB);
    let insert = seq(5 * MB);
    let mut rope = Rope::from_bytes(&base);
    rope.insert_rope(2 * MB, &Rope::from_bytes(&insert));

    let mut model = base.clone();
    model.splice(2 * MB..2 * MB, insert.iter().copied());
    assert_eq!(rope.len(), model.len());
    assert_eq!(rope.to_vec(), model);
}

#[test]
fn slicing_a_large_rope_agrees_with_the_slice_of_the_bytes() {
    let bytes = seq(4 * MB);
    let rope = Rope::from_bytes(&bytes);
    for (start, end) in [(0, MB), (MB, 3 * MB), (4 * MB - 7, 4 * MB), (0, 4 * MB)] {
        assert_eq!(rope.slice(start..end).to_vec(), &bytes[start..end]);
    }
}

#[test]
fn a_clone_survives_heavy_editing_of_the_original() {
    let bytes = seq(2 * MB);
    let original = Rope::from_bytes(&bytes);
    let snapshot = original.clone();

    let mut edited = original;
    for step in 0..200 {
        let at = (step * 9_973) % edited.len();
        edited.remove(at..at + 1);
    }

    assert_eq!(snapshot.len(), bytes.len());
    assert_eq!(snapshot.to_vec(), bytes, "the snapshot was mutated");
}
