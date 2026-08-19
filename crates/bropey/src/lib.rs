//! A byte-first persistent rope.
//!
//! Bropey stores arbitrary bytes. It has no notion of characters, encodings,
//! or lines — a caller that needs those applies them on top. Cloning a `Rope`
//! is O(1) and shares structure; editing a shared rope copies O(log n) nodes
//! and leaves every other handle untouched.

mod iter;
#[cfg(test)]
mod proptests;
mod source;
mod tree;
mod tune;

pub use iter::Chunks;
pub use source::ByteSource;

use std::sync::Arc;

use crate::tree::Node;

/// A persistent rope over arbitrary bytes.
///
/// `clone` is O(1) and shares structure. Editing a rope that has been cloned
/// copies O(log n) nodes and leaves every other handle untouched.
#[derive(Clone, Debug)]
pub struct Rope {
    root: Arc<Node>,
}

impl Rope {
    /// An empty rope.
    pub fn new() -> Rope {
        Rope { root: Node::empty() }
    }

    /// Build a rope from bytes in O(n).
    pub fn from_bytes(bytes: &[u8]) -> Rope {
        Rope { root: tree::build(bytes) }
    }

    /// Total bytes.
    pub fn len(&self) -> usize {
        self.root.byte_len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate the rope's chunks in byte order.
    pub fn chunks(&self) -> Chunks<'_> {
        Chunks::new(&self.root)
    }

    /// Insert `bytes` at `offset`.
    ///
    /// Panics if `offset > self.len()`. Inserting at exactly `len()` appends.
    pub fn insert(&mut self, offset: usize, bytes: &[u8]) {
        let len = self.len();
        assert!(offset <= len, "insert offset {offset} exceeds rope length {len}");
        if bytes.is_empty() {
            return;
        }
        tree::insert_into(&mut self.root, offset, bytes);
    }

    /// Append `other` to the end of this rope.
    pub fn append(&mut self, other: Rope) {
        let root = std::mem::replace(&mut self.root, Node::empty());
        self.root = tree::append(root, other.root);
    }

    /// Assert every structural invariant. Test-only; call at operation
    /// boundaries.
    #[cfg(test)]
    pub(crate) fn check(&self) {
        tree::check_invariants(&self.root);
    }
}

impl Default for Rope {
    fn default() -> Rope {
        Rope::new()
    }
}

#[cfg(test)]
mod insert_api_tests {
    use super::*;
    use crate::ByteSource;

    #[test]
    fn insert_at_every_offset_of_a_multi_level_rope() {
        let base: Vec<u8> = (0..300).map(|i| (i % 251) as u8).collect();
        for offset in 0..=base.len() {
            let mut rope = Rope::from_bytes(&base);
            rope.insert(offset, b"XYZ");
            rope.check();
            let mut expect = base.clone();
            expect.splice(offset..offset, b"XYZ".iter().copied());
            assert_eq!(rope.to_vec(), expect, "differs inserting at {offset}");
        }
    }

    #[test]
    fn inserting_nothing_takes_the_fast_path_without_touching_the_root() {
        // Content equality alone can't discriminate this: `Vec::splice` with
        // an empty iterator is already a no-op, so removing the fast path
        // in `Rope::insert` would still leave `to_vec()` unchanged. Pin the
        // fast path itself by holding a shared root (via clone) and
        // checking identity: without the fast path, `insert_into` would
        // `Arc::make_mut` a shared root, which clones it and changes the
        // pointer even though the bytes end up equal.
        let mut rope = Rope::from_bytes(b"abc");
        let shared = rope.clone();
        rope.insert(1, &[]);
        assert!(Arc::ptr_eq(&rope.root, &shared.root), "empty insert touched the root");
        assert_eq!(rope.to_vec(), b"abc");
    }

    #[test]
    fn insert_at_the_end_is_legal() {
        let mut rope = Rope::from_bytes(b"abc");
        rope.insert(3, b"d");
        assert_eq!(rope.to_vec(), b"abcd");
    }

    #[test]
    #[should_panic(expected = "exceeds rope length")]
    fn insert_past_the_end_panics() {
        let mut rope = Rope::from_bytes(b"abc");
        rope.insert(4, b"d");
    }

    #[test]
    fn editing_a_clone_leaves_the_original_alone() {
        let original = Rope::from_bytes(&(0..300).map(|i| (i % 251) as u8).collect::<Vec<u8>>());
        let before = original.to_vec();
        let mut edited = original.clone();
        edited.insert(150, b"INTRUDER");
        assert_eq!(original.to_vec(), before, "the original was mutated through a shared node");
        assert_ne!(edited.to_vec(), before);
        original.check();
        edited.check();
    }
}

#[cfg(test)]
mod append_api_tests {
    use super::*;
    use crate::ByteSource;

    #[test]
    fn append_concatenates_and_leaves_clones_alone() {
        let left = Rope::from_bytes(&(0..200).map(|i| (i % 251) as u8).collect::<Vec<u8>>());
        let snapshot = left.clone();
        let before = snapshot.to_vec();
        let right = Rope::from_bytes(b"tail");

        let mut joined = left;
        joined.append(right);
        joined.check();

        let mut expect = before.clone();
        expect.extend_from_slice(b"tail");
        assert_eq!(joined.to_vec(), expect);
        assert_eq!(snapshot.to_vec(), before, "the snapshot was mutated");
    }
}
