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

use std::ops::Range;
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
        if bytes.len() <= tune::BULK_THRESHOLD {
            // One descent. Routing this through split/append would be several
            // times slower on the common case.
            tree::insert_into(&mut self.root, offset, bytes);
        } else {
            // Bulk-build in O(m) and splice, rather than shattering one leaf
            // into thousands and cascading a split per leaf.
            self.insert_rope(offset, &Rope::from_bytes(bytes));
        }
    }

    /// Insert `other` at `offset`, sharing its structure rather than copying
    /// its bytes. A multi-megabyte splice is pointer work.
    ///
    /// Panics if `offset > self.len()`.
    pub fn insert_rope(&mut self, offset: usize, other: &Rope) {
        let len = self.len();
        assert!(offset <= len, "insert offset {offset} exceeds rope length {len}");
        if other.is_empty() {
            return;
        }
        let (left, right) = tree::split(&self.root, offset);
        let joined = tree::append(left, Arc::clone(&other.root));
        self.root = tree::append(joined, right);
    }

    /// Remove `range`.
    ///
    /// Panics if `range.start > range.end` or `range.end > self.len()`.
    pub fn remove(&mut self, range: Range<usize>) {
        let len = self.len();
        assert!(
            range.start <= range.end,
            "invalid range {}..{}",
            range.start,
            range.end
        );
        assert!(range.end <= len, "range end {} exceeds rope length {len}", range.end);
        if range.start == range.end {
            return;
        }
        let (head, rest) = tree::split(&self.root, range.start);
        let (_removed, tail) = tree::split(&rest, range.end - range.start);
        self.root = tree::append(head, tail);
    }

    /// The sub-rope over `range`, sharing structure with this one.
    ///
    /// Panics if `range.start > range.end` or `range.end > self.len()`.
    pub fn slice(&self, range: Range<usize>) -> Rope {
        let len = self.len();
        assert!(
            range.start <= range.end,
            "invalid range {}..{}",
            range.start,
            range.end
        );
        assert!(range.end <= len, "range end {} exceeds rope length {len}", range.end);
        let (_head, rest) = tree::split(&self.root, range.start);
        let (middle, _tail) = tree::split(&rest, range.end - range.start);
        Rope { root: middle }
    }

    /// Append `other` to the end of this rope.
    pub fn append(&mut self, other: Rope) {
        let root = std::mem::replace(&mut self.root, Node::empty());
        self.root = tree::append(root, other.root);
    }

    /// Split the rope at `at`, keeping `..at` and returning `at..`.
    ///
    /// Panics if `at > self.len()`.
    pub fn split_off(&mut self, at: usize) -> Rope {
        let len = self.len();
        assert!(at <= len, "split offset {at} exceeds rope length {len}");
        let (left, right) = tree::split(&self.root, at);
        self.root = left;
        Rope { root: right }
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

#[cfg(test)]
mod split_api_tests {
    use super::*;
    use crate::ByteSource;

    #[test]
    fn split_off_partitions_and_leaves_clones_alone() {
        let bytes: Vec<u8> = (0..300).map(|i| (i % 251) as u8).collect();
        let original = Rope::from_bytes(&bytes);
        let snapshot = original.clone();

        let mut left = original;
        let right = left.split_off(137);
        left.check();
        right.check();

        assert_eq!(left.to_vec(), &bytes[..137]);
        assert_eq!(right.to_vec(), &bytes[137..]);
        assert_eq!(snapshot.to_vec(), bytes, "the snapshot was mutated");
    }

    #[test]
    fn split_off_at_the_ends_is_legal() {
        let mut rope = Rope::from_bytes(b"abc");
        let tail = rope.split_off(3);
        assert!(tail.is_empty());
        assert_eq!(rope.to_vec(), b"abc");

        let mut rope = Rope::from_bytes(b"abc");
        let tail = rope.split_off(0);
        assert!(rope.is_empty());
        assert_eq!(tail.to_vec(), b"abc");
    }

    #[test]
    #[should_panic(expected = "exceeds rope length")]
    fn split_off_past_the_end_panics() {
        let mut rope = Rope::from_bytes(b"abc");
        let _ = rope.split_off(4);
    }
}

#[cfg(test)]
mod composition_tests {
    use super::*;
    use crate::tune::BULK_THRESHOLD;
    use crate::ByteSource;

    fn seq(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn remove_every_range_of_a_multi_level_rope() {
        let bytes = seq(200);
        for start in (0..=200).step_by(7) {
            for end in (start..=200).step_by(11) {
                let mut rope = Rope::from_bytes(&bytes);
                rope.remove(start..end);
                rope.check();
                let mut expect = bytes.clone();
                expect.drain(start..end);
                assert_eq!(rope.to_vec(), expect, "differs removing {start}..{end}");
            }
        }
    }

    #[test]
    fn repeated_single_byte_removals_keep_the_tree_legal() {
        // The degeneration case: remove is split-then-append, so if small
        // pieces were joined rather than absorbed this collapses into a tree
        // of one-byte leaves and the invariant check fires.
        let mut rope = Rope::from_bytes(&seq(300));
        for _ in 0..250 {
            let at = rope.len() / 2;
            rope.remove(at..at + 1);
            rope.check();
        }
        assert_eq!(rope.len(), 50);
    }

    #[test]
    fn slice_every_range_and_leave_the_source_alone() {
        let bytes = seq(200);
        let rope = Rope::from_bytes(&bytes);
        for start in (0..=200).step_by(13) {
            for end in (start..=200).step_by(17) {
                let piece = rope.slice(start..end);
                piece.check();
                assert_eq!(piece.to_vec(), &bytes[start..end], "differs slicing {start}..{end}");
            }
        }
        assert_eq!(rope.to_vec(), bytes, "slicing must not mutate the source");
    }

    #[test]
    fn insert_rope_splices_at_every_offset() {
        let base = seq(200);
        let inserted = seq(150);
        for at in [0usize, 1, 99, 200] {
            let mut rope = Rope::from_bytes(&base);
            rope.insert_rope(at, &Rope::from_bytes(&inserted));
            rope.check();
            let mut expect = base.clone();
            expect.splice(at..at, inserted.iter().copied());
            assert_eq!(rope.to_vec(), expect, "differs splicing at {at}");
        }
    }

    #[test]
    fn insert_rope_shares_structure_instead_of_copying() {
        // Content equality alone can't discriminate "shared the subtree" from
        // "copied its bytes into a fresh leaf" -- both produce the same
        // to_vec(). Arc::strong_count on `other`'s root does discriminate, at
        // an offset chosen so neither side of the self-split is small enough
        // for `append` to absorb it byte-by-byte (that absorption is by
        // design for remainders below MIN_BYTES -- see append.rs -- and it
        // legitimately path-copies the just-cloned Arc away, so this check
        // is offset-sensitive and only meaningful away from that boundary).
        //
        // `inserted` must clear MIN_BYTES for the same reason: append routes
        // anything smaller through insert's byte copy by design.
        let base = seq(200);
        let inserted = seq(150);
        let other = Rope::from_bytes(&inserted);
        let before = Arc::strong_count(&other.root);

        let mut rope = Rope::from_bytes(&base);
        rope.insert_rope(100, &other);

        assert!(
            Arc::strong_count(&other.root) > before,
            "insert_rope copied instead of sharing structure",
        );
        rope.check();
        let mut expect = base.clone();
        expect.splice(100..100, inserted.iter().copied());
        assert_eq!(rope.to_vec(), expect);
    }

    #[test]
    fn a_large_insert_takes_the_bulk_route_and_agrees_with_the_direct_one() {
        let base = seq(100);
        let big = seq(BULK_THRESHOLD * 4);
        assert!(big.len() > BULK_THRESHOLD, "must exceed the routing threshold");
        let mut rope = Rope::from_bytes(&base);
        rope.insert(50, &big);
        rope.check();
        let mut expect = base.clone();
        expect.splice(50..50, big.iter().copied());
        assert_eq!(rope.to_vec(), expect);
    }

    #[test]
    fn an_empty_range_is_a_no_op() {
        let mut rope = Rope::from_bytes(b"abc");
        rope.remove(1..1);
        assert_eq!(rope.to_vec(), b"abc");
        assert_eq!(rope.slice(1..1).len(), 0);
    }

    #[test]
    #[should_panic(expected = "exceeds rope length")]
    fn remove_past_the_end_panics() {
        let mut rope = Rope::from_bytes(b"abc");
        rope.remove(1..4);
    }

    #[test]
    #[should_panic(expected = "invalid range")]
    #[allow(clippy::reversed_empty_ranges)] // the inverted range is the input under test
    fn a_backwards_range_panics() {
        let mut rope = Rope::from_bytes(b"abc");
        rope.remove(2..1);
    }
}
