use std::sync::Arc;

use crate::tree::{grow, insert_into, Children, Node};
use crate::tune::MIN_BYTES;

/// Concatenate two trees into one balanced tree.
///
/// This is the only balancing code in the crate. `split`, `remove`, `slice`
/// and `insert_rope` all compose from it.
pub(crate) fn append(left: Arc<Node>, right: Arc<Node>) -> Arc<Node> {
    if right.byte_len() == 0 {
        return left;
    }
    if left.byte_len() == 0 {
        return right;
    }

    // A side below MIN_BYTES can only be a lone leaf, because every non-root
    // leaf in a well-formed tree clears the minimum. Route it through the
    // ordinary insert path so it is absorbed into a neighbouring leaf instead
    // of being left standing at a join. This is what removes seam repair from
    // the design: joining two trees that each satisfy the leaf minimum makes
    // their adjacent leaves legal by construction.
    if right.byte_len() < MIN_BYTES {
        let bytes = lone_leaf_bytes(&right);
        let mut root = left;
        let end = root.byte_len();
        insert_into(&mut root, end, &bytes);
        return root;
    }
    if left.byte_len() < MIN_BYTES {
        let bytes = lone_leaf_bytes(&left);
        let mut root = right;
        insert_into(&mut root, 0, &bytes);
        return root;
    }

    join(left, right)
}

fn lone_leaf_bytes(node: &Arc<Node>) -> Vec<u8> {
    match &**node {
        Node::Leaf(buf) => buf.clone(),
        Node::Internal(_) => unreachable!(
            "a well-formed tree below MIN_BYTES is always a single leaf"
        ),
    }
}

/// Join two trees that both clear `MIN_BYTES`, by height.
fn join(left: Arc<Node>, right: Arc<Node>) -> Arc<Node> {
    let (left_height, right_height) = (left.height(), right.height());

    if left_height == right_height {
        return Arc::new(Node::Internal(Children::from_pair(left, right)));
    }

    if left_height > right_height {
        let mut root = left;
        let split = Arc::make_mut(&mut root).attach_right(right);
        grow(root, split)
    } else {
        let mut root = right;
        let split = Arc::make_mut(&mut root).attach_left(left);
        grow(root, split)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::{build, check_invariants};
    use crate::tune::MIN_BYTES;

    fn seq(from: usize, n: usize) -> Vec<u8> {
        (from..from + n).map(|i| (i % 251) as u8).collect()
    }

    fn bytes_of(root: &Arc<Node>) -> Vec<u8> {
        match &**root {
            Node::Leaf(buf) => buf.clone(),
            Node::Internal(children) => {
                let mut out = Vec::new();
                for i in 0..children.len() {
                    out.extend_from_slice(&bytes_of(children.node(i)));
                }
                out
            }
        }
    }

    #[test]
    fn appending_to_or_from_empty_returns_the_other_side() {
        let full = build(&seq(0, 100));
        let joined = append(Node::empty(), Arc::clone(&full));
        assert_eq!(bytes_of(&joined), seq(0, 100));
        let joined = append(Arc::clone(&full), Node::empty());
        assert_eq!(bytes_of(&joined), seq(0, 100));
    }

    #[test]
    fn every_pair_of_sizes_concatenates_and_stays_balanced() {
        // Crosses matched heights, both mismatched directions, and — crucially
        // — every case where one side is below MIN_BYTES and must be absorbed
        // rather than joined.
        for left_len in [0usize, 1, MIN_BYTES - 1, MIN_BYTES, 20, 100, 400] {
            for right_len in [0usize, 1, MIN_BYTES - 1, MIN_BYTES, 20, 100, 400] {
                let left = build(&seq(0, left_len));
                let right = build(&seq(left_len, right_len));
                let joined = append(left, right);
                check_invariants(&joined);
                assert_eq!(
                    bytes_of(&joined),
                    seq(0, left_len + right_len),
                    "differs joining {left_len} + {right_len}"
                );
            }
        }
    }

    #[test]
    fn an_underfull_side_is_absorbed_not_left_standing() {
        // A one-byte tree joined to a big one must not survive as a one-byte
        // leaf. Without the small-piece route this passes content checks and
        // fails the invariant check, which is exactly why both run.
        let big = build(&seq(0, 400));
        let tiny = build(&seq(400, 1));
        let joined = append(big, tiny);
        check_invariants(&joined);
        assert_eq!(bytes_of(&joined), seq(0, 401));
    }

    #[test]
    fn repeated_small_appends_do_not_degenerate_the_tree() {
        let mut root = Node::empty();
        for i in 0..400 {
            root = append(root, build(&[(i % 251) as u8]));
            check_invariants(&root);
        }
        assert_eq!(root.byte_len(), 400);
    }

    // The following two tests go beyond the brief: they actively probe the
    // design's no-seam-repair claim (that a well-formed tree below MIN_BYTES
    // is always a single leaf, so `append` never needs to patch up a stranded
    // underfull edge leaf) at scale and under multi-level recursion, rather
    // than just at the sizes the brief calls out.

    // Deterministic splitmix64 so this doesn't need the `rand` crate (a
    // runtime dependency ban applies here regardless, but staying
    // dependency-free is simplest for a test-only helper).
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    #[test]
    fn hammer_mixed_small_and_large_appends_from_both_ends() {
        // Try hard to break the no-seam-repair claim: build a real multi-level
        // tree, then interleave hundreds of appends whose sizes deliberately
        // dance around MIN_BYTES from both the growing tree's side and the
        // freshly-built operand's side, in both left and right position,
        // across many different resulting heights. If any append call ever
        // leaves an edge leaf underfull, check_invariants must catch it here.
        let mut rng = Rng(0x9e3779b97f4a7c15);
        let mut root = Node::empty();
        let mut model: Vec<u8> = Vec::new();
        let mut next_byte = 0usize;

        // Kinds of size to try at each step, named rather than counted so no
        // bare literal stands in for how many there are.
        enum SizeKind {
            Empty,
            One,
            JustUnderMin,
            AtMin,
            JustOverMin,
            SmallRandom,
            LargeRandom,
        }
        let kinds = [
            SizeKind::Empty,
            SizeKind::One,
            SizeKind::JustUnderMin,
            SizeKind::AtMin,
            SizeKind::JustOverMin,
            SizeKind::SmallRandom,
            SizeKind::LargeRandom,
        ];

        for step in 0..2000 {
            // Sizes that straddle MIN_BYTES on both sides, plus occasional
            // large pieces to force height mismatches during join.
            let len = match kinds[step % kinds.len()] {
                SizeKind::Empty => 0,
                SizeKind::One => 1,
                SizeKind::JustUnderMin => MIN_BYTES - 1,
                SizeKind::AtMin => MIN_BYTES,
                SizeKind::JustOverMin => MIN_BYTES + 1,
                SizeKind::SmallRandom => rng.below(50),
                SizeKind::LargeRandom => rng.below(500),
            };
            let chunk = seq(next_byte, len);
            next_byte += len;
            let piece = build(&chunk);

            if rng.below(2) == 0 {
                root = append(root, piece);
                model.extend_from_slice(&chunk);
            } else {
                root = append(piece, root);
                let mut new_model = chunk.clone();
                new_model.extend_from_slice(&model);
                model = new_model;
            }

            check_invariants(&root);
            assert_eq!(bytes_of(&root), model, "content diverged at step {step}");
        }
    }

    #[test]
    fn joining_two_deep_trees_of_very_different_height_stays_legal() {
        // Force join()'s height-mismatch branch to recurse through several
        // levels (not just one), on both the attach_right and attach_left
        // paths, and on both directions of height difference.
        for (small_len, big_len) in [(1usize, 3000usize), (MIN_BYTES, 3000), (20, 5000)] {
            let small = build(&seq(0, small_len));
            let big = build(&seq(small_len, big_len));
            assert!(
                big.height() > small.height() + 1,
                "test setup must actually force multi-level recursion: {} vs {}",
                big.height(),
                small.height()
            );

            // small appended after big: right side is the short tree, so this
            // exercises attach_right's multi-level descent.
            let right_join = append(Arc::clone(&big), Arc::clone(&small));
            check_invariants(&right_join);
            let mut expect = seq(small_len, big_len);
            expect.extend(seq(0, small_len));
            assert_eq!(bytes_of(&right_join), expect, "big-then-small content differs");

            // small appended before big: left side is the short tree, so this
            // exercises attach_left's multi-level descent.
            let left_join = append(Arc::clone(&small), Arc::clone(&big));
            check_invariants(&left_join);
            expect = seq(0, small_len);
            expect.extend(seq(small_len, big_len));
            assert_eq!(bytes_of(&left_join), expect, "small-then-big content differs");
        }
    }
}
