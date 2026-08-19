use crate::tree::Node;
use crate::tune::{MAX_BYTES, MAX_CHILDREN, MIN_BYTES, MIN_CHILDREN};

/// Assert every structural invariant of the tree.
///
/// Call this at operation boundaries only. Mutating routines transiently
/// exceed the maximum-occupancy bounds — an insert splices into a leaf before
/// splitting it — so the maximum assertions are false mid-operation by design.
pub(crate) fn check_invariants(root: &Node) {
    check(root, true);
}

/// Returns `(height, byte_len)` of the subtree, verifying it on the way.
fn check(node: &Node, is_root: bool) -> (u8, usize) {
    match node {
        Node::Leaf(buf) => {
            assert!(
                buf.len() <= MAX_BYTES,
                "leaf of {} bytes exceeds MAX_BYTES {MAX_BYTES}",
                buf.len()
            );
            if !is_root {
                assert!(
                    buf.len() >= MIN_BYTES,
                    "non-root leaf of {} bytes is below MIN_BYTES {MIN_BYTES}",
                    buf.len()
                );
            }
            (0, buf.len())
        }
        Node::Internal(children) => {
            assert!(
                children.len() >= 2,
                "internal node has {} children; nothing in this design removes a child",
                children.len()
            );
            assert!(
                children.len() <= MAX_CHILDREN,
                "internal node with {} children exceeds MAX_CHILDREN {MAX_CHILDREN}",
                children.len()
            );
            if !is_root {
                assert!(
                    children.len() >= MIN_CHILDREN,
                    "non-root internal node with {} children is below MIN_CHILDREN {MIN_CHILDREN}",
                    children.len()
                );
            }

            let mut total = 0;
            let mut child_height: Option<u8> = None;
            for i in 0..children.len() {
                let (height, len) = check(children.node(i), false);
                assert_eq!(
                    children.size(i),
                    len,
                    "cached size {} disagrees with subtree length {len} at child {i}",
                    children.size(i)
                );
                match child_height {
                    None => child_height = Some(height),
                    Some(prev) => assert_eq!(prev, height, "children at differing heights"),
                }
                total += len;
            }

            let height = child_height.expect("non-empty, asserted above") + 1;
            assert_eq!(
                children.height(),
                height,
                "stored height {} disagrees with actual {height}",
                children.height()
            );
            (height, total)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::Children;
    use std::sync::Arc;

    fn leaf(n: usize) -> Arc<Node> {
        Arc::new(Node::Leaf(vec![0u8; n]))
    }

    #[test]
    fn a_lone_root_leaf_may_be_underfull() {
        check_invariants(&Node::Leaf(vec![1, 2, 3]));
        check_invariants(&Node::Leaf(Vec::new()));
    }

    #[test]
    fn a_well_formed_two_level_tree_passes() {
        let root = Node::Internal(Children::from_pair(leaf(MIN_BYTES), leaf(MIN_BYTES)));
        check_invariants(&root);
    }

    #[test]
    #[should_panic(expected = "exceeds MAX_BYTES")]
    fn catches_an_oversized_leaf() {
        check_invariants(&Node::Leaf(vec![0u8; MAX_BYTES + 1]));
    }

    #[test]
    #[should_panic(expected = "below MIN_BYTES")]
    fn catches_an_underfull_non_root_leaf() {
        let root = Node::Internal(Children::from_pair(leaf(MIN_BYTES), leaf(MIN_BYTES - 1)));
        check_invariants(&root);
    }

    #[test]
    #[should_panic(expected = "disagrees with subtree length")]
    fn catches_a_desynchronised_cached_size() {
        let mut children = Children::from_pair(leaf(MIN_BYTES), leaf(MIN_BYTES));
        children.corrupt_size_for_test(0, MIN_BYTES + 1);
        check_invariants(&Node::Internal(children));
    }

    #[test]
    #[should_panic(expected = "children at differing heights")]
    fn catches_ragged_depth() {
        let deep = Arc::new(Node::Internal(Children::from_pair(
            leaf(MIN_BYTES),
            leaf(MIN_BYTES),
        )));
        let mut children = Children::new(2);
        children.push(deep);
        children.push_ragged_for_test(leaf(MIN_BYTES));
        check_invariants(&Node::Internal(children));
    }

    #[test]
    #[should_panic(expected = "exceeds MAX_CHILDREN")]
    fn catches_an_overfull_internal_node() {
        let mut children = Children::new(1);
        for _ in 0..(MAX_CHILDREN + 1) {
            children.push(leaf(MIN_BYTES));
        }
        check_invariants(&Node::Internal(children));
    }
}
