use std::sync::Arc;

use crate::tree::{Children, Node};
use crate::tune::{MAX_BYTES, MAX_CHILDREN, MIN_BYTES, MIN_CHILDREN};

/// Build a balanced tree from `bytes`, bottom-up, in O(n).
///
/// Every size is known in advance, so no rebalancing is needed: leaves are
/// filled to capacity and internal levels laid on top. The two redistribution
/// rules exist so the final leaf and the final group are never left below
/// their minimums.
pub(crate) fn build(bytes: &[u8]) -> Arc<Node> {
    if bytes.len() <= MAX_BYTES {
        return Arc::new(Node::Leaf(bytes.to_vec()));
    }

    let mut level: Vec<Arc<Node>> = Vec::new();
    let mut rest = bytes;
    while rest.len() > MAX_BYTES {
        let take = if rest.len() - MAX_BYTES < MIN_BYTES {
            // A full leaf here would strand a tail below MIN_BYTES; halve instead.
            rest.len() / 2
        } else {
            MAX_BYTES
        };
        let (head, tail) = rest.split_at(take);
        level.push(Arc::new(Node::Leaf(head.to_vec())));
        rest = tail;
    }
    level.push(Arc::new(Node::Leaf(rest.to_vec())));

    let mut height = 1u8;
    while level.len() > 1 {
        let mut next: Vec<Arc<Node>> = Vec::new();
        let mut i = 0;
        while i < level.len() {
            let remaining = level.len() - i;
            let take = if remaining > MAX_CHILDREN && remaining - MAX_CHILDREN < MIN_CHILDREN {
                remaining / 2
            } else {
                MAX_CHILDREN.min(remaining)
            };
            let mut group = Children::new(height);
            for node in &level[i..i + take] {
                group.push(Arc::clone(node));
            }
            next.push(Arc::new(Node::Internal(group)));
            i += take;
        }
        level = next;
        height += 1;
    }

    level.pop().expect("the loop leaves exactly one node")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::check_invariants;

    fn seq(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    fn collect(root: &Node) -> Vec<u8> {
        match root {
            Node::Leaf(buf) => buf.clone(),
            Node::Internal(children) => {
                let mut out = Vec::new();
                for i in 0..children.len() {
                    out.extend_from_slice(&collect(children.node(i)));
                }
                out
            }
        }
    }

    #[test]
    fn empty_input_builds_an_empty_root_leaf() {
        let root = build(&[]);
        assert_eq!(root.byte_len(), 0);
        assert_eq!(root.height(), 0);
        check_invariants(&root);
    }

    #[test]
    fn input_up_to_one_leaf_stays_a_single_leaf() {
        let bytes = seq(MAX_BYTES);
        let root = build(&bytes);
        assert_eq!(root.height(), 0);
        assert_eq!(collect(&root), bytes);
        check_invariants(&root);
    }

    #[test]
    fn every_size_round_trips_and_stays_balanced() {
        // Spans several tree levels at test constants, and crosses each
        // awkward boundary: one past a leaf, one past a full node, and the
        // sizes where the last-group redistribution kicks in.
        for n in 0..600 {
            let bytes = seq(n);
            let root = build(&bytes);
            assert_eq!(collect(&root), bytes, "content differs at n={n}");
            assert_eq!(root.byte_len(), n, "length differs at n={n}");
            check_invariants(&root);
        }
    }
}
