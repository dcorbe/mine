use std::sync::Arc;

use crate::tree::{append, Node};

/// Split `root` at byte `at`, returning two balanced trees.
///
/// Nothing is mutated: siblings are shared by `Arc` clone, and only the leaf
/// that `at` falls inside is copied.
pub(crate) fn split(root: &Arc<Node>, at: usize) -> (Arc<Node>, Arc<Node>) {
    let mut left = Vec::new();
    let mut right = Vec::new();
    collect(root, at, &mut left, &mut right);
    (fold(left), fold(right))
}

/// Walk to `at`, pushing whole valid subtrees into `left` and `right` in byte
/// order.
///
/// Each piece is a complete, well-formed subtree — never a node stripped of
/// children — which is why no node in this crate ever underflows. Pieces come
/// out in descending height order, so folding them left to right attaches
/// smaller trees onto larger ones.
fn collect(
    node: &Arc<Node>,
    at: usize,
    left: &mut Vec<Arc<Node>>,
    right: &mut Vec<Arc<Node>>,
) {
    match &**node {
        Node::Leaf(buf) => {
            if at > 0 {
                left.push(Arc::new(Node::Leaf(buf[..at].to_vec())));
            }
            if at < buf.len() {
                right.push(Arc::new(Node::Leaf(buf[at..].to_vec())));
            }
        }
        Node::Internal(children) => {
            let (index, local) = children.locate_insert(at);
            for k in 0..index {
                left.push(Arc::clone(children.node(k)));
            }
            collect(children.node(index), local, left, right);
            for k in (index + 1)..children.len() {
                right.push(Arc::clone(children.node(k)));
            }
        }
    }
}

fn fold(pieces: Vec<Arc<Node>>) -> Arc<Node> {
    pieces.into_iter().fold(Node::empty(), append)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::{build, check_invariants};

    fn seq(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
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
    fn splitting_at_every_offset_partitions_the_bytes() {
        let bytes = seq(300);
        let root = build(&bytes);
        for at in 0..=bytes.len() {
            let (left, right) = split(&root, at);
            check_invariants(&left);
            check_invariants(&right);
            assert_eq!(bytes_of(&left), &bytes[..at], "left differs at {at}");
            assert_eq!(bytes_of(&right), &bytes[at..], "right differs at {at}");
        }
    }

    #[test]
    fn splitting_does_not_disturb_the_original() {
        let bytes = seq(300);
        let root = build(&bytes);
        let (_left, _right) = split(&root, 137);
        assert_eq!(bytes_of(&root), bytes, "split must not mutate its input");
        check_invariants(&root);
    }

    #[test]
    fn split_then_append_is_the_identity() {
        let bytes = seq(300);
        let root = build(&bytes);
        for at in [0usize, 1, 7, 150, 299, 300] {
            let (left, right) = split(&root, at);
            let rejoined = crate::tree::append(left, right);
            check_invariants(&rejoined);
            assert_eq!(bytes_of(&rejoined), bytes, "round trip differs at {at}");
        }
    }
}
