//! The tree itself.

mod build;
mod children;
#[cfg(test)]
mod invariants;

pub(crate) use build::build;
pub(crate) use children::Children;
#[cfg(test)]
pub(crate) use invariants::check_invariants;

use std::sync::Arc;

use crate::tune::{MAX_BYTES, MAX_CHILDREN};

/// A node of the rope's B-tree.
///
/// A leaf holds bytes directly; an internal node holds `Arc`-shared children
/// and their cached byte counts. Nothing outside `Children` may write those
/// counts.
#[derive(Clone, Debug)]
pub(crate) enum Node {
    Leaf(Vec<u8>),
    Internal(Children),
}

impl Node {
    /// The canonical empty tree: a root leaf holding no bytes.
    pub(crate) fn empty() -> Arc<Node> {
        Arc::new(Node::Leaf(Vec::new()))
    }

    /// Total bytes in this subtree. Bounded by `MAX_CHILDREN` additions, so
    /// O(1) in the size of the rope. Nothing caches this: a third derived
    /// field would be a third thing to desynchronise.
    pub(crate) fn byte_len(&self) -> usize {
        match self {
            Node::Leaf(buf) => buf.len(),
            Node::Internal(children) => children.total(),
        }
    }

    /// Distance to the leaves. Leaves are height 0.
    pub(crate) fn height(&self) -> u8 {
        match self {
            Node::Leaf(_) => 0,
            Node::Internal(children) => children.height(),
        }
    }

    /// Insert `bytes` at `offset`, returning this node's new right sibling if
    /// it split.
    ///
    /// `bytes.len()` must not exceed `MAX_BYTES`. That bound is what
    /// guarantees a single split is always enough: a full leaf receiving a
    /// full insert reaches `2 * MAX_BYTES`, and halving that lands exactly on
    /// the limit. Callers route anything larger through the bulk path.
    pub(crate) fn insert(&mut self, offset: usize, bytes: &[u8]) -> Option<Arc<Node>> {
        debug_assert!(
            bytes.len() <= MAX_BYTES,
            "direct insert of {} bytes exceeds MAX_BYTES {MAX_BYTES}",
            bytes.len()
        );
        match self {
            Node::Leaf(buf) => {
                buf.splice(offset..offset, bytes.iter().copied());
                if buf.len() <= MAX_BYTES {
                    None
                } else {
                    let half = buf.len() / 2;
                    Some(Arc::new(Node::Leaf(buf.split_off(half))))
                }
            }
            Node::Internal(children) => {
                let (index, local) = children.locate_insert(offset);
                let split = children.with_child_mut(index, |child| child.insert(local, bytes));
                let sibling = split?;
                children.insert_at(index + 1, sibling);
                overflow(children)
            }
        }
    }
}

/// Split an internal node if it is over capacity, returning its new right
/// sibling. Both halves clear `MIN_CHILDREN` because `2 * MIN_CHILDREN <=
/// MAX_CHILDREN` is asserted at compile time.
pub(crate) fn overflow(children: &mut Children) -> Option<Arc<Node>> {
    if children.len() <= MAX_CHILDREN {
        None
    } else {
        let half = children.len() / 2;
        Some(Arc::new(Node::Internal(children.split_off(half))))
    }
}

/// Wrap a root and its new sibling in a fresh root, if it split.
pub(crate) fn grow(root: Arc<Node>, split: Option<Arc<Node>>) -> Arc<Node> {
    match split {
        None => root,
        Some(sibling) => Arc::new(Node::Internal(Children::from_pair(root, sibling))),
    }
}

/// Insert into a root, growing the tree by one level if the root splits.
pub(crate) fn insert_into(root: &mut Arc<Node>, offset: usize, bytes: &[u8]) {
    let split = Arc::make_mut(root).insert(offset, bytes);
    if split.is_some() {
        let old = std::mem::replace(root, Node::empty());
        *root = grow(old, split);
    }
}

#[cfg(test)]
mod insert_tests {
    use super::*;
    use crate::tune::{MAX_BYTES, MIN_BYTES};

    #[test]
    fn a_leaf_splits_into_two_legal_halves() {
        // The worst case the direct path can produce: a full leaf receiving a
        // full insert. One split must always be enough, and both halves must
        // clear MIN_BYTES.
        let mut node = Node::Leaf(vec![1u8; MAX_BYTES]);
        let split = node.insert(0, &vec![2u8; MAX_BYTES]);
        let rhs = split.expect("must split");
        assert!(node.byte_len() <= MAX_BYTES, "left half is oversized");
        assert!(rhs.byte_len() <= MAX_BYTES, "right half is oversized");
        assert!(node.byte_len() >= MIN_BYTES, "left half is underfull");
        assert!(rhs.byte_len() >= MIN_BYTES, "right half is underfull");
        assert_eq!(node.byte_len() + rhs.byte_len(), 2 * MAX_BYTES);
    }

    #[test]
    fn a_small_insert_into_a_small_leaf_does_not_split() {
        let mut node = Node::Leaf(vec![1u8; 2]);
        assert!(node.insert(1, &[9]).is_none());
        let Node::Leaf(buf) = &node else { unreachable!() };
        assert_eq!(buf.as_slice(), &[1, 9, 1]);
    }
}
