//! The tree itself.

mod build;
mod children;
mod invariants;

pub(crate) use build::build;
pub(crate) use children::Children;
pub(crate) use invariants::check_invariants;

use std::sync::Arc;

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
}
