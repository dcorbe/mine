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
