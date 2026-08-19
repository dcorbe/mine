use std::sync::Arc;

use crate::tree::Node;

/// The children of an internal node, and their byte counts.
///
/// `sizes[i]` is the byte length of the subtree at `nodes[i]`. Keeping those
/// two in step is the monoid invariant the whole structure rests on, so every
/// write goes through this type — no caller ever touches the vectors.
#[derive(Clone, Debug)]
pub(crate) struct Children {
    height: u8,
    sizes: Vec<usize>,
    nodes: Vec<Arc<Node>>,
}

impl Children {
    pub(crate) fn new(height: u8) -> Children {
        debug_assert!(height >= 1, "internal nodes are never height 0");
        Children { height, sizes: Vec::new(), nodes: Vec::new() }
    }

    /// A node over exactly two children of equal height.
    pub(crate) fn from_pair(left: Arc<Node>, right: Arc<Node>) -> Children {
        debug_assert_eq!(left.height(), right.height(), "pair must be level");
        Children {
            height: left.height() + 1,
            sizes: vec![left.byte_len(), right.byte_len()],
            nodes: vec![left, right],
        }
    }

    pub(crate) fn height(&self) -> u8 {
        self.height
    }

    pub(crate) fn len(&self) -> usize {
        self.nodes.len()
    }

    pub(crate) fn total(&self) -> usize {
        self.sizes.iter().sum()
    }

    /// Byte length of the subtree at `i`.
    ///
    /// Only the invariant checker and this module's tests read this; the tree's
    /// own operations index `self.sizes` directly.
    #[cfg(test)]
    pub(crate) fn size(&self, i: usize) -> usize {
        self.sizes[i]
    }

    pub(crate) fn node(&self, i: usize) -> &Arc<Node> {
        &self.nodes[i]
    }

    pub(crate) fn push(&mut self, node: Arc<Node>) {
        debug_assert_eq!(node.height() + 1, self.height, "child must be one level down");
        self.sizes.push(node.byte_len());
        self.nodes.push(node);
    }

    pub(crate) fn insert_at(&mut self, i: usize, node: Arc<Node>) {
        debug_assert_eq!(node.height() + 1, self.height, "child must be one level down");
        self.sizes.insert(i, node.byte_len());
        self.nodes.insert(i, node);
    }

    /// Split children `i..` off into a new node, keeping `0..i` here.
    pub(crate) fn split_off(&mut self, i: usize) -> Children {
        Children {
            height: self.height,
            sizes: self.sizes.split_off(i),
            nodes: self.nodes.split_off(i),
        }
    }

    /// Mutate child `i` and refresh its cached size.
    ///
    /// This is the only way to mutate a child, and it is why two of the
    /// crate's likeliest bugs cannot be written. Forgetting `Arc::make_mut`
    /// would silently corrupt every other handle sharing the node; forgetting
    /// the size writeback would desynchronise the monoid. Neither is
    /// expressible through this API.
    pub(crate) fn with_child_mut<R>(&mut self, i: usize, f: impl FnOnce(&mut Node) -> R) -> R {
        let out = f(Arc::make_mut(&mut self.nodes[i]));
        self.sizes[i] = self.nodes[i].byte_len();
        out
    }

    /// Break the size/node correspondence on purpose, so the invariant checker
    /// can be shown to catch it. Tests only — there is no other way to
    /// construct this state, which is the point.
    #[cfg(test)]
    pub(crate) fn corrupt_size_for_test(&mut self, i: usize, size: usize) {
        self.sizes[i] = size;
    }

    /// Push a child at the wrong level, so the invariant checker can be shown
    /// to catch ragged depth. Tests only.
    #[cfg(test)]
    pub(crate) fn push_ragged_for_test(&mut self, node: Arc<Node>) {
        self.sizes.push(node.byte_len());
        self.nodes.push(node);
    }

    /// The child containing `offset`, and the offset within it.
    ///
    /// Biases *right* at a child boundary: byte `n` of a child of size `n`
    /// belongs to the next child. Panics if `offset >= self.total()`.
    pub(crate) fn locate_read(&self, offset: usize) -> (usize, usize) {
        let mut acc = 0;
        for (i, &size) in self.sizes.iter().enumerate() {
            if offset < acc + size {
                return (i, offset - acc);
            }
            acc += size;
        }
        panic!("read offset {offset} past end of node (total {acc})");
    }

    /// The child that should receive an insertion at `offset`, and the offset
    /// within it.
    ///
    /// Biases *left* at a child boundary, so inserting at a child's end
    /// appends into that child rather than prepending to the next. Panics if
    /// `offset > self.total()`.
    pub(crate) fn locate_insert(&self, offset: usize) -> (usize, usize) {
        let mut acc = 0;
        for (i, &size) in self.sizes.iter().enumerate() {
            if offset <= acc + size {
                return (i, offset - acc);
            }
            acc += size;
        }
        panic!("insert offset {offset} past end of node (total {acc})");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(n: usize) -> Arc<Node> {
        Arc::new(Node::Leaf(vec![0u8; n]))
    }

    #[test]
    fn from_pair_sums_and_lifts_height() {
        let c = Children::from_pair(leaf(3), leaf(6));
        assert_eq!(c.len(), 2);
        assert_eq!(c.total(), 9);
        assert_eq!(c.height(), 1);
        assert_eq!(c.size(0), 3);
        assert_eq!(c.size(1), 6);
    }

    #[test]
    fn locate_read_biases_right_at_a_boundary() {
        // sizes [5, 5]: offset 5 is the *first* byte of child 1.
        let c = Children::from_pair(leaf(5), leaf(5));
        assert_eq!(c.locate_read(0), (0, 0));
        assert_eq!(c.locate_read(4), (0, 4));
        assert_eq!(c.locate_read(5), (1, 0));
        assert_eq!(c.locate_read(9), (1, 4));
    }

    #[test]
    fn locate_insert_biases_left_at_a_boundary() {
        // sizes [5, 5]: inserting at 5 appends to child 0 rather than
        // prepending to child 1. Confusing this with locate_read is the most
        // likely off-by-one in the crate, so both are pinned here.
        let c = Children::from_pair(leaf(5), leaf(5));
        assert_eq!(c.locate_insert(0), (0, 0));
        assert_eq!(c.locate_insert(5), (0, 5));
        assert_eq!(c.locate_insert(6), (1, 1));
        assert_eq!(c.locate_insert(10), (1, 5));
    }

    #[test]
    #[should_panic(expected = "past end of node")]
    fn locate_read_rejects_the_end_offset() {
        let c = Children::from_pair(leaf(5), leaf(5));
        c.locate_read(10);
    }

    #[test]
    #[should_panic(expected = "past end of node")]
    fn locate_insert_rejects_past_the_end() {
        let c = Children::from_pair(leaf(5), leaf(5));
        c.locate_insert(11);
    }

    #[test]
    fn with_child_mut_refreshes_the_cached_size() {
        let mut c = Children::from_pair(leaf(3), leaf(4));
        c.with_child_mut(0, |n| {
            let Node::Leaf(buf) = n else { unreachable!() };
            buf.extend_from_slice(&[1, 2, 3]);
        });
        assert_eq!(c.size(0), 6, "cached size must follow the mutation");
        assert_eq!(c.total(), 10);
    }

    #[test]
    fn with_child_mut_does_not_disturb_a_shared_child() {
        let shared = leaf(3);
        let mut c = Children::from_pair(Arc::clone(&shared), leaf(4));
        c.with_child_mut(0, |n| {
            let Node::Leaf(buf) = n else { unreachable!() };
            buf.extend_from_slice(&[9, 9]);
        });
        assert_eq!(shared.byte_len(), 3, "the other handle must be untouched");
        assert_eq!(c.size(0), 5);
    }

    #[test]
    fn split_off_moves_both_arrays_together() {
        let mut c = Children::new(1);
        c.push(leaf(1));
        c.push(leaf(2));
        c.push(leaf(3));
        let tail = c.split_off(1);
        assert_eq!(c.len(), 1);
        assert_eq!(c.total(), 1);
        assert_eq!(tail.len(), 2);
        assert_eq!(tail.total(), 5);
        assert_eq!(tail.height(), 1);
    }

    #[test]
    fn insert_at_places_the_size_alongside_the_node() {
        let mut c = Children::from_pair(leaf(1), leaf(3));
        c.insert_at(1, leaf(2));
        assert_eq!((c.size(0), c.size(1), c.size(2)), (1, 2, 3));
        assert_eq!(c.total(), 6);
    }
}
