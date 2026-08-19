use crate::tree::Node;

/// Iterator over a rope's chunks, in byte order.
///
/// Chunk boundaries are an implementation detail and carry no meaning: this is
/// a byte rope, so a chunk may end anywhere at all. A caller decoding a
/// multi-byte encoding must carry partial sequences across chunk boundaries
/// itself.
pub struct Chunks<'a> {
    stack: Vec<(&'a Node, usize)>,
}

impl<'a> Chunks<'a> {
    pub(crate) fn new(root: &'a Node) -> Chunks<'a> {
        Chunks { stack: vec![(root, 0)] }
    }
}

impl<'a> Iterator for Chunks<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        while let Some((node, index)) = self.stack.pop() {
            match node {
                Node::Leaf(buf) => {
                    if !buf.is_empty() {
                        return Some(buf.as_slice());
                    }
                }
                Node::Internal(children) => {
                    if index < children.len() {
                        self.stack.push((node, index + 1));
                        self.stack.push((&**children.node(index), 0));
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::Rope;

    #[test]
    fn chunks_of_an_empty_rope_yields_nothing() {
        let rope = Rope::new();
        assert_eq!(rope.chunks().count(), 0);
    }

    #[test]
    fn chunks_concatenate_to_the_whole_rope() {
        let bytes: Vec<u8> = (0..500).map(|i| (i % 251) as u8).collect();
        let rope = Rope::from_bytes(&bytes);
        let joined: Vec<u8> = rope.chunks().flatten().copied().collect();
        assert_eq!(joined, bytes);
    }

    #[test]
    fn chunks_are_in_order_and_never_empty() {
        let bytes: Vec<u8> = (0..500).map(|i| (i % 251) as u8).collect();
        let rope = Rope::from_bytes(&bytes);
        let mut seen = 0;
        for chunk in rope.chunks() {
            assert!(!chunk.is_empty(), "an empty chunk is never useful");
            assert_eq!(chunk, &bytes[seen..seen + chunk.len()]);
            seen += chunk.len();
        }
        assert_eq!(seen, bytes.len());
    }
}
