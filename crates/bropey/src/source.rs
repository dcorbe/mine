use std::ops::Range;

use crate::tree::Node;
use crate::Rope;

/// Anything that reads as a sequence of bytes in chunks.
///
/// Two required methods, no generic methods, no associated types, and every
/// borrow tied to `&self` — so this stays object-safe and `Box<dyn ByteSource>`
/// works. `Rope::chunks` is deliberately *not* here: returning an iterator from
/// a trait method is exactly what would cost object safety, and `chunk_at` is
/// enough to write a generic chunk walk.
///
/// The required surface is chunk-granular rather than byte-granular so that
/// `dyn` dispatch costs one virtual call per chunk, not per byte.
pub trait ByteSource {
    /// Total bytes.
    fn len(&self) -> usize;

    /// The chunk containing `offset`, together with that chunk's absolute
    /// start offset. `None` if and only if `offset >= self.len()`.
    fn chunk_at(&self, offset: usize) -> Option<(&[u8], usize)>;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn byte_at(&self, offset: usize) -> Option<u8> {
        let (chunk, start) = self.chunk_at(offset)?;
        chunk.get(offset - start).copied()
    }

    /// Copy `range` into `dst`, which must be exactly the length of the range.
    fn copy_into(&self, range: Range<usize>, dst: &mut [u8]) {
        assert_eq!(
            dst.len(),
            range.end - range.start,
            "destination length {} does not match range {}..{}",
            dst.len(),
            range.start,
            range.end
        );
        let mut written = 0;
        let mut offset = range.start;
        while offset < range.end {
            let (chunk, start) = self.chunk_at(offset).expect("range is within bounds");
            let from = offset - start;
            let take = (chunk.len() - from).min(range.end - offset);
            dst[written..written + take].copy_from_slice(&chunk[from..from + take]);
            written += take;
            offset += take;
        }
    }

    fn to_vec(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.len()];
        let end = out.len();
        self.copy_into(0..end, &mut out);
        out
    }
}

impl ByteSource for Rope {
    fn len(&self) -> usize {
        Rope::len(self)
    }

    fn chunk_at(&self, offset: usize) -> Option<(&[u8], usize)> {
        if offset >= Rope::len(self) {
            return None;
        }
        let mut node: &Node = &self.root;
        let mut start = 0;
        loop {
            match node {
                Node::Leaf(buf) => return Some((buf.as_slice(), start)),
                Node::Internal(children) => {
                    let (index, local) = children.locate_read(offset - start);
                    start = offset - local;
                    node = children.node(index);
                }
            }
        }
    }
}

impl ByteSource for [u8] {
    fn len(&self) -> usize {
        // Must name the inherent method: a bare `self.len()` here resolves to
        // this very trait method and recurses forever.
        <[u8]>::len(self)
    }

    fn chunk_at(&self, offset: usize) -> Option<(&[u8], usize)> {
        if offset < <[u8]>::len(self) {
            Some((self, 0))
        } else {
            None
        }
    }
}

impl ByteSource for Vec<u8> {
    fn len(&self) -> usize {
        <[u8]>::len(self.as_slice())
    }

    fn chunk_at(&self, offset: usize) -> Option<(&[u8], usize)> {
        <[u8] as ByteSource>::chunk_at(self.as_slice(), offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Rope;

    fn seq(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn the_trait_is_object_safe() {
        // If this stops compiling, a generic method or GAT has crept into the
        // required surface and `Box<dyn ByteSource>` is gone.
        let boxed: Box<dyn ByteSource> = Box::new(Rope::from_bytes(b"hello"));
        assert_eq!(boxed.len(), 5);
        assert_eq!(boxed.byte_at(1), Some(b'e'));
        assert_eq!(boxed.byte_at(5), None);
    }

    #[test]
    fn rope_and_slice_and_vec_agree_byte_for_byte() {
        let bytes = seq(500);
        let rope = Rope::from_bytes(&bytes);
        let as_vec: Vec<u8> = bytes.clone();
        for i in 0..bytes.len() {
            let expected = Some(bytes[i]);
            assert_eq!(rope.byte_at(i), expected, "rope differs at {i}");
            assert_eq!(bytes.as_slice().byte_at(i), expected, "slice differs at {i}");
            assert_eq!(as_vec.byte_at(i), expected, "vec differs at {i}");
        }
        assert_eq!(rope.byte_at(bytes.len()), None);
        assert_eq!(bytes.as_slice().byte_at(bytes.len()), None);
        assert_eq!(as_vec.byte_at(bytes.len()), None);
    }

    #[test]
    fn chunk_at_reports_the_chunk_start_offset() {
        let bytes = seq(500);
        let rope = Rope::from_bytes(&bytes);
        let mut offset = 0;
        while offset < bytes.len() {
            let (chunk, start) = rope.chunk_at(offset).expect("in bounds");
            assert!(start <= offset, "start {start} must not exceed offset {offset}");
            assert!(offset - start < chunk.len(), "offset must fall inside the chunk");
            assert_eq!(chunk, &bytes[start..start + chunk.len()]);
            offset += 1;
        }
        assert!(rope.chunk_at(bytes.len()).is_none());
    }

    #[test]
    fn to_vec_round_trips_every_size() {
        // 15 and 17 straddle the test-regime max-leaf boundary without
        // transcribing the tuning constants 7 or 16, which the crate's
        // banned-literal rule (tune.rs is the sole source) forbids elsewhere.
        for n in [0usize, 1, 8, 15, 17, 100, 499, 500] {
            let bytes = seq(n);
            assert_eq!(Rope::from_bytes(&bytes).to_vec(), bytes, "differs at n={n}");
        }
    }

    #[test]
    fn copy_into_extracts_an_arbitrary_range() {
        let bytes = seq(300);
        let rope = Rope::from_bytes(&bytes);
        for (start, end) in [(0usize, 0usize), (0, 300), (5, 6), (17, 200), (299, 300)] {
            let mut dst = vec![0u8; end - start];
            rope.copy_into(start..end, &mut dst);
            assert_eq!(dst, &bytes[start..end], "differs on {start}..{end}");
        }
    }
}
