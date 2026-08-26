//! A v6 key's position order, without record bytes.
//!
//! `records::Records` keeps, per key, every record's whole body sorted into
//! that key's order -- the read model this crate used for every v6 op
//! before this module existed, and still uses for v5 and for a
//! variable-length v6 file (see `lib.rs`'s `Block::v6_fast_reads`). Built
//! once, that model answers a rank query for free; built for a 55.7 MB,
//! 26,720-record `WCCMP002.DAT`, it costs the whole file, every time,
//! because nothing about a `Get Equal` for one record needs any other
//! record's bytes at all.
//!
//! [`OrderIndex`] is the same shape with the bytes removed: `order`, a
//! key's record positions in that key's own order (what
//! `Records::ordered`/`Records::seek` answer from), and `rank`, the
//! inverse (what `Records::place_in` answers from). Built once per key,
//! from **one [`super::nav::TreeCursor`] walk, Lowest to the end** --
//! through the block's own page cache, so an index rebuilt mid-deferred-
//! transaction sees whatever that transaction has staged there rather
//! than stale disk (`super::lib::Block::stage_changed_pages`) -- rather
//! than by materialising `Records`.
//!
//! A 26,720-record key costs roughly `order.len() * 4` bytes for `order`
//! plus a `HashMap<u32, u32>` entry per record for `rank` -- measured at
//! machine scale in `docs/2026-08-24-btrieve-write-cost-baseline.md`'s own
//! Task 7 addendum, not asserted here as a specific number: a `HashMap`'s
//! own per-entry overhead is a property of `std`'s implementation, not of
//! this format, and correctness came ahead of shaving it further -- see
//! this task's own report for the measured figure and why a
//! `HashMap` was chosen over a sorted side array.

use std::cell::RefCell;
use std::collections::HashMap;

use super::cache::PageCache;
use super::nav::{self, Duplicates};
use super::pages::Shape;

/// One key's record positions, in that key's own order, plus the reverse
/// lookup -- everything [`super::records::Records::ordered`]/
/// [`super::records::Records::ordered_len`]/[`super::records::Records::
/// place_in`] answer, without a single record's bytes.
pub(crate) struct OrderIndex {
    /// Record positions, ascending in this key's own order -- what
    /// [`super::nav::TreeCursor`]'s own in-order walk produces, matching
    /// [`super::records::Records`]'s tie-break (physical position within a
    /// duplicate-value group) byte for byte, per that cursor's own
    /// differential proof.
    order: Vec<u32>,
    /// The inverse of `order`: a position's own rank. A record this key
    /// excludes from its index (`Key::excluded`) never appears in either
    /// field -- the tree itself never has an entry for it, so nothing here
    /// has to check for it separately.
    rank: HashMap<u32, u32>,
}

impl OrderIndex {
    /// A key with no tree yet -- a virgin file, or an `ANOSEG` continuation
    /// definition (see [`super::nav::root_of`]'s own doc comment).
    pub(crate) fn empty() -> Self {
        Self { order: Vec::new(), rank: HashMap::new() }
    }

    /// How many records this key currently indexes.
    pub(crate) fn len(&self) -> usize {
        self.order.len()
    }

    /// The position at rank `at`, or `None` past the end.
    pub(crate) fn position_at(&self, at: usize) -> Option<u32> {
        self.order.get(at).copied()
    }

    /// `position`'s own rank in this key's order, or `None` if this key
    /// does not index it (excluded by [`super::keys::Key::excluded`], or
    /// simply not a record this file holds).
    pub(crate) fn rank_of(&self, position: u32) -> Option<usize> {
        self.rank.get(&position).map(|&at| at as usize)
    }

    /// Build directly from an already-ordered list of positions -- the
    /// physical-order counterpart to [`Self::build`], for
    /// [`super::lib::Block::v6_build_physical_index`]: there is no per-key
    /// tree to walk for "every claimed position, file-wide", only the
    /// allocation table plus each claimed page's own live-slot markers, so
    /// that caller assembles `positions` itself and this just builds the
    /// reverse lookup over it.
    ///
    /// # Panics
    ///
    /// If `positions` holds more than `u32::MAX` entries -- not a real
    /// Btrieve file's shape.
    pub(crate) fn from_positions(positions: Vec<u32>) -> Self {
        let mut rank = HashMap::with_capacity(positions.len());
        for (at, &position) in positions.iter().enumerate() {
            rank.insert(position, u32::try_from(at).expect("far fewer records than u32::MAX"));
        }
        Self { order: positions, rank }
    }

    /// Build by walking `root`'s whole tree once, [`nav::Bias::Lowest`] to
    /// the end -- the same cursor [`super::lib::Block::nav_root`] hands a
    /// caller already positioned, just driven to exhaustion instead of
    /// stopped after one entry.
    ///
    /// # Errors
    ///
    /// Whatever [`nav::TreeCursor::seek`]/[`nav::TreeCursor::next`] refuse.
    pub(crate) fn build(
        cache: &RefCell<PageCache>,
        resolve: &mut dyn FnMut(u32) -> Result<u32, String>,
        root: u32,
        shape: Shape,
        dup: Option<Duplicates>,
        cmp: &dyn Fn(&[u8], &[u8]) -> std::cmp::Ordering,
    ) -> Result<Self, String> {
        let (mut cursor, first) =
            nav::TreeCursor::seek(cache, resolve, root, shape, None, nav::Bias::Lowest, dup, cmp)?;
        let mut order = Vec::new();
        let mut rank = HashMap::new();
        let mut next = first;
        while let Some(position) = next {
            rank.insert(position, u32::try_from(order.len()).expect("far fewer records than u32::MAX"));
            order.push(position);
            next = cursor.next(cache, resolve, shape)?;
        }
        Ok(Self { order, rank })
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::records::Records;
    use crate::testing::{Flat, FlatHeap, FlatMem, FlatPtr};
    use crate::{Btrieve, Geometry, Version};

    /// Every v6 file this repository's own corpus (plus a handful of named
    /// fixtures) has -- the same list [`super::super::nav::tests::
    /// v6_candidate_paths`] walks, duplicated rather than shared across a
    /// `mod tests` boundary neither file's own privacy already crosses.
    fn v6_candidate_paths() -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = crate::corpus::walk().into_iter().map(|e| e.path).collect();
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        for extra in [
            "tests/data/variable/V6DUP.DAT",
            "tests/data/variable/V6SHRINK.DAT",
            "../../tools/btrieve-oracle/fixtures/DUPKEY30.DAT",
            "../../tools/btrieve-oracle/fixtures/DUPKEY30SWAPPED.DAT",
            "../../tools/btrieve-oracle/fixtures/V6EMPTY1KEY.DAT",
        ] {
            let path = manifest_dir.join(extra);
            if path.is_file() {
                paths.push(path);
            }
        }
        paths
    }

    /// Open `path` through the real `Btrieve::open`, exactly as
    /// [`super::super::nav::tests::open_v6`] does -- a v6 file gets the
    /// same page cache [`super::super::Block::nav_root`]/[`super::super::
    /// Block::v6_record_bytes_at`] both need. `None` for anything not a
    /// fixed-length v6 file: this differential is [`super::super::Block::
    /// v6_fast_reads`]'s own scope, and a variable-length file is
    /// deliberately excluded from it (see that method's own doc comment).
    fn open_v6_fixed(path: &Path) -> Option<(Btrieve<Flat>, FlatPtr)> {
        let name = path.file_name()?.to_string_lossy().into_owned();
        let geometry = Geometry::read(&name, path).ok()?;
        if geometry.version != Version::V6 || geometry.variable {
            return None;
        }
        let maxlen = geometry.reclen;
        let mut mem = FlatMem::new(usize::from(maxlen) + 8192);
        let mut heap = FlatHeap::new(0x100);
        let mut btrieve = Btrieve::<Flat>::default();
        let at = btrieve.open(&mut mem, &mut heap, &name, path, geometry, maxlen).ok()?;
        Some((btrieve, at))
    }

    /// [`OrderIndex::build`] (via `Block::nav_root`, the same route
    /// `Block::v6_ensure_order` takes) and `Block::v6_record_bytes_at`,
    /// checked against a freshly read [`Records`] over every fixed-length
    /// v6 file this repository's corpus has, every key, every rank: same
    /// length, same position at each rank, same rank for each position,
    /// same bytes. This is the differential [`super::super::nav`]'s own
    /// `tree_cursor_matches_records_over_the_v6_corpus` does not cover --
    /// that one proves `TreeCursor` finds the right *position*; this one
    /// proves the *rank* built around it, and the bytes fetched for it,
    /// both agree with `Records` too.
    #[test]
    fn order_index_and_byte_fetch_match_records_over_the_v6_corpus() {
        let mut files_compared = 0usize;
        let mut keys_compared = 0usize;
        let mut records_compared = 0usize;

        for path in v6_candidate_paths() {
            let Some((btrieve, at)) = open_v6_fixed(&path) else { continue };
            let block = btrieve.block(at).expect("just opened");
            let keys = block.keys().to_vec();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let records = match Records::read(&name, &path, block.geometry(), &keys) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for key in &keys {
                let count = match records.ordered_len(key.number) {
                    Some(n) if n > 0 => n,
                    _ => continue,
                };

                let Some((root, shape, dup, cache, mut resolve)) = block
                    .nav_root(key.number)
                    .unwrap_or_else(|e| panic!("{name} key {}: nav_root: {e}", key.number))
                else {
                    panic!(
                        "{name} key {}: Records counts {count} records but nav_root found no \
                         tree at all",
                        key.number
                    );
                };
                let cmp = |a: &[u8], b: &[u8]| key.compare_extracted(a, b);
                let index = OrderIndex::build(cache, &mut resolve, root, shape, dup, &cmp)
                    .unwrap_or_else(|e| panic!("{name} key {}: OrderIndex::build: {e}", key.number));

                assert_eq!(
                    index.len(),
                    count,
                    "{name} key {}: OrderIndex length disagrees with Records",
                    key.number
                );

                for rank in 0..count {
                    let expected = records.ordered(key.number, rank).expect("in range");
                    let position = index.position_at(rank).unwrap_or_else(|| {
                        panic!("{name} key {}: rank {rank}: OrderIndex has no position", key.number)
                    });
                    assert_eq!(
                        position, expected.position,
                        "{name} key {}: rank {rank}: position disagrees with Records",
                        key.number
                    );
                    assert_eq!(
                        index.rank_of(position),
                        Some(rank),
                        "{name} key {}: position {position}: rank_of disagrees with its own \
                         forward mapping",
                        key.number
                    );

                    let fetched = block
                        .v6_record_bytes_at(position)
                        .unwrap_or_else(|e| {
                            panic!("{name} key {}: rank {rank}: v6_record_bytes_at: {e}", key.number)
                        })
                        .unwrap_or_else(|| {
                            panic!(
                                "{name} key {}: rank {rank}: position {position} reads as an \
                                 empty slot",
                                key.number
                            )
                        });
                    assert_eq!(
                        fetched, expected.bytes,
                        "{name} key {}: rank {rank}: fetched bytes disagree with Records",
                        key.number
                    );
                }

                keys_compared += 1;
                records_compared += count;
            }

            files_compared += 1;
        }

        assert!(files_compared > 0, "the walker found no fixed-length v6 files -- it has gone blind");
        assert!(keys_compared > 0, "no key with any records was compared -- gone blind a level down");
        eprintln!(
            "order_index_and_byte_fetch_match_records_over_the_v6_corpus: {files_compared} files, \
             {keys_compared} keys, {records_compared} records"
        );
    }
}
