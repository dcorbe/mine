//! Tuning constants.
//!
//! This is the only file in the crate that may contain these numbers. Leaf
//! capacity governs the shape of the tree: larger leaves give a shallower tree
//! and faster scans, but a one-byte interior edit memmoves half a leaf, a
//! *shared* rope path-copies a whole leaf per edit, and slack memory scales
//! with it. 1024 is ropey's measured default and the starting point here.
//!
//! Under `cfg(test)` the constants shrink so that unit tests build trees many
//! levels deep out of a few dozen bytes. Note this does not reach integration
//! tests under `tests/`, which link the library built without `cfg(test)`.

#[cfg(not(test))]
pub(crate) const MAX_BYTES: usize = 1024;
#[cfg(not(test))]
pub(crate) const MAX_CHILDREN: usize = 16;

#[cfg(test)]
pub(crate) const MAX_BYTES: usize = 15;
#[cfg(test)]
pub(crate) const MAX_CHILDREN: usize = 5;

/// Deliberately below half of `max`. The slack stops an insert/remove
/// alternation at a chunk boundary from thrashing split and join.
const fn min_bytes(max: usize) -> usize {
    (max / 2) - (max / 32)
}

/// Deliberately below half of `max`, mirroring `min_bytes`'s slack for the
/// same anti-thrash reason, one level up the tree.
const fn min_children(max: usize) -> usize {
    max.div_ceil(2) - 1
}

pub(crate) const MIN_BYTES: usize = min_bytes(MAX_BYTES);
pub(crate) const MIN_CHILDREN: usize = min_children(MAX_CHILDREN);

/// Inserts at or below this size take the direct descent path; larger ones are
/// bulk-built and spliced. Separate from `MAX_BYTES` because it answers a
/// different question — API routing, not leaf capacity — and will want
/// independent tuning.
///
/// Unused until a later task wires up the bulk-build insert path; the allow
/// is scoped to this one constant so unrelated dead code still warns.
#[allow(dead_code)]
pub(crate) const BULK_THRESHOLD: usize = MAX_BYTES;

const _: () = assert!(MIN_BYTES >= 1);
const _: () = assert!(MIN_CHILDREN >= 2);
// Cover both regimes explicitly: the const fns make this possible regardless
// of which regime (`cfg(test)` or not) is active in this build.
const _: () = assert!(2 * min_bytes(1024) <= 1024);
const _: () = assert!(2 * min_children(16) <= 16);
const _: () = assert!(2 * min_bytes(15) <= 15);
const _: () = assert!(2 * min_children(5) <= 5);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regime_is_small_enough_to_build_a_real_tree() {
        // If these grow, unit tests stop exercising the tree and start
        // exercising a single root leaf. That would make the whole suite
        // undiscriminating without failing anything.
        assert!(MAX_BYTES <= 16, "test MAX_BYTES must stay tiny, got {MAX_BYTES}");
        assert!(MAX_CHILDREN <= 5, "test MAX_CHILDREN must stay tiny, got {MAX_CHILDREN}");
    }

    #[test]
    fn minimums_are_derived_not_transcribed() {
        // The formulas must reproduce ropey's measured constants at both
        // regimes, so that moving the knob cannot desynchronise them. Pin
        // both regimes through the const fns directly, then tie the live
        // constants to the same formula so editing it fails this test.
        assert_eq!(min_bytes(1024), 480);
        assert_eq!(min_children(16), 7);
        assert_eq!(min_bytes(15), 7);
        assert_eq!(min_children(5), 2);
        assert_eq!(MIN_BYTES, min_bytes(MAX_BYTES));
        assert_eq!(MIN_CHILDREN, min_children(MAX_CHILDREN));
    }
}
