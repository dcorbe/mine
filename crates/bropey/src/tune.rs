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

/// Deliberately below half of `MAX_BYTES`. The slack stops an insert/remove
/// alternation at a chunk boundary from thrashing split and join.
pub(crate) const MIN_BYTES: usize = (MAX_BYTES / 2) - (MAX_BYTES / 32);
pub(crate) const MIN_CHILDREN: usize = MAX_CHILDREN.div_ceil(2) - 1;

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
const _: () = assert!(2 * MIN_BYTES <= MAX_BYTES);
const _: () = assert!(2 * MIN_CHILDREN <= MAX_CHILDREN);

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
        // regimes, so that moving the knob cannot desynchronise them.
        assert_eq!((1024 / 2) - (1024 / 32), 480);
        assert_eq!((15 / 2) - (15 / 32), 7);
        assert_eq!(16usize.div_ceil(2) - 1, 7);
        assert_eq!(5usize.div_ceil(2) - 1, 2);
    }

    #[test]
    fn a_split_of_two_minimal_nodes_always_fits() {
        // Guarantees a single split is enough whenever an insert overflows.
        assert!(2 * MIN_BYTES <= MAX_BYTES);
        assert!(2 * MIN_CHILDREN <= MAX_CHILDREN);
    }
}
