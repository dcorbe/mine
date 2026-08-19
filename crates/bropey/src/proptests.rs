//! Differential property tests against a `Vec<u8>` reference model.
//!
//! This file lives in `src/` on purpose. `#[cfg(test)]` applies only when the
//! crate itself is compiled for testing, so an integration test under `tests/`
//! would link the library at *production* constants — a 1 KB input would never
//! leave the root leaf and none of the tree would be exercised.

use proptest::prelude::*;

use crate::tune::MAX_BYTES;
use crate::{ByteSource, Rope};

/// One operation applied to both the rope and the model.
///
/// Indices are unconstrained here and clamped into range at apply time, so
/// proptest never has to generate a valid index and shrinking stays effective.
#[derive(Debug, Clone)]
enum Op {
    FromBytes { bytes: Vec<u8> },
    Snapshot,
    Insert { at: u16, bytes: Vec<u8> },
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        proptest::collection::vec(any::<u8>(), 0..80).prop_map(|bytes| Op::FromBytes { bytes }),
        Just(Op::Snapshot),
        // Bounded by MAX_BYTES, not an arbitrary literal: the direct-insert
        // path this exercises accepts at most MAX_BYTES per call (larger
        // inputs route through the bulk path added in Task 10), and under
        // cfg(test) MAX_BYTES shrinks to a value smaller than a fixed literal
        // like 20 would respect.
        (any::<u16>(), proptest::collection::vec(any::<u8>(), 0..=MAX_BYTES))
            .prop_map(|(at, bytes)| Op::Insert { at, bytes }),
    ]
}

/// Scale an arbitrary index into `0..=len`.
fn clamp(raw: u16, len: usize) -> usize {
    if len == 0 { 0 } else { (raw as usize) % (len + 1) }
}

/// Apply `ops` to a rope and a `Vec<u8>` model, checking they agree after
/// every step, that the tree's invariants hold, and that no earlier clone was
/// disturbed.
fn run(ops: Vec<Op>) {
    let mut rope = Rope::new();
    let mut model: Vec<u8> = Vec::new();
    // Live clones taken along the way, each with the bytes it must still hold.
    // This is not a live detector: the crate has zero `unsafe` and no
    // interior mutability, so a shared `Arc<Node>` cannot be mutated in
    // place at all — `Arc::make_mut` clones it, `Arc::get_mut` refuses it,
    // and there is no third path. It is the type system, not this
    // assertion, that rules out silent aliasing corruption today. The check
    // is kept as a regression guard: it goes live only if the crate's
    // zero-`unsafe` invariant is ever weakened.
    let mut snapshots: Vec<(Rope, Vec<u8>)> = Vec::new();

    for op in ops {
        match &op {
            Op::FromBytes { bytes } => {
                rope = Rope::from_bytes(bytes);
                model = bytes.clone();
            }
            Op::Snapshot => {
                snapshots.push((rope.clone(), model.clone()));
            }
            Op::Insert { at, bytes } => {
                let at = clamp(*at, model.len());
                rope.insert(at, bytes);
                model.splice(at..at, bytes.iter().copied());
            }
        }

        rope.check();
        assert_eq!(rope.len(), model.len(), "length diverged after {op:?}");
        assert_eq!(rope.to_vec(), model, "content diverged after {op:?}");

        for (index, (snapshot, expected)) in snapshots.iter().enumerate() {
            snapshot.check();
            assert_eq!(
                &snapshot.to_vec(),
                expected,
                "snapshot {index} was mutated by a later edit, after {op:?}"
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn rope_matches_the_model(ops in proptest::collection::vec(op_strategy(), 0..40)) {
        run(ops);
    }
}

#[test]
fn clamp_maps_into_the_inclusive_range() {
    assert_eq!(clamp(0, 0), 0);
    assert_eq!(clamp(9999, 0), 0);
    assert_eq!(clamp(0, 10), 0);
    assert_eq!(clamp(10, 10), 10);
    assert_eq!(clamp(11, 10), 0);
}
