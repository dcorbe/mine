//! Differential property tests against a `Vec<u8>` reference model.
//!
//! This file lives in `src/` on purpose. `#[cfg(test)]` applies only when the
//! crate itself is compiled for testing, so an integration test under `tests/`
//! would link the library at *production* constants — a 1 KB input would never
//! leave the root leaf and none of the tree would be exercised.

use proptest::prelude::*;

use crate::tune::{BULK_THRESHOLD, MAX_BYTES};
use crate::{ByteSource, Rope};

/// Well past `BULK_THRESHOLD` so `Insert` drives both routes of
/// `Rope::insert`: at or below the threshold it descends directly, above it
/// the bulk-build-and-splice path runs. Bounding this at `MAX_BYTES`, as
/// Task 7 did before this routing existed, would give the bulk route zero
/// coverage from this harness.
const MAX_INSERT_LEN: usize = MAX_BYTES * 4;
const _: () = assert!(MAX_INSERT_LEN > BULK_THRESHOLD);

/// One operation applied to both the rope and the model.
///
/// Indices are unconstrained here and clamped into range at apply time, so
/// proptest never has to generate a valid index and shrinking stays effective.
#[derive(Debug, Clone)]
enum Op {
    FromBytes { bytes: Vec<u8> },
    Snapshot,
    Insert { at: u16, bytes: Vec<u8> },
    Append { bytes: Vec<u8> },
    SplitOff { at: u16 },
    Remove { at: u16, len: u16 },
    Slice { at: u16, len: u16 },
    InsertRope { at: u16, bytes: Vec<u8> },
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        proptest::collection::vec(any::<u8>(), 0..80).prop_map(|bytes| Op::FromBytes { bytes }),
        Just(Op::Snapshot),
        // Bounded by MAX_INSERT_LEN, not an arbitrary literal: it must clear
        // BULK_THRESHOLD so both of Rope::insert's routes (direct descent at
        // or below the threshold, bulk-build-and-splice above it) actually
        // get driven by this harness, and under cfg(test) MAX_BYTES shrinks
        // to a value smaller than a fixed literal like 20 would respect.
        (any::<u16>(), proptest::collection::vec(any::<u8>(), 0..=MAX_INSERT_LEN))
            .prop_map(|(at, bytes)| Op::Insert { at, bytes }),
        proptest::collection::vec(any::<u8>(), 0..60)
            .prop_map(|bytes| Op::Append { bytes }),
        any::<u16>().prop_map(|at| Op::SplitOff { at }),
        (any::<u16>(), any::<u16>()).prop_map(|(at, len)| Op::Remove { at, len }),
        (any::<u16>(), any::<u16>()).prop_map(|(at, len)| Op::Slice { at, len }),
        (any::<u16>(), proptest::collection::vec(any::<u8>(), 0..90))
            .prop_map(|(at, bytes)| Op::InsertRope { at, bytes }),
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
            Op::Append { bytes } => {
                rope.append(Rope::from_bytes(bytes));
                model.extend_from_slice(bytes);
            }
            Op::SplitOff { at } => {
                let at = clamp(*at, model.len());
                let tail = rope.split_off(at);
                let expected_tail = model.split_off(at);
                tail.check();
                assert_eq!(tail.to_vec(), expected_tail, "split tail diverged");
            }
            Op::Remove { at, len } => {
                let start = clamp(*at, model.len());
                let end = start + clamp(*len, model.len() - start);
                rope.remove(start..end);
                model.drain(start..end);
            }
            Op::Slice { at, len } => {
                let start = clamp(*at, model.len());
                let end = start + clamp(*len, model.len() - start);
                let piece = rope.slice(start..end);
                piece.check();
                assert_eq!(piece.to_vec(), &model[start..end], "slice diverged");
            }
            Op::InsertRope { at, bytes } => {
                let at = clamp(*at, model.len());
                rope.insert_rope(at, &Rope::from_bytes(bytes));
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
