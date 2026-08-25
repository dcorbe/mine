//! The oracle replay contract: for every sequence recorded in
//! `docs/2026-08-25-btree-split-oracle.md` (fixtures under `tests/data/
//! btree-split-oracle/`), copy the sequence's starting snapshot to scratch,
//! then apply each recorded op *through this crate's own write path*
//! (`Btrieve::open` on the scratch file, the op, `Btrieve::close` -- the
//! same open-do-one-thing-close discipline the recorder itself used against
//! genuine Btrieve 6.15) and compare the resulting file to the next
//! recorded snapshot.
//!
//! Two gates, per step:
//!   - **Gate A** (preferred): the scratch file is byte-identical to the
//!     recorded snapshot.
//!   - **Gate B** (floor, only attempted where Gate A fails): our own
//!     output round-trips cleanly through `read::file`/`emit::file`, AND a
//!     fresh `Btrieve::open` of both our output and the recorded snapshot
//!     produce the same key-ordered sequence of whole record bytes (same
//!     walk order, same census). A step that only clears Gate B is still
//!     recorded, never silently folded into a plain pass -- see each
//!     `Verdict::GateB`'s own diff detail in the report this test prints.
//!
//! **Task 6 landed incremental maintenance** (`Block::insert_v6`/
//! `update_v6`/`delete_v6` locate the touched entry and edit only the pages
//! a split/merge/redistribute needs, per `docs/2026-08-25-btree-split-
//! rules.md`, rather than calling `v6_reindex` -- a full per-key rebuild --
//! on any per-op path). Today's own per-step map: **0 Gate-A, 33 Gate-B,
//! 0 red** -- every step's own live records and key order already agree
//! with the recording exactly, but no step reaches Gate A. Two reasons,
//! neither a disagreement about the B-tree's own shape: the FCR's own
//! `generation` field (this crate bumps it `+1` per op, matching the rules
//! doc's own §10, but the recorder's session had already run other
//! operations before the snapshot each sequence starts from, so the two
//! engines' absolute counters were never going to agree from a cold
//! start), and `v6::Map::relocate`'s twin search inheriting different
//! abandoned-twin availability from that same unreplayed history. Both are
//! demonstrated on real rows, with concrete byte-level diffs, in
//! `docs/btrieve-unproven.md` §6 -- not merely inferred from file sizes.
//! The last thirteen steps are Phase 2's own recordings: partial duplicate-
//! chain deletion, an interior-separator delete, delete-to-empty (the root
//! reverting to its virgin shape), and free-list reclaim order -- see
//! `docs/btrieve-unproven.md` §6 for what remains unmeasured beyond them.
//!
//! This test is a standing regression, not `#[ignore]`d: any future change
//! that turns a currently-green step red, or silently downgrades a
//! Gate-A/Gate-B pass, fails `cargo test -p btrieve` outright. Run it with
//! `-- --nocapture` to see the full per-step map on any run, passing or not.
//!
//! # Op reconstruction
//!
//! The recorder's own `tools/btrieve-oracle/split_oracle.py` (`record_hex`)
//! writes every inserted record as a 4-byte little-endian key at offset 0,
//! a 4-byte little-endian "insertion order" tag at offset 4, then zero
//! padding to `reclen` -- confirmed directly against a committed fixture's
//! own decoded record bodies (`underflow-lifecycle-512/4-reclaimed.txt`,
//! slot bodies for keys 65/66 read `410000004100000000000000` /
//! `420000004200000000000000`: key and tag both equal the record's own key
//! value). Every op table below either reads its `(value, tag)` pair
//! straight out of a `manifest.tsv` row (round 1's per-op log) or -- for
//! round 2/3's fixtures, which have no `manifest.tsv` -- uses `tag = value`,
//! the one pattern ever observed for an ascending, non-duplicate insertion
//! run in this corpus (checked against the raw bytes above, not assumed).
//! Deletes need only the key; this crate's own `delete` takes a record
//! *position*, so [`apply_op`]'s delete arm looks the position up by
//! scanning the freshly-opened file's own [`btrieve::Records`] for the
//! matching key bytes -- the same thing a real `B_GET_EQUAL` + `B_DELETE`
//! pair (`crtprobe.exe`'s own `delete` command) does one level up.

use std::fs;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use btrieve::testing::{scratch, Flat, FlatHeap, FlatMem};
use btrieve::{emit, read, Btrieve, Geometry};

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/btree-split-oracle").join(rel)
}

/// One write, in the shape the recorder's own manifest logs it: an insert's
/// `(key, insertion-order tag)`, a delete's bare key, or -- for a
/// duplicate-permitting key, where several records share one key value --
/// a delete naming which specific member by its own insertion-order tag
/// (`dup-chain-partial-delete`'s own recipe: `delete_nth(key, n)`, tags
/// assigned in insertion order so tag `n+1` names the same member).
#[derive(Clone, Copy)]
enum ReplayOp {
    Insert { key: u32, tag: u32 },
    Delete { key: u32 },
    DeleteTagged { key: u32, tag: u32 },
}

/// `key`(4B LE) + `tag`(4B LE) + zero padding to `reclen` -- see this file's
/// own module doc for the citation that this is the recorder's own record
/// shape, not an invented one.
fn record_bytes(reclen: u16, key: u32, tag: u32) -> Vec<u8> {
    let mut bytes = key.to_le_bytes().to_vec();
    bytes.extend_from_slice(&tag.to_le_bytes());
    bytes.resize(reclen as usize, 0);
    bytes
}

/// Apply one recorded op to the file at `path`, through a fresh
/// `Btrieve::open` / op / `Btrieve::close` cycle -- mirroring
/// `tools/btrieve-oracle/split_oracle.py`'s own "opens fresh, does one op,
/// closes" discipline, so this crate's write path is exercised the same way
/// the real engine was when the recording was taken.
fn apply_op(label: &str, path: &Path, op: ReplayOp) -> Result<(), String> {
    let mut mem = FlatMem::new(64 * 1024);
    let mut heap = FlatHeap::new(0x100);
    let mut btrieve = Btrieve::<Flat>::default();

    let geometry = Geometry::read(label, path).map_err(|e| e.to_string())?;
    let reclen = geometry.reclen;
    let maxlen = reclen;
    let at = btrieve.open(&mut mem, &mut heap, label, path, geometry, maxlen)?;

    match op {
        ReplayOp::Insert { key, tag } => {
            let bytes = record_bytes(reclen, key, tag);
            btrieve.block_mut(at)?.insert(&bytes).map_err(|e| e.to_string())?;
        }
        ReplayOp::Delete { key } => {
            let position = {
                let block = btrieve.block_mut(at)?;
                let records = block.records().map_err(|e| e.to_string())?;
                let want = key.to_le_bytes();
                (0..records.len())
                    .find_map(|i| {
                        let r = records.physical(i)?;
                        (r.bytes.len() >= 4 && r.bytes[0..4] == want).then_some(r.position)
                    })
                    .ok_or_else(|| format!("key {key} not present in {}", path.display()))?
            };
            btrieve.block_mut(at)?.delete(position).map_err(|e| e.to_string())?;
        }
        ReplayOp::DeleteTagged { key, tag } => {
            let position = {
                let block = btrieve.block_mut(at)?;
                let records = block.records().map_err(|e| e.to_string())?;
                let want_key = key.to_le_bytes();
                let want_tag = tag.to_le_bytes();
                (0..records.len())
                    .find_map(|i| {
                        let r = records.physical(i)?;
                        (r.bytes.len() >= 8 && r.bytes[0..4] == want_key && r.bytes[4..8] == want_tag)
                            .then_some(r.position)
                    })
                    .ok_or_else(|| format!("key {key} tag {tag} not present in {}", path.display()))?
            };
            btrieve.block_mut(at)?.delete(position).map_err(|e| e.to_string())?;
        }
    }

    btrieve.close(&mut mem, &mut heap, at).map_err(|e| e.to_string())?;
    Ok(())
}

/// Every live record's whole bytes, in KEY 0's order -- "walk order" and
/// "census" for Gate B, read the same way `Block::records()` reads them for
/// any real `Get`/`Step` sequence a module could issue.
///
/// `Records::ordered_len` returns `None` only when key index 0 itself does
/// not exist (every fixture here has exactly one key, index 0) -- a
/// **structural** problem, not "zero records." That case is a hard error
/// here, not `.unwrap_or(0)`: silently treating "no such key" as "an empty
/// walk" would let two broken reads that both hit this path agree with
/// each other (`vec![] == vec![]`) and be reported as a Gate-B pass.
fn ordered_bytes(label: &str, path: &Path) -> Result<Vec<Vec<u8>>, String> {
    let mut mem = FlatMem::new(64 * 1024);
    let mut heap = FlatHeap::new(0x100);
    let mut btrieve = Btrieve::<Flat>::default();
    let geometry = Geometry::read(label, path).map_err(|e| e.to_string())?;
    let maxlen = geometry.reclen;
    let at = btrieve.open(&mut mem, &mut heap, label, path, geometry, maxlen)?;
    let block = btrieve.block_mut(at)?;
    let records = block.records().map_err(|e| e.to_string())?;
    let n = records
        .ordered_len(0)
        .ok_or_else(|| "key index 0 does not exist on this file (every fixture here has one key)".to_string())?;
    let out = (0..n).map(|i| records.ordered(0, i).expect("index in range").bytes.clone()).collect();
    let _ = btrieve.close(&mut mem, &mut heap, at);
    Ok(out)
}

/// One step's outcome: Gate A cleared outright, Gate B cleared as the floor
/// (carrying its own byte-diff description, per this task's "no silent
/// downgrades" rule), neither (but the ops themselves applied), or the ops
/// themselves failed to apply.
///
/// [`Verdict::Aborted`] is its own variant, distinct from [`Verdict::Red`],
/// specifically so [`run_sequence`] can decide whether to skip the rest of
/// a sequence by matching on the *variant* rather than sniffing an error
/// message's own wording -- a message can be reworded for clarity without
/// silently breaking that decision.
enum Verdict {
    GateA,
    GateB(String),
    Red(String),
    Aborted(String),
}

/// Whether `step_label`, within `seq_name`, is recorded as a genuinely empty
/// walk -- the one named exception [`gate_b`]'s own doc comment reserves,
/// rather than a blanket `vec![] == vec![]`. `delete_to_empty`'s first step
/// deletes a single-level key's only record; genuine Btrieve answers OK and
/// the root reverts to the virgin shape (`docs/2026-08-25-btree-split-
/// rules.md` §7) -- an intentionally empty key, not a broken read.
fn expects_empty_census(seq_name: &str, step_label: &str) -> bool {
    seq_name == "delete_to_empty" && step_label == "delete the key's only record -- root reverts to virgin shape"
}

/// Gate B: our own output round-trips cleanly, AND a fresh open of both our
/// output and the recorded snapshot see the same key-ordered record bytes.
fn gate_b(
    scratch_path: &Path,
    scratch_label: &str,
    expect_bytes: &[u8],
    expect_copy_path: &Path,
    expect_empty: bool,
) -> (bool, String) {
    let scratch_bytes = match fs::read(scratch_path) {
        Ok(b) => b,
        Err(e) => return (false, format!("cannot re-read our own scratch output: {e}")),
    };

    let model = match read::file(&scratch_bytes) {
        Ok(m) => m,
        Err(e) => return (false, format!("our own output does not decode: {}", e.why)),
    };
    match emit::file(&model) {
        Ok(emitted) if emitted.bytes() == scratch_bytes.as_slice() => {}
        Ok(_) => return (false, "our own output does not round-trip cleanly through read::file/emit::file".to_string()),
        Err(e) => return (false, format!("round-trip emit faulted on our own output: {e}")),
    }

    if let Err(e) = fs::write(expect_copy_path, expect_bytes) {
        return (false, format!("could not stage a scratch copy of the recorded snapshot: {e}"));
    }

    let ours = match ordered_bytes(scratch_label, scratch_path) {
        Ok(v) => v,
        Err(e) => return (false, format!("cannot open our own output for a records walk: {e}")),
    };
    let theirs = match ordered_bytes("expect-compare", expect_copy_path) {
        Ok(v) => v,
        Err(e) => return (false, format!("recorded snapshot is not readable by this crate's own engine: {e}")),
    };

    // Two empty walks trivially satisfy `ours == theirs` without proving
    // anything -- every fixture in this corpus holds live records except
    // the one `expect_empty` names, so an empty walk elsewhere means
    // something upstream already went wrong (a mis-copied scratch file, an
    // op that silently deleted everything, ...). Gate B must never launder
    // that into a pass on its own say-so; only the named, recorded-as-empty
    // case gets to treat `vec![] == vec![]` as agreement.
    if theirs.is_empty() {
        if expect_empty && ours.is_empty() {
            return (true, "0 records both sides -- the key's last record was deleted, and the recorded snapshot agrees the tree is genuinely empty".to_string());
        }
        return (
            false,
            "recorded snapshot's key-0 walk is empty -- refusing to call an empty match a pass; \
             an intentionally empty fixture needs its own explicit case here"
                .to_string(),
        );
    }
    if ours.is_empty() {
        return (
            false,
            "our own output's key-0 walk is empty while the recorded snapshot's is not".to_string(),
        );
    }

    if ours == theirs {
        (true, format!("{} records, key-order and content identical", ours.len()))
    } else {
        (
            false,
            format!(
                "key-ordered census differs: ours has {} record(s), the recording has {}",
                ours.len(),
                theirs.len()
            ),
        )
    }
}

fn first_diff(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).position(|(x, y)| x != y).unwrap_or_else(|| a.len().min(b.len()))
}

/// Apply `step`'s ops to `working_path` (which already holds the prior
/// step's -- or the sequence's starting -- state) and score the result
/// against `step.expect`.
fn run_step(working_path: &Path, working_label: &str, seq_name: &str, step: &Step) -> Verdict {
    for op in &step.ops {
        if let Err(e) = apply_op(working_label, working_path, *op) {
            return Verdict::Aborted(format!("op application failed: {e}"));
        }
    }

    let ours = fs::read(working_path).unwrap_or_else(|e| panic!("re-reading scratch file: {e}"));
    let theirs =
        fs::read(&step.expect).unwrap_or_else(|e| panic!("{}: {e}", step.expect.display()));

    if ours == theirs {
        return Verdict::GateA;
    }

    let diff_at = first_diff(&ours, &theirs);
    let expect_copy = working_path.with_file_name("expect-compare.dat");
    let expect_empty = expects_empty_census(seq_name, step.label);
    let (ok, detail) = gate_b(working_path, working_label, &theirs, &expect_copy, expect_empty);
    if ok {
        Verdict::GateB(format!(
            "first byte diff at {diff_at:#x} (ours {} bytes, recorded {} bytes); {detail}",
            ours.len(),
            theirs.len()
        ))
    } else {
        Verdict::Red(format!(
            "Gate A failed (first diff at {diff_at:#x}, ours {} bytes, recorded {} bytes); \
             Gate B unavailable: {detail}",
            ours.len(),
            theirs.len()
        ))
    }
}

struct Step {
    ops: Vec<ReplayOp>,
    expect: PathBuf,
    label: &'static str,
}

struct Sequence {
    name: &'static str,
    start: PathBuf,
    file_label: &'static str,
    steps: Vec<Step>,
}

fn insert(key: u32, tag: u32) -> ReplayOp {
    ReplayOp::Insert { key, tag }
}

fn delete(key: u32) -> ReplayOp {
    ReplayOp::Delete { key }
}

fn delete_tagged(key: u32, tag: u32) -> ReplayOp {
    ReplayOp::DeleteTagged { key, tag }
}

/// Every sequence this corpus can replay -- one entry per committed
/// snapshot chain, ops reconstructed per this file's own module doc.
fn sequences() -> Vec<Sequence> {
    vec![
        Sequence {
            name: "append512u_leaf_split",
            start: fixture("append512u/leaf-split/before.dat"),
            file_label: "SPLAPPU.DAT",
            steps: vec![Step {
                ops: vec![insert(42, 42)],
                expect: fixture("append512u/leaf-split/after.dat"),
                label: "insert 42 (41-entry leaf splits, root grows depth 1->2)",
            }],
        },
        Sequence {
            name: "append512u_interior_split",
            start: fixture("append512u/interior-split/before.dat"),
            file_label: "SPLAPPU.DAT",
            steps: vec![Step {
                ops: vec![insert(944, 944)],
                expect: fixture("append512u/interior-split/after.dat"),
                label: "insert 944 (interior root splits, depth 2->3)",
            }],
        },
        Sequence {
            name: "append4096u_leaf_split",
            start: fixture("append4096u/leaf-split/before.dat"),
            file_label: "SPLAPP4.DAT",
            steps: vec![Step {
                ops: vec![insert(341, 341)],
                expect: fixture("append4096u/leaf-split/after.dat"),
                label: "insert 341 (340-entry leaf splits, even max_entries)",
            }],
        },
        Sequence {
            name: "middle512u_leaf_split",
            start: fixture("middle512u/leaf-split/before.dat"),
            file_label: "SPLMIDV2.DAT",
            steps: vec![Step {
                ops: vec![insert(20_500, 42)],
                expect: fixture("middle512u/leaf-split/after.dat"),
                label: "insert 20500 (splits by position in the merged sequence, not by edge)",
            }],
        },
        Sequence {
            name: "dup512_leaf_split",
            start: fixture("dup512/leaf-split/before.dat"),
            file_label: "SPLDUPU.DAT",
            steps: vec![Step {
                ops: vec![insert(32, 32)],
                expect: fixture("dup512/leaf-split/after.dat"),
                label: "insert 32 (31-entry dup-permitting leaf splits)",
            }],
        },
        Sequence {
            name: "dup512_duplicate_chain",
            start: fixture("dup512/duplicate-chain/before.dat"),
            file_label: "SPLDUPU.DAT",
            steps: vec![Step {
                ops: vec![insert(40, 41), insert(40, 42), insert(40, 43), insert(40, 44), insert(40, 45)],
                expect: fixture("dup512/duplicate-chain/after.dat"),
                label: "5 more records under key 40 (extends one entry's head/tail chain)",
            }],
        },
        Sequence {
            name: "underflow512u_merge_on_delete",
            start: fixture("underflow512u/merge-on-delete/before.dat"),
            file_label: "SPLDELU.DAT",
            steps: vec![Step {
                ops: (61..=120).rev().map(delete).collect(),
                expect: fixture("underflow512u/merge-on-delete/after.dat"),
                label: "delete 120..61 descending (60 deletes; empties/merges 3 leaves)",
            }],
        },
        Sequence {
            name: "underflow_lifecycle_512",
            start: fixture("underflow-lifecycle-512/1-pristine.dat"),
            file_label: "REPLAY512.DAT",
            steps: vec![
                Step {
                    ops: vec![delete(23)],
                    expect: fixture("underflow-lifecycle-512/2-at-threshold.dat"),
                    label: "delete 23 (21->20 == half_entries: no structural change)",
                },
                Step {
                    ops: vec![delete(24)],
                    expect: fixture("underflow-lifecycle-512/3-merged.dat"),
                    label: "delete 24 (20->19 < half_entries: merges into right sibling)",
                },
                Step {
                    ops: vec![insert(65, 65), insert(66, 66)],
                    expect: fixture("underflow-lifecycle-512/4-reclaimed.dat"),
                    label: "insert 65, 66 (right sibling re-splits, reclaims the vacated page)",
                },
            ],
        },
        Sequence {
            name: "underflow_lifecycle_4096",
            start: fixture("underflow-lifecycle-4096/1-pristine.dat"),
            file_label: "REPLAY4096.DAT",
            steps: vec![Step {
                ops: vec![delete(172)],
                expect: fixture("underflow-lifecycle-4096/2-merged.dat"),
                label: "delete 172 (170->169 < half_entries on the FIRST delete: even max_entries)",
            }],
        },
        Sequence {
            name: "underflow_edge_rightmost",
            start: fixture("underflow-edge-rightmost/1-pristine.dat"),
            file_label: "REPLAYRM.DAT",
            steps: vec![Step {
                ops: vec![delete(45)],
                expect: fixture("underflow-edge-rightmost/2-redistributed.dat"),
                label: "delete 45 (rightmost leaf, no right sibling: redistributes left)",
            }],
        },
        Sequence {
            name: "underflow_edge_leftmost",
            start: fixture("underflow-edge-leftmost/1-pristine.dat"),
            file_label: "REPLAYLM.DAT",
            steps: vec![Step {
                ops: vec![delete(1), delete(2)],
                expect: fixture("underflow-edge-leftmost/2-redistributed.dat"),
                label: "delete 1, 2 (leftmost leaf, no left sibling: redistributes right)",
            }],
        },
        Sequence {
            name: "underflow_no_room_redistribute",
            start: fixture("underflow-no-room-redistribute/1-topped-up.dat"),
            file_label: "REPLAYNR.DAT",
            steps: vec![Step {
                ops: vec![delete(23), delete(24)],
                expect: fixture("underflow-no-room-redistribute/2-redistributed.dat"),
                label: "delete 23, 24 (right sibling has no room to merge: redistributes anyway)",
            }],
        },
        Sequence {
            name: "underflow_right_absent_cascade_donor_8",
            start: fixture("underflow-right-absent-cascade/00133-delete-109.dat"),
            file_label: "REPLAYC1.DAT",
            steps: vec![
                Step {
                    ops: vec![delete(108)],
                    expect: fixture("underflow-right-absent-cascade/00134-delete-108.dat"),
                    label: "delete 108 (rightmost leaf redistributes with leaf 8: 21->20)",
                },
                Step {
                    ops: vec![delete(107)],
                    expect: fixture("underflow-right-absent-cascade/00135-delete-107.dat"),
                    label: "delete 107 (leaf 8 now at half_entries: merges instead)",
                },
            ],
        },
        Sequence {
            name: "underflow_right_absent_cascade_donor_10",
            start: fixture("underflow-right-absent-cascade/00155-delete-87.dat"),
            file_label: "REPLAYC2.DAT",
            steps: vec![
                Step {
                    ops: vec![delete(86)],
                    expect: fixture("underflow-right-absent-cascade/00156-delete-86.dat"),
                    label: "delete 86 (new rightmost redistributes with leaf 10: 21->20)",
                },
                Step {
                    ops: vec![delete(85)],
                    expect: fixture("underflow-right-absent-cascade/00157-delete-85.dat"),
                    label: "delete 85 (leaf 10 now at half_entries: merges instead)",
                },
            ],
        },
        Sequence {
            name: "underflow_right_absent_cascade_donor_4",
            start: fixture("underflow-right-absent-cascade/00177-delete-65.dat"),
            file_label: "REPLAYC3.DAT",
            steps: vec![
                Step {
                    ops: vec![delete(64)],
                    expect: fixture("underflow-right-absent-cascade/00178-delete-64.dat"),
                    label: "delete 64 (new rightmost redistributes with leaf 4: 21->20)",
                },
                Step {
                    ops: vec![delete(63)],
                    expect: fixture("underflow-right-absent-cascade/00179-delete-63.dat"),
                    label: "delete 63 (leaf 4 now at half_entries: merges instead; matches round 1's end state)",
                },
            ],
        },
        // --- Phase 2 (review-driven): partial dup-chain delete, interior-
        // separator delete, delete-to-empty, multi-candidate reclaim order.
        Sequence {
            name: "dup_chain_partial_delete",
            start: fixture("dup-chain-partial-delete/00-baseline-all-groups.dat"),
            file_label: "SPLDUPPD.DAT",
            steps: vec![
                Step {
                    ops: vec![delete_tagged(100, 1)],
                    expect: fixture("dup-chain-partial-delete/01-head-deleted-group100.dat"),
                    label: "delete the head (tag 1) of group 100",
                },
                Step {
                    ops: vec![delete_tagged(200, 2)],
                    expect: fixture("dup-chain-partial-delete/02-middle-deleted-group200.dat"),
                    label: "delete the middle (tag 2) of group 200",
                },
                Step {
                    ops: vec![delete_tagged(300, 3)],
                    expect: fixture("dup-chain-partial-delete/03-tail-deleted-group300.dat"),
                    label: "delete the tail (tag 3) of group 300",
                },
                Step {
                    ops: vec![delete_tagged(400, 1)],
                    expect: fixture("dup-chain-partial-delete/04-group400-3-to-2.dat"),
                    label: "group 400: 3 members -> 2 (delete the head)",
                },
                Step {
                    ops: vec![delete_tagged(400, 2)],
                    expect: fixture("dup-chain-partial-delete/05-group400-2-to-1-solo.dat"),
                    label: "group 400: 2 members -> 1 solo (delete the new head)",
                },
                Step {
                    ops: vec![delete_tagged(400, 3)],
                    expect: fixture("dup-chain-partial-delete/06-group400-eliminated.dat"),
                    label: "group 400: solo -> eliminated, like any unique key's last record",
                },
            ],
        },
        Sequence {
            name: "interior_separator_delete",
            start: fixture("interior-separator-delete/before.dat"),
            file_label: "SPLISEPD.DAT",
            steps: vec![Step {
                ops: vec![delete(22)],
                expect: fixture("interior-separator-delete/after.dat"),
                label: "delete 22 (an interior separator; replaced by predecessor 21)",
            }],
        },
        Sequence {
            name: "delete_to_empty",
            start: fixture("delete-to-empty/1-one-record.dat"),
            file_label: "SPLEMPTY.DAT",
            steps: vec![
                Step {
                    ops: vec![delete(1)],
                    expect: fixture("delete-to-empty/2-emptied.dat"),
                    label: "delete the key's only record -- root reverts to virgin shape",
                },
                Step {
                    ops: vec![insert(2, 2)],
                    expect: fixture("delete-to-empty/3-reinserted.dat"),
                    label: "re-insert -- reuses the same root logical id",
                },
            ],
        },
        Sequence {
            name: "retired_page_reclaim_order_retire",
            start: fixture("retired-page-reclaim-order/1-none-retired.dat"),
            file_label: "SPLRECL1.DAT",
            steps: vec![Step {
                ops: vec![delete(63)],
                expect: fixture("retired-page-reclaim-order/2-leaf10-retired.dat"),
                label: "delete 63 (leaf 10 underflows and retires)",
            }],
        },
        Sequence {
            name: "retired_page_reclaim_order_retire_second",
            start: fixture("retired-page-reclaim-order/3-before-leaf12-retirement.dat"),
            file_label: "SPLRECL2.DAT",
            steps: vec![Step {
                ops: vec![delete(130)],
                expect: fixture("retired-page-reclaim-order/4-both-retired.dat"),
                label: "delete 130 (leaf 12 underflows and retires too -- LIFO chain 12 -> 10)",
            }],
        },
        Sequence {
            name: "retired_page_reclaim_order_reclaim_first",
            start: fixture("retired-page-reclaim-order/5-before-first-reclaim.dat"),
            file_label: "SPLRECL3.DAT",
            steps: vec![Step {
                ops: vec![insert(155, 155)],
                expect: fixture("retired-page-reclaim-order/6-leaf12-reclaimed-first.dat"),
                label: "insert 155 (forces a split; reclaims 12, the LIFO head, first)",
            }],
        },
        Sequence {
            name: "retired_page_reclaim_order_reclaim_second",
            start: fixture("retired-page-reclaim-order/7-before-second-reclaim.dat"),
            file_label: "SPLRECL4.DAT",
            steps: vec![Step {
                ops: vec![insert(177, 177)],
                expect: fixture("retired-page-reclaim-order/8-leaf10-reclaimed-second.dat"),
                label: "insert 177 (forces another split; reclaims 10, the only one left)",
            }],
        },
    ]
}

/// Copy `seq.start` to scratch, then run every step in order against the
/// SAME evolving file (never reset to a recorded snapshot mid-sequence --
/// this is what makes the harness test a real chain of our own engine's
/// writes, not a series of independent single-op checks). Once a step's op
/// application itself fails, the working file's state is undefined, so
/// every remaining step in that sequence is recorded as skipped rather than
/// scored against a meaningless byte compare.
fn run_sequence(seq: &Sequence, report: &mut Vec<(String, String, Verdict)>) {
    let dir = scratch(&format!("btree-replay-{}", seq.name));
    let working_path = dir.join(seq.file_label);
    fs::copy(&seq.start, &working_path)
        .unwrap_or_else(|e| panic!("copying start fixture {}: {e}", seq.start.display()));

    let mut aborted: Option<String> = None;
    for step in &seq.steps {
        if let Some(reason) = &aborted {
            report.push((
                seq.name.to_string(),
                step.label.to_string(),
                Verdict::Red(format!("skipped: an earlier step in this sequence failed ({reason})")),
            ));
            continue;
        }

        let outcome =
            panic::catch_unwind(AssertUnwindSafe(|| run_step(&working_path, seq.file_label, seq.name, step)));
        let verdict = match outcome {
            Ok(v) => v,
            Err(payload) => {
                let msg = payload
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "panicked with a non-string payload".to_string());
                Verdict::Aborted(format!("panicked applying this step's op(s): {msg}"))
            }
        };

        // Classified by variant, not by matching the message text -- see
        // `Verdict::Aborted`'s own doc comment.
        if let Verdict::Aborted(ref msg) = verdict {
            aborted = Some(msg.clone());
        }
        report.push((seq.name.to_string(), step.label.to_string(), verdict));
    }
}

/// The replay contract itself. Un-ignored as of Task 6, which landed
/// `insert_v6`/`update_v6`/`delete_v6` maintaining each key's B-tree
/// incrementally per `docs/2026-08-25-btree-split-rules.md` -- see
/// `docs/btrieve-unproven.md` §6 for the standing register of every step
/// that clears only Gate B (all 20, today) and why. A standing regression:
/// any future change that turns a Gate-A/Gate-B pass red must fix it or
/// re-register it there, never silently downgrade it.
#[test]
fn the_oracle_replay_contract() {
    let mut report: Vec<(String, String, Verdict)> = Vec::new();
    for seq in sequences() {
        run_sequence(&seq, &mut report);
    }

    let mut gate_a = Vec::new();
    let mut gate_b_only = Vec::new();
    let mut reds = Vec::new();

    eprintln!("\n=== btree_replay: today's per-step map ({} steps) ===", report.len());
    for (seq, step, verdict) in &report {
        match verdict {
            Verdict::GateA => {
                eprintln!("[GATE A]  {seq} :: {step}");
                gate_a.push(format!("{seq} :: {step}"));
            }
            Verdict::GateB(detail) => {
                eprintln!("[GATE B]  {seq} :: {step} -- {detail}");
                gate_b_only.push(format!("{seq} :: {step} -- {detail}"));
            }
            Verdict::Red(detail) => {
                eprintln!("[RED]     {seq} :: {step} -- {detail}");
                reds.push(format!("{seq} :: {step} -- {detail}"));
            }
            Verdict::Aborted(detail) => {
                eprintln!("[RED]     {seq} :: {step} -- {detail}");
                reds.push(format!("{seq} :: {step} -- {detail}"));
            }
        }
    }
    eprintln!(
        "\n{} Gate-A pass(es), {} Gate-B-only pass(es), {} red, {} step(s) total\n",
        gate_a.len(),
        gate_b_only.len(),
        reds.len(),
        report.len()
    );
    if !gate_a.is_empty() {
        eprintln!(
            "ACCIDENTAL GATE-A PASS(ES) -- flag for Task 6, this op's CURRENT behaviour \
             already matches genuine Btrieve 6.15 byte-for-byte:"
        );
        for p in &gate_a {
            eprintln!("  {p}");
        }
        eprintln!();
    }

    assert!(
        reds.is_empty(),
        "{} of {} steps are RED (neither gate cleared) -- see stderr above (rerun with \
         `-- --nocapture` to see it) for the full per-step map. This is a standing \
         regression, not an expected failure: `insert_v6`/`update_v6`/`delete_v6` all \
         maintain their B-tree incrementally (Task 6), and every step here has already \
         been measured to clear at least Gate B. A red step means something that used to \
         match the recording no longer does.",
        reds.len(),
        report.len(),
    );
}
