//! Task 12: replay `crates/btrieve-oracle`'s committed fixtures -- recorded
//! from genuine Pervasive Btrieve 6.15 under Wine, Task 11 -- through this
//! crate's own numeric [`btrieve::btrcall::btrcall`] and diff.
//!
//! Wine never runs here. This test reads only `fixtures/*.fixture`, already
//! committed to the repo by `btrieve-oracle`'s `#[ignore]`d generator (see
//! `crates/btrieve-oracle/src/scenario.rs`'s own doc comment).
//!
//! # What is compared, and what is not
//!
//! Each [`Scenario`](btrieve_oracle::scenario::Scenario) call is replayed
//! against a file this crate's own [`btrieve::create`] builds from the
//! seed's decoded `B_CREATE` geometry, and the answer is compared to the
//! recorded [`Transcript`](btrieve_oracle::scenario::Transcript) response:
//!
//! - **Status** is always compared.
//! - **The data buffer** is compared only when the recorded status says a
//!   record was actually delivered (0, or 22 for a truncated one -- none of
//!   the committed fixtures hit 22, but the rule is the same one [`get`]'s
//!   own dispatch uses for "delivered"). On every other status the buffer is
//!   **not** compared: measured directly against these fixtures, a miss's
//!   recorded `databuf` is not a real Btrieve answer at all, it is whatever
//!   `tools/btrieve-oracle/btrvprobe.c`'s own reused send buffer happened to
//!   be holding from an earlier call on the wire (`status_ten_refusal_and_
//!   same_value_rewrite.fixture`'s call 5, a `Get Equal` miss, answers a
//!   `databuf` that is byte-for-byte the *B_CREATE* request's own
//!   `FileSpec`/`KeySpec` payload -- stale server-side memory, not a Btrieve
//!   status's payload). Comparing it would fail every miss for a reason that
//!   means nothing, the same shape this module's own `posblk` exclusion is.
//! - **`posblk` is never compared.** Genuine Btrieve's position block is
//!   128 bytes of engine-private cursor state; this engine's is a handle
//!   into host-side state (`Call::posblk`'s own doc comment in
//!   `crates/btrieve/src/btrcall.rs`). Neither shape is scenario data.
//! - **Not raw file bytes.** `crates/btrieve/src/lib.rs:6140-6146` records
//!   that this crate's index builder does not promise genuine Btrieve's own
//!   byte layout -- and separately, every fixture's seed file is genuine
//!   Btrieve 6.15's own v6 layout, while [`btrieve::create`] only ever
//!   builds v5 (`crates/btrieve/src/create.rs`'s own doc comment), so the
//!   two files being compared are never going to be byte-identical even in
//!   principle. Instead, [`resulting_records`] reopens **both** the file
//!   this replay's own run produced and the fixture's own recorded `file`
//!   bytes through this crate's own reader (`Get First`/`Get Next` walked to
//!   exhaustion) and compares what each answers: the records, in key order,
//!   and how many there are.
//! - **`B_STAT` (op 15) is excluded from the whole-buffer `databuf` diff, but
//!   its `approx_count` fields are compared on their own** ([`approx_counts`]).
//!   The exclusion is the v5/v6 wire-format difference
//!   [`Stat::wire`](btrieve::Stat) already accounts for by taking a `version`
//!   parameter: every fixture's own file is genuine Btrieve 6.15's v6 layout
//!   and [`btrieve::create`] only ever builds v5.
//!
//!   It used to hide a second thing, which was not a format difference at all:
//!   this engine's v5 write path updated the file's own record count but never
//!   a key's own stored `approx_count` (`pages::fcr::KEY_RECORDS`), so a
//!   freshly created and written v5 file reported `approx_count: 0` after
//!   three inserts where genuine Btrieve answers 3. Reported rather than
//!   fixed at the time (Task 12 was scoped to the status 4/9 defect);
//!   fixed since, and this is the comparison that pins it. The lesson is the
//!   narrower one: an exclusion drawn wider than its reason takes real
//!   findings out with it.
//!
//! # An empty sweep is a failure
//!
//! for the same reason a denylist that finds nothing to deny is not proof
//! nothing was wrong. See [`MIN_SCENARIOS`].

use std::path::Path;

use btrieve::btrcall::{btrcall, Call, Status};
use btrieve::testing::{scratch, Flat, FlatHeap, FlatMem};
use btrieve::{Btrieve, FileSpec, KeySpec, SegmentSpec};

use btrieve_oracle::scenario::{self, Seed};
use btrieve_oracle::Request;

/// The fewest fixtures a clean run must find. Pinned at the number
/// `crates/btrieve-oracle/fixtures/` carries today (`open_close`,
/// `insert_get_step_stat`, `update_and_delete`,
/// `status_ten_refusal_and_same_value_rewrite`) so a run that silently finds
/// zero fixtures -- a moved directory, a build that never copied them, a
/// glob that stopped matching -- fails loudly instead of reporting a clean
/// sweep of nothing.
const MIN_SCENARIOS: usize = 4;

/// Decodes a `B_CREATE` request's `databuf` into the [`FileSpec`] shape
/// [`btrieve::create`] accepts.
///
/// The wire layout is `crates/btrieve-oracle/src/scenario.rs`'s own doc
/// comment's: one 16-byte `FileSpec` followed by one 16-byte `KeySpec`.
/// Every fixture this crate replays declares exactly one key -- asserted
/// here, rather than silently decoding only the first of several and
/// dropping the rest.
fn filespec_of(databuf: &[u8]) -> FileSpec {
    assert_eq!(
        databuf.len(),
        32,
        "a B_CREATE databuf of {} bytes is not the single FileSpec+KeySpec pair (32 bytes) \
         every committed fixture uses -- this decoder does not understand more than one key",
        databuf.len()
    );
    let u16le = |o: usize| u16::from_le_bytes([databuf[o], databuf[o + 1]]);

    let record_length = u16le(0);
    let page_size = u16le(2);

    const KEY: usize = 16;
    let position = u16le(KEY); // 1-based, KeySpec.position
    let length = u16le(KEY + 2);
    let flags = u16le(KEY + 4);
    let ext_type = databuf[KEY + 10];

    // KeySpec.flags bits -- scenario.rs's own doc comment.
    const DUP: u16 = 0x01;
    const MODIFY: u16 = 0x02;
    const DESCENDING: u16 = 0x40;

    FileSpec {
        record_length,
        page_size,
        keys: vec![KeySpec {
            segments: vec![SegmentSpec {
                offset: position - 1,
                length,
                kind: ext_type,
                descending: flags & DESCENDING != 0,
            }],
            duplicates: flags & DUP != 0,
            modifiable: flags & MODIFY != 0,
        }],
    }
}

/// True for the two statuses that mean "a record actually came back" --
/// [`get`](btrieve::btrcall)'s own truncation convention, and the only
/// statuses whose recorded `databuf` is real Btrieve data rather than
/// leftover wire-server memory. See this module's own doc comment.
fn delivers(status: i16) -> bool {
    status == 0 || status == 22
}

/// Pre-sizes a call's `databuf` to `capacity` bytes, zero-padded.
///
/// The genuine wire's own `Request` separates "how many bytes the caller's
/// buffer can hold" (`datalen`) from "how many bytes of it were worth
/// putting on the wire" (`databuf`'s own length) -- a `Get` sends `datalen:
/// 64, databuf: []`, because there is nothing meaningful to pre-fill before
/// the call and no reason to ship 64 zero bytes over a socket for it
/// (`crates/btrieve-oracle/src/scenario.rs`'s own `get_request` doc
/// comment). This crate's own numeric [`Call::databuf`] has no such second
/// field -- it is the one real buffer, and [`stat`](btrieve::btrcall)'s own
/// truncation check reads its length directly rather than `*datalen`
/// (`crates/btrieve/src/btrcall.rs`'s `stat`, and its own unit test
/// `stat_through_numbers_reports_shape_and_truncates` pre-sizes `databuf` to
/// `vec![0u8; 1024]`, never `Vec::new()`). Replaying a fixture's `databuf`
/// verbatim would hand `stat` a zero-length buffer no matter what `datalen`
/// said, so every `B_STAT` call would answer a spurious 22. This is the
/// harness translating between the two wire shapes, not a product change.
/// Each key spec's stored `approx_count` in a `B_STAT` reply.
///
/// The reply is one 16-byte file spec followed by one 16-byte spec per key
/// *segment* (`crates/btrieve/src/stat.rs`'s own doc comment), and
/// `approx_count` is the little-endian `u32` six bytes into each of those --
/// `position`, `length`, `flags`, then the count (`Stat::wire`). Comparing
/// this and not the whole buffer is deliberate: the rest of the reply
/// legitimately differs between a v5 file and the v6 one genuine Btrieve
/// created, and `approx_count` does not.
fn approx_counts(reply: &[u8]) -> Vec<u32> {
    const FILE_SPEC: usize = 16;
    const KEY_SPEC: usize = 16;
    const AT: usize = 6;
    reply
        .get(FILE_SPEC..)
        .unwrap_or_default()
        .chunks_exact(KEY_SPEC)
        .map(|k| u32::from_le_bytes([k[AT], k[AT + 1], k[AT + 2], k[AT + 3]]))
        .collect()
}

fn sized(databuf: &[u8], capacity: u32) -> Vec<u8> {
    let capacity = usize::try_from(capacity).unwrap_or(0).max(databuf.len());
    let mut out = databuf.to_vec();
    out.resize(capacity, 0);
    out
}

/// Replays `calls` against `path` (already created) through
/// [`btrieve::btrcall::btrcall`], threading one `posblk` by hand exactly the
/// way `scenario.rs`'s own `generate::drive` says a harness must -- carrying
/// each answer's `posblk` into the next call, starting at zero. The first
/// call in every committed fixture is a `B_OPEN`; its `keybuf` is replaced
/// with `path` (a real, openable path on this machine) rather than the DOS
/// path the fixture recorded, since this replay's file lives somewhere the
/// genuine engine's `C:\btrieve\...` never did.
///
/// Returns one `(status, databuf-after-the-call)` pair per call, in order.
/// Call 0's own `databuf` is not meaningful to compare -- [`sized`] gives it
/// the length the fixture recorded, which for an Open is zero -- so
/// [`replay_and_diff`] skips it deliberately rather than by accident.
fn drive(calls: &[Request], path: &Path) -> Vec<(i16, Vec<u8>)> {
    let mut mem = FlatMem::new(64 * 1024);
    let mut heap = FlatHeap::new(0x100);
    let mut session: Btrieve<Flat> = Btrieve::default();
    let mut posblk = [0u8; 128];

    // Every call is replayed with the `datalen` the fixture recorded,
    // including the `B_OPEN`'s own `0`. This harness used to override that
    // one, sizing it to the largest `datalen` anywhere in the scenario,
    // because this crate's numeric Open fixed every later Get/Step's
    // truncation ceiling to it and replaying the genuine `0` starved them
    // all. The ceiling is now taken per call, from the caller's own buffer
    // (`crates/btrieve/src/ops.rs`'s `deliver_current`), which is what the
    // genuine wire does -- so the override has nothing left to work around
    // and is gone. A harness that has to rewrite its own recorded input to
    // get a pass is describing a defect in what it is testing.

    calls
        .iter()
        .enumerate()
        .map(|(i, call)| {
            let mut datalen = call.datalen;
            let mut databuf = sized(&call.databuf, datalen);
            let mut keybuf = if i == 0 {
                let mut b = path.to_string_lossy().as_bytes().to_vec();
                b.push(0);
                b
            } else {
                call.keybuf.clone()
            };
            let keylen = if i == 0 {
                u8::try_from(keybuf.len()).expect("a scratch path under 255 bytes")
            } else {
                call.keylen
            };

            let status = btrcall(
                &mut session,
                &mut mem,
                &mut heap,
                Call {
                    op: call.op,
                    posblk: &mut posblk,
                    databuf: &mut databuf,
                    datalen: &mut datalen,
                    keybuf: &mut keybuf,
                    keylen,
                    keynum: call.keynum,
                },
            )
            .unwrap_or_else(|gap| {
                panic!("call {i} (op {}): this engine has no answer at all: {}", call.op, gap.what)
            });

            (status.0, databuf)
        })
        .collect()
}

/// Reopens `path` fresh and walks every record in key order (`Get First`,
/// then `Get Next` to exhaustion), returning each record's delivered bytes.
/// The count this replay checks is simply the returned `Vec`'s length --
/// there is no separate count to disagree with it.
fn resulting_records(path: &Path) -> Vec<Vec<u8>> {
    let mut mem = FlatMem::new(64 * 1024);
    let mut heap = FlatHeap::new(0x100);
    let mut session: Btrieve<Flat> = Btrieve::default();
    let mut posblk = [0u8; 128];

    let mut keybuf = path.to_string_lossy().as_bytes().to_vec();
    keybuf.push(0);
    let keylen = u8::try_from(keybuf.len()).expect("a scratch path under 255 bytes");
    let status = btrcall(
        &mut session,
        &mut mem,
        &mut heap,
        Call {
            op: 0, // Open
            posblk: &mut posblk,
            databuf: &mut Vec::new(),
            // See `drive`'s own doc comment on `open_maxlen`: 0 here would
            // starve every Get that follows.
            datalen: &mut 4096,
            keybuf: &mut keybuf,
            keylen,
            keynum: 0,
        },
    )
    .expect("Open is modelled");
    assert_eq!(status, Status::OK, "{}: reopening for the final walk", path.display());

    let mut records = Vec::new();
    let mut op = 12u16; // Get First
    loop {
        let mut databuf = Vec::new();
        let mut datalen = 4096u32;
        let mut kb = Vec::new();
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut datalen,
                keybuf: &mut kb,
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Get is modelled");
        if status != Status::OK {
            break;
        }
        records.push(databuf);
        op = 6; // Get Next
    }

    let status = btrcall(
        &mut session,
        &mut mem,
        &mut heap,
        Call {
            op: 1, // Close
            posblk: &mut posblk,
            databuf: &mut Vec::new(),
            datalen: &mut 0,
            keybuf: &mut Vec::new(),
            keylen: 0,
            keynum: 0,
        },
    )
    .expect("Close is modelled");
    assert_eq!(status, Status::OK, "{}: closing after the final walk", path.display());

    records
}

/// Runs one fixture through [`drive`], diffs every call against the
/// recorded [`Transcript`](scenario::Transcript), then diffs the resulting
/// records against the fixture's own recorded file (re-read through this
/// crate's own reader on both sides -- see this module's doc comment).
/// Panics with the fixture's name and the disagreement on the first
/// mismatch, so a failing run says exactly which fixture and which call.
fn replay_and_diff(fixture: &scenario::Fixture) {
    let name = &fixture.scenario.name;
    let dir = scratch(&format!("differential-{name}"));
    let ours = dir.join("OURS.DAT");
    let genuine = dir.join("GENUINE.DAT");

    let create_databuf = match &fixture.scenario.seed {
        Seed::Create(req) => &req.databuf,
        Seed::File(_) => panic!(
            "{name}: this replay only decodes a Seed::Create seed -- no committed fixture uses \
             Seed::File today, so a File seed here is worth investigating, not skipping"
        ),
    };
    let spec = filespec_of(create_databuf);
    btrieve::create(&ours, &spec).unwrap_or_else(|e| panic!("{name}: building the file: {e}"));

    let outcomes = drive(&fixture.scenario.calls, &ours);
    assert_eq!(
        outcomes.len(),
        fixture.transcript.responses.len(),
        "{name}: replayed {} call(s), the fixture recorded {}",
        outcomes.len(),
        fixture.transcript.responses.len()
    );

    for (i, ((status, databuf), recorded)) in
        outcomes.iter().zip(fixture.transcript.responses.iter()).enumerate()
    {
        assert_eq!(
            *status, recorded.status,
            "{name}: call {i} (op {}): status disagrees -- we answered {status}, \
             genuine Btrieve answered {}",
            fixture.scenario.calls[i].op, recorded.status
        );
        let op = fixture.scenario.calls[i].op;
        // Call 0's own databuf is never compared: it is always the B_OPEN
        // this harness itself rewrote `datalen` for (`drive`'s own doc
        // comment on `open_maxlen`), so its post-call length answers this
        // harness's own choice, not anything genuine Btrieve said.
        //
        // Op 15 (`B_STAT`) is excluded from the *whole-buffer* diff, and that
        // exclusion is a finding rather than a convenience -- see Task 12's
        // report. It had two reasons. One stands: every fixture's own file is
        // genuine Btrieve 6.15's v6 layout while this harness's own
        // `btrieve::create` only ever builds v5 (this module's own doc
        // comment), and `Stat::wire` takes a `version` precisely because the
        // two legitimately differ.
        //
        // The other was a real gap in this engine, and it is now closed: this
        // engine's v5 write path updated the *file's* record count but never
        // a *key's* own stored `approx_count` (`pages::fcr::KEY_RECORDS`), so
        // a freshly created and written v5 file reported `approx_count: 0`
        // after three inserts where genuine Btrieve answered 3. Excluding the
        // whole reply hid that behind a version-format difference that has
        // nothing to do with it. `approx_count` is compared on its own below,
        // which is what would have caught it.
        if i != 0 && op != 15 && delivers(recorded.status) {
            assert_eq!(
                databuf, &recorded.databuf,
                "{name}: call {i} (op {op}): data buffer disagrees on a delivering status ({status})"
            );
        }
        if op == 15 && delivers(recorded.status) {
            assert_eq!(
                approx_counts(databuf),
                approx_counts(&recorded.databuf),
                "{name}: call {i} (op 15): the keys' stored approx_count disagrees -- \
                 this is the field a v5 write path has to keep live per operation, not \
                 defer to close"
            );
        }
    }

    // The resulting file's own contents: reopen what this replay's run
    // produced, and separately materialise the fixture's own recorded file
    // bytes and reopen those -- both through this crate's own reader, so
    // the comparison is never a byte-layout one. See this module's doc
    // comment on why this is not a second B_STAT comparison too.
    std::fs::write(&genuine, &fixture.transcript.file)
        .unwrap_or_else(|e| panic!("{name}: materialising the recorded file: {e}"));

    let ours_records = resulting_records(&ours);
    let genuine_records = resulting_records(&genuine);
    assert_eq!(
        ours_records, genuine_records,
        "{name}: the resulting file's records disagree (in key order, {} of ours vs {} of \
         genuine Btrieve's)",
        ours_records.len(),
        genuine_records.len()
    );
}

/// Task 12: every committed fixture, replayed through this crate's own
/// `btrcall` and diffed against what genuine Pervasive Btrieve 6.15
/// answered. See this module's doc comment for exactly what is and is not
/// compared.
#[test]
fn every_committed_fixture_agrees_with_genuine_btrieve() {
    let fixtures = scenario::load_all().expect("the committed fixtures decode");
    assert!(
        fixtures.len() >= MIN_SCENARIOS,
        "found {} fixture(s), wanted at least {MIN_SCENARIOS} -- an empty or shrunken sweep is \
         a failure, not a clean report (this module's own doc comment)",
        fixtures.len()
    );

    for fixture in &fixtures {
        replay_and_diff(fixture);
    }
}
