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
/// `status_ten_refusal_and_same_value_rewrite`, and the three
/// `v5_variable_*` recordings) so a run that silently finds zero fixtures --
/// a moved directory, a build that never copied them, a glob that stopped
/// matching -- fails loudly instead of reporting a clean sweep of nothing.
const MIN_SCENARIOS: usize = 7;

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
            acs: false,
        }],
        acs: None,
        variable: false,
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
/// Returns one `(status, databuf-after-the-call)` pair per call answered, in
/// order, and -- if this engine had no answer at all for one of them -- that
/// call's index and what it said instead. A gap stops the replay: nothing
/// after it ran, so there are fewer pairs than calls. Call 0's own `databuf`
/// is not meaningful to compare -- [`sized`] gives it the length the fixture
/// recorded, which for an Open is zero -- so [`replay_and_diff`] skips it
/// deliberately rather than by accident.
fn drive(calls: &[Request], path: &Path) -> (Vec<(i16, Vec<u8>)>, Option<(usize, String)>) {
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

    let mut outcomes = Vec::with_capacity(calls.len());
    for (i, call) in calls.iter().enumerate() {
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

        let status = match btrcall(
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
        ) {
            Ok(status) => status,
            // A gap is not a status: this engine had no answer at all.
            // Handed back with whatever was already answered rather than
            // panicked on, so [`PENDING`] can assert the one refusal that is
            // expected today while every other one still fails the test.
            Err(gap) => return (outcomes, Some((i, gap.what))),
        };

        outcomes.push((status.0, databuf));
    }
    (outcomes, None)
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

/// Puts `fixture`'s seed file in place at `path`, ready for the scenario's
/// own first call (always a `B_OPEN`) to open.
///
/// The two seed shapes are the recorder's own, and this mirrors what its
/// `drive` (`crates/btrieve-oracle/src/scenario.rs`) did when the fixture
/// was recorded:
///
/// - [`Seed::Create`]: the recorder sent a `B_CREATE` over the wire and the
///   genuine engine built the file. This replay cannot send that request to
///   anything, so it decodes the request's geometry ([`filespec_of`]) and
///   builds the same file with [`btrieve::create`] instead. The two files
///   are not byte-identical -- genuine Btrieve builds v6, `create` builds v5
///   -- which is why nothing downstream compares their bytes.
/// - [`Seed::File`]: the recorder wrote a file [`btrieve::create`] had
///   already built into the Wine prefix verbatim, and this replay writes
///   those same recorded bytes to its own path. Here the two engines really
///   did start from one identical file, which is what makes the byte
///   comparison in [`replay_and_diff`] meaningful.
fn seed(fixture: &scenario::Fixture, path: &Path) {
    let name = &fixture.scenario.name;
    match &fixture.scenario.seed {
        Seed::Create(req) => {
            let spec = filespec_of(&req.databuf);
            btrieve::create(path, &spec)
                .unwrap_or_else(|e| panic!("{name}: building the file: {e}"));
        }
        Seed::File(bytes) => {
            assert!(
                !bytes.is_empty(),
                "{name}: a Seed::File seed of zero bytes is not a file any B_OPEN can open"
            );
            std::fs::write(path, bytes)
                .unwrap_or_else(|e| panic!("{name}: writing the seed file: {e}"));
        }
    }
}

/// A scenario this engine cannot finish yet: which call it stops at, and
/// what its refusal has to say.
struct Pending {
    /// The fixture's `Scenario::name`.
    fixture: &'static str,
    /// The index of the call this engine has no answer for. Every call
    /// before it is still replayed and diffed exactly as usual.
    call: usize,
    /// A phrase the refusal must contain, so a *different* gap at the same
    /// call still fails.
    refusal: &'static str,
}

/// Every scenario this engine stops partway through, and why.
///
/// **Empty, and that is the point.** Its one entry was
/// `v5_variable_delete`'s call 4, a `B_DELETE` against a version 5
/// variable-length record: this engine had no answer at all, and the entry
/// asserted the refusal's own wording and the call it landed on so that the
/// rest of the fixture stayed honest. The v5 delete has landed
/// (`variable::free_fragment`), the fixture replays to its last call, and
/// the entry is gone -- which the `(None, Some(p))` arm below would have
/// failed the test over had it been left behind.
///
/// The mechanism stays. It is not a way to park a fixture: nothing is
/// skipped except the calls past a refusal and the two whole-file
/// comparisons, which cannot mean anything for a scenario that never
/// finished, and an entry that stops being needed fails this test rather
/// than passing quietly.
const PENDING: &[Pending] = &[];

/// The prefix of every fixture whose resulting file this replay compares to
/// genuine Btrieve's as **bytes**, not only as records.
///
/// Only the `v5_variable_*` recordings can be compared that way at all:
/// their seed is one file [`btrieve::create`] wrote, so both engines started
/// from the same bytes and both maintained a version 5 layout from there.
/// Every other fixture's file is genuine Btrieve's own v6 layout, which this
/// crate does not build (this module's own doc comment).
///
/// # What is compared, and why it is not the whole file
///
/// The whole file was compared first, and the answer is worth writing down
/// rather than only working around. Against `v5_variable_insert` it is:
///
/// ```text
/// the resulting file's bytes disagree at offset 0x0004
///   ours:    00 00 00 04 00 04 00 00 ff ff ff ff ff ff ff ff
///   genuine: 01 00 00 04 00 04 00 00 ff ff ff ff 00 00 4c 10
/// ```
///
/// and against `v5_variable_grow` the same offset, with `02 00` and
/// `00 00 4c 30`. Both are one cause, and it is not the variable pages:
/// **genuine Btrieve never puts a record on the empty data page
/// [`btrieve::create`] pre-allocates.** The seed is four pages, the fourth
/// (physical page 3) a data page with no records; genuine appends a
/// *fifth* page for its first record and threads that page's remaining
/// slots onto the v5 free list at `fcr::FREE` (`0x104c` in the insert
/// scenario, `0x304c` in the grow one, both a slot on a page the engine
/// added). This crate's `pages::Layout::next_slot` scans the data pages the
/// file already has, finds page 3 empty and fills it, leaving `fcr::FREE`
/// at `ff ff ff ff`. Every later byte follows from that: the record
/// positions, so the index entries that name them; which page number each
/// variable page gets; `fcr::PAGES`; and the pages' own modification
/// stamps.
///
/// That divergence is in the **fixed-length** allocator, which no fixture
/// before these three could witness, and it long predates the variable
/// insert this compares. So what is compared here is the part these
/// recordings were made to pin and this crate does own: every variable page
/// in each file, in order, byte for byte, plus the two control-record bytes
/// at `0x39` and `0x3a` that say the file is no longer virgin and which
/// variable page it offers ([`diff_variable_pages`] and
/// [`diff_variable_head`]). Measured today, each page matches genuine
/// Btrieve's in **every byte but its own page number** -- fragment bytes,
/// entry array, fragment count, free-chain field and modification stamp all
/// exact -- and the page number differs only because the file's data pages
/// are numbered differently for the reason above.
const BYTE_COMPARED: &str = "v5_variable_";

/// Diffs two byte strings, reporting the first offset that differs with
/// sixteen bytes of context from each side. `at` is what that offset is
/// called in the message, so a caller comparing a page can name the page.
fn diff_bytes(name: &str, at: &str, ours: &[u8], genuine: &[u8]) {
    const CONTEXT: usize = 16;
    let hex = |b: &[u8]| b.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
    if let Some(i) = (0..ours.len().min(genuine.len())).find(|&i| ours[i] != genuine[i]) {
        let end = (i + CONTEXT).min(ours.len().min(genuine.len()));
        panic!(
            "{name}: {at} disagree at offset {i:#06x}\n\
             \x20 ours:    {}\n\
             \x20 genuine: {}",
            hex(&ours[i..end]),
            hex(&genuine[i..end])
        );
    }
    assert_eq!(
        ours.len(),
        genuine.len(),
        "{name}: {at} agree on every shared byte but not on their length -- ours is {} \
         bytes, genuine Btrieve's is {}",
        ours.len(),
        genuine.len()
    );
}

/// Every version 5 variable page in `file`, lowest page first, as
/// `(number, bytes)`.
///
/// A page qualifies when all four of `variable.rs`'s own v5 rules hold, and
/// they are the engine's own: the data bit of the header's second field is
/// clear (`pages::Header::decode`, so no record page qualifies), the first
/// four bytes decode -- high word first, `pages::long` -- to the page's own
/// physical number ([`variable::Header::read`]'s v5 check), the fragment
/// count at `0x0a` is between 1 and 256, and entry 0, the last two bytes of
/// the page, names `0x0c` (`W32MKDE_decompiled.c:19035`: fragment 0 starts
/// where the header ends, or the engine refuses the file with status 54).
///
/// That last rule is what separates a variable page from an index page,
/// which also clears the data bit and also opens with its own page number:
/// an index page's tail is its unused entry space, all zero, so its entry 0
/// reads `0x0000`.
fn variable_pages(file: &[u8], page: usize) -> Vec<(u32, &[u8])> {
    const DATA_BIT: u16 = 0x8000;
    const FRAGMENT_COUNT: usize = 0x0a;
    const FIRST_FRAGMENT: u16 = 0x0c;
    const MAX_FRAGMENTS: u16 = 256;

    let u16le = |b: &[u8], at: usize| u16::from_le_bytes([b[at], b[at + 1]]);
    // High word first, the way every page pointer in this format is stored.
    let long = |b: &[u8]| u32::from(u16le(b, 0)) << 16 | u32::from(u16le(b, 2));

    (1..file.len() / page)
        .filter_map(|number| {
            let bytes = &file[number * page..(number + 1) * page];
            let fragments = u16le(bytes, FRAGMENT_COUNT);
            let entry_zero = u16le(bytes, page - 2);
            (u16le(bytes, 4) & DATA_BIT == 0
                && long(bytes) == number as u32
                && (1..=MAX_FRAGMENTS).contains(&fragments)
                && entry_zero == FIRST_FRAGMENT)
                .then_some((number as u32, bytes))
        })
        .collect()
}

/// Compares every variable page of `ours` with every variable page of
/// `genuine`, in order, and then the two control-record bytes that name
/// them ([`diff_variable_head`]). See [`BYTE_COMPARED`] for why this and not
/// the whole file.
///
/// Each page is compared from offset `0x04` -- past its own page number,
/// the one field the two files legitimately disagree about. The number is
/// not left unchecked by that: [`variable_pages`] only counts a page whose
/// number field names the page it is actually at, the same self-consistency
/// `variable::Header::read` enforces on the read side, so a page that got
/// its own number wrong is not compared, it is missing -- and the count
/// below is what fails.
fn diff_variable_pages(name: &str, ours: &[u8], genuine: &[u8]) {
    const PAGE_SIZE: usize = 0x08;
    let page = usize::from(u16::from_le_bytes([genuine[PAGE_SIZE], genuine[PAGE_SIZE + 1]]));
    assert!(page >= 512, "{name}: a {page}-byte page is not a Btrieve page size");

    let mine = variable_pages(ours, page);
    let theirs = variable_pages(genuine, page);
    assert_eq!(
        mine.len(),
        theirs.len(),
        "{name}: we wrote {} variable page(s) ({:?}) and genuine Btrieve wrote {} ({:?}) -- \
         a different number of pages is a different allocation policy, not a layout detail",
        mine.len(),
        mine.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
        theirs.len(),
        theirs.iter().map(|(n, _)| *n).collect::<Vec<_>>()
    );
    assert!(
        !mine.is_empty(),
        "{name}: neither file has a variable page, and both scenarios insert records with a \
         body -- this comparison found nothing to compare, which is a failure"
    );

    const NUMBER: usize = 4;
    for ((ours_at, ours_page), (their_at, their_page)) in mine.iter().zip(theirs.iter()) {
        diff_bytes(
            name,
            &format!("our variable page {ours_at} and genuine Btrieve's {their_at}"),
            &ours_page[NUMBER..],
            &their_page[NUMBER..],
        );
    }

    diff_variable_head(name, ours, genuine, &mine, &theirs);
}

/// The two control-record bytes a variable-length write owns, compared the
/// only two ways they can be.
///
/// `VARIABLE_SUBFLAG` (`0x39`) is compared **absolutely**: it is a flag, not
/// a page number, and both engines wrote records into the same virgin file,
/// so both must have cleared it. The seed carries `0xff` here.
///
/// `VARIABLE_HIGHEST` (`0x3a`, a little-endian `u16`) is compared
/// **relatively**: it is the free-space chain's head, so each engine's must
/// name the last variable page *that engine* wrote. Genuine's is 5 for the
/// insert scenario and 10 for the grow one; ours is 4 and 6, because this
/// crate's data pages are numbered differently (see [`BYTE_COMPARED`]).
/// Comparing the two numbers to each other would only re-measure that
/// divergence; comparing each to its own file's last variable page is what
/// catches a head written one off, written stale, or not written at all.
fn diff_variable_head(
    name: &str,
    ours: &[u8],
    genuine: &[u8],
    mine: &[(u32, &[u8])],
    theirs: &[(u32, &[u8])],
) {
    const SUBFLAG: usize = 0x39;
    const HIGHEST: usize = 0x3a;
    let head = |fcr: &[u8]| u32::from(u16::from_le_bytes([fcr[HIGHEST], fcr[HIGHEST + 1]]));
    let last = |pages: &[(u32, &[u8])]| pages.last().expect("checked non-empty above").0;

    assert_eq!(
        ours[SUBFLAG], genuine[SUBFLAG],
        "{name}: the control record's variable subflag at {SUBFLAG:#04x} is {:#04x} for us \
         and {:#04x} for genuine Btrieve -- both engines wrote records into the same virgin \
         file, so both must say it is no longer virgin",
        ours[SUBFLAG], genuine[SUBFLAG]
    );
    assert_eq!(
        head(ours),
        last(mine),
        "{name}: our control record offers variable page {} at {HIGHEST:#04x}, and the last \
         variable page we wrote is {}",
        head(ours),
        last(mine)
    );
    assert_eq!(
        head(genuine),
        last(theirs),
        "{name}: genuine Btrieve's control record offers variable page {} at {HIGHEST:#04x}, \
         and the last variable page it wrote is {} -- this side of the check is the \
         recording disagreeing with itself, which would mean the rule read off it is wrong",
        head(genuine),
        last(theirs)
    );
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

    seed(fixture, &ours);

    let pending = PENDING.iter().find(|p| p.fixture == name);
    // One run only: a gap hands back what it had already answered, so the
    // calls before it are diffed from the same run that produced them --
    // replaying the prefix a second time would be replaying it against a
    // file the first run had already written to.
    let (outcomes, gap) = drive(&fixture.scenario.calls, &ours);
    match (gap, pending) {
        (None, None) => assert_eq!(
            outcomes.len(),
            fixture.transcript.responses.len(),
            "{name}: replayed {} call(s), the fixture recorded {}",
            outcomes.len(),
            fixture.transcript.responses.len()
        ),
        (None, Some(p)) => panic!(
            "{name}: this engine answered every call, including call {} -- the PENDING \
             entry expecting it to refuse with {:?} is stale and must be removed",
            p.call, p.refusal
        ),
        (Some((at, why)), Some(p)) if at == p.call => {
            assert!(
                why.contains(p.refusal),
                "{name}: call {at} refused, as PENDING expects, but with {why:?} rather \
                 than something containing {:?}",
                p.refusal
            );
            assert_eq!(outcomes.len(), at, "{name}: a gap at call {at} answers {at} calls");
        }
        (Some((at, why)), _) => panic!(
            "{name}: call {at} (op {}): this engine has no answer at all: {why}",
            fixture.scenario.calls[at].op
        ),
    }

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

    // A scenario that stopped partway has no resulting file to compare: the
    // recorded one is what the genuine engine wrote after every call.
    if pending.is_some() {
        return;
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

    // And, for the fixtures that started from one file both engines could
    // maintain, the bytes themselves. See [`BYTE_COMPARED`].
    if name.starts_with(BYTE_COMPARED) {
        let written = std::fs::read(&ours)
            .unwrap_or_else(|e| panic!("{name}: reading back what we wrote: {e}"));
        diff_variable_pages(name, &written, &fixture.transcript.file);
    }
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
