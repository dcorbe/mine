//! The regression the btrieve-page-cache branch's own throughput measurement
//! found: a serial A/B against `main-code` showed the mass-write workload
//! (MajorMUD's boot-time "Automatic Database Update", insert-heavy) reading
//! 83x more bytes overall and finishing slower despite far fewer read
//! syscalls -- the signature of a large read replacing many small ones. A
//! live `strace` against the branch binary found a second file handle, not
//! the resident page cache's own, repeating once per write op: one read of
//! the file's entire current length from offset zero (growing in step with
//! the file itself), which is exactly what [`btrieve::records::Records::read`]
//! does on a cache miss.
//!
//! # The caller, not the engine
//!
//! `crates/btrieve`'s own write path was already correct: `Block::insert`'s
//! fast path (`Block::v6_fast_reads`) never touches `Block::records()` for a
//! fixed-length v6 file with a page cache attached -- `write_cost.rs`'s own
//! `wccmp002_insert_cost_today` measures a single `Block::insert()` call
//! directly and it reads a bounded, page-sized amount regardless of file
//! size. The whole-file read was coming from *this* crate instead:
//! `shims/btrieve.rs`'s `duplicate_key` and `insert_record`/`update_variable`
//! called `Block::records()` directly -- a public API with no fast-path
//! awareness of its own; that gate lives in the *callers* `Block::query`/
//! `Block::step` already check -- to answer "does this key already have a
//! collision" and "what cursor does the record I just wrote occupy", on
//! every single insert and update, regardless of whether the fast path
//! applied. Fixed by riding `Block::query`/`Block::get_position` (for the
//! duplicate check) and the new `Block::cursor_for` (for currency) instead,
//! both of which honour `Block::v6_fast_reads` already.
//!
//! # What this test asserts, and why not bytes
//!
//! `btrieve::testing::record_walks()` counts `Records::read` calls directly
//! -- the one call this whole defect funnels through, regardless of the
//! fixture's size. A byte-count bound would need a file large enough to make
//! the difference dramatic; this does not, because it asserts the walk never
//! happens at all for a fixed-length v6 file with a key that already
//! permits duplicates (so `duplicate_key`'s own loop skips its query too,
//! on both the broken and the fixed code -- the bound below is not tuned to
//! this fixture's shape, it holds regardless of it). `DUPKEY30.DAT` is a
//! genuine, small (6,144-byte) v6 fixed-length keyed file already committed
//! for `crates/btrieve`'s own tests -- copied here, not written to in place
//! (every test below runs against its own [`scratch_with`] copy).

use mbbs::shims::dfa::{dfaCountRec, dfaInsertV, dfaOpen};
use mbbs::testing::{Fixture, scratch_with};
use mbbs_machine::m16::{FarPtr, Ret};

/// `DUPKEY30.DAT`'s own shape: 12-byte fixed-length records, a single
/// 4-byte key at offset 0 that permits duplicates, 30 records to start.
const MAXLEN: u16 = 12;

/// Open `name` through the real `dfaOpen` shim, as a module would.
fn open(f: &mut Fixture, name: &str, maxlen: u16) -> FarPtr {
    let at = f.text(name);
    match f.invoke(dfaOpen, &[at.offset, at.selector, maxlen, 0, 0]).expect("dfaOpen") {
        Ret::Far(block) => block,
        other => panic!("dfaOpen returns a pointer, got {other:?}"),
    }
}

/// A 12-byte `DUPKEY30.DAT`-shaped record: `key` at offset 0 (little-endian,
/// four bytes), the remaining eight bytes zero -- this file's own key reads
/// a 4-byte value there (`records.rs`'s own doc comment: "its one key reads
/// offset: 2" of the *physical* slot, which is offset 0 of the logical
/// record once the v6 slot marker is accounted for).
fn record(key: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; usize::from(MAXLEN)];
    bytes[..4].copy_from_slice(&key.to_le_bytes());
    bytes
}

/// `dfaInsertV(recptr, length)` -- insert one record, refusing on a
/// duplicate (this file's key permits them, so nothing here ever refuses).
fn insert(f: &mut Fixture, bytes: &[u8]) {
    let recptr = f.bytes(bytes, false);
    f.invoke(dfaInsertV, &[recptr.offset, recptr.selector, MAXLEN]).expect("dfaInsertV");
}

/// Thirty `dfaInsertV` calls against a fixed-length v6 keyed file with a
/// page cache attached must never rebuild the file's whole-file `Records`
/// model -- that model exists for files this fast path cannot serve
/// (variable-length, or no cache), not for the ordinary case every one of
/// these inserts is.
///
/// **Fails against the code this task found**: before `duplicate_key`/
/// `insert_record` were changed to use `Block::query`/`Block::cursor_for`,
/// this measured 31 walks for 30 inserts -- `git stash` the fix in
/// `crates/mbbs/src/shims/btrieve.rs` and `crates/btrieve/src/ops.rs` and
/// this assertion fails with that exact count.
#[test]
fn dfainsertv_never_rebuilds_the_whole_file_record_model() {
    let dir = scratch_with("dfa-insertv-record-walks", &["DUPKEY30.DAT"]);
    let mut f = Fixture::rooted(dir);
    open(&mut f, "DUPKEY30.DAT", MAXLEN);

    let before = f.invoke(dfaCountRec, &[]).expect("counts");
    assert_eq!(before, Ret::U32(30), "DUPKEY30.DAT starts with 30 records");

    btrieve::testing::reset_record_walks();
    for key in 1000u32..1030 {
        insert(&mut f, &record(key));
    }

    let after = f.invoke(dfaCountRec, &[]).expect("counts");
    assert_eq!(after, Ret::U32(60), "all 30 new records landed");

    assert_eq!(
        btrieve::testing::record_walks(),
        0,
        "30 inserts on a fixed-length v6 file with a page cache rebuilt the whole-file \
         Records model {} times -- expected 0: this file's fast path (Block::v6_fast_reads) \
         should mean Block::records() is never called at all, by any of duplicate_key, \
         insert_record's currency step, or the engine's own insert_v6",
        btrieve::testing::record_walks()
    );
}
