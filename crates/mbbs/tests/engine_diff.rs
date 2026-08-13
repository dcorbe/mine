//! The same operation stream through this crate's own Btrieve implementation
//! and through the genuine engine, compared per call.
//!
//! `docs/plans/2026-08-09-btrieve-engine-in-the-loop.md`, Stage 3 (Task 8).
//! Not byte equality of files -- `pages::build_index` deliberately packs
//! pages fuller than Btrieve does, so the right comparison is logical: same
//! record set, same key order, same status per call. See the warning at the
//! top of every file under `tools/btrieve-oracle/`.
//!
//! Two tests:
//!
//! - [`wccspels_reindexed_matches_our_own_walk_and_the_real_engine`] starts
//!   with a sequence that already has a known answer -- `forge.rs`'s
//!   `reindex` variant, which changes nothing about the record set -- and
//!   checks that this crate's own reader and the real engine agree on every
//!   record, by content, in the same key order.
//! - [`duplicate_insertion_order_the_real_engine_uses`] answers the question
//!   `Records::ties`'s doc comment names as unmeasurable: inserted records
//!   that collide on a duplicate-permitting key come back from this crate's
//!   own reader in file-position order (insertion order, by construction --
//!   `Block::reindex` writes the chain that way). Whether the genuine engine
//!   agrees was never checked against a file that holds any such records,
//!   because none MajorMUD ships does. This inserts some.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use btrieve_engine::{Engine, Request};
use mbbs::abi::Wg16;
use mbbs::btrieve::{Btrieve, Geometry};
use mbbs::{Config, Heap};
use mbbs16::Machine;

const B_OPEN: u16 = 0;
const B_CLOSE: u16 = 1;
const B_INSERT: u16 = 2;
const B_GET_EQUAL: u16 = 5;
const B_GET_NEXT: u16 = 6;
const B_GET_FIRST: u16 = 12;

const MODE_NORMAL: i8 = 0;
const MODE_READ_ONLY: i8 = -2;

fn data_dir() -> Option<PathBuf> {
    let at = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tmp");
    at.is_dir().then_some(at)
}

fn wine_on_path() -> bool {
    Command::new("wine")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn btrieve_work_dir() -> PathBuf {
    let prefix = std::env::var("BTRIEVE_WINEPREFIX")
        .unwrap_or_else(|_| format!("{}/.btrieve-wine", std::env::var("HOME").unwrap()));
    Path::new(&prefix).join("drive_c/btrieve")
}

/// Stage `src` under a fresh, per-process name in the wine work dir. The
/// Microkernel caches pages by path and outlives its clients -- a name reused
/// across runs is served from whichever file it cached first.
fn stage(src: &Path, tag: &str) -> (PathBuf, String) {
    let name = format!("{}{tag}", std::process::id());
    let dest = btrieve_work_dir().join(&name);
    std::fs::copy(src, &dest).expect("copying the fixture into the wine work dir");
    (dest, name)
}

fn dos_path(name: &str) -> Vec<u8> {
    let mut p = format!("C:\\btrieve\\{name}").into_bytes();
    p.push(0);
    p
}

/// Open, read `len` bytes back through `B_STAT`/`B_GET_FIRST`/`B_GET_NEXT` on
/// key 0, and close. Returns the records in key order, as bytes.
fn engine_walk_key0(engine: &mut Engine, name: &str) -> Vec<Vec<u8>> {
    let open = engine
        .call(Request {
            op: B_OPEN,
            posblk: [0u8; 128],
            datalen: 0,
            databuf: Vec::new(),
            keylen: dos_path(name).len() as u8,
            keynum: MODE_READ_ONLY,
            keybuf: dos_path(name),
        })
        .expect("B_OPEN");
    assert_eq!(open.status, 0, "opening {name} for the walk should succeed");

    let mut posblk = open.posblk;
    let mut out = Vec::new();
    let mut resp = engine
        .call(Request {
            op: B_GET_FIRST,
            posblk,
            datalen: 32768,
            databuf: Vec::new(),
            keylen: 255,
            keynum: 0,
            keybuf: vec![0u8; 255],
        })
        .expect("B_GET_FIRST");
    while resp.status == 0 {
        out.push(resp.databuf.clone());
        posblk = resp.posblk;
        resp = engine
            .call(Request {
                op: B_GET_NEXT,
                posblk,
                datalen: 32768,
                databuf: Vec::new(),
                keylen: 255,
                keynum: 0,
                keybuf: vec![0u8; 255],
            })
            .expect("B_GET_NEXT");
    }
    assert_eq!(resp.status, 9, "the walk should end at end-of-file");
    out
}

/// `reindex` changes nothing about the record set (`forge.rs`'s C1 variant),
/// so this crate's own reader and the real engine should see the same
/// records, by content, in the same key-0 order.
#[test]
#[ignore = "needs MajorMUD's data files in tmp/, and wine"]
fn wccspels_reindexed_matches_our_own_walk_and_the_real_engine() {
    let Some(data) = data_dir() else {
        eprintln!("skipped: tmp/ is not present in this checkout");
        return;
    };
    if !wine_on_path() {
        eprintln!("skipped: wine is not on PATH");
        return;
    }

    let name = "WCCSPELS.VIR";
    let (staged, staged_name) = stage(&data.join(name), name);

    // Our own reader, over the SAME reindexed bytes the engine will read.
    let mut machine = Machine::new().expect("a 16-bit machine");
    let mut heap = Heap::<Wg16>::new(Config::default());
    let mut btrieve = Btrieve::default();
    let geometry = Geometry::read(name, &staged).expect("WCCSPELS.VIR's geometry reads");
    let at = btrieve
        .open(machine.mem_mut(), &mut heap, name, &staged, geometry, geometry.reclen)
        .expect("opening WCCSPELS.VIR");
    let block = btrieve.block_mut(at).unwrap_or_else(|e| panic!("{e}"));
    let ours: Vec<Vec<u8>> = {
        let records = block.records().unwrap_or_else(|e| panic!("{e}"));
        let len = records.ordered_len(0).expect("key 0 exists");
        (0..len)
            .map(|n| records.ordered(0, n).expect("in range").bytes.clone())
            .collect()
    };
    block.reindex().unwrap_or_else(|e| panic!("{e}"));
    btrieve
        .close(machine.mem_mut(), &mut heap, at)
        .unwrap_or_else(|e| panic!("{e}"));

    let mut engine = Engine::spawn().expect("spawning btrvprobe serve");
    let theirs = engine_walk_key0(&mut engine, &staged_name);

    assert_eq!(ours.len(), theirs.len(), "record count should agree");
    for (n, (o, t)) in ours.iter().zip(theirs.iter()).enumerate() {
        assert_eq!(o, t, "record {n}: our reader and the engine disagree on its bytes");
    }
}

/// Build a 12-byte-record file with one duplicate-permitting key -- the same
/// shape `tools/btrieve-oracle/btrvprobe.c`'s `cmd_create` builds, and the
/// same one `crates/mbbs/tests/forge.rs`'s doc comment on
/// `insert_duplicate_users` uses -- and insert `n` records that all collide,
/// tagging each with its insertion index at byte 4 so the walk order can be
/// read back unambiguously.
fn colliding_records(n: u8) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| {
            let mut record = vec![0u8; 12];
            record[4] = i; // the tag; key (bytes 0..4) stays zero on every record
            record
        })
        .collect()
}

/// Answers the question `Records::ties`'s doc comment names as unmeasurable:
/// is a duplicate chain's walk order the insertion order this crate's own
/// writer assumes, or something else?
#[test]
#[ignore = "needs wine and the btrvprobe fixture"]
fn duplicate_insertion_order_the_real_engine_uses() {
    if !wine_on_path() {
        eprintln!("skipped: wine is not on PATH");
        return;
    }

    let records = colliding_records(5);

    // The engine's order: create the file, insert in order, close (flushing
    // the chain), reopen read-only, and read the tag byte back in walk order.
    let mut engine = Engine::spawn().expect("spawning btrvprobe serve");
    let name = format!("{}DUPORDER.DAT", std::process::id());
    let create = engine
        .call(Request {
            op: 14, // B_CREATE, tools/btrieve-oracle/btrvprobe.c:42-51
            posblk: [0u8; 128],
            datalen: create_file_spec().len() as u32,
            databuf: create_file_spec(),
            keylen: dos_path(&name).len() as u8,
            keynum: 0, // fail if it already exists
            keybuf: dos_path(&name),
        })
        .expect("B_CREATE");
    assert_eq!(create.status, 0, "creating the duplicate-key fixture should succeed");

    let open = engine
        .call(Request {
            op: B_OPEN,
            posblk: [0u8; 128],
            datalen: 0,
            databuf: Vec::new(),
            keylen: dos_path(&name).len() as u8,
            keynum: MODE_NORMAL,
            keybuf: dos_path(&name),
        })
        .expect("B_OPEN");
    assert_eq!(open.status, 0, "opening the freshly created fixture should succeed");
    let mut posblk = open.posblk;
    for record in &records {
        let resp = engine
            .call(Request {
                op: B_INSERT,
                posblk,
                datalen: record.len() as u32,
                databuf: record.clone(),
                keylen: 255,
                keynum: 0,
                keybuf: vec![0u8; 255],
            })
            .expect("B_INSERT");
        assert_eq!(resp.status, 0, "every insert should succeed -- they all collide on purpose");
        posblk = resp.posblk;
    }
    let close = engine
        .call(Request { op: B_CLOSE, posblk, datalen: 0, databuf: Vec::new(), keylen: 0, keynum: 0, keybuf: Vec::new() })
        .expect("B_CLOSE");
    assert_eq!(close.status, 0);

    let theirs: Vec<u8> = engine_walk_key0(&mut engine, &name)
        .into_iter()
        .map(|record| record[4])
        .collect();

    // This crate's own order, over the identical insert sequence: file
    // position order, by construction (Block::reindex writes the chain that
    // way -- see Records::ties's doc comment).
    let ours: Vec<u8> = (0..records.len() as u8).collect();

    eprintln!("our order (file-position / insertion order, by construction): {ours:?}");
    eprintln!("the real engine's chain-walk order:                           {theirs:?}");

    let (mut a, mut b) = (ours.clone(), theirs.clone());
    a.sort_unstable();
    b.sort_unstable();
    assert_eq!(a, b, "both readers should see the same 5 records, order aside");

    if ours == theirs {
        eprintln!("FINDING: the engine's duplicate-chain walk is insertion order -- matches what this crate assumes.");
    } else {
        eprintln!("FINDING: the engine's duplicate-chain walk is NOT insertion order -- Records::ties's assumption does not hold.");
    }
}

/// Oracle validation for `stpbtvl`'s `Cursor::Ordered` arm
/// (`shims/btrieve.rs` ~1026-1074, corrected in Task 12): a keyed Get leaves
/// the file positioned on a *duplicate* key's chain, and a following step
/// (`stpbtvl`, "no key at all", opt 24 == `B_GET_NEXT`'s step-family
/// counterpart) must walk on to the next record in that same chain -- not
/// refuse the call as a module bug, which an earlier version of this arm did.
///
/// `shims::btrieve::stpbtvl` itself is `pub(crate)` in `mbbs`, so it cannot be
/// named from this integration test crate -- only `mbbs::btrieve`'s public
/// `Btrieve`/`Block`/`Records` types are reachable here. This drives the real
/// engine through exactly the sequence a module makes (`B_GET_EQUAL` then
/// `B_GET_NEXT`) and, on the same file, reproduces the *exact* sequence of
/// public calls `stpbtvl`'s own body makes for that case: the keyed find is
/// `Records::seek`/`Records::matches` (`shims/btrieve.rs` `qrybtv`,
/// ~728-729), and the step is `Records::ordered` -> `Records::find_physical`
/// -> one physical slot forward (`shims/btrieve.rs` ~1046-1063, word for
/// word). If those two independent readers -- the genuine Btrieve engine
/// walking its own on-disk chain, and this crate's own reader replaying
/// `stpbtvl`'s computation -- land on the same record, the fix's own
/// reasoning ("real Btrieve keeps one physical cursor regardless of how it
/// was reached") is oracle-backed rather than merely plausible.
///
/// This is exactly the character-creation duplicate-name shape the fix's own
/// doc comment names: a real `WCCUSERS.DAT` (`tests/forge.rs`'s
/// `insert_duplicate_users` builds the same shape at larger scale, for the
/// same reason -- key 2, experience, is the one duplicate-permitting key
/// MajorMUD ships and a fresh character always collides on it), written
/// directly by this crate's own `Block::insert`/`reindex` rather than through
/// the live wire engine.
///
/// **Why not build the fixture through `B_CREATE`/`B_INSERT` over the wire,
/// the way `duplicate_insertion_order_the_real_engine_uses` does?** Tried
/// first, and measured to not work for a test that also needs its own
/// independent reader on the same bytes: `tools/btrieve-oracle/`'s
/// `W32MKDE.EXE AUTOSTART` is a persistent process that outlives every
/// individual `btrvprobe.exe serve` client (`ps aux` shows one running since
/// this environment's Btrieve prefix was first used), and it never wrote the
/// on-disk record count back for a file this test created and inserted into
/// over the wire -- not after `B_CLOSE`, not after an explicit `B_STOP`, not
/// after the whole `serve` process was killed, not after ten seconds' wait.
/// Every file this crate created that way still reads a record count of 0 at
/// `at::RECORDS_HIGH`/`RECORDS_LOW`, even ones from runs minutes old. The
/// live engine's own subsequent reads (`B_STAT`, `B_GET_FIRST`/`B_GET_NEXT`)
/// still see the record correctly -- they are served from the Microkernel's
/// cache, not the disk -- which is exactly why
/// `duplicate_insertion_order_the_real_engine_uses` (which never reads the
/// raw file) still passes. This test needs the raw file, so it writes the
/// raw file itself and only asks the wine engine to *read* it, which has no
/// such problem: `wccspels_reindexed_matches_our_own_walk_and_the_real_engine`
/// above reads a file this process never wrote a byte of, over the same
/// engine, correctly.
#[test]
#[ignore = "needs wine and MajorMUD's data files in tmp/"]
fn keyed_get_then_step_matches_the_real_engines_duplicate_chain_walk() {
    let Some(data) = data_dir() else {
        eprintln!("skipped: tmp/ is not present in this checkout");
        return;
    };
    if !wine_on_path() {
        eprintln!("skipped: wine is not on PATH");
        return;
    }

    let name = "WCCUSERS.DAT";
    let (staged, staged_name) = stage(&data.join(name), name);

    // This crate's own writer: three records that collide on key 2
    // (experience -- the one duplicate-permitting key `WCCUSERS.DAT` has,
    // per `tests/forge.rs`'s `insert_duplicate_users`), distinct on keys 0
    // and 1 (name, owner -- both forbid duplicates).
    let mut machine = Machine::new().expect("a 16-bit machine");
    let mut heap = Heap::<Wg16>::new(Config::default());
    let mut btrieve = Btrieve::default();
    let geometry = Geometry::read(name, &staged).expect("WCCUSERS.DAT's geometry reads");
    let at = btrieve
        .open(machine.mem_mut(), &mut heap, name, &staged, geometry, geometry.reclen)
        .expect("opening WCCUSERS.DAT");
    let block = btrieve.block_mut(at).unwrap_or_else(|e| panic!("{e}"));

    let starting = block.records().unwrap_or_else(|e| panic!("{e}")).len();
    assert_eq!(starting, 0, "a freshly staged WCCUSERS.DAT should hold no records yet");

    let keys = block.keys().to_vec();
    let [key0, key1, key2] = keys.as_slice() else {
        panic!("WCCUSERS.DAT has {} keys, not the 3 this test assumes", keys.len());
    };
    let name_seg = match key0.segments.as_slice() {
        [only] => *only,
        other => panic!("key 0 has {} segments, not 1", other.len()),
    };
    let owner_seg = match key1.segments.as_slice() {
        [only] => *only,
        other => panic!("key 1 has {} segments, not 1", other.len()),
    };
    let exp_seg = match key2.segments.as_slice() {
        [only] => *only,
        other => panic!("key 2 has {} segments, not 1", other.len()),
    };
    assert!(key2.duplicates, "key 2 (experience) should permit duplicates");

    let reclen = usize::from(block.geometry().reclen);
    let tag_count = 3u8;
    for tag in 0..tag_count {
        let mut record = vec![0u8; reclen];
        let name_bytes = format!("Diff{tag:04}").into_bytes();
        let name_at = usize::from(name_seg.offset);
        record[name_at..name_at + name_bytes.len()].copy_from_slice(&name_bytes);

        let owner_bytes = format!("Diffowner{tag:04}").into_bytes();
        let owner_at = usize::from(owner_seg.offset);
        record[owner_at..owner_at + owner_bytes.len()].copy_from_slice(&owner_bytes);

        // Every record gets the SAME experience value -- 0 -- so they all
        // collide on key 2.
        let exp_at = usize::from(exp_seg.offset);
        let exp_len = usize::from(exp_seg.length);
        record[exp_at..exp_at + exp_len].fill(0);

        block.insert(&record).unwrap_or_else(|e| panic!("{e}"));
    }
    block.reindex().unwrap_or_else(|e| panic!("{e}"));

    // `qrybtv`'s keyed find (`shims/btrieve.rs` ~728-729), and `stpbtvl`'s
    // `Cursor::Ordered` arm for a GetNext-family step (opt 24): the ordered
    // position resolves to a physical record, and the step moves one
    // physical slot forward. Read here, from the live in-memory `Records`,
    // before `close` -- the same data `reindex` just wrote to disk.
    let exp_value = vec![0u8; usize::from(exp_seg.length)];
    let records = block.records().unwrap_or_else(|e| panic!("{e}"));
    let found_at = records.seek(&keys, 2, &exp_value);
    assert!(
        records.matches(&keys, 2, found_at, &exp_value),
        "our reader should find the colliding experience value on key 2"
    );
    let physical = records
        .ordered(2, found_at)
        .and_then(|record| records.find_physical(record.position))
        .expect("the ordered position resolves to a physical record");
    let next_physical = physical + 1;
    assert!(next_physical < records.len(), "there is another colliding record to step to");
    let ours_next_name = {
        let bytes = &records.physical(next_physical).expect("in range").bytes;
        let name_at = usize::from(name_seg.offset);
        String::from_utf8_lossy(&bytes[name_at..name_at + 8]).into_owned()
    };

    btrieve
        .close(machine.mem_mut(), &mut heap, at)
        .unwrap_or_else(|e| panic!("{e}"));

    // The real engine's own answer, over the identical bytes this process
    // just wrote and closed: `B_GET_EQUAL` on key 2's colliding value
    // positions the cursor on the chain, then `B_GET_NEXT` steps to the next
    // record in it.
    let mut engine = Engine::spawn().expect("spawning btrvprobe serve");
    let open = engine
        .call(Request {
            op: B_OPEN,
            posblk: [0u8; 128],
            datalen: 0,
            databuf: Vec::new(),
            keylen: dos_path(&staged_name).len() as u8,
            keynum: MODE_READ_ONLY,
            keybuf: dos_path(&staged_name),
        })
        .expect("B_OPEN");
    assert_eq!(open.status, 0, "opening the fixture read-only should succeed");
    let geteq = engine
        .call(Request {
            op: B_GET_EQUAL,
            posblk: open.posblk,
            datalen: 32768,
            databuf: Vec::new(),
            keylen: exp_seg.length as u8,
            keynum: 2,
            keybuf: exp_value.clone(),
        })
        .expect("B_GET_EQUAL");
    assert_eq!(geteq.status, 0, "the colliding experience value should be found on key 2");
    let getnext = engine
        .call(Request {
            op: B_GET_NEXT,
            posblk: geteq.posblk,
            datalen: 32768,
            databuf: Vec::new(),
            keylen: 255,
            keynum: 2,
            keybuf: vec![0u8; 255],
        })
        .expect("B_GET_NEXT");
    assert_eq!(getnext.status, 0, "stepping within the colliding chain should find the next record");
    let name_at = usize::from(name_seg.offset);
    let engine_next_name =
        String::from_utf8_lossy(&getnext.databuf[name_at..name_at + 8]).into_owned();

    eprintln!("real engine's GetEqual+GetNext landed on {engine_next_name:?}");
    eprintln!("our reader's seek+Cursor::Ordered step landed on {ours_next_name:?}");

    assert_eq!(
        ours_next_name, engine_next_name,
        "stpbtvl's Cursor::Ordered arm (resolve an ordered position to a physical slot, then \
         step by one physical slot) must land on the same record the real engine's own \
         GetEqual-then-GetNext does"
    );
}

/// `FileSpec` + one `KeySpec`: a 12-byte record, one 4-byte duplicate-
/// permitting key at position 1. Mirrors `tools/btrieve-oracle/btrvprobe.c`'s
/// `cmd_create`, which this reuses the shape of rather than re-deriving.
///
/// **Correction (Task 12, oracle-validating `stpbtvl`'s `Cursor::Ordered`
/// fix):** this buffer used to size itself for a 24-byte `KeySpec` and write
/// `ext_type` at that struct's byte 12. Neither matches
/// `tools/btrieve-oracle/btrvprobe.c:93-102`'s real `KeySpec`, which is 16
/// bytes (`position` WORD@0, `length` WORD@2, `flags` WORD@4, `approx_count`
/// DWORD@6, `ext_type` BYTE@10, `null_value` BYTE@11, `reserved[2]`@12-13,
/// `number` BYTE@14, `acs_number` BYTE@15) -- byte 12 is `reserved`, which
/// `cmd_create` never reads. The old buffer's `ext_type` write landed on a
/// byte the engine ignores, so every file this built came back with
/// `ext_type` still zero: `keys::parse` read it as `Kind::Text`, not
/// `Kind::Unsigned`, even though the request asked for `KT_UNSIGNED_BINARY`.
/// Measured directly with a hex dump of a file this helper created
/// (`xxd`, offset `0x12c` == the key definition's own `BASE + at::EXTENDED`
/// in `keys.rs`, which read `00` before this fix and `0e` after) -- not
/// inferred from any test's assertions, because none of them happened to
/// check: `duplicate_insertion_order_the_real_engine_uses` only ever reads
/// file/physical order, which does not touch the key's kind at all, and
/// `keyed_get_then_step_matches_the_real_engines_duplicate_chain_walk`
/// (found while chasing this exact bug) ended up building its own fixture a
/// different way -- directly through `Block::insert`/`reindex`, over a real
/// `WCCUSERS.DAT`, rather than through this helper -- once it turned out
/// this crate's own writer can build a correctly-typed key in one step where
/// getting `B_CREATE` to do it over the wire took two fixes. So no test in
/// this file currently exercises the corrected `ext_type` byte through an
/// assertion; the fix stands on the hex dump above and on matching
/// `cmd_create` byte-for-byte, for whatever next uses this helper for a
/// keyed search.
///
/// `flags = 0x0141` is bit 0 (duplicates permitted) + bit 6 (descending) +
/// bit 8 (use `ext_type`) -- `cmd_create`'s own comment on the matching line,
/// not "modifiable" as an earlier version of this doc comment guessed.
fn create_file_spec() -> Vec<u8> {
    let mut data = vec![0u8; 16 + 16]; // sizeof(FileSpec) + sizeof(KeySpec)
    data[0..2].copy_from_slice(&12u16.to_le_bytes()); // reclen
    data[2..4].copy_from_slice(&512u16.to_le_bytes()); // pagesize
    data[4..6].copy_from_slice(&1u16.to_le_bytes()); // indexes_raw (1 key)
    // KeySpec at offset 16: position=1, length=4, flags=0x0141 (dup|descending|exttype),
    // ext_type=14 (KT_UNSIGNED_BINARY) at the KeySpec's own byte 10.
    data[16..18].copy_from_slice(&1u16.to_le_bytes());
    data[18..20].copy_from_slice(&4u16.to_le_bytes());
    data[20..22].copy_from_slice(&0x0141u16.to_le_bytes());
    data[16 + 10] = 14;
    data
}
