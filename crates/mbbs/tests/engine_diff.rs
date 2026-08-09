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
use mbbs::btrieve::{Btrieve, Geometry};
use mbbs::{Config, Heap};
use mbbs16::Machine;

const B_OPEN: u16 = 0;
const B_CLOSE: u16 = 1;
const B_INSERT: u16 = 2;
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
    let mut heap = Heap::new(Config::default());
    let mut btrieve = Btrieve::default();
    let geometry = Geometry::read(name, &staged).expect("WCCSPELS.VIR's geometry reads");
    let at = btrieve
        .open(&mut machine, &mut heap, name, &staged, geometry, geometry.reclen)
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
        .close(&mut machine, &mut heap, at)
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

/// `FileSpec` + one `KeySpec`: a 12-byte record, one 4-byte duplicate-
/// permitting key at position 1. Mirrors `tools/btrieve-oracle/btrvprobe.c`'s
/// `cmd_create`, which this reuses the shape of rather than re-deriving.
fn create_file_spec() -> Vec<u8> {
    let mut data = vec![0u8; 16 + 24]; // sizeof(FileSpec) + sizeof(KeySpec)
    data[0..2].copy_from_slice(&12u16.to_le_bytes()); // reclen
    data[2..4].copy_from_slice(&512u16.to_le_bytes()); // pagesize
    data[4..6].copy_from_slice(&1u16.to_le_bytes()); // indexes_raw (1 key)
    // KeySpec at offset 16: position=1, length=4, flags=0x0141 (dup|modifiable|exttype),
    // ext_type=14 (KT_UNSIGNED_BINARY).
    data[16..18].copy_from_slice(&1u16.to_le_bytes());
    data[18..20].copy_from_slice(&4u16.to_le_bytes());
    data[20..22].copy_from_slice(&0x0141u16.to_le_bytes());
    data[16 + 12] = 14;
    data
}
