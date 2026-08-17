//! The engine agrees with itself: open a real MajorMUD file over the RPC,
//! stat it, and walk it end to end, checking every number against what
//! `crates/mbbs/tests/btrieve.rs`'s `FILES` table already carries for
//! `WCCSPELS.VIR` -- reading it here by a third, independent path.
//!
//! Skips, loudly, when `tmp/WCCSPELS.VIR` is absent or `wine` is not on
//! PATH, following the house pattern in `crates/mbbs-machine/tests/m16_wccmmud.rs`.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use btrieve_oracle::{Engine, Request, Response};

/// Btrieve operation codes, `tools/btrieve-oracle/btrvprobe.c:42-51`.
const B_OPEN: u16 = 0;
const B_CLOSE: u16 = 1;
const B_INSERT: u16 = 2;
const B_GET_NEXT: u16 = 6;
const B_GET_FIRST: u16 = 12;
const B_STAT: u16 = 15;

const MODE_NORMAL: i8 = 0;
const MODE_READ_ONLY: i8 = -2;

fn wccspels_path() -> Option<PathBuf> {
    // The crate lives two directories below the repository root.
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tmp/WCCSPELS.VIR");
    path.exists().then_some(path)
}

fn wccusers_vir_path() -> Option<PathBuf> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tmp/WCCUSERS.VIR");
    path.exists().then_some(path)
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

/// `datalen` is documented as the byte count the engine actually
/// transferred; `databuf`'s own length comes off the wire separately. A
/// correct server keeps the two in agreement on every reply.
fn assert_consistent(what: &str, resp: &Response) {
    assert_eq!(
        resp.datalen as usize,
        resp.databuf.len(),
        "{what}: datalen ({}) should match the bytes actually returned ({})",
        resp.datalen,
        resp.databuf.len()
    );
}

#[test]
fn the_engine_agrees_with_itself_on_wccspels() {
    let Some(src) = wccspels_path() else {
        eprintln!("skipped: tmp/WCCSPELS.VIR is not present in this checkout");
        return;
    };
    if !wine_on_path() {
        eprintln!("skipped: wine is not on PATH");
        return;
    }

    // Fresh name: the Microkernel caches pages by path and outlives its
    // clients, so two different files under one name would be served from
    // whichever's pages it cached first.
    let name = format!("{}WCCSPELS.VIR", std::process::id());
    let dest = btrieve_work_dir().join(&name);
    std::fs::copy(&src, &dest).expect("copying WCCSPELS.VIR into the wine work dir");

    let mut engine = Engine::spawn().expect("spawning btrvprobe serve");

    // B_OPEN takes the filename in the key buffer, not the data buffer --
    // see open_file() in tools/btrieve-oracle/btrvprobe.c.
    let mut keybuf = format!(r"C:\btrieve\{name}").into_bytes();
    keybuf.push(0);
    let open = engine
        .call(Request {
            op: B_OPEN,
            posblk: [0u8; 128],
            datalen: 0,
            databuf: Vec::new(),
            keylen: keybuf.len() as u8,
            keynum: MODE_READ_ONLY,
            keybuf,
        })
        .expect("B_OPEN call");
    assert_eq!(open.status, 0, "B_OPEN should succeed");
    assert_consistent("B_OPEN", &open);

    let stat = engine
        .call(Request {
            op: B_STAT,
            posblk: open.posblk,
            datalen: 32768,
            databuf: Vec::new(),
            keylen: 255,
            keynum: -1,
            keybuf: vec![0u8; 255],
        })
        .expect("B_STAT call");
    assert_eq!(stat.status, 0, "B_STAT should succeed");
    assert_consistent("B_STAT", &stat);

    // FileSpec layout, tools/btrieve-oracle/btrvprobe.c:73-88 (packed, no
    // padding): reclen at 0, pagesize at 2, records at 6.
    let reclen = u16::from_le_bytes(stat.databuf[0..2].try_into().unwrap());
    let pagesize = u16::from_le_bytes(stat.databuf[2..4].try_into().unwrap());
    let records = u32::from_le_bytes(stat.databuf[6..10].try_into().unwrap());
    assert_eq!(reclen, 253, "WCCSPELS.VIR's record length");
    assert_eq!(pagesize, 512, "WCCSPELS.VIR's page size");
    assert_eq!(records, 1379, "WCCSPELS.VIR's record count");

    // Walk the one key this file has (key 0) from first to end of file,
    // carrying posblk forward call to call -- this crate's whole point.
    let mut posblk = stat.posblk;
    let mut count = 0u32;
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
        .expect("B_GET_FIRST call");

    // Bounded rather than `while resp.status == 0`: a broken posblk
    // hand-off could make this loop never advance, and a bound turns that
    // into a clean assertion failure instead of a hang.
    for _ in 0..(records + 10) {
        if resp.status != 0 {
            break;
        }
        assert_consistent("B_GET_NEXT", &resp);
        assert_eq!(resp.datalen, 253, "every WCCSPELS.VIR record is 253 bytes");
        count += 1;
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
            .expect("B_GET_NEXT call");
    }

    assert_eq!(resp.status, 9, "the walk should end at end-of-file, not stall or error");
    assert_eq!(count, 1379, "the walk should visit every record WCCSPELS.VIR has");
}

/// Settles the question `docs/plans/2026-08-09-btrieve-duplicate-writes.md`
/// left open: `WCCUSERS.VIR`'s key 2 (experience) descriptor names a chain
/// offset of 2034 against a physical record length of 2006, which does not
/// fit -- this host refuses to write a chain there. Does the *engine* care?
///
/// Inserts three records that collide on key 2 (all experience 0) and reads
/// the raw bytes back. This is a measurement, not a correctness check: the
/// answer decides what happens next, so nothing here asserts what that
/// answer must be. See the doc above for what came out of it.
#[test]
fn wccusers_vir_chain_offset_measurement() {
    let Some(src) = wccusers_vir_path() else {
        eprintln!("skipped: tmp/WCCUSERS.VIR is not present in this checkout");
        return;
    };
    if !wine_on_path() {
        eprintln!("skipped: wine is not on PATH");
        return;
    }

    let name = format!("{}WCCUSERS.VIR", std::process::id());
    let dest = btrieve_work_dir().join(&name);
    std::fs::copy(&src, &dest).expect("copying WCCUSERS.VIR into the wine work dir");

    let mut engine = Engine::spawn().expect("spawning btrvprobe serve");

    let mut keybuf = format!(r"C:\btrieve\{name}").into_bytes();
    keybuf.push(0);
    let open = engine
        .call(Request {
            op: B_OPEN,
            posblk: [0u8; 128],
            datalen: 0,
            databuf: Vec::new(),
            keylen: keybuf.len() as u8,
            keynum: MODE_NORMAL,
            keybuf,
        })
        .expect("B_OPEN call");
    assert_eq!(open.status, 0, "opening WCCUSERS.VIR (normal mode) should succeed");

    // Three records, each with a distinct 30-byte name at offset 0 (key 0 in
    // this file, same as the .DAT's) and a distinct 11-byte value at offset
    // 30 (key 1 in THIS file -- measured, not the 30-byte owner field the
    // .DAT carries there); experience 0 at offset 60 collides on key 2,
    // which is what names the disputed chain offset.
    //
    // The 41-byte concatenation of name and value, not the 30-byte name
    // alone, is what gets searched for in the raw file afterward: the name
    // alone also appears in key 0's own index page (30-byte key + 8-byte
    // pointer entries -- measured on a first version of this test, which
    // found index bytes 38 apart and reported them as the record). Name
    // immediately followed by ITS OWN value is specific to the data record.
    let markers: Vec<[u8; 41]> = (0..3)
        .map(|i| {
            let name = format!("{:0>30}", format!("CHAINPROBE{i}"));
            let value = format!("{i:0>11}");
            let mut marker = [0u8; 41];
            marker[0..30].copy_from_slice(name.as_bytes());
            marker[30..41].copy_from_slice(value.as_bytes());
            marker
        })
        .collect();

    let mut posblk = open.posblk;
    for (i, marker) in markers.iter().enumerate() {
        let mut record = vec![0u8; 1998];
        record[0..41].copy_from_slice(marker);
        // experience (4 bytes) at offset 60 stays zero -- the collision.

        let resp = engine
            .call(Request {
                op: B_INSERT,
                posblk,
                datalen: record.len() as u32,
                databuf: record,
                keylen: 255,
                keynum: 0,
                keybuf: vec![0u8; 255],
            })
            .expect("B_INSERT call");
        eprintln!(
            "insert {i} name={:?}: status {}",
            String::from_utf8_lossy(marker),
            resp.status
        );
        posblk = resp.posblk;
    }

    // Btrieve buffers writes; the raw file on disk does not reflect them
    // until the file is closed.
    let close = engine
        .call(Request {
            op: B_CLOSE,
            posblk,
            datalen: 0,
            databuf: Vec::new(),
            keylen: 0,
            keynum: 0,
            keybuf: Vec::new(),
        })
        .expect("B_CLOSE call");
    assert_eq!(close.status, 0, "closing WCCUSERS.VIR should succeed");

    let raw = std::fs::read(&dest).expect("reading WCCUSERS.VIR back");
    for (i, marker) in markers.iter().enumerate() {
        let Some(slot) = raw.windows(marker.len()).position(|w| w == marker) else {
            eprintln!("record {i}: not found in the file -- its insert did not land");
            continue;
        };
        let at = |off: usize| raw.get(slot + off..slot + off + 8);
        eprintln!(
            "record {i} at file offset {slot}: bytes@reclen(1998)={:02x?} bytes@2034={:02x?}",
            at(1998),
            at(2034)
        );
    }
}
