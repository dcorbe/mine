//! The engine agrees with itself: open a real MajorMUD file over the RPC,
//! stat it, and walk it end to end, checking every number against what
//! `crates/mbbs/tests/btrieve.rs`'s `FILES` table already carries for
//! `WCCSPELS.VIR` -- reading it here by a third, independent path.
//!
//! Skips, loudly, when `tmp/WCCSPELS.VIR` is absent or `wine` is not on
//! PATH, following the house pattern in `crates/mbbs16/tests/wccmmud.rs`.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use btrieve_engine::{Engine, Request, Response};

/// Btrieve operation codes, `tools/btrieve-oracle/btrvprobe.c:42-51`.
const B_OPEN: u16 = 0;
const B_GET_NEXT: u16 = 6;
const B_GET_FIRST: u16 = 12;
const B_STAT: u16 = 15;

const MODE_READ_ONLY: i8 = -2;

fn wccspels_path() -> Option<PathBuf> {
    // The crate lives two directories below the repository root.
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tmp/WCCSPELS.VIR");
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
