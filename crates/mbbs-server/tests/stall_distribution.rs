//! Measures `Host::cycle`'s "N seconds of timers in one pass" stalls, over a
//! real `TcpStream` against the live board's own real data -- the same shape
//! the owner feels as input latency.
//!
//! This is a measurement harness, not a correctness test: it prints what it
//! found (`--nocapture`) and does not assert a bound on the numbers. It was
//! built to compare `--passes` values against each other, on the hypothesis
//! that shrinking `--passes` well below `--polls-per-wake` would make
//! `Host::cycle` return to the driver loop more often and so bound how long
//! a keystroke can sit undrained. **The measurement falsified that
//! hypothesis** -- three `--passes` values (1024, 16, 1) produced the same
//! stall count, because `Host::cycle` stamps its own catch-up clock every
//! single pass regardless of how many passes one call is allowed, so the
//! stall is the cost of *one* pass, not an accumulation `--passes` could cap.
//! See `docs/2026-08-14-maxpol-throttle.md` for the full measurement, the
//! reasoning, and why the real fix does not live in `crates/mbbs-server`.
//!
//! Kept as the harness for verifying whichever real fix lands next (inside
//! `Host::cycle` or the save-buffer sweep's own per-firing cost) against
//! real, live-board-shaped data over a real socket -- the checked-in test
//! fixtures elsewhere in this repo have never reproduced this class of
//! stall.
//!
//! A straight adaptation of `two_players.rs`'s board-copying and login
//! helpers (duplicated rather than shared -- each file under `tests/` is its
//! own binary crate, so there is no third place to put them without adding a
//! library-shaped dependency this measurement does not otherwise need).
//!
//! ```text
//! cargo test -p mbbs-server --release --test stall_distribution -- --ignored --nocapture --test-threads=1 <name>
//! ```

use std::path::{Path, PathBuf};
use std::time::Duration;

use mbbs::abi::Wg16;
use mbbs_machine::m16::Machine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;

use mbbs_server::conn::{self, default_keys};
use mbbs_server::host::Boot;
use mbbs_server::pool::MachineId;

fn repo(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(rel)
}

fn wccmmud() -> Option<Vec<u8>> {
    match std::fs::read(repo("re/WCCMMUD.DLL")) {
        Ok(file) => Some(file),
        Err(_) => {
            eprintln!("skipped: re/WCCMMUD.DLL is not present in this checkout");
            None
        }
    }
}

/// A straight copy of `two_players.rs`'s `characters()` -- see that file's
/// doc comment. `None` skips the measurement rather than failing it: the
/// live board's roster is one person's and never committed.
fn characters() -> Option<Vec<(String, Vec<u8>)>> {
    let home = std::env::var("HOME").ok()?;
    let db = PathBuf::from(home).join("mbbsemu/wccmmud/WCCUSERS.DB");
    if !db.is_file() {
        eprintln!("skipped: {} is not present", db.display());
        return None;
    }

    let output = match std::process::Command::new("sqlite3")
        .arg(&db)
        .arg("SELECT key_0, hex(data) FROM data_t ORDER BY id;")
        .output()
    {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            eprintln!(
                "skipped: sqlite3 exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            return None;
        }
        Err(e) => {
            eprintln!("skipped: the sqlite3 binary is not on PATH: {e}");
            return None;
        }
    };

    let text = String::from_utf8(output.stdout).expect("sqlite3 prints ASCII");
    let rows: Vec<(String, Vec<u8>)> = text
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (name, hex) = line.split_once('|').expect("key_0|hex(data)");
            let bytes = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("a hex digit pair"))
                .collect();
            (name.to_owned(), bytes)
        })
        .collect();
    if rows.is_empty() {
        eprintln!("skipped: the character roster is empty");
        return None;
    }
    Some(rows)
}

/// Serialises everything in this binary that touches the LDT -- see
/// `two_players.rs`'s `LDT` for the full rationale.
static LDT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Where [`copy_board`] reads from: `tmp/` by default, or a
/// pre-stabilised snapshot of it via `MBBS_STALL_TMP_SNAPSHOT`.
///
/// `tmp/` is the live board's own data directory, and the process on
/// 2424/2425 is actively writing several files in it (`WCCMP001.DAT` most of
/// all -- 44MB and growing, per the room-save sweep both idle-cost docs
/// describe) for as long as it runs. A plain `std::fs::copy` racing that
/// writer produces a torn, structurally inconsistent snapshot -- measured:
/// booting `re/WCCMMUD.DLL` against one hung ordinal 1 (init) at the same
/// address twice in a row (`module timed out at 0x008f:0x37bf`), which never
/// happens against a quiesced copy. `MBBS_STALL_TMP_SNAPSHOT` points at a
/// directory copied with a stability retry (stat-copy-stat, retry while the
/// size/mtime moved) instead, sidestepping the race without ever pausing or
/// touching the live process.
fn tmp_source() -> PathBuf {
    std::env::var_os("MBBS_STALL_TMP_SNAPSHOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo("tmp"))
}

/// A private copy of [`tmp_source`]'s files into `into`. Never `tmp/` itself,
/// and never a link -- see [`tmp_source`]'s own doc for why, and the
/// coordinator's instruction not to disturb the live board.
fn copy_board(into: &Path) -> PathBuf {
    for entry in std::fs::read_dir(tmp_source()).expect("the board source exists") {
        let entry = entry.expect("a directory entry");
        if entry.file_type().expect("a file type").is_file() {
            let _ = std::fs::copy(entry.path(), into.join(entry.file_name()));
        }
    }
    into.join("WCCUSERS.DAT")
}

/// A straight port of `two_players.rs`'s `populated_wccusers`: writes a fresh
/// `WCCUSERS.DAT` holding the live board's real characters, over a virgin
/// `.VIR` skeleton, so login takes the returning-player path.
fn populated_wccusers(scratch_name: &str) -> Option<PathBuf> {
    let characters = characters()?;

    let dir = mbbs::testing::scratch(scratch_name);
    let path = dir.join("WCCUSERS.DAT");
    std::fs::copy(repo("tmp/WCCUSERS.VIR"), &path).expect("the virgin file");

    let mut machine = Machine::new().expect("a 16-bit machine");
    let mut heap = mbbs::Heap::<mbbs::abi::Wg16>::new(mbbs::Config::default());
    let mut btrieve = mbbs::btrieve::Btrieve::default();
    let geometry =
        mbbs::btrieve::Geometry::read("WCCUSERS.DAT", &path).expect("the virgin file's geometry");
    let maxlen = geometry.reclen;

    let at = btrieve
        .open(machine.mem_mut(), &mut heap, "WCCUSERS.DAT", &path, geometry, maxlen)
        .expect("opens");
    let block = btrieve.block_mut(at).expect("the block just opened");
    for (name, bytes) in &characters {
        block
            .insert(bytes)
            .unwrap_or_else(|e| panic!("inserting {name}: {e}"));
    }

    Some(path)
}

const READ_TIMEOUT: Duration = Duration::from_secs(30);

async fn read_until(stream: &mut TcpStream, acc: &mut Vec<u8>, needle: &str) {
    loop {
        if String::from_utf8_lossy(acc).contains(needle) {
            return;
        }
        let mut buf = [0u8; 4096];
        let n = match tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf)).await {
            Ok(Ok(0)) => panic!(
                "socket closed before {needle:?} appeared; received so far: {:?}",
                String::from_utf8_lossy(acc)
            ),
            Ok(Ok(n)) => n,
            Ok(Err(e)) => panic!("read error waiting for {needle:?}: {e}"),
            Err(_) => panic!(
                "timed out after {READ_TIMEOUT:?} waiting for {needle:?}; received so far: {:?}",
                String::from_utf8_lossy(acc)
            ),
        };
        acc.extend_from_slice(&buf[..n]);
    }
}

/// Keeps `stream` drained for `budget`, discarding whatever arrives -- a
/// polling channel keeps drawing (status lines, ambient room text) and an
/// un-drained socket would eventually make `host::flush`'s `try_send` back
/// up. There is nothing to assert here: this is the idle-in-the-Realm window
/// the stall notes are measured across.
async fn idle_for(stream: &mut TcpStream, budget: Duration) {
    let deadline = Instant::now() + budget;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return;
        }
        let mut buf = [0u8; 4096];
        match tokio::time::timeout(remaining, stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return,
            Ok(Ok(_)) => {}
            Err(_) => return,
        }
    }
}

/// Logs one real character in (the connect banner alone is enough -- see the
/// module doc, this reproduces before login even finishes), then idles the
/// connection for `window` while the host thread's own notes -- including
/// "cycle: N seconds of timers in one pass" -- print to this process's
/// stderr via `eprintln!`. Run with `--nocapture` and grep the output; there
/// is nothing this function itself can assert, because the number it
/// produces is exactly the number under investigation.
///
/// `passes` is `Boot::passes`, the one variable across this file's three
/// `#[tokio::test]`s. `polls_per_wake` is left at the shipped default (512)
/// in every run.
async fn measure(scratch_name: &str, passes: usize, window: Duration) {
    let Some(_dll) = wccmmud() else { return };
    let Some(characters) = characters() else { return };
    let name = characters
        .iter()
        .find(|(n, _)| n == "rangerdan")
        .map(|(n, _)| n.clone())
        .unwrap_or_else(|| characters[0].0.clone());

    let _ldt = LDT.lock().await;

    let board = mbbs::testing::scratch(scratch_name);
    let users_path = copy_board(&board);
    let populated = populated_wccusers(&format!("{scratch_name}-wccusers"))
        .expect("characters() was already checked above");
    std::fs::copy(&populated, &users_path).expect("stage the populated WCCUSERS.DAT");

    let boot: Boot<Wg16> = Boot {
        machine: MachineId(0),
        // Not `Box::new(Machine::new)`: the live board's real, accumulated
        // `WCCMP001.DAT` (44MB) makes ordinal 1 (init) alone take longer than
        // `mbbs_machine::m16`'s 5-second default CPU watchdog budget --
        // measured, both in a debug and a release build, at two different
        // trip addresses (an overrun, not an infinite loop at a fixed spot).
        // That is a fact about booting fresh against real accumulated data,
        // orthogonal to this measurement's own subject and not something
        // this crate owns a fix for -- raised generously here so the
        // measurement can proceed at all.
        build: Box::new(|| {
            let mut machine = Machine::new()?;
            machine.set_budget(Duration::from_secs(120));
            Ok(machine)
        }),
        root: board,
        modules: vec![repo("re/WCCMMUD.DLL")],
        terms: mbbs::Terms::new(2),
        bturno: Some("10006172".to_owned()),
        polls_per_wake: 512,
        passes,
        clock_reads: None,
        wake_age_ms: None,
        dispatched_total: None,
        calls_total: None,
        survey: None,
    };

    let addr = conn::serve(
        boot,
        default_keys(),
        &[("127.0.0.1:0", mbbs_server::termcompat::Stack::modern)],
    )
    .await
    .expect("bind 127.0.0.1:0")[0];

    let mut a = TcpStream::connect(addr).await.expect("connect");
    let mut a_buf = Vec::new();
    read_until(&mut a, &mut a_buf, "Enter your user ID: ").await;

    a.write_all(format!("{name}\r").as_bytes())
        .await
        .expect("write userid");
    read_until(&mut a, &mut a_buf, &format!("{name}\r\n")).await;

    a.write_all(b"look\r").await.expect("write priming command");
    a.write_all(b"E\r").await.expect("write E");
    // Boot itself (module load + ordinal 1 init against the live board's real
    // data) can take several real seconds -- measured, see `Boot::build`'s
    // own comment above -- and `look`/`E` are only processed once the host
    // thread's serve loop starts draining `rx`, so this waits for the first
    // byte with a generous budget rather than a fixed short window, then
    // gives the module a further 3 idle seconds to finish settling into
    // whatever screen `E` reaches before the measurement window starts.
    let mut settle = Vec::new();
    {
        let mut buf = [0u8; 4096];
        match tokio::time::timeout(Duration::from_secs(60), a.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => settle.extend_from_slice(&buf[..n]),
            other => eprintln!("mbbs-server: stall_distribution: first read after E: {other:?}"),
        }
    }
    idle_for(&mut a, Duration::from_secs(3)).await;
    eprintln!(
        "mbbs-server: stall_distribution: screen reached after E: {:?}",
        String::from_utf8_lossy(&settle)
    );

    eprintln!(
        "mbbs-server: stall_distribution: passes={passes} window={window:?} idling begins now"
    );
    idle_for(&mut a, window).await;
    eprintln!("mbbs-server: stall_distribution: passes={passes} window={window:?} idling ends");
}

/// The shipped default: `--passes 1024`. Run this, `reduced_passes` and
/// `passes_of_one` back to back (same window) and grep each for `cycle: .*
/// seconds of timers in one pass` to compare stall counts -- measured at 9,
/// 9 and 12 respectively; see `docs/2026-08-14-maxpol-throttle.md`.
#[tokio::test]
#[ignore = "needs re/WCCMMUD.DLL, a live board's WCCUSERS.DB, and a real 60s window"]
async fn default_passes() {
    measure("mbbs-server-stall-default", 1024, Duration::from_secs(60)).await;
}

/// `--passes 16`, well below `--polls-per-wake`'s 512 -- the shape the
/// `maxpol` analogy predicted would help. It did not; see the module doc and
/// `docs/2026-08-14-maxpol-throttle.md`.
#[tokio::test]
#[ignore = "needs re/WCCMMUD.DLL, a live board's WCCUSERS.DB, and a real 60s window"]
async fn reduced_passes() {
    measure("mbbs-server-stall-reduced", 16, Duration::from_secs(60)).await;
}

/// The most extreme case `--passes` can express: one pass per `Host::cycle`
/// call. If a single pass's own dispatch is what costs multiple real
/// seconds -- the hypothesis `reduced_passes` at 16 could not rule out on
/// its own -- this should show it exactly as clearly as 1024 does, because
/// `tcklst` is stamped every pass regardless of `max`. If `passes` were
/// instead about *accumulation* across many passes in one burst, this is
/// where that theory would have to show its effect.
#[tokio::test]
#[ignore = "needs re/WCCMMUD.DLL, a live board's WCCUSERS.DB, and a real 60s window"]
async fn passes_of_one() {
    measure("mbbs-server-stall-passes-1", 1, Duration::from_secs(60)).await;
}
