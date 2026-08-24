//! Task 2 of `docs/superpowers/plans/2026-08-24-btrieve-plan-3-incremental-
//! updates.md`: measure, not reason about, what one record update costs
//! today -- bytes read, bytes written, peak heap growth, wall time -- before
//! Stage B touches the write path. No behaviour changes here.
//!
//! # Instruments, both std-only (`Cargo.toml`'s `[dependencies]` stays empty)
//!
//! - **Bytes read/written**: `/proc/self/io`'s `rchar`/`wchar` deltas around
//!   the one call under measurement -- the same instrument
//!   `v6_update_writes_only_the_pages_it_changed` (this crate's own `lib.rs`)
//!   already uses, for the same reason its own comment gives: "the counters
//!   are bytes this process asked the kernel for, which is exactly the
//!   question." Linux-only, and that is fine -- a diagnostic test, not a
//!   portability contract.
//! - **Peak heap growth**: a `#[global_allocator]` wrapping `System` with two
//!   atomics (current, peak-since-reset).
//!
//! # `verify_writes`, and why this file cannot turn it off directly
//!
//! `Block::verify_writes` (Task 1) is a private field, set by `Btrieve::open`
//! to `cfg!(debug_assertions)` with no public setter -- deliberately: it is
//! an explicit opt-in a test can flip only from inside the crate. So the
//! **build profile controls it here**: `--release` measures the OFF state
//! (`cfg!(debug_assertions)` is `false` there); a plain debug build measures
//! the ON state -- same code path, same file, the verifier's own cost
//! isolated by nothing but the profile. Both are recorded in
//! `docs/2026-08-24-btrieve-write-cost-baseline.md`.
//!
//! # A defect this measurement found, not one it was looking for
//!
//! `Btrieve::open` is the one path a real module's `opnbtv` reaches, and
//! measuring through it (rather than through `lib.rs`'s own test-only
//! `block_from_file`, which hardcodes `verify_writes: false` -- see that
//! function's own comment) is what surfaced this: **updating any record of a
//! genuine `WCCMP002.DAT` left the file unparseable.** `verify::written`
//! reported physical page 7024 claimed by the allocation table but
//! attributed to no key's B-tree, tagged neither `TAG_ACS`, `TAG_DATA` nor
//! `TAG_VARIABLE`. Confirmed independently: the pristine, unmodified file
//! parsed cleanly (`verify::written` `Ok`), and the corruption reproduced
//! identically regardless of which record was updated or which byte within
//! it changed -- so this was not about a particular record choice. Every
//! existing `$WCCMP002`-gated test in `lib.rs` builds its `Block` with
//! `verify_writes: false` and only checks record count or page-diff counts,
//! neither of which a page mistagged this way would ever fail.
//!
//! **Fixed** by Plan 3 Task 3b, same root cause as `lib.rs`'s
//! `a_shrinking_multi_key_v6_reindex_releases_its_surplus_pages`:
//! `Block::v6_reindex`'s bulk rebuild packs a key's tree denser than genuine
//! Btrieve 6.15 ever wrote, so an ordinary update can need fewer index nodes
//! than the file's own tree occupies (208 nodes to 106, measured on this
//! exact file), and the surplus used to stay claimed with nothing pointing
//! at it. `v6::Map::unclaim` now releases those pages before the write
//! returns. `wccmp002_update_cost_today` below asserts the write succeeds in
//! both build profiles now, not just `--release`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use btrieve::testing::{make_keys_modifiable, scratch, Flat, FlatHeap, FlatMem};
use btrieve::{Btrieve, Geometry};

// --- peak-heap tracking --------------------------------------------------

struct Tracking;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static BASELINE: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let now = CURRENT.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            PEAK.fetch_max(now, Ordering::SeqCst);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
    }
}

#[global_allocator]
static ALLOC: Tracking = Tracking;

/// Mark the current heap size as this window's baseline. Every measurement
/// in this file runs from its own `#[test]` function and this crate's
/// harness never runs two `#[test]`s from this file at once by default (the
/// big one is `#[ignore]`d, so a plain `cargo test` never overlaps it with
/// the small one) -- a concurrent allocation from another test in this
/// binary would otherwise contaminate the reading.
fn reset_peak() {
    let now = CURRENT.load(Ordering::SeqCst);
    BASELINE.store(now, Ordering::SeqCst);
    PEAK.store(now, Ordering::SeqCst);
}

/// The largest `CURRENT` has been since the matching [`reset_peak`], minus
/// what `CURRENT` already stood at then -- how much this window's own work
/// grew the heap at its worst point, not the process's whole footprint.
fn peak_growth_since_reset() -> usize {
    PEAK.load(Ordering::SeqCst).saturating_sub(BASELINE.load(Ordering::SeqCst))
}

// --- /proc/self/io --------------------------------------------------------

/// `(rchar, wchar)` -- total bytes ever passed to `read(2)`/`write(2)` by
/// this process, per `proc(5)`. Monotonic counters; a caller diffs two
/// readings to get one call's traffic.
fn proc_io() -> (u64, u64) {
    let text = std::fs::read_to_string("/proc/self/io")
        .expect("this test reads /proc/self/io and only runs on Linux");
    let mut rchar = 0u64;
    let mut wchar = 0u64;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("rchar: ") {
            rchar = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("wchar: ") {
            wchar = v.trim().parse().unwrap_or(0);
        }
    }
    (rchar, wchar)
}

// --- the measurement itself -----------------------------------------------

#[derive(Debug)]
struct Cost {
    rchar: u64,
    wchar: u64,
    peak: usize,
    wall: Duration,
}

/// Open `path` as a genuine Btrieve file (through the real, public
/// `Btrieve::open` path), find its first record, flip one byte, and time
/// the `update()` that writes it back.
///
/// `records()` is called *before* the measurement window opens: a real
/// `dfaUpdateDup` sequence already knows the record's position from an
/// earlier `Get`/`Step`, so priming the model here is the realistic
/// precondition, not part of what is being measured. What happens *inside*
/// `update()` -- including `v6_slot`'s own unconditional whole-file read --
/// is what this measures.
///
/// # Panics
///
/// If the file cannot be opened or read, or if `update()` itself refuses or
/// fails -- including a `verify_writes` failure in a debug build. That last
/// one is a real, reproducible defect on `WCCMP002.DAT` (see this file's own
/// module doc); it is not swallowed here.
fn measure_one_update(label: &str, path: &Path) -> Cost {
    let mut mem = FlatMem::new(64 * 1024);
    let mut heap = FlatHeap::new(0x100);
    let mut btrieve = Btrieve::<Flat>::default();

    let geometry = Geometry::read(label, path).unwrap_or_else(|e| panic!("{label}: {e}"));
    assert!(!geometry.variable, "{label}: this measurement is the fixed-length write path");
    let maxlen = geometry.reclen;

    let at = btrieve
        .open(&mut mem, &mut heap, label, path, geometry, maxlen)
        .unwrap_or_else(|e| panic!("{label}: open: {e}"));

    let record = {
        let block = btrieve.block_mut(at).expect("just opened");
        let records = block.records().unwrap_or_else(|e| panic!("{label}: records: {e}"));
        assert!(!records.is_empty(), "{label}: this file has no records to update");
        records.physical(0).expect("index 0 of a non-empty Records").clone()
    };

    let mut bytes = record.bytes.clone();
    bytes[0] ^= 0xff; // the smallest possible semantic change: flip one bit

    let (r0, w0) = proc_io();
    reset_peak();
    let start = Instant::now();
    btrieve
        .block_mut(at)
        .expect("still open")
        .update(record.position, &bytes)
        .unwrap_or_else(|e| panic!("{label}: update: {e}"));
    let wall = start.elapsed();
    let (r1, w1) = proc_io();

    Cost {
        rchar: r1.saturating_sub(r0),
        wchar: w1.saturating_sub(w0),
        peak: peak_growth_since_reset(),
        wall,
    }
}

fn report(label: &str, file_len: u64, cost: &Cost) {
    eprintln!(
        "write_cost[{label}]: file {file_len} bytes -- read {read} bytes, wrote {wrote} \
         bytes, peak heap growth {peak} bytes, wall {wall:?} (verify_writes={verify})",
        read = cost.rchar,
        wrote = cost.wchar,
        peak = cost.peak,
        wall = cost.wall,
        verify = cfg!(debug_assertions),
    );
}

/// One record update on a small, genuine v6 fixed-length file --
/// `WCCRACE2.VIR` (MajorMUD-NT's race table, 40,960 bytes, reclen 126, one
/// key), confirmed real and readable via `btrieve-census` against this
/// exact archive tree before this test was written. Copied into scratch,
/// never mutated in place: corpus files are read-only evidence.
///
/// Ungated (no `$WCCMP002`-style env var needed): the file is small enough
/// that this runs by default under `cargo test -p btrieve`, but still skips
/// cleanly, rather than panicking, on a checkout with no `archive/` --
/// `crate::corpus::root`'s own doc comment: "anything reading it must
/// handle its absence explicitly."
#[test]
fn small_v6_fixed_update_cost_today() {
    let Some(archive) = btrieve::corpus::root() else {
        eprintln!("write_cost: no archive/ on this box, nothing measured -- expected on a fresh checkout");
        return;
    };

    let small_src = archive.join("modules/majormud-nt/wccnt8pj/out/wccrace2.vir");
    if !small_src.is_file() {
        eprintln!("write_cost: {} not found, nothing measured", small_src.display());
        return;
    }
    let small_dir = scratch("write-cost-small");
    let small_path = small_dir.join("WCCRACE2.VIR");
    std::fs::copy(&small_src, &small_path)
        .unwrap_or_else(|e| panic!("copying {}: {e}", small_src.display()));
    // Flipping a byte that happens to land in a key's own bytes would be
    // refused (status 10, "not modifiable") regardless of the read/write
    // amplification this test measures -- make every key modifiable first,
    // the same helper `mbbs`'s own tests use for the identical reason.
    make_keys_modifiable(&small_path);
    let small_len = std::fs::metadata(&small_path).expect("metadata").len();

    let cost = measure_one_update("WCCRACE2.VIR", &small_path);
    report("small v6 fixed (WCCRACE2.VIR)", small_len, &cost);
}

/// One record update on the exact file the plan's own measured defect #2
/// names: `WCCMP002.DAT`, 55,734,272 bytes, 13,607 pages, v6, fixed-length,
/// one key. This is the number Stage B must move.
///
/// Ignored and gated on `$WCCMP002`, exactly like `lib.rs`'s own
/// `v6_update_writes_only_the_pages_it_changed` and its neighbours: the file
/// is too large to commit, so an operator names a copy explicitly. Run with:
///
/// ```text
/// WCCMP002=/path/to/wccmp002.vir \
///   cargo test -p btrieve --release --test write_cost -- --ignored --nocapture
/// ```
///
/// for the OFF (no-verification) baseline, and the same command without
/// `--release` for the ON one. Both now produce a clean number: see this
/// file's own module doc, "A defect this measurement found" -- Task 2 found
/// the ON run corrupting the file outright, and Task 3b fixed it, so this
/// assertion is now a regression guard rather than a documented failure.
#[test]
#[ignore = "needs a real WCCMP002.DAT, named by $WCCMP002"]
fn wccmp002_update_cost_today() {
    let Ok(source) = std::env::var("WCCMP002") else {
        eprintln!("set WCCMP002=/path/to/wccmp002.vir to run this");
        return;
    };

    let big_dir = scratch("write-cost-big");
    let big_path = big_dir.join("WCCMP002.DAT");
    std::fs::copy(&source, &big_path).unwrap_or_else(|e| panic!("copying {source}: {e}"));
    make_keys_modifiable(&big_path);
    let big_len = std::fs::metadata(&big_path).expect("metadata").len();
    assert_eq!(big_len, 55_734_272, "this is the exact file the plan measured defect #2 against");

    let cost = measure_one_update("WCCMP002.DAT", &big_path);
    report("WCCMP002.DAT", big_len, &cost);

    // Not a tight bound -- this is a measurement, and the point is the
    // number in the report, not a pass/fail gate on it. But a write that
    // read less than the file itself would mean this test stopped
    // measuring what it claims to, so that much is asserted.
    assert!(
        cost.rchar >= big_len,
        "expected at least one full-file read inside update() on WCCMP002.DAT, got {} bytes \
         read against a {big_len}-byte file",
        cost.rchar
    );
}
