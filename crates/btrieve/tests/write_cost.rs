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
//! - **Read syscalls**: `/proc/self/io`'s `syscr` delta, alongside `rchar`.
//!   Added after a live-board defect this file's own byte counters could not
//!   see: `v6::Store` and `read_at`/`read_head` used to open the file fresh
//!   on every page access, so bytes read fell (page-scoped reads instead of
//!   a whole-file `Vec<u8>`) while `open`+`seek`+`read`+`close` syscall
//!   traffic *rose* -- measured live at 35,860 `openat`s in three seconds
//!   against one 55 MB file, `/proc/[pid]/fd` showing zero held handles the
//!   whole time. `rchar` fell 56x across that same change and nothing here
//!   noticed, because nothing was watching `syscr`. It is not, by itself,
//!   a discriminator for *this specific* defect -- `Store`'s own per-operation
//!   page cache already keeps `read(2)` calls bounded to one per distinct
//!   page touched, before or after the fix -- so [`file_opens`] below is the
//!   instrument that actually moves.
//! - **File opens**: [`btrieve::testing::file_opens`], a choke-point counter
//!   this crate keeps of its own (`Block::FILE_OPENS`) -- Linux exposes no
//!   per-process `open(2)` count via `/proc/self/io` the way it does `syscr`
//!   for `read(2)`, so this is the crate counting its own chokepoint rather
//!   than a kernel one. This is the number an open-per-page regression
//!   actually moves, and what `wccmp002_update_cost_today`'s new bound below
//!   is written against.
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

/// Serialises every measurement window in this file. `/proc/self/io`'s
/// counters are process-wide, not per-thread, and the heap tracker above is
/// process-wide too -- Rust's test harness runs `#[test]`s in parallel
/// threads of one process by default, so two measurement windows open at
/// once would each see the other's reads and allocations. A plain
/// `cargo test` never triggers this (the big tests are `#[ignore]`d and the
/// small one is alone), but `--ignored` now runs *two* `#[ignore]`d tests
/// (warm and cold) from this file together, so this is no longer optional.
/// Every `#[test]` below takes this before its own `reset_peak`/`proc_io`
/// baseline and holds it for the whole measurement.
static MEASURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Mark the current heap size as this window's baseline.
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

/// `(rchar, wchar, syscr)` -- total bytes ever passed to `read(2)`/`write(2)`
/// by this process, and the total count of read syscalls themselves, per
/// `proc(5)`. Monotonic counters; a caller diffs two readings to get one
/// call's traffic.
///
/// `syscr` is read alongside `rchar` so a falling byte count can no longer
/// hide a rising syscall count the way it did here: Task 5 cut `rchar` 56x
/// (55.7 MB to ~992 KB) by moving from a whole-file read to page-scoped
/// ones, and nothing watching only `rchar` noticed that the *live* board's
/// syscall traffic went the other way (`openat`s specifically -- see
/// [`file_opens`] below for why `syscr` itself is tracked but is not the
/// instrument that catches that particular regression).
fn proc_io() -> (u64, u64, u64) {
    let text = std::fs::read_to_string("/proc/self/io")
        .expect("this test reads /proc/self/io and only runs on Linux");
    let mut rchar = 0u64;
    let mut wchar = 0u64;
    let mut syscr = 0u64;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("rchar: ") {
            rchar = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("wchar: ") {
            wchar = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("syscr: ") {
            syscr = v.trim().parse().unwrap_or(0);
        }
    }
    (rchar, wchar, syscr)
}

/// How many times this process has opened a file to serve a Btrieve read,
/// since the caller's own [`btrieve::testing::reset_file_opens`] -- the
/// crate's own choke-point count, because `/proc/self/io` has no per-process
/// `open(2)` counter the way it has `syscr` for `read(2)`. This is the
/// number an open-per-page regression actually moves: `Store`'s in-memory
/// page cache already bounds `read(2)` calls to one per distinct page a
/// write touches, before or after such a regression, so `syscr` stays flat
/// while this does not.
fn file_opens() -> u64 {
    btrieve::testing::file_opens()
}

// --- the measurement itself -----------------------------------------------

#[derive(Debug)]
struct Cost {
    rchar: u64,
    wchar: u64,
    syscr: u64,
    opens: u64,
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

    let (r0, w0, sc0) = proc_io();
    btrieve::testing::reset_file_opens();
    reset_peak();
    let start = Instant::now();
    btrieve
        .block_mut(at)
        .expect("still open")
        .update(record.position, &bytes)
        .unwrap_or_else(|e| panic!("{label}: update: {e}"));
    let wall = start.elapsed();
    let (r1, w1, sc1) = proc_io();

    Cost {
        rchar: r1.saturating_sub(r0),
        wchar: w1.saturating_sub(w0),
        syscr: sc1.saturating_sub(sc0),
        opens: file_opens(),
        peak: peak_growth_since_reset(),
        wall,
    }
}

/// The same measurement as [`measure_one_update`], but *cold*: nothing on
/// the `Block` under test has called `records()`, `Get`, or `Step` before
/// `update()` does its own internal `self.records()?` -- the real precondition
/// the first write after a board's own `Btrieve::open` faces, not the
/// steady-state one `measure_one_update` deliberately isolates.
///
/// A second, throwaway `Btrieve` instance opens `path` first, purely to learn
/// which position and bytes to hand `update()` -- a real caller already knows
/// this from an earlier `Get`/`Step` on *some* cursor, but this measurement
/// must not let *this* `Block` be the one that answered it, or the read
/// `records()` costs would land outside the timed window and this would
/// silently become `measure_one_update` again. `/proc/self/io` is
/// process-wide, not per-`Btrieve`, so the scout's own reads are made to
/// finish, and its stack drop, before `(r0, w0)` is taken.
///
/// # Panics
///
/// Same as [`measure_one_update`].
fn measure_one_update_cold(label: &str, path: &Path) -> Cost {
    let (position, bytes) = {
        let mut scout_mem = FlatMem::new(64 * 1024);
        let mut scout_heap = FlatHeap::new(0x100);
        let mut scout = Btrieve::<Flat>::default();
        let geometry = Geometry::read(label, path).unwrap_or_else(|e| panic!("{label}: {e}"));
        let maxlen = geometry.reclen;
        let at = scout
            .open(&mut scout_mem, &mut scout_heap, label, path, geometry, maxlen)
            .unwrap_or_else(|e| panic!("{label}: scout open: {e}"));
        let block = scout.block_mut(at).expect("just opened");
        let records = block.records().unwrap_or_else(|e| panic!("{label}: scout records: {e}"));
        assert!(!records.is_empty(), "{label}: this file has no records to update");
        let record = records.physical(0).expect("index 0 of a non-empty Records");
        let mut bytes = record.bytes.clone();
        bytes[0] ^= 0xff;
        (record.position, bytes)
    };

    let mut mem = FlatMem::new(64 * 1024);
    let mut heap = FlatHeap::new(0x100);
    let mut btrieve = Btrieve::<Flat>::default();
    let geometry = Geometry::read(label, path).unwrap_or_else(|e| panic!("{label}: {e}"));
    let maxlen = geometry.reclen;
    let at = btrieve
        .open(&mut mem, &mut heap, label, path, geometry, maxlen)
        .unwrap_or_else(|e| panic!("{label}: open: {e}"));

    let (r0, w0, sc0) = proc_io();
    btrieve::testing::reset_file_opens();
    reset_peak();
    let start = Instant::now();
    btrieve
        .block_mut(at)
        .expect("still open")
        .update(position, &bytes)
        .unwrap_or_else(|e| panic!("{label}: update: {e}"));
    let wall = start.elapsed();
    let (r1, w1, sc1) = proc_io();

    Cost {
        rchar: r1.saturating_sub(r0),
        wchar: w1.saturating_sub(w0),
        syscr: sc1.saturating_sub(sc0),
        opens: file_opens(),
        peak: peak_growth_since_reset(),
        wall,
    }
}

fn report(label: &str, file_len: u64, cost: &Cost) {
    eprintln!(
        "write_cost[{label}]: file {file_len} bytes -- read {read} bytes ({syscr} read \
         syscalls, {opens} file opens), wrote {wrote} bytes, peak heap growth {peak} bytes, \
         wall {wall:?} (verify_writes={verify})",
        read = cost.rchar,
        syscr = cost.syscr,
        opens = cost.opens,
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
    let _guard = MEASURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
/// one key. This is the number Plan 3 Task 5 is judged against.
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
/// `--release` for the ON one.
///
/// # The bound, and why it is pages, not bytes
///
/// Task 5 replaced the whole-file `Vec<u8>` every v6 write used to load with
/// [`btrieve::v6::Store`] (not exported; see the crate's own module), a
/// page-at-a-time cache backed by disk reads. What still scales with the
/// file is [`btrieve::v6::Map::relocate`]'s twin search -- a genuine
/// `4..pages` scan with no index to shortcut it, see that function's own
/// doc comment -- but each candidate now costs 8 header bytes, not a whole
/// 4,096-byte page, and the scan's answer is cached for the rest of the
/// operation. Measured on this exact file: 991,670 bytes read, against
/// 55,734,402 before Task 5 -- a ~56x reduction, and closer to `pages *
/// header_len` (13,607 * 8 = 108,856) plus the few hundred content and
/// index pages an update actually touches than to the file's own 55.7 MB.
/// `300 * page_size` gives that headroom without coming anywhere near
/// asserting the number can never move again.
#[test]
#[ignore = "needs a real WCCMP002.DAT, named by $WCCMP002"]
fn wccmp002_update_cost_today() {
    let _guard = MEASURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
    report("WCCMP002.DAT (warm -- records() primed before the window)", big_len, &cost);

    // `verify_writes` (debug builds only) re-reads and re-parses the whole
    // file on top of the write itself -- Task 1's own cost, not Task 5's to
    // bound. Asserted only in `--release`, the same way this file's module
    // doc says every number here must be measured.
    if cfg!(debug_assertions) {
        eprintln!("write_cost: verify_writes is on in this build; not bounding its extra read");
        return;
    }
    let page_size = 4096u64;
    let bound = 300 * page_size;
    assert!(
        cost.rchar <= bound,
        "update() on a warm WCCMP002.DAT read {} bytes -- expected at most {bound} \
         ({bound} = 300 pages of {page_size}), a small multiple of the page size, not \
         something that scales with the file's {big_len} bytes",
        cost.rchar
    );

    // `syscr` alongside `rchar`, per this file's own module doc: a page-scoped
    // read path can drop `rchar` while raising syscall traffic, and `rchar`
    // alone would not notice. `Store`'s per-operation page cache already
    // bounds `read(2)` calls to one per distinct page a write touches, so
    // this shares `rchar`'s own page-count reasoning rather than a tighter
    // one -- it is a sanity bound on read syscalls, not the instrument that
    // catches an open-per-page regression (that is `opens`, below).
    assert!(
        cost.syscr <= 300,
        "update() on a warm WCCMP002.DAT issued {} read(2) syscalls -- expected at most 300, \
         a small multiple of the pages a write actually touches",
        cost.syscr
    );

    // The bound this class of defect actually needs: before the fix that
    // added `FILE_OPENS`, `v6::Store` opened `path` fresh on every page
    // access (`Store::read_disk`), so this count scaled with the number of
    // distinct pages a write touched -- in the hundreds for `WCCMP002.DAT`,
    // exactly the shape measured live: 35,860 `openat`s in three seconds
    // against one file, with zero handles ever held (`/proc/[pid]/fd`).
    // After the fix, a v6 write opens the file at most twice: once in
    // `Block::v6_resolve_logical` (both shadow allocation-table halves
    // through one handle) and once in `v6::Store::open` (every page touched
    // after that reads through the same handle). `4` gives headroom without
    // hiding a regression back toward one open per page.
    assert!(
        cost.opens <= 4,
        "update() on a warm WCCMP002.DAT opened its file {} times -- expected at most 4 \
         (one for Block::v6_resolve_logical, one for v6::Store::open), not something that \
         scales with how many pages the write touches",
        cost.opens
    );
}

/// The same file, the same one-record update, but *cold*: nothing has
/// called `records()`, `Get`, or `Step` on the `Block` under test before
/// `update()` makes its own internal call. This is the number a board's
/// very first update after `Btrieve::open` actually pays -- the baseline
/// doc's own Part 3 excluded it by priming `records()` first, and said so:
/// "the real cold-cache cost is higher than 55.7 MB -- a board's first
/// update after open reads the file twice."
///
/// [`records::walk_v6`] (not exported; the crate's own `records` module)
/// is not part of Task 5's scope -- see this crate's `docs/` for why: it
/// must visit very nearly every claimed page to enumerate a densely packed
/// fixed-length file's records, which is not a read-path inefficiency but
/// what building the in-memory model this host's `Records::ordered_len`/
/// `ordered` needs actually costs. So this test's own bound is **not**
/// `300 * page_size` -- it is `file_len + 300 * page_size`, the warm bound
/// plus one full read of the file for `records()` to prime from. What Task
/// 5 changed is that this now costs the file **once**, not twice: before
/// this task, `update()`'s own internal whole-file read added a *second*
/// full pass on top of `records()`'s.
#[test]
#[ignore = "needs a real WCCMP002.DAT, named by $WCCMP002"]
fn wccmp002_update_cost_today_cold() {
    let _guard = MEASURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Ok(source) = std::env::var("WCCMP002") else {
        eprintln!("set WCCMP002=/path/to/wccmp002.vir to run this");
        return;
    };

    let big_dir = scratch("write-cost-big-cold");
    let big_path = big_dir.join("WCCMP002.DAT");
    std::fs::copy(&source, &big_path).unwrap_or_else(|e| panic!("copying {source}: {e}"));
    make_keys_modifiable(&big_path);
    let big_len = std::fs::metadata(&big_path).expect("metadata").len();
    assert_eq!(big_len, 55_734_272, "this is the exact file the plan measured defect #2 against");

    let cost = measure_one_update_cold("WCCMP002.DAT", &big_path);
    report("WCCMP002.DAT (cold -- update() primes records() itself)", big_len, &cost);

    if cfg!(debug_assertions) {
        eprintln!("write_cost: verify_writes is on in this build; not bounding its extra read");
        return;
    }
    let page_size = 4096u64;
    let bound = big_len + 300 * page_size;
    assert!(
        cost.rchar <= bound,
        "a cold update() on WCCMP002.DAT read {} bytes -- expected at most {bound} \
         (one full-file read for records() to prime from, plus the warm update's own \
         bounded read), not something that scales with a second full-file read on top",
        cost.rchar
    );

    // Same reasoning as `wccmp002_update_cost_today`'s own `opens` bound: a
    // cold update pays one extra whole-file read for `records()` to prime
    // from (`walk_v6` -- `std::fs::read`, one `open` of its own, not routed
    // through `FILE_OPENS`), on top of the warm update's own opens. `5`
    // gives that one extra open room without hiding a regression back
    // toward one open per page.
    assert!(
        cost.opens <= 5,
        "a cold update() on WCCMP002.DAT opened its file {} times -- expected at most 5, not \
         something that scales with how many pages the write touches",
        cost.opens
    );
}
