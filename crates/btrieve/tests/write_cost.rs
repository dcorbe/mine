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
    /// [`btrieve::testing::page_fetches`] since this window's own
    /// [`btrieve::testing::reset_page_fetches`] -- how many pages a v6
    /// write's attached cache actually went to disk for, as opposed to
    /// [`Self::opens`]'s count of whole-file handles.
    page_fetches: u64,
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
    btrieve::testing::reset_page_fetches();
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
        page_fetches: btrieve::testing::page_fetches(),
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
    btrieve::testing::reset_page_fetches();
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
        page_fetches: btrieve::testing::page_fetches(),
        peak: peak_growth_since_reset(),
        wall,
    }
}

/// Two updates against the same still-open `Btrieve` session, on the same
/// `Block` -- the shape neither [`measure_one_update`] nor
/// [`measure_one_update_cold`] covers, both opening once and writing once.
/// The first update is untimed and unmeasured, exactly the real precondition
/// a board's *second* write to a file faces: whatever the first write's own
/// reads left resident.
///
/// A real, distinct edit -- not a flip-back of the same byte -- so the
/// second update is not accidentally a no-op the model could special-case.
///
/// # Panics
///
/// Same as [`measure_one_update`].
fn measure_second_update(label: &str, path: &Path) -> Cost {
    let mut mem = FlatMem::new(64 * 1024);
    let mut heap = FlatHeap::new(0x100);
    let mut btrieve = Btrieve::<Flat>::default();

    let geometry = Geometry::read(label, path).unwrap_or_else(|e| panic!("{label}: {e}"));
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

    let mut first_bytes = record.bytes.clone();
    first_bytes[0] ^= 0xff;
    btrieve
        .block_mut(at)
        .expect("still open")
        .update(record.position, &first_bytes)
        .unwrap_or_else(|e| panic!("{label}: first update: {e}"));

    let mut second_bytes = first_bytes.clone();
    second_bytes[1] ^= 0xff;

    let (r0, w0, sc0) = proc_io();
    btrieve::testing::reset_file_opens();
    btrieve::testing::reset_page_fetches();
    reset_peak();
    let start = Instant::now();
    btrieve
        .block_mut(at)
        .expect("still open")
        .update(record.position, &second_bytes)
        .unwrap_or_else(|e| panic!("{label}: second update: {e}"));
    let wall = start.elapsed();
    let (r1, w1, sc1) = proc_io();

    Cost {
        rchar: r1.saturating_sub(r0),
        wchar: w1.saturating_sub(w0),
        syscr: sc1.saturating_sub(sc0),
        opens: file_opens(),
        page_fetches: btrieve::testing::page_fetches(),
        peak: peak_growth_since_reset(),
        wall,
    }
}

/// Same shape as [`measure_second_update`], but the second update touches
/// a *different* record than the first, rather than the same one twice.
/// Named directly by Task 3's own review (Important 4): this is the case
/// this file's own bounds do not, and are not claimed to, speed up.
/// `v6::Map::read`'s bounded allocation-table walk and `v6::Map::relocate`'s
/// twin search both read their own header bytes fresh off disk every
/// single operation -- uncached across operations by design, see
/// [`wccmp002_update_cost_today`]'s own comment on its `page_fetches`
/// bound for why. Measured here, not bounded: this task did not change
/// that cost, so there is no claim for an assertion to protect -- only
/// visibility into what remains, deferred to Task 6's write-path rebuild.
///
/// # Panics
///
/// Same as [`measure_one_update`], plus if `path` has fewer than two
/// records.
fn measure_second_update_different_record(label: &str, path: &Path) -> Cost {
    let mut mem = FlatMem::new(64 * 1024);
    let mut heap = FlatHeap::new(0x100);
    let mut btrieve = Btrieve::<Flat>::default();

    let geometry = Geometry::read(label, path).unwrap_or_else(|e| panic!("{label}: {e}"));
    let maxlen = geometry.reclen;
    let at = btrieve
        .open(&mut mem, &mut heap, label, path, geometry, maxlen)
        .unwrap_or_else(|e| panic!("{label}: open: {e}"));

    let (first, second) = {
        let block = btrieve.block_mut(at).expect("just opened");
        let records = block.records().unwrap_or_else(|e| panic!("{label}: records: {e}"));
        assert!(records.len() >= 2, "{label}: this measurement needs at least two records");
        // Halfway through the file, not the adjacent index-1 record: two
        // records next to each other in logical order almost always share
        // the same allocation-table block (~1,022 entries per 4,096-byte
        // block, per `format::alloc`), which the first update's own
        // resolution already made cache-resident -- indistinguishable from
        // the same-record case this measurement exists to contrast with.
        // Halfway across a 13,607-page file all but guarantees a different
        // block, one this session has not resolved yet.
        let midpoint = records.len() / 2;
        let first = records.physical(0).expect("index 0").clone();
        let second = records.physical(midpoint).expect("the midpoint index").clone();
        (first, second)
    };

    let mut first_bytes = first.bytes.clone();
    first_bytes[0] ^= 0xff;
    btrieve
        .block_mut(at)
        .expect("still open")
        .update(first.position, &first_bytes)
        .unwrap_or_else(|e| panic!("{label}: first update: {e}"));

    let mut second_bytes = second.bytes.clone();
    second_bytes[0] ^= 0xff;

    let (r0, w0, sc0) = proc_io();
    btrieve::testing::reset_file_opens();
    btrieve::testing::reset_page_fetches();
    reset_peak();
    let start = Instant::now();
    btrieve
        .block_mut(at)
        .expect("still open")
        .update(second.position, &second_bytes)
        .unwrap_or_else(|e| panic!("{label}: second update: {e}"));
    let wall = start.elapsed();
    let (r1, w1, sc1) = proc_io();

    Cost {
        rchar: r1.saturating_sub(r0),
        wchar: w1.saturating_sub(w0),
        syscr: sc1.saturating_sub(sc0),
        opens: file_opens(),
        page_fetches: btrieve::testing::page_fetches(),
        peak: peak_growth_since_reset(),
        wall,
    }
}

fn report(label: &str, file_len: u64, cost: &Cost) {
    eprintln!(
        "write_cost[{label}]: file {file_len} bytes -- read {read} bytes ({syscr} read \
         syscalls, {opens} file opens, {fetches} page fetches), wrote {wrote} bytes, peak heap \
         growth {peak} bytes, wall {wall:?} (verify_writes={verify})",
        read = cost.rchar,
        syscr = cost.syscr,
        opens = cost.opens,
        fetches = cost.page_fetches,
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

    // Task 7's own bound, on `wchar`: one update on WCCMP002.DAT (55.7 MB,
    // 13,607 pages) may write the touched data page, the root-to-leaf index
    // path each key's tree edit disturbs, and the allocation-table/FCR
    // shadow pages that edit's own claims/relocations touch. This scenario's
    // own flip (`bytes[0] ^= 0xff`) lands on this file's one key, so this is
    // a key-changing update (delete-then-insert, `Block::update_v6`'s own
    // doc comment) -- measured today at 16,388 bytes, real margin under this
    // bound (the same-leaf, no-key-change case `v6_update_writes_only_the_
    // pages_it_changed` in `lib.rs` measures lower still, 12,292 B). See this
    // bound's own baseline-doc entry for the argument that it discriminates
    // (reverting to a whole-tree rebuild measured 499,742 B before Task 6,
    // ~30-40x either figure). Unlike `cost.rchar` below, this runs in *both*
    // build profiles: `verify_writes` re-reads and re-parses the file on top
    // of the write (Task 1's own cost), it does not write anything extra, so
    // `wchar` is not inflated by debug assertions the way `rchar` is.
    assert!(
        cost.wchar <= 65_536,
        "update() on a warm WCCMP002.DAT wrote {} bytes -- expected at most 65,536 \
         (measured today: 16,388 B for this key-changing scenario, 12,292 B for a \
         same-leaf non-key-changing one), not something that scales back toward a \
         whole-tree rebuild (499,742 B, before Task 6)",
        cost.wchar
    );

    // A second update on the same open Block must resolve its FULL PAGES
    // from the cache: a record's data/index pages, and whichever
    // allocation-table page `Block::v6_resolve_logical`/`v6::Store::attach`
    // touch in full, must not cost a fresh disk read on the next operation
    // once an earlier one has already fetched or written them -- that is
    // exactly what `Block::write_changed_pages`'s write-through and
    // `v6_resolve_logical`'s own cache routing buy. Bound: the SECOND
    // update fetches at most the full pages it newly touches -- assert
    // page_fetches delta <= 32.
    //
    // What this does **not** cover, and is not claimed to: `v6::Map::read`'s
    // bounded allocation-table walk and `v6::Map::relocate`'s twin search
    // both read their own HEADER-only bytes (`v6::Store::header`) straight
    // off disk every single operation, uncached across operations by
    // design -- `v6::Store::attach`'s own doc comment explains why routing
    // an 8-byte header check through the shared, whole-page cache would
    // reintroduce the 55.7 MB whole-file scan Task 5 eliminated. That
    // per-operation header cost is the "8-byte allocation-table probes...
    // re-read up to 36x" traffic this task's own brief cites; it is not
    // fixed here, and is deferred to Task 6's write-path rebuild, not
    // silently dropped.
    //
    // A fresh copy, not `big_path` above: that file already carries the
    // first test's own edit, and this scenario -- two updates in one
    // session -- is its own precondition, not a continuation of the other.
    // Checked in both build profiles: `page_fetches` never passes through
    // `verify_writes`'s own re-read (a separate, `read::file`-based path),
    // so nothing about this bound depends on which profile measures it.
    let second_dir = scratch("write-cost-big-second");
    let second_path = second_dir.join("WCCMP002.DAT");
    std::fs::copy(&source, &second_path).unwrap_or_else(|e| panic!("copying {source}: {e}"));
    make_keys_modifiable(&second_path);

    let second = measure_second_update("WCCMP002.DAT", &second_path);
    report("WCCMP002.DAT (second update -- same open Block)", big_len, &second);
    assert!(
        second.page_fetches <= 32,
        "a second update on the same open Block fetched {} pages from disk -- \
         expected at most 32 (only the pages it newly touches), not a fresh \
         allocation-table walk repeating what the first update already read",
        second.page_fetches
    );

    // A complementary bound, added after mutation-testing this one:
    // `page_fetches` above cannot see a regression in
    // `Block::v6_resolve_logical`'s own routing through the cache, because
    // within one operation `v6::Map::relocate` independently re-touches the
    // same allocation-table page `v6_resolve_logical` already resolved --
    // whichever of the two asks first pays for the fetch and the other is
    // free, so the total is the same either way. What actually moves is
    // `opens`: reverting `v6_resolve_logical` to its own handle costs one
    // extra `open(2)` every single operation (measured: 1 -> 2, on both
    // the warm update above and this second one), because it no longer
    // shares this open `Store::attach`'s own header handle already pays
    // for.
    assert!(
        second.opens <= 1,
        "a second update on the same open Block opened its file {} times -- \
         expected at most 1 (Store::attach's own header handle), not a \
         second one from v6_resolve_logical falling back to its own",
        second.opens
    );

    // A third bound, on `rchar` itself: neither `page_fetches` nor `opens`
    // above catches a full `v6::Store::attach` -> `v6::Store::open`
    // reversion at this file's own two call sites (`Block::insert_v6`,
    // `Block::v6_slot`) -- both open exactly one handle either way
    // (`opens` stays 1), and a reverted `Store` never touches `PageCache`
    // at all, so `page_fetches` stays ~0 regardless (confirmed directly,
    // not assumed -- see `docs/2026-08-24-btrieve-write-cost-baseline.md`'s
    // own "Important 3" section for the red/green output both ways).
    // `rchar` is what actually moves: measured 389 B with the cache wired
    // in, reverting toward the pre-Task-3 524,678 B this same second-update
    // scenario cost before. `65_536` (16 pages of headroom at this file's
    // 4,096-byte page size) sits between the two with real margin either
    // way -- large enough that ordinary variance or a future, deliberate
    // change to how many pages a second update touches will not flap it,
    // small enough that a full reversion (524,678 B) cannot hide under it.
    assert!(
        second.rchar <= 65_536,
        "a second update on the same open Block read {} bytes -- expected at most \
         65,536 (measured with the cache wired in: 389 B; a full Store::attach -> \
         Store::open reversion measures 524,678 B), not something that scales back \
         toward a fresh per-operation disk read",
        second.rchar
    );

    // A DIFFERENT record for the second update, not the same one -- see
    // `measure_second_update_different_record`'s own doc comment. Measured
    // and reported, deliberately not bounded: this is the partial-fix
    // visibility Task 3's review asked for, not a new claim.
    let third_dir = scratch("write-cost-big-third");
    let third_path = third_dir.join("WCCMP002.DAT");
    std::fs::copy(&source, &third_path).unwrap_or_else(|e| panic!("copying {source}: {e}"));
    make_keys_modifiable(&third_path);
    let different_record = measure_second_update_different_record("WCCMP002.DAT", &third_path);
    report("WCCMP002.DAT (second update, a DIFFERENT record)", big_len, &different_record);

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
    // after that reads through the same handle). Measured: 2. `4` gives
    // headroom without hiding a regression back toward one open per page.
    //
    // `FILE_OPENS` now counts every read-serving open in this crate's
    // non-test code, not just these two (`open_for_read`/`read_whole` in
    // `src/lib.rs`, enforced by `tests/file_opens_guard.rs`) -- this warm
    // path just does not happen to reach any of the others.
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
    // from (`records::walk_v6`, through `read_whole` -- one `open` of its
    // own). Measured: 3 (the warm update's own 2, plus this one). `walk_v6`
    // used to open the file with a bare `std::fs::read`, invisible to
    // `FILE_OPENS`, so this bound stayed 5 across a fix that actually moved
    // the true count from 2 to 3 -- the exact overclaim `tests/
    // file_opens_guard.rs` now exists to stop happening again. `5` still
    // gives one open of headroom without hiding a regression back toward
    // one open per page.
    assert!(
        cost.opens <= 5,
        "a cold update() on WCCMP002.DAT opened its file {} times -- expected at most 5, not \
         something that scales with how many pages the write touches",
        cost.opens
    );
}
