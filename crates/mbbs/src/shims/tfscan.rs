//! The TFSCAN family -- `tfsopn`, `tfsrdl`, `tfspfx`, `tfsabt` -- Galacticomm's
//! text-file scanner. `MJRBBS.CFG` (the DLL/app load list) is read with it,
//! and `WCCMMUD.DLL` imports all four.
//!
//! `archive/galacticomm/extract/wg1/GALDSRC/SRC/TFSCAN.H` (the wg1 tree --
//! see the memory note "cite wg1, not wg20", the same file in wg20 has
//! different line numbers and produces silently wrong citations), whole:
//!
//!
//! `tfsdpr` (TFSCAN.H:31) is not one of the four this file implements -- it is
//! not among the symbols the task named, and no call site found below ever
//! reaches it (every one of them tests `tfspfx`'s return, never chains a
//! second, "deeper" prefix off it). Left unimplemented on purpose.
//!
//! # There is no vendor `.C` for this file in the archive
//!
//! Every other host routine this crate has ported so far had `TFSCAN.H`'s
//! counterpart: a `.C` file in the same `GALDSRC/SRC` tree with the actual
//! function bodies. This one does not. Searched (both patterns, to rule out a
//! definition Ghidra's line-oriented grep would miss): every `.C` file for a
//! bare `tfsopn`/`tfsrdl`/`tfspfx`/`tfsabt`/`tfsdpr` definition, and every
//! file that mentions `MAXTFS`/`fndblk`/`tfsfb` at all, in
//! `archive/galacticomm/extract/wg1/GALDSRC/SRC/`. Nothing but the header and
//! its callers turned up -- `TFSCAN.C` itself is not in the archive, in any
//! of the five extracted trees (`wg1`, `wg20`, `wg101host`, `mbbs625sdk`,
//! `phar304`/`phar312`). Galacticomm shipped the SDK's demo `.C` files
//! (`MAJORBBS.C`, `BBSMAINM.C`, `PLBBS.C`, `GCSASYS.C` among them) but not the
//! host library's own implementation of this one -- the same gap
//! `shims/stream.rs`'s own module doc describes for `fnd1st`/`fndnxt`'s 32-bit
//! `struct ffblk` layout, just one file over.
//!
//! So what follows is **inferred from the header's own contract and from
//! every call site that uses it**, not measured against a decompiled binary
//! or a surviving source file. Every inference is called out below, at the
//! function it drives. The call sites, all in the wg1 tree:
//!
//! - `MAJORBBS.C:726-734` -- `tfsopn("MJRBBS.CFG")`, loop, `tfspfx("NEEDED4 ")`.
//! - `MAJORBBS.C:953-964` -- `tfsopn("GALDEBUG.MSG")`, `switch (tfstate) { case
//!   TFSLIN: ... }`, `tfspfx("DBGMEM {")`. The only site that dispatches on
//!   `tfstate` with a `switch` rather than an `if` -- confirms `tfstate`/the
//!   return value walks more than the two codes (`TFSDUN`/`TFSLIN`) the other
//!   sites test for explicitly, i.e. `TFSBGN`/`TFSBOF`/`TFSEOF` are real
//!   values a caller can see, not vestigial.
//! - `BBSMAINM.C:889-899` -- `tfsopn("MJRBBS.CFG")`, `tfspfx("CSTART=")`.
//! - `BBSMAINM.C:1014-1034` -- `tfsopn("MJRBBS.CFG")` **twice**, back to back
//!   in the same routine (`gappnams`): a first pass counts `APP=` lines, then
//!   a second `tfsopn` of the identical name re-scans from the top to fill an
//!   array now sized for that count. Load-bearing evidence that re-opening a
//!   scan that already ran to completion has to work cleanly -- see
//!   [`tfsopn`]'s own doc comment.
//! - `PLBBS.C:69-92` (`setbparm`) -- `tfsopn("BBSBTR.BAT")`, and inside the
//!   loop, `tfspfx("BREQUEST")` then, in the `else`, `tfspfx("BTRIEVE >NUL")`
//!   against the *same* current line. Evidence that `tfspfx` only peeks at
//!   `tfsbuf` and never mutates or consumes it -- a second, different prefix
//!   test against the same line has to see the line `tfspfx` was just handed,
//!   unchanged.
//! - `PLBBS.C:95-119` (`callinits`) -- `tfsopn("MJRBBS.CFG")`,
//!   `tfspfx("DLL=")`, then `tfspst` used both as a `spr` argument and passed
//!   straight to `loaddll`/`printfat("%8.8s", tfspst)` -- `tfspst` has to be a
//!   real, NUL-terminated C string a module can hand to any string-consuming
//!   routine, not just something `tfspfx`'s own caller inspects byte-by-byte.
//! - `GCSASYS.C:2407-2414` -- `tfsopn(OSMSUBDR"GCSVCMAN.LST")`,
//!   `depad(tfsbuf)` (`tfsbuf` used directly, not through `tfspfx`) followed
//!   by `fnd1st`.
//!
//! None of the four host globals `tfsfb`/`tfsfp` (TFSCAN.H:23-25; `tfstate`/
//! `tfsbuf`/`tfspst` are the other three) is ever read at a call site above --
//! consistent with `crate::globals::GLOBALS` (`globals.rs:215-218`), which
//! places `tfstate`, `tfspst` and `tfsbuf` as module-addressable globals but
//! not `tfsfb`/`tfsfp`. This file follows that lead: the current file handle
//! and the queue of files still to scan are host-side state a module was
//! never going to read directly, kept off `tfsfb`/`tfsfp` for the same reason
//! `globals.rs`'s own module doc gives for `bb`/`curmbk` the other
//! direction -- a global belongs in module memory *only when something reads
//! it there*, and nothing does for these two.
//!
//! # State lives host-side, not round-tripped out of `tfstate`
//!
//! `tfstate`/`tfsbuf`/`tfspst` are the three globals a module can see, and
//! every shim below writes them (via [`crate::globals::Globals::write_mem`]/
//! [`crate::globals::Globals::write_int_mem`]) as an *output* of the state
//! machine -- never reads them back to decide what to do next. The
//! authoritative copy is [`TfScan`], added to `Host<A>` for exactly this
//! (see the note at the bottom of this file for what field that requires).
//! The same relationship `shims::btrieve` has with `bb`, or `shims::fsd` with
//! `fsdscb`: the module's copy is a mirror a module reads, not a source of
//! truth the host consults.
//!
//! # One scan, not one per channel
//!
//! `TFSCAN.H` declares `tfstate`/`tfsbuf`/`tfspst`/`tfsfb`/`tfsfp` as plain
//! `extern` globals -- not an array, not anything indexed by channel, unlike
//! e.g. `Host::fsdscb` (per-channel, because two channels really can be
//! mid-`fsdroom` at once). That only makes sense under MajorBBS's
//! cooperative, non-preemptive scheduling: a routine runs to completion (or
//! to its next `alertsc`) before another gets the CPU, and every call site
//! above scans a config file start-to-finish inside one routine, in one
//! uninterrupted `while (tfsrdl() != TFSDUN)` loop -- nothing yields
//! mid-scan. So [`TfScan`] is a single value, not a per-channel table.
//!
//! The reachability argument for this family -- a uniform two-call-site
//! count, exclusive to MajorMUD rather than shared with LunatiX,
//! Tele-Arena or The Rose, and both sites confirmed genuine gameplay use
//! -- is recorded in `docs/2026-08-14-tfscan-reachability.md`.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use mbbs_machine::ptr::ModulePtr;

use crate::Host;
use crate::abi::{self, Abi, Call, Wg16};
use crate::dos;
use crate::shims::ShimError;

/// `tfsrdl()`'s return value and `tfstate`'s codes -- `TFSCAN.H:35-39`,
/// quoted in full in this file's own module doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// `TFSDUN` (0) -- no scan is running, or the last one ran out.
    Dun,
    /// `TFSBGN` (1) -- `tfsopn()` has been called; `tfsrdl()` has not run yet.
    Bgn,
    /// `TFSBOF` (2) -- about to start a new file: it is open, but no line has
    /// been read from it yet.
    Bof,
    /// `TFSLIN` (3) -- a line is waiting in `tfsbuf`.
    Lin,
    /// `TFSEOF` (4) -- the file just read to its end has been closed; the
    /// next call moves on to another file, or finishes the scan.
    Eof,
}

impl State {
    /// The `#define`d code this state is, as `tfstate`'s width wants it.
    fn code(self) -> u16 {
        match self {
            State::Dun => 0,
            State::Bgn => 1,
            State::Bof => 2,
            State::Lin => 3,
            State::Eof => 4,
        }
    }
}

impl Default for State {
    /// An enum needs this written out explicitly -- there is no bare variant
    /// to derive it from. [`TfScan::state`]'s own doc comment is what this
    /// choice of default is *for*.
    fn default() -> Self {
        State::Dun
    }
}

/// The one running (or finished, or never-started) `tfsopn`/`tfsrdl` scan --
/// see this file's own module doc, "one scan, not one per channel", for why
/// this is a single value and not a per-channel table like
/// [`crate::Host::fsdscb`].
///
/// Not generic over `A`: nothing in here is module memory, an `A::Ptr`, or
/// anything else ABI-shaped. It is a directory listing and a file handle,
/// both entirely host-side -- the ABI only enters when a shim below writes
/// the result into `tfstate`/`tfsbuf`/`tfspst`.
///
/// # What is required of `Host<A>`
///
/// **Not added here, per the task's own instruction not to edit `lib.rs`.**
/// `Host<A>` needs one field:
///
/// ```text
/// pub(crate) tfscan: shims::tfscan::TfScan,
/// ```
///
/// placed the way `finds` is (`lib.rs:843-846`, itself right after
/// `Host::finds`'s own doc comment, before `installed: Vec<String>,` at
/// `lib.rs:850`), and initialised in `Host::new`'s `Ok(Self { ... })` block
/// the way `finds: std::collections::HashMap::new(),` is (`lib.rs:1279`) --
/// `tfscan: shims::tfscan::TfScan::default(),`. It also needs
/// `pub mod tfscan;` added to `shims/mod.rs` alongside the other `pub mod`
/// lines there (`shims/mod.rs:3-14`) -- without it this file is not part of
/// the crate at all. Neither edit is made here; both are exactly the two
/// changes the task asked to be reported rather than made.
#[derive(Debug, Default)]
pub(crate) struct TfScan {
    /// Where the scan's FSM currently is. `Default` is [`State::Dun`] (the
    /// hand-written `impl Default for State` above, next to [`State`]
    /// itself), which is right: a `Host` nobody has called `tfsopn` on yet
    /// has no scan running, and `tfsrdl()` on it should behave exactly like
    /// a scan that already ran out -- see [`tfsrdl`]'s own doc comment.
    state: State,
    /// Files `tfsopn` matched, sorted, most-recently-opened first popped.
    /// Emptied as [`tfsrdl`] walks it; refilled wholesale by the next
    /// `tfsopn`, which is also what makes calling `tfsopn` again mid-scan
    /// safe -- see [`tfsopn`]'s own doc comment on `BBSMAINM.C`'s two-pass
    /// `gappnams`.
    pending: VecDeque<PathBuf>,
    /// The file [`State::Bof`]/[`State::Lin`] are reading from, or `None` in
    /// every other state.
    current: Option<BufReader<File>>,
    /// `current`'s path, kept only so an I/O error midway through a file
    /// names which one in its message. Not `tfsfb` -- see this file's module
    /// doc for why that global is not placed at all.
    current_path: Option<PathBuf>,
    /// The line [`advance`] just read, handed off for [`tfsrdl`] to write
    /// into module memory as `tfsbuf`. Set exactly when [`advance`] returns
    /// [`State::Lin`], and taken (emptied) by the caller that reads it --
    /// `advance` itself never touches module memory (see its own doc
    /// comment for why it stays free of `A`), so the line has to cross that
    /// boundary through host-side state rather than a return value typed
    /// `abi::Ret<A>`.
    pending_line: Option<Vec<u8>>,
}

/// `int tfsopn(char *fname)` -- match `fname` (a bare 8.3 name or wildcard
/// spec, `TFSCAN.H:28`'s "may NOT use path prefix") against every file in the
/// board's own directory, and answer how many matched.
///
/// # Path rule
///
/// `TFSCAN.H`'s own top comment (quoted whole in this file's module doc) is
/// explicit that a scan must "stay in the current directory (no path
/// prefixes)" -- a *stricter* rule than [`Host::dos_name`]'s, which (as of
/// the `fopen`/`fnd1st` widening its own doc comment describes,
/// `lib.rs:1330-1347`) now accepts a relative subdirectory. `tfsopn` still
/// refuses one: `Host::dos_name` is run first, for the escapes it is the one
/// place that checks (a drive letter, an absolute path, a `..` anywhere), and
/// its answer is then refused a second time if it contains `/` at all --
/// `Host::dos_name` normalises `\` to `/`, so that one check catches either
/// spelling of a subdirectory the same way `TFSCAN.H` says to.
///
/// "The current directory" is [`Host::root`], for the same reason
/// `shims::stream::fopen`'s own doc comment gives for the identical phrase in
/// its own path rule -- both are the one directory this host ever resolves a
/// bare module filename against.
///
/// # Matching
///
/// Built on [`dos::Name::spec`]/[`dos::Name::parse`]/[`dos::Name::matches`] --
/// the same primitives `shims::stream::fnd1st` uses for its own wildcard
/// scan (`shims/stream.rs:1007-1074`), for the same DOS 8.3, case-insensitive
/// reading. Only *files* match; `TFSCAN.H`'s comment calls this "text file
/// scanning routines" and `tfsopn` takes no attribute byte the way `fnd1st`'s
/// `attr` admits directories, so there is no reading under which a
/// subdirectory should ever be one of the "# of files" returned.
///
/// Matches are sorted by DOS name before being queued, the same
/// determinism-over-a-real-FAT-directory-order reasoning
/// [`crate::shims::stream::fnd1st`]'s own doc comment gives ("Scan state")
/// for doing the identical sort.
///
/// # Re-opening mid-scan, or after one finished, is not a bug
///
/// `BBSMAINM.C:1014-1034`'s `gappnams` calls `tfsopn("MJRBBS.CFG")` twice in
/// the same routine, back to back, the second time to re-walk a scan the
/// first `tfsopn`/`tfsrdl` loop already ran to `TFSDUN`. So a second
/// `tfsopn` -- whether the first scan is exhausted, mid-flight, or was never
/// drained at all -- has to discard whatever the running scan held and start
/// clean, which is what this does: `host.tfscan` is replaced outright, which
/// drops any open `BufReader<File>` (closing it) and any undrained
/// `pending` queue. Real DOS would have leaked or reused a file handle here
/// in ways this host has no reason to reproduce; "close what was open,
/// start fresh" is the same non-leaking choice
/// `shims::stream::fopen`'s own doc comment made for a stale cookie.
///
/// # `tfstate` after this call
///
/// Always [`State::Bgn`] (`TFSBGN`, 1) -- `TFSCAN.H:36`'s own definition of
/// the constant is "`tfsopn()` has been called, `tfsrdl()` calls will
/// begin", unconditionally, not "...if it found anything". A `tfsopn` that
/// matched nothing still leaves `tfsrdl()` free to be called (and it answers
/// `TFSDUN` immediately, per [`tfsrdl`]'s own doc comment) -- the same shape
/// `MAJORBBS.C:726-734`'s `if (tfsopn("MJRBBS.CFG") == 0) catastro(...)`
/// implies: the caller decides whether zero files is fatal, `tfsopn` itself
/// does not refuse it.
///
/// # Errors
///
/// If `fname` cannot be read as a C string, if [`Host::dos_name`] refuses it
/// (a drive letter, an absolute path, a `..`), if it names a subdirectory at
/// all, if it is not a spec DOS could have parsed
/// ([`dos::Name::spec`](crate::dos::Name::spec)'s own rule), if the board
/// root cannot be listed, or if more than 65,535 files matched (an `int`
/// cannot report more, and guessing which subset of them to report would be
/// exactly the plausible-but-wrong answer this crate exists to refuse).
pub fn tfsopn<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `int tfsopn(char *fname)` -- `TFSCAN.H:27-28`, quoted whole in this
    // file's own module doc.
    let fname = call.ptr();
    let named = String::from_utf8_lossy(
        fname.read_cstr(call.mem()).map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();

    let name = Host::<Wg16>::dos_name(&named).map_err(ShimError::Failed)?;
    if name.contains('/') {
        return Err(ShimError::Failed(format!(
            "tfsopn({named}): TFSCAN.H's own comment is explicit that a scan \
             must stay in the current directory -- no path prefixes"
        )));
    }
    let spec = dos::Name::spec(&name)
        .map_err(|why| ShimError::Failed(format!("tfsopn({named}): {why}")))?;

    let entries = std::fs::read_dir(&host.root)
        .map_err(|e| ShimError::Failed(format!("tfsopn({named}): {}: {e}", host.root.display())))?;

    let mut matches: Vec<(dos::Name, PathBuf)> = Vec::new();
    for entry in entries {
        let entry = entry
            .map_err(|e| ShimError::Failed(format!("tfsopn({named}): {}: {e}", host.root.display())))?;
        let found = entry.file_name();
        let found = found.to_string_lossy();

        // A name DOS could not have written down is one no real tfsopn scan
        // could have matched -- same reading `fnd1st`'s own doc comment
        // gives for the identical skip.
        let Some(parsed) = dos::Name::parse(&found) else {
            continue;
        };
        if !spec.matches(&parsed) {
            continue;
        }

        let path = entry.path();
        if !path.is_file() {
            // Directories, and anything else that is not a plain file
            // (sockets, device nodes), never match -- see this doc
            // comment's own "Matching" section.
            continue;
        }
        matches.push((parsed, path));
    }
    matches.sort_by(|a, b| a.0.display().cmp(&b.0.display()));

    let count = u16::try_from(matches.len()).map_err(|_| {
        ShimError::Failed(format!(
            "tfsopn({named}): matched {} files, more than an int can report",
            matches.len()
        ))
    })?;

    host.tfscan = TfScan {
        state: State::Bgn,
        pending: matches.into_iter().map(|(_, path)| path).collect(),
        ..TfScan::default()
    };

    host
        .globals()
        .write_int_mem(call.mem(), "tfstate", u32::from(State::Bgn.code()))
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    Ok(abi::Ret::Int(A::Int::from(count)))
}

/// `int tfsrdl(void)` -- advance the scan one step, and answer the new
/// `tfstate`.
///
/// # The state machine, inferred from `TFSCAN.H`'s own codes and every call
/// site
///
/// No vendor `.C` survives for this routine -- see this file's own module
/// doc, "There is no vendor `.C` for this file in the archive". What follows
/// is built from `TFSCAN.H:35-39`'s own definitions of what each code
/// *means* (quoted whole in the module doc) plus what every call site does
/// with them:
///
/// - **`TFSBGN` -> `TFSBOF`.** The first call after `tfsopn` opens the first
///   matched file (or, if none matched, answers `TFSDUN` outright -- see
///   below) and answers `TFSBOF`, "about to start a new file", without
///   having read a line from it yet.
/// - **`TFSBOF` -> `TFSLIN` or `TFSEOF`.** The next call reads the file's
///   first line. A file with at least one line answers `TFSLIN`, with the
///   line in `tfsbuf`; an empty file answers `TFSEOF` immediately, having
///   read nothing.
/// - **`TFSLIN` -> `TFSLIN` or `TFSEOF`.** Every call after that reads the
///   next line the same way, until the file runs out, at which point the
///   file is closed and the call answers `TFSEOF`.
/// - **`TFSEOF` -> `TFSBOF` or `TFSDUN`.** The call after a file finishes
///   either opens the next matched file (`TFSBOF` again) or, if none is
///   left, finishes the whole scan (`TFSDUN`).
/// - **`TFSDUN` -> `TFSDUN`.** Once finished, further calls keep answering
///   `TFSDUN` -- the same "already finished is not a refusal" reading
///   `shims::stream::fndnxt`'s own doc comment gives a stale scan (its
///   "Errors" section: "never started" is a host bug, refused; "started and
///   finished" is an ordinary `0`). `tfsrdl` draws the identical line: a
///   `Host` nobody ever called `tfsopn` on defaults to [`State::Dun`] (see
///   [`TfScan`]'s own doc comment on its `Default`), so "never opened" and
///   "opened and exhausted" are the same, ordinary, non-refusing answer.
///
/// This gives the `switch (tfstate) { case TFSLIN: ... }` at
/// `MAJORBBS.C:955-962` somewhere real to land on cases it does not list
/// (`TFSBGN`/`TFSBOF`/`TFSEOF` all fall through and do nothing there), which
/// a design that only ever produced `TFSLIN`/`TFSDUN` would not.
///
/// # What "a line" is -- inferred, not measured
///
/// Bytes up to (and not including) the next `\n`, with one trailing `\r`
/// also stripped if present (so a DOS `\r\n`-terminated file reads the same
/// as a bare-`\n` one), truncated to fit `tfsbuf`'s own placed size minus one
/// byte (leaving room for the NUL), and NUL-terminated. None of this is
/// measured against a vendor binary; it is the ordinary "getline" reading no
/// call site's use of `tfsbuf`/`tfspst` contradicts -- `BBSMAINM.C:1032-1033`
/// pulls a second field *out of* a line with `skpwht(skpwrd(tfspst))`, which
/// only makes sense if the line arrived without its own trailing newline
/// glued on the end. `fgets`'s own doc comment
/// (`shims::stream::fgets`, "the newline is kept") is Borland's own,
/// measured, and deliberately different: `tfsrdl` is not `fgets`, and
/// nothing here claims the two share a convention just because both read
/// lines.
///
/// # `tfsfp` is not written
///
/// `TFSCAN.H:25`'s `tfsfp` is a `FILE *`, and this crate's `FILE *` is
/// [`crate::stream::Streams`]'s own cookie space (see
/// `shims::stream::fopen`'s doc comment). Nothing in the surveyed call sites
/// reads `tfsfp`, and it is not among the globals `crate::globals::GLOBALS`
/// places (`tfstate`/`tfspst`/`tfsbuf` are; `tfsfb`/`tfsfp` are not) -- see
/// this file's own module doc for the citation. Minting a `Streams` cookie
/// nothing can read would be inventing state to match a struct field no
/// caller uses, which is the opposite of this crate's own rule about
/// plausible-looking answers nobody asked for.
///
/// # Errors
///
/// If a matched file cannot be opened or read -- a file `tfsopn` saw moments
/// ago that a concurrent process then removed or made unreadable, which this
/// host reports rather than silently skipping.
pub fn tfsrdl<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `int tfsrdl(void)` -- `TFSCAN.H:29`, quoted whole in this file's own
    // module doc. No arguments to read off `call`.
    let next = advance(host)?;

    if let State::Lin = next {
        // Safe to `.expect`: `tfsbuf` is placed by `crate::globals::GLOBALS`
        // (`globals.rs:218`) unconditionally, not something this file adds --
        // see `TfScan`'s own doc comment on what *is* left for `Host` to
        // grow. A missing `tfsbuf` is a host build error, not a module input.
        let cap = host.globals().size("tfsbuf").expect("tfsbuf is placed by globals.rs") as usize;

        // `TfScan::pending_line` was just filled by `advance`'s `Bof`/`Lin`
        // arm with the line this state transition read.
        let mut line = host
            .tfscan
            .pending_line
            .take()
            .expect("advance() only returns State::Lin after stashing the line it read");

        line.truncate(cap.saturating_sub(1));
        line.push(0);
        host
            .globals()
            .write_mem(call.mem(), "tfsbuf", &line)
            .map_err(|e| ShimError::Failed(e.to_string()))?;
    }

    host
        .globals()
        .write_int_mem(call.mem(), "tfstate", u32::from(next.code()))
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    Ok(abi::Ret::Int(A::Int::from(next.code())))
}

/// One step of [`tfsrdl`]'s state machine -- see that function's own doc
/// comment for what each transition means and why. Split out so `tfsrdl`
/// itself only has to handle the one cross-cutting piece every transition
/// shares (writing `tfstate`), not the FSM's branching.
///
/// On a transition into [`State::Lin`], the line just read is left in
/// `host.tfscan.pending_line` for [`tfsrdl`] to write into `tfsbuf` --
/// `advance` itself never touches module memory, so it stays a plain
/// `Result<State, ShimError>` and does not need `A` at all.
fn advance<A: Abi>(host: &mut Host<A>) -> Result<State, ShimError> {
    match host.tfscan.state {
        State::Dun => Ok(State::Dun),

        State::Bgn | State::Eof => match host.tfscan.pending.pop_front() {
            None => {
                host.tfscan.state = State::Dun;
                host.tfscan.current = None;
                host.tfscan.current_path = None;
                Ok(State::Dun)
            }
            Some(path) => {
                let file = File::open(&path)
                    .map_err(|e| ShimError::Failed(format!("tfsrdl({}): {e}", path.display())))?;
                host.tfscan.current = Some(BufReader::new(file));
                host.tfscan.current_path = Some(path);
                host.tfscan.state = State::Bof;
                Ok(State::Bof)
            }
        },

        State::Bof | State::Lin => {
            let named = host
                .tfscan
                .current_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            let reader = host
                .tfscan
                .current
                .as_mut()
                .ok_or_else(|| ShimError::Failed(format!("tfsrdl({named}): scan lost its own open file")))?;

            let mut raw = Vec::new();
            let n = reader
                .read_until(b'\n', &mut raw)
                .map_err(|e| ShimError::Failed(format!("tfsrdl({named}): {e}")))?;

            if n == 0 {
                host.tfscan.current = None;
                host.tfscan.current_path = None;
                host.tfscan.state = State::Eof;
                return Ok(State::Eof);
            }

            if raw.last() == Some(&b'\n') {
                raw.pop();
            }
            if raw.last() == Some(&b'\r') {
                raw.pop();
            }

            host.tfscan.pending_line = Some(raw);
            host.tfscan.state = State::Lin;
            Ok(State::Lin)
        }
    }
}

/// `int tfspfx(char *prefix)` -- is the current line (`tfsbuf`) prefixed with
/// `prefix`?
///
/// # What this reads
///
/// `tfsbuf` itself, off module memory, not a host-side copy -- there is no
/// host-side copy of the line, on purpose (see [`tfsrdl`]'s own doc comment,
/// "`tfsfp` is not written", for the same reasoning applied there: the
/// module-visible global is the one and only copy). `PLBBS.C:69-92`'s
/// `setbparm` tests two different prefixes against what has to be the same
/// line (`tfspfx("BREQUEST")`, and in the `else`, `tfspfx("BTRIEVE >NUL")`),
/// so `tfspfx` cannot consume or otherwise mutate `tfsbuf` -- it only reads
/// it, which reading straight from the global (rather than from some
/// `tfsrdl`-owned buffer that `tfsrdl` might already have moved past) makes
/// automatic.
///
/// # Matching -- inferred, not measured
///
/// Case-sensitive, exact byte prefix. Every prefix any surveyed call site
/// passes is upper-case shouting-case config syntax -- `"NEEDED4 "`,
/// `"CSTART="`, `"APP="`, `"DLL="`, `"BREQUEST"`, `"BTRIEVE >NUL"`,
/// `"DBGMEM {"` -- the convention DOS-era config files wrote directives in,
/// and none of it reads as a place that wanted `sameto`'s case-folding
/// (`crate::shims::text::sameto`) rather than a literal `strncmp`.
///
/// # `tfspst` on a match
///
/// `TFSCAN.H:21`'s own comment: "when `tfspfx()` returns 1, this is
/// `spkwht(what follows it)`". No `spkwht` symbol exists anywhere in this
/// archive (checked: `archive/`, `crates/`, `re/`) -- read as the vendor's
/// own shorthand/typo for `skpwht`, the skip-leading-spaces primitive this
/// crate already has at [`crate::strings::skpwht`] (and which
/// `BBSMAINM.C:1033` itself calls by that correct spelling, on a `tfspst`
/// result, in the very tree this header comes from: `skpwht(skpwrd(tfspst))`
/// only makes sense if a genuine `skpwht` is the intended reading of the
/// header's `spkwht`). So `tfspst` is set to a pointer into `tfsbuf`, past
/// `prefix` and then past every leading `crate::strings::skpwht`-defined
/// space (**a literal `0x20` only, not every whitespace byte** -- see that
/// function's own doc comment for why a tab does not count).
///
/// On a non-match, `tfspst` is left untouched -- nothing measured or cited
/// says a failed match clears it, and `PLBBS.C`'s two-prefix `setbparm`
/// above never reads `tfspst` after the branch that did not match, so there
/// is no evidence either way; leaving it alone is the smaller behaviour to
/// guess wrong about.
///
/// # Errors
///
/// If `prefix` cannot be read as a C string, or if the pointer arithmetic
/// for `tfspst` would leave the address space this ABI's own pointer can
/// name (`Abi::ptr_checked_add`'s own refusal -- the same one
/// `shims::text`'s private `at` helper uses for `skpwht`/`skpwrd`'s
/// identical "a pointer into the caller's own buffer" case).
pub fn tfspfx<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `int tfspfx(char *prefix)` -- `TFSCAN.H:30`, quoted whole in this
    // file's own module doc.
    let prefix_ptr = call.ptr();
    let prefix = prefix_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    // Safe to `.expect`: see `tfsrdl`'s identical `.expect` on this same
    // lookup for why `tfsbuf` being placed is a host invariant, not
    // something a module input can falsify.
    let tfsbuf_addr = host.globals().address("tfsbuf").expect("tfsbuf is placed by globals.rs");
    let cap = host.globals().size("tfsbuf").expect("tfsbuf is placed by globals.rs") as usize;

    let raw = tfsbuf_addr
        .resolve(call.mem(), cap)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let line_len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let line = &raw[..line_len];

    if !line.starts_with(prefix.as_slice()) {
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    }

    let after = &line[prefix.len()..];
    let skip = crate::strings::skpwht(after);
    let offset = prefix.len() + skip;

    let pst = A::ptr_checked_add(tfsbuf_addr, offset).ok_or_else(|| {
        ShimError::Failed(format!(
            "tfspfx: {offset} bytes past tfsbuf overflows the address space this ABI's own pointer can name"
        ))
    })?;
    host
        .globals()
        .write_mem(call.mem(), "tfspst", &A::ptr_to_bytes(pst))
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    Ok(abi::Ret::Int(A::Int::from(1u16)))
}

/// `void tfsabt(void)` -- abort file scanning.
///
/// Closes whatever file is open, drops every file still queued, and resets
/// the scan to [`State::Dun`] -- the same "future `tfsrdl()` calls answer
/// `TFSDUN`, exactly as though the scan had run to completion on its own"
/// behaviour finishing a scan normally leaves. `tfstate` is written to match
/// (`TFSDUN`, 0), on the same "the module-visible mirror never lags the
/// host-side truth" principle every other write in this file follows -- a
/// module that called `tfsabt()` and then, unusually, went on to test
/// `tfstate` itself rather than just stopping its loop should see the scan
/// really is over.
///
/// `tfsbuf`/`tfspst` are left as whatever they last held. Nothing surveyed
/// says an abort scrubs the last line read, and a module that just called
/// `tfsabt()` because it found what it wanted (the ordinary reason to abort
/// a scan early) may still want that line a moment longer.
///
/// # Errors
///
/// Never, beyond the same "the host's own `tfstate` global went missing"
/// build error [`tfsrdl`]/[`tfspfx`] would also raise, which cannot happen
/// once `Host` is wired up (see [`TfScan`]'s own doc comment).
pub fn tfsabt<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `void tfsabt(void)` -- `TFSCAN.H:32`, quoted whole in this file's own
    // module doc. No arguments to read off `call`, and no value to return.
    host.tfscan = TfScan::default();
    host
        .globals()
        .write_int_mem(call.mem(), "tfstate", u32::from(State::Dun.code()))
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Void)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mbbs_machine::m16::{FarPtr, Ret};

    use crate::testing::{Fixture, scratch};

    fn word(ret: Ret) -> u16 {
        match ret {
            Ret::U16(n) => n,
            _ => panic!("expected an int"),
        }
    }

    /// `tfsopn(fname)`.
    fn tfsopn_(f: &mut Fixture, pattern: &str) -> Result<Ret, ShimError> {
        let name = f.text(pattern);
        f.invoke(tfsopn, &Fixture::far(name))
    }

    /// `tfsrdl()`.
    fn tfsrdl_(f: &mut Fixture) -> Result<Ret, ShimError> {
        f.invoke(tfsrdl, &[])
    }

    /// `tfspfx(prefix)`.
    fn tfspfx_(f: &mut Fixture, prefix: &str) -> Result<Ret, ShimError> {
        let p = f.text(prefix);
        f.invoke(tfspfx, &Fixture::far(p))
    }

    /// `tfsabt()`.
    fn tfsabt_(f: &mut Fixture) -> Result<Ret, ShimError> {
        f.invoke(tfsabt, &[])
    }

    /// `tfstate`, read straight out of module memory.
    fn tfstate(f: &Fixture) -> u16 {
        f.host.globals().word(&f.machine, "tfstate").expect("tfstate is a placed global")
    }

    /// `tfsbuf`, read straight out of module memory, as a C string.
    fn tfsbuf(f: &Fixture) -> String {
        let at = f.host.globals().address("tfsbuf").expect("tfsbuf is a placed global");
        String::from_utf8_lossy(f.machine.read_cstr(at).expect("readable")).into_owned()
    }

    /// `tfspst`'s four raw bytes -- the pointer itself, not what it points at.
    /// Used to prove a non-match leaves it untouched, byte for byte.
    fn tfspst_bytes(f: &Fixture) -> [u8; 4] {
        let at = f.host.globals().address("tfspst").expect("tfspst is a placed global");
        f.machine.resolve(at, 4).expect("in bounds").try_into().expect("4 bytes")
    }

    /// `tfspst`, dereferenced and read as a C string -- what `tfspfx` left a
    /// module free to pass straight to another string-consuming routine.
    fn tfspst_text(f: &Fixture) -> String {
        let ptr = FarPtr::from_bytes(tfspst_bytes(f));
        String::from_utf8_lossy(f.machine.read_cstr(ptr).expect("readable")).into_owned()
    }

    // ---- tfsopn -------------------------------------------------------------

    #[test]
    fn tfsopn_matches_a_wildcard_and_always_leaves_tfstate_at_tfsbgn() {
        let root = scratch("tfscan-opn-count");
        std::fs::write(root.join("ALPHA.TXT"), b"a\n").expect("a file");
        std::fs::write(root.join("BETA.TXT"), b"b\n").expect("a file");
        std::fs::write(root.join("OTHER.DAT"), b"c\n").expect("a file");
        let mut f = Fixture::rooted(root);

        assert_eq!(word(tfsopn_(&mut f, "*.TXT").expect("tfsopn")), 2);
        // TFSCAN.H:36's own definition: TFSBGN unconditionally, not
        // "...if it found anything" -- see `tfsopn`'s own doc comment.
        assert_eq!(tfstate(&f), 1, "TFSBGN");
    }

    #[test]
    fn tfsopn_matching_nothing_still_sets_tfsbgn_and_tfsrdl_answers_tfsdun_at_once() {
        let root = scratch("tfscan-opn-none");
        let mut f = Fixture::rooted(root);

        assert_eq!(word(tfsopn_(&mut f, "*.XYZ").expect("tfsopn")), 0);
        assert_eq!(tfstate(&f), 1, "TFSBGN even though nothing matched");

        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 0, "TFSDUN");
        assert_eq!(tfstate(&f), 0, "TFSDUN");
    }

    #[test]
    fn tfsopn_refuses_a_name_with_a_path_prefix() {
        // TFSCAN.H's own top comment: "stay in the current directory (no
        // path prefixes)".
        let mut f = Fixture::new();
        let e = tfsopn_(&mut f, "SUB/FILE.TXT").expect_err("a refusal");
        assert!(e.to_string().contains("path prefixes"), "{e}");
    }

    // ---- tfsrdl's state machine ---------------------------------------------

    #[test]
    fn tfsrdl_walks_bgn_bof_lin_eof_across_two_files_then_dun_and_stays_there() {
        let root = scratch("tfscan-rdl-two-files");
        std::fs::write(root.join("ALPHA.TXT"), b"one\ntwo\n").expect("a file");
        std::fs::write(root.join("BETA.TXT"), b"three\n").expect("a file");
        let mut f = Fixture::rooted(root);
        assert_eq!(word(tfsopn_(&mut f, "*.TXT").expect("tfsopn")), 2);

        // ALPHA.TXT, sorted first.
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 2, "TFSBOF: about to start ALPHA.TXT");
        assert_eq!(tfstate(&f), 2);

        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 3, "TFSLIN");
        assert_eq!(tfstate(&f), 3);
        assert_eq!(tfsbuf(&f), "one");

        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 3, "TFSLIN, second line");
        assert_eq!(tfsbuf(&f), "two");

        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 4, "TFSEOF: ALPHA.TXT ran out");
        assert_eq!(tfstate(&f), 4);

        // BETA.TXT, sorted second.
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 2, "TFSBOF: about to start BETA.TXT");
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 3, "TFSLIN");
        assert_eq!(tfsbuf(&f), "three");
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 4, "TFSEOF: BETA.TXT ran out");

        // No file left: the whole scan is done.
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 0, "TFSDUN");
        assert_eq!(tfstate(&f), 0);
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 0, "TFSDUN stays TFSDUN");
    }

    #[test]
    fn tfsrdl_of_an_empty_file_answers_tfseof_immediately_with_no_line() {
        let root = scratch("tfscan-rdl-empty");
        std::fs::write(root.join("EMPTY.TXT"), b"").expect("an empty file");
        let mut f = Fixture::rooted(root);
        assert_eq!(word(tfsopn_(&mut f, "*.TXT").expect("tfsopn")), 1);

        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 2, "TFSBOF");
        assert_eq!(
            word(tfsrdl_(&mut f).expect("tfsrdl")),
            4,
            "TFSEOF straight away, never TFSLIN"
        );
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 0, "TFSDUN");
    }

    #[test]
    fn tfsrdl_strips_a_trailing_crlf_and_reads_a_final_line_with_no_newline() {
        let root = scratch("tfscan-rdl-crlf");
        std::fs::write(root.join("CRLF.TXT"), b"abc\r\ndef").expect("a file");
        let mut f = Fixture::rooted(root);
        assert_eq!(word(tfsopn_(&mut f, "*.TXT").expect("tfsopn")), 1);

        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 2, "TFSBOF");
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 3);
        assert_eq!(tfsbuf(&f), "abc", "the \\r\\n is gone, not just the \\n");

        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 3, "the file's last line, unterminated");
        assert_eq!(tfsbuf(&f), "def");

        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 4, "TFSEOF");
    }

    #[test]
    fn tfsrdl_truncates_a_line_longer_than_tfsbufs_128_byte_capacity() {
        // MAXTFS is 129 (globals.rs), so 128 bytes of content plus a NUL.
        let root = scratch("tfscan-rdl-long-line");
        let content = format!("{}\n", "A".repeat(200));
        std::fs::write(root.join("LONG.TXT"), content.as_bytes()).expect("a file");
        let mut f = Fixture::rooted(root);
        assert_eq!(word(tfsopn_(&mut f, "*.TXT").expect("tfsopn")), 1);

        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 2);
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 3);
        let got = tfsbuf(&f);
        assert_eq!(got.len(), 128, "truncated to tfsbuf's capacity minus the NUL");
        assert_eq!(got, "A".repeat(128));
    }

    // ---- tfsopn discarding a live scan --------------------------------------

    #[test]
    fn tfsopn_called_again_mid_scan_discards_the_live_scan_and_starts_the_new_pattern_fresh() {
        let root = scratch("tfscan-opn-reopen-mid-scan");
        std::fs::write(root.join("ALPHA.TXT"), b"hello\n").expect("a file");
        std::fs::write(root.join("BETA.DAT"), b"data\n").expect("a file");
        let mut f = Fixture::rooted(root);

        assert_eq!(word(tfsopn_(&mut f, "*.TXT").expect("tfsopn")), 1);
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 2, "TFSBOF on ALPHA.TXT");
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 3, "mid-file, ALPHA.TXT open");
        assert_eq!(tfsbuf(&f), "hello");

        // BBSMAINM.C:1014-1034's own shape: tfsopn called again while a scan
        // is still running.
        assert_eq!(word(tfsopn_(&mut f, "*.DAT").expect("tfsopn")), 1);
        assert_eq!(tfstate(&f), 1, "TFSBGN immediately after the second tfsopn");

        // If the old scan had merely been left running underneath, this
        // would still read from ALPHA.TXT.
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 2, "TFSBOF on BETA.DAT, not ALPHA.TXT");
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 3);
        assert_eq!(tfsbuf(&f), "data", "reading the NEW pattern's file");
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 4);
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 0);
    }

    #[test]
    fn tfsopn_of_the_same_pattern_after_a_full_scan_restarts_from_the_top() {
        // BBSMAINM.C:1014-1034's `gappnams`: the identical `tfsopn` name
        // called a second time, once the first scan has already run to
        // TFSDUN, has to walk the file again from its first line.
        let root = scratch("tfscan-opn-reopen-same-pattern");
        std::fs::write(root.join("X.CFG"), b"one\ntwo\n").expect("a file");
        let mut f = Fixture::rooted(root);

        assert_eq!(word(tfsopn_(&mut f, "*.CFG").expect("tfsopn")), 1);
        // Drain the first pass to TFSDUN.
        while word(tfsrdl_(&mut f).expect("tfsrdl")) != 0 {}
        assert_eq!(tfstate(&f), 0);

        assert_eq!(word(tfsopn_(&mut f, "*.CFG").expect("tfsopn")), 1, "same count, second pass");
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 2, "TFSBOF again");
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 3);
        assert_eq!(tfsbuf(&f), "one", "back at the top, not still exhausted");
    }

    // ---- tfsabt ---------------------------------------------------------------

    #[test]
    fn tfsabt_mid_scan_then_tfsrdl_behaves_like_an_already_exhausted_scan() {
        let root = scratch("tfscan-abt-mid-scan");
        std::fs::write(root.join("ONE.TXT"), b"a\nb\n").expect("a file");
        std::fs::write(root.join("TWO.TXT"), b"c\n").expect("a file");
        let mut f = Fixture::rooted(root);

        assert_eq!(word(tfsopn_(&mut f, "*.TXT").expect("tfsopn")), 2);
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 2, "TFSBOF");
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 3, "TFSLIN, mid ONE.TXT");
        assert_eq!(tfsbuf(&f), "a");

        assert!(matches!(tfsabt_(&mut f).expect("tfsabt"), Ret::Void));
        assert_eq!(tfstate(&f), 0, "TFSDUN written immediately");

        // Not "b" (the next line of the aborted file) -- the scan is over.
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 0, "TFSDUN");
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 0, "still TFSDUN");
    }

    // ---- tfspfx -----------------------------------------------------------

    #[test]
    fn tfspfx_reads_tfsbuf_live_from_module_memory_not_a_host_side_copy() {
        // A host that cached the line `advance()` last read, rather than
        // re-reading `tfsbuf` on every call, would still see "BREQUEST FOO"
        // here after the buffer was overwritten out from under it.
        let root = scratch("tfscan-pfx-live-read");
        std::fs::write(root.join("LINE.TXT"), b"BREQUEST FOO\n").expect("a file");
        let mut f = Fixture::rooted(root);
        assert_eq!(word(tfsopn_(&mut f, "*.TXT").expect("tfsopn")), 1);
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 2);
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 3);
        assert_eq!(tfsbuf(&f), "BREQUEST FOO");

        // Overwrite tfsbuf directly, bypassing tfsrdl entirely.
        f.host
            .globals()
            .write(&mut f.machine, "tfsbuf", b"ZEBRA BAR\0")
            .expect("seed tfsbuf directly");

        assert_eq!(
            word(tfspfx_(&mut f, "BREQUEST").expect("tfspfx")),
            0,
            "the old prefix no longer matches the new content"
        );
        assert_eq!(
            word(tfspfx_(&mut f, "ZEBRA").expect("tfspfx")),
            1,
            "the new content matches a prefix tfsrdl never saw"
        );
        assert_eq!(tfspst_text(&f), "BAR");
    }

    #[test]
    fn tfspfx_tests_two_different_prefixes_against_the_same_line_without_mutating_it() {
        // PLBBS.C:69-92's own `setbparm`: two different prefixes, tested
        // against the same current line, one after the other.
        let root = scratch("tfscan-pfx-two-prefixes");
        std::fs::write(root.join("BTR.BAT"), b"BTRIEVE >NUL extra_arg\n").expect("a file");
        let mut f = Fixture::rooted(root);
        assert_eq!(word(tfsopn_(&mut f, "*.BAT").expect("tfsopn")), 1);
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 2);
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 3);

        assert_eq!(word(tfspfx_(&mut f, "BREQUEST").expect("tfspfx")), 0, "first prefix: no match");
        assert_eq!(
            word(tfspfx_(&mut f, "BTRIEVE >NUL").expect("tfspfx")),
            1,
            "second prefix, same line: matches"
        );
        assert_eq!(tfspst_text(&f), "extra_arg");
        assert_eq!(tfsbuf(&f), "BTRIEVE >NUL extra_arg", "neither call mutated tfsbuf");
    }

    #[test]
    fn tfspfx_is_case_sensitive() {
        let root = scratch("tfscan-pfx-case");
        std::fs::write(root.join("CASE.TXT"), b"needed4 lower\n").expect("a file");
        let mut f = Fixture::rooted(root);
        assert_eq!(word(tfsopn_(&mut f, "*.TXT").expect("tfsopn")), 1);
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 2);
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 3);

        assert_eq!(
            word(tfspfx_(&mut f, "NEEDED4 ").expect("tfspfx")),
            0,
            "the vendor's own shouting-case prefix does not match a lower-case line"
        );
        assert_eq!(word(tfspfx_(&mut f, "needed4 ").expect("tfspfx")), 1);
        assert_eq!(tfspst_text(&f), "lower");
    }

    #[test]
    fn tfspfx_skips_a_literal_space_after_the_prefix_but_not_a_tab() {
        // `crate::strings::skpwht`: a literal 0x20 only, not every
        // whitespace byte -- see `tfspfx`'s own doc comment.
        let root = scratch("tfscan-pfx-skpwht");
        std::fs::write(root.join("TAB.CFG"), b"DLL=\tFOO.DLL\n").expect("a file");
        let mut f = Fixture::rooted(root);
        assert_eq!(word(tfsopn_(&mut f, "*.CFG").expect("tfsopn")), 1);
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 2);
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 3);

        assert_eq!(word(tfspfx_(&mut f, "DLL=").expect("tfspfx")), 1);
        assert_eq!(tfspst_text(&f), "\tFOO.DLL", "a tab is not skipped, only a literal space");
    }

    #[test]
    fn tfspfx_leaves_tfspst_untouched_on_a_non_match() {
        let root = scratch("tfscan-pfx-untouched");
        std::fs::write(root.join("MATCH.TXT"), b"MATCH123\n").expect("a file");
        let mut f = Fixture::rooted(root);
        assert_eq!(word(tfsopn_(&mut f, "*.TXT").expect("tfsopn")), 1);
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 2);
        assert_eq!(word(tfsrdl_(&mut f).expect("tfsrdl")), 3);

        assert_eq!(word(tfspfx_(&mut f, "MATCH").expect("tfspfx")), 1);
        let before = tfspst_bytes(&f);

        assert_eq!(word(tfspfx_(&mut f, "NOPE").expect("tfspfx")), 0, "does not match");
        let after = tfspst_bytes(&f);
        assert_eq!(before, after, "a failed match must not disturb tfspst");
    }
}
