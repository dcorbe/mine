//! Survey mode: an opt-in, default-**off** diagnostic that lets a running
//! host enumerate every symbol it was asked for and could not honestly
//! answer, instead of stopping at the first one.
//!
//! # This produces wrong behaviour. It exists for enumeration only.
//!
//! [`Machine::poison`](mbbs_machine::m16::Machine::poison)'s own doc says the whole
//! reason it exists: "Returning zero instead is the bug this method is here
//! to prevent." Survey mode is [`Host::run`](crate::Host::run) deliberately
//! doing that bug, under a flag, on purpose -- fabricating a return
//! (`Ret::Void`: zero in every register the module might read) for a routine
//! the module expected to do real work, and resuming as though nothing had
//! happened.
//!
//! That is **not safe for a board anyone plays on.** A module that asked
//! `alczer` for memory and got a fabricated null pointer back does not fail
//! at the call site -- it fails later, wherever it first dereferences that
//! pointer, in a way that names nothing about where the lie was told. Survey
//! mode buys the *opposite* of what [`Machine::poison`] exists to guarantee:
//! it trades an honest, attributable stop for a live count of every place
//! the host cannot yet tell the truth. That trade is worth making for
//! exactly one purpose -- a throwaway session whose only job is to produce
//! [`Inventory::render`]'s list -- and worth making for no other.
//!
//! # What this does and does not cover
//!
//! Only [`Entry::Unimplemented`](crate::Entry::Unimplemented) is ever
//! continued past, and only when [`Host::enable_survey`](crate::Host::enable_survey)
//! has been called. `Entry::Datum` and `Entry::Absolute` reaching a call
//! site mean the host has mismodelled that symbol's very *type* -- not
//! "missing", but "wrong": the module treated as a call target something
//! this host filed as a plain global or a constant. There is no shim to have
//! skipped registering and no return value to fabricate for a call that, as
//! far as this host understands the symbol, should not have been a call at
//! all. Those are recorded (see [`Kind::Datum`] and [`Kind::Absolute`]) so a
//! survey still surfaces the host's own modelling bugs, but they always
//! still stop the module, survey mode or not.
//!
//! A [`Poison::Fault`](mbbs_machine::m16::Poison::Fault) or
//! [`Poison::Timeout`](mbbs_machine::m16::Poison::Timeout) is never continued past
//! either, and cannot be: `crates/mbbs-machine/src/m16/mod.rs`'s own doc on
//! [`Machine::poisoned`](mbbs_machine::m16::Machine::poisoned) says why -- the module
//! faulted or wedged with its globals mid-update, the call frame is
//! deliberately forgotten, and there is no resume point to fabricate a
//! return into even if this crate wanted to. Those never reach this module
//! at all; [`Host::run`](crate::Host::run) reports them before it ever asks
//! `shims::entry` what a thunk index means.
//!
//! # The cleanup-convention hazard
//!
//! Resuming a module after a fabricated call requires knowing who pops that
//! call's arguments off the module's stack -- [`Cleans`](crate::Cleans). For
//! an unimplemented symbol nothing registered a [`Cleans`] for it, because
//! nothing implements it. Guessing wrong does not crash; it leaves the
//! module's stack quietly wrong, and every symbol this inventory records
//! *after* that guess is then downstream of a corrupted stack -- the survey's
//! own output would look authoritative while being fiction.
//!
//! Measured against every symbol this host *does* know the convention for
//! (`crates/mbbs/src/shims/mod.rs`'s `ROUTINES` table): 136 [`Cleans::Caller`]
//! against 10 [`Cleans::Callee`], and every `Callee` entry is one of
//! Borland's own runtime helpers, named with a trailing `@`. So
//! [`crate::shims::survey_continue_convention`] defaults to
//! [`Cleans::Caller`] -- cdecl, "what every MajorBBS routine does" -- and
//! refuses to continue at all, for anything shaped like that one exception.
//! Refusing is always safe; guessing a byte count to pop is not. See that
//! function's own doc for the full reasoning, including why `@` alone
//! cannot even be trusted to mean `Callee`.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::Path;
use std::rc::Rc;

use crate::Chan;

/// A convenience alias for what [`Host::enable_survey`](crate::Host::enable_survey)
/// takes: one inventory, shared with whatever built it.
///
/// `Rc`, not `Arc`: this host is single-threaded by force (`Machine` is
/// `!Send`; see `crates/mbbs/src/lib.rs`'s own module doc), so there is
/// never a second thread for an `Arc`'s atomics to matter to, and reaching
/// for one anyway would be claiming a guarantee this crate does not need
/// and cannot cheaply give a `!Send` neighbour.
pub type Shared = Rc<RefCell<Inventory>>;

/// Which of the three ways a module can reach something this host has not
/// modelled as a callable routine.
///
/// Kept distinct rather than flattened into one bucket: [`Kind::Unimplemented`]
/// is a routine nobody has written yet, which is exactly what a survey is
/// for. [`Kind::Datum`] and [`Kind::Absolute`] are a different fact entirely
/// -- the host's own classification of the symbol is wrong -- and conflating
/// the two would make a survey's output claim "this many routines are
/// missing" when some fraction of the count is actually "this many globals
/// are mistyped".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// Named, and not implemented. The only kind [`Host::run`](crate::Host::run)
    /// ever fabricates a continuation past.
    Unimplemented,
    /// Registered as a global the module addresses directly, but reached by
    /// a CALL instead. The host has mismodelled this symbol's type.
    Datum,
    /// Registered as a constant with no address, but reached by a CALL. The
    /// host has mismodelled this symbol's type.
    Absolute,
}

impl Kind {
    /// The word this kind renders as in [`Inventory::render`] -- stable,
    /// because a plan greps for it.
    fn label(self) -> &'static str {
        match self {
            Kind::Unimplemented => "unimplemented",
            Kind::Datum => "mismodelled-datum",
            Kind::Absolute => "mismodelled-absolute",
        }
    }
}

/// One symbol's accumulated history. Only the *first* occurrence's channel
/// and context are kept -- cheap, and enough to go find a call site; later
/// occurrences only advance `count`.
#[derive(Debug, Clone)]
struct Record {
    kind: Kind,
    ordinal: Option<u16>,
    count: u64,
    first_chan: Option<Chan>,
    first_context: Option<String>,
}

/// Everything survey mode has seen this run, and where it is being written.
///
/// See this module's own doc for what turning this on means, and
/// [`Host::enable_survey`](crate::Host::enable_survey) for how it is
/// attached. Durability is two-tier, because a live board is normally
/// stopped with a signal, not a clean shutdown, and this has to be useful
/// either way:
///
/// - [`Inventory::record`] appends one line to the output file **the moment
///   a symbol is seen for the first time**, flushed before it returns. New
///   symbols are rare once a session has run for a while, so this costs
///   nothing worth measuring. This is what a `kill -9`'d session leaves
///   behind: every distinct symbol reached, each on its own line, in
///   discovery order, every count reading `1` (true at the moment it was
///   written, however many times that symbol was actually hit afterwards).
/// - [`Inventory::finish`] overwrites the same file with the full, sorted,
///   correctly-counted inventory. Call it once, at a clean shutdown. If the
///   process never reaches it -- `kill -9`, a panic, a power loss -- what is
///   on disk is the first tier above, which is why that tier exists at all.
pub struct Inventory {
    entries: BTreeMap<(String, String), Record>,
    out: Option<File>,
}

impl Inventory {
    /// Open (creating if necessary) `path` for survey output, truncating
    /// whatever was there.
    ///
    /// Truncated rather than appended to across runs: this is one session's
    /// diagnostic, keyed to one process's lifetime, and a stale tail from an
    /// earlier run sitting behind this run's [`Inventory::finish`] rewrite
    /// (which can only ever make the file *shorter or equal*, never
    /// guaranteed to overwrite a longer previous file in full) would be
    /// silent corruption of the very thing this exists to make trustworthy.
    /// Keep a copy between sessions if the history matters.
    ///
    /// # Errors
    ///
    /// If `path` cannot be created or opened for writing.
    pub fn new(path: impl AsRef<Path>) -> io::Result<Self> {
        let out = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path.as_ref())?;
        Ok(Self {
            entries: BTreeMap::new(),
            out: Some(out),
        })
    }

    /// An inventory that only ever lives in memory -- no file, nothing to
    /// flush. For a test that wants [`Inventory::record`]'s counting and
    /// deduplication without a filesystem in the way.
    pub fn in_memory() -> Self {
        Self {
            entries: BTreeMap::new(),
            out: None,
        }
    }

    /// Record one occurrence of `(module, symbol)`. Returns whether this was
    /// the first time this inventory has ever seen that pair -- callers of
    /// this crate do not need the answer; it exists so a test can assert on
    /// it directly rather than inferring it from a line count.
    ///
    /// `ordinal`, `chan` and `context` are only ever kept for the *first*
    /// occurrence -- see [`Record`]'s own doc for why capturing them again on
    /// every repeat would not be cheap, only be redundant.
    pub(crate) fn record(
        &mut self,
        module: &str,
        symbol: &str,
        ordinal: Option<u16>,
        chan: Option<Chan>,
        context: Option<&str>,
        kind: Kind,
    ) -> bool {
        let key = (module.to_owned(), symbol.to_owned());
        if let Some(existing) = self.entries.get_mut(&key) {
            existing.count += 1;
            return false;
        }

        let record = Record {
            kind,
            ordinal,
            count: 1,
            first_chan: chan,
            first_context: context.map(str::to_owned),
        };

        if let Some(out) = &mut self.out {
            let line = format_line(&key.0, &key.1, &record);
            // Best-effort. A write failure here must not be why the module
            // this survey is observing stops -- `record` has no `Result` to
            // report one through, on purpose: the inventory is a diagnostic
            // riding along, not something the session depends on.
            let _ = out
                .seek(SeekFrom::End(0))
                .and_then(|_| writeln!(out, "{line}"))
                .and_then(|()| out.flush());
        }

        self.entries.insert(key, record);
        true
    }

    /// How many distinct symbols have been seen.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing has been recorded yet.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The total occurrences recorded for `(module, symbol)`, or `None` if
    /// it was never seen. Test-only: production code has no use for a
    /// single symbol's count in isolation, only the ranked whole
    /// ([`Inventory::render`]). `pub(crate)` rather than private so
    /// `crate::tests` (`Host::run`'s own integration tests) can use it too,
    /// not only this module's.
    #[cfg(test)]
    pub(crate) fn count_of(&self, module: &str, symbol: &str) -> Option<u64> {
        self.entries
            .get(&(module.to_owned(), symbol.to_owned()))
            .map(|r| r.count)
    }

    /// The full inventory as stable, sorted, greppable text -- one line per
    /// symbol, ranked by how often it was actually reached (most first), so
    /// the top of the file is where the highest-value gap is.
    ///
    /// Tab-separated so a plan (or `cut -f`, or `awk`) can consume it without
    /// a parser: `count kind module symbol ordinal channel context`. A
    /// missing optional field (`ordinal`, `channel`, `context`) is `-`,
    /// never an empty column, so every row has the same number of fields.
    pub fn render(&self) -> String {
        let mut rows: Vec<(&(String, String), &Record)> = self.entries.iter().collect();
        // Highest count first; ties break on (module, symbol) so the order
        // is stable across runs that saw the same set at the same counts,
        // not merely across identical `BTreeMap` iteration (which is already
        // stable, but count is the fact a reader actually wants ranked).
        rows.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(b.0)));

        let mut out = String::from("# count\tkind\tmodule\tsymbol\tordinal\tchannel\tcontext\n");
        for (key, record) in rows {
            out.push_str(&format_line(&key.0, &key.1, record));
            out.push('\n');
        }
        out
    }

    /// Overwrite the output file with [`Inventory::render`]'s full, sorted,
    /// correctly-counted text. See this struct's own doc for when to call
    /// this and what is lost if it never runs.
    ///
    /// A no-op if this inventory was built with [`Inventory::in_memory`].
    ///
    /// # Errors
    ///
    /// If the file cannot be truncated, seeked, written, or flushed.
    pub fn finish(&mut self) -> io::Result<()> {
        let text = self.render();
        let Some(out) = &mut self.out else {
            return Ok(());
        };
        out.set_len(0)?;
        out.seek(SeekFrom::Start(0))?;
        out.write_all(text.as_bytes())?;
        out.flush()
    }
}

/// One [`Inventory::render`] row, shared by the incremental append in
/// [`Inventory::record`] and the final sorted dump in [`Inventory::render`]
/// -- one format, so a reader does not have to learn two.
fn format_line(module: &str, symbol: &str, record: &Record) -> String {
    let module = if module.is_empty() { "-" } else { module };
    let ordinal = record
        .ordinal
        .map(|n| n.to_string())
        .unwrap_or_else(|| "-".to_owned());
    let chan = record
        .first_chan
        .map(|c| c.to_string())
        .unwrap_or_else(|| "-".to_owned());
    let context = record.first_context.as_deref().unwrap_or("-");
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}",
        record.count,
        record.kind.label(),
        module,
        symbol,
        ordinal,
        chan,
        context
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chan(n: i16) -> Chan {
        crate::Terms::new(n as u16 + 1)
            .chan(n)
            .expect("that many channels")
    }

    #[test]
    fn recording_a_symbol_the_first_time_says_so() {
        let mut inv = Inventory::in_memory();
        assert!(
            inv.record("MAJORBBS", "gmdnam", None, None, None, Kind::Unimplemented),
            "never seen before -- must answer true"
        );
        assert_eq!(inv.count_of("MAJORBBS", "gmdnam"), Some(1));
    }

    #[test]
    fn recording_the_same_symbol_again_says_so_and_only_advances_the_count() {
        let mut inv = Inventory::in_memory();
        inv.record("MAJORBBS", "gmdnam", None, None, None, Kind::Unimplemented);
        assert!(
            !inv.record("MAJORBBS", "gmdnam", Some(99), Some(chan(0)), Some("seg 9:0x1"), Kind::Unimplemented),
            "seen before -- must answer false"
        );
        assert_eq!(inv.count_of("MAJORBBS", "gmdnam"), Some(2));
        assert_eq!(inv.len(), 1, "one distinct symbol, however many times it was hit");
    }

    #[test]
    fn two_different_symbols_are_two_entries() {
        let mut inv = Inventory::in_memory();
        inv.record("MAJORBBS", "gmdnam", None, None, None, Kind::Unimplemented);
        inv.record("MAJORBBS", "rtihdlr", None, None, None, Kind::Unimplemented);
        assert_eq!(inv.len(), 2);
        assert_eq!(inv.count_of("MAJORBBS", "gmdnam"), Some(1));
        assert_eq!(inv.count_of("MAJORBBS", "rtihdlr"), Some(1));
    }

    #[test]
    fn datum_and_absolute_are_recorded_distinctly_from_unimplemented() {
        let mut inv = Inventory::in_memory();
        inv.record("MAJORBBS", "usrnum", None, None, None, Kind::Datum);
        inv.record("DOSCALLS", "doshugeshift", None, None, None, Kind::Absolute);
        inv.record("MAJORBBS", "gmdnam", None, None, None, Kind::Unimplemented);

        let text = inv.render();
        assert!(text.contains("\tmismodelled-datum\tMAJORBBS\tusrnum\t"), "{text}");
        assert!(
            text.contains("\tmismodelled-absolute\tDOSCALLS\tdoshugeshift\t"),
            "{text}"
        );
        assert!(text.contains("\tunimplemented\tMAJORBBS\tgmdnam\t"), "{text}");
    }

    #[test]
    fn render_ranks_by_count_then_breaks_ties_by_module_and_symbol() {
        let mut inv = Inventory::in_memory();
        inv.record("MAJORBBS", "b_once", None, None, None, Kind::Unimplemented);
        for _ in 0..5 {
            inv.record("MAJORBBS", "a_five_times", None, None, None, Kind::Unimplemented);
        }
        inv.record("MAJORBBS", "c_once", None, None, None, Kind::Unimplemented);

        let text = inv.render();
        let rows: Vec<&str> = text.lines().skip(1).collect();
        assert_eq!(
            rows,
            vec![
                "5\tunimplemented\tMAJORBBS\ta_five_times\t-\t-\t-",
                "1\tunimplemented\tMAJORBBS\tb_once\t-\t-\t-",
                "1\tunimplemented\tMAJORBBS\tc_once\t-\t-\t-",
            ],
            "highest count first, then alphabetical on the tie: {text}"
        );
    }

    #[test]
    fn render_writes_a_dash_for_every_missing_optional_field() {
        let mut inv = Inventory::in_memory();
        inv.record("MAJORBBS", "gmdnam", None, None, None, Kind::Unimplemented);
        assert_eq!(
            inv.render(),
            "# count\tkind\tmodule\tsymbol\tordinal\tchannel\tcontext\n\
             1\tunimplemented\tMAJORBBS\tgmdnam\t-\t-\t-\n"
        );
    }

    #[test]
    fn render_carries_the_ordinal_channel_and_context_when_given() {
        let mut inv = Inventory::in_memory();
        inv.record(
            "MAJORBBS",
            "gmdnam",
            Some(474),
            Some(chan(0)),
            Some("seg 3:0x1a8b"),
            Kind::Unimplemented,
        );
        assert_eq!(
            inv.render(),
            "# count\tkind\tmodule\tsymbol\tordinal\tchannel\tcontext\n\
             1\tunimplemented\tMAJORBBS\tgmdnam\t474\t0\tseg 3:0x1a8b\n"
        );
    }

    #[test]
    fn an_empty_module_name_renders_as_a_dash_too() {
        // The `module.import(index) == None` fallback in `Host::run` reports
        // an unnamed thunk with an empty module string -- see that fn's own
        // comment on why. A blank cell would look like a parse error to
        // anything reading this with `cut -f`; `-` is unambiguous.
        let mut inv = Inventory::in_memory();
        inv.record("", "thunk #3", None, None, None, Kind::Unimplemented);
        assert!(inv.render().contains("\tunimplemented\t-\tthunk #3\t"));
    }

    // --- Durability: constraint 6 is that a SIGINT'd session still yields
    // something. These tests read the actual bytes on disk rather than the
    // in-memory `Inventory`, on purpose -- an in-memory-only assertion here
    // would never notice if `record` stopped writing through to the file at
    // all, which is exactly the gap that would defeat the whole point.

    fn scratch_file(name: &str) -> std::path::PathBuf {
        let dir = crate::testing::scratch(&format!("mbbs-survey-{name}"));
        dir.join("survey.log")
    }

    #[test]
    fn a_first_sighting_is_on_disk_before_finish_ever_runs() {
        let path = scratch_file("first-sighting-on-disk");
        let mut inv = Inventory::new(&path).expect("open");
        inv.record("MAJORBBS", "gmdnam", None, None, None, Kind::Unimplemented);

        let on_disk = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(
            on_disk, "1\tunimplemented\tMAJORBBS\tgmdnam\t-\t-\t-\n",
            "the append must already be flushed -- nothing has called finish()"
        );
    }

    #[test]
    fn a_repeat_sighting_does_not_grow_the_file() {
        let path = scratch_file("repeat-sighting-no-growth");
        let mut inv = Inventory::new(&path).expect("open");
        inv.record("MAJORBBS", "gmdnam", None, None, None, Kind::Unimplemented);
        let after_first = std::fs::read_to_string(&path).expect("read back");

        inv.record("MAJORBBS", "gmdnam", None, None, None, Kind::Unimplemented);
        inv.record("MAJORBBS", "gmdnam", None, None, None, Kind::Unimplemented);
        let after_repeats = std::fs::read_to_string(&path).expect("read back");

        assert_eq!(
            after_first, after_repeats,
            "only a symbol's FIRST sighting is appended -- repeats must not \
             grow the file"
        );
        assert_eq!(inv.count_of("MAJORBBS", "gmdnam"), Some(3), "but the in-memory count still does");
    }

    #[test]
    fn finish_overwrites_the_append_log_with_the_sorted_tally() {
        let path = scratch_file("finish-overwrites");
        let mut inv = Inventory::new(&path).expect("open");
        inv.record("MAJORBBS", "b_once", None, None, None, Kind::Unimplemented);
        inv.record("MAJORBBS", "a_five_times", None, None, None, Kind::Unimplemented);
        for _ in 0..4 {
            inv.record("MAJORBBS", "a_five_times", None, None, None, Kind::Unimplemented);
        }

        // Before finish(): discovery order, every count reading 1 -- this is
        // what a kill -9 right here would leave behind.
        let before = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(
            before,
            "1\tunimplemented\tMAJORBBS\tb_once\t-\t-\t-\n\
             1\tunimplemented\tMAJORBBS\ta_five_times\t-\t-\t-\n",
        );

        inv.finish().expect("finish");
        let after = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(after, inv.render(), "finish() writes exactly what render() renders");
        assert_eq!(
            after,
            "# count\tkind\tmodule\tsymbol\tordinal\tchannel\tcontext\n\
             5\tunimplemented\tMAJORBBS\ta_five_times\t-\t-\t-\n\
             1\tunimplemented\tMAJORBBS\tb_once\t-\t-\t-\n",
        );
    }

    #[test]
    fn opening_the_same_path_twice_starts_fresh_rather_than_appending_across_runs() {
        let path = scratch_file("fresh-per-session");
        let mut first = Inventory::new(&path).expect("open");
        first.record(
            "MAJORBBS",
            "a_very_long_symbol_name_from_a_previous_run",
            None,
            None,
            None,
            Kind::Unimplemented,
        );
        drop(first);

        let mut second = Inventory::new(&path).expect("reopen");
        second.record("MAJORBBS", "x", None, None, None, Kind::Unimplemented);
        let on_disk = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(
            on_disk, "1\tunimplemented\tMAJORBBS\tx\t-\t-\t-\n",
            "no trace of the previous run's longer line must survive"
        );
    }

    #[test]
    fn in_memory_record_never_touches_a_file() {
        // `Inventory::in_memory` has no `File`, so `record`'s `if let
        // Some(out) = &mut self.out` must simply skip the write side -- this
        // pins that it does not panic or error trying.
        let mut inv = Inventory::in_memory();
        assert!(inv.record("MAJORBBS", "gmdnam", None, None, None, Kind::Unimplemented));
        assert!(inv.finish().is_ok(), "a no-op finish() on an in-memory inventory must not error");
    }
}
