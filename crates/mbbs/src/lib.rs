//! The MajorBBS host: the other side of a 16-bit module's imports.
//!
//! [`mbbs16`] puts a module's code on the CPU and tells the host when it wants
//! something. This crate is what answers. It owns the export table, the globals
//! a module addresses directly, and the routines behind the thunks; `mbbs16`
//! stays the execution core and knows nothing about MajorBBS.
//!
//! The design is `docs/plans/2026-08-04-host-shims.md`.
//!
//! # A shim that lies is worse than one that refuses
//!
//! This is the rule the whole crate is shaped around, and it is measured rather
//! than asserted. `crates/mbbs16/tests/trace_init.rs` drives MajorMUD's
//! initialisation with a host that answers zero to everything. It reaches 201
//! calls and then takes SIGSEGV *inside module code*, because `alczer` was told
//! it returned a null pointer at call 183 and the module dereferenced it
//! eighteen calls later. The fault names the module, not the lie.
//!
//! So an import the host cannot service does not return zero and does not
//! return an error the module can interpret. It stops the module, naming the
//! symbol -- see [`Poison::Unimplemented`](mbbs16::Poison::Unimplemented).

mod arena;
pub mod btrieve;
pub mod chan;
pub mod clock;
pub mod dos;
mod exports;
mod fmt;
pub mod fsd;
mod globals;
pub mod gsbl;
pub mod heap;
pub mod keys;
pub mod msg;
pub mod random;
mod shims;
pub mod strings;
pub mod stream;
/// Not `#[cfg(test)]`: `crates/mbbs/tests/wccmmud.rs` is a separate crate that
/// links against this one built *without* `cfg(test)` (integration tests
/// never see items gated that way), so this has to be an ordinary `pub mod`
/// for `wccmmud.rs` to reach [`testing::scratch`] rather than keep its own
/// copy of it.
///
/// `#[doc(hidden)]`: it has to be reachable, not advertised. [`testing::scratch`]
/// calls `remove_dir_all` on the path it is given, which belongs in a test
/// harness's hands and nowhere near the release public API a caller of this
/// crate as a library would see documented.
#[doc(hidden)]
pub mod testing;
pub mod textvar;
pub mod users;

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::PathBuf;

pub use chan::{Chan, Terms};
pub use clock::{Civil, Clock};
pub use exports::Exports;
pub use fsd::Form;
pub use globals::{GLOBALS, Global, Globals, NTERMS, OUTBSZ};
pub use heap::{Config, Heap, Region};
pub use keys::KeySet;
pub use random::{RAND_MAX, Random, Runaway};
pub use shims::system::{Agent, Dispatch, Kick, Native, Registration};
pub use shims::{Cleans, Entry, Shim, ShimError};
pub use strings::{depad, is_white, rmvwht, skpwht, skpwrd};
pub use textvar::{TextVar, TextVars};
pub use users::{Connection, Users};

use mbbs16::{
    Exit, FarPtr, Import, ImportResolver, Machine, Module, NeImage, Poison, Relocation, Source,
    Symbol, Target,
};

/// How a module entry point ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// It returned. `ax` alone for an `int`, `dx:ax` for anything 32 bits wide.
    Returned { ax: u16, dx: u16 },

    /// It was stopped for good, and will not run again.
    Stopped(Poison),
}

/// Which of `struct module`'s two disconnect vectors a disconnect runs.
///
/// **They are sequential stages of one path, not two disjoint paths.** An
/// earlier version of this comment claimed the opposite, and the claim was
/// wrong in a way worth spelling out, because the reasoning that produced it
/// looks sound: `aschup()` -- the `huprou` sweep, `MAJORBBS.C:4607-4637` -- is
/// indeed called from exactly one place in the whole host, `loscar()` at
/// `:4581`. What does not follow is that a graceful logoff avoids it.
///
/// `loscar` has a second entry. `MAJORBBS.C:39` puts it in **`module00`'s own
/// `huprou` slot**, and `imdrop` (`:3423`) calls `module00.huprou` whenever
/// `usrptr->class > SUPIPG`. `nxtlof` sets `class = SUPLOF` at `:4074`, and
/// `MAJORBBS.H:164-166` makes that 5 against `SUPIPG`'s 3. So the test is true
/// for every logging-off user and the graceful path converges:
///
/// ```text
/// /x -> xitter -> bgnlof -> nxtlof sweep -> "Logoff self" (:4100)
///    -> finlof -> byenow(SEEYA) -> setbbye -> finbye -> imdrop
///    -> module00.huprou == loscar -> aschup [huprou sweep] -> rstchn
///
/// carrier loss ------------------> loscar -> aschup [huprou sweep] -> rstchn
/// ```
///
/// # What this host does instead, and why it is still right
///
/// [`Host::logoff`] runs the `lofrou` stage and stops; it does not go on to
/// call `huprou`. For MajorMUD that loses nothing, and it was checked rather
/// than assumed: `_LJNGAME_LOFROU` (`WCCMMUD_named.c:12628-12639`) already does
/// `_CLEAR_FORGET_LIST`, `_CLEANUP_WHEN_USER_LEAVES`, `_SAVE_PLAYER` and
/// `_CLEAR_PLAYER`, and `_LJNGAME_HUPROU`'s body is gated at `:12681` on the
/// player record it just cleared, so the second stage would find nothing to do.
///
/// That is a deliberate omission for *this* module, not a general truth. A
/// second module whose `huprou` does work its `lofrou` does not would need the
/// stage restored. Do not read the enum as saying the two are alternatives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Vector {
    /// `lofrou`, reached through `bgnlof`/`nxtlof` (`MAJORBBS.C:4067-4105`).
    Logoff,

    /// `huprou`, reached through `loscar`/`aschup`.
    Hangup,
}

impl Vector {
    /// Its position in `struct module` after `descrp`, which is what
    /// [`Registration::dispatch`] takes.
    ///
    /// `MAJORBBS.H:241-252` fixes the order: `descrp`, `lonrou`, `sttrou`,
    /// `stsrou`, `injrou`, `lofrou`, `huprou`, `mcurou`, `dlarou`, `finrou`.
    fn entry(self) -> usize {
        match self {
            Vector::Logoff => 4,
            Vector::Hangup => 5,
        }
    }

    /// The C name, for anything this host has to refuse by name.
    fn name(self) -> &'static str {
        match self {
            Vector::Logoff => "lofrou",
            Vector::Hangup => "huprou",
        }
    }
}

/// Why [`Host::cycle`] stopped.
///
/// Descriptive: this is the host's state, not an instruction. [`Ended::wait`]
/// turns it into one, in a single place, so that the socket driver and the
/// tests cannot come to disagree about what a given state means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ended {
    /// No status queued and no timer outstanding: nothing can happen until the
    /// transport delivers something. A driver blocks here.
    Idle,

    /// No status queued, but a timer is outstanding. `next_kick` is the
    /// soonest countdown in the kicktable, in whole seconds, and is never `0`
    /// -- `rtkick` refuses a zero delay and `prcrtk` removes an entry the
    /// moment it reaches zero.
    ///
    /// A driver sleeps up to that long and wakes early if input arrives.
    /// Nothing can happen before then: `prcrtk` cannot fire anything until the
    /// next whole second, and no other source of work exists, because the
    /// 16-bit world only advances when this host dispatches into it.
    ///
    /// `polls_cut` is whether the poll budget was exhausted -- **and that is
    /// all it is.** It is NOT a signal that the budget is too small, though
    /// this doc claimed exactly that until it was measured.
    ///
    /// Measured against MajorMUD with two players in the Realm, at budgets of
    /// 32, 128 and 512: `polls_cut` was `true` at every one, and the pass
    /// count came back as `budget + 1` each time. That is structural, not a
    /// property of the budget being low. [`Host::dopoll`] re-arms after every
    /// dispatch for as long as budget remains, so a polling channel consumes
    /// whatever it is given; the chain has no way to say "done". The module's
    /// routine simply falls through once its own pending-round counter is
    /// zero, and falling through still costs a dispatch.
    ///
    /// So a driver cannot calibrate from this. Whether the budget is high
    /// enough is a question about the *module's* amortised work -- for
    /// MajorMUD, whether monsters are acting at the rate they should -- and
    /// the host has no way to see it. What `polls_cut` is good for is the
    /// other direction: `false` means the module ran out of work before the
    /// budget ran out, which is the only cheap evidence that the budget is
    /// more than enough.
    Waiting { next_kick: u16, polls_cut: bool },

    /// `max` passes were made and there is still work queued. A driver calls
    /// straight back.
    Bound { next_kick: Option<u16> },

    /// The module stopped, on the pass it stopped on.
    Stopped(Poison),
}

/// What a driver should do about an [`Ended`].
///
/// One function computes this, because a bare scalar answer derived at each
/// call site is how call sites drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wait {
    /// Block until the transport delivers something.
    Blocked,
    /// Sleep at most this many whole seconds, waking early on input.
    Until(u16),
    /// Call `cycle` again now.
    Now,
    /// The module stopped. Shut the host down.
    Stop,
}

impl Ended {
    /// What a driver should do about this state.
    #[must_use]
    pub fn wait(&self) -> Wait {
        match self {
            Ended::Idle => Wait::Blocked,
            Ended::Waiting { next_kick, .. } => Wait::Until(*next_kick),
            Ended::Bound { .. } => Wait::Now,
            Ended::Stopped(_) => Wait::Stop,
        }
    }
}

/// What one [`Host::cycle`] run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cycles {
    /// Passes made, at most `max`. The host's own share of
    /// [`Host::clock_reads`], since each pass reads the clock once.
    pub iterations: usize,

    /// Module calls made: polling routines, entry points, and fired kicks.
    /// **The meter.**
    pub dispatched: usize,

    /// Why it stopped.
    pub ended: Ended,
}

/// A global the module addresses that the host cannot place.
///
/// Not a warning. A datum the host does not have would be given a *thunk* --
/// the address of a far call -- and the module would read and write it as a
/// variable, silently. There is no value in loading a module that will do that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingGlobal {
    pub module: String,
    pub symbol: String,
    pub why: Why,
}

/// What is wrong with a global the module addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// The host does not place it at all.
    NotPlaced,

    /// The host places it, but the module reaches past the end of it.
    TooSmall { addend: i16, size: u16 },
}

impl std::fmt::Display for MissingGlobal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            module,
            symbol,
            why,
        } = self;
        match why {
            Why::NotPlaced => write!(f, "{module}.{symbol} is a global the host does not have"),
            Why::TooSmall { addend, size } => write!(
                f,
                "{module}.{symbol} is {size} bytes here, and the module reaches {addend} into it"
            ),
        }
    }
}

/// Where the date-and-time routines format, once one of them has needed to.
///
/// One block per routine rather than one shared block, because the original had
/// three separate statics and a module may hold an `ncdate` result across an
/// `nctime` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DateBuffers {
    /// 9 bytes: `MM/DD/YY` and its terminator.
    pub(crate) date: FarPtr,

    /// 9 bytes: `HH:MM:SS` and its terminator.
    pub(crate) time: FarPtr,

    /// 10 bytes: `DD-Mon-YY` and its terminator.
    pub(crate) edat: FarPtr,

    /// One byte, always NUL. What `ncdate(0)` returns -- and a **different**
    /// address from `date`, so a null date leaves an earlier result standing,
    /// exactly as `seg 33:0x0c14` does by never writing at all. Written
    /// explicitly at `shims/system.rs:110` rather than trusted to the heap's
    /// zero-fill -- see [`Host::empty`] for the sibling that exists for the
    /// module's first instruction instead of its first date call.
    pub(crate) empty: FarPtr,
}

/// Why a module could not be loaded.
#[derive(Debug)]
pub enum LoadError {
    /// The file is not a module this loader can map. See
    /// [`NeError`](mbbs16::NeError).
    Image(io::Error),

    /// The module addresses host globals the host cannot honestly provide.
    Globals(Vec<MissingGlobal>),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Image(e) => write!(f, "{e}"),
            Self::Globals(missing) => {
                writeln!(f, "{} host globals cannot be provided:", missing.len())?;
                for m in missing {
                    writeln!(f, "    {m}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for LoadError {}

impl From<io::Error> for LoadError {
    fn from(e: io::Error) -> Self {
        Self::Image(e)
    }
}

/// One `haskey` call: what was asked, on whose behalf, and what it got.
///
/// See [`Host::keys_asked`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    /// The channel, from `usrnum`. `-1` when nobody was on one.
    pub chan: i16,
    /// The lock name, as the module passed it -- **not** uppercased. What the
    /// sysop configured is more useful to read than what it folded to.
    pub lock: String,
    /// What the host answered.
    pub answer: bool,
}

/// One MajorBBS host.
pub struct Host {
    exports: &'static Exports,
    globals: Globals,

    /// Where the module's own files are: its `.MDF`, its `.MSG` files, and
    /// eventually its Btrieve tables. A DOS module names them without a path
    /// and in whatever case it likes.
    pub root: PathBuf,

    /// `spr`'s rotating buffers, and which one is next.
    spr: FarPtr,
    spr_next: usize,

    /// Where `strtok` left off.
    ///
    /// `MAJORBBS.EXE` keeps this as one far `char *` in its own `DGROUP`, at
    /// offset `0x18a8` -- `seg 1:0x24f4` sets it, advances it and reads it back
    /// through `les bx,[0x18a8]`. It is not an exported symbol, so no module
    /// can see or reset it, and there is exactly one of it for every module and
    /// every channel. That is safe only because MajorBBS schedules
    /// cooperatively, and it is what the real host did.
    ///
    /// Starts null, so a `strtok(NULL, ...)` with no `strtok(s, ...)` before it
    /// stops the module rather than reading whatever happened to be there.
    pub(crate) strtok: FarPtr,

    /// Where `ncdate`, `nctime` and `ncedat` format, once one of them has run.
    ///
    /// `MAJORBBS.EXE` keeps these as statics in its own `DGROUP` -- 9 bytes at
    /// `0x40`, 9 at `0x49`, 10 at `0x52`, and a lone NUL at `0x82`. **They are
    /// allocated once and reused, because the aliasing is observable**: the
    /// pointer one call returns names a string the next call overwrites, and a
    /// host allocating afresh each time would hand back three live strings
    /// where the original had one.
    ///
    /// `None` until something needs them. Allocating in [`Host::new`] would put
    /// four blocks on the heap of a module that may never ask the time.
    pub(crate) datebuf: Option<DateBuffers>,

    /// The line buffer `gmdnam` returns a pointer into.
    mdf: FarPtr,

    /// One NUL byte the host owns and keeps, forever.
    ///
    /// `parsin`'s `margv[0]=""` on an empty line points at a string literal in
    /// Galacticomm's own data segment -- memory this host has none of, since
    /// there is no host-side copy of `MAJORBBS.EXE` running. This is that
    /// literal's stand-in: the module dereferences `margv[0]` unguarded, and a
    /// `FarPtr::NULL` there is a segment-zero read rather than an empty string.
    ///
    /// Written explicitly in [`Host::new`] rather than trusted to the
    /// allocator's zero-fill -- see [`DateBuffers::empty`] for the sibling
    /// that gets the same treatment for the same reason, lazily instead.
    empty: FarPtr,

    /// Where the print buffer ends, so `prf` can refuse to run past it.
    prf_end: u16,

    /// What `srand` started, and what `genrdn` draws from.
    ///
    /// One generator for the whole host, because that is what a C program
    /// linked against one copy of the runtime had: `srand` and `rand` share a
    /// single `RANDSEED` and every caller pulls from the same stream.
    pub(crate) random: Random,

    /// What `now`, `today` and `time` answer from. See [`Clock`].
    clock: Clock,

    /// Every line `shocst` has been given.
    audit: Vec<String>,

    /// Every module that has come online, in registration order. A module's
    /// number is its index here, which is what `register_module` returns and
    /// what the module passes back.
    modules: Vec<Registration>,

    /// Every client/server agent that has come online, in registration order.
    /// Unlike [`Host::modules`] these are *copies* -- see [`Agent`].
    pub(crate) agents: Vec<Agent>,

    /// The text variables the module has registered. Unlike [`Host::agents`]
    /// these live in memory the module can reach -- see [`TextVars`].
    pub(crate) textvars: TextVars,

    /// The message files that are open, and their text in module memory. Which
    /// one is *current* is not here -- that is `curmbk`, a global the module
    /// can see.
    pub(crate) messages: msg::Messages,

    /// The Btrieve files that are open, and the stack of which is current.
    /// Which one *is* current is `bb`, for the same reason.
    pub(crate) btrieve: btrieve::Btrieve,

    /// The terminal channels. See [`gsbl`].
    pub(crate) gsbl: gsbl::Gsbl,

    /// The streams that are open. No notion of a current one -- `fopen` hands
    /// back a `FILE *` and every routine takes it, so there is no `curmbk` or
    /// `bb` equivalent to keep in module memory.
    pub(crate) streams: stream::Streams,

    /// Every data file the host created from its virgin copy, in the order it
    /// did. See [`Host::btrieve_file`].
    installed: Vec<String>,

    /// Everything the host did that a module cannot be told about.
    ///
    /// The rule everywhere else is that a host which cannot answer honestly
    /// stops the module. A few things are neither an answer nor a refusal --
    /// a `setbtv` stack that overflowed exactly as the real host's would, a
    /// file installed from its virgin copy -- and they would otherwise happen
    /// in silence. Kept rather than printed, so a test can assert on them.
    notes: Vec<String>,

    /// Which [`Host::note_once`] keys have already been recorded.
    ///
    /// Separate from the note text so that a note carrying a file name still
    /// reports once for the routine that produced it.
    noted: HashSet<String>,

    /// Every callback `rtkick` has been asked to run later, in the order it
    /// was asked. [`Host::cycle`] runs them, once per elapsed second, via
    /// [`Host::prcrtk`]. See [`Host::kicks`].
    pub(crate) kicks: Vec<Kick>,

    /// Poll dispatches left in this burst.
    ///
    /// [`Host::dopoll`] spends one per call and stops re-arming at zero;
    /// [`Host::refill_polls`] is the only thing that raises it. Zero at
    /// construction: a host nobody is driving polls nothing.
    pub(crate) polls_left: usize,

    /// Every form `fsdroom` has sized, keyed by the `(message number, amode)`
    /// it was compiled from. See [`Host::forms`].
    ///
    /// **Channel-keyed as of the commit that added this doc comment.** Used
    /// to be a flat `Vec<Form>` -- see [`Host::fsdscb`](Host#structfield.fsdscb)'s
    /// history for why that was a debt -- but the compiled form itself is not
    /// per-channel state at all: two channels filling out the *same* form
    /// (the same message number and amode) share one compilation, the way the
    /// real host's `fsdroom` would have parsed the same template twice and
    /// gotten the same answer both times. What is per-channel is which form a
    /// given channel is using, which [`Host::fsdtmp`] records.
    pub(crate) forms: std::collections::HashMap<(u16, i16), Form>,

    /// Where each channel's `struct fsdscb` lives, once its `fsdroom` has
    /// needed one. Indexed by [`Chan::index`].
    ///
    /// `inifsdscb()`, `FSDBBS.C:64`, allocates `nterms` of them, and the real
    /// `setfsd(chan)` exists precisely to select among them -- which this
    /// mirrors: one segment per channel rather than one segment shared by
    /// all of them. `None` until that channel's first `fsdroom`, because the
    /// module *tests* the `fsdscb` global for null -- `seg 3:0x430f` -- and
    /// takes another path when it is.
    ///
    /// # The debt this repays
    ///
    /// This used to be a single `Option<FarPtr>`, on the reasoning that the
    /// FSD was out of scope for the multi-channel work and nothing could
    /// reach the hazard. That reasoning held until [`Host::fsd_state`]
    /// existed to dispatch a channel into an FSD session at all -- from that
    /// point on, two channels entering data at once would have shared one
    /// control block and interleaved their answers into a single `newans`.
    /// Keyed by channel now, so that cannot happen by construction.
    pub(crate) fsdscb: Vec<Option<FarPtr>>,

    /// Each channel's `fsdusr->{curmbk,tmpmsg,amode}` -- which message block
    /// `fsdroom` last read a template out of, which template, and in which
    /// mode. `FSDBBS.C:134`, and Rust-side rather than in module memory
    /// because `fsdusr` is ordinal 264 and `WCCMMUD.DLL` never imports it.
    /// Indexed by [`Chan::index`], for the same reason [`Host::fsdscb`] is.
    pub(crate) fsdtmp: Vec<Option<(FarPtr, u16, i16)>>,

    /// The FSD's own `state` slot, registered in [`Host::finish_init`] the
    /// way `inifsd()` registers FSDBBS as a module. `None` before
    /// `finish_init` has run.
    pub(crate) fsd_state: Option<usize>,

    /// Per-channel state an entry session needs that no module can see, so
    /// it lives only here rather than round-tripping through `Machine` the
    /// way [`Scb`](fsd::Scb) does.
    ///
    /// `FSDBBS.C`'s own home for these is `struct fsdbbs` (`fsdusr`):
    /// `whndun` there is a far pointer into the module the host must call
    /// back, and the save/quit flag is `fsdusr->flags & FBSAVE`, read by
    /// `goback()` after the session's own buffer may already be gone. Both
    /// are genuinely invisible to the module -- unlike `Scb`'s bytes, which
    /// the module dereferences directly -- so they are Rust-side. Indexed by
    /// [`Chan::index`], for the reason [`Host::fsdscb`] is: one session per
    /// channel, not one shared by all of them.
    pub(crate) fsd_sessions: Vec<Option<FsdSession>>,

    /// Scratch memory for the candidate answer `fsdprc`'s `FSDBUF` arm
    /// hands `fldvfy`: the module reads `char *answer` out of it, and
    /// `VFYOK`'s own contract (`FSD.H` Note 2) lets it rewrite the bytes
    /// there in place. `None` until the first field-verify call needs it.
    ///
    /// **Not per-channel, unlike [`Host::fsdscb`].** The original's own
    /// `fsdbuf` (`FSDBBS.C:45`) is a single global buffer too, not one per
    /// channel -- `alcmem(fsdbln)` runs once, in `inifsd()`. That is safe
    /// there for the same reason it is safe here: only one channel's
    /// `fsdprc` ever runs at a time (this host is single-threaded by
    /// force), and the buffer's whole lifetime is the span of one
    /// `fldvfy` call, never carried across one. Sized `ANSLEN+1` rather
    /// than the original's `fsdbln` (`ANSILN*ANSIWD*2`, a much larger
    /// buffer also used by the ANSI screen paths this crate does not
    /// build) -- the one purpose this port ever writes it for is a single
    /// candidate answer, never longer than `ANSLEN`.
    pub(crate) fsd_scratch: Option<FarPtr>,

    /// The module's heap and its tiled regions.
    pub(crate) heap: Heap,

    /// The per-channel tables: `user[]`, `extusr[]` and the account block.
    ///
    /// One slot each per channel, allocated at construction because the real
    /// host allocated them before any module's init ran -- `MAJORBBS.C:735-736`
    /// and `ACCOUNT.C:109`. See [`Users`].
    pub(crate) users: Users,

    /// Every lock a module has asked about, in order. See [`Host::keys_asked`].
    asked: Vec<Query>,

    /// The channel whose polling routine is running right now, or `None`.
    ///
    /// `inpolr`, `MAJORBBS.C:322`, with the original's `-1` as `None`. Rust-side
    /// because `WCCMMUD.DLL` neither imports it nor reads it -- unlike `polrou`,
    /// which it does.
    pub(crate) inpolr: Option<Chan>,

    /// The last whole second [`Host::prcrtk`] has been run for.
    ///
    /// `tcklst`, `MAJORBBS.C:476`. `None` until the first [`Host::cycle`] pass,
    /// which syncs it to the clock and fires nothing: a counter starting at zero
    /// would make that first pass catch up from 1970, which is about 1.1 billion
    /// `prcrtk` rounds. The original had no equivalent because `ticker` was a
    /// free-running counter that both ends of the comparison read.
    tcklst: Option<u32>,

    /// How many host calls have been serviced. The progress meter: with an
    /// unfinished host, how far a module gets before it asks for something
    /// that is not there is a number rather than an impression.
    calls: u64,

    /// How many times anything has read the clock. See [`Host::clock_reads`].
    clock_reads: u64,

    /// Whether to print each call as it is serviced. See [`Host::set_trace`].
    trace: bool,

    /// Whether [`Host::finish_init`] has run. See it for why this is checked
    /// rather than assumed.
    inited: bool,
}

/// Where in the module the call being refused came from, as a place you can
/// look up in a disassembly.
///
/// When a shim runs, the top of the module's stack is the far return address of
/// the `9A` far call that got there: `frame_sp+0` is the offset, `+2` the
/// selector. A `9A` call is five bytes, so the instruction itself begins five
/// before the address it would have returned to.
///
/// Reported as an **NE segment**, not a selector. The selector is whatever the
/// loader happened to hand out this run; the segment is a fact about the file,
/// and it is what `re/ne_arity.py` and every disassembler speak.
///
/// `None` rather than a guess whenever the answer would be misleading: no
/// outstanding call, a stack that will not resolve, or a selector this module
/// does not own. A wrong address costs more than no address -- it sends someone
/// to a real instruction that had nothing to do with it.
fn caller(machine: &Machine, module: &Module) -> Option<String> {
    let frame = FarPtr {
        offset: machine.frame_sp()?,
        selector: machine.stack_selector(),
    };
    let bytes = machine.resolve(frame, 4).ok()?;
    let offset = u16::from_le_bytes([bytes[0], bytes[1]]);
    let selector = u16::from_le_bytes([bytes[2], bytes[3]]);
    let segment = module.segment_at(selector)?;
    Some(format!("seg {segment}:{:#06x}", offset.wrapping_sub(5)))
}

/// What `poll` does with a status.
///
/// Two shapes, not one index: `CRSTG`, `INBLK` and `OUTMT` reach an entry point
/// the module registered at init, and `POLSTS` reaches a callback it installed
/// at runtime. There is no entry-point number for the second, which is why this
/// is an enum and not the `usize` it used to be.
///
/// Named `PollTarget` rather than `Dispatch` to leave that name for
/// [`shims::system::Dispatch`], which is what a channel's `state` itself
/// resolves to -- a different question from the one this enum answers.
enum PollTarget {
    Entry(usize),
    Poll,
}

/// The two things about an FSD session no module can see. See
/// [`Host::fsd_sessions`].
#[derive(Debug, Clone, Default)]
pub(crate) struct FsdSession {
    /// The `whndun(save)` callback `fsdego` was handed, or `None` if the
    /// module passed `NULL` -- `goback()`'s own `else` branch
    /// (`FSDBBS.C:236`) is what a `None` here means to it.
    pub whndun: Option<FarPtr>,

    /// Whether the session is exiting to save (`FSDSAV`) or to quit
    /// (`FSDQIT`). `fsdusr->flags & FBSAVE`, read by `goback()` after
    /// `xitfsd` decided.
    pub save: bool,
}

impl Host {
    /// Build a host over a machine, placing its globals in memory the module
    /// will be able to address.
    ///
    /// `root` is the directory the module's own files live in, and `terms` is
    /// how many channels it serves.
    ///
    /// **The count is an input because it was one in the original.**
    /// `MAJORBBS.C:557` accumulates `nterms` per configured channel group --
    /// `nterms+=numopt(msg+NUMBR1,1,256)`, whose `1` is the floor -- `:569`
    /// catastros above 256, and `:845-866` walks the groups that result,
    /// raising `hichp1` at `:861` and filling `channel[]` at `:862`. It was
    /// never a constant the host chose for itself. [`NTERMS`](crate::NTERMS)
    /// names the one-channel case -- `MAJORBBS.C:80`'s initialiser and
    /// `GMEOFF.C:23`'s offline host, which is the shape every meter in this
    /// crate was measured against.
    ///
    /// There is deliberately no two-argument form defaulting to one channel. A
    /// caller who wanted four and got one would find out at the first
    /// `Terms::chan(1)` that returned `None`, which is a long way from the
    /// mistake; requiring the argument makes it a compile error instead.
    ///
    /// # Errors
    ///
    /// If the globals or the host's buffers cannot be mapped.
    pub fn new(
        machine: &mut Machine,
        root: impl Into<PathBuf>,
        terms: Terms,
    ) -> io::Result<Self> {
        // Every table this host keys by channel is sized from this one binding:
        // the `nterms` global the module reads, `Users`' four tables, and
        // `Gsbl`'s channels. It is deliberately one parameter and not three
        // reads of `globals::NTERMS` -- see `crate::chan` for what the three
        // separate reads cost, and for the measurement that showed one of the
        // two directions of disagreement was completely silent.
        let globals = Globals::new(machine, terms)?;
        let prf_end = OUTBSZ;

        // One segment for everything the host hands a module a pointer into and
        // then keeps: `spr`'s four buffers, `gmdnam`'s line, and one NUL byte
        // for `parsin`'s empty-line `margv[0]`. Separate from the globals so
        // that a module overrunning one of these cannot reach `usrnum`.
        let spr_bytes = shims::text::SPR_BYTES as usize * shims::text::SPR_BUFFERS;
        let selector = machine.alloc_segment(spr_bytes + 64 + 1)?;

        // The per-channel tables come off the module heap, because the real
        // host's did: `MAJORBBS.C:735-736` builds them with `alczer` and
        // `ACCOUNT.C:109` with `alcblok`, both of which are the same heap a
        // module allocates from. So the heap has to exist before they do.
        let mut heap = Heap::new(Config::default());
        let users = users::Users::new(machine, &mut heap, terms)?;

        // The three authorities, checked against each other once.
        //
        // `Chan` makes a channel of one bound unusable against a table of
        // another, but it does not by itself make a *construction* error
        // visible: at `nterms == 1` nothing ever mints the channel-1 handle that
        // would panic, so building `Gsbl` one channel longer than `Users` still
        // passed all 688 tests. Measured, not assumed -- the same mutation was
        // run before this line existed and after it, and only the second one
        // went red. Without it the divergence waits for a real second channel
        // and arrives as `point_curusr` refusing a channel `Gsbl::scan` just
        // handed out, which reads as a module fault.
        //
        // `nterms` is read back out of module memory rather than compared to
        // `terms`, because what the module bounds its loops by is the word in
        // the segment, not the value this function meant to write there.
        let gsbl = gsbl::Gsbl::new(terms);
        let nterms = globals
            .word(machine, "nterms")
            .map_err(|e| io::Error::other(format!("nterms: {e}")))?;
        assert_eq!(
            (users.terms(), gsbl.terms(), nterms),
            (terms, terms, terms.count()),
            "the host's channel tables and the module's `nterms` disagree"
        );

        // `MAJORBBS.H:345` declares `struct user *user` -- the *head* of the
        // array, not a slot. The module never asks the host for a channel's
        // record; it loads this pointer and indexes off it itself, at 58 sites
        // of `_user_625 + usrnum * 0x29`. So it has to be a real far pointer
        // before the module's first access, and pointing it at channel 0 is
        // pointing it at the array.
        //
        // `extusr` and `uablok` get no such line, because neither is a global
        // this host places: `WCCMMUD.DLL` imports neither, and reaches an
        // account record only by calling `uacoff`.
        globals.write(machine, "user", &users.head().to_bytes())?;
        globals.write(machine, "channel", &users.channels().to_bytes())?;

        // R17: written explicitly rather than left to `alloc_segment`'s
        // `mmap(MAP_ANONYMOUS)` zero-fill. `DateBuffers`'s own empty byte gets
        // the identical write at `shims/system.rs:110` -- two facilities for
        // one NUL because they cannot be the same one: this one must exist
        // before the module's first instruction, and that one is allocated
        // lazily off the heap the first time a date routine runs.
        let empty = FarPtr {
            offset: spr_bytes as u16 + 64,
            selector,
        };
        machine.write(empty, &[0])?;

        Ok(Self {
            exports: Exports::wg101(),
            globals,
            root: root.into(),
            spr: FarPtr {
                offset: 0,
                selector,
            },
            spr_next: 0,
            strtok: FarPtr::NULL,
            datebuf: None,
            mdf: FarPtr {
                offset: spr_bytes as u16,
                selector,
            },
            empty,
            prf_end,
            random: Random::default(),
            clock: Clock::system()?,
            audit: Vec::new(),
            modules: Vec::new(),
            agents: Vec::new(),
            textvars: TextVars::default(),
            messages: msg::Messages::default(),
            btrieve: btrieve::Btrieve::default(),
            gsbl,
            streams: stream::Streams::default(),
            installed: Vec::new(),
            notes: Vec::new(),
            noted: HashSet::new(),
            kicks: Vec::new(),
            polls_left: 0,
            forms: HashMap::new(),
            fsdscb: vec![None; usize::from(terms.count())],
            fsdtmp: vec![None; usize::from(terms.count())],
            fsd_state: None,
            fsd_sessions: vec![None; usize::from(terms.count())],
            fsd_scratch: None,
            heap,
            users,
            asked: Vec::new(),
            inpolr: None,
            tcklst: None,
            calls: 0,
            clock_reads: 0,
            trace: std::env::var_os("MBBS_TRACE").is_some(),
            inited: false,
        })
    }

    /// The host's globals.
    pub fn globals(&self) -> &Globals {
        &self.globals
    }

    /// Every line `shocst` has produced, oldest first.
    pub fn audit(&self) -> &[String] {
        &self.audit
    }

    /// Every module that has registered, in the order they did.
    /// Entry `n` of the module channel `chan`'s `state` names -- or, if
    /// `state` names a host-native registration, the native handler itself.
    ///
    /// `MAJORBBS.C:2703` is `(*(module[usrptr->state]->sttrou))()`: a channel's
    /// `state` **is** an index into the module table, and `register_module`
    /// returning that index is the whole handshake. This host had dispatched to
    /// `modules().first()` instead, which is the same thing only while exactly
    /// one module is registered -- and `inifsd()` registers FSDBBS as an
    /// ordinary module, so the FSD is a second one.
    ///
    /// A `state` naming a slot nobody registered stops with a reason. Falling
    /// back to module 0 would send another module's keystrokes to MajorMUD and
    /// look, from the outside, like a module that ignored its input.
    ///
    /// The two layers of `Result` are not decoration: the outer is "this host
    /// cannot go on", the inner is a [`ShimError`] the caller turns into
    /// [`Outcome::Stopped`] through [`Host::shim_stop`], and only the caller
    /// knows which of its own step names to attach.
    ///
    /// # Errors
    ///
    /// If `state` names no registered module.
    fn state_entry(
        &self,
        machine: &Machine,
        chan: Chan,
        n: usize,
    ) -> io::Result<Result<Dispatch, ShimError>> {
        let state = match self.users.state(machine, chan) {
            Ok(state) => state,
            Err(e) => return Ok(Err(e)),
        };
        let Some(registered) = self.modules().get(usize::from(state)) else {
            let count = self.modules().len();
            return Err(io::Error::other(format!(
                "channel {chan} is in state {state} and {count} module(s) are registered, \
                 so there is no module to enter: either a module wrote a state it was \
                 never given, or a registration this host owes has not happened"
            )));
        };
        Ok(registered.dispatch(machine, n))
    }

    /// `Dispatch::Native`'s side of [`Host::poll`]'s `sttrou`/`stsrou`
    /// dispatch: entry `n` of the FSD's own native slot, run directly
    /// instead of through a far call.
    ///
    /// Entry 2 is `stsrou`, the only one `FSDBBS.C`'s own `fsdmod` ever gave
    /// a body -- `fsdsts`, folded here into
    /// [`shims::fsd::fsd_cycle`]. Entry 1 (`sttrou`, reached on `CRSTG`)
    /// is never real: raw mode means `CRSTG` cannot fire while a session is
    /// under way (the design doc's "Input" section), so a `CRSTG` reaching
    /// this slot at all means the channel is in the FSD's `state` without a
    /// live session -- the same shape as a module that left the entry point
    /// null, noted rather than refused so [`Host::poll`]'s own "no entry
    /// registered" fallback handles it exactly as it would a module's own
    /// null pointer.
    ///
    /// Always answers "no far pointer to call": the FSD's own work, when
    /// there is any, happens right here rather than through a far call --
    /// that is the whole point of a *native* registration.
    ///
    /// # Errors
    ///
    /// If [`shims::fsd::fsd_cycle`] does -- in particular, if this channel's
    /// state names the FSD's own slot but `fsdego` never ran for it, which
    /// is a bug in whatever set that state rather than a condition to
    /// silently ignore.
    fn fsd_dispatch(
        &mut self,
        machine: &mut Machine,
        chan: Chan,
        n: usize,
    ) -> Result<Option<FarPtr>, ShimError> {
        if n != 2 {
            self.note(format!(
                "fsd_dispatch: channel {chan} entry {n} reached the FSD's native slot, \
                 which has no handler wired up yet"
            ));
            return Ok(None);
        }

        shims::fsd::fsd_cycle(machine, self, chan)?;
        Ok(None)
    }

    pub fn modules(&self) -> &[Registration] {
        &self.modules
    }

    /// The first *module* registration, skipping any [`Registration::Native`]
    /// ahead of it in the table -- [`Host::connect`]'s `lonrou` lookup and
    /// [`Host::disconnect`]'s `huprou` lookup both want "the one real module"
    /// and neither wants to mistake the FSD's native slot for it.
    fn first_module(&self) -> Option<&Registration> {
        self.modules
            .iter()
            .find(|r| matches!(r, Registration::Module { .. }))
    }

    /// The FSD's own `state` slot, the way `register_module`'s caller keeps
    /// the number it returned.
    ///
    /// # Panics
    ///
    /// If called before [`Host::finish_init`] has registered it -- nothing
    /// in this crate can reach a channel's `state` that early, so this is a
    /// programming error rather than a condition callers should handle.
    pub(crate) fn fsd_state(&self) -> usize {
        self.fsd_state
            .expect("finish_init registers the FSD before anything can reach it")
    }

    /// What time it is, and one step later than the last time anyone asked.
    ///
    /// **Reading the clock moves it**, under [`Clock::stepped`]. The returned
    /// value is a frozen snapshot, so `now`'s `.civil()` and `time`'s `.epoch()`
    /// stay consistent within one call; it is the *next* read that has moved.
    /// A [`Clock::pinned`] or [`Clock::system`] clock does not move, so this is
    /// only a counter for them.
    pub fn clock(&mut self) -> Clock {
        self.clock = self.clock.advanced();
        self.clock_reads += 1;
        self.clock
    }

    /// How many times the clock has been read, host and module together.
    ///
    /// Under [`Clock::stepped`] a read is also a step, so how far invented time
    /// has run is a function of how often the module looked at it -- a property
    /// of the module, which no host-side argument bounds. This is how the size
    /// of that is measured instead of argued about, the way
    /// [`Host::keys_asked`] measures locks. The host's own share of these is
    /// [`Cycles::iterations`]; the rest is the module's.
    pub fn clock_reads(&self) -> u64 {
        self.clock_reads
    }

    /// Freeze the clock, or hand the host a different one.
    ///
    /// **A pinned clock is what makes a run reproducible.** MajorMUD seeds its
    /// generator with `srand(time(NULL))` six calls into initialisation, so
    /// without this no test can assert what the module *built* -- only how many
    /// calls it took to build it. See [`Clock`] for the hazard a frozen clock
    /// carries.
    pub fn set_clock(&mut self, clock: Clock) {
        self.clock = clock;
    }

    /// Every client/server agent that has registered, in the order it did.
    ///
    /// **Nothing dispatches to them.** An agent is one end of the Galacticomm
    /// Client/Server protocol and the other end is a Worldgroup client, which
    /// this host has no way to be talking to. So this is the record of what a
    /// client/server layer would call into, in the same sense that
    /// [`Host::kicks`] is a record of what a main loop would owe.
    pub fn agents(&self) -> &[Agent] {
        &self.agents
    }

    /// The text variables that have been registered.
    ///
    /// Unlike [`Host::agents`] and [`Host::kicks`] this is **not** only a
    /// record: the table is real module memory and the `txtvars` global points
    /// at it, so the module can walk it whether or not this host ever
    /// substitutes anything. What is still owed is `findtvar` and the
    /// substitution itself.
    pub fn textvars(&self) -> &TextVars {
        &self.textvars
    }

    /// Every callback the module asked `rtkick` to run later.
    ///
    /// [`Host::cycle`] runs them, once per elapsed second, the same way the
    /// real host's main loop did: `rtkick` is a one-shot timer measured in
    /// seconds, and `MAJORBBS.C:476-480` ran `prcrtk()` once per elapsed
    /// second. `Host::cycle` tracks elapsed seconds against its own clock and
    /// calls [`Host::prcrtk`] the same number of times, catching up in one
    /// pass if more than a second has elapsed since the last call.
    ///
    /// So this list is not only a record: it is served, on the schedule above.
    /// MajorMUD registers two during initialisation -- a one-second heartbeat
    /// into its own segment 6, and a second one-second callback into segment
    /// 10, which is the last thing it does before it asks for a random number.
    pub fn kicks(&self) -> &[Kick] {
        &self.kicks
    }

    /// Every form the module asked `fsdroom` to size, keyed by the
    /// `(message number, amode)` it was compiled from.
    ///
    /// A cache, not a session: what a caller can usefully ask this host is
    /// "what forms exist" and not "what is channel 0 in the middle of" --
    /// see [`Host::fsdtmp`] and [`Host::fsdscb`] for the per-channel half of
    /// that question.
    pub fn forms(&self) -> &std::collections::HashMap<(u16, i16), Form> {
        &self.forms
    }

    /// The message files that are open.
    pub fn messages(&self) -> &msg::Messages {
        &self.messages
    }

    /// The Btrieve files that are open.
    pub fn btrieve(&self) -> &btrieve::Btrieve {
        &self.btrieve
    }

    /// The streams that are open.
    pub fn streams(&self) -> &stream::Streams {
        &self.streams
    }

    /// Every data file the host created from its virgin copy.
    pub fn installed(&self) -> &[String] {
        &self.installed
    }

    /// Everything the host did that the module could not be told about.
    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    /// Record something the module cannot be told. See [`Host::notes`].
    pub(crate) fn note(&mut self, what: String) {
        self.notes.push(what);
    }

    /// Record something once, however many times it happens.
    ///
    /// For a note whose cause can repeat without changing: a `qrybtv` with no
    /// Btrieve file current inside a loop would otherwise put thousands of
    /// identical lines in [`Host::notes`], and a channel that has to be skimmed
    /// is one nobody reads.
    ///
    /// `key` is what "the same thing" means -- usually the routine's name --
    /// and is kept apart from `what` so a message carrying a file name still
    /// reports once.
    pub(crate) fn note_once(&mut self, key: &str, what: String) {
        if self.noted.insert(key.to_owned()) {
            self.notes.push(what);
        }
    }

    /// The module's heap.
    pub fn heap(&self) -> &Heap {
        &self.heap
    }

    /// The per-channel tables. See [`Users`].
    pub fn users(&self) -> &Users {
        &self.users
    }

    /// `user[unum].usrcls` -- what kind of channel this is.
    ///
    /// Zero for every channel this host makes, which is neither `ONLINE` nor
    /// `BBSPRV`. Read rather than assumed because `low_haskey` branches on it.
    ///
    /// # Errors
    ///
    /// If the read runs off a segment.
    pub fn class(&self, machine: &Machine, unum: Chan) -> Result<u16, ShimError> {
        let slot = self.users().slot(unum);
        let at = FarPtr {
            offset: slot.offset + users::user::USRCLS,
            selector: slot.selector,
        };
        let bytes = machine.resolve(at, 2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Every lock a module has asked about, in order.
    ///
    /// The lock names are sysop-editable text in the module's `.MSG` --
    /// `PLAYKEY {USER}` is a default, not a measurement -- and most call
    /// sites are guarded by `if (lockname[0] != '\0')`, so which ones a
    /// module actually asks about is a property of the installed
    /// configuration and not of the DLL. Reading the sequence off a real run
    /// is the only way to know it.
    ///
    /// This is how `a_connected_channel_takes_a_command_and_answers`
    /// (`tests/wccmmud.rs`) pins which gates the module walked and what each
    /// answered, rather than trusting the call count alone. A key set that
    /// grants too much still moves that count while quietly putting the
    /// module on a different branch -- MajorMUD's namespace has negative
    /// locks -- and that is not hypothetical here: two of the five locks the
    /// meter test's run asks about are ban keys, and a mutation that answered
    /// every lock `true` was caught by the call count moving, not by luck.
    pub fn keys_asked(&self) -> &[Query] {
        &self.asked
    }

    /// Record a `haskey` call. See [`Host::keys_asked`].
    pub(crate) fn asked_for_key(&mut self, chan: i16, lock: &str, answer: bool) {
        self.asked.push(Query {
            chan,
            lock: lock.to_string(),
            answer,
        });
    }

    /// The terminal channels.
    pub fn gsbl(&self) -> &gsbl::Gsbl {
        &self.gsbl
    }

    /// The terminal channels, mutably. The transport pushes bytes in and drains
    /// them out through this.
    pub fn gsbl_mut(&mut self) -> &mut gsbl::Gsbl {
        &mut self.gsbl
    }

    /// `paccin()` then `parsin()`, and the far pointer `getin()` hands back:
    /// `char *margv[0]`.
    ///
    /// `archive/galacticomm/extract/wg20/galdsrc/SRC/MAJORBBS.C:3368`:
    ///
    ///
    /// `paccin` is `inplen=btuinp(usrnum,input)` followed by `paccit()` --
    /// the modem monitor and the profanity check, both BBS-shaped and out of
    /// scope. This host's `paccin` is `btuinp` and nothing else: take the
    /// channel's completed line (an empty one if none is ready, which is
    /// exactly the byte string an empty line already is) and write it,
    /// NUL-terminated, into `input`. `btuinp` is not itself a shim --
    /// `WCCMMUD.DLL` imports it only on the 32-bit side -- so it has no
    /// argument stack to read; what it does is folded in here.
    ///
    /// Shared rather than inlined into the `getin` shim because
    /// [`Host::poll`] (Task 9) needs the identical sequence and must not have
    /// to fake a call frame to reach it.
    ///
    /// # Errors
    ///
    /// If `input`, `margv` or `margn` are not placed, or a write runs off a
    /// segment.
    pub(crate) fn get_input(
        &mut self,
        machine: &mut Machine,
        chan: Chan,
    ) -> Result<FarPtr, ShimError> {
        // R16: resolve everything that can fail before touching the channel.
        // `take_line` pops the ready queue -- if the line were taken first and
        // `input` then turned out not to be placed, the user's line would be
        // gone with nothing to retry. `input` not being placed cannot happen
        // in practice (`Globals::new` places it unconditionally), but the
        // ordering is what makes that true by construction rather than by
        // coincidence of what `Globals::new` currently does.
        let input = self
            .globals()
            .address("input")
            .ok_or_else(|| ShimError::Failed("input is not placed".into()))?;
        let size = usize::from(
            self.globals()
                .size("input")
                .expect("input is placed, its address just resolved"),
        );

        let line = self.gsbl_mut().take_line(chan).unwrap_or_default();
        let take = line.len().min(size - 1);
        let mut bytes = line[..take].to_vec();
        bytes.push(0);
        machine.write(input, &bytes)?;

        shims::text::parsin(machine, self)?;

        let margv = self
            .globals()
            .address("margv")
            .expect("margv is placed, or parsin above would already have failed");
        let bytes = machine.resolve(margv, 4)?;
        Ok(FarPtr::from_bytes(bytes.try_into().expect("4 bytes")))
    }

    /// Point the four globals that name "the current channel" -- `usrnum`,
    /// `usrptr`, `usaptr` and `vdaptr` -- at `uno`.
    ///
    /// `MAJORBBS.C:4290`'s `curusr`, minus the range check: every caller here
    /// already knows `uno` is a channel that exists, for a different reason
    /// each. [`shims::user::curusr`] checked it itself, because an
    /// out-of-range `uno` there is the documented silent no-op
    /// (`MAJORBBS.C:4293`) and not a failure. [`Host::connect_state`] gets
    /// its answer from [`Users::account`] failing first. Factored out so
    /// both call one piece of code rather than keep two that can drift.
    ///
    /// # Errors
    ///
    /// If a write runs off a segment.
    pub(crate) fn point_curusr(&mut self, machine: &mut Machine, uno: Chan) -> Result<(), ShimError> {
        let slot = self.users().slot(uno);
        let account = self.users().account(uno);
        let vda = self.users().vda(uno).unwrap_or(FarPtr::NULL);

        self.globals()
            .write(machine, "usrnum", &uno.number().to_le_bytes())
            .map_err(|e| ShimError::Failed(format!("point_curusr: {e}")))?;
        self.globals()
            .write(machine, "usrptr", &slot.to_bytes())
            .map_err(|e| ShimError::Failed(format!("point_curusr: {e}")))?;
        self.globals()
            .write(machine, "usaptr", &account.to_bytes())
            .map_err(|e| ShimError::Failed(format!("point_curusr: {e}")))?;
        self.globals()
            .write(machine, "vdaptr", &vda.to_bytes())
            .map_err(|e| ShimError::Failed(format!("point_curusr: {e}")))?;
        Ok(())
    }

    /// The channel [`Host::point_curusr`] last made current, read back the
    /// way the module itself would: out of the `usrnum` global.
    ///
    /// Every FSD shim needs to know which channel it is serving, and none of
    /// them are handed a [`Chan`] argument -- the module's own call
    /// signatures have no room for one (`fsdroom(msgno, fldspc, amode)`, four
    /// words, matches `FSDBBS.H:60-67` and `GALP&Q.C:1273`). This is how they
    /// ask.
    ///
    /// # Errors
    ///
    /// If `usrnum` does not name a channel of this host -- in particular, if
    /// nobody is current at all. `MAJORBBS.C:882` sets `usrnum=-1` before any
    /// module's init runs, and that value survives until the first
    /// [`Host::point_curusr`], which is exactly the state a module's own
    /// initialisation runs in. Most callers of this may propagate the error;
    /// [`crate::shims::fsd::fsdroom`] is the one exception, because it is the
    /// one FSD routine measured calling in from there.
    pub(crate) fn current_channel(&self, machine: &Machine) -> Result<Chan, ShimError> {
        let uno = self
            .globals()
            .word(machine, "usrnum")
            .map_err(|e| ShimError::Failed(format!("current_channel: {e}")))?;
        self.users.terms().chan(uno as i16).ok_or_else(|| {
            ShimError::Failed(format!(
                "current_channel: usrnum is {}, which names no channel",
                uno as i16
            ))
        })
    }

    /// Plant a connecting user's account record and channel state, and make
    /// the channel current.
    ///
    /// Writes what a real board's `loadup()` would have read out of
    /// `bbsusr.dat` -- this host has no accounts and none are being grown
    /// here; see [`users::Connection`]. `usrcls`, `state` and `substt` are
    /// all written as zero: that is already what a freshly allocated slot
    /// reads as (`Users::new`'s `alczer` zeroed it), and it is what
    /// [`Host::connect`] (Task 8) then hands to the module's own `lonrou` to
    /// set for real. Written anyway, rather than left to the allocator's
    /// zero, so the state a connecting channel is in is something this
    /// function visibly does and not an accident of history.
    ///
    /// # Errors
    ///
    /// If `chan` names no channel, or a write runs off a segment.
    pub fn connect_state(
        &mut self,
        machine: &mut Machine,
        chan: Chan,
        who: &users::Connection,
    ) -> Result<(), ShimError> {
        // The module reads `vdatmp` before it draws, so a channel connected to
        // a host that never allocated one fails silently much later and
        // somewhere else. See [`Host::finish_init`].
        if !self.inited {
            return Err(ShimError::Failed(
                "connect: this host has not run finish_init, so no channel has a \
                 volatile data area yet"
                    .to_owned(),
            ));
        }
        let account = self.users().account(chan);
        let slot = self.users().slot(chan);

        // `UIDSIZ` (`UStructs.h:10`) is 30 *including the trailing zero* --
        // the header's own comment says so -- so at most 29 characters fit
        // and byte 29 must stay a NUL; `psword` starts immediately after
        // `userid` in the record, at 30, and a longer name is truncated
        // rather than overrunning it.
        //
        // The whole field is zeroed before the name is written in, not just
        // the bytes the name occupies. `connect_state` can run again on a
        // channel that already held a user -- Task 8/9's driver reuses
        // channels rather than allocating a fresh one per connection -- and
        // writing only `take` bytes would leave the tail of a longer, earlier
        // name sitting past the new one. `userid` is what `obtbtvl` keys the
        // character lookup on (`WCCMMUD_named.c:9847`), so that tail is not
        // cosmetic: "dan" over "rangerdan" reads back as "dangerdan" and the
        // module finds a stranger's character.
        //
        // Only `userid` is reset here, not the account's other 308 bytes.
        // Whether a reused channel should clear the whole record was an open
        // question; it is not open any more. `dftrst` clears all of it, and
        // [`Host::rstchn`] is where that happens -- at startup over every
        // channel and at the tail of every disconnect, so a channel arriving
        // here has already been emptied by whoever left it.
        const UIDSIZ: usize = 30;
        let userid = who.userid.as_bytes();
        let take = userid.len().min(UIDSIZ - 1);
        let mut field = [0u8; UIDSIZ];
        field[..take].copy_from_slice(&userid[..take]);
        let at = FarPtr {
            offset: account.offset + users::usracc::USERID as u16,
            selector: account.selector,
        };
        machine.write(at, &field)?;

        let at = FarPtr {
            offset: account.offset + users::usracc::ANSIFL as u16,
            selector: account.selector,
        };
        machine.write(at, &[u8::from(who.ansi)])?;

        let at = FarPtr {
            offset: account.offset + users::usracc::SCNWID as u16,
            selector: account.selector,
        };
        machine.write(at, &[who.width])?;

        let at = FarPtr {
            offset: account.offset + users::usracc::SCNFSE as u16,
            selector: account.selector,
        };
        machine.write(at, &[who.height])?;

        for (field, value) in [
            (users::user::USRCLS, 0u16),
            (users::user::STATE, 0u16),
            (users::user::SUBSTT, 0u16),
        ] {
            let at = FarPtr {
                offset: slot.offset + field,
                selector: slot.selector,
            };
            machine.write(at, &value.to_le_bytes())?;
        }

        // `loadkeys()`, `LOCKNKEY.C:88`. On a real board this read `bbsk.dat`
        // and a `&CLASS` keyring record; here the keys arrived with the
        // connection, because whatever authenticated the user is what knows
        // them. Set unconditionally, so a channel reused by a second user does
        // not inherit the first one's access.
        self.users.set_keys(chan, who.keys.clone());

        // A channel that already held a user may still hold that user's polling
        // routine, and `polrou` is a pointer into module code installed for
        // *them*. Cleared for the same reason `userid` above is zeroed whole:
        // this function runs again on a reused channel.
        self.users.set_polrou(machine, chan, None)?;

        // `MASTER`, `MAJORBBS.H:206` -- bit 0x40 of `user.flags`, whose low
        // byte is at offset 0x14. Read-modify-write on that one bit: the rest
        // of the byte is the module's, `WCCMMUD.DLL` sets and tests masks 2, 4
        // and 0x10 in it, and `connect_state` runs again on a channel that
        // already held a user. A whole-field store would clear the module's
        // bits out from under it.
        //
        // Host-private in practice -- the module never tests 0x40 -- but the
        // bit is real and `user.flags` should not lie about it.
        const MASTER: u8 = 0x40;
        let at = FarPtr {
            offset: slot.offset + users::user::FLAGS,
            selector: slot.selector,
        };
        let was = machine.resolve(at, 1)?[0];
        let now = if who.keys.is_master() {
            was | MASTER
        } else {
            was & !MASTER
        };
        machine.write(at, &[now])?;

        self.point_curusr(machine, chan)
    }

    /// Completely reset a channel: `rstchn`, via its default handler `dftrst`.
    ///
    ///
    /// `MAJORBBS.C:3487-3500`. Everything after those five lines is hardware:
    /// `rcdbaud`, `lincst`, `bturst` and the `switch` over its return code
    /// exist to bring a *modem* channel back up, and this host has no channel
    /// hardware to reset. `mnuusr` is zeroed there too and is not here: it
    /// belongs to the menuing subsystem, whose `muusrs` table this host does
    /// not have and whose absence is deliberate. `gcsprst` is the
    /// client/server reset, which this host has nothing to reset.
    ///
    /// # Why this is one routine and not two
    ///
    /// The original calls this from two places that look unrelated: startup
    /// (`:908-911`, over every channel, right after `alcvda`) and the tail of
    /// both disconnect paths. That is not a coincidence -- it is what makes "a
    /// channel nobody has used" and "a channel just freed" the same state.
    /// [`Host::connect_state`] used to note that whether a reused channel
    /// should clear its whole record was an open question; it is not open, it
    /// is answered here.
    ///
    /// # What this does NOT clear, and where that is done instead
    ///
    /// The volatile data area. `dftrst` does not clear it either -- the
    /// original zeroes it on the way *in*, at `MAJORBBS.C:4000`, the line
    /// before `cyclon` calls a module's `lonrou`. [`Host::connect`] is where
    /// that line lives here, so the guarantee is "a channel a module is handed
    /// has a zeroed VDA", not "`rstchn` leaves nothing at all". An earlier
    /// version of this comment claimed the latter and said "the answer is all
    /// of it", which was false for 1,961 bytes per channel.
    ///
    /// At one channel none of this is observable, because no second user ever
    /// arrives to inherit the first one's bytes.
    ///
    /// # Errors
    ///
    /// If a write runs off a segment.
    pub fn rstchn(&mut self, machine: &mut Machine, chan: Chan) -> Result<(), ShimError> {
        self.users.clear_keys(chan);
        for (at, len) in [
            (self.users.slot(chan), users::USER),
            (self.users.extra(chan), users::EXTUSR),
            (self.users.account(chan), users::USRACC),
        ] {
            machine.write(at, &vec![0u8; usize::from(len)])?;
        }
        // `bturst(usrnum)`, `MAJORBBS.C:3503` -- the last thing `dftrst` does
        // that this host has anything to do. Without it the three `setmem`s
        // above clear the module's view of the channel while GSBL's view keeps
        // the previous player's buffers and terminal settings.
        self.gsbl.reset(chan);
        Ok(())
    }

    /// Put a channel into the module's state machine and let the module know.
    ///
    /// `connect_state` writes what a real board's `loadup()` would have read
    /// out of `bbsusr.dat`; `lonrou` is the module's own logon hook, which
    /// `MAJORBBS.C:558`'s `lonstf()` called for every registered module. Only
    /// one module is registered here, so this calls the one.
    ///
    /// Returns `None` if the module supplies no `lonrou` -- the real host
    /// never called one either, so there is no [`Outcome`] to report for a
    /// call that never happened.
    ///
    /// R21: a `ShimError` out of `connect_state` or the `lonrou` lookup
    /// poisons the machine and comes back as `Outcome::Stopped`, the same
    /// policy [`Host::run`] applies to a `ShimError` from a shim it
    /// dispatched. See `shim_stop`.
    ///
    /// # Errors
    ///
    /// If no module has registered. (A malformed `chan`, a write running off
    /// a segment, or the module being unenterable all poison the machine and
    /// come back as `Ok(Some(Outcome::Stopped(..)))` instead -- see above.)
    pub fn connect(
        &mut self,
        machine: &mut Machine,
        module: &Module,
        chan: Chan,
        who: &users::Connection,
    ) -> io::Result<Option<Outcome>> {
        if let Err(e) = self.connect_state(machine, chan, who) {
            return self.shim_stop(machine, "connect_state", e).map(Some);
        }

        // `Registration::dispatch` borrows `self.modules()` immutably, and
        // `self.run` needs `self` mutably right after -- so the pointer is
        // read out here and the borrow ends before `run` is ever reached.
        //
        // The first *module* registration, and not the channel's state, on
        // purpose. `cyclon` calls `if ((rouptr = module[i]->lonrou) != NULL)`
        // over an `i`: a logon is announced to every registered module, not
        // dispatched to one. This host makes the first iteration only, which
        // is the whole loop while one real module is registered -- and now
        // that `Host::finish_init` registers the FSD's native slot ahead of
        // any module, `first_module` (not `modules().first()`) is what keeps
        // that "one module" reading correct: a `Native` registration has no
        // `lonrou` to announce (`FSDBBS.C` supplies no module-shaped logon
        // hook) and skipping past it is not the same thing as counting it as
        // the sole module. A **second real module** is still owed the rest
        // of `cyclon`'s loop; that debt is unaffected by this change.
        let lonrou = {
            let registered = self.first_module().ok_or_else(|| {
                io::Error::other("no module has registered, so there is nothing to enter")
            })?;
            match registered.dispatch(machine, 0) {
                Ok(Dispatch::Module(rou)) => Ok(rou),
                // `first_module` never answers `Native`, but the match stays
                // exhaustive and the fallback stays correct if that changes.
                Ok(Dispatch::Native(_)) => Ok(None),
                Err(e) => Err(e),
            }
        };
        let lonrou = match lonrou {
            Ok(lonrou) => lonrou,
            Err(e) => return self.shim_stop(machine, "lonrou lookup", e).map(Some),
        };
        let Some(lonrou) = lonrou else {
            // R24: a null `lonrou` is legal -- the real host checked
            // `if ((rouptr = module[i]->lonrou) != NULL)` before calling --
            // and it means no call happened, not that one returned zero.
            // `None` says that honestly; a fabricated `Returned { ax: 0,
            // dx: 0 }` would claim a call this host never made.
            return Ok(None);
        };
        // `MAJORBBS.C:4000` -- `setmem(vdaptr,vdasiz,0)`, the line before
        // `cyclon` calls a module's `lonrou`. The volatile data area is the one
        // per-channel block `rstchn` does *not* clear, because `dftrst` does not
        // clear it either: the original zeroes it on the way *in* rather than on
        // the way out, and this is that line.
        //
        // Found by a mutation that stayed green across all 786 tests -- pointing
        // `vdaptr` at channel 0 for every dispatch. That is invisible today
        // because MajorMUD leaves the area zero on the returning-player path,
        // which is exactly the argument that made `btuxmt`'s channel argument
        // unfalsifiable at one channel. This branch exists because that argument
        // was wrong once already.
        if let Some(vda) = self.users.vda(chan) {
            let size = self.globals.word(machine, "vdasiz")?;
            if let Err(e) = machine.write(vda, &vec![0u8; usize::from(size)]) {
                return self.shim_stop(machine, "clearing the volatile data area", e.into()).map(Some);
            }
        }

        self.run(machine, module, lonrou, &[]).map(Some)
    }

    /// Lost carrier: hand the channel to the module's `huprou`, then reset it.
    ///
    /// `loscar()` -> `aschup()` -> `rstchn()`, `MAJORBBS.C:4562-4605` and
    /// `:4607-4637`. This is what a closed socket raises, and `aschup` is the
    /// only caller of the `huprou` sweep in the entire host -- a graceful
    /// logoff does not pass through here. See [`Vector`].
    ///
    /// MajorMUD's `_LJNGAME_HUPROU` (`re/exports/WCCMMUD_named.c:12646`) is the
    /// substantial one: `_GET_PLAYER`, `_CLEAR_FORGET_LIST` and `_SAVE_PLAYER`
    /// unconditionally, and then -- gated on `user[usrnum].substt >= 0x82`, in
    /// the Realm -- it works the room, dropping carried items and announcing
    /// the departure through `_TELL_GAME`, whose loop is bounded by `nterms`.
    /// It is a `void` routine, so its [`Outcome::Returned`] words are whatever
    /// it happened to leave behind rather than an answer.
    ///
    /// Returns `None` if the module supplies no `huprou`. **The reset happens
    /// either way** -- `loscar` reaches `rstchn` at `:4593` whether or not
    /// `aschup` found a routine to call.
    ///
    /// # Errors
    ///
    /// If no module has registered.
    pub fn hangup(
        &mut self,
        machine: &mut Machine,
        module: &Module,
        chan: Chan,
    ) -> io::Result<Option<Outcome>> {
        self.disconnect(machine, module, chan, Vector::Hangup)
    }

    /// Graceful logoff: hand the channel to the module's `lofrou`, then reset
    /// it.
    ///
    /// `bgnlof`/`nxtlof`, `MAJORBBS.C:4054-4105`. The original's sweep walks
    /// every registered module and falls back to `go2mnu(JSTRET)` -- the
    /// menuing system, which is out of scope here. With one module the sweep's
    /// loop body never runs at all (`:4076` skips `i == lofstt`, and `lofstt` is the
    /// only module there is), so it collapses to the self-call at `:4100-4101`
    /// and `go2mnu` never arises.
    ///
    /// That self-call is `if ((*lofrou)() != 1) go2mnu(JSTRET);`, so **`1` is
    /// the only value the original distinguishes for a one-module host**: it
    /// means "I am not finished", and the channel stays in the module's logoff
    /// state for another pass. This host has no logoff state to stay in, so a
    /// `1` is refused with a named stop rather than discarded -- a silent
    /// discard would leave the module believing a multi-pass dialogue is in
    /// progress.
    ///
    /// **Only `1`.** `-1` -- the sweep's "abandon and return to the menu" at
    /// `:4087-4089` -- is *not* refused, because that branch is inside the loop
    /// this host never reaches. Against `:4100`'s `!= 1`, the values `0`, `-1`
    /// and `42` are one answer: finished, go to the menu. "Go to the menu" for
    /// a headless host collapses to "the logoff is over", which is exactly the
    /// [`rstchn`](Self::rstchn) that follows. Refusing `-1` as well would be
    /// this host inventing a distinction the original does not draw at the only
    /// line it reaches. See
    /// `a_lofrou_that_abandons_the_sweep_is_taken_at_its_word_like_any_non_one`.
    ///
    /// MajorMUD's own `_LJNGAME_LOFROU` (`re/exports/WCCMMUD_named.c:12628`)
    /// returns 0, which is exactly why the refusal has to exist rather than be
    /// assumed unreachable.
    ///
    /// Returns `None` if the module supplies no `lofrou`. As with
    /// [`Host::hangup`], the reset happens either way.
    ///
    /// # Errors
    ///
    /// If no module has registered.
    pub fn logoff(
        &mut self,
        machine: &mut Machine,
        module: &Module,
        chan: Chan,
    ) -> io::Result<Option<Outcome>> {
        self.disconnect(machine, module, chan, Vector::Logoff)
    }

    /// What [`Host::hangup`] and [`Host::logoff`] have in common: point the
    /// channel, call its vector if the module supplied one, then reset it.
    ///
    /// The order is the contract. The routine runs **first**, while the channel
    /// still holds the departing player -- `_LJNGAME_HUPROU` opens with
    /// `_GET_PLAYER(usrnum)` and goes on to `_SAVE_PLAYER`, and a `rstchn` that
    /// ran before it would hand the module a zeroed record to save. The reset
    /// runs **last, and unconditionally**: a null vector means no call
    /// happened, not that the channel stays occupied, and `loscar` reaches
    /// `rstchn` either way.
    ///
    /// R21: a `ShimError` out of `point_curusr` or the entry lookup poisons the
    /// machine and comes back as [`Outcome::Stopped`], matching
    /// [`Host::connect`].
    fn disconnect(
        &mut self,
        machine: &mut Machine,
        module: &Module,
        chan: Chan,
        vector: Vector,
    ) -> io::Result<Option<Outcome>> {
        if let Err(e) = self.point_curusr(machine, chan) {
            return self.shim_stop(machine, "point_curusr", e).map(Some);
        }

        // `Registration::dispatch` borrows `self.modules()` immutably and
        // `self.run` needs `self` mutably right after, so the pointer is read
        // out here and the borrow ends before `run` is ever reached -- the same
        // discipline `Host::connect` follows.
        //
        // The two vectors are not reached the same way, and this is the one
        // place that difference is visible:
        //
        // - `bgnlof` tests `module[usrptr->state]->lofrou == NULL` -- keyed on
        //   the channel's state, like `sttrou`.
        // - `aschup` tests `(rouptr=module[i]->huprou) != NULL` -- an `i`, a
        //   loop over *every* registered module. This host makes the first
        //   iteration and no more, which is exactly right while one real
        //   module is registered and is owed a loop the day a second one is.
        //   It is the first *module* and not the channel's state
        //   deliberately: a hangup is news for every module, not just the
        //   one holding the channel -- `first_module`, not `modules().first()`,
        //   because the FSD's native slot registers ahead of any module now
        //   and has no `huprou` to be news to.
        //
        // Neither vector has a native-handler shape: `FSDBBS.C` supplies no
        // `lofrou` or `huprou`, so a `Dispatch::Native` answer here is the
        // same "no call happened" as a module that left the pointer null --
        // unlike `poll`'s `sttrou`/`stsrou` dispatch, which is the FSD's own
        // reason to exist as a state at all.
        let rou = match vector {
            Vector::Logoff => match self.state_entry(machine, chan, vector.entry())? {
                Ok(Dispatch::Module(rou)) => Ok(rou),
                Ok(Dispatch::Native(_)) => Ok(None),
                Err(e) => Err(e),
            },
            Vector::Hangup => {
                let registered = self.first_module().ok_or_else(|| {
                    io::Error::other(
                        "no module has registered, so there is nothing to disconnect from",
                    )
                })?;
                match registered.dispatch(machine, vector.entry()) {
                    Ok(Dispatch::Module(rou)) => Ok(rou),
                    Ok(Dispatch::Native(_)) => Ok(None),
                    Err(e) => Err(e),
                }
            }
        };
        let rou = match rou {
            Ok(rou) => rou,
            Err(e) => {
                let where_ = format!("{} lookup", vector.name());
                return self.shim_stop(machine, &where_, e).map(Some);
            }
        };

        // R24: a null vector is legal -- `aschup` tests
        // `(rouptr=module[i]->huprou) != NULL` (`:4623`) and `bgnlof` tests
        // `module[usrptr->state]->lofrou == NULL` -- and it means no call
        // happened, not that one returned zero.
        let outcome = match rou {
            Some(rou) => Some(self.run(machine, module, rou, &[])?),
            None => None,
        };

        // `nxtlof`'s protocol; see [`Host::logoff`] for why a non-zero return
        // is refused rather than discarded. `huprou` is `void` and has no
        // protocol, so its words are not read.
        let outcome = match (vector, outcome) {
            (Vector::Logoff, Some(Outcome::Returned { ax, .. })) if ax == 1 => {
                Some(self.stop(
                    machine,
                    Poison::Unimplemented {
                        module: "mbbs".to_owned(),
                        symbol: format!(
                            "lofrou returned {}, asking to be called again, and this \
                             host has no second logoff pass to give it \
                             (MAJORBBS.C:4100)",
                            ax as i16
                        ),
                    },
                )?)
            }
            (_, outcome) => outcome,
        };

        if let Err(e) = self.rstchn(machine, chan) {
            return self.shim_stop(machine, "rstchn", e).map(Some);
        }
        Ok(outcome)
    }

    /// `dopoll()` -- call a channel's polling routine now. `MAJORBBS.C:3258`.
    ///
    ///
    /// The routine takes no arguments and its return value is discarded, as
    /// `(*usrptr->polrou)()` discards it. `poll` has already pointed `curusr`
    /// and written `status`, so it runs with `usrnum`, `usrptr`, `usaptr` and
    /// `vdaptr` correct.
    ///
    /// `polrou` is read again after the call rather than remembered: a routine
    /// that called `stop_polling` on itself must not be re-armed, and that is
    /// the *only* thing the second read is for.
    ///
    /// Returns `None` when the channel is not polling -- a status left over
    /// from a `begin_polling` the module has since undone. No call happened, so
    /// there is no [`Outcome`] to report and R24 forbids inventing one.
    fn dopoll(
        &mut self,
        machine: &mut Machine,
        module: &Module,
        chan: Chan,
    ) -> io::Result<Option<Outcome>> {
        let rou = match self.users.polrou(machine, chan) {
            Ok(Some(rou)) => rou,
            Ok(None) => return Ok(None),
            Err(e) => return self.shim_stop(machine, "dopoll", e).map(Some),
        };

        self.inpolr = Some(chan);
        let outcome = self.run(machine, module, rou, &[]);
        // Cleared before the `?`, so a machine that malfunctioned does not leave
        // `inpolr` naming a channel that is no longer running anything. The
        // original does the same from the `longjmp` landings at
        // `MAJORBBS.C:2488` and `:4150`.
        self.inpolr = None;
        let outcome = outcome?;

        // One dispatch, one token. Saturating because the budget may already
        // be zero: when it runs out, up to `nterms` injections are still
        // queued, and those are dispatched rather than dropped -- a status the
        // host queued is one it owes the module.
        self.polls_left = self.polls_left.saturating_sub(1);

        // `MAJORBBS.C:3258` re-injects unconditionally, because the original
        // owned the machine and had nothing else to do with the turn. The
        // re-read of `polrou` below is its check and is kept exactly: a
        // routine that zeroed its own `polrou` must not be re-armed.
        //
        // The budget is the addition. Without it this chain never breaks,
        // `pending()` is permanently true, and `cycle` can never tell a driver
        // it is safe to sleep.
        if self.polls_left > 0 && matches!(outcome, Outcome::Returned { .. }) {
            match self.users.polrou(machine, chan) {
                Ok(Some(_)) => {
                    self.gsbl.inject(chan, gsbl::Gsbl::POLSTS);
                }
                Ok(None) => {}
                Err(e) => return self.shim_stop(machine, "dopoll", e).map(Some),
            }
        }
        Ok(Some(outcome))
    }

    /// `prcrtk()` -- one second's worth of the kicktable. `RTKICK.C:59`:
    ///
    ///
    /// Called once per elapsed second, never once per pass -- see
    /// [`Host::cycle`].
    ///
    /// Every due entry is taken out of the table *before* any of them runs.
    /// `GALMJD.C:1106` re-arms `mjdrtk` from inside `mjdrtk`, so a callback
    /// pushes onto the list being walked; draining first puts the re-armed kick
    /// in the next round, which is where the original's free-slot scan puts it
    /// too.
    ///
    /// `fired` is added to rather than assigned, so a caller can accumulate
    /// across the rounds of one catch-up.
    ///
    /// Returns the poison if a callback stopped the machine, and `None`
    /// otherwise. A callback's return value is discarded, as `prcrtk` discards
    /// it.
    fn prcrtk(
        &mut self,
        machine: &mut Machine,
        module: &Module,
        fired: &mut usize,
    ) -> io::Result<Option<Poison>> {
        let mut due = Vec::new();
        self.kicks.retain_mut(|kick| {
            // `rtkick` refuses a zero delay, so no live entry can underflow.
            kick.delay -= 1;
            if kick.delay == 0 {
                due.push(*kick);
                false
            } else {
                true
            }
        });

        for kick in due {
            *fired += 1;
            match self.run(machine, module, kick.dstrou, &[])? {
                Outcome::Stopped(poison) => return Ok(Some(poison)),
                Outcome::Returned { .. } => {}
            }
        }
        Ok(None)
    }

    /// Service one channel that has something to report.
    ///
    /// `MAJORBBS.C:169`'s loop, with everything bulletin-board-shaped taken
    /// out -- the `usrptr->class` switch, `RING`/`CMDOK`, `rstchn`, `dwopr`,
    /// `prcrtk` and `hdlinp`'s fallback to `module00` are all MajorBBS and not
    /// the module, and none of them are here:
    ///
    /// ```text
    /// scan() -> a channel with a status
    ///   status 3 (CRSTG)  -> curusr(chan), getin(), then entry 1 (sttrou)
    ///   status 4 (INBLK)
    ///      or 5 (OUTMT)   -> curusr(chan), write the `status` global, entry 2 (stsrou)
    ///   anything else     -> a note, and no call
    /// ```
    ///
    /// Returns `None` if no channel has a status waiting, if the one that
    /// did raised a status nothing here dispatches, or if the module
    /// supplies no entry point for the one that would have been called --
    /// none of those is a module call, so there is no [`Outcome`] to report.
    ///
    /// R21: a `ShimError` out of `point_curusr`, `get_input` or the entry
    /// lookup poisons the machine and comes back as `Outcome::Stopped`, the
    /// same policy [`Host::run`] applies to a `ShimError` from a shim it
    /// dispatched. See `shim_stop`.
    ///
    /// # Errors
    ///
    /// If no module has registered. (A write running off a segment, or the
    /// module being unenterable, poisons the machine and comes back as
    /// `Ok(Some(Outcome::Stopped(..)))` instead -- see above.)
    pub fn poll(&mut self, machine: &mut Machine, module: &Module) -> io::Result<Option<Outcome>> {
        // R23: a status this host does not dispatch (`OVRFLW`, say) is not
        // the same fact as "nothing queued" -- looping past it here, rather
        // than answering `Ok(None)` for it, keeps that distinction from
        // leaking into the return value. A driver written
        // `while host.poll(..)?.is_some() {}` would otherwise stop dead on
        // one undispatched status with a `CRSTG` still queued behind it.
        // Every iteration consumes exactly one status, so this cannot
        // legitimately run more times than there were statuses queued. The
        // bound is not for the legitimate case.
        //
        // Both `continue` arms below allocate a note, and the status queue is
        // deliberately unbounded (see `gsbl::Channel::status`). So an edit that
        // stops consuming turns this loop into something that eats the machine
        // instead of failing a test -- which is not hypothetical: a mutation
        // that peeked instead of popping reached 4.7 GB resident and the global
        // OOM killer took the session down with it. A host bug should cost a
        // red test, not the box.
        const SPINS: usize = 1024;
        let mut spins = 0usize;

        loop {
            spins += 1;
            if spins > SPINS {
                return Err(io::Error::other(format!(
                    "poll went round {SPINS} times without dispatching to the module: \
                     a status is being read but not consumed"
                )));
            }

            let Some(chan) = self.gsbl_mut().scan() else {
                return Ok(None);
            };

            // Popped before either entry point is called, not after -- a
            // `sttrou` that re-enters through `hdlinp` must not see its own
            // status still queued.
            let status = self
                .gsbl_mut()
                .next_status(chan)
                .expect("scan just found a channel with one");

            let dispatch = match status {
                gsbl::Gsbl::CRSTG => PollTarget::Entry(1),
                // `susing()` (`MAJORBBS.C:2478`) names `POLSTS`, `SPXTRM`,
                // `SPXWDG`, `RING`, `LOST2C`, `LOST25`, `CRSTG`, `OBFCLR`,
                // `ABOREQ` and `OUTMT`, and lets everything else fall to
                // `default: (*(module[usrptr->state]->stsrou))()`. `CYCLE`
                // (`MAJORBBS.H:236`) is in "everything else", which is what
                // makes `fsdnfy()` work at all -- it injects 240 at itself
                // expecting `stsrou` to run.
                gsbl::Gsbl::INBLK | gsbl::Gsbl::OUTMT | gsbl::Gsbl::CYCLE => PollTarget::Entry(2),
                gsbl::Gsbl::POLSTS => PollTarget::Poll,
                other => {
                    self.note(format!(
                        "poll: channel {chan} raised status {other}, which nothing here dispatches"
                    ));
                    continue;
                }
            };

            // The module reads `usrnum` at 2,570 sites and `usrptr` at 255;
            // `MAJORBBS.C:154-155` points both, and `usaptr` with them, before
            // every dispatch -- `:157` is the `usrptr->class` switch this host
            // deliberately does not have. `vdaptr` is not named there at all;
            // `point_curusr` sets it because the real host's own `curusr`
            // (`MAJORBBS.C:4290`) does.
            if let Err(e) = self.point_curusr(machine, chan) {
                return self.shim_stop(machine, "point_curusr", e).map(Some);
            }

            // `MAJORBBS.C:152`: `status=btusts(usrnum)` is unconditional --
            // only the `!= 3` guard on `shomal()` (the operator console, out of
            // scope) is conditional. `status` is a placed global
            // (`globals.rs:107`) that `stsrou` reads (`WCCMMUD.DLL` imports it
            // at 2 sites); writing it only on the non-CRSTG path left the
            // module reading a stale value on the CRSTG path -- zero on a
            // fresh host, or a leftover `OUTMT` from an earlier poll.
            self.globals()
                .write(machine, "status", &status.to_le_bytes())?;

            let entry_index = match dispatch {
                // A polling routine is not an entry point and has no index. The
                // arm diverges either way, so the `match` still yields the index
                // the `Entry` arm carries.
                PollTarget::Poll => match self.dopoll(machine, module, chan)? {
                    Some(outcome) => return Ok(Some(outcome)),
                    None => continue,
                },
                PollTarget::Entry(index) => index,
            };

            if status == gsbl::Gsbl::CRSTG
                && let Err(e) = self.get_input(machine, chan)
            {
                return self.shim_stop(machine, "get_input", e).map(Some);
            }

            // `MAJORBBS.C:2703` keys both of these on the channel's own state:
            // `sttrou` through `(*(module[usrptr->state]->sttrou))()` and
            // `stsrou` beside it. Same borrow trap as `connect` -- the pointer
            // is read out here and the borrow ends before `self.run` needs
            // `self` mutably.
            //
            // This is the one dispatch site a `Native` registration is
            // genuinely for -- `inifsd()` registers the FSD so that a
            // channel's `state` can name it exactly the way one names a
            // module, and `sttrou`/`stsrou` are the entry points it exists to
            // answer. `fsd_dispatch` carries that; every other call site in
            // this file treats `Native` as a hook a module left null instead,
            // because none of them are input dispatch.
            let entry = self.state_entry(machine, chan, entry_index)?;
            let entry = match entry {
                Ok(Dispatch::Module(entry)) => Ok(entry),
                Ok(Dispatch::Native(Native::Fsd)) => {
                    self.fsd_dispatch(machine, chan, entry_index)
                }
                Err(e) => Err(e),
            };
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => return self.shim_stop(machine, "entry lookup", e).map(Some),
            };
            let Some(entry) = entry else {
                // R24: `sttrou`'s `ax` is TRUE/FALSE for "did you consume
                // the input", which the module never answered here -- a
                // fabricated `Returned { ax: 0, dx: 0 }` would claim a call
                // that never happened. On the CRSTG path `get_input` above
                // has already taken the line, so a module with no `sttrou`
                // silently drops every command; not implementing
                // `module00`'s fallback is in scope, dropping the line
                // without a word about it is not.
                self.note(format!(
                    "poll: channel {chan} has no entry {entry_index} registered; \
                     status {status} was serviced with no module call"
                ));
                continue;
            };
            return self.run(machine, module, entry, &[]).map(Some);
        }
    }

    /// Grant `n` poll dispatches and arm every channel that polls.
    ///
    /// The analogue of `begin_polling`'s initial injection (`MAJORBBS.C:1183`).
    /// [`Host::dopoll`] carries the chain from there, re-arming after each
    /// call until the budget runs out; this is what starts it again.
    ///
    /// **It must arm, not merely count.** A budget that only gated the re-arm
    /// would break the chain with nothing to restart it, and the channel would
    /// be polled never again.
    ///
    /// A driver calls this once per wake. `n` has a floor -- enough dispatches
    /// to drain a round of whatever the module amortises across its polling
    /// routine -- and no ceiling worth worrying about: once a round is drained
    /// the module's own pending-work counter is zero and every further poll
    /// falls through. Overshooting buys no-ops. Undershooting is graceful.
    ///
    /// **`n` is the driver's whole sleep policy, so pick it knowingly.** The
    /// chain re-arms until the budget runs out, so a polling channel spends
    /// exactly what it is given: measured against MajorMUD, one wake per
    /// second consumed all of 32, 128 and 512, and the host thread's pass
    /// count came back as `n + 1` each time. `n` is therefore very nearly
    /// "poll dispatches per second" on a board whose wakes are kick-driven,
    /// and it is also, to within one, the host thread's idle CPU cost.
    /// [`Ended::Waiting`]'s `polls_cut` does NOT tell a driver whether `n` was
    /// large enough -- see its own doc for why not.
    ///
    /// # Errors
    ///
    /// If a channel's `polrou` cannot be read out of the machine.
    pub fn refill_polls(&mut self, machine: &Machine, n: usize) -> io::Result<()> {
        self.polls_left = n;
        if n == 0 {
            return Ok(());
        }
        for chan in self.users.terms().all() {
            // Already armed: either `dopoll` re-injected before the budget ran
            // out, or the last burst hit `cycle`'s pass bound with statuses
            // still queued. Injecting again would add a dispatch per wake.
            if self.gsbl.polling_armed(chan) {
                continue;
            }
            match self.users.polrou(machine, chan) {
                Ok(Some(_)) => self.gsbl.inject(chan, gsbl::Gsbl::POLSTS),
                Ok(None) => {}
                Err(e) => {
                    return Err(io::Error::other(format!(
                        "refill_polls: reading polrou for channel {chan}: {e:?}"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Turn the main loop until something says stop.
    ///
    /// `MAJORBBS.C:417-480`, minus everything this host has already declined --
    /// `syscyc`/`prctask` (`:423`), `chncyc` (`:474`), `shomal`, and the
    /// `usrptr->class` switch. What is left is: service one status if any, then
    /// catch the tick counter up to the clock, running [`Host::prcrtk`] once per
    /// elapsed second.
    ///
    /// **`max` bounds passes, not dispatches.** A bound on dispatches would
    /// make a module that stopped polling to wait on a timer return zero work
    /// forever.
    ///
    /// It returns as soon as nothing is queued, rather than spinning until a
    /// timer comes due. The caller advances time by sleeping and calling back;
    /// [`Ended::wait`] says how long. The old loop turned here because the
    /// original's did, and the original's did because it owned the machine.
    ///
    /// This never sleeps. One thread owns the `Machine`, so a sleep here would
    /// be a sleep the socket cannot interrupt; the caller owns all blocking and
    /// [`Ended`] carries what it needs to decide.
    ///
    /// # Errors
    ///
    /// If no module has registered, or the machine malfunctions. A module that
    /// stops is [`Ended::Stopped`], not an error.
    pub fn cycle(
        &mut self,
        machine: &mut Machine,
        module: &Module,
        max: usize,
    ) -> io::Result<Cycles> {
        let mut iterations = 0;
        let mut dispatched = 0;

        while iterations < max {
            iterations += 1;

            // No `pending()` guard here, and deliberately. `Host::poll`'s first
            // act is the same scan, and it returns `Ok(None)` before touching
            // the module or the machine when that scan finds nothing -- so a
            // guard testing the identical predicate could only agree with it.
            // It was written as one, and review found that mutating the guard
            // away left all 739 tests passing, which is what unobservable looks
            // like.
            match self.poll(machine, module)? {
                Some(Outcome::Stopped(poison)) => {
                    return Ok(Cycles {
                        iterations,
                        dispatched,
                        ended: Ended::Stopped(poison),
                    });
                }
                Some(Outcome::Returned { .. }) => dispatched += 1,
                // A status that dispatched nothing: a stale `POLSTS`, or an
                // entry point the module never registered. `poll` has
                // consumed it either way.
                None => {}
            }

            // `MAJORBBS.C:476`, with two changes the original did not need.
            // `get_or_insert` is the first pass syncing rather than catching up
            // from 1970, and `<` is where the original had `!=`: `ticker` could
            // only wrap, a system clock can be set backwards, and `!=` would
            // then run about four billion rounds firing timers on every one.
            let now = self.clock().epoch().map_err(io::Error::other)?;
            let mut last = *self.tcklst.get_or_insert(now);
            if now < last {
                self.note(format!(
                    "cycle: the clock went backwards, {last} to {now}; resyncing without firing"
                ));
                last = now;
            }
            let mut rounds = 0;
            while last < now {
                last += 1;
                rounds += 1;
                if let Some(poison) = self.prcrtk(machine, module, &mut dispatched)? {
                    // Written back before the early return: the rounds already
                    // run must not run again on the next `cycle`.
                    self.tcklst = Some(last);
                    return Ok(Cycles {
                        iterations,
                        dispatched,
                        ended: Ended::Stopped(poison),
                    });
                }
            }
            self.tcklst = Some(last);
            if rounds > 1 {
                self.note(format!(
                    "cycle: {rounds} seconds of timers in one pass -- the host stalled"
                ));
            }

            // Nothing queued. Whether a timer is outstanding decides which
            // kind of nothing this is, but either way the loop has no reason
            // to turn again: `prcrtk` cannot fire before the next whole
            // second, and no other source of work exists -- the 16-bit world
            // only advances when this host dispatches into it. Spinning here
            // was the whole of the old busy-wait.
            if !self.gsbl().pending() {
                let next_kick = self.kicks.iter().map(|kick| kick.delay).min();
                return Ok(Cycles {
                    iterations,
                    dispatched,
                    ended: match next_kick {
                        Some(next_kick) => Ended::Waiting {
                            next_kick,
                            polls_cut: self.polls_left == 0,
                        },
                        None => Ended::Idle,
                    },
                });
            }
        }

        let next_kick = self.kicks.iter().map(|kick| kick.delay).min();
        Ok(Cycles {
            iterations,
            dispatched,
            ended: Ended::Bound { next_kick },
        })
    }

    /// `void alcvda(void)` -- give every channel its volatile data area.
    ///
    /// `MAJORBBS.C:1370`, called from `:896` *after* every module's init
    /// routine has run, because `dclvda` is what decides the size and it is
    /// still being called until then. Not part of [`Host::new`] for that
    /// reason: a host that allocated at construction would size the area off a
    /// `vdasiz` of zero and every `vdaptr` the module read would be null.
    ///
    ///
    /// `vdaptr` is left pointing at channel 0, matching `vdarea=vdaoff(0)` at
    /// `:1374`; `curusr` is what re-points it per channel afterwards. `vdatmp`
    /// is a block of its own and not a slot, because `fsdapr` is handed both at
    /// once and they must not be the same bytes.
    ///
    /// Doing nothing when `vdasiz` is zero is the original's own `if`, and it
    /// is load-bearing here: this heap refuses an allocation of nothing.
    ///
    /// # Errors
    ///
    /// If the heap has no room.
    /// Every module has initialised: finish the host's own setup.
    ///
    /// `MAJORBBS.C:896`. The real host runs `inimod()` over every module and
    /// then, on the next line, `alcvda()` -- in that order and not the other,
    /// because `dclvda` is still accumulating `vdasiz` while modules
    /// initialise. A host that allocated in [`Host::new`] would size every
    /// volatile data area off a `vdasiz` of zero.
    ///
    /// # Why this is a step the caller must take, and why forgetting it is refused
    ///
    /// [`Host::alcvda`] was correct, complete and tested for weeks while
    /// **nothing in the crate called it** -- every caller was a test. Nothing
    /// failed. `vdasiz` reached 1,961 from `WCCMMUD.DLL`'s own `dclvda` and
    /// `vdaptr`/`vdatmp` stayed null, and the module noticed long before this
    /// host did: `_EDIT_CHARACTER_STATS` tests `vdatmp` before it draws
    /// anything and returns silently when it is null. Character creation took
    /// the player's answer, computed the whole character, resolved its title,
    /// and stopped without printing a byte or advancing its substate.
    ///
    /// That cost days to find, because a *global* the module reads is invisible
    /// to a host-call trace -- the signature is "every routine it reaches is
    /// implemented and it still does nothing". So this host refuses to
    /// [`connect`](Self::connect) a channel until this has run, which turns the
    /// whole class of mistake into an error message naming the step.
    ///
    /// Idempotent, and doing nothing when no module declared a size is
    /// `alcvda`'s own `if (vdasiz != 0)`.
    ///
    /// # Errors
    ///
    /// If the volatile data areas cannot be allocated.
    pub fn finish_init(&mut self, machine: &mut Machine) -> io::Result<()> {
        self.alcvda(machine)?;
        // `MAJORBBS.C:908-911`, the next thing the real host does after
        // `alcvda()`: reset every channel. See [`Host::rstchn`] for why startup
        // and disconnect share one routine. The order is `:896` then `:908` and
        // not the other way about.
        for chan in self.users.terms().all() {
            self.rstchn(machine, chan)
                .map_err(|e| io::Error::other(format!("rstchn({chan}): {e}")))?;
        }
        // `inifsd()` registers FSDBBS as an ordinary module during startup;
        // this is that registration. It must happen before `inited` is set,
        // so nothing can reach a channel's `state` before the FSD's slot
        // exists to be named.
        self.fsd_state = Some(self.register_native(Native::Fsd));
        self.inited = true;
        Ok(())
    }

    pub fn alcvda(&mut self, machine: &mut Machine) -> io::Result<()> {
        let size = self.globals.word(machine, "vdasiz")?;
        if size == 0 {
            return Ok(());
        }
        self.users.alcvda(machine, &mut self.heap, size)?;
        let console = self
            .users
            .terms()
            .chan(0)
            .expect("every host has a channel zero");
        let area = self.users.vda(console).expect("just allocated");
        let temp = self.heap.alloc(machine, size).map_err(io::Error::other)?;
        self.globals.write(machine, "vdaptr", &area.to_bytes())?;
        self.globals.write(machine, "vdatmp", &temp.to_bytes())?;
        Ok(())
    }

    /// How many host calls this host has serviced.
    pub fn calls(&self) -> u64 {
        self.calls
    }

    /// Print every host call as it is serviced, numbered.
    ///
    /// Where a module *stopped* is in the outcome, but how it got there is only
    /// visible as a sequence -- and every step of this host so far has found the
    /// order the module actually asks in differing from what was predicted for
    /// it. On by default when `MBBS_TRACE` is set in the environment, so that
    /// producing the sequence never means editing code to get it.
    pub fn set_trace(&mut self, trace: bool) {
        self.trace = trace;
    }

    /// Find one of the module's files, whatever case it named it in.
    ///
    /// DOS filenames are case-insensitive and a module's are all upper case in
    /// some places and not in others; the filesystem underneath is not. An
    /// exact match first, then one scan of the directory -- so the ordinary
    /// case costs nothing and the awkward one still works.
    pub fn find(&self, name: &str) -> Option<PathBuf> {
        let exact = self.root.join(name);
        if exact.is_file() {
            return Some(exact);
        }
        std::fs::read_dir(&self.root)
            .ok()?
            .filter_map(Result::ok)
            .find(|e| e.file_name().to_string_lossy().eq_ignore_ascii_case(name))
            .map(|e| e.path())
    }

    /// The file a module named, with the directory it is allowed to name
    /// stripped off.
    ///
    /// A module builds its filenames from `DATADIR`, an option in its `.MSG`.
    /// MajorMUD's is empty, so what `spr` produces is `.\WCCITEMS.DAT` -- the
    /// module's own directory, which is [`Host::root`] and is where this host
    /// looks anyway. That prefix is accepted and removed.
    ///
    /// **Any other directory is refused rather than stripped.** A module
    /// configured with `DATADIR` of `D:\MUD\DATA` means it, and quietly reading
    /// the file of the same name from somewhere else would be the exact failure
    /// this crate exists to avoid -- with the added charm that a board with two
    /// installs would silently play the wrong one.
    ///
    /// # Errors
    ///
    /// If the name has a directory component other than `.\`.
    pub fn dos_name(named: &str) -> Result<&str, String> {
        let bare = named
            .strip_prefix(".\\")
            .or_else(|| named.strip_prefix("./"))
            .unwrap_or(named);
        if bare.contains(['\\', '/', ':']) {
            return Err(format!(
                "{named} names a directory; this host only opens a module's own"
            ));
        }
        Ok(bare)
    }

    /// Find one of the module's Btrieve files, installing it if this is a fresh
    /// board.
    ///
    /// A MajorMUD distribution ships fifteen `.VIR` files and no `.DAT`, and the
    /// module opens `.DAT`. The `.VIR` is the *virgin* copy -- the pristine
    /// content, ready to be played on -- and turning one into the other is an
    /// install step that the sysop's `WCCMISC.BAT` and the setup program did
    /// between them. It is done here, once per file, and said out loud.
    ///
    /// This is the one place the host creates something rather than reading it,
    /// so it is worth being exact about what it is not: it never invents a file
    /// that has no virgin copy, and it never writes to the `.VIR` itself. A
    /// `.DAT` this host cannot account for is a refusal, because the failure it
    /// replaces -- handing the module an empty file where the game's content
    /// should be -- looks exactly like a working board with no items in it.
    ///
    /// # Errors
    ///
    /// If neither the file nor a virgin copy of it is there, or the copy fails.
    pub fn btrieve_file(&mut self, name: &str) -> Result<PathBuf, String> {
        if let Some(path) = self.find(name) {
            return Ok(path);
        }

        let stem = name.rsplit_once('.').map_or(name, |(stem, _)| stem);
        let virgin = format!("{stem}.VIR");
        let from = self.find(&virgin).ok_or_else(|| {
            format!(
                "no {name} in {}, and no {virgin} to install it from",
                self.root.display()
            )
        })?;

        // Copied beside the destination and then renamed onto it, because a
        // rename within a directory is the one filesystem operation that
        // cannot be seen half-done. `WCCMP001.DAT` is 43 MB, and a plain copy
        // interrupted -- or merely *read* while it is still going -- is a file
        // whose header says it has 29,232 pages and whose body does not. That
        // file would then look installed forever after.
        let to = self.root.join(name);
        let part = self
            .root
            .join(format!("{name}.{}.part", std::process::id()));
        std::fs::copy(&from, &part)
            .and_then(|_| std::fs::rename(&part, &to))
            .map_err(|e| {
                let _ = std::fs::remove_file(&part);
                format!("installing {name} from {}: {e}", from.display())
            })?;
        self.installed.push(name.to_owned());
        self.note(format!(
            "installed {name} from {} -- this board had never been played on",
            from.display()
        ));
        Ok(to)
    }

    /// The next of `spr`'s rotating buffers.
    fn next_spr_buffer(&mut self) -> FarPtr {
        let at = FarPtr {
            offset: self.spr.offset + (self.spr_next as u16) * shims::text::SPR_BYTES,
            selector: self.spr.selector,
        };
        self.spr_next = (self.spr_next + 1) % shims::text::SPR_BUFFERS;
        at
    }

    /// The line buffer `gmdnam` writes into.
    fn mdf_buffer(&self) -> FarPtr {
        self.mdf
    }

    /// One NUL byte the host owns and keeps. See [`Host::empty`].
    fn empty_string(&self) -> FarPtr {
        self.empty
    }

    /// One past the last byte `prf` may write.
    fn prf_end(&self) -> u16 {
        self.prf_end
    }

    /// Take a module online, and give it its number.
    fn register(&mut self, description: String, block: FarPtr) -> u16 {
        self.modules.push(Registration::Module { description, block });
        (self.modules.len() - 1) as u16
    }

    /// Give a host-native handler a `state` slot, the way [`Host::register`]
    /// gives a module one. Returns the slot's index, for the same reason
    /// `register_module` hands its caller a number back: whoever registered
    /// it is the one who writes it into `user[chan].state`.
    ///
    /// [`Host::finish_init`] is this crate's `inifsd()` -- the FSD registers
    /// its own native slot there, not here.
    pub(crate) fn register_native(&mut self, native: Native) -> usize {
        self.modules.push(Registration::Native(native));
        self.modules.len() - 1
    }

    /// Load a module, binding its imports to this host.
    ///
    /// The globals the module addresses are checked *before* anything is
    /// mapped, because the failure they would otherwise produce is silent: a
    /// datum the host does not place gets a thunk, and a module reading a
    /// thunk as a variable reads executable bytes and carries on.
    ///
    /// # Errors
    ///
    /// If the file is not a well-formed NE module, or the module addresses a
    /// global the host cannot provide.
    pub fn load(&mut self, machine: &mut Machine, file: &[u8]) -> Result<Module, LoadError> {
        let image = NeImage::parse(file).map_err(io::Error::from)?;

        let missing = self.check_globals(&image, file);
        if !missing.is_empty() {
            return Err(LoadError::Globals(missing));
        }

        let resolver = Resolver {
            exports: self.exports,
            globals: &self.globals,
        };
        Ok(machine.load_ne(file, &resolver)?)
    }

    /// Call a module entry point, servicing its imports until it stops.
    ///
    /// # Errors
    ///
    /// If the module cannot be entered, or the machine malfunctions. A module
    /// that faults, overruns or asks for something unimplemented is not an
    /// error -- it is [`Outcome::Stopped`], which says which.
    pub fn run(
        &mut self,
        machine: &mut Machine,
        module: &Module,
        entry: FarPtr,
        args: &[u16],
    ) -> io::Result<Outcome> {
        let mut exit = machine.call(entry, args)?;
        loop {
            let index = match exit {
                Exit::Returned { ax, dx } => return Ok(Outcome::Returned { ax, dx }),
                Exit::Fault { .. } | Exit::Timeout { .. } => {
                    let poison = machine
                        .poisoned()
                        .expect("a terminal exit poisons the machine")
                        .clone();
                    return Ok(Outcome::Stopped(poison));
                }
                Exit::Call { index } => index,
            };

            // A thunk index the module does not have is not something a module
            // can cause -- it comes from the bridge, and the bridge is the
            // host's. Report it as an unnamed import rather than panicking, so
            // that a loader bug looks like every other refusal.
            let (from, symbol) = match module.import(index) {
                Some(site) => (
                    site.module.clone(),
                    self.symbol_name(&site.module, &site.symbol),
                ),
                None => (String::new(), format!("thunk #{index}")),
            };

            let (shim, cleans) = match shims::entry(&from, &symbol) {
                Entry::Routine(shim, cleans) => (shim, cleans),
                Entry::Datum | Entry::Absolute(_) | Entry::Unimplemented => {
                    let symbol = match caller(machine, module) {
                        Some(at) => format!("{symbol}, called from {at}"),
                        None => symbol,
                    };
                    return self.stop(
                        machine,
                        Poison::Unimplemented {
                            module: from,
                            symbol,
                        },
                    );
                }
            };

            self.calls += 1;
            if self.trace {
                eprintln!("{:4} {symbol}", self.calls);
            }
            match shim(machine, self) {
                Ok(ret) => {
                    exit = match cleans {
                        shims::Cleans::Caller => machine.resume(ret)?,
                        shims::Cleans::Callee(bytes) => machine.resume_cleaning(ret, bytes)?,
                    };
                }
                Err(e) => {
                    let symbol = match caller(machine, module) {
                        Some(at) => format!("{symbol} ({e}), called from {at}"),
                        None => format!("{symbol} ({e})"),
                    };
                    return self.stop(
                        machine,
                        Poison::Unimplemented {
                            module: from,
                            symbol,
                        },
                    );
                }
            }
        }
    }

    fn stop(&self, machine: &mut Machine, reason: Poison) -> io::Result<Outcome> {
        machine.poison(reason)?;
        let poison = machine.poisoned().expect("just poisoned").clone();
        Ok(Outcome::Stopped(poison))
    }

    /// Cross a `ShimError` from [`Host::connect`] or [`Host::poll`]'s own
    /// internal calls into a poisoned machine, the same way [`Host::run`]
    /// does for a `ShimError` a shim it dispatched through a thunk returns.
    ///
    /// `connect_state`, `point_curusr` and `get_input` predate `connect`/
    /// `poll` and already answer in `Result<_, ShimError>`, reached directly
    /// rather than through a thunk -- so `run`'s own crossing does not cover
    /// them, and this is the only other place a `ShimError` becomes an
    /// `Outcome`. Refusing plausible-but-wrong state is this crate's whole
    /// ethic; leaving the machine runnable after `connect_state` half-wrote
    /// an account record, or after `point_curusr` pointed `usrnum` at the
    /// wrong channel, would be a hole in it -- so this does what `run` does
    /// for the identical failure reached through a thunk: poison and answer
    /// `Outcome::Stopped`, rather than an `Err` that leaves the machine
    /// runnable.
    ///
    /// `where_` names the call that failed, since none of the three is an
    /// imported symbol with a DLL of its own to report. The
    /// `BadPointer`/`Failed` distinction survives into the poison's
    /// `symbol` rather than being flattened through `Display` alone --
    /// `ShimError` has no `Error` impl to recover it from afterwards.
    fn shim_stop(&self, machine: &mut Machine, where_: &str, e: ShimError) -> io::Result<Outcome> {
        let symbol = match &e {
            ShimError::BadPointer(_) => format!("{where_}: bad pointer, {e}"),
            ShimError::Failed(_) => format!("{where_}: {e}"),
        };
        self.stop(
            machine,
            Poison::Unimplemented {
                module: "mbbs".to_owned(),
                symbol,
            },
        )
    }

    /// The C name of an imported symbol, or something that identifies it when
    /// the host has no name for it.
    fn symbol_name(&self, from: &str, symbol: &Symbol) -> String {
        match symbol {
            Symbol::Name(name) => exports::c_name(name).into_string(),
            Symbol::Ordinal(n) => self
                .exports
                .name(from, *n)
                .map(str::to_owned)
                .unwrap_or_else(|| format!("#{n}")),
        }
    }

    /// Every global the module addresses that the host cannot honestly place.
    fn check_globals(&self, image: &NeImage, file: &[u8]) -> Vec<MissingGlobal> {
        let mut missing = Vec::new();
        for ((from, symbol), reach) in addressed_as_data(image, file) {
            let name = self.symbol_name(&from, &symbol);
            let why = match shims::entry(&from, &name) {
                // A constant has no memory to be too small, and a routine whose
                // address is taken in pieces is a routine -- the thunk's
                // address is the right thing to write.
                Entry::Absolute(_) | Entry::Routine(..) => continue,
                Entry::Unimplemented => Why::NotPlaced,
                Entry::Datum => {
                    let size = self.globals.size(&name).expect("a datum is placed");
                    if reach.max < i32::from(size) {
                        continue;
                    }
                    Why::TooSmall {
                        addend: reach.max as i16,
                        size,
                    }
                }
            };
            missing.push(MissingGlobal {
                module: from,
                symbol: name,
                why,
            });
        }
        missing.sort_by(|a, b| (&a.module, &a.symbol).cmp(&(&b.module, &b.symbol)));
        missing
    }
}

/// How far into a symbol the module's fixups reach.
#[derive(Debug, Clone, Copy)]
struct Reach {
    min: i32,
    max: i32,
}

/// Which imported symbols the module *addresses* rather than calls, and how far
/// into each one it reaches.
///
/// Read out of the relocations rather than from a list of names. A `SEGMENT`,
/// `OFFSET` or `LOBYTE` fixup writes part of an address into the middle of an
/// instruction, which is what taking a variable's address looks like; only
/// `FAR_ADDR` writes the whole thing, which is what a call needs. The
/// classification is one-directional and deliberately so: a routine whose
/// address is taken in pieces would be misread as data, and that is a load
/// error rather than a silent wrong binding.
///
/// The reach is the addend the fixup carries, which for an additive record is
/// the word already sitting at the site. It is **signed**: `WCCMMUD.DLL`
/// reaches `margv` with `0xfffe`, which is -2 and not 65,534.
fn addressed_as_data(image: &NeImage, file: &[u8]) -> HashMap<(String, Symbol), Reach> {
    // Which symbols are data, and how far into each one anything reaches, are
    // two different questions over the same 22,371 records: a datum can also be
    // reached by FAR_ADDR -- `p = margv` and `f()` are the same fixup -- and
    // those addends count too. So classify first, measure second.
    let mut data = std::collections::HashSet::new();
    let mut reach: HashMap<(String, Symbol), Reach> = HashMap::new();

    for pass in 0..2 {
        for segment in &image.segments {
            let bytes = &file[segment.file.clone()];
            for reloc in &segment.relocations {
                let Target::Import { module, symbol } = &reloc.target else {
                    continue;
                };
                let Ok(from) = image.module_name(*module) else {
                    continue;
                };
                let key = (from.to_owned(), symbol.clone());

                if pass == 0 {
                    if reloc.source != Source::FarAddr {
                        data.insert(key);
                    }
                    continue;
                }
                if !data.contains(&key) {
                    continue;
                }

                let at = i32::from(addend(reloc, bytes));
                let seen = reach.entry(key).or_insert(Reach { min: at, max: at });
                seen.min = seen.min.min(at);
                seen.max = seen.max.max(at);
            }
        }
    }

    reach
}

/// The addend a fixup carries.
///
/// Only an additive record has one: a chained record's site holds the offset of
/// the next link, which is not a number to add to anything. Same reading as
/// `apply()` in the loader, and it has to stay the same reading.
fn addend(reloc: &Relocation, segment: &[u8]) -> i16 {
    if !reloc.additive {
        return 0;
    }
    let at = usize::from(reloc.offset);
    match reloc.source {
        Source::LoByte => segment.get(at).map_or(0, |b| i16::from(*b)),
        _ => match segment.get(at..at + 2) {
            Some(word) => i16::from_le_bytes([word[0], word[1]]),
            None => 0,
        },
    }
}

/// Answers "what is `MAJORBBS.474`?" for the loader.
struct Resolver<'a> {
    exports: &'static Exports,
    globals: &'a Globals,
}

impl ImportResolver for Resolver<'_> {
    fn resolve(&self, module: &str, symbol: &Symbol) -> Option<Import> {
        let name = match symbol {
            Symbol::Name(name) => exports::c_name(name).into_string(),
            Symbol::Ordinal(n) => self.exports.name(module, *n)?.to_owned(),
        };

        match shims::entry(module, &name) {
            // A datum is addressed, never called, so the host's own memory goes
            // into the fixup and nothing is ever dispatched for it.
            Entry::Datum => Some(Import::Data(self.globals.address(&name)?)),
            Entry::Absolute(value) => Some(Import::Absolute(value)),
            Entry::Routine(..) => Some(Import::Routine),

            // The loader gives it a thunk anyway. That is what makes calling it
            // an event the host is told about rather than a far call into
            // nothing.
            Entry::Unimplemented => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::testing::Fixture;
    use crate::users::Connection;
    use crate::{
        Clock, Dispatch, Ended, Host, Kick, Native, Outcome, Registration, Terms, gsbl, testing,
        users,
    };
    use mbbs16::{FarPtr, Machine, Ret};

    #[test]
    fn a_host_is_built_with_as_many_channels_as_it_is_asked_for() {
        // The three authorities `Host::new` asserts against each other -- `Users`'
        // tables, `Gsbl`'s channels, and the `nterms` word in module memory -- must
        // all follow the count the caller passed, not a constant this crate reads
        // for itself. Four channels rather than two so that an off-by-one in the
        // table sizing cannot coincide with the count.
        let mut machine = Machine::new().expect("16-bit machine");
        let host = Host::new(&mut machine, testing::data(), Terms::new(4)).expect("host");

        assert_eq!(host.users().terms().count(), 4, "Users' tables");
        assert_eq!(host.gsbl().terms().count(), 4, "Gsbl's channels");
        assert_eq!(
            host.globals().word(&machine, "nterms").expect("nterms"),
            4,
            "what the module bounds its own loops by"
        );
        assert!(
            host.users().terms().chan(3).is_some(),
            "the fourth channel is nameable"
        );
        assert!(
            host.users().terms().chan(4).is_none(),
            "and there is no fifth"
        );

        // Everything above reads a *declared* count. That is not enough, and
        // the gap was found by mutation rather than argued: sizing
        // `Users::new`'s three blocks from `globals::NTERMS` while still
        // recording the caller's `terms` leaves `Users::terms()` answering four
        // over tables one record long, and **all 736 tests passed**. Silent in
        // exactly the direction `crate::chan` calls dangerous, and the
        // `Gsbl` direction was already covered by `Host::new`'s three-way
        // assert while this one was not.
        //
        // So this writes through every channel's `user` slot and checks the
        // neighbouring blocks did not move under it. Four slots span
        // `4 * 41` bytes from the base; a block sized for one channel is 41,
        // so the write runs off the end of it and into whatever the heap
        // handed out next. Alignment cannot save it -- 123 bytes of overrun is
        // wider than any padding between two heap blocks.
        let sentinel = [0xffu8; users::USER as usize];
        for chan in host.users().terms().all() {
            machine
                .write(host.users().slot(chan), &sentinel)
                .expect("every channel has a whole user record to write");
        }
        for chan in host.users().terms().all() {
            for (what, at, len) in [
                ("extusr", host.users().extra(chan), users::EXTUSR),
                ("usracc", host.users().account(chan), users::USRACC),
            ] {
                let bytes = machine.resolve(at, usize::from(len)).expect(what);
                assert!(
                    bytes.iter().all(|&b| b == 0),
                    "writing the four user records reached channel {chan}'s {what}, \
                     so the tables are not four channels long"
                );
            }
        }
    }

    #[test]
    fn every_global_that_names_the_current_channel_follows_the_channel() {
        // `point_curusr` writes four globals, and until this test three of them
        // were pinned and one was not. Pointing `vdaptr` at channel 0's area for
        // every dispatch passed **all 786 tests** -- 769 lib and all 17
        // real-module, including the two-player run.
        //
        // The reason it hid is the reason this whole branch exists: every other
        // `point_curusr` test uses a one-channel fixture, where `vda(console)`
        // and `vda(chan 0)` are the same address and the assertion is satisfied
        // by construction. `curusr_repoints_every_global_that_names_the_current_channel`
        // in `shims/user.rs` is one of those, and it is not wrong -- it is just
        // unable to see this.
        //
        // MajorMUD leaves the volatile data area zero on the returning-player
        // path, so the defect is unobservable through the module *today*. That
        // is precisely the argument that made `btuxmt`'s channel argument
        // unfalsifiable at one channel, and it was wrong then.
        let mut machine = Machine::new().expect("16-bit machine");
        let mut host =
            Host::new(&mut machine, testing::data(), Terms::new(2)).expect("host");
        // A volatile data area only exists once a module has declared a size,
        // and `Fixture` has no module -- so declare one the way `dclvda` would.
        host.globals()
            .write(&mut machine, "vdasiz", &64u16.to_le_bytes())
            .expect("vdasiz");
        host.finish_init(&mut machine).expect("finished starting up");

        for chan in host.users().terms().all() {
            host.point_curusr(&mut machine, chan).expect("point_curusr");
            let g = host.globals();
            assert_eq!(
                g.word(&machine, "usrnum").expect("usrnum") as i16,
                chan.number(),
                "usrnum"
            );
            for (name, want) in [
                ("usrptr", host.users().slot(chan)),
                ("usaptr", host.users().account(chan)),
                ("vdaptr", host.users().vda(chan).expect("an area per channel")),
            ] {
                let got = g.pointer(&machine, name).expect(name);
                assert_eq!(got, want, "{name} does not follow channel {chan}");
            }
        }
    }

    #[test]
    fn a_reset_channel_keeps_none_of_the_previous_players_gsbl_state() {
        // `dftrst` does not stop at the three `setmem`s: `MAJORBBS.C:3503` is
        // `switch (rc=bturst(usrnum))`, and the guide (`bturst`, page 138) says
        // it "completely resets a channel, in both hardware and software, to its
        // initial default conditions."
        //
        // Clearing the module's three records while GSBL keeps its own is the
        // worst shape this could take: the module believes nobody is there and
        // the channel still holds a half-typed command, which then arrives as
        // the *next* player's first input. Nothing observes it at one channel,
        // because there is never a next player.
        let mut f = Fixture::new();
        let chan = f.console();

        // Every kind of state a channel carries: queued input, a partial line,
        // undrained output, a queued status, and terminal settings.
        f.host.gsbl_mut().push_input(chan, b"who\rhalf-typed");
        f.host.gsbl_mut().inject(chan, gsbl::Gsbl::CRSTG);
        {
            let c = f.host.gsbl_mut().channel_mut(chan);
            c.width = 40;
            c.echo = false;
            c.locked = true;
        }
        f.host.gsbl_mut().transmit(chan, b"a line the previous player never read");

        assert!(f.host.gsbl().pending(), "the channel is dirty before the reset");

        f.host.rstchn(&mut f.machine, chan).expect("reset");

        let c = f.host.gsbl().channel(chan);
        assert_eq!(c.width, 0, "btutsw width");
        assert!(c.echo, "btuech is on by default");
        assert!(!c.locked, "btulok");
        assert!(
            !f.host.gsbl().pending(),
            "a queued status survived the reset"
        );
        assert!(
            f.host.gsbl_mut().drain_output(chan).is_empty(),
            "the previous player's undrained output survived the reset"
        );
    }

    #[test]
    fn resetting_a_channel_leaves_nothing_of_the_previous_user_behind() {
        // `dftrst`, `MAJORBBS.C:3487-3500`. The bug this prevents is a channel
        // handed to a second player while still holding the first player's
        // account bytes -- invisible at one channel, because there is never a
        // second player to hand it to.
        let mut f = Fixture::new();
        let chan = f.console();

        let who = users::Connection::ansi("rangerdan").with_keys(["PLAYKEY"]);
        f.host
            .connect_state(&mut f.machine, chan, &who)
            .expect("a user on the channel");

        // Prove the channel is dirty before the reset, so the assertions after
        // it are testing the reset rather than an allocator's zero.
        let account = f.host.users().account(chan);
        assert_eq!(
            f.machine.resolve(account, 9).expect("account"),
            b"rangerdan",
            "the userid is really there before rstchn runs"
        );
        assert!(f.host.users().keys(chan).is_some(), "and so is a keyring");

        f.host.rstchn(&mut f.machine, chan).expect("reset");

        for (what, at, len) in [
            ("user", f.host.users().slot(chan), users::USER),
            ("extusr", f.host.users().extra(chan), users::EXTUSR),
            ("usracc", f.host.users().account(chan), users::USRACC),
        ] {
            let bytes = f.machine.resolve(at, usize::from(len)).expect(what);
            assert!(
                bytes.iter().all(|&b| b == 0),
                "{what} still holds {} non-zero bytes after rstchn",
                bytes.iter().filter(|&&b| b != 0).count()
            );
        }

        assert!(
            f.host.users().keys(chan).is_none(),
            "freekey() leaves NULL, not an empty keyring -- \
             `usrptr->keys != NULL` is what MAJORBBS.C:3492 tests"
        );
    }

    #[test]
    fn every_channel_is_reset_when_the_host_finishes_starting_up() {
        // `MAJORBBS.C:908-911` -- the reset loop runs over every channel right
        // after alcvda. A channel the host has never touched and a channel just
        // freed must be the same state, and this is what makes them so.
        let mut machine = Machine::new().expect("16-bit machine");
        let mut host = Host::new(&mut machine, testing::data(), Terms::new(3)).expect("host");

        // Dirty a channel *before* finish_init, the way a heap that does not
        // zero would have left it.
        let chan = host.users().terms().chan(2).expect("channel 2");
        let account = host.users().account(chan);
        machine.write(account, &[0xffu8; 16]).expect("dirty it");

        host.finish_init(&mut machine).expect("finished starting up");

        let bytes = machine
            .resolve(host.users().account(chan), 16)
            .expect("account");
        assert!(
            bytes.iter().all(|&b| b == 0),
            "finish_init did not reset channel 2"
        );
    }

    #[test]
    fn finish_init_registers_the_fsd_as_a_native_module() {
        // `inifsd()` registers FSDBBS as an ordinary module during startup,
        // the same startup sequence `finish_init` already runs `alcvda` and
        // the `rstchn` loop for. The FSD's own `state` slot must exist by
        // the time anything could reach it -- `Host::fsd_state()` is how the
        // rest of the FSD subsystem finds that slot's number.
        let mut machine = Machine::new().expect("16-bit machine");
        let mut host = Host::new(&mut machine, testing::data(), Terms::new(1)).expect("host");

        host.finish_init(&mut machine).expect("finished starting up");

        let n = host.fsd_state();
        assert_eq!(
            host.modules()[n],
            Registration::Native(Native::Fsd),
            "finish_init did not register the FSD's native slot"
        );
    }

    #[test]
    fn a_reset_clears_the_channel_it_names_and_leaves_its_neighbours_alone() {
        // The two tests above share a shape, and three real defects fit through
        // it. Every assertion either of them makes is about the *target*
        // channel, the first runs on a one-channel host where "the wrong
        // channel" cannot be spelled at all, and the only block ever observed
        // dirty beforehand is `usracc` -- `connect_state` writes no non-zero
        // byte into `user` or `extusr`, and `Users::new` zeroed both, so those
        // two assertions were checking zero against zero. Measured, not
        // supposed: with only those two tests, all 743 passed while
        //
        //   * `rstchn` cleared `usracc` and left `user` and `extusr` alone,
        //   * `rstchn` cleared *every* channel rather than the one named --
        //     one player disconnecting wipes the record of everyone still on,
        //   * `Users::clear_keys` ignored its argument and freed channel 0's
        //     keyring whichever channel was being reset.
        //
        // So: three channels, all three dirtied in all three blocks and given
        // keyrings, the *middle* one reset, and both neighbours asserted
        // byte-for-byte afterwards. A gap on each side, because an off-by-one
        // in either direction lands on a channel that is being watched.
        let mut f = Fixture::rooted_with_terms(testing::data(), Terms::new(3));
        let chans: Vec<crate::Chan> = f.host.users().terms().all().collect();

        // The mark is per channel, so "untouched" is a stronger claim than
        // "non-zero": a neighbour holding another channel's mark would fail
        // too.
        let mark = |chan: crate::Chan| 0xa0u8 | chan.index() as u8;
        for &chan in &chans {
            let who = users::Connection::ansi("rangerdan").with_keys(["PLAYKEY"]);
            f.host
                .connect_state(&mut f.machine, chan, &who)
                .expect("a user on every channel");
            for (at, len) in [
                (f.host.users().slot(chan), users::USER),
                (f.host.users().extra(chan), users::EXTUSR),
                (f.host.users().account(chan), users::USRACC),
            ] {
                f.machine
                    .write(at, &vec![mark(chan); usize::from(len)])
                    .expect("a whole record to dirty");
            }
        }

        let middle = chans[1];
        f.host.rstchn(&mut f.machine, middle).expect("reset");

        for (what, at, len) in [
            ("user", f.host.users().slot(middle), users::USER),
            ("extusr", f.host.users().extra(middle), users::EXTUSR),
            ("usracc", f.host.users().account(middle), users::USRACC),
        ] {
            let bytes = f.machine.resolve(at, usize::from(len)).expect(what);
            assert!(
                bytes.iter().all(|&b| b == 0),
                "channel 1's {what} still holds {} non-zero bytes after rstchn",
                bytes.iter().filter(|&&b| b != 0).count()
            );
        }
        assert!(
            f.host.users().keys(middle).is_none(),
            "the reset channel's keyring is gone"
        );

        for &chan in [&chans[0], &chans[2]] {
            for (what, at, len) in [
                ("user", f.host.users().slot(chan), users::USER),
                ("extusr", f.host.users().extra(chan), users::EXTUSR),
                ("usracc", f.host.users().account(chan), users::USRACC),
            ] {
                let bytes = f.machine.resolve(at, usize::from(len)).expect(what);
                assert!(
                    bytes.iter().all(|&b| b == mark(chan)),
                    "resetting channel 1 reached channel {chan}'s {what}"
                );
            }
            assert!(
                f.host.users().keys(chan).is_some(),
                "channel {chan} was never reset and still holds its keyring"
            );
        }
    }

    /// `connect` needs a `&Module` whether or not this path ever reads it --
    /// [`Fixture::minimal_module`] loads one, but loading is not registering,
    /// so `f.host.modules()` is still empty and `connect` has nothing to
    /// enter. The full path, with a module that does register, is Task 10's
    /// integration test.
    #[test]
    fn connect_with_no_module_registered_is_an_error_not_a_panic() {
        let mut f = Fixture::new();
        let console = f.console();
        let module = f.minimal_module();
        let err = f
            .host
            .connect(&mut f.machine, &module, console, &Connection::ansi("rangerdan"))
            .expect_err("no module has registered");
        // R19: `is_err()` alone cannot tell this apart from a ShimError out
        // of `connect_state` or the `lonrou` lookup -- both are wrong for
        // different reasons and both would satisfy it. The text pins which
        // one this is.
        assert!(
            err.to_string().contains("no module has registered"),
            "expected the missing-registration message, got: {err}"
        );
    }

    /// A status that is read but never consumed must cost a red test, not the
    /// machine.
    ///
    /// This is the guard, exercised the only way it can be without mutating
    /// `poll` itself: queue more undispatched statuses than the bound. Each is
    /// consumed normally, so the loop is doing the right thing and still trips
    /// -- which is what makes the bound observable at all.
    ///
    /// The mutation this exists for -- peeking instead of popping -- reached
    /// 4.7 GB resident on a 7.5 GB box and the OOM killer took the whole
    /// session with it, because both `continue` arms allocate a note.
    #[test]
    fn poll_refuses_to_spin_forever_on_a_status_nothing_consumes() {
        let mut f = Fixture::new();
        let console = f.console();
        let module = f.minimal_module();

        // 253 is OVRFLW -- a real status this host queues and does not
        // dispatch, so every one takes the `continue` arm.
        for _ in 0..1100 {
            f.host
                .gsbl_mut()
                .channel_mut(console)
                .status
                .push_back(crate::gsbl::Gsbl::OVRFLW);
        }

        let e = f
            .host
            .poll(&mut f.machine, &module)
            .expect_err("the guard trips rather than looping");
        assert!(
            e.to_string().contains("not consumed"),
            "the error says what happened: {e}"
        );
    }

    /// No status queued, no channel to service, nothing to call.
    #[test]
    fn poll_with_nothing_queued_returns_none_and_calls_nothing() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let before = f.host.calls();
        assert!(
            f.host
                .poll(&mut f.machine, &module)
                .expect("no fault")
                .is_none()
        );
        assert_eq!(f.host.calls(), before, "nothing was dispatched");
    }

    /// A status is queued, but `poll` still needs somewhere to deliver it --
    /// and here, as in [`connect_with_no_module_registered_is_an_error_not_a_panic`],
    /// there is a `Module` but nothing has registered for this channel's
    /// state.
    #[test]
    fn poll_with_a_status_queued_but_no_module_registered_is_an_error_not_a_panic() {
        let mut f = Fixture::new();
        let console = f.console();
        let module = f.minimal_module();
        // `Fixture::new` -> `finish_init` has already registered the FSD's
        // own native slot at state 0 -- a real registration, just one with
        // no `sttrou` shape -- so "nothing registered" can no longer be had
        // by leaving state at its default. A state nothing names at all is
        // what this test is actually after; see
        // `poll_refuses_a_state_that_names_no_registered_module`.
        set_state(&mut f, console, 99);
        f.host.gsbl_mut().push_input(console, b"look\r");
        let err = f
            .host
            .poll(&mut f.machine, &module)
            .expect_err("state 99 names nothing");
        // R19: same reasoning as the `connect` test above -- `is_err()`
        // cannot distinguish this from a `ShimError` out of `point_curusr`,
        // `get_input` or the entry lookup, each a different failure.
        //
        // The wording is `state_entry`'s rather than a bare "no module has
        // registered": a channel at a state nothing names and a channel at
        // state 3 with one module registered are now different sentences,
        // and conflating them is what this assertion exists to stop.
        assert!(
            err.to_string().contains("state 99") && err.to_string().contains("1 module(s)"),
            "expected the missing-registration message, got: {err}"
        );
    }

    /// R20: `MAJORBBS.C:152` writes `status` unconditionally; only `shomal()`
    /// (out of scope) is behind the `!= 3` guard. Writing it only on the
    /// non-CRSTG path left `stsrou` reading a stale value on the CRSTG path.
    #[test]
    fn poll_writes_the_status_global_on_the_crstg_path_too() {
        let mut f = Fixture::new();
        let console = f.console();
        let module = f.minimal_module();
        f.host.gsbl_mut().push_input(console, b"look\r");
        // Whatever `poll` does with the dispatch itself -- error, or reach
        // the FSD's native slot at the channel's default state -- happens
        // after `point_curusr` and the `status` write, which is exactly what
        // is being checked; the outcome of the dispatch is not.
        let _ = f.host.poll(&mut f.machine, &module);
        assert_eq!(
            f.host
                .globals()
                .word(&f.machine, "status")
                .expect("status is placed"),
            crate::gsbl::Gsbl::CRSTG as u16,
            "status must be written before dispatch, not only off the CRSTG path"
        );
    }

    /// R23: an undispatched status ahead of a dispatchable one must not read
    /// as "nothing queued". `Ok(None)` is what `poll` answers when there is
    /// truly nothing to report; a driver written
    /// `while host.poll(..)?.is_some() {}` would stop dead on the first
    /// `OVRFLW` otherwise, with the CRSTG behind it never serviced.
    #[test]
    fn poll_loops_past_an_undispatched_status_to_the_dispatchable_one_behind_it() {
        let mut f = Fixture::new();
        let console = f.console();
        let module = f.minimal_module();
        // A state nothing names, so the CRSTG dispatch this test wants to
        // reach still errors -- state 0 is the FSD's own slot now that
        // `finish_init` registers it, and dispatching there would succeed
        // with `Ok(None)` instead. See `poll_refuses_a_state_that_names_no_registered_module`.
        set_state(&mut f, console, 99);
        f.host
            .gsbl_mut()
            .channel_mut(console)
            .status
            .push_back(crate::gsbl::Gsbl::OVRFLW);
        f.host.gsbl_mut().push_input(console, b"look\r");

        // No module is registered for this state, so `poll` errors -- but
        // only once it reaches the CRSTG dispatch, which it does only if the
        // `OVRFLW` ahead of it did not make `poll` stop and answer `Ok(None)`.
        let err = f
            .host
            .poll(&mut f.machine, &module)
            .expect_err("the CRSTG behind the OVRFLW is still there to dispatch");
        assert!(
            err.to_string().contains("no module to enter"),
            "expected to reach the CRSTG dispatch past the OVRFLW: {err}"
        );
    }

    /// R24: a module that registers but supplies no `sttrou` must not make
    /// `poll` fabricate `Returned { ax: 0, dx: 0 }` for a call that never
    /// happened -- and the CRSTG line `get_input` already took must leave a
    /// note behind, not disappear silently.
    #[test]
    fn poll_notes_rather_than_fabricates_when_the_registered_module_has_no_sttrou() {
        let mut f = Fixture::new();
        let console = f.console();
        let module = f.minimal_module();

        // A `struct module` block: a name, then nine far pointers, all left
        // null -- a module that registers but supplies no entry points at
        // all, `sttrou` included.
        let mut bytes = b"MajorMUD".to_vec();
        bytes.resize(25 + 9 * 4, 0);
        let block = f.bytes(&bytes, false);
        f.invoke(crate::shims::system::register_module, &Fixture::far(block))
            .expect("registered");

        f.host.gsbl_mut().push_input(console, b"look\r");
        let notes_before = f.host.notes().len();
        let outcome = f.host.poll(&mut f.machine, &module).expect("no fault");

        assert_eq!(outcome, None, "no sttrou means no call happened");
        assert!(
            f.host.notes().len() > notes_before,
            "a command dropped for lack of an entry point must leave a note"
        );
    }

    /// R24: the same fabrication, on `connect`'s side -- a module that
    /// registers with no `lonrou` at all must answer `None`, not a
    /// `Returned { ax: 0, dx: 0 }` for a `lonrou` call that never happened.
    #[test]
    fn connect_answers_none_rather_than_fabricates_when_lonrou_is_null() {
        let mut f = Fixture::new();
        let console = f.console();
        let module = f.minimal_module();
        let mut bytes = b"MajorMUD".to_vec();
        bytes.resize(25 + 9 * 4, 0);
        let block = f.bytes(&bytes, false);
        f.invoke(crate::shims::system::register_module, &Fixture::far(block))
            .expect("registered");

        let outcome = f
            .host
            .connect(&mut f.machine, &module, console, &Connection::ansi("rangerdan"))
            .expect("connect_state ran and there was nothing to call");
        assert_eq!(outcome, None, "no lonrou means no call happened");
    }

    /// Register a `struct module` whose entry points are these `(index,
    /// vector)` pairs, and null everywhere else. Returns the module number,
    /// the same way [`register_named`] does -- since `Host::finish_init`
    /// registers the FSD's own native slot first, this is no longer always
    /// zero, and a caller that needs to put a channel in *this* module's
    /// state has to use the number actually handed back.
    ///
    /// `index` is the position in `struct module` after `descrp` --
    /// [`Registration::dispatch`]'s own numbering, which `MAJORBBS.H:241-252`
    /// fixes: 0 `lonrou`, 1 `sttrou`, 2 `stsrou`, 3 `injrou`, 4 `lofrou`,
    /// 5 `huprou`.
    fn register_module_with(f: &mut Fixture, entries: &[(usize, FarPtr)]) -> u16 {
        let mut bytes = b"MajorMUD".to_vec();
        bytes.resize(25 + 9 * 4, 0);
        for (n, at) in entries {
            let field = 25 + n * 4;
            bytes[field..field + 4].copy_from_slice(&at.to_bytes());
        }
        let block = f.bytes(&bytes, false);
        let ret = f
            .invoke(crate::shims::system::register_module, &Fixture::far(block))
            .expect("registered");
        match ret {
            Ret::U16(n) => n,
            other => panic!("register_module returns the module number, not {other:?}"),
        }
    }

    /// 16-bit code that stores `mark` at `at` and returns, leaving `AX` alone.
    ///
    /// `AX` is the reason the selector goes through `BX`: `lofrou` returns an
    /// `int`, a non-zero one is refused by name, and a stub that loaded its
    /// selector through `AX` the way the rest of this file's stubs do would be
    /// indistinguishable from a module asking to be called again.
    /// [`Machine::call`] zeroes `AX` before every entry, so a stub that never
    /// touches it returns zero.
    fn marker_stub(at: FarPtr, mark: u8) -> Vec<u8> {
        let mut code = vec![0xbb]; // mov bx, <selector>
        code.extend_from_slice(&at.selector.to_le_bytes());
        code.extend_from_slice(&[0x8e, 0xc3]); // mov es, bx
        code.extend_from_slice(&[0x26, 0xc6, 0x06]); // mov byte ptr es:[at], mark
        code.extend_from_slice(&at.offset.to_le_bytes());
        code.push(mark);
        code.push(0xcb); // retf
        code
    }

    /// Register a module under `name` with the entry points `entries` names.
    ///
    /// [`register_module_with`] exists for the one-module case and calls its
    /// module `MajorMUD`; the state-dispatch tests need two that can be told
    /// apart in a failure message.
    fn register_named(f: &mut Fixture, name: &str, entries: &[(usize, FarPtr)]) -> u16 {
        let mut bytes = name.as_bytes().to_vec();
        bytes.resize(25 + 9 * 4, 0);
        for (n, at) in entries {
            let field = 25 + n * 4;
            bytes[field..field + 4].copy_from_slice(&at.to_bytes());
        }
        let block = f.bytes(&bytes, false);
        let ret = f
            .invoke(crate::shims::system::register_module, &Fixture::far(block))
            .expect("registered");
        match ret {
            Ret::U16(n) => n,
            other => panic!("register_module returns the module number, not {other:?}"),
        }
    }

    /// Write `state` into `user[chan].state`, the way the module does.
    ///
    /// Through [`Users::slot`] and `user::STATE` rather than a setter, because
    /// production code never assigns a state -- `register_module` hands the
    /// number back and the module stores it itself, at 14 sites in
    /// `WCCMMUD.DLL`. A test that wrote it any other way would be agreeing with
    /// [`Users::state`] about an offset instead of checking it.
    fn set_state(f: &mut Fixture, chan: crate::Chan, state: u16) {
        let slot = f.host.users().slot(chan);
        let at = FarPtr {
            offset: slot.offset + users::user::STATE,
            selector: slot.selector,
        };
        f.machine.write(at, &state.to_le_bytes()).expect("in the segment");
    }

    /// `MAJORBBS.C:2703` is `(*(module[usrptr->state]->sttrou))()`, and this is
    /// the test that says so.
    ///
    /// Two modules, both with a `sttrou`, each writing a different marker byte.
    /// The channel is put in state 1 and the input is delivered to the *second*
    /// module.
    ///
    /// **One module is not enough to test this.** Every other test in this file
    /// has exactly one registered module and every channel at state 0, where
    /// `modules()[state]` and `modules().first()` are the same pointer -- so the
    /// bug this fixes is invisible to all of them. Mutate `state_entry` back to
    /// `.first()` and this must go red; nothing else will.
    #[test]
    fn poll_dispatches_to_the_module_the_channels_state_names() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let console = f.console();

        let marker = f.bytes(&[0x00], false);
        let first = f.machine.code_ptr(0);
        let first_stub = marker_stub(marker, 0xa0);
        let second = f.machine.code_ptr(first_stub.len() as u16);
        let second_stub = marker_stub(marker, 0xb1);

        // `Fixture::new` -> `finish_init` has already taken slot 0 for the
        // FSD's own native registration, so "first" and "second" land one
        // past where they would have before -- read back rather than
        // assumed, same reasoning as `register_module_with`.
        let first_state = register_named(&mut f, "first", &[(1, first)]);
        let second_state = register_named(&mut f, "second", &[(1, second)]);
        assert_eq!(second_state, first_state + 1, "registered back to back");

        // After the registrations: `Fixture::invoke` builds its trampoline in
        // this same scratch segment at offset zero.
        let mut code = first_stub;
        code.extend_from_slice(&second_stub);
        f.machine.load_code(&code).expect("both stubs fit");

        set_state(&mut f, console, second_state);
        f.host.gsbl_mut().push_input(console, b"look\r");
        f.host
            .poll(&mut f.machine, &module)
            .expect("polled")
            .expect("the module was entered");

        assert_eq!(
            f.machine.resolve(marker, 1).expect("the marker")[0],
            0xb1,
            "state 1 must reach the second module's sttrou, not the first's"
        );
    }

    /// `inifsd()` registers FSDBBS as an ordinary module (`Host::finish_init`
    /// will do the same, once it exists), so `state_entry` has to answer a
    /// native registration exactly the way [`Registration::dispatch`] does --
    /// no far pointer, but the *fact* that this state is host-native rather
    /// than one nobody registered -- and a channel sitting in a *module's*
    /// state must be completely unaffected by a native slot existing
    /// elsewhere in the table.
    ///
    /// Mutate the `Dispatch::Native(Native::Fsd) => self.fsd_dispatch(...)`
    /// arm in `poll` to fall through to `Dispatch::Module(None)` instead and
    /// the `notes()` assertion below goes red: `poll`'s own "no entry
    /// registered" note still fires either way (a native slot with nothing
    /// wired up and a module that left the pointer null look the same from
    /// there), so only `fsd_dispatch`'s own note tells the two apart.
    #[test]
    fn poll_dispatches_to_a_native_registration_without_a_far_call() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let console = f.console();

        let sttrou = f.machine.code_ptr(0);
        let stub = returns_stub(1);
        f.machine.load_code(&stub).expect("the stub fits");
        // `Fixture::new` -> `finish_init` has already registered the FSD's
        // own native slot (`Host::fsd_state`), so that is the native
        // registration this test drives against -- a second one is not
        // needed, and registering one would only add a slot nothing else
        // points at.
        let native = f.host.fsd_state() as u16;
        let module_state = register_named(&mut f, "MajorMUD", &[(1, sttrou)]);
        assert_ne!(
            module_state, native,
            "the module must not land in the FSD's own slot"
        );

        // `state_entry` itself, both ways: the native slot answers `Native`,
        // and the module's own slot still answers `Module` with its far
        // pointer -- unaffected by a second, native registration existing.
        set_state(&mut f, console, native);
        assert_eq!(
            f.host
                .state_entry(&f.machine, console, 1)
                .expect("readable")
                .expect("no ShimError"),
            Dispatch::Native(Native::Fsd),
        );
        set_state(&mut f, console, module_state);
        assert_eq!(
            f.host
                .state_entry(&f.machine, console, 1)
                .expect("readable")
                .expect("no ShimError"),
            Dispatch::Module(Some(sttrou)),
        );

        // Now drive it through `poll`, with the channel in the native state:
        // no far call happens -- `poll` returns cleanly rather than faulting
        // on a bogus call -- and the native arm was genuinely reached.
        set_state(&mut f, console, native);
        f.host.gsbl_mut().push_input(console, b"look\r");
        let outcome = f.host.poll(&mut f.machine, &module).expect("polled");
        assert_eq!(
            outcome, None,
            "a native slot with nothing wired up answers no far pointer, \
             so no call happens"
        );
        assert!(
            f.host.notes().iter().any(|n| n.contains("fsd_dispatch")),
            "the native arm must be reached, not folded into Dispatch::Module(None): {:?}",
            f.host.notes()
        );
    }

    /// A `state` naming a slot nobody registered stops with a reason.
    ///
    /// Falling back to module 0 would deliver another module's keystrokes to
    /// MajorMUD, which from outside looks like a module that ignored its input
    /// -- the least diagnosable failure this host could choose.
    #[test]
    fn poll_refuses_a_state_that_names_no_registered_module() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let console = f.console();

        let stub = returns_stub(1);
        let sttrou = f.machine.code_ptr(0);
        register_named(&mut f, "only", &[(1, sttrou)]);
        f.machine.load_code(&stub).expect("the stub fits");

        // `Fixture::new` -> `finish_init` has already taken slot 0 for the
        // FSD, so two slots are occupied (the FSD, then "only") and the
        // count the error names has grown to match.
        set_state(&mut f, console, 3);
        f.host.gsbl_mut().push_input(console, b"look\r");
        let err = f
            .host
            .poll(&mut f.machine, &module)
            .expect_err("state 3 names nothing");
        let text = err.to_string();
        assert!(
            text.contains("state 3") && text.contains("2 module(s)"),
            "the error names the state and the count, got: {text}"
        );
    }

    /// `CYCLE` reaches `stsrou`, entry index 2.
    ///
    /// `susing()` (`MAJORBBS.C:2478`) is the status handler for a channel
    /// inside a module. It names `POLSTS`, `SPXTRM`/`SPXWDG`, `RING`/`LOST2C`/
    /// `LOST25`, `CRSTG`, `OBFCLR`, `ABOREQ` and `OUTMT` as cases; `CYCLE`
    /// (`MAJORBBS.H:236`) is not among them, so it falls to
    /// `default: (*(module[usrptr->state]->stsrou))()`. `dfsthn`
    /// (`MAJORBBS.C:4488`), the `stsrou` the real host installs for a module
    /// that supplies none, lists `case CYCLE:` among the statuses it ignores --
    /// which only makes sense if `CYCLE` reaches `stsrou` in the first place.
    #[test]
    fn poll_dispatches_cycle_to_stsrou() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let console = f.console();

        let marker = f.bytes(&[0x00], false);
        let stsrou = f.machine.code_ptr(0);
        let stub = marker_stub(marker, 0x2f);
        let state = register_named(&mut f, "only", &[(2, stsrou)]);
        f.machine.load_code(&stub).expect("the stub fits");

        // The channel's `state` defaults to zero, which is the FSD's own
        // slot now that `finish_init` registers it first -- put the channel
        // in the module's actual slot the way a real logon would have.
        set_state(&mut f, console, state);
        f.host.gsbl_mut().inject(console, gsbl::Gsbl::CYCLE);
        f.host
            .poll(&mut f.machine, &module)
            .expect("polled")
            .expect("stsrou was entered");

        assert_eq!(
            f.machine.resolve(marker, 1).expect("the marker")[0],
            0x2f,
            "CYCLE must reach stsrou"
        );
        assert_eq!(
            f.host
                .globals()
                .word(&f.machine, "status")
                .expect("status is placed"),
            gsbl::Gsbl::CYCLE as u16,
            "stsrou reads `status` to find out why it was called"
        );
    }

    /// A raw channel's keystrokes reach `stsrou`, with nothing in between.
    ///
    /// The two halves of the FSD's input path are tested apart: `crate::gsbl`
    /// proves that a raw delivery queues a `CYCLE`, and
    /// `poll_dispatches_cycle_to_stsrou` proves that an *injected* `CYCLE`
    /// reaches entry point 2. Nothing joined them, so a wake-up that queued
    /// some other status, or a `poll` that only dispatched what `btuinj` put
    /// there, would have passed both.
    ///
    /// This is the whole of `fsdchi` (`FSDBBS.C:329`) as this host does it,
    /// end to end and in one call: bytes arrive from the transport, the module
    /// is entered at its status routine, and the keystrokes are still in
    /// `input` for the `btuica` that routine will make -- `poll` delivers the
    /// wake-up, not the bytes.
    ///
    /// The bytes are an arrow key, because that is what the flag exists for:
    /// `\x1b[A` is three bytes of which the translate table would keep only
    /// `[` and `A` outside raw mode, and a `CYCLE` would never be queued at all.
    #[test]
    fn raw_input_wakes_the_loop_and_poll_dispatches_it_to_stsrou() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let console = f.console();

        let marker = f.bytes(&[0x00], false);
        let stsrou = f.machine.code_ptr(0);
        let stub = marker_stub(marker, 0x1b);
        let state = register_named(&mut f, "only", &[(2, stsrou)]);
        f.machine.load_code(&stub).expect("the stub fits");

        // See `poll_dispatches_cycle_to_stsrou`'s identical comment: state
        // zero is the FSD's own slot now, not "only"'s.
        set_state(&mut f, console, state);
        f.host.gsbl_mut().channel_mut(console).raw = true;
        f.host.gsbl_mut().push_input(console, b"\x1b[A");

        f.host
            .poll(&mut f.machine, &module)
            .expect("polled")
            .expect("stsrou was entered");

        assert_eq!(
            f.machine.resolve(marker, 1).expect("the marker")[0],
            0x1b,
            "the keystrokes' own wake-up must reach stsrou, not just an injected one"
        );
        assert_eq!(
            f.host
                .globals()
                .word(&f.machine, "status")
                .expect("status is placed"),
            gsbl::Gsbl::CYCLE as u16,
            "and stsrou must be told it was CYCLE that brought it here"
        );
        assert_eq!(
            f.host
                .gsbl()
                .channel(console)
                .input
                .iter()
                .copied()
                .collect::<Vec<u8>>(),
            b"\x1b[A".to_vec(),
            "poll delivers the wake-up; the bytes are still there for btuica"
        );
    }

    /// One injected `CYCLE` is one dispatch, and then the loop is done.
    ///
    /// The FSD's whole entry engine is driven by `fsdnfy()` (`FSDBBS.C:368`)
    /// re-injecting `CYCLE` at the channel, and `fsdsts` (`FSDBBS.C:262`) is
    /// the original documenting its own spin: in `case FINISHING`, `if
    /// (btuoba(usrnum) == outbsz-1) goback(); else { actdet=0; fsdnfy(); }` --
    /// re-dispatch on every pass until the output buffer drains, with
    /// `actdet=0` so the host's idle detector does not count the loop as work.
    ///
    /// **This measures the consuming side, and only that.** The `stsrou` below
    /// is a bare `retf` that re-arms nothing, so what is proved is that the
    /// host takes one edge once and does not manufacture more from it: a status
    /// is an edge, not a level. Worth pinning, and not the same fact as "this
    /// host does not inherit the FSD's spin", which is what this test used to
    /// claim.
    ///
    /// It says nothing about a module that *produces* edges, which is precisely
    /// what `fsdsts` does through `fsdnfy()`. Measured rather than reasoned
    /// about: queue 200 `CYCLE`s instead of one and `dispatched` comes back 50
    /// with `iterations` at the bound. **There is no gate** -- `max` is the
    /// only thing that ends it. A Stage 3 `fsdsts` that calls `fsdnfy()` on
    /// every pass will run `cycle` to `max` every time, the way the original
    /// does, but without the original's `btuoba(usrnum) == outbsz-1` to stop.
    ///
    /// Open question, deliberately not answered here: the concurrent
    /// tokio-transport branch adds a `polls_left` budget to `Host` for this
    /// exact shape on `POLSTS` -- a count armed with the polling and spent per
    /// re-arm, so a self-re-arming chain ends on its own. `CYCLE` has no
    /// equivalent. Whether it should share that budget, carry its own, or be
    /// bounded by the FSD's own drain condition instead is for the two branches
    /// to settle together; building a second budget here would prejudge it.
    ///
    /// Asserted on [`Cycles`] rather than on [`Ended`]: the `Ended` enum is
    /// being rewritten on the tokio transport branch, and
    /// `iterations`/`dispatched` say the thing that matters anyway -- how many
    /// times the module was entered, and whether the loop ran to its bound.
    #[test]
    fn one_injected_cycle_is_one_dispatch_and_the_loop_settles() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let console = f.console();

        // A bare `retf`: a stsrou that does its work and does not ask to be
        // called again.
        let stsrou = f.machine.code_ptr(0);
        let state = register_named(&mut f, "only", &[(2, stsrou)]);
        f.machine.load_code(&[0xcb]).expect("the stub fits");

        // State zero is the FSD's own slot now; see
        // `poll_dispatches_cycle_to_stsrou`'s identical comment.
        set_state(&mut f, console, state);
        f.host.gsbl_mut().inject(console, gsbl::Gsbl::CYCLE);
        let cycles = f.host.cycle(&mut f.machine, &module, 50).expect("cycled");

        assert_eq!(cycles.dispatched, 1, "one CYCLE is one entry into stsrou");
        assert!(
            cycles.iterations < 50,
            "the loop settled instead of running to its bound; it took {} passes",
            cycles.iterations
        );
    }

    /// 16-bit code that returns `ax` and does nothing else.
    fn returns_stub(ax: u16) -> Vec<u8> {
        let mut code = vec![0xb8]; // mov ax, <ax>
        code.extend_from_slice(&ax.to_le_bytes());
        code.push(0xcb); // retf
        code
    }

    /// 16-bit code that returns the first byte of the account record `usaptr`
    /// names.
    ///
    /// What a disconnect routine can see of the channel it was handed. Read
    /// through the *global* rather than a planted address, so it answers two
    /// questions at once: whether `point_curusr` pointed at this channel, and
    /// whether the record still held its user when the routine ran. A `rstchn`
    /// that ran first would leave this reading zero, and MajorMUD's own
    /// `huprou` opens with `_GET_PLAYER(usrnum)`.
    fn reads_usaptr_stub(f: &Fixture) -> Vec<u8> {
        let usaptr = f
            .host
            .globals()
            .address("usaptr")
            .expect("usaptr is placed");
        let mut code = vec![0xb8]; // mov ax, <globals selector>
        code.extend_from_slice(&usaptr.selector.to_le_bytes());
        code.extend_from_slice(&[0x8e, 0xd8]); // mov ds, ax
        code.extend_from_slice(&[0xc4, 0x1e]); // les bx, [usaptr]
        code.extend_from_slice(&usaptr.offset.to_le_bytes());
        code.extend_from_slice(&[0x26, 0x8a, 0x07]); // mov al, es:[bx]
        code.extend_from_slice(&[0xb4, 0x00]); // mov ah, 0
        code.push(0xcb); // retf
        code
    }

    /// A host with `build`'s stubs installed as the disconnect vectors they
    /// name, a module registered pointing at them, and `rangerdan` connected to
    /// the console with a keyring.
    ///
    /// `build` is handed the fixture rather than the stubs being passed in
    /// ready-made: a selector belongs to the `Machine` that minted it, so a
    /// stub built against one fixture and run in another addresses whatever
    /// that selector happens to name there.
    ///
    /// The stubs are loaded **after** `register_module`, because
    /// [`Fixture::invoke`] builds its own trampoline in the same scratch code
    /// segment and `load_code` always writes at offset zero -- registering
    /// second would overwrite them.
    fn connected_with(
        build: impl FnOnce(&Fixture) -> Vec<(usize, Vec<u8>)>,
    ) -> (Fixture, mbbs16::Module, crate::Chan) {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let console = f.console();

        let mut code = Vec::new();
        let mut vectors = Vec::new();
        for (n, stub) in build(&f) {
            vectors.push((n, f.machine.code_ptr(code.len() as u16)));
            code.extend_from_slice(&stub);
        }
        let state = register_module_with(&mut f, &vectors);
        f.machine.load_code(&code).expect("the stubs fit");

        f.host
            .connect_state(
                &mut f.machine,
                console,
                &Connection::ansi("rangerdan").with_keys(["PLAYKEY"]),
            )
            .expect("a user on the channel");
        // A real logon would have put the channel in the module's own state;
        // `connect_state` (deliberately, see its own doc comment) does not
        // touch `state` at all, and it defaults to zero -- which, since
        // `Host::finish_init` registers the FSD's native slot first, no
        // longer names this module. `logoff`'s `lofrou` lookup is keyed on
        // state (`state_entry`), so a test that wants it reached has to put
        // the channel there itself, the same way the module would.
        set_state(&mut f, console, state);
        (f, module, console)
    }

    #[test]
    fn hanging_up_a_channel_with_no_huprou_still_resets_it() {
        // A null vector is legal -- `aschup` tests
        // `(rouptr=module[i]->huprou) != NULL` before calling
        // (`MAJORBBS.C:4623`) -- and means no call happened, not that one
        // returned zero. The reset at the tail is unconditional: `loscar`
        // reaches `rstchn` either way (`:4593`).
        let (mut f, module, chan) = connected_with(|_| Vec::new());
        assert!(
            f.host.users().keys(chan).is_some(),
            "a keyring before the hangup, so the assertion after it means something"
        );

        let outcome = f.host.hangup(&mut f.machine, &module, chan).expect("hangup");

        assert_eq!(outcome, None, "no huprou means no call happened");
        assert!(
            f.host.users().keys(chan).is_none(),
            "the channel was reset even though nothing was called"
        );
    }

    #[test]
    fn logging_off_a_channel_with_no_lofrou_still_resets_it() {
        // `bgnlof`, `MAJORBBS.C:4057`: a null `lofrou` goes straight to
        // `go2mnu(JSTRET)`, the menuing system this host does not have -- and
        // whose absence a headless host answers by finishing the disconnect.
        let (mut f, module, chan) = connected_with(|_| Vec::new());

        let outcome = f.host.logoff(&mut f.machine, &module, chan).expect("logoff");

        assert_eq!(outcome, None, "no lofrou means no call happened");
        assert!(
            f.host.users().keys(chan).is_none(),
            "the channel was reset even though nothing was called"
        );
    }

    #[test]
    fn a_lofrou_that_asks_to_be_called_again_is_refused_by_name() {
        // `nxtlof`'s protocol, `MAJORBBS.C:4100`: for the module the user is
        // *in* -- the only one a one-module host has -- the test is
        // `if ((*lofrou)() != 1) go2mnu(JSTRET)`, so 1 and only 1 is "I am not
        // finished, hold the channel". A one-module headless host has no second
        // pass to give, and a silent discard would leave the module believing a
        // dialogue is in progress. House rule: a host that cannot answer poisons
        // with its own name. See
        // `a_lofrou_that_abandons_the_sweep_is_taken_at_its_word_like_any_non_one`
        // for why the refusal is `== 1` and not `!= 0`.
        let (mut f, module, chan) = connected_with(|_| vec![(4, returns_stub(1))]);

        let outcome = f
            .host
            .logoff(&mut f.machine, &module, chan)
            .expect("logoff")
            .expect("lofrou was called");

        let Outcome::Stopped(poison) = outcome else {
            panic!("a lofrou asking for another pass must stop, got {outcome:?}");
        };
        assert!(
            poison.to_string().contains("lofrou"),
            "the refusal must name the routine: {poison}"
        );

        // `disconnect`'s doc calls the reset "last, and unconditionally". Until
        // this line nothing held it to that on the stopping path: wrapping the
        // tail in `if !matches!(outcome, Some(Outcome::Stopped(_)))` left all
        // 754 tests green. A refused `lofrou` is still a channel nobody is on.
        assert!(
            f.host.users().keys(chan).is_none(),
            "the channel was reset even though the disconnect ended in a stop"
        );
    }

    /// `-1` is **not** refused, and getting here took a correction.
    ///
    /// The refusal was written as `ax != 0`, reasoning from `nxtlof`'s loop:
    /// `1` means "call me again" (`MAJORBBS.C:4087`) and `-1` means "abandon
    /// and go to the menu" (`:4089`). But with one module that loop body never
    /// executes -- `:4076` skips `i == lofstt` and `lofstt` is the only module
    /// there is -- so the operative line is the self-call at `:4100`:
    ///
    ///
    /// Against that test `0`, `-1` and `42` are the same answer: finished, go
    /// to the menu. Only `1` says "hold the channel, I am not done", and only
    /// that is something this host cannot honour. "Go to the menu" for a
    /// headless host collapses to "the logoff is over", which is exactly the
    /// `rstchn` that follows -- so it is accepted rather than refused.
    ///
    /// Refusing `-1` as well would have been this host inventing a distinction
    /// the original does not draw at the only line it reaches.
    #[test]
    fn a_lofrou_that_abandons_the_sweep_is_taken_at_its_word_like_any_non_one() {
        let (mut f, module, chan) = connected_with(|_| vec![(4, returns_stub(0xffff))]);

        let outcome = f
            .host
            .logoff(&mut f.machine, &module, chan)
            .expect("logoff")
            .expect("lofrou was called");

        assert_eq!(
            outcome,
            Outcome::Returned { ax: 0xffff, dx: 0 },
            "-1 is not 1, so `:4100` sends it to the menu like any other value"
        );
        assert!(
            f.host.users().keys(chan).is_none(),
            "and the channel was still reset"
        );
    }

    /// And the value that is *not* refused, which is what keeps the refusal
    /// from being "every logoff stops". MajorMUD's own `_LJNGAME_LOFROU`
    /// (`re/exports/WCCMMUD_named.c:12628`) returns 0.
    #[test]
    fn a_lofrou_that_has_finished_is_taken_at_its_word() {
        let (mut f, module, chan) = connected_with(|_| vec![(4, returns_stub(0))]);

        let outcome = f.host.logoff(&mut f.machine, &module, chan).expect("logoff");

        assert_eq!(
            outcome,
            Some(Outcome::Returned { ax: 0, dx: 0 }),
            "0 is 'I am done', the only answer this host can act on"
        );
        assert!(
            f.host.users().keys(chan).is_none(),
            "and the channel is reset after it"
        );
    }

    /// The ordering, stated as something the module can observe rather than as
    /// a comment about the order of two statements.
    #[test]
    fn a_disconnect_routine_runs_before_the_channel_is_reset() {
        let (mut f, module, chan) = connected_with(|f| vec![(5, reads_usaptr_stub(f))]);

        let outcome = f.host.hangup(&mut f.machine, &module, chan).expect("hangup");

        assert_eq!(
            outcome,
            Some(Outcome::Returned {
                ax: u16::from(b'r'),
                dx: 0
            }),
            "huprou read `rangerdan`'s first byte through usaptr -- a reset that \
             ran first would hand the module a zeroed record, which is what \
             MajorMUD's `_GET_PLAYER(usrnum)` would then load"
        );
        assert!(
            f.host.users().keys(chan).is_none(),
            "and the reset still happened, after the call"
        );
    }

    /// The one documented `Err` on either path. A host with no *module*
    /// registered has no `struct module` to read a vector out of, and
    /// answering `Ok(None)` -- which is what "the module supplied no vector"
    /// means -- would say a module had been asked and had nothing to offer.
    #[test]
    fn disconnecting_with_no_module_registered_is_an_error_not_a_silent_none() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let console = f.console();

        // `hangup`'s `huprou` lookup is `first_module` -- the FSD's own
        // native slot, which `finish_init` has already registered, does not
        // count as a module -- so this stays an error with no setup needed.
        assert!(
            f.host.hangup(&mut f.machine, &module, console).is_err(),
            "hangup with no module registered"
        );

        // `logoff`'s `lofrou` lookup is keyed on the channel's state
        // instead, and state zero now names the FSD's own slot -- a real
        // registration, just one with no `lofrou` shape, so it answers
        // `Ok(None)` rather than erroring. A state nothing names at all is
        // what "no module registered" means here now.
        set_state(&mut f, console, 99);
        assert!(
            f.host.logoff(&mut f.machine, &module, console).is_err(),
            "logoff with no module registered"
        );
    }

    /// Which entry point a disconnect ran, as the index that entry point
    /// stamped into memory. `None` if neither ran.
    fn vector_that_ran(hangup: bool) -> Option<u8> {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let console = f.console();
        let mark = f.buffer(1);

        let lofrou = f.machine.code_ptr(0);
        let mut code = marker_stub(mark, 4);
        let huprou = f.machine.code_ptr(code.len() as u16);
        code.extend_from_slice(&marker_stub(mark, 5));

        let state = register_module_with(&mut f, &[(4, lofrou), (5, huprou)]);
        f.machine.load_code(&code).expect("both stubs fit");
        f.host
            .connect_state(&mut f.machine, console, &Connection::ansi("rangerdan"))
            .expect("a user on the channel");
        // `logoff`'s `lofrou` lookup is state-keyed; see `connected_with`'s
        // identical comment for why this can no longer be left at zero.
        set_state(&mut f, console, state);

        if hangup {
            f.host.hangup(&mut f.machine, &module, console)
        } else {
            f.host.logoff(&mut f.machine, &module, console)
        }
        .expect("disconnected");

        let stamped = f.machine.resolve(mark, 1).expect("the marker")[0];
        (stamped != 0).then_some(stamped)
    }

    /// `struct module` (`MAJORBBS.H:241-252`) is `descrp`, `lonrou`, `sttrou`,
    /// `stsrou`, `injrou`, `lofrou`, `huprou` -- so `lofrou` is entry 4 and
    /// `huprou` is entry 5, and the two disconnects are disjoint paths rather
    /// than stages of one: `aschup` (`:4607`) sweeps `huprou` and is called
    /// only from `loscar` (`:4581`), while `lofrou` is reached only through
    /// `bgnlof`. Asserted by what *ran*, not by which pointer was read.
    #[test]
    fn hangup_runs_huprou_and_logoff_runs_lofrou() {
        assert_eq!(
            vector_that_ran(true),
            Some(5),
            "hangup runs huprou, `struct module`'s sixth entry point"
        );
        assert_eq!(
            vector_that_ran(false),
            Some(4),
            "logoff runs lofrou, its fifth"
        );
    }

    /// Three channels, and the one that disconnects is the middle one.
    ///
    /// Every other test here is a one-channel fixture asserting about channel
    /// zero, where "reset the channel it was given" and "reset channel zero"
    /// and "reset every channel" are the same sentence. They are not the same
    /// sentence at three, and neither is "the routine saw the departing
    /// player's record".
    #[test]
    fn hanging_up_one_channel_leaves_every_other_channel_alone() {
        let mut f = Fixture::rooted_with_terms(testing::data(), Terms::new(3));
        let module = f.minimal_module();
        let stub = reads_usaptr_stub(&f);
        let huprou = f.machine.code_ptr(0);
        register_module_with(&mut f, &[(5, huprou)]);
        f.machine.load_code(&stub).expect("the stub fits");

        let terms = f.host.users().terms();
        let chans: Vec<crate::Chan> = (0..3)
            .map(|n| terms.chan(n).expect("three channels"))
            .collect();
        for (chan, who) in chans.iter().zip(["rangerdan", "Kaimon", "Mireko"]) {
            f.host
                .connect_state(
                    &mut f.machine,
                    *chan,
                    &Connection::ansi(who).with_keys(["PLAYKEY"]),
                )
                .expect("a user on the channel");
        }

        let outcome = f
            .host
            .hangup(&mut f.machine, &module, chans[1])
            .expect("hangup");

        assert_eq!(
            outcome,
            Some(Outcome::Returned {
                ax: u16::from(b'K'),
                dx: 0
            }),
            "huprou ran with usaptr on channel 1 -- `Kaimon`, not `rangerdan`"
        );
        assert!(
            f.host.users().keys(chans[1]).is_none(),
            "channel 1 was reset"
        );
        for (chan, who) in [(chans[0], "rangerdan"), (chans[2], "Mireko")] {
            assert!(
                f.host.users().keys(chan).is_some(),
                "{who}'s keyring survived a hangup on another channel"
            );
            let account = f.host.users().account(chan);
            let bytes = f
                .machine
                .resolve(account, who.len())
                .expect("the account record");
            assert_eq!(
                std::str::from_utf8(bytes).expect("an ASCII userid"),
                who,
                "{who}'s account record survived a hangup on another channel"
            );
        }
    }

    // R21 -- "a `ShimError` out of `connect_state` poisons the machine and comes
    // back as `Outcome::Stopped`" -- had a test here. It drove that failure by
    // handing `connect` a channel past `nterms`, which `Chan` has made an
    // unrepresentable state, so the test was deleted rather than rewritten into
    // something that no longer exercised what it named.
    //
    // **The `shim_stop` arm in `Host::connect` is consequently untested.** It is
    // still reachable -- `connect_state` writes into the account record, and a
    // write off the end of a segment is a `ShimError` -- but nothing reachable
    // through `Host::new` puts a table there, so there is no honest way to drive
    // it from here. `Host::run`'s own tests still cover the policy for the shim
    // path; what is no longer covered is this call site applying it.

    #[test]
    fn the_host_records_every_lock_a_module_asked_about() {
        let mut f = Fixture::new();
        let console = f.console();
        f.host
            .connect_state(
                &mut f.machine,
                console,
                &Connection::ansi("rangerdan").with_keys(["USER"]),
            )
            .expect("channel 0");

        // Lowercase deliberately: M19 (record the uppercased lock instead of
        // what the module passed) is invisible unless one of these locks
        // isn't already uppercase.
        for lock in ["USER", "wccsysop"] {
            let at = f.text(lock);
            f.invoke(crate::shims::user::haskey, &Fixture::far(at))
                .expect("answered");
        }

        let asked = f.host.keys_asked();
        assert_eq!(asked.len(), 2);
        assert_eq!((asked[0].chan, asked[0].lock.as_str(), asked[0].answer), (0, "USER", true));
        assert_eq!((asked[1].chan, asked[1].lock.as_str(), asked[1].answer), (0, "wccsysop", false));
    }

    /// The driver reuses channels rather than allocating one per connection --
    /// which is why `connect_state` already zeroes the whole `userid` field
    /// rather than only the bytes it writes. A stale `polrou` is the same bug
    /// with a worse blast radius: the next user's channel would tick into the
    /// previous user's game routine.
    #[test]
    fn connecting_clears_a_polling_routine_the_last_user_left_behind() {
        let mut f = crate::testing::Fixture::new();
        let console = f.console();
        let stale = mbbs16::FarPtr {
            offset: 0x2184,
            selector: 0x1010,
        };
        f.host
            .users
            .set_polrou(&mut f.machine, console, Some(stale))
            .expect("channel 0");

        f.host
            .connect_state(
                &mut f.machine,
                console,
                &crate::users::Connection::ansi("somebodyelse"),
            )
            .expect("connected");

        assert_eq!(
            f.host.users().polrou(&f.machine, console).expect("channel 0"),
            None,
            "the new user must not inherit the old user's poll routine"
        );
    }

    /// A polling routine is a `void (*)(void)`, so the smallest real one is a
    /// single `retf`. `load_code` puts it somewhere the machine will execute
    /// and `code_ptr` addresses it.
    fn polling_fixture() -> (crate::testing::Fixture, mbbs16::Module, FarPtr) {
        let mut f = crate::testing::Fixture::new();
        let module = f.minimal_module();
        f.machine.load_code(&[0xcb]).expect("a retf fits");
        let rou = f.machine.code_ptr(0);
        (f, module, rou)
    }

    /// The same, at `count` channels.
    ///
    /// `polling_fixture` is one channel, which is what `Terms::new(NTERMS)`
    /// means -- and at one channel "every channel" and "channel zero" are the
    /// same set, so nothing built on it can tell a per-channel sweep from a
    /// sweep that stops after the first.
    fn polling_fixture_with(count: u16) -> (crate::testing::Fixture, mbbs16::Module, FarPtr) {
        let mut f = crate::testing::Fixture::rooted_with_terms(testing::data(), Terms::new(count));
        let module = f.minimal_module();
        f.machine.load_code(&[0xcb]).expect("a retf fits");
        let rou = f.machine.code_ptr(0);
        (f, module, rou)
    }

    #[test]
    fn a_polling_channel_is_serviced_and_re_arms_itself() {
        let (mut f, module, rou) = polling_fixture();
        let console = f.console();
        f.host
            .users
            .set_polrou(&mut f.machine, console, Some(rou))
            .expect("channel 0");
        f.host.refill_polls(&f.machine, 2).expect("armed");

        let outcome = f.host.poll(&mut f.machine, &module).expect("polled");

        assert!(
            matches!(outcome, Some(Outcome::Returned { .. })),
            "the routine ran and returned, got {outcome:?}"
        );
        assert_eq!(
            f.host.globals().word(&f.machine, "status").expect("read"),
            192,
            "the module reads `status`, and POLSTS is written like any other"
        );
        assert_eq!(
            f.host.gsbl_mut().next_status(console),
            Some(gsbl::Gsbl::POLSTS),
            "still polling on return, so dopoll re-armed it"
        );
        assert_eq!(
            f.host.gsbl_mut().next_status(console),
            None,
            "re-armed ONCE -- a second status here doubles every tick"
        );
        assert_eq!(f.host.inpolr, None, "cleared on the way out");
    }

    /// The case a remembered copy of `polrou` would get wrong. The routine is
    /// real 16-bit code that zeroes its own `user[0].polrou` and returns, so
    /// `dopoll`'s re-arm check has to be a fresh read of emulated memory.
    #[test]
    fn a_routine_that_stops_polling_itself_is_not_re_armed() {
        let mut f = crate::testing::Fixture::new();
        let console = f.console();
        let module = f.minimal_module();
        let slot = f.host.users().slot(console);
        let lo = slot.offset + crate::users::user::POLROU;

        // mov ax, <selector>       B8 ss ss
        // mov es, ax               8E C0
        // mov word ptr es:[lo], 0  26 C7 06 lo lo 00 00
        // mov word ptr es:[lo+2],0 26 C7 06 hi hi 00 00
        // retf                     CB
        let mut code = vec![0xb8];
        code.extend_from_slice(&slot.selector.to_le_bytes());
        code.extend_from_slice(&[0x8e, 0xc0]);
        for offset in [lo, lo + 2] {
            code.extend_from_slice(&[0x26, 0xc7, 0x06]);
            code.extend_from_slice(&offset.to_le_bytes());
            code.extend_from_slice(&[0x00, 0x00]);
        }
        code.push(0xcb);
        f.machine.load_code(&code).expect("fits");
        let rou = f.machine.code_ptr(0);

        f.host
            .users
            .set_polrou(&mut f.machine, console, Some(rou))
            .expect("channel 0");
        // A budget, and it is what makes this test a test at all. `dopoll`'s
        // re-arm is gated `polls_left > 0 && ..`, so at the default budget of
        // zero the whole branch is skipped and the fresh read of `polrou`
        // inside it never runs. Deleting that read outright then passed all
        // 781 lib tests and all 17 real-module tests -- the budget silently
        // defanged the one test that protects it.
        f.host.refill_polls(&f.machine, 4).expect("armed");

        let outcome = f.host.poll(&mut f.machine, &module).expect("polled");

        assert!(
            matches!(outcome, Some(Outcome::Returned { .. })),
            "got {outcome:?}"
        );
        assert_eq!(
            f.host.users().polrou(&f.machine, console).expect("channel 0"),
            None,
            "the routine cleared it mid-call"
        );
        assert_eq!(
            f.host.gsbl_mut().next_status(console),
            None,
            "so nothing was re-armed and the channel goes quiet"
        );
    }

    /// `begin_polling` injects, the module calls `stop_polling` before the pass
    /// that would have serviced it, and the status arrives with nothing to
    /// call. The original's whole handling is `if (usrptr->polrou != NULL)`.
    #[test]
    fn a_stale_polling_status_is_consumed_without_a_module_call() {
        let (mut f, module, _rou) = polling_fixture();
        let console = f.console();
        f.host.gsbl_mut().inject(console, gsbl::Gsbl::POLSTS);
        let before = f.host.calls();
        let notes = f.host.notes().len();

        let outcome = f.host.poll(&mut f.machine, &module).expect("polled");

        assert_eq!(outcome, None, "no call happened, so there is no Outcome");
        assert_eq!(f.host.calls(), before, "and nothing was serviced");
        assert_eq!(
            f.host.gsbl_mut().next_status(console),
            None,
            "the status is consumed, not left to spin"
        );
        assert_eq!(
            f.host.notes().len(),
            notes,
            "and it is not noted -- this is the normal path, not an anomaly"
        );
    }

    /// Every read steps the clock, the module's and the host's alike, so the
    /// count is the only honest way to say how much invented time has passed.
    /// Pinned by the same logic as `keys_asked`: a number that moves when
    /// behaviour changes.
    #[test]
    fn every_read_of_a_stepped_clock_moves_it_and_is_counted() {
        let mut f = crate::testing::Fixture::new();
        f.host.set_clock(Clock::stepped(1_135_952_405, 500));
        assert_eq!(f.host.clock_reads(), 0);

        assert_eq!(f.host.clock().epoch(), Ok(1_135_952_405), "half a second in");
        assert_eq!(f.host.clock().epoch(), Ok(1_135_952_406), "and a whole one");
        assert_eq!(f.host.clock_reads(), 2);
    }

    #[test]
    fn a_pinned_clock_reads_the_same_instant_however_often_it_is_asked() {
        let mut f = crate::testing::Fixture::new();
        f.host.set_clock(Clock::pinned(1_135_952_405));
        for _ in 0..100 {
            assert_eq!(f.host.clock().epoch(), Ok(1_135_952_405));
        }
        assert_eq!(f.host.clock_reads(), 100, "counted even though it did not move");
    }

    #[test]
    fn prcrtk_counts_down_and_fires_exactly_once() {
        let (mut f, module, rou) = polling_fixture();
        f.host.kicks.push(Kick { delay: 2, dstrou: rou });

        let mut fired = 0;
        assert_eq!(f.host.prcrtk(&mut f.machine, &module, &mut fired).expect("ran"), None);
        assert_eq!(fired, 0, "one second in, a two-second kick has not fired");
        assert_eq!(f.host.kicks().len(), 1);

        assert_eq!(f.host.prcrtk(&mut f.machine, &module, &mut fired).expect("ran"), None);
        assert_eq!(fired, 1, "the second round fires it");
        assert!(f.host.kicks().is_empty(), "and takes it out of the table");

        assert_eq!(f.host.prcrtk(&mut f.machine, &module, &mut fired).expect("ran"), None);
        assert_eq!(fired, 1, "a one-shot fires once -- GALMJD.C:1106 re-arms by hand");
    }

    /// `GALMJD.C:1106` calls `rtkick(1,mjdrtk)` from inside `mjdrtk`, so a
    /// callback pushes onto the very table being walked. The due entries come
    /// out before any of them runs, which puts a re-armed kick in the *next*
    /// round -- the same place the original's free-slot scan puts it.
    #[test]
    fn a_kick_that_re_arms_itself_belongs_to_the_next_round() {
        let (mut f, module, rou) = polling_fixture();
        f.host.kicks.push(Kick { delay: 1, dstrou: rou });

        let mut fired = 0;
        f.host.prcrtk(&mut f.machine, &module, &mut fired).expect("ran");
        assert_eq!(fired, 1);

        // What the callback would have done, done here because a `retf` cannot
        // call a shim from inside this fixture.
        f.host.kicks.push(Kick { delay: 1, dstrou: rou });
        assert_eq!(f.host.kicks().len(), 1, "armed again, not fired again");

        f.host.prcrtk(&mut f.machine, &module, &mut fired).expect("ran");
        assert_eq!(fired, 2, "and it fires on the round after");
    }

    #[test]
    fn a_cycle_with_nothing_to_do_ends_idle_without_burning_the_bound() {
        let (mut f, module, _rou) = polling_fixture();
        let cycles = f.host.cycle(&mut f.machine, &module, 50).expect("cycled");
        assert_eq!(cycles.ended, Ended::Idle);
        assert_eq!(cycles.dispatched, 0);
        assert_eq!(cycles.iterations, 1, "it works that out on the first pass");
    }

    #[test]
    fn a_polling_channel_ticks_until_the_bound() {
        let (mut f, module, rou) = polling_fixture();
        let console = f.console();
        f.host.users.set_polrou(&mut f.machine, console, Some(rou)).expect("channel 0");
        f.host.refill_polls(&f.machine, 1_000).expect("armed");

        let cycles = f.host.cycle(&mut f.machine, &module, 20).expect("cycled");

        assert_eq!(cycles.iterations, 20, "the bound is what stopped it");
        assert_eq!(cycles.dispatched, 20, "one tick a pass, self-sustaining");
        assert_eq!(cycles.ended, Ended::Bound { next_kick: None });
        // The status queue must not have grown while all that happened.
        assert_eq!(f.host.gsbl_mut().next_status(console), Some(gsbl::Gsbl::POLSTS));
        assert_eq!(
            f.host.gsbl_mut().next_status(console),
            None,
            "exactly one status outstanding after 20 ticks, not 21 and not 2^20"
        );
    }

    /// The same question as
    /// `next_kick_is_the_soonest_of_several_and_not_merely_one_of_them`, asked
    /// of the other place that answers it.
    ///
    /// `cycle` computes `next_kick` at two sites: the early return, when
    /// nothing is queued, and the tail, when the pass bound is reached with
    /// work still going. A fixture with nothing polling can only ever reach
    /// the first. Review found the second by mutating it alone to `.max()` and
    /// watching all 774 tests stay green -- the two sites are the same
    /// arithmetic written twice, which is how call sites drift apart.
    #[test]
    fn the_bound_reports_the_soonest_kick_too() {
        let (mut f, module, rou) = polling_fixture();
        let console = f.console();
        f.host.set_clock(Clock::pinned(1_135_952_405));
        f.host.users.set_polrou(&mut f.machine, console, Some(rou)).expect("channel 0");
        f.host.refill_polls(&f.machine, 1_000).expect("armed");
        f.host.kicks.push(Kick { delay: 300, dstrou: rou });
        f.host.kicks.push(Kick { delay: 7, dstrou: rou });
        f.host.kicks.push(Kick { delay: 45, dstrou: rou });

        // A polling channel keeps `pending()` true, so the loop runs out of
        // passes instead of returning early -- which is the only way to reach
        // the tail at all.
        let cycles = f.host.cycle(&mut f.machine, &module, 20).expect("cycled");

        assert_eq!(
            cycles.ended,
            Ended::Bound { next_kick: Some(7) },
            "the soonest of the three, from the tail rather than the early return"
        );
    }

    /// A kick comes due across the calls a driver makes, not within one.
    ///
    /// The clock reads are conserved -- one per pass before, one per call now
    /// -- so the count that used to be `iterations` is now the number of
    /// calls. If this number changes, the clock is being read a different
    /// number of times, which is a real change and not a test to adjust.
    #[test]
    fn a_kick_comes_due_across_the_calls_a_driver_makes() {
        let (mut f, module, rou) = polling_fixture();
        f.host.set_clock(Clock::stepped(1_135_952_405, 500));
        f.host.kicks.push(Kick { delay: 2, dstrou: rou });

        let mut dispatched = 0;
        let mut calls = 0;
        while dispatched == 0 {
            calls += 1;
            assert!(calls < 20, "the kick never came due");
            let cycles = f.host.cycle(&mut f.machine, &module, 50).expect("cycled");
            assert_eq!(
                cycles.iterations, 1,
                "nothing is ever pending here, so every call returns on its first pass"
            );
            dispatched += cycles.dispatched;
        }

        assert_eq!(dispatched, 1, "the kick fired, once");
        assert_eq!(calls, 4, "two reads to the second, two seconds to the kick");
        let cycles = f.host.cycle(&mut f.machine, &module, 50).expect("cycled");
        assert_eq!(cycles.ended, Ended::Idle, "and then there was nothing left");
    }

    /// The anti-spin test. Nothing is pending and a kick is outstanding, so
    /// there is nothing to do until the clock moves -- and under a pinned
    /// clock it cannot. The old loop burned every one of its passes here.
    #[test]
    fn nothing_pending_returns_at_once_instead_of_spinning_to_the_bound() {
        let (mut f, module, rou) = polling_fixture();
        f.host.kicks.push(Kick { delay: 60, dstrou: rou });
        f.host.set_clock(Clock::pinned(1_135_952_405));

        let cycles = f.host.cycle(&mut f.machine, &module, 10_000).expect("cycled");

        assert_eq!(
            cycles.ended,
            Ended::Waiting { next_kick: 60, polls_cut: true },
            "no refill was ever granted, so the budget reads exhausted"
        );
        assert_eq!(
            cycles.iterations, 1,
            "one pass to work out there is nothing to do -- not 10,000"
        );
        assert_eq!(cycles.dispatched, 0);
    }

    /// `next_kick` is the SOONEST countdown, which is the whole of what makes
    /// it safe to sleep on: a driver told the furthest one would sleep through
    /// every timer before it.
    ///
    /// Every other test of `next_kick` in this crate has exactly one kick in
    /// the table, where the soonest and the furthest are the same number.
    /// Mutating `.min()` to `.max()` passed all 773 lib tests and all 17
    /// real-module tests -- the gap predates this branch, and it is the shape
    /// of the tests rather than any of them being wrong.
    #[test]
    fn next_kick_is_the_soonest_of_several_and_not_merely_one_of_them() {
        let (mut f, module, rou) = polling_fixture();
        f.host.set_clock(Clock::pinned(1_135_952_405));
        // Pushed furthest-first, so a `next_kick` that took the last entry, or
        // the first, or the largest is a different number from the answer.
        f.host.kicks.push(Kick { delay: 300, dstrou: rou });
        f.host.kicks.push(Kick { delay: 7, dstrou: rou });
        f.host.kicks.push(Kick { delay: 45, dstrou: rou });

        let cycles = f.host.cycle(&mut f.machine, &module, 10).expect("cycled");

        assert_eq!(
            cycles.ended,
            Ended::Waiting { next_kick: 7, polls_cut: true },
            "the soonest of the three, not the last pushed and not the largest"
        );
    }

    /// The budget is what stops the poll pump, and the pump stops with the
    /// queue empty -- which is what lets `cycle` report `Waiting` and the
    /// driver sleep.
    #[test]
    fn the_poll_budget_bounds_dispatches_and_leaves_nothing_queued() {
        let (mut f, module, rou) = polling_fixture();
        let console = f.console();
        f.host.users.set_polrou(&mut f.machine, console, Some(rou)).expect("channel 0");

        f.host.refill_polls(&f.machine, 5).expect("armed");
        let cycles = f.host.cycle(&mut f.machine, &module, 1_000).expect("cycled");

        assert_eq!(cycles.dispatched, 5, "the budget, not the pass bound");
        assert_eq!(
            cycles.ended,
            Ended::Idle,
            "no kicks here, and the queue drained: there is nothing to wake for"
        );
        assert_eq!(
            f.host.gsbl_mut().next_status(console),
            None,
            "the pump stopped with the queue empty, or the driver could never sleep"
        );
    }

    /// The cold start. Once the budget is spent nothing re-arms the chain, so
    /// a refill that only counted would poll this channel never again.
    #[test]
    fn a_refill_arms_the_chain_again_after_the_budget_ran_out() {
        let (mut f, module, rou) = polling_fixture();
        let console = f.console();
        f.host.users.set_polrou(&mut f.machine, console, Some(rou)).expect("channel 0");

        f.host.refill_polls(&f.machine, 3).expect("armed");
        let first = f.host.cycle(&mut f.machine, &module, 1_000).expect("cycled");
        assert_eq!(first.dispatched, 3);

        f.host.refill_polls(&f.machine, 3).expect("armed again");
        let second = f.host.cycle(&mut f.machine, &module, 1_000).expect("cycled");
        assert_eq!(second.dispatched, 3, "the second burst polls too");
    }

    /// A refill while the chain is still armed must not add a second status.
    /// `cycle` hitting its pass bound leaves one queued, the driver refills on
    /// every wake, and a queue that grows by one per wake is a leak no
    /// single-burst test can see.
    #[test]
    fn a_refill_does_not_arm_a_channel_that_is_already_armed() {
        let (mut f, module, rou) = polling_fixture();
        let console = f.console();
        f.host.users.set_polrou(&mut f.machine, console, Some(rou)).expect("channel 0");

        f.host.refill_polls(&f.machine, 100).expect("armed");
        // One pass: dispatches one poll, and `dopoll` re-arms because budget
        // remains. So a status is queued when the refill below runs.
        let _ = f.host.cycle(&mut f.machine, &module, 1).expect("cycled");
        f.host.refill_polls(&f.machine, 100).expect("refilled while armed");

        assert_eq!(f.host.gsbl_mut().next_status(console), Some(gsbl::Gsbl::POLSTS));
        assert_eq!(
            f.host.gsbl_mut().next_status(console),
            None,
            "one arming, not two"
        );
    }

    /// A refill arms EVERY polling channel, not merely the first one it finds.
    ///
    /// Every other test of the budget uses `polling_fixture`, which is one
    /// channel -- and at one channel a sweep over `terms().all()` and a sweep
    /// that stops after the first are the same function. Mutating the loop to
    /// `.take(1)` passed all 780 lib tests AND all 17 real-module tests,
    /// including the two-player one, because there the module's own
    /// `begin_polling` had already armed both channels and the refill's sweep
    /// never had to do the work.
    ///
    /// This is the shape the multi-channel branch was built to make
    /// falsifiable: `btuxmt` writing to the current channel instead of its
    /// argument passed all sixteen real-module tests too.
    #[test]
    fn a_refill_arms_every_polling_channel_and_not_just_the_first() {
        let (mut f, module, rou) = polling_fixture_with(3);
        let terms = f.host.users().terms();
        let zero = terms.chan(0).expect("channel 0");
        let one = terms.chan(1).expect("channel 1");
        let two = terms.chan(2).expect("channel 2");

        // The middle channel deliberately does not poll, so that "armed every
        // channel" and "armed every channel that polls" are also different
        // answers here.
        for chan in [zero, two] {
            f.host
                .users
                .set_polrou(&mut f.machine, chan, Some(rou))
                .expect("a polling channel");
        }

        f.host.refill_polls(&f.machine, 100).expect("armed");

        assert!(f.host.gsbl().polling_armed(zero), "channel 0 polls, so it is armed");
        assert!(
            f.host.gsbl().polling_armed(two),
            "channel 2 polls too, and a sweep that stopped at the first would miss it"
        );
        assert!(
            !f.host.gsbl().polling_armed(one),
            "channel 1 has no polling routine, so arming it would be a dispatch \
             the module never asked for"
        );

        // And they are not merely queued: both armings become dispatches.
        let cycles = f.host.cycle(&mut f.machine, &module, 1_000).expect("cycled");
        assert_eq!(
            cycles.dispatched, 101,
            "the budget plus one, and the plus one is the point: when the \
             budget reaches zero the OTHER channel still holds an injection, \
             and `dopoll` dispatches it rather than dropping it -- a status \
             the host queued is one it owes the module. So the overshoot is \
             bounded by the number of armed channels, not by the budget"
        );
        assert_eq!(
            f.host.gsbl_mut().next_status(zero),
            None,
            "and it stops with the queues empty, or the driver could never sleep"
        );
        assert_eq!(f.host.gsbl_mut().next_status(two), None);
    }

    /// A refill of nothing arms nothing.
    ///
    /// The `n == 0` early return is not an optimisation: dispatch itself is
    /// never budget-gated, only the re-arm is, so arming a channel here would
    /// buy exactly one unbudgeted poll per channel per wake. Deleting the
    /// guard passed the whole suite, so nothing said this out loud.
    #[test]
    fn a_refill_of_zero_arms_nothing_and_dispatches_nothing() {
        let (mut f, module, rou) = polling_fixture();
        let console = f.console();
        f.host.users.set_polrou(&mut f.machine, console, Some(rou)).expect("channel 0");

        f.host.refill_polls(&f.machine, 0).expect("granted nothing");

        assert!(
            !f.host.gsbl().polling_armed(console),
            "a budget of zero arms nothing, or it buys a poll it did not grant"
        );
        let cycles = f.host.cycle(&mut f.machine, &module, 50).expect("cycled");
        assert_eq!(cycles.dispatched, 0);
    }

    /// The meter that calibrates the budget in production.
    #[test]
    fn polls_cut_says_the_budget_was_the_thing_that_stopped_it() {
        let (mut f, module, rou) = polling_fixture();
        let console = f.console();
        f.host.users.set_polrou(&mut f.machine, console, Some(rou)).expect("channel 0");
        f.host.kicks.push(Kick { delay: 60, dstrou: rou });
        f.host.set_clock(Clock::pinned(1_135_952_405));

        f.host.refill_polls(&f.machine, 2).expect("armed");
        let cut = f.host.cycle(&mut f.machine, &module, 1_000).expect("cycled");
        assert_eq!(cut.ended, Ended::Waiting { next_kick: 60, polls_cut: true });

        // Nothing polling: the budget is untouched, so nothing was cut.
        f.host.users.set_polrou(&mut f.machine, console, None).expect("channel 0");
        f.host.refill_polls(&f.machine, 2).expect("nothing to arm");
        let uncut = f.host.cycle(&mut f.machine, &module, 1_000).expect("cycled");
        assert_eq!(uncut.ended, Ended::Waiting { next_kick: 60, polls_cut: false });
    }

    /// The whole sleep policy, in one place, so that the socket driver and any
    /// other driver cannot answer this question differently.
    #[test]
    fn ended_tells_a_driver_what_to_wait_on() {
        use crate::Wait;
        assert_eq!(Ended::Idle.wait(), Wait::Blocked);
        assert_eq!(
            Ended::Waiting { next_kick: 1, polls_cut: false }.wait(),
            Wait::Until(1)
        );
        assert_eq!(
            Ended::Waiting { next_kick: 60, polls_cut: true }.wait(),
            Wait::Until(60)
        );
        assert_eq!(Ended::Bound { next_kick: None }.wait(), Wait::Now);
        assert_eq!(Ended::Bound { next_kick: Some(3) }.wait(), Wait::Now);

        // The arm a driver reaches once and never returns from. Left out of
        // the first draft of this test, and review found it by mutating
        // `Wait::Stop` to `Wait::Blocked` and watching all 773 tests stay
        // green -- a driver that blocked forever on a stopped module instead
        // of shutting down, with nothing to say so.
        assert_eq!(
            Ended::Stopped(mbbs16::Poison::Timeout { cs: 0, ip: 0 }).wait(),
            Wait::Stop
        );
    }

    /// `MAJORBBS.C:476` is `while (tcklst != ticker)`, which was safe only
    /// because `ticker` was an unsigned counter that could not go backwards. A
    /// system clock can -- NTP, a manual set -- and `!=` would then run about
    /// four billion rounds, firing timers on every one.
    #[test]
    fn a_clock_that_goes_backwards_resyncs_instead_of_firing_four_billion_rounds() {
        let (mut f, module, rou) = polling_fixture();
        f.host.set_clock(Clock::pinned(1_135_952_405));
        let _ = f.host.cycle(&mut f.machine, &module, 1).expect("cycled");

        f.host.kicks.push(Kick { delay: 1, dstrou: rou });
        f.host.set_clock(Clock::pinned(1_135_952_000));

        let cycles = f.host.cycle(&mut f.machine, &module, 3).expect("cycled");

        assert_eq!(cycles.dispatched, 0, "going backwards fires nothing");
        assert!(
            f.host.notes().iter().any(|n| n.contains("backwards")),
            "and it does not happen in silence: {:?}",
            f.host.notes()
        );
    }

    /// `tcklst` starts unset rather than at zero. Zero would make the first pass
    /// catch up from 1970 -- about 1.1 billion `prcrtk` rounds, each one walking
    /// the whole kicktable.
    #[test]
    fn the_first_pass_syncs_the_tick_counter_rather_than_catching_up_from_1970() {
        let (mut f, module, rou) = polling_fixture();
        f.host.set_clock(Clock::pinned(1_135_952_405));
        f.host.kicks.push(Kick { delay: 2, dstrou: rou });

        let cycles = f.host.cycle(&mut f.machine, &module, 3).expect("cycled");

        assert_eq!(cycles.dispatched, 0, "no second has elapsed yet");
        assert_eq!(
            f.host.kicks().first().map(|kick| kick.delay),
            Some(2),
            "and the kick has not been counted down at all"
        );
    }

    /// What a `cycle` pass costs, reported and asserted by nothing.
    ///
    /// Two numbers matter and they are very different: an idle pass is a scan,
    /// a clock read and an integer compare, while a dispatching pass is a full
    /// emulated 16-bit call. Under a system clock an idle pass is also a
    /// busy-wait, which is why `Ended::Idle` exists for a driver to block on.
    ///
    /// Deliberately asserts nothing. Throughput on a shared box is not stable
    /// enough to pin, and a flaky meter is worse than no meter.
    #[test]
    #[ignore = "timing, not a meter"]
    fn what_a_cycle_pass_costs() {
        let (mut f, module, rou) = polling_fixture();
        f.host.kicks.push(Kick { delay: 30_000, dstrou: rou });
        f.host.set_clock(Clock::stepped(1_135_952_405, 1));

        let n = 100_000;
        let at = std::time::Instant::now();
        let idle = f.host.cycle(&mut f.machine, &module, n).expect("cycled");
        let each = at.elapsed() / idle.iterations as u32;
        eprintln!("{} idle passes, {each:?} each", idle.iterations);

        let (mut f, module, rou) = polling_fixture();
        let console = f.console();
        f.host.users.set_polrou(&mut f.machine, console, Some(rou)).expect("channel 0");
        f.host.gsbl_mut().inject(console, gsbl::Gsbl::POLSTS);
        let at = std::time::Instant::now();
        let busy = f.host.cycle(&mut f.machine, &module, n).expect("cycled");
        let each = at.elapsed() / busy.iterations as u32;
        eprintln!("{} dispatching passes, {each:?} each", busy.iterations);
    }
}
