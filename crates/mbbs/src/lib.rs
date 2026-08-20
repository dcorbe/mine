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
//! than asserted. `crates/mbbs-machine/tests/trace_init.rs` drives MajorMUD's
//! initialisation with a host that answers zero to everything. It reaches 201
//! calls and then takes SIGSEGV *inside module code*, because `alczer` was told
//! it returned a null pointer at call 183 and the module dereferenced it
//! eighteen calls later. The fault names the module, not the lie.
//!
//! So an import the host cannot service does not return zero and does not
//! return an error the module can interpret. It stops the module, naming the
//! symbol -- see [`Poison::Unimplemented`](mbbs_machine::m16::Poison::Unimplemented).

/// The vocabulary for serving more than one ABI: [`abi::Abi`], [`abi::Cursor`]
/// and the single implementation [`abi::Wg16`].
///
/// `pub` for a different reason than its neighbours, so it is worth saying
/// which. `btrieve`, `fsd`, `msg` and the rest are public because
/// `crates/mbbs/tests/*.rs` are separate compilation units that `use` them.
/// Nothing uses this one yet -- Task 2 of the ABI plan builds the vocabulary
/// and converts nothing, so every item here is unreferenced by construction,
/// and as a private module it would be six dead-code warnings against a
/// baseline that is meant to stay flat.
///
/// `pub` rather than `#[allow(dead_code)]` because this is the crate's
/// intended surface, not a suppression: the shim signature itself is what
/// locks this host to 16-bit pointers, so `Abi` is what the shim layer will
/// eventually be written in terms of. If Tasks 4 and 5 land on a different
/// shape than [`abi::Cursor`] -- the borrow question its own doc comment
/// leaves open is a live one -- then what is left over should be deleted, not
/// left public to keep the lint quiet.
pub mod abi;
mod arena;
pub mod btrieve;
pub mod chan;
pub mod clock;
pub mod dos;
pub mod extension;
mod exports;
mod fmt;
pub mod fsd;
mod globals;
pub mod gsbl;
pub mod heap;
pub mod ifansi;
pub mod keys;
pub mod mcv;
pub mod msg;
pub mod random;
// `pub`, not `mod`: `tests/corpus_coverage.rs` is a legitimate external
// consumer of `shims::entry`/`shims::Entry` -- the coverage ledger asks the
// host's own resolution path directly rather than re-implementing it, so it
// needs the module path, not just the re-exports below (which name the
// *types* `Entry`/`Cleans`/`Shim`/`ShimError` but not the `entry` fn itself,
// and not under the `shims::` path the ledger's `served()` spells it with).
pub mod shims;
pub mod strings;
pub mod stream;
pub mod survey;
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
use std::time::Duration;

pub use chan::{Chan, Terms};
pub use clock::{Civil, Clock};
pub use exports::Exports;
pub use fsd::Form;
pub use globals::{GLOBALS, Global, Globals, NTERMS, OUTBSZ};
pub use heap::{Config, Heap, Region};
pub use keys::KeySet;
pub use random::{RAND_MAX, Random, Runaway};
pub use shims::system::{Agent, Dispatch, Kick, Native, Registration};
// `append` alone, not the rest of `shims::text`: `crates/mbbs/tests/newline_oracle.rs`
// needs a way to drive `normalize_newlines` from outside this crate (it is a
// private fn of `shims::text`, unreachable across the crate boundary a
// `tests/*.rs` file compiles as), and `append` is the narrowest public entry
// point that reaches it.
pub use shims::text::append;
pub use shims::{Cleans, Entry, Shim, ShimError};
pub use strings::{depad, is_white, rmvwht, skpwht, skpwrd};
pub use textvar::{TextVar, TextVars};
pub use users::{Connection, Users};

use mbbs_machine::m16::{NeImage, Relocation, Source, Symbol, Target};

// `ModuleMem` for `A::mem(cpu).alloc_region(..)` in `Host::new` below --
// generic since Task 13 of
// `docs/plans/2026-08-12-abi-border-implementation.md`, the same allocator
// `Heap`/`Arena`/`Globals` already went through. `Abi` itself is what
// `Host<A>` is generic over; nothing in this file's production code names
// `Wg16` any more (Task 14 moved the last two things that did, `dos_name`
// and the free function `caller`, off it) -- the test module imports it
// itself, where a concrete machine still has to be built.
use crate::abi::{Abi, ModuleMem};
// `ModulePtr` for `A::Ptr::resolve`/`write` below -- `Host::class_mem` and
// `Host::point_curusr_mem` are this file's first two generic-core methods
// that touch a pointer's own memory access rather than only `Globals`'/
// `Users`'/`Heap`'s already-generic surface.
use mbbs_machine::ptr::ModulePtr;

/// How a module entry point ended.
///
/// `A` carries no default -- Task 10 of
/// `docs/plans/2026-08-12-abi-border-implementation.md` added the parameter
/// (the plan's "Corrections, measured during execution" section is explicit
/// that this type never had one to change). `Returned`/`Stopped` mirror
/// [`crate::abi::Exit`]'s own two live variants: `lo`/`hi` are `AX`/`DX`
/// zero-extended for `Wg16`, `EAX`/`EDX` for `Wg32`, and `Stopped` carries
/// this ABI's own poison rather than `mbbs_machine::m16::Poison` by name.
///
/// Not `#[derive(..)]`: the derive macro's generated bound is `A: Trait`,
/// wrong here for the same reason `Ret<A>`/`Exit<A>` in `abi.rs` are
/// hand-written -- the only field that varies by `A` is `A::Poison`
/// (`Abi::Poison` already requires `Clone + Debug + PartialEq`), not `A`
/// itself.
pub enum Outcome<A: Abi> {
    /// It returned. `lo` is `AX`/`EAX` zero-extended, `hi` is `DX`/`EDX`.
    Returned { lo: u32, hi: u32 },

    /// It was stopped for good, and will not run again.
    Stopped(A::Poison),
}

impl<A: Abi> Clone for Outcome<A> {
    fn clone(&self) -> Self {
        match self {
            Self::Returned { lo, hi } => Self::Returned { lo: *lo, hi: *hi },
            Self::Stopped(poison) => Self::Stopped(poison.clone()),
        }
    }
}

impl<A: Abi> std::fmt::Debug for Outcome<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Returned { lo, hi } => f.debug_struct("Returned").field("lo", lo).field("hi", hi).finish(),
            Self::Stopped(poison) => f.debug_tuple("Stopped").field(poison).finish(),
        }
    }
}

impl<A: Abi> PartialEq for Outcome<A> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Returned { lo, hi }, Self::Returned { lo: lo2, hi: hi2 }) => lo == lo2 && hi == hi2,
            (Self::Stopped(a), Self::Stopped(b)) => a == b,
            (Self::Returned { .. }, Self::Stopped(_)) | (Self::Stopped(_), Self::Returned { .. }) => false,
        }
    }
}

impl<A: Abi> Eq for Outcome<A> {}

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
///
/// `A` carries no default, added by Task 11 of
/// `docs/plans/2026-08-12-abi-border-implementation.md`: the plan's
/// "Corrections, measured during execution" section named `Ended` alongside
/// `Outcome`/`Vector`/`Wait` as parameterless, but Task 10 only needed to add
/// the parameter to `Outcome` -- neither `run`/`stop`/`shim_stop` nor any
/// `Vector` use site ever built an `Ended`. [`Host::cycle`] is the first
/// method that does, and it is this task's, so the parameter lands here.
/// `Vector` and `Wait` stay bare: neither carries a `Poison`.
///
/// Not `#[derive(..)]`, for the same reason [`Outcome<A>`] is not: the
/// derive macro's generated bound is `A: Trait`, and only `A::Poison` varies
/// with `A` here, not `A` itself.
pub enum Ended<A: Abi> {
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
    Waiting { next_kick: u32, polls_cut: bool },

    /// `max` passes were made and there is still work queued. A driver calls
    /// straight back.
    Bound { next_kick: Option<u32> },

    /// The module stopped, on the pass it stopped on.
    ///
    /// `Option<Chan>` names which channel was being serviced when it
    /// happened, for a driver that wants to say who -- `None` when the stop
    /// came from [`Host::prcrtk`]'s kick sweep rather than [`Host::poll`]: a
    /// timer callback has no channel to name (see [`crate::Kick`]'s own
    /// doc), and that is an honest fact rather than a gap to paper over.
    Stopped(A::Poison, Option<Chan>),
}

impl<A: Abi> Clone for Ended<A> {
    fn clone(&self) -> Self {
        match self {
            Self::Idle => Self::Idle,
            Self::Waiting { next_kick, polls_cut } => Self::Waiting {
                next_kick: *next_kick,
                polls_cut: *polls_cut,
            },
            Self::Bound { next_kick } => Self::Bound { next_kick: *next_kick },
            Self::Stopped(poison, chan) => Self::Stopped(poison.clone(), *chan),
        }
    }
}

impl<A: Abi> std::fmt::Debug for Ended<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "Idle"),
            Self::Waiting { next_kick, polls_cut } => f
                .debug_struct("Waiting")
                .field("next_kick", next_kick)
                .field("polls_cut", polls_cut)
                .finish(),
            Self::Bound { next_kick } => f.debug_struct("Bound").field("next_kick", next_kick).finish(),
            Self::Stopped(poison, chan) => f.debug_tuple("Stopped").field(poison).field(chan).finish(),
        }
    }
}

impl<A: Abi> PartialEq for Ended<A> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Idle, Self::Idle) => true,
            (
                Self::Waiting { next_kick, polls_cut },
                Self::Waiting { next_kick: nk2, polls_cut: pc2 },
            ) => next_kick == nk2 && polls_cut == pc2,
            (Self::Bound { next_kick }, Self::Bound { next_kick: nk2 }) => next_kick == nk2,
            (Self::Stopped(poison, chan), Self::Stopped(poison2, chan2)) => poison == poison2 && chan == chan2,
            _ => false,
        }
    }
}

impl<A: Abi> Eq for Ended<A> where A::Poison: Eq {}

/// What a driver should do about an [`Ended`].
///
/// One function computes this, because a bare scalar answer derived at each
/// call site is how call sites drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wait {
    /// Block until the transport delivers something.
    Blocked,
    /// Sleep at most this long, waking early on input.
    ///
    /// `Duration`, not a whole-second count -- Task 18 of
    /// `docs/plans/2026-08-12-abi-border-implementation.md`: the vendor
    /// semantic ([`Ended::Waiting`]'s `next_kick`, which decrements on
    /// elapsed *whole* seconds) is unchanged, but the type a driver sleeps on
    /// should not force sub-second pacing through a seconds-shaped hole.
    /// [`Ended::wait`] is the one place that converts -- every value built
    /// here today is still a whole number of seconds, in value, until a
    /// caller has a reason to ask for less.
    Until(std::time::Duration),
    /// Call `cycle` again now.
    Now,
    /// The module stopped. Shut the host down.
    Stop,
}

/// What the poll budget is actually buying, counted per poll dispatch.
///
/// `polls_per_wake` is the host guessing how much simulation to allow, and
/// the module has no way to answer "I am done": [`Host::dopoll`] re-arms
/// after every dispatch for as long as budget remains, and a poll routine
/// with nothing left to do simply falls through -- which still costs a full
/// emulated far call. So the budget cannot be judged from the outside by
/// whether it was consumed (it always is, see [`Ended::Waiting`]'s
/// `polls_cut`), only by what the dispatches it paid for actually did.
///
/// `barren` is the number that answers that. A poll that made no host call
/// at all did nothing this host can observe -- it took the far call, tested
/// its own counters, and returned. A budget whose polls are mostly barren is
/// a budget spending emulated far calls on nothing; one with few barren polls
/// is too small to be starving the module of anything.
///
/// **Not a control input.** Nothing branches on this; it exists so an
/// operator can size `--polls-per-wake` against measurement instead of
/// against the 512 that has never been calibrated.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PollCensus {
    /// Poll dispatches counted.
    pub polls: u64,
    /// ...of which made no host call whatsoever.
    pub barren: u64,
    /// Host routine calls the counted polls made between them.
    pub calls: u64,
    /// The most host calls any one of them made.
    pub worst: u64,
}

impl PollCensus {
    /// Host calls per poll, or `0.0` for a census that counted nothing.
    #[must_use]
    pub fn per_poll(&self) -> f64 {
        if self.polls == 0 {
            return 0.0;
        }
        self.calls as f64 / self.polls as f64
    }

    /// What share of the counted polls did nothing at all, as a percentage.
    #[must_use]
    pub fn barren_pct(&self) -> f64 {
        if self.polls == 0 {
            return 0.0;
        }
        self.barren as f64 * 100.0 / self.polls as f64
    }
}

/// How long one pass may take before it is worth a line.
///
/// One second because that is the granularity of everything it competes with:
/// `prcrtk` fires on whole elapsed seconds and `rtkick` counts in them, so a
/// pass under a second cannot have cost the module a timer.
const STALL_FLOOR: Duration = Duration::from_secs(1);

/// Whether one pass of [`Host::cycle`] took long enough to be worth reporting,
/// and what to say about it.
///
/// `worked` is wall-clock **inside** `cycle`, never the epoch delta. The two
/// are not interchangeable: `Host::tcklst` persists across calls, so an epoch
/// delta counts the driver's sleep between them, and a note derived from it
/// fires hardest when the driver is behaving best. That is what this used to
/// do -- see
/// [`tests::two_seconds_of_correct_sleep_are_not_reported_as_a_stall`].
///
/// Pure, and separate from `cycle`, so that both answers can be tested without
/// a fixture that really does burn a second of wall-clock -- the same reason
/// `mbbs-server`'s own `describe_stop` is its own function.
fn stall_note(worked: Duration, rounds: u32, polled: Option<Chan>) -> Option<String> {
    if worked < STALL_FLOOR {
        return None;
    }
    let who = match polled {
        Some(chan) => format!("channel {chan}'s poll"),
        None => "the kick sweep".to_owned(),
    };
    Some(format!(
        "cycle: one pass took {:.1}s -- {who} stalled the host, and {rounds} second(s) \
         of timers fired to catch up",
        worked.as_secs_f32()
    ))
}

impl<A: Abi> Ended<A> {
    /// What a driver should do about this state.
    #[must_use]
    pub fn wait(&self) -> Wait {
        match self {
            Ended::Idle => Wait::Blocked,
            Ended::Waiting { next_kick, .. } => {
                Wait::Until(std::time::Duration::from_secs(u64::from(*next_kick)))
            }
            Ended::Bound { .. } => Wait::Now,
            Ended::Stopped(..) => Wait::Stop,
        }
    }
}

/// What one [`Host::cycle`] run did.
///
/// `A` carries no default -- see [`Ended`]'s own doc comment. Not
/// `#[derive(..)]`, for the same reason: only `A::Poison`, buried inside
/// `Ended<A>`, varies with `A`.
pub struct Cycles<A: Abi> {
    /// Passes made before the interrupt asked for the thread back, or before
    /// the board went idle. The host's own share of [`Host::clock_reads`],
    /// since each pass reads the clock once.
    pub iterations: usize,

    /// Module calls made: polling routines, entry points, and fired kicks.
    /// **The meter.**
    pub dispatched: usize,

    /// Why it stopped.
    pub ended: Ended<A>,
}

impl<A: Abi> Clone for Cycles<A> {
    fn clone(&self) -> Self {
        Self {
            iterations: self.iterations,
            dispatched: self.dispatched,
            ended: self.ended.clone(),
        }
    }
}

impl<A: Abi> std::fmt::Debug for Cycles<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cycles")
            .field("iterations", &self.iterations)
            .field("dispatched", &self.dispatched)
            .field("ended", &self.ended)
            .finish()
    }
}

impl<A: Abi> PartialEq for Cycles<A> {
    fn eq(&self, other: &Self) -> bool {
        self.iterations == other.iterations && self.dispatched == other.dispatched && self.ended == other.ended
    }
}

impl<A: Abi> Eq for Cycles<A> where A::Poison: Eq {}

/// A global the module addresses that the host cannot place -- or, since
/// cross-module import support landed, a routine the module calls from a
/// module that *is* loaded but does not export it (`Why::NotExported`
/// below).
///
/// The second case stretches the name: it is a symbol the module *calls*,
/// not addresses as data. It rides this same type anyway, rather than a
/// parallel `MissingModule`/`LoadError::Module` pair, because the shape is
/// identical in every way that matters -- a DLL name, a symbol, a reason the
/// loader could not honour it -- and `LoadError::Globals` already carries
/// exactly that. See `Resolver::resolve`'s own doc comment for why this is
/// the one case that gets a hard refusal rather than the graceful
/// degradation every other unimplemented import gets.
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

/// What is wrong with a global the module addresses, or a routine it calls
/// from another loaded module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// The host does not place it at all.
    NotPlaced,

    /// The host places it, but the module reaches past the end of it.
    TooSmall { addend: i16, size: u16 },

    /// `module` names another module this `Host` has already loaded in this
    /// life -- not a host DLL, and not one still unloaded -- but its export
    /// table has no such ordinal or name.
    ///
    /// **Deliberately not raised for a module the registry has never heard
    /// of at all.** That case is indistinguishable, from the resolver's own
    /// vantage point, from a host DLL this crate simply has not implemented
    /// every symbol of yet (`DOSCALLS`, `PHAPI`, ...) -- both answer
    /// [`crate::shims::Entry::Unimplemented`] and neither is in
    /// [`Resolver`]'s registry, and the existing, load-bearing behaviour for
    /// the second case is to load anyway and thunk the call, faulting only
    /// if the module actually reaches it. Making *every* unrecognised module
    /// name a hard refusal would refuse to load `WCCMMUD.DLL` itself over
    /// its own unimplemented `DOSCALLS`/`PHAPI` imports. `NotExported` only
    /// ever fires once a module genuinely is present in memory and
    /// genuinely does not have what was asked of it -- a version mismatch or
    /// a wrong ordinal, not a gap more shim code could ever close.
    NotExported,
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
            Why::NotExported => write!(f, "{module} is loaded, but exports no {symbol}"),
        }
    }
}

/// Where the date-and-time routines format, once one of them has needed to.
///
/// One block per routine rather than one shared block, because the original had
/// three separate statics and a module may hold an `ncdate` result across an
/// `nctime` call.
///
/// `A` carries no default. It was `= Wg16` until Task 3 of
/// `docs/plans/2026-08-12-abi-border-implementation.md` struck every
/// declaration-site default in this crate: a default reads as generic at the
/// use site while pinning one ABI, and nothing warns. Every caller now spells
/// its ABI -- see [`Host`]'s own doc comment. Not
/// `#[derive(Debug, Clone, Copy, PartialEq, Eq)]`: the derive macros bound `A:
/// Trait` on the impl, which is wrong here -- `Wg16` itself implements none of
/// these, only `A::Ptr` does (`Abi::Ptr: mbbs_machine::ptr::ModulePtr + Copy + Eq +
/// Hash`, and `ModulePtr` itself requires `Debug`). See `abi.rs`'s `Ret<A>`
/// for the same trap hit and fixed the same way.
pub(crate) struct DateBuffers<A: Abi> {
    /// 9 bytes: `MM/DD/YY` and its terminator.
    pub(crate) date: A::Ptr,

    /// 9 bytes: `HH:MM:SS` and its terminator.
    pub(crate) time: A::Ptr,

    /// 10 bytes: `DD-Mon-YY` and its terminator.
    pub(crate) edat: A::Ptr,

    /// One byte, always NUL. What `ncdate(0)` returns -- and a **different**
    /// address from `date`, so a null date leaves an earlier result standing,
    /// exactly as `seg 33:0x0c14` does by never writing at all. Written
    /// explicitly at `shims/system.rs:110` rather than trusted to the heap's
    /// zero-fill -- see [`Host::empty`] for the sibling that exists for the
    /// module's first instruction instead of its first date call.
    pub(crate) empty: A::Ptr,
}

impl<A: Abi> Clone for DateBuffers<A> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<A: Abi> Copy for DateBuffers<A> {}

impl<A: Abi> std::fmt::Debug for DateBuffers<A>
where
    A::Ptr: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DateBuffers")
            .field("date", &self.date)
            .field("time", &self.time)
            .field("edat", &self.edat)
            .field("empty", &self.empty)
            .finish()
    }
}

impl<A: Abi> PartialEq for DateBuffers<A>
where
    A::Ptr: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.date == other.date
            && self.time == other.time
            && self.edat == other.edat
            && self.empty == other.empty
    }
}

impl<A: Abi> Eq for DateBuffers<A> where A::Ptr: Eq {}

/// Why a module could not be loaded.
#[derive(Debug)]
pub enum LoadError {
    /// The file is not a module this loader can map. See
    /// [`NeError`](mbbs_machine::m16::NeError) (`Wg16`) and
    /// [`PeError`](mbbs_machine::m32::PeError) (`Wg32`).
    Image(io::Error),

    /// The module addresses host globals the host cannot honestly provide --
    /// or calls a symbol from a module this `Host` already loaded that does
    /// not export it. See [`Why::NotExported`] and [`MissingGlobal`]'s own
    /// doc comment for why the second case rides this variant rather than a
    /// new one.
    Globals(Vec<MissingGlobal>),

    /// A host table answered [`mbbs_machine::module::Import::Absolute`] for a
    /// symbol a PE import site asked to bind -- `Wg32` only. See
    /// [`mbbs_machine::m32::AbsoluteImport`]'s own doc comment for why only
    /// NE relocations can ever honour that answer: an NE fixup can patch
    /// part of an address into an instruction's own immediate field, and a
    /// PE fixup always writes a whole address-sized IAT slot and never can.
    /// Refused rather than silently written as if it were data or a thunk --
    /// both would compile and both would be wrong.
    Absolute { module: String, symbol: String },

    /// Two or more generations are admissible and disagree about a symbol the
    /// modules actually import. Refused rather than picked: a bare ordinal is
    /// reported, a wrong name is believed.
    AmbiguousProfile(Vec<mbbs_machine::library::Discriminator>),
    /// No generation covers everything the modules demand.
    NoProfile {
        excluded: Vec<(&'static str, Vec<(&'static str, Vec<u16>)>)>,
        unevidenced: Vec<&'static str>,
    },
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
            Self::Absolute { module, symbol } => write!(
                f,
                "{module}.{symbol} resolved to Import::Absolute, which a PE import site \
                 cannot bind (a PE fixup writes a whole address-sized IAT slot, never an \
                 instruction's immediate field)"
            ),
            Self::AmbiguousProfile(discriminating) => {
                writeln!(f, "more than one host generation fits, and they disagree:")?;
                for d in discriminating {
                    let names: Vec<String> =
                        d.names.iter().map(|(p, n)| format!("{p} calls it {n}")).collect();
                    writeln!(f, "  {}.{} -- {}", d.library, d.ordinal, names.join(", "))?;
                }
                write!(f, "refusing rather than guessing which one this module was built against")
            }
            Self::NoProfile { excluded, unevidenced } => {
                writeln!(f, "no host generation covers what these modules import:")?;
                for (profile, uncovered) in excluded {
                    for (library, ordinals) in uncovered {
                        writeln!(f, "  {profile} has no {library} ordinal {ordinals:?}")?;
                    }
                }
                if !unevidenced.is_empty() {
                    writeln!(f, "  no table at all for: {}", unevidenced.join(", "))?;
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

impl From<mbbs_machine::m32::PeError> for LoadError {
    fn from(e: mbbs_machine::m32::PeError) -> Self {
        Self::Image(io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }
}

impl From<mbbs_machine::m32::AbsoluteImport> for LoadError {
    fn from(e: mbbs_machine::m32::AbsoluteImport) -> Self {
        Self::Absolute {
            module: e.module,
            symbol: e.symbol.to_string(),
        }
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
///
/// `A` carries no default. It was `= Wg16`, which let every caller -- every
/// field access and method call in this file, every `&mut Host` in
/// `crates/mbbs/src/shims/`, `crates/mbbs-server`, and every test -- name this
/// type as plain `Host` and keep compiling unchanged. Task 3 of
/// `docs/plans/2026-08-12-abi-border-implementation.md` removed it, so each of
/// those now spells `Host<Wg16>`. See `docs/plans/2026-08-11-abi-
/// abstraction-implementation.md`'s "Tasks 5 and 6 are in the wrong order,
/// and `Host` is missing from both": `Host` owns [`Heap`], [`Globals`],
/// [`TextVars`], [`msg::Messages`], [`stream::Streams`] and [`Users`], each
/// already generic over `A` (`Heap`/`Arena`/`Globals` in one commit, the other
/// four one file at a time), so those fields flip to `<A>` here.
///
/// # Split method surface, like `Users`
///
/// Unlike `Heap`/`Globals`/`TextVars`/`Messages`/`Streams` -- each of which
/// landed as "generic at the type level, `Wg16`-only method surface" on
/// purpose -- part of `Host`'s own surface is genuinely generic, the same way
/// [`Users::nth`] and its dependents turned out to be. Every accessor and
/// piece of bookkeeping that never touches a `Machine` lives in `impl<A:
/// Abi> Host<A>`: field accessors (`globals`, `heap`, `users`, `textvars`,
/// `messages`, `streams`, ...), the notes/audit/keys-asked logs, the module
/// filesystem helpers, and `next_spr_buffer`/`next_l2as_buffer`/`mdf_buffer`/
/// `empty_string`, which now build their pointers through [`Abi::ptr_offset`]
/// instead of a hand-built `FarPtr`. That includes
/// (`modules`/`first_module`/`register`/`register_native`/`agents`/`kicks`),
/// which read or build [`Registration`]/[`Agent`]/[`Kick`] -- all three of
/// which *are* parameterised, as `Registration<A: Abi>` and its two
/// siblings, so these accessors are generic in substance and not merely by
/// position.
///
/// An earlier revision of this comment said the opposite -- that the three
/// were "concrete `FarPtr`-typed structs with no `Abi` parameter of their
/// own", and that "the module dispatch table itself will not serve a 32-bit
/// module until those three types grow one too". They grew one; the comment
/// was not updated with them, and it outlived the fact by long enough to be
/// quoted back as a live blocker. The `= Wg16` *default* each carried until
/// Task 3 of `docs/plans/2026-08-12-abi-border-implementation.md` was what
/// made the staleness hard to see: a bare `Kick` in a signature still read as
/// concrete and still compiled, because the default silently supplied
/// `Wg16` -- so genericity here had to be confirmed at the declaration, never
/// inferred from a use site. Task 3 removed the default; a bare `Kick` no
/// longer compiles at all, so the compiler now names every site that still
/// needs `<Wg16>` spelled out, and this exact staleness cannot hide again.
///
/// `impl Host<Wg16>` itself is gone as of Task 14 of
/// `docs/plans/2026-08-12-abi-border-implementation.md`: every method that
/// used to live there for touching module memory (`&mut Machine`/`&Machine`)
/// moved onto `impl<A: Abi> Host<A>` across Tasks 9-13, generic on the
/// memory access itself (`Abi::mem`/`Abi::mem_ref`) rather than on the
/// parameter's concrete type, and the two survivors with no ABI-dependent
/// behaviour at all (`Host::new`, `Host::dos_name`) followed them once
/// nothing else forced the block to exist. `Host::load` -- and the
/// NE-specific mechanism `check_globals` used to be, now folded into
/// `Resolver::resolve` -- moved out in Task 9; its own NE-specific mechanism
/// is private module-level machinery, not a method on `Host` at all -- see
/// `Host::load`'s own doc comment.
///
/// [`btrieve::Btrieve`] is `Btrieve<A>` now. It was concrete while another
/// session owned that file, and the field elided its parameter to say so.
/// The members of `struct curatr` (`INC/VIDAPI.H:198-228`) the served console
/// routines touch, and no others.
///
/// See [`Host::display`] for why this is host state rather than a placed
/// global.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Display {
    /// `curatr.attrib` -- the display attribute `sstatr` sets.
    ///
    /// Starts at **7**, which is what a genuine `MAJORBBS.EXE` holds before
    /// anything calls `sstatr`: measured on both period builds in
    /// `tests/oracle_gate.rs`
    /// (`sstatr_stores_the_attribute_in_one_byte_of_host_data`), not chosen
    /// because light-grey-on-black is the conventional default.
    pub attrib: u8,

    /// `scnstt`/`ulx`/`uly`/`lrx`/`lry`/`scropt` -- the current window, and
    /// the **one** saved copy behind it (`oscnstt`/`oulx`/... in the same
    /// struct).
    ///
    /// One slot, not a stack: `setwin` copies current to saved and `rstwin`
    /// copies saved back, so two `setwin`s followed by two `rstwin`s restore
    /// the second saved state both times. That is the vendor's behaviour, not
    /// a simplification.
    pub window: Window,
    pub saved: Window,
}

/// One window's worth of `struct curatr`: where the screen starts, the two
/// corners, and whether scrolling is enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Window {
    /// `scnstt` -- the screen this window writes to, `0` meaning real video.
    /// Kept as the raw word pair a module passed rather than an `A::Ptr`,
    /// because nothing here dereferences it.
    pub scnstt: (u16, u16),
    pub ulx: u8,
    pub uly: u8,
    pub lrx: u8,
    pub lry: u8,
    pub scropt: u8,
}

impl Default for Display {
    fn default() -> Self {
        Self { attrib: 7, window: Window::default(), saved: Window::default() }
    }
}

pub struct Host<A: Abi> {
    exports: Exports,

    /// Every ordinal every loaded module has imported so far, across every
    /// [`Host::load`] call in this life -- accumulated, never rebuilt. A
    /// later module can narrow the admissible set of profiles, but must never
    /// be able to change what an ordinal an earlier module already resolved
    /// was taken to mean. See [`mbbs_machine::library::detect`].
    demand: mbbs_machine::library::Demand,

    /// The set of profile names `detect` reported as agreeing on everything
    /// demanded so far, the last time it ran -- empty until the first
    /// [`Host::load`]. Reported rather than silently swallowed, so the host
    /// never claims to have identified the generation when it has only
    /// picked the anchor among several indistinguishable candidates.
    indistinguishable: Vec<&'static str>,

    /// The profile `detect` settled on, kept alongside the [`Exports`] derived
    /// from it because a report has to name the generation, not just resolve
    /// through it. Starts at the anchor for the same reason `exports` does.
    profile: &'static mbbs_machine::library::Profile,

    globals: Globals<A>,

    /// Where the module's own files are: its `.MDF`, its `.MSG` files, and
    /// eventually its Btrieve tables. A DOS module names them without a path
    /// and in whatever case it likes.
    pub root: PathBuf,

    /// Behaviour installed above this host -- see [`crate::extension`].
    ///
    /// `None` is the supported default and must remain one: a board with no
    /// extension behaves exactly as it did before the seam existed, which is
    /// what lets the whole existing suite go on running unmodified.
    extension: Option<Box<dyn extension::Extension<A>>>,

    /// `spr`'s rotating buffers, and which one is next.
    spr: A::Ptr,
    spr_next: usize,

    /// `l2as`'s rotating buffers, and which one is next.
    ///
    /// **Deliberately not `spr`'s pool.** `spr` rotates
    /// [`shims::text::SPR_BUFFERS`] slots of [`shims::text::SPR_BYTES`] each,
    /// sized for `%s`-shaped text; sharing that rotation with `l2as` would
    /// mean a module's `spr` calls could evict an `l2as` result the module
    /// still holds (or vice versa) sooner than either routine's own contract
    /// implies -- a behaviour change to `spr` smuggled in by an unrelated
    /// shim. `l2as` gets its own small rotation instead, in the same
    /// module-addressable segment `spr`, `mdf` and `empty` already share.
    l2as: A::Ptr,
    l2as_next: usize,

    /// When this host started, in epoch seconds -- what `clock` counts from.
    ///
    /// Borland's `clock()` answers ticks since the *program* started, so
    /// something has to remember when that was. Taken from the same
    /// [`Clock`] every other time routine reads, so a pinned clock pins this
    /// too and `clock()` is testable at all.
    started: u32,

    /// `MCVAPI.C:37-51`'s `mxmssz` -- the largest message buffer any module
    /// has asked `inimsg` for.
    ///
    /// The vendor keeps one shared `msgbuf` of this size and `rawmsg` reads
    /// each message into it, so `mxmssz` is that buffer's length. This host
    /// interns each message at its own exact length instead
    /// ([`crate::messages`]), so there is no single buffer to size -- but
    /// `inimsg`'s promise is still "at least this much room for one message",
    /// and it is still monotonic (`if (mxmssz < maxsiz)`), so the number is
    /// kept and can be asserted.
    msgbuf_size: u16,

    /// `SETCNF.C:46-52`'s `onams`/`ovals` and the `applied` flag: the
    /// name/value pairs `setcnf` has recorded but nothing has applied yet.
    ///
    /// Host-side rather than module memory, because the vendor's are
    /// file-scope `static`s that no module can reach; the only way to observe
    /// them is through `setcnf` and `applyem` themselves.
    setcnf: Vec<(Vec<u8>, Vec<u8>)>,
    setcnf_applied: bool,

    /// The line `scnmdf` answers a `.MDF` option out of.
    ///
    /// The vendor's is `tmpbuf`, a shared `BUFSIZ` scratch buffer, and its
    /// `scnmdf` returns a pointer *into* it -- so in the real host too the
    /// answer only survives until the next thing that uses `tmpbuf`. This is
    /// that buffer, sized the same and owned here instead of shared with
    /// `gmdnam`'s much smaller line.
    scnmdf: A::Ptr,

    /// The console's display attribute and window, as `struct curatr`
    /// (`INC/VIDAPI.H:198-228`) holds them for the real host.
    ///
    /// **Host state rather than a placed global, and that is a decision.**
    /// `curatr` is an exported datum in the vendor
    /// (`EXPWGSV(struct curatr) curatr`) but **no corpus module imports it**
    /// -- checked against every `crates/mbbs/tests/data/corpus/*.tsv` -- so
    /// nothing a module can do observes its layout. Placing it would mean
    /// committing to a 59-byte field order whose packing this repo has no
    /// evidence for (Borland's default alignment for the 16-bit build is not
    /// recorded anywhere tracked), to serve a reader that does not exist. A
    /// wrong layout is worse than no layout. The day a module imports
    /// `curatr`, or this host grows a console, placing it becomes right and
    /// this struct is what moves.
    ///
    /// Only the members the served routines touch are here: the attribute
    /// `sstatr` sets, and the window `setwin` saves and `rstwin` restores.
    display: Display,

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
    pub(crate) strtok: A::Ptr,

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
    pub(crate) datebuf: Option<DateBuffers<A>>,

    /// The line buffer `gmdnam` returns a pointer into.
    mdf: A::Ptr,

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
    empty: A::Ptr,

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
    modules: Vec<Registration<A>>,

    /// Channels whose module handed them back to the absent BBS, waiting for
    /// the driver to close them. Drained by [`Host::drain_ended`], the same
    /// shape [`Host::drain_notes`] already uses to get information out to
    /// whatever is running this host.
    ended: Vec<Chan>,

    /// Every module [`Host::load`] has loaded so far in this life, keyed by
    /// its own declared name ([`Abi::module_name`]) -- **not** the same
    /// bookkeeping as [`Host::modules`] above, which is about a module
    /// *registering itself* with the running host (`register_module`) and
    /// is keyed by registration order, not name. This is purely a loader
    /// concern: what a *later* `Host::load` call's own imports may resolve
    /// against, so that one module compiled to import another's exports
    /// (`WCCMMPLS.DLL` importing `WCCMMUD.DLL`'s `mmlog`, the case this
    /// exists for) can be loaded at all. See [`Resolver`]'s own doc comment
    /// for how an import gets answered out of this map, and
    /// [`Why::NotExported`] for what happens when the answer is "loaded, but
    /// does not have that".
    ///
    /// Empty at [`Host::new`] and never touched anywhere but [`Host::load`],
    /// so it is rebuilt fresh -- never leaked across a life -- exactly the
    /// way every other piece of per-life state here is: a new [`Host`] is
    /// built per life (`crates/mbbs-server`'s restart loop), and this map is
    /// part of that fresh `Self`, not a `static` or anything else that could
    /// outlive one.
    loaded_modules: HashMap<String, A::Module>,

    /// Every client/server agent that has come online, in registration order.
    /// Unlike [`Host::modules`] these are *copies* -- see [`Agent`].
    pub(crate) agents: Vec<Agent<A>>,

    /// The text variables the module has registered. Unlike [`Host::agents`]
    /// these live in memory the module can reach -- see [`TextVars`].
    pub(crate) textvars: TextVars<A>,

    /// The message files that are open, and their text in module memory. Which
    /// one is *current* is not here -- that is `curmbk`, a global the module
    /// can see.
    pub(crate) messages: msg::Messages<A>,

    /// The Btrieve files that are open, and the stack of which is current.
    /// Which one *is* current is `bb`, for the same reason.
    ///
    /// **Write the `<A>`.** A bare `Btrieve` here used not to be "generic,
    /// parameter inferred from the enclosing `Host<A>`" -- in a
    /// type-annotation position the field's `= Wg16` default applied
    /// unconditionally, so it would have been `Btrieve<Wg16>` inside
    /// `Host<Wg32>` just as much as inside `Host<Wg16>`. It compiled, it read
    /// as generic, and it silently pinned the whole Btrieve subsystem to one
    /// ABI.
    ///
    /// That elision is what blocked the seventeen `btv*` shims from taking a
    /// `Call<A>` long after the engine behind them became `Btrieve<A>`: a
    /// generic shim's `call.ptr()` is `A::Ptr`, `Btrieve<Wg16>::block` wants
    /// `FarPtr`, and the compiler reported a type mismatch for *every* `A`
    /// rather than only for `Wg32`. The error pointed at the shim, so it
    /// read as the shim being unconvertible; the cause was one missing
    /// parameter here. Task 3 of
    /// `docs/plans/2026-08-12-abi-border-implementation.md` removed the
    /// `= Wg16` default from `Btrieve` (and every other declaration that had
    /// one): a bare `Btrieve` is now a hard `E0107` at every call site, not a
    /// silent pin, so this exact mistake can no longer compile.
    pub(crate) btrieve: btrieve::Btrieve<btrieve::AbiMem<A>>,

    /// The terminal channels. See [`gsbl`].
    pub(crate) gsbl: gsbl::Gsbl,

    /// The streams that are open. No notion of a current one -- `fopen` hands
    /// back a `FILE *` and every routine takes it, so there is no `curmbk` or
    /// `bb` equivalent to keep in module memory.
    pub(crate) streams: stream::Streams<A>,

    /// Scans [`fnd1st`](crate::shims::stream::fnd1st) has started and
    /// `fndnxt` continues, keyed by which `fbptr` buffer the module is
    /// scanning through and which `Abi` encoded that pointer.
    ///
    /// Real DOS kept this in the block's own `junk[21]` -- which is what
    /// that undocumented field was. This host keeps it beside the module
    /// instead, because the DTA's internal layout is a DOS implementation
    /// detail no header describes, and inventing one would be a fiction the
    /// module could trip over.
    ///
    /// A `Host` field and not a `thread_local!`. A thread-local would be
    /// *nearly* right -- a `Host` runs on one dedicated thread per machine
    /// -- but "nearly" is how hidden process state gets in, and Tasks 1-3 of
    /// this refactor were spent taking exactly that kind of state out of the
    /// shadows and making it something an owner claims. Two `Host`s on one
    /// thread (which `--lib` tests really do build) would share one scan
    /// table, and nothing would say so.
    ///
    /// Keyed per block rather than kept as a single scan so that two
    /// interleaved walks cannot eat each other's matches -- the property the
    /// real DTA had.
    pub(crate) finds: std::collections::HashMap<
        (&'static str, Vec<u8>),
        std::collections::VecDeque<shims::stream::FoundEntry>,
    >,

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

    /// What the poll budget is actually buying. See [`PollCensus`].
    census: PollCensus,

    /// Every callback `rtkick` has been asked to run later, in the order it
    /// was asked. [`Host::cycle`] runs them, once per elapsed second, via
    /// [`Host::prcrtk`]. See [`Host::kicks`].
    pub(crate) kicks: Vec<Kick<A>>,

    /// Real-time interrupt routines a module installed with `rtihdlr`, in
    /// the order it installed them.
    ///
    /// **The host remembers them and nothing runs them**, for exactly the
    /// reason [`Host::kicks`] documents: running one needs a main loop and a
    /// clock this host does not have. `rtihdlr` returns `void`, so it
    /// promises the caller nothing at call time, and a module cannot observe
    /// an 18 Hz tick that never arrives.
    ///
    /// `MAJORBBS.C:145` is `VOID (*rtirs[RTIMAX])(VOID)` with `RTIMAX` 10
    /// (`:143`), and `:1536` `catastro`s on the eleventh. That bound is
    /// enforced here rather than let the `Vec` grow: a module installing
    /// eleven handlers had a bug the real host stopped it for, and silently
    /// accepting the eleventh would hide it.
    pub(crate) rtirs: Vec<A::Ptr>,

    /// Routines registered through `initask` (`GCOMM.H:493`,
    /// `int initask(void (*tskaddr)(int taskid))`), in registration order --
    /// the index IS the task id the original hands back, and what it passes
    /// each routine when it runs it.
    ///
    /// [`Host::prctask`] runs them. `MAJORBBS.C:323` initialises the
    /// `syscyc` vector to `prctask` itself, so on the original every module
    /// that chains onto that vector calls the task runner at its own tail;
    /// this host runs it from [`Host::cycle`] instead, which reaches the same
    /// place without depending on every module chaining correctly. See
    /// `cycle`'s own comment.
    ///
    /// **Not per channel.** A task is a system-wide routine, not a user's --
    /// `The Rose 2.0` registers one at init and `GALMHS.C:707` keeps its id
    /// in a global, neither of which is channel-scoped.
    pub(crate) tasks: Vec<A::Ptr>,

    /// Whether each of DOS's five pre-opened standard handles is currently
    /// in binary mode, for `shims::crt::setmode`/`read`/`write` -- Borland's
    /// low-level POSIX-shaped `int handle` I/O, not the `FILE *` streams
    /// [`Host::streams`](Host#structfield.streams) owns.
    ///
    /// Index `0..=4` is `stdin`/`stdout`/`stderr`/`aux`/`prn`, in that
    /// order -- the same five DOS hands every process before it opens
    /// anything of its own, which is exactly why
    /// [`crate::stream::Streams`]'s own numbering (`FIRST_FD`) starts
    /// immediately *after* them, at `5`. `false` (text mode) is DOS's own
    /// default for all five until a module calls `setmode`.
    ///
    /// # A second table, not a view onto `Streams` -- and why
    ///
    /// The natural design ties a `read`/`write` handle to the exact open
    /// file `Streams` already tracks -- a module that `fopen`s a stream and
    /// reads `fileno(fp)` (a macro over `FILE.fd`, so it leaves no import
    /// record: `tmp/gapsurvey/round2/rose32/RCIROSE.DLL` imports `read` and
    /// `write` but never `fileno`, `open` or `creat`) is naming exactly the
    /// `fd` `Streams::open_mem` already assigned. Reusing that identity
    /// would need `Streams` to answer "which cookie does this `fd` name",
    /// and its `fd`/`open` fields are private to `stream.rs`
    /// (`crates/mbbs/src/stream.rs:484-498`) -- reaching them from here would
    /// mean `stream.rs` growing a new `pub(crate)` accessor, which is a
    /// second file this task's grant does not cover (only `lib.rs` was
    /// extended, not `stream.rs`). So this table is deliberately narrower
    /// instead: it covers only the five handles DOS pre-opens, which
    /// `Streams` structurally never touches (`FIRST_FD = 5` is the proof --
    /// `Streams` cannot assign any of `0..=4` even by accident), so there is
    /// no shared identity to diverge from in the first place. A module
    /// calling `read`/`write`/`setmode` on an `fd` `Streams` itself handed
    /// out (`5` or above, from a real `fopen`) is refused by name, not
    /// silently answered from a second, unsynchronised copy of `Streams`'s
    /// own state. Whoever gets `stream.rs` next can fold the two together by
    /// adding that accessor and widening this table; until then, keeping
    /// them apart is the choice that cannot drift, because there is nothing
    /// in this table for `Streams` to invalidate.
    pub(crate) stdio_modes: [bool; 5],

    /// The one live `tfsopn` text-file scan, if any. `TFSCAN.H`'s family is
    /// stateful -- `tfsopn` opens, `tfsrdl` walks, `tfspfx` tests the current
    /// line, `tfsabt` drops it -- and the original keeps that state in host
    /// globals (`tfstate`, `tfsbuf`, `tfspst`), one set for the whole host
    /// rather than one per channel. This is that state.
    pub(crate) tfscan: shims::tfscan::TfScan,

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
    pub(crate) fsdscb: Vec<Option<A::Ptr>>,

    /// Each channel's `fsdusr->{curmbk,tmpmsg,amode}` -- which message block
    /// `fsdroom` last read a template out of, which template, and in which
    /// mode. `FSDBBS.C:134`, and Rust-side rather than in module memory
    /// because `fsdusr` is ordinal 264 and `WCCMMUD.DLL` never imports it.
    /// Indexed by [`Chan::index`], for the same reason [`Host::fsdscb`] is.
    pub(crate) fsdtmp: Vec<Option<(A::Ptr, u16, i16)>>,

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
    pub(crate) fsd_sessions: Vec<Option<FsdSession<A>>>,

    /// Per-channel ANSI keystroke-decoder state, one byte apiece.
    ///
    /// The original hangs this off `struct fsdbbs` as `fsdusr->ainscb` and
    /// reaches it through a global pointer that `fsdchi` swaps in and back
    /// out around each call (`FSDBBS.C:344-355`). It is invisible to the
    /// module either way -- a half-finished `ESC [` is not something a form
    /// can ask about -- so it lives here rather than in [`Scb`](fsd::Scb).
    ///
    /// Sized for every channel and never `Option`: a decoder with no session
    /// in progress is just one sitting in `WT4ESC`, which is exactly what
    /// [`Ainscb::default`](fsd::ain::Ainscb::default) is. `fsdego` calls
    /// `ainbeg` on it for **both** modes (`FSDBBS.C:217-218`), which is the
    /// whole reason line mode is decoded too.
    pub(crate) fsd_ain: Vec<fsd::ain::Ainscb>,

    /// `getasc(tmpmsg)`'s output, materialised in module memory, keyed by the
    /// `(message block, message number)` it came from.
    ///
    /// `fsdrft` hands the module a `char *`, and the module passes it straight
    /// back in as `fsdbkg(fsdrft())` (`FSDBBS.C:87`). That pointer has to
    /// address the *same* string the form's field offsets were measured
    /// against -- the ASCII-expanded one (`FSDBBS.C:137`) -- so it cannot
    /// simply be the message text where it already sits. The genuine host has
    /// the same problem and solves it the same way: `getasc` writes into a
    /// buffer of the host's and returns a pointer to that.
    ///
    /// Cached rather than rebuilt because message text does not change once
    /// read, and because a fresh segment per `fsdrft` call would leak one per
    /// redisplay.
    pub(crate) fsd_ascii: std::collections::HashMap<(A::Ptr, u16), A::Ptr>,

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
    pub(crate) fsd_scratch: Option<A::Ptr>,

    /// The `static` return buffers `CNCUTL.C`'s pointer-returning routines
    /// hand back, in one region. `None` until the first of them is called.
    ///
    /// `cncuid`, `cncsig`, `cncwrd` and `cncnum` each `return` the address of
    /// a function-scope `static` array (`CNCUTL.C:80`, `:96`, `:136`,
    /// `:215`). That storage outlives the call and is overwritten by the next
    /// call to *the same* routine -- a module holding two `cncwrd()` results
    /// at once sees the second one twice. This host reproduces that rather
    /// than improving on it, because a module written against the original
    /// may copy the result before the next call precisely *because* it had
    /// to, and one that does not was already relying on the aliasing.
    ///
    /// One allocation, four disjoint sub-buffers -- see `shims::cnc`'s own
    /// `CNCUID_AT`/`CNCSIG_AT`/`CNCWRD_AT`/`CNCNUM_AT`. Disjoint because the
    /// vendor's four statics are four distinct objects: `cncuid` calling
    /// `cncsig` must not have its own answer overwritten by the answer it is
    /// about to return instead, and `cncwrd` must not clobber a `cncuid`
    /// result the caller still holds.
    ///
    /// Not per-channel, for the reason [`Host::fsd_scratch`] gives at
    /// length: only one channel's command line is ever being parsed at a
    /// time, this host being single-threaded by force, and the vendor's own
    /// storage is a plain `static` rather than anything per-channel either.
    pub(crate) cnc_statics: Option<A::Ptr>,

    /// The module's heap and its tiled regions.
    pub(crate) heap: Heap<A>,

    /// The per-channel tables: `user[]`, `extusr[]` and the account block.
    ///
    /// One slot each per channel, allocated at construction because the real
    /// host allocated them before any module's init ran -- `MAJORBBS.C:735-736`
    /// and `ACCOUNT.C:109`. See [`Users`].
    pub(crate) users: Users<A>,

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

    /// The survey inventory, if [`Host::enable_survey`] has attached one.
    /// `None` -- the default, and the only setting safe for a board anyone
    /// plays on -- means [`Host::run`] never fabricates a continuation past
    /// [`Entry::Unimplemented`] and always stops, exactly as it always has.
    ///
    /// A `Rc<RefCell<_>>` and not an owned [`survey::Inventory`], because
    /// this field does not own the survey's *lifetime* -- see
    /// `crates/mbbs-server/src/host.rs`'s "Surviving a module stop": a
    /// `Host` is rebuilt from scratch on every restart, so an inventory
    /// stored here alone would be destroyed with it. The shared handle lets
    /// something that outlives `Host` (the supervisor in `mbbs-server`) keep
    /// the same inventory across every life this process has.
    survey: Option<survey::Shared>,

    /// `shims::entry`'s answer for a thunk index, remembered.
    ///
    /// The dispatch loop below resolved every call from scratch: an
    /// `import_owner` lookup, a `String` clone of the library name, a second
    /// `String` built for the symbol (formatted, for an ordinal), then
    /// `shims::entry`. That is fine at a few thousand calls and ruinous at the
    /// real rate -- `MBBS_TRACE_SHIMS` over one 32-bit session counted
    /// **1,918,319** calls to `ptrblok` alone, 99.7% of all its shim traffic,
    /// because MajorMUD reaches every element of its big tables through it.
    ///
    /// Safe to remember because the answer cannot change: `shims::entry` is a
    /// pure function of `(dll, symbol)` and this crate's static tables, the
    /// dispatch path never consults `self.loaded` (only `Resolver` does, at
    /// load time), and thunk indices are machine-wide unique since `50944874`
    /// -- so one index means one import for the life of the machine.
    ///
    /// Only routine hits are cached. Every other `Entry` goes down the slow
    /// path, which is where survey recording and the refusal diagnostics live
    /// and which is not hot by construction: a `Datum` resolves at load time
    /// and never traps, and an `Unimplemented` stops the module.
    resolved: Vec<Option<(shims::Shim<A>, shims::Cleans)>>,
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
///
/// `A` carries no default, for the same reason [`DateBuffers`] carries
/// none. Not
/// `#[derive(Debug, Clone, Default)]`: same trap, same fix -- see
/// `DateBuffers`'s own doc comment. `Default` in particular would bound `A:
/// Default`, which `Wg16` does not implement and does not need to: every
/// field here defaults on its own (`bool` and `Option<A::Ptr>` both do,
/// regardless of what `A::Ptr` is).
pub(crate) struct FsdSession<A: Abi> {
    /// Whether `fsdego` started this session with `fsdent` rather than
    /// `fsdlin` -- the original's `fsdusr->flags & FBFULL` (`FSDBBS.C:207`,
    /// `:211`). `goback` reads it to decide whether to park the cursor below
    /// the form on the way out (`FSDBBS.C:227`).
    ///
    /// Written by `fsdego`, and read by `goback` (Task 12) to decide whether
    /// to emit the `FBFULL` cursor park. Recorded at `fsdego` time rather
    /// than reconstructed later from `amode`, because it is the original's
    /// own `fsdusr->flags` bookkeeping, set at the moment the fork is taken;
    /// reconstructing it later would be a second source of truth for one
    /// fact.
    pub(crate) full_screen: bool,

    /// The `whndun(save)` callback `fsdego` was handed, or `None` if the
    /// module passed `NULL` -- `goback()`'s own `else` branch
    /// (`FSDBBS.C:236`) is what a `None` here means to it.
    pub whndun: Option<A::Ptr>,

    /// Whether the session is exiting to save (`FSDSAV`) or to quit
    /// (`FSDQIT`). `fsdusr->flags & FBSAVE`, read by `goback()` after
    /// `xitfsd` decided.
    pub save: bool,
}

impl<A: Abi> Clone for FsdSession<A> {
    fn clone(&self) -> Self {
        Self {
            full_screen: self.full_screen,
            whndun: self.whndun,
            save: self.save,
        }
    }
}

impl<A: Abi> std::fmt::Debug for FsdSession<A>
where
    A::Ptr: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsdSession")
            .field("full_screen", &self.full_screen)
            .field("whndun", &self.whndun)
            .field("save", &self.save)
            .finish()
    }
}

impl<A: Abi> Default for FsdSession<A> {
    fn default() -> Self {
        Self {
            full_screen: false,
            whndun: None,
            save: false,
        }
    }
}

/// Every method here works purely off the fields `Host<A>` already owns --
/// field accessors, pointer arithmetic through [`Abi::ptr_offset`],
/// bookkeeping vectors and maps -- and never needs a `Machine`. See the
/// struct's own doc comment ("Split method surface, like `Users`") for
/// which methods that includes. The few that read or build
/// [`Registration`]/[`Agent`]/[`Kick`]
/// (`modules`/`first_module`/`register`/`register_native`/`agents`/`kicks`)
/// belong here on the same terms as the rest: those three types carry their
/// own `A` (`Registration<A: Abi>` and siblings), so the pointers they
/// hold are `A::Ptr`, not `FarPtr`.
///
/// This comment used to claim they were "concrete `FarPtr`-typed structs that
/// are not themselves generic over `A`" and that their presence "does not by
/// itself make the module dispatch table serve a second ABI". Both halves
/// were true when written and neither survived the conversion that
/// parameterised them. See the struct's own doc comment for why the
/// `= Wg16` default each carried made that easy to miss, and why, since
/// Task 3 of `docs/plans/2026-08-12-abi-border-implementation.md` removed
/// it, a bare `Registration`/`Agent`/`Kick` no longer compiles at all.
impl<A: Abi> Host<A> {
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
    /// # Generic since Task 13
    ///
    /// `docs/plans/2026-08-12-abi-border-implementation.md`'s Task 13. What
    /// used to be a single `.selector` field access
    /// (`machine.mem_mut().alloc_region(..)?.selector`) feeding four
    /// `FarPtr { offset, selector }` literals and one `FarPtr::NULL` is now
    /// one `A::mem(machine).alloc_region(..)?` call, whose result -- `base`,
    /// an `A::Ptr` -- every offset is built from through [`Abi::ptr_offset`].
    /// Under `Wg32` there is no selector to project at all: the base pointer
    /// *is* the address, and `A::null_ptr()` answers `strtok`'s starting
    /// value the way `FarPtr::NULL` used to.
    ///
    /// # Errors
    ///
    /// If the globals or the host's buffers cannot be mapped.
    pub fn new(machine: &mut A::Cpu, root: impl Into<PathBuf>, terms: Terms) -> io::Result<Self> {
        // Every table this host keys by channel is sized from this one binding:
        // the `nterms` global the module reads, `Users`' four tables, and
        // `Gsbl`'s channels. It is deliberately one parameter and not three
        // reads of `globals::NTERMS` -- see `crate::chan` for what the three
        // separate reads cost, and for the measurement that showed one of the
        // two directions of disagreement was completely silent.
        let globals = Globals::<A>::new(machine, terms)?;
        let prf_end = OUTBSZ;

        // One segment for everything the host hands a module a pointer into and
        // then keeps: `spr`'s four buffers, `gmdnam`'s line, one NUL byte for
        // `parsin`'s empty-line `margv[0]`, `l2as`'s own small rotation (see
        // `Host::l2as`'s doc comment for why that is a separate pool rather
        // than more of `spr`'s), and `scnmdf`'s line. Separate from the
        // globals so that a module overrunning one of these cannot reach
        // `usrnum`.
        let spr_bytes = shims::text::SPR_BYTES as usize * shims::text::SPR_BUFFERS;
        let l2as_bytes = shims::text::L2AS_BYTES as usize * shims::text::L2AS_BUFFERS;
        // `scnmdf` is appended **after** `l2as` rather than inserted anywhere
        // earlier, so that every offset already established here is unchanged
        // by its arrival -- the four-buffer layout invariant below keeps
        // holding for the four it was written about.
        let scnmdf_bytes = usize::from(shims::msg::SCNMDF_BYTES);
        // `ModuleMem::alloc_region` through `Abi::mem` -- every `A::ptr_offset`
        // below is this same `base` at a chosen offset within it.
        let base =
            A::mem(machine).alloc_region(spr_bytes + 64 + 1 + l2as_bytes + scnmdf_bytes)?;

        // The per-channel tables come off the module heap, because the real
        // host's did: `MAJORBBS.C:735-736` builds them with `alczer` and
        // `ACCOUNT.C:109` with `alcblok`, both of which are the same heap a
        // module allocates from. So the heap has to exist before they do.
        let mut heap = Heap::<A>::new(Config::default());
        let users = users::Users::new(A::mem(machine), &mut heap, terms)?;

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
        // `terms`, because what the module bounds its own loops by is the word
        // in the segment, not the value this function meant to write there.
        let gsbl = gsbl::Gsbl::new(terms);
        let nterms = globals
            .word_mem(A::mem_ref(machine), "nterms")
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
        globals.write_mem(A::mem(machine), "user", &A::ptr_to_bytes(users.head()))?;
        globals.write_mem(A::mem(machine), "channel", &A::ptr_to_bytes(users.channels()))?;

        // R17: written explicitly rather than left to `alloc_segment`'s
        // `mmap(MAP_ANONYMOUS)` zero-fill. `DateBuffers`'s own empty byte gets
        // the identical write at `shims/system.rs:110` -- two facilities for
        // one NUL because they cannot be the same one: this one must exist
        // before the module's first instruction, and that one is allocated
        // lazily off the heap the first time a date routine runs.
        let empty = A::ptr_offset(base, spr_bytes as u16 + 64);
        empty
            .write(A::mem(machine), &[0])
            .map_err(|e| io::Error::other(e.to_string()))?;

        // `_streams` is where every `FILE` this host opens will live, so
        // `Streams` has to be told the address before anything can open one.
        // See `Streams::place` and `Streams::slot` for the slot-is-the-
        // descriptor invariant that depends on it.
        let mut streams_placed = stream::Streams::<A>::default();
        streams_placed.place(globals.address("_streams").ok_or_else(|| {
            io::Error::other("_streams is not placed, so no FILE has anywhere to live")
        })?);

        let mut host = Self {
            // The anchor, not a hardcoded answer: before any module has been
            // loaded there is no demand to detect against, and this is
            // exactly what `detect` on an empty `Demand` would report --
            // every profile agrees vacuously, so the anchor is chosen. The
            // first `Host::load` call replaces this with a real, evidenced
            // answer.
            exports: Exports::for_profile(
                mbbs_machine::library::profile(mbbs_machine::library::ANCHOR)
                    .expect("the anchor names a real profile"),
            ),
            demand: mbbs_machine::library::Demand::new(),
            indistinguishable: Vec::new(),
            profile: mbbs_machine::library::profile(mbbs_machine::library::ANCHOR)
                .expect("the anchor names a real profile"),
            globals,
            root: root.into(),
            extension: None,
            spr: A::ptr_offset(base, 0),
            spr_next: 0,
            l2as: A::ptr_offset(base, spr_bytes as u16 + 64 + 1),
            l2as_next: 0,
            scnmdf: A::ptr_offset(base, spr_bytes as u16 + 64 + 1 + l2as_bytes as u16),
            display: Display::default(),
            // Zero here, then set from `clock` immediately after the struct
            // is built -- `Clock::system()` is constructed inline in this
            // same literal, so there is no `clock` binding to read yet.
            started: 0,
            msgbuf_size: 0,
            setcnf: Vec::new(),
            setcnf_applied: false,
            strtok: A::null_ptr(),
            datebuf: None,
            mdf: A::ptr_offset(base, spr_bytes as u16),
            empty,
            prf_end,
            random: Random::default(),
            finds: std::collections::HashMap::new(),
            clock: Clock::system()?,
            audit: Vec::new(),
            // Slot zero is the BBS's own menuing system, which this host does
            // not have -- see `Registration::AbsentBbs`. Reserving it is what
            // makes every other index match a real host's, where
            // `inimod()` registers `module00` before any DLL registers itself.
            modules: vec![Registration::AbsentBbs],
            ended: Vec::new(),
            loaded_modules: HashMap::new(),
            agents: Vec::new(),
            textvars: TextVars::default(),
            messages: msg::Messages::default(),
            btrieve: btrieve::Btrieve::default(),
            gsbl,
            streams: streams_placed,
            installed: Vec::new(),
            notes: Vec::new(),
            noted: HashSet::new(),
            kicks: Vec::new(),
            rtirs: Vec::new(),
            tasks: Vec::new(),
            stdio_modes: [false; 5],
            tfscan: shims::tfscan::TfScan::default(),
            polls_left: 0,
            census: PollCensus::default(),
            forms: HashMap::new(),
            fsdscb: vec![None; usize::from(terms.count())],
            fsdtmp: vec![None; usize::from(terms.count())],
            fsd_state: None,
            fsd_sessions: vec![None; usize::from(terms.count())],
            fsd_ain: vec![fsd::ain::Ainscb::default(); usize::from(terms.count())],
            fsd_ascii: std::collections::HashMap::new(),
            fsd_scratch: None,
            cnc_statics: None,
            heap,
            users,
            asked: Vec::new(),
            inpolr: None,
            tcklst: None,
            calls: 0,
            clock_reads: 0,
            trace: std::env::var_os("MBBS_TRACE").is_some(),
            inited: false,
            survey: None,
            resolved: Vec::new(),
        };

        // `clock()` counts from here. Set after construction because
        // `Clock::system()` is built inline in the literal above, so there is
        // no binding to read while it is being written.
        host.started = host.clock.epoch().unwrap_or(0);
        Ok(host)
    }

    /// Open the host's own generic data file and publish `genbb`.
    ///
    /// `MAJORBBS.C:999` -- `genbb=dfaOpen("wgsgen2.dat",GENSIZ,NULL)`, run once
    /// as the real `WGSERVER.EXE` starts, long before any module is asked to
    /// initialise. `MAJORBBS.H:548` exports the resulting `DFAFILE *` to every
    /// module (`EXPWGSV(DFAFILE*) genbb`), and modules use it *without ever
    /// assigning it* -- Galacticomm's own `GALNOTE.C:242`, `GALFIL.C:1161` and
    /// the host's `BBSGEN.C:30` all just `dfaSetBlk(genbb)` and trust the host.
    ///
    /// # Why this is not optional
    ///
    /// Leaving it null is not a quiet gap. `WCCMMUD.DLL` (the 32-bit build)
    /// reads the imported pointer and hands its *value* straight to
    /// `dfaSetBlk`, disassembled at VA `0x40b0e3`:
    ///
    /// ```text
    /// mov  eax, ds:0x49d560      ; the IAT slot for the host's `genbb`
    /// push dword ptr [eax]       ; *genbb -- null, on a host that never set it
    /// call dfaSetBlk
    /// ...  dfaAcqLock -> today -> dfaInsertV
    /// ```
    ///
    /// and `DFAAPI.C` gives `dfaInsertV` no `dfa == NULL` guard at all, so the
    /// module's own init dies there. That block is MajorMUD's demo clock, the
    /// same one `tests/wccmmud.rs`'s call-127 commentary works through for the
    /// 16-bit build. There it is invisible -- `setbtv(NULL)` is guarded and
    /// merely does nothing, so the module grants itself a fresh 14-day demo
    /// every boot -- and here the identical host omission stops the board.
    ///
    /// # The file, and where it comes from
    ///
    /// `WGSGEN2.DAT` is the *host's* file, not a module's, so no module
    /// distribution ships it and [`Host::btrieve_file`]'s usual `.VIR` install
    /// has nothing to install from. This crate therefore carries its own virgin
    /// copy (`data/WGSGEN2.VIR`) and lays it down when a board has neither.
    ///
    /// Those bytes were not invented here. They were built by genuine Pervasive
    /// Btrieve 6.15 (`B_CREATE` through `tools/btrieve-oracle`, under Wine) from
    /// Galacticomm's own create description
    /// `re/wg33src/SRC/server/wgserver/WGSGEN2.BCR` -- `record=55 variable=y
    /// key=2 page=4096`, two keys over three segments, every segment a
    /// duplicate-permitting `zstring` collating through the `galcaps.alt`
    /// alternate sequence -- and the engine's own `B_STAT` confirmed the result
    /// before it was committed. Nothing here builds it, because
    /// [`crate::btrieve::create`] refuses all three of variable-length records,
    /// alternate collating sequences and a second duplicate-permitting key for
    /// want of a measured create-time layout; borrowing the vendor engine's
    /// answer is what those refusals are for.
    ///
    /// `GENSIZ` is `MAJORBBS.H:65`'s 8192, and it is the `maxlen` a caller
    /// opens *with* -- the biggest record it intends to handle -- not the
    /// file's own 55-byte `reclen`. Conflating the two is what produced the
    /// earlier `reclen 8192` files under `target/`, which are wrong.
    ///
    /// # Why a board calls this and [`Host::new`] does not
    ///
    /// This lays a file down in [`Host::root`], and that directory is one the
    /// *module* reads: `cntdir`, `fndnxt` and `tfsopn` all enumerate it, and a
    /// module counting `*.*` counts whatever the host left there. Doing it from
    /// the constructor therefore changes what every `Host` in the crate can see
    /// of its own root, which is not a constructor's business -- it was tried,
    /// and ten tests went red, every one of them a directory count rather than
    /// anything to do with `genbb`.
    ///
    /// So it is the board's own startup step, called once from
    /// `mbbs-server`'s `host.rs`, exactly where the real `WGSERVER.EXE` runs
    /// `MAJORBBS.C:999`. A `Host` built for a test has no generic data file and
    /// a null `genbb`, which is what it had before this existed.
    ///
    /// # Failure is noted, never fatal
    ///
    /// A board whose root cannot be written, or whose `WGSGEN2.DAT` this host
    /// cannot parse, leaves `genbb` null and records why with [`Host::note`],
    /// so the null is attributable rather than silent. It is not an error
    /// return, because a board that cannot keep a demo clock is still a board
    /// that can run -- what it must not be is a board that cannot say so.
    pub fn open_genbb(&mut self, machine: &mut A::Cpu) {
        /// `MAJORBBS.H:65` -- `#define GENSIZ 8192`, "max size of a generic
        /// user dbase rec".
        const GENSIZ: u16 = 8192;
        const NAME: &str = "WGSGEN2.DAT";
        static TEMPLATE: &[u8] = include_bytes!("../data/WGSGEN2.VIR");

        // Written as the `.DAT` itself rather than as a `.VIR` for
        // [`Host::btrieve_file`] to install: that convention belongs to the
        // fifteen files a *module* distribution ships virgin, and a real
        // Worldgroup install has no `WGSGEN2.VIR` at all. One file, under the
        // name the host actually opens.
        if self.find(NAME).is_none() {
            let to = self.root.join(NAME);
            if let Err(e) =
                std::fs::create_dir_all(&self.root).and_then(|()| std::fs::write(&to, TEMPLATE))
            {
                self.note(format!(
                    "genbb stays null: {} could not be written ({e}), so the host has no \
                     generic data file and any module that does dfaSetBlk(genbb) will be \
                     handed a null one",
                    to.display()
                ));
                return;
            }
        }

        let Some(path) = self.find(NAME) else {
            self.note(format!("genbb stays null: no {NAME} under {}", self.root.display()));
            return;
        };
        let geometry = match btrieve::Geometry::read(NAME, &path) {
            Ok(geometry) => geometry,
            Err(e) => {
                self.note(format!("genbb stays null: {NAME} is not readable: {e}"));
                return;
            }
        };

        let opened = {
            let Host { btrieve, heap, .. } = self;
            btrieve.open(A::mem(machine), heap, NAME, &path, geometry, GENSIZ)
        };
        let block = match opened {
            Ok(block) => block,
            Err(why) => {
                self.note(format!("genbb stays null: {NAME} would not open: {why}"));
                return;
            }
        };

        if let Err(e) = self.globals.write_mem(A::mem(machine), "genbb", &A::ptr_to_bytes(block)) {
            self.note(format!("genbb was opened but could not be published: {e}"));
        }
    }

    /// The file a module named, with the directory it is allowed to name
    /// stripped off.
    ///
    /// A module builds its filenames from `DATADIR`, an option in its `.MSG`.
    /// MajorMUD's is empty, so what `spr` produces is `.\WCCITEMS.DAT` -- the
    /// module's own directory, which is [`Host::root`] and is where this host
    /// looks anyway. That prefix is accepted and removed.
    ///
    /// **The rule is containment, not "no directories."** It used to be the
    /// latter: any `\`, `/` or `:` in the name at all was refused outright.
    /// That was too strict for the world it models. LunatiX 5.3F's own
    /// installer config (`INSTALL.CFG`, in its distribution ZIP) does
    ///
    /// ```text
    /// MAKEDIR LUN5DATA
    /// COPY LUNJOKES.TXT LUN5DATA
    /// UPDATE LUNRAND1.TXT LUN5DATA
    /// ```
    ///
    /// and the module then opens what it just installed with
    /// `fopen("lun5data\lunrand1.txt", ...)`. A module that ships and uses a
    /// subdirectory of its own install is not naming somewhere else -- it is
    /// naming a real part of what [`Host::root`] holds, and refusing it
    /// outright meant LunatiX's own init could never finish. So a relative
    /// path with subdirectory components -- `lun5data\lunrand1.txt`,
    /// `.\lun5data\lunrand1.txt`, either separator -- is now accepted and
    /// normalised to `/`; [`Host::find`] resolves it case-insensitively at
    /// every level, the same way it always has for a bare name.
    ///
    /// **What is still refused is anything that names, or could reach,
    /// somewhere outside [`Host::root`]** -- because that half of the old
    /// rule was never about directories as such, it was about this: a
    /// module configured with `DATADIR` of `D:\MUD\DATA` means it, and
    /// quietly reading the file of the same name from somewhere else would
    /// be the exact failure this crate exists to avoid, with the added
    /// charm that a board with two installs would silently play the wrong
    /// one. That reasoning does not weaken just because subdirectories are
    /// now allowed -- it is the part of the old rule that was always load-
    /// bearing, and it is kept in full:
    ///
    /// - a drive letter, or any `:` at all (`D:\MUD\DATA\X.DAT` and every
    ///   other reading of `:` DOS ever had);
    /// - any `..` component, checked after separators are normalised, so a
    ///   name cannot walk back out through subdirectories it was just
    ///   allowed into (`lun5data\..\..\etc\passwd` is refused for the same
    ///   reason `D:\` is, not a weaker one).
    ///
    /// # A leading separator means *this board's* own root
    ///
    /// `\rci_univ.dat` and `/rci_univ.dat` resolve to `rci_univ.dat` under
    /// [`Host::root`]. **This reverses an earlier rule** which refused a
    /// leading separator outright, on the grounds that "root of *what* is a
    /// question this host has no business answering".
    ///
    /// The Rose 3.0NT answered it. Its init calls `access("\rci_univ.dat")`,
    /// and `RCI_UNIV.DAT` is a file the module ships in its own directory.
    /// Under DOS a leading `\` is the root of the current drive, and a period
    /// BBS install *was* the root of its drive — which is precisely what
    /// `Host::root` models. So this host does have a defensible answer, and
    /// refusing protected nothing: it stopped a module from opening a file it
    /// had installed itself.
    ///
    /// **The escape guarantee is unchanged**, because it never rested on this
    /// rule. `..` is still checked component-wise after normalisation, so
    /// `\..\etc\passwd` and `\lun5data\..\..\etc\passwd` are refused exactly
    /// as they were — starting at root is not a way *through* root. That is
    /// pinned by `dos_name_root_absolute_still_cannot_escape`.
    ///
    /// # No `Machine`, and no `self`, and generic anyway
    ///
    /// This is pure string logic with nothing ABI-dependent in it -- the last
    /// method `impl Host<Wg16>` held, moved here in Task 14 of
    /// `docs/plans/2026-08-12-abi-border-implementation.md`, which is what let
    /// that block be deleted outright. Every call site that used to read
    /// `Host::dos_name(...)` and infer `Wg16` because it was the only impl now
    /// spells `Host::<Wg16>::dos_name(...)` (or `Host::<A>::dos_name(...)`
    /// inside a generic shim, e.g. `shims::btrieve::opnbtv`) -- `rustc` cannot
    /// infer which `Abi` a bare `impl<A: Abi> Host<A>` copy means from a
    /// signature that mentions neither `Self` nor `A`.
    ///
    /// **Returns an owned `String`, not `&str`.** Normalising `\` to `/`
    /// means the answer is not always a substring of `named` any more --
    /// `.\lun5data\lunrand1.txt` has no `lun5data/lunrand1.txt` inside it to
    /// borrow.
    ///
    /// # Errors
    ///
    /// If the name has a drive letter or a `..` component anywhere in it.
    /// **Not** for a leading separator — that is mapped onto [`Host::root`],
    /// see above.
    pub fn dos_name(named: &str) -> Result<String, String> {
        let bare = named
            .strip_prefix(".\\")
            .or_else(|| named.strip_prefix("./"))
            .unwrap_or(named);

        let escapes = || {
            format!(
                "{named} names a directory outside this host's own; this host only opens a module's own"
            )
        };

        // A colon is a drive letter under every DOS reading this crate has
        // found (`D:`, but also the bare `:` a well-formed name never has),
        // so any of it at all is refused before separators are even looked
        // at.
        if bare.contains(':') {
            return Err(escapes());
        }
        // Root-absolute in either spelling is **mapped onto [`Host::root`]**,
        // not refused. See this method's own doc comment, "A leading
        // separator means this board's own root", for why the older refusal
        // was wrong. No strip is needed: the component loop below drops empty
        // parts, so a leading separator falls out on its own -- and, more
        // importantly, the `..` check still runs over every remaining
        // component, so starting at root is not a way through it.

        let mut parts = Vec::new();
        for part in bare.split(['\\', '/']) {
            // Both separators collapse together and repeats vanish, so
            // `a\\b` and `a/b` and `a\/b` all normalise the same way.
            if part.is_empty() {
                continue;
            }
            // Checked component-wise, after normalisation, so a name cannot
            // spell its way back out through a subdirectory it was just let
            // into -- `lun5data\..\..\etc\passwd` is exactly as refused as
            // `D:\etc\passwd` is, not merely inconvenienced.
            if part == ".." {
                return Err(escapes());
            }
            parts.push(part);
        }

        Ok(parts.join("/"))
    }

    /// Turn on survey mode: [`Host::run`] will fabricate a continuation past
    /// every `Entry::Unimplemented` call site it reaches from now on,
    /// recording each one into `inventory` instead of stopping the module.
    ///
    /// # Read `crate::survey`'s module doc before calling this
    ///
    /// **This produces wrong behaviour, on purpose, for enumeration only.**
    /// A fabricated return is a lie the module cannot tell from a real
    /// answer -- it is not "the call did nothing", it is "the call
    /// succeeded and returned zero/null", and the module acts on that lie
    /// for as long as it runs afterwards. Never call this outside a
    /// throwaway diagnostic session; never call it on a board anyone is
    /// actually playing on.
    ///
    /// `inventory` is a shared handle rather than a value this method takes
    /// ownership of, because `Host` does not live long enough to be trusted
    /// with the only copy -- see this struct's own `survey` field.
    pub fn enable_survey(&mut self, inventory: survey::Shared) {
        self.survey = Some(inventory);
    }

    /// The host's globals.
    pub fn globals(&self) -> &Globals<A> {
        &self.globals
    }

    /// Every line `shocst` has produced, oldest first.
    pub fn audit(&self) -> &[String] {
        &self.audit
    }

    pub fn modules(&self) -> &[Registration<A>] {
        &self.modules
    }

    /// The first *module* registration, skipping any [`Registration::Native`]
    /// ahead of it in the table -- [`Host::connect`]'s `lonrou` lookup and
    /// [`Host::disconnect`]'s `huprou` lookup both want "the one real module"
    /// and neither wants to mistake the FSD's native slot for it.
    /// The index of the first real module -- what a freshly connected
    /// channel's `state` is set to, since this host has no menuing system to
    /// arrive at first. See [`Host::connect_state`].
    fn first_module_index(&self) -> Option<u16> {
        self.modules
            .iter()
            .position(|r| matches!(r, Registration::Module { .. }))
            .map(|i| i as u16)
    }

    fn first_module(&self) -> Option<&Registration<A>> {
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
    /// When this host started, in epoch seconds. See [`Host::started`].
    pub fn started(&self) -> u32 {
        self.started
    }

    /// The largest message buffer `inimsg` has been asked for. See
    /// [`Host::msgbuf_size`].
    pub fn msgbuf_size(&self) -> u16 {
        self.msgbuf_size
    }

    /// `inimsg`'s monotonic grow: `if (mxmssz < maxsiz)` (`MCVAPI.C:42`).
    pub fn grow_msgbuf(&mut self, maxsiz: u16) {
        self.msgbuf_size = self.msgbuf_size.max(maxsiz);
    }

    /// The name/value pairs `setcnf` has recorded. See [`Host::setcnf`].
    pub fn setcnf_changes(&self) -> &[(Vec<u8>, Vec<u8>)] {
        &self.setcnf
    }

    /// Record one `setcnf` pair, answering `false` if the vendor's `MAXCHG`
    /// bound is already reached.
    ///
    /// `SETCNF.C:63-75`: a `setcnf` after an `applyem` clears the list first,
    /// which is what `applied` tracks.
    pub fn record_setcnf(&mut self, name: Vec<u8>, value: Vec<u8>, max: usize) -> bool {
        if self.setcnf_applied {
            self.setcnf_applied = false;
            self.setcnf.clear();
        }
        if self.setcnf.len() >= max {
            return false;
        }
        self.setcnf.push((name, value));
        true
    }

    /// The console's attribute and window state. See [`Host::display`].
    pub fn display(&self) -> Display {
        self.display
    }

    /// The console's attribute and window state, to change.
    pub fn display_mut(&mut self) -> &mut Display {
        &mut self.display
    }

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
    pub fn agents(&self) -> &[Agent<A>] {
        &self.agents
    }

    /// The text variables that have been registered.
    ///
    /// Unlike [`Host::agents`] and [`Host::kicks`] this is **not** only a
    /// record: the table is real module memory and the `txtvars` global points
    /// at it, so the module can walk it whether or not this host ever
    /// substitutes anything. What is still owed is `findtvar` and the
    /// substitution itself.
    pub fn textvars(&self) -> &TextVars<A> {
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
    pub fn kicks(&self) -> &[Kick<A>] {
        &self.kicks
    }

    /// Every 18 Hz handler a module installed with `rtihdlr`, in install
    /// order. See [`Host::rtirs`] for why none of them runs.
    pub fn rtihdlrs(&self) -> &[A::Ptr] {
        &self.rtirs
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
    pub fn messages(&self) -> &msg::Messages<A> {
        &self.messages
    }

    /// The Btrieve files that are open.
    pub fn btrieve(&self) -> &btrieve::Btrieve<btrieve::AbiMem<A>> {
        &self.btrieve
    }

    /// The streams that are open.
    pub fn streams(&self) -> &stream::Streams<A> {
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

    /// Take every note recorded so far, leaving none behind.
    ///
    /// [`Self::notes`] alone makes this list write-only in practice: nothing
    /// ever removes an entry, so a long-lived host accumulates one string per
    /// note for as long as it runs. That is not hypothetical -- one session
    /// driving a character into the Realm recorded 4,962 notes, all but a
    /// handful of them the same `setbtv` stack overflow, and a caller reading
    /// `notes()` has no way to tell which of them it has already seen.
    ///
    /// So a caller that wants to *report* notes drains them, and a caller that
    /// wants to *assert* on them (every test in this crate) borrows them. The
    /// two cannot be the same method: draining in `notes()` would need `&mut
    /// self` and would make two consecutive reads disagree.
    ///
    /// [`Self::note_once`]'s `noted` set is deliberately **not** cleared here.
    /// Its promise is "once per host", not "once per drain" -- resetting it
    /// would turn every drain into a fresh licence to repeat, which is the
    /// flood it exists to prevent.
    /// Note every connected channel whose `state` now names the absent BBS.
    ///
    /// The dispatch path cannot see this on its own. A module that hands a
    /// user back stops raising statuses for that channel in the same breath,
    /// so `poll_with_chan` never looks at it again and `state_entry` is never
    /// reached -- the channel simply goes quiet forever. Reading `state`
    /// directly is what notices.
    ///
    /// A channel that has never connected also reads zero, because its slot
    /// is zeroed memory. That is why this only records, and why the driver
    /// closes only channels it actually holds a connection for: a never-used
    /// channel has nothing to close and is skipped there. A channel that
    /// *has* connected was put into the first real module by
    /// [`Host::connect_state`], so zero on one of those means the module put
    /// it back.
    pub fn sweep_ended(&mut self, machine: &mut A::Cpu) {
        let chans: Vec<Chan> = self.users().terms().all().collect();
        for chan in chans {
            if matches!(self.users().state_mem(A::mem(machine), chan), Ok(0))
                && !self.ended.contains(&chan)
            {
                self.ended.push(chan);
            }
        }
    }

    /// Channels whose module handed them back to the absent BBS since the
    /// last call, and which the driver should now close.
    ///
    /// The same shape [`Host::drain_notes`] uses, and for the same reason:
    /// this host does not own the sockets. It can observe that a session is
    /// over -- a module wrote `state = 0`, naming the menuing system that
    /// `Registration::AbsentBbs` stands in for -- but only whatever is
    /// driving it can hang the connection up.
    pub fn drain_ended(&mut self) -> Vec<Chan> {
        std::mem::take(&mut self.ended)
    }

    pub fn drain_notes(&mut self) -> Vec<String> {
        std::mem::take(&mut self.notes)
    }

    /// Everything the module has announced through `shocst` since the last
    /// call, and clear it.
    ///
    /// **`shocst` is the module's console, not a log this host keeps for
    /// itself.** `SHOCST.C`'s whole job is putting a line in front of the
    /// operator; a host that collects them and never prints them has taken
    /// the module's one channel for talking to a human and pointed it at a
    /// wall. [`Host::audit`] existed, with no caller anywhere in the
    /// workspace, for exactly as long as that was true.
    ///
    /// What it cost: MajorMUD announces "Recovery mode has now completed."
    /// this way, and the board it was running on could not have said whether
    /// recovery ever finished. The one recovery message anyone did see
    /// ("Some monsters may not regenerate") was visible only because
    /// `_DISPLAY_RECOVERY_MODE_STATUS` also prints it to a player entering
    /// the Realm.
    ///
    /// Drained rather than read, matching [`Host::drain_notes`]: a driver
    /// that prints on a schedule wants what is new, and anything else grows
    /// without bound for the life of the process.
    pub fn drain_audit(&mut self) -> Vec<String> {
        std::mem::take(&mut self.audit)
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
    pub fn heap(&self) -> &Heap<A> {
        &self.heap
    }

    /// The per-channel tables. See [`Users`].
    pub fn users(&self) -> &Users<A> {
        &self.users
    }

    /// The per-channel tables, mutably. See [`Users`].
    pub fn users_mut(&mut self) -> &mut Users<A> {
        &mut self.users
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

    /// How many host calls this host has serviced.
    pub fn calls(&self) -> u64 {
        self.calls
    }

    /// Install behaviour above this host. Replaces any previous extension.
    pub fn set_extension(&mut self, ext: Box<dyn extension::Extension<A>>) {
        self.extension = Some(ext);
    }

    /// Whether an extension is installed.
    pub fn extension(&self) -> Option<&dyn extension::Extension<A>> {
        self.extension.as_deref()
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
    ///
    /// **Every component, not just the last.** [`Host::dos_name`] now accepts
    /// a subdirectory, and a 1997 DOS distribution stores its names in upper
    /// case (`LUN5DATA/LUNRAND1.TXT`) while the module that reads them was
    /// compiled to ask in lower case (`fopen("lun5data\lunrand1.txt", ...)`).
    /// Matching only the final segment case-insensitively would still miss
    /// `LUN5DATA` itself, so this walks `name` one path component at a time,
    /// `read_dir`-ing and matching case-insensitively at each step, rather
    /// than case-folding only the leaf.
    pub fn find(&self, name: &str) -> Option<PathBuf> {
        let exact = self.root.join(name);
        if exact.is_file() {
            return Some(exact);
        }

        let mut at = self.root.clone();
        for part in name.split(['\\', '/']).filter(|p| !p.is_empty()) {
            at = std::fs::read_dir(&at)
                .ok()?
                .filter_map(Result::ok)
                .find(|e| e.file_name().to_string_lossy().eq_ignore_ascii_case(part))
                .map(|e| e.path())?;
        }
        Some(at)
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
        //
        // No `create_dir_all` for `to`'s parent, unlike `shims::stream::fopen`:
        // `name` may hold a subdirectory now that [`Host::dos_name`] accepts
        // one, but `from` was just resolved through it by [`Host::find`], so
        // that directory already exists -- a `.VIR` cannot have been found
        // inside a directory that is not there.
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
    ///
    /// Built through [`Abi::ptr_offset`] rather than a hand-built `FarPtr` --
    /// `self.spr` is `A::Ptr`, opaque outside the `Abi` trait, so this is what
    /// makes the rotation itself real for any ABI rather than only `Wg16`.
    fn next_spr_buffer(&mut self) -> A::Ptr {
        let at = A::ptr_offset(self.spr, (self.spr_next as u16) * shims::text::SPR_BYTES);
        self.spr_next = (self.spr_next + 1) % shims::text::SPR_BUFFERS;
        at
    }

    /// The next of `l2as`'s rotating buffers. See [`Host::l2as`] for why this
    /// is not [`Host::next_spr_buffer`].
    fn next_l2as_buffer(&mut self) -> A::Ptr {
        let at = A::ptr_offset(self.l2as, (self.l2as_next as u16) * shims::text::L2AS_BYTES);
        self.l2as_next = (self.l2as_next + 1) % shims::text::L2AS_BUFFERS;
        at
    }

    /// The line buffer `gmdnam` writes into.
    fn mdf_buffer(&self) -> A::Ptr {
        self.mdf
    }

    /// The line buffer `scnmdf` answers out of. See [`Host::scnmdf`].
    pub(crate) fn scnmdf_buffer(&self) -> A::Ptr {
        self.scnmdf
    }

    /// One NUL byte the host owns and keeps. See [`Host::empty`].
    fn empty_string(&self) -> A::Ptr {
        self.empty
    }

    /// One past the last byte `prf` may write.
    fn prf_end(&self) -> u16 {
        self.prf_end
    }

    /// Take a module online, and give it its number.
    fn register(&mut self, description: String, block: A::Ptr) -> u16 {
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

    /// The channel [`Host::point_curusr`] last made current, read back the
    /// way the module itself would: out of the `usrnum` global -- against
    /// memory directly rather than a whole `Machine`.
    ///
    /// Every FSD shim needs to know which channel it is serving, and none of
    /// them are handed a [`Chan`] argument -- the module's own call
    /// signatures have no room for one (`fsdroom(msgno, fldspc, amode)`, four
    /// words, matches `FSDBBS.H:60-67` and `GALP&Q.C:1273`). This is how they
    /// ask.
    ///
    /// No `Wg16` facade: the last `&Machine`-taking caller (`fsdego`) went
    /// generic in the ABI abstraction's fifth task, so every remaining
    /// caller already holds `&A::Mem` rather than a whole `Machine`.
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
    pub(crate) fn current_channel_mem(&self, mem: &A::Mem) -> Result<Chan, ShimError> {
        let uno = self
            .globals()
            .word_mem(mem, "usrnum")
            .map_err(|e| ShimError::Failed(format!("current_channel: {e}")))?;
        self.users.terms().chan(uno as i16).ok_or_else(|| {
            ShimError::Failed(format!(
                "current_channel: usrnum is {}, which names no channel",
                uno as i16
            ))
        })
    }

    /// `user[unum].usrcls` -- what kind of channel this is, against memory
    /// directly rather than a whole `Machine`.
    ///
    /// The generic core [`Host::class`]'s `Wg16` facade delegates into -- see
    /// [`Globals`]'s own doc comment ("Generic core, `Wg16`-facade names")
    /// for why the split exists and why the two need different names.
    ///
    /// # Errors
    ///
    /// If the read runs off a segment.
    pub(crate) fn class_mem(&self, mem: &A::Mem, unum: Chan) -> Result<u16, ShimError> {
        self.users().usrcls_mem(mem, unum)
    }

    /// Point the four globals that name "the current channel" -- `usrnum`,
    /// `usrptr`, `usaptr` and `vdaptr` -- at `uno`, against memory directly
    /// rather than a whole `Machine`.
    ///
    /// The generic core [`Host::point_curusr`]'s `Wg16` facade delegates
    /// into -- same split, same reason.
    ///
    /// Null is written as `PTR_WIDTH` zero bytes rather than through an
    /// ABI-specific `NULL` constant, the same way
    /// [`Users::set_polrou_mem`](crate::users::Users::set_polrou_mem) writes
    /// a cleared polling routine.
    ///
    /// # Errors
    ///
    /// If a write runs off a segment.
    pub(crate) fn point_curusr_mem(&mut self, mem: &mut A::Mem, uno: Chan) -> Result<(), ShimError> {
        let slot = self.users().slot(uno);
        let account = self.users().account(uno);
        let vda = self.users().vda(uno);

        self.globals()
            // `usrnum` is an `int`, so the whole of it is rewritten -- see
            // `Globals::write_int_mem`. A two-byte write on top of the
            // all-ones seed would have left `0xFFFF0000` under `Wg32`.
            .write_int_mem(mem, "usrnum", uno.number() as i32 as u32)
            .map_err(|e| ShimError::Failed(format!("point_curusr: {e}")))?;
        self.globals()
            .write_mem(mem, "usrptr", &A::ptr_to_bytes(slot))
            .map_err(|e| ShimError::Failed(format!("point_curusr: {e}")))?;
        self.globals()
            .write_mem(mem, "usaptr", &A::ptr_to_bytes(account))
            .map_err(|e| ShimError::Failed(format!("point_curusr: {e}")))?;
        let vda_bytes = match vda {
            Some(ptr) => A::ptr_to_bytes(ptr),
            None => vec![0u8; A::PTR_WIDTH],
        };
        self.globals()
            .write_mem(mem, "vdaptr", &vda_bytes)
            .map_err(|e| ShimError::Failed(format!("point_curusr: {e}")))?;
        Ok(())
    }

    /// `paccin()` then `parsin()`, and the far pointer `getin()` hands back:
    /// `char *margv[0]`, against memory directly rather than a whole
    /// `Machine`.
    ///
    /// The generic core [`Host::get_input`]'s `Wg16` facade delegates into --
    /// same split, same reason as [`Host::class_mem`]/[`Host::point_curusr_mem`].
    /// This is what unblocks `shims::user::getin` (Task 5's one file this
    /// task finishes): [`shims::text::parsin_mem`] was the last piece of the
    /// sequence still `Wg16`-only, and it converted in the text.rs/fsd.rs
    /// commit.
    ///
    /// # Errors
    ///
    /// If `input`, `margv` or `margn` are not placed, or a write runs off a
    /// segment.
    pub(crate) fn get_input_mem(&mut self, mem: &mut A::Mem, chan: Chan) -> Result<A::Ptr, ShimError> {
        // R16: resolve everything that can fail before touching the channel.
        // See `Host::get_input`'s own doc comment for why this ordering
        // matters -- unchanged by the move onto `A::Mem`.
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
        input.write(mem, &bytes).map_err(|e| ShimError::Failed(e.to_string()))?;

        shims::text::parsin_mem(mem, self)?;

        let margv = self
            .globals()
            .address("margv")
            .expect("margv is placed, or parsin above would already have failed");
        let bytes = margv
            .resolve(mem, A::PTR_WIDTH)
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        Ok(A::ptr_from_bytes(bytes))
    }

    /// The C name of an imported symbol, or something that identifies it when
    /// the host has no name for it.
    fn symbol_name(&self, from: &str, symbol: &Symbol) -> String {
        symbol_name(&self.exports, from, symbol)
    }

    /// Which loaded module `index` -- a thunk index off a live [`Exit::Call`]
    /// -- actually belongs to, and what it names there.
    ///
    /// `entered` is the module [`Host::run`] was *called with*: the one whose
    /// entry point started this call chain. It is tried first, and it is
    /// right every time execution never leaves that module's own code -- the
    /// overwhelming majority of calls. It stops being right the moment
    /// `entered`'s code far-calls directly into a *different* loaded
    /// module's own exported routine (an ordinary, thunk-free cross-module
    /// call -- see `crates/mbbs/tests/cross_module_imports.rs`'s
    /// `an_ordinal_import_reaches_another_loaded_modules_own_code`) and that
    /// routine then hits an unresolved import of its *own*: the `Exit::Call`
    /// names a thunk `entered` never had a hand in, and `entered.import`
    /// correctly answers `None` for it (see
    /// `mbbs_machine::m16::ne::Module::import`'s own doc comment on why an
    /// out-of-range index is `None`, not a panic).
    ///
    /// Falling back to `self.loaded_modules` -- every module this `Host` has
    /// loaded, keyed by [`Abi::module_name`] -- is safe rather than a guess:
    /// thunk indices are disjoint across every module loaded into one
    /// machine (`mbbs_machine::m16::ne::Thunks`'s own doc comment), so at
    /// most one candidate can ever answer `Some`. This method belongs on
    /// `Host`, not on `A::Cpu`/`A::Module`: only `Host` keeps the
    /// cross-module registry `loaded_modules` is, and neither `mbbs_machine`
    /// machine has -- or should have -- any notion of "which modules has
    /// this host loaded" (see `Host::loaded_modules`'s own doc comment).
    /// `Wg32` never populates `loaded_modules` at all (`Abi::module_name`'s
    /// default `None`), so this degrades to exactly `A::import(entered,
    /// index)` for it -- unchanged from before this method existed, which is
    /// correct: only one `Wg32` module can be loaded today at all
    /// (`Memory::replace_image` replaces the image wholesale), so there is
    /// no second module a `Wg32` index could ever belong to.
    ///
    /// Returns owned copies (`A::Module: Clone`, already required for
    /// `Host::loaded_modules` itself), not borrows: `Host::run`'s caller
    /// needs the answer to outlive a later `&mut self` reborrow
    /// (`shim(&mut call, self)`), which a borrow rooted in `self` cannot.
    /// This runs once per stop, never per dispatch, so the clone costs
    /// nothing worth avoiding.
    /// `None` for the owner means *the module that was entered* -- the
    /// caller already holds that one, so there is nothing to hand back.
    ///
    /// This is the whole reason the owner is optional rather than an
    /// `A::Module`. Returning `entered.clone()` here reads harmlessly and is
    /// not: `A::Module` owns its import table, so a clone deep-copies a
    /// `HashMap<String, u16>` and a `Vec<ImportSite>` of owned strings --
    /// 2,600-odd of them for `WCCMMUD.DLL` -- and this runs once per shim
    /// dispatch, several hundred times per driver wake. Measured against a
    /// live board it pegged a core at 100% with `Module::clone` and its
    /// matching drop accounting for six of eight stack samples. The
    /// cross-module arm below still clones, which is correct: it is reached
    /// only when a far call has landed in a *different* module's code, and
    /// then the caller genuinely does not have that module to hand.
    fn import_owner(
        &self,
        entered: &A::Module,
        index: u16,
    ) -> Option<(Option<A::Module>, mbbs_machine::module::ImportSite)> {
        if let Some(site) = A::import(entered, index) {
            return Some((None, site.clone()));
        }
        self.loaded_modules
            .values()
            .find_map(|candidate| A::import(candidate, index).map(|site| (Some(candidate.clone()), site.clone())))
    }

    /// Parse and map `file`, resolving every import against this host's own
    /// tables, and refuse to load a module that addresses a global this
    /// host cannot honestly place.
    ///
    /// Format mechanics belong to [`Abi::load`], not here -- this is the
    /// thin wrapper design §3 describes: build the one `Resolver` this
    /// load will use (host policy: this host's export table and placed
    /// globals), hand it to `A::load`, then decide what the walk found.
    ///
    /// **Refusal is checked before `A::load` ever touches `cpu`, in a pass
    /// of its own.** Task 9 folded the miss-detection into `Resolver`'s own
    /// walk and left it running *inside* `A::load`, which meant a `Wg16`
    /// module that was ultimately refused had still had `cpu` written to --
    /// segments allocated, thunks assigned, relocations applied -- before
    /// this method ever inspected `resolver`'s recorded misses. Every other
    /// `LoadError` left `cpu` untouched by construction (parsing fails
    /// before anything is mapped); this was the one case whose contract
    /// depended on which error came back, and two independent reviews
    /// called it a defect during Task 10.
    ///
    /// The fix costs nothing extra to compute: `Resolver::resolve`'s
    /// miss-detection reads only `self.exports`/`self.globals`/`self.reach`
    /// -- never `cpu`, never anything `A::load` has mutated -- so calling it
    /// once per key in `reach` *before* `A::load` runs finds exactly the
    /// same misses the walk inside `A::load` would, without waiting for
    /// that walk to run at all. If this pass finds nothing, `cpu` has not
    /// been touched yet either, so `A::load` runs clean; if it finds
    /// something, `cpu` is refused before a single byte is written to it.
    ///
    /// The `reach` classification `Resolver` uses to decide *which* misses
    /// matter (see `addressed_as_data`'s own doc comment) is NE
    /// relocation mechanism -- meaningless for any other container format,
    /// and this task's own brief forbids inventing a PE equivalent (there is
    /// no signal in a PE import table that could answer "how far does this
    /// fixup reach"; every PE import site is a full-width IAT write, see
    /// `mbbs_machine::m32::image::Image::bind_imports`'s own doc comment).
    /// So this classification is attempted against whatever bytes `file`
    /// holds, without asking which `A` is loading them: a non-NE file (a PE
    /// image loaded through `Wg32`, once Task 10 builds that arm) simply
    /// fails to parse here and contributes an empty `reach`, which is
    /// exactly what makes [`Why::TooSmall`] unreachable under `Wg32` "by
    /// construction" -- there is no code path anywhere in this crate that
    /// could build one without a non-empty `reach`, and `reach` is never
    /// non-empty for a file that is not NE. This is a temporary seam, not a
    /// permanent design point: if a second format ever grows its own
    /// "addressed as data" signal, this is where it would need to split by
    /// `A` -- nothing about today's single-format reality requires that
    /// split yet.
    ///
    /// # Errors
    ///
    /// If `file` is not a well-formed module for `A`, or the module
    /// addresses a global this host cannot honestly provide -- see
    /// [`LoadError`].
    /// Which generation was chosen and how each library it names is served.
    ///
    /// The report is part of the feature rather than decoration: a board that
    /// silently switched a library to vendor code would be indistinguishable
    /// from one that did not, right up until it behaved differently. Before
    /// the first [`Host::load`] it reports the anchor against an empty demand,
    /// which is the truth -- nothing has been asked for yet.
    #[must_use]
    pub fn provision_report(&self) -> Vec<String> {
        // Nothing is served from an authentic binary yet. Selecting one is
        // designed (`Provision::Authentic`, `Eligibility`), but *executing*
        // vendor code needs plumbing this host does not have -- the UART
        // bridging and channel-state ownership that GALGSBL's real code
        // implies. This predicate is the seam that changes when it does.
        let present = |_: &str| false;
        let mut out = vec![format!("profile: {}", self.profile.name)];
        if !self.indistinguishable.is_empty() {
            out.push(format!(
                "  indistinguishable from {} -- the modules loaded so far cannot tell them apart",
                self.indistinguishable.join(", ")
            ));
        }
        for row in mbbs_machine::library::provision(&self.demand, self.profile, &present) {
            out.push(format!("  {}", row.render()));
        }
        out
    }

    /// The ordinal tables this host resolves `dll`-and-number imports
    /// against, for the generation it was built for.
    ///
    /// Exists for `src/bin/gaps.rs`, which needs to put a *name* on an
    /// unresolved ordinal import so a gap report reads `prfmsg` rather than
    /// `#476`. Deliberately a borrow of the host's own table rather than
    /// letting the caller build one: which generation applies is
    /// `Exports::for_profile`'s decision, and a survey that picked its own
    /// would be one more copy of a host rule living outside the host -- the
    /// exact failure `gaps.rs` exists to retire.
    #[must_use]
    pub fn exports(&self) -> &Exports {
        &self.exports
    }

    pub fn load(&mut self, cpu: &mut A::Cpu, file: &[u8]) -> Result<A::Module, LoadError> {
        self.load_with_precedence(cpu, file, &[])
    }

    /// [`Host::load`], with `prefer` naming libraries whose already-loaded
    /// module wins over this host's own tables when this one load's own
    /// imports are resolved -- the opposite of [`Resolver::resolve`]'s
    /// ordinary "host tables first" order. [`Host::load`] itself is
    /// `self.load_with_precedence(cpu, file, &[])`, so the default is no
    /// flip and every existing caller is unaffected.
    ///
    /// **Per load, never global, and never for the library being loaded right
    /// now.** A synthesised forwarder (`mbbs_machine::m16::emit`) imports
    /// each of its own exports back from a module of its own name -- see that
    /// function's own doc comment, "The circularity this would create, and
    /// the rule that avoids it". If a forwarder's own load named its own
    /// library in `prefer` and some earlier load had already registered a
    /// module under that same name in [`Host::loaded_modules`], the
    /// forwarder's self-import would resolve to that earlier module's export
    /// instead of a real host thunk -- which may itself be nothing but
    /// another forwarder, extending the chain rather than ever reaching a
    /// host routine. The rule that avoids it: **a forwarder's own load always
    /// calls plain [`Host::load`]**, never this method with its own library
    /// named in `prefer`. Only a *module* loaded afterwards, wanting its
    /// import of that library routed through the forwarder rather than
    /// straight to the host, opts in here.
    ///
    /// # Errors
    ///
    /// Same as [`Host::load`].
    pub fn load_with_precedence(
        &mut self,
        cpu: &mut A::Cpu,
        file: &[u8],
        prefer: &[&str],
    ) -> Result<A::Module, LoadError> {
        let image = NeImage::parse(file).ok();
        let reach = image
            .as_ref()
            .map(|image| addressed_as_data(image, file))
            .unwrap_or_default();

        // Every distinct symbol `file` imports, NE or not -- a strict
        // superset of `reach`'s own keys (see `imported_symbols`'s own doc
        // comment). Driving the pre-check loop below off this set rather
        // than `reach.keys()` alone is what lets a missing cross-module
        // *routine* -- a call site, invisible to `reach` by construction --
        // get the same "refused before `cpu` is touched" guarantee
        // `Why::NotPlaced`/`Why::TooSmall` already had; see
        // `Why::NotExported`'s own doc comment for the case this exists for.
        let precheck: HashSet<(String, Symbol)> =
            image.as_ref().map(imported_symbols).unwrap_or_default();

        // The modules' own imports are the only evidence always present -- a
        // real board directory holds no vendor host binaries at all, so
        // fingerprinting one is not an option. See the design's "Detection".
        //
        // Accumulated on `self`, NOT rebuilt per load: detection is over the
        // union of every module loaded so far. Loading a second module can
        // narrow the admissible set, and must never be able to change what an
        // ordinal an earlier module already resolved was taken to mean.
        for (from, symbol) in &precheck {
            if let Symbol::Ordinal(n) = symbol {
                self.demand.add(from, *n);
            }
        }
        match mbbs_machine::library::detect(&self.demand) {
            mbbs_machine::library::Outcome::Unique(p) => {
                self.profile = p;
                self.exports = Exports::for_profile(p);
            }
            mbbs_machine::library::Outcome::Unobservable { chosen, agreeing } => {
                self.indistinguishable = agreeing;
                self.profile = chosen;
                self.exports = Exports::for_profile(chosen);
            }
            mbbs_machine::library::Outcome::Ambiguous { discriminating } => {
                return Err(LoadError::AmbiguousProfile(discriminating));
            }
            mbbs_machine::library::Outcome::NoneAdmissible { excluded, unevidenced } => {
                return Err(LoadError::NoProfile { excluded, unevidenced });
            }
        }

        let resolver = Resolver {
            exports: &self.exports,
            globals: &self.globals,
            loaded: &self.loaded_modules,
            prefer,
            reach,
            missing: std::cell::RefCell::new(Vec::new()),
        };

        // Refuse before `cpu` is touched at all: every symbol that could
        // ever be recorded as missing is a key of `precheck` (`reach`'s own
        // keys are a subset of it, and `Why::NotExported` is never gated on
        // `reach` at all -- see `Resolver::resolve`'s own doc comment), and
        // `resolve` reads nothing but `self.exports`/`self.globals`/
        // `self.reach`/`self.loaded` to answer, so walking those keys here
        // finds the identical misses the same walk would find from inside
        // `A::load`, without `A::load` having run yet.
        use mbbs_machine::module::ImportResolver as _;
        for (module, symbol) in &precheck {
            resolver.resolve(module, symbol);
        }
        let mut missing = resolver.missing.replace(Vec::new());
        if !missing.is_empty() {
            missing.sort_by(|a, b| (&a.module, &a.symbol).cmp(&(&b.module, &b.symbol)));
            return Err(LoadError::Globals(missing));
        }

        let module = A::load(cpu, file, &resolver)?;

        // The pass above already found every miss `precheck` can produce, so
        // this is a closed set, not a second independent source of
        // refusals -- kept as the honest fallback rather than an
        // `unreachable!()`, since `resolve` is a `dyn` trait method and
        // nothing prevents a *future* resolver from recording a miss this
        // pre-check did not anticipate.
        missing = resolver.missing.into_inner();
        if !missing.is_empty() {
            missing.sort_by(|a, b| (&a.module, &a.symbol).cmp(&(&b.module, &b.symbol)));
            return Err(LoadError::Globals(missing));
        }

        // Make this module's own exports reachable to whatever `Host::load`
        // call comes next in this life -- see `Host::loaded_modules`'s own
        // doc comment. `A::module_name` answering `None` (`Wg32`, today)
        // just means nothing else will ever find this module by name, which
        // is no worse than today's single-module reality.
        if let Some(name) = A::module_name(&module) {
            self.loaded_modules.insert(name.to_owned(), module.clone());
        }

        Ok(module)
    }

    /// Call a module entry point, servicing its imports until it stops.
    ///
    /// `chan` names which channel this call is being made on -- purely for
    /// [`survey::Inventory`]'s own record-keeping (see [`Host::enable_survey`]),
    /// never read for anything else. `None` when the call genuinely has no
    /// channel to name: [`Host::prcrtk`]'s kick sweep (a timer callback is
    /// not running on behalf of any player), or the module's own init
    /// routine, called before any channel exists to connect.
    ///
    /// Generic since Task 10 of
    /// `docs/plans/2026-08-12-abi-border-implementation.md`: every touch of
    /// the machine goes through `A::call`/`A::resume`/`A::poisoned`/
    /// `A::unimplemented`/`A::import`/`A::caller` rather than
    /// `mbbs_machine::m16::Machine` directly. `A::resume` already folds the
    /// caller/callee-clean split and the `Ret<A>` conversion in -- see
    /// [`Abi::resume`]'s own doc comment -- so the `let ret: Ret =
    /// ret.into()` this method used to do by hand, and the `match cleans {
    /// .. }` beside it, both sink into that one call; this is the actual
    /// content of the move, not merely a signature change.
    ///
    /// # Errors
    ///
    /// If the module cannot be entered, or the machine malfunctions. A module
    /// that faults, overruns or asks for something unimplemented is not an
    /// error -- it is [`Outcome::Stopped`], which says which.
    pub fn run(
        &mut self,
        machine: &mut A::Cpu,
        module: &A::Module,
        entry: A::Ptr,
        args: &[crate::abi::Arg<A>],
        chan: Option<Chan>,
    ) -> io::Result<Outcome<A>> {
        let mut exit = A::call(machine, entry, args)?;
        loop {
            let index = match exit {
                crate::abi::Exit::Returned { lo, hi } => return Ok(Outcome::Returned { lo, hi }),
                // Never continued past, survey mode or not -- see
                // `crate::survey`'s module doc. The machine is poisoned
                // already (`A::call`/`A::resume` do that before handing back
                // a terminal `Exit`), its globals may be mid-update, and the
                // machine has already forgotten the call frame: there is no
                // resume point left to fabricate a continuation into even if
                // this crate wanted to.
                crate::abi::Exit::Stopped => {
                    let poison = A::poisoned(machine).expect("a terminal exit poisons the machine");
                    return Ok(Outcome::Stopped(poison));
                }
                crate::abi::Exit::Call { index } => index,
                // Not a real variant -- see `Exit`'s own doc comment.
                crate::abi::Exit::_Phantom(never, _) => match never {},
            };

            // A thunk index neither `module` nor any other loaded module
            // claims is not something a module can cause -- it comes from
            // the bridge, and the bridge is the host's. Report it as an
            // unnamed import rather than panicking, so that a loader bug
            // looks like every other refusal.
            //
            // `owner` -- not `module` -- is who `index` actually belongs to;
            // see [`Host::import_owner`]'s own doc comment for why the two
            // can differ (a cross-module far call landing inside a different
            // module's code, which then hits its own unresolved import).
            // Every read below that used to name `module` for a *diagnostic*
            // (`A::caller`) now names `owner`, since a return address is only
            // ever meaningful decoded against the module whose code was
            // actually running -- which, once execution has crossed into
            // `owner`, is no longer `module`.
            // The remembered answer, when there is one. Skips two `String`
            // allocations and the table lookups; see `Host::resolved`.
            //
            // Stood down while `MBBS_TRACE_SHIMS` is on, because the trace
            // needs the library and symbol names that this path exists to
            // avoid building.
            // The remembered answer, when there is one. Skips the
            // `import_owner` lookup, both `String` allocations and the table
            // lookups; see `Host::resolved`.
            //
            // Stood down while either trace is on, because both print names
            // this path exists precisely to avoid building.
            if !self.trace
                && !shims::traced()
                && let Some(Some((shim, cleans))) = self.resolved.get(usize::from(index)).copied()
            {
                self.calls += 1;
                let mut call = shims::call::<A>(machine);
                match shim(&mut call, self) {
                    Ok(ret) => {
                        exit = A::resume(machine, ret, cleans)?;
                        continue;
                    }
                    Err(e) => {
                        // Terminal, so the names are worth rebuilding here to
                        // report properly -- the fast path skips them for the
                        // millions of calls that succeed, not for the one that
                        // stops the module.
                        let (from, symbol, owner) = match self.import_owner(module, index) {
                            Some((owner, site)) => (
                                site.module.clone(),
                                self.symbol_name(&site.module, &site.symbol),
                                owner,
                            ),
                            None => (String::new(), format!("thunk #{index}"), None),
                        };
                        let why = match A::caller(machine, owner.as_ref().unwrap_or(module)) {
                            Some(at) => format!("{e}, called from {at}"),
                            None => e.to_string(),
                        };
                        return self.stop(machine, A::refused(from, symbol, why));
                    }
                }
            }

            let (from, symbol, ordinal, owner) = match self.import_owner(module, index) {
                Some((owner, site)) => (
                    site.module.clone(),
                    self.symbol_name(&site.module, &site.symbol),
                    match &site.symbol {
                        Symbol::Ordinal(n) => Some(*n),
                        Symbol::Name(_) => None,
                    },
                    owner,
                ),
                None => (String::new(), format!("thunk #{index}"), None, None),
            };

            let (shim, cleans) = match shims::entry::<A>(&from, &symbol) {
                Entry::Routine(shim, cleans) => {
                    // `MBBS_TRACE_SHIMS`: name every shim the module reaches.
                    //
                    // This exists because the in-Realm wedge (2026-08-12) was
                    // invisible to every other instrument. Diffing one working
                    // command's dispatch sequence against a failing one's is
                    // what localised it: `look` ran
                    // `toupper x4 -> prf x35 -> btutsw -> btuxmt x5`, while a
                    // move ran `toupper -> prf -> f_ludiv@ x5 -> btuech ->
                    // rstmbk x3` and never transmitted. Nothing else in this
                    // host could have shown that.
                    //
                    // Costs one `var_os` per dispatch when off. Read with the
                    // `KICK-FIRE` line in `prcrtk` and the `PRF` line in
                    // `shims::text::prf`, which share the same variable.
                    if shims::traced() {
                        eprintln!("mbbs-trace: chan={chan:?} {from}!{symbol}");
                    }
                    // Remember it, so the next of the million calls to this
                    // thunk takes the fast path above.
                    let at = usize::from(index);
                    if self.resolved.len() <= at {
                        self.resolved.resize(at + 1, None);
                    }
                    self.resolved[at] = Some((shim, cleans));
                    (shim, cleans)
                }
                other @ (Entry::Datum | Entry::Absolute(_) | Entry::Unimplemented) => {
                    let kind = match other {
                        Entry::Datum => survey::Kind::Datum,
                        Entry::Absolute(_) => survey::Kind::Absolute,
                        Entry::Unimplemented => survey::Kind::Unimplemented,
                        Entry::Routine(..) => unreachable!("matched above"),
                    };
                    let context = A::caller(machine, owner.as_ref().unwrap_or(module));

                    if let Some(inventory) = &self.survey {
                        inventory.borrow_mut().record(
                            &from,
                            &symbol,
                            ordinal,
                            chan,
                            context.as_deref(),
                            kind,
                        );
                    }

                    // Only `Entry::Unimplemented`, only in survey mode, and
                    // only when the cleanup convention is one this host is
                    // willing to guess -- see `shims::survey_continue_convention`
                    // for what "willing" means and why. Every other case
                    // (survey mode off; `Entry::Datum`/`Entry::Absolute`, a
                    // mismodelled *type* rather than a missing routine; a
                    // convention this host refuses to guess) falls through to
                    // the same stop it always has.
                    if self.survey.is_some()
                        && kind == survey::Kind::Unimplemented
                        && let Some(continue_as) = shims::survey_continue_convention(&symbol)
                    {
                        exit = A::resume(machine, crate::abi::Ret::Void, continue_as)?;
                        continue;
                    }

                    let symbol = match &context {
                        Some(at) => format!("{symbol}, called from {at}"),
                        None => symbol,
                    };
                    return self.stop(machine, A::unimplemented(from, symbol));
                }
            };

            self.calls += 1;
            if self.trace {
                eprintln!("{:4} {symbol}", self.calls);
            }
            // `shims::entry`'s `Shim<A>` takes a `Call<A>`, not a bare
            // `&mut A::Cpu` -- this is the one place that gap is bridged, now
            // that `routines` names generic cores directly rather than 111
            // individual `_wg16` siblings; see `shims::mod`'s own `call` doc
            // comment.
            let mut call = shims::call::<A>(machine);
            match shim(&mut call, self) {
                Ok(ret) => {
                    exit = A::resume(machine, ret, cleans)?;
                }
                Err(e) => {
                    // `refused`, not `unimplemented`. This routine EXISTS --
                    // the table answered with it and it ran. Reporting that
                    // as "not implemented" sends the next reader looking for
                    // a symbol that is already there: The Rose reported
                    // `cw3220mt.DLL.strlen (...) is not implemented` when
                    // `strlen` had been implemented for months and the real
                    // fault was the host entering the module at the wrong
                    // address (`ordinal 1` is Rose's crt0 stub, not its
                    // init), so it was running gameplay code that called
                    // `strlen` on a null pointer.
                    let why = match A::caller(machine, owner.as_ref().unwrap_or(module)) {
                        Some(at) => format!("{e}, called from {at}"),
                        None => e.to_string(),
                    };
                    return self.stop(machine, A::refused(from, symbol, why));
                }
            }
        }
    }

    fn stop(&self, machine: &mut A::Cpu, reason: A::Poison) -> io::Result<Outcome<A>> {
        A::poison(machine, reason)?;
        let poison = A::poisoned(machine).expect("just poisoned");
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
    fn shim_stop(&self, machine: &mut A::Cpu, where_: &str, e: ShimError) -> io::Result<Outcome<A>> {
        // `refused`, not `unimplemented`: these three calls are host routines
        // that ran and could not answer, which is a different thing from a
        // symbol this host lacks. See the `Err` arm in `run`'s dispatch loop.
        let why = match &e {
            ShimError::BadPointer(_) => format!("bad pointer, {e}"),
            ShimError::Failed(_) => e.to_string(),
        };
        self.stop(
            machine,
            A::refused("mbbs".to_owned(), where_.to_owned(), why),
        )
    }

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
    /// Moved here (Task 11 of
    /// `docs/plans/2026-08-12-abi-border-implementation.md`) ahead of the
    /// rest of its own cluster (`connect`/`connect_state`/... -- Task 12):
    /// [`Host::poll_with_chan`] calls this directly, and its own body is
    /// already `A`-generic in substance -- it never touches anything but
    /// [`Users::state_mem`] and [`Registration::dispatch`], both already
    /// generic. `machine` widens from `&Machine` to `&mut A::Cpu` because
    /// [`Abi::mem`] is the only way to reach `A::Mem` generically and it
    /// takes `&mut Self::Cpu` even to read -- see that trait method's own
    /// doc comment.
    ///
    /// # Errors
    ///
    /// If `state` names no registered module.
    fn state_entry(
        &self,
        machine: &mut A::Cpu,
        chan: Chan,
        n: usize,
    ) -> io::Result<Result<Dispatch<A>, ShimError>> {
        let state = match self.users.state_mem(A::mem(machine), chan) {
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
        Ok(registered.dispatch(A::mem(machine), n))
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
    /// [`Host::poll`] needs the identical sequence and must not have to fake
    /// a call frame to reach it.
    ///
    /// The generic core [`Host::get_input_mem`] delegates into -- see
    /// `Host::class_mem`'s own doc comment for why the split exists. Moved
    /// here (Task 11 of
    /// `docs/plans/2026-08-12-abi-border-implementation.md`): the plan's
    /// four dissolution clusters never name it, but its own doc comment
    /// (before this move) said it is a shared helper for `Host::poll`, which
    /// is this cluster.
    ///
    /// # Errors
    ///
    /// If `input`, `margv` or `margn` are not placed, or a write runs off a
    /// segment.
    pub(crate) fn get_input(&mut self, machine: &mut A::Cpu, chan: Chan) -> Result<A::Ptr, ShimError> {
        self.get_input_mem(A::mem(machine), chan)
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
        machine: &mut A::Cpu,
        module: &A::Module,
        chan: Chan,
    ) -> io::Result<Option<Outcome<A>>> {
        let rou = match self.users.polrou_mem(A::mem(machine), chan) {
            Ok(Some(rou)) => rou,
            Ok(None) => return Ok(None),
            Err(e) => return self.shim_stop(machine, "dopoll", e).map(Some),
        };

        self.inpolr = Some(chan);
        // Bracketing `run` rather than the whole function so the census counts
        // what the module's own routine did, not this host's bookkeeping
        // around it. See `PollCensus`.
        let before = self.calls();
        let outcome = self.run(machine, module, rou, &[], Some(chan));
        // Cleared before the `?`, so a machine that malfunctioned does not leave
        // `inpolr` naming a channel that is no longer running anything. The
        // original does the same from the `longjmp` landings at
        // `MAJORBBS.C:2488` and `:4150`.
        self.inpolr = None;

        // Counted before the `?`, so a poll that ended the machine is still
        // counted -- it is the most expensive one there is, and losing it
        // would bias the census towards the dispatches that went well.
        let spent = self.calls().saturating_sub(before);
        self.census.polls += 1;
        self.census.calls += spent;
        self.census.worst = self.census.worst.max(spent);
        if spent == 0 {
            self.census.barren += 1;
        }

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
            match self.users.polrou_mem(A::mem(machine), chan) {
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
    /// `prctask()` -- run every routine `initask` registered, in
    /// registration order, handing each its own task id.
    ///
    /// `MAJORBBS.C:323` makes this the `syscyc` vector's initial value, so on
    /// the original it is the tail of every module's chain and runs once per
    /// system cycle. This host calls it from [`Host::cycle`] directly instead
    /// -- see the comment at that call site for why depending on a module to
    /// chain correctly would be the wrong bet.
    ///
    /// Every registered task runs every cycle; there is no expiry, which is
    /// what separates a task from a [`Kick`]. `fired` is added to rather than
    /// assigned, matching [`Host::prcrtk`]'s own contract.
    ///
    /// A task that stops the machine ends the sweep and returns the poison --
    /// the remaining tasks do not run, exactly as they would not on a host
    /// whose task jumped into a fault.
    ///
    /// # Errors
    ///
    /// If a task's own call tree fails in a way [`Host::run`] reports as an
    /// error rather than a poisoning.
    fn prctask(
        &mut self,
        machine: &mut A::Cpu,
        module: &A::Module,
        fired: &mut usize,
    ) -> io::Result<Option<A::Poison>> {
        for at in 0..self.tasks.len() {
            let task = self.tasks[at];
            *fired += 1;
            match self.run(machine, module, task, &[], None)? {
                Outcome::Stopped(poison) => return Ok(Some(poison)),
                Outcome::Returned { .. } => {}
            }
        }
        Ok(None)
    }

    /// Advance the `ticker` global by one, wrapping the way its vendor-declared
    /// `USHORT` does.
    ///
    /// One caller, [`Host::cycle`]'s per-elapsed-second loop -- **not**
    /// [`Host::cycle`] itself, which runs far more often than once a second
    /// (see that loop's own comment on why `syscyc` needed the identical
    /// split). The GSBL Development Guide's own words for this datum are the difference between two readings is the seconds between them -- true only if the rate is
    /// genuinely one per second of wall-clock time, not once per poll pass.
    /// `globals.rs`'s own doc comment on the `ticker` entry in `GLOBALS`
    /// gives the full citation (`BRKTHU.H:214`).
    ///
    /// # Errors
    ///
    /// If module memory cannot be reached to read or write the global.
    fn tick_ticker(&mut self, machine: &mut A::Cpu) -> io::Result<()> {
        let current = self.globals.word_mem(A::mem(machine), "ticker")?;
        self.globals
            .write_mem(A::mem(machine), "ticker", &current.wrapping_add(1).to_le_bytes())
    }

    /// Call the `syscyc` vector once, if a module has installed one.
    ///
    /// Its own function because [`Host::cycle`] fires it from two places for
    /// two different reasons, and a second copy of the null check and the
    /// stop handling is how those two drift apart.
    fn syscyc(
        &mut self,
        machine: &mut A::Cpu,
        module: &A::Module,
        dispatched: &mut usize,
    ) -> io::Result<Option<A::Poison>> {
        let vector = self.globals().pointer_mem(A::mem(machine), "syscyc")?;
        if vector == A::null_ptr() {
            return Ok(None);
        }
        match self.run(machine, module, vector, &[], None)? {
            Outcome::Stopped(poison) => Ok(Some(poison)),
            Outcome::Returned { .. } => {
                *dispatched += 1;
                Ok(None)
            }
        }
    }

    fn prcrtk(
        &mut self,
        machine: &mut A::Cpu,
        module: &A::Module,
        fired: &mut usize,
    ) -> io::Result<Option<A::Poison>> {
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
            // Name each kick as it fires. A module whose timers are dead and
            // one whose timers run but do nothing look identical from
            // outside; this tells them apart.
            //
            // `MBBS_TRACE_KICKS` as well as `MBBS_TRACE_SHIMS`, because the
            // question "is this module's heartbeat still beating?" is worth
            // asking without the shim flood that answers it -- one idle
            // MajorMUD window is 137,211 shim lines, 96.5% of them `ptrtile`,
            // against a handful of kicks a second.
            if shims::traced() || std::env::var_os("MBBS_TRACE_KICKS").is_some() {
                eprintln!("mbbs-trace: KICK-FIRE dstrou={:?}", kick.dstrou);
            }
            match self.run(machine, module, kick.dstrou, &[], None)? {
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
    ///   curusr(chan), then write the `status` global -- BOTH unconditional,
    ///   as `MAJORBBS.C:152` is (see the comment at the write itself for the
    ///   stale-value bug that writing it only on the non-CRSTG path caused)
    ///   status 3 (CRSTG)  -> getin(), then entry 1 (sttrou)
    ///   status 4 (INBLK)
    ///      or 5 (OUTMT)   -> entry 2 (stsrou)
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
    pub fn poll(&mut self, machine: &mut A::Cpu, module: &A::Module) -> io::Result<Option<Outcome<A>>> {
        Ok(self.poll_with_chan(machine, module)?.map(|(outcome, _chan)| outcome))
    }

    /// [`Host::poll`], plus the channel an [`Outcome`] belongs to.
    ///
    /// Private: the only caller that needs the channel is [`Host::cycle`],
    /// which wants it to name who a stop happened to in [`Ended::Stopped`].
    /// Every external caller of `poll` (`crates/mbbs/tests/wccmmud.rs` and
    /// `ifansi_oracle.rs`, dozens of call sites) only ever wanted the
    /// `Outcome`, so `poll` keeps that shape and this carries the extra fact
    /// out through the one caller that has a use for it.
    ///
    /// The `Dispatch::Native` arm calls [`Host::fsd_dispatch`] directly,
    /// generically, since Task 12 of
    /// `docs/plans/2026-08-12-abi-border-implementation.md`: `shims/fsd.rs`'s
    /// session engine went generic in that task (`fsd_cycle`, `fsdprc`,
    /// `goback` and their `FarPtr`-typed helpers all took `A::Cpu`/`A::Ptr`
    /// instead), which retired the `Abi::native_dispatch` bridge Task 11 had
    /// added to reach this arm while `fsd_dispatch` was still `Wg16`-only.
    /// `Native::Fsd` is the only [`shims::system::Native`] variant, so this
    /// match has nothing else to route.
    fn poll_with_chan(
        &mut self,
        machine: &mut A::Cpu,
        module: &A::Module,
    ) -> io::Result<Option<(Outcome<A>, Chan)>> {
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
            // (`MAJORBBS.C:4290`) does. Calls the generic core
            // [`Host::point_curusr_mem`] directly rather than the `Wg16`
            // facade [`Host::point_curusr`] -- that facade stays concrete
            // (Task 12), and there is no reason for generic code to route
            // through it when the core it delegates to is already generic.
            if let Err(e) = self.point_curusr_mem(A::mem(machine), chan) {
                return self
                    .shim_stop(machine, "point_curusr", e)
                    .map(|outcome| Some((outcome, chan)));
            }

            // `MAJORBBS.C:152`: `status=btusts(usrnum)` is unconditional --
            // only the `!= 3` guard on `shomal()` (the operator console, out of
            // scope) is conditional. `status` is a placed global
            // (`globals.rs:107`) that `stsrou` reads (`WCCMMUD.DLL` imports it
            // at 2 sites); writing it only on the non-CRSTG path left the
            // module reading a stale value on the CRSTG path -- zero on a
            // fresh host, or a leftover `OUTMT` from an earlier poll.
            self.globals()
                // `status` is an `i16` here and an `int` there: sign-extended to 32
                // bits first, so a negative one is still negative at either width.
                .write_int_mem(A::mem(machine), "status", status as i32 as u32)?;

            let entry_index = match dispatch {
                // A polling routine is not an entry point and has no index. The
                // arm diverges either way, so the `match` still yields the index
                // the `Entry` arm carries.
                PollTarget::Poll => match self.dopoll(machine, module, chan)? {
                    Some(outcome) => return Ok(Some((outcome, chan))),
                    None => continue,
                },
                PollTarget::Entry(index) => index,
            };

            if status == gsbl::Gsbl::CRSTG
                && let Err(e) = self.get_input(machine, chan)
            {
                return self
                    .shim_stop(machine, "get_input", e)
                    .map(|outcome| Some((outcome, chan)));
            }

            // The command seam. The line is in `input` and the module has not
            // been told about it yet, which makes this the one place an
            // extension can answer a command without the module also seeing
            // it. `None` skips the whole block, so a host without an
            // extension executes exactly the path it always did.
            //
            // `Handled` needs no channel-state cleanup beyond a bare
            // `continue` -- see `task-2-findings.md`, in full. Summarized:
            // `Gsbl::take_line` (`gsbl.rs:549`) already popped the line
            // inside `get_input`, above, before this seam runs; popping it
            // *is* the clearing. Everything else the `CRSTG` path touches
            // (`status`, `usrnum`/`usrptr`/`usaptr`/`vdaptr`, `margv`/`margn`)
            // is wholesale-overwritten by the next line's own `get_input`
            // and `point_curusr_mem`, never appended to. And the `sttrou`
            // TRUE/FALSE "did you consume it" contract
            // (`MAJORBBS.C:2703`, `hdlcri()`) needs no emulation: this host
            // does not implement it at all (no `go2mnu`, no `substt` reset,
            // no `hdlcri` equivalent -- see this same function's own R24
            // comment on the `entry == None` fallback, further down), so
            // there is nothing for `Handled` to fake.
            if status == gsbl::Gsbl::CRSTG && self.extension.is_some() {
                if let extension::Verdict::Handled = self.dispatch_command(machine, chan)? {
                    continue;
                }
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
            // answer. [`Host::fsd_dispatch`] carries that, generically, since
            // Task 12; every other call site in this file treats `Native` as
            // a hook a module left null instead, because none of them are
            // input dispatch.
            let entry = self.state_entry(machine, chan, entry_index)?;
            let entry = match entry {
                Ok(Dispatch::Module(entry)) => Ok(entry),
                Ok(Dispatch::Native(_native)) => {
                    self.fsd_dispatch(machine, module, chan, entry_index)
                }
                // The module handed this channel back to a BBS this host does
                // not have -- see `Registration::AbsentBbs`. There is nothing
                // above a module here to take the user, so the session is
                // over: record it for the driver to close, and service the
                // status without a module call.
                Ok(Dispatch::SessionOver) => {
                    if !self.ended.contains(&chan) {
                        self.ended.push(chan);
                    }
                    Ok(None)
                }
                Err(e) => Err(e),
            };
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    return self
                        .shim_stop(machine, "entry lookup", e)
                        .map(|outcome| Some((outcome, chan)));
                }
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
            return self
                .run(machine, module, entry, &[], Some(chan))
                .map(|outcome| Some((outcome, chan)));
        }
    }

    /// Give the installed extension first look at a `CRSTG` line, before the
    /// module is told about it.
    ///
    /// `Ok(Verdict::Pass)` with no extension installed, unconditionally --
    /// [`Host::poll_with_chan`]'s own `self.extension.is_some()` guard means
    /// this is only reached when there is one, but the fallback keeps the
    /// contract right even if that guard is ever lifted.
    ///
    /// Takes the extension out of `self` for the call, the same borrow trap
    /// [`Host::poll_with_chan`] already documents for `connect`:
    /// [`extension::CommandCtx`] borrows `self` mutably to let a handler ask
    /// the host questions, which is only legal while `self.extension` itself
    /// is not also borrowed. Taking it out and putting it back is what makes
    /// that legal, and it also means a handler cannot re-enter itself
    /// through the host.
    fn dispatch_command(&mut self, machine: &mut A::Cpu, chan: Chan) -> io::Result<extension::Verdict> {
        let Some(mut ext) = self.extension.take() else {
            return Ok(extension::Verdict::Pass);
        };
        let line = self.input_line(A::mem(machine));
        let mut ctx = extension::CommandCtx { chan, line, host: self };
        let verdict = ext.command(&mut ctx);
        self.extension = Some(ext);
        Ok(verdict)
    }

    /// The `input` global, as the line it holds -- the same bytes
    /// [`Host::get_input_mem`] just wrote there, NUL-terminated, read back
    /// out as a `String`. Lossy: a line is whatever the terminal sent through
    /// [`gsbl::Gsbl::take_line`]'s translate table, not guaranteed UTF-8, and
    /// a malformed byte here is not a reason to poison the machine.
    fn input_line(&self, mem: &A::Mem) -> String {
        let Some(input) = self.globals().address("input") else {
            return String::new();
        };
        match input.read_cstr(mem) {
            Ok(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            Err(_) => String::new(),
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
    /// `machine` widens from `&Machine` to `&mut A::Cpu` -- the same reason
    /// `state_entry`'s own signature does: [`Abi::mem`] takes `&mut
    /// Self::Cpu` even to read.
    ///
    /// # Errors
    ///
    /// If a channel's `polrou` cannot be read out of the machine.
    /// What the poll budget bought since the last [`Host::take_census`], and
    /// clear it. See [`PollCensus`].
    pub fn take_census(&mut self) -> PollCensus {
        std::mem::take(&mut self.census)
    }

    pub fn refill_polls(&mut self, machine: &mut A::Cpu, n: usize) -> io::Result<()> {
        self.polls_left = n;
        if n == 0 {
            return Ok(());
        }
        for chan in self.users.terms().all() {
            // Already armed: either `dopoll` re-injected before the budget ran
            // out, or the last burst ended with statuses still queued --
            // which is what `cycle`'s interrupt does when the pump's mailbox
            // has input waiting. Injecting again would add a dispatch per
            // wake, and the pump refills on every wake that saw input, so
            // that is a queue growing without bound.
            if self.gsbl.polling_armed(chan) {
                continue;
            }
            match self.users.polrou_mem(A::mem(machine), chan) {
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
    /// **`interrupted` is asked once per pass, not once per dispatch.** It is
    /// consulted at the end of a pass, after that pass's `syscyc`/`prcrtk`
    /// catch-up, so time work is never starved by a caller in a hurry. A
    /// bound on dispatches would make a module that stopped polling to wait
    /// on a timer return zero work forever.
    ///
    /// `--passes` used to bound this loop. It was a proxy for "has input
    /// arrived?", and a count cannot answer that question: it fired when
    /// nothing was waiting and stayed silent when something was. The pump
    /// peeks its own mailbox now, which is the signal itself. See
    /// `docs/superpowers/specs/2026-08-20-cycle-interrupt-and-syscyc-design.md`.
    ///
    /// It returns as soon as nothing is queued, rather than spinning until a
    /// timer comes due. The caller advances time by sleeping and calling back;
    /// [`Ended::wait`] says how long. The old loop turned here because the
    /// original's did, and the original's did because it owned the machine.
    ///
    /// This never sleeps. One thread owns the machine, so a sleep here would
    /// be a sleep the socket cannot interrupt; the caller owns all blocking and
    /// [`Ended`] carries what it needs to decide.
    ///
    /// # Errors
    ///
    /// If no module has registered, or the machine malfunctions. A module that
    /// stops is [`Ended::Stopped`], not an error.
    pub fn cycle(
        &mut self,
        machine: &mut A::Cpu,
        module: &A::Module,
        interrupted: &mut dyn FnMut() -> bool,
    ) -> io::Result<Cycles<A>> {
        let mut iterations = 0;
        let mut dispatched = 0;

        // **`syscyc` is not fired here.** `MAJORBBS.C:419-424` fires it
        // whenever the channel scan does not advance; this host fires it once
        // per elapsed second instead, in the catch-up below, ahead of that
        // second's kicks. The scan-based call was deleted 2026-08-20: the
        // module's gate is idempotent (`|= 1`) and `_BACKGROUND_FAST` consumes
        // it at 1 Hz, so it could not advance the Realm by a tick the
        // per-second call does not -- it only tied the vector's rate to this
        // pump's cadence, and with it every measurement of this host to the
        // board's load. See the test
        // `cycle_does_not_fire_syscyc_merely_because_the_scan_did_not_advance`.

        if let Some(poison) = self.prctask(machine, module, &mut dispatched)? {
            return Ok(Cycles {
                iterations,
                dispatched,
                // `None`: a task belongs to no channel, same as a kick.
                ended: Ended::Stopped(poison, None),
            });
        }

        // Wall-clock for the stall note below, reset at the end of every pass.
        // Started here rather than before the `syscyc` dispatch above so that
        // the first pass is charged for its own work and not for the vector's.
        let mut pass_mark = std::time::Instant::now();

        // No clock bound. `interrupted` is the only bound on a cycle, and a
        // caller with nothing to say passes `&mut || false`, so a cycle turns
        // until the board goes idle. See
        // `docs/superpowers/specs/2026-08-20-cycle-interrupt-and-syscyc-design.md`'s
        // "Retired measurements" appendix for the measurement that retired
        // the 250ms budget (and the `--passes` count bound) this loop used
        // to carry.
        loop {
            iterations += 1;


            // No `pending()` guard here, and deliberately. `Host::poll`'s first
            // act is the same scan, and it returns `Ok(None)` before touching
            // the module or the machine when that scan finds nothing -- so a
            // guard testing the identical predicate could only agree with it.
            // It was written as one, and review found that mutating the guard
            // away left all 739 tests passing, which is what unobservable looks
            // like.
            // Who this pass served, for the stall note below to name. `None`
            // stays `None` when nothing was dispatched, which is the honest
            // answer: the time went to the kick sweep, not to a channel.
            let mut polled = None;
            match self.poll_with_chan(machine, module)? {
                Some((Outcome::Stopped(poison), chan)) => {
                    return Ok(Cycles {
                        iterations,
                        dispatched,
                        ended: Ended::Stopped(poison, Some(chan)),
                    });
                }
                Some((Outcome::Returned { .. }, chan)) => {
                    polled = Some(chan);
                    dispatched += 1;
                }
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
                // `ticker` (`GALGSBL`, `globals.rs`'s own doc comment on it
                // names the guide's exact wording): one increment per
                // elapsed real second, wrapping the way its `USHORT` does,
                // driven by this loop's own "one round per second that
                // genuinely passed" invariant rather than by `cycle`'s much
                // faster poll cadence -- see `Host::tick_ticker`'s own doc
                // comment for why that distinction matters.
                self.tick_ticker(machine)?;
                // **One `syscyc` per elapsed second, ahead of that second's
                // kicks.** Firing it only once per `cycle` call above is not
                // enough, and the shortfall is a lost second of the module's
                // own time rather than a late one.
                //
                // MajorMUD is the case that shows it. Its whole internal timer
                // system -- monster respawn, player saves (`SECOTH`), buffer
                // saves (`SECBUFF`), item restocking, the medium and slow
                // monster sweeps -- runs off a private queue (`_MY_RTKICK`)
                // keyed on a tick counter it increments in exactly one place:
                // inside `_BACKGROUND_FAST`, in the branch it takes only when
                // this vector has set its gate bit, and which clears that bit
                // on the way out. `_BACKGROUND_FAST` is an ordinary `rtkick`
                // heartbeat, so `prcrtk` below fires it once per elapsed
                // second -- but a `cycle` that spanned four seconds fires it
                // four times against a single gate-set, and the module counts
                // one tick, not four. Its clock then runs slow by however
                // long a cycle takes and never catches up. Measured on a live
                // board at the shipped budgets: 3 to 5 `cycle` calls per ten
                // seconds, a module clock at a third of real time, and
                // monsters that stayed dead.
                //
                // Ungated by the `btuscn` test the call above uses, on
                // purpose: that test asks "is there a channel waiting?", which
                // is the right question for the vendor's spin-as-fast-as-you-
                // can loop and the wrong one for "a second of real time has
                // passed." A board busy enough to always have a channel queued
                // is exactly the board that must not have its world stop.
                if let Some(poison) = self.syscyc(machine, module, &mut dispatched)? {
                    self.tcklst = Some(last);
                    return Ok(Cycles {
                        iterations,
                        dispatched,
                        ended: Ended::Stopped(poison, None),
                    });
                }
                if let Some(poison) = self.prcrtk(machine, module, &mut dispatched)? {
                    // Written back before the early return: the rounds already
                    // run must not run again on the next `cycle`.
                    self.tcklst = Some(last);
                    return Ok(Cycles {
                        iterations,
                        dispatched,
                        // `None`: a kick fired this, and `Kick` carries only
                        // `delay` and `dstrou` -- no channel exists to name.
                        // See `Ended::Stopped`'s own doc.
                        ended: Ended::Stopped(poison, None),
                    });
                }
            }
            self.tcklst = Some(last);
            // **Elapsed epoch time is not evidence of a stall.** `tcklst`
            // persists across `cycle` calls, and between two of them the
            // driver is asleep -- that is what `Ended::Waiting` is for. So
            // `rounds` counts sleep and work alike, and reporting it as a
            // stall reports the healthy case: the longer the driver correctly
            // sleeps, the more "stalls" it announces. It did, for as long as
            // this note existed, and two investigations
            // (`e0ae785`, `0903399`) built conclusions on the flood --
            // `--passes` could not move the count because passes were never
            // what it measured.
            //
            // `pass_mark` is wall-clock inside this call only, reset every
            // pass, so it cannot see the sleep that happened before `cycle`
            // was entered. A pass that really did take a second or more is a
            // stall and says so, with the channel it was serving; anything
            // else is time this host spent asleep, which is not worth a line.
            let worked = pass_mark.elapsed();
            pass_mark = std::time::Instant::now();
            if let Some(note) = stall_note(worked, rounds, polled) {
                self.note(note);
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

            // **The interrupt, consulted here and nowhere else.** After the
            // tick catch-up above, never before it: a predicate answered at
            // the top of the pass would let a fast typist return this call
            // before `syscyc`/`prcrtk` ever ran, and the module's world would
            // stop for as long as they kept typing. Every pass therefore
            // carries its own second of time work before it can be cut short.
            //
            // After the `pending()` test above, too. A drained board is
            // `Idle`/`Waiting`, which is a fact about the module; `Bound` is a
            // fact about the caller wanting the thread back. Asking in the
            // other order would report the caller's impatience as the
            // module's state and send the driver straight back into a `cycle`
            // with nothing to do.
            //
            // Nothing else bounds this loop. The poll budget
            // (`Host::refill_polls`) always was the real bound -- `dopoll`
            // stops re-arming when it runs out, the queue drains, and the
            // `pending()` test above returns. The `max` count this replaced
            // was redundant safety on top of that, and a proxy for "has input
            // arrived?" that could not answer the question.
            if interrupted() {
                let next_kick = self.kicks.iter().map(|kick| kick.delay).min();
                return Ok(Cycles {
                    iterations,
                    dispatched,
                    ended: Ended::Bound { next_kick },
                });
            }
        }
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
    /// Generic since Task 12 of
    /// `docs/plans/2026-08-12-abi-border-implementation.md`:
    /// [`shims::fsd::fsd_cycle`] and everything under it went generic in the
    /// same task, which is what lets `Host::poll_with_chan` call this
    /// directly instead of through `Abi::native_dispatch` -- see that
    /// former trait method's own doc comment (deleted alongside this move)
    /// for the bridge this retires.
    ///
    /// # Errors
    ///
    /// If [`shims::fsd::fsd_cycle`] does -- in particular, if this channel's
    /// state names the FSD's own slot but `fsdego` never ran for it, which
    /// is a bug in whatever set that state rather than a condition to
    /// silently ignore.
    fn fsd_dispatch(
        &mut self,
        machine: &mut A::Cpu,
        module: &A::Module,
        chan: Chan,
        n: usize,
    ) -> Result<Option<A::Ptr>, ShimError> {
        if n != 2 {
            self.note(format!(
                "fsd_dispatch: channel {chan} entry {n} reached the FSD's native slot, \
                 which has no handler wired up yet"
            ));
            return Ok(None);
        }

        shims::fsd::fsd_cycle(machine, self, module, chan)?;
        Ok(None)
    }

    /// `user[unum].usrcls` -- what kind of channel this is.
    ///
    /// Zero for every channel this host makes, which is neither `ONLINE` nor
    /// `BBSPRV`. Read rather than assumed because `low_haskey` branches on it.
    ///
    /// Generic since Task 12: a thin facade over the already-generic
    /// [`Host::class_mem`], reached through [`Abi::mem_ref`] rather than
    /// [`Abi::mem`] -- this never writes, so it never needs `&mut A::Cpu`.
    ///
    /// # Errors
    ///
    /// If the read runs off a segment.
    pub fn class(&self, machine: &A::Cpu, unum: Chan) -> Result<u16, ShimError> {
        self.class_mem(A::mem_ref(machine), unum)
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
    /// Generic since Task 12: a thin facade over the already-generic
    /// [`Host::point_curusr_mem`].
    ///
    /// # Errors
    ///
    /// If a write runs off a segment.
    pub(crate) fn point_curusr(&mut self, machine: &mut A::Cpu, uno: Chan) -> Result<(), ShimError> {
        self.point_curusr_mem(A::mem(machine), uno)
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
    /// Generic since Task 12 of
    /// `docs/plans/2026-08-12-abi-border-implementation.md`: the five raw
    /// `FarPtr { offset, selector }` literals this carried become
    /// [`Abi::ptr_offset`] calls from `account`/`slot`, and the five direct
    /// `machine.write` calls become `ModulePtr::write` against
    /// [`Abi::mem`] -- this had no generic `_mem` core to delegate into the
    /// way `class`/`point_curusr` do, so this is the conversion itself, not
    /// a facade over one.
    ///
    /// # Errors
    ///
    /// If `chan` names no channel, or a write runs off a segment.
    pub fn connect_state(
        &mut self,
        machine: &mut A::Cpu,
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
        let account_layout = *self.users().account_layout();
        let at = A::ptr_offset(account, account_layout.userid);
        at.write(A::mem(machine), &field)
            .map_err(|e| ShimError::Failed(e.to_string()))?;

        let at = A::ptr_offset(account, account_layout.ansifl);
        at.write(A::mem(machine), &[u8::from(who.ansi)])
            .map_err(|e| ShimError::Failed(e.to_string()))?;

        let at = A::ptr_offset(account, account_layout.scnwid);
        at.write(A::mem(machine), &[who.width])
            .map_err(|e| ShimError::Failed(e.to_string()))?;

        let at = A::ptr_offset(account, account_layout.scnfse);
        at.write(A::mem(machine), &[who.height])
            .map_err(|e| ShimError::Failed(e.to_string()))?;

        // Zeroed at the field's own width. Under `Wg32` these are four-byte
        // `INT`s and a two-byte store would leave the previous occupant's
        // high half in place -- which is the same class of bug `userid`
        // above is zeroed whole to avoid.
        let layout = *self.users().user_layout();
        for (field, name) in [
            (layout.usrcls, "usrcls"),
            (layout.state, "state"),
            (layout.substt, "substt"),
        ] {
            let at = A::ptr_offset(slot, field.at);
            at.write(A::mem(machine), &vec![0u8; usize::from(field.width)])
                .map_err(|e| ShimError::Failed(format!("{name}: {e}")))?;
        }

        // Zero is right for a real board and wrong here. `state` indexes the
        // module table, and on a real MajorBBS slot zero is `module00`: a
        // user arrives at the BBS's own menu and picks a module from it.
        // This host has no menu -- slot zero is `Registration::AbsentBbs` --
        // so a channel left at zero would arrive already handed back, and
        // the driver would close it on the first pass.
        //
        // A headless host puts the user straight into the module instead.
        // This used to happen by accident, because the first module
        // registered *at* zero and a zeroed `state` named it; reserving slot
        // zero is what made the difference visible.
        if let Some(index) = self.first_module_index() {
            self.users
                .set_state_mem(A::mem(machine), chan, index)
                .map_err(|e| ShimError::Failed(format!("state: {e}")))?;
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
        self.users.set_polrou_mem(A::mem(machine), chan, None)?;

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
        let at = A::ptr_offset(slot, self.users().user_layout().flags.at);
        let was = at
            .resolve(A::mem_ref(machine), 1)
            .map_err(|e| ShimError::Failed(e.to_string()))?[0];
        let now = if who.keys.is_master() {
            was | MASTER
        } else {
            was & !MASTER
        };
        at.write(A::mem(machine), &[now])
            .map_err(|e| ShimError::Failed(e.to_string()))?;

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
    /// Generic since Task 12: the three `machine.write` calls become
    /// `ModulePtr::write` against [`Abi::mem`].
    ///
    /// # Errors
    ///
    /// If a write runs off a segment.
    pub fn rstchn(&mut self, machine: &mut A::Cpu, chan: Chan) -> Result<(), ShimError> {
        self.users.clear_keys(chan);
        let user_stride = self.users.user_layout().stride;
        let account_stride = self.users.account_stride();
        // `extusr` is GCV2's, and this may be a host that has none. A missing
        // table is not a table of zero bytes: there is nothing to clear.
        let mut tables = vec![
            (self.users.slot(chan), user_stride),
            (self.users.account(chan), account_stride),
        ];
        if let (Some(at), Some(each)) = (self.users.extra(chan), users::extusr_stride::<A>()) {
            tables.push((at, each));
        }
        for (at, len) in tables {
            at.write(A::mem(machine), &vec![0u8; usize::from(len)])
                .map_err(|e| ShimError::Failed(e.to_string()))?;
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
    /// Generic since Task 12.
    ///
    /// # Errors
    ///
    /// If no module has registered. (A malformed `chan`, a write running off
    /// a segment, or the module being unenterable all poison the machine and
    /// come back as `Ok(Some(Outcome::Stopped(..)))` instead -- see above.)
    pub fn connect(
        &mut self,
        machine: &mut A::Cpu,
        module: &A::Module,
        chan: Chan,
        who: &users::Connection,
    ) -> io::Result<Option<Outcome<A>>> {
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
            match registered.dispatch(A::mem(machine), 0) {
                Ok(Dispatch::Module(rou)) => Ok(rou),
                // `first_module` never answers `Native` or `AbsentBbs`, but
                // the match stays exhaustive and the fallback stays correct
                // if that changes.
                Ok(Dispatch::Native(_)) | Ok(Dispatch::SessionOver) => Ok(None),
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
            let size = self.globals.word_mem(A::mem_ref(machine), "vdasiz")?;
            if let Err(e) = vda.write(A::mem(machine), &vec![0u8; usize::from(size)]) {
                return self
                    .shim_stop(machine, "clearing the volatile data area", ShimError::Failed(e.to_string()))
                    .map(Some);
            }
        }

        self.run(machine, module, lonrou, &[], Some(chan)).map(Some)
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
    /// `mjrfin`'s module sweep -- `MAJORBBS.C:4818-4831`:
    ///
    ///
    /// **The caller does `hupall` first.** This is the second half only, so
    /// that a driver can hang its channels up through whatever path it
    /// already has (`Host::hangup`, once per connected channel) rather than
    /// have a second one invented here.
    ///
    /// From index 1, because slot zero is [`Registration::AbsentBbs`] and the
    /// original's `module00` is the BBS rather than a module -- the same
    /// reason the vendor's own loop starts there. `nmods` is re-read every
    /// iteration, as the original's `i < nmods` does, so a `finrou` that
    /// registers something is not skipped.
    ///
    /// **Not calling this is not a neutral omission**, which is why it exists.
    /// MajorMUD's `_LJNGAME_FINROU` is where `_SAVE_BUFFERS(0)` runs and where
    /// `WCCRECOV.FLG` is unlinked; a host that never dispatches the vector
    /// loses every buffered change since the last `SECBUFF` sweep and leaves
    /// the recovery marker behind, so the next boot comes up in recovery mode
    /// with monster regeneration suppressed. That is a real board, observed:
    /// see `BUGS.md`.
    ///
    /// Returns the poison of the first module that stopped, and stops
    /// sweeping there -- a machine that has faulted cannot be asked to run
    /// the next module's shutdown on top of it.
    ///
    /// `dispatched` counts the vectors actually called, which is how a driver
    /// tells "every module shut down" from "no module had anything to do"
    /// without either looking like the other in a log. An out-parameter
    /// rather than a return value because [`Host::prcrtk`] already spells
    /// this exact pairing that way.
    ///
    /// # Errors
    ///
    /// If a registration's `struct module` no longer names memory the module
    /// owns.
    pub fn finalize(
        &mut self,
        machine: &mut A::Cpu,
        module: &A::Module,
        dispatched: &mut usize,
    ) -> io::Result<Option<A::Poison>> {
        /// `finrou`'s position in `struct module` after `descrp`. See
        /// [`Registration::dispatch`], whose own doc fixes the order.
        const FINROU: usize = 8;

        let mut index = 1;
        while index < self.modules().len() {
            let entry = self.modules()[index]
                .dispatch(A::mem(machine), FINROU)
                .map_err(|e| io::Error::other(e.to_string()))?;
            // Only a real module has a `finrou` to call. `Native` has no
            // `struct module` to index and `AbsentBbs` is the slot this loop
            // starts past; neither is a module with shutdown work to do.
            if let Dispatch::Module(Some(vector)) = entry {
                match self.run(machine, module, vector, &[], None)? {
                    Outcome::Stopped(poison) => return Ok(Some(poison)),
                    Outcome::Returned { .. } => *dispatched += 1,
                }
            }
            index += 1;
        }
        Ok(None)
    }

    /// Generic since Task 12.
    ///
    /// # Errors
    ///
    /// If no module has registered.
    pub fn hangup(
        &mut self,
        machine: &mut A::Cpu,
        module: &A::Module,
        chan: Chan,
    ) -> io::Result<Option<Outcome<A>>> {
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
    /// Generic since Task 12.
    ///
    /// # Errors
    ///
    /// If no module has registered.
    pub fn logoff(
        &mut self,
        machine: &mut A::Cpu,
        module: &A::Module,
        chan: Chan,
    ) -> io::Result<Option<Outcome<A>>> {
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
    ///
    /// Generic since Task 12: the `Poison::Unimplemented` literal this built
    /// for the refused `lofrou` retry becomes [`Abi::unimplemented`].
    fn disconnect(
        &mut self,
        machine: &mut A::Cpu,
        module: &A::Module,
        chan: Chan,
        vector: Vector,
    ) -> io::Result<Option<Outcome<A>>> {
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
                Ok(Dispatch::Native(_)) | Ok(Dispatch::SessionOver) => Ok(None),
                Err(e) => Err(e),
            },
            Vector::Hangup => {
                let registered = self.first_module().ok_or_else(|| {
                    io::Error::other(
                        "no module has registered, so there is nothing to disconnect from",
                    )
                })?;
                match registered.dispatch(A::mem(machine), vector.entry()) {
                    Ok(Dispatch::Module(rou)) => Ok(rou),
                    Ok(Dispatch::Native(_)) | Ok(Dispatch::SessionOver) => Ok(None),
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
            Some(rou) => Some(self.run(machine, module, rou, &[], Some(chan))?),
            None => None,
        };

        // `nxtlof`'s protocol; see [`Host::logoff`] for why a non-zero return
        // is refused rather than discarded. `huprou` is `void` and has no
        // protocol, so its words are not read.
        let outcome = match (vector, outcome) {
            (Vector::Logoff, Some(Outcome::Returned { lo: ax, .. })) if ax == 1 => {
                Some(self.stop(
                    machine,
                    A::unimplemented(
                        "mbbs".to_owned(),
                        format!(
                            "lofrou returned {}, asking to be called again, and this \
                             host has no second logoff pass to give it \
                             (MAJORBBS.C:4100)",
                            ax as i16
                        ),
                    ),
                )?)
            }
            (_, outcome) => outcome,
        };

        if let Err(e) = self.rstchn(machine, chan) {
            return self.shim_stop(machine, "rstchn", e).map(Some);
        }
        Ok(outcome)
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
    /// Generic since Task 12: [`Heap::reserve`] rather than the `Wg16`-only
    /// `Heap::alloc` facade Task 13 went on to delete outright -- its
    /// generic core already existed for this to call.
    ///
    /// # Errors
    ///
    /// If the heap has no room.
    pub fn alcvda(&mut self, machine: &mut A::Cpu) -> io::Result<()> {
        let size = self.globals.word_mem(A::mem_ref(machine), "vdasiz")?;
        if size == 0 {
            return Ok(());
        }
        self.users
            .alcvda_mem(A::mem(machine), &mut self.heap, size)?;
        let console = self
            .users
            .terms()
            .chan(0)
            .expect("every host has a channel zero");
        let area = self.users.vda(console).expect("just allocated");
        let temp = self
            .heap
            .reserve(A::mem(machine), size)
            .map_err(io::Error::other)?;
        self.globals
            .write_mem(A::mem(machine), "vdaptr", &A::ptr_to_bytes(area))?;
        self.globals
            .write_mem(A::mem(machine), "vdatmp", &A::ptr_to_bytes(temp))?;
        Ok(())
    }

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
    /// Generic since Task 12.
    ///
    /// # Errors
    ///
    /// If the volatile data areas cannot be allocated.
    pub fn finish_init(&mut self, machine: &mut A::Cpu) -> io::Result<()> {
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

/// Every distinct symbol `image` imports, however it is addressed.
///
/// A strict superset of [`addressed_as_data`]'s own keys: that function
/// walks the identical `Target::Import` relocations, filtering by *how* the
/// module reaches each one (`FAR_ADDR` -- a call -- excluded, everything
/// else counted as data), where this walks the same relocations and names
/// every one it finds, call sites included. Built for [`Host::load`]'s
/// pre-check pass, so that a cross-module *routine* import -- a call site,
/// which `addressed_as_data` never classifies as data at all -- still gets
/// resolved, and any resulting [`Why::NotExported`] recorded, before
/// `A::load` ever touches `cpu`. See that method's own doc comment.
fn imported_symbols(image: &NeImage) -> HashSet<(String, Symbol)> {
    let mut symbols = HashSet::new();
    for segment in &image.segments {
        for reloc in &segment.relocations {
            let Target::Import { module, symbol } = &reloc.target else {
                continue;
            };
            let Ok(from) = image.module_name(*module) else {
                continue;
            };
            symbols.insert((from.to_owned(), symbol.clone()));
        }
    }
    symbols
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

/// The C name of an imported symbol, or something that identifies it when
/// `exports` has no name for it (`"#42"` for an ordinal no table names).
///
/// A free function rather than only [`Host::symbol_name`] because
/// [`Resolver`] needs the identical computation and is not a `Host` --
/// see [`Resolver::resolve`]'s own doc comment for why the two used to
/// disagree (one gave up early on an unnamed ordinal, the other always
/// produced a display string) and why the fold requires them to agree.
fn symbol_name(exports: &Exports, from: &str, symbol: &Symbol) -> String {
    match symbol {
        Symbol::Name(name) => exports::c_name(name).into_string(),
        Symbol::Ordinal(n) => exports
            .name(from, *n)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("#{n}")),
    }
}

/// Answers "what is `MAJORBBS.474`?" for the loader -- and, folded in, what
/// used to be [`Host`]'s own separate `check_globals` pass.
///
/// Generic over `A` since Task 9 of
/// `docs/plans/2026-08-12-abi-border-implementation.md`. Both arms are
/// written: `Wg32::load` parses a `PeImage`, relocates it, binds imports and
/// arms the `__ftol` ST0 capture (`abi/wg32.rs`). Nothing about this type
/// assumes `Wg16` -- see [`Import`]/`Host::load`'s own doc comments for the
/// one arm (`reach`) that is NE-specific mechanism reused generically rather
/// than NE-specific *policy*.
struct Resolver<'a, A: Abi> {
    exports: &'a Exports,
    globals: &'a Globals<A>,

    /// Every module [`Host::load`] has already loaded in this life, by its
    /// own declared name -- see [`Host::loaded_modules`]'s own doc comment.
    /// Consulted only once the host's own tables (`exports`/`globals`, via
    /// `shims::entry`) have nothing to say about a symbol: **order matters**,
    /// and host tables go first, so a module can never shadow a host
    /// routine by declaring itself under a name like `MAJORBBS` and
    /// exporting a same-named symbol -- `shims::entry` is asked first every
    /// time, and this map is only ever reached when that answered
    /// [`Entry::Unimplemented`]. See [`Resolver::resolve`]'s own doc
    /// comment for the rest of the design, and [`Resolver::prefer`] for the
    /// one case where a library named there is consulted *before* host
    /// tables instead.
    loaded: &'a HashMap<String, A::Module>,

    /// Libraries this one load prefers an already-[`loaded`](Self::loaded)
    /// module's export over this host's own tables for -- see
    /// [`Host::load_with_precedence`]'s own doc comment for what this is for
    /// and the circularity it must never be used to create. Empty for every
    /// ordinary [`Host::load`] call, which is what keeps this a per-load
    /// opt-in rather than a change to `Resolver::resolve`'s default order.
    prefer: &'a [&'a str],

    /// How far into each data-addressed symbol this module's own
    /// relocations reach -- see [`addressed_as_data`]'s own doc comment.
    /// Always empty for anything that does not parse as an NE image (a PE
    /// image, today): there is no equivalent question a PE import table can
    /// answer, and `Host::load` builds this without knowing which ABI it is
    /// building it for -- see that method's own doc comment.
    reach: HashMap<(String, Symbol), Reach>,

    /// [`MissingGlobal`]s found during the walk, recorded here instead of
    /// through a second pass over the whole image -- this is the fold
    /// itself. `RefCell` because [`mbbs_machine::module::ImportResolver::resolve`]
    /// takes `&self` (shared with every other symbol this walk resolves,
    /// including ones cached and never re-asked -- see
    /// `mbbs_machine::m16::ne::Machine::map_ne`'s own doc comment on why a
    /// resolver is asked once per distinct symbol, not once per site).
    missing: std::cell::RefCell<Vec<MissingGlobal>>,
}

impl<A: Abi> mbbs_machine::module::ImportResolver<A::Ptr> for Resolver<'_, A> {
    /// # Cross-module imports: order matters
    ///
    /// A symbol is answered by, in this order: this host's own tables
    /// (`shims::entry`, unchanged from before this feature existed);
    /// failing that, [`Resolver::loaded`], a module this same `Host` already
    /// loaded earlier in this life. Host tables are consulted first and
    /// unconditionally -- never *because* the registry came up empty, but
    /// before it is ever asked -- so a loaded module can never shadow a host
    /// routine: `shims::entry("MAJORBBS", "spr")` always answers
    /// [`Entry::Routine`] before this method has any chance to notice that
    /// some other loaded module also happens to be named `MAJORBBS` and also
    /// happens to export something called `spr`.
    ///
    /// **Unless `module` is named in [`Resolver::prefer`]**, opted into per
    /// load through [`Host::load_with_precedence`] and empty for every
    /// ordinary [`Host::load`]. For a `prefer`-listed library, [`loaded`]
    /// is consulted *first*: if it names a module under that library and
    /// that module exports the requested symbol, its address is what this
    /// method answers, before `shims::entry` is ever asked. A `prefer` hit
    /// that finds no such module, or a loaded module that does not export
    /// the symbol, falls straight through to the ordinary order below rather
    /// than recording a miss of its own -- `prefer` names a library this
    /// load *wants* routed through a loaded module, not one it requires to
    /// be; declining silently and asking the host tables is the same
    /// graceful degradation an unheard-of module name already gets, not a
    /// new failure mode.
    ///
    /// A registry hit resolves to [`Import::Data`] -- not [`Import::Routine`]
    /// -- because it is not a host thunk: `Abi::export_address` hands back
    /// the target module's own code address, and the loader writes it into
    /// the fixup site directly, exactly as it would a host global's address.
    /// A call through that site never round-trips through this host at all;
    /// it is an ordinary far call into memory this same machine already
    /// owns. See [`Import::Data`]'s own doc comment for why that variant is
    /// the right one to reuse rather than adding a third that would behave
    /// identically.
    ///
    /// A registry *miss* -- the module is loaded, but does not export the
    /// requested ordinal or name -- records [`Why::NotExported`] the same
    /// way a `reach`-tracked datum records [`Why::NotPlaced`]. This is
    /// **not** gated behind `self.reach` the way the other two `Why` arms
    /// are: `reach` only ever contains symbols this module addresses *as
    /// data*, and every real case this feature exists for (`WCCMMPLS.DLL`'s
    /// `mmlog`, `retrieve_public_usrnum_userinfo`, ...) is a **call** site,
    /// never tracked by `reach` at all -- gating this check on `reach` the
    /// way the others are would make it unreachable for the exact imports it
    /// was built to catch.
    ///
    /// A module name `self.loaded` has never heard of at all is **not**
    /// treated as a miss -- see [`Why::NotExported`]'s own doc comment for
    /// why that would be wrong (indistinguishable from a host DLL this crate
    /// has not finished implementing, and today's graceful degradation for
    /// that case must not regress).
    fn resolve(&self, module: &str, symbol: &Symbol) -> Option<mbbs_machine::module::Import<A::Ptr>> {
        // One name computation, reused for both the miss check below and
        // the value this method returns -- `Resolver::resolve` used to
        // compute its own (via a fallible `self.exports.name(..)?`, which
        // gave up on an unnamed ordinal before ever asking `shims::entry`
        // about it), and `Host::check_globals` computed a second, always-
        // succeeding one (`Host::symbol_name`'s own `"#{n}"` fallback) for
        // display. Folding the two walks into one forces them onto the same
        // name, and the always-succeeding one is the right one to keep:
        // `shims::entry(module, "#42")` answers `Entry::Unimplemented` for
        // an ordinal no export table names, exactly as the fallible version
        // did by giving up early -- so the resolved *value* is identical
        // either way, and the miss-detection side gets a real symbol string
        // to report instead of silently skipping an ordinal it cannot name.
        let name = symbol_name(self.exports, module, symbol);

        // The precedence flip: only for a library this one load named in
        // `prefer` (see `Resolver::prefer`'s and this method's own doc
        // comments), and only when a module is actually loaded under that
        // name and actually exports the symbol -- otherwise this falls
        // through to the ordinary host-tables-first order below exactly as
        // if `prefer` had never named it.
        if self.prefer.contains(&module)
            && let Some(loaded) = self.loaded.get(module)
            && let Some(ptr) = A::export_address(loaded, symbol)
        {
            return Some(mbbs_machine::module::Import::Data(ptr));
        }

        let entry = shims::entry::<A>(module, &name);

        // Cross-module: host tables answered first, above, and only once
        // they came back empty is a loaded module even consulted -- see
        // this method's own doc comment, "Order matters". A module name the
        // registry has never heard of falls straight through to the
        // existing `reach`/`entry` handling below, completely unchanged.
        if matches!(entry, Entry::Unimplemented)
            && let Some(loaded) = self.loaded.get(module)
        {
            return match A::export_address(loaded, symbol) {
                Some(ptr) => Some(mbbs_machine::module::Import::Data(ptr)),
                None => {
                    self.missing.borrow_mut().push(MissingGlobal {
                        module: module.to_owned(),
                        symbol: name,
                        why: Why::NotExported,
                    });
                    None
                }
            };
        }

        // The fold: `Host::check_globals` used to walk `addressed_as_data`'s
        // whole map as a separate pass before any fixup was written. Here
        // it is the same check, run inline for whichever symbol this call
        // is already resolving -- only for a symbol this module's own
        // relocations address *as data* (`reach.get` answers at all only
        // for those; see `Reach`/`addressed_as_data`'s own doc comments).
        // `Why::TooSmall` can only ever be built here: nothing else in this
        // crate ever constructs a `Reach` to build one from, and `reach` is
        // unconditionally empty for a format that is not NE (see
        // `Host::load`'s own doc comment) -- which is what makes it
        // unreachable under `Wg32` by construction, not merely unexercised.
        if let Some(reach) = self.reach.get(&(module.to_owned(), symbol.clone())) {
            match entry {
                // A constant has no memory to be too small, and a routine
                // whose address is taken in pieces is a routine -- the
                // thunk's address is the right thing to write.
                Entry::Absolute(_) | Entry::Routine(..) => {}
                Entry::Unimplemented => self.missing.borrow_mut().push(MissingGlobal {
                    module: module.to_owned(),
                    symbol: name.clone(),
                    why: Why::NotPlaced,
                }),
                Entry::Datum => {
                    let size = self.globals.size(&name).expect("a datum is placed");
                    if reach.max >= i32::from(size) {
                        self.missing.borrow_mut().push(MissingGlobal {
                            module: module.to_owned(),
                            symbol: name.clone(),
                            why: Why::TooSmall {
                                addend: reach.max as i16,
                                size,
                            },
                        });
                    }
                }
            }
        }

        match entry {
            // A datum is addressed, never called, so the host's own memory goes
            // into the fixup and nothing is ever dispatched for it.
            Entry::Datum => Some(mbbs_machine::module::Import::Data(self.globals.address(&name)?)),
            Entry::Absolute(value) => Some(mbbs_machine::module::Import::Absolute(value)),
            Entry::Routine(..) => Some(mbbs_machine::module::Import::Routine),

            // The loader gives it a thunk anyway. That is what makes calling it
            // an event the host is told about rather than a far call into
            // nothing.
            Entry::Unimplemented => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::abi::{Abi, Wg16};
    use crate::testing::Fixture;
    use crate::users::Connection;
    use crate::{
        Clock, Dispatch, Duration, Ended, Host, Kick, Native, Outcome, PollCensus, Registration, Terms,
        gsbl, stall_note, testing, users,
    };
    use mbbs_machine::m16::{FarPtr, Machine, Poison, Ret};

    /// `genbb` is a *host* global. `MAJORBBS.C:999` fills it in with
    /// `dfaOpen("wgsgen2.dat",GENSIZ,NULL)` and modules dereference it without
    /// ever assigning it -- so a null one is not a quiet gap but the thing that
    /// stopped `WCCMMUD.DLL`'s init at `dfaInsertV`, which `DFAAPI.C` does not
    /// guard.
    ///
    /// This asserts the whole chain rather than just "the global is non-zero":
    /// a pointer that does not resolve to an open file, or resolves to a file
    /// of the wrong shape, would satisfy a null check and still hand the module
    /// something useless. The 55-byte record length is the assertion that
    /// actually discriminates -- it is `WGSGEN2.BCR`'s own `record=55`, and it
    /// is *not* `GENSIZ`. Conflating the two is a real failure mode with real
    /// artefacts: the `WGSGEN2.DAT` files this repo produced before this
    /// existed carry `reclen 8192`, the open-time buffer size written into the
    /// file as its record length.
    #[test]
    fn a_board_opens_its_own_generic_data_file_and_publishes_genbb() {
        let root = testing::scratch("genbb-published");
        let mut machine = Machine::new().expect("16-bit machine");
        let mut host = Host::<Wg16>::new(&mut machine, root.clone(), Terms::new(1)).expect("host");

        // Not the constructor's job -- see `Host::open_genbb`. Before the board
        // takes its startup step there is no file and no pointer.
        assert!(
            !root.join("WGSGEN2.DAT").exists(),
            "Host::new must not lay a file down in a module's own directory"
        );

        host.open_genbb(&mut machine);

        assert!(
            root.join("WGSGEN2.DAT").is_file(),
            "the board seeds its own generic data file: {:?}",
            host.notes()
        );
        let genbb = host
            .globals()
            .pointer_mem(Wg16::mem_ref(&machine), "genbb")
            .expect("genbb is placed");
        assert_ne!(
            genbb,
            crate::btrieve::Btrieve::<crate::btrieve::AbiMem<Wg16>>::null(),
            "the module reads this pointer and passes its value straight to \
             dfaSetBlk: {:?}",
            host.notes()
        );

        let file = host.btrieve.block(genbb).expect("genbb names an open file");
        assert_eq!(
            file.geometry().reclen,
            55,
            "WGSGEN2.BCR says record=55; GENSIZ (8192) is the open-time buffer, \
             not the file's record length"
        );
    }

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
        let sentinel = vec![0xffu8; usize::from(host.users().user_layout().stride)];
        for chan in host.users().terms().all() {
            machine
                .write(host.users().slot(chan), &sentinel)
                .expect("every channel has a whole user record to write");
        }
        for chan in host.users().terms().all() {
            for (what, at, len) in [
                (
                    "extusr",
                    host.users().extra(chan).expect("Wg16 is GCV2, extusr exists"),
                    users::extusr_stride::<Wg16>().expect("Wg16 is GCV2"),
                ),
                ("usracc", host.users().account(chan), host.users().account_stride()),
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
    fn the_host_buffers_cannot_drift_into_each_other_unnoticed() {
        // `Host::new` carves `spr`, `mdf`, `empty`, `l2as` and `scnmdf` out
        // of one allocated region, back to back:
        //
        //   spr    [0, spr_bytes)                  spr_bytes = SPR_BYTES * SPR_BUFFERS
        //   mdf    [spr_bytes, spr_bytes + 64)      64 -- `gmdnam`'s line, headroom over MDF_LINE(40)
        //   empty  [spr_bytes + 64, spr_bytes + 65) one NUL byte
        //   l2as   [spr_bytes + 65, spr_bytes + 65 + l2as_bytes)
        //   scnmdf [spr_bytes + 65 + l2as_bytes, .. + SCNMDF_BYTES)
        //
        // `scnmdf` was appended last, after `l2as`, precisely so that adding
        // it moved none of the four offsets this test was originally written
        // about -- see `Host::new`'s own comment.
        //
        // and `alloc_region` is asked for exactly `spr_bytes + 64 + 1 +
        // l2as_bytes + scnmdf_bytes` -- so these five add up to the *whole*
        // allocation, with
        // no padding anywhere between any of them. That was measured, not
        // assumed: shifting any one of the four offsets in `Host::new` by a
        // single byte passed every test in the repository (1448 lib/target
        // tests plus all 19 `--ignored` module tests). Every existing
        // `spr`/`l2as` test compares buffers against *each other* (rotation,
        // distinctness) or writes strings short enough that a shifted buffer
        // never reaches its true edge, so none of them can see a boundary
        // move.
        //
        // This test fills each region to its own *full declared length* with
        // a byte no other region uses, then reads every region back. A
        // one-byte shift in any offset means a full-length write into the
        // shifted region reaches one byte into its neighbour, and the
        // neighbour's own read-back shows the intruder's byte instead of its
        // own.
        //
        // Fill order is deliberately the *reverse* of address order: `l2as`,
        // then `mdf`, then `spr`. Every mutation this test is built to catch
        // shifts a region *forward*, spilling into whatever follows it in
        // memory -- so that following region's fill has to already be in
        // place, or its own later, correctly-placed fill would simply
        // overwrite the spillover and hide it. Filling high-to-low guarantees
        // each region is written only after everything above it already holds
        // its own pattern, so a forward spill is always the last write to
        // land and survives to the read-back below.
        //
        // `empty` is never written by this test -- `Host::new` writes its one
        // NUL byte during construction and nothing should touch it again.
        // Reading it back is the check for a shifted `mdf`: if `mdf`'s offset
        // moves forward by one, `mdf`'s full-length fill reaches exactly the
        // byte `empty` occupies (`spr_bytes + 64`, unaffected by `mdf`'s own
        // mutation), and the read-back no longer sees the NUL `Host::new` put
        // there. It also catches `empty`'s own offset moving forward by one:
        // `spr_bytes + 64 + 1` is `l2as`'s true first byte, so a shifted
        // `empty` field points at whatever `l2as`'s own fill wrote, not the
        // NUL `Host::new` wrote to the wrong place.
        let mut machine = Machine::new().expect("16-bit machine");
        let host =
            Host::<Wg16>::new(&mut machine, testing::data(), Terms::new(1)).expect("host");

        let spr_len =
            usize::from(crate::shims::text::SPR_BYTES) * crate::shims::text::SPR_BUFFERS;
        // Not a named constant anywhere -- it is `Host::new`'s own literal
        // (the gap between `mdf`'s offset and `empty`'s), reproduced here
        // rather than guessed.
        let mdf_len = 64usize;
        let l2as_len =
            usize::from(crate::shims::text::L2AS_BYTES) * crate::shims::text::L2AS_BUFFERS;
        let scnmdf_len = usize::from(crate::shims::msg::SCNMDF_BYTES);

        const SCNMDF_PATTERN: u8 = 0xD2;
        const L2AS_PATTERN: u8 = 0xC3;
        const MDF_PATTERN: u8 = 0xB4;
        const SPR_PATTERN: u8 = 0xA1;

        machine
            .write(host.scnmdf, &vec![SCNMDF_PATTERN; scnmdf_len])
            .expect("scnmdf's full declared length fits in the allocated region");
        machine
            .write(host.l2as, &vec![L2AS_PATTERN; l2as_len])
            .expect("l2as's full declared length fits in the allocated region");
        machine
            .write(host.mdf, &vec![MDF_PATTERN; mdf_len])
            .expect("mdf's full declared length fits in the allocated region");
        machine
            .write(host.spr, &vec![SPR_PATTERN; spr_len])
            .expect("spr's full declared length fits in the allocated region");

        let spr_read = machine.resolve(host.spr, spr_len).expect("read spr");
        assert!(
            spr_read.iter().all(|&b| b == SPR_PATTERN),
            "spr's own region was not entirely its own pattern: {spr_read:?}"
        );

        let mdf_read = machine.resolve(host.mdf, mdf_len).expect("read mdf");
        assert!(
            mdf_read.iter().all(|&b| b == MDF_PATTERN),
            "mdf's own region was not entirely its own pattern -- a neighbour's \
             buffer overlaps it: {mdf_read:?}"
        );

        let l2as_read = machine.resolve(host.l2as, l2as_len).expect("read l2as");
        assert!(
            l2as_read.iter().all(|&b| b == L2AS_PATTERN),
            "l2as's own region was not entirely its own pattern -- a neighbour's \
             buffer overlaps it: {l2as_read:?}"
        );

        let scnmdf_read = machine.resolve(host.scnmdf, scnmdf_len).expect("read scnmdf");
        assert!(
            scnmdf_read.iter().all(|&b| b == SCNMDF_PATTERN),
            "scnmdf's own region was not entirely its own pattern -- a \
             neighbour's buffer overlaps it: {scnmdf_read:?}"
        );

        let empty_read = machine.resolve(host.empty, 1).expect("read empty");
        assert_eq!(
            empty_read,
            &[0u8],
            "empty no longer holds the NUL byte Host::new wrote -- its offset, \
             or mdf's, has drifted into a neighbour"
        );
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
            ("user", f.host.users().slot(chan), f.host.users().user_layout().stride),
            (
                "extusr",
                f.host.users().extra(chan).expect("Wg16 is GCV2, extusr exists"),
                users::extusr_stride::<Wg16>().expect("Wg16 is GCV2"),
            ),
            ("usracc", f.host.users().account(chan), f.host.users().account_stride()),
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
        let mut host = Host::<Wg16>::new(&mut machine, testing::data(), Terms::new(3)).expect("host");

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
        let mut host = Host::<Wg16>::new(&mut machine, testing::data(), Terms::new(1)).expect("host");

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
                (f.host.users().slot(chan), f.host.users().user_layout().stride),
                (
                    f.host.users().extra(chan).expect("Wg16 is GCV2, extusr exists"),
                    users::extusr_stride::<Wg16>().expect("Wg16 is GCV2"),
                ),
                (f.host.users().account(chan), f.host.users().account_stride()),
            ] {
                f.machine
                    .write(at, &vec![mark(chan); usize::from(len)])
                    .expect("a whole record to dirty");
            }
        }

        let middle = chans[1];
        f.host.rstchn(&mut f.machine, middle).expect("reset");

        for (what, at, len) in [
            ("user", f.host.users().slot(middle), f.host.users().user_layout().stride),
            (
                "extusr",
                f.host.users().extra(middle).expect("Wg16 is GCV2, extusr exists"),
                users::extusr_stride::<Wg16>().expect("Wg16 is GCV2"),
            ),
            ("usracc", f.host.users().account(middle), f.host.users().account_stride()),
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
                ("user", f.host.users().slot(chan), f.host.users().user_layout().stride),
                (
                    "extusr",
                    f.host.users().extra(chan).expect("Wg16 is GCV2, extusr exists"),
                    users::extusr_stride::<Wg16>().expect("Wg16 is GCV2"),
                ),
                ("usracc", f.host.users().account(chan), f.host.users().account_stride()),
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
            err.to_string().contains("state 99") && err.to_string().contains("2 module(s)"),
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

    /// `drain_notes` hands over what `notes` was showing and leaves the list
    /// empty, so a caller reporting notes never reports one twice.
    ///
    /// Driven through a real note rather than by pushing onto the field: the
    /// point is that the reporting path and the recording path agree, and a
    /// test that writes `self.notes` directly would pass against a
    /// `drain_notes` that drained some *other* list.
    #[test]
    fn draining_notes_takes_them_and_leaves_none_behind() {
        let mut f = Fixture::new();
        let console = f.console();
        let module = f.minimal_module();
        let mut bytes = b"MajorMUD".to_vec();
        bytes.resize(25 + 9 * 4, 0);
        let block = f.bytes(&bytes, false);
        f.invoke(crate::shims::system::register_module, &Fixture::far(block))
            .expect("registered");

        f.host.gsbl_mut().push_input(console, b"look\r");
        f.host.poll(&mut f.machine, &module).expect("no fault");

        let seen = f.host.notes().to_vec();
        assert!(!seen.is_empty(), "the dropped command left a note to drain");

        assert_eq!(f.host.drain_notes(), seen, "the drain yields what was there");
        assert!(f.host.notes().is_empty(), "and leaves nothing behind");
        assert!(
            f.host.drain_notes().is_empty(),
            "a second drain with nothing recorded in between yields nothing"
        );
    }

    /// Draining must not reset `note_once`'s memory. Its promise is once per
    /// host, and a drain that cleared `noted` would turn every report into a
    /// licence for the next flood.
    #[test]
    fn draining_notes_does_not_re_arm_note_once() {
        let mut f = Fixture::new();
        f.host.note_once("a-key", "the first and only time".to_owned());
        assert_eq!(f.host.drain_notes().len(), 1, "recorded once");

        f.host.note_once("a-key", "the first and only time".to_owned());
        assert!(
            f.host.drain_notes().is_empty(),
            "the same key after a drain must still be suppressed"
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
    /// Through [`Users::slot`] and `UserLayout::state` rather than a setter,
    /// because production code never assigns a state -- `register_module`
    /// hands the number back and the module stores it itself, at 14 sites in
    /// `WCCMMUD.DLL`. A test that wrote it any other way would be agreeing with
    /// [`Users::state`] about an offset instead of checking it.
    fn set_state(f: &mut Fixture, chan: crate::Chan, state: u16) {
        let slot = f.host.users().slot(chan);
        let at = FarPtr {
            offset: slot.offset + users::UserLayout::of::<Wg16>().state.at,
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
                .state_entry(&mut f.machine, console, 1)
                .expect("readable")
                .expect("no ShimError"),
            Dispatch::Native(Native::Fsd),
        );
        set_state(&mut f, console, module_state);
        assert_eq!(
            f.host
                .state_entry(&mut f.machine, console, 1)
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

    /// The design doc's own standing rule, restated as a test:
    /// `docs/plans/2026-08-08-fsd-subsystem-design.md`, "The standing
    /// rule" --
    ///
    /// ```text
    /// channel in an FSD session, mid-field, no input delivered
    ///   -> cycle(max) returns Ended::Idle, not Bound
    /// ```
    ///
    /// A channel mid-FSD-session with nothing left in `channel.input` must
    /// leave `cycle` idle, not spend its whole pass budget getting nowhere.
    ///
    /// Measured, not assumed -- three mutations of `shims::fsd::fsd_cycle`
    /// were actually run, because the design doc warns that this assertion
    /// "passes trivially against a spinning implementation until the
    /// implementation is made to spin on purpose":
    ///
    /// 1. Re-arm `CYCLE` unconditionally, every pass (an unconditional
    ///    `host.gsbl_mut().inject(chan, gsbl::Gsbl::CYCLE);` right before
    ///    `fsd_cycle`'s final `Ok(())`). This does **not** come back
    ///    `Bound { next_kick: None }` after five iterations -- `Host::poll`'s
    ///    own pre-existing runaway guard (`SPINS = 1024`, `lib.rs` ~1943-1953,
    ///    predates this task entirely) fires first, from *inside* the single
    ///    `poll()` call this test's first `cycle()` iteration makes, and
    ///    `cycled` comes back `Err("poll went round 1024 times without
    ///    dispatching to the module: a status is being read but not
    ///    consumed")` -- the `assert_eq!` below is never reached.
    /// 2. Re-arm `CYCLE` a *bounded* number of times instead (measured at 1,
    ///    10, and 1020 re-arms, all well under 1024): every one of them still
    ///    converges to `Cycles { iterations: 1, dispatched: 0, ended: Idle }`
    ///    -- the right answer, just reached by wasting extra spins inside
    ///    that same `poll()` call. This is not a fluke of the numbers tried:
    ///    `fsd_dispatch` always answers "no far pointer" for the FSD's native
    ///    slot (see its own doc, above `Host::fsd_dispatch`), so `poll`'s
    ///    inner loop `continue`s on every dispatch to this channel and cannot
    ///    return until `Gsbl::pending()` is already false -- so
    ///    `Host::cycle`'s outer loop can only ever see `iterations == 1`
    ///    here. **`Ended::Bound` is not reachable at all** from a bounded
    ///    `CYCLE`-re-arm bug confined to this one channel: it either resolves
    ///    correctly (Idle) or trips the unrelated SPINS guard: there is no
    ///    bounded mutation in between that lands on `Bound`.
    /// 3. What *does* trip the `assert_eq!` below on its own terms, nowhere
    ///    near `poll`'s spin counter: leaving a stale [`shims::system::Kick`]
    ///    registered in `host.kicks` instead of consuming or clearing it (one
    ///    unconditional push, right before `fsd_cycle`'s final `Ok(())`).
    ///    `Host::cycle` only reports `Ended::Idle` off an *empty*
    ///    `self.kicks`; with one left behind it reports
    ///    `Ended::Waiting { next_kick: 3, polls_cut: true }` on the very
    ///    first iteration instead, which the assertion below catches
    ///    cleanly: `Cycles { iterations: 1, dispatched: 0, ended: Waiting {
    ///    next_kick: 3, polls_cut: true } }`.
    ///
    /// So this test's own assertion cannot discriminate the specific
    /// "spins on CYCLE" shape the design doc's prose describes -- that shape
    /// is caught by `poll`'s pre-existing SPINS guard instead, one layer
    /// down -- but it does have real, measured discriminating power against
    /// a channel-scoped regression of comparable severity (mutation 3).
    #[test]
    fn a_channel_mid_field_with_no_input_goes_idle_not_bound() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let chan = f.console();
        f.host
            .point_curusr(&mut f.machine, chan)
            .expect("channel 0 is current");

        let name = f.text("FSDFORM.MSG");
        let opened = f
            .invoke(crate::shims::msg::opnmsg, &Fixture::far(name))
            .expect("opened");
        assert!(matches!(opened, Ret::Far(_)));

        let spec = f.text("NAME RANK");
        let Ok(Ret::U16(size)) =
            f.invoke(crate::shims::fsd::fsdroom, &[0, spec.offset, spec.selector, 0])
        else {
            panic!("fsdroom refused")
        };
        let buffer = f.buffer(size);
        let defaults = f.bytes(b"\0", false);
        f.invoke(crate::shims::fsd::fsdapr,
            &[
                buffer.offset,
                buffer.selector,
                size,
                defaults.offset,
                defaults.selector,
            ],
        )
        .expect("prepared");
        f.invoke(crate::shims::fsd::fsdego, &[0, 0, 0, 0])
            .expect("handed the channel to the FSD");

        // Enough to fill part of a field, deliberately with no `\r` --
        // real, pending work (an unfinished keystroke) that fsd_cycle must
        // drain, but nothing left in `channel.input` once it has.
        f.host.gsbl_mut().push_input(chan, b"Kai");

        let cycles = f.host.cycle(&mut f.machine, &module, &mut || false).expect("cycled");
        assert_eq!(
            cycles.ended,
            Ended::Idle,
            "a channel mid-field with no input left must go Idle, not spin to the bound: {cycles:?}"
        );
        assert_eq!(cycles.iterations, 1, "the one queued CYCLE is drained on the first pass");
    }

    /// A `state` naming a slot nobody registered stops with a reason.
    ///
    /// Falling back to module 0 would deliver another module's keystrokes to
    /// MajorMUD, which from outside looks like a module that ignored its input
    /// -- the least diagnosable failure this host could choose.
    /// Slot zero is the BBS this host does not have, so a channel whose
    /// `state` names it has been handed back to nothing, and the driver
    /// should close it.
    ///
    /// `MENUING.C:390` is where zero is the vendor's own test:
    /// `for (i=0 ; i < XTRIES && usrptr->state != 0 ; i++)`, with `:397`
    /// returning `usrptr->state == 0` -- "did the module let go?". So this
    /// is the documented handback, not an invention here.
    ///
    /// MajorMUD's own "[X] Exit Game" does *not* use it. Measured on a live
    /// board, a channel's `state` goes to one at connect and never returns
    /// to zero, which is why pressing X leaves you sitting at the menu
    /// instead of disconnected. That is a gap in what this host can detect,
    /// not a reason for the mechanism to be wrong.
    #[test]
    fn a_channel_handed_back_to_the_absent_bbs_is_reported_as_ended() {
        let mut f = Fixture::new();
        let console = f.host.gsbl().terms().chan(0).expect("channel 0");

        set_state(&mut f, console, 1);
        f.host.sweep_ended(&mut f.machine);
        assert!(
            f.host.drain_ended().is_empty(),
            "a channel inside a module has not been handed back"
        );

        set_state(&mut f, console, 0);
        f.host.sweep_ended(&mut f.machine);
        assert_eq!(
            f.host.drain_ended(),
            vec![console],
            "state 0 names the absent BBS, so the session is over"
        );
        assert!(
            f.host.drain_ended().is_empty(),
            "draining twice must not report the same channel again"
        );
    }

    #[test]
    fn poll_refuses_a_state_that_names_no_registered_module() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let console = f.console();

        let stub = returns_stub(1);
        let sttrou = f.machine.code_ptr(0);
        register_named(&mut f, "only", &[(1, sttrou)]);
        f.machine.load_code(&stub).expect("the stub fits");

        // Slot 0 is `Registration::AbsentBbs`, the menuing system this host
        // does not have, and `Fixture::new` -> `finish_init` has taken slot 1
        // for the FSD -- so three slots are occupied (the absent BBS, the
        // FSD, then "only") and the count the error names has grown to match.
        set_state(&mut f, console, 3);
        f.host.gsbl_mut().push_input(console, b"look\r");
        let err = f
            .host
            .poll(&mut f.machine, &module)
            .expect_err("state 3 names nothing");
        let text = err.to_string();
        assert!(
            text.contains("state 3") && text.contains("3 module(s)"),
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
        let cycles = f.host.cycle(&mut f.machine, &module, &mut || false).expect("cycled");

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
    ) -> (Fixture, mbbs_machine::m16::Module, crate::Chan) {
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
            Outcome::Returned { lo: 0xffff, hi: 0 },
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
            Some(Outcome::Returned { lo: 0, hi: 0 }),
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
                lo: u32::from(b'r'),
                hi: 0
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
                lo: u32::from(b'K'),
                hi: 0
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
        let stale = mbbs_machine::m16::FarPtr {
            offset: 0x2184,
            selector: 0x1010,
        };
        f.host
            .users
            .set_polrou_mem(f.machine.mem_mut(), console, Some(stale))
            .expect("channel 0");

        f.host
            .connect_state(
                &mut f.machine,
                console,
                &crate::users::Connection::ansi("somebodyelse"),
            )
            .expect("connected");

        assert_eq!(
            f.host.users().polrou_mem(f.machine.mem(), console).expect("channel 0"),
            None,
            "the new user must not inherit the old user's poll routine"
        );
    }

    /// A polling routine is a `void (*)(void)`, so the smallest real one is a
    /// single `retf`. `load_code` puts it somewhere the machine will execute
    /// and `code_ptr` addresses it.
    fn polling_fixture() -> (crate::testing::Fixture, mbbs_machine::m16::Module, FarPtr) {
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
    fn polling_fixture_with(count: u16) -> (crate::testing::Fixture, mbbs_machine::m16::Module, FarPtr) {
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
            .set_polrou_mem(f.machine.mem_mut(), console, Some(rou))
            .expect("channel 0");
        f.host.refill_polls(&mut f.machine, 2).expect("armed");

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
        let lo = slot.offset + crate::users::UserLayout::of::<Wg16>().polrou.at;

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
            .set_polrou_mem(f.machine.mem_mut(), console, Some(rou))
            .expect("channel 0");
        // A budget, and it is what makes this test a test at all. `dopoll`'s
        // re-arm is gated `polls_left > 0 && ..`, so at the default budget of
        // zero the whole branch is skipped and the fresh read of `polrou`
        // inside it never runs. Deleting that read outright then passed all
        // 781 lib tests and all 17 real-module tests -- the budget silently
        // defanged the one test that protects it.
        f.host.refill_polls(&mut f.machine, 4).expect("armed");

        let outcome = f.host.poll(&mut f.machine, &module).expect("polled");

        assert!(
            matches!(outcome, Some(Outcome::Returned { .. })),
            "got {outcome:?}"
        );
        assert_eq!(
            f.host.users().polrou_mem(f.machine.mem(), console).expect("channel 0"),
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


    /// **The channel scan is not a `syscyc` trigger, and the clock is.**
    ///
    /// `MAJORBBS.C:419-424` fires the vector whenever the scan does not
    /// advance, and this host did too until 2026-08-20. That call could not
    /// advance MajorMUD's world by a single tick the per-second call does not:
    /// `_MAJORMUD_SYSCYC` sets a gate with `|= 1` and `_BACKGROUND_FAST` --
    /// an `rtkick` heartbeat -- tests and clears it at 1 Hz, so setting it
    /// once and setting it a thousand times between two heartbeats are
    /// indistinguishable. What it *did* do was tie the vector's rate to the
    /// pump's cadence, which is a function of socket traffic rather than of
    /// time, and made every measurement of this host depend on load.
    ///
    /// The vendor could not make this separation: on Worldgroup 3.3 NT
    /// `syscyc` *was* the I/O pump (`TCPIP.C:420` chains a zero-timeout
    /// `select()` onto it). Here tokio owns I/O and the vector carries only
    /// the module's gate.
    ///
    /// `Fixture::new` hands out a real, advancing [`Clock::system`] --
    /// `Host::new` installs one, and nothing about a fixture changes that.
    /// This test pins it, so no second can elapse across the four calls
    /// below and the per-second site cannot fire -- which is exactly what
    /// makes `dispatched == 0` discriminate Site A's absence. Without the
    /// pin the test would still usually pass (four in-process calls finish
    /// in microseconds), but "usually" is not a proof, and a scheduling
    /// stall spanning a wall-clock second would make the per-second site
    /// fire legitimately and fail the assertion for a reason that has
    /// nothing to do with what this test exists to check.
    #[test]
    fn cycle_does_not_fire_syscyc_merely_because_the_scan_did_not_advance() {
        let (mut f, module, rou) = polling_fixture();
        f.host.set_clock(Clock::pinned(1_135_952_405));

        // Install a vector, as a module's init routine does.
        let mut bytes = [0u8; 4];
        bytes[0..2].copy_from_slice(&rou.offset.to_le_bytes());
        bytes[2..4].copy_from_slice(&rou.selector.to_le_bytes());
        f.host
            .globals()
            .write(&mut f.machine, "syscyc", &bytes)
            .expect("syscyc is a placed global");

        for turn in 0..4 {
            let cycles = f
                .host
                .cycle(&mut f.machine, &module, &mut || false)
                .expect("ran");
            assert_eq!(
                cycles.dispatched, 0,
                "turn {turn}: the clock did not move, so an installed syscyc \
                 vector must not be called -- an idle scan is not a trigger"
            );
        }
    }

    /// A registered task runs on every cycle, and keeps running -- that is
    /// what separates it from a `Kick`, which fires once and is consumed.
    /// `The Rose 2.0` registers one at init and expects it every cycle
    /// thereafter.
    #[test]
    fn prctask_runs_every_registered_task_every_time() {
        let (mut f, module, rou) = polling_fixture();

        let mut fired = 0;
        assert_eq!(f.host.prctask(&mut f.machine, &module, &mut fired).expect("ran"), None);
        assert_eq!(fired, 0, "nothing registered, nothing run");

        f.host.tasks.push(rou);
        assert_eq!(f.host.prctask(&mut f.machine, &module, &mut fired).expect("ran"), None);
        assert_eq!(fired, 1, "the registered task runs");

        assert_eq!(f.host.prctask(&mut f.machine, &module, &mut fired).expect("ran"), None);
        assert_eq!(fired, 2, "and again -- a task is not consumed the way a kick is");
        assert_eq!(f.host.tasks.len(), 1, "and stays registered");
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
    fn a_cycle_with_nothing_to_do_ends_idle_on_the_first_pass() {
        let (mut f, module, _rou) = polling_fixture();
        let cycles = f.host.cycle(&mut f.machine, &module, &mut || false).expect("cycled");
        assert_eq!(cycles.ended, Ended::Idle);
        assert_eq!(cycles.dispatched, 0);
        assert_eq!(cycles.iterations, 1, "it works that out on the first pass");
    }

    /// A caller that asks for the thread back gets it, on the pass it asks.
    ///
    /// This replaces `a_polling_channel_ticks_until_the_bound`, which pinned
    /// the `max` parameter. That count was a proxy for "has input arrived?"
    /// and a bad one; the predicate is the signal itself, so the count and
    /// the test that measured it both went.
    #[test]
    fn a_cycle_hands_the_thread_back_when_the_interrupt_asks() {
        let (mut f, module, rou) = polling_fixture();
        let console = f.console();
        f.host.users.set_polrou_mem(f.machine.mem_mut(), console, Some(rou)).expect("channel 0");
        f.host.refill_polls(&mut f.machine, 1_000).expect("armed");

        let mut asks = 0;
        let cycles = f
            .host
            .cycle(&mut f.machine, &module, &mut || {
                asks += 1;
                asks >= 3
            })
            .expect("cycled");

        assert_eq!(cycles.iterations, 3, "the interrupt is what stopped it");
        assert_eq!(cycles.dispatched, 3, "one tick a pass, self-sustaining");
        assert_eq!(cycles.ended, Ended::Bound { next_kick: None });
        // The status queue must not have grown while all that happened.
        assert_eq!(f.host.gsbl_mut().next_status(console), Some(gsbl::Gsbl::POLSTS));
        assert_eq!(f.host.gsbl_mut().next_status(console), None);
    }

    /// The same question as
    /// `next_kick_is_the_soonest_of_several_and_not_merely_one_of_them`, asked
    /// of the other place that answers it.
    ///
    /// `cycle` computes `next_kick` at two sites: the early return, when
    /// nothing is queued, and the `interrupted()` arm, when the caller asks
    /// for the thread back with work still going. A fixture with nothing
    /// polling can only ever reach the first. Review found the second by
    /// mutating it alone to `.max()` and watching all 774 tests stay green --
    /// the two sites are the same arithmetic written twice, which is how call
    /// sites drift apart.
    #[test]
    fn the_bound_reports_the_soonest_kick_too() {
        let (mut f, module, rou) = polling_fixture();
        let console = f.console();
        f.host.set_clock(Clock::pinned(1_135_952_405));
        f.host.users.set_polrou_mem(f.machine.mem_mut(), console, Some(rou)).expect("channel 0");
        f.host.refill_polls(&mut f.machine, 1_000).expect("armed");
        f.host.kicks.push(Kick { delay: 300, dstrou: rou });
        f.host.kicks.push(Kick { delay: 7, dstrou: rou });
        f.host.kicks.push(Kick { delay: 45, dstrou: rou });

        // A polling channel keeps `pending()` true, so the early return is
        // never taken and the interrupt is what ends the call -- which is the
        // only way to reach the `Bound` arm at all.
        let mut asks = 0;
        let cycles = f
            .host
            .cycle(&mut f.machine, &module, &mut || {
                asks += 1;
                asks >= 20
            })
            .expect("cycled");

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
            let cycles = f.host.cycle(&mut f.machine, &module, &mut || false).expect("cycled");
            assert_eq!(
                cycles.iterations, 1,
                "nothing is ever pending here, so every call returns on its first pass"
            );
            dispatched += cycles.dispatched;
        }

        assert_eq!(dispatched, 1, "the kick fired, once");
        assert_eq!(calls, 4, "two reads to the second, two seconds to the kick");
        let cycles = f.host.cycle(&mut f.machine, &module, &mut || false).expect("cycled");
        assert_eq!(cycles.ended, Ended::Idle, "and then there was nothing left");
    }

    /// A cycle that spanned four seconds owes the module four ticks, not one.
    ///
    /// MajorMUD's own timer queue is clocked by a counter it advances inside
    /// `_BACKGROUND_FAST`, in the branch it takes only when `syscyc` has set
    /// its gate -- and that branch clears the gate. `_BACKGROUND_FAST` is an
    /// ordinary `rtkick` heartbeat, so a `cycle` spanning N seconds fires it N
    /// times; if the gate was set once, the module counts one tick and the
    /// other N-1 are gone for good. Its clock then runs slow by however long a
    /// cycle takes, which is what left monsters dead.
    ///
    /// Counted by difference rather than by a probe: the same run with the
    /// vector installed and with it absent differ by exactly the syscyc
    /// dispatches, and nothing else in the run changes.
    #[test]
    fn a_cycle_spanning_four_seconds_fires_syscyc_once_per_second() {
        let dispatches = |install: bool, elapsed: u32| {
            let (mut f, module, rou) = polling_fixture();
            if install {
                let mut bytes = [0u8; 4];
                bytes[0..2].copy_from_slice(&rou.offset.to_le_bytes());
                bytes[2..4].copy_from_slice(&rou.selector.to_le_bytes());
                f.host
                    .globals()
                    .write(&mut f.machine, "syscyc", &bytes)
                    .expect("syscyc is a placed global");
            }
            // A pinned clock, moved by hand: the first call syncs `tcklst`,
            // then `elapsed` seconds pass with the driver asleep -- exactly
            // what `Ended::Waiting` tells it to do -- and the next call has
            // all of them to catch up in one go.
            f.host.set_clock(Clock::pinned(1_135_952_405));
            f.host.cycle(&mut f.machine, &module, &mut || false).expect("first");
            f.host.set_clock(Clock::pinned(1_135_952_405 + elapsed));
            f.host.cycle(&mut f.machine, &module, &mut || false).expect("second").dispatched
        };
        let fired = |elapsed| dispatches(true, elapsed) - dispatches(false, elapsed);

        // One per elapsed second, ahead of that second's kicks -- and nothing
        // else. `MAJORBBS.C:421`'s idle-pass call (fired whether or not a
        // second had passed) was deleted 2026-08-20; see
        // `cycle_does_not_fire_syscyc_merely_because_the_scan_did_not_advance`.
        assert_eq!(fired(1), 1, "one second: that second's call, nothing more");
        assert_eq!(fired(4), 4, "four seconds: four calls, one per second");

        // The scaling is the whole point. A constant here -- which is what
        // firing once per `cycle` gave -- means the module loses every second
        // but the first out of any cycle that spans several.
        assert_eq!(
            fired(4) - fired(1),
            3,
            "three extra seconds must buy three extra ticks, not nothing"
        );
    }

    /// A caller that always wants the thread back still gets a second of the
    /// module's time on every call. The interrupt is consulted after the tick
    /// catch-up precisely so that a fast typist cannot stop the world.
    #[test]
    fn an_always_interrupting_caller_still_runs_the_tick_catch_up() {
        let (mut f, module, rou) = polling_fixture();
        let mut bytes = [0u8; 4];
        bytes[0..2].copy_from_slice(&rou.offset.to_le_bytes());
        bytes[2..4].copy_from_slice(&rou.selector.to_le_bytes());
        f.host
            .globals()
            .write(&mut f.machine, "syscyc", &bytes)
            .expect("syscyc is a placed global");
        f.host.set_clock(Clock::stepped(1_135_952_405, 1_000));

        // First call syncs `tcklst`; the second owes a second of time work.
        let _ = f.host.cycle(&mut f.machine, &module, &mut || true).expect("first");
        let cycles = f.host.cycle(&mut f.machine, &module, &mut || true).expect("second");

        assert!(
            cycles.dispatched >= 1,
            "a cycle cut short on its first pass must still have run that \
             pass's syscyc/prcrtk catch-up; dispatched was {}",
            cycles.dispatched
        );
    }

    /// `ticker` (`globals.rs`'s own doc comment on the datum) advances once
    /// per elapsed real second -- the same round `syscyc`/`prcrtk` already
    /// fire in, driven by `cycle`'s own `tcklst` reconciliation -- and NOT
    /// once per `cycle` call, which would make the module's own "difference
    /// reflects elapsed time" arithmetic (the GSBL guide's own words for
    /// this datum) wrong the moment a driver's poll cadence changed.
    ///
    /// Same two-call shape as `a_cycle_spanning_four_seconds_fires_syscyc_once_per_second`
    /// just above: the first call only syncs `tcklst` (nothing has elapsed
    /// yet within it), then the clock is moved by hand and a second call
    /// owes the module everything that "elapsed" in between, in one go.
    #[test]
    fn ticker_advances_once_per_elapsed_second_not_once_per_cycle_call() {
        let (mut f, module, _rou) = polling_fixture();

        f.host.set_clock(Clock::pinned(1_135_952_405));
        f.host.cycle(&mut f.machine, &module, &mut || false).expect("first call syncs tcklst");
        let before = f.host.globals().word(&f.machine, "ticker").expect("ticker is a placed global");

        f.host.set_clock(Clock::pinned(1_135_952_405 + 4));
        f.host.cycle(&mut f.machine, &module, &mut || false).expect("second call owes four seconds");
        let after = f.host.globals().word(&f.machine, "ticker").expect("read");

        assert_eq!(
            after.wrapping_sub(before),
            4,
            "four elapsed seconds must advance ticker by exactly four -- not by one \
             (once per cycle call) and not by ten (once per poll pass, the cycle's own bound)"
        );
    }

    /// The vendor's own contract: "after it reaches 65535, it goes back to 0
    /// and starts over again" (GSBL Development Guide, quoted in
    /// `globals.rs`'s own doc comment on `ticker`). A plain `+ 1` here would
    /// panic on overflow in a debug build the moment this boundary was
    /// crossed -- this seeds the global one below the wrap and proves the
    /// landing value, not merely that nothing panicked.
    #[test]
    fn ticker_wraps_from_65535_to_zero_the_way_a_ushort_does() {
        let (mut f, module, _rou) = polling_fixture();

        f.host.set_clock(Clock::pinned(1_135_952_405));
        f.host.cycle(&mut f.machine, &module, &mut || false).expect("first call syncs tcklst");
        f.host
            .globals()
            .write(&mut f.machine, "ticker", &65535u16.to_le_bytes())
            .expect("ticker is a placed global");

        f.host.set_clock(Clock::pinned(1_135_952_405 + 1));
        f.host.cycle(&mut f.machine, &module, &mut || false).expect("one more second elapses");

        assert_eq!(
            f.host.globals().word(&f.machine, "ticker").expect("read"),
            0,
            "65535 + 1 wraps to 0, not a panic and not 65536"
        );
    }

    /// A poll routine that does nothing is counted as having done nothing.
    ///
    /// The fixture's routine is a single `retf`, which is exactly the shape
    /// the census exists to find: the module took a full emulated far call,
    /// reached no host routine at all, and returned. Five budgeted polls, five
    /// dispatches, five barren -- and `dopoll` re-armed after every one of
    /// them regardless, which is the behaviour that makes the count worth
    /// having.
    #[test]
    fn polls_that_reach_no_host_routine_are_counted_as_barren() {
        let (mut f, module, rou) = polling_fixture();
        let console = f.console();
        f.host
            .users
            .set_polrou_mem(f.machine.mem_mut(), console, Some(rou))
            .expect("channel 0");
        f.host.set_clock(Clock::pinned(1_135_952_405));
        f.host.refill_polls(&mut f.machine, 5).expect("armed");

        let cycles = f.host.cycle(&mut f.machine, &module, &mut || false).expect("cycled");
        let census = f.host.take_census();

        assert_eq!(cycles.dispatched, 5, "the budget bought five dispatches");
        assert_eq!(census.polls, 5, "and the census saw all five");
        assert_eq!(census.barren, 5, "a bare retf reaches no host routine");
        assert_eq!(census.calls, 0);
        assert_eq!(census.worst, 0);
        assert!((census.barren_pct() - 100.0).abs() < f64::EPSILON);

        assert_eq!(
            f.host.take_census(),
            PollCensus::default(),
            "taking it clears it, so a reporter measures an interval and not all time"
        );
    }

    /// The ratios are per-poll, not per-call, and a census that counted
    /// nothing answers zero rather than dividing by it.
    #[test]
    fn census_ratios_divide_by_polls_and_tolerate_an_empty_census() {
        let census = PollCensus { polls: 4, barren: 1, calls: 10, worst: 7 };

        assert!((census.per_poll() - 2.5).abs() < 1e-9, "ten calls over four polls");
        assert!((census.barren_pct() - 25.0).abs() < 1e-9, "one of four");

        let empty = PollCensus::default();
        assert!(empty.per_poll().abs() < f64::EPSILON);
        assert!(empty.barren_pct().abs() < f64::EPSILON);
    }

    /// Sleeping correctly is not stalling, and is not reported as it.
    ///
    /// `tcklst` persists across `cycle` calls, and the catch-up loop compares
    /// it against the clock on the *first pass of the next call*. Between two
    /// calls the driver is asleep -- that is the whole point of
    /// `Ended::Waiting` -- so `rounds` counts sleep and work alike. Reporting
    /// it as a stall reported the healthy case, and the healthier the sleep
    /// the louder the report: every note on a live board read "2 seconds",
    /// the signature of a two-second sleep rather than of any real work,
    /// and `e0ae785` and `0903399` both built conclusions on that flood.
    ///
    /// Nothing is pending in this fixture and both calls return on their
    /// first pass having dispatched nothing, so the two seconds are pure
    /// sleep with no work anywhere to attribute them to.
    #[test]
    fn two_seconds_of_correct_sleep_are_not_reported_as_a_stall() {
        let (mut f, module, rou) = polling_fixture();
        f.host.kicks.push(Kick { delay: 60, dstrou: rou });
        f.host.set_clock(Clock::pinned(1_135_952_405));

        let first = f.host.cycle(&mut f.machine, &module, &mut || false).expect("cycled");
        assert_eq!(first.iterations, 1, "nothing pending; one pass");
        f.host.drain_notes();

        // The driver sleeps. It was told a kick was 60 seconds out, and it
        // woke two seconds later on input that turned out to be nothing.
        f.host.set_clock(Clock::pinned(1_135_952_405 + 2));

        let second = f.host.cycle(&mut f.machine, &module, &mut || false).expect("cycled");
        assert_eq!(second.iterations, 1, "still nothing pending; still one pass");
        assert_eq!(second.dispatched, 0, "and nothing was dispatched at all");

        let notes = f.host.notes().to_vec();
        assert!(
            !notes.iter().any(|n| n.contains("stalled")),
            "two seconds of sleep is not a stall; got {notes:?}"
        );
    }

    /// ...and a pass that really does take a second says so, and names who.
    ///
    /// The counterpart to
    /// [`two_seconds_of_correct_sleep_are_not_reported_as_a_stall`]: the note
    /// has to survive as a signal for the case it was named for, or removing
    /// the false positive would just have deleted the diagnostic instead of
    /// correcting it.
    #[test]
    fn a_pass_that_really_took_a_second_is_reported_and_names_the_channel() {
        let note = stall_note(Duration::from_millis(1_100), 2, Terms::new(4).chan(3))
            .expect("1.1s of work in one pass is a stall");

        assert!(note.contains("1.1s"), "it must say how long: {note}");
        assert!(note.contains("channel 3's poll"), "and who: {note}");
    }

    /// The threshold is a floor on *work*, so work below it is silent no
    /// matter how many seconds of timers the catch-up fired -- which is the
    /// whole distinction the old note could not draw.
    #[test]
    fn a_fast_pass_is_silent_however_many_timer_rounds_it_fired() {
        assert_eq!(
            stall_note(Duration::from_millis(3), 6, Terms::new(1).chan(0)),
            None,
            "three milliseconds of work is not a stall, even six seconds behind"
        );
    }

    /// A stall with nothing dispatched belongs to the kick sweep, and saying
    /// "channel" there would name a channel that did nothing.
    #[test]
    fn a_stall_with_no_channel_polled_names_the_kick_sweep() {
        let note = stall_note(Duration::from_secs(4), 4, None).expect("four seconds is a stall");

        assert!(note.contains("the kick sweep"), "got {note}");
        assert!(!note.contains("channel"), "no channel was served: {note}");
    }

    /// The anti-spin test. Nothing is pending and a kick is outstanding, so
    /// there is nothing to do until the clock moves -- and under a pinned
    /// clock it cannot. The old loop burned every one of its passes here.
    #[test]
    fn nothing_pending_returns_at_once_instead_of_spinning_to_the_bound() {
        let (mut f, module, rou) = polling_fixture();
        f.host.kicks.push(Kick { delay: 60, dstrou: rou });
        f.host.set_clock(Clock::pinned(1_135_952_405));

        let cycles = f.host.cycle(&mut f.machine, &module, &mut || false).expect("cycled");

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

        let cycles = f.host.cycle(&mut f.machine, &module, &mut || false).expect("cycled");

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
        f.host.users.set_polrou_mem(f.machine.mem_mut(), console, Some(rou)).expect("channel 0");

        f.host.refill_polls(&mut f.machine, 5).expect("armed");
        let cycles = f.host.cycle(&mut f.machine, &module, &mut || false).expect("cycled");

        assert_eq!(cycles.dispatched, 5, "the budget is what stopped it -- nothing else bounds a cycle");
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
        f.host.users.set_polrou_mem(f.machine.mem_mut(), console, Some(rou)).expect("channel 0");

        f.host.refill_polls(&mut f.machine, 3).expect("armed");
        let first = f.host.cycle(&mut f.machine, &module, &mut || false).expect("cycled");
        assert_eq!(first.dispatched, 3);

        f.host.refill_polls(&mut f.machine, 3).expect("armed again");
        let second = f.host.cycle(&mut f.machine, &module, &mut || false).expect("cycled");
        assert_eq!(second.dispatched, 3, "the second burst polls too");
    }

    /// A refill while the chain is still armed must not add a second status.
    ///
    /// `cycle` returning on its interrupt -- the pump's mailbox has input
    /// waiting -- leaves a status queued with budget to spare. The pump then
    /// refills on that same wake, and a queue that grows by one per wake is a
    /// leak no single-burst test can see.
    ///
    /// **The interrupt is load-bearing here.** Cutting the cycle short is the
    /// only way to reach the `polling_armed` guard: left to run, `cycle`
    /// drains to budget exhaustion and `dopoll` stops re-arming, so the
    /// channel is not armed when the refill lands and the guard is never
    /// consulted. This test used to rely on the pass bound for that early
    /// exit; when the bound was deleted 2026-08-20 the test kept passing and
    /// stopped testing anything -- measured: the guard could be deleted
    /// outright with all 1,932 tests still green.
    #[test]
    fn a_refill_does_not_arm_a_channel_that_is_already_armed() {
        let (mut f, module, rou) = polling_fixture();
        let console = f.console();
        f.host.users.set_polrou_mem(f.machine.mem_mut(), console, Some(rou)).expect("channel 0");

        f.host.refill_polls(&mut f.machine, 100).expect("armed");
        // Interrupt on the first pass, as the pump does when input is waiting.
        // One poll dispatched, 99 of the budget left, so `dopoll` re-armed --
        // a status is queued when the refill below runs. `&mut || false` here
        // would drain the whole budget and leave nothing armed to guard.
        let _ = f.host.cycle(&mut f.machine, &module, &mut || true).expect("cycled");
        f.host.refill_polls(&mut f.machine, 100).expect("refilled while armed");

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
                .set_polrou_mem(f.machine.mem_mut(), chan, Some(rou))
                .expect("a polling channel");
        }

        f.host.refill_polls(&mut f.machine, 100).expect("armed");

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
        let cycles = f.host.cycle(&mut f.machine, &module, &mut || false).expect("cycled");
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
        f.host.users.set_polrou_mem(f.machine.mem_mut(), console, Some(rou)).expect("channel 0");

        f.host.refill_polls(&mut f.machine, 0).expect("granted nothing");

        assert!(
            !f.host.gsbl().polling_armed(console),
            "a budget of zero arms nothing, or it buys a poll it did not grant"
        );
        let cycles = f.host.cycle(&mut f.machine, &module, &mut || false).expect("cycled");
        assert_eq!(cycles.dispatched, 0);
    }

    /// The meter that calibrates the budget in production.
    #[test]
    fn polls_cut_says_the_budget_was_the_thing_that_stopped_it() {
        let (mut f, module, rou) = polling_fixture();
        let console = f.console();
        f.host.users.set_polrou_mem(f.machine.mem_mut(), console, Some(rou)).expect("channel 0");
        f.host.kicks.push(Kick { delay: 60, dstrou: rou });
        f.host.set_clock(Clock::pinned(1_135_952_405));

        f.host.refill_polls(&mut f.machine, 2).expect("armed");
        let cut = f.host.cycle(&mut f.machine, &module, &mut || false).expect("cycled");
        assert_eq!(cut.ended, Ended::Waiting { next_kick: 60, polls_cut: true });

        // Nothing polling: the budget is untouched, so nothing was cut.
        f.host.users.set_polrou_mem(f.machine.mem_mut(), console, None).expect("channel 0");
        f.host.refill_polls(&mut f.machine, 2).expect("nothing to arm");
        let uncut = f.host.cycle(&mut f.machine, &module, &mut || false).expect("cycled");
        assert_eq!(uncut.ended, Ended::Waiting { next_kick: 60, polls_cut: false });
    }

    /// The whole sleep policy, in one place, so that the socket driver and any
    /// other driver cannot answer this question differently.
    #[test]
    fn ended_tells_a_driver_what_to_wait_on() {
        use crate::Wait;
        use crate::abi::Wg16;
        assert_eq!(Ended::<Wg16>::Idle.wait(), Wait::Blocked);
        assert_eq!(
            Ended::<Wg16>::Waiting { next_kick: 1, polls_cut: false }.wait(),
            Wait::Until(std::time::Duration::from_secs(1))
        );
        assert_eq!(
            Ended::<Wg16>::Waiting { next_kick: 60, polls_cut: true }.wait(),
            Wait::Until(std::time::Duration::from_secs(60))
        );
        assert_eq!(Ended::<Wg16>::Bound { next_kick: None }.wait(), Wait::Now);
        assert_eq!(Ended::<Wg16>::Bound { next_kick: Some(3) }.wait(), Wait::Now);

        // The arm a driver reaches once and never returns from. Left out of
        // the first draft of this test, and review found it by mutating
        // `Wait::Stop` to `Wait::Blocked` and watching all 773 tests stay
        // green -- a driver that blocked forever on a stopped module instead
        // of shutting down, with nothing to say so.
        assert_eq!(
            Ended::<Wg16>::Stopped(mbbs_machine::m16::Poison::Timeout { cs: 0, ip: 0 }, None).wait(),
            Wait::Stop
        );
    }

    /// `cycle`'s poll-sourced stop names the exact channel that tripped it.
    ///
    /// Nothing before Task 1 (`docs/plans/2026-08-11-survivability-and-the-
    /// reachable-surface.md`) threaded a channel out of `Ended::Stopped` at
    /// all, and no test anywhere in this file pinned the wiring `cycle`
    /// added: `Ended::Stopped(poison, None)` -- silently dropping which
    /// channel it was -- would compile and pass every other test in this
    /// crate unchanged, because `polls_cut_says_the_budget_was_the_thing_
    /// that_stopped_it` and `ended_tells_a_driver_what_to_wait_on` above
    /// only ever exercise `Waiting`/`Bound`/a hand-built `Stopped`, never
    /// one `cycle` produced from a real dispatch.
    #[test]
    fn cycle_names_the_channel_a_poll_sourced_stop_happened_on() {
        let mut f = Fixture::new();
        let console = f.console();
        let module = f.minimal_module();

        // sttrou (index 1): a privileged instruction, HLT, which raises
        // SIGSEGV inside the sandboxed segment the same way
        // `crates/mbbs-machine/tests/fault.rs` pins for `Machine` directly.
        let sttrou = f.machine.code_ptr(0);
        let state = register_module_with(&mut f, &[(1, sttrou)]);
        // Loaded *after* `register_module_with` -- see `connected_with`'s own
        // doc comment: `Fixture::invoke` uses the same scratch code segment
        // for its own call trampoline, and `load_code` always writes at
        // offset zero, so registering first and loading the real stub
        // second is the only order that leaves the stub standing.
        f.machine.load_code(&[0xf4]).expect("one byte fits"); // hlt

        f.host
            .connect_state(&mut f.machine, console, &Connection::ansi("rangerdan"))
            .expect("a user on the channel");
        set_state(&mut f, console, state);

        f.host.gsbl_mut().push_input(console, b"look\r");

        let cycles = f.host.cycle(&mut f.machine, &module, &mut || false).expect("cycle runs");
        match cycles.ended {
            Ended::Stopped(mbbs_machine::m16::Poison::Fault { .. }, Some(chan)) => {
                assert_eq!(
                    chan, console,
                    "the stop must name the channel actually being serviced"
                );
            }
            other => panic!("expected a Fault naming the console channel, got {other:?}"),
        }
    }

    /// `MAJORBBS.C:476` is `while (tcklst != ticker)`, which was safe only
    /// because `ticker` was an unsigned counter that could not go backwards. A
    /// system clock can -- NTP, a manual set -- and `!=` would then run about
    /// four billion rounds, firing timers on every one.
    #[test]
    fn a_clock_that_goes_backwards_resyncs_instead_of_firing_four_billion_rounds() {
        let (mut f, module, rou) = polling_fixture();
        f.host.set_clock(Clock::pinned(1_135_952_405));
        let _ = f.host.cycle(&mut f.machine, &module, &mut || false).expect("cycled");

        f.host.kicks.push(Kick { delay: 1, dstrou: rou });
        f.host.set_clock(Clock::pinned(1_135_952_000));

        let cycles = f.host.cycle(&mut f.machine, &module, &mut || false).expect("cycled");

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

        let cycles = f.host.cycle(&mut f.machine, &module, &mut || false).expect("cycled");

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
        let mut left = n;
        let at = std::time::Instant::now();
        let idle = f
            .host
            .cycle(&mut f.machine, &module, &mut || {
                left -= 1;
                left == 0
            })
            .expect("cycled");
        let each = at.elapsed() / idle.iterations as u32;
        eprintln!("{} idle passes, {each:?} each", idle.iterations);

        let (mut f, module, rou) = polling_fixture();
        let console = f.console();
        f.host.users.set_polrou_mem(f.machine.mem_mut(), console, Some(rou)).expect("channel 0");
        f.host.gsbl_mut().inject(console, gsbl::Gsbl::POLSTS);
        let mut left = n;
        let at = std::time::Instant::now();
        let busy = f
            .host
            .cycle(&mut f.machine, &module, &mut || {
                left -= 1;
                left == 0
            })
            .expect("cycled");
        let each = at.elapsed() / busy.iterations as u32;
        eprintln!("{} dispatching passes, {each:?} each", busy.iterations);
    }

    // --- Survey mode (docs/plans/2026-08-11-survivability-and-the-reachable-surface.md,
    // Task 2). `Host::run`'s `Entry::Unimplemented` fallthrough, continued
    // only when a `survey::Inventory` has been attached.
    //
    // The shared shape every test below shares, and is deliberately violated
    // at least once: every OTHER test enables survey mode (so
    // `survey_mode_off_by_default_still_stops` pins the opposite); every
    // OTHER test records exactly one symbol once (so
    // `..._counts_a_repeat_call...` and `..._records_two_different_symbols...`
    // pin more than one, and the same symbol twice); every OTHER test's
    // symbol is `Entry::Unimplemented` (so `..._still_stops_on_a_fault...`
    // and `..._still_stops_on_a_timeout...` pin the two kinds survey mode
    // must never touch); and every test here inspects the in-memory
    // `Inventory` (see `survey.rs`'s own durability tests for the file-based
    // proof that constraint 6 needs -- this module has no reason to
    // duplicate them).

    /// A shared, in-memory survey inventory -- the harness these tests share.
    fn survey_inventory() -> std::rc::Rc<std::cell::RefCell<crate::survey::Inventory>> {
        std::rc::Rc::new(std::cell::RefCell::new(crate::survey::Inventory::in_memory()))
    }

    /// Code that `lcall`s thunk `indices`, in that order, then `retf`s.
    ///
    /// `minimal_module` (used by every test below) imports nothing, so
    /// `Module::import` answers `None` for any index a raw call names --
    /// `Host::run` then reports it as an unnamed thunk, `"thunk #N"` (see its
    /// own comment on `module.import(index)`). That is a real, exercised
    /// code path (a loader bug looks like this too), and it is enough to
    /// pin `Host::run`'s continuation/counting/dedup mechanics without a
    /// full NE import table -- `testing::Fixture::call_with` uses the same
    /// trick, calling a thunk no module claimed.
    fn lcall_thunks(machine: &mut Machine, indices: &[u16]) -> FarPtr {
        let mut code = Vec::new();
        for &index in indices {
            code.push(0x9a); // lcall
            code.extend_from_slice(&machine.thunk_address(index).to_bytes());
        }
        code.push(0xcb); // retf
        machine.load_code(&code).expect("code fits");
        machine.code_ptr(0)
    }

    #[test]
    fn survey_mode_off_by_default_still_stops_on_unimplemented() {
        let mut f = Fixture::new();
        assert!(f.host.survey.is_none(), "off unless enable_survey was called");
        let module = f.minimal_module();
        let entry = lcall_thunks(&mut f.machine, &[0]);

        let outcome = f.host.run(&mut f.machine, &module, entry, &[], None).expect("ran");
        match outcome {
            Outcome::Stopped(Poison::Unimplemented { module, symbol }) => {
                assert_eq!(module, "");
                assert!(symbol.starts_with("thunk #0"), "{symbol}");
            }
            other => panic!("survey mode is off; must stop, not {other:?}"),
        }
    }

    #[test]
    fn survey_mode_continues_past_a_single_unimplemented_call_and_records_it() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let entry = lcall_thunks(&mut f.machine, &[0]);
        let chan = f.console();

        let inventory = survey_inventory();
        f.host.enable_survey(inventory.clone());

        let outcome = f.host.run(&mut f.machine, &module, entry, &[], Some(chan)).expect("ran");
        assert_eq!(
            outcome,
            Outcome::Returned { lo: 0, hi: 0 },
            "the module must see the fabricated Ret::Void and reach its own retf"
        );

        let inv = inventory.borrow();
        assert_eq!(inv.len(), 1);
        assert_eq!(inv.count_of("", "thunk #0"), Some(1));
        let text = inv.render();
        assert!(text.contains("1\tunimplemented\t-\tthunk #0\t-\t0\t"), "{text}");
    }

    #[test]
    fn survey_mode_counts_a_repeat_call_to_the_same_symbol_without_a_second_entry() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let entry = lcall_thunks(&mut f.machine, &[0, 0]);

        let inventory = survey_inventory();
        f.host.enable_survey(inventory.clone());

        let outcome = f.host.run(&mut f.machine, &module, entry, &[], None).expect("ran");
        assert_eq!(outcome, Outcome::Returned { lo: 0, hi: 0 });

        let inv = inventory.borrow();
        assert_eq!(inv.len(), 1, "one distinct symbol, called twice");
        assert_eq!(inv.count_of("", "thunk #0"), Some(2));
    }

    #[test]
    fn survey_mode_records_two_different_symbols_as_two_entries() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let entry = lcall_thunks(&mut f.machine, &[0, 1]);

        let inventory = survey_inventory();
        f.host.enable_survey(inventory.clone());

        let outcome = f.host.run(&mut f.machine, &module, entry, &[], None).expect("ran");
        assert_eq!(outcome, Outcome::Returned { lo: 0, hi: 0 });

        let inv = inventory.borrow();
        assert_eq!(inv.len(), 2);
        assert_eq!(inv.count_of("", "thunk #0"), Some(1));
        assert_eq!(inv.count_of("", "thunk #1"), Some(1));
    }

    #[test]
    fn survey_mode_still_stops_on_a_fault_reached_after_a_continued_call() {
        // Constraint 1: never continue past `Poison::Fault`. The module
        // reaches a fabricated return from thunk 0, then walks straight
        // into `hlt` -- if survey mode's `continue` somehow looped past a
        // terminal `Exit` instead of returning through the normal
        // `Exit::Fault` arm, this would come back `Returned` instead.
        let mut f = Fixture::new();
        let module = f.minimal_module();

        let mut code = vec![0x9a];
        code.extend_from_slice(&f.machine.thunk_address(0).to_bytes());
        code.push(0xf4); // hlt
        f.machine.load_code(&code).expect("code fits");
        let entry = f.machine.code_ptr(0);

        let inventory = survey_inventory();
        f.host.enable_survey(inventory.clone());

        let outcome = f.host.run(&mut f.machine, &module, entry, &[], None).expect("ran");
        assert!(
            matches!(outcome, Outcome::Stopped(Poison::Fault { .. })),
            "a fault after a fabricated return must still stop the machine: {outcome:?}"
        );
        assert_eq!(
            inventory.borrow().len(),
            1,
            "the continued call was still recorded on the way through"
        );
    }

    #[test]
    fn survey_mode_still_stops_on_a_timeout_reached_after_a_continued_call() {
        // Constraint 1: never continue past `Poison::Timeout`, the other
        // terminal `Exit` survey mode must not paper over.
        let mut f = Fixture::new();
        let module = f.minimal_module();

        let mut code = vec![0x9a];
        code.extend_from_slice(&f.machine.thunk_address(0).to_bytes());
        code.extend_from_slice(&[0xeb, 0xfe]); // jmp $ -- never returns on its own
        f.machine.load_code(&code).expect("code fits");
        let entry = f.machine.code_ptr(0);
        f.machine.set_budget(std::time::Duration::from_millis(20));

        let inventory = survey_inventory();
        f.host.enable_survey(inventory.clone());

        let outcome = f.host.run(&mut f.machine, &module, entry, &[], None).expect("ran");
        assert!(
            matches!(outcome, Outcome::Stopped(Poison::Timeout { .. })),
            "a timeout after a fabricated return must still stop the machine: {outcome:?}"
        );
        assert_eq!(inventory.borrow().len(), 1);
    }

    /// A minimal NE image with exactly one *genuine* import -- unlike
    /// `testing::minimal_module_bytes`, which imports nothing at all.
    ///
    /// Needed for the two tests below that cannot be reached through
    /// `lcall_thunks`' "unnamed thunk" trick: an ordinal and an `@`-suffixed
    /// name are both facts `Host::run` reads off the module's *own*
    /// `ImportSite` (`module.import(index)`), which is only ever populated
    /// by `mbbs_machine::m16::Machine::load_ne` actually resolving a real relocation --
    /// see `crates/mbbs-machine/src/m16/ne.rs`'s `map_ne`. `dll` is deliberately never
    /// `"MAJORBBS"`/`"GALGSBL"`/`"DOSCALLS"`, so `shims::entry` always
    /// answers `Entry::Unimplemented` for it and the loader gives it a real
    /// thunk (a `Datum`/`Absolute` classification resolves straight to an
    /// address or a constant and never gets a thunk at all -- traced by hand
    /// against `map_ne`, and the reason this file has no equivalent
    /// `Entry::Datum`-reaches-`Host::run` integration test: as far as this
    /// crate's loader is concerned, that combination cannot be produced by
    /// loading any module, only by `Inventory::record`'s own unit tests
    /// exercising the bookkeeping directly).
    fn module_with_one_import(dll: &str, symbol: &mbbs_machine::m16::Symbol) -> Vec<u8> {
        use mbbs_machine::m16::Symbol;

        const ALIGN: u16 = 4;
        const SECTOR: usize = 1 << ALIGN;

        fn pstring_with_ordinal(name: &str, ordinal: u16) -> Vec<u8> {
            let mut out = vec![name.len() as u8];
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&ordinal.to_le_bytes());
            out
        }
        fn pstring(name: &str) -> Vec<u8> {
            let mut out = vec![name.len() as u8];
            out.extend_from_slice(name.as_bytes());
            out
        }

        // The imported-names blob: a reserved empty entry at offset 0 (kept
        // for parity with `minimal_module_bytes`, which nothing here reads),
        // then the module name, then -- only for a `Symbol::Name` import --
        // the symbol name.
        let mut impnames = vec![0u8];
        let module_name_at = impnames.len() as u16;
        impnames.extend_from_slice(&pstring(dll));
        let symbol_name_at = impnames.len() as u16;
        if let Symbol::Name(name) = symbol {
            impnames.extend_from_slice(&pstring(name));
        }

        let mut restab = pstring_with_ordinal("TESTMOD", 0);
        restab.push(0);
        let mut nrtab = pstring_with_ordinal("a test module with one import", 0);
        nrtab.push(0);
        let entrytab = vec![0u8];

        let mut out = vec![0u8; 0x80];
        out[0..2].copy_from_slice(b"MZ");
        out[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        out[0x40..0x42].copy_from_slice(b"NE");

        let segtab = 0x80;
        out.resize(segtab + 8, 0);

        // One module reference: the offset of its name within `impnames`.
        let modtab = out.len();
        out.extend_from_slice(&module_name_at.to_le_bytes());

        let imptab = out.len();
        out.extend_from_slice(&impnames);
        let restab_at = out.len();
        out.extend_from_slice(&restab);
        let entrytab_at = out.len();
        out.extend_from_slice(&entrytab);
        let nrtab_at = out.len();
        out.extend_from_slice(&nrtab);

        while !out.len().is_multiple_of(SECTOR) {
            out.push(0);
        }
        let sector = (out.len() / SECTOR) as u16;

        // The one segment's data: 4 bytes, holding one relocation site
        // (`SRC_FAR_ADDR`, 4 bytes, additive) at offset 0. Nothing ever
        // executes or reads this segment's bytes -- the only thing this
        // relocation is for is making `mbbs_machine::m16::ne::map_ne` resolve this
        // import and assign it a thunk, which is what makes
        // `Module::import(0)` answer `Some`.
        //
        // `SRC_FAR_ADDR`, not `SRC_OFFSET`: `Host::check_globals`'s
        // `addressed_as_data` classifies a symbol as *data* the moment any
        // one of its fixups is not `FAR_ADDR` (see that fn's own doc), and a
        // `Host::load` that believes this import is addressed as data would
        // then refuse to load a module that never placed it -- which,
        // for `Entry::Unimplemented`, `check_globals` always refuses
        // (`Why::NotPlaced`). `FAR_ADDR` is the shape "this is a call
        // target" -- the honest fixup for what this test is actually
        // pretending to build -- and it is also the one shape
        // `addressed_as_data` never classifies as data at all, so
        // `check_globals` never looks at it and `Host::load` succeeds.
        let data = [0u8; 4];
        out.extend_from_slice(&data);

        let (target_flag, hi): (u8, u16) = match symbol {
            Symbol::Name(_) => (0x02, symbol_name_at), // TGT_IMPORTNAME
            Symbol::Ordinal(n) => (0x01, *n),          // TGT_IMPORTORDINAL
        };
        out.extend_from_slice(&1u16.to_le_bytes()); // relocation count
        out.push(3); // SRC_FAR_ADDR
        out.push(target_flag | 0x04); // | TGT_ADDITIVE
        out.extend_from_slice(&0u16.to_le_bytes()); // site offset within segment
        out.extend_from_slice(&1u16.to_le_bytes()); // module index (1-based)
        out.extend_from_slice(&hi.to_le_bytes());

        out[segtab..segtab + 2].copy_from_slice(&sector.to_le_bytes());
        out[segtab + 2..segtab + 4].copy_from_slice(&(data.len() as u16).to_le_bytes());
        // SEG_DATA (0x0001) | SEG_RELOCINFO (0x0100)
        out[segtab + 4..segtab + 6].copy_from_slice(&0x0101u16.to_le_bytes());
        out[segtab + 6..segtab + 8].copy_from_slice(&(data.len() as u16).to_le_bytes());

        let w = |out: &mut Vec<u8>, at: usize, v: u16| {
            out[0x40 + at..0x40 + at + 2].copy_from_slice(&v.to_le_bytes());
        };
        w(&mut out, 0x04, (entrytab_at - 0x40) as u16);
        w(&mut out, 0x06, entrytab.len() as u16);
        w(&mut out, 0x0c, 0x8001); // a single-data library
        w(&mut out, 0x0e, 1); // autodata: the one segment
        w(&mut out, 0x1c, 1); // segment count
        w(&mut out, 0x1e, 1); // imported module count
        w(&mut out, 0x20, nrtab.len() as u16);
        w(&mut out, 0x22, (segtab - 0x40) as u16);
        w(&mut out, 0x26, (restab_at - 0x40) as u16);
        w(&mut out, 0x28, (modtab - 0x40) as u16);
        w(&mut out, 0x2a, (imptab - 0x40) as u16);
        w(&mut out, 0x32, ALIGN);
        out[0x40 + 0x2c..0x40 + 0x30].copy_from_slice(&(nrtab_at as u32).to_le_bytes());
        out[0x40 + 0x36] = 0x02;

        out
    }

    #[test]
    fn survey_mode_records_the_ordinal_of_a_genuinely_imported_unimplemented_symbol() {
        let mut f = Fixture::new();
        let bytes = module_with_one_import("TESTDLL", &mbbs_machine::m16::Symbol::Ordinal(42));
        let module = f.host.load(&mut f.machine, &bytes).expect("loads");

        // Thunk index 0: the module's one and only import, and the first
        // (and only) relocation `map_ne` ever resolves for it.
        let entry = lcall_thunks(&mut f.machine, &[0]);

        let inventory = survey_inventory();
        f.host.enable_survey(inventory.clone());

        let outcome = f.host.run(&mut f.machine, &module, entry, &[], None).expect("ran");
        assert_eq!(outcome, Outcome::Returned { lo: 0, hi: 0 });

        let inv = inventory.borrow();
        assert_eq!(inv.len(), 1);
        // `Exports::wg101()` has no ordinal table for "TESTDLL", so
        // `Host::symbol_name` falls back to `#<ordinal>` -- see its own doc.
        assert_eq!(inv.count_of("TESTDLL", "#42"), Some(1));
        assert!(
            inv.render().contains("\tTESTDLL\t#42\t42\t"),
            "the ordinal must appear in its own column: {}",
            inv.render()
        );
    }

    #[test]
    fn survey_mode_records_but_refuses_to_continue_past_an_at_suffixed_symbol() {
        // Constraint 2: an unimplemented symbol shaped like a Borland
        // runtime helper is recorded like any other, but `Host::run` must
        // not guess its cleanup convention -- so it still stops, survey mode
        // or not. `shims::survey_continue_convention` is unit-tested for the
        // *decision*; this is the end-to-end proof `Host::run` actually
        // obeys it rather than only recording and then continuing anyway.
        let mut f = Fixture::new();
        let bytes = module_with_one_import(
            "TESTDLL",
            &mbbs_machine::m16::Symbol::Name("f_lxdiv@_not_a_real_routine".to_owned()),
        );
        let module = f.host.load(&mut f.machine, &bytes).expect("loads");
        let entry = lcall_thunks(&mut f.machine, &[0]);

        let inventory = survey_inventory();
        f.host.enable_survey(inventory.clone());

        let outcome = f.host.run(&mut f.machine, &module, entry, &[], None).expect("ran");
        match outcome {
            Outcome::Stopped(Poison::Unimplemented { module, symbol }) => {
                assert_eq!(module, "TESTDLL");
                assert!(symbol.starts_with("f_lxdiv@_not_a_real_routine"), "{symbol}");
            }
            other => panic!("an @-suffixed symbol must still stop: {other:?}"),
        }

        let inv = inventory.borrow();
        assert_eq!(
            inv.len(),
            1,
            "recorded even though the host refused to fabricate a return for it"
        );
        assert_eq!(inv.count_of("TESTDLL", "f_lxdiv@_not_a_real_routine"), Some(1));
    }

    // The tests above all call `Host::run` directly, which pins its own
    // continuation/counting/dedup mechanics but proves nothing about the
    // `chan` argument each of `Host::run`'s five real callers passes it --
    // `connect`, `disconnect`, `dopoll`, `poll_with_chan`'s own direct call,
    // and `prcrtk`'s kick sweep. A mutation swapping `Some(chan)` for `None`
    // (or vice versa) at any of those call sites would pass every test
    // above unnoticed. These two close that gap for the two paths a live
    // session actually takes on every request: logging on, and polling.

    #[test]
    fn survey_mode_records_the_channel_a_connect_call_was_serviced_on() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let console = f.console();

        // `register_module_with` runs its own synthetic call through
        // `Fixture::invoke`, which (like `lcall_thunks`) writes over the
        // scratch code segment at offset 0 -- so it has to happen BEFORE
        // `lonrou`'s own code is written, not after, or `connect` would run
        // whatever `register_module_with` left behind instead. `Host::connect`
        // reaches `lonrou` through `first_module()`, not the channel's
        // `state`, so nothing here needs `set_state`.
        let module_number = register_module_with(&mut f, &[]);
        let lonrou = lcall_thunks(&mut f.machine, &[0]);
        register_module_with_lonrou_at(&mut f, module_number, lonrou);

        let inventory = survey_inventory();
        f.host.enable_survey(inventory.clone());

        let outcome = f
            .host
            .connect(&mut f.machine, &module, console, &Connection::ansi("rangerdan"))
            .expect("connect_state ran");
        assert!(
            matches!(outcome, Some(Outcome::Returned { lo: 0, hi: 0 })),
            "{outcome:?}"
        );

        let inv = inventory.borrow();
        assert_eq!(inv.len(), 1);
        assert!(
            inv.render().contains(&format!("unimplemented\t-\tthunk #0\t-\t{console}\t")),
            "connect's own channel must be the one recorded: {}",
            inv.render()
        );
    }

    /// Overwrite an already-registered module's `lonrou` (vector 0) in
    /// place, so a test can build the routine's *code* after registering --
    /// see `survey_mode_records_the_channel_a_connect_call_was_serviced_on`
    /// for why the order matters. `register_module_with` only ever writes
    /// vectors at registration time, which is one call too early for a
    /// routine built from `lcall_thunks`.
    fn register_module_with_lonrou_at(f: &mut Fixture, module_number: u16, lonrou: FarPtr) {
        let Registration::Module { block, .. } = &f.host.modules()[usize::from(module_number)]
        else {
            panic!("module {module_number} is not a module registration");
        };
        let at = FarPtr {
            offset: block.offset + 25,
            selector: block.selector,
        };
        f.machine.write(at, &lonrou.to_bytes()).expect("lonrou fits");
    }

    #[test]
    fn survey_mode_records_the_channel_a_dopoll_call_was_serviced_on() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let console = f.console();
        let rou = lcall_thunks(&mut f.machine, &[0]);

        f.host
            .users
            .set_polrou_mem(f.machine.mem_mut(), console, Some(rou))
            .expect("channel 0");
        f.host.refill_polls(&mut f.machine, 1).expect("armed");

        let inventory = survey_inventory();
        f.host.enable_survey(inventory.clone());

        let outcome = f.host.poll(&mut f.machine, &module).expect("polled");
        assert!(
            matches!(outcome, Some(Outcome::Returned { lo: 0, hi: 0 })),
            "{outcome:?}"
        );

        let inv = inventory.borrow();
        assert_eq!(inv.len(), 1);
        assert!(
            inv.render().contains(&format!("unimplemented\t-\tthunk #0\t-\t{console}\t")),
            "dopoll's own channel must be the one recorded: {}",
            inv.render()
        );
    }

    // ---- `Host::dos_name`/`Host::find`: containment, not "no directories" --

    #[test]
    fn dos_name_leaves_a_bare_name_alone() {
        assert_eq!(
            Host::<Wg16>::dos_name("WCCITEMS.DAT").expect("no directory to refuse"),
            "WCCITEMS.DAT"
        );
    }

    #[test]
    fn dos_name_strips_the_modules_own_directory_prefix_either_spelling() {
        assert_eq!(
            Host::<Wg16>::dos_name(".\\WCCITEMS.DAT").expect("the module's own prefix"),
            "WCCITEMS.DAT"
        );
        assert_eq!(
            Host::<Wg16>::dos_name("./WCCITEMS.DAT").expect("the forward-slash spelling too"),
            "WCCITEMS.DAT"
        );
    }

    #[test]
    fn dos_name_accepts_and_normalises_a_subdirectory_lunatix_actually_ships() {
        // LunatiX 5.3F's own `INSTALL.CFG` does `MAKEDIR LUN5DATA` and copies
        // `LUNRAND1.TXT` into it; the module then opens
        // `fopen("lun5data\lunrand1.txt", ...)`. That subdirectory is real,
        // is under this host's own root, and is exactly the case this rule
        // was relaxed to let through.
        assert_eq!(
            Host::<Wg16>::dos_name("lun5data\\lunrand1.txt").expect("a real subdirectory of root"),
            "lun5data/lunrand1.txt"
        );
        // The `.\` prefix and both separators together, since a module is
        // free to mix them.
        assert_eq!(
            Host::<Wg16>::dos_name(".\\lun5data/lunrand1.txt").expect("mixed separators"),
            "lun5data/lunrand1.txt"
        );
    }

    #[test]
    fn dos_name_refuses_a_drive_letter() {
        let e = Host::<Wg16>::dos_name("D:\\MUD\\DATA\\X.DAT")
            .expect_err("a drive is somewhere this host does not look");
        assert!(e.contains("D:\\MUD\\DATA\\X.DAT"), "{e}");
    }

    /// **Deliberate behaviour change, 2026-08-15**, replacing
    /// `dos_name_refuses_a_leading_separator_root_absolute_in_either_spelling`,
    /// which asserted the opposite.
    ///
    /// The old rule refused a leading separator on the grounds that "root of
    /// *what* is a question this host has no business answering". The Rose
    /// 3.0NT answered it: its init calls `access("\rci_univ.dat")`, and
    /// `RCI_UNIV.DAT` is a file it ships in its own directory. Under DOS a
    /// leading `\` means the root of the current drive, and a period BBS
    /// install *was* the root of its drive -- which is exactly what
    /// [`Host::root`] models here.
    ///
    /// So this host does have a defensible answer: root means the board
    /// directory. Refusing instead did not protect anything, it just stopped
    /// a module from opening its own shipped data file.
    #[test]
    fn dos_name_maps_a_leading_separator_onto_the_modules_own_root() {
        for (named, want) in [
            ("\\rci_univ.dat", "rci_univ.dat"),
            ("/rci_univ.dat", "rci_univ.dat"),
            ("\\MUD\\DATA\\X.DAT", "MUD/DATA/X.DAT"),
            ("/MUD/DATA/X.DAT", "MUD/DATA/X.DAT"),
        ] {
            assert_eq!(Host::<Wg16>::dos_name(named).as_deref(), Ok(want), "{named}");
        }
    }

    /// The half of the old rule that was always load-bearing, kept in full:
    /// mapping the leading separator to root must not become a way *through*
    /// root. The `..` check runs component-wise after separators are
    /// normalised, so it sees these no differently than it saw
    /// `lun5data\..\..\etc\passwd` before.
    #[test]
    fn dos_name_root_absolute_still_cannot_escape() {
        for named in [
            "\\..\\etc\\passwd",
            "/../etc/passwd",
            "\\lun5data\\..\\..\\etc\\passwd",
            "\\D:\\MUD\\X.DAT",
        ] {
            assert!(
                Host::<Wg16>::dos_name(named).is_err(),
                "{named} must not reach outside root just because it starts at root"
            );
        }
    }

    #[test]
    fn dos_name_refuses_a_dotdot_escape_including_a_sneaky_one_through_a_real_subdirectory() {
        for named in [
            "..\\WCCITEMS.DAT",
            "lun5data\\..\\..\\etc\\passwd",
        ] {
            assert!(
                Host::<Wg16>::dos_name(named).is_err(),
                "{named} must not escape root, however many real components lead up to the .."
            );
        }
    }

    #[test]
    fn find_resolves_a_two_level_path_case_insensitively_at_every_level() {
        // The distribution stores 1997 DOS names in upper case
        // (`LUN5DATA/LUNRAND1.TXT`), and the module asks in lower case
        // (`lun5data/lunrand1.txt`, what `Host::dos_name` hands back). Matching
        // only the last segment would still miss `LUN5DATA` itself.
        let root = testing::scratch("dos-name-find-two-level");
        std::fs::create_dir(root.join("LUN5DATA")).expect("a directory");
        std::fs::write(root.join("LUN5DATA").join("LUNRAND1.TXT"), b"jokes\r\n")
            .expect("a file inside it");

        let f = Fixture::rooted(root.clone());

        let found = f
            .host
            .find("lun5data/lunrand1.txt")
            .expect("case-insensitive at every level, not just the last");
        assert_eq!(found, root.join("LUN5DATA").join("LUNRAND1.TXT"));
    }
}
