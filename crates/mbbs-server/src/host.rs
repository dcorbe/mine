//! The host thread: the only place `A::Cpu` is ever built.
//!
//! Every `Abi`'s `Cpu` is `!Send` -- `mbbs_machine::m16::Machine`'s segments
//! are `Rc`s over `mmap`s, its watchdog timer is bound with
//! `SIGEV_THREAD_ID` to the `gettid()` of the thread that created it, and
//! its fault handler's alternate stack is a `thread_local`; `Wg32Cpu`
//! bundles `mbbs_machine::m32::Machine`, which carries the same three
//! per-thread commitments. So an `A::Cpu` is built *inside* this thread and
//! never crosses into it: [`Boot`] carries everything that is `Send` --
//! paths, [`Terms`], numbers, and [`Boot::build`], the closure that builds
//! this machine's own `A::Cpu` when called *on* this thread -- and [`run`]
//! does the rest. Task 20 of
//! `docs/plans/2026-08-12-abi-border-implementation.md` made this driver
//! generic over `A`; design doc §4 point 2 is the invariant this file
//! exists to uphold: one dedicated thread per machine, `!Send` never
//! violated because nothing ever moves, and no `Send`/`Sync` bound added
//! anywhere to get there -- `A::Cpu` is produced by calling
//! [`Boot::build`] *inside* the spawned thread's own stack frame, never
//! captured by the closure `std::thread::spawn` receives.
//!
//! [`Host::hangup`] is the answer to both a lost carrier and a client that
//! cannot keep up with its own output: the driver does not distinguish them,
//! because a socket that will not drain is indistinguishable from one that
//! is gone.
//!
//! [`Boot::clock_reads`], if set, is how `crates/mbbs-server/tests/sleep.rs`
//! observes the real, shipped loop below rather than a copy of it: `Host`
//! never leaves this thread, so without this the sleep meter would have had
//! to reimplement the driver to measure it.
//!
//! # Surviving a module stop
//!
//! A module that faults, overruns its budget, or calls something this host
//! does not implement poisons the `A::Cpu` it is running on --
//! `A::call` then refuses to enter that machine again, for
//! **every** channel, not just the one that tripped it, and
//! each ABI's own `poison` deliberately forgets the call frame
//! (`frame_sp = None`, for `mbbs_machine::m16::Machine`), so there is no resume point to salvage even if a
//! host wanted one. "Hang up only the offending channel and keep going" is
//! therefore not a safer, more surgical alternative to a restart -- it is
//! not available at all: the very next dispatch on any *other* channel would
//! hit the same refusal, and today that refusal surfaces through a bare `?`
//! that tells nobody anything.
//!
//! So [`run`] is a small supervisor: [`life`] does one machine's whole life
//! -- build, boot, drive the steady state -- and [`run`] rebuilds a fresh
//! one when a life ends in [`Ended::Stopped`], up to [`RestartPolicy`]'s
//! bound. A boot failure (the machine cannot be built, the module cannot be
//! loaded or relocated, ordinal 1 itself stops, or `finish_init` fails) is a
//! broken deployment, not a survivable stop, and is not retried: only a stop
//! reached from the steady-state driver loop restarts.

use std::collections::VecDeque;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::TryRecvError;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mbbs::abi::Abi;
use mbbs::{Chan, Ended, Host, Outcome, Terms, Wait};
use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot;
use tokio::sync::watch;

use crate::msg::{In, Out};
use crate::pool::Pool;

/// The type [`Boot::extension`] carries -- named so the field itself does
/// not have to spell out four levels of nesting, and public so a caller
/// building one (`main.rs`'s `--scripts` wiring today) can name it too. See
/// that field's own doc for why this is a builder, not the extension
/// itself.
///
/// Takes every `(name, module)` pair [`life`] has loaded onto this machine
/// by the time it calls this -- see [`Boot::extension`]'s own doc comment
/// for why this receives them at all (a `declare`d export must validate
/// against a LIVE export table, so the extension can only be built AFTER
/// every module has loaded and initialised, not before). `name` is each
/// entry's own [`Boot::modules`] path stem, lowercased -- see that field's
/// own doc for the exact derivation `life` uses.
pub type ExtensionBuilder<A> = Box<dyn Fn(&[(String, <A as Abi>::Module)]) -> io::Result<Box<dyn mbbs::extension::Extension<A>>> + Send>;

/// Everything the host thread needs, all of it `Send`. `A::Cpu` is not
/// here and cannot be: it is `!Send`, and the thread builds its own -- see
/// [`Boot::build`].
pub struct Boot<A: Abi> {
    /// Build a fresh `A::Cpu`, called on the host thread itself, once per
    /// life (see the module doc's "Surviving a module stop").
    ///
    /// This is the seam Task 20 introduced to make [`run`]/[`life`] generic
    /// over `A` at all: `mbbs_machine::m16::Machine::new()` takes no
    /// arguments and needs nothing but this closure to call it, but a future
    /// `Wg32` board's `Wg32Cpu` needs a placeholder `Memory` built from the
    /// module's own file bytes first (`crates/mbbs/tests/wg32_round_trip.rs`'s
    /// `machine_and_placeholder`) -- ABI-specific construction detail this
    /// driver has no business knowing, and does not: whoever builds a `Boot`
    /// supplies it. `Fn`, not `FnOnce`, because [`run`]'s restart loop calls
    /// this once per life, not once per process.
    ///
    /// `Box<dyn Fn() -> io::Result<A::Cpu> + Send>` is `Send` on its own
    /// terms -- the closure's captured *environment* must be `Send` to cross
    /// into the spawned thread, which says nothing about whether `A::Cpu`,
    /// the value it *produces*, is `Send`. It is not, and does not need to
    /// be: the result of calling this lives only in this thread's own stack
    /// frame from the moment it is built (see the module doc's second
    /// paragraph).
    pub build: Box<dyn Fn() -> io::Result<A::Cpu> + Send>,
    /// The board directory the module's own files live in.
    pub root: PathBuf,
    /// Every module to load onto this machine, in the order [`life`] must
    /// load and initialise them -- dependency order, not registration
    /// importance. Must be non-empty; [`life`] refuses an empty list rather
    /// than panicking on `modules[0]` (see its own doc, "Booting N modules").
    ///
    /// # Why order is the whole contract
    ///
    /// Each entry gets `Host::load` (which makes its exports reachable to
    /// every *later* entry's own imports -- see [`mbbs::Host`]'s
    /// `loaded_modules` doc comment, the mechanism `071c5a0` landed for
    /// exactly this: MajorMUD Plus's `WCCMMPLS.DLL` imports eight symbols --
    /// `mmlog`, `register_mud_addon`, and six others -- directly from
    /// `WCCMMUD.DLL`, and can only load at all once `WCCMMUD.DLL` is already
    /// in the registry `Host::load` consults), then `A::init_entry` (ordinal
    /// 1, resolved by export table -- **not** the PE/NE entry point, which a
    /// real bug this session fixed had been reading instead), then
    /// `Host::run` to completion, in that order, one module fully before the
    /// next one starts.
    ///
    /// **Load order is registration order, and registration order decides
    /// who owns a channel.** A module's own ordinal 1 is what calls
    /// `register_module` (`MAJORBBS!register_module`, `crate::shims::system::register_module`);
    /// this driver does not call it and has no say in whether a given module
    /// calls it at all. `Host::connect`/`Host::hangup` dispatch through
    /// `Host::first_module()` -- the earliest `Registration::Module` in the
    /// table, skipping the FSD's native slot -- so **the first module in this
    /// list to run its own init and call `register_module` is the one every
    /// connecting channel enters**, for as long as this life lasts.
    ///
    /// Put the module that should own channels first. A later entry that
    /// also calls `register_module` (measured true of MajorMUD Plus's
    /// `WCCMMPLS.DLL`: it imports `MAJORBBS!register_module`, one call site,
    /// confirmed served and distinct from `WCCMMUD!register_mud_addon` --
    /// WCCMMUD's own tiny in-module addon table, unrelated to this host's
    /// module registry) still gets a `Registration` of its own, but
    /// `first_module()` never reaches it: `Host::connect`/`Host::hangup`
    /// dispatching to every registered module's `lonrou`/`huprou`, the way
    /// the real host's `cyclon`/`aschup` loops do, is `first_module`'s own
    /// doc comment's "still owed" debt, unaffected by this change. A second
    /// module here is therefore an **addon** in the sense that matters
    /// operationally: it never owns a channel, but its own exports are
    /// reachable the moment it loads, so the primary module can call into it
    /// directly (MajorMUD Plus's own `register_mud_addon` hook is exactly
    /// that shape from the *module* side -- WCCMMUD's own code, not this
    /// host, is what would call back into it).
    ///
    /// # Thunk ownership across modules
    ///
    /// A trap's raw thunk index used to be ambiguous with two modules on one
    /// machine (each load numbered from zero): booting `WCCMMUD.DLL` then
    /// `WCCMMPLS.DLL` stopped at `.thunk #66`, and the far likelier reading
    /// was a slot both modules claimed -- never confirmed symbol by symbol,
    /// because the pair was not re-booted against the old numbering to prove
    /// it. Thunk slices are machine-wide now -- `m16` since `50944874`,
    /// `m32` alongside it -- so the ambiguity itself is gone, and
    /// `Host::import_owner` finds the true owner when execution has crossed
    /// into another module's code. What remains is the order contract above.
    pub modules: Vec<PathBuf>,
    /// The fixed channel count. Sizes every per-channel table at `Host::new`.
    pub terms: Terms,
    /// The board's own Galacticomm registration number -- `bturno`,
    /// `BRKTHU.H:108`, eight digits and a NUL.
    ///
    /// `None` leaves the global as `Host::new` placed it: nine zero bytes.
    /// That is what this host did unconditionally until now, and it is not a
    /// neutral default -- it is a board with no serial. The real article got
    /// this from the board's own registration and modules read it: it is a
    /// `GALGSBL` datum (`crate::shims`'s table serves it), MajorBBS-family
    /// modules key their own licensing on it, and a module that finds it
    /// blank cannot tell a board apart from any other.
    ///
    /// One machine per `mbbs-server` process, so this is really set per
    /// board: two boards are two processes, each with its own `Boot` and its
    /// own serial.
    pub bturno: Option<String>,
    /// Poll firings granted per elapsed second. Set once, at boot, via
    /// [`mbbs::Host::set_polls_per_second`] -- the clock inside
    /// [`mbbs::Host::cycle`] grants it every elapsed second from then on,
    /// which is why this is no longer a per-wake re-arm: there is no
    /// `refill_polls` to call any more.
    pub polls_per_second: usize,
    // This struct used to carry `passes: usize` here too, `Host::cycle`'s
    // pass-count bound. Retired 2026-08-20 alongside `--passes`: a count is
    // a proxy for "has input arrived?", and a bad one -- see
    // `docs/superpowers/specs/2026-08-20-cycle-interrupt-and-syscyc-design.md`.
    // `cycle` now takes an interrupt predicate instead ([`life`]'s own
    // `interrupted` closure, below); `polls_per_second` above is the only
    // tuning dial left.
    /// Where this thread reports its own [`Host::clock_reads`] after every
    /// `cycle` call, for a caller outside the thread to sample.
    ///
    /// `Host` never leaves this thread -- it holds the `!Send` `Machine` by
    /// reference throughout `run`'s whole life -- so this is the only way
    /// anything outside can observe the counter that names how hard the
    /// driver is spinning. `None` (the ordinary case) skips the write
    /// entirely and costs nothing. `Ordering::Relaxed` because a reader is
    /// polling this on its own schedule; nothing else in the program
    /// synchronises against it.
    pub clock_reads: Option<Arc<AtomicU64>>,

    /// Epoch milliseconds of the start of the driver's most recent loop
    /// turn, stamped once per turn regardless of what that turn did -- the
    /// **frozen-world detector**. See design doc
    /// `docs/plans/2026-08-12-abi-border-design.md` §7.
    ///
    /// A driver that is genuinely waiting correctly still turns once per
    /// kick, once per input burst, or once per stray bell: this can go stale
    /// for at most one kick interval under correct operation. A driver that
    /// has stopped waking for timers at all -- the regression
    /// `crates/mbbs-server/tests/sleep.rs` documents as invisible to the
    /// clock-reads meter alone, because a driver that never wakes also never
    /// reads the clock -- leaves this stamp motionless indefinitely, which a
    /// reader outside the thread (which owns the `!Send` `Machine` and so
    /// cannot itself be probed) can detect by simply comparing this against
    /// wall-clock time. Same `Ordering::Relaxed` convention as
    /// [`Boot::clock_reads`]: a reader polls this on its own schedule.
    pub wake_age_ms: Option<Arc<AtomicU64>>,

    /// Running total of [`mbbs::Cycles::dispatched`] across every `cycle`
    /// call this life has made, for a reader to sample alongside
    /// [`Boot::calls_total`] and derive the **no-op ratio**: how many host
    /// routine calls ([`Host::calls`]) each top-level dispatch actually
    /// costs. Design doc §7: "a meter, not a control input" -- nothing in
    /// this driver ever branches on it. `fetch_add`, not `store`, because
    /// `Cycles::dispatched` itself resets to zero every `cycle` call rather
    /// than accumulating the way `Host::clock_reads`/[`Host::calls`] do.
    ///
    /// [`Host::calls`]: mbbs::Host::calls
    pub dispatched_total: Option<Arc<AtomicU64>>,

    /// [`Host::calls`] itself, sampled the same way [`Boot::clock_reads`]
    /// samples [`Host::clock_reads`] -- a running total, stored (not added)
    /// after every `cycle` call. Paired with [`Boot::dispatched_total`] for
    /// the no-op ratio; see that field's doc.
    ///
    /// [`Host::calls`]: mbbs::Host::calls
    pub calls_total: Option<Arc<AtomicU64>>,

    /// Where to write a survey of every unimplemented symbol this board
    /// reaches, or `None` (the default, and the only setting safe for a
    /// board anyone plays on) to run the way this crate always has.
    ///
    /// **This is a diagnostic, not a way to run a board.** See
    /// `mbbs::survey`'s module doc for what turning it on means: every
    /// unimplemented import gets a fabricated return instead of a stop, and
    /// that is wrong behaviour by design, tolerable only for a throwaway
    /// session whose sole purpose is to enumerate gaps.
    ///
    /// Built into one [`mbbs::survey::Shared`] inventory in [`run`], *not*
    /// in [`life`] -- see [`run`]'s own comment on why. The path is not a
    /// `PathBuf` per life; every restart within one process keeps writing
    /// the same file, so the survey a SIGINT interrupts is the whole
    /// process's, not just its last life's.
    pub survey: Option<PathBuf>,

    /// Build this machine's own extension, called on the host thread itself,
    /// once per life -- the same shape as [`Boot::build`], and for the same
    /// reason.
    ///
    /// A `Box<dyn Extension<A>>` cannot simply be handed in ready-made: an
    /// extension is participant, general behaviour above the module, so
    /// nothing here says its own state is `Send` -- `mbbs-lua`'s
    /// `LuaExtension`, this seam's first and so far only implementation,
    /// embeds an `mlua::Lua` VM that is not (its handle is `Rc`-based, not
    /// `Arc`-based, since nothing about the extension seam needs it to
    /// cross a thread). [`Boot`] itself must stay entirely `Send` -- it
    /// moves into [`crate::conn::spawn_machine`]'s `std::thread::spawn` --
    /// so, exactly like `A::Cpu`, a `!Send` extension is never built until
    /// it is already on the one thread it will ever run on. `Fn`, not
    /// `FnOnce`, so a restart (see the module doc, "Surviving a module
    /// stop") rebuilds a fresh extension for the fresh `Host` it is
    /// installed on, the same way `Boot::build` rebuilds a fresh `A::Cpu`.
    ///
    /// **Built AFTER `boot.modules` load and initialise, not before.** A
    /// script's `M.declare{...}` (`mbbs-lua`'s own declared-bindings
    /// surface) validates every declared export against the module's LIVE
    /// export table, so the extension cannot be built until every module
    /// [`life`] loads has actually finished loading and running its own
    /// init -- see the declared-bindings design doc's "Boot-order
    /// consequence". [`life`] calls this builder with every `(name,
    /// module)` pair it loaded, right after the module-loading loop (and
    /// `Host::finish_init`) completes, never before.
    ///
    /// `None` is the supported default: a board given no builder here runs
    /// exactly as it did before this field existed.
    pub extension: Option<ExtensionBuilder<A>>,
}

/// What one wake yielded.
enum Woke {
    /// A message arrived -- including [`In::Alarm`], a deadline this driver
    /// itself asked for coming due. There is no other way to learn that one
    /// has: see [`wake`]'s own doc.
    Message(In),
    /// Nothing arrived. Only possible under `Wait::Now`'s non-blocking peek
    /// -- a burst still in progress that found nothing queued this instant.
    Nothing,
    /// Every `Sender<In>` is gone. The listener and every connection task
    /// have dropped theirs, so nobody can ever send again.
    Gone,
}

/// Tell [`crate::alarm::spawn`]'s task what to wait for next, translating
/// [`Wait`] into the one thing that task understands: a duration from now,
/// or none at all.
///
/// `Wait::Now` disarms (`None`) rather than requesting a zero-length sleep --
/// this turn is not going to block on `rx` at all (see [`wake`]'s `Now` arm),
/// so a bell that fired anyway would just be one more stale one for the next
/// turn to shrug off. A `send` failing means nobody is watching the
/// `watch::Receiver` any more (the alarm task ended, or -- in a test that
/// never wired one up at all -- there never was one); either way there is
/// nothing this call could do about it, so the error is dropped rather than
/// propagated. A driver with no working bell degrades to `Wait::Blocked`'s
/// old failure mode (see the mutation `crates/mbbs-server/tests/host_supervisor.rs`
/// re-derives for this task), not a panic.
fn arm(wait: Wait, deadline: &watch::Sender<Option<Duration>>) {
    let request = match wait {
        Wait::Until(d) => Some(d),
        Wait::Blocked | Wait::Now | Wait::Stop => None,
    };
    let _ = deadline.send(request);
}

/// Block, peek, or refuse to wait at all, according to what the last `cycle`
/// asked for.
///
/// Separated from [`run`] so that it can be tested at all: `run` needs a
/// booted `A::Cpu`, and this needs only a channel.
///
/// **The one blocking point.** `Wait::Blocked` and `Wait::Until` both reduce
/// to the same bare `rx.recv()` -- design doc §7's "single spine": every
/// source of a wake, including a deadline coming due, is now a message on
/// this one channel ([`crate::msg::In::Alarm`], rendered by
/// [`crate::alarm::spawn`]'s task from whatever [`arm`] most recently
/// requested). There is no more `recv_timeout` here at all; `Wait::Until`'s
/// distinction from `Wait::Blocked` lives entirely in what [`arm`] told the
/// bell to ring for, not in this function.
///
/// **`Gone` is the case worth having a name.** Once every sender is dropped,
/// `recv` stops blocking and returns an error immediately, every time. A
/// driver that treated that as "nothing arrived" -- which is what a bare
/// `.ok()` does -- would spin at full speed forever under `Wait::Blocked`,
/// which is precisely the busy-wait this crate exists to remove, arriving by
/// the back door at shutdown.
fn wake(wait: Wait, rx: &std::sync::mpsc::Receiver<In>) -> Woke {
    match wait {
        Wait::Blocked | Wait::Until(_) => match rx.recv() {
            Ok(msg) => Woke::Message(msg),
            Err(_) => Woke::Gone,
        },
        Wait::Now => match rx.try_recv() {
            Ok(msg) => Woke::Message(msg),
            Err(TryRecvError::Empty) => Woke::Nothing,
            Err(TryRecvError::Disconnected) => Woke::Gone,
        },
        Wait::Stop => Woke::Gone,
    }
}

/// Downgrade a wait when a message is already in hand.
///
/// `Host::cycle`'s interrupt predicate receives messages out of the mailbox
/// and parks them in a one-slot buffer, so `rx` can be empty while a message
/// is still unread. `Ended::Idle`/`Waiting` are honest about the *module* --
/// it has no work -- but acting on them here would block on `recv()` with
/// input already taken, and the board would hang holding a keystroke.
///
/// `Wait::Stop` is left alone: the module stopped, and nothing in the mailbox
/// changes that.
///
/// **The `Blocked`/`Until` downgrade is unreachable via [`life`]'s real
/// control flow today.** `peeked` becomes `Some` in exactly one place --
/// [`life`]'s `interrupted` closure -- and every call that sets it also
/// makes `interrupted` return `true` on that same call, which is what
/// `Host::cycle` checks to decide whether to return `Ended::Bound` right
/// there. `Ended::Bound::wait()` is always `Wait::Now`, and `life`'s `wait`
/// variable is assigned only from the previous turn's `cycles.ended.wait()`
/// (or `Wait::Now` initially) -- so whenever this function is called with
/// `peeked == true`, `wait` is already `Wait::Now`, and the `if peeked`
/// guard on `Blocked`/`Until` never fires. Kept anyway, not removed: it is
/// the guard that keeps this invariant true if `Host::cycle`'s exit checks
/// are ever reordered, and its own direct unit test
/// (`a_peeked_message_downgrades_a_blocking_wait`) exercises it without
/// going through `life` at all.
fn wait_with_peek(wait: Wait, peeked: bool) -> Wait {
    match wait {
        Wait::Blocked | Wait::Until(_) if peeked => Wait::Now,
        other => other,
    }
}

/// What step 2 of `life`'s turn decided to do, before any of it is acted on.
///
/// Extracted out of `life` so the property this fix rests on -- draining
/// `peeked`, `first` and `rx`'s backlog happens *before* a `Woke::Gone` wake
/// gets any say in whether the turn ends -- can be tested without a real
/// `Host`/`Machine`/`Module`, the way [`wait_with_peek`] already is.
/// `drain_turn` never touches `apply` or `shut_down` itself; it hands the
/// caller a plan, in order, and reports the decision rather than the side
/// effects.
struct Drain {
    /// Every message to hand to `apply`, in the order `life`'s step 2 always
    /// used: `peeked` first (it was received before anything `wake`
    /// returned this turn), then `first`, then the rest of `rx`'s backlog.
    /// Never contains `In::Shutdown` -- see `stopping`.
    apply: Vec<In>,
    /// The first `In::Shutdown` drained, pulled out of `apply`'s batch
    /// because ending the loop is `life`'s job, not `apply`'s -- see
    /// `apply`'s own doc for what happens if one reaches it directly.
    stopping: Option<oneshot::Sender<()>>,
    /// Whether this turn should end with `LifeEnd::Gone`, once `apply`'s
    /// batch has actually been applied and, if `stopping` is `Some`,
    /// `shut_down` has run instead of this.
    ends_gone: bool,
}

/// Build this turn's [`Drain`] plan: fold `peeked`, `first` and `rx`'s
/// backlog into one ordered batch, and only then let `woke_gone` decide
/// whether the turn ends.
///
/// This is the whole fix for the bug `wait_with_peek`'s own doc warns
/// about: `woke_gone` is not consulted until *after* the loop below has
/// already decided `apply` and `stopping`. A message already taken out of
/// `rx` -- `peeked`'s reason to exist -- is a message already received, and
/// `Woke::Gone` says nobody can send *again*, not that this batch never
/// happened. A drained `Shutdown` always wins over a `Gone` wake too: it
/// still deserves the real `shut_down()` sweep `life` runs for `stopping`,
/// not silent starvation because it happened to be the last message anyone
/// ever sent.
fn drain_turn(
    peeked: Option<In>,
    first: Option<In>,
    rx: &std::sync::mpsc::Receiver<In>,
    woke_gone: bool,
) -> Drain {
    let mut apply = Vec::new();
    let mut stopping = None;
    for msg in peeked
        .into_iter()
        .chain(first)
        .chain(std::iter::from_fn(|| rx.try_recv().ok()))
    {
        if let In::Shutdown { done } = msg {
            stopping = Some(done);
            continue;
        }
        apply.push(msg);
    }
    let ends_gone = woke_gone && stopping.is_none();
    Drain { apply, stopping, ends_gone }
}

/// How often to report [`mbbs::PollCensus`], from `MBBS_POLL_CENSUS` -- a
/// whole number of seconds, or absent to report never.
///
/// An environment variable rather than a flag for the same reason
/// `MBBS_TRACE_SHIMS` is one: it is a diagnostic an operator turns on for a
/// window to answer a question, not a way to configure a board. Anything
/// unparseable is "off" rather than an error, because a board refusing to
/// start over a malformed diagnostic knob would be the worse failure.
fn census_interval() -> Option<Duration> {
    std::env::var("MBBS_POLL_CENSUS")
        .ok()?
        .parse::<u64>()
        .ok()
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
}

/// Print what the poll budget bought, no more than once per `every`.
///
/// Reported from the host thread rather than sampled by a reader outside it,
/// because unlike [`Boot::clock_reads`] and its neighbours this is not a
/// single counter -- it is four that only mean anything read together and
/// cleared together, which [`mbbs::Host::take_census`] does in one step.
///
/// The census is taken on every reporting turn and dropped between them, so
/// the numbers describe the interval just ended rather than all of time.
///
/// # The two lines are gated separately, on purpose
///
/// An earlier version returned before either `eprintln!` when `census.polls`
/// was zero -- reasonable for the *poll* line, which has nothing to divide
/// by at that point, but it silently dropped the *driver-turn* line too,
/// which answers a completely different question and is never undefined:
/// `turns`/`worst_turn` come from `life`'s own loop, not from
/// `mbbs::Host::take_census`, and are meaningful whenever this function
/// runs at all. A machine with no terminal connected yet -- exactly the
/// shape of a board's boot-time database update, before any channel exists
/// to poll -- has `census.polls == 0` for the update's entire duration, and
/// the worst-cycle number is precisely the stall metric worth seeing during
/// it (see the `MBBS_TRACE_TURNS` diagnostic this same gap already drove
/// someone to add, at this function's own call site in `life`, as a
/// stopgap for the report this fixes). So the driver-turn line prints
/// whenever this function runs and at least one turn happened, and the
/// poll line prints only when there is a poll census worth dividing by --
/// two conditions, not one shared early return.
fn report_census<A: Abi>(
    host: &mut mbbs::Host<A>,
    due: &mut Instant,
    every: Option<Duration>,
    turns: &mut u64,
    worst_turn: &mut Duration,
) {
    let Some(every) = every else { return };
    if Instant::now() < *due {
        return;
    }
    *due = Instant::now() + every;
    let (loops, longest) = (*turns, *worst_turn);
    *turns = 0;
    *worst_turn = Duration::ZERO;
    let census = host.take_census();
    let secs = every.as_secs_f64();
    if census.polls > 0 {
        eprintln!(
            "mbbs-server: census: {polls} polls ({rate:.0}/s), {barren} barren \
             ({barren_pct:.1}%), {calls:.1} host calls each, worst {worst}",
            polls = census.polls,
            rate = census.polls as f64 / secs,
            barren = census.barren,
            barren_pct = census.barren_pct(),
            calls = census.per_poll(),
            worst = census.worst,
        );
    }
    if loops > 0 {
        eprintln!(
            "mbbs-server: census: {loops} driver turns, \
             worst cycle {longest:.0?} -- that is the ceiling on input latency",
        );
    }
}

/// `mjrfin` -- `MAJORBBS.C:4818-4831`: hang every channel up, then run every
/// module's `finrou`.
///
///
/// **Hangup first, and in that order.** A module's `huprou`/`lofrou` is where
/// per-player state is written back; its `finrou` is where the world's is.
/// Running them the other way round would finalise a world whose players had
/// not yet been saved into it.
///
/// Nothing here is allowed to abort the rest. A module that stops during its
/// own shutdown has already had whatever `finrou` ran before the fault, and
/// the remaining modules still have theirs to run -- so a stop is reported
/// and the sweep continues rather than propagating. There is no next life to
/// recover into: this is the last thing the thread does.
fn shut_down<A: Abi>(
    host: &mut mbbs::Host<A>,
    machine: &mut A::Cpu,
    module: &A::Module,
    conns: &mut [Option<Sender<Out>>],
    terms: Terms,
) {
    for chan in terms.all() {
        if conns[chan.index()].is_none() {
            continue;
        }
        if let Err(e) = host.hangup(machine, module, chan) {
            eprintln!("mbbs-server: shutdown: hanging up channel {chan}: {e}");
        }
        if let Some(conn) = conns[chan.index()].as_ref() {
            let _ = conn.try_send(Out::Close);
        }
        conns[chan.index()] = None;
    }

    let mut dispatched = 0;
    match host.finalize(machine, module, &mut dispatched) {
        Ok(None) => {
            eprintln!("mbbs-server: shutdown: {dispatched} module(s) finalised");
        }
        Ok(Some(poison)) => eprintln!(
            "mbbs-server: shutdown: a module stopped during its own finrou after \
             {dispatched} finalised: {poison:?}"
        ),
        Err(e) => eprintln!(
            "mbbs-server: shutdown: finrou sweep failed after {dispatched}: {e}"
        ),
    }

    // After the modules' own shutdown, not before -- a `finrou` still has
    // its files open to write through, and `close_btrieve` reindexes
    // whatever a module leaves dirty rather than assuming every module
    // closed everything itself.
    match host.close_btrieve() {
        Ok(n) => eprintln!("mbbs-server: shutdown: {n} btrieve block(s) closed"),
        Err(e) => eprintln!("mbbs-server: shutdown: closing btrieve blocks failed: {e}"),
    }

    report_notes(host);
}

/// How many times [`run`] will rebuild a machine after [`Ended::Stopped`]
/// before giving up, and over what window. See [`RestartPolicy`].
///
/// A module that stops on every life is a bug a restart will not fix --
/// rebuilding forever would spend a full NE load and relocation pass in a
/// tight loop, which for a real multi-megabyte `.DLL` is not free the way an
/// idle poll dispatch is. Five restarts inside a minute is generous room for
/// a genuine one-off wall (or five different players each finding a
/// different one) to recover the board unattended, while still bounding a
/// true crash loop to five module reloads a minute -- noise next to the
/// ~500 poll dispatches a second this host already spends idling with two
/// players in the Realm (see `DEFAULT_POLLS_PER_SECOND`'s doc in `main.rs`).
/// Five and sixty are both arbitrary within that bound; a future operator
/// with a real crash-loop incident to look at should retune the constant,
/// not the mechanism.
const MAX_RESTARTS: usize = 5;
const RESTART_WINDOW: Duration = Duration::from_secs(60);

/// Bounds how often [`run`] may rebuild the machine after [`Ended::Stopped`].
///
/// A bare counter, not a counter-plus-sleep: the window alone already bounds
/// the worst case (at most [`MAX_RESTARTS`] machine rebuilds in any
/// [`RESTART_WINDOW`]) regardless of how quickly one life can reach a stop,
/// so an explicit backoff sleep on top of it would be a second mechanism
/// enforcing the same bound.
struct RestartPolicy {
    /// Every restart still inside `RESTART_WINDOW` of the last [`allow`]
    /// call, oldest first.
    ///
    /// [`allow`]: RestartPolicy::allow
    recent: VecDeque<Instant>,
}

impl RestartPolicy {
    fn new() -> Self {
        Self { recent: VecDeque::new() }
    }

    /// Record a stop at `now` and say whether [`run`] may restart.
    ///
    /// `now` is a parameter rather than read from the clock here so a test
    /// can drive the rolling window without a real sleep -- see this
    /// module's tests, which advance `now` by arithmetic on `Instant`
    /// instead of waiting sixty real seconds for the window to roll over.
    fn allow(&mut self, now: Instant) -> bool {
        while let Some(&oldest) = self.recent.front() {
            if now.duration_since(oldest) > RESTART_WINDOW {
                self.recent.pop_front();
            } else {
                break;
            }
        }
        if self.recent.len() >= MAX_RESTARTS {
            false
        } else {
            self.recent.push_back(now);
            true
        }
    }
}

/// How one life of the host thread ended.
enum LifeEnd<A: Abi> {
    /// Every `Sender<In>` is gone -- see [`Woke::Gone`]. The whole
    /// supervisor should stop, not just this life.
    Gone,
    /// [`In::Shutdown`] arrived and [`shut_down`] has already run. Distinct
    /// from [`LifeEnd::Gone`] because a restart would be actively wrong here:
    /// the module has been finalised, and rebuilding it would take the board
    /// back up -- and, for MajorMUD, rewrite the `WCCRECOV.FLG` that the
    /// shutdown just removed.
    ShutDown,
    /// The module stopped inside the steady-state driver loop.
    ///
    /// `chan` is `None` when the stop came from [`Host::cycle`]'s kick
    /// sweep rather than a channel dispatch: a timer callback has no
    /// channel to name. See [`mbbs::Ended::Stopped`].
    Stopped { poison: A::Poison, chan: Option<Chan> },
}

/// Names who a stop happened to, for [`run`]'s log line -- pulled out as its
/// own pure function so it has a unit test of its own rather than being
/// legible only by eyeballing `--nocapture` output. `None` is spelled out
/// rather than left to a reader's inference, because the honest fact ("a
/// kick fired, not a player") is exactly the thing a driver reading the log
/// wants to know and a bare "no channel" does not say.
fn describe_stop(chan: Option<Chan>) -> String {
    match chan {
        Some(chan) => format!("channel {chan}"),
        None => "no channel (a kick fired, not a player)".to_owned(),
    }
}

/// Turn a batch of notes into the lines to print, collapsing each run of
/// identical ones into a single line with a count.
///
/// **The collapsing is not cosmetic.** `Host::note` has no per-message
/// suppression of its own -- that is `note_once`, and only some call sites
/// use it -- so one note inside a loop the module runs to completion arrives
/// thousands of times. Measured: a single session driving a character into
/// the Realm recorded 4,962 notes, 4,962 of them the *same* `setbtv` stack
/// overflow. Printed one per line that buries the twenty-odd distinct notes
/// around it, which is the same as not reporting them at all.
///
/// That particular note has since moved to `note_once` (see `shims::btrieve`'s
/// `push`), because it recurs *by design* rather than in one burst, and this
/// function deliberately cannot help with that -- runs collapse within a batch
/// only, so a note arriving a few times per driver turn still prints every
/// turn. The measurement above is kept because it is still what justifies
/// collapsing at all: any note reached from inside a module loop behaves that
/// way, and most call sites are still plain `note`.
///
/// Runs are collapsed **within one batch and never across batches**, so a
/// line's count is always the whole run and nothing has to be remembered
/// between calls. The cost is that a note repeating once per driver turn
/// prints once per turn -- a note that repeats *forever* at a slow rate is
/// `note_once`'s job, not this function's, and pretending otherwise here
/// would mean holding a run open indefinitely and never printing its tally.
fn collapse(notes: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < notes.len() {
        let mut end = at + 1;
        while end < notes.len() && notes[end] == notes[at] {
            end += 1;
        }
        out.push(match end - at {
            1 => notes[at].clone(),
            n => format!("{} [x{n}]", notes[at]),
        });
        at = end;
    }
    out
}

/// The bare name a `Boot::extension` builder sees for a loaded module: the
/// module's own path stem (`WCCMMUD.DLL` -> `WCCMMUD`), lowercased
/// (-> `wccmmud`) -- exactly what a script or lib file writes as a bare
/// global (`local mud = wccmmud`). A path with no stem at all (empty, or
/// `..`) names as an empty string rather than panicking; an extension
/// builder that receives one is free to treat it as unresolvable, the same
/// as any other name nothing binds.
fn module_name(path: &std::path::Path) -> String {
    path.file_stem().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default()
}

/// Drain everything the host has recorded since the last call and print it.
///
/// `Host::notes` is the host's only way to say something the *module* cannot
/// be told -- a status nothing dispatches, a command dropped for lack of an
/// entry point, a `setbtv` stack that overflowed, the clock going backwards.
/// Every one of those is a fact about this host's fidelity, and until this
/// existed the binary never read the list: the notes accumulated in memory
/// for the life of the process and were discarded with it. Draining rather
/// than borrowing is what keeps the same note from being reported on every
/// turn of the driver loop, and is also what stops the list growing without
/// bound -- see `Host::drain_notes`.
fn report_notes<A: Abi>(host: &mut Host<A>) {
    // The module's own console first: `shocst` is how a module addresses the
    // operator directly (MajorMUD announces "Recovery mode has now
    // completed." this way), so it outranks this host's observations about
    // it. Collapsed the same way for the same reason -- a module that
    // announces from inside a loop announces thousands of times.
    for line in collapse(&host.drain_audit()) {
        eprintln!("mbbs-server: console: {line}");
    }
    for line in collapse(&host.drain_notes()) {
        eprintln!("mbbs-server: note: {line}");
    }
}

/// The extra clause an init stop earns when the library it could not serve
/// is a module the operator listed *later* on the command line.
///
/// `--module` order is load order (see [`Boot::modules`]): an import binds
/// against what is already loaded and against nothing else, so
/// `--module wccmmpls.dll --module wccmmud.dll` stops on `WCCMMUD.dll`'s
/// own symbols with nothing in the message to say the file is right there,
/// one argument to the right. Matched on the file stem, case-insensitively:
/// a PE import directory spells the library `WCCMMUD.dll` and the file on
/// disk is `wccmmud.dll`.
fn later_module_hint(library: &str, remaining: &[PathBuf]) -> Option<String> {
    let want = Path::new(library).file_stem()?.to_str()?;
    remaining
        .iter()
        .filter_map(|p| p.file_stem()?.to_str())
        .any(|stem| stem.eq_ignore_ascii_case(want))
        .then(|| format!(" -- {library} is given later on the command line; --module order is load order"))
}

/// Build a fresh machine, boot every module in `boot.modules` on it in the
/// order given, and drive the steady state until the module stops or every
/// connection is gone.
///
/// # Errors
///
/// If the machine cannot be built, `boot.modules` is empty, any module
/// cannot be loaded or relocated, any module's ordinal 1 (the init routine)
/// itself stops, `finish_init` fails, or [`Boot::extension`] is present and
/// fails to build, this returns `Err` -- a broken deployment, which [`run`]
/// does not retry (see the module doc). A script directory that fails to
/// load belongs in this same bucket, not a warning: a board that silently
/// came up without its scripts is the failure this refuses to be. Every one
/// of those errors names the module's own path, the way [`LoadError::Globals`]
/// names the symbol it refuses -- with `N` modules "the module failed to
/// load" is not an answer an operator can act on. Once the steady state
/// begins, only [`LifeEnd::Stopped`] is reported through the `Ok` path; any
/// other error out of `apply`/`cycle`/`flush` (a host bug, not a module
/// poisoning) still ends the whole supervisor -- restarting on an error this
/// crate does not understand would hide it, not fix it.
///
/// [`LoadError::Globals`]: mbbs::LoadError::Globals
fn life<A: Abi>(
    boot: &Boot<A>,
    rx: &std::sync::mpsc::Receiver<In>,
    deadline: &watch::Sender<Option<Duration>>,
    survey: Option<&mbbs::survey::Shared>,
) -> io::Result<LifeEnd<A>> {
    if boot.modules.is_empty() {
        // A caller bug, not an operator mistake -- the CLI layer (`main.rs`)
        // always supplies at least one path (`--module`'s own default), so
        // this can only be reached by a `Boot` built by hand. Refused here,
        // loudly, rather than left to panic on `loaded[0]` below: "compile
        // errors beat runtime crashes beat undefined behaviour", and a
        // `Vec<PathBuf>` cannot enforce non-emptiness at the type level
        // without a bespoke wrapper this one call site does not justify.
        return Err(io::Error::other(
            "Boot::modules is empty; at least one module is required to boot a machine",
        ));
    }

    // 1. Build the machine HERE, via `Boot::build`. It is !Send; it cannot
    //    be handed in.
    let mut machine = (boot.build)()?;
    let mut host = Host::<A>::new(&mut machine, boot.root.clone(), boot.terms)?;
    // `MAJORBBS.C:999` -- the real `WGSERVER.EXE` opens its own generic data
    // file and publishes `genbb` before any module initialises, and modules
    // dereference that global without ever assigning it. A board is exactly the
    // caller this belongs to: it is a startup step with a side effect on
    // `boot.root`, which is why `Host::new` does not do it. See
    // `Host::open_genbb` for the disassembled call site that made it necessary.
    host.open_genbb(&mut machine);

    // Every life gets the SAME shared inventory `run` built -- see `Boot::survey`'s
    // own doc for why this cannot be a fresh `Inventory` per life: a `Host`
    // (and everything it owns) is rebuilt from scratch on every restart, and
    // an inventory attached only to a life's own `Host` would be destroyed
    // with it.
    if let Some(inventory) = survey {
        host.enable_survey(inventory.clone());
    }
    // Before any module runs a single instruction: `bturno` is read during
    // init by modules that gate on it, so a serial written after the first
    // module's ordinal 1 would be written too late to be seen. See
    // `Boot::bturno`.
    if let Some(serial) = &boot.bturno {
        host.globals()
            .write_mem(A::mem(&mut machine), "bturno", serial.as_bytes())?;
    }

    // 2. Load and initialise every module, in the order `boot.modules` gives
    //    them -- one module fully loaded, entered at ordinal 1, and run to
    //    completion before the next one's file is even read. See
    //    `Boot::modules`'s own doc for why this order is the entire channel-
    //    entry contract (load order -> registration order -> who
    //    `Host::connect` dispatches into) and not merely a loop shape.
    //
    //    `loaded[0]` -- not the last, not "whichever registered" -- is what
    //    every `apply`/`flush` call below hands to `Host::connect`/
    //    `Host::hangup`/`Host::run` as "the module": see `Boot::modules`'s
    //    doc, "Thunk ownership across modules", for exactly what that does
    //    and does not promise.
    let mut loaded: Vec<A::Module> = Vec::with_capacity(boot.modules.len());
    for (index, path) in boot.modules.iter().enumerate() {
        let file = std::fs::read(path)
            .map_err(|e| io::Error::other(format!("{}: {e}", path.display())))?;
        let module = host
            .load(&mut machine, &file)
            .map_err(|e| io::Error::other(format!("{}: {e}", path.display())))?;
        let entry = A::init_entry(&module).ok_or_else(|| {
            io::Error::other(format!("{}: module has no ordinal 1 (the init routine)", path.display()))
        })?;
        match host.run(&mut machine, &module, entry, &[], None)? {
            Outcome::Returned { .. } => {}
            // The init routine itself poisoning the machine is a boot
            // failure, not a survivable stop: `Host::run` reports it as
            // `Ok(Outcome::Stopped)` rather than an `Err`, so it has to be
            // checked here rather than relying on `?` above to catch it.
            // Continuing to load the next module (or to `finish_init`) on an
            // already-poisoned machine would run setup on a machine that will
            // refuse every call, so this stops the whole boot before either
            // happens.
            //
            // "init", not "ordinal 1": init is resolved by NAME now
            // (`_INIT__<DLL>`, `Abi::init_entry`), and ordinal 1 is only the
            // fallback. This message said "ordinal 1" long after that stopped
            // being true, naming an entry point the loader no longer uses --
            // for The Rose it is ordinal 403, and ordinal 1 is a crt0 stub
            // this host deliberately never enters.
            //
            // `A::fault_site` appends the NE segment when the poison carries
            // a code address, because the raw `cs:ip` in it is a *selector*
            // and reading one as a segment sends the reader to the wrong
            // function entirely -- see that method's own doc comment for the
            // hour that cost.
            Outcome::Stopped(poison) => {
                let site = match A::fault_site(&module, &poison) {
                    Some(at) => format!(" ({at})"),
                    None => String::new(),
                };
                // The commonest way to get here is the operator naming the
                // modules in the wrong order, and the raw stop cannot say
                // so: "WCCMMUD.mmlog is not implemented" reads as a host
                // gap when the module supplying it is sitting in the very
                // next `--module`. Read out of the poison itself
                // (`Abi::unimplemented_library`), never off the formatted
                // message.
                let hint = A::unimplemented_library(&poison)
                    .and_then(|library| later_module_hint(library, &boot.modules[index + 1..]))
                    .unwrap_or_default();
                return Err(io::Error::other(format!(
                    "{}: module init stopped before boot completed: {poison}{site}{hint}",
                    path.display()
                )));
            }
        }
        loaded.push(module);
    }
    // `alcvda`'s allocation, inside `finish_init`, sizes every channel's
    // volatile data area off `vdasiz` -- and `vdasiz` is still accumulating
    // as each module's own `dclvda` calls run during ITS init (see
    // `Host::finish_init`'s own doc, `MAJORBBS.C:896`: `inimod()` over every
    // module, `alcvda()` next, in that order). Calling this once, after the
    // loop above rather than inside it, is not a convenience -- a machine
    // with two modules that each call `dclvda` and got `finish_init` per
    // module would size the volatile area off whichever module's own
    // `dclvda` total happened to be visible at that module's own turn, never
    // the sum every module actually needs.
    host.finish_init(&mut machine)?;

    // 3. Build and install this life's own extension, on this thread, the
    //    way `boot.build` builds this life's own `A::Cpu` above -- see
    //    `Boot::extension`'s own doc for why this cannot be handed in
    //    ready-made, and why it must run HERE, after every module has
    //    loaded AND initialised, not before: `M.declare{...}` validates
    //    against a module's LIVE export table, so building the extension
    //    any earlier (as this driver did before this reorder) would
    //    validate against a table that was not fully populated yet. A
    //    directory that fails to load is this life's own boot failure,
    //    reported and *not* retried, exactly like a module that cannot
    //    load (see this function's own doc, "Errors").
    //
    //    `loaded.iter()`, not `loaded.into_iter()` -- `loaded` is still
    //    needed just below, to pick out the primary module. Each pair's
    //    own name is its `boot.modules` path's stem, lowercased (matching
    //    a bare `local mud = wccmmud` a script or lib file would write),
    //    zipped positionally with `loaded` since both vectors are built by
    //    the SAME loop above, in the SAME order.
    if let Some(build_ext) = &boot.extension {
        let named: Vec<(String, A::Module)> = boot
            .modules
            .iter()
            .zip(loaded.iter())
            .map(|(path, module)| (module_name(path), module.clone()))
            .collect();
        host.set_extension(build_ext(&named)?);
    }

    let module = loaded
        .into_iter()
        .next()
        .expect("boot.modules was checked non-empty above, so the loop pushed at least one");
    // Boot has its own notes -- every `opnbtv` whose `maxlen` disagrees with
    // the file, every `setbtv` stack overflow during init -- and they are
    // reported here rather than waiting for the first driver turn, so a board
    // that boots and then sits idle still says what it noticed on the way up.
    report_notes(&mut host);
    eprintln!(
        "mbbs-server: {} module(s) booted, serving {} channel(s)",
        boot.modules.len(),
        boot.terms.count()
    );
    // Granted by the clock inside `Host::cycle` now, not by this loop. The
    // pump's wake pattern is a property of socket traffic; the module's
    // world rate must not be.
    host.set_polls_per_second(boot.polls_per_second);
    let census_every = census_interval();
    // The poll grant's floor is a property of the MODULE's config, and this
    // host does not read another program's config and pretend to understand
    // it. What it can honestly do is report what the module asked for, so an
    // operator can apply the rule in --polls-per-second's own doc. For
    // MajorMUD the one that matters is option 24, MONSBUF. Gated on the same
    // `MBBS_POLL_CENSUS` as the running census, not a flag of its own: an
    // operator tuning the grant is exactly the operator already reading it.
    if census_every.is_some() {
        for (msgnum, value) in host.numeric_options() {
            eprintln!("mbbs-server: numopt: option {msgnum} = {value}");
        }
    }

    let terms = boot.terms;
    let mut pool = Pool::new(terms);
    let mut conns: Vec<Option<Sender<Out>>> = vec![None; terms.count().into()];
    let mut wait = Wait::Now;
    let mut census_due = Instant::now();
    // Driver-loop counters for the same report: how many turns this interval
    // took, and the longest single `cycle` call -- the ceiling on input
    // latency. Reset with it.
    let mut turns = 0u64;
    let mut worst_turn = Duration::ZERO;
    // Messages `Host::cycle`'s interrupt took out of the mailbox and has not
    // handed to `apply` yet. At most one: the predicate stops filling it as
    // soon as it is occupied, because one waiting message is all the answer
    // "should I come back?" needs.
    let mut peeked: Option<In> = None;

    loop {
        // 0. Tell the bell what to ring for -- see `arm`'s own doc -- then
        //    stamp this turn's start. `Boot::wake_age_ms`'s whole value is
        //    in being stamped unconditionally, every turn, before anything
        //    below can early-return or fail: a turn that stamps only on
        //    success could not tell "waiting correctly" from "stopped
        //    turning at all", which is exactly the distinction this meter
        //    exists to make.
        // A peeked message is a message already received: this turn must not
        // block on `rx` regardless of what the last `cycle` asked for, or the
        // board would hang holding a keystroke (see `wait_with_peek`'s doc).
        // `wait` itself -- the strategy the *next* turn inherits -- is left
        // alone; only `armed`, this turn's own arm/wake value, is downgraded.
        let armed = wait_with_peek(wait, peeked.is_some());
        arm(armed, deadline);
        if let Some(age) = &boot.wake_age_ms {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
            age.store(now_ms, Ordering::Relaxed);
        }

        // 1. Sleep according to what the previous cycle told us to do.
        let (first, woke_gone) = match wake(armed, rx) {
            Woke::Message(msg) => (Some(msg), false),
            Woke::Nothing => (None, false),
            Woke::Gone => (None, true),
        };

        // 2. Drain every message available, not just the one that woke us --
        //    taking one per wake would make a ten-line paste cost ten wakes.
        //    `In::Alarm` carries no work of its own (see its own doc) but
        //    still has to pass through `apply` so a driver here behaves
        //    exactly like `apply`'s other callers.
        //
        //    `drain_turn` is what makes this run unconditionally, even when
        //    `wake` just reported `Gone` above: `peeked` was received before
        //    anything `wake` returns this turn, and `woke_gone` does not get
        //    a say until `drain_turn` has already decided what to apply --
        //    see its own doc for why.
        let batch = drain_turn(peeked.take(), first, rx, woke_gone);
        for msg in batch.apply {
            apply(&mut host, &mut machine, &module, &mut pool, &mut conns, msg)?;
        }
        if let Some(done) = batch.stopping {
            shut_down(&mut host, &mut machine, &module, &mut conns, terms);
            // Sent after the sweep, not before: the whole point of the
            // channel is that the waiter learns when `finrou` has finished,
            // which for MajorMUD is when its buffers are on disk and
            // `WCCRECOV.FLG` is gone.
            let _ = done.send(());
            return Ok(LifeEnd::ShutDown);
        }
        if batch.ends_gone {
            // Everything `peeked` and `rx` were holding has just been
            // applied above -- `drain_turn` guarantees that regardless of
            // `woke_gone`. There is nothing left to drain and nobody left
            // to serve: every sender is gone, including the one
            // `conn::spawn_machine`'s own alarm task keeps for the
            // process's whole life -- see that function's doc for why that
            // makes this path unreachable on a real board, and reachable
            // only by a test that drives `run` with a channel of its own.
            return Ok(LifeEnd::Gone);
        }

        // 3. Turn the world.
        //
        // Timed because this is exactly how long a keystroke can sit unread
        // in the worst case. The interrupt closure below also polls `rx`, so
        // input arriving mid-cycle no longer waits for the whole burst to
        // finish -- it cuts the current pass short instead. What this timing
        // still bounds is the single pass in progress when input arrives:
        // `cycle` only consults the predicate between passes, so the felt
        // "it will echo when it is good and ready" is one pass's worth of
        // work, not the whole burst as before.
        //
        // The closure is scoped to this block so its borrow of `peeked` and
        // `rx` ends before step 2 of the *next* turn needs to drain them.
        let turn_start = Instant::now();
        // Channels whose output could not be handed over *during* the cycle.
        // Collected rather than acted on there: hanging one up needs `host`,
        // `machine` and `pool`, and `host` is mutably borrowed by `cycle` for
        // as long as the emitter can run. See `drop_channel`.
        let mut undeliverable: Vec<Chan> = Vec::new();
        let cycles = {
            let mut interrupted = || {
                if peeked.is_none() {
                    peeked = rx.try_recv().ok();
                }
                peeked.is_some()
            };
            // **Step 4 used to be the only place output left this host, and
            // that was the input-latency bug.** `flush` still runs below and
            // is still what sweeps a channel nothing dispatched into, but an
            // echo no longer waits for `cycle` to return to find it: the
            // emitter hands it over twice a pass, on both sides of the tick
            // catch-up. See `Host::cycle`'s own comments at both call sites,
            // and `MBBS_TRACE_TURNS` for the measurement that found it.
            let mut emit = |gsbl: &mut mbbs::gsbl::Gsbl| {
                emit_pending(gsbl, &conns, terms, &mut undeliverable);
            };
            host.cycle(&mut machine, &module, &mut interrupted, &mut emit)?
        };
        for chan in undeliverable {
            drop_channel(&mut host, &mut machine, &module, &mut pool, &mut conns, chan)?;
        }
        let spent = turn_start.elapsed();
        turns += 1;
        if spent > worst_turn {
            worst_turn = spent;
        }
        // DIAGNOSTIC 2026-08-20 -- `MBBS_TRACE_TURNS=<ms>` prints every turn
        // that took longer than that, at full resolution -- still the tool
        // for finding *which* turn stalled. `report_census`'s own
        // driver-turn line (below) used to be unable to answer this at all
        // on a zero-poll interval -- exactly the idle board, or the
        // boot-time database update before any terminal exists to poll --
        // because it shared one early return with the poll line it had
        // nothing to divide by; it is gated on `loops > 0` now, not on
        // `census.polls`, so the worst-cycle number this comment is about
        // shows up on the periodic report too, not only under this env var.
        if let Some(floor) = std::env::var("MBBS_TRACE_TURNS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
        {
            if spent >= Duration::from_millis(floor) {
                eprintln!(
                    "mbbs-server: turn: {spent:?}, {iters} passes, {disp} dispatches, ended {ended:?}",
                    iters = cycles.iterations,
                    disp = cycles.dispatched,
                    ended = std::mem::discriminant(&cycles.ended),
                );
            }
        }
        if let Some(meter) = &boot.clock_reads {
            meter.store(host.clock_reads(), Ordering::Relaxed);
        }
        if let Some(meter) = &boot.dispatched_total {
            meter.fetch_add(u64::try_from(cycles.dispatched).unwrap_or(u64::MAX), Ordering::Relaxed);
        }
        if let Some(meter) = &boot.calls_total {
            meter.store(host.calls(), Ordering::Relaxed);
        }
        report_census(&mut host, &mut census_due, census_every, &mut turns, &mut worst_turn);

        // 4. Everything the channels queued goes out.
        flush(&mut host, &mut machine, &module, &mut pool, &mut conns, terms)?;

        // 5. Say whatever this turn noticed. Ahead of the `Ended::Stopped`
        //    arm below on purpose: the notes from the turn that ended the
        //    life are the ones most worth having, and a drain placed after
        //    that `return` would never run on the turn that mattered.
        report_notes(&mut host);

        // 5b. Close any channel whose module handed it back to the BBS.
        //
        //     `Registration::AbsentBbs` is what a module reaches when it
        //     writes `state = 0` -- "return this user to the menuing
        //     system". A real MajorBBS has one; this host is headless and
        //     the only thing above a module here is this driver, so the
        //     honest answer to a handback is to hang the connection up
        //     rather than leave the player at a prompt nothing will ever
        //     answer again. See `Host::drain_ended`.
        host.sweep_ended(&mut machine);
        for chan in host.drain_ended() {
            if let Some(conn) = conns.get(chan.index()).and_then(Option::as_ref) {
                eprintln!("mbbs-server: channel {chan} left the module; closing");
                let _ = conn.try_send(Out::Close);
            }
        }

        match cycles.ended {
            Ended::Stopped(poison, chan) => {
                for conn in conns.iter().flatten() {
                    let _ = conn.try_send(Out::Close);
                }
                return Ok(LifeEnd::Stopped { poison, chan });
            }
            other => wait = other.wait(),
        }
    }
}

/// Build the machine, boot the module, and drive it -- rebuilding and
/// reloading everything from scratch whenever the module stops, up to
/// [`RestartPolicy`]'s bound. See the module doc for why a restart, rather
/// than hanging up one channel, is the only safe response to a stop.
///
/// `deadline` is the host thread's half of [`crate::alarm::spawn`]'s
/// channel -- every [`arm`] call this thread ever makes goes through it. A
/// caller that never spawned an alarm task (every test in this file that
/// drives `run` directly rather than through [`crate::conn::serve`]) may
/// still pass one built from a bare `tokio::sync::watch::channel(None)`: with
/// no task reading the other end, `arm`'s `send` simply finds nobody home
/// (see its own doc) and this thread falls back to `Wait::Blocked`'s and
/// `Wait::Until`'s shared behaviour of blocking on `rx` alone -- correct for
/// any test that drives every wake by hand over `rx` itself.
///
/// # Errors
///
/// If a life's *boot* fails (see [`life`]), or the module stops more than
/// [`RestartPolicy`] allows within [`RESTART_WINDOW`].
pub fn run<A: Abi>(
    boot: Boot<A>,
    rx: std::sync::mpsc::Receiver<In>,
    deadline: watch::Sender<Option<Duration>>,
) -> io::Result<()> {
    let mut policy = RestartPolicy::new();

    // Built ONCE, here -- not inside `life` -- and handed to every life by a
    // shared `Rc<RefCell<_>>`. `life` rebuilds `A::Cpu` and `Host` from
    // scratch on every restart (see the module doc, "Surviving a module
    // stop"); an inventory owned by a life's own `Host` would be destroyed
    // with it, and a survey that lost everything at the first restart would
    // not be a survey. This thread never crosses a thread boundary (`run` is
    // always called already running on the dedicated host thread -- see
    // `crates/mbbs-server/src/conn.rs`'s `std::thread::spawn` call), so
    // `Rc<RefCell<_>>` is enough; nothing here needs `Arc`.
    let inventory: Option<mbbs::survey::Shared> = match &boot.survey {
        Some(path) => Some(std::rc::Rc::new(std::cell::RefCell::new(
            mbbs::survey::Inventory::new(path)?,
        ))),
        None => None,
    };

    let result = loop {
        match life(&boot, &rx, &deadline, inventory.as_ref()) {
            Err(e) => break Err(e),
            Ok(LifeEnd::Gone) => break Ok(()),
            Ok(LifeEnd::ShutDown) => break Ok(()),
            Ok(LifeEnd::Stopped { poison, chan }) => {
                eprintln!("mbbs-server: module stopped ({}): {poison}", describe_stop(chan));

                if !policy.allow(Instant::now()) {
                    break Err(io::Error::other(format!(
                        "the module stopped {MAX_RESTARTS} times within {RESTART_WINDOW:?}; \
                         giving up rather than crash-looping"
                    )));
                }
                eprintln!("mbbs-server: restarting the module");
            }
        }
    };

    // The clean-shutdown tier of survey durability -- see `mbbs::survey::Inventory`'s
    // own doc for the other tier (`Inventory::record`'s per-symbol append,
    // which is what a `kill -9` or a crash leaves behind instead). Whatever
    // `result` is, every restart already ran through the same `inventory`,
    // so this always has the whole process's history to write, not just the
    // last life's.
    if let Some(inventory) = &inventory
        && let Err(e) = inventory.borrow_mut().finish()
    {
        eprintln!("mbbs-server: failed to write the final survey inventory: {e}");
    }

    result
}

/// Apply one boundary message to the host.
fn apply<A: Abi>(
    host: &mut Host<A>,
    machine: &mut A::Cpu,
    module: &A::Module,
    pool: &mut Pool,
    conns: &mut [Option<Sender<Out>>],
    msg: In,
) -> io::Result<()> {
    match msg {
        In::Connect { who, out, reply } => {
            let Some(chan) = pool.take() else {
                // All lines busy. Whoever is waiting on `reply` is the only
                // audience -- if they are already gone (the connection task
                // died before we got here) there is nobody left to tell.
                let _ = reply.send(None);
                return Ok(());
            };
            host.connect(machine, module, chan, &who)?;
            conns[chan.index()] = Some(out);
            let _ = reply.send(Some(chan));
            Ok(())
        }
        In::Input { chan, bytes } => {
            if conns[chan.index()].is_none() {
                // Nobody is connected on this channel in this life. Either
                // this is a duplicate arriving after `flush` already hung
                // this same connection up (Path 1: the sender closed and a
                // queued `Disconnect` drained late), or it crossed a life
                // boundary entirely -- a connection whose `Out::Close` never
                // landed (the bounded channel was full, `life`'s `try_send`
                // silently drops it) survives into a fresh life with a fresh
                // `Pool` and fresh `conns`, and this is one of its stale
                // messages (Path 2). Either way, pushing these bytes into
                // GSBL would land them on whichever *this* life's connection
                // takes this channel index next -- a stranger's keystrokes
                // in someone else's session -- so they are dropped instead.
                return Ok(());
            }
            // A `btuchi` handler that stops the machine surfaces the same
            // way a stop inside `Host::connect` does: the poison is on the
            // machine, and the next cycle reports it. Nothing to do with
            // the outcome here.
            host.push_input(machine, module, chan, &bytes)?;
            Ok(())
        }
        In::Disconnect { chan } => {
            if conns[chan.index()].is_none() {
                // Already disconnected in this life -- see the matching
                // comment on `In::Input` above for the two ways this
                // arrives. Running `Host::hangup` here would run the
                // module's `huprou`/`lofrou` against a channel this life
                // never called `Host::connect` on, and `Pool::give_back`
                // would be asked to free a channel that was never re-taken.
                // `Pool::give_back` is idempotent on its own (see its doc),
                // but `Host::hangup` is not guarded at all -- this check is
                // what keeps it from running in the first place.
                return Ok(());
            }
            host.hangup(machine, module, chan)?;
            pool.give_back(chan);
            conns[chan.index()] = None;
            Ok(())
        }
        // Nothing to apply -- see `In::Alarm`'s own doc. It exists purely to
        // unblock `wake`'s `rx.recv()`, and this arm is the whole of how that
        // shows up here: nothing upstream singles it out any more --
        // `drain_turn` used to (`saw_input`), before that field lost its last
        // reader and was deleted.
        In::Alarm => Ok(()),
        // `life` takes this out of the batch before `apply` is called, because
        // it ends the loop rather than acting on it. Reaching here means a
        // caller that is not `life` routed one in; dropping the `done` sender
        // is the safe degradation, because a dropped `oneshot::Sender` wakes
        // its receiver exactly as a send does (see `In::Shutdown`'s doc), so
        // a waiter is released rather than left hanging on a shutdown that is
        // never going to happen.
        In::Shutdown { done } => {
            drop(done);
            Ok(())
        }
    }
}

/// Offer one channel's queued output to its connection: deliver it whole if
/// the queue has a slot, leave it in GSBL to coalesce with whatever the
/// module queues next if the queue is momentarily full, and answer `false`
/// -- hang this channel up -- only when the connection is actually gone.
///
/// **A full queue is never a hangup on its own any more.** It used to be
/// (`try_send` failed, `drop_channel` ran), and slots alone made bursts of
/// tiny writes lethal: MajorMUD's character-save spinner emits a few bytes
/// per poll tick, each tick was drained into its own slot, and a timer
/// catch-up after one stalled cycle pass fired enough backlogged ticks
/// back-to-back to eat all 32 slots before the socket task woke --
/// "channel dropped (could not send output)" in the middle of creating a
/// character, with a client that was draining fine. Measured live
/// 2026-08-26/27, twice, once on each side of the m32 FS-base fix.
///
/// Holding is bounded and faithful, which is why no byte-budget hangup
/// replaces the slot one. Bounded: GSBL's own output buffer refuses to grow
/// past `OUTSIZ` (8 KiB) and raises `OVRFLW` to the module instead, so a
/// channel that never drains holds at most one buffer here plus
/// `conn::OUT_CHANNEL_BOUND` queued items -- the same ~264 KiB the old
/// design could already have in flight. Faithful: `OVRFLW` *is* the real
/// host's flow control -- GSBL never hung up a slow reader; a dead
/// connection announces itself through the socket (the writer task errors,
/// the queue closes, and the next offer here answers `Closed`), and an
/// idle-but-alive one is the module's own policy to kick, exactly as it
/// was on real hardware.
///
/// `try_reserve` before `drain_output`, not `try_send` after: draining is
/// what raises the module-visible `OUTMT` status ("your output has been
/// taken"), so a channel whose output cannot be taken yet must not drain --
/// holding the bytes *and* the status is what keeps the module's own flow
/// control honest. It also means there is never a drained buffer with
/// nowhere to go.
fn offer(gsbl: &mut mbbs::gsbl::Gsbl, sender: &Sender<Out>, chan: Chan) -> bool {
    use tokio::sync::mpsc::error::TrySendError;
    if gsbl.output_len(chan) == 0 {
        return true;
    }
    match sender.try_reserve() {
        Ok(permit) => {
            permit.send(Out::Bytes(gsbl.drain_output(chan)));
            true
        }
        Err(TrySendError::Full(())) => true,
        Err(TrySendError::Closed(())) => false,
    }
}

/// Send everything every channel queued, and hang up on anyone who cannot
/// take it -- where "cannot take it" is [`offer`]'s verdict, not a single
/// full queue.
fn flush<A: Abi>(
    host: &mut Host<A>,
    machine: &mut A::Cpu,
    module: &A::Module,
    pool: &mut Pool,
    conns: &mut [Option<Sender<Out>>],
    terms: Terms,
) -> io::Result<()> {
    for chan in terms.all() {
        let Some(sender) = &conns[chan.index()] else {
            // Output queued for a channel nobody is connected to. GSBL
            // cannot produce this on its own -- a channel is only ever
            // dispatched into after `Host::connect` -- but there is nowhere
            // to send it, so it is dropped rather than held.
            host.gsbl_mut().drain_output(chan);
            continue;
        };
        let sender = sender.clone();
        if !offer(host.gsbl_mut(), &sender, chan) {
            drop_channel(host, machine, module, pool, conns, chan)?;
        }
    }
    Ok(())
}

/// Hand every channel's pending output to its connection, recording any
/// channel that could not take it.
///
/// `flush`'s in-cycle counterpart, and deliberately not `flush` itself: this
/// runs while `Host::cycle` holds `host` mutably, so it can neither hang a
/// channel up nor clear its `conns` slot. It records instead, and `life`
/// sweeps what it recorded once the cycle has returned.
fn emit_pending(
    gsbl: &mut mbbs::gsbl::Gsbl,
    conns: &[Option<Sender<Out>>],
    terms: Terms,
    undeliverable: &mut Vec<Chan>,
) {
    for chan in terms.all() {
        // Already known dead this cycle. `flush` does not need this test --
        // it clears `conns[chan]` the moment a send fails, so its own loop
        // skips the channel and it visits each one once anyway. Here the slot
        // cannot be cleared: `conns` is held immutably while `host` is
        // borrowed by `cycle`. So this is what stops a second failure being
        // recorded, and with it a second `drop_channel` -- which would
        // dispatch the module's `huprou` again for one disconnect.
        if undeliverable.contains(&chan) {
            continue;
        }
        let Some(sender) = &conns[chan.index()] else {
            continue;
        };
        if !offer(gsbl, sender, chan) {
            undeliverable.push(chan);
        }
    }
}

/// Hang up a channel whose connection is gone.
///
/// Reached only on [`offer`]'s `Closed` verdict -- the connection task has
/// dropped its receiver, which is this design's lost-carrier signal. A
/// merely *full* queue no longer comes here at all; `offer`'s own doc
/// comment carries that story.
///
/// One function because there are now two places that reach it -- [`flush`],
/// and `life`'s own sweep of what the in-cycle emitter could not deliver --
/// and a second copy of the pool bookkeeping is how those two drift apart.
fn drop_channel<A: Abi>(
    host: &mut Host<A>,
    machine: &mut A::Cpu,
    module: &A::Module,
    pool: &mut Pool,
    conns: &mut [Option<Sender<Out>>],
    chan: Chan,
) -> io::Result<()> {
    host.hangup(machine, module, chan)?;
    pool.give_back(chan);
    conns[chan.index()] = None;
    eprintln!("mbbs-server: channel {chan} dropped (could not send output), hung up");
    Ok(())
}

#[cfg(test)]
mod tests {
    //! What these tests cannot see: `host.users` and `host.kicks` are
    //! `pub(crate)` to `mbbs`, so nothing outside that crate can call
    //! `set_polrou` or push a `Kick` -- there is no way from here to build a
    //! channel that polls, or a `Boot` whose module is anything but a real
    //! `.DLL` on disk. That means `run`'s loop, `apply`'s `Connect` success
    //! path, and `flush`'s hangup-on-full-queue path are untested here. What
    //! *is* tested is the part of `apply` that does not need a live
    //! `Host`/`Module`/`Machine` triple: a `Pool` refusing a `Connect` when
    //! empty, and a `Disconnect` returning a channel. The real coverage for
    //! the driver loop is Task 12 (two real sockets) and Task 13 (the sleep
    //! meter), both of which run against `re/WCCMMUD.DLL`.
    //!
    //! `apply`'s two "channel nobody is connected on" guards (`In::Input` and
    //! `In::Disconnect`, added for the double-free defect -- see
    //! `crates/mbbs-server/src/pool.rs`'s `give_back` doc) are the exception:
    //! they need a real `Host`/`Module`/`Machine`, but not a real `.DLL` --
    //! `mbbs::testing::Fixture` builds all three without one, which is enough
    //! to call `apply` directly and inspect `Host::gsbl_mut` afterward. The
    //! end-to-end version of the same guard, through an actual restart, is
    //! `crates/mbbs-server/tests/host_supervisor.rs`.

    use mbbs::Terms;
    use tokio::sync::mpsc::Sender;
    use tokio::sync::oneshot;

    use crate::pool::Pool;

    use super::{Woke, collapse, drain_turn, offer, wait_with_peek, wake};
    use crate::msg::{In, Out};
    use mbbs::Wait;

    fn lines(notes: &[&str]) -> Vec<String> {
        notes.iter().map(|s| (*s).to_owned()).collect()
    }

    /// A run of identical notes collapses to one line carrying the count,
    /// and the count is the length of the run rather than of the batch.
    /// One dead channel is one hang-up, however many times the emitter runs.
    ///
    /// `Host::cycle` calls the emitter twice a pass and runs many passes, and
    /// the emitter cannot clear a dead channel's `conns` slot the way `flush`
    /// does -- it holds `conns` immutably while `host` is borrowed by `cycle`.
    /// Without a guard every later call retried the same dead channel and
    /// recorded it again, and `life` calls `drop_channel` once per record --
    /// which dispatches the module's `huprou` every time. Observed on a live
    /// board as ~90 `channel 0 dropped` lines for a single disconnect.
    #[test]
    fn a_channel_that_cannot_take_its_output_is_recorded_once_however_often_the_emitter_runs() {
        let terms = Terms::new(1);
        let chan = terms.chan(0).expect("channel 0 exists at one terminal");
        let mut gsbl = mbbs::gsbl::Gsbl::new(terms);

        // A connection whose task is gone: every `try_send` answers Closed.
        let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Out>(4);
        drop(out_rx);
        let conns = vec![Some(out_tx)];

        let mut undeliverable = Vec::new();
        for _ in 0..10 {
            gsbl.transmit_raw(chan, b"ECHO");
            super::emit_pending(&mut gsbl, &conns, terms, &mut undeliverable);
        }

        assert_eq!(
            undeliverable,
            vec![chan],
            "a dead channel must be recorded once, not once per emitter call"
        );
    }

    #[test]
    fn collapse_folds_a_run_into_one_line_with_its_count() {
        let got = collapse(&lines(&["a", "b", "b", "b", "c"]));
        assert_eq!(got, lines(&["a", "b [x3]", "c"]));
    }

    /// Only *consecutive* notes fold. Two separated runs of the same message
    /// are two facts about two moments, and merging them would report a
    /// history that did not happen.
    #[test]
    fn collapse_does_not_fold_across_an_interruption() {
        let got = collapse(&lines(&["b", "b", "a", "b", "b"]));
        assert_eq!(got, lines(&["b [x2]", "a", "b [x2]"]));
    }

    /// A run that ends the batch still gets its tally -- the loop must not
    /// leave the last run unemitted.
    #[test]
    fn collapse_emits_a_run_that_reaches_the_end() {
        assert_eq!(collapse(&lines(&["a", "z", "z"])), lines(&["a", "z [x2]"]));
        assert_eq!(collapse(&lines(&["z", "z"])), lines(&["z [x2]"]));
    }

    /// Nothing recorded means nothing printed: an empty batch must not emit
    /// a blank line or a `[x0]`.
    #[test]
    fn collapse_of_nothing_is_nothing() {
        assert!(collapse(&[]).is_empty());
    }

    /// A single note keeps its exact text. The count suffix is for runs, and
    /// a `[x1]` on every ordinary line would be noise on the common case.
    #[test]
    fn collapse_leaves_a_lone_note_exactly_as_recorded() {
        assert_eq!(collapse(&lines(&["the clock went backwards"])), lines(&["the clock went backwards"]));
    }


    /// A driver whose senders are all gone must stop, not spin.
    ///
    /// This is the one part of the loop that can be tested without a booted
    /// `Machine`, and it is worth having: the plan this was built from wrote
    /// the wait step as a bare `.ok()` on each recv, which turns a dropped
    /// sender into "nothing arrived" and spins at full speed forever under
    /// `Wait::Blocked`. That is the busy-wait this whole crate exists to
    /// remove, reached by the back door at shutdown -- and no socket test
    /// finds it, because a socket test never drops its senders.
    #[test]
    fn every_wait_stops_once_the_senders_are_gone() {
        for wait in [Wait::Blocked, Wait::Until(Duration::from_secs(60)), Wait::Now, Wait::Stop] {
            let (tx, rx) = std::sync::mpsc::channel::<In>();
            drop(tx);
            assert!(
                matches!(wake(wait, &rx), Woke::Gone),
                "{wait:?} must report Gone, not spin"
            );
        }
    }

    /// `Wait::Now`'s non-blocking peek finding nothing queued is `Nothing`,
    /// not `Gone` -- a driver that shut down on an empty peek would end the
    /// board the first turn nobody had anything queued.
    ///
    /// `Wait::Until` no longer has a "nothing arrived" answer of its own: see
    /// `wake`'s doc for why it now reduces to the same blocking `rx.recv()`
    /// as `Wait::Blocked` -- a deadline coming due arrives as
    /// [`In::Alarm`], a `Woke::Message`, not a timeout `wake` can see.
    #[test]
    fn an_idle_peek_is_nothing_rather_than_gone() {
        let (tx, rx) = std::sync::mpsc::channel::<In>();
        assert!(matches!(wake(Wait::Now, &rx), Woke::Nothing));
        drop(tx);
    }

    /// `Wait::Until` blocks on the same channel `Wait::Blocked` does, and a
    /// deadline coming due is indistinguishable from any other message at
    /// this level -- it is [`In::Alarm`], delivered as `Woke::Message` like
    /// any other `In`.
    #[test]
    fn wait_until_wakes_on_a_plain_alarm_message_like_any_other() {
        let (tx, rx) = std::sync::mpsc::channel::<In>();
        tx.send(In::Alarm).expect("the receiver is still alive");
        assert!(matches!(
            wake(Wait::Until(Duration::from_secs(1)), &rx),
            Woke::Message(In::Alarm)
        ));
    }

    /// A message peeked out of the mailbox mid-cycle is a message already
    /// received. `Ended::Idle` asks the driver to block, and blocking on top
    /// of one would hang the board with input in hand -- so a full slot
    /// downgrades the wait to `Wait::Now`.
    #[test]
    fn a_peeked_message_downgrades_a_blocking_wait() {
        assert_eq!(wait_with_peek(Wait::Blocked, true), Wait::Now);
        assert_eq!(wait_with_peek(Wait::Until(Duration::from_secs(5)), true), Wait::Now);
        assert_eq!(wait_with_peek(Wait::Blocked, false), Wait::Blocked);
        assert_eq!(
            wait_with_peek(Wait::Until(Duration::from_secs(5)), false),
            Wait::Until(Duration::from_secs(5))
        );
        assert_eq!(wait_with_peek(Wait::Stop, true), Wait::Stop);
    }

    /// The whole fix, pinned directly against `drain_turn` (not a hand
    /// copy of its shape): a message `peeked` is holding must end up in
    /// `Drain::apply` even when `woke_gone` is `true`. `life` itself cannot
    /// be driven without a real `.DLL` (see this module's own doc), which is
    /// exactly why `drain_turn` was pulled out of it -- this calls the real
    /// function `life` calls, not a reimplementation of it.
    #[test]
    fn drain_turn_applies_a_peeked_message_even_when_the_wake_was_gone() {
        let terms = Terms::new(1);
        let mut pool = Pool::new(terms);
        let taken = pool.take().expect("the only channel");

        // `rx` empty and disconnected -- exactly what `wake` sees once the
        // interrupt closure has already taken the one message anyone was
        // ever going to send.
        let (tx, rx) = std::sync::mpsc::channel::<In>();
        drop(tx);
        assert!(
            matches!(wake(Wait::Now, &rx), Woke::Gone),
            "the channel must report Gone, not spin"
        );

        let peeked = Some(In::Input { chan: taken, bytes: b"hi".to_vec() });
        let batch = drain_turn(peeked, None, &rx, true);

        assert_eq!(batch.apply.len(), 1, "the peeked message must survive draining");
        let In::Input { chan, bytes } = &batch.apply[0] else {
            panic!("expected the peeked In::Input to survive draining");
        };
        assert_eq!(*chan, taken);
        assert_eq!(bytes, b"hi");
        assert!(batch.stopping.is_none());
        assert!(
            batch.ends_gone,
            "nothing else is queued, so Gone still ends the turn once the batch is applied"
        );
    }

    /// A `Shutdown` drained in the very batch that also found `rx` gone
    /// must still win: `ends_gone` is `false` whenever `stopping` is
    /// `Some`, so `life` runs the real `shut_down()` sweep instead of a bare
    /// `LifeEnd::Gone` exit that would drop `done` without ever touching
    /// `finrou`.
    #[test]
    fn drain_turn_lets_a_drained_shutdown_win_over_a_gone_wake() {
        let (tx, rx) = std::sync::mpsc::channel::<In>();
        drop(tx);

        let (done, _waiter) = oneshot::channel();
        let peeked = Some(In::Shutdown { done });
        let batch = drain_turn(peeked, None, &rx, true);

        assert!(batch.apply.is_empty(), "Shutdown must not reach apply's batch");
        assert!(batch.stopping.is_some(), "life must still see it to run shut_down");
        assert!(
            !batch.ends_gone,
            "a drained Shutdown must win over Gone, not be absorbed by a bare exit"
        );
    }

    /// `apply`'s `Connect` arm, stripped of the `Host`/`Module` it would
    /// otherwise need: a pool with nothing free must answer the reply
    /// channel with `None`; it must never build a `Chan` out of thin air.
    #[tokio::test]
    async fn a_connect_against_an_empty_pool_replies_none() {
        let terms = Terms::new(1);
        let mut pool = Pool::new(terms);
        let taken = pool.take().expect("the only channel");

        // Reproduce exactly the branch `apply` takes on `pool.take() ==
        // None`, since `apply` itself needs a live `Host`.
        let (reply_tx, reply_rx) = oneshot::channel::<Option<mbbs::Chan>>();
        match pool.take() {
            Some(_) => panic!("the pool had one channel and it is already out"),
            None => {
                let _ = reply_tx.send(None);
            }
        }
        assert_eq!(reply_rx.await, Ok(None), "all lines busy");

        pool.give_back(taken);
        assert!(pool.take().is_some(), "the channel is reusable again");
    }

    /// `apply`'s `Disconnect` arm's pool half: giving a channel back makes it
    /// takeable again. (The `Host::hangup` *success* path -- a registered
    /// module actually running `huprou` -- still needs a real `.DLL` and is
    /// not reachable from this crate's tests. The *guard* that skips
    /// `Host::hangup` entirely for an unconnected channel is reachable, and
    /// is covered by `apply_ignores_a_disconnect_for_a_channel_nobody_is_
    /// connected_on` below.)
    #[test]
    fn a_disconnect_returns_its_channel_to_the_pool() {
        let terms = Terms::new(2);
        let mut pool = Pool::new(terms);
        let a = pool.take().expect("first");
        let _b = pool.take().expect("second");
        assert!(pool.take().is_none(), "both lines busy");

        pool.give_back(a);
        assert_eq!(pool.take(), Some(a), "disconnect frees the line for reuse");
    }

    /// `apply`'s `In::Disconnect` guard: a channel nobody is connected to in
    /// *this* life must be left alone, not handed to `Host::hangup`.
    ///
    /// This is the fix for both reachable double-free paths (see
    /// `crates/mbbs-server/src/pool.rs`'s `give_back` doc and this file's
    /// module doc, "Surviving a module stop"): a duplicate `Disconnect`
    /// after `flush` already hung the same connection up in this life
    /// (Path 1), and a stale `Disconnect` carrying a channel identity from a
    /// life that has already ended, arriving after a fresh restart gave that
    /// index a fresh, unconnected `Pool`/`conns` (Path 2). Both look
    /// identical to `apply` at this point: `conns[chan.index()]` is `None`.
    ///
    /// The tripwire is deliberate: this `Fixture` loads a module but never
    /// runs its ordinal 1, so nothing ever calls `register_module` --
    /// `Host::hangup` would fail with "no module has registered" if `apply`
    /// ever reached it. Without the guard, `apply` would propagate that
    /// `Err`, which is exactly what `life`'s real loop does with it
    /// (`apply(...)?`): end the whole host thread. With the guard, `apply`
    /// never calls `Host::hangup` and returns `Ok(())`.
    #[test]
    fn apply_ignores_a_disconnect_for_a_channel_nobody_is_connected_on() {
        use mbbs::testing::Fixture;

        let terms = Terms::new(1);
        let mut fixture = Fixture::rooted_with_terms(
            mbbs::testing::scratch("mbbs-server-host-apply-guard-disconnect"),
            terms,
        );
        let module = fixture.minimal_module();
        let chan = fixture.console();

        let mut pool = Pool::new(terms);
        let mut conns: Vec<Option<Sender<Out>>> = vec![None; terms.count().into()];

        let result = super::apply(
            &mut fixture.host,
            &mut fixture.machine,
            &module,
            &mut pool,
            &mut conns,
            In::Disconnect { chan },
        );

        assert!(
            result.is_ok(),
            "an unconnected channel's stale Disconnect must be ignored \
             rather than reach Host::hangup (which errors here, with no \
             module registered): {result:?}"
        );
        assert_eq!(
            pool.take(),
            Some(chan),
            "the channel must still be free exactly once"
        );
        assert!(
            pool.take().is_none(),
            "and not a second time -- give_back must never have run"
        );
    }

    /// `apply`'s `In::Input` guard, the other half of the same fix.
    ///
    /// Proven through `Host::gsbl_mut().take_line`, which only ever answers
    /// a line `gsbl::Channel::take` actually completed. `bytes` below ends
    /// in a CR on purpose: without the guard, `push_input` would run and
    /// that CR would complete a line for a channel nobody is connected to
    /// in this life -- exactly the "a dead session's keystrokes land on
    /// whoever this life connects to the channel next" harm the guard on
    /// `In::Input` exists to prevent (see `apply`'s own comment on that
    /// arm).
    #[test]
    fn apply_ignores_input_for_a_channel_nobody_is_connected_on() {
        use mbbs::testing::Fixture;

        let terms = Terms::new(1);
        let mut fixture = Fixture::rooted_with_terms(
            mbbs::testing::scratch("mbbs-server-host-apply-guard-input"),
            terms,
        );
        let module = fixture.minimal_module();
        let chan = fixture.console();

        let mut pool = Pool::new(terms);
        let mut conns: Vec<Option<Sender<Out>>> = vec![None; terms.count().into()];

        let result = super::apply(
            &mut fixture.host,
            &mut fixture.machine,
            &module,
            &mut pool,
            &mut conns,
            In::Input { chan, bytes: b"EVIL\r".to_vec() },
        );

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(
            fixture.host.gsbl_mut().take_line(chan),
            None,
            "bytes for an unconnected channel must never reach GSBL"
        );
    }

    // `RestartPolicy`. Driven entirely by arithmetic on `Instant`, never a
    // real sleep -- see `RestartPolicy::allow`'s own doc for why `now` is a
    // parameter. Every test below shares that shape (advance `now` by
    // `Duration` math, never `std::thread::sleep`), which is exactly what
    // makes `RestartPolicy` testable without paying sixty real seconds per
    // assertion.
    use super::{MAX_RESTARTS, RESTART_WINDOW, RestartPolicy, describe_stop};
    use std::time::{Duration, Instant};

    /// `describe_stop` names a channel when it has one, and says plainly
    /// when it does not -- the only place these two facts get formatted for
    /// the log line `run` prints on every stop, so a mutation swapping the
    /// two arms (or losing the "not a player" honesty) would otherwise only
    /// be visible by eyeballing `cargo test -- --nocapture` output from
    /// `tests/host_supervisor.rs`.
    #[test]
    fn describe_stop_names_a_channel_or_says_there_is_none() {
        let chan = mbbs::Terms::new(1).chan(0).expect("channel zero of one");
        assert_eq!(describe_stop(Some(chan)), "channel 0");
        assert_eq!(describe_stop(None), "no channel (a kick fired, not a player)");
    }

    /// The first `MAX_RESTARTS` stops, all at the same instant, are every
    /// one allowed -- and the very next is refused.
    #[test]
    fn allows_exactly_max_restarts_then_refuses() {
        let mut policy = RestartPolicy::new();
        let now = Instant::now();

        for n in 0..MAX_RESTARTS {
            assert!(policy.allow(now), "restart {n} of {MAX_RESTARTS} must be allowed");
        }
        assert!(
            !policy.allow(now),
            "restart {MAX_RESTARTS} (one past the bound) must be refused"
        );
    }

    /// A restart older than the window rolls off, freeing exactly the
    /// capacity it held -- not the whole window's worth at once.
    ///
    /// The `MAX_RESTARTS` restarts are staggered a second apart (not all at
    /// one instant) so that aging them out is gradual too -- restarts
    /// recorded at the identical instant would all age out together the
    /// moment any one of them does, which would make "frees its own slot
    /// and no more" true by accident rather than by the window logic this
    /// test means to pin.
    #[test]
    fn a_restart_older_than_the_window_frees_its_own_slot_and_no_more() {
        let mut policy = RestartPolicy::new();
        let t0 = Instant::now();

        for n in 0..MAX_RESTARTS {
            assert!(policy.allow(t0 + Duration::from_secs(n as u64)), "filling the window from t0");
        }

        // Just past t0 + RESTART_WINDOW: only the restart recorded at t0
        // itself has aged out (t0 + 1s is exactly RESTART_WINDOW old here,
        // which the boundary test below pins as *not* aged out), so exactly
        // one more is allowed...
        let past_first = t0 + RESTART_WINDOW + Duration::from_secs(1);
        assert!(policy.allow(past_first), "one slot must have freed");
        // ...and the next one, at the same instant, must not be -- the
        // newly-recorded restart above refilled the slot that just freed,
        // and the other MAX_RESTARTS - 1 have not aged out yet.
        assert!(
            !policy.allow(past_first),
            "only one slot freed; a second restart at the same instant must be refused"
        );
    }

    /// The window's boundary is exclusive: a restart exactly `RESTART_WINDOW`
    /// old has not yet aged out.
    ///
    /// This is the one assertion `a_restart_older_than_the_window_frees_its_own_slot_and_no_more`
    /// does not cover -- it only exercises *past* the window, one second
    /// over. A mutation that changed `allow`'s `>` to `>=` would still pass
    /// every other test in this module and only be caught here.
    #[test]
    fn exactly_at_the_window_boundary_has_not_aged_out_yet() {
        let mut policy = RestartPolicy::new();
        let t0 = Instant::now();

        for _ in 0..MAX_RESTARTS {
            assert!(policy.allow(t0), "filling the window at t0");
        }

        let at_boundary = t0 + RESTART_WINDOW;
        assert!(
            !policy.allow(at_boundary),
            "a restart exactly RESTART_WINDOW old must not have aged out yet"
        );
    }

    /// A policy that has never refused anything keeps a bounded history --
    /// restarts spread out one at a time, each older than the window by the
    /// time the next arrives, never accumulate.
    #[test]
    fn spaced_out_restarts_never_fill_the_window() {
        let mut policy = RestartPolicy::new();
        let mut now = Instant::now();

        for n in 0..MAX_RESTARTS * 3 {
            assert!(
                policy.allow(now),
                "restart {n}, always alone in its window, must be allowed"
            );
            now += RESTART_WINDOW + Duration::from_secs(1);
        }
    }

    /// [`offer`] with room in the queue drains the channel and delivers its
    /// output as one message.
    #[test]
    fn offer_delivers_queued_output_whole() {
        let terms = Terms::new(1);
        let chan = terms.chan(0).expect("channel zero of one");
        let mut gsbl = mbbs::gsbl::Gsbl::new(terms);
        gsbl.transmit(chan, b"hello");

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Out>(4);
        assert!(offer(&mut gsbl, &tx, chan), "a deliverable channel stays up");
        assert_eq!(gsbl.output_len(chan), 0, "delivery drains the channel");
        match rx.try_recv() {
            Ok(Out::Bytes(bytes)) => assert_eq!(bytes, b"hello"),
            Ok(Out::Close) => panic!("expected bytes, got Out::Close"),
            Err(e) => panic!("expected one Out::Bytes: {e}"),
        }
    }

    /// The retired rule was `Full` == hang up, and it is what dropped a
    /// character-creation session mid-save (see [`offer`]'s doc comment):
    /// this pins the replacement. A full queue holds the bytes in GSBL --
    /// channel up, nothing drained -- and once the queue has room again,
    /// everything the module queued meanwhile arrives coalesced into one
    /// message, one slot.
    #[test]
    fn offer_holds_and_coalesces_when_the_queue_is_full() {
        let terms = Terms::new(1);
        let chan = terms.chan(0).expect("channel zero of one");
        let mut gsbl = mbbs::gsbl::Gsbl::new(terms);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Out>(1);
        tx.try_send(Out::Bytes(b"occupied".to_vec())).expect("fills the one slot");

        gsbl.transmit(chan, b"spin");
        assert!(offer(&mut gsbl, &tx, chan), "a full queue is backpressure, not a hangup");
        assert_eq!(gsbl.output_len(chan), 4, "held in GSBL, not drained into thin air");

        // The module keeps writing while the queue is full -- the spinner's
        // exact shape -- and none of it costs a slot yet.
        gsbl.transmit(chan, b"ning");
        assert!(offer(&mut gsbl, &tx, chan));

        // Queue drains; the next offer delivers everything as ONE message.
        match rx.try_recv() {
            Ok(Out::Bytes(bytes)) => assert_eq!(bytes, b"occupied"),
            Ok(Out::Close) => panic!("expected the occupying message, got Out::Close"),
            Err(e) => panic!("expected the occupying message: {e}"),
        }
        assert!(offer(&mut gsbl, &tx, chan));
        match rx.try_recv() {
            Ok(Out::Bytes(bytes)) => assert_eq!(bytes, b"spinning", "held output coalesces"),
            Ok(Out::Close) => panic!("expected the coalesced message, got Out::Close"),
            Err(e) => panic!("expected the coalesced message: {e}"),
        }
        assert_eq!(gsbl.output_len(chan), 0);
    }

    /// A connection whose task is gone is the one thing that still hangs a
    /// channel up -- and the bytes stay queued for [`drop_channel`]'s own
    /// path rather than being drained into a message nobody will take.
    #[test]
    fn offer_reports_only_a_closed_connection() {
        let terms = Terms::new(1);
        let chan = terms.chan(0).expect("channel zero of one");
        let mut gsbl = mbbs::gsbl::Gsbl::new(terms);
        gsbl.transmit(chan, b"bye");

        let (tx, rx) = tokio::sync::mpsc::channel::<Out>(4);
        drop(rx);
        assert!(!offer(&mut gsbl, &tx, chan), "a closed connection is the hangup signal");
    }

    /// The reversed-order hint: a missing library that is a module still to
    /// come earns the clause, and nothing else does. The spellings differ on
    /// purpose (`WCCMMUD.dll` in the import directory, `wccmmud.dll` on
    /// disk) -- a case-sensitive match here would never fire on the real
    /// board.
    #[test]
    fn later_module_hint_fires_only_for_a_module_still_to_be_loaded() {
        use std::path::PathBuf;

        let remaining =
            vec![PathBuf::from("/b/wccmmpls.dll"), PathBuf::from("/b/wccmmud.dll")];
        let hint = super::later_module_hint("WCCMMUD.dll", &remaining)
            .expect("the missing library is still to come");
        assert!(hint.contains("WCCMMUD.dll"), "the hint names the library: {hint}");
        assert!(hint.contains("--module order is load order"), "{hint}");

        assert_eq!(
            super::later_module_hint("WCCMMUD.dll", &[]),
            None,
            "nothing comes later: the library really is a host gap"
        );
        assert_eq!(
            super::later_module_hint("WCCMMUD.dll", &[PathBuf::from("/b/rcirose.dll")]),
            None,
            "an unrelated module later on the line explains nothing"
        );
    }
}
