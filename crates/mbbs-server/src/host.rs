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
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::TryRecvError;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mbbs::abi::Abi;
use mbbs::{Chan, Ended, Host, Outcome, Terms, Wait};
use tokio::sync::mpsc::Sender;
use tokio::sync::watch;

use crate::msg::{In, Out};
use crate::pool::{MachineId, Pool};

/// Everything the host thread needs, all of it `Send`. `A::Cpu` is not
/// here and cannot be: it is `!Send`, and the thread builds its own -- see
/// [`Boot::build`].
pub struct Boot<A: Abi> {
    /// This machine's process-wide id -- see `crate::pool`'s module doc.
    /// Assigned by whoever builds this `Boot` (`main.rs` today, always the
    /// same id, since only one machine boots); [`life`] hands it straight to
    /// [`Pool::new`], so every `Chan` this machine's `Pool` takes comes back
    /// tagged with it.
    pub machine: MachineId,
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
    /// # A caveat this driver does not paper over -- MEASURED, not merely reasoned
    ///
    /// `Host::run`'s `module: &A::Module` argument names whose import table
    /// an unimplemented-symbol trap resolves against (thunk indices are
    /// assigned fresh, from zero, by each module's own `Host::load` call --
    /// see `mbbs_machine::m16::ne::Thunks::new` -- and every module's own
    /// thunk table lives at the *same* physical addresses in the machine's
    /// one shared bridge segment, so the same numeric index means a
    /// different symbol in two different modules' own tables). Whichever
    /// `A::Module` handle a given `Host::run` call is made with is the only
    /// table a trap during that call is ever resolved against -- for the
    /// whole call, even if execution crosses into a *different* already-
    /// loaded module's own code along the way (exactly the cross-module
    /// linkage `071c5a0` added `Host::load`'s `loaded_modules` registry to
    /// allow: a call resolved as `Import::Data` is a real far call straight
    /// into the other module's own code, with no host involvement and no
    /// hand-off of which `A::Module` names its thunk table).
    ///
    /// This is not a hypothetical. Booting `re/WCCMMUD.DLL` then
    /// `WCCMMPLS.DLL` (MajorMUD Plus) on one `Wg16` machine -- both real
    /// files, this driver's own per-module loop, `modules[1]`'s own handle
    /// passed to *its own* `Host::run` call exactly as this loop is
    /// written -- reached `WCCMMPLS.DLL: module ordinal 1 (init) stopped
    /// before boot completed: .thunk #66 is not implemented`. The leading
    /// `.` (an empty module name ahead of the symbol) is `Host::run`'s own
    /// fallback for `A::import` answering `None`: Plus's own thunk table
    /// index 66 came up empty. Plus's own `WCCMMUD.DLL` cross-module calls
    /// (`register_mud_addon` among them) are exactly the kind of direct,
    /// no-thunk far call described above, and `WCCMMUD.DLL` -- loaded and
    /// initialised first in this same run, `188` distinct host symbols
    /// measured -- has more than 66 of its own. The far likelier reading is
    /// that Plus's init transitively called into `WCCMMUD.DLL`'s own code,
    /// that code hit its *own* thunk 66, and this driver -- still holding
    /// Plus's `A::Module` for the `Host::run` call it made -- resolved index
    /// 66 against the wrong table and reported a symbol that may well
    /// already be served. Confirming exactly which symbol thunk 66 names in
    /// each module's own table was not done (out of scope for this driver,
    /// and arguably `mbbs-machine`'s call to fix: thunk allocation would
    /// need to be shared across every module loaded onto one machine, not
    /// restarted at zero per `Host::load` call, for a trap's raw index to
    /// mean one thing regardless of which module's code was executing when
    /// it fired).
    ///
    /// This is a pre-existing fact about cross-module calls (true since
    /// `071c5a0`, not introduced by N-module boot) that N-module-per-machine
    /// boot is simply the first feature to actually exercise -- a single
    /// module never crosses into another's code at all, and neither does two
    /// modules on two *separate* machines (this repository's only other
    /// multi-module configuration, `--module32`'s own `Wg32` machine, has its
    /// own separate `Machine`/thunk table entirely). Not something this stage
    /// claims to fix; recorded here, with the real run that found it, rather
    /// than assumed away.
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
    /// Set per machine rather than per process because two machines on one
    /// server are two boards; nothing says they share a serial.
    pub bturno: Option<String>,
    /// Poll dispatches granted per driver wake. See [`Host::refill_polls`].
    pub polls_per_wake: usize,
    /// Passes made per [`Host::cycle`] call.
    pub passes: usize,
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
/// players in the Realm (see `DEFAULT_POLLS_PER_WAKE`'s doc in `main.rs`).
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
    for line in collapse(&host.drain_notes()) {
        eprintln!("mbbs-server: note: {line}");
    }
}

/// Build a fresh machine, boot every module in `boot.modules` on it in the
/// order given, and drive the steady state until the module stops or every
/// connection is gone.
///
/// # Errors
///
/// If the machine cannot be built, `boot.modules` is empty, any module
/// cannot be loaded or relocated, any module's ordinal 1 (the init routine)
/// itself stops, or `finish_init` fails, this returns `Err` -- a broken
/// deployment, which [`run`] does not retry (see the module doc). Every one
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
    //    doc, "A caveat this driver does not paper over", for exactly what
    //    that does and does not promise.
    let mut loaded: Vec<A::Module> = Vec::with_capacity(boot.modules.len());
    for path in &boot.modules {
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
            // Ordinal 1 itself poisoning the machine is a boot failure, not a
            // survivable stop: `Host::run` reports it as `Ok(Outcome::Stopped)`
            // rather than an `Err`, so it has to be checked here rather than
            // relying on `?` above to catch it. Continuing to load the next
            // module (or to `finish_init`) on an already-poisoned machine
            // would run setup on a machine that will refuse every call, so
            // this stops the whole boot before either happens.
            Outcome::Stopped(poison) => {
                return Err(io::Error::other(format!(
                    "{}: module ordinal 1 (init) stopped before boot completed: {poison}",
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

    let terms = boot.terms;
    let mut pool = Pool::new(boot.machine, terms);
    let mut conns: Vec<Option<Sender<Out>>> = vec![None; terms.count().into()];
    let mut wait = Wait::Now;

    loop {
        // 0. Tell the bell what to ring for -- see `arm`'s own doc -- then
        //    stamp this turn's start. `Boot::wake_age_ms`'s whole value is
        //    in being stamped unconditionally, every turn, before anything
        //    below can early-return or fail: a turn that stamps only on
        //    success could not tell "waiting correctly" from "stopped
        //    turning at all", which is exactly the distinction this meter
        //    exists to make.
        arm(wait, deadline);
        if let Some(age) = &boot.wake_age_ms {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
            age.store(now_ms, Ordering::Relaxed);
        }

        // 1. Sleep according to what the previous cycle told us to do.
        let first = match wake(wait, rx) {
            Woke::Message(msg) => Some(msg),
            Woke::Nothing => None,
            Woke::Gone => return Ok(LifeEnd::Gone),
        };

        // 2. Drain every message available, not just the one that woke us --
        //    taking one per wake would make a ten-line paste cost ten wakes.
        //    `In::Alarm` carries no work of its own (see its own doc) but
        //    still has to pass through `apply` so a driver here behaves
        //    exactly like `apply`'s other callers -- `saw_input` is what
        //    tells step 3 apart from a bare bell.
        let mut saw_input = false;
        for msg in first
            .into_iter()
            .chain(std::iter::from_fn(|| rx.try_recv().ok()))
        {
            saw_input |= !matches!(msg, In::Alarm);
            apply(&mut host, &mut machine, &module, &mut pool, &mut conns, msg)?;
        }

        // 3. The pump as a derived clock (design doc §7): grant a fresh poll
        //    budget only on a turn that had a reason to expect new work --
        //    real input, or a `Wait::Until` deadline this same loop armed
        //    for an outstanding kick. Never unconditionally: a turn reached
        //    only by a stray `Alarm` while nothing was expected
        //    (`Wait::Blocked` -- no kick was ever outstanding to ring for,
        //    see `arm`) or by `Wait::Now`'s non-blocking peek (`Ended::Bound`
        //    already has budget left over from the burst in progress, so
        //    handing it a fresh one would just restart the countdown) is
        //    left to run `cycle` on whatever `polls_left` already is --
        //    ordinarily zero, which is exactly a `polling_armed` channel's
        //    resting state between bursts. `syscyc` and `prcrtk`'s kick
        //    sweep are unaffected either way: neither is gated on
        //    `polls_left` (see `Host::cycle`), so they run regardless -- the
        //    "free rider" design doc §7 names them.
        let expected_kick = matches!(wait, Wait::Until(_));
        if saw_input || expected_kick {
            host.refill_polls(&mut machine, boot.polls_per_wake)?;
        }

        // 4. Turn the world.
        let cycles = host.cycle(&mut machine, &module, boot.passes)?;
        if let Some(meter) = &boot.clock_reads {
            meter.store(host.clock_reads(), Ordering::Relaxed);
        }
        if let Some(meter) = &boot.dispatched_total {
            meter.fetch_add(u64::try_from(cycles.dispatched).unwrap_or(u64::MAX), Ordering::Relaxed);
        }
        if let Some(meter) = &boot.calls_total {
            meter.store(host.calls(), Ordering::Relaxed);
        }

        // 5. Everything the channels queued goes out.
        flush(&mut host, &mut machine, &module, &mut pool, &mut conns, terms)?;

        // 6. Say whatever this turn noticed. Ahead of the `Ended::Stopped`
        //    arm below on purpose: the notes from the turn that ended the
        //    life are the ones most worth having, and a drain placed after
        //    that `return` would never run on the turn that mattered.
        report_notes(&mut host);

        // 6b. Close any channel whose module handed it back to the BBS.
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
            let Some(routed) = pool.take() else {
                // All lines busy. Whoever is waiting on `reply` is the only
                // audience -- if they are already gone (the connection task
                // died before we got here) there is nobody left to tell.
                let _ = reply.send(None);
                return Ok(());
            };
            host.connect(machine, module, routed.chan, &who)?;
            conns[routed.chan.index()] = Some(out);
            let _ = reply.send(Some(routed));
            Ok(())
        }
        In::Input { chan: routed, bytes } => {
            if conns[routed.chan.index()].is_none() {
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
            host.gsbl_mut().push_input(routed.chan, &bytes);
            Ok(())
        }
        In::Disconnect { chan: routed } => {
            if conns[routed.chan.index()].is_none() {
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
            host.hangup(machine, module, routed.chan)?;
            pool.give_back(routed);
            conns[routed.chan.index()] = None;
            Ok(())
        }
        // Nothing to apply -- see `In::Alarm`'s own doc. It exists purely to
        // unblock `wake`'s `rx.recv()`; `life`'s own loop is what reads it
        // apart from the other variants (`saw_input`), not this function.
        In::Alarm => Ok(()),
    }
}

/// Send everything every channel queued, and hang up on anyone who cannot
/// take it.
fn flush<A: Abi>(
    host: &mut Host<A>,
    machine: &mut A::Cpu,
    module: &A::Module,
    pool: &mut Pool,
    conns: &mut [Option<Sender<Out>>],
    terms: Terms,
) -> io::Result<()> {
    for chan in terms.all() {
        let bytes = host.gsbl_mut().drain_output(chan);
        if bytes.is_empty() {
            continue;
        }
        let Some(sender) = &conns[chan.index()] else {
            // Output queued for a channel nobody is connected to. GSBL
            // cannot produce this on its own -- a channel is only ever
            // dispatched into after `Host::connect` -- but there is nowhere
            // to send it, so it is dropped rather than held.
            continue;
        };
        if sender.try_send(Out::Bytes(bytes)).is_err() {
            // Full (a client that cannot keep up) or Closed (the connection
            // task is already gone): the same treatment either way, because
            // a socket that will not drain is indistinguishable from one
            // that is gone. This is already the lost-carrier path.
            host.hangup(machine, module, chan)?;
            // `chan` here is a bare `Chan` from `terms.all()`, not a
            // `Routed` that arrived on the wire -- `Pool::key` is the
            // caller-trusts-itself pairing for exactly that case (this
            // pool's own sweep of its own channels), as opposed to
            // `Pool::give_back`'s guarded acceptance of a `Routed` handed in
            // from outside. See `pool.rs`'s doc on both.
            pool.give_back(pool.key(chan));
            conns[chan.index()] = None;
            eprintln!("mbbs-server: channel {chan} dropped (could not send output), hung up");
        }
    }
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

    use crate::pool::{MachineId, Pool};

    use super::{Woke, collapse, wake};
    use crate::msg::{In, Out};
    use mbbs::Wait;

    fn lines(notes: &[&str]) -> Vec<String> {
        notes.iter().map(|s| (*s).to_owned()).collect()
    }

    /// A run of identical notes collapses to one line carrying the count,
    /// and the count is the length of the run rather than of the batch.
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

    /// `apply`'s `Connect` arm, stripped of the `Host`/`Module` it would
    /// otherwise need: a pool with nothing free must answer the reply
    /// channel with `None`; it must never build a `Chan` out of thin air.
    #[tokio::test]
    async fn a_connect_against_an_empty_pool_replies_none() {
        let terms = Terms::new(1);
        let mut pool = Pool::new(MachineId(0), terms);
        let taken = pool.take().expect("the only channel");

        // Reproduce exactly the branch `apply` takes on `pool.take() ==
        // None`, since `apply` itself needs a live `Host`.
        let (reply_tx, reply_rx) = oneshot::channel::<Option<crate::pool::Routed>>();
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
        let mut pool = Pool::new(MachineId(0), terms);
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

        let mut pool = Pool::new(MachineId(0), terms);
        let routed = pool.key(chan);
        let mut conns: Vec<Option<Sender<Out>>> = vec![None; terms.count().into()];

        let result = super::apply(
            &mut fixture.host,
            &mut fixture.machine,
            &module,
            &mut pool,
            &mut conns,
            In::Disconnect { chan: routed },
        );

        assert!(
            result.is_ok(),
            "an unconnected channel's stale Disconnect must be ignored \
             rather than reach Host::hangup (which errors here, with no \
             module registered): {result:?}"
        );
        assert_eq!(
            pool.take(),
            Some(routed),
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

        let mut pool = Pool::new(MachineId(0), terms);
        let routed = pool.key(chan);
        let mut conns: Vec<Option<Sender<Out>>> = vec![None; terms.count().into()];

        let result = super::apply(
            &mut fixture.host,
            &mut fixture.machine,
            &module,
            &mut pool,
            &mut conns,
            In::Input { chan: routed, bytes: b"EVIL\r".to_vec() },
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
}
