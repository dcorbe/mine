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
pub use shims::system::{Agent, Kick, Registration};
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

/// Why [`Host::cycle`] stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ended {
    /// No status queued and no timer outstanding: nothing can happen until the
    /// transport delivers something. A driver should block on the socket here,
    /// not call `cycle` again.
    Idle,

    /// `max` passes were made and there is still work. `polling` is whether any
    /// channel has a polling routine installed -- the module genuinely running,
    /// where spinning is legitimate. `next_kick` is the soonest countdown in
    /// the kicktable.
    ///
    /// A driver must not spin on `Bound { polling: false, next_kick: Some(_) }`
    /// under a system clock: `prcrtk` cannot do anything before the next whole
    /// second, so it should sleep to it. See
    /// `docs/plans/2026-08-08-polling-design.md`.
    Bound {
        polling: bool,
        next_kick: Option<u16>,
    },

    /// The module stopped, on the pass it stopped on.
    Stopped(Poison),
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
    /// was asked. **Nothing runs them.** See [`Host::kicks`].
    pub(crate) kicks: Vec<Kick>,

    /// Every form `fsdroom` has sized, in the order it was asked. See
    /// [`Host::forms`].
    ///
    /// **Flat, and owed a channel key.** See [`Host::fsdscb`](Host#structfield.fsdscb).
    pub(crate) forms: Vec<Form>,

    /// Where `struct fsdscb` lives, once `fsdroom` has needed one.
    ///
    /// `inifsdscb()`, `FSDBBS.C:64`, allocates `nterms` of them, and the real
    /// `setfsd(chan)` exists precisely to select among them. `None` until the
    /// first `fsdroom`, because the module *tests* the `fsdscb` global for
    /// null -- `seg 3:0x430f` -- and takes another path when it is.
    ///
    /// # This is one control block and it should be `nterms` of them
    ///
    /// This field and [`forms`](Host#structfield.forms) above are both flat.
    /// That was a *fact* while `Host::new` fixed the count at one; since the
    /// count became a caller's input it is a **debt**, and the capability to
    /// trip it shipped with that change. Two channels in the full-screen data
    /// entry subsystem at once would share one control block and interleave
    /// their answers into a single `newans`.
    ///
    /// Not fixed here because the FSD is out of scope for the multi-channel
    /// work -- a *returning* player reaches the realm without touching a single
    /// `fsd*` routine, which is why raising the count did not have to wait for
    /// it -- so nothing in this crate can currently reach the hazard. It is
    /// recorded rather than repaired, and keying both by [`Chan`] belongs with
    /// whoever builds the form engine.
    pub(crate) fsdscb: Option<FarPtr>,

    /// Which message block `fsdroom` last read a template out of, which
    /// template, and in which mode. `fsdusr->{curmbk,tmpmsg,amode}`,
    /// `FSDBBS.C:134`, and Rust-side rather than in module memory because
    /// `fsdusr` is ordinal 264 and `WCCMMUD.DLL` never imports it.
    pub(crate) fsdtmp: Option<(FarPtr, u16, i16)>,

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
enum Dispatch {
    Entry(usize),
    Poll,
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
            forms: Vec::new(),
            fsdscb: None,
            fsdtmp: None,
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
    pub fn modules(&self) -> &[Registration] {
        &self.modules
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
    /// **This host never runs them**, and that is the one thing to know about
    /// this list. `rtkick` is a one-shot timer measured in seconds; the real
    /// host ran `prcrtk()` once per elapsed second from its main loop
    /// (`MAJORBBS.C:476-480`) and this host has neither loop nor second.
    ///
    /// So this is a record of what a main loop would owe, not a queue that is
    /// being served. MajorMUD registers two during initialisation -- a
    /// one-second heartbeat into its own segment 6, and a second one-second
    /// callback into segment 10, which is the last thing it does before it asks
    /// for a random number -- and until something runs them, MajorMUD is a world
    /// that has been built and never started.
    pub fn kicks(&self) -> &[Kick] {
        &self.kicks
    }

    /// Every form the module asked `fsdroom` to size.
    ///
    /// A record rather than a session. The real host keeps one control block
    /// per channel and overwrites it on each call; this keeps them all, because
    /// what a caller can usefully ask this host is "what did initialisation
    /// size?" and not "what is channel 0 in the middle of?".
    ///
    /// **Nothing fills one in.** A form is a screen and a user, and this host
    /// has neither -- so these are the shapes of the two screens MajorMUD would
    /// have put a new player through, measured and then set down.
    pub fn forms(&self) -> &[Form] {
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
    /// channel nobody has used" and "a channel just freed" the *same state by
    /// construction*. [`Host::connect_state`] used to note that whether a
    /// reused channel should clear its whole record was an open question; it is
    /// not open, it is answered here, and the answer is "all of it".
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

        // `Registration::entry` borrows `self.modules()` immutably, and
        // `self.run` needs `self` mutably right after -- so the pointer is
        // read out here and the borrow ends before `run` is ever reached.
        let lonrou = {
            let registered = self.modules().first().ok_or_else(|| {
                io::Error::other("no module has registered, so there is nothing to enter")
            })?;
            registered.entry(machine, 0)
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
        self.run(machine, module, lonrou, &[]).map(Some)
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

        if matches!(outcome, Outcome::Returned { .. }) {
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
                gsbl::Gsbl::CRSTG => Dispatch::Entry(1),
                gsbl::Gsbl::INBLK | gsbl::Gsbl::OUTMT => Dispatch::Entry(2),
                gsbl::Gsbl::POLSTS => Dispatch::Poll,
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
                Dispatch::Poll => match self.dopoll(machine, module, chan)? {
                    Some(outcome) => return Ok(Some(outcome)),
                    None => continue,
                },
                Dispatch::Entry(index) => index,
            };

            if status == gsbl::Gsbl::CRSTG
                && let Err(e) = self.get_input(machine, chan)
            {
                return self.shim_stop(machine, "get_input", e).map(Some);
            }

            // Same borrow trap as `connect`: read the entry pointer out of
            // `self.modules()` and let that borrow end before `self.run` needs
            // `self` mutably.
            let entry = {
                let registered = self.modules().first().ok_or_else(|| {
                    io::Error::other("no module has registered, so there is nothing to enter")
                })?;
                registered.entry(machine, entry_index)
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

    /// Turn the main loop until something says stop.
    ///
    /// `MAJORBBS.C:417-480`, minus everything this host has already declined --
    /// `syscyc`/`prctask` (`:423`), `chncyc` (`:474`), `shomal`, and the
    /// `usrptr->class` switch. What is left is: service one status if any, then
    /// catch the tick counter up to the clock, running [`Host::prcrtk`] once per
    /// elapsed second.
    ///
    /// **`max` bounds passes, not dispatches.** The real loop keeps spinning
    /// when `btuscn()` finds nothing, and that spin is not waste -- it is what
    /// lets timers come due. A bound on dispatches would make a module that
    /// stopped polling to wait on a timer return zero work forever.
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

            if !self.gsbl().pending() && self.kicks.is_empty() {
                return Ok(Cycles {
                    iterations,
                    dispatched,
                    ended: Ended::Idle,
                });
            }
        }

        let polling = self
            .users
            .terms()
            .all()
            .any(|chan| matches!(self.users.polrou(machine, chan), Ok(Some(_))));
        let next_kick = self.kicks.iter().map(|kick| kick.delay).min();
        Ok(Cycles {
            iterations,
            dispatched,
            ended: Ended::Bound { polling, next_kick },
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
        self.modules.push(Registration { description, block });
        (self.modules.len() - 1) as u16
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
    use crate::{Clock, Ended, Host, Kick, Outcome, Terms, gsbl, testing, users};
    use mbbs16::{FarPtr, Machine};

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
    /// there is a `Module` but nothing has registered.
    #[test]
    fn poll_with_a_status_queued_but_no_module_registered_is_an_error_not_a_panic() {
        let mut f = Fixture::new();
        let console = f.console();
        let module = f.minimal_module();
        f.host.gsbl_mut().push_input(console, b"look\r");
        let err = f
            .host
            .poll(&mut f.machine, &module)
            .expect_err("no module has registered");
        // R19: same reasoning as the `connect` test above -- `is_err()`
        // cannot distinguish this from a `ShimError` out of `point_curusr`,
        // `get_input` or the entry lookup, each a different failure.
        assert!(
            err.to_string().contains("no module has registered"),
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
        // No module registered, so this errors after `point_curusr` and the
        // `status` write have already run -- which is exactly what is being
        // checked.
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
        f.host
            .gsbl_mut()
            .channel_mut(console)
            .status
            .push_back(crate::gsbl::Gsbl::OVRFLW);
        f.host.gsbl_mut().push_input(console, b"look\r");

        // No module is registered, so `poll` errors -- but only once it
        // reaches the CRSTG dispatch, which it does only if the `OVRFLW`
        // ahead of it did not make `poll` stop and answer `Ok(None)`.
        let err = f
            .host
            .poll(&mut f.machine, &module)
            .expect_err("the CRSTG behind the OVRFLW is still there to dispatch");
        assert!(
            err.to_string().contains("no module has registered"),
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

    #[test]
    fn a_polling_channel_is_serviced_and_re_arms_itself() {
        let (mut f, module, rou) = polling_fixture();
        let console = f.console();
        f.host
            .users
            .set_polrou(&mut f.machine, console, Some(rou))
            .expect("channel 0");
        f.host.gsbl_mut().inject(console, gsbl::Gsbl::POLSTS);

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
        f.host.gsbl_mut().inject(console, gsbl::Gsbl::POLSTS);

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
    fn a_polling_channel_ticks_until_the_bound_and_says_it_is_still_polling() {
        let (mut f, module, rou) = polling_fixture();
        let console = f.console();
        f.host.users.set_polrou(&mut f.machine, console, Some(rou)).expect("channel 0");
        f.host.gsbl_mut().inject(console, gsbl::Gsbl::POLSTS);

        let cycles = f.host.cycle(&mut f.machine, &module, 20).expect("cycled");

        assert_eq!(cycles.iterations, 20, "the bound is what stopped it");
        assert_eq!(cycles.dispatched, 20, "one tick a pass, self-sustaining");
        assert_eq!(
            cycles.ended,
            Ended::Bound { polling: true, next_kick: None }
        );
        // The status queue must not have grown while all that happened.
        assert_eq!(f.host.gsbl_mut().next_status(console), Some(gsbl::Gsbl::POLSTS));
        assert_eq!(
            f.host.gsbl_mut().next_status(console),
            None,
            "exactly one status outstanding after 20 ticks, not 21 and not 2^20"
        );
    }

    /// A kick cannot come due under a pin, so a stepping clock is what makes
    /// this reachable at all.
    #[test]
    fn a_kick_comes_due_on_its_own_once_the_clock_moves() {
        let (mut f, module, rou) = polling_fixture();
        f.host.set_clock(Clock::stepped(1_135_952_405, 500));
        f.host.kicks.push(Kick { delay: 2, dstrou: rou });

        let cycles = f.host.cycle(&mut f.machine, &module, 50).expect("cycled");

        assert_eq!(cycles.dispatched, 1, "the kick fired, once");
        assert_eq!(cycles.ended, Ended::Idle, "and then there was nothing left");
        assert_eq!(
            cycles.iterations, 4,
            "two reads to the second, two seconds to the kick"
        );
    }

    #[test]
    fn nothing_polling_and_a_timer_pending_is_what_the_transport_must_sleep_on() {
        let (mut f, module, rou) = polling_fixture();
        f.host.kicks.push(Kick { delay: 60, dstrou: rou });
        // A pinned clock: no second can elapse, so the kick can never come due
        // and the loop can only run out of passes.
        f.host.set_clock(Clock::pinned(1_135_952_405));

        let cycles = f.host.cycle(&mut f.machine, &module, 5).expect("cycled");

        assert_eq!(
            cycles.ended,
            Ended::Bound { polling: false, next_kick: Some(60) },
            "which is exactly what _UPDATE_POLLING_ROUTINE leaves behind"
        );
        assert_eq!(cycles.dispatched, 0);
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
