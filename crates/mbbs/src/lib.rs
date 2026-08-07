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
pub mod clock;
pub mod dos;
mod exports;
mod fmt;
pub mod fsd;
mod globals;
pub mod gsbl;
pub mod heap;
pub mod msg;
pub mod random;
mod shims;
pub mod strings;
pub mod stream;
#[cfg(test)]
mod testing;
pub mod textvar;
pub mod users;

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::PathBuf;

pub use clock::{Civil, Clock};
pub use exports::Exports;
pub use fsd::Form;
pub use globals::{GLOBALS, Global, Globals, OUTBSZ};
pub use heap::{Config, Heap, Region};
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
    pub(crate) forms: Vec<Form>,

    /// Where `struct fsdscb` lives, once `fsdroom` has needed one.
    ///
    /// `inifsdscb()`, `FSDBBS.C:64`, allocates `nterms` of them and only
    /// `if (fsdtbl == NULL)`; `nterms` is one here. `None` until the first
    /// `fsdroom`, because the module *tests* the `fsdscb` global for null --
    /// `seg 3:0x430f` -- and takes another path when it is.
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

    /// How many host calls have been serviced. The progress meter: with an
    /// unfinished host, how far a module gets before it asks for something
    /// that is not there is a number rather than an impression.
    calls: u64,

    /// Whether to print each call as it is serviced. See [`Host::set_trace`].
    trace: bool,
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

impl Host {
    /// Build a host over a machine, placing its globals in memory the module
    /// will be able to address.
    ///
    /// `root` is the directory the module's own files live in.
    ///
    /// # Errors
    ///
    /// If the globals or the host's buffers cannot be mapped.
    pub fn new(machine: &mut Machine, root: impl Into<PathBuf>) -> io::Result<Self> {
        let globals = Globals::new(machine)?;
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
        let users = users::Users::new(machine, &mut heap, globals::NTERMS)?;

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
            gsbl: gsbl::Gsbl::new(globals::NTERMS),
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
            calls: 0,
            trace: std::env::var_os("MBBS_TRACE").is_some(),
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

    /// The clock `now`, `today` and `time` answer from.
    pub fn clock(&self) -> Clock {
        self.clock
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
        chan: i16,
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
    /// If `uno` names no channel, or a write runs off a segment.
    pub(crate) fn point_curusr(&mut self, machine: &mut Machine, uno: i16) -> Result<(), ShimError> {
        let slot = self
            .users()
            .slot(uno)
            .ok_or_else(|| ShimError::Failed(format!("point_curusr({uno}): there is no such channel")))?;
        let account = self
            .users()
            .account(uno)
            .expect("in range, so it has a record");
        let vda = self.users().vda(uno).unwrap_or(FarPtr::NULL);

        self.globals()
            .write(machine, "usrnum", &uno.to_le_bytes())
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
        chan: i16,
        who: &users::Connection,
    ) -> Result<(), ShimError> {
        let account = self.users().account(chan).ok_or_else(|| {
            ShimError::Failed(format!("connect_state({chan}): there is no such channel"))
        })?;
        let slot = self
            .users()
            .slot(chan)
            .expect("in range, so it has a user slot too");

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
        // Whether a reused channel should clear the whole record is a real
        // question, but it belongs with `lofrou`/disconnect -- there is no
        // disconnect in this plan to decide it against.
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

        self.point_curusr(machine, chan)
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
        chan: i16,
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
        loop {
            let Some(chan) = self.gsbl().scan() else {
                return Ok(None);
            };

            // Popped before either entry point is called, not after -- a
            // `sttrou` that re-enters through `hdlinp` must not see its own
            // status still queued.
            let status = self
                .gsbl_mut()
                .next_status(chan)
                .expect("scan just found a channel with one");

            let entry_index = match status {
                gsbl::Gsbl::CRSTG => 1,
                gsbl::Gsbl::INBLK | gsbl::Gsbl::OUTMT => 2,
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
    pub fn alcvda(&mut self, machine: &mut Machine) -> io::Result<()> {
        let size = self.globals.word(machine, "vdasiz")?;
        if size == 0 {
            return Ok(());
        }
        self.users.alcvda(machine, &mut self.heap, size)?;
        let area = self.users.vda(0).expect("channel 0, just allocated");
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

    /// `connect` needs a `&Module` whether or not this path ever reads it --
    /// [`Fixture::minimal_module`] loads one, but loading is not registering,
    /// so `f.host.modules()` is still empty and `connect` has nothing to
    /// enter. The full path, with a module that does register, is Task 10's
    /// integration test.
    #[test]
    fn connect_with_no_module_registered_is_an_error_not_a_panic() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        assert!(
            f.host
                .connect(&mut f.machine, &module, 0, &Connection::ansi("rangerdan"))
                .is_err()
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
        let module = f.minimal_module();
        f.host.gsbl_mut().push_input(0, b"look\r");
        assert!(f.host.poll(&mut f.machine, &module).is_err());
    }

    /// R20: `MAJORBBS.C:152` writes `status` unconditionally; only `shomal()`
    /// (out of scope) is behind the `!= 3` guard. Writing it only on the
    /// non-CRSTG path left `stsrou` reading a stale value on the CRSTG path.
    #[test]
    fn poll_writes_the_status_global_on_the_crstg_path_too() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        f.host.gsbl_mut().push_input(0, b"look\r");
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
        let module = f.minimal_module();
        f.host
            .gsbl_mut()
            .channel_mut(0)
            .expect("chan 0")
            .status
            .push_back(crate::gsbl::Gsbl::OVRFLW);
        f.host.gsbl_mut().push_input(0, b"look\r");

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
        let module = f.minimal_module();

        // A `struct module` block: a name, then nine far pointers, all left
        // null -- a module that registers but supplies no entry points at
        // all, `sttrou` included.
        let mut bytes = b"MajorMUD".to_vec();
        bytes.resize(25 + 9 * 4, 0);
        let block = f.bytes(&bytes, false);
        f.invoke(crate::shims::system::register_module, &Fixture::far(block))
            .expect("registered");

        f.host.gsbl_mut().push_input(0, b"look\r");
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
        let module = f.minimal_module();
        let mut bytes = b"MajorMUD".to_vec();
        bytes.resize(25 + 9 * 4, 0);
        let block = f.bytes(&bytes, false);
        f.invoke(crate::shims::system::register_module, &Fixture::far(block))
            .expect("registered");

        let outcome = f
            .host
            .connect(&mut f.machine, &module, 0, &Connection::ansi("rangerdan"))
            .expect("connect_state ran and there was nothing to call");
        assert_eq!(outcome, None, "no lonrou means no call happened");
    }

    /// R21: a `ShimError` out of `connect_state` must poison the machine and
    /// come back as `Outcome::Stopped`, the same policy `Host::run` applies
    /// to a `ShimError` from a shim it dispatched through a thunk -- not an
    /// `Err` that leaves the machine free to be called again on state that
    /// never finished writing.
    #[test]
    fn a_shim_error_in_connect_poisons_the_machine_rather_than_leaving_it_runnable() {
        let mut f = Fixture::new();
        let module = f.minimal_module();
        let past = f.host.gsbl().terms() as i16;

        let outcome = f
            .host
            .connect(&mut f.machine, &module, past, &Connection::ansi("rangerdan"))
            .expect("connect_state's failure is a stop, not a panic");
        match outcome {
            Some(crate::Outcome::Stopped(mbbs16::Poison::Unimplemented { symbol, .. })) => {
                assert!(
                    symbol.contains("connect_state"),
                    "the poison should name what failed: {symbol}"
                );
            }
            other => panic!("expected a named stop: {other:?}"),
        }

        assert!(
            f.machine.poisoned().is_some(),
            "a ShimError in connect must leave the machine unrunnable"
        );
        let entry = mbbs16::FarPtr {
            offset: 0,
            selector: f.machine.code_selector(),
        };
        assert!(
            f.machine.call(entry, &[]).is_err(),
            "a poisoned machine must refuse to be entered again"
        );
    }
}
