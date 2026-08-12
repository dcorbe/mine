//! Running 16-bit protected-mode code on x86-64 Linux, natively.
//!
//! This is the execution core a MajorBBS/Worldgroup module host needs: it puts
//! real 16-bit code on the real CPU, in long mode's compatibility mode, with no
//! interpreter and no hypervisor. The machine-level groundwork -- that this is
//! possible at all, what it costs, and where it bites -- was established in
//! <https://github.com/dcorbe/x86-compat16>, and the design that follows from it
//! is written up in `docs/plans/2026-08-03-16bit-module-execution.md`.
//!
//! # The model
//!
//! A module is a coroutine. It runs until it wants something from the host,
//! at which point control returns here with the thunk index it called; the host
//! services the call and resumes it with an answer:
//!
//! ```no_run
//! # use mbbs16::{Exit, Machine, Ret};
//! # fn demo() -> std::io::Result<()> {
//! let mut machine = Machine::new()?;
//! machine.load_code(&[0xcb])?;              // a module that returns at once
//! let mut exit = machine.call(machine.code_ptr(0), &[])?;
//! loop {
//!     match exit {
//!         Exit::Call { index } => {
//!             let sum = machine.arg_u16(0).wrapping_add(machine.arg_u16(1));
//!             let _ = index;
//!             exit = machine.resume(Ret::U16(sum))?;
//!         }
//!         Exit::Returned { .. } | Exit::Fault { .. } | Exit::Timeout { .. } => break,
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Servicing therefore happens in ordinary Rust on the ordinary stack, not in
//! anything resembling a signal handler. It costs no extra mode transitions:
//! the module has to leave 16-bit mode to be serviced either way.
//!
//! # The ABI
//!
//! Galacticomm built these modules with Borland C in the **huge** memory model
//! using the **cdecl** convention -- established from the SDK's own compiler
//! configuration, not inferred. Arguments are pushed right to left and cleaned
//! by the caller, results come back in `AX` (or `DX:AX`), `char` is unsigned,
//! and no instruction newer than the 286 will ever appear.
//!
//! A module therefore gets three segments: code, a stack, and a data segment of
//! its own for globals -- Borland's `DGROUP`, which `MAJORBBS` exports as
//! `DGROUP@`. `DS` is loaded before entry and, like `SI`, `DI` and `BP`, is
//! **callee-saved**: whatever the module had is handed back on every resume.
//!
//! # A module cannot take the host with it
//!
//! Neither by dying nor by refusing to stop. A module that faults comes back as
//! [`Exit::Fault`]; one that overruns its CPU budget comes back as
//! [`Exit::Timeout`]. Both are terminal: the machine is [`Machine::poisoned`]
//! afterwards and refuses to be entered again.
//!
//! That is as far as this crate goes, and the limit is worth stating. A
//! module's globals are shared by every user of it, so killing a wedged call
//! leaves `DGROUP` in whatever state it was mid-update. Poisoning contains the
//! damage to "this module is now untrustworthy"; it does not repair a list
//! someone was halfway through relinking. What the host does about a poisoned
//! module -- drop its sessions, reload it, refuse it -- is the host's decision,
//! not this crate's.
//!
//! The watchdog measures **CPU time**, so a call blocked in a syscall is
//! invisible to it. See the `watchdog` module for why, and for what a host has
//! to do instead.
//!
//! # Testing
//!
//! **Run the tests in both profiles.** `cargo test -p mbbs16` and
//! `cargo test -p mbbs16 --release` are not the same check here.
//!
//! This is not a general principle, it is a measured property of this crate.
//! Deleting the instruction that loads `DX` before entering 16-bit code leaves
//! every test passing in debug and fails four of them in release: at `-O0` the
//! host's own code generation happens to leave the right value in `%rdx`
//! anyway, so the module gets it by accident. Anything whose correctness rests
//! on the contents of a register at a mode transition can be masked this way,
//! and only the other profile shows it.

mod asm;
mod farptr;
mod fault;
mod ne;
mod seg;
mod segments;
mod watchdog;

use std::io;
use std::time::Duration;

use asm::{Ctx, mbbs16_enter, trampoline};
pub use farptr::{FarPtr, FarPtrError};
pub use ne::{
    EntryPoint, Import, ImportResolver, ImportSite, Module, NeError, NeImage, Relocation,
    SegmentEntry, Source, Symbol, Target,
};
use seg::Segment;
pub use segments::Segments;
use watchdog::Watched;

/// Size of a module's code and stack segments. 64 KiB is the most a 16-bit
/// segment can address, so there is nothing to gain by asking for less.
const SEGMENT_BYTES: usize = 64 * 1024;

/// How much a selector value increases from one LDT entry to the next.
///
/// A selector is its descriptor's index shifted left by three, because the low
/// three bits carry the table-indicator and the privilege level. So consecutive
/// entries are eight apart, always.
///
/// Exported because a host has to know it. 16-bit code that walks an object
/// larger than a segment steps the *selector* to reach the next 64 KiB, and
/// the amount to step by is the one number that makes those pointers land --
/// `DOSCALLS.135` is how a Phar Lap module asks for it. Deriving it here rather
/// than writing 3 or 8 into the host keeps the two from drifting apart.
pub const SELECTOR_STEP: u16 = 1 << 3;

/// Where the thunk table sits within the **bridge** segment, which holds
/// nothing else before it.
///
/// The bridge has a segment of its own rather than a corner of the module's
/// code segment. A real module image is up to 64 KiB per segment -- six of
/// `WCCMMUD.DLL`'s are larger than the 0x8000 this used to be -- so any fixed
/// offset inside the module's own code is an offset some module collides with.
/// Nothing about the crossings changes: a thunk is reached by far call and names
/// its selector explicitly.
const THUNK_TABLE_OFFSET: usize = 0;

/// Bytes per thunk. The entry needs sixteen; thirty-two keeps `index * STRIDE`
/// legible against a hex dump and leaves room for the next thing a thunk has to
/// do before it can name itself.
const THUNK_STRIDE: usize = 32;

/// How many import thunks a module may have. The measured 16-bit API surface is
/// 408 symbols, so this is room to spare.
pub const MAX_THUNKS: u16 = 512;

/// Where the 64-bit trampoline is copied to: immediately past the thunk table,
/// in the same segment. It must live below 4 GiB, because the 16-bit far jump
/// that reaches it can name a 32-bit offset and no more.
const TRAMPOLINE_OFFSET: usize = THUNK_TABLE_OFFSET + (MAX_THUNKS as usize + 1) * THUNK_STRIDE;

/// Stack pointer a module starts with: the top of its stack segment, less a
/// word so that the first push has somewhere to go.
pub const INITIAL_SP: u16 = 0xfff0;

/// What kind of thunk reached the trampoline, carried in `CX`.
///
/// `CX` rather than `AX` because a returning module has its result in `AX`, and
/// a thunk announcing itself there would destroy it. `CX` is scratch under
/// cdecl, so nothing can be relying on it across a call.
const KIND_CALL: u16 = 0;
const KIND_RETURN: u16 = 1;

/// Bytes a **call** thunk pushes before it announces itself: the module's `AX`
/// and `CX`, which it is about to overwrite.
///
/// The module cannot be asked to save them -- it is calling what it believes is
/// an ordinary far routine -- and the thunk has nowhere else to put them. It
/// cannot reach the [`Ctx`], which lives at a 64-bit address in `%r14` that
/// compatibility mode has no encoding to name, and it cannot use `DS`, which a
/// huge-model module moves constantly. `SS:SP` is the only memory it can be sure
/// of.
///
/// [`Machine::run`] takes them straight back off and steps `SP` over them, so
/// this number appears nowhere else: `frame_sp` means what it always meant.
const THUNK_SAVES: u16 = 4;

/// The thunk a module returns *through*. Its address is what the host pushes as
/// the return half of the far-call frame, so `RETF` lands here.
const RETURN_THUNK_SLOT: u16 = MAX_THUNKS;

/// CPU time one entry point gets before the watchdog stops it.
///
/// Generous on purpose. A `sttrou` handling a line of input should return in
/// microseconds, but an `inirou` reading message files and opening Btrieve
/// tables at startup can legitimately burn real CPU, and a watchdog that fires
/// on correct behaviour is worse than none. Adjust per module with
/// [`Machine::set_budget`].
const DEFAULT_BUDGET: Duration = Duration::from_secs(5);

/// Why 16-bit execution stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// The module far-called an import thunk. Arguments are readable with
    /// [`Machine::arg_u16`]; [`Machine::resume`] continues it.
    Call { index: u16 },

    /// The module returned from the entry point it was called at, by `RETF`.
    /// `ax` alone for an `int`, `dx:ax` for anything 32 bits wide.
    Returned { ax: u16, dx: u16 },

    /// The module took a signal. Nothing is resumable, and the machine is
    /// [`Machine::poisoned`].
    ///
    /// `cs:ip` is where it stopped, as an offset within the module's own code
    /// segment -- the address a disassembly of the image is labelled with.
    Fault { signo: i32, cs: u16, ip: u16 },

    /// The module used its whole CPU budget without returning. Nothing is
    /// resumable, and the machine is [`Machine::poisoned`].
    ///
    /// `cs:ip` is wherever the tick happened to land, which for a wedged module
    /// is somewhere inside the loop it will not leave.
    Timeout { cs: u16, ip: u16 },
}

/// Why a machine will not be entered again.
///
/// The first two are the same shape as the [`Exit`] that produced them, kept so
/// a host that discarded the exit can still say what happened -- and so that
/// refusing a call can explain itself.
///
/// The third has no [`Exit`] behind it. It is the host's own judgement, reached
/// while servicing a call: this module asked for something the host does not
/// implement, and there is no honest answer to give it. See [`Machine::poison`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Poison {
    /// It faulted. See [`Exit::Fault`].
    Fault { signo: i32, cs: u16, ip: u16 },

    /// It overran its budget. See [`Exit::Timeout`].
    Timeout { cs: u16, ip: u16 },

    /// It called an import the host has no implementation for.
    Unimplemented { module: String, symbol: String },
}

impl std::fmt::Display for Poison {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fault { signo, cs, ip } => {
                write!(
                    f,
                    "module faulted with signal {signo} at {cs:#06x}:{ip:#06x}"
                )
            }
            Self::Timeout { cs, ip } => {
                write!(f, "module timed out at {cs:#06x}:{ip:#06x}")
            }
            Self::Unimplemented { module, symbol } => {
                write!(f, "{module}.{symbol} is not implemented")
            }
        }
    }
}

/// What a host call hands back to the module.
///
/// Borland's 16-bit C returns an `int` in `AX`, and anything 32 bits wide --
/// a `long`, or a far pointer -- in `DX:AX`, high half in `DX`. Naming the
/// width here rather than offering a resume method per shape keeps the choice
/// explicit at the one place it is made, which is what a table of several
/// hundred shims wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ret {
    /// Nothing to return. Both halves are cleared, so a module that reads them
    /// anyway sees something deterministic.
    Void,

    /// An `int`, in `AX`.
    U16(u16),

    /// A `long`, split `DX:AX` with the high half in `DX`.
    U32(u32),

    /// A far pointer: **segment in `DX`, offset in `AX`**. Same order as a
    /// `long`, since that is what it is -- and the pair most easily swapped.
    Far(FarPtr),
}

impl Ret {
    /// The `(AX, DX)` the module should resume with.
    fn registers(self) -> (u16, u16) {
        match self {
            Self::Void => (0, 0),
            Self::U16(v) => (v, 0),
            Self::U32(v) => (v as u16, (v >> 16) as u16),
            Self::Far(p) => (p.offset, p.selector),
        }
    }
}

/// One module's 16-bit world: its code, its stack, and the state needed to
/// re-enter it where it left off.
pub struct Machine {
    /// This module's address space: every segment it owns, plus the code,
    /// stack and data selectors execution needs to name them. See
    /// [`Segments`] for why this is a separate type rather than fields here --
    /// `mbbs32` already draws the same line between its `Machine` and `Image`.
    mem: Segments,

    /// The thunk table and the trampoline. The host's, and no module's.
    bridge: u16,

    /// The state the assembly is entered through, together with the CPU-time
    /// timer that stops a module which will not stop itself. One object because
    /// the timer holds the context's address; see [`watchdog::Watched`]. Armed
    /// for the whole of a [`Machine::call`], shim servicing included.
    ctx: Watched,

    /// `SP` when the module last called out, or `None` before its first call.
    /// The call frame -- `CS:IP`, two words -- sits at exactly this offset.
    frame_sp: Option<u16>,

    /// The module's `AX` and `CX` at that call, recovered from what its thunk
    /// pushed on the way through. Meaningless unless `frame_sp` is `Some`, which
    /// is what [`Machine::ax`] and [`Machine::cx`] assert before reading them.
    call_ax: u16,
    call_cx: u16,

    /// How much CPU time one entry point may have.
    budget: Duration,

    /// Set once the module has faulted or overrun, and never cleared. A
    /// poisoned machine refuses to be entered.
    poisoned: Option<Poison>,
}

impl Machine {
    /// Build a module's segments and lay out its thunk table.
    pub fn new() -> io::Result<Self> {
        let code = Segment::new(SEGMENT_BYTES, true)?;
        let stack = Segment::new(SEGMENT_BYTES, false)?;

        // The module's globals. Borland calls this DGROUP, and MAJORBBS exports
        // `DGROUP@` so a module can find its own -- which is what the NE loader
        // will resolve against this segment.
        let data = Segment::new(SEGMENT_BYTES, false)?;

        // The bridge: thunk table then trampoline, and nothing a module wrote.
        // Sized to exactly what it holds, so the segment limit is itself a
        // bound on where a stray far call can land.
        let tramp = trampoline();
        let mut bridge = Segment::new(TRAMPOLINE_OFFSET + tramp.len(), true)?;

        let cs64 = current_cs();
        fault::arm(cs64)?;

        let tramp_linear = bridge.linear(TRAMPOLINE_OFFSET);
        bridge.write(TRAMPOLINE_OFFSET, tramp)?;

        // An import thunk saves what it is about to destroy, names itself, and
        // leaves. That is all a real one does either; the work happens on this
        // side.
        //
        //   50                    push  %ax        \  the module's own, for a
        //   51                    push  %cx        /  shim that needs them
        //   b9 00 00              mov   $KIND_CALL, %cx
        //   b8 ii ii              mov   $index, %ax
        //   66 ea <off32> <sel>   ljmpl $CS64, $trampoline
        //
        // The return thunk does neither the pushes nor the second instruction:
        // the module's RETF has already popped its frame so there is nothing
        // beneath to save, and AX is carrying the module's result and has to
        // survive.
        //
        // The 0x66 is what makes any of this possible: without it `EA` in a
        // 16-bit segment takes a 16-bit offset and could not name the
        // trampoline. With it the offset is 32 bits, which reaches anywhere
        // below 4 GiB.
        for slot in 0..=RETURN_THUNK_SLOT {
            let kind = if slot == RETURN_THUNK_SLOT {
                KIND_RETURN
            } else {
                KIND_CALL
            };

            let mut thunk = Vec::with_capacity(THUNK_STRIDE);
            if kind == KIND_CALL {
                thunk.extend_from_slice(&[0x50, 0x51]); // push %ax; push %cx
            }
            thunk.push(0xb9);
            thunk.extend_from_slice(&kind.to_le_bytes());
            if kind == KIND_CALL {
                thunk.push(0xb8);
                thunk.extend_from_slice(&slot.to_le_bytes());
            }
            thunk.extend_from_slice(&[0x66, 0xea]);
            thunk.extend_from_slice(&tramp_linear.to_le_bytes());
            thunk.extend_from_slice(&cs64.to_le_bytes());

            // Not a `debug_assert`. A thunk that outgrew its slot writes over
            // the start of the next one, which is a corrupted jump target
            // rather than an error -- the module would leave 16-bit mode for an
            // address nobody chose. This runs 513 times at construction and
            // never again, so checking it in release costs nothing that can be
            // measured against the fault it prevents.
            assert!(
                thunk.len() <= THUNK_STRIDE,
                "thunk {slot} needs {} bytes and the stride is {THUNK_STRIDE}",
                thunk.len(),
            );
            bridge.write(
                THUNK_TABLE_OFFSET + usize::from(slot) * THUNK_STRIDE,
                &thunk,
            )?;
        }

        let (code_sel, stack_sel) = (code.selector(), stack.selector());
        let (data_sel, bridge_sel) = (data.selector(), bridge.selector());

        Ok(Self {
            mem: Segments::new(vec![code, stack, data, bridge], code_sel, stack_sel, data_sel),
            bridge: bridge_sel,
            ctx: Watched::new()?,
            frame_sp: None,
            call_ax: 0,
            call_cx: 0,
            budget: DEFAULT_BUDGET,
            poisoned: None,
        })
    }

    /// How much CPU time one entry point may have. See [`Machine::set_budget`].
    pub fn budget(&self) -> Duration {
        self.budget
    }

    /// Change the CPU budget an entry point gets, for calls made from now on.
    ///
    /// # Panics
    ///
    /// If `budget` is zero, which would mean "no time at all" but is how
    /// `timer_settime` spells "no limit". Nothing good comes of guessing which
    /// was meant.
    pub fn set_budget(&mut self, budget: Duration) {
        assert!(!budget.is_zero(), "a zero watchdog budget is not a budget");
        self.budget = budget;
    }

    /// Why this machine will not run again, if it will not.
    ///
    /// A module that faulted or overran left its globals mid-update, so it is
    /// not merely stopped -- it is untrustworthy. The host decides what follows
    /// from that; this crate only refuses to make it worse.
    pub fn poisoned(&self) -> Option<&Poison> {
        self.poisoned.as_ref()
    }

    /// Refuse this module from now on, for a reason the host reached itself.
    ///
    /// The machinery is the same one a fault or an overrun uses: the watchdog
    /// stops, the call frame is forgotten, and every later
    /// [`call`](Machine::call) fails naming the reason. Only the reason is new.
    ///
    /// It exists for the case where a module asks for something the host cannot
    /// answer. **Returning zero instead is the bug this method is here to
    /// prevent.** A host that invents a null pointer for an allocator gets a
    /// SIGSEGV somewhere in module code many calls later, naming nothing about
    /// where the lie was told; a host that poisons gets the symbol's name.
    ///
    /// The first reason wins. A module poisoned for one thing that then trips
    /// over another is still poisoned for the first, which is the one that is
    /// true.
    ///
    /// # Errors
    ///
    /// If the watchdog timer cannot be disarmed.
    pub fn poison(&mut self, reason: Poison) -> io::Result<()> {
        if self.poisoned.is_none() {
            self.poisoned = Some(reason);
        }
        self.frame_sp = None;
        self.ctx.disarm()
    }

    /// The far pointer a module should `lcall` to reach import `index`.
    ///
    /// # Panics
    ///
    /// If `index` is not below [`MAX_THUNKS`].
    pub fn thunk_address(&self, index: u16) -> FarPtr {
        assert!(
            index < MAX_THUNKS,
            "thunk index {index} is beyond MAX_THUNKS ({MAX_THUNKS})"
        );
        self.thunk_slot(index)
    }

    pub(crate) fn thunk_slot(&self, slot: u16) -> FarPtr {
        FarPtr {
            offset: (THUNK_TABLE_OFFSET + usize::from(slot) * THUNK_STRIDE) as u16,
            selector: self.bridge,
        }
    }

    /// Map `len` bytes of writable memory the module can address, and return
    /// the selector naming it.
    ///
    /// This is how the host owns memory a module can reach. It needs it twice
    /// over: for the globals a module addresses directly -- `usrnum`, `margv`,
    /// `prfbuf` and their like are imports the module never *calls*, so their
    /// fixups have to name real memory -- and later for whatever the host's
    /// allocator hands out.
    ///
    /// The segment lives as long as this machine and is not otherwise
    /// distinguished: a far pointer into it resolves through
    /// [`resolve`](Machine::resolve) and [`write`](Machine::write) like any
    /// other, and a stray far pointer that lands outside it is bounded by the
    /// same descriptor limit.
    ///
    /// # Errors
    ///
    /// If `len` is zero or larger than a 16-bit segment can address, or if the
    /// mapping or its descriptor cannot be made.
    ///
    /// Delegates to [`Segments::alloc_segment`]; kept on `Machine` so the shim
    /// layer compiles unchanged until the `Abi` conversion reaches it.
    pub fn alloc_segment(&mut self, len: usize) -> io::Result<u16> {
        self.mem.alloc_segment(len)
    }

    /// One region of `qty * size` bytes, described by `qty` consecutive LDT
    /// entries of `size` bytes each.
    ///
    /// The far pointer names the first tile; **tile `n` is at
    /// `selector + n * `[`SELECTOR_STEP`]**. That is what makes this different
    /// from `qty` separate segments, and it is not a convenience: `ptrtile` in
    /// Galacticomm's `PLSTUFF.C` is `(long)bigptr + (index << 19)`, which is
    /// the module computing a tile's address *itself*, on the selector, without
    /// telling the host. Every descriptor has to exist and be adjacent before
    /// it does.
    ///
    /// Each tile's descriptor windows only its own tile, so 16-bit code that
    /// runs off the end of one is stopped rather than sliding into the next --
    /// which is also what the real hardware did, `pltile` having passed the
    /// tile size as both the stride and the limit.
    ///
    /// # Errors
    ///
    /// If `qty` or `size` is zero, if the region cannot be mapped, or if the
    /// LDT has no run of `qty` free entries.
    ///
    /// Delegates to [`Segments::alloc_tiled`]; kept on `Machine` so the shim
    /// layer compiles unchanged until the `Abi` conversion reaches it.
    pub fn alloc_tiled(&mut self, qty: u16, size: u16) -> io::Result<FarPtr> {
        self.mem.alloc_tiled(qty, size)
    }

    /// Place a raw image at offset 0 of the scratch code segment.
    ///
    /// The image may be as large as a 16-bit segment: nothing of the host's
    /// shares that segment with it. For a real module, see
    /// [`Machine::load_ne`].
    pub fn load_code(&mut self, image: &[u8]) -> io::Result<()> {
        let code = self.mem.code_selector();
        self.mem
            .segment_mut(code)
            .expect("the scratch code segment is this machine's own")
            .write(0, image)
    }

    /// A far pointer to `offset` within the scratch code segment. The entry
    /// point of anything [`Machine::load_code`] placed there.
    pub fn code_ptr(&self, offset: u16) -> FarPtr {
        FarPtr {
            offset,
            selector: self.mem.code_selector(),
        }
    }

    /// Call a module entry point, the way the real host does.
    ///
    /// `args` are 16-bit words in declaration order; they are pushed right to
    /// left, as cdecl requires. A far pointer argument is two words, offset
    /// first.
    ///
    /// 64-bit mode has no far call that could reach 16-bit code, so the frame a
    /// far call would have left is built by hand -- the arguments, then the
    /// return `CS:IP` -- and the entry point is reached by far jump. From
    /// inside, the module cannot tell the difference: its `RETF` pops that
    /// frame and lands on the return thunk, which brings control back here as
    /// [`Exit::Returned`].
    ///
    /// The stack starts fresh at [`INITIAL_SP`] on every call, so the arguments
    /// need no cleaning afterwards even though cdecl makes that the caller's
    /// job.
    ///
    /// The watchdog is armed here and stays armed until the module reaches a
    /// terminal exit, so the budget covers the whole entry point -- every
    /// crossing, and all the time the host spends servicing imports in between.
    /// Re-arming per crossing instead would reset the budget on every host
    /// call, and a module looping on one would never expire.
    ///
    /// # Errors
    ///
    /// If the machine is [`Machine::poisoned`], or the arguments and frame will
    /// not fit on the module's stack.
    pub fn call(&mut self, entry: FarPtr, args: &[u16]) -> io::Result<Exit> {
        let () = Ctx::ASSERT_FAR_POINTER_FIRST;

        // A far jump into a segment we do not own would leave 16-bit mode with
        // no way back. Better an error here than a fault there.
        self.mem.segment(entry.selector)?;

        if let Some(poison) = &self.poisoned {
            return Err(io::Error::other(format!(
                "refusing to enter a poisoned module: {poison}"
            )));
        }

        let frame_words = args.len() + 2;
        let bytes = frame_words
            .checked_mul(2)
            .filter(|n| *n <= usize::from(INITIAL_SP))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "call frame will not fit")
            })?;

        let sp = INITIAL_SP - bytes as u16;
        let ret = self.thunk_slot(RETURN_THUNK_SLOT);

        // Laid out low to high, which is the order the module reads them:
        // return offset, return selector, then argument zero upwards. Pushing
        // right to left produces exactly this arrangement.
        let frame: Vec<u16> = std::iter::once(ret.offset)
            .chain(std::iter::once(ret.selector))
            .chain(args.iter().copied())
            .collect();

        let stack_sel = self.mem.stack_selector();
        let stack = self
            .mem
            .segment_mut(stack_sel)
            .expect("the stack segment is this machine's own");
        for (i, word) in frame.iter().enumerate() {
            stack.write(usize::from(sp) + i * 2, &word.to_le_bytes())?;
        }

        self.frame_sp = None;
        self.ctx.out_ax = 0;
        self.ctx.out_dx = 0;
        self.ctx.out_bx = 0;
        self.ctx.out_si = 0;
        self.ctx.out_di = 0;
        self.ctx.out_bp = 0;
        self.call_ax = 0;
        self.call_cx = 0;

        // A module starts with DS naming its own data segment. After that it is
        // whatever the module last had, since DS is callee-saved.
        self.ctx.out_ds = u64::from(self.mem.data);

        self.ctx.arm(self.budget)?;
        self.run(entry, sp, Ret::Void)
    }

    /// Resume the module from its outstanding call, handing back `value` in
    /// `AX`.
    ///
    /// The call frame is dropped -- `SP` moves up over the `CS:IP` the far call
    /// pushed -- but the arguments are left alone, because cdecl makes cleaning
    /// them the module's job. That is what every MajorBBS routine uses; for the
    /// ones that pop their own, see
    /// [`resume_cleaning`](Machine::resume_cleaning).
    ///
    /// # Panics
    ///
    /// If the module is not stopped at a call.
    pub fn resume(&mut self, ret: Ret) -> io::Result<Exit> {
        self.resume_cleaning(ret, 0)
    }

    /// Resume, dropping `bytes` of the module's arguments as well.
    ///
    /// For an import that pops its own arguments. Borland's 32-bit arithmetic
    /// helpers do -- `f_lumod@` and its family are called with four words on the
    /// stack and no `add sp` after the call -- and servicing one of those with
    /// [`resume`](Machine::resume) is not a crash but something worse: the
    /// module carries on with eight bytes of rubbish under its stack pointer and
    /// every frame after it is shifted.
    ///
    /// `bytes` is what the *module* pushed, so it does not include the far
    /// return address; `0` is exactly [`resume`](Machine::resume).
    ///
    /// This is where an overrun spent on host code is caught. A watchdog tick
    /// that arrives while the host is servicing an import proves the budget is
    /// gone just as surely as one that interrupts 16-bit code, and there is no
    /// sense re-entering a module whose time is up in order to stop it a moment
    /// later.
    ///
    /// # Panics
    ///
    /// If the module is not stopped at a call.
    pub fn resume_cleaning(&mut self, ret: Ret, bytes: u16) -> io::Result<Exit> {
        let sp = self
            .frame_sp
            .expect("resume() with no outstanding call to resume from");

        // Where the module's own far call will return to. A module with 34 code
        // segments calls out from any of them, so this is read back rather than
        // assumed -- but it must still be a segment we own.
        let at = FarPtr {
            offset: self.mem.stack().read_u16(usize::from(sp)),
            selector: self.mem.stack().read_u16(usize::from(sp) + 2),
        };
        debug_assert!(
            self.mem.segment(at.selector).is_ok(),
            "call frame names a segment that is not this machine's"
        );

        if self.ctx.expired() {
            // Report where it would have resumed. That is the honest answer to
            // "where did it stop": the module is parked at an import call, and
            // this is the instruction after it.
            return self.terminate(Exit::Timeout {
                cs: at.selector,
                ip: at.offset,
            });
        }

        self.run(at, sp + 4 + bytes, ret)
    }

    /// Read the `n`th 16-bit argument of the outstanding call.
    ///
    /// Arguments sit immediately above the `CS:IP` the far call pushed. cdecl
    /// pushes right to left, so argument 0 is the one nearest the frame.
    ///
    /// # Panics
    ///
    /// If the module is not stopped at a call.
    pub fn arg_u16(&self, n: usize) -> u16 {
        let sp = self
            .frame_sp
            .expect("arg_u16() with no outstanding call to read from");
        self.mem.stack().read_u16(usize::from(sp) + 4 + n * 2)
    }

    /// Read the `n`th and `n + 1`th argument words as one 32-bit value, low
    /// half first.
    ///
    /// That is a `long`, and it is also the shape a far pointer arrives in --
    /// [`arg_far`](Machine::arg_far) is the same two words read as an address
    /// rather than a number. Which of the two a given argument is depends on
    /// the routine, and for a varargs routine on the format string, so the
    /// choice belongs to the caller.
    ///
    /// # Panics
    ///
    /// If the module is not stopped at a call.
    pub fn arg_u32(&self, n: usize) -> u32 {
        u32::from(self.arg_u16(n)) | (u32::from(self.arg_u16(n + 1)) << 16)
    }

    /// The outstanding call's raw argument frame, as bytes -- the same bytes
    /// [`arg_u16`](Machine::arg_u16)/[`arg_far`](Machine::arg_far) read, but
    /// as a slice a byte-oriented cursor can walk instead of a word index.
    ///
    /// `crates/mbbs/src/abi.rs`'s `Cursor` is the caller: it decodes a shim's
    /// arguments by C type and advances by that type's byte width, so it
    /// needs the frame as one contiguous `&[u8]` rather than a method that
    /// answers one word at a time. This is where that slice comes from --
    /// starting exactly where `arg_u16` starts counting, `sp + 4`, which
    /// skips the far return address the call pushed.
    ///
    /// # How long is the frame?
    ///
    /// There is no way to know a callee's arity here -- that lives in the
    /// routine's own prototype, several layers up, and this method has no
    /// access to it. So it returns everything from the first argument to the
    /// end of the stack segment, which is the widest slice that is still
    /// honestly backed by real memory: nothing past it belongs to this
    /// module at all. A cursor built from a too-short prototype reads
    /// garbage from whatever the next call's frame left behind, exactly as
    /// `arg_u16(n)` would for too-large an `n` today -- that is a host bug in
    /// the shim's prototype, not something this method is positioned to
    /// catch.
    ///
    /// # Panics
    ///
    /// If the module is not stopped at a call, or if the frame begins past the
    /// end of the stack segment -- see below.
    ///
    /// # Why the length is computed with `checked_sub`
    ///
    /// `frame_sp` is `out_sp + THUNK_SAVES`, and [`Machine::resume`] checks
    /// only that that addition does not leave `u16` -- so `out_sp = 0xfffb`
    /// yields `frame_sp = 0xffff`, and `start` is then `0x10003`: three bytes
    /// past a 64 KiB stack. `stack.len() - start` underflows there.
    ///
    /// In debug that is a subtraction-overflow panic. In release it wraps to
    /// `usize::MAX - 2`, and -- this is the part worth stating -- that wrapped
    /// length **defeats [`seg::Segment::slice`]'s own bounds assertion**,
    /// because `offset + len` wraps in turn and lands back on exactly
    /// `self.len`. The assert passes and `from_raw_parts` is handed a length
    /// near `usize::MAX` at an out-of-bounds address, which is undefined
    /// behaviour rather than a crash.
    ///
    /// `resume` guards the adjacent case one screen up and says why; this is
    /// the same hazard reached from the other side, so it is checked the same
    /// way. A module whose stack has drifted into the last few bytes of its
    /// segment is broken, and saying so is the point.
    pub fn arg_frame(&self) -> &[u8] {
        let sp = self
            .frame_sp
            .expect("arg_frame() with no outstanding call to read from");
        let start = usize::from(sp) + 4;
        let stack = self.mem.stack();
        let len = stack.len().checked_sub(start).unwrap_or_else(|| {
            panic!(
                "the module called out at SP={sp:#06x}, so its argument frame \
                 begins at {start:#x} -- past the end of its {} byte stack",
                stack.len()
            )
        });
        stack.slice(start, len)
    }

    /// Selector of the scratch code segment [`Machine::load_code`] fills.
    ///
    /// Delegates to [`Segments::code_selector`]; kept on `Machine` so the shim
    /// layer compiles unchanged until the `Abi` conversion reaches it. Not
    /// listed among the memory methods in the design doc's file list, but
    /// `code` moved with the rest of [`Segments`], so this has to move with it
    /// to stay callable.
    pub fn code_selector(&self) -> u16 {
        self.mem.code_selector()
    }

    /// Selector of the module's stack segment.
    ///
    /// Worth having separately from the code one: under `DS != SS` a module
    /// hands out pointers to its own locals, and this is the segment they name.
    ///
    /// Delegates to [`Segments::stack_selector`]; kept on `Machine` so the
    /// shim layer compiles unchanged until the `Abi` conversion reaches it.
    pub fn stack_selector(&self) -> u16 {
        self.mem.stack_selector()
    }

    /// Selector of the module's data segment: its `DGROUP`.
    ///
    /// The scratch one until [`Machine::load_ne`] replaces it with the loaded
    /// module's own.
    ///
    /// Delegates to [`Segments::data_selector`]; kept on `Machine` so the shim
    /// layer compiles unchanged until the `Abi` conversion reaches it.
    pub fn data_selector(&self) -> u16 {
        self.mem.data_selector()
    }

    /// Borrow `len` bytes of module memory through a far pointer.
    ///
    /// This is the only correct way to follow a pointer a module gave you. The
    /// segment is found by selector -- never by adding a base -- and the access
    /// is bounds-checked against that segment's own length, which is the only
    /// place the limit is known.
    ///
    /// # Errors
    ///
    /// If the selector names nothing of this module's, or the access would run
    /// past the end of what it names. Both are things a module can do, so
    /// neither is a panic.
    ///
    /// Delegates to [`Segments::resolve`]; kept on `Machine` so the shim layer
    /// compiles unchanged until the `Abi` conversion reaches it.
    pub fn resolve(&self, ptr: FarPtr, len: usize) -> Result<&[u8], FarPtrError> {
        self.mem.resolve(ptr, len)
    }

    /// Borrow this module's whole address space, mutably.
    ///
    /// Every other memory method on `Machine` is a one-line delegation, kept
    /// deliberately narrow so `crates/mbbs`'s 247 call sites see the same
    /// surface Task 1 found -- *not* a reason to expose `mem` itself, since a
    /// bare field would let a caller replace the whole address space instead
    /// of just reading through it. This one is different in kind: `Abi::mem`
    /// (`crates/mbbs/src/abi.rs`) needs to reach `Self::Mem` from `Self::Cpu`
    /// generically, for any ABI, and `Wg16::Cpu` *is* `Machine` -- there is no
    /// narrower delegation to write, because the whole point is handing back
    /// `&mut Segments` itself rather than one more method that reads through
    /// it. So this is the one deliberate exception to "delegate, don't
    /// expose": a reborrow of the field the struct's own doc comment names,
    /// not a second copy of it.
    pub fn mem_mut(&mut self) -> &mut Segments {
        &mut self.mem
    }

    /// Read a NUL-terminated string through a far pointer, without the NUL.
    ///
    /// Most of the MajorBBS API is shaped this way. The scan stops at the end
    /// of the segment rather than running on, so a module that forgets its
    /// terminator gets an error instead of handing the host whatever follows.
    ///
    /// # Errors
    ///
    /// As [`Machine::resolve`], plus [`FarPtrError::Unterminated`].
    ///
    /// Delegates to [`Segments::read_cstr`]; kept on `Machine` so the shim
    /// layer compiles unchanged until the `Abi` conversion reaches it.
    pub fn read_cstr(&self, ptr: FarPtr) -> Result<&[u8], FarPtrError> {
        self.mem.read_cstr(ptr)
    }

    /// Write into module memory through a far pointer.
    ///
    /// The same rules as [`Machine::resolve`]: found by selector, bounds
    /// checked. Real shims need this for the API calls that fill a caller's
    /// buffer.
    ///
    /// # Errors
    ///
    /// As [`Machine::resolve`].
    ///
    /// Delegates to [`Segments::write`]; kept on `Machine` so the shim layer
    /// compiles unchanged until the `Abi` conversion reaches it.
    pub fn write(&mut self, ptr: FarPtr, bytes: &[u8]) -> Result<(), FarPtrError> {
        self.mem.write(ptr, bytes)
    }

    /// Read the `n`th argument of the outstanding call as a far pointer.
    ///
    /// A far pointer occupies two argument words: offset first, then segment,
    /// which is how a right-to-left push of `seg` then `off` leaves them. `n`
    /// counts words, so a far pointer at `n` is followed by the next argument
    /// at `n + 2`.
    ///
    /// # Panics
    ///
    /// If the module is not stopped at a call.
    pub fn arg_far(&self, n: usize) -> FarPtr {
        FarPtr {
            offset: self.arg_u16(n),
            selector: self.arg_u16(n + 1),
        }
    }

    /// `SP` as the module left it, or `None` if it is not stopped at a call.
    ///
    /// [`Machine::sp`] is this without the `None`, and panics instead: a shim
    /// reading its own arguments is always inside a call, so an absent frame
    /// there is a host bug worth crashing for. Anything that inspects a machine
    /// it did not put in that state wants this one.
    pub fn frame_sp(&self) -> Option<u16> {
        self.frame_sp
    }

    /// The module's `SP` at the outstanding call, before the call frame.
    ///
    /// Worth checking in tests: a module that is being resumed with the wrong
    /// stack pointer still runs, and says nothing about it until much later.
    ///
    /// # Panics
    ///
    /// If the module is not stopped at a call.
    pub fn sp(&self) -> u16 {
        self.frame_sp.expect("sp() with no outstanding call")
    }

    /// `SI` as the module last left it.
    pub fn si(&self) -> u16 {
        self.ctx.out_si as u16
    }

    /// `DI` as the module last left it.
    pub fn di(&self) -> u16 {
        self.ctx.out_di as u16
    }

    /// `BP` as the module last left it -- its frame pointer.
    pub fn bp(&self) -> u16 {
        self.ctx.out_bp as u16
    }

    /// `AX` as the module left it at the outstanding call.
    ///
    /// Not read from the trampoline: by the time that runs, the thunk has put
    /// its own index in `AX`. This is what the thunk pushed before it did --
    /// see [`THUNK_SAVES`].
    ///
    /// Wanted by exactly one kind of routine. Borland's 32-bit runtime helpers
    /// take their operands in registers -- `F_LXMUL@` is `DX:AX * CX:BX` and
    /// `F_LXLSH@` is `DX:AX` shifted by `CL` -- and a MajorBBS module imports
    /// those from the host like anything else.
    ///
    /// # Panics
    ///
    /// If the module is not stopped at a call.
    pub fn ax(&self) -> u16 {
        assert!(self.frame_sp.is_some(), "ax() with no outstanding call");
        self.call_ax
    }

    /// `BX` as the module left it at the outstanding call. See [`Machine::ax`].
    ///
    /// # Panics
    ///
    /// If the module is not stopped at a call.
    pub fn bx(&self) -> u16 {
        assert!(self.frame_sp.is_some(), "bx() with no outstanding call");
        self.ctx.out_bx as u16
    }

    /// `CX` as the module left it at the outstanding call. See [`Machine::ax`].
    ///
    /// # Panics
    ///
    /// If the module is not stopped at a call.
    pub fn cx(&self) -> u16 {
        assert!(self.frame_sp.is_some(), "cx() with no outstanding call");
        self.call_cx
    }

    /// `DX` as the module left it at the outstanding call. See [`Machine::ax`].
    ///
    /// No thunk destroys `DX`, so this one comes straight off the trampoline.
    ///
    /// # Panics
    ///
    /// If the module is not stopped at a call.
    pub fn dx(&self) -> u16 {
        assert!(self.frame_sp.is_some(), "dx() with no outstanding call");
        self.ctx.out_dx as u16
    }

    /// Cross into 16-bit mode and come back.
    fn run(&mut self, at: FarPtr, sp: u16, ret: Ret) -> io::Result<Exit> {
        let (ax, dx) = ret.registers();

        self.ctx.target_offset = u32::from(at.offset);
        self.ctx.target_selector = at.selector;
        self.ctx.ss16 = self.mem.stack_selector();
        self.ctx.sp = u64::from(sp);
        self.ctx.ax = u64::from(ax);
        self.ctx.dx = u64::from(dx);

        // Hand the callee-saved registers back exactly as the module left them.
        // Borland's cdecl makes SI, DI and BP the callee's to preserve, and a
        // host call is a callee like any other. Losing them does not crash
        // anything -- the module simply carries on with a value it stored
        // before the call quietly replaced, which is far worse.
        self.ctx.si = self.ctx.out_si;
        self.ctx.di = self.ctx.out_di;
        self.ctx.bp = self.ctx.out_bp;
        self.ctx.ds = self.ctx.out_ds;

        // BX and CX go back too, which cdecl does not require of a callee.
        // Not everything a module imports is a cdecl routine: Borland's own
        // runtime helpers have clobber sets its code generator knows, and
        // `F_SCOPY@` -- `rep movsb`, which never touches BX -- is one a caller
        // may hold a live value across. Preserving is the safe direction of
        // that argument, since no caller can depend on a register being
        // *destroyed*. Without this the module resumed with the host's scratch:
        // CX naming the stack segment and BX holding SP.
        self.ctx.bx = self.ctx.out_bx;
        self.ctx.cx = u64::from(self.call_cx);

        // The trampoline writes SS as a bare 16-bit store, so the rest of the
        // slot has to start clean.
        self.ctx.out_sp = 0;
        self.ctx.out_ss = 0;
        self.ctx.out_signo = 0;
        self.ctx.out_cx = 0;

        // SAFETY: every field the assembly reads is set immediately above; the
        // code and stack segments are mapped, described and live for as long as
        // `self`; and the trampoline the module will far-jump to was written
        // into the code segment by `new`.
        unsafe { mbbs16_enter(self.ctx.as_ptr()) };

        if self.ctx.out_signo != 0 {
            let signo = self.ctx.out_signo as i32;
            let cs = self.ctx.out_cs as u16;
            // The CPU pushed a 16-bit IP; the wider field is only how the
            // handler could store it.
            let ip = self.ctx.out_ip as u16;

            // Which signal it was is the whole distinction. Everything else --
            // the recovery, the poisoning, the lost state -- is identical.
            return if signo == watchdog::signo() {
                self.terminate(Exit::Timeout { cs, ip })
            } else {
                self.terminate(Exit::Fault { signo, cs, ip })
            };
        }

        debug_assert_eq!(
            self.ctx.out_ss as u16,
            self.mem.stack_selector(),
            "came back on a stack that is not the module's"
        );

        let out_sp = self.ctx.out_sp as u16;

        // Which thunk brought us here. The module's return value would have
        // been destroyed if the answer lived in AX, so it lives in CX.
        if self.ctx.out_cx as u16 == KIND_RETURN {
            self.frame_sp = None;
            // The entry point is over, so its budget is too. Leaving the timer
            // armed would charge the next call for this one's leftovers.
            self.ctx.disarm()?;
            return Ok(Exit::Returned {
                ax: self.ctx.out_ax as u16,
                dx: self.ctx.out_dx as u16,
            });
        }

        // A call thunk had to destroy AX and CX to name itself, so it pushed
        // them first, CX nearest. Take them here and step back over them, so
        // that `frame_sp` means exactly what it has always meant -- the far-call
        // frame, with the module's arguments just above -- and nothing that
        // reads an argument has to know a thunk saves anything.
        //
        // Stepping back can only leave the segment if the module called out
        // with `SP` already within four bytes of the top, which is a module
        // that has underflowed its own stack. In release `out_sp + 4` would
        // wrap to near zero and `arg_u16` would go on to read the *bottom* of
        // the stack segment and report plausible arguments, so this is checked
        // rather than assumed.
        let frame = out_sp.checked_add(THUNK_SAVES).ok_or_else(|| {
            io::Error::other(format!(
                "the module called out at SP={out_sp:#06x}, so its stack has underflowed"
            ))
        })?;
        self.call_cx = self.mem.stack().read_u16(usize::from(out_sp));
        self.call_ax = self.mem.stack().read_u16(usize::from(out_sp) + 2);
        self.frame_sp = Some(frame);

        Ok(Exit::Call {
            index: self.ctx.out_ax as u16,
        })
    }

    /// Stop for good: disarm the watchdog, poison the machine and forget the
    /// call frame.
    ///
    /// Forgetting the frame matters as much as the rest. A module that died or
    /// was stopped mid-call has nothing meaningful left on its stack, and
    /// `arg_u16` and friends would otherwise happily report the leftovers.
    fn terminate(&mut self, exit: Exit) -> io::Result<Exit> {
        self.poisoned = Some(match exit {
            Exit::Fault { signo, cs, ip } => Poison::Fault { signo, cs, ip },
            Exit::Timeout { cs, ip } => Poison::Timeout { cs, ip },
            other => unreachable!("{other:?} is not a terminal exit"),
        });
        self.frame_sp = None;
        self.ctx.disarm()?;
        Ok(exit)
    }
}

/// The selector of the 64-bit code segment we are running in.
///
/// Read rather than assumed. Linux's `__USER_CS` is 0x33, but the value has to
/// be right for the return jump to land and reading it costs one instruction.
fn current_cs() -> u16 {
    let cs: u16;
    // SAFETY: reading a segment register has no side effects.
    unsafe {
        std::arch::asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags))
    };
    cs
}
