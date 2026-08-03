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
//! let mut exit = machine.call(0, &[])?;
//! loop {
//!     match exit {
//!         Exit::Call { index } => {
//!             let sum = machine.arg_u16(0).wrapping_add(machine.arg_u16(1));
//!             let _ = index;
//!             exit = machine.resume(Ret::U16(sum))?;
//!         }
//!         Exit::Returned { .. } | Exit::Fault { .. } => break,
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
//! # What this is not, yet
//!
//! A module that faults is survivable: see [`Exit::Fault`] and the `fault`
//! module. A module that **loops forever is not** -- there is no way to
//! interrupt one yet, and for a host serving many users a wedged module is as
//! bad as a crashing one.
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
mod seg;

use std::io;

use asm::{Ctx, mbbs16_enter, trampoline};
use farptr::ldt_index;
pub use farptr::{FarPtr, FarPtrError};
use seg::Segment;

/// Size of a module's code and stack segments. 64 KiB is the most a 16-bit
/// segment can address, so there is nothing to gain by asking for less.
const SEGMENT_BYTES: usize = 64 * 1024;

/// Where the thunk table sits within the code segment, past any plausible
/// module image.
const THUNK_TABLE_OFFSET: usize = 0x8000;

/// Bytes per thunk. The entry needs eleven; sixteen keeps `index * STRIDE`
/// legible against a hex dump.
const THUNK_STRIDE: usize = 16;

/// How many import thunks a module may have. The measured 16-bit API surface is
/// 408 symbols, so this is room to spare.
pub const MAX_THUNKS: u16 = 512;

/// Where the 64-bit trampoline is copied to. It must live below 4 GiB, because
/// the 16-bit far jump that reaches it can name a 32-bit offset and no more.
const TRAMPOLINE_OFFSET: usize = 0xc000;

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

/// The thunk a module returns *through*. Its address is what the host pushes as
/// the return half of the far-call frame, so `RETF` lands here.
const RETURN_THUNK_SLOT: u16 = MAX_THUNKS;

/// Why 16-bit execution stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// The module far-called an import thunk. Arguments are readable with
    /// [`Machine::arg_u16`]; [`Machine::resume`] continues it.
    Call { index: u16 },

    /// The module returned from the entry point it was called at, by `RETF`.
    /// `ax` alone for an `int`, `dx:ax` for anything 32 bits wide.
    Returned { ax: u16, dx: u16 },

    /// The module took a signal. Nothing is resumable.
    Fault { signo: i32 },
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
    /// Every segment this module owns, in no particular order. Lookup is by
    /// selector, because that is the only thing a far pointer carries; a real
    /// NE image will add its own code and data segments here.
    segments: Vec<Segment>,
    code: usize,
    stack: usize,
    data: usize,
    ctx: Ctx,

    /// `SP` when the module last called out, or `None` before its first call.
    /// The call frame -- `CS:IP`, two words -- sits at exactly this offset.
    frame_sp: Option<u16>,
}

impl Machine {
    /// Build a module's segments and lay out its thunk table.
    pub fn new() -> io::Result<Self> {
        let mut code = Segment::new(SEGMENT_BYTES, true)?;
        let stack = Segment::new(SEGMENT_BYTES, false)?;

        // The module's globals. Borland calls this DGROUP, and MAJORBBS exports
        // `DGROUP@` so a module can find its own -- which is what the NE loader
        // will resolve against this segment.
        let data = Segment::new(SEGMENT_BYTES, false)?;

        let cs64 = current_cs();
        fault::arm(cs64)?;

        let tramp_linear = code.linear(TRAMPOLINE_OFFSET);
        code.write(TRAMPOLINE_OFFSET, trampoline())?;

        // An import thunk names itself and leaves. That is all a real one does
        // either; the work happens on this side.
        //
        //   b9 00 00              mov   $KIND_CALL, %cx
        //   b8 ii ii              mov   $index, %ax
        //   66 ea <off32> <sel>   ljmpl $CS64, $trampoline
        //
        // The return thunk omits the second instruction, because AX is carrying
        // the module's result and has to survive.
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
            thunk.push(0xb9);
            thunk.extend_from_slice(&kind.to_le_bytes());
            if kind == KIND_CALL {
                thunk.push(0xb8);
                thunk.extend_from_slice(&slot.to_le_bytes());
            }
            thunk.extend_from_slice(&[0x66, 0xea]);
            thunk.extend_from_slice(&tramp_linear.to_le_bytes());
            thunk.extend_from_slice(&cs64.to_le_bytes());

            debug_assert!(thunk.len() <= THUNK_STRIDE, "thunk outgrew its slot");
            code.write(
                THUNK_TABLE_OFFSET + usize::from(slot) * THUNK_STRIDE,
                &thunk,
            )?;
        }

        Ok(Self {
            segments: vec![code, stack, data],
            code: 0,
            stack: 1,
            data: 2,
            ctx: Ctx::default(),
            frame_sp: None,
        })
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

    fn thunk_slot(&self, slot: u16) -> FarPtr {
        FarPtr {
            offset: (THUNK_TABLE_OFFSET + usize::from(slot) * THUNK_STRIDE) as u16,
            selector: self.code_selector(),
        }
    }

    /// Place a module image at offset 0 of the code segment.
    pub fn load_code(&mut self, image: &[u8]) -> io::Result<()> {
        if image.len() > THUNK_TABLE_OFFSET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "module image would overlap the thunk table",
            ));
        }
        self.segments[self.code].write(0, image)
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
    /// # Errors
    ///
    /// If the arguments and frame will not fit on the module's stack.
    pub fn call(&mut self, entry: u16, args: &[u16]) -> io::Result<Exit> {
        let () = Ctx::ASSERT_FAR_POINTER_FIRST;

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

        let stack = &mut self.segments[self.stack];
        for (i, word) in frame.iter().enumerate() {
            stack.write(usize::from(sp) + i * 2, &word.to_le_bytes())?;
        }

        self.frame_sp = None;
        self.ctx.out_ax = 0;
        self.ctx.out_dx = 0;
        self.ctx.out_si = 0;
        self.ctx.out_di = 0;
        self.ctx.out_bp = 0;

        // A module starts with DS naming its own data segment. After that it is
        // whatever the module last had, since DS is callee-saved.
        self.ctx.out_ds = u64::from(self.data_selector());

        self.run(entry, sp, Ret::Void)
    }

    /// Resume the module from its outstanding call, handing back `value` in
    /// `AX`.
    ///
    /// The call frame is dropped -- `SP` moves up over the `CS:IP` the far call
    /// pushed -- but the arguments are left alone, because cdecl makes cleaning
    /// them the module's job.
    ///
    /// # Panics
    ///
    /// If the module is not stopped at a call.
    pub fn resume(&mut self, ret: Ret) -> io::Result<Exit> {
        let sp = self
            .frame_sp
            .expect("resume() with no outstanding call to resume from");

        let ip = self.stack().read_u16(usize::from(sp));
        let cs = self.stack().read_u16(usize::from(sp) + 2);
        debug_assert_eq!(cs, self.code_selector(), "call frame names another segment");

        self.run(ip, sp + 4, ret)
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
        self.stack().read_u16(usize::from(sp) + 4 + n * 2)
    }

    /// Selector of the module's code segment.
    pub fn code_selector(&self) -> u16 {
        self.segments[self.code].selector()
    }

    /// Selector of the module's stack segment.
    ///
    /// Worth having separately from the code one: under `DS != SS` a module
    /// hands out pointers to its own locals, and this is the segment they name.
    pub fn stack_selector(&self) -> u16 {
        self.segments[self.stack].selector()
    }

    /// Selector of the module's data segment: its `DGROUP`.
    pub fn data_selector(&self) -> u16 {
        self.segments[self.data].selector()
    }

    fn stack(&self) -> &Segment {
        &self.segments[self.stack]
    }

    /// Find the segment a selector names.
    fn segment(&self, selector: u16) -> Result<&Segment, FarPtrError> {
        let index = ldt_index(selector)?;
        self.segments
            .iter()
            .find(|s| s.entry() == u32::from(index))
            .ok_or(FarPtrError::NoSuchSegment { selector })
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
    pub fn resolve(&self, ptr: FarPtr, len: usize) -> Result<&[u8], FarPtrError> {
        let segment = self.segment(ptr.selector)?;
        let start = usize::from(ptr.offset);
        let end = start.checked_add(len).ok_or(FarPtrError::OutOfBounds {
            ptr,
            len,
            limit: segment.len(),
        })?;
        if end > segment.len() {
            return Err(FarPtrError::OutOfBounds {
                ptr,
                len,
                limit: segment.len(),
            });
        }
        Ok(segment.slice(start, len))
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
    pub fn read_cstr(&self, ptr: FarPtr) -> Result<&[u8], FarPtrError> {
        let limit = self.segment(ptr.selector)?.len();
        let start = usize::from(ptr.offset);

        // Everything from the pointer to the end of its segment is the most a
        // string could possibly be. Going through `resolve` rather than
        // reaching for the segment directly keeps one bounds check and one
        // lookup in the crate, instead of two that can drift apart.
        let avail = limit
            .checked_sub(start)
            .filter(|n| *n > 0)
            .ok_or(FarPtrError::OutOfBounds { ptr, len: 1, limit })?;
        let tail = self.resolve(ptr, avail)?;

        let n = tail
            .iter()
            .position(|&b| b == 0)
            .ok_or(FarPtrError::Unterminated { ptr })?;
        Ok(&tail[..n])
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
    pub fn write(&mut self, ptr: FarPtr, bytes: &[u8]) -> Result<(), FarPtrError> {
        // Resolve first so the bounds check and the error are shared.
        self.resolve(ptr, bytes.len())?;
        let index = ldt_index(ptr.selector)?;
        let segment = self
            .segments
            .iter_mut()
            .find(|s| s.entry() == u32::from(index))
            .ok_or(FarPtrError::NoSuchSegment {
                selector: ptr.selector,
            })?;
        segment
            .write(usize::from(ptr.offset), bytes)
            .expect("bounds already checked by resolve");
        Ok(())
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

    /// Cross into 16-bit mode and come back.
    fn run(&mut self, ip: u16, sp: u16, ret: Ret) -> io::Result<Exit> {
        let (ax, dx) = ret.registers();

        self.ctx.target_offset = u32::from(ip);
        self.ctx.target_selector = self.code_selector();
        self.ctx.ss16 = self.stack_selector();
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
        unsafe { mbbs16_enter(&raw mut self.ctx) };

        if self.ctx.out_signo != 0 {
            // The module died and the handler carried us out. Nothing about its
            // state is meaningful now, so forget the call frame rather than let
            // `arg_u16` and friends report stale nonsense.
            self.frame_sp = None;
            return Ok(Exit::Fault {
                signo: self.ctx.out_signo as i32,
            });
        }

        debug_assert_eq!(
            self.ctx.out_ss as u16,
            self.stack_selector(),
            "came back on a stack that is not the module's"
        );

        let out_sp = self.ctx.out_sp as u16;
        self.frame_sp = Some(out_sp);

        // Which thunk brought us here. The module's return value would have
        // been destroyed if the answer lived in AX, so it lives in CX.
        if self.ctx.out_cx as u16 == KIND_RETURN {
            self.frame_sp = None;
            return Ok(Exit::Returned {
                ax: self.ctx.out_ax as u16,
                dx: self.ctx.out_dx as u16,
            });
        }

        Ok(Exit::Call {
            index: self.ctx.out_ax as u16,
        })
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
