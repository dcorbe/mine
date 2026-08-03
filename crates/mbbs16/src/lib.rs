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
//! # use mbbs16::{Exit, Machine};
//! # fn demo() -> std::io::Result<()> {
//! let mut machine = Machine::new()?;
//! machine.load_code(&[0xcb])?;
//! let mut exit = machine.enter(0)?;
//! loop {
//!     match exit {
//!         Exit::Call { index } => {
//!             let sum = machine.arg_u16(0).wrapping_add(machine.arg_u16(1));
//!             let _ = index;
//!             exit = machine.resume(sum)?;
//!         }
//!         Exit::Fault { .. } => break,
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
//! # What this is not, yet
//!
//! The host cannot yet *call into* a module -- entry is by far jump, so there is
//! no return frame for module code to `RETF` through, and a module signals
//! completion by calling [`EXIT_THUNK`] instead.
//!
//! **Faults are fatal, not reported.** [`Exit::Fault`] is part of the shape this
//! wants to have and is currently unreachable: a module that faults takes the
//! process with it. Recovering needs a `SIGSEGV`/`SIGILL` handler that rewrites
//! the interrupted context -- setting `RIP` from `R11`, `RSP` from `R15` and the
//! saved `CS`/`SS` back to the host's, which is precisely the restore the
//! trampoline performs, and precisely what `<asm/ucontext.h>` describes DOSEMU
//! doing. That handler must carry `SA_ONSTACK` over an alternate signal stack
//! mapped below 4 GiB, because a signal taken in compatibility mode cannot have
//! its frame built on a stack above that line: the kernel fails, calls
//! `force_sigsegv()`, fails again, and the process dies. None of that is built
//! yet, so **any signal delivered during an excursion is fatal**, not only a
//! fault.
//!
//! Neither gap is a limit of the mechanism; both are simply not built.

mod asm;
mod seg;

use std::io;

use asm::{Ctx, mbbs16_enter, trampoline};
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

/// Thunk index reserved to mean "this module is finished".
///
/// A stand-in. Real modules return to whoever called them; until this crate can
/// enter a module by far call, they say so by calling this instead.
pub const EXIT_THUNK: u16 = 0xffff;

/// Why 16-bit execution stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// The module far-called an import thunk. Arguments are readable with
    /// [`Machine::arg_u16`]; [`Machine::resume`] continues it.
    Call { index: u16 },

    /// The module took a signal. Nothing is resumable.
    Fault { signo: i32 },
}

/// A far pointer as 16-bit code understands it: a 16-bit offset and a 16-bit
/// selector, offset first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FarPtr {
    pub offset: u16,
    pub selector: u16,
}

impl FarPtr {
    /// The four bytes an `lcall`'s operand expects.
    pub fn to_bytes(self) -> [u8; 4] {
        let mut out = [0u8; 4];
        out[0..2].copy_from_slice(&self.offset.to_le_bytes());
        out[2..4].copy_from_slice(&self.selector.to_le_bytes());
        out
    }
}

/// One module's 16-bit world: its code, its stack, and the state needed to
/// re-enter it where it left off.
pub struct Machine {
    code: Segment,
    stack: Segment,
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

        let tramp_linear = code.linear(TRAMPOLINE_OFFSET);
        code.write(TRAMPOLINE_OFFSET, trampoline())?;

        // A thunk announces which import it is and leaves. That is all a real
        // import thunk does either; the work happens on this side.
        //
        //   b8 ii ii              mov   $index, %ax
        //   66 ea <off32> <sel>   ljmpl $CS64, $trampoline
        //
        // The 0x66 is what makes this possible at all: without it `EA` in a
        // 16-bit segment takes a 16-bit offset and could not name the
        // trampoline. With it the offset is 32 bits, which reaches anywhere
        // below 4 GiB.
        let cs64 = current_cs();
        for index in 0..=MAX_THUNKS {
            let logical = if index == MAX_THUNKS { EXIT_THUNK } else { index };

            let mut thunk = [0u8; 11];
            thunk[0] = 0xb8;
            thunk[1..3].copy_from_slice(&logical.to_le_bytes());
            thunk[3] = 0x66;
            thunk[4] = 0xea;
            thunk[5..9].copy_from_slice(&tramp_linear.to_le_bytes());
            thunk[9..11].copy_from_slice(&cs64.to_le_bytes());

            code.write(
                THUNK_TABLE_OFFSET + usize::from(index) * THUNK_STRIDE,
                &thunk,
            )?;
        }

        Ok(Self {
            code,
            stack,
            ctx: Ctx::default(),
            frame_sp: None,
        })
    }

    /// The far pointer a module should `lcall` to reach import `index`.
    ///
    /// [`EXIT_THUNK`] is accepted and maps to the reserved final slot.
    ///
    /// # Panics
    ///
    /// If `index` is neither below [`MAX_THUNKS`] nor [`EXIT_THUNK`].
    pub fn thunk_address(&self, index: u16) -> FarPtr {
        let slot = match index {
            EXIT_THUNK => MAX_THUNKS,
            i if i < MAX_THUNKS => i,
            other => panic!("thunk index {other} is beyond MAX_THUNKS ({MAX_THUNKS})"),
        };

        FarPtr {
            offset: (THUNK_TABLE_OFFSET + usize::from(slot) * THUNK_STRIDE) as u16,
            selector: self.code.selector(),
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
        self.code.write(0, image)
    }

    /// Begin executing at `ip` in the code segment, on a fresh stack.
    pub fn enter(&mut self, ip: u16) -> io::Result<Exit> {
        let () = Ctx::ASSERT_LAYOUT;

        self.frame_sp = None;
        self.run(ip, INITIAL_SP, 0)
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
    pub fn resume(&mut self, value: u16) -> io::Result<Exit> {
        let sp = self
            .frame_sp
            .expect("resume() with no outstanding call to resume from");

        let ip = self.stack.read_u16(usize::from(sp));
        let cs = self.stack.read_u16(usize::from(sp) + 2);
        debug_assert_eq!(cs, self.code.selector(), "call frame names another segment");

        self.run(ip, sp + 4, value)
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
        self.stack.read_u16(usize::from(sp) + 4 + n * 2)
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
        self.frame_sp
            .expect("sp() with no outstanding call")
    }

    /// `SI` as the module last left it. Borland's cdecl treats it as
    /// callee-saved, so modules keep values there across calls.
    pub fn si(&self) -> u16 {
        self.ctx.out_si as u16
    }

    /// Cross into 16-bit mode and come back.
    fn run(&mut self, ip: u16, sp: u16, ax: u16) -> io::Result<Exit> {
        self.ctx.target_offset = u32::from(ip);
        self.ctx.target_selector = self.code.selector();
        self.ctx.ss16 = self.stack.selector();
        self.ctx.sp = u64::from(sp);
        self.ctx.ax = u64::from(ax);

        // The trampoline writes SS as a bare 16-bit store, so the rest of the
        // slot has to start clean.
        self.ctx.out_ax = 0;
        self.ctx.out_sp = 0;
        self.ctx.out_ss = 0;
        self.ctx.out_si = 0;

        // SAFETY: every field the assembly reads is set immediately above; the
        // code and stack segments are mapped, described and live for as long as
        // `self`; and the trampoline the module will far-jump to was written
        // into the code segment by `new`.
        unsafe { mbbs16_enter(&raw mut self.ctx) };

        debug_assert_eq!(
            self.ctx.out_ss as u16,
            self.stack.selector(),
            "came back on a stack that is not the module's"
        );

        let out_sp = self.ctx.out_sp as u16;
        self.frame_sp = Some(out_sp);

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
    unsafe { std::arch::asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags)) };
    cs
}
