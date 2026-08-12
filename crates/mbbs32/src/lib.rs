//! Running 32-bit Worldgroup modules on x86-64 Linux, natively.
//!
//! The 32-bit sibling of [`mbbs16`](../mbbs16/index.html). Same idea -- a module
//! is a coroutine that runs until it wants something from the host -- against a
//! different container (PE32 rather than NE) and a different ABI (flat 32-bit
//! cdecl rather than Borland's 16-bit huge model).
//!
//! The design, and every measurement the tests assert, is in
//! `docs/plans/2026-08-08-mbbs32-design.md`.
//!
//! # Two things this is not
//!
//! It is not a Windows loader. No TLS callbacks, no SEH, no resources, no
//! delay-imports -- the module measured here needs none of them, and a loader
//! that implements what its input does not contain is untested code pretending
//! to be a feature.
//!
//! Forwarded exports are the one thing here that is *detected but not
//! serviced*: a forwarder's "address" is a `"DLL.Symbol"` string rather than
//! code, so mistaking one for an RVA hands back a pointer into text. The
//! measured module forwards nothing, and following a forwarder into another DLL
//! is a Windows loader's job, not this one's.
//!
//! Exports with no name (`NumberOfFunctions > NumberOfNames`) are not
//! surfaced by [`PeImage::exports`] at all -- not hypothetical:
//! `WGSERVER.EXE` has 222 such ordinal-only exports out of 1615 functions,
//! and `GALGSBL.DLL` has 20 out of 109. Nothing through Task 17 parses those
//! files, so it is inert today, but `export_rva` returning `None` for one is
//! indistinguishable from the symbol not existing.
//!
//! It is not a host. Imports bind to thunks that report which symbol was wanted;
//! nothing services them.
//!
//! [`Image::load`] maps a [`PeImage`] and copies its sections into place, but
//! leaves every page `PROT_READ | PROT_WRITE | PROT_EXEC` -- section
//! characteristics are parsed (`Section::characteristics`) but not yet turned
//! into per-page protections. `CODE` being writable and `.reloc` being
//! present at runtime at all are both looser than the real module needs;
//! tightening that is later work, not a gap this crate is unaware of.
//!
//! # Testing
//!
//! **Run the tests in both profiles.** `cargo test -p mbbs32` and
//! `cargo test -p mbbs32 --release` are not the same check -- see the sibling
//! crate's note for the measurement behind that.

mod asm;
mod fault;
pub mod flatptr;
mod image;
mod map;
mod pe;
mod tib;

use std::io;

use asm::{Ctx, USER32_CS, current_cs, trampoline};
pub use flatptr::{Flat32Ptr, Flat32PtrError};
pub use image::{Image, Import32, ImportResolver, ThunkSite};
pub use map::Mapping;
pub use pe::{Export, ExportAddress, Import, PeError, PeImage, Relocation, Section, Symbol};
use tib::{DEFAULT_STACK_LEN, Tib};

/// Where the thunk table sits within the **bridge** mapping, which holds
/// nothing else before it.
///
/// The bridge has a mapping of its own rather than a corner of the module's
/// own memory, exactly as `mbbs16`'s bridge *segment* does and for the same
/// reason: nothing about a real module's own layout is guaranteed to leave a
/// fixed offset free.
const THUNK_TABLE_OFFSET: usize = 0;

/// Bytes per thunk slot.
///
/// A call thunk's longest encoding is 17 bytes (`mov ecx, imm32` [5] +
/// `mov eax, imm32` [5] + `ljmp ptr16:32` [7]); 32 keeps `index * STRIDE`
/// legible against a hex dump and leaves room to spare, matching
/// `mbbs16::THUNK_STRIDE`'s own reasoning.
const THUNK_STRIDE: usize = 32;

/// How many import thunks a module may have. `wccmmud.dll` measures 210
/// imports (`docs/plans/2026-08-08-mbbs32-design.md`), so this is room to
/// spare -- the same headroom `mbbs16::MAX_THUNKS` keeps over its own
/// measured 16-bit API surface.
pub const MAX_THUNKS: u16 = 512;

/// Where the 64-bit trampoline is copied to: immediately past the thunk
/// table, in the same mapping. It must live below 4 GiB -- [`Mapping::new`]
/// already guarantees that -- because the far jump that reaches it can name
/// a 32-bit offset and no more.
const TRAMPOLINE_OFFSET: usize = THUNK_TABLE_OFFSET + (MAX_THUNKS as usize + 1) * THUNK_STRIDE;

/// The thunk a module returns *through*. Its address is what [`Machine::call`]
/// writes as the near return address of the cdecl frame it builds, so the
/// module's own `ret` lands here.
const RETURN_THUNK_SLOT: u16 = MAX_THUNKS;

/// What kind of thunk reached the trampoline, carried in `ECX` --
/// [`asm::Ctx::out_ecx`].
///
/// `ECX` rather than `EAX` because a returning module has its result in
/// `EAX` (or `EDX:EAX`), and a thunk announcing itself there would destroy
/// it. `ECX` is ordinary caller-saved scratch under 32-bit cdecl, so nothing
/// a module returns through it, and nothing here needs to save and restore
/// it the way `mbbs16`'s call thunk saves `AX`/`CX` -- see `asm.rs`'s module
/// doc comment, "no Borland-runtime-helper quirk ... EAX, ECX and EDX are
/// ordinary caller-saved scratch".
const KIND_CALL: u32 = 0;
const KIND_RETURN: u32 = 1;

/// Why 32-bit execution stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// The module called an import thunk. `index` names which one --
    /// look it up in the `Vec<ThunkSite>` [`Image::bind_imports`] returned.
    Call { index: u16 },

    /// The module returned from the entry point it was called at, via an
    /// ordinary near `ret`. `eax` alone for a 32-bit result, `edx:eax` for a
    /// 64-bit one.
    Returned { eax: u32, edx: u32 },

    /// The module took a signal. Nothing is resumable, and the machine is
    /// [`Machine::poisoned`].
    ///
    /// `eip` is a **linear address**, directly usable -- unlike
    /// `mbbs16::Exit::Fault`'s `cs:ip`, a flat segment has base zero, so the
    /// value the CPU pushed already is the number a disassembly of the
    /// mapped image is annotated with.
    Fault { signo: i32, eip: u32 },
}

/// Why a machine will not be entered again. See [`Machine::poisoned`].
///
/// The one variant here mirrors the one terminal [`Exit`], kept separately
/// (as `mbbs16::Poison` is) so a host that has discarded the `Exit` can still
/// say what happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Poison {
    /// It faulted. See [`Exit::Fault`].
    Fault { signo: i32, eip: u32 },
}

impl std::fmt::Display for Poison {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fault { signo, eip } => {
                write!(f, "module faulted with signal {signo} at {eip:#010x}")
            }
        }
    }
}

/// What a host call hands back to the module, for [`Machine::resume`].
///
/// The 32-bit-cdecl tier of `mbbs16::Ret`: plain 32-bit `cdecl` returns an
/// `int` (or a pointer -- this ABI is flat, so there is no `mbbs16::Ret::Far`
/// counterpart) in `EAX`, and anything 64 bits wide in `EDX:EAX`, high half
/// in `EDX`. Naming the width here rather than a resume method per shape is
/// the same choice `mbbs16::Ret` makes, for the same reason: a table of
/// several hundred shims wants the choice explicit at the one place it is
/// made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ret {
    /// Nothing to return. Both halves are cleared, so a module that reads
    /// `EDX` anyway -- mistaking a 32-bit result for a 64-bit one -- sees
    /// something deterministic.
    Void,

    /// A 32-bit result -- an `int`, or a pointer, since this ABI has no
    /// separate segment to carry -- in `EAX`.
    U32(u32),

    /// A 64-bit result, split `EDX:EAX` with the high half in `EDX`. What a
    /// `long long` comes back as under cdecl.
    U64(u64),
}

impl Ret {
    /// The `(EAX, EDX)` the module should resume with.
    fn registers(self) -> (u32, u32) {
        match self {
            Self::Void => (0, 0),
            Self::U32(v) => (v, 0),
            Self::U64(v) => (v as u32, (v >> 32) as u32),
        }
    }
}

/// A 32-bit module's execution state: its thunk table, its Win32 [`Tib`], and
/// the crossing context needed to re-enter it.
///
/// Unlike `mbbs16::Machine`, this does not own a loaded [`Image`] -- see
/// [`Machine::call`]'s doc comment. A module's memory is the caller's to keep
/// alive; this owns only what execution itself needs, and needs regardless of
/// which (or how many) images are ever entered through it.
pub struct Machine {
    /// The thunk table and the trampoline. The host's, and no module's.
    bridge: Mapping,

    /// The module's stack and Win32 TIB. `FS` is loaded from this on every
    /// entry; see `tib.rs`.
    tib: Tib,

    /// The state the assembly is entered through.
    ctx: Ctx,

    /// `ESP` (a linear address) when the module last called out, or `None`
    /// before its first call and after it has returned. The frame the
    /// module's own `call` pushed -- one 4-byte near return address -- sits
    /// at exactly this offset; [`Machine::resume`] reads it back to know
    /// where to continue.
    ///
    /// Unlike `mbbs16::Machine::frame_sp`, nothing needs stepping over to
    /// reach it: the call thunk here pushes nothing before reaching the
    /// trampoline (`asm.rs`'s module doc comment -- `EAX`/`ECX` are ordinary
    /// caller-saved scratch under 32-bit cdecl, so a thunk has nothing of
    /// the module's to save), so `out_esp` at the moment of [`Exit::Call`]
    /// already names this address directly.
    frame_sp: Option<u32>,

    /// Set once this machine has faulted, and never cleared. A poisoned
    /// machine refuses to be entered again.
    poisoned: Option<Poison>,
}

impl Machine {
    /// Build the thunk table and trampoline, a module stack and TIB, and arm
    /// fault recovery on this thread.
    pub fn new() -> io::Result<Self> {
        let tramp = trampoline();
        let mut bridge = Mapping::new(TRAMPOLINE_OFFSET + tramp.len())?;

        let cs64 = current_cs();
        fault::arm(cs64)?;

        let bridge_base = bridge.base() as usize as u32;
        let tramp_addr = bridge_base + TRAMPOLINE_OFFSET as u32;
        {
            let dst = bridge.as_mut_slice();
            dst[TRAMPOLINE_OFFSET..TRAMPOLINE_OFFSET + tramp.len()].copy_from_slice(tramp);
        }

        // Every call thunk records its own index and far-jumps to the
        // trampoline; the return thunk does the same but never touches
        // EAX/EDX, which for it carry the module's actual return value
        // rather than a thunk index. This is necessarily a runtime data
        // table, not a `global_asm!` template: the one thing that varies
        // slot to slot -- the embedded index -- has no compile-time struct
        // field for `offset_of!` to name (unlike every crossing in `asm.rs`,
        // which addresses the one, fixed-shape `Ctx`). The crossing protocol
        // itself (`Ctx::out_ecx` above, the trampoline it is written by) is
        // real `global_asm!`, `offset_of!`-addressed, exactly as `asm.rs`
        // requires; only the per-slot immediate below is hand-assembled,
        // which is the same shape `mbbs16::Machine::new` uses for its own
        // thunk table (`crates/mbbs16/src/lib.rs:375-411`) and for the same
        // reason -- there is no struct here to misaddress, only an index to
        // write, and the `assert!` below plus the falsifying end-to-end test
        // are what actually verify it, not the encoding style.
        for slot in 0..=RETURN_THUNK_SLOT {
            let kind = if slot == RETURN_THUNK_SLOT {
                KIND_RETURN
            } else {
                KIND_CALL
            };

            let mut thunk = Vec::with_capacity(THUNK_STRIDE);
            thunk.push(0xb9); // mov ecx, imm32
            thunk.extend_from_slice(&kind.to_le_bytes());
            if kind == KIND_CALL {
                thunk.push(0xb8); // mov eax, imm32
                thunk.extend_from_slice(&u32::from(slot).to_le_bytes());
            }
            // ljmp ptr16:32. No 0x66 operand-size prefix: unlike `mbbs16`'s
            // 16-bit-default code segment, `USER32_CS` is already a 32-bit
            // default segment (`D` bit set), so opcode 0xEA already takes a
            // 32-bit offset -- see `asm.rs::tests::ljmp_back`, which builds
            // the identical 7 bytes the same way.
            thunk.push(0xea);
            thunk.extend_from_slice(&tramp_addr.to_le_bytes());
            thunk.extend_from_slice(&cs64.to_le_bytes());

            // Not a `debug_assert`: a thunk that outgrew its slot writes over
            // the start of the next one, corrupting a jump target rather
            // than raising an error. Runs 513 times at construction, never
            // again.
            assert!(
                thunk.len() <= THUNK_STRIDE,
                "thunk {slot} needs {} bytes and the stride is {THUNK_STRIDE}",
                thunk.len(),
            );
            let off = THUNK_TABLE_OFFSET + usize::from(slot) * THUNK_STRIDE;
            bridge.as_mut_slice()[off..off + thunk.len()].copy_from_slice(&thunk);
        }

        let tib = Tib::new(DEFAULT_STACK_LEN)?;

        Ok(Self {
            bridge,
            tib,
            ctx: Ctx::default(),
            frame_sp: None,
            poisoned: None,
        })
    }

    /// Why this machine will not run again, if it will not.
    pub fn poisoned(&self) -> Option<&Poison> {
        self.poisoned.as_ref()
    }

    /// The linear address a module should `call` to reach import `index`.
    ///
    /// Meant to be handed to [`Image::patch_thunk_addresses`] as the
    /// `thunk_addr` closure -- see that method and [`Machine::call`]'s doc
    /// comment for why this crate does not bind the two together itself.
    ///
    /// # Panics
    ///
    /// If `index` is not below [`MAX_THUNKS`].
    pub fn thunk_addr(&self, index: u16) -> u32 {
        assert!(
            index < MAX_THUNKS,
            "thunk index {index} is beyond MAX_THUNKS ({MAX_THUNKS})"
        );
        self.thunk_slot_addr(index)
    }

    fn thunk_slot_addr(&self, slot: u16) -> u32 {
        self.bridge.base() as usize as u32
            + (THUNK_TABLE_OFFSET + usize::from(slot) * THUNK_STRIDE) as u32
    }

    fn return_thunk_addr(&self) -> u32 {
        self.thunk_slot_addr(RETURN_THUNK_SLOT)
    }

    /// Call 32-bit code the way the real host does: a flat cdecl frame,
    /// entered fresh.
    ///
    /// `entry` is a **linear address** -- typically
    /// `image.base() + pe_image.entry_point` for an [`Image`] this crate
    /// mapped. `args` are 32-bit words in declaration order; they are pushed
    /// right to left, as cdecl requires, with a 4-byte **near** return
    /// address (not `mbbs16`'s far `CS:IP`) placed beneath them -- the
    /// address of this machine's own return thunk, so the module's own `ret`
    /// comes back here as [`Exit::Returned`].
    ///
    /// This crate does not own the [`Image`] being entered, unlike
    /// `mbbs16::Machine`, which owns its loaded NE module -- deliberately:
    /// the only state a call leaves behind between crossings is the
    /// module's own stack, which this `Machine` already owns through its
    /// [`Tib`], plus the near return address [`Machine::resume`] reads back
    /// out of it. Keeping the module's own mapped memory -- code, data,
    /// everything but the stack -- alive is the caller's job, for as long as
    /// any call issued against it might still be outstanding: across every
    /// [`Machine::resume`], not only the initial [`Machine::call`]. Exactly
    /// as `tib.rs`'s and `asm.rs`'s own tests keep their scratch
    /// [`Mapping`]s alive across [`asm::enter`].
    ///
    /// The stack starts fresh at the top of this machine's [`Tib`] on every
    /// `call`. An [`Exit::Call`] this returned earlier left a frame this
    /// machine still remembers -- [`Machine::resume`] is how the module
    /// continues past it, with the host's answer in `EAX`/`EDX:EAX`. Calling
    /// `call` again instead of resuming abandons that frame outright: the
    /// two are not interchangeable, and nothing here enforces which one a
    /// caller means.
    ///
    /// # Errors
    ///
    /// If this machine is [`Machine::poisoned`], or the arguments and frame
    /// will not fit on the module's stack.
    pub fn call(&mut self, entry: u32, args: &[u32]) -> io::Result<Exit> {
        if let Some(poison) = &self.poisoned {
            return Err(io::Error::other(format!(
                "refusing to enter a poisoned module: {poison}"
            )));
        }

        let frame_words = args.len() + 1; // the near return address, then args
        let bytes = frame_words
            .checked_mul(4)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "call frame overflows"))?;

        let stack_base = self.tib.stack_base();
        let stack_limit = self.tib.stack_limit();
        let sp = stack_base
            .checked_sub(bytes as u32)
            .filter(|&sp| sp >= stack_limit)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "call frame will not fit")
            })?;

        let ret = self.return_thunk_addr();
        let stack_off = (sp - stack_limit) as usize;
        let stack = self.tib.stack_mut();
        stack[stack_off..stack_off + 4].copy_from_slice(&ret.to_le_bytes());
        for (i, arg) in args.iter().enumerate() {
            let off = stack_off + 4 + i * 4;
            stack[off..off + 4].copy_from_slice(&arg.to_le_bytes());
        }

        // A fresh entry point, not a continuation of whatever the last one
        // left behind: no outstanding frame, and the callee-saved quad
        // starts at a defined zero rather than some earlier call's leftovers
        // -- exactly the reset `mbbs16::Machine::call` gives `out_bx`/
        // `out_si`/`out_di`/`out_bp` before its own `self.run(...)`.
        self.frame_sp = None;
        self.ctx.out_ebx = 0;
        self.ctx.out_esi = 0;
        self.ctx.out_edi = 0;
        self.ctx.out_ebp = 0;

        self.run(entry, sp, Ret::Void)
    }

    /// Resume the module from its outstanding call, handing back `ret` in
    /// `EAX` (`EDX:EAX` for a 64-bit result), and re-entering at the
    /// instruction after the module's own `call`.
    ///
    /// There is no `resume_cleaning` counterpart here, unlike
    /// `mbbs16::Machine`. That method exists there because 16-bit Borland
    /// huge-model code has genuinely callee-cleaned helpers (`f_lumod@` and
    /// its family); 32-bit Worldgroup does not carry that quirk forward --
    /// it is uniformly cdecl. The ten callee-cleaned `F_*@` helpers a reader
    /// of `WGSERVER.DEF` might expect an analogue for live inside its
    /// `#ifdef GCDOS` block only, which a plain 32-bit cdecl PE like
    /// `wccmmud.dll` never takes. A module always cleans its own arguments
    /// under this ABI, so [`resume`](Machine::resume) is the only shape a
    /// resume ever needs.
    ///
    /// # Errors
    ///
    /// If this machine is [`Machine::poisoned`].
    ///
    /// # Panics
    ///
    /// If the module is not stopped at a call.
    pub fn resume(&mut self, ret: Ret) -> io::Result<Exit> {
        // Stated once, not left to depend on `frame_sp` happening to be
        // cleared alongside `poisoned` in `run`'s `Fault` arm below -- that
        // coupling is an accident of implementation, not a guard: removing
        // `frame_sp = None` from the `Fault` arm alone leaves every test in
        // this crate passing, because the one case exercised (a fault during
        // a fresh `call`) already has `frame_sp` at `None` from `call`'s own
        // reset just above. A fault taken on a *resumed* call would leave
        // `frame_sp` stale and `Some`, and without this check that stale
        // value would carry this method past the `.expect()` below and into
        // `run` on a poisoned machine -- exactly what `run`'s own SAFETY
        // comment says never happens. Mirrors [`Machine::call`]'s check:
        // same error type, same message.
        if let Some(poison) = &self.poisoned {
            return Err(io::Error::other(format!(
                "refusing to enter a poisoned module: {poison}"
            )));
        }

        let sp = self
            .frame_sp
            .expect("resume() with no outstanding call to resume from");

        // The near return address the module's own `call` pushed, read back
        // rather than assumed -- a module with more than one code section
        // calls out from any of them. Checked, not merely `debug_assert`ed:
        // a poisoned or corrupted `frame_sp` below `stack_limit` must not
        // silently wrap into a plausible-looking offset the way
        // `mbbs16::Machine::resume_cleaning`'s own comment warns an
        // unchecked `+= THUNK_SAVES` would -- an out-of-range `sp` here
        // fails loudly instead.
        let limit = self.tib.stack_limit();
        let off = sp
            .checked_sub(limit)
            .expect("resume(): the remembered call frame is below this machine's own stack")
            as usize;
        let at = {
            let stack = self.tib.stack_mut();
            let bytes = stack.get(off..off + 4).expect(
                "resume(): the remembered call frame is outside this machine's own stack",
            );
            u32::from_le_bytes(bytes.try_into().expect("checked to be exactly 4 bytes"))
        };

        // Step over the 4 bytes just read, exactly as the module's own `ret`
        // would when the call it made returns normally: `ESP` ends up where
        // it stood the instant after the `call` instruction pushed that
        // return address, with the host's answer now sitting in `EAX`/`EDX`
        // in its place.
        self.run(at, sp + 4, ret)
    }

    /// Cross into 32-bit mode and come back, handing the module `ret` in
    /// `EAX`/`EDX:EAX` on the way in.
    fn run(&mut self, entry: u32, sp: u32, ret: Ret) -> io::Result<Exit> {
        let (eax, edx) = ret.registers();

        self.ctx.target_offset = entry;
        self.ctx.target_selector = USER32_CS;
        self.ctx.fs = self.tib.fs_selector();
        self.ctx.esp = sp;
        self.ctx.eax = eax;
        self.ctx.edx = edx;

        // Hand the callee-saved quad back exactly as the module left it --
        // whether that is a fresh call's defined zero (`Machine::call`
        // primes `out_ebx`/`out_esi`/`out_edi`/`out_ebp` before calling
        // here) or a resume's leftovers from the crossing that produced the
        // `Exit::Call` being serviced. The same propagation
        // `mbbs16::Machine::run` does for `si`/`di`/`bp`/`ds`, one register
        // wider and one register longer, and for the same reason: a host
        // call is a callee like any other under cdecl, and losing these
        // would not crash anything -- it would silently hand the module back
        // a value it never stored, which is worse.
        self.ctx.ebx = self.ctx.out_ebx;
        self.ctx.esi = self.ctx.out_esi;
        self.ctx.edi = self.ctx.out_edi;
        self.ctx.ebp = self.ctx.out_ebp;

        // The trampoline writes these on every crossing, but a poisoned
        // machine never re-enters `run`, and a fresh `Ctx` starts zeroed
        // anyway -- this is a defensive reset, not load-bearing today, kept
        // for the same reason `mbbs16::Machine::run` clears `out_signo`
        // before every entry: the next crossing must not be able to read a
        // stale value from the one before it.
        self.ctx.out_signo = 0;
        self.ctx.out_eip = 0;
        self.ctx.out_ecx = 0;

        // SAFETY: `target_offset`/`target_selector`/`fs`/`esp` are set
        // immediately above; the thunk table and trampoline in `self.bridge`
        // were written by `new` and live for as long as `self`; `self.tib`'s
        // stack and TIB mappings are likewise live for as long as `self`,
        // and `fault::arm` was called in `new`, so a fault this call takes
        // is recoverable rather than fatal.
        unsafe { asm::enter(&mut self.ctx) };

        if self.ctx.out_signo != 0 {
            let signo = self.ctx.out_signo as i32;
            let eip = self.ctx.out_eip;
            self.poisoned.get_or_insert(Poison::Fault { signo, eip });
            self.frame_sp = None;
            return Ok(Exit::Fault { signo, eip });
        }

        if self.ctx.out_ecx == KIND_RETURN {
            self.frame_sp = None;
            return Ok(Exit::Returned {
                eax: self.ctx.out_eax,
                edx: self.ctx.out_edx,
            });
        }

        self.frame_sp = Some(self.ctx.out_esp);
        Ok(Exit::Call {
            index: self.ctx.out_eax as u16,
        })
    }
}
