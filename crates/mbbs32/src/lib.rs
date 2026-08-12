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

// As in `mbbs16` -- see the longer note there -- but for a different mechanism:
// entry is a far jump to `__USER32_CS` (`0x23`) rather than to an LDT selector,
// and `FS` is set through `arch_prctl`. Both are facilities the kernel offers
// only on x86, so the crate cannot build anywhere else and should say so
// itself.
#[cfg(not(target_arch = "x86_64"))]
compile_error!("mbbs32 enters 32-bit code via __USER32_CS: x86_64 only");

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
    /// `mbbs16::Machine`, which owns its loaded NE module --
    /// deliberately: nothing through this increment services a call
    /// ([`Exit::Call`] is where execution stops, not a point some other
    /// method resumes from), so there is no "outstanding call" state for a
    /// loaded module to need to outlive across. Keeping the module's own
    /// mapped memory alive for the duration of this call is the caller's
    /// job -- an [`Image`] kept in scope across the call, exactly as
    /// `tib.rs`'s and `asm.rs`'s own tests keep their scratch [`Mapping`]s
    /// alive across [`asm::enter`].
    ///
    /// The stack starts fresh at the top of this machine's [`Tib`] on every
    /// call, so a call made after a previous one returned [`Exit::Call`] --
    /// which this crate has no way to resume -- simply abandons whatever
    /// frame that left behind.
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

        self.run(entry, sp)
    }

    /// Cross into 32-bit mode and come back.
    fn run(&mut self, entry: u32, sp: u32) -> io::Result<Exit> {
        self.ctx.target_offset = entry;
        self.ctx.target_selector = USER32_CS;
        self.ctx.fs = self.tib.fs_selector();
        self.ctx.esp = sp;

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
            return Ok(Exit::Fault { signo, eip });
        }

        if self.ctx.out_ecx == KIND_RETURN {
            return Ok(Exit::Returned {
                eax: self.ctx.out_eax,
                edx: self.ctx.out_edx,
            });
        }

        Ok(Exit::Call {
            index: self.ctx.out_eax as u16,
        })
    }
}
