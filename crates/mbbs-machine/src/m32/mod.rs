//! Running 32-bit Worldgroup modules on x86-64 Linux, natively.
//!
//! The 32-bit sibling of [`crate::m16`]. Same idea -- a module
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
//! tightening that is later work, not a gap this module is unaware of.
//!
//! # Testing
//!
//! **Run the tests in both profiles.** `cargo test -p mbbs-machine` and
//! `cargo test -p mbbs-machine --release` are not the same check -- see the
//! sibling module's note for the measurement behind that.

// As in `m16` -- see the longer note there -- but for a different mechanism:
// entry is a far jump to `__USER32_CS` (`0x23`) rather than to an LDT selector,
// and `FS` is set through `arch_prctl`. Both are facilities the kernel offers
// only on x86, so the crate cannot build anywhere else and should say so
// itself.
#[cfg(not(target_arch = "x86_64"))]
compile_error!("m32 enters 32-bit code via __USER32_CS: x86_64 only");

mod asm;
mod fault;
pub mod flatptr;
mod image;
mod map;
mod mem;
mod pe;
mod tib;
mod watchdog;

use std::io;
use std::time::Duration;

use asm::{USER32_CS, current_cs, trampoline};
pub use flatptr::{Flat32Ptr, Flat32PtrError};
pub use image::{AbsoluteImport, Image, Import32, ImportResolver};
pub use map::Mapping;
pub use mem::Memory;
pub use crate::module::{ImportSite, Symbol};
pub use pe::{Export, ExportAddress, Import, PeError, PeImage, Relocation, Section};
use tib::{DEFAULT_STACK_LEN, Tib};
use watchdog::Watched;

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
/// `crate::m16::THUNK_STRIDE`'s own reasoning.
const THUNK_STRIDE: usize = 32;

/// How many import thunks a module may have. `wccmmud.dll` measures 210
/// imports (`docs/plans/2026-08-08-mbbs32-design.md`), so this is room to
/// spare -- the same headroom `crate::m16::MAX_THUNKS` keeps over its own
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

/// Bytes reserved past the trampoline in the bridge mapping for
/// [`Machine::arm_st0_capture`]'s scratch qword: one `f64`, the width
/// `fstp`/`fld` `m64fp` addresses. See that method's doc comment for why it
/// exists and why a plain qword is enough -- Borland's `__ftol` is fed by a
/// preceding `fld`/`fild`/`fmul` at every call site this crate has measured
/// (`cw3220mt.DLL!__ftol`, 13 sites in `LUNATIX.DLL`), never a value that
/// needs the FPU's full 80-bit extended range to survive intact.
const ST0_SCRATCH_LEN: usize = 8;

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

/// CPU time one entry point gets before the watchdog stops it. Mirrors
/// `crate::m16::DEFAULT_BUDGET` exactly -- see that constant's own doc
/// comment for the reasoning. Adjust per module with [`Machine::set_budget`].
const DEFAULT_BUDGET: Duration = Duration::from_secs(5);

/// Why 32-bit execution stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// The module called an import thunk. `index` names which one --
    /// look it up in the `Vec<ImportSite>` [`Image::bind_imports`] returned.
    Call { index: u16 },

    /// The module returned from the entry point it was called at, via an
    /// ordinary near `ret`. `eax` alone for a 32-bit result, `edx:eax` for a
    /// 64-bit one.
    Returned { eax: u32, edx: u32 },

    /// The module took a signal. Nothing is resumable, and the machine is
    /// [`Machine::poisoned`].
    ///
    /// `eip` is a **linear address**, directly usable -- unlike
    /// `crate::m16::Exit::Fault`'s `cs:ip`, a flat segment has base zero, so the
    /// value the CPU pushed already is the number a disassembly of the
    /// mapped image is annotated with.
    Fault { signo: i32, eip: u32 },

    /// The module used its whole CPU budget without returning. Nothing is
    /// resumable, and the machine is [`Machine::poisoned`]. Mirrors
    /// `crate::m16::Exit::Timeout`; `eip` is a linear address for the same
    /// reason [`Exit::Fault`]'s is.
    Timeout { eip: u32 },
}

/// Every register a 32-bit crossing carries, in both directions.
///
/// Read with [`Machine::regs`], written with [`Machine::set_regs`] or the
/// individual setters, and honoured wholesale by [`Machine::jump`]. The two
/// structured entry points compute some of these for themselves and overwrite
/// whatever was set:
///
/// | register | `call` | `resume` | `jump` |
/// |---|---|---|---|
/// | `eip` | the entry point | the outstanding call's return address | as set |
/// | `esp` | below the frame it wrote | past the finished frame | as set |
/// | `eax`, `edx` | zero | the host call's [`Ret`] | as set |
/// | `ebx`, `esi`, `edi`, `ebp` | zero | as the module left them | as set |
///
/// # There is no `ecx`
///
/// Deliberately, and it is the one asymmetry here. `ECX` is caller-saved
/// scratch under 32-bit cdecl, so nothing crosses *inward* in it and the
/// entry sequence never loads it (`m32/asm.rs`'s `enter`). On the way *out*
/// it carries the thunk-kind discriminant, which is this machine's own
/// signalling rather than the module's data. A field here would be a setter
/// that silently did nothing, which is worse than its absence.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Regs {
    /// Where the next entry lands. A linear address.
    pub eip: u32,
    /// The stack pointer to enter with, likewise linear -- 32-bit
    /// compatibility mode runs on the host's own flat `SS`.
    pub esp: u32,
    /// A host call's result, or a module return's.
    pub eax: u32,
    /// The high half of a 64-bit one.
    pub edx: u32,
    /// The callee-saved quad, restored on entry so a host call is transparent
    /// to the module.
    pub ebx: u32,
    /// See [`Regs::ebx`].
    pub esi: u32,
    /// See [`Regs::ebx`].
    pub edi: u32,
    /// See [`Regs::ebx`].
    pub ebp: u32,
}

/// Why a machine will not be entered again. See [`Machine::poisoned`].
///
/// The first variant mirrors the one terminal [`Exit`], kept separately (as
/// `crate::m16::Poison` is) so a host that has discarded the `Exit` can still
/// say what happened. `Unimplemented` mirrors `crate::m16::Poison`'s own
/// variant of the same name -- the host's own judgement, reached while
/// servicing a call, that a module asked for an import this host does not
/// implement; there is no `Exit` behind it at all. See
/// `crate::abi::Abi::unimplemented`.
///
/// Not `Copy`, unlike `crate::m16::Poison`: `Unimplemented`'s `String` fields
/// cannot be. Every use here already goes through `Clone` or a reference, so
/// nothing chases this beyond the derive line itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Poison {
    /// It faulted. See [`Exit::Fault`].
    Fault { signo: i32, eip: u32 },

    /// It overran its budget. See [`Exit::Timeout`].
    Timeout { eip: u32 },

    /// It called an import the host has no implementation for.
    Unimplemented { module: String, symbol: String },

    /// It called an import the host **does** implement, and that
    /// implementation refused. The `m16` mirror of this variant carries the
    /// full reasoning; in short, "not implemented" and "implemented, and it
    /// could not answer" send a reader in opposite directions, and collapsing
    /// them cost a long detour tracing The Rose's boot.
    Refused {
        module: String,
        symbol: String,
        why: String,
    },
}

impl std::fmt::Display for Poison {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fault { signo, eip } => {
                write!(f, "module faulted with signal {signo} at {eip:#010x}")
            }
            Self::Timeout { eip } => {
                write!(f, "module timed out at {eip:#010x}")
            }
            Self::Unimplemented { module, symbol } => {
                write!(f, "{module}.{symbol} is not implemented")
            }
            Self::Refused {
                module,
                symbol,
                why,
            } => {
                write!(f, "{module}.{symbol} refused: {why}")
            }
        }
    }
}

/// What a host call hands back to the module, for [`Machine::resume`].
///
/// The 32-bit-cdecl tier of `crate::m16::Ret`: plain 32-bit `cdecl` returns an
/// `int` (or a pointer -- this ABI is flat, so there is no `crate::m16::Ret::Far`
/// counterpart) in `EAX`, and anything 64 bits wide in `EDX:EAX`, high half
/// in `EDX`. Naming the width here rather than a resume method per shape is
/// the same choice `crate::m16::Ret` makes, for the same reason: a table of
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

/// A module in memory: what sits behind each thunk, and where its entry
/// point is.
///
/// The 32-bit sibling of `crate::m16::ne::Module`, much smaller. A PE
/// image's own mapping -- sections, relocations, the IAT -- lives in
/// [`Memory`]/[`Image`] once loaded, not here: `crate::abi::Abi::Mem`
/// (`Wg32::Mem`, in `crates/mbbs` -- a different crate, so this is
/// deliberately not an intra-doc link; `mbbs-machine` does not depend on
/// `mbbs` and rustdoc cannot resolve it from here) owns that, since
/// `Abi::mem` needs somewhere to reborrow it from `Cpu` regardless of
/// whether a module has been loaded yet -- see
/// `crates/mbbs/src/abi/wg32.rs`'s own module doc comment ("Collision 2").
/// This only needs to carry what `crate::abi::Abi::import`/
/// `crate::abi::Abi::caller` read: the bound import table, in thunk-index
/// order, and the entry point's linear address.
#[derive(Debug, Clone)]
pub struct Module {
    entry: u32,
    init: Option<u32>,
    imports: Vec<crate::module::ImportSite>,
}

impl Module {
    pub fn new(entry: u32, init: Option<u32>, imports: Vec<crate::module::ImportSite>) -> Self {
        Self { entry, init, imports }
    }

    /// The linear address `DllMain`/the module's own entry point sits at --
    /// `AddressOfEntryPoint`, the address the OS loader would jump to.
    ///
    /// **This is not where a Worldgroup module's own init routine lives.**
    /// For a Borland-linked PE, `AddressOfEntryPoint` is the C runtime
    /// startup stub, not `DllMain` and certainly not `register_module`'s
    /// caller -- see [`Module::init`], which is the address a host actually
    /// wants. Measured against `LUNATIX.DLL`: `entry()` answers RVA
    /// `0x1000` (the Borland stub), `init()` answers RVA `0x115c`
    /// (`_init__lunatix`, exported ordinal 1). Entering `entry()` directly
    /// is exactly the bug this doc comment exists to keep from happening
    /// again -- `mbbs-server`'s host thread took SIGSEGV 13 bytes into the
    /// stub, at `entry() + 0xd`, before `Module::init` existed to answer
    /// the question correctly.
    pub fn entry(&self) -> u32 {
        self.entry
    }

    /// The linear address of the module's own init routine -- what a host
    /// must call to reach `register_module`, and, unlike [`Module::entry`],
    /// not necessarily anywhere near the PE entry point.
    ///
    /// **Not "exported ordinal 1."** That was this crate's belief until it
    /// was measured against a second module: `LUNATIX.DLL`'s ordinal 1 is
    /// `_init__lunatix`, its real init routine, but `RCIROSE.DLL`'s ordinal
    /// 1 is `_his_mods`, gameplay code -- its init routine,
    /// `_init__rcirose`, sits at ordinal 352. One module agreeing with
    /// itself is not a convention, only a coincidence that survived because
    /// nobody had yet measured a module linked the other way around. The
    /// name both modules actually agree on is `_init__<dll>`
    /// (case-insensitive; PE spells it lower-case), which is what this
    /// field is resolved by now -- see [`crate::m32::PeImage::init_rva`]
    /// for the full reasoning, including why ordinal 1 is tried only as a
    /// fallback and never preferred once a name resolves.
    ///
    /// `None` if the image has no export directory, no `_init__<dll>`
    /// export, and no export at ordinal 1 either -- mirrors
    /// `crate::m16::ne::Module::init`'s own `None` case, the NE-side
    /// analogue of this same name-first-ordinal-fallback resolution. Set at
    /// load time by `crate::abi::wg32::Wg32::load` (a different crate; not
    /// doc-linked from here for the same reason `Module`'s own module doc
    /// comment gives) from `PeImage::init_rva`.
    pub fn init(&self) -> Option<u32> {
        self.init
    }

    /// What thunk `index` stands for, as [`Exit::Call`] reports it. Mirrors
    /// `crate::m16::ne::Module::import`.
    pub fn import(&self, index: u16) -> Option<&crate::module::ImportSite> {
        self.imports.get(usize::from(index))
    }

    /// Every import the module has, in thunk-index order.
    pub fn imports(&self) -> &[crate::module::ImportSite] {
        &self.imports
    }
}

/// A 32-bit module's execution state: its thunk table, its Win32 [`Tib`], and
/// the crossing context needed to re-enter it.
///
/// Unlike `crate::m16::Machine`, this does not own a loaded [`Image`] -- see
/// [`Machine::call`]'s doc comment. A module's memory is the caller's to keep
/// alive; this owns only what execution itself needs, and needs regardless of
/// which (or how many) images are ever entered through it.
pub struct Machine {
    /// The thunk table and the trampoline. The host's, and no module's.
    bridge: Mapping,

    /// The module's stack and Win32 TIB. `FS` is loaded from this on every
    /// entry; see `tib.rs`.
    tib: Tib,

    /// The state the assembly is entered through, together with the
    /// CPU-time timer that stops a module which will not stop itself. One
    /// object because the timer holds the context's address; see
    /// [`watchdog::Watched`]. Armed for the whole of a [`Machine::call`],
    /// shim servicing included -- mirrors `crate::m16::Machine::ctx` exactly.
    ctx: Watched,

    /// `ESP` (a linear address) when the module last called out, or `None`
    /// before its first call and after it has returned. The frame the
    /// module's own `call` pushed -- one 4-byte near return address -- sits
    /// at exactly this offset; [`Machine::resume`] reads it back to know
    /// where to continue.
    ///
    /// Unlike `crate::m16::Machine::frame_sp`, nothing needs stepping over to
    /// reach it: the call thunk here pushes nothing before reaching the
    /// trampoline (`asm.rs`'s module doc comment -- `EAX`/`ECX` are ordinary
    /// caller-saved scratch under 32-bit cdecl, so a thunk has nothing of
    /// the module's to save), so `out_esp` at the moment of [`Exit::Call`]
    /// already names this address directly.
    frame_sp: Option<u32>,

    /// How much CPU time one entry point may have. Mirrors
    /// `crate::m16::Machine::budget`.
    budget: Duration,

    /// Set once this machine has faulted or overrun, and never cleared. A
    /// poisoned machine refuses to be entered again.
    poisoned: Option<Poison>,

    /// Where the x87 `ST0` capture scratch qword sits within [`Machine::bridge`],
    /// past the trampoline. See [`Machine::arm_st0_capture`] for why it
    /// exists at all and why it lives here rather than in [`asm::Ctx`].
    st0_scratch_off: usize,

    /// The one thunk slot currently wired to capture `ST0`, if any -- see
    /// [`Machine::arm_st0_capture`]. `None` until armed; [`Machine::take_st0`]
    /// panics against that, rather than silently handing back whatever
    /// garbage happens to sit in the scratch qword.
    st0_capture_slot: Option<u16>,
}

impl Machine {
    /// The module's own stack, as `(limit, base)` -- low end and high end.
    ///
    /// Exposed because a stack address is a linear address like any other,
    /// and `crate::m32::Memory` (image plus host arena) cannot resolve one:
    /// the stack is a third `Mapping`, owned by the `Tib` in here. Any
    /// module passing a pointer to one of its own locals -- `char buf[128];
    /// fgets(buf, sizeof buf, f);`, the commonest C idiom there is -- hands
    /// the host an address that resolves in neither of `Memory`'s two
    /// mappings.
    pub fn stack_range(&self) -> (u32, u32) {
        (self.tib.stack_limit(), self.tib.stack_base())
    }

    /// Build the thunk table and trampoline, a module stack and TIB, and arm
    /// fault recovery on this thread.
    pub fn new() -> io::Result<Self> {
        let tramp = trampoline();
        let st0_scratch_off = TRAMPOLINE_OFFSET + tramp.len();
        let mut bridge = Mapping::new(st0_scratch_off + ST0_SCRATCH_LEN)?;

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
        // which is the same shape `crate::m16::Machine::new` uses for its own
        // thunk table (`crates/mbbs-machine/src/m16/mod.rs:375-411`) and for the same
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
            ctx: Watched::new()?,
            frame_sp: None,
            budget: DEFAULT_BUDGET,
            poisoned: None,
            st0_scratch_off,
            st0_capture_slot: None,
        })
    }

    /// How much CPU time one entry point may have. See [`Machine::set_budget`].
    pub fn budget(&self) -> Duration {
        self.budget
    }

    /// Change the CPU budget an entry point gets, for calls made from now on.
    /// Mirrors `crate::m16::Machine::set_budget` exactly.
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
    pub fn poisoned(&self) -> Option<&Poison> {
        self.poisoned.as_ref()
    }

    /// Refuse this module from now on, for a reason the host reached itself.
    ///
    /// Mirrors `crate::m16::Machine::poison` exactly, watchdog disarm
    /// included: the call frame is forgotten, the watchdog timer is
    /// stopped, and every later [`call`](Machine::call)/
    /// [`resume`](Machine::resume) fails naming the reason. The first
    /// reason wins -- a module poisoned for one thing that then trips over
    /// another is still poisoned for the first, which is the one that is
    /// true. See `crate::m16::Machine::poison`'s own doc comment for why a
    /// host-reached reason (e.g. an unimplemented import) is worth having
    /// at all, alongside the fault and timeout paths that already poison
    /// through `Machine::run`'s own terminal arms.
    ///
    /// **This method used to skip the disarm.** Until Task 16
    /// (`docs/plans/2026-08-12-abi-border-implementation.md`) landed the
    /// 32-bit watchdog, `crate::m32::asm::Ctx` carried no timer state at
    /// all, so there was nothing here for a poisoned machine to leave
    /// running. That gap is closed now: this machine has a watchdog exactly
    /// like `crate::m16::Machine`'s, and this method disarms it exactly the
    /// same way.
    ///
    /// # Errors
    ///
    /// If the watchdog timer cannot be disarmed.
    /// Is this machine's watchdog timer still counting down?
    ///
    /// For asserting that [`Machine::poison`] really stopped it -- see
    /// `crate::m32::watchdog::Watchdog::armed` for why that needed an
    /// observer rather than trust.
    ///
    /// # Errors
    ///
    /// If the kernel will not report the timer's state.
    pub fn watchdog_armed(&self) -> io::Result<bool> {
        self.ctx.armed()
    }

    pub fn poison(&mut self, reason: Poison) -> io::Result<()> {
        self.poisoned.get_or_insert(reason);
        self.frame_sp = None;
        self.ctx.disarm()
    }

    /// The linear address of the outstanding call's near return address --
    /// `None` before any call and after the module has returned. Mirrors
    /// `crate::m16::Machine::frame_sp`, which exists for the same reason: a
    /// diagnostic a caller can read without this crate needing to expose the
    /// stack itself. `examples/init_trace.rs` uses it to report how much
    /// stack margin is left above a given call, since [`Machine::arg_u32`]
    /// panics rather than silently reading past this machine's own stack.
    pub fn frame_sp(&self) -> Option<u32> {
        self.frame_sp
    }

    /// The module's stack's high end -- one past the last mapped byte.
    /// Diagnostic-only, for the same reason as [`Machine::frame_sp`].
    pub fn stack_base(&self) -> u32 {
        self.tib.stack_base()
    }

    /// The register set a crossing would carry, and the one the module last
    /// left behind -- see [`Regs`].
    ///
    /// After any crossing this reports what the *module* had, not what this
    /// machine entered with: [`Machine::run`] folds the trampoline's
    /// observations back in, and a fault fills the same fields from the
    /// interrupted context (`m32/fault.rs`'s `rewrite`). Before the first
    /// crossing it is all zero.
    pub fn regs(&self) -> Regs {
        Regs {
            eip: self.ctx.target_offset,
            esp: self.ctx.esp,
            eax: self.ctx.eax,
            edx: self.ctx.edx,
            ebx: self.ctx.ebx,
            esi: self.ctx.esi,
            edi: self.ctx.edi,
            ebp: self.ctx.ebp,
        }
    }

    /// Replace the whole register set. See [`Regs`] for which of these
    /// [`Machine::call`] and [`Machine::resume`] overwrite, and
    /// [`Machine::jump`] for the entry point that honours all of them.
    ///
    /// Delegates to the individual setters rather than assigning the eight
    /// fields itself, so there is exactly one definition of what setting each
    /// register means -- `set_ebx` and friends have to touch `out_*` as well
    /// as the entry field, and a second copy of that here would be a place
    /// for the two to drift apart silently.
    pub fn set_regs(&mut self, regs: Regs) {
        self.set_eip(regs.eip);
        self.set_esp(regs.esp);
        self.set_eax(regs.eax);
        self.set_edx(regs.edx);
        self.set_ebx(regs.ebx);
        self.set_esi(regs.esi);
        self.set_edi(regs.edi);
        self.set_ebp(regs.ebp);
    }

    /// Where [`Machine::jump`] will enter. Overwritten by [`Machine::call`]
    /// (with its `entry`) and by [`Machine::resume`] (with the outstanding
    /// call's own return address).
    pub fn set_eip(&mut self, eip: u32) {
        self.ctx.target_offset = eip;
    }

    /// The stack pointer to enter with, as a linear address -- there is no
    /// segment base to add in 32-bit compatibility mode. Overwritten by
    /// [`Machine::call`] (which computes it from the frame it just wrote) and
    /// by [`Machine::resume`] (which steps it past the finished frame).
    ///
    /// Nothing here checks it against [`Machine::stack_range`]: a non-local
    /// jump's whole purpose is to leave the stack somewhere the call path
    /// would not have chosen, and this crate cannot know which of a module's
    /// mappings is a legitimate stack for it. An `ESP` outside the module's
    /// own mappings faults on first use, which is the honest outcome and the
    /// one [`Machine::poisoned`] already reports.
    pub fn set_esp(&mut self, esp: u32) {
        self.ctx.esp = esp;
    }

    /// Overwritten by [`Machine::resume`], which carries a host call's result
    /// here (`EDX:EAX` for a 64-bit one) -- see [`Ret`].
    pub fn set_eax(&mut self, eax: u32) {
        self.ctx.eax = eax;
    }

    /// The high half of a 64-bit result. Overwritten by [`Machine::resume`]
    /// alongside [`Machine::set_eax`].
    pub fn set_edx(&mut self, edx: u32) {
        self.ctx.edx = edx;
    }

    /// One of the callee-saved quad. Every entry point restores these from
    /// what the module last left, so a value set here survives a
    /// [`Machine::resume`] -- unlike `EAX`/`EDX`/`EIP`/`ESP`.
    pub fn set_ebx(&mut self, ebx: u32) {
        self.ctx.ebx = ebx;
        self.ctx.out_ebx = ebx;
    }

    /// See [`Machine::set_ebx`].
    pub fn set_esi(&mut self, esi: u32) {
        self.ctx.esi = esi;
        self.ctx.out_esi = esi;
    }

    /// See [`Machine::set_ebx`].
    pub fn set_edi(&mut self, edi: u32) {
        self.ctx.edi = edi;
        self.ctx.out_edi = edi;
    }

    /// See [`Machine::set_ebx`].
    pub fn set_ebp(&mut self, ebp: u32) {
        self.ctx.ebp = ebp;
        self.ctx.out_ebp = ebp;
    }

    /// Enter the module with exactly the registers [`Machine::regs`] reports
    /// -- the non-local jump.
    ///
    /// [`Machine::call`] and [`Machine::resume`] are the two structured
    /// entries: one starts an entry point at a frame it writes itself, the
    /// other continues an outstanding call at the address on the module's own
    /// stack. Both compute `EIP` and `ESP` and refuse to be told. This one
    /// computes nothing -- it is what a `longjmp` or a C++ unwind needs, where
    /// the destination and the stack both come from a buffer the module saved
    /// earlier and this host has no other way to honour.
    ///
    /// Everything else is identical to the structured entries: the same
    /// selector and `FS`, the same trampoline, the same exit classification,
    /// the same poisoning on a fault.
    ///
    /// # The watchdog is armed if nothing else armed it
    ///
    /// The budget is per *entry point*, not per crossing
    /// ([`Machine::call`] arms it and a terminal exit disarms it), so a jump
    /// taken from inside a running entry point must not restart it -- that
    /// would make an unwind loop a way to buy unbounded CPU one jump at a
    /// time. It re-arms only when the timer is not already running, which is
    /// the cold-start case a caller driving the machine by jumps alone
    /// would otherwise run entirely unwatched.
    ///
    /// # Errors
    ///
    /// If this machine is [`Machine::poisoned`], or the watchdog's timer
    /// cannot be read or armed.
    pub fn jump(&mut self) -> io::Result<Exit> {
        if let Some(poison) = &self.poisoned {
            return Err(io::Error::other(format!(
                "refusing to enter a poisoned module: {poison}"
            )));
        }
        if !self.ctx.armed()? {
            self.ctx.arm(self.budget)?;
        }
        self.enter()
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

    /// The linear address of [`Machine::arm_st0_capture`]'s scratch qword,
    /// within [`Machine::bridge`] and therefore -- like every address in that
    /// mapping -- guaranteed below 4 GiB, so a compat-mode `fstp m64fp` can
    /// address it with a plain `disp32`.
    fn st0_scratch_addr(&self) -> u32 {
        self.bridge.base() as usize as u32 + self.st0_scratch_off as u32
    }

    /// Rewrite thunk `slot`'s bytes so that, once bound to an import site,
    /// the call it services captures the x87 `ST0` the module left there --
    /// its own preceding `fld`/`fild`/`fmul`'s result -- before anything else
    /// runs.
    ///
    /// # Why this exists: Borland's `__ftol` needs its argument off the FPU
    /// stack, not off the cdecl stack
    ///
    /// `cw3220mt.DLL!__ftol` (Borland's float-to-long helper -- `fld <value>;
    /// call __ftol` is the calling convention, measured at all 13 of
    /// `LUNATIX.DLL`'s call sites: every one is immediately preceded by
    /// `fld`/`fild`/`fmul` and immediately followed by reading the result out
    /// of `EAX` alone, never `EDX`) takes its argument on `ST0`, which
    /// nothing in this crate's ordinary crossing protocol touches, saves, or
    /// exposes -- [`asm::Ctx`] carries GPRs and segment state only.
    ///
    /// # Why this happens in the module-side thunk, not the (shared, 64-bit)
    /// trampoline in `asm.rs`
    ///
    /// This machine's own worry, once execution is back in 64-bit long mode,
    /// is that ordinary compiled Rust code between the trampoline landing and
    /// a shim actually reading `ST0` might disturb it: the x87 register file
    /// is architecturally distinct from the `XMM` registers System V
    /// mandates for `f64`/`f32`, so ordinary floating-point Rust code cannot
    /// touch it, but "cannot today" is not the standard this crate holds
    /// itself to elsewhere (`asm.rs`'s own module doc comment: "measured, not
    /// assumed"). Capturing `ST0` *before* the far jump back -- while still
    /// in 32-bit compat mode, in code this method controls completely --
    /// closes that question rather than resting on it: no Rust code, and
    /// therefore no compiler decision this crate does not control, ever runs
    /// between the module's `call` and the `fstp` that reads `ST0`.
    ///
    /// The alternative -- capturing unconditionally for *every* thunk, in the
    /// shared trampoline -- was considered and rejected: `fstp` pops. Doing
    /// that on every host call regardless of whether the import was
    /// `__ftol` would, for every other import, either discard a value the
    /// module still needed further down its own FPU stack or -- when `ST0`
    /// legitimately held nothing -- raise a masked stack-fault/invalid-
    /// operation condition that leaves a spurious mark in the module's own
    /// status word for no reason connected to what it called. Confining the
    /// pop to the one slot that is actually bound to `__ftol` costs nothing
    /// on every other call, which an unconditional capture cannot say.
    ///
    /// # What the caller (the ABI layer) still owes
    ///
    /// This does not know, and cannot know, which slot `bind_imports` gave
    /// `cw3220mt.DLL!__ftol` -- that binding happens one layer up, after this
    /// machine exists. Call this once, after `Image::bind_imports` names the
    /// slot, before the module can reach it.
    ///
    /// # Panics
    ///
    /// If `slot` is not below [`MAX_THUNKS`], or if the specialised encoding
    /// below somehow outgrows [`THUNK_STRIDE`] (it does not: 6 + 17 = 23
    /// bytes against a 32-byte stride, and the `assert!` in [`Machine::new`]'s
    /// own thunk-building loop is the precedent for checking this at the
    /// point of construction rather than trusting the arithmetic silently).
    pub fn arm_st0_capture(&mut self, slot: u16) {
        assert!(
            slot < MAX_THUNKS,
            "thunk slot {slot} is beyond MAX_THUNKS ({MAX_THUNKS})"
        );

        let scratch_addr = self.st0_scratch_addr();
        let tramp_addr = self.bridge.base() as usize as u32 + TRAMPOLINE_OFFSET as u32;
        let cs64 = current_cs();

        let mut thunk = Vec::with_capacity(THUNK_STRIDE);
        // fstp qword ptr [scratch_addr] -- DD /3, ModRM 00_011_101 (disp32,
        // no base/index -- the 32-bit-mode encoding for a bare absolute
        // address), then the disp32 itself. Pops ST0, storing it as an
        // IEEE-754 double; exactly what a real `__ftol` does to read its
        // argument before converting it.
        thunk.push(0xdd);
        thunk.push(0x1d);
        thunk.extend_from_slice(&scratch_addr.to_le_bytes());
        // The ordinary call-thunk body: announce the kind, announce the
        // slot, far-jump to the trampoline. Identical to the generic thunk
        // `Machine::new` wrote here, because from this point on the crossing
        // is exactly as generic as any other -- only what led up to the jump
        // is special.
        thunk.push(0xb9); // mov ecx, imm32
        thunk.extend_from_slice(&KIND_CALL.to_le_bytes());
        thunk.push(0xb8); // mov eax, imm32
        thunk.extend_from_slice(&u32::from(slot).to_le_bytes());
        thunk.push(0xea); // ljmp ptr16:32
        thunk.extend_from_slice(&tramp_addr.to_le_bytes());
        thunk.extend_from_slice(&cs64.to_le_bytes());

        assert!(
            thunk.len() <= THUNK_STRIDE,
            "the ST0-capturing thunk needs {} bytes and the stride is {THUNK_STRIDE}",
            thunk.len(),
        );

        let off = THUNK_TABLE_OFFSET + usize::from(slot) * THUNK_STRIDE;
        self.bridge.as_mut_slice()[off..off + thunk.len()].copy_from_slice(&thunk);
        self.st0_capture_slot = Some(slot);
    }

    /// The `f64` [`Machine::arm_st0_capture`]'s thunk most recently popped
    /// off the module's `ST0`.
    ///
    /// Reads the scratch qword directly; there is exactly one, not one per
    /// call, so this is only meaningful immediately after the
    /// [`Exit::Call`] the armed slot produced, before anything resumes the
    /// module past it -- the same "read it before you move on" contract
    /// [`Machine::arg`] already carries for an ordinary cdecl argument.
    ///
    /// # Panics
    ///
    /// If [`Machine::arm_st0_capture`] was never called. A value read out of
    /// an unarmed scratch qword is not a *wrong* `f64` in any sense a caller
    /// could detect -- it is silently whatever `Mapping::new`'s zeroed page
    /// happens to still hold, which reads as a perfectly plausible `0.0`.
    /// This crate's standard is a diagnosable crash over a value that is
    /// wrong without announcing it (see the crate root and
    /// `docs/plans/2026-08-08-mbbs32-design.md`), so this panics instead of
    /// answering.
    pub fn take_st0(&self) -> f64 {
        assert!(
            self.st0_capture_slot.is_some(),
            "take_st0 called before arm_st0_capture bound a thunk slot to capture ST0"
        );
        let off = self.st0_scratch_off;
        let bytes: [u8; 8] = self.bridge.as_slice()[off..off + ST0_SCRATCH_LEN]
            .try_into()
            .expect("ST0_SCRATCH_LEN is 8, matching f64::from_le_bytes's input");
        f64::from_le_bytes(bytes)
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
    /// `crate::m16::Machine`, which owns its loaded NE module -- deliberately:
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
    /// The self-owned form: uses this machine's own stack, which it still
    /// holds when no `crate::m32::Memory` has adopted it. Every crossing
    /// test in this crate goes through here.
    ///
    /// The mapping is taken out for the duration and handed straight back,
    /// so that the stack slice and `&mut self` are never two live borrows of
    /// the same object -- which is also why [`Machine::call_on`] exists as
    /// the form production uses.
    ///
    /// # Panics
    ///
    /// If the stack has moved to `Memory` (see `Memory::adopt_stack`). After
    /// that move there is exactly one owner, and this is the wrong one.
    pub fn call(&mut self, entry: u32, args: &[u32]) -> io::Result<Exit> {
        let mut stack = self
            .tib
            .take_stack()
            .expect("the stack mapping has moved to `Memory`; use `call_on`");
        let out = self.call_on(stack.as_mut_slice(), entry, args);
        self.tib.put_stack(stack);
        out
    }

    /// Enter the module at `entry`, writing the call frame into `stack`.
    ///
    /// `stack` is the module's own stack bytes. Production passes
    /// `Memory`'s, because that is where they live once a `Wg32Cpu` exists
    /// -- see `Memory::adopt_stack` for why the stack has to be one of the
    /// mappings `Memory` can resolve.
    pub fn call_on(&mut self, stack: &mut [u8], entry: u32, args: &[u32]) -> io::Result<Exit> {
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
        stack[stack_off..stack_off + 4].copy_from_slice(&ret.to_le_bytes());
        for (i, arg) in args.iter().enumerate() {
            let off = stack_off + 4 + i * 4;
            stack[off..off + 4].copy_from_slice(&arg.to_le_bytes());
        }

        // A fresh entry point, not a continuation of whatever the last one
        // left behind: no outstanding frame, and the callee-saved quad
        // starts at a defined zero rather than some earlier call's leftovers
        // -- exactly the reset `crate::m16::Machine::call` gives `out_bx`/
        // `out_si`/`out_di`/`out_bp` before its own `self.run(...)`.
        self.frame_sp = None;
        self.ctx.out_ebx = 0;
        self.ctx.out_esi = 0;
        self.ctx.out_edi = 0;
        self.ctx.out_ebp = 0;

        // The watchdog is armed here and stays armed until the module
        // reaches a terminal exit, so the budget covers the whole entry
        // point -- every crossing, and all the time the host spends
        // servicing imports in between. Mirrors
        // `crate::m16::Machine::call`'s own arm exactly; see that method's
        // doc comment for why arming per crossing instead would be wrong.
        self.ctx.arm(self.budget)?;
        self.run(entry, sp, Ret::Void)
    }

    /// Resume the module from its outstanding call, handing back `ret` in
    /// `EAX` (`EDX:EAX` for a 64-bit result), and re-entering at the
    /// instruction after the module's own `call`.
    ///
    /// **This module's own doc comment used to claim there was no
    /// `resume_cleaning` counterpart here "because 32-bit Worldgroup is
    /// uniformly cdecl."** That was true of `WGSERVER`'s own game-host API --
    /// the ten callee-cleaned `F_*@` helpers a reader of `WGSERVER.DEF` might
    /// expect an analogue for really do live inside its `#ifdef GCDOS` block
    /// only, which a plain 32-bit cdecl PE like `wccmmud.dll` never takes --
    /// but it does not follow for the Win32 API a Worldgroup NT module
    /// imports directly. `KERNEL32.dll!GetModuleHandleA` and
    /// `!GetProcAddress` are stdcall by definition, and are measured that
    /// way at `LUNATIX.DLL`'s own call sites (`0x41d61d`, `0x41d62c`: 4 and 8
    /// bytes pushed, neither followed by an `add esp`). See
    /// [`resume_cleaning`](Machine::resume_cleaning)'s own doc comment for
    /// the counterpart this file now has, mirroring
    /// `crate::m16::Machine::resume_cleaning` on the flat 32-bit stack.
    ///
    /// # Errors
    ///
    /// If this machine is [`Machine::poisoned`].
    ///
    /// # Panics
    ///
    /// If the module is not stopped at a call.
    /// The self-owned form of [`Machine::resume_on`]; see [`Machine::call`].
    ///
    /// # Panics
    ///
    /// If the stack has moved to `Memory`.
    pub fn resume(&mut self, ret: Ret) -> io::Result<Exit> {
        self.resume_cleaning(ret, 0)
    }

    /// Resume, dropping `bytes` of the module's own arguments as well --
    /// the self-owned form of [`Machine::resume_on_cleaning`], the same
    /// relationship [`resume`](Machine::resume) has to
    /// [`resume_on`](Machine::resume_on).
    ///
    /// For an import that pops its own arguments under Win32's stdcall
    /// convention -- `GetModuleHandleA`/`GetProcAddress`, measured at
    /// `LUNATIX.DLL`'s own call sites (see [`resume`](Machine::resume)'s own
    /// doc comment). `bytes` is what the *module* pushed, so it does not
    /// include the near return address; `0` is exactly
    /// [`resume`](Machine::resume).
    ///
    /// # Panics
    ///
    /// If the stack has moved to `Memory`, or the module is not stopped at a
    /// call.
    pub fn resume_cleaning(&mut self, ret: Ret, bytes: u16) -> io::Result<Exit> {
        let mut stack = self
            .tib
            .take_stack()
            .expect("the stack mapping has moved to `Memory`; use `resume_on_cleaning`");
        let out = self.resume_on_cleaning(stack.as_mut_slice(), ret, bytes);
        self.tib.put_stack(stack);
        out
    }

    /// Resume the outstanding call, reading its frame out of `stack`.
    pub fn resume_on(&mut self, stack: &mut [u8], ret: Ret) -> io::Result<Exit> {
        self.resume_on_cleaning(stack, ret, 0)
    }

    /// [`Machine::resume_on`], dropping `bytes` of the module's own
    /// arguments as well -- the production form of
    /// [`Machine::resume_cleaning`], and the 32-bit analogue of
    /// `crate::m16::Machine::resume_cleaning`. See
    /// [`Machine::resume`]'s own doc comment for why this exists at all:
    /// `WGSERVER`'s own exports are uniformly cdecl, but the Win32 API a
    /// Worldgroup NT module imports directly is not, and this is what
    /// services `Cleans::Callee` for it.
    ///
    /// Identical to [`Machine::resume_on`] except for the last line: where
    /// that steps `ESP` past exactly the 4-byte near return address (leaving
    /// the module's own arguments for *it* to clean, cdecl-style), this
    /// steps past the return address **and** `bytes` more -- exactly what a
    /// stdcall callee's own `ret bytes` does in real x86, collapsed into one
    /// assignment because this host never actually executes a `ret`
    /// instruction to get back to the module; it splices `ESP` directly.
    pub fn resume_on_cleaning(&mut self, stack: &mut [u8], ret: Ret, bytes: u16) -> io::Result<Exit> {
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
        // `crate::m16::Machine::resume_cleaning`'s own comment warns an
        // unchecked `+= THUNK_SAVES` would -- an out-of-range `sp` here
        // fails loudly instead.
        let limit = self.tib.stack_limit();
        let off = sp
            .checked_sub(limit)
            .expect("resume(): the remembered call frame is below this machine's own stack")
            as usize;
        let at = {
            let bytes = stack.get(off..off + 4).expect(
                "resume(): the remembered call frame is outside this machine's own stack",
            );
            u32::from_le_bytes(bytes.try_into().expect("checked to be exactly 4 bytes"))
        };

        // This is where an overrun spent on host code is caught -- mirrors
        // `crate::m16::Machine::resume_cleaning`'s own check exactly. A
        // watchdog tick that arrives while the host is servicing an import
        // proves the budget is gone just as surely as one that interrupts
        // 32-bit code, and there is no sense re-entering a module whose
        // time is up in order to stop it a moment later.
        if self.ctx.expired() {
            // Report where it would have resumed -- the instruction after
            // the module's own `call`, which is the honest answer to
            // "where did it stop" for a module parked at an import call.
            return self.terminate(Exit::Timeout { eip: at });
        }

        // Step over the 4 bytes just read, exactly as the module's own `ret`
        // would when the call it made returns normally, plus `bytes` more --
        // exactly what a stdcall callee's own `ret bytes` would additionally
        // pop. `ESP` ends up where it stood the instant after the `call`
        // instruction pushed that return address, advanced by whichever
        // convention `bytes` encodes (`0` for cdecl, `resume_on`'s case),
        // with the host's answer now sitting in `EAX`/`EDX` in its place.
        self.run(at, sp + 4 + u32::from(bytes), ret)
    }

    /// Read the `n`th 32-bit cdecl argument of the outstanding call.
    ///
    /// Arguments sit immediately above the near return address the module's
    /// own `call` pushed -- cdecl pushes right to left, so argument 0 is the
    /// one nearest the frame. The 32-bit-cdecl analogue of
    /// `crate::m16::Machine::arg_u16`, one word wider and with no segment half to
    /// read separately, since this ABI is flat.
    ///
    /// Added for `crates/mbbs-machine/examples/init_trace.rs`
    /// (`docs/plans/2026-08-12-btrieve-finish.md`, Task 2): a recorder that
    /// only ever calls `resume`, never a real shim, still needs to see what
    /// was asked for in order to print it.
    ///
    /// # Panics
    ///
    /// If the module is not stopped at a call, or if `n` (or the offset it
    /// produces) does not fit within this machine's own stack -- every step
    /// is checked, mirroring [`Machine::resume`]'s own `checked_sub` above
    /// and for the same reason: a corrupted `frame_sp`, or a caller-supplied
    /// `n` far larger than any real argument list, must not silently wrap
    /// into an offset that `.get()` then accepts and reads garbage back for.
    /// Give up ownership of the module's stack mapping.
    ///
    /// Called once, by `mbbs::abi::Wg32Cpu::new`, to hand the stack to the
    /// `Memory` that will resolve addresses into it. `None` afterwards.
    pub fn take_stack(&mut self) -> Option<crate::m32::Mapping> {
        self.tib.take_stack()
    }

    /// This machine's own stack bytes, valid only while it still owns them.
    ///
    /// A `Machine` built on its own -- no `Memory` beside it -- keeps its
    /// stack in its `Tib`, which is where every one of this crate's own
    /// crossing tests reads an argument frame from. Once a `Wg32Cpu` is
    /// built, ownership moves to `Memory` (see `Memory::adopt_stack`) and
    /// this panics: after the move there is exactly one owner, and asking
    /// the wrong one is a bug rather than a fallback.
    pub fn stack_bytes(&self) -> &[u8] {
        self.tib.stack()
    }

    /// `stack` is the module's own stack bytes, which live in
    /// `crate::m32::Memory` rather than in here -- see
    /// `Memory::adopt_stack`. Passed in because this `Machine` no longer
    /// owns them and the caller (`Wg32::arg_frame`) holds both halves.
    pub fn arg_u32(&self, stack: &[u8], n: usize) -> u32 {
        let sp = self
            .frame_sp
            .expect("arg_u32() with no outstanding call to read from");
        let limit = self.tib.stack_limit();
        let frame_off = sp.checked_sub(limit).expect(
            "arg_u32(): the remembered call frame is below this machine's own stack",
        ) as usize;
        // The 4-byte near return address the module's own `call` pushed,
        // stepped over the same way `resume`'s own `off` does -- argument 0
        // sits immediately above it. `n * 4` is the one multiplication in
        // this file with no natural ceiling on `n` (a caller can pass
        // anything), so it gets its own `checked_mul` rather than folding
        // into the addition below and losing which operation overflowed.
        let arg_bytes = n
            .checked_mul(4)
            .expect("arg_u32(): argument index overflows a byte offset");
        let off = 4usize
            .checked_add(arg_bytes)
            .and_then(|past_ret| frame_off.checked_add(past_ret))
            .expect("arg_u32(): argument offset overflows this machine's own stack");
        let end = off
            .checked_add(4)
            .expect("arg_u32(): argument slot overflows this machine's own stack");
        let bytes = stack
            .get(off..end)
            .expect("arg_u32(): argument slot runs past this machine's own stack");
        u32::from_le_bytes(bytes.try_into().expect("checked to be exactly 4 bytes"))
    }

    /// The bytes of the outstanding call's argument frame, starting right
    /// after the 4-byte near return address **the module's own `call`**
    /// pushed beneath the arguments, and running to the end of this
    /// machine's stack.
    ///
    /// Not the return address [`Machine::call`] builds for the entry frame:
    /// that one is consumed on `Exit::Returned` through the return-thunk
    /// slot. The frame this reads is the one captured into
    /// `frame_sp` at `Exit::Call`, when a module called an import thunk. The
    /// two coincide only when a test enters directly at a thunk address, so
    /// naming the wrong pusher reads plausibly and is still wrong.
    ///
    /// Mirrors `crate::m16::Machine::arg_frame`: the same "widest slice that
    /// is still honestly backed by real memory" answer, for the same reason
    /// -- there is no arity here to size the window against, only the stack
    /// itself as a bound. It is the window [`Machine::arg_u32`] already reads
    /// one dword at a time, handed back whole; `crate::abi::Abi::arg_frame`'s
    /// `Wg32` arm delegates straight here, the same way `Wg16`'s delegates to
    /// `crate::m16::Machine::arg_frame`.
    ///
    /// Unlike `crate::m16::Machine::arg_frame`, there is no `THUNK_SAVES`-sized
    /// register-save area between the return address and argument 0 to step
    /// over -- [`Machine::frame_sp`]'s own doc comment says this machine's
    /// call thunk pushes nothing of the module's before reaching the
    /// trampoline, so only the 4-byte return address itself needs skipping,
    /// the same `+ 4` [`Machine::arg_u32`] uses.
    ///
    /// Also unlike `crate::m16::Machine::arg_frame`, `self.tib.stack()` is
    /// already an ordinary Rust slice rather than a `Segment` addressed
    /// through a hand-rolled `slice(offset, len)`, so the bounds check below
    /// is an ordinary `.get(start..)` -- no `checked_sub`-then-multiply
    /// arithmetic feeds an `unsafe` `from_raw_parts` the way
    /// `crate::m16::Machine::arg_frame`'s own doc comment warns a wrapped
    /// length would. There is no equivalent hazard here for the same
    /// `.get` to be checked twice against.
    ///
    /// # Panics
    ///
    /// If the module is not stopped at a call, or if the frame begins past
    /// the end of the stack -- mirroring [`Machine::arg_u32`]'s own panics,
    /// for the same reason: a corrupted `frame_sp` must fail loudly rather
    /// than read garbage or silently wrap.
    /// `stack` is the module's own stack bytes -- see [`Machine::arg_u32`].
    pub fn arg_frame<'s>(&self, stack: &'s [u8]) -> &'s [u8] {
        let sp = self
            .frame_sp
            .expect("arg_frame() with no outstanding call to read from");
        let limit = self.tib.stack_limit();
        let frame_off = sp.checked_sub(limit).expect(
            "arg_frame(): the remembered call frame is below this machine's own stack",
        ) as usize;
        let start = frame_off
            .checked_add(4)
            .expect("arg_frame(): the argument frame start overflows this machine's own stack");
        stack.get(start..).unwrap_or_else(|| {
            panic!(
                "arg_frame(): the module called out at a frame starting at {start:#x}, \
                 past the end of this machine's {} byte stack",
                stack.len()
            )
        })
    }

    /// Cross into 32-bit mode and come back, handing the module `ret` in
    /// `EAX`/`EDX:EAX` on the way in.
    fn run(&mut self, entry: u32, sp: u32, ret: Ret) -> io::Result<Exit> {
        let (eax, edx) = ret.registers();

        self.ctx.target_offset = entry;
        self.ctx.esp = sp;
        self.ctx.eax = eax;
        self.ctx.edx = edx;

        // Hand the callee-saved quad back exactly as the module left it --
        // whether that is a fresh call's defined zero (`Machine::call`
        // primes `out_ebx`/`out_esi`/`out_edi`/`out_ebp` before calling
        // here) or a resume's leftovers from the crossing that produced the
        // `Exit::Call` being serviced. The same propagation
        // `crate::m16::Machine::run` does for `si`/`di`/`bp`/`ds`, one register
        // wider and one register longer, and for the same reason: a host
        // call is a callee like any other under cdecl, and losing these
        // would not crash anything -- it would silently hand the module back
        // a value it never stored, which is worse.
        self.ctx.ebx = self.ctx.out_ebx;
        self.ctx.esi = self.ctx.out_esi;
        self.ctx.edi = self.ctx.out_edi;
        self.ctx.ebp = self.ctx.out_ebp;

        self.enter()
    }

    /// Cross with the register set already in `self.ctx`, and classify how it
    /// came back.
    ///
    /// The tail [`Machine::run`] and [`Machine::jump`] share. Everything
    /// above this line differs between them -- `run` computes `EIP`/`ESP` and
    /// the argument registers, `jump` takes whatever a caller set -- and
    /// everything below is the crossing itself, which is identical and must
    /// stay that way: the selector, the `FS` reload, the fault classification
    /// and the poisoning are properties of *this machine*, not of how a
    /// caller chose to enter it.
    fn enter(&mut self) -> io::Result<Exit> {
        self.ctx.target_selector = USER32_CS;
        self.ctx.fs = self.tib.fs_selector();

        // The trampoline writes these on every crossing, but a poisoned
        // machine never re-enters here, and a fresh `Ctx` starts zeroed
        // anyway -- this is a defensive reset, not load-bearing today, kept
        // for the same reason `crate::m16::Machine::run` clears `out_signo`
        // before every entry: the next crossing must not be able to read a
        // stale value from the one before it.
        self.ctx.out_signo = 0;
        self.ctx.out_eip = 0;
        self.ctx.out_ecx = 0;

        // SAFETY: `target_offset`/`target_selector`/`fs`/`esp` are all set --
        // the first by whichever entry point called this, the rest
        // immediately above; the thunk table and trampoline in `self.bridge`
        // were written by `new` and live for as long as `self`; `self.tib`'s
        // stack and TIB mappings are likewise live for as long as `self`,
        // and `fault::arm` was called in `new`, so a fault this call takes
        // is recoverable rather than fatal.
        unsafe { asm::enter(self.ctx.as_ptr()) };

        // Fold what the module left into the set the next entry would carry,
        // so [`Machine::regs`] answers about the *module* rather than about
        // the values this crossing happened to start with. Deliberately not a
        // replacement for `run`'s own quad propagation above: that one is
        // what makes `call_on`'s zeroing of the `out_*` quad reach a fresh
        // entry point, and this one would hand the new entry point the
        // previous one's leftovers if it were relied on alone.
        self.ctx.eax = self.ctx.out_eax;
        self.ctx.edx = self.ctx.out_edx;
        self.ctx.ebx = self.ctx.out_ebx;
        self.ctx.esi = self.ctx.out_esi;
        self.ctx.edi = self.ctx.out_edi;
        self.ctx.ebp = self.ctx.out_ebp;
        self.ctx.esp = self.ctx.out_esp;
        if self.ctx.out_signo != 0 {
            let signo = self.ctx.out_signo as i32;
            let eip = self.ctx.out_eip;
            // Only a fault knows where the module actually was: an ordinary
            // crossing comes back through the trampoline, and the module's
            // own resume address is the near return address on its stack
            // rather than anything the CPU handed back. Elsewhere
            // `target_offset` keeps meaning "where the last entry went",
            // which is the only answer this machine has.
            self.ctx.target_offset = eip;
            // Which signal it was is the whole distinction -- everything
            // else (the recovery, the poisoning, the lost state) is
            // identical. Mirrors `crate::m16::Machine::run`'s own dispatch.
            return if signo == watchdog::signo() {
                self.terminate(Exit::Timeout { eip })
            } else {
                self.terminate(Exit::Fault { signo, eip })
            };
        }

        if self.ctx.out_ecx == KIND_RETURN {
            self.frame_sp = None;
            // The entry point is over, so its budget is too. Leaving the
            // timer armed would charge the next call for this one's
            // leftovers -- mirrors `crate::m16::Machine::run`'s own disarm
            // on `Exit::Returned`.
            self.ctx.disarm()?;
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

    /// Stop for good: disarm the watchdog, poison the machine and forget the
    /// call frame. Mirrors `crate::m16::Machine::terminate` exactly.
    ///
    /// Forgetting the frame matters as much as the rest. A module that died
    /// or was stopped mid-call has nothing meaningful left on its stack, and
    /// `arg_u32` and friends would otherwise happily report the leftovers.
    fn terminate(&mut self, exit: Exit) -> io::Result<Exit> {
        self.poisoned.get_or_insert(match exit {
            Exit::Fault { signo, eip } => Poison::Fault { signo, eip },
            Exit::Timeout { eip } => Poison::Timeout { eip },
            other => unreachable!("{other:?} is not a terminal exit"),
        });
        self.frame_sp = None;
        self.ctx.disarm()?;
        Ok(exit)
    }
}

#[cfg(test)]
mod st0_tests {
    use super::*;

    /// The shape every real `cw3220mt.DLL!__ftol` call site uses (measured
    /// by disassembling `LUNATIX.DLL`'s 13 call sites): the module loads a
    /// value onto `ST0` -- here a bare `fld`, where the real module also
    /// interposes an `fmul`, which changes nothing about what crosses the
    /// boundary -- then calls the thunk with no cdecl arguments at all,
    /// because `__ftol`'s one argument lives on the FPU stack.
    ///
    /// This is the failing test this feature did not have before
    /// [`Machine::arm_st0_capture`] existed: without it, nothing captures
    /// `ST0` at all, and [`Machine::take_st0`] has nothing to read.
    #[test]
    fn arm_st0_capture_delivers_the_module_s_fld_across_the_crossing() {
        const VALUE: f64 = 12345.5; // exactly representable in f64 and in the eye
        const SLOT: u16 = 3;

        let mut machine = Machine::new().expect("a fresh machine");
        machine.arm_st0_capture(SLOT);

        let mut code_mapping = Mapping::new(4096).expect("a low code mapping");
        let base = code_mapping.base() as usize as u32;

        const CONST_OFF: usize = 512;
        let const_addr = base + CONST_OFF as u32;
        code_mapping.as_mut_slice()[CONST_OFF..CONST_OFF + 8]
            .copy_from_slice(&VALUE.to_le_bytes());

        // fld qword ptr [const_addr] -- DD /0, ModRM 00_000_101 (disp32, no
        // base/index), then the absolute address itself.
        let mut code = vec![0xdd_u8, 0x05];
        code.extend_from_slice(&const_addr.to_le_bytes());

        // call rel32 -- E8, then target - (address right after this
        // instruction), the ordinary near-call encoding.
        let target = machine.thunk_addr(SLOT);
        let next_ip = base + code.len() as u32 + 5;
        code.push(0xe8);
        code.extend_from_slice(&target.wrapping_sub(next_ip).to_le_bytes());

        code_mapping.as_mut_slice()[..code.len()].copy_from_slice(&code);

        let exit = machine
            .call(base, &[])
            .expect("the module traps into the armed thunk");
        assert_eq!(
            exit,
            Exit::Call { index: SLOT },
            "the armed thunk must still report as an ordinary Exit::Call"
        );

        assert_eq!(
            machine.take_st0(),
            VALUE,
            "ST0 did not survive the module -> host crossing intact"
        );

        // `code_mapping` must outlive `machine.call`, matching every other
        // crossing test in this crate family (`asm.rs`'s own module doc
        // comment on `low_mapping_with`).
        drop(code_mapping);
    }

    /// A value read out of an unarmed scratch qword would be indistinguishable
    /// from a genuine `0.0` -- this crate's standard is a diagnosable panic
    /// over an answer that is wrong without announcing it.
    #[test]
    #[should_panic(expected = "take_st0 called before arm_st0_capture")]
    fn take_st0_refuses_to_answer_before_a_slot_is_armed() {
        let machine = Machine::new().expect("a fresh machine");
        let _ = machine.take_st0();
    }
}

/// [`Machine::jump`] and the register setters it exists to honour.
///
/// Every test here asserts against something the *module* did with a value,
/// never against the field it was written into -- a setter that stores into a
/// struct nobody loads would pass any test that reads the struct back, and
/// that was the whole objection to adding these at all.
#[cfg(test)]
mod register_tests {
    use super::*;

    const SLOT: u16 = 2;
    const SCRATCH_OFF: usize = 1024;

    /// Writes `code` at the base of a fresh low mapping and returns it with
    /// that base. The mapping must outlive every crossing into it.
    fn mapped(code: &[u8]) -> (Mapping, u32) {
        let mut mapping = Mapping::new(4096).expect("a low code mapping");
        mapping.as_mut_slice()[..code.len()].copy_from_slice(code);
        let base = mapping.base() as usize as u32;
        (mapping, base)
    }

    /// `call rel32` to `target`, from an instruction stream whose next
    /// instruction begins at `next_ip`.
    fn call_rel32(target: u32, next_ip: u32) -> Vec<u8> {
        let mut out = vec![0xe8u8];
        out.extend_from_slice(&target.wrapping_sub(next_ip).to_le_bytes());
        out
    }

    /// **Every** setter reaches the module, one row per register.
    ///
    /// The first version of this test set three registers through
    /// [`Machine::set_regs`] and checked one of them. Making `set_ebx` a
    /// no-op left it passing -- it never called `set_ebx` at all. So each
    /// setter is now exercised on its own, and each is proven by the module
    /// *storing that register to memory*, which no amount of writing into an
    /// unread struct field can fake.
    ///
    /// `EIP` needs no row: every row only runs because [`Machine::set_eip`]
    /// put it at `base`. A no-op there enters at zero and faults instead.
    #[test]
    fn every_register_setter_reaches_the_module() {
        type Setter = fn(&mut Machine, u32);
        // `mov [disp32], r32` is `89 /r` with ModRM `00 rrr 101`: the r/m
        // field is the disp32 form and `rrr` names the source register.
        // `ESP` is fine as a *source* -- the encoding that would be ambiguous
        // is `100` in the r/m field, which is the SIB escape, not this.
        let rows: &[(&str, Setter, u8)] = &[
            ("eax", |m, v| m.set_eax(v), 0x05),
            ("edx", |m, v| m.set_edx(v), 0x15),
            ("ebx", |m, v| m.set_ebx(v), 0x1d),
            ("esp", |m, v| m.set_esp(v), 0x25),
            ("ebp", |m, v| m.set_ebp(v), 0x2d),
            ("esi", |m, v| m.set_esi(v), 0x35),
            ("edi", |m, v| m.set_edi(v), 0x3d),
        ];

        for (name, set, modrm) in rows {
            let mut machine = Machine::new().expect("a fresh machine");
            let (mut mapping, base) = mapped(&[]);
            let scratch = base + SCRATCH_OFF as u32;
            let (_limit, stack_base) = machine.stack_range();

            // `ESP` has to name a real stack: the `call` below pushes onto
            // it. The store happens first either way, so what is asserted is
            // still exactly the value that was set.
            let value = if *name == "esp" { stack_base - 128 } else { 0xdead_0000 | u32::from(modrm.to_owned()) };

            let mut code = vec![0x89u8, *modrm];
            code.extend_from_slice(&scratch.to_le_bytes());
            let next_ip = base + code.len() as u32 + 5;
            code.extend_from_slice(&call_rel32(machine.thunk_addr(SLOT), next_ip));
            mapping.as_mut_slice()[..code.len()].copy_from_slice(&code);

            machine.set_eip(base);
            machine.set_esp(stack_base - 64);
            set(&mut machine, value);

            let exit = machine.jump().expect("a jump into mapped code");
            assert_eq!(
                exit,
                Exit::Call { index: SLOT },
                "{name}: the module did not run and trap"
            );

            let stored = u32::from_le_bytes(
                mapping.as_mut_slice()[SCRATCH_OFF..SCRATCH_OFF + 4]
                    .try_into()
                    .expect("four bytes"),
            );
            assert_eq!(
                stored, value,
                "{name} did not reach the module -- its setter wrote a field \
                 the crossing does not load"
            );

            drop(mapping);
        }
    }

    /// A callee-saved register set between crossings survives a
    /// [`Machine::resume`], which is why those four setters write `out_*` as
    /// well as the entry field.
    ///
    /// `resume` restores the quad from what the module last left
    /// (`Machine::run`'s own propagation), so a setter that wrote only the
    /// entry field would be silently undone on the way back in -- the setter
    /// would appear to work under [`Machine::jump`] and do nothing under the
    /// entry point a host actually uses in production.
    #[test]
    fn a_callee_saved_register_set_between_crossings_survives_a_resume() {
        const VALUE: u32 = 0x5150_5150;

        let mut machine = Machine::new().expect("a fresh machine");
        let (mut mapping, base) = mapped(&[]);
        let scratch = base + SCRATCH_OFF as u32;
        let thunk = machine.thunk_addr(SLOT);

        // call thunk; mov [scratch], ebx; call thunk
        let mut code = call_rel32(thunk, base + 5);
        code.extend_from_slice(&[0x89, 0x1d]);
        code.extend_from_slice(&scratch.to_le_bytes());
        let next_ip = base + code.len() as u32 + 5;
        code.extend_from_slice(&call_rel32(thunk, next_ip));
        mapping.as_mut_slice()[..code.len()].copy_from_slice(&code);

        let exit = machine.call(base, &[]).expect("the module traps");
        assert_eq!(exit, Exit::Call { index: SLOT }, "stopped at the first thunk");

        machine.set_ebx(VALUE);
        let exit = machine.resume(Ret::Void).expect("the module resumes");
        assert_eq!(exit, Exit::Call { index: SLOT }, "stopped at the second thunk");

        let stored = u32::from_le_bytes(
            mapping.as_mut_slice()[SCRATCH_OFF..SCRATCH_OFF + 4]
                .try_into()
                .expect("four bytes"),
        );
        assert_eq!(
            stored, VALUE,
            "resume restored the module's own EBX over the one that was set"
        );

        drop(mapping);
    }

    /// The other half of the same claim: what the module leaves in the
    /// callee-saved quad is what [`Machine::regs`] reports afterwards, rather
    /// than the value the crossing was entered with.
    #[test]
    fn regs_reports_what_the_module_left_not_what_it_was_entered_with() {
        const ENTERED: u32 = 0x1111_1111;
        const MODULE_SET: u32 = 0x2222_2222;

        let mut machine = Machine::new().expect("a fresh machine");
        let (mut mapping, base) = mapped(&[]);

        // mov esi, imm32 -- BE id.
        let mut code = vec![0xbeu8];
        code.extend_from_slice(&MODULE_SET.to_le_bytes());
        let next_ip = base + code.len() as u32 + 5;
        code.extend_from_slice(&call_rel32(machine.thunk_addr(SLOT), next_ip));
        mapping.as_mut_slice()[..code.len()].copy_from_slice(&code);

        let (_limit, stack_base) = machine.stack_range();
        machine.set_regs(Regs {
            eip: base,
            esp: stack_base - 64,
            esi: ENTERED,
            ..Regs::default()
        });
        machine.jump().expect("a jump into mapped code");

        assert_eq!(
            machine.regs().esi,
            MODULE_SET,
            "regs() answered about the entry rather than about the module"
        );

        drop(mapping);
    }

    /// After a fault, the registers reported are the ones the module held at
    /// the faulting instruction. Without `fault.rs`'s own capture they would
    /// be whatever the *previous* crossing left -- a plausible register set
    /// belonging to another moment, which is the worst kind of wrong answer.
    #[test]
    fn regs_after_a_fault_are_the_modules_own_at_the_faulting_instruction() {
        const ENTERED: u32 = 0x3333_3333;
        const MODULE_SET: u32 = 0x4444_4444;

        let mut machine = Machine::new().expect("a fresh machine");
        let (mapping, base) = mapped(&[]);

        // mov edi, imm32; then mov eax, moffs32(0) -- the null read
        // `m32/fault.rs`'s own tests use to take a SIGSEGV inside 32-bit
        // compatibility mode.
        let mut code = vec![0xbfu8];
        code.extend_from_slice(&MODULE_SET.to_le_bytes());
        let fault_at = base + code.len() as u32;
        code.extend_from_slice(&[0xa1, 0x00, 0x00, 0x00, 0x00]);
        let mut mapping = mapping;
        mapping.as_mut_slice()[..code.len()].copy_from_slice(&code);

        let (_limit, stack_base) = machine.stack_range();
        machine.set_regs(Regs {
            eip: base,
            esp: stack_base - 64,
            edi: ENTERED,
            ..Regs::default()
        });

        let exit = machine.jump().expect("a jump into mapped code");
        assert_eq!(
            exit,
            Exit::Fault {
                signo: libc::SIGSEGV,
                eip: fault_at
            },
            "the module did not fault where this test placed the fault"
        );

        let regs = machine.regs();
        assert_eq!(
            regs.edi, MODULE_SET,
            "the fault path reported a register from an earlier moment"
        );
        assert_eq!(regs.eip, fault_at, "regs().eip did not name the fault");

        drop(mapping);
    }

    /// A jump is an entry like any other, so a poisoned machine refuses it --
    /// the check `call` and `resume` already make, which a third entry point
    /// would otherwise walk straight past.
    #[test]
    fn a_poisoned_machine_refuses_to_be_jumped_into() {
        let mut machine = Machine::new().expect("a fresh machine");
        let (mapping, base) = mapped(&[0xa1, 0x00, 0x00, 0x00, 0x00]); // null read

        let (_limit, stack_base) = machine.stack_range();
        machine.set_regs(Regs {
            eip: base,
            esp: stack_base - 64,
            ..Regs::default()
        });
        machine.jump().expect("the first jump faults");
        assert!(machine.poisoned().is_some(), "a fault must poison");

        let refused = machine.jump().expect_err("a poisoned machine refuses");
        assert!(
            refused.to_string().contains("poisoned"),
            "the refusal must say why: {refused}"
        );

        drop(mapping);
    }

    /// A caller driving the machine by jumps alone still gets a watchdog.
    /// `call` is what arms it for a structured entry point, and a machine
    /// entered only by `jump` would otherwise run with the timer stopped.
    #[test]
    fn a_cold_jump_arms_the_watchdog() {
        let mut machine = Machine::new().expect("a fresh machine");
        let (mut mapping, base) = mapped(&[]);

        let code = call_rel32(machine.thunk_addr(SLOT), base + 5);
        mapping.as_mut_slice()[..code.len()].copy_from_slice(&code);

        assert!(
            !machine.ctx.armed().expect("gettime"),
            "a fresh machine's watchdog is stopped"
        );

        let (_limit, stack_base) = machine.stack_range();
        machine.set_regs(Regs {
            eip: base,
            esp: stack_base - 64,
            ..Regs::default()
        });
        machine.jump().expect("a jump into mapped code");

        assert!(
            machine.ctx.armed().expect("gettime"),
            "a cold jump left the module running unwatched"
        );

        drop(mapping);
    }
}
