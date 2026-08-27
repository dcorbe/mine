//! The two pieces of assembly that cross between 64-bit and 32-bit compat-mode
//! code.
//!
//! Same manoeuvre as `crates/mbbs-machine/src/m16/asm.rs`, adapted for a flat 32-bit ABI
//! rather than Borland's 16-bit huge model. Read that file first -- this one
//! only documents where it differs, and every difference is a measurement, not
//! a guess: `docs/plans/mbbs32/compat32.c` and `compat32_fault.c` are the two
//! experiments, and `docs/plans/2026-08-08-mbbs32-design.md` ("The execution
//! substrate") is where they are written up.
//!
//! Both routines are written as real assembly rather than hand-assembled byte
//! arrays, and both address [`Ctx`] through `const` operands built from
//! `offset_of!` rather than literal displacements -- the sibling crate's own
//! doc comment explains why: a hand-worked-out offset is the mistake this
//! project keeps making, and it is always silent.
//!
//! # What is different from `crate::m16::asm`, and why
//!
//! **No `ss16` field, and no segment switch at all.** `compat32_fault.c`
//! measured `SS` unchanged across a fault in 32-bit compat mode -- 32-bit flat
//! code runs on the host's own stack segment, so there is nothing to save or
//! restore. `mbbs16`'s `R13` (which carries the host's `SS` across the
//! excursion) has no counterpart here.
//!
//! **`FS` is the one segment register this crate still swaps**, because
//! `wccmmud.dll`'s `DllMain` dereferences through it before it does anything
//! else (see `tib.rs`). The *selector* load/restore shape is exactly
//! `mbbs16`'s `DS` handling: the module's selector is loaded from [`Ctx::fs`]
//! before the jump, the host's is carried across in a register the CPU cannot
//! touch while compatibility mode is running (`%r12`, mirroring `mbbs16`'s use
//! of the same register for `DS`), and restored by the trampoline on the way
//! back.
//!
//! **That is not the whole story for `FS`, and `DS`'s shape is not enough on
//! its own -- this was measured, not assumed, and the first version of this
//! file got it wrong.** `DS`'s base is architecturally irrelevant once we are
//! back in 64-bit long mode -- the CPU ignores it for addressing -- so
//! round-tripping `mbbs16`'s selector is sufficient there. `FS` is different
//! on this architecture: glibc's thread-local storage is addressed through
//! `FS_BASE`, a hidden per-thread value the kernel sets once via
//! `arch_prctl(ARCH_SET_FS)` while the selector itself stays `0` (null) for
//! the whole life of the thread. Loading *any* selector into `FS` -- even
//! reloading the null selector the host was already running under -- makes
//! the CPU re-derive `FS_BASE` from the descriptor table (which means zero,
//! for a null selector) rather than leaving the existing base alone. So a
//! selector round-trip through `0 -> 0` still **zeroes** `FS_BASE`: measured
//! on this box, one crossing with [`Ctx::fs`] left at its default was enough
//! to break the very next `std::thread_local` access after `mbbs32_enter`
//! returned. [`enter`] is the fix: it reads the calling thread's real
//! `FS_BASE` before touching `FS` at all ([`host_fs_base`] -- one
//! `arch_prctl(ARCH_GET_FS)` per thread, cached, because glibc never moves
//! it), and writes it back after the raw crossing is over -- through the
//! `wrfsbase` instruction where the kernel allows it ([`fsgsbase_enabled`]),
//! through `arch_prctl(ARCH_SET_FS)` otherwise. Every time, not only when
//! [`Ctx::fs`] is non-zero, because the selector reload that breaks
//! `FS_BASE` happens unconditionally. A module with no TIB still carries
//! `fs = 0`, which is a no-op for the *selector*; it is [`enter`]'s job, not
//! the assembly's, to make it a no-op for `FS_BASE` too. The save/restore
//! used to be a pair of `arch_prctl` syscalls per crossing, and per crossing
//! is the wrong unit: MajorMUD's database-update sweep crosses ~800 times
//! per Btrieve operation, which put ~60,000 `arch_prctl` calls a second on
//! the machine thread and made one module-batched kick overrun the host's
//! one-second stall floor where the 16-bit machine (which never touches
//! `FS`) stayed far under it.
//!
//! **`DS` and `ES` are loaded from `SS` before the jump, unconditionally, and
//! this was also measured rather than assumed -- the second thing the first
//! version of this file got wrong.** Neither `mbbs16` nor `compat32.c`/
//! `compat32_fault.c` needed to think about this: `mbbs16` always had a real
//! `DS` to load (a module's `DGROUP`), and both C references only ever touch
//! memory through `FS` or not at all. A fresh host thread's `DS`/`ES` carry
//! the null selector -- harmless in 64-bit long mode, which ignores
//! data-segment bases for addressing entirely -- but 32-bit compatibility
//! mode is full legacy protected mode, where an absent segment faults *any*
//! access through it, at *any* address, mapped or not. `DllMain` needs this
//! immediately: `rep stos` zeroing its own BSS addresses through `ES`, and
//! practically everything else it does addresses through `DS`. This one was
//! caught by `tib.rs`'s own end-to-end test, and only because its TIB and
//! stack mappings happened to land adjacent in memory -- `FS:[4]` resolved
//! correctly, so the *next* instruction was the first ordinary, unprefixed
//! access, and that is where it faulted. `ordinary_memory_access_through_ds_works`
//! below is the test that would have caught it directly. Since `SS` is
//! already known both present and flat (`compat32_fault.c` measured it
//! unchanged across a fault), it costs nothing to reuse its selector for
//! `DS`/`ES`, and it needs no restore afterward for the same reason `mbbs16`'s
//! `DS` needs none: irrelevant to addressing once we are back in 64-bit mode.
//!
//! **The far jump target is `0x23`, not an LDT selector**, and the way back is
//! `0x33` (read at runtime by [`current_cs`], not hardcoded, for the same
//! reason `mbbs16` does not hardcode it). Both are Linux's fixed GDT entries
//! for 32-bit compatibility-mode code and 64-bit long-mode code respectively --
//! see `compat32.c`'s header comment. Unlike the 16-bit case there is no
//! `modify_ldt` call for the code segment itself: `__USER32_CS` already exists,
//! for every process, for free.
//!
//! **Registers carry `u32`, not `u64`.** `mbbs16` widens 16-bit values into
//! 64-bit `Ctx` fields and loads them with `movq` because compatibility mode
//! only ever reads the low 16 bits and the rest is inert. 32-bit compat mode
//! is the same story one tier up: a `movl` into a 32-bit register name
//! zero-extends the upper 32 bits of its 64-bit home automatically, on this
//! architecture, in either mode -- so `u32` fields loaded with `movl` are both
//! sufficient and simpler than carrying dead high bits around in a `u64`.
//!
//! **The callee-saved set is `EBX`/`ESI`/`EDI`/`EBP`, plain 32-bit cdecl.**
//! There is no Borland-runtime-helper quirk analogous to `mbbs16`'s `BX`/`CX`
//! preservation on this side -- nothing in the design doc's survey of this
//! module's imports calls for one -- so `EAX`, `ECX` and `EDX` are ordinary
//! caller-saved scratch and this file never preserves them across a crossing.
//!
//! Everything else -- `R11` for the return address, `R15` for the host's
//! `RSP`, the trampoline living below 4 GiB because a far jump's offset field
//! is 32 bits either way, and `R14` carrying the `Ctx` pointer through a mode
//! compatibility mode cannot even name -- is identical in shape to the 16-bit
//! crate.

use core::arch::global_asm;
use core::mem::offset_of;

/// Linux's fixed GDT selector for 32-bit compatibility-mode code. Present in
/// every process; unlike the 16-bit case, entering 32-bit code costs no
/// `modify_ldt` call at all.
pub(crate) const USER32_CS: u16 = 0x23;

/// State handed to [`enter`], and filled in by the trampoline on the way
/// back out.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Ctx {
    /// Far pointer to enter through, in the `m16:32` form `ljmpl` expects: a
    /// 32-bit offset immediately followed by a 16-bit selector. These two must
    /// stay adjacent and at the very front -- the jump reads them as one
    /// operand, straight off `%r14`. This is the format the instruction needs
    /// regardless of the target's own bitness: a far jump executed *from*
    /// 64-bit long mode has no encoding for anything narrower.
    pub target_offset: u32,
    pub target_selector: u16,

    /// The module's `FS` selector, loaded before the jump and restored to the
    /// host's own on the way back. `0` -- the null selector -- when the
    /// excursion has no Win32 TIB to offer; loading and restoring a null
    /// selector is a harmless no-op. See `tib.rs`.
    pub fs: u16,

    /// Stack pointer to enter with, as a **linear address**, never a segment
    /// offset. Unlike `mbbs16`'s `sp`, there is no segment base to add: 32-bit
    /// compat mode runs on the host's own flat `SS`, so this is simply written
    /// straight into `ESP`.
    pub esp: u32,

    /// Registers carrying a host call's return value back to the module.
    /// `EAX` alone for most results, `EDX:EAX` for a 64-bit one.
    pub eax: u32,
    pub edx: u32,

    /// The callee-saved quad in 32-bit cdecl, restored on entry so that a host
    /// call is transparent to the module -- exactly the role `crate::m16::asm::Ctx`'s
    /// `si`/`di`/`bp` play, one register wider and one register longer.
    pub ebx: u32,
    pub esi: u32,
    pub edi: u32,
    pub ebp: u32,

    /// `EAX`/`EDX` as the trampoline found them: a thunk index, or the
    /// module's own return value, depending on how it got there.
    pub out_eax: u32,
    pub out_edx: u32,
    /// `ECX` as the trampoline found it: the thunk-kind discriminant
    /// (`crate::m32::KIND_CALL`/`crate::m32::KIND_RETURN`) a thunk placed there before
    /// jumping. `ECX` is ordinary caller-saved scratch under 32-bit cdecl --
    /// nothing a module returns through it -- so a thunk is free to load it,
    /// and [`crate::m32::Machine::run`] reads this field to tell "the module
    /// called an import" from "the module returned" without disturbing
    /// `EAX`/`EDX`, which for a return carry the module's actual result.
    pub out_ecx: u32,
    /// The callee-saved quad as the module left it, to be handed back
    /// unchanged on the next entry.
    pub out_ebx: u32,
    pub out_esi: u32,
    pub out_edi: u32,
    pub out_ebp: u32,
    /// `ESP` at the same instant, still a linear address. The call frame --
    /// whatever `cdecl` return address and arguments are on it -- is just
    /// above.
    pub out_esp: u32,

    /// Nonzero once a watchdog tick has been recorded against this module,
    /// whether or not it was in 32-bit mode at the time. The assembly never
    /// touches it: the signal handler sets it and
    /// [`crate::m32::watchdog::Watched::arm`] clears it, so it survives the
    /// crossings in between and outlives the excursion a tick may have
    /// interrupted. Mirrors `crate::m16::asm::Ctx::expired` exactly, one
    /// register narrower to match the rest of this struct.
    ///
    /// Separate from `out_signo` because that one is cleared before every
    /// entry, and a tick that arrives while the host is servicing an import
    /// must not be wiped out by the next crossing it triggers.
    pub expired: u32,

    /// The signal that stopped the module, or `0` if the crossing ended by
    /// reaching the trampoline normally. Set only by `crate::fault::handler`
    /// -- never by the assembly above, which has no branch that touches it --
    /// so `0` is a reliable "no fault happened" sentinel for
    /// [`crate::m32::Machine::run`] to test.
    pub out_signo: u64,

    /// Linear `EIP` at the moment of the fault, meaningless unless
    /// `out_signo != 0`. Unlike `crate::m16::asm::Ctx`'s `out_cs`/`out_ip`, this
    /// needs no segment base added: 32-bit compat mode here always runs flat,
    /// so the value the CPU pushed already is the address a disassembly of
    /// the image is annotated with.
    pub out_eip: u32,

    // ---- DPMI extension (append-only) --------------------------------------
    //
    // These fields exist for `crate::m32::dpmi`, which runs a DOS-extender
    // guest whose privileged `int`/`in`/`out`/`cli`/`sti` faults are *decoded*
    // rather than fatal. They are appended deliberately: the assembly above
    // addresses only the fixed-offset fields at the front of this struct
    // (`offset_of!`-named), so adding fields at the end changes no offset it
    // reads. Every field here is zero for an ordinary m32 (PE32) crossing --
    // which never sets `dpmi` -- and that zero is exactly what keeps the DPMI
    // branch in `crate::m32::fault::recover` invisible to the PE32 path.
    /// `0` = an ordinary m32 excursion (faults are poisoned). Nonzero = a DPMI
    /// excursion: `crate::m32::fault::recover` hands the fault to
    /// `crate::m32::dpmi::fault::recover_trap` first.
    pub dpmi: u64,

    /// Virtual interrupt-enable flag, owned by the fault handler: a guest
    /// `cli`/`sti` writes it and IRQ injection reads it. Meaningful only when
    /// `dpmi != 0`.
    pub vif: u64,

    /// Inclusive-low / exclusive-high linear bounds of the guest's mapping, so
    /// the handler can read instruction bytes at the faulting `EIP` without
    /// risking a fault of its own. Meaningful only when `dpmi != 0`.
    pub code_lo: u64,
    pub code_hi: u64,

    /// What the handler decoded, when `dpmi != 0`: `0` = a genuine fault
    /// (`out_signo`/`out_eip` authoritative), `1` = a software interrupt
    /// (`out_vector` is the vector), `2` = a port access (`out_vector` packs
    /// it -- see `crate::m32::dpmi::machine`).
    pub out_kind: u64,

    /// The decoded software-interrupt vector (kind 1) or packed port op
    /// (kind 2). Meaningless for kind 0.
    pub out_vector: u64,

    /// Length in bytes of the decoded trapping instruction, so the host knows
    /// where the guest resumes (`out_eip + out_len`). Meaningful for kinds 1
    /// and 2.
    pub out_len: u64,
}

impl Ctx {
    /// The one part of the layout `const` operands cannot express: `ljmpl
    /// *(%r14)` reads a packed `m16:32` from the start of the struct, so the
    /// far pointer's two halves must be adjacent and first.
    pub const ASSERT_FAR_POINTER_FIRST: () = {
        assert!(offset_of!(Ctx, target_offset) == 0);
        assert!(offset_of!(Ctx, target_selector) == 4);
    };
}

// Forces the assertion above to be checked at compile time regardless of
// whether anything else in this crate references it yet -- there is no
// `Machine` here for it to ride along with the way `crate::m16::Machine::new`
// does.
const _: () = Ctx::ASSERT_FAR_POINTER_FIRST;

// The outbound half. Lives in the ordinary text segment and may sit anywhere
// in the address space: the jump is the indirect `m16:32` form, so only its
// *target* -- and the trampoline it names -- are confined to the low 4 GiB.
//
// R11, R14 and R15 carry state across the excursion, same as `mbbs16`. R12
// joins them here to carry the host's FS selector, playing exactly the role it
// plays for DS on the 16-bit side. Compatibility mode has no encoding that
// names r8-r15, which is what makes any of this survive the crossing: nothing
// on the other side can disturb them.
//
// RBP and RBX are pushed and popped too, and this is not optional decoration:
// both are callee-saved under the SysV x86-64 ABI this function is called
// under from Rust, and this function's own body *writes* EBP and EBX (loading
// [`Ctx::ebp`]/[`Ctx::ebx`], the module's half of the callee-saved quad) on
// every path, including the one where the far jump is never reached. A
// function that assigns to a callee-saved register without saving and
// restoring it is not "using it as scratch" -- it is corrupting whatever the
// *caller* had there, silently, for exactly as long as it takes something in
// the caller (here, or several frames up) to next read that register. This
// was found the hard way: an earlier version of this file pushed only
// R12/R14/R15, reasoning that RBP/RBX were not needed as scratch -- true, and
// irrelevant, since they are clobbered regardless -- and a mutation aimed at
// something else entirely (deleting the EBX load, two tests below) crashed
// the whole test process instead of failing a single assertion, because by
// then some caller several frames up already depended on RBX surviving the
// call.
global_asm!(
    r#"
.globl mbbs32_enter_raw
.hidden mbbs32_enter_raw
.p2align 4
mbbs32_enter_raw:
    pushq   %rbp
    pushq   %rbx
    pushq   %r12
    pushq   %r14
    pushq   %r15

    movq    %rdi, %r14                  /* the Ctx */
    leaq    1f(%rip), %r11              /* where the trampoline sends us back */
    movq    %rsp, %r15                  /* the host's RSP, to restore */

    movw    %fs, %r12w                  /* the host's FS, for the way back */
    movzwl  {fs}(%r14), %ecx            /* the module's, or 0 if it has none */
    movw    %cx, %fs

    movw    %ss, %cx                    /* DS and ES need a REAL descriptor too --  */
    movw    %cx, %ds                    /* see the module doc comment. SS is already */
    movw    %cx, %es                    /* known good and flat, so borrow its selector */

    movl    {eax}(%r14), %eax           /* the call's return value, EAX or EDX:EAX */
    movl    {edx}(%r14), %edx
    movl    {ebx}(%r14), %ebx           /* the callee-saved quad, as the module */
    movl    {esi}(%r14), %esi           /* had it before whatever call sent us  */
    movl    {edi}(%r14), %edi           /* out to the host                     */
    movl    {ebp}(%r14), %ebp
    movl    {esp}(%r14), %esp           /* a linear address, not a segment offset */

    ljmpl   *(%r14)                     /* into 32-bit compatibility mode */
1:
    popq    %r15
    popq    %r14
    popq    %r12
    popq    %rbx
    popq    %rbp
    retq
"#,
    fs = const offset_of!(Ctx, fs),
    eax = const offset_of!(Ctx, eax),
    edx = const offset_of!(Ctx, edx),
    ebx = const offset_of!(Ctx, ebx),
    esi = const offset_of!(Ctx, esi),
    edi = const offset_of!(Ctx, edi),
    ebp = const offset_of!(Ctx, ebp),
    esp = const offset_of!(Ctx, esp),
    options(att_syntax)
);

// The inbound half, and the only code here that must live below 4 GiB: a
// 32-bit far jump can name a 32-bit offset and no more, so 32-bit code jumping
// back out has to find this trampoline at an address that fits. It is
// therefore copied into the module's low mapping at run time rather than
// called where it sits, which is why it touches nothing but registers and
// displacements off %r14 -- it has to run correctly from an address it was not
// linked for.
//
// This code itself runs in 64-bit long mode: the far jump that reaches it
// switches CS to the host's own 64-bit selector, which is exactly what makes
// `movq %r15, %rsp` and `jmp *%r11` valid instructions again.
global_asm!(
    r#"
.globl mbbs32_tramp_start, mbbs32_tramp_end
.hidden mbbs32_tramp_start, mbbs32_tramp_end
.p2align 4
mbbs32_tramp_start:
    movl    %eax, {out_eax}(%r14)       /* a thunk index, or a return value */
    movl    %edx, {out_edx}(%r14)
    movl    %ecx, {out_ecx}(%r14)       /* the thunk-kind discriminant a thunk set */
    movl    %ebx, {out_ebx}(%r14)       /* the callee-saved quad, to be handed */
    movl    %esi, {out_esi}(%r14)       /* back unchanged when the module is   */
    movl    %edi, {out_edi}(%r14)       /* resumed                             */
    movl    %ebp, {out_ebp}(%r14)
    movl    %esp, {out_esp}(%r14)       /* the call frame is just above */

    movw    %r12w, %fs                  /* the host's FS back */

    movq    %r15, %rsp
    jmp     *%r11
mbbs32_tramp_end:
"#,
    out_eax = const offset_of!(Ctx, out_eax),
    out_edx = const offset_of!(Ctx, out_edx),
    out_ecx = const offset_of!(Ctx, out_ecx),
    out_ebx = const offset_of!(Ctx, out_ebx),
    out_esi = const offset_of!(Ctx, out_esi),
    out_edi = const offset_of!(Ctx, out_edi),
    out_ebp = const offset_of!(Ctx, out_ebp),
    out_esp = const offset_of!(Ctx, out_esp),
    options(att_syntax)
);

unsafe extern "C" {
    /// The raw crossing. **Do not call this directly** -- see [`enter`],
    /// which wraps it with the `FS_BASE` save/restore the module doc comment
    /// explains. Not even `pub(crate)`, so nothing in this crate can reach it
    /// by accident.
    fn mbbs32_enter_raw(ctx: *mut Ctx);

    static mbbs32_tramp_start: u8;
    static mbbs32_tramp_end: u8;
}

/// `ARCH_GET_FS` / `ARCH_SET_FS` from `<asm/prctl.h>`, which `libc` does not
/// re-export (only the `SYS_arch_prctl` syscall number itself does).
const ARCH_SET_FS: i32 = 0x1002;
const ARCH_GET_FS: i32 = 0x1003;

/// The calling thread's current `FS_BASE` -- glibc's thread-local-storage
/// pointer on this architecture, set once via `arch_prctl(ARCH_SET_FS)` when
/// the thread was created and otherwise left alone by ordinary code.
fn fs_base() -> u64 {
    let mut base: u64 = 0;
    // SAFETY: `&mut base` is a live, correctly sized place for the kernel to
    // write into for the duration of the call; `ARCH_GET_FS` has no failure
    // mode for a thread that exists to be asking.
    unsafe {
        libc::syscall(libc::SYS_arch_prctl, ARCH_GET_FS, &mut base as *mut u64);
    }
    base
}

/// [`fs_base`], read once per thread and cached.
///
/// glibc sets a thread's `FS_BASE` exactly once, at thread creation, and
/// nothing in this process moves it afterwards -- the only writer is
/// [`enter`]'s restore, which writes back this same value. So the syscall
/// read is per-thread, not per-crossing. Per-crossing it was ruinous: a
/// MajorMUD database-update operation makes ~800 crossings, and `strace -c`
/// on a live board's update sweep counted 910,468 `arch_prctl` calls in 15
/// seconds against 569 Btrieve operations (2026-08-26) -- ~98% of the
/// thread's syscall time.
///
/// Must be called while `FS_BASE` is still the host's -- before the raw
/// crossing -- because the cache lives in thread-local storage addressed
/// through that very base. [`enter`] is the only caller and does exactly
/// that.
fn host_fs_base() -> u64 {
    thread_local! {
        static CACHED: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
    }
    // `0` doubles as "not read yet": a glibc thread's `FS_BASE` is never 0 --
    // it addresses the thread control block itself.
    CACHED.with(|cache| {
        let mut base = cache.get();
        if base == 0 {
            base = fs_base();
            cache.set(base);
        }
        base
    })
}

/// Whether the kernel lets user space execute `wrfsbase` (CR4.FSGSBASE set).
///
/// `AT_HWCAP2` bit 1 is Linux's own signal for exactly this. CPUID is *not*
/// enough: a kernel older than 5.9, or booted with `nofsgsbase`, leaves
/// CR4.FSGSBASE clear on a CPU that advertises the feature, and the
/// instruction faults `#UD`. Resolved once; an atomic load afterwards --
/// and [`enter`] resolves it *before* the crossing, because `OnceLock`'s
/// initialisation path is ordinary Rust that may touch thread-local state,
/// which does not exist between the raw crossing and the restore.
fn fsgsbase_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    const HWCAP2_FSGSBASE: libc::c_ulong = 1 << 1;
    // SAFETY: `getauxval` reads the process's own auxiliary vector and has no
    // preconditions.
    *ENABLED.get_or_init(|| unsafe { libc::getauxval(libc::AT_HWCAP2) } & HWCAP2_FSGSBASE != 0)
}

/// Restore `FS_BASE` to a value [`fs_base`] previously read back on this same
/// thread -- the syscall fallback for a kernel without [`fsgsbase_enabled`].
fn set_fs_base(base: u64) {
    // SAFETY: setting the calling thread's own FS_BASE back to a value it
    // held before the crossing -- never a made-up address, never another
    // thread's.
    unsafe {
        libc::syscall(libc::SYS_arch_prctl, ARCH_SET_FS, base as usize);
    }
}

/// Restore `FS_BASE` through the `wrfsbase` instruction: the same write
/// [`set_fs_base`] asks the kernel for, without the kernel round-trip.
///
/// # Safety
///
/// [`fsgsbase_enabled`] must have answered `true`, or this instruction is
/// undefined (`#UD`). `base` must be a value this same thread's `FS_BASE`
/// actually held -- the identical contract [`set_fs_base`] documents.
unsafe fn write_fs_base(base: u64) {
    // SAFETY: forwarded from this function's own contract; the instruction
    // itself touches nothing but the named register and the hidden base.
    unsafe {
        std::arch::asm!("wrfsbase {0}", in(reg) base, options(nomem, nostack, preserves_flags));
    }
}

/// Enter 32-bit compatibility mode through `ctx`, returning when the
/// trampoline is reached.
///
/// This is [`mbbs32_enter_raw`] plus the `FS_BASE` save/restore the module
/// doc comment explains -- unconditionally, whether or not [`Ctx::fs`] is
/// non-zero, because it is the act of loading *any* selector into `FS` that
/// disturbs `FS_BASE`, not merely loading a real one.
///
/// # Safety
///
/// `ctx` must be a valid, exclusively-owned `Ctx` for the duration of the
/// call: every field the assembly reads must already be set, and the code and
/// stack the entry describes must be mapped, executable/writable as
/// appropriate, and live until the trampoline (or a fault) returns control
/// here.
pub(crate) unsafe fn enter(ctx: *mut Ctx) {
    // Both resolved BEFORE the crossing and carried in locals: from the
    // moment `mbbs32_enter_raw` returns until the restore below, `FS_BASE`
    // is zero, so nothing on that path may touch thread-local state -- not
    // the per-thread cache behind `host_fs_base`, and not `OnceLock`'s
    // initialisation path behind `fsgsbase_enabled`.
    let host_fs_base = host_fs_base();
    let wrfsbase = fsgsbase_enabled();
    // SAFETY: forwarded from this function's own contract.
    unsafe { mbbs32_enter_raw(ctx) };
    if wrfsbase {
        // SAFETY: `wrfsbase` gated on `fsgsbase_enabled`; the base is the one
        // this same thread held before the crossing.
        unsafe { write_fs_base(host_fs_base) };
    } else {
        set_fs_base(host_fs_base);
    }
}

/// The trampoline's bytes, for copying into a mapping below 4 GiB.
pub(crate) fn trampoline() -> &'static [u8] {
    // SAFETY: both symbols bracket a contiguous run of instructions emitted by
    // the assembler in one `global_asm!` block, so the range is valid and the
    // end is never before the start.
    unsafe {
        let start = &raw const mbbs32_tramp_start;
        let end = &raw const mbbs32_tramp_end;
        let len = end.offset_from_unsigned(start);
        core::slice::from_raw_parts(start, len)
    }
}

/// The selector of the 64-bit code segment we are running in.
///
/// Read rather than assumed, exactly as `crate::m16::current_cs` is: Linux's
/// `__USER_CS` is 0x33, but the value has to be right for a far jump back to
/// land, and reading it costs one instruction.
pub(crate) fn current_cs() -> u16 {
    let cs: u16;
    // SAFETY: reading a segment register has no side effects.
    unsafe {
        std::arch::asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags))
    };
    cs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m32::map::Mapping;

    /// Bytes for `ljmp $USER_CS, $target` (`ljmp ptr16:32`, opcode `0xea`),
    /// the way back out of 32-bit code.
    fn ljmp_back(target: u32) -> [u8; 7] {
        let mut b = [0u8; 7];
        b[0] = 0xea;
        b[1..5].copy_from_slice(&target.to_le_bytes());
        b[5..7].copy_from_slice(&current_cs().to_le_bytes());
        b
    }

    /// A fresh low mapping with a copy of the trampoline at its base and
    /// `build(tramp_addr)`'s bytes 16-byte-aligned right after it -- the same
    /// layout `docs/plans/mbbs32/compat32.c` uses. Returns the mapping (which
    /// must outlive the call to [`enter`]) and the code's address.
    fn low_mapping_with(build: impl FnOnce(u32) -> Vec<u8>) -> (Mapping, u32) {
        let mut mapping = Mapping::new(4096).expect("a low mapping");
        let tramp_addr = mapping.base() as usize as u32;
        let tramp = trampoline();
        let tramp_len = tramp.len();
        let code_off = tramp_len.div_ceil(16) * 16;

        let code = build(tramp_addr);
        assert!(
            code_off + code.len() <= mapping.len(),
            "test code does not fit the 4 KiB scratch mapping"
        );

        let dst = mapping.as_mut_slice();
        dst[..tramp_len].copy_from_slice(tramp);
        dst[code_off..code_off + code.len()].copy_from_slice(&code);

        (mapping, tramp_addr + code_off as u32)
    }

    /// Assemble `mov eax, imm32 ; ljmp $USER_CS, $tramp` into a fresh low
    /// mapping and enter it. This is `docs/plans/mbbs32/compat32.c` translated
    /// to Rust: the minimal proof that 32-bit compatibility-mode code runs at
    /// all, entered from 64-bit code with no LDT, and comes back with a value
    /// in `EAX`.
    #[test]
    fn a_hand_assembled_mov_and_far_jump_arrives_in_eax() {
        let (_mapping, code_addr) = low_mapping_with(|tramp_addr| {
            let mut code = vec![0xb8u8]; // mov eax, imm32
            code.extend_from_slice(&0xc0_ffeeu32.to_le_bytes());
            code.extend_from_slice(&ljmp_back(tramp_addr));
            code
        });

        let mut ctx = Ctx {
            target_offset: code_addr,
            target_selector: USER32_CS,
            ..Default::default()
        };
        // SAFETY: `code_addr` points at the freshly written instructions
        // above, which are mapped read/write/execute; `_mapping` is not
        // dropped until after `enter` returns.
        unsafe { enter(&mut ctx) };

        assert_eq!(ctx.out_eax, 0xc0_ffee, "EAX did not carry the value back");
    }

    /// Ordinary `DS`-relative memory access must work in entered code, not
    /// only `FS`-prefixed access -- neither test above touches memory at all,
    /// and `tib.rs`'s own test caught the gap this closes only by coincidence
    /// of address layout (its TIB and stack mappings happened to land
    /// adjacent, so `FS`-relative addressing alone got far enough to fault on
    /// the very next, unprefixed instruction).
    ///
    /// `DS` (and `ES`) on a fresh host thread carry the null selector --
    /// harmless in 64-bit long mode, where the CPU ignores data-segment bases
    /// entirely, but fatal the instant 32-bit compatibility mode tries to use
    /// one: an absent segment faults *any* access through it, at *any*
    /// address, mapped or not. `mbbs32_enter_raw` loads `DS`/`ES` from `SS`
    /// (already known flat and valid -- `compat32_fault.c` measured it
    /// unchanged) before the jump; this test is what would have caught it
    /// directly, without needing two mappings to happen to land adjacent.
    #[test]
    fn ordinary_memory_access_through_ds_works() {
        const SENTINEL_OFFSET: usize = 3072; // well clear of trampoline + code
        const SENTINEL: u32 = 0x1357_9bdf;

        let (mut mapping, code_addr) = low_mapping_with(|tramp_addr| {
            let sentinel_addr = tramp_addr + SENTINEL_OFFSET as u32;
            let mut code = vec![0xa1u8]; // mov eax, moffs32 -- DS-relative, no prefix
            code.extend_from_slice(&sentinel_addr.to_le_bytes());
            code.extend_from_slice(&ljmp_back(tramp_addr));
            code
        });
        mapping.as_mut_slice()[SENTINEL_OFFSET..SENTINEL_OFFSET + 4]
            .copy_from_slice(&SENTINEL.to_le_bytes());

        let mut ctx = Ctx {
            target_offset: code_addr,
            target_selector: USER32_CS,
            ..Default::default()
        };
        // SAFETY: as `a_hand_assembled_mov_and_far_jump_arrives_in_eax`.
        unsafe { enter(&mut ctx) };

        assert_eq!(
            ctx.out_eax, SENTINEL,
            "DS did not resolve to a working flat segment"
        );
    }

    /// The registers 32-bit cdecl treats as callee-saved must arrive as
    /// [`Ctx`] describes them, and come back as the module left them.
    ///
    /// Distinct, unlikely-to-collide sentinels per register, each incremented
    /// by the module: a missing load would leave whatever the *host's* own
    /// code last put in that register (zero, most likely, immediately after
    /// `Ctx::default()`), which `+ 1` makes easy to tell apart from the
    /// expected `sentinel + 1`.
    #[test]
    fn callee_saved_registers_survive_a_crossing() {
        // INC r32, single-byte forms valid only outside 64-bit mode -- legal
        // 32-bit compatibility-mode instructions, opcode 0x40 + register.
        const INC_EBX: u8 = 0x43;
        const INC_ESI: u8 = 0x46;
        const INC_EDI: u8 = 0x47;
        const INC_EBP: u8 = 0x45;

        let (_mapping, code_addr) = low_mapping_with(|tramp_addr| {
            let mut code = vec![INC_EBX, INC_ESI, INC_EDI, INC_EBP];
            code.extend_from_slice(&ljmp_back(tramp_addr));
            code
        });

        let mut ctx = Ctx {
            target_offset: code_addr,
            target_selector: USER32_CS,
            ebx: 0x1000_0000,
            esi: 0x2000_0000,
            edi: 0x3000_0000,
            ebp: 0x4000_0000,
            esp: code_addr, // never dereferenced by this code; any valid value will do
            ..Default::default()
        };
        // SAFETY: as above.
        unsafe { enter(&mut ctx) };

        assert_eq!(ctx.out_ebx, 0x1000_0001, "EBX was not loaded, or not restored");
        assert_eq!(ctx.out_esi, 0x2000_0001, "ESI was not loaded, or not restored");
        assert_eq!(ctx.out_edi, 0x3000_0001, "EDI was not loaded, or not restored");
        assert_eq!(ctx.out_ebp, 0x4000_0001, "EBP was not loaded, or not restored");
    }

    /// The cache answers what the syscall answers -- on this thread and on a
    /// fresh one -- and keeps answering it, since [`enter`] restores exactly
    /// this value after every crossing.
    #[test]
    fn host_fs_base_matches_a_fresh_arch_prctl_read() {
        assert_eq!(host_fs_base(), fs_base(), "first read must come from the same place");
        assert_eq!(host_fs_base(), fs_base(), "the cached answer must not drift");
        std::thread::spawn(|| {
            let cached = host_fs_base();
            assert_ne!(cached, 0, "a glibc thread's FS_BASE is never 0");
            assert_eq!(cached, fs_base(), "another thread caches its own base, not this one's");
        })
        .join()
        .expect("the spawned thread's own assertions hold");
    }

    /// `wrfsbase` writes the same hidden base `arch_prctl(ARCH_SET_FS)`
    /// does: write the thread's own current base back through the
    /// instruction, then prove thread-local storage still works and the
    /// kernel reads the same value back. Exercises the exact instruction
    /// [`enter`]'s fast path uses, on the real CPU.
    #[test]
    fn wrfsbase_restore_round_trips_when_the_kernel_offers_it() {
        if !fsgsbase_enabled() {
            // Nothing to exercise: `enter` takes the syscall path here, which
            // the three crossing tests above already ran.
            return;
        }
        let before = fs_base();
        // A discriminating write: point the base somewhere else entirely and
        // make the KERNEL confirm it moved -- writing `before` back first
        // would pass even if the instruction silently did nothing. Between
        // the two writes nothing may touch thread-local state, so the
        // read-back is captured raw and asserted only after the restore.
        let scratch = [0u8; 64];
        let elsewhere = scratch.as_ptr() as u64;
        // SAFETY: `fsgsbase_enabled` just answered true; `elsewhere` is a
        // live local buffer this thread owns, and nothing dereferences
        // through FS before the restore two lines down.
        unsafe { write_fs_base(elsewhere) };
        let kernel_saw = fs_base();
        // SAFETY: as above; `before` is this same thread's own real base.
        unsafe { write_fs_base(before) };

        assert_eq!(kernel_saw, elsewhere, "the kernel must read back the base wrfsbase wrote");
        thread_local! {
            static ALIVE: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
        }
        ALIVE.with(|c| c.set(0xC0FFEE));
        assert_eq!(ALIVE.with(core::cell::Cell::get), 0xC0FFEE, "TLS must survive the round trip");
        assert_eq!(fs_base(), before, "the restore must land the original base");
    }
}
