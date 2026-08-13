//! The two pieces of assembly that cross between 64-bit and 16-bit code.
//!
//! Both are written as real assembly rather than hand-assembled byte arrays,
//! and both address [`Ctx`] through `const` operands rather than literal
//! displacements. That is deliberate: an encoding or an offset worked out by
//! hand is the mistake this project keeps making, and it is always silent --
//! a field written one byte late lands on its neighbour and nothing complains.
//! Deriving the numbers from the struct removes the possibility.
//!
//! Everything here follows the findings recorded in
//! `docs/plans/2026-08-03-16bit-module-execution.md`, measured in
//! <https://github.com/dcorbe/x86-compat16>.

use core::arch::global_asm;
use core::mem::offset_of;

/// State handed to [`mbbs16_enter`], and filled in by the trampoline on the way
/// back out.
#[repr(C)]
#[derive(Default)]
pub(crate) struct Ctx {
    /// Far pointer to enter through, in the `m16:32` form `ljmp` expects: a
    /// 32-bit offset immediately followed by a 16-bit selector. These two must
    /// stay adjacent and at the very front -- the jump reads them as one
    /// operand, straight off `%r14`.
    pub target_offset: u32,
    pub target_selector: u16,

    /// Selector of the module's 16-bit stack segment.
    pub ss16: u16,

    /// Stack pointer to enter with, as a **segment offset**, never a linear
    /// address. 16-bit mode consults only the low 16 bits and the descriptor
    /// supplies the base; a linear address here would work only when the
    /// segment happened to start on a 64 KiB boundary.
    pub sp: u64,

    /// Registers carrying a host call's return value back to the module. `AX`
    /// alone for an `int`; `DX:AX` for a `long` or a far pointer, high half in
    /// `DX`.
    pub ax: u64,
    pub dx: u64,

    /// Registers Borland's cdecl treats as **callee-saved**, restored on entry
    /// so that a host call is transparent to the module.
    ///
    /// Getting this wrong is quiet and awful: the module keeps running, with a
    /// value it stored before the call silently replaced. `DI` is the easiest
    /// to lose, because `mbbs16_enter` is handed its `Ctx` in `%rdi`.
    pub si: u64,
    pub di: u64,
    pub bp: u64,

    /// The module's data segment -- Borland's `DGROUP`, where its globals live.
    /// Also callee-saved: a shim must hand back the `DS` the module had.
    pub ds: u64,

    /// `BX` and `CX` as the module had them at the call, handed straight back.
    ///
    /// cdecl makes both scratch, so no compiled *cdecl* caller depends on them
    /// -- but not everything a module imports from this host is one. Borland's
    /// runtime helpers have clobber sets its code generator knows and works
    /// around: `F_SCOPY@` was `rep movsb`, which destroys `CX`, `SI` and `DI`
    /// and leaves `BX` alone, so a caller may hold a live value in `BX` across
    /// it.
    ///
    /// These two must be loaded *after* `SS` and `SP`, because the entry
    /// sequence uses `%rcx` and `%rbx` as the scratch that gets those there.
    pub bx: u64,
    pub cx: u64,

    /// `AX` when the trampoline was reached: a thunk index on the way in, or a
    /// module's return value on the way out.
    pub out_ax: u64,
    /// `DX` alongside it, for a `long` or far pointer returned by the module.
    pub out_dx: u64,
    /// `BX` at the same instant. Unlike `AX` and `CX` no thunk destroys it, so
    /// recording it here costs one instruction and nothing else. Borland's
    /// `F_LXMUL@` takes half of one operand in it.
    pub out_bx: u64,
    /// `CX`, which every thunk sets to say which kind it is. Distinguishing the
    /// two this way keeps `AX` free to carry a return value.
    pub out_cx: u64,
    /// `SP` at the same instant, still a segment offset.
    pub out_sp: u64,
    /// `SS` at the same instant. Only 16 bits are written, so the field is
    /// zeroed before every entry.
    pub out_ss: u64,
    /// The callee-saved trio as the module left them, to be fed back in on the
    /// next entry.
    pub out_si: u64,
    pub out_di: u64,
    pub out_bp: u64,
    pub out_ds: u64,

    /// Nonzero once a watchdog tick has been recorded against this module,
    /// whether or not it was in 16-bit mode at the time. The assembly never
    /// touches it: the signal handler sets it and
    /// [`crate::m16::watchdog::Watched::arm`] clears it, so it survives the crossings
    /// in between and outlives the excursion a tick may have interrupted.
    ///
    /// Separate from `out_signo` because that one is cleared before every entry,
    /// and a tick that arrives while the host is servicing an import must not be
    /// wiped out by the next crossing it triggers.
    pub expired: u64,
    /// Set by the signal handler when a module dies or is stopped in 16-bit
    /// mode, and by nothing else. Zero means the excursion ended by reaching the
    /// trampoline.
    pub out_signo: u64,
    /// Where 16-bit execution stopped, recorded before the handler overwrites
    /// the interrupted context. `CS` is the module's code selector and `IP` is
    /// an offset within it, because that is what the CPU pushed. Meaningless
    /// unless `out_signo` is nonzero.
    pub out_cs: u64,
    pub out_ip: u64,
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

// The outbound half. This lives in the ordinary text segment and may sit
// anywhere in the address space: the jump is the indirect `m16:32` form, so
// only its *target* is confined to the low 4 GiB.
//
// R11, R13, R14 and R15 carry state across the excursion. Compatibility mode
// has no encoding that names r8-r15, which is precisely what makes them safe
// there -- and is why they must all be loaded before the jump, since after it
// there is no way to reach them.
global_asm!(
    r#"
.globl mbbs16_enter
.hidden mbbs16_enter
.p2align 4
mbbs16_enter:
    pushq   %rbp
    pushq   %rbx
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15

    movq    %rdi, %r14                  /* the Ctx */
    leaq    1f(%rip), %r11              /* where the trampoline sends us back */
    xorl    %r13d, %r13d
    movw    %ss, %r13w                  /* the host's SS, for the trampoline */
    movq    %rsp, %r15                  /* and the host's RSP */

    movw    %ds, %r12w                  /* the host's DS, for the way back */
    movzwl  {ds}(%r14), %ecx            /* and the module's, which its globals */
    movw    %cx, %ds                    /* are addressed through */

    movq    {ax}(%r14), %rax            /* the call's return value, AX or DX:AX */
    movq    {dx}(%r14), %rdx
    movq    {si}(%r14), %rsi            /* and the callee-saved trio, which a */
    movq    {di}(%r14), %rdi            /* host call must leave untouched --  */
    movq    {bp}(%r14), %rbp            /* note %rdi arrived holding the Ctx  */
    movzwl  {ss16}(%r14), %ecx          /* the 16-bit stack selector */
    movq    {sp}(%r14), %rbx            /* SP, as a segment offset */

    movw    %cx, %ss                    /* paired with the next instruction: */
    movq    %rbx, %rsp                  /* MOV SS's shadow covers the gap */

    movq    {bx}(%r14), %rbx            /* BX and CX as the module had them,  */
    movq    {cx}(%r14), %rcx            /* now the two are done being scratch */

    ljmpl   *(%r14)                     /* into 16-bit mode */
1:
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp
    retq
"#,
    ax = const offset_of!(Ctx, ax),
    bx = const offset_of!(Ctx, bx),
    cx = const offset_of!(Ctx, cx),
    ds = const offset_of!(Ctx, ds),
    dx = const offset_of!(Ctx, dx),
    si = const offset_of!(Ctx, si),
    di = const offset_of!(Ctx, di),
    bp = const offset_of!(Ctx, bp),
    ss16 = const offset_of!(Ctx, ss16),
    sp = const offset_of!(Ctx, sp),
    options(att_syntax)
);

// The inbound half, and the only code here that must live below 4 GiB: a
// 16-bit far jump can name a 32-bit offset and no more. It is therefore copied
// into the module's low mapping at run time rather than called where it sits,
// which is why it touches nothing but registers and displacements off %r14 --
// it has to run correctly from an address it was not linked for.
//
// SS is restored before RSP. MOV SS inhibits interrupts for exactly one
// instruction, so the pair executes with no window in which a signal could
// arrive to find a 64-bit SS beside a 16-bit stack pointer.
global_asm!(
    r#"
.globl mbbs16_tramp_start, mbbs16_tramp_end
.hidden mbbs16_tramp_start, mbbs16_tramp_end
.p2align 4
mbbs16_tramp_start:
    movq    %rax, {out_ax}(%r14)        /* a thunk index, or a return value */
    movq    %rdx, {out_dx}(%r14)
    movq    %rbx, {out_bx}(%r14)        /* an operand of a runtime helper */
    movq    %rcx, {out_cx}(%r14)        /* which kind of thunk we came through */
    movq    %rsp, {out_sp}(%r14)        /* SP: the call frame is just above */
    movw    %ss,  {out_ss}(%r14)
    movq    %rsi, {out_si}(%r14)        /* the callee-saved trio, to be handed */
    movq    %rdi, {out_di}(%r14)        /* back unchanged when the module is   */
    movq    %rbp, {out_bp}(%r14)        /* resumed                             */
    movw    %ds,  {out_ds}(%r14)        /* including DS, which the module may  */
    movw    %r12w, %ds                  /* have moved; then the host's back    */

    movw    %r13w, %ss
    movq    %r15, %rsp
    jmp     *%r11
mbbs16_tramp_end:
"#,
    out_ax = const offset_of!(Ctx, out_ax),
    out_dx = const offset_of!(Ctx, out_dx),
    out_bx = const offset_of!(Ctx, out_bx),
    out_cx = const offset_of!(Ctx, out_cx),
    out_sp = const offset_of!(Ctx, out_sp),
    out_ss = const offset_of!(Ctx, out_ss),
    out_si = const offset_of!(Ctx, out_si),
    out_di = const offset_of!(Ctx, out_di),
    out_bp = const offset_of!(Ctx, out_bp),
    out_ds = const offset_of!(Ctx, out_ds),
    options(att_syntax)
);

unsafe extern "C" {
    /// Enter 16-bit mode through `ctx`, returning when the trampoline is
    /// reached. See the assembly above.
    pub(crate) fn mbbs16_enter(ctx: *mut Ctx);

    static mbbs16_tramp_start: u8;
    static mbbs16_tramp_end: u8;
}

/// The trampoline's bytes, for copying into a mapping below 4 GiB.
pub(crate) fn trampoline() -> &'static [u8] {
    // SAFETY: both symbols bracket a contiguous run of instructions emitted by
    // the assembler in one `global_asm!` block, so the range is valid and the
    // end is never before the start.
    unsafe {
        let start = &raw const mbbs16_tramp_start;
        let end = &raw const mbbs16_tramp_end;
        let len = end.offset_from_unsigned(start);
        core::slice::from_raw_parts(start, len)
    }
}
