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

    /// `AX` when the trampoline was reached: the thunk index.
    pub out_ax: u64,
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

    movq    {ax}(%r14), %rax            /* the call's return value, AX or DX:AX */
    movq    {dx}(%r14), %rdx
    movq    {si}(%r14), %rsi            /* and the callee-saved trio, which a */
    movq    {di}(%r14), %rdi            /* host call must leave untouched --  */
    movq    {bp}(%r14), %rbp            /* note %rdi arrived holding the Ctx  */
    movzwl  {ss16}(%r14), %ecx          /* the 16-bit stack selector */
    movq    {sp}(%r14), %rbx            /* SP, as a segment offset */

    movw    %cx, %ss                    /* paired with the next instruction: */
    movq    %rbx, %rsp                  /* MOV SS's shadow covers the gap */

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
    movq    %rax, {out_ax}(%r14)        /* the thunk index */
    movq    %rsp, {out_sp}(%r14)        /* SP: the call frame is just above */
    movw    %ss,  {out_ss}(%r14)
    movq    %rsi, {out_si}(%r14)        /* the callee-saved trio, to be handed */
    movq    %rdi, {out_di}(%r14)        /* back unchanged when the module is   */
    movq    %rbp, {out_bp}(%r14)        /* resumed                             */

    movw    %r13w, %ss
    movq    %r15, %rsp
    jmp     *%r11
mbbs16_tramp_end:
"#,
    out_ax = const offset_of!(Ctx, out_ax),
    out_sp = const offset_of!(Ctx, out_sp),
    out_ss = const offset_of!(Ctx, out_ss),
    out_si = const offset_of!(Ctx, out_si),
    out_di = const offset_of!(Ctx, out_di),
    out_bp = const offset_of!(Ctx, out_bp),
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
