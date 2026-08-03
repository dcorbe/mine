//! The two pieces of assembly that cross between 64-bit and 16-bit code.
//!
//! Both are written as real assembly rather than hand-assembled byte arrays.
//! The encodings involved are easy to get subtly wrong -- an off-by-one in a
//! patch offset silently overwrites the following instruction -- and the
//! assembler does not make that mistake.
//!
//! Everything here follows the findings recorded in
//! `docs/plans/2026-08-03-16bit-module-execution.md`, measured in
//! <https://github.com/dcorbe/x86-compat16>.

use core::arch::global_asm;

/// State handed to [`mbbs16_enter`], and filled in by the trampoline on the way
/// back out.
///
/// The offsets are load-bearing: both assembly stubs address these fields by
/// displacement off `%r14`. [`Ctx::ASSERT_LAYOUT`] fails the build if they
/// drift.
#[repr(C)]
#[derive(Default)]
pub(crate) struct Ctx {
    /// Far pointer to enter through, in the `m16:32` form `ljmp` expects: a
    /// 32-bit offset immediately followed by a 16-bit selector.
    pub target_offset: u32,
    pub target_selector: u16,

    /// Selector of the module's 16-bit stack segment.
    pub ss16: u16,

    /// Stack pointer to enter with, as a **segment offset**, never a linear
    /// address. 16-bit mode consults only the low 16 bits and the descriptor
    /// supplies the base; a linear address here would work only when the
    /// segment happened to start on a 64 KiB boundary.
    pub sp: u64,

    /// Value to present in `AX` on entry -- a host call's return value.
    pub ax: u64,

    /// `AX` when the trampoline was reached: the thunk index.
    pub out_ax: u64,
    /// `SP` at the same instant, still a segment offset.
    pub out_sp: u64,
    /// `SS` at the same instant. Only 16 bits are written, so the field is
    /// zeroed before every entry.
    pub out_ss: u64,
    /// `SI`, which Borland's cdecl treats as callee-saved and modules use for
    /// values that outlive a call.
    pub out_si: u64,
}

impl Ctx {
    /// Compile-time check that the field offsets the assembly hardcodes still
    /// match the struct. Referenced from [`super::Machine::enter`] so it is
    /// actually evaluated.
    pub const ASSERT_LAYOUT: () = {
        assert!(core::mem::offset_of!(Ctx, target_offset) == 0x00);
        assert!(core::mem::offset_of!(Ctx, target_selector) == 0x04);
        assert!(core::mem::offset_of!(Ctx, ss16) == 0x06);
        assert!(core::mem::offset_of!(Ctx, sp) == 0x08);
        assert!(core::mem::offset_of!(Ctx, ax) == 0x10);
        assert!(core::mem::offset_of!(Ctx, out_ax) == 0x18);
        assert!(core::mem::offset_of!(Ctx, out_sp) == 0x20);
        assert!(core::mem::offset_of!(Ctx, out_ss) == 0x28);
        assert!(core::mem::offset_of!(Ctx, out_si) == 0x30);
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

    movq    0x10(%r14), %rax            /* AX to present to 16-bit code */
    movzwl  0x06(%r14), %ecx            /* the 16-bit stack selector */
    movq    0x08(%r14), %rbx            /* SP, as a segment offset */

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
    movq    %rax, 0x18(%r14)            /* the thunk index */
    movq    %rsp, 0x20(%r14)            /* SP: the call frame is just above */
    movw    %ss,  0x28(%r14)
    movq    %rsi, 0x30(%r14)

    movw    %r13w, %ss
    movq    %r15, %rsp
    jmp     *%r11
mbbs16_tramp_end:
"#,
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
