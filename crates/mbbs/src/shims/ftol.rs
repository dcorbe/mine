//! `cw3220mt.DLL!__ftol` -- Borland C++ 5.x's 32-bit float-to-long helper.
//!
//! The 32-bit sibling of `shims::runtime`'s `f_ldiv@` family: not
//! Worldgroup module logic at all, but Borland compiler runtime `LUNATIX.DLL`
//! links against because it does floating-point arithmetic somewhere in its
//! own code, same as `re/wg33src`'s two 16-bit modules needed a 32-bit
//! `long` divide the 8086 has no instruction for.
//!
//! # The calling convention, measured rather than assumed
//!
//! Disassembling every one of `LUNATIX.DLL`'s 13 call sites to this import
//! (`objdump -d -M intel`, resolving the IAT thunk at RVA `0x3627c` to the
//! `jmp DWORD PTR ds:0x43627c` stub at `0x41d838`, then every `call
//! 0x41d838`) shows the same shape at all 13:
//!
//! ```text
//! 40bc33: fild  dword ptr [...]
//! 40bc39: fmul  dword ptr [...]     ; leaves the value to convert on ST0
//! 40bc3f: call  0x41d838           ; -> __ftol
//! 40bc44: mov   [...], eax          ; the result, EAX alone -- EDX untouched
//! ```
//!
//! Every site is `fld`/`fild`/`fmul` immediately before the call (never a
//! stack argument -- `__ftol` takes nothing on the cdecl frame) and `mov
//! ds:[...], eax` immediately after (never `edx`). That is the classic
//! Borland/MSVC `__ftol`: pop `ST0`, convert to a signed 32-bit integer
//! truncating toward zero, answer in `EAX` alone. Nothing here needs the
//! 64-bit `EDX:EAX` variant some Borland runtimes also export under a
//! different name.
//!
//! **LunatiX does call this, 13 times measured, not merely link against
//! it.** Contrast `WGSERVER.EXE!dfsthn`, pinned in
//! `crates/mbbs/tests/lunatix.rs` as "almost certainly never called" --
//! `__ftol` is the opposite case: real, exercised boilerplate.
//!
//! # Why this is `Call<Wg32>`/`Host<Wg32>`, not generic over `Abi`
//!
//! Every other symbol in this crate's "eager boilerplate" pile
//! (`shims::borland`) is generic over `<A: Abi>` because its body touches
//! nothing ABI-specific -- `abort`, `startup` and the two KERNEL32 stubs all
//! answer the same way regardless of `A`. This one cannot be: its answer
//! comes off the x87 FPU stack the module's own preceding `fld` left a value
//! on, which [`mbbs_machine::m32::Machine::take_st0`] reads out of a capture
//! only that concrete machine performs (see that method and
//! [`mbbs_machine::m32::Machine::arm_st0_capture`]'s own doc comments for why
//! the read has to happen inside the 32-bit thunk, before any 64-bit host
//! code -- Rust included -- gets a chance to disturb `ST0`). `Abi` has no
//! generic accessor for it, and adding one is out of this file's scope. The
//! precedent for an ABI-concrete entry in this same shim table already
//! exists on the 16-bit side: `shims::runtime::f_ldiv` and its Borland
//! `F_L*@` siblings are `Call<Wg16>`/`Host<Wg16>` for the identical reason --
//! compiler runtime, not module logic, tied to one ABI's own machine.
//!
//! # What is deliberately not replicated
//!
//! The real `__ftol` temporarily forces the FPU control word to
//! truncate-toward-zero before its `fistp`, then restores it -- needed
//! because the *default* x87 rounding mode is round-to-nearest, not C's
//! truncation. [`ftol_convert`] does not touch any control word: it converts
//! the already-captured `f64` with Rust's own `as i32`, which truncates
//! toward zero unconditionally, so the outcome matches for every value in
//! `i32`'s range without needing the control-word dance at all. Where it
//! knowingly diverges is out of range: real hardware answers the "integer
//! indefinite" pattern (`0x8000_0000`) for a `NaN` or an out-of-range value,
//! masked-exception style; Rust's cast saturates toward whichever bound the
//! value overshot, and a `NaN` becomes `0`. None of the 13 measured call
//! sites come remotely close to `i32`'s range -- every one feeds a small
//! scaling/percentage constant -- so this divergence is not reachable by
//! anything this host has measured LunatiX doing, but it is real and worth
//! stating rather than leaving implicit.

use crate::Host;
use crate::abi::{self, Call, Wg32};
use crate::shims::ShimError;

/// Truncate `value` toward zero into a signed 32-bit integer, the way a C
/// `(long)` cast -- and therefore a real `__ftol` -- does for every value
/// this host has measured a module actually converting.
///
/// See this module's own doc comment, "What is deliberately not
/// replicated", for the one place this and real hardware disagree (`NaN`
/// and out-of-range magnitudes) and why it does not matter for `LUNATIX.DLL`.
fn ftol_convert(value: f64) -> i32 {
    value as i32
}

/// `long __ftol(void)` -- reads its one argument off `ST0`, which
/// [`arm_st0_capture`](mbbs_machine::m32::Machine::arm_st0_capture) must have
/// been wired to capture for this import's thunk slot before the module
/// could ever reach it (see this module's own doc comment). Answers in
/// [`abi::Ret::Long`], matching the measured `EAX`-alone convention.
///
/// # Panics
///
/// Via [`mbbs_machine::m32::Machine::take_st0`], if the loader never called
/// `arm_st0_capture` for the slot `cw3220mt.DLL!__ftol` was bound to -- a
/// wiring gap this host refuses to paper over with a plausible-looking
/// `0.0`. See that method's own doc comment.
pub fn ftol(call: &mut Call<Wg32>, _host: &mut Host<Wg32>) -> Result<abi::Ret<Wg32>, ShimError> {
    let value = call.cpu.machine.take_st0();
    Ok(abi::Ret::Long(ftol_convert(value) as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_toward_zero_like_a_c_long_cast() {
        assert_eq!(ftol_convert(2.9), 2);
        assert_eq!(ftol_convert(2.1), 2);
        assert_eq!(ftol_convert(-2.9), -2);
        assert_eq!(ftol_convert(-2.1), -2);
        assert_eq!(ftol_convert(0.0), 0);
        assert_eq!(ftol_convert(-0.0), 0);
    }

    /// The magnitudes actually measured at `LUNATIX.DLL`'s 13 call sites:
    /// small scaling/percentage constants, well inside `i32` and exactly
    /// representable in `f64` -- so exact equality, not an epsilon
    /// comparison, is the right assertion here.
    #[test]
    fn handles_the_magnitudes_lunatix_actually_multiplies_by() {
        assert_eq!(ftol_convert(100.0 * 1.5), 150);
        assert_eq!(ftol_convert(65535.0 * 0.999_f64), 65469);
    }

    /// Documents the one divergence from real hardware -- see this module's
    /// own doc comment, "What is deliberately not replicated". Not a
    /// correctness requirement LunatiX exercises; a record that the
    /// difference is known, not accidental.
    #[test]
    fn out_of_range_and_nan_saturate_rather_than_answer_the_fpu_s_indefinite_pattern() {
        assert_eq!(ftol_convert(f64::NAN), 0);
        assert_eq!(ftol_convert(1e30), i32::MAX);
        assert_eq!(ftol_convert(-1e30), i32::MIN);
    }
}
