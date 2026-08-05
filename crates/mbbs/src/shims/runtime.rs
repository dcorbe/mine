//! The compiler's runtime, which the host happens to export.
//!
//! These are not MajorBBS routines. `f_lumod@` and its family are **Borland's**
//! 32-bit arithmetic helpers: the 8086 has no 32-bit divide, so a C compiler
//! targeting it emits a call for every `/` and `%` on a `long`. On this platform
//! that runtime was linked into `MAJORBBS.DLL`, so a module imports `%` from the
//! host exactly as it imports `opnbtv`, and a host that runs modules has to
//! provide it.
//!
//! The `@` is Borland's marker for a runtime helper and the `f_` prefix is its
//! far-call form. `WCCMMUD.DLL` imports eight of them across 290 call sites.
//!
//! # These four pop their own arguments
//!
//! Four words go on the stack, and there is no `add sp` after the call -- the
//! helper takes them with it. That is why the shim table has a
//! [`Cleans`](crate::shims::Cleans) column, and these are the entries that need
//! it. The others in the family do not share this shape: `F_LXMUL@`, `F_LXLSH@`
//! and `F_LXURSH@` pass everything in registers and touch the stack not at all.
//!
//! # The dividend is the argument nearest the frame
//!
//! Plain cdecl order for `f(dividend, divisor)`, which is worth stating because
//! getting it backwards produces plausible numbers rather than errors. It was
//! read off the disassembly -- across `F_LDIV@`, `F_LUDIV@` and `F_LMOD@` the
//! literal operand is always the *first* pushed, so `param / 2` and `local / 100`
//! rather than the reverse -- and then confirmed against the running module,
//! which asks `f_lumod@` for `x % 2000` four times with a different `x` each
//! time.

use mbbs16::{Machine, Ret};

use crate::Host;
use crate::shims::ShimError;

/// How many bytes of argument these helpers pop. Two `long`s.
pub const OPERANDS: u16 = 8;

/// The two operands of the outstanding call, as the module pushed them.
fn operands(machine: &Machine) -> (u32, u32) {
    (machine.arg_u32(0), machine.arg_u32(2))
}

/// What the real helper did instead of returning: `div` by zero is `INT 0`, and
/// on a DOS box that is the end of the process.
///
/// There is nothing to return here. Zero would not be a wrong answer so much as
/// a claim that the arithmetic happened.
fn by_zero(name: &str, dividend: u32) -> ShimError {
    ShimError::Failed(format!(
        "{name}({dividend}, 0): division by zero, which on the real machine was INT 0"
    ))
}

/// `long f_ldiv@(long dividend, long divisor)` -- signed 32-bit division.
///
/// # Errors
///
/// If the divisor is zero, or if the result does not fit in a `long` -- which
/// happens for exactly one pair of operands. `idiv` faults on both.
pub fn f_ldiv(machine: &mut Machine, _host: &mut Host) -> Result<Ret, ShimError> {
    let (dividend, divisor) = operands(machine);
    let (a, b) = (dividend as i32, divisor as i32);
    if b == 0 {
        return Err(by_zero("f_ldiv@", dividend));
    }
    a.checked_div(b)
        .map(|v| Ret::U32(v as u32))
        .ok_or_else(|| overflow("f_ldiv@", a, b))
}

/// `long f_lmod@(long dividend, long divisor)` -- signed 32-bit remainder.
///
/// The sign follows the dividend, because `idiv` truncates toward zero and Rust
/// does the same. `-7 % 2` is `-1`.
///
/// # Errors
///
/// As [`f_ldiv`].
pub fn f_lmod(machine: &mut Machine, _host: &mut Host) -> Result<Ret, ShimError> {
    let (dividend, divisor) = operands(machine);
    let (a, b) = (dividend as i32, divisor as i32);
    if b == 0 {
        return Err(by_zero("f_lmod@", dividend));
    }
    a.checked_rem(b)
        .map(|v| Ret::U32(v as u32))
        .ok_or_else(|| overflow("f_lmod@", a, b))
}

/// `unsigned long f_ludiv@(unsigned long, unsigned long)` -- unsigned division.
///
/// # Errors
///
/// If the divisor is zero. Unsigned division cannot overflow.
pub fn f_ludiv(machine: &mut Machine, _host: &mut Host) -> Result<Ret, ShimError> {
    let (dividend, divisor) = operands(machine);
    match dividend.checked_div(divisor) {
        Some(v) => Ok(Ret::U32(v)),
        None => Err(by_zero("f_ludiv@", dividend)),
    }
}

/// `unsigned long f_lumod@(unsigned long, unsigned long)` -- unsigned remainder.
///
/// The one of the four initialisation actually reaches, and it asks for
/// `x % 2000` four times.
///
/// # Errors
///
/// If the divisor is zero. Unsigned remainder cannot overflow.
pub fn f_lumod(machine: &mut Machine, _host: &mut Host) -> Result<Ret, ShimError> {
    let (dividend, divisor) = operands(machine);
    match dividend.checked_rem(divisor) {
        Some(v) => Ok(Ret::U32(v)),
        None => Err(by_zero("f_lumod@", dividend)),
    }
}

/// The single signed pair that has no answer: `i32::MIN / -1`.
fn overflow(name: &str, a: i32, b: i32) -> ShimError {
    ShimError::Failed(format!("{name}({a}, {b}): the result does not fit in a long"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;

    /// Push a dividend and a divisor the way the module does, and run `shim`.
    fn div(shim: crate::shims::Shim, dividend: u32, divisor: u32) -> Result<Ret, ShimError> {
        let mut f = Fixture::new();
        let args = [
            dividend as u16,
            (dividend >> 16) as u16,
            divisor as u16,
            (divisor >> 16) as u16,
        ];
        f.invoke(shim, &args)
    }

    #[test]
    fn the_dividend_is_the_argument_nearest_the_frame() {
        // Measured against the module: initialisation asks `f_lumod@` for
        // 2189 % 2000, four times over with a different dividend each time and
        // 2000 every time. Reading the pair the other way round would answer
        // 2000 % 2189 = 2000, which is also a number.
        assert_eq!(div(f_lumod, 2189, 2000).unwrap(), Ret::U32(189));
        assert_eq!(div(f_lumod, 376, 2000).unwrap(), Ret::U32(376));
        assert_eq!(div(f_lumod, 2140, 2000).unwrap(), Ret::U32(140));
        assert_eq!(div(f_lumod, 142, 2000).unwrap(), Ret::U32(142));
    }

    #[test]
    fn unsigned_and_signed_are_different_routines_for_a_reason() {
        // The one bit pattern that tells them apart. As unsigned this is
        // 4,294,967,295; as signed it is -1.
        assert_eq!(div(f_ludiv, 0xffff_ffff, 10).unwrap(), Ret::U32(429496729));
        assert_eq!(div(f_lumod, 0xffff_ffff, 10).unwrap(), Ret::U32(5));

        assert_eq!(div(f_ldiv, -1i32 as u32, 10).unwrap(), Ret::U32(0));
        assert_eq!(div(f_lmod, -1i32 as u32, 10).unwrap(), Ret::U32(-1i32 as u32));
    }

    #[test]
    fn signed_division_truncates_toward_zero_as_the_instruction_does() {
        // `idiv` truncates toward zero, so -7/2 is -3 and not -4, and the
        // remainder takes the sign of the dividend. Rust's `/` and `%` agree,
        // which is why this is an assertion rather than an implementation.
        assert_eq!(div(f_ldiv, -7i32 as u32, 2).unwrap(), Ret::U32(-3i32 as u32));
        assert_eq!(div(f_lmod, -7i32 as u32, 2).unwrap(), Ret::U32(-1i32 as u32));
        assert_eq!(div(f_ldiv, 7, -2i32 as u32).unwrap(), Ret::U32(-3i32 as u32));
        assert_eq!(div(f_lmod, 7, -2i32 as u32).unwrap(), Ret::U32(1));
    }

    #[test]
    fn dividing_by_zero_stops_the_module_rather_than_answering() {
        // On the real machine this is `INT 0` and the process dies. There is no
        // value to return: zero would be a lie about arithmetic itself.
        for shim in [f_ldiv, f_lmod, f_ludiv, f_lumod] {
            let e = div(shim, 1, 0).expect_err("refused");
            assert!(format!("{e}").contains("zero"), "{e}");
        }
    }

    #[test]
    fn the_one_signed_division_that_does_not_fit_is_refused_too() {
        // -2147483648 / -1 is 2147483648, which is not an i32. `idiv` faults.
        let e = div(f_ldiv, i32::MIN as u32, -1i32 as u32).expect_err("refused");
        assert!(format!("{e}").contains("does not fit"), "{e}");
        let e = div(f_lmod, i32::MIN as u32, -1i32 as u32).expect_err("refused");
        assert!(format!("{e}").contains("does not fit"), "{e}");
    }
}
