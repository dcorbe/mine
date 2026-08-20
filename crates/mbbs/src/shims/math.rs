//! `cw3220mt.DLL`'s ISO C floating-point routines: `sqrt`, `pow`, `sin`,
//! `atan`, `atan2` -- and `modf`, which is not registered anywhere (see its
//! own doc comment).
//!
//! # Why these were unimplementable until now
//!
//! Every one of these is `double`-returning, and a `double`-returning cdecl
//! function leaves its result on the x87 FPU stack, in `ST(0)` -- not in
//! `EAX`/`EDX:EAX`, the only places a host call could hand a value back
//! before this file. `mbbs_machine::m32::Ret` had `Void`/`U32`/`U64` and
//! nothing wider; `crates/mbbs/src/abi.rs`'s own `Ret<A>` mirrored that
//! exactly. See [`abi::Ret::F64`] and
//! [`mbbs_machine::m32::Machine::arm_st0_return`] for the primitive that
//! closes the gap, and this crate's history (`shims::ftol`) for the
//! *argument*-side half of the same asymmetry, closed first because
//! `__ftol` needed it to boot `LUNATIX.DLL` at all.
//!
//! # Why this is `Call<Wg32>`/`Host<Wg32>`, not generic over `Abi`
//!
//! Same reasoning as `shims::ftol`'s own module doc comment: [`abi::Ret::F64`]
//! can only be honestly constructed for `Wg32` (see that variant's own doc
//! comment), and `CW3220MT` -- the library every routine here is measured
//! importing from -- is itself Wg32-exclusive
//! (`crates/mbbs-machine/src/library.rs`'s `CW3220MT` entry: "Borland's
//! 32-bit C runtime, which a Worldgroup NT module links"). A generic `<A:
//! Abi>` signature would let these compile against `Wg16` and then panic at
//! the `Ret::F64` boundary the first time one actually ran there -- a
//! reachable footgun this crate's own precedent (`ftol`, `runtime::f_ldiv`
//! and its Borland `F_L*@` siblings) already avoids by being ABI-concrete
//! wherever the body is.
//!
//! # Evidence
//!
//! **The import spellings are measured, not assumed.**
//! `re/isv_union_pe_symbols.tsv` is this repository's own union of every PE32
//! import table its 32-bit module corpus has ever recovered (`library`,
//! `ordinal_or_name`, `modules`, `count`). It lists, under `CW3220MT`:
//! `_sqrt` (4 modules, 4 references, line 171), `_pow` (2, 2, line 299),
//! `_sin` (2, 2, line 300), `_atan2` (1, 1, line 623) and `_atan` (1, 1, line
//! 654). No `modf`/`_modf` row exists anywhere in that file -- see
//! [`modf`]'s own doc comment for what that absence means for this crate's
//! evidence rules.
//!
//! **The behaviour is Evidence::Standard**, not measured: ISO C (C99 §7.12,
//! which Borland's own runtime documents itself as implementing) defines
//! `sqrt`, `pow`, `sin`, `atan` and `atan2`'s domains and results, and
//! Rust's own `f64` methods of the same names implement the identical IEEE
//! 754 operations -- `f64::sqrt`/`powf`/`sin`/`atan`/`atan2` are not
//! reimplementations of anything Borland-specific, they are the same
//! hardware operation (`SQRTSD`/a polynomial `sin`/etc.) any C runtime on
//! this hardware would also produce. Where the two could plausibly diverge
//! -- `NaN`/infinity edge cases -- both ISO C and Rust's docs agree with
//! IEEE 754, so there is no divergence to record the way `shims::ftol`'s own
//! doc comment records one for `__ftol`.

use mbbs_machine::ptr::ModulePtr;

use crate::Host;
use crate::abi::{self, Call, Wg32};
use crate::shims::ShimError;

// Every routine below is a thin `Call`-reading wrapper around a small `_value`
// function. That split exists for one reason: a routine that inlined
// `x.sqrt()` directly has nothing for `#[cfg(test)]` to call without a real
// `Call<Wg32>` (built only from a live `Wg32Cpu`, kept out of this crate's
// `--lib` tests -- see this module's own doc comment on why
// `crates/mbbs/tests/wg32_math_st0.rs` is a separate process). An earlier
// version of this file's tests asserted things like `1.0_f64.atan2(0.0) ==
// FRAC_PI_2` -- true, and provable no matter what `pub fn atan2` below
// actually does with its two arguments, because nothing called it. Splitting
// out `atan2_value(y, x)` and testing *that* is what lets a swapped argument
// order fail a named test instead of nothing at all -- caught by mutation
// testing during this file's own review; see the handoff report.

/// `double sqrt(double x)`. `NaN` for `x < 0.0`, matching C's documented
/// domain-error behaviour rather than raising one -- Rust has no
/// signalling-NaN distinction to raise through here, and neither does the
/// masked-exception x87 hardware Borland's own runtime runs on.
fn sqrt_value(x: f64) -> f64 {
    x.sqrt()
}

/// `double pow(double x, double y)`. `f64::powf`, not `f64::powi`: `y` is a
/// `double` argument here, not a C `int`, and `powf` is what ISO C's own
/// `pow` signature calls for.
fn pow_value(x: f64, y: f64) -> f64 {
    x.powf(y)
}

/// `double sin(double x)`, radians -- ISO C's own units, and Rust's `f64::sin`
/// agrees.
fn sin_value(x: f64) -> f64 {
    x.sin()
}

/// `double atan(double x)`, answering in radians on `(-pi/2, pi/2)`.
fn atan_value(x: f64) -> f64 {
    x.atan()
}

/// `double atan2(double y, double x)` -- **`y` first**, ISO C's own declared
/// parameter order and `f64::atan2`'s (`y.atan2(x)`), not the `(x, y)` order
/// a reader might guess from the plain `atan`'s single argument.
fn atan2_value(y: f64, x: f64) -> f64 {
    y.atan2(x)
}

/// `double modf(double value, double *iptr)` -- `(integral, fractional)`,
/// both keeping `value`'s own sign per ISO C (Rust's `trunc`/`fract` already
/// agree, unlike a naive `as i64 as f64` cast, which would not reproduce a
/// signed zero fractional part).
fn modf_value(value: f64) -> (f64, f64) {
    (value.trunc(), value.fract())
}

/// `double sqrt(double x)`.
///
/// # Errors
///
/// Never fails -- see [`sqrt_value`].
pub fn sqrt(call: &mut Call<Wg32>, _host: &mut Host<Wg32>) -> Result<abi::Ret<Wg32>, ShimError> {
    let x = call.double();
    Ok(abi::Ret::F64(sqrt_value(x)))
}

/// `double pow(double x, double y)`. See [`pow_value`].
pub fn pow(call: &mut Call<Wg32>, _host: &mut Host<Wg32>) -> Result<abi::Ret<Wg32>, ShimError> {
    let x = call.double();
    let y = call.double();
    Ok(abi::Ret::F64(pow_value(x, y)))
}

/// `double sin(double x)`. See [`sin_value`].
pub fn sin(call: &mut Call<Wg32>, _host: &mut Host<Wg32>) -> Result<abi::Ret<Wg32>, ShimError> {
    let x = call.double();
    Ok(abi::Ret::F64(sin_value(x)))
}

/// `double atan(double x)`. See [`atan_value`].
pub fn atan(call: &mut Call<Wg32>, _host: &mut Host<Wg32>) -> Result<abi::Ret<Wg32>, ShimError> {
    let x = call.double();
    Ok(abi::Ret::F64(atan_value(x)))
}

/// `double atan2(double y, double x)`. `Call::double()` reads arguments in
/// declaration order, the same convention every other multi-argument shim in
/// this crate already follows (see e.g. `shims::credits::otstcrd`), so this
/// reads `y` before `x` because the C prototype declares `y` before `x`. See
/// [`atan2_value`].
pub fn atan2(call: &mut Call<Wg32>, _host: &mut Host<Wg32>) -> Result<abi::Ret<Wg32>, ShimError> {
    let y = call.double();
    let x = call.double();
    Ok(abi::Ret::F64(atan2_value(y, x)))
}

/// `double modf(double value, double *iptr)` -- splits `value` into integral
/// and fractional parts, writing the integral part through `iptr` and
/// returning the fractional part. See [`modf_value`].
///
/// **Not registered in `shims::mod`'s tables, and this crate's own convention
/// -- state the reason rather than leave the omission silent.**
/// `re/isv_union_pe_symbols.tsv` (this module's own doc comment) has no
/// `modf`/`_modf` row at all: unlike `sqrt`/`pow`/`sin`/`atan`/`atan2`, no
/// 32-bit module in this repository's recovered corpus has ever been
/// measured importing it. Implementing it anyway proves the `Ret::F64`
/// primitive also serves a routine that writes to module memory *and*
/// returns through `ST0` in the same call -- a shape none of the other five
/// exercise -- but registering an unmeasured symbol spelling under a guessed
/// name would be exactly the "plausible answer with no witness" this crate's
/// `Evidence` enum exists to make impossible to land silently. If a module
/// is ever measured importing this, the real PE import spelling (almost
/// certainly `_modf`, following every other row's single-leading-underscore
/// pattern) needs to be confirmed against it before this is wired into
/// [`crate::shims::entry`], not assumed from this comment.
///
/// # Errors
///
/// If the write through `iptr` fails -- out of bounds, or past the end of
/// the module's own image/arena/stack.
pub fn modf(call: &mut Call<Wg32>, _host: &mut Host<Wg32>) -> Result<abi::Ret<Wg32>, ShimError> {
    let value = call.double();
    let iptr = call.ptr();
    let (integral, fractional) = modf_value(value);
    iptr.write(call.mem(), &integral.to_le_bytes())
        .map_err(|e| ShimError::Failed(format!("modf: {e}")))?;
    Ok(abi::Ret::F64(fractional))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pure-Rust checks against the `_value` functions the shims above
    /// actually call -- not merely against `std`'s own methods restated, the
    /// mistake an earlier version of this file made (see the module-level
    /// comment above the `_value` functions). These prove the *math* is
    /// right; they prove nothing about whether the answer ever reaches a
    /// guest's `ST0` -- see
    /// `crates/mbbs-machine/src/m32/mod.rs`'s
    /// `st0_tests::resume_with_ret_f64_delivers_the_value_into_the_module_s_st0`
    /// for that half, and `crates/mbbs/tests/wg32_math_st0.rs` for the
    /// shim-level round trip through a real `Wg32Cpu`.
    #[test]
    fn sqrt_value_matches_the_ieee_754_operation() {
        assert_eq!(sqrt_value(4.0), 2.0);
        assert_eq!(sqrt_value(2.0), std::f64::consts::SQRT_2);
        assert!(sqrt_value(-1.0).is_nan(), "a domain error answers NaN, not a panic");
        assert_eq!(sqrt_value(0.0), 0.0);
    }

    #[test]
    fn pow_value_takes_base_before_exponent() {
        assert_eq!(pow_value(2.0, 10.0), 1024.0);
        assert_eq!(pow_value(9.0, 0.5), 3.0, "a fractional exponent is exactly pow's point");
        assert_eq!(pow_value(2.0, 0.0), 1.0);
        // 2**10 != 10**2 -- discriminates a swapped (x, y) the way
        // `1.0.powf(anything) == 1.0` alone could not.
        assert_ne!(pow_value(2.0, 10.0), pow_value(10.0, 2.0));
    }

    #[test]
    fn sin_and_atan_value_agree_with_std_at_the_textbook_points() {
        assert_eq!(sin_value(0.0), 0.0);
        assert!((sin_value(std::f64::consts::FRAC_PI_2) - 1.0).abs() < 1e-15);
        assert_eq!(atan_value(0.0), 0.0);
        assert!((atan_value(1.0) - std::f64::consts::FRAC_PI_4).abs() < 1e-15);
    }

    /// `atan2_value(y, x)`, not `(x, y)` -- the one argument-order mistake
    /// `atan_value`'s own single-argument test could never catch. All four
    /// quadrants, since a swapped order agrees with the correct one exactly
    /// on the `y == x` diagonal and nowhere else -- this is what actually
    /// caught the swap this file's own mutation-testing pass introduced
    /// (`atan2_value(x, y)` in place of `atan2_value(y, x)`).
    #[test]
    fn atan2_value_takes_y_before_x() {
        assert_eq!(atan2_value(1.0, 0.0), std::f64::consts::FRAC_PI_2, "+y, x=0: straight up");
        assert_eq!(atan2_value(0.0, 1.0), 0.0, "y=0, +x: straight along x");
        assert!(
            (atan2_value(1.0, 1.0) - std::f64::consts::FRAC_PI_4).abs() < 1e-15,
            "y=x: 45 degrees"
        );
        assert!(
            (atan2_value(1.0, -1.0) - 3.0 * std::f64::consts::FRAC_PI_4).abs() < 1e-15,
            "second quadrant"
        );
    }

    #[test]
    fn modf_value_splits_integral_and_fractional_with_the_value_s_own_sign() {
        assert_eq!(modf_value(2.5), (2.0, 0.5));
        // ISO C: the integral part keeps value's sign, even though the
        // magnitude alone might suggest otherwise.
        assert_eq!(modf_value(-2.5), (-2.0, -0.5));
        assert_eq!(modf_value(0.0), (0.0, 0.0));
    }
}
