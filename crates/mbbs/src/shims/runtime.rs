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

/// The `long` a module passed in `DX:AX`, high half in `DX`.
fn dxax(machine: &Machine) -> u32 {
    u32::from(machine.ax()) | (u32::from(machine.dx()) << 16)
}

/// `long F_LXMUL@(void)` -- `DX:AX * CX:BX`, answered in `DX:AX`.
///
/// The most-called import in `WCCMMUD.DLL`: 124 sites, and not one of them puts
/// anything on the stack. `CX:BX` is one 32-bit operand with its high half in
/// `CX`, which 66 of those sites say out loud by building it as `push dx;
/// push ax` ... `pop bx; pop cx`.
///
/// **Signed or unsigned is not a question this routine answers.** The low 32
/// bits of a 32x32 product are the same either way, which is why Worldgroup 1.01
/// exports `F_LDIV@`/`F_LUDIV@` and `F_LXRSH@`/`F_LXURSH@` as signed and
/// unsigned pairs and exports exactly one multiply. It wraps, and wrapping is
/// right for both.
///
/// What is not reproduced: whatever the real helper left in the flags for a
/// product that did not fit. No call site reads one -- all 124 store `DX:AX`,
/// add to it, or overwrite `AX` at once -- and this host has no way to hand a
/// flag back regardless.
///
/// # Errors
///
/// None. Multiplication modulo 2^32 is total.
pub fn f_lxmul(machine: &mut Machine, _host: &mut Host) -> Result<Ret, ShimError> {
    let cxbx = u32::from(machine.bx()) | (u32::from(machine.cx()) << 16);
    Ok(Ret::U32(dxax(machine).wrapping_mul(cxbx)))
}

/// The shift count a module passed, which is `CL` and never `CX`.
///
/// # Errors
///
/// If it is 32 or more. See [`f_lxlsh`].
fn count(name: &str, machine: &Machine) -> Result<u32, ShimError> {
    let cl = machine.cx() as u8;
    if cl >= 32 {
        return Err(ShimError::Failed(format!(
            "{name}(.., {cl}): a shift of 32 or more has no established answer"
        )));
    }
    Ok(u32::from(cl))
}

/// `long F_LXLSH@(void)` -- `DX:AX` shifted left by `CL`, answered in `DX:AX`.
///
/// Three call sites, all of them building a 64-bit bit-set out of two `long`s.
/// `CH` is not set at any of them, so the count is `CL` and the high byte is
/// whatever happened to be there.
///
/// # Errors
///
/// If the count is 32 or more, which no reachable call site produces. The
/// bounded one, `seg 27:0x0c93`, refuses `n < 1` and `n > 0x40` before calling
/// and then shifts by `n - 1` or `n - 33`; the other two use a literal 11. What
/// the real helper did past 31 is not recorded anywhere this project has --
/// Borland's runtime source is not in `archive/galacticomm/`, which holds only
/// the `.DEF` that names it -- and the two plausible implementations disagree: a
/// `shl ax,1 / rcl dx,1` loop answers zero, and a 286 masking `CL` to five bits
/// answers `value << (n & 31)`. Picking one would be a guess that reads as an
/// answer.
pub fn f_lxlsh(machine: &mut Machine, _host: &mut Host) -> Result<Ret, ShimError> {
    let by = count("f_lxlsh@", machine)?;
    Ok(Ret::U32(dxax(machine) << by))
}

/// `unsigned long F_LXURSH@(void)` -- `DX:AX` shifted right by `CL`, logically.
///
/// The `U` is the whole of the difference: Worldgroup exports the arithmetic
/// shift separately as `F_LXRSH@` at ordinal 660, and `WCCMMUD.DLL` does not
/// import it. Corroborated at `seg 8:0x0120`, where the next statement does the
/// same job 16 bits wide with an unsigned `shr ax,0xb`.
///
/// # Errors
///
/// As [`f_lxlsh`].
pub fn f_lxursh(machine: &mut Machine, _host: &mut Host) -> Result<Ret, ShimError> {
    let by = count("f_lxursh@", machine)?;
    Ok(Ret::U32(dxax(machine) >> by))
}

/// How many bytes of argument `f_scopy@` pops. Two far pointers.
///
/// The same number as [`OPERANDS`] and deliberately not the same constant: one
/// is two `long`s and the other is two addresses, and a single name would
/// describe one of them wrongly.
pub const POINTERS: u16 = 8;

/// `void F_SCOPY@(void *source, void *dest)` -- Borland's structure copy, with
/// the length in `CX`.
///
/// What `struct x = {...}` inside a function and `a = b` on a struct compile to,
/// and the only one of these helpers that is not arithmetic. It pops its own
/// eight bytes, like the division family and unlike the register-only ones.
///
/// **The first-pushed pointer is the destination**, so it is the argument
/// *farther* from the frame. Measured three ways rather than assumed, because
/// reading it backwards overwrites the source with uninitialised stack and
/// reports success: the initialiser pattern at `seg 2:0x0e4c1` copies a static
/// into a local that `enter` made an instant earlier; the loop at
/// `seg 34:0x001f0` fills 100 elements of a far array from one local, and 100
/// copies *into* one place would be dead code; and `seg 34:0x0f20` deletes an
/// array element by shifting the tail down, always writing the lower address.
///
/// `CX` is a count of **bytes**: the same site steps its array with
/// `imul ax,ax,0x63` and passes `CX = 0x63`, and 99 is not an even number of
/// words.
///
/// # It returns the registers it was given
///
/// Not [`Ret::Void`], which zeroes `AX` and `DX`. `seg 34:0x0f20` keeps its loop
/// counter in `DX` across the call -- the instruction after it is `inc dx` -- so
/// the real helper preserved `DX`, and a host that zeroed it would restart that
/// loop forever without faulting. `AX` is preserved on the same principle; no
/// site proves it either way, and a caller cannot depend on a register being
/// *destroyed*.
///
/// The real routine was `rep movsb`, so it also advanced `SI` and `DI` and left
/// `CX` at zero. This one leaves all three alone, which is the safe direction of
/// the same argument.
///
/// # Errors
///
/// If either pointer names nothing of the module's or the copy would leave a
/// segment, and if the two ranges overlap -- `rep movsb` smears a forward
/// overlap where a buffered copy would not, and no struct assignment produces
/// one.
pub fn f_scopy(machine: &mut Machine, _host: &mut Host) -> Result<Ret, ShimError> {
    let source = machine.arg_far(0);
    let dest = machine.arg_far(2);
    let len = usize::from(machine.cx());

    if source.selector == dest.selector {
        let (from, to) = (usize::from(source.offset), usize::from(dest.offset));
        if from < to + len && to < from + len {
            return Err(ShimError::Failed(format!(
                "f_scopy@({source}, {dest}, {len}): the two ranges overlap"
            )));
        }
    }

    let bytes = machine.resolve(source, len)?.to_vec();
    machine.write(dest, &bytes)?;

    Ok(Ret::U32(
        u32::from(machine.ax()) | (u32::from(machine.dx()) << 16),
    ))
}

/// The single signed pair that has no answer: `i32::MIN / -1`.
fn overflow(name: &str, a: i32, b: i32) -> ShimError {
    ShimError::Failed(format!(
        "{name}({a}, {b}): the result does not fit in a long"
    ))
}

#[cfg(test)]
mod tests {
    use mbbs16::FarPtr;

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
        assert_eq!(
            div(f_lmod, -1i32 as u32, 10).unwrap(),
            Ret::U32(-1i32 as u32)
        );
    }

    #[test]
    fn signed_division_truncates_toward_zero_as_the_instruction_does() {
        // `idiv` truncates toward zero, so -7/2 is -3 and not -4, and the
        // remainder takes the sign of the dividend. Rust's `/` and `%` agree,
        // which is why this is an assertion rather than an implementation.
        assert_eq!(
            div(f_ldiv, -7i32 as u32, 2).unwrap(),
            Ret::U32(-3i32 as u32)
        );
        assert_eq!(
            div(f_lmod, -7i32 as u32, 2).unwrap(),
            Ret::U32(-1i32 as u32)
        );
        assert_eq!(
            div(f_ldiv, 7, -2i32 as u32).unwrap(),
            Ret::U32(-3i32 as u32)
        );
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

    /// Set `DX:AX` and `CX:BX` the way a module does, and run `shim`.
    fn regs(shim: crate::shims::Shim, dxax: u32, cxbx: u32) -> Result<Ret, ShimError> {
        let mut f = Fixture::new();
        let regs = [
            dxax as u16,         // AX
            cxbx as u16,         // BX
            (cxbx >> 16) as u16, // CX
            (dxax >> 16) as u16, // DX
        ];
        f.invoke_with(shim, &[], regs)
    }

    #[test]
    fn the_multiply_takes_its_operands_from_registers_and_nothing_else() {
        // Measured: `mov cx,[es:bx+0x611]; mov bx,[es:bx+0x60f]; xor dx,dx;
        // mov ax,0xa; call F_LXMUL@` -- a coin count times its denomination.
        // The high half of each operand is in the *second* register of its
        // pair, and reading a pair backwards multiplies numbers that are off by
        // 65,536 without failing.
        assert_eq!(
            regs(f_lxmul, 10, 0x0001_0002).unwrap(),
            Ret::U32(0x000a_0014)
        );
        assert_eq!(regs(f_lxmul, 1_000_000, 25).unwrap(), Ret::U32(25_000_000));
    }

    #[test]
    fn the_multiply_keeps_the_low_thirty_two_bits_and_no_more() {
        // There is one `F_LXMUL@` and no `F_LXUMUL@`, because for the low half
        // of the product signed and unsigned agree. So the routine wraps, and
        // these are the same multiplication read two ways.
        assert_eq!(
            regs(f_lxmul, 0x0001_0000, 0x0001_0000).unwrap(),
            Ret::U32(0)
        );
        assert_eq!(
            regs(f_lxmul, -3i32 as u32, 7).unwrap(),
            Ret::U32(-21i32 as u32)
        );
        assert_eq!(
            regs(f_lxmul, 0xffff_ffff, 0xffff_ffff).unwrap(),
            Ret::U32(1),
            "as unsigned this overflows and as signed it is (-1)*(-1)"
        );
    }

    /// Set `DX:AX` and a shift count in `CL`, and run `shim`.
    fn shift(shim: crate::shims::Shim, value: u32, count: u8) -> Result<Ret, ShimError> {
        let mut f = Fixture::new();
        // CH is deliberately not zero: no call site sets it, so a shim that read
        // CX rather than CL would shift by an enormous number.
        let cx = u16::from_le_bytes([count, 0xff]);
        let regs = [value as u16, 0, cx, (value >> 16) as u16];
        f.invoke_with(shim, &[], regs)
    }

    #[test]
    fn the_shifts_take_the_count_from_cl_alone() {
        // Measured: `add cl,0xdf; xor dx,dx; mov ax,0x1; call F_LXLSH@` builds a
        // 64-bit flag word as two longs. CH is never set at any of the seven
        // sites, so only CL can be the count.
        assert_eq!(shift(f_lxlsh, 1, 11).unwrap(), Ret::U32(1 << 11));
        assert_eq!(shift(f_lxlsh, 1, 31).unwrap(), Ret::U32(1 << 31));
        assert_eq!(shift(f_lxursh, 0x8000_0000, 31).unwrap(), Ret::U32(1));
    }

    #[test]
    fn the_right_shift_is_logical_and_not_arithmetic() {
        // `F_LXURSH@` is the unsigned one -- Worldgroup exports `F_LXRSH@` at
        // 660 for the signed shift and this module does not import it. An
        // arithmetic shift would answer 0xffffffff to both of these.
        assert_eq!(
            shift(f_lxursh, 0xffff_ffff, 1).unwrap(),
            Ret::U32(0x7fff_ffff)
        );
        assert_eq!(shift(f_lxursh, 0xffff_ffff, 31).unwrap(), Ret::U32(1));
    }

    #[test]
    fn shifting_by_nothing_is_the_value_back() {
        assert_eq!(
            shift(f_lxlsh, 0xdead_beef, 0).unwrap(),
            Ret::U32(0xdead_beef)
        );
        assert_eq!(
            shift(f_lxursh, 0xdead_beef, 0).unwrap(),
            Ret::U32(0xdead_beef)
        );
    }

    #[test]
    fn shifting_a_long_off_the_end_is_refused_rather_than_guessed() {
        // A count of 32 or more has two defensible answers -- zero, from a
        // software `shl ax,1 / rcl dx,1` loop, or the value shifted by
        // `count & 31`, from a 286 masking CL -- and Borland's runtime source is
        // not in the archive to settle it. Every reachable call site is bounded
        // to 0..=31, so this is a guard that should never fire.
        for shim in [f_lxlsh, f_lxursh] {
            let e = shift(shim, 1, 32).expect_err("refused");
            assert!(format!("{e}").contains("32"), "{e}");
            let e = shift(shim, 1, 255).expect_err("refused");
            assert!(format!("{e}").contains("255"), "{e}");
        }
    }

    #[test]
    fn the_struct_copy_writes_the_pointer_that_was_pushed_first() {
        // Measured three ways, because getting it backwards overwrites the
        // source with uninitialised memory and reports nothing: the initialiser
        // pattern at `seg 2:0x0e4c1` copies a static into a fresh local; the
        // loop at `seg 34:0x001f0` fills 100 array elements from one local; and
        // `seg 34:0x0f20` shifts an array down, always writing the lower
        // address. The first-pushed pointer is the destination.
        let mut f = Fixture::new();
        let source = f.text("Galacticomm");
        let dest = f.buffer(16);
        let args = [Fixture::far(source), Fixture::far(dest)].concat();

        f.invoke_with(f_scopy, &args, [0, 0, 11, 0]).unwrap();
        assert_eq!(f.read(dest), "Galacticomm");
    }

    #[test]
    fn the_length_is_a_count_of_bytes() {
        // `seg 34:0x001f0` steps an array with `imul ax,ax,0x63` and passes
        // `CX = 0x63`. 99 is odd, so it cannot be a count of words.
        let mut f = Fixture::new();
        let source = f.bytes(b"abcdefghij", false);
        let dest = f.buffer(10);
        let args = [Fixture::far(source), Fixture::far(dest)].concat();

        f.invoke_with(f_scopy, &args, [0, 0, 3, 0]).unwrap();
        assert_eq!(f.read(dest), "abc", "three bytes, not three words");
    }

    #[test]
    fn the_struct_copy_hands_back_the_registers_it_was_given() {
        // The one that would have been silently wrong. `seg 34:0x0f20` keeps its
        // loop counter in DX across the call and does `inc dx` on the very next
        // instruction, so `F_SCOPY@` preserves DX. `Ret::Void` zeroes both
        // halves -- that loop would restart forever, with no fault and no error
        // to say why.
        let mut f = Fixture::new();
        let source = f.text("x");
        let dest = f.buffer(4);
        let args = [Fixture::far(source), Fixture::far(dest)].concat();

        let ret = f
            .invoke_with(f_scopy, &args, [0xbeef, 0, 1, 0x0007])
            .unwrap();
        assert_eq!(ret, Ret::U32(0x0007_beef), "DX:AX, exactly as they arrived");
    }

    #[test]
    fn copying_nothing_copies_nothing() {
        // `CX` of zero is a struct of no bytes. `rep movsb` does nothing and
        // neither does this; refusing would be inventing a rule.
        let mut f = Fixture::new();
        let source = f.text("ignored");
        let dest = f.buffer(4);
        let args = [Fixture::far(source), Fixture::far(dest)].concat();

        f.invoke_with(f_scopy, &args, [0, 0, 0, 0]).unwrap();
        assert_eq!(f.read(dest), "");
    }

    #[test]
    fn a_copy_that_runs_off_a_segment_is_refused() {
        // The bound is the destination segment's own limit, which is the only
        // place it is known. A host that copied anyway would be writing into
        // whatever the loader put next.
        let mut f = Fixture::new();
        let source = f.bytes(&[b'z'; 8], false);

        // A segment of its own, so what is refused is its length and not the
        // two ranges meeting -- the fixture's scratch holds both otherwise.
        let selector = f.machine.alloc_segment(4).expect("a four-byte segment");
        let dest = FarPtr {
            offset: 0,
            selector,
        };
        let args = [Fixture::far(source), Fixture::far(dest)].concat();

        let e = f
            .invoke_with(f_scopy, &args, [0, 0, 8, 0])
            .expect_err("refused");
        assert!(format!("{e}").contains("runs past the end"), "{e}");
    }

    #[test]
    fn a_copy_onto_itself_is_refused_rather_than_smeared() {
        // `rep movsb` copies forward a byte at a time, so an overlapping copy
        // with the destination above the source repeats bytes rather than moving
        // them; buffering the source first would quietly do the other thing. No
        // struct assignment can overlap, so this is a guard.
        let mut f = Fixture::new();
        let source = f.bytes(b"overlapping", false);
        let dest = FarPtr {
            offset: source.offset + 2,
            selector: source.selector,
        };
        let args = [Fixture::far(source), Fixture::far(dest)].concat();

        let e = f
            .invoke_with(f_scopy, &args, [0, 0, 8, 0])
            .expect_err("refused");
        assert!(format!("{e}").contains("overlap"), "{e}");
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
