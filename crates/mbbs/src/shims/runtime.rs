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
//! far-call form. `WCCMMUD.DLL` imports eight of them across 290 call sites, and
//! all eight are implemented here.
//!
//! # Three conventions, in one family of eight
//!
//! Nothing about the names says which, so each was read off the call sites:
//!
//! ```text
//! ordinal  name        sites  convention
//!    654   F_LDIV@        48  \
//!    655   F_LMOD@         9   |  four words on the stack, callee pops 8,
//!    656   F_LUDIV@       54   |  answer in DX:AX
//!    657   F_LUMOD@       22  /
//!    658   F_LXLSH@        3  \
//!    659   F_LXMUL@      124   |  registers only: DX:AX against CX:BX or CL,
//!    661   F_LXURSH@       4  /   answer in DX:AX, stack untouched
//!    665   F_SCOPY@       26     two far pointers on the stack and a length in
//!                                CX; callee pops 8; answers nothing, and means
//!                                it -- see [`f_scopy`]
//! ```
//!
//! The five that take arguments on the stack pop them themselves: the words go
//! down and there is no `add sp` after the call. That is why the shim table has
//! a [`Cleans`](crate::shims::Cleans) column, and those are the entries that
//! need it. `re/ne_arity.py` reports "cleans void" for every site of all eight,
//! which is the tool being unable to see a callee-cleaned convention rather than
//! eight nullary routines -- it looks for the caller's stack adjustment and
//! there is not one to find.
//!
//! The three register-only ones are why [`Machine::ax`](mbbs_machine::m16::Machine::ax) and
//! its siblings exist. An import thunk overwrites `AX` and `CX` to name itself,
//! so it now saves them first.
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

use mbbs_machine::m16::Machine;

use crate::Host;
use crate::abi::{self, Call, Wg16};
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
pub fn f_ldiv(call: &mut Call<Wg16>, _host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let machine = &mut *call.cpu;
    let (dividend, divisor) = operands(machine);
    let (a, b) = (dividend as i32, divisor as i32);
    if b == 0 {
        return Err(by_zero("f_ldiv@", dividend));
    }
    a.checked_div(b)
        .map(|v| abi::Ret::Long(v as u32))
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
pub fn f_lmod(call: &mut Call<Wg16>, _host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let machine = &mut *call.cpu;
    let (dividend, divisor) = operands(machine);
    let (a, b) = (dividend as i32, divisor as i32);
    if b == 0 {
        return Err(by_zero("f_lmod@", dividend));
    }
    a.checked_rem(b)
        .map(|v| abi::Ret::Long(v as u32))
        .ok_or_else(|| overflow("f_lmod@", a, b))
}

/// `unsigned long f_ludiv@(unsigned long, unsigned long)` -- unsigned division.
///
/// # Errors
///
/// If the divisor is zero. Unsigned division cannot overflow.
pub fn f_ludiv(call: &mut Call<Wg16>, _host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let machine = &mut *call.cpu;
    let (dividend, divisor) = operands(machine);
    match dividend.checked_div(divisor) {
        Some(v) => Ok(abi::Ret::Long(v)),
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
pub fn f_lumod(call: &mut Call<Wg16>, _host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let machine = &mut *call.cpu;
    let (dividend, divisor) = operands(machine);
    match dividend.checked_rem(divisor) {
        Some(v) => Ok(abi::Ret::Long(v)),
        None => Err(by_zero("f_lumod@", dividend)),
    }
}

/// The `DX:AX` pair a module called with, as one 32-bit value with the high
/// half in `DX`.
///
/// An operand for the helpers that take one there, and for `f_scopy@` -- which
/// takes none -- the answer, because handing those two registers back untouched
/// is what "returns nothing" has to mean for it.
fn dxax(machine: &Machine) -> u32 {
    u32::from(machine.ax()) | (u32::from(machine.dx()) << 16)
}

/// `long F_LXMUL@(void)` -- `DX:AX * CX:BX`, answered in `DX:AX`.
///
/// The most-called of the eight helpers by a wide margin -- 124 sites, against
/// 54 for the next -- though not of the module's imports at large, where
/// `re/ne_imports.py` puts it eighteenth. Not one of the 124 puts anything on
/// the stack. `CX:BX` is one 32-bit operand with its high half in
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
pub fn f_lxmul(call: &mut Call<Wg16>, _host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let machine = &mut *call.cpu;
    let cxbx = u32::from(machine.bx()) | (u32::from(machine.cx()) << 16);
    Ok(abi::Ret::Long(dxax(machine).wrapping_mul(cxbx)))
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
pub fn f_lxlsh(call: &mut Call<Wg16>, _host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let machine = &mut *call.cpu;
    let by = count("f_lxlsh@", machine)?;
    Ok(abi::Ret::Long(dxax(machine) << by))
}

/// `unsigned long F_LXURSH@(void)` -- `DX:AX` shifted right by `CL`, logically.
///
/// The `U` is the whole of the difference: Worldgroup exports the arithmetic
/// shift separately as `F_LXRSH@` at ordinal 660, and `WCCMMUD.DLL` does not
/// import it. Corroborated at `seg 8:0x0120`, where the surrounding code shifts
/// unsigned -- the next statement is `mov ax,[bp+0xc]; shr ax,0xb`, an `shr` and
/// not an `sar`, though on a different variable and a different count.
///
/// # Errors
///
/// As [`f_lxlsh`].
pub fn f_lxursh(call: &mut Call<Wg16>, _host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let machine = &mut *call.cpu;
    let by = count("f_lxursh@", machine)?;
    Ok(abi::Ret::Long(dxax(machine) >> by))
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
/// `CX` at zero. This one leaves all three as the module had them -- `mbbs16`
/// hands `SI`, `DI`, `BX` and `CX` back across every host call -- which is the
/// safe direction of the same argument. `BX` is the one that matters: `rep
/// movsb` never touched it, so Borland's code generator is entitled to keep a
/// live value there across this call, and it is preserved for that reason
/// rather than by cdecl, which makes it scratch.
///
/// # Errors
///
/// If either pointer names nothing of the module's or the copy would leave a
/// segment, and if the two ranges overlap -- `rep movsb` smears a forward
/// overlap where a buffered copy would not, and no struct assignment produces
/// one. Overlap is judged on the selectors being equal, which is the same
/// question as the segments being the same one only because every selector this
/// host hands out carries the same low three bits.
pub fn f_scopy(call: &mut Call<Wg16>, _host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let machine = &mut *call.cpu;
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

    Ok(abi::Ret::Long(dxax(machine)))
}

/// `void far *f_spush@(void far *src, unsigned len)` -- Borland's
/// structure-by-value stack push, ordinal 884.
///
/// # Where this comes from
///
/// Not declared in any recovered Galacticomm header
/// (`archive/galacticomm/extract/wg1/GALDSRC/SRC`), any more than its seven
/// siblings above are -- this is the compiler's own runtime, not the
/// MajorBBS API, linked into `MAJORBBS.DLL` the same incidental way. Ordinal
/// 884 is stable across every export map this project has recovered:
/// MajorBBS 5.11 (`archive/galacticomm/majorbbs_mbbs625.tsv:945`),
/// Worldgroup 1.01 (`majorbbs_wg101.tsv:1086`) and Worldgroup 2.00
/// (`majorbbs_wg200.tsv:1109`). No body survives in `re/wg33src` or
/// `mbbs511s.zip` either -- neither SDK ships the compiler's own runtime
/// source -- so, like `f_scopy@` above it, this is implemented from The
/// Rose's own call sites rather than from a declaration: six of them, in
/// `RCIROSE.DLL` segment 8, at fixups `0x26b`, `0x279`, `0x287` and their
/// exact duplicates `0x37e`, `0x38c`, `0x39a`.
///
/// # The calling convention, measured and not assumed
///
/// Every site is
///
///
/// with nothing pushed before the call and no `add sp`/`pop` after it --
/// `re/ne_arity.py 884 tmp/gapsurvey/rose/RCIROSE.DLL` reports "cleans void"
/// for all six sites, exactly what it reports for `f_lxmul@`/`f_lxlsh@`/
/// `f_lxursh@` above for the same reason: a register-only routine looks
/// identical to a callee-cleaned one to a tool that only watches for a
/// caller-side stack adjustment after the call. **`Cleans::Caller`, not
/// `Callee`** -- there are no argument words on the module's stack for
/// either side to clean. The plan that scheduled this task expected
/// `Callee` from this routine's family resemblance to the four division
/// helpers; the guess does not survive the disassembly, which is the entire
/// point of measuring instead of assuming.
///
/// # What the routine actually does, and why this host cannot do it
///
/// `F_SPUSH@`'s name is literal: it pushes the struct at `AX:DX` onto the
/// module's own hardware stack, `CX` bytes at a time (`SP -= CX`, then a
/// copy into the space that opens up), so that a struct passed by value can
/// be built on the stack without a run of individual `push` instructions --
/// the same problem `f_scopy@` solves for a plain assignment, here solved
/// for an argument. Confirmed at both of The Rose's call groups: three
/// consecutive `F_SPUSH@` calls of `0xe0` (224) bytes each are immediately
/// followed by `push cs; call near <seg 8:0x3f5>; add sp,0x2a0` -- and
/// `0x2a0 == 3 * 0xe0` exactly, so the *caller's* own cleanup after that
/// near call removes precisely what the three pushes added, nothing more
/// and nothing less. `seg 8:0x3f5` itself opens with the ordinary `push bp;
/// mov bp,sp` prologue and reads its own arguments starting at `[bp+0x1e]`
/// and beyond: real struct fields, addressed the only way a compiler ever
/// addresses a by-value argument -- relative to a stack pointer that
/// actually has to have moved before the call reads it.
///
/// This host's shim layer has no way to move it. [`crate::shims::Cleans`]
/// only ever *adds* bytes to the module's `SP` on return
/// (`Machine::resume_cleaning`), for popping arguments a module already
/// pushed before the call -- there is no direction that subtracts, and
/// neither [`Call`] nor [`Machine`] exposes an `SP` setter at all; the
/// resume path is the only place `SP` is ever written, and it is driven
/// entirely by the table's static `Cleans` value, not by anything a shim
/// decides mid-call. That is the same shape of gap `shims::misc`'s module
/// doc names for `byenow` and `listing` -- a capability the call needs and
/// the shim layer does not have -- except there the missing piece is
/// calling back into the module's own code, and here it is moving the
/// module's own stack pointer. Reading the arguments faithfully and
/// refusing, rather than reporting a copy that repositioned nothing a
/// subsequent instruction could find, is the same choice this crate makes
/// everywhere else that happens.
///
/// # Errors
///
/// Always. There is no argument value this can succeed for.
pub fn f_spush(call: &mut Call<Wg16>, _host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let machine = &mut *call.cpu;
    // Formatted from the registers rather than built into a `FarPtr`: this
    // routine always errors and never dereferences the address, so naming
    // `Wg16`'s concrete pointer type here would put a 16-bit type into a
    // shim purely to make a debug string -- exactly what
    // `tests/no_direct_farptr.rs` exists to keep out. `selector:offset` is
    // the same rendering `FarPtr`'s own `Display` produces.
    let src = format!("{:04x}:{:04x}", machine.dx(), machine.ax());
    let len = machine.cx();

    Err(ShimError::Failed(format!(
        "f_spush@({src}, {len}): this host cannot grow the module's own \
         stack from inside a shim -- see this function's own doc comment \
         for exactly what capability is missing"
    )))
}

/// The single signed pair that has no answer: `i32::MIN / -1`.
fn overflow(name: &str, a: i32, b: i32) -> ShimError {
    ShimError::Failed(format!(
        "{name}({a}, {b}): the result does not fit in a long"
    ))
}

#[cfg(test)]
mod tests {
    use mbbs_machine::m16::FarPtr;

    use super::*;
    // Wg16-only, and used by these fixtures alone -- the
    // production code above reaches memory through the ABI.
    use mbbs_machine::m16::Ret;
    use crate::testing::Fixture;

    /// Push a dividend and a divisor the way the module does, and run `shim`.
    fn div(shim: crate::shims::Shim<Wg16>, dividend: u32, divisor: u32) -> Result<Ret, ShimError> {
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
    fn regs(shim: crate::shims::Shim<Wg16>, dxax: u32, cxbx: u32) -> Result<Ret, ShimError> {
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
    fn shift(shim: crate::shims::Shim<Wg16>, value: u32, count: u8) -> Result<Ret, ShimError> {
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
        //
        // The counts are matched with their surrounding punctuation because
        // `CH` is 0xff in this fixture: a shim that read `CX` would report
        // 65,312 rather than 32, and a bare `contains("32")` would accept that.
        for shim in [f_lxlsh, f_lxursh] {
            let e = shift(shim, 1, 32).expect_err("refused");
            assert!(format!("{e}").contains(", 32)"), "{e}");
            let e = shift(shim, 1, 255).expect_err("refused");
            assert!(format!("{e}").contains(", 255)"), "{e}");
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
    fn a_copy_that_runs_off_a_segment_is_refused_at_either_end() {
        // The bound is each segment's own limit, which is the only place it is
        // known. A host that copied anyway would be reading whatever followed
        // the source, or writing over whatever followed the destination.
        //
        // Both directions, because they are refused by different calls --
        // `resolve` for the source and `write` for the destination -- and a
        // four-byte segment of its own keeps each refusal about a length rather
        // than about the two ranges meeting in the fixture's shared scratch.
        let mut f = Fixture::new();
        let small = FarPtr {
            offset: 0,
            selector: f.machine.alloc_segment(4).expect("a four-byte segment"),
        };
        let roomy = f.bytes(&[b'z'; 8], false);

        for (source, dest, end) in [(roomy, small, "destination"), (small, roomy, "source")] {
            let args = [Fixture::far(source), Fixture::far(dest)].concat();
            let e = f
                .invoke_with(f_scopy, &args, [0, 0, 8, 0])
                .expect_err("refused");
            assert!(format!("{e}").contains("runs past the end"), "{end}: {e}");
        }
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

    #[test]
    fn f_spush_reads_ax_dx_cx_and_refuses() {
        // AX = source offset, DX = source segment, CX = length -- measured
        // off The Rose's own six call sites (`lea ax,[bp+disp]; mov dx,ss;
        // mov cx,<len>; call far F_SPUSH@`). Three distinct field values,
        // and the full formatted `selector:offset` pair asserted in order
        // rather than a bare `contains` on one number, so a shim that read
        // AX and DX swapped -- exactly the kind of silent-shift bug
        // `Cleans` exists to catch one level up -- fails this test too.
        let mut f = Fixture::new();
        let e = f
            .invoke_with(f_spush, &[], [0x00aa, 0, 0x0038, 0x1234])
            .expect_err("f_spush@ always refuses: no shim can grow the module's own stack");
        let msg = format!("{e}");
        assert!(msg.contains("1234:00aa"), "{msg}");
        assert!(msg.contains("56"), "{msg}"); // 0x0038 == 56, CX as a plain decimal length
    }

    #[test]
    fn f_spush_refuses_regardless_of_the_arguments() {
        // The mutation this has to survive is reporting `Ok` -- a
        // plausible-looking success that claims a struct landed somewhere a
        // later instruction could find it, when nothing on the module's
        // real stack pointer moved. That is true for every input, not just
        // the six measured sites, so this checks a second, unrelated set of
        // values: an all-zero call is not special-cased into succeeding.
        let mut f = Fixture::new();
        assert!(f.invoke_with(f_spush, &[], [0, 0, 0, 0]).is_err());
    }
}
