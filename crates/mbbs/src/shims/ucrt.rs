//! Microsoft's Universal C Runtime, as an MSVC-built module imports it.
//!
//! The Major BBS v10 modules are built with Visual Studio (LunatiX 5.3H,
//! 2025-11-30, is the first this host met), and link the C library under
//! `api-ms-win-crt-*-l1-1-0.dll` / `VCRUNTIME140.dll` rather than Borland's
//! `cw3220mt.DLL`. Almost everything they import under those names --
//! `fopen`, `strncpy`, `memcpy`, `rand`, 21 names for LunatiX -- is the same
//! C library this host already serves, and [`super::entry`] folds the
//! spelling onto it. What lives here is the remainder: the four routines
//! that exist only in the UCRT's own vocabulary.
//!
//! * [`feof`] -- a real call. Borland's is a macro over `FILE.flags` that
//!   never reaches a host.
//! * [`time64`] -- `time()` under MSVC, returning a 64-bit `__time64_t`.
//! * [`stdio_common_vsprintf`] / [`stdio_common_vfprintf`] -- what every
//!   `sprintf`/`vsprintf`/`_snprintf`/`fprintf` compiles to since VS2015:
//!   the inline wrappers in `stdio.h` pack the call into one exported
//!   worker with an options word in front.
//!
//! Registered under [`mbbs_machine::library::UCRT`] and only for `Wg32`
//! ([`super::WG32_ROUTINES`]): no 16-bit module links the UCRT, and
//! [`time64`]'s return needs `EDX:EAX`.
//!
//! Not here, deliberately: `_initterm`, `_initialize_onexit_table`,
//! `_configure_narrow_argv`, `_seh_filter_dll`, `_except_handler4_common`,
//! `__std_type_info_destroy_list` and the twelve `KERNEL32` names beside
//! them. All are referenced only from `_DllMainCRTStartup`, the PE entry
//! point, which `Wg32::load` records and never runs (`abi/wg32.rs`: the
//! module's init routine is `_init__<name>`, not the entry point). They stay
//! [`super::Entry::Unimplemented`] -- named, refused if ever reached -- which
//! is the honest answer for code this host has decided not to execute.

use mbbs_machine::ptr::ModulePtr;

use super::{Call, ShimError};
use crate::Host;
use crate::abi::{self, Abi};
use crate::fmt::format_va_list;

/// `_CRT_INTERNAL_PRINTF_STANDARD_SNPRINTF_BEHAVIOR` (`corecrt_stdio_config.h`):
/// C99 `snprintf` -- always terminate, always report the full length.
/// Without it the worker keeps `_snprintf`'s older contract, which the
/// `_CRT_INTERNAL_PRINTF_LEGACY_VSPRINTF_NULL_TERMINATION` bit (`0x0001`)
/// merely names: an exactly-filled buffer gets no terminator.
const STANDARD_SNPRINTF_BEHAVIOR: u64 = 0x0002;

/// `count` for `sprintf`/`vsprintf`: `(size_t)-1`, "no limit".
const UNBOUNDED: u32 = u32::MAX;

/// The UCRT's `unsigned __int64 options`, two stack slots under `Wg32`,
/// low dword first.
fn options<A: Abi>(call: &mut Call<A>) -> u64 {
    let lo = u64::from(call.long());
    let hi = u64::from(call.long());
    lo | (hi << 32)
}

/// `int feof(FILE *stream)` -- nonzero once a read has hit the end.
pub fn feof<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let cookie = call.ptr();
    let ended = host.streams.ended(cookie).map_err(|e| ShimError::Failed(format!("feof: {e}")))?;
    Ok(abi::Ret::Int(A::Int::from(u16::from(ended))))
}

/// `__time64_t _time64(__time64_t *destination)` -- seconds since 1970, as
/// a 64-bit integer, stored through `destination` when it is not null.
///
/// `time()` itself under MSVC; `time.h` maps the name unless
/// `_USE_32BIT_TIME_T` is set. Same clock as `system::time`, so a module
/// mixing the two (or a pinned `Clock` in a test) sees one time.
pub fn time64<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let seconds = u64::from(host.clock().epoch().map_err(ShimError::Failed)?);
    let destination = call.ptr();
    if !A::ptr_to_bytes(destination).iter().all(|&b| b == 0) {
        destination
            .write(call.mem(), &seconds.to_le_bytes())
            .map_err(|e| ShimError::Failed(e.to_string()))?;
    }
    Ok(abi::Ret::Long64(seconds))
}

/// `int __stdio_common_vsprintf(unsigned __int64 options, char *buffer,
/// size_t count, const char *format, _locale_t locale, va_list args)`.
///
/// One worker behind `sprintf`, `vsprintf`, `_snprintf`, `_vsnprintf` and
/// `snprintf`, which differ only in `count` and `options`
/// (`corecrt_stdio_config.h` / `stdio.h`'s inline wrappers). The contract,
/// from the UCRT's `output.cpp`:
///
/// * `count == (size_t)-1` -- `sprintf`: everything, terminated, length
///   returned.
/// * fits (`length < count`): everything, terminated, length returned.
/// * [`STANDARD_SNPRINTF_BEHAVIOR`] and does not fit: `count - 1` bytes and
///   a terminator (nothing at all for `count == 0`), the *full* length
///   returned -- C99's "how big a buffer would I have needed".
/// * legacy and does not fit: `count` bytes, **no terminator**; `count`
///   returned when the text was exactly that long, `-1` when it was longer.
///
/// `locale` is accepted and ignored: this host formats in the "C" locale
/// and nothing else, which is also what a module that never calls
/// `setlocale` gets.
pub fn stdio_common_vsprintf<A: Abi>(
    call: &mut Call<A>,
    _: &mut Host<A>,
) -> Result<abi::Ret<A>, ShimError> {
    let options = options(call);
    let buffer = call.ptr();
    let count = call.long();
    let template = call.ptr();
    let _locale = call.ptr();
    let list = call.ptr();
    let (text, _) = format_va_list(call, template, list)?;

    let length = text.len();
    let bounded = count != UNBOUNDED;
    let count = count as usize;
    let (stored, terminated, answer): (usize, bool, i32) = if !bounded || length < count {
        (length, true, length as i32)
    } else if options & STANDARD_SNPRINTF_BEHAVIOR != 0 {
        (count.saturating_sub(1), count > 0, length as i32)
    } else {
        (count, false, if length == count { count as i32 } else { -1 })
    };

    let mut bytes = text[..stored].to_vec();
    if terminated {
        bytes.push(0);
    }
    if !bytes.is_empty() {
        buffer.write(call.mem(), &bytes).map_err(|e| ShimError::Failed(e.to_string()))?;
    }
    Ok(abi::Ret::Int(A::int_from_u32(answer as u32)))
}

/// `int __stdio_common_vfprintf(unsigned __int64 options, FILE *stream,
/// const char *format, _locale_t locale, va_list args)` -- `fprintf` and
/// `vfprintf`, the same way [`stdio_common_vsprintf`] is `sprintf`.
///
/// `options` carries nothing a stream write needs (the `snprintf` bits are
/// about a bounded buffer, and a stream has none), so it is read past.
pub fn stdio_common_vfprintf<A: Abi>(
    call: &mut Call<A>,
    host: &mut Host<A>,
) -> Result<abi::Ret<A>, ShimError> {
    let _options = options(call);
    let cookie = call.ptr();
    let template = call.ptr();
    let _locale = call.ptr();
    let list = call.ptr();
    let (text, _) = format_va_list(call, template, list)?;
    host.streams
        .write(cookie, &text)
        .map_err(|e| ShimError::Failed(format!("fprintf: {e}")))?;
    Ok(abi::Ret::Int(A::int_from_u32(text.len() as u32)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::Wg32;
    use crate::shims::stream::{fclose, fgetc, fopen};
    use crate::testing::Fixture;
    use mbbs_machine::m32::Flat32Ptr;

    fn int(ret: abi::Ret<Wg32>) -> u32 {
        match ret {
            abi::Ret::Int(n) => n,
            _ => panic!("expected an int"),
        }
    }

    /// A `va_list` under MSVC x86: a pointer at the arguments, laid out as
    /// they would sit on the stack -- one dword per `int`/pointer.
    fn va_list(f: &mut Fixture<Wg32>, args: &[u32]) -> Flat32Ptr {
        let bytes: Vec<u8> = args.iter().flat_map(|a| a.to_le_bytes()).collect();
        f.bytes_wg32(&bytes)
    }

    /// `n` bytes of `0xff` and a terminator after them, so what a routine
    /// wrote -- terminator or none -- can be read back exactly.
    fn scratch(f: &mut Fixture<Wg32>, n: usize) -> Flat32Ptr {
        let mut bytes = vec![0xff; n];
        bytes.push(0);
        f.bytes_wg32(&bytes)
    }

    fn contents(f: &mut Fixture<Wg32>, at: Flat32Ptr) -> Vec<u8> {
        let mem = <Wg32 as Abi>::mem(&mut f.machine);
        at.read_cstr(mem).expect("terminated").to_vec()
    }

    /// `sprintf(dst, "%s/%d", "gold", 9)` as `stdio.h` compiles it.
    fn vsprintf(f: &mut Fixture<Wg32>, options: u64, dst: Flat32Ptr, count: u32) -> u32 {
        let template = f.text_wg32("%s/%d");
        let text = f.text_wg32("gold");
        let list = va_list(f, &[text.0, 9]);
        let args = [options as u32, (options >> 32) as u32, dst.0, count, template.0, 0, list.0];
        int(f.invoke_wg32(stdio_common_vsprintf, &args).expect("formatted"))
    }

    #[test]
    fn sprintf_is_unbounded_terminated_and_answers_the_length() {
        let mut f = Fixture::new_wg32();
        let dst = scratch(&mut f, 16);
        assert_eq!(vsprintf(&mut f, 0, dst, UNBOUNDED), 6);
        assert_eq!(contents(&mut f, dst), b"gold/9");
    }

    #[test]
    fn a_fitting_bounded_write_is_the_same_as_unbounded() {
        let mut f = Fixture::new_wg32();
        let dst = scratch(&mut f, 16);
        assert_eq!(vsprintf(&mut f, 0, dst, 7), 6, "six bytes plus a terminator fit in seven");
        assert_eq!(contents(&mut f, dst), b"gold/9");
    }

    #[test]
    fn legacy_snprintf_fills_exactly_without_a_terminator_and_answers_count() {
        let mut f = Fixture::new_wg32();
        let dst = scratch(&mut f, 16);
        assert_eq!(vsprintf(&mut f, 0, dst, 6), 6);
        // Six bytes written, the seventh is the scratch fill: no terminator.
        assert_eq!(contents(&mut f, dst), b"gold/9\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff");
    }

    #[test]
    fn legacy_snprintf_truncates_without_a_terminator_and_answers_minus_one() {
        let mut f = Fixture::new_wg32();
        let dst = scratch(&mut f, 16);
        assert_eq!(vsprintf(&mut f, 0, dst, 4), u32::MAX);
        assert_eq!(&contents(&mut f, dst)[..5], b"gold\xff");
    }

    #[test]
    fn standard_snprintf_truncates_terminates_and_answers_the_full_length() {
        let mut f = Fixture::new_wg32();
        let dst = scratch(&mut f, 16);
        assert_eq!(vsprintf(&mut f, STANDARD_SNPRINTF_BEHAVIOR, dst, 4), 6);
        assert_eq!(contents(&mut f, dst), b"gol");
    }

    #[test]
    fn standard_snprintf_with_no_room_writes_nothing_and_still_measures() {
        let mut f = Fixture::new_wg32();
        let dst = scratch(&mut f, 16);
        assert_eq!(vsprintf(&mut f, STANDARD_SNPRINTF_BEHAVIOR, dst, 0), 6);
        assert_eq!(contents(&mut f, dst), vec![0xff; 16], "untouched");
    }

    #[test]
    fn time64_answers_64_bits_and_stores_them_when_asked() {
        let mut f = Fixture::new_wg32();
        let slot = f.bytes_wg32(&[0u8; 8]);
        let abi::Ret::Long64(direct) = f.invoke_wg32(time64, &[slot.0]).expect("time") else {
            panic!("time64 returns Long64");
        };
        let stored = u64::from_le_bytes(contents_raw(&mut f, slot));
        assert_eq!(stored, direct);
        assert!(direct > 1_600_000_000, "seconds since 1970, not a 32-bit wrap or a zero");
        assert!(matches!(f.invoke_wg32(time64, &[0]).expect("time"), abi::Ret::Long64(_)), "null: no store, still answers");
    }

    fn contents_raw(f: &mut Fixture<Wg32>, at: Flat32Ptr) -> [u8; 8] {
        let mem = <Wg32 as Abi>::mem(&mut f.machine);
        at.resolve(mem, 8).expect("readable").try_into().expect("eight bytes")
    }

    #[test]
    fn feof_is_false_until_a_read_hits_the_end() {
        let mut f = Fixture::new_wg32();
        let name = f.text_wg32("LINES.TXT");
        let mode = f.text_wg32("rb");
        let abi::Ret::Ptr(fp) = f.invoke_wg32(fopen, &[name.0, mode.0]).expect("fopen") else {
            panic!("fopen returns a pointer");
        };
        assert_eq!(int(f.invoke_wg32(feof, &[fp.0]).expect("feof")), 0);
        while int(f.invoke_wg32(fgetc, &[fp.0]).expect("fgetc")) != u32::MAX {}
        assert_eq!(int(f.invoke_wg32(feof, &[fp.0]).expect("feof")), 1);
        f.invoke_wg32(fclose, &[fp.0]).expect("fclose");
    }

    #[test]
    fn feof_of_a_stream_never_opened_is_refused() {
        let mut f = Fixture::new_wg32();
        assert!(f.invoke_wg32(feof, &[0x1234]).is_err());
    }

    #[test]
    fn vfprintf_formats_onto_the_stream_and_answers_the_length() {
        let root = crate::testing::scratch_with("ucrt-vfprintf", &[]);
        let mut f = Fixture::rooted_wg32(root.clone());
        let name = f.text_wg32("OUT.TXT");
        let mode = f.text_wg32("wt");
        let abi::Ret::Ptr(fp) = f.invoke_wg32(fopen, &[name.0, mode.0]).expect("fopen") else {
            panic!("fopen returns a pointer");
        };
        let template = f.text_wg32("%s=%d\n");
        let key = f.text_wg32("gold");
        let list = va_list(&mut f, &[key.0, 9]);
        let n = int(f.invoke_wg32(stdio_common_vfprintf, &[0, 0, fp.0, template.0, 0, list.0]).expect("fprintf"));
        assert_eq!(n, 7);
        f.invoke_wg32(fclose, &[fp.0]).expect("fclose");
        assert_eq!(std::fs::read(root.join("OUT.TXT")).expect("written"), b"gold=9\r\n");
    }
}
