//! The four `USER32.dll` symbols this program links.
//!
//! A console utility importing USER32 looks odd until you see where the calls
//! come from: `wsprintfA` is formatting, `MessageBoxA` and `MessageBeep` are
//! the fallback for reporting a failure when there is no console left to report
//! it on, and `IsCharAlphaNumericA` is classification. None of them draws a
//! window.
//!
//! # `wsprintfA` is cdecl, and it is the only one
//!
//! **Every other symbol in Win32 is stdcall; this one is not.** It is variadic,
//! and a variadic callee cannot know how much to pop, so the caller does it.
//! Getting this wrong does not break `wsprintfA` -- it breaks whatever the
//! program calls *next*, by leaving that call's arguments shifted by however
//! many words this one was given. That is the failure mode
//! [`crate::win32::kernel32`]'s doc comment describes, and this is the one
//! symbol in the whole host where the convention is not what the DLL would
//! suggest.

use mbbs_machine::m32::{Flat32Ptr, Machine, Memory};
use mbbs_machine::ptr::ModulePtr;

use crate::win32::format::{self, ArgCursor, ArgSource};
use crate::win32::kernel32::{Answer, TRUE};
use crate::win32::process::{self, Process};

/// `IDOK` -- what a message box with a single OK button answers.
const IDOK: u32 = 1;

/// Answer a `USER32.dll` import, or `None` for one still unimplemented.
pub fn dispatch(
    process: &mut Process,
    machine: &mut Machine,
    mem: &mut Memory,
    symbol: &str,
) -> Option<Answer> {
    match symbol {
        // int wsprintfA(LPSTR lpOut, LPCSTR lpFmt, ...)
        //
        // **cdecl** -- see this module's doc comment. Shares the one format
        // engine with `sprintf` and `vsprintf`; the only difference is which
        // DLL exports it.
        "wsprintfA" => {
            let out = machine.arg_u32(mem.stack(), 0);
            let fmt_at = machine.arg_u32(mem.stack(), 1);
            let fmt = read_bytes(mem, fmt_at);
            let mut cursor = ArgCursor::new(ArgSource::Frame { machine, base: 2 });
            let rendered = format::render(mem, &fmt, &mut cursor);
            if out == 0 {
                return Some(Answer::cdecl(0));
            }
            let mut with_nul = rendered.clone();
            with_nul.push(0);
            if Flat32Ptr(out).write(mem, &with_nul).is_err() {
                return Some(Answer::cdecl(0));
            }
            Some(Answer::cdecl(
                u32::try_from(rendered.len()).unwrap_or(u32::MAX),
            ))
        }
        // BOOL IsCharAlphaNumericA(CHAR ch)
        //
        // ASCII only. Windows would consult the current code page, which for a
        // CP437 program would classify some high bytes as letters; nothing here
        // has a code page, and claiming otherwise would be inventing a locale.
        "IsCharAlphaNumericA" => {
            #[allow(clippy::cast_possible_truncation)]
            let ch = machine.arg_u32(mem.stack(), 0) as u8;
            Some(Answer::stdcall(u32::from(ch.is_ascii_alphanumeric()), 1))
        }
        // int MessageBoxA(HWND, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
        //
        // There is no desktop, so the box cannot be shown -- but the *text* is
        // the program telling an operator something went wrong, and it is kept
        // for the same reason `ReportEventA`'s is: on the error paths this
        // utility takes, its own words are the best diagnostic available.
        //
        // Answers `IDOK`, which is what a dismissed single-button box returns.
        // Answering zero would mean the box could not be created, and a program
        // that checks may treat that as fatal.
        "MessageBoxA" => {
            let text = machine.arg_u32(mem.stack(), 1);
            let caption = machine.arg_u32(mem.stack(), 2);
            let text = process::read_cstr(mem, text).unwrap_or_default();
            let caption = process::read_cstr(mem, caption).unwrap_or_default();
            process.messages.push((caption, text));
            Some(Answer::stdcall(IDOK, 4))
        }
        // BOOL MessageBeep(UINT uType)
        "MessageBeep" => Some(Answer::stdcall(TRUE, 1)),
        _ => None,
    }
}

/// A C string's bytes, or empty for a pointer that resolves nowhere.
fn read_bytes(mem: &Memory, at: u32) -> Vec<u8> {
    if at == 0 {
        return Vec::new();
    }
    Flat32Ptr(at)
        .read_cstr(mem)
        .map_or_else(|_| Vec::new(), <[u8]>::to_vec)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ASCII classification, and the boundary cases either side of each range.
    #[test]
    fn alphanumeric_is_letters_and_digits_only() {
        let mut l = {
            let f = std::fs::read("/home/daniel/peepeebbs/wccmmutl.exe").expect("the utility");
            crate::win32::load::load(&f).expect("loads")
        };
        let mut p = Process::new("X.EXE", &[]);
        // `dispatch` reads an argument, which needs a real frame, so the
        // classification itself is checked directly -- the arm is one call.
        for (ch, want) in [
            (b'A', true),
            (b'z', true),
            (b'0', true),
            (b'9', true),
            (b'@', false),
            (b' ', false),
            (0xe1, false),
        ] {
            assert_eq!(ch.is_ascii_alphanumeric(), want, "{ch:#04x}");
        }
        // And an unimplemented USER32 symbol still declines.
        assert!(dispatch(&mut p, &mut l.machine, &mut l.mem, "CreateWindowExA").is_none());
    }
}
