//! The two `WSOCK32.dll` symbols this program links, and why an offline
//! utility links any at all.
//!
//! `WSAGetLastError` and `WSASetLastError` are Winsock's per-thread error slot.
//! Nothing here opens a socket -- the import table names no `socket`, `connect`,
//! `send` or `recv` -- so the pair arrives not from networking but from shared
//! Galacticomm error-reporting code that reports *whichever* last error is
//! relevant to the subsystem it was compiled beside.
//!
//! That is why this is a separate slot from
//! [`crate::win32::process::Process::last_error`] rather than an alias for it.
//! Windows keeps them separate too: `WSASetLastError` and `SetLastError` are
//! different calls onto different storage, and a host that merged them would
//! have a failed `OpenEventA` show up as a socket error.

use mbbs_machine::m32::{Machine, Memory};

use crate::win32::kernel32::Answer;
use crate::win32::process::Process;

/// Answer a `WSOCK32.dll` import, or `None` for one still unimplemented.
pub fn dispatch(
    process: &mut Process,
    machine: &mut Machine,
    mem: &mut Memory,
    symbol: &str,
) -> Option<Answer> {
    match symbol {
        // int WSAGetLastError(void)
        //
        // Zero, meaning no error, because nothing on this host has produced a
        // Winsock error -- there is no socket to fail. Real state rather than a
        // constant so that `WSASetLastError` below has somewhere to put what it
        // is given; a setter whose value no getter can return is the
        // half-generator mistake `crt.rs` documents for `srand`.
        "WSAGetLastError" => Some(Answer::stdcall(process.wsa_last_error, 0)),
        // void WSASetLastError(int iError)
        "WSASetLastError" => {
            let code = machine.arg_u32(mem.stack(), 0);
            process.wsa_last_error = code;
            Some(Answer::stdcall(0, 1))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Winsock error slot is not the Win32 one. Merging them would report
    /// a failed event open as a socket failure.
    #[test]
    fn the_winsock_error_slot_is_separate_from_the_win32_one() {
        let mut p = Process::new("X.EXE", &[]);
        assert_eq!(p.wsa_last_error, 0, "nothing has failed yet");

        p.last_error = crate::win32::process::ERROR_FILE_NOT_FOUND;
        assert_eq!(
            p.wsa_last_error, 0,
            "a Win32 error does not become a Winsock error"
        );

        p.wsa_last_error = 10054;
        assert_eq!(
            p.last_error,
            crate::win32::process::ERROR_FILE_NOT_FOUND,
            "and a Winsock error does not overwrite the Win32 one"
        );
    }
}
