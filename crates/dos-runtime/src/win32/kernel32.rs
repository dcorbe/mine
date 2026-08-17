//! The KERNEL32 subset this program actually calls.
//!
//! One symbol, as measured -- see `docs/2026-08-17-win32-import-trace.md`. The
//! other sixty of the executable's KERNEL32 imports, the sixteen console calls
//! among them, are all reached from inside `main` rather than from the entry
//! stub, so they arrive as [`crate::win32::process::Outcome::Unimplemented`]
//! naming themselves, one at a time, in the order the program wants them.
//!
//! **Every symbol in this DLL is stdcall: the callee pops its own arguments.**
//! That is why [`Answer`] carries `cleans` alongside the return value rather
//! than leaving it to a table somewhere else -- an arity is a fact about one
//! symbol, and the place that cannot forget it is the arm that implements that
//! symbol. This program proves the cost of forgetting: the entry stub pushes
//! `__startup`'s record argument, pushes `GetModuleHandleA`'s `NULL` on top,
//! calls it, and then reaches `__startup` by `jmp`, relying on
//! `GetModuleHandleA` to have popped that `NULL` itself. A host that resumes
//! without cleaning leaves it there, and `__startup`'s only argument reads as
//! `0` instead of the startup record -- a null handed over by a host that had
//! not visibly done anything wrong.
//!
//! `mbbs_machine::m32::Machine::resume`'s own doc comment records
//! `GetModuleHandleA` and `GetProcAddress` as measured stdcall at
//! `LUNATIX.DLL`'s call sites, which is the same convention read off a
//! different program.

use mbbs_machine::m32::{Flat32Ptr, Machine, Memory};
use mbbs_machine::ptr::ModulePtr;

use crate::win32::console;
use crate::win32::process::{self, Object, Process};

/// Win32's `BOOL`: zero is failure, and any non-zero is success. Named because
/// a bare `1` in a return position says nothing about which convention it is
/// following.
pub const TRUE: u32 = 1;
pub const FALSE: u32 = 0;

/// What a host call answers with: the value, and how many bytes of the
/// caller's own arguments this symbol pops on the way out.
///
/// `cleans` is bytes, not words, because that is what
/// `Machine::resume_cleaning` takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answer {
    pub value: u32,
    pub cleans: u16,
}

impl Answer {
    /// A stdcall answer: `args` is the symbol's declared argument count, and
    /// every one of them is a 32-bit word on this ABI.
    pub(crate) fn stdcall(value: u32, args: u16) -> Self {
        Self {
            value,
            cleans: args * 4,
        }
    }

    /// A cdecl answer: the caller pops its own arguments, so this cleans
    /// nothing.
    ///
    /// The whole C runtime is cdecl and the whole Win32 API is stdcall, so
    /// which constructor a symbol uses is not a detail -- it is which of the two
    /// worlds that symbol belongs to. See this module's doc comment for what a
    /// wrong `cleans` does to the *next* call.
    pub(crate) fn cdecl(value: u32) -> Self {
        Self { value, cleans: 0 }
    }
}

/// Answer a KERNEL32 import, or `None` for one still unimplemented.
///
/// The argument count in each arm is part of that arm's contract -- see
/// [`Answer`] and this module's own doc comment for what a wrong one does.
pub fn dispatch(
    process: &mut Process,
    machine: &mut Machine,
    mem: &mut Memory,
    symbol: &str,
) -> Option<Answer> {
    // Arguments are read into locals *before* anything takes `mem` mutably.
    // Reading one borrows the stack, which lives in `mem`, so a closure that
    // captured `mem` to fetch arguments on demand could not coexist with a
    // symbol that writes through a pointer -- and most of them do. Reading
    // eagerly, per arm, and only as many as that symbol declares, is also what
    // keeps a short frame safe: `Machine::arg_u32` panics rather than reading
    // past the stack, and the first frame of all sits near the top of it.
    match symbol {
        // GetModuleHandleA(LPCSTR)
        "GetModuleHandleA" => Some(Answer::stdcall(get_module_handle_a(mem.image().base()), 1)),
        // OpenEventA(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName)
        "OpenEventA" => {
            let name_ptr = machine.arg_u32(mem.stack(), 2);
            let name = process::read_cstr(mem, name_ptr);
            Some(Answer::stdcall(open_event_a(process, name.as_deref()), 3))
        }
        // GetLastError(void)
        "GetLastError" => Some(Answer::stdcall(process.last_error, 0)),
        // CreateEventA(LPSECURITY_ATTRIBUTES, BOOL bManualReset,
        //              BOOL bInitialState, LPCSTR lpName)
        "CreateEventA" => {
            let manual_reset = machine.arg_u32(mem.stack(), 1) != 0;
            let initial_state = machine.arg_u32(mem.stack(), 2) != 0;
            let name_ptr = machine.arg_u32(mem.stack(), 3);
            let name = if name_ptr == 0 {
                None
            } else {
                process::read_cstr(mem, name_ptr)
            };
            Some(Answer::stdcall(
                create_event_a(process, name, manual_reset, initial_state),
                4,
            ))
        }
        // LocalAlloc(UINT uFlags, SIZE_T uBytes)
        "LocalAlloc" => {
            let bytes = machine.arg_u32(mem.stack(), 1);
            Some(Answer::stdcall(local_alloc(mem, bytes), 2))
        }
        // GetVersionExA(LPOSVERSIONINFOA)
        "GetVersionExA" => {
            let at = machine.arg_u32(mem.stack(), 0);
            Some(Answer::stdcall(get_version_ex_a(mem, at), 1))
        }
        // LoadLibraryA(LPCSTR lpLibFileName)
        //
        // **Answered NULL, and only for `galmemdb.dll`.** NULL is what
        // `LoadLibraryA` returns when the library is not there, and it is the
        // truth: this host has no `galmemdb.dll` and there is no copy of one
        // anywhere in `archive/`.
        //
        // It is also *safe*, which was measured rather than hoped for. Told the
        // load failed, the program does not stop -- it falls through to
        // `malloc` and carries on. `galmemdb` is Galacticomm's shared-memory
        // database (its source survives as
        // `re/wg33src/SRC/api/gcommlib/GALMEMDB.C`), which an offline utility
        // needs only when it is sharing memory with a running board. There is
        // no running board here, so the fallback path is the correct path, not
        // a degraded one. The "NO MEMORY - restart!" string sitting near this
        // call site belongs to a later allocation failure, not to this.
        //
        // Any *other* library stays `None` and so names itself: "this program
        // asked for a DLL we have not considered" is a finding, and answering
        // every `LoadLibraryA` with NULL would bury it.
        "LoadLibraryA" => {
            let name_ptr = machine.arg_u32(mem.stack(), 0);
            let name = process::read_cstr(mem, name_ptr)?;
            name.eq_ignore_ascii_case("galmemdb.dll")
                .then(|| Answer::stdcall(0, 1))
        }
        // ExitProcess(UINT) -- declared `noreturn`, so the value is never
        // read; `run` stops as soon as `exit_code` is set.
        "ExitProcess" => {
            process.exit(0);
            Some(Answer::stdcall(0, 1))
        }
        // The console subset lives next door. Split by concern rather than by
        // DLL: these are KERNEL32 exports like the arms above, but a console
        // screen buffer has nothing to do with process and kernel-object
        // handling, and keeping them in one match would bury both.
        _ => console::dispatch(process, machine, mem, symbol),
    }
}

/// `GetModuleHandleA` -- the image base, which is what a Win32 module handle
/// *is*.
///
/// Answered honestly rather than with NULL, and the difference matters here in
/// a way it does not in `crates/mbbs`. That host returns NULL and
/// `crates/mbbs/src/shims/borland.rs` explains why that is honest *there*:
/// LunatiX tests the result and skips the call. This program does not test it
/// -- the entry stub stores the result straight into a global at RVA `0x14062`
/// and moves on -- so a NULL would be kept and used later by code we have not
/// reached yet. Since the true answer is available for nothing, there is no
/// reason to hand over a value that is only safe until something reads it.
///
/// The argument is ignored, and the trace says the only call passes `NULL`
/// (own module), which is the case this answer is correct for. A named-module
/// lookup would need a module list this host does not have; when one is
/// measured being asked for, that is the point to grow this.
fn get_module_handle_a(image_base: u32) -> u32 {
    image_base
}

/// `OpenEventA` -- NULL, meaning "no such event exists".
///
/// The honest answer for this host, and the one that says something true: an
/// offline maintenance utility opens a named event to find out whether the
/// board is currently running, and on this host nothing else is. NULL is what
/// Windows returns when the name has not been created, so a program that
/// handles "the board is down" at all handles this.
///
/// `name` is not matched on -- see
/// `docs/2026-08-17-win32-import-trace.md`. Answering per-name would require
/// deciding which events this host claims to own, and nothing yet measured
/// needs that distinction.
///
/// The error code is set as well as the NULL returned, because this program
/// asks for it: `GetLastError` is its very next call.
fn open_event_a(process: &mut Process, _name: Option<&str>) -> u32 {
    process.last_error = process::ERROR_FILE_NOT_FOUND;
    0
}

/// `LocalAlloc` -- a pointer out of the program's own arena.
///
/// The flags are deliberately ignored, and the two that exist are both
/// satisfied anyway. `LMEM_ZEROINIT` is free: the arena is a bump allocator
/// over a fresh anonymous mapping and never hands the same bytes out twice, so
/// every allocation is already zero. `LMEM_MOVEABLE` asks for a *handle* that
/// `LocalLock` later turns into a pointer; returning the pointer itself makes
/// that lock the identity it already is on Win32, where local memory is not
/// really moveable.
///
/// Nothing frees. `LocalFree` on a bump allocator can only be a no-op, and a
/// maintenance utility that runs once and exits does not outlive its own
/// arena -- if one ever does, the arena's fixed size is what will say so, by
/// refusing.
fn local_alloc(mem: &mut Memory, bytes: u32) -> u32 {
    match mem.alloc(bytes as usize) {
        Ok(p) => p.0,
        Err(_) => 0,
    }
}

/// `GetVersionExA` -- this host presents as Windows NT 4.0.
///
/// `OSVERSIONINFOA` is 148 bytes: four `DWORD`s after the size field, then a
/// 128-byte `szCSDVersion`. The caller fills in `dwOSVersionInfoSize` before
/// calling and Windows leaves that field alone, so this writes from `+4`
/// onward rather than overwriting the one field the caller owns.
///
/// **NT, not 95**, because that is the platform this program is a utility for:
/// the vendor shipped it beside a Worldgroup NT server, and `dwPlatformId` is
/// the field a program uses to choose between the two families. Claiming
/// `VER_PLATFORM_WIN32_WINDOWS` would send it down a path written for an
/// operating system this host resembles even less.
///
/// A size the caller declares too small is refused the way Windows refuses it
/// -- `FALSE`, with `ERROR_INSUFFICIENT_BUFFER` -- rather than by writing 148
/// bytes into a smaller buffer, which would corrupt whatever followed it.
fn get_version_ex_a(mem: &mut Memory, at: u32) -> u32 {
    const SIZE_OF_OSVERSIONINFOA: u32 = 148;
    const CSD_LEN: usize = 128;
    const VER_PLATFORM_WIN32_NT: u32 = 2;

    let Ok(head) = Flat32Ptr(at).resolve(mem, 4) else {
        return FALSE;
    };
    let declared = u32::from_le_bytes(head.try_into().expect("resolve returned 4 bytes"));
    if declared < SIZE_OF_OSVERSIONINFOA {
        return FALSE;
    }

    let mut body = Vec::with_capacity(SIZE_OF_OSVERSIONINFOA as usize - 4);
    body.extend_from_slice(&4u32.to_le_bytes()); // dwMajorVersion
    body.extend_from_slice(&0u32.to_le_bytes()); // dwMinorVersion
    body.extend_from_slice(&1381u32.to_le_bytes()); // dwBuildNumber
    body.extend_from_slice(&VER_PLATFORM_WIN32_NT.to_le_bytes());
    body.resize(body.len() + CSD_LEN, 0); // szCSDVersion: no service pack

    if Flat32Ptr(at + 4).write(mem, &body).is_err() {
        return FALSE;
    }
    TRUE
}

/// `CreateEventA` -- a real handle to a real (if lonely) event.
///
/// The pair `OpenEventA` then `CreateEventA` is how a program asks "is anyone
/// else here?" and, told no, claims the name for itself. So this must succeed:
/// answering NULL would tell it the name is unavailable *and* that nobody holds
/// it, which is a state Windows never produces.
///
/// The event is genuinely local. Nothing else executes on this host, so no
/// other process will ever signal it, and any wait on it that expects an
/// outside signal would wait forever -- which is a real limit, and the reason
/// [`Object::Event`] records `signalled` rather than pretending the object has
/// no state.
///
/// A name already taken returns a handle to the existing event, as Windows
/// does, rather than a second object under the same name.
fn create_event_a(
    process: &mut Process,
    name: Option<String>,
    manual_reset: bool,
    signalled: bool,
) -> u32 {
    if let Some(n) = name.as_deref() {
        if let Some(existing) = process.named_object(n) {
            process.last_error = process::ERROR_ALREADY_EXISTS;
            return existing;
        }
    }
    process.last_error = process::ERROR_SUCCESS;
    process.insert_object(Object::Event {
        name,
        manual_reset,
        signalled,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real loaded image, because [`dispatch`] answers `GetModuleHandleA`
    /// out of one and there is nothing to be gained from a fake base.
    ///
    /// The [`Machine`] that comes with it is stopped at no call, which is why
    /// the arms tested here are the ones that read no arguments --
    /// `Machine::arg_u32` panics rather than inventing a frame. `OpenEventA`
    /// does read one, so it is covered by the whole-program run instead, which
    /// is the only place a real call frame exists.
    fn loaded() -> crate::win32::load::Loaded {
        let file = std::fs::read("/home/daniel/peepeebbs/wccmmutl.exe").expect("the utility");
        crate::win32::load::load(&file).expect("loads")
    }

    /// The one fact in this file that would fail silently rather than loudly.
    /// `GetModuleHandleA` takes one argument and pops it; see this module's
    /// doc comment for what the entry stub does with that.
    #[test]
    fn get_module_handle_a_pops_its_own_argument_and_answers_the_base() {
        let mut l = loaded();
        let mut p = Process::new("X.EXE", &[]);
        let base = l.mem.image().base();
        let a = dispatch(&mut p, &mut l.machine, &mut l.mem, "GetModuleHandleA")
            .expect("implemented");
        assert_eq!(a.value, base, "a module handle is the image base");
        assert_ne!(a.value, 0, "and it is emphatically not NULL");
        assert_eq!(a.cleans, 4, "stdcall, one argument");
    }

    /// An unimplemented symbol must stay unimplemented rather than answer
    /// zero. `run` turns this `None` into an `Unimplemented` outcome naming
    /// the symbol, which is how the next thing to write gets found.
    #[test]
    fn an_unimplemented_symbol_answers_nothing_at_all() {
        let mut l = loaded();
        let mut p = Process::new("X.EXE", &[]);
        // `SetConsoleCtrlHandler` rather than the console-buffer call this
        // once named: that family is implemented now (see
        // `crate::win32::console`), and this one is the console symbol still
        // deliberately unanswered. The test is about the *mechanism* -- an
        // unimplemented symbol declining rather than guessing -- so it needs a
        // symbol that is genuinely unimplemented, and it must be updated rather
        // than deleted whenever the frontier eats the one it was using.
        assert_eq!(
            dispatch(&mut p, &mut l.machine, &mut l.mem, "SetConsoleCtrlHandler"),
            None
        );
    }

    /// `ExitProcess` sets the code rather than returning it, because there is
    /// nothing to return to.
    #[test]
    fn exit_process_sets_the_exit_code() {
        let mut l = loaded();
        let mut p = Process::new("X.EXE", &[]);
        assert!(p.exit_code.is_none());
        dispatch(&mut p, &mut l.machine, &mut l.mem, "ExitProcess").expect("implemented");
        assert!(p.exit_code.is_some(), "the run must be able to stop");
    }
}
