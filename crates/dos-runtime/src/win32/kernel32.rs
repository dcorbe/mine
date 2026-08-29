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

use mbbs_machine::m32::{Flat32Ptr, Machine, Memory, Regs};
use mbbs_machine::ptr::ModulePtr;

use crate::win32::console;
use crate::win32::process::{self, Object, Process};
use crate::win32::wintime;

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
        "GetModuleHandleA" => {
            let base = mem
                .image()
                .expect("a PE program always has its image loaded before any import is answered")
                .base();
            Some(Answer::stdcall(get_module_handle_a(base), 1))
        }
        // OpenEventA(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName)
        "OpenEventA" => {
            let name_ptr = machine.arg_u32(mem.stack(), 2);
            let name = process::read_cstr(mem, name_ptr);
            Some(Answer::stdcall(open_event_a(process, name.as_deref()), 3))
        }
        // GetLastError(void)
        "GetLastError" => Some(Answer::stdcall(process.last_error, 0)),
        // RtlUnwind(PVOID TargetFrame, PVOID TargetIp,
        //           PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue)
        "RtlUnwind" => {
            let target_frame = machine.arg_u32(mem.stack(), 0);
            let target_ip = machine.arg_u32(mem.stack(), 1);
            let return_value = machine.arg_u32(mem.stack(), 3);
            match rtl_unwind(machine, mem, target_frame, target_ip, return_value) {
                Ok(regs) => {
                    process.transfer = Some(regs);
                    // The value is never delivered -- `Process::transfer`
                    // diverts the module before `run` can resume it -- but
                    // every arm must answer something. The arity is the real
                    // one so that a reader is not misled about the ABI.
                    Some(Answer::stdcall(0, 4))
                }
                Err(why) => {
                    process.unwind_gap = Some(why);
                    None
                }
            }
        }
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
        // CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess,
        //             DWORD dwShareMode, LPSECURITY_ATTRIBUTES,
        //             DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
        //             HANDLE hTemplateFile)
        //
        // Two different things wear this one name. `CONIN$` and `CONOUT$` are
        // console *devices* and get a console handle; everything else is a path
        // and goes through the root jail. The program does both -- it opens
        // `CONIN$` during startup and `GALCAT.OUT` later -- so the split has to
        // be here rather than in either module alone.
        "CreateFileA" => {
            let name_ptr = machine.arg_u32(mem.stack(), 0);
            let access = machine.arg_u32(mem.stack(), 1);
            let disposition = machine.arg_u32(mem.stack(), 4);
            let name = process::read_cstr(mem, name_ptr)?;

            if let Some(input) = console::console_device(&name) {
                let mode = console::default_mode(input);
                let handle = process.insert_object(Object::Console { input, mode });
                return Some(Answer::stdcall(handle, 7));
            }
            let handle = match process
                .streams
                .create_file(name.as_bytes(), access, disposition)
            {
                Some(dos) => process.insert_object(Object::File { dos }),
                // INVALID_HANDLE_VALUE, not NULL -- `CreateFileA` is the one
                // Win32 opener that reports failure as -1, and a caller testing
                // against the wrong sentinel concludes it succeeded.
                None => {
                    process.last_error = process::ERROR_FILE_NOT_FOUND;
                    console::INVALID_HANDLE_VALUE
                }
            };
            Some(Answer::stdcall(handle, 7))
        }
        // FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)
        //
        // Answers a search handle, or `INVALID_HANDLE_VALUE` -- **not NULL**,
        // the same wart `CreateFileA` has. One search at a time, which is what
        // the jail underneath supports; the handle is a constant rather than an
        // index because there is only ever one thing it could refer to, and
        // pretending otherwise would imply concurrent searches work.
        "FindFirstFileA" => {
            let name_ptr = machine.arg_u32(mem.stack(), 0);
            let out = machine.arg_u32(mem.stack(), 1);
            let name = process::read_cstr(mem, name_ptr)?;
            match process.streams.find_first(name.as_bytes()) {
                Some(data) if out != 0 && Flat32Ptr(out).write(mem, &data).is_ok() => {
                    Some(Answer::stdcall(FIND_HANDLE, 2))
                }
                _ => {
                    process.last_error = process::ERROR_FILE_NOT_FOUND;
                    Some(Answer::stdcall(console::INVALID_HANDLE_VALUE, 2))
                }
            }
        }
        // FindNextFileA(HANDLE, LPWIN32_FIND_DATAA) -- FALSE when exhausted.
        "FindNextFileA" => {
            let out = machine.arg_u32(mem.stack(), 1);
            match process.streams.find_next() {
                Some(data) if out != 0 && Flat32Ptr(out).write(mem, &data).is_ok() => {
                    Some(Answer::stdcall(TRUE, 2))
                }
                _ => {
                    // ERROR_NO_MORE_FILES, which is how a caller tells "the
                    // search is finished" from "the search broke".
                    process.last_error = 18;
                    Some(Answer::stdcall(FALSE, 2))
                }
            }
        }
        // FindClose(HANDLE)
        "FindClose" => Some(Answer::stdcall(TRUE, 1)),
        // WriteFile(HANDLE, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
        //           LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED)
        //
        // The out-parameter is not optional when it is non-null: it is how the
        // caller learns a short write happened, and a program that checks it
        // against what it asked for would read an uninitialised local.
        "WriteFile" => {
            let handle = machine.arg_u32(mem.stack(), 0);
            let buf = machine.arg_u32(mem.stack(), 1);
            let len = machine.arg_u32(mem.stack(), 2);
            let count_at = machine.arg_u32(mem.stack(), 3);
            let Some(Object::File { dos }) = process.object(handle) else {
                return Some(Answer::stdcall(FALSE, 5));
            };
            let dos = *dos;
            let Ok(bytes) = Flat32Ptr(buf).resolve(mem, len as usize) else {
                return Some(Answer::stdcall(FALSE, 5));
            };
            let owned = bytes.to_vec();
            let written = process.streams.write_handle(dos, &owned).unwrap_or(0);
            if count_at != 0 {
                let n = u32::try_from(written).unwrap_or(u32::MAX);
                let _ = Flat32Ptr(count_at).write(mem, &n.to_le_bytes());
            }
            Some(Answer::stdcall(u32::from(written == owned.len()), 5))
        }
        // SetFilePointer(HANDLE, LONG lDistanceToMove,
        //                PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod)
        //
        // Answers the new offset, and `INVALID_SET_FILE_POINTER` (-1) on
        // failure -- which is indistinguishable from a legitimate seek to
        // offset `0xffffffff`, a genuine wart in the API that callers resolve
        // with `GetLastError`. `dwMoveMethod` is C's 0/1/2, which is also what
        // the jail takes.
        "SetFilePointer" => {
            let handle = machine.arg_u32(mem.stack(), 0);
            #[allow(clippy::cast_possible_wrap)]
            let distance = i64::from(machine.arg_u32(mem.stack(), 1) as i32);
            #[allow(clippy::cast_possible_truncation)]
            let method = machine.arg_u32(mem.stack(), 3) as u8;
            let Some(Object::File { dos }) = process.object(handle) else {
                return Some(Answer::stdcall(0xffff_ffff, 4));
            };
            let dos = *dos;
            let at = process.streams.seek_handle(dos, distance, method);
            Some(Answer::stdcall(
                at.map_or(0xffff_ffff, |v| u32::try_from(v).unwrap_or(u32::MAX)),
                4,
            ))
        }
        // GetCurrentThread(void) / GetCurrentProcess(void)
        //
        // **Pseudo-handles, and they are constants by definition rather than by
        // convenience.** Windows documents `GetCurrentThread` as always
        // returning `-2` and `GetCurrentProcess` as always returning `-1`;
        // they are not entries in a handle table, they are sentinel values the
        // kernel recognises. Inventing a real handle here would be *less*
        // faithful, not more, and would break any code that compares against
        // the documented constant.
        "GetCurrentThread" => Some(Answer::stdcall(0xffff_fffe, 0)),
        "GetCurrentProcess" => Some(Answer::stdcall(0xffff_ffff, 0)),
        // GetProcessHeap(void)
        //
        // A non-null cookie. Nothing in this host allocates through a Win32
        // heap -- `LocalAlloc` comes out of the arena -- so the value only has
        // to be distinguishable from the NULL that means failure.
        "GetProcessHeap" => Some(Answer::stdcall(HEAP_HANDLE, 0)),
        // CloseHandle(HANDLE) / FreeLibrary(HMODULE)
        //
        // TRUE, and nothing is reclaimed. Handles here index a `Vec` that lives
        // as long as the process, and the one library this host is asked for
        // never loaded. Refusing would be worse than accepting: a program that
        // checks `CloseHandle` and finds it failed has been told its own
        // bookkeeping is broken.
        "CloseHandle" => {
            let handle = machine.arg_u32(mem.stack(), 0);
            // A file handle really is closed -- a descriptor left open is a
            // descriptor leaked, and a program that opens and closes in a loop
            // would exhaust the table. Console and event handles index a `Vec`
            // that lives as long as the process and have nothing to release.
            if let Some(Object::File { dos }) = process.object(handle) {
                let dos = *dos;
                process.streams.close_handle(dos);
            }
            Some(Answer::stdcall(TRUE, 1))
        }
        // FreeLibrary(HMODULE) -- TRUE. The one library this host is asked for
        // never loaded, so there is nothing to release.
        "FreeLibrary" => Some(Answer::stdcall(TRUE, 1)),
        // LocalFree(HLOCAL) -- answers NULL for success, not TRUE.
        //
        // The inverted-looking return is the API's: `LocalFree` gives back the
        // handle on *failure* and NULL on success, so a host answering TRUE
        // would be reporting a failed free every time.
        "LocalFree" => Some(Answer::stdcall(0, 1)),
        // SetConsoleCtrlHandler(PHANDLER_ROUTINE, BOOL bAdd)
        //
        // Accepted and not recorded. The handler fires on Ctrl-C, Ctrl-Break
        // and console close; this host delivers none of those to the guest, so
        // a registered handler could never run and keeping a pointer to it
        // would imply otherwise. Answering FALSE would tell the program it
        // cannot install a handler, which some treat as fatal.
        "SetConsoleCtrlHandler" => Some(Answer::stdcall(TRUE, 2)),
        // lstrlenA / lstrcpyA / lstrcatA / lstrcpynA
        //
        // Win32's own string helpers, which exist because 16-bit Windows had no
        // C runtime. They are *stdcall*, unlike the `cw3220mt` functions of the
        // same shape next door -- a program can call both in one expression,
        // and getting the convention wrong for either corrupts the following
        // call rather than this one.
        "lstrlenA" => {
            let at = machine.arg_u32(mem.stack(), 0);
            let len = process::read_cstr(mem, at)
                .map_or(0, |s| u32::try_from(s.len()).unwrap_or(u32::MAX));
            Some(Answer::stdcall(len, 1))
        }
        "lstrcpyA" | "lstrcatA" => {
            let dest = machine.arg_u32(mem.stack(), 0);
            let src = machine.arg_u32(mem.stack(), 1);
            let mut out = if symbol == "lstrcatA" {
                read_bytes(mem, dest)
            } else {
                Vec::new()
            };
            out.extend_from_slice(&read_bytes(mem, src));
            out.push(0);
            let ok = dest != 0 && Flat32Ptr(dest).write(mem, &out).is_ok();
            Some(Answer::stdcall(if ok { dest } else { 0 }, 2))
        }
        // **`lstrcpynA` is not `strncpy`.** It copies at most `n - 1` bytes and
        // *always* terminates; `strncpy` copies exactly `n` and terminates only
        // if the source was short. Two functions with nearly the same name and
        // opposite guarantees, and this program calls both.
        "lstrcpynA" => {
            let dest = machine.arg_u32(mem.stack(), 0);
            let src = machine.arg_u32(mem.stack(), 1);
            let n = machine.arg_u32(mem.stack(), 2) as usize;
            if dest == 0 || n == 0 {
                return Some(Answer::stdcall(0, 3));
            }
            let mut out = read_bytes(mem, src);
            out.truncate(n - 1);
            out.push(0);
            let ok = Flat32Ptr(dest).write(mem, &out).is_ok();
            Some(Answer::stdcall(if ok { dest } else { 0 }, 3))
        }
        // GetModuleFileNameA(HMODULE, LPSTR lpFilename, DWORD nSize)
        //
        // The program's own path, which is how a DOS-era utility finds its home
        // directory: it reads this back and strips the filename off the end.
        // Answering an empty string would send it looking in the root.
        "GetModuleFileNameA" => {
            let out = machine.arg_u32(mem.stack(), 1);
            let size = machine.arg_u32(mem.stack(), 2) as usize;
            let path = process.args().first().unwrap_or(&"").to_string();
            Some(Answer::stdcall(store_bounded(mem, out, size, &path), 3))
        }
        // GetCurrentDirectoryA(DWORD nBufferLength, LPSTR lpBuffer)
        //
        // Note the argument order is the reverse of `GetModuleFileNameA`'s --
        // the length comes *first* here. That asymmetry is in the API, not a
        // slip, and reading them the same way puts a length where a pointer
        // belongs.
        //
        // Always the root of the jail, spelled as a DOS path. There is no
        // notion of changing directory on this host: every path resolves
        // beneath one descriptor, so the current directory is that descriptor
        // and cannot be anywhere else.
        "GetCurrentDirectoryA" => {
            let size = machine.arg_u32(mem.stack(), 0) as usize;
            let out = machine.arg_u32(mem.stack(), 1);
            Some(Answer::stdcall(store_bounded(mem, out, size, "C:\\"), 2))
        }
        // GetThreadContext(HANDLE hThread, LPCONTEXT lpContext)
        //
        // See [`thread_context`]. This is the one call in this host that
        // cannot be answered fully, and the reason is structural rather than
        // unfinished work.
        "GetThreadContext" => {
            let at = machine.arg_u32(mem.stack(), 1);
            let sp = machine.frame_sp().unwrap_or(0);
            Some(Answer::stdcall(thread_context(mem, at, sp), 2))
        }
        // VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer,
        //              SIZE_T dwLength)
        //
        // The program is validating a pointer: it asks whether an address is
        // committed before dereferencing it. So the answer must be *measured
        // against this host's real mappings*, not a constant "yes" -- a host
        // that claimed every address was committed would turn a caught bad
        // pointer into a fault, which is the opposite of what the caller is
        // asking for.
        "VirtualQuery" => {
            let address = machine.arg_u32(mem.stack(), 0);
            let out = machine.arg_u32(mem.stack(), 1);
            let len = machine.arg_u32(mem.stack(), 2);
            Some(Answer::stdcall(virtual_query(mem, address, out, len), 3))
        }
        // FileTimeToLocalFileTime(const FILETIME*, LPFILETIME)
        // LocalFileTimeToFileTime(const FILETIME*, LPFILETIME)
        //
        // A `FILETIME` carries no timezone, so these two are the only thing
        // that says which one a given value is in. Getting the direction
        // backwards shifts every timestamp by twice the local offset -- and is
        // invisible in UTC, which is where tests tend to run.
        "FileTimeToLocalFileTime" | "LocalFileTimeToFileTime" => {
            let src = machine.arg_u32(mem.stack(), 0);
            let dst = machine.arg_u32(mem.stack(), 1);
            let Some(ticks) = read_filetime(mem, src) else {
                return Some(Answer::stdcall(FALSE, 2));
            };
            let secs = wintime::unix_from_ticks(ticks);
            let offset = wintime::utc_offset(secs);
            let shifted = if symbol == "FileTimeToLocalFileTime" {
                secs + offset
            } else {
                secs - offset
            };
            Some(Answer::stdcall(
                write_filetime(mem, dst, wintime::ticks_from_unix(shifted)),
                2,
            ))
        }
        // FileTimeToSystemTime(const FILETIME*, LPSYSTEMTIME)
        "FileTimeToSystemTime" => {
            let src = machine.arg_u32(mem.stack(), 0);
            let dst = machine.arg_u32(mem.stack(), 1);
            let Some(ticks) = read_filetime(mem, src) else {
                return Some(Answer::stdcall(FALSE, 2));
            };
            let secs = wintime::unix_from_ticks(ticks);
            Some(Answer::stdcall(system_time_at(mem, dst, secs), 2))
        }
        // FileTimeToDosDateTime(const FILETIME*, LPWORD lpFatDate,
        //                       LPWORD lpFatTime)
        //
        // Two separate `WORD` out-parameters, not one `DWORD`: writing four
        // bytes through the first would overwrite the second, which on a stack
        // frame is the next local.
        "FileTimeToDosDateTime" => {
            let src = machine.arg_u32(mem.stack(), 0);
            let date_at = machine.arg_u32(mem.stack(), 1);
            let time_at = machine.arg_u32(mem.stack(), 2);
            let Some(ticks) = read_filetime(mem, src) else {
                return Some(Answer::stdcall(FALSE, 3));
            };
            let (date, time) = wintime::dos_from_unix(wintime::unix_from_ticks(ticks));
            let ok = write_word(mem, date_at, date) && write_word(mem, time_at, time);
            Some(Answer::stdcall(u32::from(ok), 3))
        }
        // DosDateTimeToFileTime(WORD wFatDate, WORD wFatTime, LPFILETIME)
        //
        // The two `WORD`s arrive as separate stack slots -- each promoted to a
        // full word by the ABI -- so this is three arguments, not two.
        "DosDateTimeToFileTime" => {
            #[allow(clippy::cast_possible_truncation)]
            let date = machine.arg_u32(mem.stack(), 0) as u16;
            #[allow(clippy::cast_possible_truncation)]
            let time = machine.arg_u32(mem.stack(), 1) as u16;
            let dst = machine.arg_u32(mem.stack(), 2);
            let ticks = wintime::ticks_from_unix(wintime::unix_from_dos(date, time));
            Some(Answer::stdcall(write_filetime(mem, dst, ticks), 3))
        }
        // GetLocalTime(LPSYSTEMTIME)
        //
        // Local, not UTC, and the distinction is not academic: this program
        // stamps records an operator reads. `GetSystemTime` is deliberately
        // *not* answered here -- it is not in this executable's import table at
        // all, so an arm for it could never fire.
        "GetLocalTime" => {
            let at = machine.arg_u32(mem.stack(), 0);
            Some(Answer::stdcall(system_time(mem, at, true), 1))
        }
        // IsBadReadPtr(LPCVOID, UINT_PTR) / IsBadWritePtr(LPVOID, UINT_PTR)
        // IsBadStringPtrA(LPCSTR, UINT_PTR) / IsBadCodePtr(FARPROC)
        //
        // **These return TRUE for a pointer that is BAD.** The sense is
        // inverted from how the names read, and a host that got it backwards
        // would tell the program every pointer it holds is unusable -- or, far
        // worse, that a null one is fine.
        //
        // Answered against this host's real mappings, like `VirtualQuery`
        // above, because the whole purpose of the call is to find out what is
        // actually there.
        "IsBadReadPtr" | "IsBadWritePtr" => {
            let at = machine.arg_u32(mem.stack(), 0);
            let len = machine.arg_u32(mem.stack(), 1);
            Some(Answer::stdcall(u32::from(!readable(mem, at, len)), 2))
        }
        // The string form stops at the terminator rather than requiring the
        // whole `ucchMax` to be mapped: a valid string near the end of a
        // mapping is not a bad pointer, and requiring the full length would
        // reject it.
        "IsBadStringPtrA" => {
            let at = machine.arg_u32(mem.stack(), 0);
            let max = machine.arg_u32(mem.stack(), 1);
            let good = at != 0
                && Flat32Ptr(at)
                    .read_cstr(mem)
                    .is_ok_and(|s| u32::try_from(s.len()).unwrap_or(u32::MAX) <= max);
            Some(Answer::stdcall(u32::from(!good), 2))
        }
        "IsBadCodePtr" => {
            let at = machine.arg_u32(mem.stack(), 0);
            Some(Answer::stdcall(u32::from(!readable(mem, at, 1)), 1))
        }
        // GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
        //
        // **Resolved against the image's real export table.** An executable
        // with exports looks like a mistake and is not one: `wccmmutl.exe` has
        // an `.edata` section, and it calls
        // `GetProcAddress(GetModuleHandleA(NULL), "_input")` -- it looks
        // symbols up in *itself*. Answering a fabricated address would hand the
        // program a pointer it is about to call.
        //
        // A name this image does not export answers NULL, which is what
        // Windows does and what the caller is checking for. Ordinal lookups
        // (a `lpProcName` below 0x10000 is an ordinal, not a pointer) are not
        // answered: nothing has been measured using one, and treating an
        // ordinal as an address would read a string from wherever page zero
        // happens to reach.
        "GetProcAddress" => {
            let name_ptr = machine.arg_u32(mem.stack(), 1);
            if name_ptr < 0x1_0000 {
                return Some(Answer::stdcall(0, 2));
            }
            let name = process::read_cstr(mem, name_ptr)?;
            let found = process
                .exports
                .iter()
                .find(|(n, _)| *n == name)
                .map_or(0, |(_, at)| *at);
            Some(Answer::stdcall(found, 2))
        }
        // Sleep(DWORD dwMilliseconds)
        //
        // **Returns immediately, and that cannot change an outcome here.**
        // `Sleep` yields to other runnable threads; this host has none -- one
        // guest, one thread, no board, no second process. There is nothing that
        // could make progress during the wait, so the only thing a faithful
        // sleep would add is wall-clock time, and a retry loop that sleeps 10ms
        // a thousand times would take ten seconds to reach the same place.
        //
        // The count is kept because a program spinning on `Sleep` looks
        // identical to one making progress unless someone can see the number.
        "Sleep" => {
            process.slept_calls += 1;
            Some(Answer::stdcall(0, 1))
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
            ABSENT_LIBRARIES
                .iter()
                .any(|l| name.eq_ignore_ascii_case(l))
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

/// Libraries this host does not have and that the program copes without.
///
/// Both are Galacticomm's own optional server components, neither exists in
/// `archive/`, and **for each, the program continuing was measured rather than
/// hoped for** -- told the load failed, it takes a fallback path and carries on
/// rather than stopping:
///
/// - `galmemdb.dll` is the shared-memory database, needed only when a utility
///   is sharing memory with a running board. There is no board here.
/// - `wgswelog.dll` is the Worldgroup event-log helper, reached from the
///   program's error-reporting path after `RegisterEventSourceA`. Its absence
///   costs a log entry this host has nowhere to put anyway -- and
///   `advapi32::ReportEventA` keeps the message regardless.
///
/// This is a list rather than a wildcard on purpose. Any library *not* named
/// here stays `None` and so names itself, because "this program wants a DLL
/// nobody has considered" is a finding, and answering every `LoadLibraryA` with
/// NULL would bury it.
const ABSENT_LIBRARIES: [&str; 2] = ["galmemdb.dll", "wgswelog.dll"];

/// `CONTEXT_i386 | CONTEXT_EXTENDED_REGISTERS` -- the flag that decides how big
/// the caller's buffer has to be.
const CONTEXT_EXTENDED_REGISTERS: u32 = 0x0000_0020;

/// Bytes of `CONTEXT` up to and including `SegSs`, which is everything
/// `CONTEXT_FULL` covers.
///
/// **204, and the program agrees.** Its own frame reserves exactly `0xCC`
/// bytes (`add esp,0xffffff34` at `0x40e2dc`) and it passes `[ebp-0xcc]`, with
/// `ContextFlags` set to `0x10007` -- `CONTEXT_i386|CONTROL|INTEGER|SEGMENTS`,
/// and pointedly *not* `FLOATING_POINT` or `EXTENDED_REGISTERS`. A host that
/// wrote the full 716-byte `CONTEXT` here would run 512 bytes past the end of a
/// stack frame, which is a memory corruption bug caused by being too thorough.
const CONTEXT_THROUGH_SEGSS: usize = 0xCC;

/// The whole x86 `CONTEXT`, including `ExtendedRegisters[512]`.
const CONTEXT_FULL_SIZE: usize = 0x2CC;

/// Offsets of the fields this host can actually fill in.
const CTX_EFLAGS: usize = 0xC0;
const CTX_ESP: usize = 0xC4;

/// `GetThreadContext` -- the register file of a thread.
///
/// **This host cannot answer it truthfully, and the shortfall is structural.**
/// `mbbs_machine::m32::Machine` exposes `frame_sp`, `stack_base` and
/// `stack_range` and *no* general register accessors -- there is no way to read
/// `EAX`, `EBX`, `EBP` or `EIP` at the point of an import call. That is the same
/// boundary the phase plan recorded for `_longjmp`, which needs register
/// *setters* the machine also lacks. Adding either is a change in
/// `mbbs-machine`, deliberately out of scope, and explicitly not to be done
/// speculatively.
///
/// So: `ContextFlags` is echoed, `Esp` is filled in from `frame_sp` because it
/// is genuinely known, `EFlags` gets the ordinary `IF`-set value, and **every
/// other register is zero**.
///
/// Zero is chosen rather than a plausible-looking value on purpose. Both call
/// sites hand this straight to a stack walker (`0x411851`) together with a
/// message string and a code address -- this is the program's crash-reporting
/// path. A walker given `Ebp = 0` stops immediately and produces an empty
/// backtrace, which is *true*: this host cannot supply one. A walker given
/// invented frame pointers would produce a fabricated backtrace, or fault
/// chasing them.
fn thread_context(mem: &mut Memory, at: u32, esp: u32) -> u32 {
    if at == 0 {
        return FALSE;
    }
    let Ok(head) = Flat32Ptr(at).resolve(mem, 4) else {
        return FALSE;
    };
    let flags = u32::from_le_bytes(head.try_into().expect("4 bytes"));

    // Only as far as the caller asked for. See `CONTEXT_THROUGH_SEGSS`.
    let len = if flags & CONTEXT_EXTENDED_REGISTERS != 0 {
        CONTEXT_FULL_SIZE
    } else {
        CONTEXT_THROUGH_SEGSS
    };

    let mut b = vec![0u8; len];
    b[0..4].copy_from_slice(&flags.to_le_bytes());
    // `IF` set and bit 1 always one, which is what a running thread's flags
    // look like. Zero would be a state no x86 is ever in.
    b[CTX_EFLAGS..CTX_EFLAGS + 4].copy_from_slice(&0x202u32.to_le_bytes());
    b[CTX_ESP..CTX_ESP + 4].copy_from_slice(&esp.to_le_bytes());

    if Flat32Ptr(at).write(mem, &b).is_err() {
        return FALSE;
    }
    TRUE
}

/// The one search handle `FindFirstFileA` hands out.
///
/// A constant rather than an index because the jail supports one search at a
/// time -- see `dos::files`'s own note on why its search state is host-side and
/// singular. Handing out distinct handles would imply concurrent searches work.
const FIND_HANDLE: u32 = 0x0046_494e;

/// The cookie `GetProcessHeap` answers with.
///
/// Any non-zero value would do; a recognisable one makes it obvious in a trace
/// that a heap handle is what is being passed around.
const HEAP_HANDLE: u32 = 0x0048_4541;

/// A C string's bytes, or empty for a pointer that resolves nowhere.
fn read_bytes(mem: &Memory, at: u32) -> Vec<u8> {
    if at == 0 {
        return Vec::new();
    }
    Flat32Ptr(at)
        .read_cstr(mem)
        .map_or_else(|_| Vec::new(), <[u8]>::to_vec)
}

/// Store `text` into a caller's buffer of `size` bytes and answer the length
/// written, excluding the terminator.
///
/// **Truncates rather than refusing**, which is what the Win32 "get a string"
/// calls do: they fill what they can and report how much. A host that answered
/// zero for a short buffer would look like failure to a caller that is prepared
/// to grow its buffer and retry, and this shape of call is exactly where that
/// pattern appears.
fn store_bounded(mem: &mut Memory, out: u32, size: usize, text: &str) -> u32 {
    if out == 0 || size == 0 {
        return 0;
    }
    let bytes = text.as_bytes();
    let room = size - 1;
    let n = bytes.len().min(room);
    let mut buf = bytes[..n].to_vec();
    buf.push(0);
    if Flat32Ptr(out).write(mem, &buf).is_err() {
        return 0;
    }
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Whether `len` bytes at `at` are actually there.
///
/// A zero length is readable at any non-null address, which is what Windows
/// says: `IsBadReadPtr(p, 0)` is always FALSE. A null pointer is never
/// readable, however short the run.
fn readable(mem: &Memory, at: u32, len: u32) -> bool {
    if at == 0 {
        return false;
    }
    if len == 0 {
        return true;
    }
    Flat32Ptr(at).resolve(mem, len as usize).is_ok()
}

/// One page, as Win32 reports granularity.
const PAGE: u32 = 0x1000;

/// The first address above the user-mode half of the address space.
///
/// NT's `MM_HIGHEST_USER_ADDRESS` is `0x7FFEFFFF`, and **`VirtualQuery` fails
/// above it**. That failure is not an edge case to be tidied away -- it is what
/// *terminates* a caller walking the address space, and this program does
/// exactly that walk to dump a memory map into its crash report. A host that
/// answered for kernel addresses too would leave the walk running until it
/// wrapped, which is the 16,514-line loop this produced before the limit
/// existed.
const USER_ADDRESS_LIMIT: u32 = 0x7fff_0000;

/// `MEMORY_BASIC_INFORMATION`'s size on 32-bit Windows, and the length the
/// caller must ask for.
const MBI_SIZE: usize = 28;

/// `VirtualQuery` -- describe the mapping containing `address`.
///
/// ```text
/// off  field                off  field
///   0  BaseAddress           4  AllocationBase
///   8  AllocationProtect    12  RegionSize
///  16  State                20  Protect
///  24  Type
/// ```
///
/// **`RegionSize` is measured, not guessed.** The extent of the mapping is
/// found by binary-searching how far a resolve succeeds from the region base --
/// about two dozen probes, which is cheap and is the only way to answer
/// honestly on a host whose `Memory` exposes resolvability rather than a
/// mapping list. A host that reported a fixed size would tell a program walking
/// the region that it may read past the end of a real allocation.
fn virtual_query(mem: &mut Memory, address: u32, out: u32, len: u32) -> u32 {
    if out == 0 || (len as usize) < MBI_SIZE || address >= USER_ADDRESS_LIMIT {
        return 0;
    }
    let bytes = describe_region(mem, address);
    if Flat32Ptr(out).write(mem, &bytes).is_err() {
        return 0;
    }
    u32::try_from(MBI_SIZE).expect("28 fits")
}

/// The three mappings this host actually has, as `(base, len)`, sorted.
///
/// **Enumerated rather than probed.** An earlier version of this hunted for
/// mapping edges by resolving addresses at exponentially growing offsets, and
/// it was wrong in a way worth recording: mappedness is not monotonic, so a
/// doubling probe steps straight over an image that does not happen to start at
/// a power of two. It reported the whole 2 GB of user space as one free region
/// and the program dutifully printed that. A real `VirtualQuery` reads the
/// kernel's list of mappings; so does this.
fn mappings(mem: &Memory) -> Vec<(u32, u32)> {
    let image = mem
        .image()
        .expect("a PE program always has its image loaded before any import is answered");
    let image_len = u32::try_from(image.as_slice().len()).unwrap_or(0);
    let (arena, arena_len) = mem.arena_range();
    let (stack, stack_len) = mem.stack_range();
    let mut all = vec![
        (image.base(), image_len),
        (arena, u32::try_from(arena_len).unwrap_or(0)),
        (stack, u32::try_from(stack_len).unwrap_or(0)),
    ];
    all.retain(|&(_, len)| len > 0);
    all.sort_unstable();
    all
}

/// The `MEMORY_BASIC_INFORMATION` bytes for `address`, without storing them.
///
/// Split out from [`virtual_query`] so that what the host *says* about a region
/// can be tested without needing a writable destination in guest memory.
///
/// **Every `RegionSize` is page-aligned and at least one page.** Both halves
/// are load-bearing rather than tidy: this program's own wrapper at `0x41284e`
/// does `if ((RegionSize & 0xfff) == 0xfff) RegionSize++`, so an unaligned
/// `0xFFFFFFFF` increments to zero; and a caller walking the space advances by
/// `RegionSize`, so a zero of any origin is an infinite loop. Both were
/// observed, at 28,314 and 16,514 iterations respectively.
fn describe_region(mem: &Memory, address: u32) -> [u8; MBI_SIZE] {
    let base = address & !(PAGE - 1);
    let maps = mappings(mem);

    // The mapping containing `base`, if any.
    let holder = maps
        .iter()
        .copied()
        .find(|&(start, len)| base >= start && base < start.saturating_add(len));

    let (region_base, region, committed) = match holder {
        Some((start, len)) => {
            let start = start & !(PAGE - 1);
            let end = start.saturating_add(len);
            (start, end.saturating_sub(start), true)
        }
        None => {
            // A free region runs to the next mapping, or to the top of user
            // space when there is none above.
            let next = maps
                .iter()
                .map(|&(start, _)| start & !(PAGE - 1))
                .filter(|&start| start > base)
                .min()
                .unwrap_or(USER_ADDRESS_LIMIT);
            (base, next.saturating_sub(base), false)
        }
    };
    let region = (region.max(PAGE)) & !(PAGE - 1);

    let (state, protect, kind) = if committed {
        // MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE.
        (0x1000u32, 0x04u32, 0x0002_0000u32)
    } else {
        // MEM_FREE, PAGE_NOACCESS, and no type -- Windows leaves `Type` zero
        // for a free region, and a program that switches on it must not see
        // MEM_PRIVATE for memory that is not there.
        (0x0001_0000u32, 0x01u32, 0)
    };

    let mut b = [0u8; MBI_SIZE];
    let put = |b: &mut [u8; MBI_SIZE], off: usize, v: u32| {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    };
    put(&mut b, 0, region_base);
    put(&mut b, 4, if committed { region_base } else { 0 });
    put(&mut b, 8, protect);
    put(&mut b, 12, region);
    put(&mut b, 16, state);
    put(&mut b, 20, protect);
    put(&mut b, 24, kind);
    b
}

/// Read a 64-bit `FILETIME` from guest memory.
fn read_filetime(mem: &Memory, at: u32) -> Option<u64> {
    if at == 0 {
        return None;
    }
    let b = Flat32Ptr(at).resolve(mem, 8).ok()?;
    let lo = u32::from_le_bytes(b[0..4].try_into().expect("4 bytes"));
    let hi = u32::from_le_bytes(b[4..8].try_into().expect("4 bytes"));
    Some((u64::from(hi) << 32) | u64::from(lo))
}

/// Store a 64-bit `FILETIME`, answering Win32's `BOOL`.
fn write_filetime(mem: &mut Memory, at: u32, ticks: u64) -> u32 {
    if at == 0 {
        return FALSE;
    }
    let mut b = [0u8; 8];
    #[allow(clippy::cast_possible_truncation)]
    b[0..4].copy_from_slice(&(ticks as u32).to_le_bytes());
    #[allow(clippy::cast_possible_truncation)]
    b[4..8].copy_from_slice(&((ticks >> 32) as u32).to_le_bytes());
    u32::from(Flat32Ptr(at).write(mem, &b).is_ok())
}

/// Store a single `WORD` out-parameter.
fn write_word(mem: &mut Memory, at: u32, v: u16) -> bool {
    at != 0 && Flat32Ptr(at).write(mem, &v.to_le_bytes()).is_ok()
}

/// Fill a `SYSTEMTIME` at `at` from a specific instant.
fn system_time_at(mem: &mut Memory, at: u32, secs: i64) -> u32 {
    if at == 0 {
        return FALSE;
    }
    let t = secs as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `t` is a live `time_t` and `tm` a live owned `struct tm`.
    if unsafe { libc::gmtime_r(&t, &mut tm) }.is_null() {
        return FALSE;
    }
    let bytes = systemtime_bytes(&tm, 0);
    u32::from(Flat32Ptr(at).write(mem, &bytes).is_ok())
}

/// `SYSTEMTIME`'s sixteen bytes, from a `struct tm`.
///
/// ```text
///   0  wYear          2  wMonth         4  wDayOfWeek     6  wDay
///   8  wHour         10  wMinute       12  wSecond       14  wMilliseconds
/// ```
///
/// **`wDayOfWeek` sits third, not last.** Writing year/month/day into the first
/// three slots -- the order they are spoken in -- puts the day where the API
/// says the weekday is, and every date the program prints is then a weekday.
fn systemtime_bytes(tm: &libc::tm, millis: u32) -> [u8; 16] {
    let mut b = [0u8; 16];
    let put = |b: &mut [u8; 16], off: usize, v: u16| {
        b[off..off + 2].copy_from_slice(&v.to_le_bytes());
    };
    put(&mut b, 0, u16::try_from(tm.tm_year + 1900).unwrap_or(1980));
    put(&mut b, 2, u16::try_from(tm.tm_mon + 1).unwrap_or(1));
    put(&mut b, 4, u16::try_from(tm.tm_wday).unwrap_or(0));
    put(&mut b, 6, u16::try_from(tm.tm_mday).unwrap_or(1));
    put(&mut b, 8, u16::try_from(tm.tm_hour).unwrap_or(0));
    put(&mut b, 10, u16::try_from(tm.tm_min).unwrap_or(0));
    put(&mut b, 12, u16::try_from(tm.tm_sec.min(59)).unwrap_or(0));
    put(&mut b, 14, u16::try_from(millis).unwrap_or(0));
    b
}

/// Fill a `SYSTEMTIME` at `at`, in local time or UTC.
///
/// ```text
/// off  field
///   0  wYear          2  wMonth         4  wDayOfWeek     6  wDay
///   8  wHour         10  wMinute       12  wSecond       14  wMilliseconds
/// ```
///
/// Sixteen bytes, eight `WORD`s, no padding. `wDayOfWeek` sits *third* rather
/// than last, which is the field order a from-memory reconstruction gets wrong:
/// writing year/month/day into the first three slots puts the day where the API
/// says the weekday is, and every date the program prints is then a day of the
/// week.
///
/// The conversion goes through `libc::localtime_r`/`gmtime_r` rather than
/// arithmetic of our own, so the local answer respects the host's real timezone
/// and its daylight-saving rules instead of a fixed offset.
fn system_time(mem: &mut Memory, at: u32, local: bool) -> u32 {
    if at == 0 {
        return FALSE;
    }
    let now = std::time::SystemTime::now();
    let since = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = since.as_secs() as libc::time_t;
    let millis = since.subsec_millis();

    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `secs` is a live `time_t` and `tm` is a live, owned `struct tm`.
    // The `_r` forms write only through the pointer given and keep no state, so
    // there is no shared buffer for a second call to overwrite.
    let ok = unsafe {
        if local {
            !libc::localtime_r(&secs, &mut tm).is_null()
        } else {
            !libc::gmtime_r(&secs, &mut tm).is_null()
        }
    };
    if !ok {
        return FALSE;
    }

    let bytes = systemtime_bytes(&tm, millis);
    if Flat32Ptr(at).write(mem, &bytes).is_err() {
        return FALSE;
    }
    TRUE
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

/// `KERNEL32!RtlUnwind` -- the non-local transfer at the heart of a Borland
/// C++ throw, and of `_longjmp`.
///
/// Returns the register set to enter the module with. It never produces a
/// value for the caller, because by contract this function does not return to
/// it: it resumes the module at `target_ip` instead.
///
/// # The contract, measured rather than looked up
///
/// Both call sites live in the runtime this repo ships
/// (`re/wg/CW3220MT.DLL`), and the arithmetic at the canonical one pins the
/// stack exactly. `__Global_unwind`'s helper (`0x405c0e`) does:
///
/// ```text
/// push ebx; push esi; push edi        ; ESP = E-12
/// push $0; push edx; push $0x405c1f; push eax   ; the four arguments
/// call RtlUnwind                      ; ESP = E-32
/// 0x405c1f: pop edi; pop esi; pop ebx; ret      ; needs ESP = E-12
/// ```
///
/// `E-12` is `(E-32) + 20`, so **the module resumes with `ESP` as though this
/// had executed a stdcall `ret 16`**: past its own return address and its four
/// arguments. `EBP` must survive too -- that helper's own caller
/// (`__Global_unwind`, `0x404407`) ends `mov %ebp,%esp; pop %ebp; ret` after
/// the transfer -- and the other registers are preserved because the module
/// is entitled to expect it, not because a call site was measured needing it.
/// `EAX` carries `ReturnValue`. See
/// `docs/2026-08-17-borland-unwind-layout.md`.
///
/// # Errors
///
/// If there is no outstanding call to read a frame from, or if the chain
/// between the module's current `FS:[0]` and `target_frame` holds frames
/// whose handlers would have to run. **That refusal is the point**: unwinding
/// past a frame means calling its handler with `EH_UNWINDING` so the module's
/// destructors run, and a host that skipped them would produce a program that
/// keeps going with objects it believes it destroyed. Nothing here calls back
/// into module code yet (no shim in this crate does), so the honest answer is
/// to name the frames and stop.
fn rtl_unwind(
    machine: &mut Machine,
    mem: &Memory,
    target_frame: u32,
    target_ip: u32,
    return_value: u32,
) -> Result<Regs, String> {
    // Read before anything else: `frame_sp` names this very call's frame, and
    // it is the only place the entry `ESP` can come from.
    let entry_esp = machine
        .frame_sp()
        .ok_or_else(|| "RtlUnwind with no outstanding call to unwind from".to_owned())?;

    // `TargetFrame == 0` is Windows' "exit unwind": unwind the whole chain and
    // do not come back. Nothing in this runtime's two call sites asks for it,
    // so it is refused rather than invented.
    if target_frame == 0 {
        return Err("RtlUnwind with TargetFrame=0 (an exit unwind), which no \
                    measured call site of this runtime makes"
            .to_owned());
    }

    let mut frames = Vec::new();
    let mut head = machine.seh_head();
    while head != target_frame {
        if head == EMPTY_SEH_CHAIN {
            return Err(format!(
                "RtlUnwind to TargetFrame={target_frame:#010x}, which is not on the \
                 module's own SEH chain (walked {} frame(s) from FS:[0] to the end)",
                frames.len()
            ));
        }
        // A registration record is `{ prev, handler }` -- the layout the
        // module itself builds and that `__Return_unwind` pops with
        // `mov (%ebx),%eax; mov %eax,%fs:0x0`.
        let record = Flat32Ptr(head)
            .resolve(mem, 8)
            .map_err(|e| format!("SEH frame at {head:#010x}: {e}"))?;
        let prev = u32::from_le_bytes([record[0], record[1], record[2], record[3]]);
        let handler = u32::from_le_bytes([record[4], record[5], record[6], record[7]]);
        frames.push((head, handler));
        head = prev;
    }

    if !frames.is_empty() {
        let listed: Vec<String> = frames
            .iter()
            .map(|(frame, handler)| format!("{frame:#010x}->{handler:#010x}"))
            .collect();
        return Err(format!(
            "RtlUnwind must unwind {} SEH frame(s) before reaching \
             TargetFrame={target_frame:#010x}, and each one's handler has to be called \
             with EH_UNWINDING so the module's destructors run. Calling back into \
             module code from a shim is not something this host does yet, and \
             skipping the handlers would resume a program that believes it \
             destroyed objects it did not. Frames (record->handler): {}",
            frames.len(),
            listed.join(", ")
        ));
    }

    // Nothing to unwind: the chain's head already is the target. Leave it
    // where the module will expect it and transfer.
    machine.set_seh_head(target_frame);

    Ok(Regs {
        eip: target_ip,
        // Past this call's own return address and its four stdcall arguments.
        esp: entry_esp + 20,
        eax: return_value,
        ..machine.regs()
    })
}

/// `FS:[0]` when no handler is registered -- the value
/// `mbbs_machine::m32`'s TIB is built with, and what the end of a chain
/// reads as.
const EMPTY_SEH_CHAIN: u32 = 0xffff_ffff;

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

    /// `KERNEL32!RtlUnwind`: the module must resume at `TargetIp`, on the
    /// stack a stdcall `ret 16` would have left, with `EAX` carrying
    /// `ReturnValue` and `EBP` intact.
    ///
    /// Proven by where the module actually ends up -- it stores `EAX` and
    /// `ESP` at the target and traps again -- rather than by reading the
    /// `Regs` this host computed, which would only be checking the host
    /// against itself.
    #[test]
    fn rtl_unwind_resumes_the_module_at_the_target_with_the_stack_a_ret_16_leaves() {
        use mbbs_machine::m32::{Exit, Mapping};

        const CALLER: u16 = 40;
        const LANDED: u16 = 41;
        const TARGET_FRAME: u32 = 0xffff_ffff; // the chain is empty, so this is its head
        const RETURN_VALUE: u32 = 0x1234_5678;
        const EBP_MARK: u32 = 0x0bad_f00d;
        const SCRATCH: usize = 2048;

        let mut l = loaded();
        let mut p = Process::new("X.EXE", &[]);

        let mut code_mapping = Mapping::new(4096).expect("a low code mapping");
        let base = code_mapping.base() as usize as u32;
        let scratch = base + SCRATCH as u32;
        let target_ip = base + 512;

        // The caller: mark EBP, push the four stdcall arguments right to
        // left, and trap into the thunk this test answers as RtlUnwind.
        let mut code = vec![0xbdu8]; // mov ebp, imm32
        code.extend_from_slice(&EBP_MARK.to_le_bytes());
        let push_imm32 = |code: &mut Vec<u8>, v: u32| {
            code.push(0x68);
            code.extend_from_slice(&v.to_le_bytes());
        };
        push_imm32(&mut code, RETURN_VALUE); // arg4: ReturnValue
        push_imm32(&mut code, 0); // arg3: ExceptionRecord
        push_imm32(&mut code, target_ip); // arg2: TargetIp
        push_imm32(&mut code, TARGET_FRAME); // arg1: TargetFrame
        let next_ip = base + code.len() as u32 + 5;
        code.push(0xe8); // call rel32
        code.extend_from_slice(&l.machine.thunk_addr(CALLER).wrapping_sub(next_ip).to_le_bytes());
        code_mapping.as_mut_slice()[..code.len()].copy_from_slice(&code);

        // The target: store EAX, ESP and EBP where this test can read them,
        // then trap again so the run stops somewhere nameable.
        let mut landed = vec![0xa3u8]; // mov [scratch], eax
        landed.extend_from_slice(&scratch.to_le_bytes());
        landed.extend_from_slice(&[0x89, 0x25]); // mov [scratch+4], esp
        landed.extend_from_slice(&(scratch + 4).to_le_bytes());
        landed.extend_from_slice(&[0x89, 0x2d]); // mov [scratch+8], ebp
        landed.extend_from_slice(&(scratch + 8).to_le_bytes());
        let landed_next = target_ip + landed.len() as u32 + 5;
        landed.push(0xe8);
        landed.extend_from_slice(&l.machine.thunk_addr(LANDED).wrapping_sub(landed_next).to_le_bytes());
        let at = (target_ip - base) as usize;
        code_mapping.as_mut_slice()[at..at + landed.len()].copy_from_slice(&landed);

        let exit = l.machine.call_on(l.mem.stack_mut(), base, &[]).expect("traps");
        assert_eq!(exit, Exit::Call { index: CALLER }, "stopped at the RtlUnwind call");

        // What a stdcall `ret 16` would leave: past the return address and
        // the four arguments.
        let expected_esp = l.machine.frame_sp().expect("an outstanding call") + 20;

        let answer = dispatch(&mut p, &mut l.machine, &mut l.mem, "RtlUnwind");
        assert!(answer.is_some(), "RtlUnwind is implemented: {:?}", p.unwind_gap);
        let regs = p.transfer.take().expect("RtlUnwind redirects rather than answering");

        l.machine.set_regs(regs);
        let exit = l.machine.jump().expect("the module resumes at the target");
        assert_eq!(exit, Exit::Call { index: LANDED }, "the module did not reach TargetIp");

        let read = |off: usize| {
            let b = &code_mapping.as_slice()[SCRATCH + off..SCRATCH + off + 4];
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        };
        assert_eq!(read(0), RETURN_VALUE, "EAX must carry ReturnValue");
        assert_eq!(read(4), expected_esp, "ESP must be what a stdcall ret 16 leaves");
        assert_eq!(read(8), EBP_MARK, "EBP must survive the unwind");

        drop(code_mapping);
    }

    /// An unwind that would have to run a module's own handlers is refused,
    /// not silently performed. Skipping them resumes a program that believes
    /// it destroyed objects it did not, which looks correct until much later.
    #[test]
    fn rtl_unwind_refuses_an_unwind_that_would_skip_a_handler() {
        use mbbs_machine::m32::{Exit, Mapping};

        const CALLER: u16 = 42;
        const HANDLER: u32 = 0x00c0_ffee;

        let mut l = loaded();
        let mut p = Process::new("X.EXE", &[]);

        // One registration record `{ prev, handler }` on the module's own
        // stack, and FS:[0] pointing at it -- the shape the module builds.
        let (stack_limit, stack_base) = l.machine.stack_range();
        let record_at = stack_limit + 64;
        assert!(record_at < stack_base, "the record sits inside the stack");
        let mut record = EMPTY_SEH_CHAIN.to_le_bytes().to_vec();
        record.extend_from_slice(&HANDLER.to_le_bytes());
        Flat32Ptr(record_at).write(&mut l.mem, &record).expect("the stack is writable");
        l.machine.set_seh_head(record_at);

        let mut code_mapping = Mapping::new(4096).expect("a low code mapping");
        let base = code_mapping.base() as usize as u32;
        let mut code = Vec::new();
        let push_imm32 = |code: &mut Vec<u8>, v: u32| {
            code.push(0x68);
            code.extend_from_slice(&v.to_le_bytes());
        };
        push_imm32(&mut code, 0); // ReturnValue
        push_imm32(&mut code, 0); // ExceptionRecord
        push_imm32(&mut code, base); // TargetIp
        push_imm32(&mut code, EMPTY_SEH_CHAIN); // TargetFrame: past the record
        let next_ip = base + code.len() as u32 + 5;
        code.push(0xe8);
        code.extend_from_slice(&l.machine.thunk_addr(CALLER).wrapping_sub(next_ip).to_le_bytes());
        code_mapping.as_mut_slice()[..code.len()].copy_from_slice(&code);

        let exit = l.machine.call_on(l.mem.stack_mut(), base, &[]).expect("traps");
        assert_eq!(exit, Exit::Call { index: CALLER });

        assert!(
            dispatch(&mut p, &mut l.machine, &mut l.mem, "RtlUnwind").is_none(),
            "an unwind that skips a handler must not be answered"
        );
        let why = p.unwind_gap.take().expect("and it must say why");
        assert!(
            why.contains("1 SEH frame") && why.contains("00c0ffee"),
            "the refusal must name the frames it would have skipped: {why}"
        );
        assert!(p.transfer.is_none(), "a refused unwind redirects nothing");

        drop(code_mapping);
    }

    /// The one fact in this file that would fail silently rather than loudly.
    /// `GetModuleHandleA` takes one argument and pops it; see this module's
    /// doc comment for what the entry stub does with that.
    #[test]
    fn get_module_handle_a_pops_its_own_argument_and_answers_the_base() {
        let mut l = loaded();
        let mut p = Process::new("X.EXE", &[]);
        let base = l
            .mem
            .image()
            .expect("a PE program always has its image loaded before any import is answered")
            .base();
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
        // The symbol here has been changed twice as the frontier ate the
        // previous one -- first `WriteConsoleOutputCharacterA`, then
        // `SetConsoleCtrlHandler`. The test is about the *mechanism*, not the
        // symbol: an unimplemented import must decline rather than guess, so
        // that `run` can name it. It needs a genuinely unimplemented symbol to
        // say that with, and it should keep being re-pointed rather than
        // deleted. `CopyFileA` is linked and unreached today.
        assert_eq!(
            dispatch(&mut p, &mut l.machine, &mut l.mem, "CopyFileA"),
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


#[cfg(test)]
mod memory_tests {
    use super::*;

    fn loaded() -> crate::win32::load::Loaded {
        let f = std::fs::read("/home/daniel/peepeebbs/wccmmutl.exe").expect("the utility");
        crate::win32::load::load(&f).expect("loads")
    }

    fn field(b: &[u8; MBI_SIZE], off: usize) -> u32 {
        u32::from_le_bytes(b[off..off + 4].try_into().expect("4 bytes"))
    }

    /// Every region this host reports is page-aligned and at least one page.
    ///
    /// Both halves were learned the hard way. The program's own wrapper does
    /// `if ((RegionSize & 0xfff) == 0xfff) RegionSize++`, so an unaligned
    /// `0xFFFFFFFF` becomes zero; and a caller walking the address space
    /// advances by `RegionSize`, so any zero is an infinite loop. This host
    /// produced both, at 28,314 and 16,514 iterations.
    #[test]
    fn every_region_is_page_aligned_and_never_zero() {
        let l = loaded();
        let base = l
            .mem
            .image()
            .expect("a PE program always has its image loaded before any import is answered")
            .base();
        for addr in [
            0,
            0x1000,
            0x0010_0000,
            base.wrapping_sub(0x1000),
            base,
            base.wrapping_add(0x1000),
            USER_ADDRESS_LIMIT - PAGE,
        ] {
            let b = describe_region(&l.mem, addr);
            let region = field(&b, 12);
            assert_ne!(region, 0, "a zero region at {addr:#x} is an infinite loop");
            assert_eq!(
                region & (PAGE - 1),
                0,
                "region {region:#x} at {addr:#x} is not page-aligned"
            );
            assert_ne!(
                region & 0xfff,
                0xfff,
                "the program's own wrapper increments this into zero"
            );
            assert_eq!(field(&b, 0) & (PAGE - 1), 0, "BaseAddress is page-aligned");
        }
    }

    /// The image is reported as committed and the space below it as free.
    ///
    /// This is what the probing implementation got wrong: mappedness is not
    /// monotonic, so an exponential search stepped over the image entirely and
    /// called the whole of user space one free region.
    #[test]
    fn the_image_is_found_rather_than_stepped_over() {
        let l = loaded();
        let base = l
            .mem
            .image()
            .expect("a PE program always has its image loaded before any import is answered")
            .base();

        let inside = describe_region(&l.mem, base);
        assert_eq!(field(&inside, 16), 0x1000, "MEM_COMMIT inside the image");
        assert_eq!(field(&inside, 0), base & !(PAGE - 1), "based at the image");

        let below = describe_region(&l.mem, 0);
        assert_eq!(field(&below, 16), 0x0001_0000, "MEM_FREE at address zero");
        assert!(
            field(&below, 12) <= base,
            "the free region below the image must stop at it, not run past"
        );
    }

    /// Walking the address space by `RegionSize` terminates, which is the
    /// property the program depends on and the one that kept breaking.
    #[test]
    fn a_walk_of_the_address_space_terminates() {
        let l = loaded();
        let mut at: u32 = 0;
        let mut steps = 0;
        loop {
            if at >= USER_ADDRESS_LIMIT {
                break;
            }
            let b = describe_region(&l.mem, at);
            let region = field(&b, 12);
            assert_ne!(region, 0, "step {steps} at {at:#x} reported no size");
            let Some(next) = field(&b, 0).checked_add(region) else {
                break;
            };
            assert!(next > at, "step {steps} did not advance past {at:#x}");
            at = next;
            steps += 1;
            assert!(steps < 100, "a real map has a handful of regions, not {steps}");
        }
        assert!(steps >= 3, "image, arena and stack are three mappings at least");
    }

    /// `VirtualQuery` fails above the user-mode limit, and that failure is what
    /// ends a caller's walk. Answering for kernel addresses runs it forever.
    #[test]
    fn virtual_query_refuses_kernel_addresses() {
        let mut l = loaded();
        let out = crate::win32::process::put(&mut l.mem, &[0u8; MBI_SIZE]).expect("arena");
        assert_eq!(virtual_query(&mut l.mem, USER_ADDRESS_LIMIT, out, 28), 0);
        assert_eq!(virtual_query(&mut l.mem, 0xffff_f000, out, 28), 0);
        assert_ne!(virtual_query(&mut l.mem, 0, out, 28), 0, "but zero is fine");
        // A buffer shorter than the struct is refused rather than truncated.
        assert_eq!(virtual_query(&mut l.mem, 0, out, 27), 0);
    }
}
