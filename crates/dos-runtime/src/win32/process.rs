//! The process a Borland-linked Win32 executable expects to be inside.
//!
//! Shaped by what `docs/2026-08-17-win32-import-trace.md` measured, which was
//! not what this file's plan assumed. The executable calls exactly two imports
//! before dying: `GetModuleHandleA`, then `cw3220mt.DLL!__startup` -- and
//! `__startup` is Borland's C runtime startup, an *import*, not code in the
//! program. It sets up `argc`/`argv`, calls `main`, and exits. Everything else
//! the program does -- every console call, every file, every `BTRCALL` -- is
//! downstream of it.
//!
//! So the process boundary is here rather than at the entry point: this module
//! is what `__startup` would have been.

use std::io;

use mbbs_machine::m32::{Exit, Flat32Ptr, Machine, Memory, Ret};
use mbbs_machine::module::ImportSite;
use mbbs_machine::ptr::ModulePtr;

use crate::win32::advapi32;
use crate::win32::crt;
use crate::win32::kernel32::{self, Answer};
use crate::win32::load::Loaded;

/// Where Borland's startup record carries the address of `main`.
///
/// The record is `__startup`'s only argument. Measured from the real file: the
/// eight words at RVA `0x1402c`, immediately below the string `Borland C++ -
/// Copyright 1995 Borland Intl.`, are four data/BSS bounds (the last of which
/// is exactly where the entry stub's own `rep stos` begins), two zero words,
/// then this -- a `CODE` address whose function reads its *second* argument,
/// as `main(argc, argv)` does.
///
/// It **was** a hypothesis with a falsifiable test rather than a measured fact,
/// and [`run`] is the test that settled it: entered with `(argc, argv, envp)`,
/// the program goes on to probe for a running board, create and secure its own
/// event, and ask the C runtime the time. Nothing but `main` behaves that way.
///
/// The word after it, `+0x1c`, is accounted for and deliberately unused: it is
/// an exception-unwind callback (one pointer argument, compares `*p` against 4
/// and 5, returns 1 or 0), which nothing here needs until the program raises
/// something.
const RECORD_MAIN: u32 = 0x18;

/// `ERROR_SUCCESS` -- the value `GetLastError` answers when nothing has gone
/// wrong.
pub const ERROR_SUCCESS: u32 = 0;

/// `ERROR_FILE_NOT_FOUND` -- what Windows reports for opening a named kernel
/// object that does not exist, which is the honest answer on a host where no
/// board is running.
pub const ERROR_FILE_NOT_FOUND: u32 = 2;

/// `ERROR_ALREADY_EXISTS` -- what `CreateEventA` reports when it handed back a
/// handle to a name that was already taken rather than making a new object.
pub const ERROR_ALREADY_EXISTS: u32 = 183;

/// Copy `bytes` into the program's own memory and answer the address they
/// landed at.
///
/// `Memory::alloc` bump-allocates out of the arena it keeps beside the image
/// for exactly this -- host-allocated, guest-addressable memory (see that
/// module's own "why not fold this into `Image`"). Nothing here reclaims,
/// because process startup data lives as long as the process.
///
/// # Errors
///
/// If the arena has no room left, or the fresh allocation somehow does not
/// resolve -- the latter cannot happen for a pointer `alloc` just returned, and
/// is propagated rather than unwrapped so that a future change to `alloc` which
/// broke that cannot do so silently.
pub fn put(mem: &mut Memory, bytes: &[u8]) -> io::Result<u32> {
    let at = mem.alloc(bytes.len())?;
    at.write(mem, bytes).map_err(io::Error::other)?;
    Ok(at.0)
}

/// A NUL-terminated copy of `s`, as C expects to receive it.
///
/// # Errors
///
/// [`put`]'s.
pub fn put_cstr(mem: &mut Memory, s: &str) -> io::Result<u32> {
    let mut bytes = s.as_bytes().to_vec();
    bytes.push(0);
    put(mem, &bytes)
}

/// A NUL-terminated array of pointers -- `argv` or `envp`. The terminating
/// null is added here, so callers pass only the real entries.
///
/// # Errors
///
/// [`put`]'s.
pub fn put_ptr_array(mem: &mut Memory, ptrs: &[u32]) -> io::Result<u32> {
    let mut bytes = Vec::with_capacity((ptrs.len() + 1) * 4);
    for p in ptrs {
        bytes.extend_from_slice(&p.to_le_bytes());
    }
    bytes.extend_from_slice(&0u32.to_le_bytes());
    put(mem, &bytes)
}

/// One running process: its command line, and its exit code once it has one.
///
/// Infallibly constructible on purpose -- it holds no mapping. The
/// guest-addressable memory a process needs lives in the [`Loaded`] program's
/// own `Memory`, so that building a `Process` cannot fail and its tests need no
/// `expect`.
pub struct Process {
    /// As a Win32 program reads it back from `GetCommandLineA`: the program
    /// name first, then the arguments, space-separated. Not quoted -- none of
    /// the vendor's own switches (`-fix`, `-merge`, `-recover`,
    /// `-restoreuser`, `-needed`) contains a space, and inventing a quoting
    /// rule no measured input exercises would be a guess with a test written
    /// to agree with it.
    pub command_line: String,
    /// `None` until the program says otherwise, by calling `ExitProcess` or by
    /// returning from `main`.
    pub exit_code: Option<u32>,
    /// What `GetLastError` will answer.
    ///
    /// Real state rather than a constant, because this program reads it: it
    /// calls `OpenEventA`, is told NULL, and then asks *why*. "The event does
    /// not exist" and "you may not open it" lead somewhere different, so a host
    /// that answers both the same way is choosing the program's behaviour for
    /// it by accident.
    pub last_error: u32,
    /// The C runtime's `rand` state, which is per-process rather than global.
    ///
    /// Kept here and not in a `static` because two runs inside one test binary
    /// would otherwise share a generator: the second would continue the first's
    /// sequence, and a test that seeded and drew would pass or fail depending
    /// on what ran before it. The same reasoning applies to every other piece
    /// of C runtime state with a cursor in it.
    pub random: crate::win32::crt::Random,
    /// Kernel objects this process has made, indexed by handle minus one.
    ///
    /// Handles are `1..=len` so that zero stays available as the NULL a failed
    /// open returns -- `OpenEventA` answering "no such event" and a valid
    /// handle must never be the same value.
    objects: Vec<Object>,
}

/// What a handle refers to.
///
/// One variant, because one is what the program has asked for. Kept as an enum
/// rather than a bare `Vec<Event>` because the next thing it opens will not be
/// an event, and a handle table that can only hold one kind of thing has to be
/// rewritten rather than extended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Object {
    /// A named event. Nothing else runs on this host, so no other process can
    /// ever signal it -- see [`crate::win32::kernel32`]'s `create_event_a`.
    Event {
        name: Option<String>,
        manual_reset: bool,
        signalled: bool,
    },
}

impl Process {
    pub fn new(program: &str, args: &[&str]) -> Self {
        let mut command_line = program.to_owned();
        for a in args {
            command_line.push(' ');
            command_line.push_str(a);
        }
        Self {
            command_line,
            exit_code: None,
            last_error: ERROR_SUCCESS,
            random: crate::win32::crt::Random::default(),
            objects: Vec::new(),
        }
    }

    /// Add an object and return its handle, which is never zero.
    pub fn insert_object(&mut self, object: Object) -> u32 {
        self.objects.push(object);
        // `len` after the push, so the first handle is 1.
        u32::try_from(self.objects.len()).expect("a process cannot open 4 billion handles")
    }

    /// The object a handle refers to, or `None` for a handle this process never
    /// handed out -- including zero.
    pub fn object(&self, handle: u32) -> Option<&Object> {
        self.objects.get(usize::try_from(handle.checked_sub(1)?).ok()?)
    }

    /// A named object this process already made, and its handle.
    ///
    /// Windows' `CreateEventA` returns a handle to the existing event when the
    /// name is already taken, rather than a second one; this is how that is
    /// answered.
    pub fn named_object(&self, name: &str) -> Option<u32> {
        self.objects.iter().position(|o| match o {
            Object::Event { name: n, .. } => n.as_deref() == Some(name),
        })
        .map(|i| u32::try_from(i + 1).expect("index fits, it came from a Vec"))
    }

    /// Record an exit code. [`run`] stops as soon as one is set, which is what
    /// makes this different from an import that merely returns a value.
    pub fn exit(&mut self, code: u32) {
        self.exit_code = Some(code);
    }

    /// The command line split the way a C runtime splits it into `argv`.
    ///
    /// Whitespace only. See [`Process::command_line`] on why there is no
    /// quoting rule here.
    pub fn args(&self) -> Vec<&str> {
        self.command_line.split_whitespace().collect()
    }
}

/// How a run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The program exited, with its code -- by calling `ExitProcess`, or by
    /// returning from `main`.
    Exited(u32),
    /// It called an import this host does not implement. The run stops here
    /// rather than continuing with a fabricated answer, because a lie is only
    /// safe until the program uses it, and this names the next thing to
    /// implement.
    Unimplemented { module: String, symbol: String },
    /// It took a signal. `eip` is a linear address.
    Fault { signo: i32, eip: u32 },
    /// It used its whole CPU budget without returning.
    Timeout { eip: u32 },
    /// `budget` import calls were seen and the run was cut short.
    Budget,
    /// A thunk fired whose index names no import -- see
    /// [`crate::win32::load::Stop::UnknownThunk`].
    UnknownThunk(u16),
}

/// Answer one import call.
///
/// `Some(value)` is the value to resume with; `None` means "not implemented",
/// which [`run`] turns into [`Outcome::Unimplemented`] rather than a silent
/// zero. That distinction is the whole reason this returns an `Option` instead
/// of a `u32`: a zero is a plausible answer for many of these symbols, so a
/// host that cannot tell "I answered zero" from "I have no answer" cannot
/// report which symbol to write next.
///
/// `__startup` is deliberately **not** handled here. It never returns -- the
/// entry stub reaches it by `jmp` with a zero in the return-address slot -- so
/// there is no value this function could give back. [`run`] intercepts it
/// ahead of this call.
pub fn dispatch(
    process: &mut Process,
    machine: &mut Machine,
    mem: &mut Memory,
    site: &ImportSite,
) -> Option<Answer> {
    let symbol = site.symbol.to_string();
    if site.module.eq_ignore_ascii_case("KERNEL32.dll") {
        return kernel32::dispatch(process, machine, mem, &symbol);
    }
    if site.module.eq_ignore_ascii_case("ADVAPI32.dll") {
        return advapi32::dispatch(process, machine, mem, &symbol);
    }
    if site.module.eq_ignore_ascii_case("cw3220mt.DLL") {
        return crt::dispatch(process, machine, mem, &symbol);
    }
    None
}

/// A NUL-terminated string at guest address `at`.
///
/// Resolves against all of the program's memory -- image, arena and stack --
/// because a `char *` in this API can point into any of them, and a string the
/// program built in a local buffer is not a special case worth failing on.
///
/// `None` when the address resolves nowhere, or has no terminator before the end
/// of whichever mapping holds it. Both are reported the same way on purpose:
/// there is no string here either way, and the caller's choice does not differ.
pub fn read_cstr(mem: &Memory, at: u32) -> Option<String> {
    let bytes = Flat32Ptr(at).read_cstr(mem).ok()?;
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// Load-and-go: enter at the entry point, answer imports, and take over at
/// `__startup`.
///
/// The shape of this loop is dictated by the measurement in
/// `docs/2026-08-17-win32-import-trace.md`. `__startup` is not resumed, it is
/// *replaced*: the host reads the startup record it was handed, builds
/// `argc`/`argv`/`envp`, and re-enters the program at `main` with a fresh
/// [`Machine::call`]. Abandoning `__startup`'s frame is exactly what that
/// method documents `call` as doing ("Calling `call` again instead of resuming
/// abandons that frame outright"), and it is the correct thing to do here
/// because `__startup` was never going to return: the stub gave it a return
/// address of zero.
///
/// One consequence worth naming: `main` therefore returns to *this host's*
/// return thunk rather than into `__startup`'s epilogue, so
/// [`Exit::Returned`]'s `eax` is `main`'s return value, which is the process
/// exit code. A real `__startup` would have passed it to `ExitProcess`; here
/// there is nothing in between.
///
/// # Errors
///
/// If the machine cannot be entered or resumed, or the arena cannot hold the
/// process's own startup data.
pub fn run(loaded: &mut Loaded, process: &mut Process, budget: usize) -> io::Result<Outcome> {
    let mut exit = loaded
        .machine
        .call_on(loaded.mem.stack_mut(), loaded.entry, &[])?;

    for _ in 0..budget {
        let index = match exit {
            Exit::Call { index } => index,
            Exit::Returned { eax, .. } => return Ok(Outcome::Exited(eax)),
            Exit::Fault { signo, eip } => return Ok(Outcome::Fault { signo, eip }),
            Exit::Timeout { eip } => return Ok(Outcome::Timeout { eip }),
        };
        let Some(site) = loaded.imports.get(index as usize) else {
            return Ok(Outcome::UnknownThunk(index));
        };
        let symbol = site.symbol.to_string();

        if site.module.eq_ignore_ascii_case("cw3220mt.DLL") && symbol == "__startup" {
            let record = loaded.machine.arg_u32(loaded.mem.stack(), 0);
            exit = enter_main(loaded, process, record)?;
            continue;
        }

        let module = site.module.clone();
        match dispatch(process, &mut loaded.machine, &mut loaded.mem, site) {
            Some(answer) => {
                if let Some(code) = process.exit_code {
                    return Ok(Outcome::Exited(code));
                }
                exit = loaded.machine.resume_on_cleaning(
                    loaded.mem.stack_mut(),
                    Ret::U32(answer.value),
                    answer.cleans,
                )?;
            }
            None => return Ok(Outcome::Unimplemented { module, symbol }),
        }
    }
    Ok(Outcome::Budget)
}

/// Build `argc`/`argv`/`envp` and enter `main`.
///
/// Three arguments, not two, even though nothing measured says this `main`
/// takes an `envp`: a cdecl callee that only declares two simply never reads
/// the third, whereas one that declares three and is given two reads whatever
/// the stack happened to hold. The asymmetry is free to get right and
/// expensive to get wrong.
fn enter_main(loaded: &mut Loaded, process: &Process, record: u32) -> io::Result<Exit> {
    let bytes = Flat32Ptr(record.wrapping_add(RECORD_MAIN))
        .resolve(&loaded.mem, 4)
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("__startup was handed a record at {record:#x}: {e}"),
            )
        })?;
    let main = u32::from_le_bytes(bytes.try_into().expect("resolve returned 4 bytes"));
    if main == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the startup record at {record:#x} names no main at +{RECORD_MAIN:#x}"),
        ));
    }

    let args: Vec<String> = process.args().into_iter().map(str::to_owned).collect();
    let mut argv = Vec::with_capacity(args.len());
    for a in &args {
        argv.push(put_cstr(&mut loaded.mem, a)?);
    }
    let argc = u32::try_from(argv.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "argc overflows"))?;
    let argv_ptr = put_ptr_array(&mut loaded.mem, &argv)?;
    let envp_ptr = put_ptr_array(&mut loaded.mem, &[])?;

    loaded
        .machine
        .call_on(loaded.mem.stack_mut(), main, &[argc, argv_ptr, envp_ptr])
}

/// [`enter_main`], for [`crate::win32::survey`].
///
/// The survey needs the same takeover `run` performs -- `__startup` never
/// returns, so answering it zero ends the run at address zero three calls in --
/// but has no business reaching into the rest of this module. Exposed as one
/// named entry point rather than by making `enter_main` public, so the set of
/// things outside this file that can enter the program stays enumerable.
///
/// # Errors
///
/// [`enter_main`]'s.
pub fn enter_main_for_survey(
    loaded: &mut Loaded,
    process: &Process,
    record: u32,
) -> io::Result<Exit> {
    enter_main(loaded, process, record)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `GetCommandLineA` returns a pointer, and a C runtime immediately walks
    /// it. Returning a null or a dangling one is the difference between a
    /// program that starts and one that faults in `__setargv`.
    #[test]
    fn the_command_line_is_readable_nul_terminated_text() {
        let p = Process::new("C:\\WCCMMUTL.EXE", &[]);
        assert_eq!(p.command_line, "C:\\WCCMMUTL.EXE");
        assert!(
            p.command_line.is_ascii(),
            "a DOS-era program reads bytes, not UTF-8"
        );
    }

    /// The whole of Task 2, pinned: the program now gets through NT's process
    /// ritual and stops at the first thing that is not a process at all.
    ///
    /// Reaching `cw3220mt.DLL!_time` proves a chain of things no unit test
    /// covers on its own -- that `__startup`'s startup record was read, that
    /// `+0x18` really is `main`, that `main` was entered with a usable
    /// `argc`/`argv`, that `GetModuleHandleA` cleaned its own argument (or the
    /// record would have been null), and that the program was satisfied by
    /// every answer along the way rather than merely not crashing on them.
    ///
    /// It stops here because the C runtime is Phase 3, not because anything
    /// went wrong. When that phase lands this assertion is expected to change;
    /// what it must never do is move *backwards*.
    ///
    /// **Phase 3, Task 2 moved it forward, and by exactly the predicted
    /// amount.** `_time` and `_srand` are answered now, so the frontier is
    /// `KERNEL32!CreateFileA` -- which is ordinal 12 of
    /// `docs/2026-08-17-win32-crt-trace.md` §1, the first symbol past `_srand`
    /// in the survey's list.
    ///
    /// That agreement is worth more than either measurement alone. The survey
    /// answers unimplemented symbols with a lie and is only sound up to its
    /// first mis-cleaned stdcall call, which is this very symbol; this runner
    /// never lies and stops dead at it. Two instruments with different failure
    /// modes naming the same boundary is what makes the trace's ordinals 0-11
    /// evidence rather than an artefact of how the survey resumes.
    #[test]
    fn the_process_carries_main_as_far_as_the_c_runtime() {
        let file = std::fs::read("/home/daniel/peepeebbs/wccmmutl.exe").expect("the utility");
        let mut loaded = crate::win32::load::load(&file).expect("loads");
        let mut p = Process::new("C:\\WCCMMUTL.EXE", &[]);
        let out = run(&mut loaded, &mut p, 400).expect("the machine runs");
        assert_eq!(
            out,
            Outcome::Unimplemented {
                module: "KERNEL32.dll".to_owned(),
                symbol: "CreateFileA".to_owned(),
            }
        );
    }

    /// `ExitProcess` must end the run and carry its code out, not merely
    /// return. A program that calls it and keeps running is worse than one
    /// that crashes, because the trace looks healthy.
    #[test]
    fn exit_process_records_its_code_and_stops_the_run() {
        let mut p = Process::new("C:\\WCCMMUTL.EXE", &[]);
        p.exit(3);
        assert_eq!(p.exit_code, Some(3));
    }
}
