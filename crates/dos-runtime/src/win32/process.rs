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
use crate::win32::btrieve;
use crate::win32::crt;
use crate::win32::stream;
use crate::win32::user32;
use crate::win32::wsock32;
use crate::win32::kernel32::{self, Answer};
use crate::win32::load::Loaded;
use crate::win32::stream::Streams;

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
    /// The console screen buffer this process draws on.
    ///
    /// One buffer, not one per handle: `CONIN$` and `CONOUT$` are two handles
    /// onto the same console, and a program that sets the text attribute
    /// through one and writes through the other expects the colour to apply.
    /// Per-handle state -- the console *mode* -- lives on the handle instead,
    /// in [`Object::Console`].
    pub console: crate::win32::console::Console,
    /// Whether the narrow file APIs interpret filenames as ANSI or OEM.
    ///
    /// Starts ANSI, which is what a Win32 process starts as. This program
    /// switches it to OEM during startup -- it is a DOS-era utility, and OEM is
    /// the code page its filenames were always written in.
    pub file_apis_ansi: bool,
    /// The open C streams, and the root jail they resolve through.
    ///
    /// Holds its own `Option<Files>` rather than this struct holding one, so
    /// that the file table and the sandbox that backs it cannot get separated
    /// -- a `Streams` with no `Files` is a coherent thing (every call fails as
    /// a missing file would), whereas a `Files` with no stream table is not.
    pub streams: Streams,
    /// The process environment, as `NAME=VALUE` pairs.
    ///
    /// **Empty, and that is a decision with a measured caller.** This program
    /// asks for exactly one variable -- `getenv("MCVPATH")`, MajorBBS's search
    /// path for `.MCV` message catalogues -- and the honest answer on this host
    /// is that it is unset, because there is no search path: everything the
    /// program can reach is under the one root directory the jail resolves
    /// against, which is where an unset `MCVPATH` makes it look anyway.
    ///
    /// Kept as real (if empty) state rather than having `getenv` return a
    /// constant NULL, because [`enter_main`] builds `envp` from this same
    /// vector. Two representations of one environment that can disagree is the
    /// bug this crate's own `bind_imports` doc comment describes for globals
    /// bound per-site, and it would surface as a program that finds a variable
    /// in `envp` which `getenv` denies.
    pub env: Vec<(String, String)>,
    /// How many times the program has called `Sleep`.
    ///
    /// Counted rather than ignored because a program spinning in a retry loop
    /// and one making progress produce the same trace otherwise -- this is the
    /// number that tells them apart.
    pub slept_calls: u64,
    /// Winsock's per-thread error slot -- see [`crate::win32::wsock32`] for why
    /// it is not the same storage as `last_error`.
    pub wsa_last_error: u32,
    /// What the program reported to the NT event log.
    ///
    /// Kept because this host has no event log to write to, and the
    /// alternative to keeping it is discarding the program's own account of
    /// what went wrong -- which on the error paths this utility takes is the
    /// most informative thing it produces. `runexe` prints these after a run.
    pub events: Vec<LoggedEvent>,
    /// The running image's own exports, name to linear address.
    ///
    /// Copied out of [`Loaded`] by [`run`] rather than looked up through it,
    /// because `dispatch` is handed the machine and its memory and has no
    /// reference to the loaded image. One copy, made once, at the point where
    /// both are in scope.
    pub exports: Vec<(String, u32)>,
    /// Where `_getch` and `_kbhit` get their keystrokes.
    ///
    /// The *same* [`Driver`](crate::driver::Driver) the real-mode guest is
    /// driven by, so `--keys` and `--script` mean the same thing for a PE32
    /// program as for a DOS one. `None` is a program with no keyboard: every
    /// read reports nothing rather than blocking, which is what a batch run
    /// needs and what every test that does not care about input gets for free.
    pub keys: Option<Box<dyn crate::driver::Driver>>,
    /// Keystrokes decoded but not yet handed to `_getch`.
    ///
    /// **A queue rather than one byte, because an extended key is two reads.**
    /// DOS conio reports a function or arrow key by answering `0` and making
    /// the *next* `getch` return the scan code, so one keypress becomes two
    /// bytes and they must be delivered in order. Modelling it as a single
    /// parked byte -- which this was -- makes every arrow key deliver a `0`
    /// and then nothing, which is exactly how it failed: the menu could be
    /// driven with Enter but not with the arrows.
    ///
    /// **`kbhit` must not consume.** It reports whether a key is waiting; a
    /// host that drew one from the driver and dropped it turns every "press any
    /// key to continue" into a swallowed keystroke and the prompt never
    /// clears. A `Driver` has no peek, so the peek is built here: `_kbhit`
    /// draws at most one key and parks it, and `_getch` takes the parked one
    /// before asking for another.
    pending_keys: std::collections::VecDeque<u8>,
    /// `(caption, text)` of every `MessageBoxA` the program tried to show.
    ///
    /// There is no desktop here, so the box cannot appear -- but the text is
    /// the program's own account of a failure, and discarding it would throw
    /// away the clearest diagnostic on the paths that produce one.
    pub messages: Vec<(String, String)>,
    /// Kernel objects this process has made, indexed by handle minus one.
    ///
    /// Handles are `1..=len` so that zero stays available as the NULL a failed
    /// open returns -- `OpenEventA` answering "no such event" and a valid
    /// handle must never be the same value.
    objects: Vec<Object>,
    /// This process's Btrieve session -- `wbtrv32.dll!BTRCALL`'s state, kept
    /// here rather than reconstructed per call because the position blocks
    /// `crate::win32::btrieve` hands back are only meaningful against the
    /// same open files across calls.
    pub btrieve: ::btrieve::Btrieve<btrieve::Win32Mem>,
    /// Where a Btrieve `Open` allocates the module's block, name, record and
    /// key buffers. See [`btrieve::Win32Heap`] for why this is not a second
    /// allocator alongside `Memory::alloc`.
    pub btrieve_heap: btrieve::Win32Heap,
    /// Set when `wbtrv32.dll!BTRCALL` asked for something this engine does
    /// not model, or handed a guest pointer that would not resolve. `None`
    /// otherwise. [`dispatch`] answers `None` in both cases -- "not
    /// implemented" and "this DLL, but a call this engine cannot honour" look
    /// the same from the answer alone -- so [`run`] reads this field right
    /// after a `None` to tell which one actually happened, and reports
    /// [`Outcome::BtrieveGap`] rather than [`Outcome::Unimplemented`] when it
    /// is set.
    /// What Open wrote into each position block, keyed by the block's guest
    /// **address**.
    ///
    /// **The engine identifies an open file by a pointer it stores inside the
    /// guest's 128-byte position block** (`crates/btrieve/src/btrcall.rs`'s
    /// `handle_of`), and that block is guest-writable memory. `wccmmutl.exe`
    /// overwrites it: measured, it opens sixteen data files, closes none, and
    /// by the time it issues a Step First against `WCCITOW2.DAT` the first
    /// four bytes of that file's block hold `0x41000007` instead of the handle
    /// Open put there. The engine then reports "is not an open Btrieve file"
    /// for a file it has open.
    ///
    /// The guest is not doing anything a real board did not do, so real
    /// Btrieve cannot be keying on those bytes -- it keys on the block itself.
    /// This is that, at the only layer that can see it: the engine is handed a
    /// 128-byte *copy* and never learns the address, but this edge marshalled
    /// the call and knows it. Open records the handle here, and every later
    /// operation puts it back into the copy before the engine sees it.
    ///
    /// A `Vec` rather than a map because a board opens on the order of sixteen
    /// files at once and a linear scan of sixteen is cheaper than hashing.
    pub btrieve_blocks: Vec<(u32, [u8; 4])>,
    pub btrieve_gap: Option<String>,
    /// Set when a shim has redirected the module rather than answering it --
    /// today only `KERNEL32!RtlUnwind`, which by contract never returns to
    /// its caller and instead resumes the module somewhere else entirely.
    ///
    /// The same shape as [`Process::exit_code`] and [`Process::btrieve_gap`]:
    /// [`dispatch`] still hands back an [`Answer`], because every arm must,
    /// and [`run`] reads this field immediately afterwards to learn that the
    /// answer is not to be delivered. Without it a redirect would have to
    /// change the type every arm returns.
    ///
    /// Carries the register set to enter with; see
    /// [`mbbs_machine::m32::Machine::jump`].
    pub transfer: Option<mbbs_machine::m32::Regs>,
    /// Set when `KERNEL32!RtlUnwind` was asked for an unwind this host cannot
    /// perform faithfully -- today, one that would have to call a module's
    /// own SEH handlers so its destructors run. Read by [`run`] right after a
    /// `None`, exactly as [`Process::btrieve_gap`] is, so that "not
    /// implemented" and "implemented, but this call cannot be honoured" stay
    /// distinguishable.
    pub unwind_gap: Option<String>,
}

/// A [`Key`](crate::driver::Key) as `getch` reports it: one byte, or two.
///
/// **An extended key is two reads, and both are returned here.** DOS conio
/// signals a function or arrow key by answering `0` from one `getch` and the
/// scan code from the *next* one. Returning only the scan code would hand the
/// program a plain character nobody pressed -- the up arrow's `0x48` reads as
/// `H` -- and returning only the `0` loses the key entirely, which is how the
/// arrows used to fail.
///
/// The `0` goes first. A program distinguishes the two cases by testing the
/// first byte, so the order is the whole signal.
fn key_bytes(key: crate::driver::Key) -> Vec<u8> {
    match key {
        crate::driver::Key::Char(b) => vec![b],
        crate::driver::Key::Ext(scan) => vec![0, scan],
    }
}

/// One `ReportEventA` call: the program's own diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggedEvent {
    /// `EVENTLOG_ERROR_TYPE` (1), `WARNING` (2), `INFORMATION` (4)...
    pub kind: u32,
    pub id: u32,
    /// The insertion strings, in order. Usually one: the message itself.
    pub strings: Vec<String>,
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
    /// A handle onto the process's console, from `CreateFileA("CONIN$")` or
    /// `CreateFileA("CONOUT$")`.
    ///
    /// The `mode` is per *handle* rather than per console, which is how Win32
    /// really works: input and output modes are different bit sets over the
    /// same two calls, and a program sets each through its own handle.
    Console { input: bool, mode: u32 },
    /// A real file opened with `CreateFileA`, and the [`dos::files::Files`]
    /// handle behind it.
    ///
    /// Distinct from a C stream: this one has no `FILE` struct, because the
    /// program that opens a file this way writes to it with `WriteFile` rather
    /// than `fwrite` and never sees a `FILE *`.
    File { dos: u16 },
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
            // 80x25, the console every DOS-era program assumes until it says
            // otherwise. This one says otherwise almost immediately -- it calls
            // `SetConsoleScreenBufferSize` during startup -- so this is the
            // value it reads *before* resizing, and it has to be the ordinary
            // one for the arithmetic it does on it to come out where the
            // program expects.
            console: crate::win32::console::Console::new(80, 25),
            file_apis_ansi: true,
            streams: Streams::default(),
            env: Vec::new(),
            slept_calls: 0,
            wsa_last_error: 0,
            events: Vec::new(),
            exports: Vec::new(),
            messages: Vec::new(),
            keys: None,
            pending_keys: std::collections::VecDeque::new(),
            objects: Vec::new(),
            btrieve: ::btrieve::Btrieve::default(),
            btrieve_heap: btrieve::Win32Heap::default(),
            btrieve_blocks: Vec::new(),
            btrieve_gap: None,
            transfer: None,
            unwind_gap: None,
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
        self.objects
            .iter()
            .position(|o| match o {
                Object::Event { name: n, .. } => n.as_deref() == Some(name),
                // A console handle has no name in this sense. `CONIN$` is the
                // name of a *device* passed to `CreateFileA`, not a kernel
                // object name `OpenEventA` could ever find, so matching it here
                // would let an event lookup return a console.
                // Neither a console device name nor a filesystem path is a
                // kernel object name `OpenEventA` could ever find.
                Object::Console { .. } | Object::File { .. } => false,
            })
            .map(|i| u32::try_from(i + 1).expect("index fits, it came from a Vec"))
    }

    /// `SetConsoleMode`, which needs mutable access to one object and so
    /// cannot be written at the call site while `process` is borrowed for the
    /// console beside it.
    ///
    /// Answers whether the handle was a console at all -- Windows fails the
    /// call rather than ignoring it, and a program that checks the result would
    /// otherwise be told its terminal setup succeeded on a handle that is not a
    /// terminal.
    pub fn set_console_mode(&mut self, handle: u32, wanted: u32) -> bool {
        let Some(index) = handle.checked_sub(1).and_then(|i| usize::try_from(i).ok()) else {
            return false;
        };
        match self.objects.get_mut(index) {
            Some(Object::Console { mode, .. }) => {
                *mode = wanted;
                true
            }
            _ => false,
        }
    }

    /// The console as a [`Screen`](crate::screen::Screen), for a `Driver`.
    ///
    /// A `Driver` decides what to type by *looking* -- `Script`'s `expect`
    /// steps read the screen -- so it has to be handed one. `Screen` is the
    /// real-mode guest's own type, built there by sampling `B800:0000`; here
    /// the host owns the cells outright, so the same structure is assembled
    /// directly instead. That is the whole reason `Screen`'s fields are public
    /// and its snapshot constructor is not the only way in.
    pub fn screen(&self) -> crate::screen::Screen {
        let (col, row) = self.console.cursor();
        let (_, visible) = self.console.cursor_info();
        crate::screen::Screen {
            grid: self.console.cells().clone(),
            cursor: (
                u8::try_from(row).unwrap_or(u8::MAX),
                u8::try_from(col).unwrap_or(u8::MAX),
            ),
            cursor_visible: visible,
        }
    }

    /// Give the driver a chance to repaint while the program is busy.
    ///
    /// **This is what makes an interactive run live.** `_getch` and `_kbhit`
    /// paint too -- a `Terminal` paints the screen it is handed before reading
    /// -- but a program that draws a progress line and then keeps working
    /// would show nothing until its next input call, which for a batch
    /// operation may be never. Called after every import, this repaints while
    /// it works.
    ///
    /// **`poll_due` is checked first, and that ordering is the whole cost
    /// control.** Building a [`Screen`](crate::screen::Screen) clones the
    /// entire cell grid; doing that per import over a hundred thousand imports
    /// would dwarf the run. `Terminal::poll_due` is a clock comparison that
    /// answers true about sixty times a second, and the default `Driver`
    /// implementation answers `false` outright -- so a scripted or keyed run
    /// pays one boolean per import and never builds a screen at all.
    ///
    /// A key the poll happens to pick up is parked rather than dropped: this
    /// is a repaint, not a read, and swallowing input here would lose
    /// keystrokes typed while the program was working.
    pub fn pump_display(&mut self) {
        if !self.pending_keys.is_empty() {
            return;
        }
        let due = self.keys.as_ref().is_some_and(|d| d.poll_due());
        if !due {
            return;
        }
        let screen = self.screen();
        if let Some(driver) = self.keys.as_mut()
            && let Some(key) = driver.poll_key(&screen)
        {
            self.pending_keys.extend(key_bytes(key));
        }
    }

    /// Is a keystroke waiting? Does **not** consume it.
    pub fn key_waiting(&mut self) -> bool {
        if !self.pending_keys.is_empty() {
            return true;
        }
        let screen = self.screen();
        let Some(driver) = self.keys.as_mut() else {
            return false;
        };
        if let Some(key) = driver.poll_key(&screen) {
            self.pending_keys.extend(key_bytes(key));
        }
        !self.pending_keys.is_empty()
    }

    /// Take the next keystroke, or `None` when there is no more input.
    pub fn next_key(&mut self) -> Option<u8> {
        if let Some(byte) = self.pending_keys.pop_front() {
            return Some(byte);
        }
        let screen = self.screen();
        let key = self.keys.as_mut()?.next_key(&screen)?;
        self.pending_keys.extend(key_bytes(key));
        self.pending_keys.pop_front()
    }

    /// The handle Open recorded for the position block at `at`.
    pub fn btrieve_handle(&self, at: u32) -> Option<[u8; 4]> {
        self.btrieve_blocks
            .iter()
            .find(|(block, _)| *block == at)
            .map(|(_, handle)| *handle)
    }

    /// Record what Open wrote, replacing any earlier handle for the same
    /// address -- a block reused for a second Open names the new file, not the
    /// old one.
    pub fn set_btrieve_handle(&mut self, at: u32, handle: [u8; 4]) {
        match self.btrieve_blocks.iter_mut().find(|(b, _)| *b == at) {
            Some(slot) => slot.1 = handle,
            None => self.btrieve_blocks.push((at, handle)),
        }
    }

    /// Forget a block, on Close. Keeping it would let a later operation on a
    /// closed file be silently redirected at whatever the engine opens next
    /// into the same slot.
    pub fn clear_btrieve_handle(&mut self, at: u32) {
        self.btrieve_blocks.retain(|(b, _)| *b != at);
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
    /// It asked Btrieve for something this engine does not model. Like
    /// [`Self::Unimplemented`] the run stops here rather than continuing with
    /// a fabricated status, because a Btrieve caller's only channel is a
    /// status word and a wrong one is indistinguishable from a right one.
    BtrieveGap { what: String },
    /// `KERNEL32!RtlUnwind` was asked for an unwind this host cannot perform
    /// faithfully -- today, one that would have to call the module's own SEH
    /// handlers so its destructors run. Stops the run for the same reason
    /// [`Self::BtrieveGap`] does: transferring control without running them
    /// resumes a program that believes it destroyed objects it did not, and
    /// that is indistinguishable from a correct unwind until much later.
    UnwindGap { what: String },
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
    if site.module.eq_ignore_ascii_case("USER32.dll") {
        return user32::dispatch(process, machine, mem, &symbol);
    }
    if site.module.eq_ignore_ascii_case("WSOCK32.dll") {
        return wsock32::dispatch(process, machine, mem, &symbol);
    }
    if site.module.eq_ignore_ascii_case("wbtrv32.dll") {
        return btrieve::dispatch(process, machine, mem, &symbol);
    }
    if site.module.eq_ignore_ascii_case("cw3220mt.DLL") {
        // The C runtime is split by concern across two files: `crt` for the
        // pure functions with no host state behind them, `stream` for the ones
        // that reach the filesystem. Streams are tried first because that
        // split is by *ownership* -- anything holding a `FILE` or a path
        // belongs to one module, and a symbol answered in both would be a
        // first-match-wins bug rather than a compile error.
        if let Some(a) = stream::dispatch(process, machine, mem, &symbol) {
            return Some(a);
        }
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
    process.exports.clone_from(&loaded.exports);
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
        // Repaint if the driver says one is due. Costs one boolean per import
        // unless something is actually watching -- see `pump_display`.
        process.pump_display();
        match dispatch(process, &mut loaded.machine, &mut loaded.mem, site) {
            Some(answer) => {
                if let Some(code) = process.exit_code {
                    return Ok(Outcome::Exited(code));
                }
                // An import answered is progress. The program's one entry
                // point is its whole life, so the machine's whole-entry
                // budget would only ever cut off correct work -- see
                // `Machine::rearm_watchdog`; `budget` above is what stops a
                // program that loops on an import instead.
                loaded.machine.rearm_watchdog()?;
                // A shim that redirected the module rather than answering it.
                // The outstanding call is abandoned deliberately -- `RtlUnwind`
                // does not return, so there is no frame to resume and no
                // value to deliver. See `Process::transfer`.
                if let Some(regs) = process.transfer.take() {
                    loaded.machine.set_regs(regs);
                    exit = loaded.machine.jump()?;
                    continue;
                }
                exit = loaded.machine.resume_on_cleaning(
                    loaded.mem.stack_mut(),
                    Ret::U32(answer.value),
                    answer.cleans,
                )?;
            }
            None => {
                // `wbtrv32.dll!BTRCALL` answers `None` for two different
                // reasons -- an unimplemented symbol, and a real Btrieve
                // call this engine cannot honour -- and only this field
                // tells them apart. See `Process::btrieve_gap`.
                if let Some(what) = process.btrieve_gap.take() {
                    return Ok(Outcome::BtrieveGap { what });
                }
                if let Some(what) = process.unwind_gap.take() {
                    return Ok(Outcome::UnwindGap { what });
                }
                return Ok(Outcome::Unimplemented { module, symbol });
            }
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
    // Built from `Process::env`, which is the same vector `getenv` answers
    // from -- see that field on why there is one source rather than two.
    let mut envp = Vec::with_capacity(process.env.len());
    for (name, value) in &process.env {
        envp.push(put_cstr(&mut loaded.mem, &format!("{name}={value}"))?);
    }
    let envp_ptr = put_ptr_array(&mut loaded.mem, &envp)?;

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

    /// A driver that records what it was shown and when it was asked.
    ///
    /// State is shared through an `Rc<RefCell<_>>` rather than recovered by
    /// downcasting, because `Process` owns the driver as a `Box<dyn Driver>`
    /// and the trait has no `Any` on it -- adding one so a test could look
    /// inside would be shaping the production type around the test.
    #[derive(Default)]
    struct SpyState {
        polls: usize,
        seen: Vec<String>,
    }

    struct Spy {
        due: bool,
        key: Option<crate::driver::Key>,
        state: std::rc::Rc<std::cell::RefCell<SpyState>>,
    }

    impl crate::driver::Driver for Spy {
        fn next_key(&mut self, _screen: &crate::screen::Screen) -> Option<crate::driver::Key> {
            self.key.take()
        }
        fn poll_due(&self) -> bool {
            self.due
        }
        fn poll_key(&mut self, screen: &crate::screen::Screen) -> Option<crate::driver::Key> {
            let mut st = self.state.borrow_mut();
            st.polls += 1;
            st.seen.push(screen.grid.line(0).trim_end().to_string());
            drop(st);
            self.key.take()
        }
    }

    /// A process whose driver offers exactly one key, of any kind.
    fn with_spy_key(
        key: crate::driver::Key,
    ) -> (Process, std::rc::Rc<std::cell::RefCell<SpyState>>) {
        let state = std::rc::Rc::new(std::cell::RefCell::new(SpyState::default()));
        let mut p = Process::new("X.EXE", &[]);
        p.keys = Some(Box::new(Spy {
            due: true,
            key: Some(key),
            state: std::rc::Rc::clone(&state),
        }));
        (p, state)
    }

    fn with_spy(
        due: bool,
        key: Option<u8>,
    ) -> (Process, std::rc::Rc<std::cell::RefCell<SpyState>>) {
        let state = std::rc::Rc::new(std::cell::RefCell::new(SpyState::default()));
        let mut p = Process::new("X.EXE", &[]);
        p.keys = Some(Box::new(Spy {
            due,
            key: key.map(crate::driver::Key::Char),
            state: std::rc::Rc::clone(&state),
        }));
        (p, state)
    }

    /// **A repaint shows the driver the console as it stands now.** This is
    /// what makes an interactive run live rather than a final snapshot.
    #[test]
    fn a_due_poll_repaints_with_the_current_console() {
        let (mut p, state) = with_spy(true, None);

        p.console.write_output_character(0, 0, b"FIRST");
        p.pump_display();
        p.console.write_output_character(0, 0, b"SECOND");
        p.pump_display();

        assert_eq!(
            state.borrow().seen,
            vec!["FIRST".to_string(), "SECOND".to_string()],
            "each repaint must show what was on screen at that moment"
        );
    }

    /// **A driver that is not due is never asked**, and no screen is built for
    /// it. That check is the only thing keeping a per-import repaint from
    /// cloning the whole cell grid a hundred thousand times.
    #[test]
    fn a_driver_that_is_not_due_is_never_polled() {
        let (mut p, state) = with_spy(false, None);
        for _ in 0..1000 {
            p.pump_display();
        }
        assert_eq!(state.borrow().polls, 0);
    }

    /// A key the repaint happens to collect is parked, not dropped -- it was
    /// typed while the program was working and `getch` must still get it.
    #[test]
    fn a_key_collected_by_a_repaint_is_not_lost() {
        let (mut p, _state) = with_spy(true, Some(b'Z'));
        p.pump_display();
        assert_eq!(p.next_key(), Some(b'Z'), "the parked key survives");
    }

    /// A repaint must not draw a key out from under a pending one, or the
    /// order keystrokes arrive in stops matching the order they were typed.
    #[test]
    fn a_repaint_does_not_run_while_a_key_is_already_parked() {
        let (mut p, state) = with_spy(true, Some(b'A'));
        p.pump_display();
        assert_eq!(state.borrow().polls, 1);
        p.pump_display();
        assert_eq!(state.borrow().polls, 1, "still parked, so no second poll");
        assert_eq!(p.next_key(), Some(b'A'));
    }

    /// **`kbhit` peeks and `getch` consumes.** A host that let `kbhit` draw and
    /// drop a key turns every "press any key to continue" into a swallowed
    /// keystroke, and the prompt never clears.
    #[test]
    fn kbhit_peeks_and_getch_consumes() {
        let mut p = Process::new("X.EXE", &[]);
        p.keys = Some(Box::new(crate::driver::Keys::new("AB")));

        assert!(p.key_waiting());
        assert!(p.key_waiting(), "peeking twice does not consume");
        assert_eq!(p.next_key(), Some(b'A'), "and getch gets the peeked key");
        assert_eq!(p.next_key(), Some(b'B'));
        assert!(!p.key_waiting(), "the queue is empty");
        assert_eq!(p.next_key(), None);
    }

    /// A process with no driver has no keyboard: nothing is waiting, and
    /// nothing ever arrives. It must not block or invent input.
    #[test]
    fn a_process_with_no_driver_reports_no_input() {
        let mut p = Process::new("X.EXE", &[]);
        assert!(!p.key_waiting());
        assert_eq!(p.next_key(), None);
    }

    /// A `Driver` decides what to type by looking at the screen, so the one it
    /// is handed must be the console the program has actually drawn on.
    #[test]
    fn the_screen_a_driver_sees_is_the_console_the_program_drew() {
        let mut p = Process::new("X.EXE", &[]);
        p.console.write_output_character(0, 2, b"Database Recovery");
        p.console.set_cursor(5, 2);

        let screen = p.screen();
        assert!(screen.contains("Database Recovery"));
        assert_eq!(screen.cursor, (2, 5), "Screen orders it (row, col)");
    }

    /// **An extended key is two reads: `0`, then the scan code.**
    ///
    /// Returning only the scan code hands the program a character nobody
    /// pressed -- the up arrow's `0x48` reads as `H`. Returning only the `0`
    /// loses the key, which is how the arrows actually failed: the menu could
    /// be driven with Enter but not with the arrows, because every arrow
    /// delivered a `0` and then nothing.
    #[test]
    fn an_extended_key_is_a_zero_then_its_scan_code() {
        assert_eq!(key_bytes(crate::driver::Key::Char(b'A')), vec![b'A']);
        assert_eq!(
            key_bytes(crate::driver::Key::Ext(0x48)),
            vec![0, 0x48],
            "the zero comes first -- it is what marks the key as extended"
        );
    }

    /// The same thing end to end: two `getch` calls for one arrow press, in
    /// order, and the second is not swallowed by the first.
    #[test]
    fn an_arrow_key_arrives_as_two_reads_in_order() {
        let (mut p, _state) = with_spy_key(crate::driver::Key::Ext(0x48));
        assert!(p.key_waiting(), "the arrow is waiting");
        assert_eq!(p.next_key(), Some(0), "first read marks it extended");
        assert!(
            p.key_waiting(),
            "the scan code is still waiting -- this is the half that was lost"
        );
        assert_eq!(p.next_key(), Some(0x48), "second read is the scan code");
        assert!(!p.key_waiting());
        assert_eq!(p.next_key(), None);
    }

    /// An ordinary character is still exactly one read -- the queue must not
    /// turn every keypress into two.
    #[test]
    fn an_ordinary_key_is_still_one_read() {
        let (mut p, _state) = with_spy_key(crate::driver::Key::Char(b'Q'));
        assert_eq!(p.next_key(), Some(b'Q'));
        assert_eq!(p.next_key(), None);
    }

}
