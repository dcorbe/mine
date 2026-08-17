//! A console screen buffer the host owns.
//!
//! **Why this is not "wire it onto `screen.rs`".** [`crate::screen::Screen`]
//! *samples* the guest: `Screen::snapshot` reads `B800:0000` out of the shared
//! mapping, because a DOS program draws by poking video memory and the host can
//! look whenever it likes. A Win32 console has no memory-mapped buffer at all.
//! Every change arrives as an explicit call, and the program reads its own
//! screen back with `ReadConsoleOutputCharacterA` -- which is in this
//! program's import table, so the buffer has to be real state rather than a
//! write-only pipe to a terminal.
//!
//! So the host owns the cells here. What is shared with the DOS side is
//! [`Cells`] and the painter that turns one into ANSI
//! ([`crate::terminal`]), which is the half that does not care who filled the
//! grid in.
//!
//! **Now reached, and wired in.** Phase 2 built this buffer and deliberately
//! left it unwired, because the trace of the day stopped at `cw3220mt.DLL!_time`
//! and no console call had been *observed*. Phase 3's survey
//! (`docs/2026-08-17-win32-crt-trace.md`) went past that point and found the
//! program doing almost nothing else: having asked the C runtime the time and
//! seeded its generator, it opens `CONIN$` and configures its console.
//!
//! **Eighteen of the nineteen console and file-API symbols this program links
//! are answered here.** They were not written in one go: each was reached by
//! implementing the one before it and re-running the strict runner, which stops
//! dead at the first unimplemented symbol and names it. The buffer's
//! `Read`/`Write`/`FillConsoleOutput*` family, built a phase ago against the
//! import table alone, turned out to be exactly right -- the program calls all
//! six.
//!
//! The nineteenth, `SetConsoleCtrlHandler`, is deliberately still `None`. It is
//! not a console-buffer call at all but a Ctrl-C handler registration, it has
//! not been observed being called, and answering it would mean deciding what
//! this host does about signals -- a question with nothing measured behind it
//! yet. Reaching it will say so by name.
//!
//! **A `COORD` is one argument, not two.** Win32 passes it by value, packed
//! into a single 32-bit stack slot with `X` in the low half. Reading it as two
//! slots would shift every argument after it, and `SetConsoleScreenBufferSize`
//! would then clean 12 bytes instead of 8 -- corrupting the *next* call rather
//! than this one, which is the failure mode [`crate::win32::kernel32`]'s doc
//! comment warns about and the hardest one to attribute after the fact.

use mbbs_machine::m32::{Flat32Ptr, Machine, Memory};
use mbbs_machine::ptr::ModulePtr;

use crate::screen::Cells;
use crate::win32::kernel32::{Answer, FALSE, TRUE};
use crate::win32::process::{Object, Process};

/// The default attribute a console starts with: light grey on black.
const DEFAULT_ATTRIBUTE: u8 = 7;

/// The percentage of a cell the cursor fills, as `CONSOLE_CURSOR_INFO.dwSize`
/// reports it. 25 is the ordinary underline cursor Windows starts with.
const DEFAULT_CURSOR_SIZE: u32 = 25;

/// One console screen buffer.
pub struct Console {
    grid: Cells,
    /// `(col, row)`, in Win32's own `COORD` order rather than the `(row, col)`
    /// the DOS side uses. Kept in the API's order because every argument that
    /// reaches it arrives that way, and flipping it at the boundary is one
    /// fewer place to get it backwards.
    cursor: (u16, u16),
    /// What `WriteConsoleA`-style output is coloured with until something
    /// changes it. Character and attribute writes are separate calls in this
    /// API, so this is only the default for the ones that do not carry their
    /// own.
    attr: u8,
    /// `CONSOLE_CURSOR_INFO`: how much of a cell the cursor fills, as a
    /// percentage, and whether it is drawn at all. Held because the program
    /// both reads it (`GetConsoleCursorInfo`) and writes it
    /// (`SetConsoleCursorInfo`) -- a host that answered a constant would lose
    /// whatever the program set, and the commonest thing a full-screen program
    /// does with this pair is hide the cursor and put it back.
    cursor_size: u32,
    cursor_visible: bool,
}

impl Console {
    pub fn new(cols: usize, rows: usize) -> Self {
        Self {
            grid: Cells::blank(cols, rows),
            cursor: (0, 0),
            attr: DEFAULT_ATTRIBUTE,
            cursor_size: DEFAULT_CURSOR_SIZE,
            cursor_visible: true,
        }
    }

    /// `(cols, rows)`, as `CONSOLE_SCREEN_BUFFER_INFO.dwSize` reports it.
    pub fn size(&self) -> (u16, u16) {
        (
            u16::try_from(self.grid.cols).unwrap_or(u16::MAX),
            u16::try_from(self.grid.rows).unwrap_or(u16::MAX),
        )
    }

    /// `SetConsoleScreenBufferSize` -- a new grid, blanked.
    ///
    /// **The contents are not preserved, and that is the honest choice rather
    /// than the lazy one.** Windows keeps what still fits when a buffer grows
    /// and truncates when it shrinks, but a program resizes its buffer *before*
    /// drawing, not after -- this one does it during startup, four calls after
    /// it first asks how big the buffer is. Reflowing text nothing has written
    /// yet would be code with no measured caller, and a blank grid is what the
    /// program is about to fill anyway.
    ///
    /// A zero dimension is refused: Windows rejects it too, and a grid with no
    /// cells would make every subsequent write silently do nothing.
    pub fn resize(&mut self, cols: u16, rows: u16) -> bool {
        if cols == 0 || rows == 0 {
            return false;
        }
        self.grid = Cells::blank(usize::from(cols), usize::from(rows));
        self.cursor = (0, 0);
        true
    }

    /// `CONSOLE_CURSOR_INFO`: `(dwSize, bVisible)`.
    pub fn cursor_info(&self) -> (u32, bool) {
        (self.cursor_size, self.cursor_visible)
    }

    /// `SetConsoleCursorInfo`. A size outside `1..=100` is refused, as Windows
    /// refuses it -- the field is a percentage, and zero would be a cursor of
    /// no height rather than a hidden one (`bVisible` is what hides it).
    pub fn set_cursor_info(&mut self, size: u32, visible: bool) -> bool {
        if !(1..=100).contains(&size) {
            return false;
        }
        self.cursor_size = size;
        self.cursor_visible = visible;
        true
    }

    /// The grid, for the painter.
    pub fn cells(&self) -> &Cells {
        &self.grid
    }

    /// `(col, row)`, as Win32 orders it.
    pub fn cursor(&self) -> (u16, u16) {
        self.cursor
    }

    pub fn set_cursor(&mut self, col: u16, row: u16) {
        self.cursor = (col, row);
    }

    pub fn attribute(&self) -> u8 {
        self.attr
    }

    pub fn set_attribute(&mut self, attr: u8) {
        self.attr = attr;
    }

    /// The index of `(col, row)`, or `None` past the end of the buffer.
    ///
    /// Win32 treats the buffer as one linear run, not as independent rows: a
    /// write that runs off the end of a line continues on the next one. So this
    /// is a single bounds check against the whole grid rather than a per-row
    /// one.
    fn index(&self, col: u16, row: u16) -> Option<usize> {
        let at = usize::from(row) * self.grid.cols + usize::from(col);
        (at < self.grid.cells.len()).then_some(at)
    }

    /// `WriteConsoleOutputCharacterA` -- characters only, attributes untouched.
    ///
    /// Returns how many cells were written, which is what the real call reports
    /// through its `lpNumberOfCharsWritten` out-parameter. A run that would pass
    /// the end of the buffer is truncated rather than refused, as Windows
    /// truncates it.
    pub fn write_output_character(&mut self, col: u16, row: u16, chars: &[u8]) -> usize {
        let Some(start) = self.index(col, row) else {
            return 0;
        };
        let n = chars.len().min(self.grid.cells.len() - start);
        for (i, ch) in chars[..n].iter().enumerate() {
            self.grid.cells[start + i].ch = *ch;
        }
        n
    }

    /// `WriteConsoleOutputAttribute` -- attributes only, characters untouched.
    ///
    /// The independence is the whole point, and it is not incidental: these are
    /// two separate imports in this program's table, and a program that colours
    /// a line it has already written expects the text to survive.
    pub fn write_output_attribute(&mut self, col: u16, row: u16, attrs: &[u8]) -> usize {
        let Some(start) = self.index(col, row) else {
            return 0;
        };
        let n = attrs.len().min(self.grid.cells.len() - start);
        for (i, attr) in attrs[..n].iter().enumerate() {
            self.grid.cells[start + i].attr = *attr;
        }
        n
    }

    /// `ReadConsoleOutputCharacterA` -- read the screen back.
    ///
    /// Short at the end of the buffer rather than padded, so a caller can tell
    /// how much was really there.
    pub fn read_output_character(&self, col: u16, row: u16, len: usize) -> Vec<u8> {
        let Some(start) = self.index(col, row) else {
            return Vec::new();
        };
        let n = len.min(self.grid.cells.len() - start);
        self.grid.cells[start..start + n]
            .iter()
            .map(|c| c.ch)
            .collect()
    }

    /// `ReadConsoleOutputAttribute` -- the colours, read back.
    pub fn read_output_attribute(&self, col: u16, row: u16, len: usize) -> Vec<u8> {
        let Some(start) = self.index(col, row) else {
            return Vec::new();
        };
        let n = len.min(self.grid.cells.len() - start);
        self.grid.cells[start..start + n]
            .iter()
            .map(|c| c.attr)
            .collect()
    }

    /// `FillConsoleOutputCharacterA` -- one character, `len` times.
    pub fn fill_output_character(&mut self, col: u16, row: u16, ch: u8, len: usize) -> usize {
        self.write_output_character(col, row, &vec![ch; len])
    }

    /// `FillConsoleOutputAttribute` -- one attribute, `len` times.
    pub fn fill_output_attribute(&mut self, col: u16, row: u16, attr: u8, len: usize) -> usize {
        self.write_output_attribute(col, row, &vec![attr; len])
    }
}

/// The console modes a fresh input handle reports.
///
/// `ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT |
/// ENABLE_WINDOW_INPUT | ENABLE_MOUSE_INPUT` -- what Windows gives a new
/// console. The value matters because the program's next move is to *clear*
/// bits from it: a full-screen program turns line input and echo off so it can
/// read keys one at a time. A host that answered zero would have the program
/// clear bits already clear, and then set a mode that never had them.
const DEFAULT_INPUT_MODE: u32 = 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010;

/// `ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT`, the output default.
const DEFAULT_OUTPUT_MODE: u32 = 0x0001 | 0x0002;

/// The mode a freshly opened console handle starts with.
///
/// Public because `CreateFileA` lives in [`crate::win32::kernel32`]; the two
/// defaults stay here, beside the console they describe.
pub fn default_mode(input: bool) -> u32 {
    if input {
        DEFAULT_INPUT_MODE
    } else {
        DEFAULT_OUTPUT_MODE
    }
}

/// `INVALID_HANDLE_VALUE` -- what `CreateFileA` fails with.
///
/// **Not zero.** `CreateFileA` is the one Win32 opener that reports failure as
/// `-1` rather than NULL, and a host that returned zero would have the program
/// test `!= INVALID_HANDLE_VALUE`, conclude it succeeded, and use a null
/// handle. That is a lie that survives exactly until something reads it.
pub const INVALID_HANDLE_VALUE: u32 = 0xffff_ffff;

/// The two console device names `CreateFileA` accepts.
///
/// Public because `CreateFileA` lives in [`crate::win32::kernel32`] -- it has
/// to choose between opening a console device and opening a real file through
/// the jail, and that choice is this predicate.
///
/// Compared case-insensitively because they are DOS device names and the API
/// has always matched them that way.
pub fn console_device(name: &str) -> Option<bool> {
    if name.eq_ignore_ascii_case("CONIN$") {
        Some(true)
    } else if name.eq_ignore_ascii_case("CONOUT$") {
        Some(false)
    } else {
        None
    }
}

/// A `COORD` as it arrives *by value*: `X` in the low half, `Y` in the high.
fn coord_parts(packed: u32) -> (u16, u16) {
    #[allow(clippy::cast_possible_truncation)]
    (packed as u16, (packed >> 16) as u16)
}

/// The console handle an argument names, and whether it is the input one.
///
/// `None` for a handle this process never handed out, or one that is not a
/// console -- an event handle passed to `SetConsoleMode` is a program bug, and
/// answering `FALSE` is what Windows does rather than pretending.
fn console_handle(process: &Process, handle: u32) -> Option<bool> {
    match process.object(handle) {
        Some(Object::Console { input, .. }) => Some(*input),
        _ => None,
    }
}

/// Answer a KERNEL32 console import, or `None` for one still unimplemented.
///
/// Reached from [`crate::win32::kernel32::dispatch`]'s fallthrough rather than
/// from [`crate::win32::process::dispatch`], because every symbol here really
/// is a KERNEL32 export -- the split is by *concern*, so that the kernel-object
/// and process arms next door stay readable, not by DLL.
pub fn dispatch(
    process: &mut Process,
    machine: &mut Machine,
    mem: &mut Memory,
    symbol: &str,
) -> Option<Answer> {
    match symbol {
        // GetConsoleMode(HANDLE, LPDWORD lpMode)
        "GetConsoleMode" => {
            let handle = machine.arg_u32(mem.stack(), 0);
            let out = machine.arg_u32(mem.stack(), 1);
            let Some(Object::Console { mode, .. }) = process.object(handle) else {
                return Some(Answer::stdcall(FALSE, 2));
            };
            let mode = *mode;
            if out == 0 || Flat32Ptr(out).write(mem, &mode.to_le_bytes()).is_err() {
                return Some(Answer::stdcall(FALSE, 2));
            }
            Some(Answer::stdcall(TRUE, 2))
        }
        // SetConsoleMode(HANDLE, DWORD dwMode)
        "SetConsoleMode" => {
            let handle = machine.arg_u32(mem.stack(), 0);
            let wanted = machine.arg_u32(mem.stack(), 1);
            Some(Answer::stdcall(
                u32::from(process.set_console_mode(handle, wanted)),
                2,
            ))
        }
        // GetConsoleScreenBufferInfo(HANDLE, PCONSOLE_SCREEN_BUFFER_INFO)
        "GetConsoleScreenBufferInfo" => {
            let handle = machine.arg_u32(mem.stack(), 0);
            let out = machine.arg_u32(mem.stack(), 1);
            if console_handle(process, handle).is_none() || out == 0 {
                return Some(Answer::stdcall(FALSE, 2));
            }
            let info = screen_buffer_info(&process.console);
            let ok = Flat32Ptr(out).write(mem, &info).is_ok();
            Some(Answer::stdcall(u32::from(ok), 2))
        }
        // GetConsoleCursorInfo(HANDLE, PCONSOLE_CURSOR_INFO)
        "GetConsoleCursorInfo" => {
            let handle = machine.arg_u32(mem.stack(), 0);
            let out = machine.arg_u32(mem.stack(), 1);
            if console_handle(process, handle).is_none() || out == 0 {
                return Some(Answer::stdcall(FALSE, 2));
            }
            let (size, visible) = process.console.cursor_info();
            let mut bytes = [0u8; 8];
            bytes[0..4].copy_from_slice(&size.to_le_bytes());
            bytes[4..8].copy_from_slice(&u32::from(visible).to_le_bytes());
            let ok = Flat32Ptr(out).write(mem, &bytes).is_ok();
            Some(Answer::stdcall(u32::from(ok), 2))
        }
        // SetConsoleCursorInfo(HANDLE, const CONSOLE_CURSOR_INFO *)
        "SetConsoleCursorInfo" => {
            let handle = machine.arg_u32(mem.stack(), 0);
            let at = machine.arg_u32(mem.stack(), 1);
            if console_handle(process, handle).is_none() {
                return Some(Answer::stdcall(FALSE, 2));
            }
            let Ok(bytes) = Flat32Ptr(at).resolve(mem, 8) else {
                return Some(Answer::stdcall(FALSE, 2));
            };
            let size = u32::from_le_bytes(bytes[0..4].try_into().expect("4 bytes"));
            let visible = u32::from_le_bytes(bytes[4..8].try_into().expect("4 bytes")) != 0;
            let ok = process.console.set_cursor_info(size, visible);
            Some(Answer::stdcall(u32::from(ok), 2))
        }
        // SetConsoleScreenBufferSize(HANDLE, COORD dwSize)
        //
        // Two stack slots, not three: the COORD is packed into one. See this
        // module's doc comment.
        "SetConsoleScreenBufferSize" => {
            let handle = machine.arg_u32(mem.stack(), 0);
            let packed = machine.arg_u32(mem.stack(), 1);
            if console_handle(process, handle).is_none() {
                return Some(Answer::stdcall(FALSE, 2));
            }
            let (cols, rows) = coord_parts(packed);
            let ok = process.console.resize(cols, rows);
            Some(Answer::stdcall(u32::from(ok), 2))
        }
        // SetConsoleWindowInfo(HANDLE, BOOL bAbsolute, const SMALL_RECT *)
        //
        // Accepted and not acted on. The window is the host terminal's
        // viewport onto the buffer, and this host paints the whole buffer --
        // there is no viewport to move. Answering TRUE is honest for a console
        // whose window is always the whole screen; answering FALSE would tell
        // the program its resize failed, and a program told that may refuse to
        // draw at all.
        "SetConsoleWindowInfo" => {
            let handle = machine.arg_u32(mem.stack(), 0);
            let ok = console_handle(process, handle).is_some();
            Some(Answer::stdcall(u32::from(ok), 3))
        }
        // SetConsoleTextAttribute(HANDLE, WORD wAttributes)
        "SetConsoleTextAttribute" => {
            let handle = machine.arg_u32(mem.stack(), 0);
            let attr = machine.arg_u32(mem.stack(), 1);
            if console_handle(process, handle).is_none() {
                return Some(Answer::stdcall(FALSE, 2));
            }
            #[allow(clippy::cast_possible_truncation)]
            process.console.set_attribute(attr as u8);
            Some(Answer::stdcall(TRUE, 2))
        }
        // SetConsoleCursorPosition(HANDLE, COORD dwCursorPosition)
        "SetConsoleCursorPosition" => {
            let handle = machine.arg_u32(mem.stack(), 0);
            let packed = machine.arg_u32(mem.stack(), 1);
            if console_handle(process, handle).is_none() {
                return Some(Answer::stdcall(FALSE, 2));
            }
            let (col, row) = coord_parts(packed);
            process.console.set_cursor(col, row);
            Some(Answer::stdcall(TRUE, 2))
        }
        // ReadConsoleOutputCharacterA(HANDLE, LPSTR lpCharacter, DWORD nLength,
        //                             COORD dwReadCoord, LPDWORD lpNumberRead)
        //
        // Five slots: the COORD is one. This is the call that made the buffer
        // above real state rather than a pipe -- the program reads its own
        // screen back, so there has to be a screen to read.
        "ReadConsoleOutputCharacterA" => {
            let handle = machine.arg_u32(mem.stack(), 0);
            let out = machine.arg_u32(mem.stack(), 1);
            let len = machine.arg_u32(mem.stack(), 2);
            let (col, row) = coord_parts(machine.arg_u32(mem.stack(), 3));
            let count_at = machine.arg_u32(mem.stack(), 4);
            if console_handle(process, handle).is_none() {
                return Some(Answer::stdcall(FALSE, 5));
            }
            let chars = process.console.read_output_character(col, row, len as usize);
            let ok = out != 0 && Flat32Ptr(out).write(mem, &chars).is_ok();
            write_count(mem, count_at, chars.len());
            Some(Answer::stdcall(u32::from(ok), 5))
        }
        // ReadConsoleOutputAttribute(HANDLE, LPWORD lpAttribute, DWORD nLength,
        //                            COORD dwReadCoord, LPDWORD lpNumberRead)
        //
        // **Attributes are WORDs here and bytes in the buffer.** Win32's
        // attribute is 16 bits, of which the low 8 are the foreground and
        // background this host models; the rest are DBCS lead/trail-byte and
        // underline flags a CGA-era program neither sets nor reads. Widening on
        // the way out and narrowing on the way in is the whole of the
        // conversion, but a host that read these as bytes would return half as
        // many cells as the caller asked for and shift every one of them.
        "ReadConsoleOutputAttribute" => {
            let handle = machine.arg_u32(mem.stack(), 0);
            let out = machine.arg_u32(mem.stack(), 1);
            let len = machine.arg_u32(mem.stack(), 2);
            let (col, row) = coord_parts(machine.arg_u32(mem.stack(), 3));
            let count_at = machine.arg_u32(mem.stack(), 4);
            if console_handle(process, handle).is_none() {
                return Some(Answer::stdcall(FALSE, 5));
            }
            let attrs = process.console.read_output_attribute(col, row, len as usize);
            let mut wide = Vec::with_capacity(attrs.len() * 2);
            for a in &attrs {
                wide.extend_from_slice(&u16::from(*a).to_le_bytes());
            }
            let ok = out != 0 && Flat32Ptr(out).write(mem, &wide).is_ok();
            write_count(mem, count_at, attrs.len());
            Some(Answer::stdcall(u32::from(ok), 5))
        }
        // WriteConsoleOutputCharacterA(HANDLE, LPCSTR, DWORD nLength,
        //                              COORD dwWriteCoord, LPDWORD lpNumberWritten)
        "WriteConsoleOutputCharacterA" => {
            let handle = machine.arg_u32(mem.stack(), 0);
            let src = machine.arg_u32(mem.stack(), 1);
            let len = machine.arg_u32(mem.stack(), 2);
            let (col, row) = coord_parts(machine.arg_u32(mem.stack(), 3));
            let count_at = machine.arg_u32(mem.stack(), 4);
            if console_handle(process, handle).is_none() {
                return Some(Answer::stdcall(FALSE, 5));
            }
            let Ok(bytes) = Flat32Ptr(src).resolve(mem, len as usize) else {
                return Some(Answer::stdcall(FALSE, 5));
            };
            let chars = bytes.to_vec();
            let n = process.console.write_output_character(col, row, &chars);
            write_count(mem, count_at, n);
            Some(Answer::stdcall(TRUE, 5))
        }
        // WriteConsoleOutputAttribute(HANDLE, const WORD *, DWORD nLength,
        //                             COORD dwWriteCoord, LPDWORD lpNumberWritten)
        "WriteConsoleOutputAttribute" => {
            let handle = machine.arg_u32(mem.stack(), 0);
            let src = machine.arg_u32(mem.stack(), 1);
            let len = machine.arg_u32(mem.stack(), 2);
            let (col, row) = coord_parts(machine.arg_u32(mem.stack(), 3));
            let count_at = machine.arg_u32(mem.stack(), 4);
            if console_handle(process, handle).is_none() {
                return Some(Answer::stdcall(FALSE, 5));
            }
            let Ok(bytes) = Flat32Ptr(src).resolve(mem, (len as usize) * 2) else {
                return Some(Answer::stdcall(FALSE, 5));
            };
            let attrs: Vec<u8> = bytes.chunks_exact(2).map(|w| w[0]).collect();
            let n = process.console.write_output_attribute(col, row, &attrs);
            write_count(mem, count_at, n);
            Some(Answer::stdcall(TRUE, 5))
        }
        // FillConsoleOutputCharacterA(HANDLE, CHAR cCharacter, DWORD nLength,
        //                             COORD dwWriteCoord, LPDWORD lpNumberWritten)
        "FillConsoleOutputCharacterA" => {
            let handle = machine.arg_u32(mem.stack(), 0);
            let ch = machine.arg_u32(mem.stack(), 1);
            let len = machine.arg_u32(mem.stack(), 2);
            let (col, row) = coord_parts(machine.arg_u32(mem.stack(), 3));
            let count_at = machine.arg_u32(mem.stack(), 4);
            if console_handle(process, handle).is_none() {
                return Some(Answer::stdcall(FALSE, 5));
            }
            #[allow(clippy::cast_possible_truncation)]
            let n = process
                .console
                .fill_output_character(col, row, ch as u8, len as usize);
            write_count(mem, count_at, n);
            Some(Answer::stdcall(TRUE, 5))
        }
        // FillConsoleOutputAttribute(HANDLE, WORD wAttribute, DWORD nLength,
        //                            COORD dwWriteCoord, LPDWORD lpNumberWritten)
        "FillConsoleOutputAttribute" => {
            let handle = machine.arg_u32(mem.stack(), 0);
            let attr = machine.arg_u32(mem.stack(), 1);
            let len = machine.arg_u32(mem.stack(), 2);
            let (col, row) = coord_parts(machine.arg_u32(mem.stack(), 3));
            let count_at = machine.arg_u32(mem.stack(), 4);
            if console_handle(process, handle).is_none() {
                return Some(Answer::stdcall(FALSE, 5));
            }
            #[allow(clippy::cast_possible_truncation)]
            let n = process
                .console
                .fill_output_attribute(col, row, attr as u8, len as usize);
            write_count(mem, count_at, n);
            Some(Answer::stdcall(TRUE, 5))
        }
        // AreFileApisANSI(void)
        //
        // Real state, not a constant, and the trace is what says it has to be:
        // the program asks this and then immediately calls `SetFileApisToOEM`.
        // A host that answered a fixed TRUE would keep saying ANSI after the
        // program had switched the process to OEM, so the one caller that reads
        // this back would be told its own call had not happened.
        "AreFileApisANSI" => Some(Answer::stdcall(u32::from(process.file_apis_ansi), 0)),
        // SetFileApisToOEM(void) / SetFileApisToANSI(void)
        //
        // Which code page the *narrow* file APIs interpret their filenames in.
        // Recorded rather than acted on: this host's filenames go through
        // `dos::files::Files`, which is byte-oriented and has no code page to
        // switch. The flag is kept because `AreFileApisANSI` above reads it,
        // and a pair of setters with no reader would be the half-generator
        // mistake `crt.rs` documents for `srand`.
        //
        // Both are `VOID` and take nothing, so they clean nothing and their
        // return value is never read.
        "SetFileApisToOEM" => {
            process.file_apis_ansi = false;
            Some(Answer::stdcall(0, 0))
        }
        "SetFileApisToANSI" => {
            process.file_apis_ansi = true;
            Some(Answer::stdcall(0, 0))
        }
        _ => None,
    }
}

/// Store a `lpNumberOf...` out-parameter, if the caller passed one.
///
/// **Every one of these calls has one, and none of them may skip it.** The
/// count is how a caller learns a run was truncated at the edge of the buffer;
/// a host that returned TRUE and left the count untouched hands back whatever
/// the caller's uninitialised local happened to hold, and the bug surfaces
/// wherever that number is next used rather than here. A null pointer is the
/// caller declining to be told, which is legal and is the only case that
/// writes nothing.
fn write_count(mem: &mut Memory, at: u32, n: usize) {
    if at == 0 {
        return;
    }
    let n = u32::try_from(n).unwrap_or(u32::MAX);
    let _ = Flat32Ptr(at).write(mem, &n.to_le_bytes());
}

/// `CONSOLE_SCREEN_BUFFER_INFO`, 22 bytes, in the order Win32 lays it out:
/// `dwSize`, `dwCursorPosition`, `wAttributes`, `srWindow`,
/// `dwMaximumWindowSize`.
///
/// The window is reported as the whole buffer, and the maximum window as the
/// same, because this host paints every cell -- see `SetConsoleWindowInfo`.
/// `srWindow` is *inclusive* on both edges, which is why the right and bottom
/// are one less than the size rather than equal to it; a host that wrote the
/// size there would tell the program its window is one row and one column
/// larger than its buffer.
fn screen_buffer_info(console: &Console) -> [u8; 22] {
    let (cols, rows) = console.size();
    let (col, row) = console.cursor();
    let mut b = [0u8; 22];
    b[0..2].copy_from_slice(&cols.to_le_bytes());
    b[2..4].copy_from_slice(&rows.to_le_bytes());
    b[4..6].copy_from_slice(&col.to_le_bytes());
    b[6..8].copy_from_slice(&row.to_le_bytes());
    b[8..10].copy_from_slice(&u16::from(console.attribute()).to_le_bytes());
    // srWindow: left, top, right, bottom -- inclusive.
    b[10..12].copy_from_slice(&0u16.to_le_bytes());
    b[12..14].copy_from_slice(&0u16.to_le_bytes());
    b[14..16].copy_from_slice(&cols.saturating_sub(1).to_le_bytes());
    b[16..18].copy_from_slice(&rows.saturating_sub(1).to_le_bytes());
    b[18..20].copy_from_slice(&cols.to_le_bytes());
    b[20..22].copy_from_slice(&rows.to_le_bytes());
    b
}

#[cfg(test)]
mod win32_tests {
    use super::*;

    /// A `COORD` arrives as one 32-bit slot with `X` in the low half. Getting
    /// the halves the wrong way round is invisible on a square buffer, so the
    /// test uses a value whose halves differ and are not transposable.
    #[test]
    fn a_coord_is_one_argument_with_x_in_the_low_half() {
        assert_eq!(coord_parts(0x0019_0050), (80, 25), "80 cols, 25 rows");
        assert_eq!(coord_parts(0), (0, 0));
        assert_eq!(coord_parts(0xffff_0001), (1, 0xffff));
    }

    /// Only the two console devices open, and case does not matter. Anything
    /// else declines, so a real filename names itself instead of being opened
    /// down a path this host has not measured.
    #[test]
    fn only_the_console_devices_are_recognised() {
        assert_eq!(console_device("CONIN$"), Some(true));
        assert_eq!(console_device("conout$"), Some(false));
        assert_eq!(console_device("WCCMMPLS.MCV"), None);
        assert_eq!(console_device("CON"), None, "CON is not CONIN$");
    }

    /// `srWindow` is inclusive on both edges, so the right and bottom are one
    /// less than the size. A host that wrote the size there tells the program
    /// its window is a row and a column bigger than its buffer, and a
    /// full-screen program believes it.
    #[test]
    fn the_screen_buffer_info_window_is_inclusive_of_its_edges() {
        let mut c = Console::new(80, 25);
        c.set_cursor(10, 3);
        c.set_attribute(0x1f);
        let b = screen_buffer_info(&c);

        let word = |at: usize| u16::from_le_bytes(b[at..at + 2].try_into().unwrap());
        assert_eq!((word(0), word(2)), (80, 25), "dwSize");
        assert_eq!((word(4), word(6)), (10, 3), "dwCursorPosition");
        assert_eq!(word(8), 0x1f, "wAttributes");
        assert_eq!(
            (word(10), word(12), word(14), word(16)),
            (0, 0, 79, 24),
            "srWindow is left, top, right, bottom -- inclusive"
        );
        assert_eq!((word(18), word(20)), (80, 25), "dwMaximumWindowSize");
        assert_eq!(b.len(), 22, "CONSOLE_SCREEN_BUFFER_INFO is 22 bytes");
    }

    /// Resizing gives a grid of the requested size, and a zero dimension is
    /// refused rather than producing a buffer with no cells that swallows every
    /// later write.
    #[test]
    fn a_resize_takes_effect_and_a_zero_dimension_is_refused() {
        let mut c = Console::new(80, 25);
        assert!(c.resize(132, 60));
        assert_eq!(c.size(), (132, 60));

        assert!(!c.resize(0, 25), "zero columns is refused");
        assert!(!c.resize(80, 0), "zero rows is refused");
        assert_eq!(c.size(), (132, 60), "and the refusal changed nothing");
    }

    /// The cursor is a percentage in `1..=100` plus a visibility flag. Zero is
    /// refused because `bVisible` is what hides a cursor -- a size of zero
    /// would be a cursor of no height, which is a different thing.
    #[test]
    fn cursor_info_round_trips_and_refuses_an_impossible_size() {
        let mut c = Console::new(80, 25);
        assert_eq!(c.cursor_info(), (25, true), "Windows' own default");

        assert!(c.set_cursor_info(100, false));
        assert_eq!(c.cursor_info(), (100, false));

        assert!(!c.set_cursor_info(0, true), "0% is not a cursor");
        assert!(!c.set_cursor_info(101, true), "over 100% is not either");
        assert_eq!(c.cursor_info(), (100, false), "the refusals changed nothing");
    }

    /// The out-parameter every buffer call carries. A null pointer is the
    /// caller declining to be told, which is legal; anything else must be
    /// written, because it is how a caller learns a run was truncated.
    #[test]
    fn a_null_count_pointer_is_legal_and_writes_nothing() {
        let file = std::fs::read("/home/daniel/peepeebbs/wccmmutl.exe").expect("the utility");
        let mut l = crate::win32::load::load(&file).expect("loads");
        let at = crate::win32::process::put(&mut l.mem, &[0u8; 4]).expect("arena");

        write_count(&mut l.mem, at, 42);
        let got = Flat32Ptr(at).resolve(&l.mem, 4).expect("in memory");
        assert_eq!(u32::from_le_bytes(got.try_into().unwrap()), 42);

        // Must not panic, and must not write to address zero.
        write_count(&mut l.mem, 0, 7);
        assert!(Flat32Ptr(0).resolve(&l.mem, 4).is_err());
    }

    /// A console mode belongs to the *handle*, not the console: input and
    /// output are different bit sets over the same two calls, and a host that
    /// kept one mode would have setting the output mode clobber the input one.
    #[test]
    fn the_console_mode_is_per_handle() {
        let mut p = Process::new("X.EXE", &[]);
        let cin = p.insert_object(Object::Console {
            input: true,
            mode: DEFAULT_INPUT_MODE,
        });
        let cout = p.insert_object(Object::Console {
            input: false,
            mode: DEFAULT_OUTPUT_MODE,
        });
        assert_ne!(cin, cout, "two handles, not one");

        assert!(p.set_console_mode(cin, 0));
        match p.object(cin) {
            Some(Object::Console { mode, .. }) => assert_eq!(*mode, 0),
            other => panic!("expected a console handle, got {other:?}"),
        }
        match p.object(cout) {
            Some(Object::Console { mode, .. }) => assert_eq!(
                *mode, DEFAULT_OUTPUT_MODE,
                "the output handle's mode was not touched"
            ),
            other => panic!("expected a console handle, got {other:?}"),
        }
    }

    /// A handle that is not a console must be refused rather than quietly
    /// treated as one. An event handle passed to `SetConsoleMode` is a program
    /// bug, and Windows fails the call.
    #[test]
    fn a_non_console_handle_is_refused() {
        let mut p = Process::new("X.EXE", &[]);
        let event = p.insert_object(Object::Event {
            name: Some("E".to_owned()),
            manual_reset: false,
            signalled: false,
        });
        assert!(!p.set_console_mode(event, 0), "an event is not a console");
        assert!(!p.set_console_mode(0, 0), "and neither is NULL");
        assert!(!p.set_console_mode(999, 0), "nor a handle never handed out");
        assert_eq!(console_handle(&p, event), None);
    }

    /// `OpenEventA`'s name lookup must not find a console handle. `CONIN$` is
    /// a device name passed to `CreateFileA`, not a kernel object name.
    #[test]
    fn a_console_handle_is_not_findable_as_a_named_object() {
        let mut p = Process::new("X.EXE", &[]);
        p.insert_object(Object::Console {
            input: true,
            mode: DEFAULT_INPUT_MODE,
        });
        assert_eq!(p.named_object("CONIN$"), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The program reads its own screen back (`ReadConsoleOutputCharacterA` is
    /// in its import table), so the buffer is real state, not a write-only
    /// pipe to a terminal.
    #[test]
    fn what_was_written_reads_back() {
        let mut c = Console::new(80, 25);
        c.write_output_character(0, 0, b"HELLO");
        assert_eq!(c.read_output_character(0, 0, 5), b"HELLO");
    }

    /// Attributes travel separately from characters in the Win32 API --
    /// `WriteConsoleOutputAttribute` and `WriteConsoleOutputCharacterA` are
    /// two different imports, and writing one must not disturb the other.
    #[test]
    fn attributes_and_characters_are_independent() {
        let mut c = Console::new(80, 25);
        c.write_output_character(0, 0, b"X");
        c.write_output_attribute(0, 0, &[0x4e]);
        assert_eq!(c.read_output_character(0, 0, 1), b"X");
        assert_eq!(c.read_output_attribute(0, 0, 1), &[0x4e]);

        c.write_output_character(0, 0, b"Y");
        assert_eq!(
            c.read_output_attribute(0, 0, 1),
            &[0x4e],
            "the attribute survived"
        );
    }

    /// A write is placed by `(col, row)` in that order, because that is the
    /// order `COORD` uses. Getting this backwards is silent on a square buffer
    /// and wrong on every real one, so the test uses a buffer that is not
    /// square and a position that is not on the diagonal.
    #[test]
    fn a_position_is_column_then_row() {
        let mut c = Console::new(80, 25);
        c.write_output_character(3, 2, b"Z");
        assert_eq!(c.read_output_character(3, 2, 1), b"Z");
        assert_eq!(
            c.cells().cell(2, 3).ch,
            b'Z',
            "row 2, column 3 in the grid's own (row, col) order"
        );
    }

    /// Win32's buffer is one linear run: a write that reaches the end of a row
    /// continues on the next, rather than being clipped at the margin.
    #[test]
    fn a_write_runs_past_the_end_of_a_row_onto_the_next() {
        let mut c = Console::new(4, 2);
        let written = c.write_output_character(2, 0, b"abcd");
        assert_eq!(written, 4, "all four fit, across the row boundary");
        assert_eq!(c.read_output_character(0, 1, 2), b"cd");
    }

    /// Past the end of the buffer entirely, nothing is written and nothing
    /// panics -- the caller is told zero.
    #[test]
    fn a_write_past_the_buffer_writes_nothing() {
        let mut c = Console::new(4, 2);
        assert_eq!(c.write_output_character(0, 9, b"x"), 0);
        assert_eq!(c.read_output_character(0, 9, 1), Vec::<u8>::new());
    }

    /// A run that starts inside the buffer and would end past it is truncated,
    /// and says how much it really wrote.
    #[test]
    fn a_write_that_overruns_is_truncated_not_refused() {
        let mut c = Console::new(4, 2);
        assert_eq!(c.write_output_character(2, 1, b"abcd"), 2);
        assert_eq!(c.read_output_character(2, 1, 4), b"ab");
    }
}
