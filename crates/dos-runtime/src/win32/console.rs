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
//! **Not yet reachable, and deliberately not wired in.** The measured trace
//! (`docs/2026-08-17-win32-import-trace.md`) stops at `cw3220mt.DLL!_time`:
//! every console call this program makes is behind the C runtime, which is
//! Phase 3. The sixteen console symbols are named in its import table, which is
//! what justifies the shape below, but none has been *observed* being called --
//! so no dispatch arm answers them yet. Adding arms now would be guessing at
//! arguments no trace has shown, and the plan's own rule is to implement a
//! symbol because this program calls it.

use crate::screen::Cells;

/// The default attribute a console starts with: light grey on black.
const DEFAULT_ATTRIBUTE: u8 = 7;

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
}

impl Console {
    pub fn new(cols: usize, rows: usize) -> Self {
        Self {
            grid: Cells::blank(cols, rows),
            cursor: (0, 0),
            attr: DEFAULT_ATTRIBUTE,
        }
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
