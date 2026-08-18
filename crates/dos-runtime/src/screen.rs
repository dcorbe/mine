//! A snapshot of the text screen, taken straight out of guest memory.
//!
//! No cooperation from the guest is needed: `B800:0000` is an ordinary part of
//! the shared mapping, so the screen can be read at any moment. That is the
//! same property the BIOS clock thread uses, pointed the other way.
//!
//! Attributes are kept, not discarded. A full-screen menu marks its selection
//! by *colour*, so text alone cannot say where the highlight bar is -- which is
//! exactly what a script needs to know before it presses Enter.

use crate::guest::{Guest, Ptr};

pub use textscreen::cell::{Cell, Cells};

/// The text screen as it stands right now: a grid, plus where the hardware
/// cursor is.
///
/// The cursor is deliberately *not* part of [`Cells`]. A grid is a grid whoever
/// filled it in, but "where the cursor is" belongs to whatever owns the screen
/// -- the CRTC for a DOS guest, a `SetConsoleCursorPosition` call for a Win32
/// one -- and the two do not keep it in the same place.
pub struct Screen {
    pub grid: Cells,
    pub cursor: (u8, u8),
    pub cursor_visible: bool,
}

impl Screen {
    /// Read the whole screen out of the guest's text buffer.
    pub fn snapshot<G: Guest>(
        g: &G,
        cols: usize,
        rows: usize,
        cursor: (u8, u8),
        cursor_visible: bool,
    ) -> Self {
        let mut cells = Vec::with_capacity(cols * rows);
        for row in 0..rows {
            let at = Ptr::new(0xb800, (row * cols * 2) as u16);
            match g.read(at, cols * 2) {
                Ok(bytes) => cells.extend(bytes.chunks_exact(2).map(|c| Cell {
                    ch: c[0],
                    attr: c[1],
                })),
                Err(_) => cells.extend(std::iter::repeat_n(Cell { ch: b' ', attr: 7 }, cols)),
            }
        }
        Self {
            grid: Cells { cols, rows, cells },
            cursor,
            cursor_visible,
        }
    }

    /// The line the hardware cursor sits on, trimmed.
    ///
    /// Not every program marks its selection with colour. LORDCFG moves the
    /// cursor and leaves the whole menu block one background, so `selected`
    /// reports the block and this reports the item -- a script needs both,
    /// and which one applies is a property of the program, not of the screen.
    ///
    /// The one query that genuinely needs both halves, which is why it lives
    /// here and the rest forward.
    pub fn cursor_line(&self) -> String {
        self.grid.line(self.cursor.0 as usize).trim().to_string()
    }

    pub fn cell(&self, row: usize, col: usize) -> Cell {
        self.grid.cell(row, col)
    }

    pub fn line(&self, row: usize) -> String {
        self.grid.line(row)
    }

    pub fn text(&self) -> String {
        self.grid.text()
    }

    pub fn contains(&self, needle: &str) -> bool {
        self.grid.contains(needle)
    }

    pub fn find(&self, needle: &str) -> Option<(usize, usize)> {
        self.grid.find(needle)
    }

    pub fn highlighted_rows(&self, min_run: usize) -> Vec<usize> {
        self.grid.highlighted_rows(min_run)
    }

    pub fn selected(&self) -> Option<String> {
        self.grid.selected()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn screen_from(lines: &[&str], highlight: Option<usize>) -> Screen {
        // Wide enough for the longest line, or the fixture silently truncates
        // the very text the test is asserting on.
        let cols = lines.iter().map(|l| l.len()).max().unwrap_or(1).max(20);
        let rows = lines.len();
        let mut cells = Vec::new();
        for (r, line) in lines.iter().enumerate() {
            let bytes = line.as_bytes();
            for col in 0..cols {
                let ch = bytes.get(col).copied().unwrap_or(b' ');
                let attr = if highlight == Some(r) { 0x70 } else { 0x07 };
                cells.push(Cell { ch, attr });
            }
        }
        Screen {
            grid: Cells { cols, rows, cells },
            cursor: (0, 0),
            cursor_visible: true,
        }
    }

    #[test]
    fn a_label_is_found_through_the_padding_a_menu_adds() {
        let s = screen_from(&["  Exit   the  program"], None);
        assert!(s.contains("Exit the program"));
        assert!(!s.contains("exit the program"), "matching is case sensitive");
    }

    #[test]
    fn the_highlighted_row_is_the_one_with_a_different_background() {
        let s = screen_from(&["Configure Nodes", "Register Lord", "Exit"], Some(1));
        assert_eq!(s.selected().as_deref(), Some("Register Lord"));
    }

    #[test]
    fn several_highlighted_rows_report_nothing_rather_than_the_first() {
        let mut s = screen_from(&["one", "two"], Some(0));
        // Colour the second row too.
        for col in 0..s.grid.cols {
            let i = s.grid.cols + col;
            s.grid.cells[i].attr = 0x70;
        }
        assert_eq!(s.selected(), None);
    }

    #[test]
    fn a_screen_with_no_highlight_selects_nothing() {
        let s = screen_from(&["plain", "text"], None);
        assert_eq!(s.selected(), None);
    }
}
