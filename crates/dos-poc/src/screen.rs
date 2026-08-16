//! A snapshot of the text screen, taken straight out of guest memory.
//!
//! No cooperation from the guest is needed: `B800:0000` is an ordinary part of
//! the shared mapping, so the screen can be read at any moment. That is the
//! same property the BIOS clock thread uses, pointed the other way.
//!
//! Attributes are kept, not discarded. A full-screen menu marks its selection
//! by *colour*, so text alone cannot say where the highlight bar is -- which is
//! exactly what a script needs to know before it presses Enter.

use crate::guest::{DosGuest, DosPtr};

/// One character cell.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cell {
    pub ch: u8,
    pub attr: u8,
}

impl Cell {
    pub fn background(self) -> u8 {
        (self.attr >> 4) & 0x07
    }

    pub fn foreground(self) -> u8 {
        self.attr & 0x0f
    }
}

/// The text screen as it stands right now.
pub struct Screen {
    pub cols: usize,
    pub rows: usize,
    pub cells: Vec<Cell>,
    pub cursor: (u8, u8),
    pub cursor_visible: bool,
}

impl Screen {
    /// Read the whole screen out of the guest's text buffer.
    pub fn snapshot<G: DosGuest>(
        g: &G,
        cols: usize,
        rows: usize,
        cursor: (u8, u8),
        cursor_visible: bool,
    ) -> Self {
        let mut cells = Vec::with_capacity(cols * rows);
        for row in 0..rows {
            let at = DosPtr::new(0xb800, (row * cols * 2) as u16);
            match g.read(at, cols * 2) {
                Ok(bytes) => cells.extend(bytes.chunks_exact(2).map(|c| Cell {
                    ch: c[0],
                    attr: c[1],
                })),
                Err(_) => cells.extend(std::iter::repeat_n(Cell { ch: b' ', attr: 7 }, cols)),
            }
        }
        Self {
            cols,
            rows,
            cells,
            cursor,
            cursor_visible,
        }
    }

    pub fn cell(&self, row: usize, col: usize) -> Cell {
        self.cells
            .get(row * self.cols + col)
            .copied()
            .unwrap_or(Cell { ch: b' ', attr: 7 })
    }

    /// One row as printable text. Control bytes and the CP437 line-drawing
    /// range collapse to a space so that `contains` matches on words.
    pub fn line(&self, row: usize) -> String {
        (0..self.cols)
            .map(|col| {
                let ch = self.cell(row, col).ch;
                if ch.is_ascii_graphic() || ch == b' ' {
                    ch as char
                } else {
                    ' '
                }
            })
            .collect()
    }

    /// Every row, newline separated.
    pub fn text(&self) -> String {
        (0..self.rows)
            .map(|r| self.line(r))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Is `needle` anywhere on screen? Whitespace-insensitive, because a menu
    /// pads its labels and a script should not have to count spaces.
    pub fn contains(&self, needle: &str) -> bool {
        self.find(needle).is_some()
    }

    /// Where `needle` starts, as `(row, col)`.
    pub fn find(&self, needle: &str) -> Option<(usize, usize)> {
        let squashed = squash(needle);
        if squashed.is_empty() {
            return None;
        }
        for row in 0..self.rows {
            let line = self.line(row);
            // Compare on a squashed copy, but report the column in the original
            // by walking forward and counting.
            if let Some(col) = find_squashed(&line, &squashed) {
                return Some((row, col));
            }
        }
        None
    }

    /// The background colour that most of the screen uses.
    fn dominant_background(&self) -> u8 {
        let mut counts = [0u32; 8];
        for cell in &self.cells {
            counts[cell.background() as usize] += 1;
        }
        counts
            .iter()
            .enumerate()
            .max_by_key(|(_, n)| **n)
            .map(|(i, _)| i as u8)
            .unwrap_or(0)
    }

    /// Rows carrying a run of cells whose background differs from the rest of
    /// the screen -- which is how a full-screen menu draws its selection.
    ///
    /// `min_run` keeps a single stray coloured cell from reading as a bar.
    pub fn highlighted_rows(&self, min_run: usize) -> Vec<usize> {
        let background = self.dominant_background();
        let mut rows = Vec::new();
        for row in 0..self.rows {
            let mut run = 0usize;
            let mut best = 0usize;
            for col in 0..self.cols {
                if self.cell(row, col).background() == background {
                    run = 0;
                } else {
                    run += 1;
                    best = best.max(run);
                }
            }
            if best >= min_run {
                rows.push(row);
            }
        }
        rows
    }

    /// The line the hardware cursor sits on, trimmed.
    ///
    /// Not every program marks its selection with colour. LORDCFG moves the
    /// cursor and leaves the whole menu block one background, so `selected`
    /// reports the block and this reports the item -- a script needs both,
    /// and which one applies is a property of the program, not of the screen.
    pub fn cursor_line(&self) -> String {
        self.line(self.cursor.0 as usize).trim().to_string()
    }

    /// The text of the single highlighted row, if exactly one stands out.
    ///
    /// Deliberately `None` when several rows are highlighted: a caller that
    /// wanted "the selected item" should not silently get the first of many.
    pub fn selected(&self) -> Option<String> {
        match self.highlighted_rows(4).as_slice() {
            [row] => Some(self.line(*row).trim().to_string()),
            _ => None,
        }
    }
}

/// Collapse runs of whitespace so a match survives a menu's own padding.
fn squash(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Find `needle` (already squashed) in `haystack`, reporting the column in the
/// *original* string.
fn find_squashed(haystack: &str, needle: &str) -> Option<usize> {
    let bytes = haystack.as_bytes();
    for start in 0..bytes.len() {
        let tail = squash(&haystack[start..]);
        if tail.starts_with(needle) {
            // Only report a start that is not itself mid-whitespace.
            if start == 0 || bytes[start - 1] == b' ' || bytes[start] != b' ' {
                return Some(start);
            }
        }
    }
    None
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
            cols,
            rows,
            cells,
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
        for col in 0..s.cols {
            let i = s.cols + col;
            s.cells[i].attr = 0x70;
        }
        assert_eq!(s.selected(), None);
    }

    #[test]
    fn a_screen_with_no_highlight_selects_nothing() {
        let s = screen_from(&["plain", "text"], None);
        assert_eq!(s.selected(), None);
    }
}
