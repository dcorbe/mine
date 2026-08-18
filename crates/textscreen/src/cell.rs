//! A grid of text-screen cells.
//!
//! A `Cell` is a CP437 byte and a DOS attribute byte, which is what both a
//! sampled `B800:0000` and a Win32 console screen buffer hold, and what the
//! vendor's own `.SCN` screen images are made of (80x25 pairs, 4000 bytes).

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

/// A grid of character cells, and nothing else.
///
/// Split out of [`Screen`] because the two ways a grid comes to exist have
/// nothing in common but the grid. A DOS program pokes `B800:0000` and
/// [`Screen::snapshot`] *samples* the result; a Win32 console program has no
/// memory-mapped buffer at all, and every change arrives as an explicit call to
/// a host that owns the cells (see [`crate::win32`]). What both share is the
/// grid itself and everything that reads one -- which is all of the querying
/// below, and the painter in [`crate::terminal`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Cells {
    pub cols: usize,
    pub rows: usize,
    pub cells: Vec<Cell>,
}

impl Cells {
    /// A grid of spaces in the ordinary light-grey-on-black attribute.
    pub fn blank(cols: usize, rows: usize) -> Self {
        Self {
            cols,
            rows,
            cells: vec![Cell { ch: b' ', attr: 7 }; cols * rows],
        }
    }

    /// The cell at `(row, col)`, or a blank one for a position off the grid.
    ///
    /// Out of range reads a blank rather than panicking because every caller
    /// here is scanning for text; a query that walks off the edge has found
    /// nothing, which is what a space says.
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
