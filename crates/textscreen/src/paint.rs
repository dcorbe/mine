//! Turning a cell grid into ANSI, one changed row at a time.
//!
//! The diff is per row, not per cell. That is enough for a local terminal and
//! for the guest screens this was built for; tightening it to runs of cells is
//! a change to make when something measures a need for it, not before.

use std::io::{self, Write};

use crate::cell::{Cell, Cells};
use crate::cp437;

/// DOS attribute colour order to ANSI's.
///
/// The two differ: DOS counts blue as 1 and red as 4, ANSI the other way
/// round. Passing the index through unchanged swaps every red and blue on the
/// screen.
const TO_ANSI: [u8; 8] = [0, 4, 2, 6, 1, 5, 3, 7];

/// A terminal's worth of remembered state: what was last painted.
#[derive(Default)]
pub struct Painter {
    last: Vec<Cell>,
}

impl Painter {
    #[must_use]
    pub fn new() -> Self {
        Self { last: Vec::new() }
    }

    /// Redraw, skipping rows that have not changed since the last paint.
    ///
    /// Writes to `out` rather than stdout so that what it chose to emit can be
    /// inspected. Does not flush -- the caller owns that decision, so that a
    /// caller batching several paints does not pay for each one.
    pub fn paint(
        &mut self,
        out: &mut impl Write,
        grid: &Cells,
        cursor: (u8, u8),
        cursor_visible: bool,
    ) -> io::Result<()> {
        let mut buf = String::with_capacity(8 * 1024);
        buf.push_str("\x1b[?25l");

        let unchanged = self.last.len() == grid.cells.len();
        for row in 0..grid.rows {
            let start = row * grid.cols;
            let end = start + grid.cols;
            if unchanged && self.last[start..end] == grid.cells[start..end] {
                continue;
            }
            buf.push_str(&format!("\x1b[{};1H", row + 1));
            let mut attr = None;
            for col in 0..grid.cols {
                let cell = grid.cell(row, col);
                if attr != Some(cell.attr) {
                    let fg = cell.foreground();
                    let bg = cell.background();
                    let fg_code = if fg >= 8 {
                        90 + u16::from(TO_ANSI[usize::from(fg - 8)])
                    } else {
                        30 + u16::from(TO_ANSI[usize::from(fg)])
                    };
                    let bg_code = 40 + u16::from(TO_ANSI[usize::from(bg)]);
                    buf.push_str(&format!("\x1b[0;{fg_code};{bg_code}m"));
                    attr = Some(cell.attr);
                }
                buf.push(cp437::glyph(cell.ch));
            }
            buf.push_str("\x1b[0m");
        }

        let (row, col) = cursor;
        buf.push_str(&format!(
            "\x1b[{};{}H",
            u16::from(row) + 1,
            u16::from(col) + 1
        ));
        buf.push_str(if cursor_visible {
            "\x1b[?25h"
        } else {
            "\x1b[?25l"
        });

        out.write_all(buf.as_bytes())?;
        self.last = grid.cells.clone();
        Ok(())
    }
}
