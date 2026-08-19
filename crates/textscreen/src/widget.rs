//! Somewhere to paint, and something that paints there.
//!
//! Deliberately small. A widget is handed a rectangle and a grid and writes
//! cells; it does not lay itself out, size itself, or own its children. The
//! screens this serves are fixed 80x25 with a fixed help pane, where a
//! constraint solver would be more configuration than arithmetic.

use crate::cell::Cells;

/// A rectangle of cells, in grid coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub col: usize,
    pub row: usize,
    pub cols: usize,
    pub rows: usize,
}

/// Something that paints itself into a rectangle of a grid.
pub trait Widget {
    fn render(&self, area: Rect, buf: &mut Cells);
}
