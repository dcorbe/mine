//! The option list: one row per visible option, the selected row in reverse
//! video.

use textscreen::cell::Cells;
use textscreen::widget::{Rect, Widget};

use crate::model::Editor;

/// `MOPTLEN` (`MSGRDR.H`): the width an option's name gets before its value
/// starts. The column after it is a single separator space.
const NAME_COLS: usize = 8;

/// Light grey on black -- an unselected row.
const NORMAL: u8 = 0x07;
/// Reverse video -- the row the cursor is on.
const SELECTED: u8 = 0x70;

/// Every option [`Editor::visible`] currently shows, drawn from the model
/// alone: this never reaches around it for a name, value or selection state.
pub struct OptionList<'a>(pub &'a Editor);

impl Widget for OptionList<'_> {
    fn render(&self, area: Rect, buf: &mut Cells) {
        if area.cols == 0 || area.rows == 0 {
            return;
        }
        let editor = self.0;
        let selected = editor.selected();
        for (offset, &index) in editor.window(area.rows).iter().enumerate() {
            let row = area.row + offset;
            let attr = if index == selected { SELECTED } else { NORMAL };

            // Paint the whole row first, so the selection bar covers the
            // full width rather than just the characters a name or value
            // happens to occupy.
            for col in 0..area.cols {
                buf.put(row, area.col + col, b' ', attr);
            }

            let (spec, value) = editor.option_at(index);
            buf.write_str(row, area.col, &spec.name, attr, NAME_COLS.min(area.cols));

            let value_col = area.col + NAME_COLS + 1;
            let right_edge = area.col + area.cols;
            if value_col < right_edge {
                buf.write_str(row, value_col, value, attr, right_edge - value_col);
            }
        }
    }
}
