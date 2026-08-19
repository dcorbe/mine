//! The help pane: the selected option's comment paragraph, word-wrapped to
//! fit its rectangle.

use textscreen::cell::Cells;
use textscreen::widget::{Rect, Widget};

use crate::model::Editor;

const NORMAL: u8 = 0x07;

/// The selected option's comment paragraph -- [`crate::spec::OptionSpec::help`]
/// -- word-wrapped rather than truncated: a comment that runs past one line is
/// common (`AFKALT`'s and plenty of others), and cutting mid-word would make
/// it unreadable rather than just short.
pub struct HelpPane<'a>(pub &'a Editor);

impl Widget for HelpPane<'_> {
    fn render(&self, area: Rect, buf: &mut Cells) {
        if area.cols == 0 || area.rows == 0 {
            return;
        }
        let editor = self.0;
        // `option_at` panics if `selected()` is not a valid flat index, and
        // is only guaranteed valid when `visible` is non-empty (see
        // `Editor`'s own field doc). A caller is expected to refuse to open
        // an editor with zero options at all (`Editor::is_empty`), but this
        // guards independently rather than trusting that: a panic in a
        // render path takes the whole editor down, so degrading to a blank
        // pane here is the safer failure.
        if editor.visible().is_empty() {
            return;
        }
        let (spec, _) = editor.option_at(editor.selected());

        let mut row = area.row;
        let last_row = area.row + area.rows;
        let mut line: Vec<u8> = Vec::new();

        for word in spec.help.split(|&b| b == b' ').filter(|w| !w.is_empty()) {
            let candidate_len = if line.is_empty() { word.len() } else { line.len() + 1 + word.len() };
            if candidate_len > area.cols && !line.is_empty() {
                buf.write_str(row, area.col, &line, NORMAL, area.cols);
                row += 1;
                line.clear();
                if row >= last_row {
                    return;
                }
            }
            if !line.is_empty() {
                line.push(b' ');
            }
            line.extend_from_slice(word);
        }
        if !line.is_empty() {
            buf.write_str(row, area.col, &line, NORMAL, area.cols);
        }
    }
}
