//! A single-line field editor: type, backspace, move the cursor, commit or
//! cancel.
//!
//! Holds its own copy of the value rather than writing through to the
//! [`crate::model::Editor`] on every keystroke -- committing is the caller's
//! decision, made from [`FieldEditor::value`] and the [`Outcome`] `key`
//! returns, not something this type does to itself.

use textscreen::cell::Cells;
use textscreen::widget::{Rect, Widget};

use super::{Key, Outcome};

const NORMAL: u8 = 0x07;
const CURSOR: u8 = 0x70;

#[derive(Debug)]
pub struct FieldEditor {
    value: Vec<u8>,
    /// A byte offset into `value`, always `<= value.len()`.
    cursor: usize,
}

impl FieldEditor {
    /// Start editing `initial`, cursor at the beginning.
    #[must_use]
    pub fn new(initial: Vec<u8>) -> Self {
        Self { value: initial, cursor: 0 }
    }

    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Apply one keystroke.
    pub fn key(&mut self, key: Key) -> Outcome {
        match key {
            Key::Char(b) => {
                self.value.insert(self.cursor, b);
                self.cursor += 1;
            }
            Key::Backspace => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    self.value.remove(self.cursor);
                }
            }
            Key::Left => self.cursor = self.cursor.saturating_sub(1),
            Key::Right => self.cursor = (self.cursor + 1).min(self.value.len()),
            Key::Home => self.cursor = 0,
            Key::End => self.cursor = self.value.len(),
            // A field editor has one line -- nothing to page or move to.
            Key::Up | Key::Down | Key::PageUp | Key::PageDown => {}
            // `Commit` (Ctrl-S) is `Enter`'s equal here: a field editor's
            // `Enter` already commits, so the binding that exists only to
            // give `TextEditor` a way to commit does not need a second
            // meaning for the type that never needed one.
            Key::Enter | Key::Commit => return Outcome::Commit,
            Key::Esc => return Outcome::Cancel,
        }
        Outcome::Continue
    }
}

impl Widget for FieldEditor {
    fn render(&self, area: Rect, buf: &mut Cells) {
        if area.cols == 0 || area.rows == 0 {
            return;
        }
        for col in 0..area.cols {
            buf.put(area.row, area.col + col, b' ', NORMAL);
        }
        buf.write_str(area.row, area.col, &self.value, NORMAL, area.cols);

        // The cursor itself, in reverse video -- the character under it if
        // there is one, a blank if the cursor sits past the last character.
        let cursor_col = self.cursor.min(area.cols.saturating_sub(1));
        let ch = self.value.get(self.cursor).copied().unwrap_or(b' ');
        buf.put(area.row, area.col + cursor_col, ch, CURSOR);
    }
}
