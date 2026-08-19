//! A multi-line text editor, for `T` options.
//!
//! Lines split on `\n` only, and `Key::Enter` inserts a bare `\n` -- never
//! `\r\n` -- between them. That is not a style choice: `msg.rs` drops every
//! `\r` inside a value unconditionally on decode, by the format's own rules.
//! A value containing `\r\n`, exactly what a naive editor relaying a CRLF
//! text box would produce, is spliced in unchanged by `write::escape`, comes
//! back from the writer's own reparse without the `\r`, and is refused as
//! `WriteError::EditedMessageWrong` -- see
//! `crates/cnf/tests/write.rs`'s `an_edit_containing_a_raw_cr_comes_back_without_it`.
//! Emitting `\n`-only breaks here is what keeps a multi-line edit savable at
//! all.
//!
//! A `\r` already present in the value this editor opened with -- an on-disk
//! value that happens to carry one, or one the sysop types as an ordinary
//! character -- is not special-cased away: it is just another byte sitting
//! inside a line, unaffected by anything above. Braces and tildes need no
//! handling here either; `write::escape` encodes them on save.

use textscreen::cell::Cells;
use textscreen::widget::{Rect, Widget};

use crate::spec::OptionType;
use crate::write::{self, WriteError};

use super::{Key, Outcome};

const NORMAL: u8 = 0x07;

#[derive(Debug)]
pub struct TextEditor {
    lines: Vec<Vec<u8>>,
    row: usize,
    /// A byte offset into `lines[row]`, always `<= lines[row].len()`.
    col: usize,
    /// `lines`, joined by `\n` -- recomputed after every keystroke that
    /// changes them, so [`Self::value`] can hand back a borrow.
    value: Vec<u8>,
    /// The value this editor was opened with, for [`Self::warning`] to check
    /// the current value against.
    original: Vec<u8>,
}

impl TextEditor {
    /// Start editing `initial`, cursor at the very beginning.
    #[must_use]
    pub fn new(initial: Vec<u8>) -> Self {
        let lines = split_lines(&initial);
        Self { lines, row: 0, col: 0, value: initial.clone(), original: initial }
    }

    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// The refusal `write::check_edit` would give if the current value were
    /// saved as-is, as a message to show live -- `None` if it would be
    /// accepted.
    ///
    /// Re-run after every keystroke rather than only at save time: a sysop
    /// who learns a `%s` is missing only when they try to save has already
    /// lost the edit that dropped it. Checked against `Text` unconditionally
    /// -- this editor is never used for anything else.
    #[must_use]
    pub fn warning(&self) -> Option<String> {
        write::check_edit(&OptionType::Text, &self.original, &self.value)
            .err()
            .map(|e| describe(&e))
    }

    /// Apply one keystroke.
    pub fn key(&mut self, key: Key) -> Outcome {
        match key {
            Key::Char(b) => {
                self.lines[self.row].insert(self.col, b);
                self.col += 1;
            }
            Key::Backspace => {
                if self.col > 0 {
                    self.col -= 1;
                    self.lines[self.row].remove(self.col);
                } else if self.row > 0 {
                    let current = self.lines.remove(self.row);
                    self.row -= 1;
                    self.col = self.lines[self.row].len();
                    self.lines[self.row].extend_from_slice(&current);
                }
            }
            Key::Enter => {
                let rest = self.lines[self.row].split_off(self.col);
                self.lines.insert(self.row + 1, rest);
                self.row += 1;
                self.col = 0;
            }
            Key::Left => {
                if self.col > 0 {
                    self.col -= 1;
                } else if self.row > 0 {
                    self.row -= 1;
                    self.col = self.lines[self.row].len();
                }
            }
            Key::Right => {
                if self.col < self.lines[self.row].len() {
                    self.col += 1;
                } else if self.row + 1 < self.lines.len() {
                    self.row += 1;
                    self.col = 0;
                }
            }
            Key::Up => {
                if self.row > 0 {
                    self.row -= 1;
                    self.col = self.col.min(self.lines[self.row].len());
                }
            }
            Key::Down => {
                if self.row + 1 < self.lines.len() {
                    self.row += 1;
                    self.col = self.col.min(self.lines[self.row].len());
                }
            }
            Key::Home => self.col = 0,
            Key::End => self.col = self.lines[self.row].len(),
            Key::Esc => return Outcome::Cancel,
        }
        self.recompute_value();
        Outcome::Continue
    }

    fn recompute_value(&mut self) {
        let mut value = Vec::with_capacity(self.value.len());
        for (i, line) in self.lines.iter().enumerate() {
            if i > 0 {
                value.push(b'\n');
            }
            value.extend_from_slice(line);
        }
        self.value = value;
    }
}

/// Split on `\n` alone -- never `\r\n` or bare `\r` -- so any `\r` already in
/// the text stays exactly where it was, as an ordinary byte inside whichever
/// line it falls in.
fn split_lines(value: &[u8]) -> Vec<Vec<u8>> {
    value.split(|&b| b == b'\n').map(<[u8]>::to_vec).collect()
}

fn describe(e: &WriteError) -> String {
    format!("{e:?}")
}

impl Widget for TextEditor {
    fn render(&self, area: Rect, buf: &mut Cells) {
        if area.cols == 0 || area.rows == 0 {
            return;
        }
        for r in 0..area.rows {
            let row = area.row + r;
            for col in 0..area.cols {
                buf.put(row, area.col + col, b' ', NORMAL);
            }
            if let Some(line) = self.lines.get(r) {
                buf.write_str(row, area.col, line, NORMAL, area.cols);
            }
        }
    }
}
