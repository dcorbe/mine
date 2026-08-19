//! Screens for the sysop editor: widgets that draw, and editors that take
//! keystrokes.
//!
//! `Key` is a small local enum, not `crossterm`'s -- everything in this
//! module is exercised by feeding it keys directly and reading a `Cells`
//! back, no terminal required. Translating a real terminal's key events into
//! `Key` is Task 15's job, not this module's; nothing here imports
//! `crossterm`.

pub mod edit;
pub mod help;
pub mod list;
pub mod text;

/// A keystroke, abstracted away from any particular terminal library.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Char(u8),
    Backspace,
    Left,
    Right,
    Up,
    Down,
    Home,
    End,
    Enter,
    Esc,
}

/// What a keystroke did to an editor's in-progress session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The keystroke was applied (or had nothing to do); editing continues.
    Continue,
    /// The sysop asked to keep the value -- [`edit::FieldEditor::value`] or
    /// [`text::TextEditor::value`] is what should be saved.
    Commit,
    /// The sysop asked to discard the edit.
    Cancel,
}
