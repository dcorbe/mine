//! Screens for the sysop editor: widgets that draw, and editors that take
//! keystrokes.
//!
//! `Key` is a small local enum, not `crossterm`'s -- every editor in this
//! module (`edit`, `help`, `list`, `text`) is exercised by feeding it keys
//! directly and reading a `Cells` back, no terminal required; none of those
//! submodules imports `crossterm`. [`from_crossterm`] is the one seam where
//! this module meets a real terminal -- Task 15's job, and the only part of
//! `bin/cnf.rs` with a pure input and a pure output, which is why it lives
//! here rather than in the binary: a function with no terminal to drive can
//! be tested directly, the way everything else in this crate is.
//!
//! [`app`] holds the rest of what the binary needs but does not have to
//! leave untested: the file picker's navigation, the fixed screen layout,
//! and the save/quit decisions -- all pure, all exercised without a
//! terminal, for the same reason.

pub mod app;
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
    PageUp,
    PageDown,
    /// Save the in-progress edit and leave the editor -- bound to Ctrl-S in
    /// [`from_crossterm`]. `Enter` cannot serve this role for
    /// [`text::TextEditor`]: it inserts a newline, as a multi-line editor's
    /// `Enter` must, so a `T` edit (73% of every option in the corpus --
    /// `crates/cnf/tests/corpus.rs`) has no other way to reach
    /// [`Outcome::Commit`]. [`edit::FieldEditor`] treats this the same as
    /// `Enter`, so the binding is uniform across both editors rather than
    /// something only `T` options have.
    Commit,
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

/// Translate a real terminal's key event into the local [`Key`] vocabulary.
///
/// `None` for anything with no meaning here -- dropped, not guessed at: an
/// unbound function key does not fall back to being treated as some other
/// key. Any other key chord held with Control is dropped too, Ctrl-S
/// excepted (see [`Key::Commit`]) -- passing a control chord through as its
/// bare letter would silently type `c` for a sysop who pressed Ctrl-C, which
/// is not what they asked for.
///
/// Release events are not filtered here -- on Unix `crossterm` only ever
/// reports `Press`, so most callers can hand this function every key event
/// unfiltered. A caller that might see `Release` (Windows, or the kitty
/// keyboard protocol's release reporting) needs to filter it first, the way
/// `mud-client`'s own loop does.
#[must_use]
pub fn from_crossterm(ev: crossterm::event::KeyEvent) -> Option<Key> {
    use crossterm::event::{KeyCode, KeyModifiers};

    if ev.modifiers.contains(KeyModifiers::CONTROL) {
        return match ev.code {
            KeyCode::Char('s' | 'S') => Some(Key::Commit),
            _ => None,
        };
    }

    match ev.code {
        // `encode` always returns exactly one byte for a one-character
        // string (unmapped characters become `?`, never nothing), so this
        // never has to guess at a fallback.
        KeyCode::Char(c) => textscreen::cp437::encode(&c.to_string()).first().copied().map(Key::Char),
        KeyCode::Backspace => Some(Key::Backspace),
        KeyCode::Left => Some(Key::Left),
        KeyCode::Right => Some(Key::Right),
        KeyCode::Up => Some(Key::Up),
        KeyCode::Down => Some(Key::Down),
        KeyCode::Home => Some(Key::Home),
        KeyCode::End => Some(Key::End),
        KeyCode::Enter => Some(Key::Enter),
        KeyCode::Esc => Some(Key::Esc),
        KeyCode::PageUp => Some(Key::PageUp),
        KeyCode::PageDown => Some(Key::PageDown),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn ev(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::CONTROL)
    }

    #[test]
    fn crossterm_keys_map_to_ours() {
        assert_eq!(from_crossterm(ev(KeyCode::Char('a'))), Some(Key::Char(b'a')));
        assert_eq!(from_crossterm(ev(KeyCode::Backspace)), Some(Key::Backspace));
        assert_eq!(from_crossterm(ev(KeyCode::Esc)), Some(Key::Esc));
        assert_eq!(from_crossterm(ev(KeyCode::PageUp)), Some(Key::PageUp));
        // A key with no meaning here is dropped, not guessed at.
        assert_eq!(from_crossterm(ev(KeyCode::F(9))), None);
    }

    #[test]
    fn ctrl_s_is_the_commit_binding() {
        assert_eq!(from_crossterm(ctrl(KeyCode::Char('s'))), Some(Key::Commit));
        // Case does not matter -- Shift+Ctrl+s still arrives as 'S' from a
        // real terminal, and it should still mean commit, not be dropped as
        // an unrecognised chord.
        assert_eq!(from_crossterm(ctrl(KeyCode::Char('S'))), Some(Key::Commit));
    }

    #[test]
    fn an_unbound_control_chord_is_dropped_not_read_as_its_bare_letter() {
        // Without the modifier check, this would fall through to the plain
        // `Char` arm and come back `Some(Key::Char(b'c'))` -- silently
        // typing 'c' for a sysop who pressed Ctrl-C to try to interrupt
        // something.
        assert_eq!(from_crossterm(ctrl(KeyCode::Char('c'))), None);
    }

    #[test]
    fn page_down_maps_too() {
        // The brief's own sample test only exercises `PageUp`; `PageDown`
        // needs its own assertion or a `PageUp`/`PageDown` swap in the match
        // arms would pass unnoticed.
        assert_eq!(from_crossterm(ev(KeyCode::PageDown)), Some(Key::PageDown));
    }
}
