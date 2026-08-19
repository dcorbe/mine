//! The editor as a pure state machine: no I/O, no ANSI, no crossterm.
//!
//! Everything the eventual screen displays -- which rows show, which one is
//! selected, what is scrolled into view, whether an edit would be accepted --
//! is a question [`Editor`] answers, so it is the one piece of this crate
//! that stays unit-testable once a terminal enters the picture.

use std::collections::BTreeMap;

use crate::hinge;
use crate::set::OptionSet;
use crate::validate::{self, Invalid};

/// Does `haystack` contain `needle`, ignoring ASCII case? An empty `needle`
/// matches everything -- "no filter typed" and "filter matches all rows" are
/// the same state.
fn contains_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || haystack.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle))
}

/// The state a sysop's editing session needs: which options exist, which are
/// currently shown, which one the cursor is on, what has been typed but not
/// yet saved.
///
/// Option identity throughout this type is the flat index [`OptionSet::at`]
/// uses -- the same number across every method, whether or not that option
/// is currently visible.
#[derive(Debug)]
pub struct Editor {
    set: OptionSet,
    /// Edited values not yet written back to the set, keyed by flat index.
    pending: BTreeMap<usize, Vec<u8>>,
    /// Flat indices that currently pass both the hinge and the filter, in
    /// set order.
    visible: Vec<usize>,
    /// A flat index. Always a member of `visible` unless `visible` is empty,
    /// in which case there is nothing to point at.
    selected: usize,
    /// A position within `visible` -- the first row the screen should draw.
    top: usize,
    filter: Vec<u8>,
}

impl Editor {
    /// Wrap a parsed set for editing. Computes the initial visible list from
    /// the set's on-disk values, with no filter and the cursor on the first
    /// row.
    #[must_use]
    pub fn new(set: OptionSet) -> Self {
        let mut editor =
            Self { set, pending: BTreeMap::new(), visible: Vec::new(), selected: 0, top: 0, filter: Vec::new() };
        editor.recompute_visible();
        editor
    }

    /// The current value of the option named `name`, wherever in the set it
    /// lives -- a pending edit if there is one, otherwise the set's own
    /// value. This is what hinge evaluation must see: a hinge on `MODE`
    /// needs to react to a `MODE` edit the sysop has typed but not yet
    /// saved, not just what is on disk.
    fn value_of(&self, name: &[u8]) -> Option<Vec<u8>> {
        let at = (0..self.set.len()).find(|&n| self.set.at(n).1.name == name)?;
        self.pending.get(&at).cloned().or_else(|| self.set.value_of(name))
    }

    /// Recompute `visible` from the set, the filter and every hinge
    /// (evaluated against pending edits, not just saved values), then repair
    /// `selected` and `top` if either now points outside the new list.
    fn recompute_visible(&mut self) {
        let mut visible = Vec::new();
        for n in 0..self.set.len() {
            let (_, opt) = self.set.at(n);
            if !contains_ignore_case(&opt.name, &self.filter) {
                continue;
            }
            if hinge::visible(opt.hinge.as_ref(), &|name| self.value_of(name)) {
                visible.push(n);
            }
        }
        self.visible = visible;

        if !self.visible.is_empty() && !self.visible.contains(&self.selected) {
            // The row the cursor was on just disappeared. Land on the next
            // remaining row at or after it, or the last row if it was the
            // tail end that vanished -- either way, somewhere still shown,
            // never on a row nobody can see.
            self.selected = self
                .visible
                .iter()
                .copied()
                .find(|&v| v >= self.selected)
                .unwrap_or_else(|| *self.visible.last().expect("just checked non-empty"));
        }

        let max_top = self.visible.len().saturating_sub(1);
        if self.top > max_top {
            self.top = max_top;
        }
    }

    /// Flat indices passing both the current hinge state and the current
    /// filter, in set order.
    #[must_use]
    pub fn visible(&self) -> &[usize] {
        &self.visible
    }

    /// The flat index the cursor is on.
    #[must_use]
    pub fn selected(&self) -> usize {
        self.selected
    }

    /// Move the cursor to flat index `n`, clamped to a valid index into the
    /// set. Does not itself check visibility -- a caller driving the cursor
    /// off the visible list is a caller bug the screen should not have, but
    /// nothing here corrupts state if it happens; the next edit or filter
    /// change repairs it exactly as it would for any other cause.
    pub fn select(&mut self, n: usize) {
        let max = self.set.len().saturating_sub(1);
        self.selected = n.min(max);
    }

    /// Move the cursor by `delta` rows within the visible list, saturating
    /// at either end rather than wrapping or going out of range.
    pub fn move_by(&mut self, delta: isize) {
        if self.visible.is_empty() {
            return;
        }
        let at = self.visible.iter().position(|&v| v == self.selected).unwrap_or(0);
        #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
        let moved = (at as isize + delta).clamp(0, self.visible.len() as isize - 1) as usize;
        self.selected = self.visible[moved];
    }

    /// Adjust `top` so the selected row is inside a window of `rows` rows
    /// starting at `top`, within the visible list. A `rows` of `0` cannot
    /// show anything, so it is left alone rather than made to satisfy an
    /// impossible constraint.
    pub fn scroll_to_show(&mut self, rows: usize) {
        if rows == 0 || self.visible.is_empty() {
            return;
        }
        let Some(at) = self.visible.iter().position(|&v| v == self.selected) else {
            return;
        };
        if at < self.top {
            self.top = at;
        } else if at >= self.top + rows {
            self.top = at + 1 - rows;
        }
    }

    /// The first row, as a position within `visible`, the screen should
    /// draw.
    #[must_use]
    pub fn top(&self) -> usize {
        self.top
    }

    /// Narrow `visible` to options whose name contains `needle`,
    /// case-insensitively. An empty `needle` clears the filter.
    pub fn set_filter(&mut self, needle: &[u8]) {
        self.filter = needle.to_vec();
        self.recompute_visible();
    }

    /// Try to set the selected option's value to `value`.
    ///
    /// Validates against the option's own declared bounds before storing
    /// anything: a rejected edit changes nothing, including [`Self::dirty`].
    /// Storing first and validating after would leave a bad value sitting in
    /// `pending` on the error path -- exactly the shape
    /// `an_invalid_edit_is_rejected_and_leaves_the_value_alone` exists to
    /// catch.
    ///
    /// # Errors
    ///
    /// [`Invalid`] if `value` does not satisfy the selected option's type
    /// and bounds.
    pub fn edit(&mut self, value: Vec<u8>) -> Result<(), Invalid> {
        let (_, opt) = self.set.at(self.selected);
        validate::check(&opt.kind, &value)?;
        self.pending.insert(self.selected, value);
        self.recompute_visible();
        Ok(())
    }

    /// Is there any edit not yet written back to the set?
    #[must_use]
    pub fn dirty(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Edited values not yet written back, keyed by flat index.
    #[must_use]
    pub fn pending(&self) -> &BTreeMap<usize, Vec<u8>> {
        &self.pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn editor() -> Editor {
        // Three options, the middle one hinged off the first.
        let src = b"MODE {FULL} E FULL,LITE\r\n\
EXTRA {1} (MODE=FULL) N 0 9\r\n\
ALWAYS {2} N 0 9\r\n";
        Editor::new(OptionSet::from_source("T.MSG", src).expect("parses"))
    }

    #[test]
    fn a_hinged_option_disappears_when_its_hinge_stops_matching() {
        let mut e = editor();
        assert_eq!(e.visible().len(), 3);
        e.select(0);
        e.edit(b"LITE".to_vec()).expect("valid choice");
        assert_eq!(e.visible().len(), 2, "EXTRA is hinged on MODE=FULL");
    }

    #[test]
    fn an_invalid_edit_is_rejected_and_leaves_the_value_alone() {
        let mut e = editor();
        e.select(2);
        assert!(e.edit(b"99".to_vec()).is_err(), "ceiling is 9");
        assert!(!e.dirty(), "a rejected edit must not dirty the set");
    }

    #[test]
    fn the_filter_narrows_by_name_case_insensitively() {
        let mut e = editor();
        e.set_filter(b"extra");
        assert_eq!(e.visible().len(), 1);
        e.set_filter(b"");
        assert_eq!(e.visible().len(), 3);
    }

    #[test]
    fn selection_stays_inside_the_visible_list() {
        let mut e = editor();
        e.select(2);
        e.move_by(5);
        assert_eq!(e.selected(), 2, "saturates at the end");
        e.move_by(-99);
        assert_eq!(e.selected(), 0, "saturates at the start");
    }

    #[test]
    fn scrolling_keeps_the_selection_on_screen() {
        let mut e = editor();
        e.select(2);
        e.scroll_to_show(1);
        assert!(e.top() <= 2 && 2 < e.top() + 1, "selection must be in view");
    }

    #[test]
    fn selecting_a_now_hidden_option_moves_the_selection() {
        // Hiding the selected row must not leave the cursor pointing at
        // nothing -- the editor would then edit an option nobody can see.
        let mut e = editor();
        e.select(1);
        e.select(0);
        e.edit(b"LITE".to_vec()).expect("valid");
        assert!(e.visible().contains(&e.selected()));
    }

    #[test]
    fn hiding_the_selected_row_itself_moves_the_selection() {
        // The brief's own version of this test cannot discriminate the
        // repair logic in `recompute_visible`: `edit` only ever touches the
        // *selected* row, and in that fixture the row that vanishes (EXTRA)
        // is never the one selected at edit time (MODE is). This fixture
        // closes that gap with a hinge that references its own option, so
        // editing the selected row is what hides it.
        let src = b"SELF {A} (SELF=A) E A,B\r\n\
OTHER {x} N 0 9\r\n";
        let mut e = Editor::new(OptionSet::from_source("T.MSG", src).expect("parses"));
        e.select(0);
        assert_eq!(e.visible(), &[0, 1], "SELF=A matches its own hinge at the start");
        e.edit(b"B".to_vec()).expect("B is a listed choice");
        assert_eq!(e.visible(), &[1], "SELF no longer equals A, so it hides itself");
        assert!(e.visible().contains(&e.selected()), "the cursor must follow the row off the list");
        assert_eq!(e.selected(), 1, "OTHER is the only row left to land on");
    }
}
