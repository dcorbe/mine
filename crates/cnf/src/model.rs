//! The editor as a pure state machine: no I/O, no ANSI, no crossterm.
//!
//! Everything the eventual screen displays -- which rows show, which one is
//! selected, what is scrolled into view, whether an edit would be accepted --
//! is a question [`Editor`] answers, so it is the one piece of this crate
//! that stays unit-testable once a terminal enters the picture.

use std::collections::BTreeMap;

use crate::hinge;
use crate::set::OptionSet;
use crate::spec::OptionSpec;
use crate::validate::{self, Invalid};

/// Does `haystack` contain `needle`, ignoring ASCII case? An empty `needle`
/// matches everything -- "no filter typed" and "filter matches all rows" are
/// the same state.
fn contains_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || haystack.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle))
}

/// Why [`Editor::edit`] refused to store a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditError {
    /// The value itself does not satisfy the selected option's type and
    /// bounds -- see [`validate::check`].
    Invalid(Invalid),
    /// The selected row is not currently in [`Editor::visible`]. A filter or
    /// another option's hinge hid it out from under the cursor since it was
    /// last selected; writing to it now would be an edit landing on a row
    /// nobody can see, which is worse than refusing outright.
    NotVisible,
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

    /// The slice of `visible` that a screen with `rows` rows should draw --
    /// `rows` entries starting at [`Self::top`], clamped to what `visible`
    /// actually holds. The scroll arithmetic lives here, tested, rather than
    /// recomputed by every widget that wants to draw a page of rows.
    #[must_use]
    pub fn window(&self, rows: usize) -> &[usize] {
        let start = self.top.min(self.visible.len());
        let end = start.saturating_add(rows).min(self.visible.len());
        &self.visible[start..end]
    }

    /// The spec for the option at flat index `n`, and its effective current
    /// value -- a pending edit if one exists, the on-disk value otherwise.
    /// Everything a screen needs to draw one row, from the model alone: no
    /// widget should need to hold its own [`OptionSet`] just to know an
    /// option's name, type, prompt or value.
    ///
    /// # Panics
    ///
    /// Same contract as [`OptionSet::at`]: if `n` is not a valid flat index
    /// into the set (`n >= ` the set's total option count), whether or not
    /// `n` is currently visible.
    #[must_use]
    pub fn option_at(&self, n: usize) -> (&OptionSpec, &[u8]) {
        let (file_index, opt) = self.set.at(n);
        let value = self.pending.get(&n).map_or_else(
            || {
                self.set.files()[file_index]
                    .messages()
                    .get(opt.index)
                    .expect("scan guarantees every option index addresses a real message")
            },
            Vec::as_slice,
        );
        (opt, value)
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
    /// Refuses before storing anything in two independent ways, checked in
    /// this order:
    ///
    /// 1. The selected row must be visible. `select` deliberately does not
    ///    enforce this (see its own doc), so it falls to `edit` to catch a
    ///    stale selection -- most sharply when a filter hides every row:
    ///    `recompute_visible` cannot repair `selected` onto an empty list,
    ///    so without this check `edit` would silently write to a row nobody
    ///    can see.
    /// 2. The value must satisfy the option's own declared bounds
    ///    ([`validate::check`]).
    ///
    /// Both checks run before `pending` is touched: a rejected edit changes
    /// nothing, including [`Self::dirty`]. Storing first and validating
    /// after would leave a bad value sitting in `pending` on the error path
    /// -- exactly the shape
    /// `an_invalid_edit_is_rejected_and_leaves_the_value_alone` exists to
    /// catch.
    ///
    /// # Errors
    ///
    /// [`EditError::NotVisible`] if the selected row is not in
    /// [`Self::visible`]. [`EditError::Invalid`] if `value` does not satisfy
    /// the selected option's type and bounds.
    pub fn edit(&mut self, value: Vec<u8>) -> Result<(), EditError> {
        if !self.visible.contains(&self.selected) {
            return Err(EditError::NotVisible);
        }
        let (_, opt) = self.set.at(self.selected);
        validate::check(&opt.kind, &value).map_err(EditError::Invalid)?;
        self.pending.insert(self.selected, value);
        self.recompute_visible();
        Ok(())
    }

    /// Does any pending edit actually differ from the value on disk?
    ///
    /// Not simply "is `pending` non-empty": editing a value back to what it
    /// started as leaves the entry in `pending` (removing it on a match
    /// would be a second place this class of bug could hide), but a
    /// sysop-facing "modified" indicator built on this must not light up
    /// when nothing would actually change on save.
    #[must_use]
    pub fn dirty(&self) -> bool {
        self.pending.iter().any(|(&n, edited)| {
            let (file_index, opt) = self.set.at(n);
            let on_disk = self.set.files()[file_index].messages().get(opt.index);
            on_disk != Some(edited.as_slice())
        })
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
        // Every assertion below must be false immediately before the action
        // that is supposed to make it true -- otherwise a no-op `move_by`,
        // or one with a broken current-position lookup, would pass anyway.
        // (The original version of this test started and ended at the same
        // boundary in one half, so a `move_by` doing nothing at all still
        // passed it -- see task-12 fix report.)
        let mut e = editor();
        e.select(1); // the middle, so both directions have somewhere to go
        assert_eq!(e.selected(), 1);

        e.move_by(1);
        assert_eq!(e.selected(), 2, "one step forward from the middle");

        e.move_by(-1);
        assert_eq!(e.selected(), 1, "one step back to the middle");

        e.move_by(-99);
        assert_eq!(e.selected(), 0, "a big step back saturates at the start, not below it");

        e.select(1); // back to the middle, so the next jump starts from non-zero
        e.move_by(99);
        assert_eq!(e.selected(), 2, "a big step forward saturates at the end, not past it");
    }

    #[test]
    fn window_returns_the_rows_currently_on_screen() {
        let mut e = editor();
        e.select(2);
        e.scroll_to_show(1);
        assert_eq!(e.window(1), &[2], "top must have scrolled to keep row 2 in a 1-row window");
    }

    #[test]
    fn window_clamps_to_the_end_of_the_visible_list_rather_than_panicking() {
        let e = editor();
        assert_eq!(e.window(10), &[0, 1, 2], "asking for more rows than exist is not an error");
    }

    #[test]
    fn option_at_gives_the_spec_and_the_effective_value_pending_first() {
        let mut e = editor();
        let (spec, value) = e.option_at(0);
        assert_eq!(spec.name, b"MODE");
        assert_eq!(value, b"FULL", "before any edit, the effective value is the on-disk one");

        e.edit(b"LITE".to_vec()).expect("valid choice"); // selected starts at 0, MODE
        let (spec, value) = e.option_at(0);
        assert_eq!(spec.name, b"MODE", "the spec itself does not change");
        assert_eq!(value, b"LITE", "a pending edit overrides the on-disk value");

        // A different, never-edited option still reports its on-disk value.
        let (other_spec, other_value) = e.option_at(2);
        assert_eq!(other_spec.name, b"ALWAYS");
        assert_eq!(other_value, b"2");
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

    #[test]
    fn editing_while_the_selected_row_is_filtered_out_is_refused() {
        // A filter narrowing to zero rows is the sharpest case:
        // `recompute_visible` cannot repair `selected` onto an empty list,
        // so without a check in `edit` itself this would silently write to
        // a row nobody can see.
        let mut e = editor();
        e.select(0);
        e.set_filter(b"nothing matches this");
        assert!(e.visible().is_empty());
        assert_eq!(e.edit(b"LITE".to_vec()), Err(EditError::NotVisible));
        assert!(!e.dirty(), "a refused edit must not dirty the set");
    }

    #[test]
    fn editing_a_directly_selected_hidden_row_is_refused() {
        // `select` does not itself check visibility (see its doc) -- so a
        // caller can point the cursor straight at a row a hinge is already
        // hiding, without going through a filter at all. `edit` still has to
        // catch it.
        let mut e = editor();
        assert!(e.visible().contains(&1), "EXTRA starts visible");
        // Make EXTRA hidden, then aim the cursor at it directly.
        e.select(0);
        e.edit(b"LITE".to_vec()).expect("valid choice");
        assert!(!e.visible().contains(&1), "EXTRA is now hidden");
        e.select(1);
        assert_eq!(e.edit(b"5".to_vec()), Err(EditError::NotVisible));
    }

    #[test]
    fn reverting_an_edit_to_its_original_value_leaves_the_set_clean() {
        let mut e = editor();
        e.select(2); // ALWAYS, on-disk value "2"
        e.edit(b"7".to_vec()).expect("7 is in range");
        assert!(e.dirty(), "7 differs from the on-disk value 2");
        e.edit(b"2".to_vec()).expect("2 is in range");
        assert!(!e.dirty(), "back to the on-disk value: nothing would change on save");
        assert!(e.pending().contains_key(&2), "the pending entry itself may still be kept");
    }
}
