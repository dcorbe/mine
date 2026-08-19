//! The parts of `bin/cnf.rs` that do not need a terminal to be right.
//!
//! Most of a terminal loop cannot be unit-tested -- there is no terminal to
//! drive it with, and the workspace has no precedent for faking one. What
//! *can* be pulled out of that loop and tested directly is kept here: the
//! file picker's navigation (the same pure state-machine shape as
//! [`crate::model::Editor`], just without a hinge or a filter), the fixed
//! screen layout's arithmetic, the quit-while-dirty rule, and what a save
//! should write before anything is written. `bin/cnf.rs` itself is left
//! holding only the terminal I/O and the glue between these pieces.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use textscreen::cell::Cells;
use textscreen::widget::{Rect, Widget};

use crate::set::OptionSet;
use crate::write::{self, WriteError};

const NORMAL: u8 = 0x07;
const SELECTED: u8 = 0x70;

/// The `*.MSG` picker: which files exist and which one the cursor is on.
/// Pure navigation, in the same shape as [`crate::model::Editor`] -- `Enter`
/// and `Esc` are the caller's decision (opening a file or quitting the
/// program is not something this type can do on its own), so it exposes
/// only movement.
#[derive(Debug)]
pub struct Picker {
    paths: Vec<PathBuf>,
    selected: usize,
    top: usize,
}

impl Picker {
    #[must_use]
    pub fn new(paths: Vec<PathBuf>) -> Self {
        Self { paths, selected: 0, top: 0 }
    }

    #[must_use]
    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }

    #[must_use]
    pub fn selected(&self) -> usize {
        self.selected
    }

    /// The path under the cursor, or `None` if the picker holds no files.
    #[must_use]
    pub fn selected_path(&self) -> Option<&Path> {
        self.paths.get(self.selected).map(PathBuf::as_path)
    }

    #[must_use]
    pub fn top(&self) -> usize {
        self.top
    }

    /// Move the cursor by `delta` rows, saturating at either end rather
    /// than wrapping or going out of range -- same rule as
    /// [`crate::model::Editor::move_by`].
    pub fn move_by(&mut self, delta: isize) {
        if self.paths.is_empty() {
            return;
        }
        #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
        let moved = (self.selected as isize + delta).clamp(0, self.paths.len() as isize - 1) as usize;
        self.selected = moved;
    }

    /// Adjust `top` so the selected row is inside a window of `rows` rows
    /// starting at `top` -- same rule as
    /// [`crate::model::Editor::scroll_to_show`].
    pub fn scroll_to_show(&mut self, rows: usize) {
        if rows == 0 || self.paths.is_empty() {
            return;
        }
        if self.selected < self.top {
            self.top = self.selected;
        } else if self.selected >= self.top + rows {
            self.top = self.selected + 1 - rows;
        }
    }

    /// The slice of `paths` a screen with `rows` rows should draw, starting
    /// at [`Self::top`] -- same rule as [`crate::model::Editor::window`].
    #[must_use]
    pub fn window(&self, rows: usize) -> &[PathBuf] {
        let start = self.top.min(self.paths.len());
        let end = start.saturating_add(rows).min(self.paths.len());
        &self.paths[start..end]
    }
}

impl Widget for Picker {
    fn render(&self, area: Rect, buf: &mut Cells) {
        if area.cols == 0 || area.rows == 0 {
            return;
        }
        for (offset, path) in self.window(area.rows).iter().enumerate() {
            let row = area.row + offset;
            let attr = if self.top + offset == self.selected { SELECTED } else { NORMAL };
            for col in 0..area.cols {
                buf.put(row, area.col + col, b' ', attr);
            }
            let name = path.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned());
            buf.write_str(row, area.col, name.as_bytes(), attr, area.cols);
        }
    }
}

/// The fixed screen split: an option list, a one-row separator, and a help
/// pane at the bottom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub list: Rect,
    /// The row a separator (or a status line -- `bin/cnf.rs` uses this row
    /// for both) belongs on. May be `>= rows` if there is no room for one;
    /// nothing in `Cells::put` panics for that, it just drops the write.
    pub separator_row: usize,
    pub help: Rect,
}

/// Split `rows` into the option list, a one-row separator and a two-row help
/// pane at the bottom -- rows 0-21, 22 and 23-24 for the brief's own 80x25
/// screen, generalised so a resize to a different height degrades rather
/// than panicking: the help pane keeps its 2 rows (down to however many
/// `rows` actually has), the separator gets 1 more if there is room left
/// after that, and the list gets whatever remains.
#[must_use]
pub fn layout(cols: usize, rows: usize) -> Layout {
    let help_rows = 2.min(rows);
    let separator_rows = usize::from(rows > help_rows);
    let list_rows = rows.saturating_sub(help_rows + separator_rows);
    let list = Rect { col: 0, row: 0, cols, rows: list_rows };
    let separator_row = list_rows;
    let help = Rect { col: 0, row: list_rows + separator_rows, cols, rows: help_rows };
    Layout { list, separator_row, help }
}

/// Whether pressing `q` should actually quit now.
///
/// Quitting while [`crate::model::Editor::dirty`] is refused on the first
/// press and only honoured on a second -- `armed` is whether the previous
/// keystroke was already such a first press. Resetting `armed` on any other
/// key is the caller's job: only the caller, running the actual event loop,
/// knows what "any other key" means across a whole session.
#[must_use]
pub fn confirm_quit(dirty: bool, armed: bool) -> bool {
    !dirty || armed
}

/// Resolve the sibling file names [`crate::set::siblings`] declares against
/// the `*.MSG` files actually present in `listing` (the same convention
/// [`crate::set::list_msg_files`] returns), matching case-insensitively on
/// the file name.
///
/// A declared sibling that names a file which is not present is dropped
/// rather than treated as an error -- `FILE0n` is a hint, not a contract
/// (see [`crate::set::siblings`]'s own doc), and a stale or missing one
/// should not stop the sysop from opening the file that IS there.
#[must_use]
pub fn resolve_siblings(listing: &[PathBuf], siblings: &[String]) -> Vec<PathBuf> {
    siblings
        .iter()
        .filter_map(|name| {
            listing
                .iter()
                .find(|p| p.file_name().is_some_and(|f| f.to_string_lossy().eq_ignore_ascii_case(name)))
                .cloned()
        })
        .collect()
}

/// The `.MCV` path a `.MSG` path compiles to, preserving the case pattern of
/// the original extension -- `WCCMMUD.MSG` gets `WCCMMUD.MCV`,
/// `wccmmud.msg` gets `wccmmud.mcv`. Every real distribution uses the
/// upper-case form; the lower-case fallback is here only so a sysop's own
/// lower-case file does not get an upper-case `.MCV` sitting oddly next to
/// it.
#[must_use]
pub fn mcv_path(msg_path: &Path) -> PathBuf {
    let upper = msg_path.extension().and_then(|e| e.to_str()).is_none_or(|e| e.chars().all(|c| !c.is_lowercase()));
    msg_path.with_extension(if upper { "MCV" } else { "mcv" })
}

/// One file's worth of what a save should write, computed but not yet
/// written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveWrite {
    /// The name [`crate::spec::SpecFile::name`] was parsed with -- a file
    /// name, not a path; `bin/cnf.rs` joins it to the directory it opened.
    pub file_name: String,
    pub msg: Vec<u8>,
    pub mcv: Vec<u8>,
}

/// Which file in `set` flat index `n` lives in, and its position within
/// that file's own `options()` list -- what [`write::rewrite`]'s edit list
/// wants, which is not the number [`OptionSet::at`] hands back (that is the
/// option itself, not its position). Mirrors `OptionSet::at`'s own walk;
/// duplicated rather than exposed from there because nothing else needs it.
///
/// # Panics
///
/// If `n` is not a valid flat index into `set` -- same contract as
/// [`OptionSet::at`].
fn locate(set: &OptionSet, n: usize) -> (usize, usize) {
    let mut remaining = n;
    for (file_index, file) in set.files().iter().enumerate() {
        let len = file.options().len();
        if remaining < len {
            return (file_index, remaining);
        }
        remaining -= len;
    }
    panic!("flat index {n} out of range for a set of {} options", set.len());
}

/// Decide what a save should write, without writing anything.
///
/// Groups `pending` by file, skips any file none of whose edits would
/// actually change it on disk (the same question [`crate::model::Editor::dirty`]
/// answers, applied per file rather than to the whole set -- editing a
/// value back to what it started as must not force a write), then for each
/// changed file: [`write::rewrite`], then [`write::recompile`].
///
/// # Errors
///
/// The first [`WriteError`] either step produces, paired with the name of
/// the file it came from. Returned before anything past it is computed --
/// nothing in this function's return value is written to anywhere,
/// `bin/cnf.rs` writes files only from an `Ok` result, so an `Err` here
/// means nothing is written for any file, including ones that would have
/// succeeded.
pub fn plan_save(set: &OptionSet, pending: &BTreeMap<usize, Vec<u8>>) -> Result<Vec<SaveWrite>, (String, WriteError)> {
    let mut by_file: Vec<Vec<(usize, Vec<u8>)>> = vec![Vec::new(); set.files().len()];
    for (&n, value) in pending {
        let (file_index, local) = locate(set, n);
        by_file[file_index].push((local, value.clone()));
    }

    let mut out = Vec::new();
    for (file_index, file) in set.files().iter().enumerate() {
        let edits = &by_file[file_index];
        if edits.is_empty() {
            continue;
        }
        let changed = edits
            .iter()
            .any(|(local, value)| file.messages().get(file.options()[*local].index) != Some(value.as_slice()));
        if !changed {
            continue;
        }
        let msg = write::rewrite(file, edits).map_err(|e| (file.name().to_string(), e))?;
        let mcv = write::recompile(&msg, file.name()).map_err(|e| (file.name().to_string(), e))?;
        out.push(SaveWrite { file_name: file.name().to_string(), msg, mcv });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(names: &[&str]) -> Vec<PathBuf> {
        names.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn move_by_saturates_at_either_end() {
        let mut p = Picker::new(paths(&["a", "b", "c"]));
        p.move_by(1);
        assert_eq!(p.selected(), 1, "one step forward from the start");
        p.move_by(-99);
        assert_eq!(p.selected(), 0, "a big step back saturates at the start, not below it");
        p.move_by(99);
        assert_eq!(p.selected(), 2, "a big step forward saturates at the end, not past it");
    }

    #[test]
    fn move_by_on_an_empty_picker_does_nothing() {
        let mut p = Picker::new(Vec::new());
        p.move_by(5);
        assert_eq!(p.selected(), 0);
        assert_eq!(p.selected_path(), None);
    }

    #[test]
    fn scrolling_keeps_the_selection_on_screen() {
        let mut p = Picker::new(paths(&["a", "b", "c", "d", "e"]));
        p.move_by(4);
        assert_eq!(p.selected(), 4);
        p.scroll_to_show(2);
        assert!(p.top() <= 4 && 4 < p.top() + 2, "selection must be in view");
        assert_eq!(p.window(2), &paths(&["d", "e"])[..]);
    }

    #[test]
    fn scrolling_at_the_exact_boundary_still_scrolls() {
        // Selecting the row exactly one past the current window's end (top
        // 0, rows 2, selected 2) is the one case that tells `selected >=
        // top + rows` and a mutated `selected > top + rows` apart -- every
        // selection further past the window satisfies both.
        let mut p = Picker::new(paths(&["a", "b", "c"]));
        p.move_by(2);
        assert_eq!(p.selected(), 2);
        p.scroll_to_show(2);
        assert!(2 < p.top() + 2, "the boundary row must have scrolled into view, top is {}", p.top());
    }

    #[test]
    fn window_clamps_to_the_end_of_the_list_rather_than_panicking() {
        let p = Picker::new(paths(&["a", "b"]));
        assert_eq!(p.window(10), &paths(&["a", "b"])[..], "asking for more rows than exist is not an error");
    }

    #[test]
    fn the_picker_draws_names_and_marks_the_selection() {
        let mut p = Picker::new(paths(&["one.msg", "two.msg"]));
        p.move_by(1);
        // Extra blank rows beyond the two real ones so the unselected
        // background has a real majority: with exactly two equal-size rows
        // (one normal, one selected) `Cells::dominant_background` ties and
        // `highlighted_rows` picks the wrong one -- see
        // `OptionList`'s own tests, which render into a taller buffer than
        // their row count for the same reason.
        let mut buf = Cells::blank(20, 5);
        p.render(Rect { col: 0, row: 0, cols: 20, rows: 2 }, &mut buf);
        assert!(buf.line(0).contains("one.msg"));
        assert!(buf.line(1).contains("two.msg"));
        assert_eq!(buf.highlighted_rows(4), vec![1], "row 1 (two.msg) is under the cursor");
    }

    #[test]
    fn layout_matches_the_briefs_80x25_split() {
        let l = layout(80, 25);
        assert_eq!(l.list, Rect { col: 0, row: 0, cols: 80, rows: 22 }, "rows 0-21");
        assert_eq!(l.separator_row, 22);
        assert_eq!(l.help, Rect { col: 0, row: 23, cols: 80, rows: 2 }, "rows 23-24");
    }

    #[test]
    fn layout_never_panics_on_a_degenerate_size() {
        for rows in 0..4 {
            let l = layout(80, rows);
            assert!(l.list.rows + l.help.rows <= rows, "must not claim more rows than exist: {rows}");
        }
    }

    #[test]
    fn quitting_clean_needs_no_confirmation() {
        assert!(confirm_quit(false, false), "nothing unsaved, first press quits");
    }

    #[test]
    fn quitting_dirty_needs_a_second_press() {
        assert!(!confirm_quit(true, false), "dirty and not yet armed: refused");
        assert!(confirm_quit(true, true), "dirty but armed by an earlier q: quits");
    }

    #[test]
    fn a_self_naming_sibling_is_not_resolved_if_absent() {
        let listing = paths(&["SELF.MSG"]);
        assert_eq!(resolve_siblings(&listing, &["MISSING.MSG".to_string()]), Vec::<PathBuf>::new());
    }

    #[test]
    fn a_present_sibling_resolves_case_insensitively() {
        let listing = paths(&["dir/ELWICTXT.MSG", "dir/ELWIC.MSG"]);
        let resolved = resolve_siblings(&listing, &["elwictxt.msg".to_string()]);
        assert_eq!(resolved, vec![PathBuf::from("dir/ELWICTXT.MSG")]);
    }

    #[test]
    fn mcv_path_matches_the_msgs_case() {
        assert_eq!(mcv_path(Path::new("WCCMMUD.MSG")), PathBuf::from("WCCMMUD.MCV"));
        assert_eq!(mcv_path(Path::new("wccmmud.msg")), PathBuf::from("wccmmud.mcv"));
    }

    fn set_with_one_option() -> OptionSet {
        // Bare value, no embedded prompt -- a `GAMCRD {Credits per minute
        // 60}`-style prompt would make the on-disk message "Credits per
        // minute 60", not "60", and a revert test needs to know the exact
        // on-disk bytes it is reverting to.
        let src = b"GAMCRD {60} N 0 32767\r\n";
        OptionSet::from_source("T.MSG", src).expect("parses")
    }

    #[test]
    fn plan_save_is_empty_when_nothing_is_pending() {
        let set = set_with_one_option();
        assert_eq!(plan_save(&set, &BTreeMap::new()), Ok(Vec::new()));
    }

    #[test]
    fn plan_save_skips_a_file_whose_edit_reverts_to_the_on_disk_value() {
        let set = set_with_one_option();
        let mut pending = BTreeMap::new();
        pending.insert(0, b"60".to_vec()); // the on-disk value, unchanged
        assert_eq!(plan_save(&set, &pending), Ok(Vec::new()), "reverting to the on-disk value must not force a write");
    }

    #[test]
    fn plan_save_produces_the_rewritten_msg_and_a_recompiled_mcv() {
        let set = set_with_one_option();
        let mut pending = BTreeMap::new();
        pending.insert(0, b"120".to_vec());
        let writes = plan_save(&set, &pending).expect("no WriteError expected");
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].file_name, "T.MSG");
        assert!(
            writes[0].msg.windows(3).any(|w| w == b"120"),
            "the rewritten bytes must contain the new value: {:?}",
            String::from_utf8_lossy(&writes[0].msg)
        );
        assert!(!writes[0].mcv.is_empty(), "recompile must produce something");
    }

    #[test]
    fn plan_save_attributes_a_flat_index_to_the_right_option_within_its_file() {
        // Two options in one file: flat index 1 must land on OTHER, not
        // ONE, or `locate`'s arithmetic (which this exists to check) has
        // drifted from `OptionSet::at`'s.
        let src = b"ONE {1} N 0 9\r\nOTHER {2} N 0 9\r\n";
        let set = OptionSet::from_source("T.MSG", src).expect("parses");
        let mut pending = BTreeMap::new();
        pending.insert(1, b"7".to_vec()); // OTHER only
        let writes = plan_save(&set, &pending).expect("no WriteError expected");
        assert_eq!(writes.len(), 1);
        assert!(writes[0].msg.windows(3).any(|w| w == b"ONE"), "ONE's own text must survive untouched");
        let reparsed = crate::spec::SpecFile::parse("T.MSG", &writes[0].msg).expect("rewrite must still parse");
        assert_eq!(
            reparsed.messages().get(reparsed.options()[0].index),
            Some(&b"1"[..]),
            "ONE must be untouched"
        );
        assert_eq!(
            reparsed.messages().get(reparsed.options()[1].index),
            Some(&b"7"[..]),
            "OTHER must carry the edit"
        );
    }

    #[test]
    fn plan_save_attributes_a_flat_index_across_a_file_boundary() {
        // `OptionSet` has no in-memory multi-file constructor (`open`
        // reads paths, and `files` is private outside `set.rs`), so this
        // is the one test in this module that touches a disk -- the same
        // `std::env::temp_dir()` convention `mud-server`'s own tests use.
        // It exists because the single-file test above cannot discriminate
        // an off-by-one in `locate`'s file-crossing arithmetic: with one
        // file, `remaining < len` and a mutated `remaining <= len` agree on
        // every index actually exercised. Only a flat index that crosses a
        // real file boundary can tell them apart.
        let dir = std::env::temp_dir().join(format!("cnf_locate_boundary_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create test dir");
        let a_path = dir.join("A.MSG");
        let b_path = dir.join("B.MSG");
        std::fs::write(&a_path, b"ONE {1} N 0 9\r\n").expect("write A.MSG");
        std::fs::write(&b_path, b"TWO {2} N 0 9\r\n").expect("write B.MSG");

        let set = OptionSet::open(&[a_path, b_path]).expect("open");
        assert_eq!(set.len(), 2, "one option per file");

        let mut pending = BTreeMap::new();
        pending.insert(1, b"9".to_vec()); // flat index 1 -- B.MSG's only option
        let writes = plan_save(&set, &pending).expect("no WriteError expected");

        assert_eq!(writes.len(), 1, "only B.MSG changed");
        assert_eq!(writes[0].file_name, "B.MSG", "flat index 1 must resolve into B.MSG, not A.MSG");
        assert!(
            writes[0].msg.windows(3).any(|w| w == b"{9}"),
            "B.MSG's own edit must land: {:?}",
            String::from_utf8_lossy(&writes[0].msg)
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
