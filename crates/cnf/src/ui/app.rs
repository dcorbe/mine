//! The parts of `bin/cnf.rs` that do not need a terminal to be right.
//!
//! Most of a terminal loop cannot be unit-tested -- there is no terminal to
//! drive it with, and the workspace has no precedent for faking one. What
//! *can* be exercised without one is kept here instead: the file picker's
//! navigation (the same pure state-machine shape as
//! [`crate::model::Editor`], just without a hinge or a filter), the fixed
//! screen layout's arithmetic, the quit-while-dirty rule, the commit chain
//! an in-progress edit runs through on its way into the model
//! ([`commit_edit`]), and the save path itself ([`attempt_save`],
//! [`write_atomic`], [`plan_save`]) -- real disk I/O, not a pure function,
//! but still exercised directly against a real temp directory rather than
//! left untested just because it touches a filesystem. `bin/cnf.rs` is left
//! holding only the terminal I/O and the glue between these pieces.
//!
//! Batch G review moved two things here that used to live in the binary,
//! untested: `handle_editing_key`'s commit chain (now [`commit_edit`]), and
//! `attempt_save` itself, after review caught a bug in it that no test
//! existed to catch (see [`attempt_save`]'s own doc).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use textscreen::cell::Cells;
use textscreen::widget::{Rect, Widget};

use crate::model::{EditError, Editor};
use crate::set::OptionSet;
use crate::spec::OptionType;
use crate::write::{self, WriteError};

use super::Key;

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

/// Whether keystroke `key` should disarm the quit-confirmation flag
/// [`confirm_quit`] reads -- every key except a repeated `q`/`Q`, which is
/// the one key allowed to accumulate across two presses (the confirmation
/// itself). Resetting on everything else is what makes it a *repeated* `q`
/// rather than any two presses anywhere in a session.
#[must_use]
pub fn disarms_quit(key: Key) -> bool {
    !matches!(key, Key::Char(b'q' | b'Q'))
}

/// What happened when [`commit_edit`] tried to apply an in-progress edit's
/// current value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitOutcome {
    /// Accepted and applied to the model -- `Editor::dirty` may now be
    /// true. The caller should close the edit session.
    Committed,
    /// [`write::check_edit`] refused first: a `T` value that dropped or
    /// reordered a `printf` conversion. The model was never touched --
    /// the caller should keep the session open so the value can be fixed.
    SpecifiersChanged(String),
    /// [`crate::model::Editor::edit`] refused the value against the
    /// option's own bounds. The model was never touched -- keep the
    /// session open.
    Invalid(String),
    /// The selected row is no longer visible
    /// ([`crate::model::EditError::NotVisible`]). Nothing is left to keep
    /// editing -- the caller should close the session.
    NotVisible,
}

/// Try to commit `value` -- an in-progress edit's current value, for the
/// selected option of type `kind` that started as `original` -- into
/// `editor`.
///
/// [`write::check_edit`] runs before [`crate::model::Editor::edit`], not
/// after: a sysop who learns a `%s` is missing only once they have already
/// left the field has already lost the edit that dropped it (see
/// `write::check_edit`'s own doc). Pulled out of `bin/cnf.rs`'s event loop
/// so this ordering itself is something a test can hold onto --
/// `commit_edit_refuses_on_specifiers_before_touching_the_model` is built
/// exactly to catch the two steps being swapped or either one being
/// skipped.
pub fn commit_edit(editor: &mut Editor, kind: &OptionType, original: &[u8], value: Vec<u8>) -> CommitOutcome {
    if let Err(e) = write::check_edit(kind, original, &value) {
        return CommitOutcome::SpecifiersChanged(format!("{e:?}"));
    }
    match editor.edit(value) {
        Ok(()) => CommitOutcome::Committed,
        Err(EditError::Invalid(invalid)) => CommitOutcome::Invalid(format!("{invalid:?}")),
        Err(EditError::NotVisible) => CommitOutcome::NotVisible,
    }
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

/// Write `bytes` to `path` without ever leaving a truncated file there.
///
/// `std::fs::write` truncates the destination before writing it -- a crash
/// or a disk-full error partway through leaves whatever was already there
/// destroyed and the new content incomplete. Writing to a sibling `.tmp`
/// file first and renaming it into place avoids that: `rename` on every
/// platform this runs on is a single directory-entry update, so the
/// destination is either the old file, complete, or the new one, complete
/// -- never a partial write of either.
///
/// # Errors
///
/// Any I/O failure writing the temp file or renaming it into place. The
/// temp file is best-effort cleaned up on a write failure; a rename
/// failure leaves it behind (the original `path` is untouched either way).
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension().and_then(|e| e.to_str()).unwrap_or("")
    ));
    if let Err(e) = std::fs::write(&tmp, bytes) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::rename(&tmp, path)
}

/// Save every changed file. Reopens the file set fresh from disk first (so
/// the writer splices against the same bytes it is about to overwrite,
/// never a stale in-memory copy), computes the whole plan with
/// [`plan_save`] before writing anything, and only then writes -- a
/// [`WriteError`] anywhere in the plan means nothing here is written at
/// all.
///
/// Each file is written with [`write_atomic`], so a crash or a disk-full
/// error mid-write cannot truncate a `.MSG` or `.MCV` that was already on
/// disk. That still leaves one smaller, unavoidable window: the `.MSG` and
/// its `.MCV` are two separate files, written (and renamed into place) one
/// after the other, not as a single atomic unit, so a failure between the
/// two renames can leave a file's `.MSG` updated with its `.MCV` one
/// generation behind. The message on that path says exactly which file and
/// which half, rather than leaving a sysop staring at a board that will not
/// start with no idea why.
///
/// Reopens `paths` **again, fresh, after the writes succeed** to rebuild
/// `editor` -- not the snapshot read before them. Batch G review caught the
/// bug in reusing that earlier snapshot: it is the pre-save bytes
/// `plan_save` diffed the edits against, so rebuilding the model from it
/// puts every just-saved value back to what it was before the save.
/// `dirty()` would report clean (correctly -- `pending` really is empty),
/// but the sysop would watch their own edit revert on screen right after
/// "saved N file(s)" printed, while the disk copy was actually correct.
/// `attempt_save_shows_the_saved_value_not_the_value_from_before_the_save`
/// is the regression test for exactly this.
pub fn attempt_save(dir: &Path, paths: &[PathBuf], editor: &mut Editor) -> String {
    let before = match OptionSet::open(paths) {
        Ok(s) => s,
        Err(e) => return format!("could not reopen the files to save: {e}"),
    };
    let writes = match plan_save(&before, editor.pending()) {
        Err((name, e)) => return format!("save refused, nothing written: {name}: {e:?}"),
        Ok(writes) => writes,
    };
    if writes.is_empty() {
        return "nothing to save".to_string();
    }

    for (done, w) in writes.iter().enumerate() {
        let msg_path = dir.join(&w.file_name);
        if let Err(e) = write_atomic(&msg_path, &w.msg) {
            return format!("disk write failed after {done}/{} file(s): {}: {e}", writes.len(), msg_path.display());
        }
        let mcv_path = mcv_path(&msg_path);
        if let Err(e) = write_atomic(&mcv_path, &w.mcv) {
            return format!(
                "disk write failed after {done}/{} file(s) plus {}'s .MSG -- its .MCV is now stale: {}: {e}",
                writes.len(),
                w.file_name,
                mcv_path.display()
            );
        }
    }

    let selected = editor.selected();
    match OptionSet::open(paths) {
        Ok(after) => {
            *editor = Editor::new(after);
            editor.select(selected);
            format!("saved {} file(s)", writes.len())
        }
        Err(e) => {
            // The writes themselves already succeeded -- only reloading
            // them failed. `editor`'s pending edits are left exactly as
            // they were rather than discarded: the model's values already
            // match what is now on disk, they just were not rebuilt into a
            // fresh `Editor`, so `dirty()` will keep reporting them as
            // pending until the next successful save. Said plainly rather
            // than silently claiming success or losing the edits.
            format!("saved {} file(s), but could not reload afterward: {e}", writes.len())
        }
    }
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

    #[test]
    fn disarms_quit_is_true_for_everything_except_a_repeated_q() {
        assert!(!disarms_quit(Key::Char(b'q')), "q must NOT disarm -- it is the key being armed");
        assert!(!disarms_quit(Key::Char(b'Q')), "case must not matter");
        assert!(disarms_quit(Key::Char(b's')), "any other key disarms");
        assert!(disarms_quit(Key::Enter));
        assert!(disarms_quit(Key::Esc));
    }

    fn number_option() -> OptionType {
        OptionType::Number { floor: 0, ceiling: 32767 }
    }

    #[test]
    fn commit_edit_applies_an_accepted_value() {
        let src = b"GAMCRD {60} N 0 32767\r\n";
        let mut e = Editor::new(OptionSet::from_source("T.MSG", src).expect("parses"));
        let outcome = commit_edit(&mut e, &number_option(), b"60", b"120".to_vec());
        assert_eq!(outcome, CommitOutcome::Committed);
        assert!(e.dirty());
        assert_eq!(e.option_at(0).1, b"120");
    }

    #[test]
    fn commit_edit_refuses_on_specifiers_before_touching_the_model() {
        // `validate::check` always accepts a `Text` value (see its own
        // doc), so this fixture is refused ONLY by `write::check_edit`'s
        // specifier check -- if `commit_edit` skipped that call, or ran it
        // after `Editor::edit` instead of before, this value would land in
        // `pending` and dirty the editor. Proves the ORDER, not just that
        // a refusal is possible.
        let src = b"NOTICE {hello %s} T\r\n";
        let mut e = Editor::new(OptionSet::from_source("T.MSG", src).expect("parses"));
        let outcome = commit_edit(&mut e, &OptionType::Text, b"hello %s", b"hello".to_vec());
        assert!(matches!(outcome, CommitOutcome::SpecifiersChanged(_)), "got {outcome:?}");
        assert!(!e.dirty(), "check_edit's refusal must happen before Editor::edit ever touches pending");
    }

    #[test]
    fn commit_edit_reports_invalid_without_dirtying() {
        let src = b"GAMCRD {60} N 0 32767\r\n";
        let mut e = Editor::new(OptionSet::from_source("T.MSG", src).expect("parses"));
        let outcome = commit_edit(&mut e, &number_option(), b"60", b"99999".to_vec());
        assert!(matches!(outcome, CommitOutcome::Invalid(_)), "got {outcome:?}");
        assert!(!e.dirty(), "a refused edit must not dirty the model");
    }

    #[test]
    fn commit_edit_reports_not_visible_without_dirtying() {
        // Same shape as `model.rs`'s own
        // `editing_while_the_selected_row_is_filtered_out_is_refused`: a
        // filter narrows to zero rows, so the selected row -- still
        // pointed at by `Editor::selected` -- is no longer in
        // `Editor::visible`.
        let src = b"MODE {FULL} E FULL,LITE\r\n";
        let mut e = Editor::new(OptionSet::from_source("T.MSG", src).expect("parses"));
        e.set_filter(b"nothing matches this");
        assert!(e.visible().is_empty());
        let kind = OptionType::Enum { choices: vec![b"FULL".to_vec(), b"LITE".to_vec()] };
        let outcome = commit_edit(&mut e, &kind, b"FULL", b"LITE".to_vec());
        assert_eq!(outcome, CommitOutcome::NotVisible);
        assert!(!e.dirty());
    }

    #[test]
    fn attempt_save_shows_the_saved_value_not_the_value_from_before_the_save() {
        // Batch G review, Critical: `attempt_save` used to rebuild `editor`
        // from the `OptionSet` it read BEFORE writing the files -- the same
        // snapshot `plan_save` diffed the pending edit against, which never
        // saw the new value. `dirty()` came back clean (correctly --
        // `pending` really was empty), but the model's own displayed value
        // reverted to what was on disk before the save, right after
        // "saved 1 file(s)" printed. A sysop watching that would reasonably
        // conclude the save failed, even though the file on disk was
        // correct the whole time. This test reads the model back out
        // through `Editor::option_at`, not just `dirty()`, because `dirty()`
        // alone cannot tell a real save from this bug.
        let dir = std::env::temp_dir().join(format!("cnf_attempt_save_shows_saved_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("A.MSG");
        std::fs::write(&path, b"GAMCRD {60} N 0 32767
").expect("write A.MSG");

        let set = OptionSet::open(std::slice::from_ref(&path)).expect("open");
        let mut editor = Editor::new(set);
        editor.select(0);
        editor.edit(b"120".to_vec()).expect("120 is in range");
        assert_eq!(editor.option_at(0).1, b"120", "the pending edit before any save");

        let status = attempt_save(&dir, std::slice::from_ref(&path), &mut editor);
        assert!(status.contains("saved"), "expected a success message, got {status:?}");

        assert!(!editor.dirty(), "nothing pending after a successful save");
        assert_eq!(
            editor.option_at(0).1,
            b"120",
            "the model must show the value that was just saved, not revert to the pre-save one: got status {status:?}"
        );

        // And the disk copy itself really did change -- not just the
        // in-memory model.
        let on_disk = std::fs::read(&path).expect("read back A.MSG");
        assert!(
            on_disk.windows(3).any(|w| w == b"120"),
            "the file on disk must carry the new value: {:?}",
            String::from_utf8_lossy(&on_disk)
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_atomic_writes_the_bytes_and_leaves_no_tmp_file_behind() {
        let dir = std::env::temp_dir().join(format!("cnf_write_atomic_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("X.MSG");

        write_atomic(&path, b"first").expect("first write");
        assert_eq!(std::fs::read(&path).expect("read"), b"first");

        write_atomic(&path, b"second, and longer than first").expect("second write");
        assert_eq!(std::fs::read(&path).expect("read"), b"second, and longer than first");

        let tmp = path.with_extension("MSG.tmp");
        assert!(!tmp.exists(), "the temp file must be renamed away, not left behind");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_atomic_failing_to_write_the_temp_file_leaves_the_original_untouched() {
        let dir = std::env::temp_dir().join(format!("cnf_write_atomic_fail_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("X.MSG");
        std::fs::write(&path, b"original").expect("seed original");

        // Shadow the exact path the temp file would use with a directory,
        // so writing there fails deterministically without touching any
        // OS-level permission bits.
        let tmp = path.with_extension("MSG.tmp");
        std::fs::create_dir(&tmp).expect("shadow the tmp path with a directory");

        assert!(write_atomic(&path, b"replacement").is_err(), "writing where a directory sits must fail");
        assert_eq!(std::fs::read(&path).expect("read"), b"original", "the original must survive a failed write");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
