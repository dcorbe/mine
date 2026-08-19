//! Widgets and editors, exercised with no terminal at all: a widget renders
//! into a `Cells` and is read back with `line()`/`contains()`/
//! `highlighted_rows()`; an editor takes the local `Key` enum and reports
//! `Outcome`.
//!
//! The tail of this file also carries `cnf::ui::app`'s four tests that
//! touch a real directory (`plan_save`'s file-boundary arithmetic,
//! `attempt_save`'s post-save model, and `write_atomic`'s own behaviour).
//! They live here rather than in `app.rs`'s own `#[cfg(test)]` module
//! because `CARGO_TARGET_TMPDIR` -- Cargo's per-package scratch directory
//! under `target/`, never `/tmp` -- only exists at compile time for a
//! `tests/*.rs` integration test binary, not for a lib's own unit tests.

use cnf::model::Editor;
use cnf::set::OptionSet;
use cnf::ui::app::{attempt_save, plan_save, write_atomic};
use cnf::ui::edit::FieldEditor;
use cnf::ui::help::HelpPane;
use cnf::ui::list::OptionList;
use cnf::ui::text::TextEditor;
use cnf::ui::{Key, Outcome};
use std::collections::BTreeMap;
use textscreen::cell::Cells;
use textscreen::widget::{Rect, Widget};

/// Three options, the middle one hinged off the first -- same shape as
/// `model.rs`'s own `editor()` fixture.
fn editor_with_three() -> Editor {
    let src = b"MODE {FULL} E FULL,LITE\r\n\
EXTRA {1} (MODE=FULL) N 0 9\r\n\
ALWAYS {2} N 0 9\r\n";
    Editor::new(OptionSet::from_source("T.MSG", src).expect("parses"))
}

/// One option with a comment paragraph above it, in the same shape as
/// `spec.rs`'s own `SAMPLE` fixture.
fn editor_with_help() -> Editor {
    let src = b"LANGUAGE {English}\r\n\
LEVEL0 {}\r\n\
\r\n\
\x20This is the number of credits.\r\n\
\r\n\
GAMCRD {Credits per minute 60} N 0 32767\r\n";
    Editor::new(OptionSet::from_source("T.MSG", src).expect("parses"))
}

/// One option whose comment is long enough to force a wrap inside a 20-column
/// pane. The first word is exactly 18 characters, so a correct wrap breaks
/// after it (18 + " cde" would be 22, past the 20-column width) and line 0
/// ends in the word's own last letter, `A`. A wrap that instead just
/// truncates the raw comment at column 20 -- ignoring word boundaries -- cuts
/// through the *second* word: column 19 (the 20th character) lands on the
/// `c` that starts `cde`, so line 0 would end in `c` instead.
fn editor_with_long_help() -> Editor {
    let src = b"\x20AAAAAAAAAAAAAAAAAA cde fgh\r\n\
\r\n\
OPT {x} S 1 p\r\n";
    Editor::new(OptionSet::from_source("T.MSG", src).expect("parses"))
}

#[test]
fn the_list_shows_names_and_values_and_marks_the_selection() {
    let mut e = editor_with_three();
    e.select(1);
    let mut buf = Cells::blank(80, 5);
    OptionList(&e).render(Rect { col: 0, row: 0, cols: 80, rows: 5 }, &mut buf);

    assert!(buf.line(0).starts_with("MODE"), "got {:?}", buf.line(0));
    assert!(buf.line(1).contains("EXTRA"));
    // The selected row is the one drawn in reverse video.
    assert_eq!(buf.highlighted_rows(4), vec![1]);
}

#[test]
fn the_list_shows_only_visible_options() {
    let mut e = editor_with_three();
    e.select(0);
    e.edit(b"LITE".to_vec()).expect("valid");
    let mut buf = Cells::blank(80, 5);
    OptionList(&e).render(Rect { col: 0, row: 0, cols: 80, rows: 5 }, &mut buf);
    // Positive first: a no-op render leaves this blank buffer with neither
    // row drawn, so asserting the rows that SHOULD show fails immediately --
    // it does not fall through to the absence check below to pass by doing
    // nothing at all.
    assert!(buf.contains("MODE"), "the still-visible rows must be drawn: got {:?}", buf.text());
    assert!(buf.contains("ALWAYS"), "the still-visible rows must be drawn: got {:?}", buf.text());
    assert!(!buf.contains("EXTRA"), "hinged out, must not be drawn");
}

#[test]
fn the_help_pane_shows_the_selected_options_comment() {
    let e = editor_with_help();
    let mut buf = Cells::blank(80, 3);
    HelpPane(&e).render(Rect { col: 0, row: 0, cols: 80, rows: 3 }, &mut buf);
    assert!(buf.contains("number of credits"), "got {:?}", buf.text());
}

#[test]
fn the_help_pane_wraps_rather_than_truncating_mid_word() {
    let e = editor_with_long_help();
    let mut buf = Cells::blank(20, 3);
    HelpPane(&e).render(Rect { col: 0, row: 0, cols: 20, rows: 3 }, &mut buf);
    // Positive: line 0 must actually hold the first word, not merely fail to
    // end in 'c' -- an untouched blank buffer would satisfy that check too
    // without ever having wrapped anything.
    assert_eq!(
        buf.line(0).trim_end(),
        "AAAAAAAAAAAAAAAAAA",
        "line 0 must hold the wrapped first word, got {:?}",
        buf.line(0)
    );
    assert!(!buf.line(0).ends_with('c'), "wrapped mid-word: {:?}", buf.line(0));
}

#[test]
fn typing_and_backspace_edit_the_value() {
    let mut f = FieldEditor::new(b"60".to_vec());
    f.key(Key::End);
    f.key(Key::Char(b'0'));
    assert_eq!(f.value(), b"600");
    f.key(Key::Backspace);
    assert_eq!(f.value(), b"60");
}

#[test]
fn the_cursor_starts_at_the_end_of_the_initial_value_not_the_front() {
    // Critical fix, `ui/edit.rs`: `FieldEditor::new` used to start the
    // cursor at column 0, so the very first keystroke inserted at the
    // FRONT of the value. For any N/L/H option whose message embeds a
    // prompt before the value -- `GAMCRD`'s "Credits per minute consumed
    // while in the game 60" is the canonical real shape -- that silently
    // produced "9Credits per minute...60", which `validate::check`
    // (looking only at the last whitespace-delimited token) accepts and
    // saves, permanently mangling the leading prose. Deliberately no
    // `Key::End` here -- that would paper over exactly the bug this test
    // exists to catch.
    let mut f = FieldEditor::new(b"Credits per minute consumed while in the game 60".to_vec());
    f.key(Key::Char(b'9'));
    assert_eq!(
        f.value(),
        b"Credits per minute consumed while in the game 609",
        "the first keystroke must land after the existing value, not before it"
    );
}

#[test]
fn enter_commits_and_escape_cancels() {
    let mut f = FieldEditor::new(b"60".to_vec());
    assert_eq!(f.key(Key::Char(b'1')), Outcome::Continue);
    assert_eq!(f.key(Key::Enter), Outcome::Commit);
    let mut f = FieldEditor::new(b"60".to_vec());
    assert_eq!(f.key(Key::Esc), Outcome::Cancel);
}

#[test]
fn commit_also_commits_a_field_editor() {
    // `Key::Commit` (Ctrl-S) exists so `TextEditor` has a way to save, but
    // `bin/cnf.rs` binds it uniformly across both editors -- a
    // `FieldEditor` session left it unhandled would mean pressing Ctrl-S
    // while editing an `N`/`S`/`E`/... option did nothing at all.
    let mut f = FieldEditor::new(b"60".to_vec());
    assert_eq!(f.key(Key::Commit), Outcome::Commit);
}

#[test]
fn the_text_editor_keeps_lines_separate() {
    let mut t = TextEditor::new(b"one\r\ntwo".to_vec());
    t.key(Key::Down);
    t.key(Key::End);
    t.key(Key::Char(b'!'));
    assert_eq!(t.value(), b"one\r\ntwo!");
}

#[test]
fn the_text_editor_accepts_a_brace_anywhere() {
    // An earlier draft refused a line-initial `}` as "not representable". It is
    // representable -- the writer escapes it as `~}` -- and refusing what the
    // format can express is as much a defect as accepting what it cannot.
    let mut t = TextEditor::new(b"one\r\n".to_vec());
    t.key(Key::Down);
    t.key(Key::Char(b'}'));
    assert_eq!(t.value(), b"one\r\n}", "the brace is ordinary text");
    assert!(t.warning().is_none(), "and nothing to warn about");
}

#[test]
fn the_text_editor_warns_when_an_edit_would_change_the_specifiers() {
    let mut t = TextEditor::new(b"hello %s".to_vec());
    t.key(Key::End);
    for _ in 0..2 {
        t.key(Key::Backspace);
    }
    assert!(t.warning().is_some(), "dropping %s must warn while typing");
}

#[test]
fn the_text_editor_warning_clears_once_the_specifier_is_retyped() {
    // A warning that latches on and never clears would be worse than no
    // warning at all -- `warning()` has to be re-derived from the current
    // value on every call, not remembered from an earlier keystroke.
    let mut t = TextEditor::new(b"hello %s".to_vec());
    t.key(Key::End);
    t.key(Key::Backspace);
    t.key(Key::Backspace);
    assert!(t.warning().is_some(), "dropping %s must warn");
    t.key(Key::Char(b'%'));
    t.key(Key::Char(b's'));
    assert!(t.warning().is_none(), "retyping %s must clear the warning, got {:?}", t.warning());
}

#[test]
fn a_pending_edit_reaches_the_rendered_list_row() {
    // `FieldEditor` covers editing and `option_at` covers effective-value
    // semantics at the model level, but neither proves a pending edit
    // actually reaches what a sysop looks at: the rendered row.
    let mut e = editor_with_three();
    e.select(2); // ALWAYS, on-disk value "2"
    e.edit(b"7".to_vec()).expect("7 is in range");
    let mut buf = Cells::blank(80, 5);
    OptionList(&e).render(Rect { col: 0, row: 0, cols: 80, rows: 5 }, &mut buf);
    assert!(buf.line(2).contains("7"), "the pending edit must reach the row: got {:?}", buf.line(2));
    assert!(!buf.line(2).contains('2'), "not the stale on-disk value: got {:?}", buf.line(2));
}

#[test]
fn the_text_editor_emits_only_bare_newlines_from_a_multi_line_edit() {
    // The seam where the UI meets the format: `msg.rs` drops every `\r`
    // inside a value on decode (unconditionally, by the format's own rules),
    // so a CRLF break survives `write::escape` unchanged and then vanishes on
    // the writer's own reparse -- the save is refused as
    // `WriteError::EditedMessageWrong`, even though nothing above the editor
    // did anything wrong. If `Key::Enter` ever inserts `\r\n` instead of `\n`,
    // this is where it would show up.
    let mut t = TextEditor::new(b"one".to_vec());
    t.key(Key::End);
    t.key(Key::Enter);
    t.key(Key::Char(b't'));
    t.key(Key::Char(b'w'));
    t.key(Key::Char(b'o'));
    assert_eq!(t.value(), b"one\ntwo");
    assert!(!t.value().contains(&b'\r'), "a multi-line edit must not introduce a CR: got {:?}", t.value());
}

#[test]
fn enter_inserts_a_newline_in_the_text_editor_rather_than_committing() {
    // Establishes the premise `a_t_edit_can_reach_outcome_commit` depends
    // on: unlike `FieldEditor`, `Enter` is not this editor's commit key.
    // `Outcome::Commit` is unreachable from `Enter` here on purpose -- a
    // multi-line editor's `Enter` has to insert a line break, so nothing
    // else can be listening for `Enter` to mean "save".
    let mut t = TextEditor::new(b"a".to_vec());
    assert_eq!(t.key(Key::Enter), Outcome::Continue, "Enter must not commit a multi-line editor");
    assert!(t.value().contains(&b'\n'), "Enter must have inserted a newline instead: {:?}", t.value());
}

#[test]
fn a_t_edit_can_reach_outcome_commit() {
    // The hazard this crate's brief calls out by name: `Enter` inserts a
    // newline (see the test above), so without a separate commit key a `T`
    // edit could be typed and never saved. `T` is 73% of every option in
    // the corpus (`crates/cnf/tests/corpus.rs`'s per-type histogram), so an
    // editor that could not reach `Commit` for it would leave most of the
    // format unsavable. `bin/cnf.rs` binds `Key::Commit` to Ctrl-S via
    // `cnf::ui::from_crossterm` -- see that function's own tests for the
    // crossterm side of this path.
    let src = b"NOTICE {hello} T\r\n";
    let mut e = Editor::new(OptionSet::from_source("T.MSG", src).expect("parses"));
    let (spec, value) = e.option_at(e.selected());
    assert_eq!(spec.kind, cnf::spec::OptionType::Text, "the fixture must actually be a T option");

    let mut t = TextEditor::new(value.to_vec());
    t.key(Key::End);
    t.key(Key::Char(b'!'));
    assert_eq!(t.key(Key::Commit), Outcome::Commit, "Ctrl-S (Key::Commit) must be able to commit a T edit");

    // And the value it hands back is not just accepted by `Outcome` in the
    // abstract -- it actually reaches the model and dirties the set, the
    // same as any other committed edit would.
    e.edit(t.value().to_vec()).expect("a plain text edit must be accepted");
    assert!(e.dirty(), "the committed T edit must reach the model");
    assert_eq!(e.option_at(0).1, b"hello!");
}

#[test]
fn page_up_and_page_down_move_the_text_editor_by_more_than_one_line() {
    fn fixture() -> Vec<u8> {
        (0..20).map(|n| format!("line{n}")).collect::<Vec<_>>().join("\n").into_bytes()
    }
    fn line_containing_the_cursor(value: &[u8]) -> String {
        // `Char('X')` is inserted at the cursor and never anywhere else, so
        // whichever line carries it is the line the cursor was actually on
        // when the page key ran.
        String::from_utf8_lossy(value).lines().find(|l| l.contains('X')).unwrap_or_default().replace('X', "")
    }

    // Positive first: without any page key, End + a character marks line 0
    // -- proving the marker itself lands on the cursor's line, not just
    // "somewhere", before trusting it to locate PageDown's result below.
    let mut plain = TextEditor::new(fixture());
    plain.key(Key::End);
    plain.key(Key::Char(b'X'));
    assert_eq!(line_containing_the_cursor(plain.value()), "line0");

    let mut down = TextEditor::new(fixture());
    down.key(Key::PageDown);
    down.key(Key::End);
    down.key(Key::Char(b'X'));
    assert_eq!(line_containing_the_cursor(down.value()), "line10", "PageDown must move by more than one line");

    let mut back = TextEditor::new(fixture());
    back.key(Key::PageDown);
    back.key(Key::PageUp);
    back.key(Key::End);
    back.key(Key::Char(b'X'));
    assert_eq!(line_containing_the_cursor(back.value()), "line0", "PageUp must undo PageDown by the same amount");
}

#[test]
fn plan_save_attributes_a_flat_index_across_a_file_boundary() {
    // `OptionSet` has no in-memory multi-file constructor (`open` reads
    // paths, and `files` is private outside `set.rs`), so this needs a
    // real multi-file directory. It exists because a single-file fixture
    // cannot discriminate an off-by-one in `locate`'s (private to
    // `app.rs`) file-crossing arithmetic: with one file, `remaining < len`
    // and a mutated `remaining <= len` agree on every index actually
    // exercised. Only a flat index that crosses a real file boundary can
    // tell them apart.
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("cnf_locate_boundary_{}", std::process::id()));
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
fn a_hinge_in_one_file_can_react_to_an_option_in_a_sibling_file() {
    // A `FILE0n` sibling exists for exactly one reason (`set.rs`'s own
    // module doc): so a hinge in one file can react to an option's value in
    // another. Nothing exercised that cross-file path before this --
    // `hinge.rs`'s own tests feed `visible` synthetic name/value pairs
    // directly, never through a real `OptionSet`, and `model.rs`'s hinge
    // tests are all single-file. This is the first test to go through
    // `Editor::value_of` -> `OptionSet::index_of` across a real file
    // boundary, including a *pending* (not yet saved) edit to the option
    // the hinge depends on -- the case `Editor::value_of`'s own doc says a
    // hinge must see.
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("cnf_cross_file_hinge_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create test dir");
    let a_path = dir.join("A.MSG");
    let b_path = dir.join("B.MSG");
    std::fs::write(&a_path, b"HINGED {A} (BOPT=YES) E A,B\r\n").expect("write A.MSG");
    std::fs::write(&b_path, b"BOPT {YES} E YES,NO\r\n").expect("write B.MSG");

    let set = OptionSet::open(&[a_path, b_path]).expect("open");
    let mut editor = Editor::new(set);
    assert_eq!(editor.visible(), &[0, 1], "BOPT (index 1, in B.MSG) starts YES, so HINGED (index 0, in A.MSG) starts visible");

    editor.select(1); // BOPT, in B.MSG
    editor.edit(b"NO".to_vec()).expect("NO is a listed choice");
    assert_eq!(
        editor.visible(),
        &[1],
        "HINGED in A.MSG must hide once BOPT in B.MSG -- still only a pending edit, not yet saved -- reads NO"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn attempt_save_shows_the_saved_value_not_the_value_from_before_the_save() {
    // Batch G review, Critical: `attempt_save` used to rebuild `editor`
    // from the `OptionSet` it read BEFORE writing the files -- the same
    // snapshot `plan_save` diffed the pending edit against, which never
    // saw the new value. `dirty()` came back clean (correctly -- `pending`
    // really was empty), but the model's own displayed value reverted to
    // what was on disk before the save, right after "saved 1 file(s)"
    // printed. A sysop watching that would reasonably conclude the save
    // failed, even though the file on disk was correct the whole time.
    // This test reads the model back out through `Editor::option_at`, not
    // just `dirty()`, because `dirty()` alone cannot tell a real save from
    // this bug.
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("cnf_attempt_save_shows_saved_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create test dir");
    let path = dir.join("A.MSG");
    std::fs::write(&path, b"GAMCRD {60} N 0 32767\r\n").expect("write A.MSG");

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
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("cnf_write_atomic_{}", std::process::id()));
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
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("cnf_write_atomic_fail_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create test dir");
    let path = dir.join("X.MSG");
    std::fs::write(&path, b"original").expect("seed original");

    // Shadow the exact path the temp file would use with a directory, so
    // writing there fails deterministically without touching any OS-level
    // permission bits.
    let tmp = path.with_extension("MSG.tmp");
    std::fs::create_dir(&tmp).expect("shadow the tmp path with a directory");

    assert!(write_atomic(&path, b"replacement").is_err(), "writing where a directory sits must fail");
    assert_eq!(std::fs::read(&path).expect("read"), b"original", "the original must survive a failed write");

    let _ = std::fs::remove_dir_all(&dir);
}
