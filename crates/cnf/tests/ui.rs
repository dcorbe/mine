//! Widgets, exercised with no terminal at all: rendered into a `Cells` and
//! read back with `line()`/`contains()`/`highlighted_rows()`.

use cnf::model::Editor;
use cnf::set::OptionSet;
use cnf::ui::help::HelpPane;
use cnf::ui::list::OptionList;
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
    assert!(!buf.line(0).ends_with('c'), "wrapped mid-word: {:?}", buf.line(0));
}
