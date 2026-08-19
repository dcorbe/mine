//! `cnf`: the sysop's terminal front end onto the `.MSG` config editor.
//!
//! Everything with a pure input and a pure output lives in the library, not
//! here -- `cnf::ui::from_crossterm` (translating one terminal key event)
//! and `cnf::ui::app` (the file picker's navigation, the fixed screen
//! layout, the quit-while-dirty rule, and what a save should write, all
//! computed without touching a filesystem or a terminal). What is left in
//! this file is what genuinely cannot be tested without a real terminal:
//! the event loop itself, and the two hazards that come with owning one --
//! unwinding raw mode and the alternate screen on every exit path
//! (including a panic), and making sure a save that hits any error writes
//! nothing at all.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cnf::model::{EditError, Editor};
use cnf::set::{self, OptionSet};
use cnf::spec::OptionType;
use cnf::ui::app::{self, Picker};
use cnf::ui::edit::FieldEditor;
use cnf::ui::help::HelpPane;
use cnf::ui::list::OptionList;
use cnf::ui::text::TextEditor;
use cnf::ui::{Key, Outcome, from_crossterm};
use cnf::write;
use crossterm::event::{Event, KeyEventKind};
use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen};
use textscreen::cell::Cells;
use textscreen::paint::Painter;
use textscreen::widget::{Rect, Widget};

/// The screen this editor draws is a fixed DOS-shaped 80x25, the size
/// `cnf::ui::app::layout` assumes -- the format it edits never assumed a
/// bigger terminal existed, and neither does this.
const COLS: usize = 80;
const ROWS: usize = 25;

fn main() -> ExitCode {
    let dir = std::env::args_os().nth(1).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));

    let msg_files = match set::list_msg_files(&dir) {
        Ok(files) => files,
        Err(e) => {
            eprintln!("{}: {e}", dir.display());
            return ExitCode::FAILURE;
        }
    };
    if msg_files.is_empty() {
        println!("no .MSG files in {}", dir.display());
        return ExitCode::FAILURE;
    }

    // Installed before raw mode or the alternate screen is ever entered,
    // so it is already in place for the whole time either one might be
    // active.
    install_panic_hook();

    match run(&dir, msg_files) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("cnf: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Chain onto whatever hook was already installed, restoring the terminal
/// first: a panic message printed while still in the alternate screen or
/// raw mode is either invisible (the alternate screen is about to be left,
/// taking the message with it) or has its line endings mangled (raw mode
/// does not translate `\n` to `\r\n`). Restoring first means the message
/// prints onto an ordinary, readable terminal.
fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        previous(info);
    }));
}

/// Best-effort and unconditional -- called from both the panic hook and
/// `TerminalGuard::drop`, so a redundant second call (a panic unwinding
/// through a live guard runs both) has to be harmless, not just cheap.
fn restore_terminal() {
    let _ = crossterm::execute!(io::stdout(), LeaveAlternateScreen);
    let _ = crossterm::terminal::disable_raw_mode();
}

/// Enters raw mode and the alternate screen on construction, leaves both on
/// drop -- covering every *normal* exit path out of [`run`] (`?`, an early
/// `return`, falling off the end of the loop) the way [`install_panic_hook`]
/// covers the abnormal one. Between the two, there is no path out of this
/// binary that leaves the terminal in raw mode or on the alternate screen.
struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        crossterm::terminal::enable_raw_mode()?;
        crossterm::execute!(io::stdout(), EnterAlternateScreen)?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

enum App {
    Picker(Picker),
    // Boxed: `EditingState` carries an `Editor`, which is not small, and
    // `Picker` (the other variant, live for as long as the editing screen
    // is not) would otherwise pay for that size on every stack copy too.
    Editing(Box<EditingState>),
}

struct EditingState {
    editor: Editor,
    dir: PathBuf,
    /// Every path `editor`'s set was built from, in the same order --
    /// kept so a save can reopen them fresh from disk (see
    /// [`attempt_save`]) without the model exposing its own [`OptionSet`].
    paths: Vec<PathBuf>,
    session: Option<EditSession>,
    /// Whether the previous keystroke was already a `q` asking to quit
    /// despite unsaved changes -- see [`app::confirm_quit`].
    quit_armed: bool,
}

/// One option's in-progress edit: whichever of the two editors its
/// [`OptionType`] calls for, plus the value it started as (for
/// [`write::check_edit`], which needs to compare against it and which
/// neither editor widget exposes on its own).
enum EditSession {
    Field { kind: OptionType, original: Vec<u8>, editor: FieldEditor },
    Text { original: Vec<u8>, editor: TextEditor },
}

impl EditSession {
    /// Start editing whatever `editor` currently has selected.
    fn open(editor: &Editor) -> Self {
        let (spec, value) = editor.option_at(editor.selected());
        let original = value.to_vec();
        match spec.kind.clone() {
            OptionType::Text => Self::Text { original: original.clone(), editor: TextEditor::new(original) },
            kind => Self::Field { kind, original: original.clone(), editor: FieldEditor::new(original) },
        }
    }

    fn key(&mut self, key: Key) -> Outcome {
        match self {
            Self::Field { editor, .. } => editor.key(key),
            Self::Text { editor, .. } => editor.key(key),
        }
    }

    fn value(&self) -> &[u8] {
        match self {
            Self::Field { editor, .. } => editor.value(),
            Self::Text { editor, .. } => editor.value(),
        }
    }

    fn kind(&self) -> OptionType {
        match self {
            Self::Field { kind, .. } => kind.clone(),
            Self::Text { .. } => OptionType::Text,
        }
    }

    fn original(&self) -> &[u8] {
        match self {
            Self::Field { original, .. } | Self::Text { original, .. } => original,
        }
    }

    /// The refusal a Ctrl-S would meet right now, shown live -- `Field`
    /// sessions have nothing to warn about (`write::check_edit` is a no-op
    /// for every kind but `Text`; see its own doc).
    fn warning(&self) -> Option<String> {
        match self {
            Self::Text { editor, .. } => editor.warning(),
            Self::Field { .. } => None,
        }
    }
}

fn run(dir: &Path, msg_files: Vec<PathBuf>) -> io::Result<()> {
    let _guard = TerminalGuard::enter()?;
    let mut stdout = io::stdout();
    let mut painter = Painter::new();
    let mut app = App::Picker(Picker::new(msg_files.clone()));
    let mut status: Option<String> = None;

    loop {
        let mut cells = Cells::blank(COLS, ROWS);
        render(&app, status.as_deref(), &mut cells);
        painter.paint(&mut stdout, &cells, (0, 0), false)?;
        stdout.flush()?;

        match crossterm::event::read()? {
            Event::Resize(_, _) => {
                // The layout is a fixed 80x25 regardless of the real
                // terminal size (see `COLS`/`ROWS`), so a resize changes
                // nothing about what should be on screen -- but the
                // previous paint's row-diff cache may now be meaningless
                // (the terminal itself reflowed), so force a full repaint
                // by replacing the `Painter` rather than trust the diff.
                painter = Painter::new();
            }
            Event::Key(ev) if ev.kind != KeyEventKind::Release => {
                let Some(key) = from_crossterm(ev) else { continue };
                let mut open_request: Option<PathBuf> = None;
                let mut quit = false;

                match &mut app {
                    App::Picker(picker) => match key {
                        Key::Up => picker.move_by(-1),
                        Key::Down => picker.move_by(1),
                        Key::PageUp => picker.move_by(-signed_page()),
                        Key::PageDown => picker.move_by(signed_page()),
                        Key::Enter => open_request = picker.selected_path().map(Path::to_path_buf),
                        Key::Esc => quit = true,
                        _ => {}
                    },
                    App::Editing(state) => quit = handle_editing_key(state, key, &mut status),
                }
                if let App::Picker(picker) = &mut app {
                    picker.scroll_to_show(list_rows());
                }

                if quit {
                    return Ok(());
                }
                if let Some(chosen) = open_request {
                    match open_editor(&msg_files, &chosen) {
                        Ok((editor, paths)) => {
                            status = None;
                            app = App::Editing(Box::new(EditingState {
                                editor,
                                dir: dir.to_path_buf(),
                                paths,
                                session: None,
                                quit_armed: false,
                            }));
                        }
                        Err(e) => status = Some(format!("{}: {e}", chosen.display())),
                    }
                }
            }
            _ => {}
        }
    }
}

/// The option list's row count in the fixed 80x25 layout -- how far a page
/// key moves, and how many rows [`Editor::scroll_to_show`] and
/// [`Picker::scroll_to_show`] keep the selection inside.
fn list_rows() -> usize {
    app::layout(COLS, ROWS).list.rows
}

#[allow(clippy::cast_possible_wrap)]
fn signed_page() -> isize {
    list_rows() as isize
}

/// Open the chosen file plus every sibling it declares (`FILE0n`; see
/// [`set::siblings`]), and build the [`Editor`] over the combined set.
///
/// # Errors
///
/// Any I/O or parse failure -- either file could be unreadable, or not a
/// valid `.MSG`.
fn open_editor(all_msgs: &[PathBuf], chosen: &Path) -> io::Result<(Editor, Vec<PathBuf>)> {
    let chosen = chosen.to_path_buf();
    let first = OptionSet::open(std::slice::from_ref(&chosen))?;
    let sibling_names = set::siblings(&first.files()[0]);
    let sibling_paths = app::resolve_siblings(all_msgs, &sibling_names);

    let mut paths = vec![chosen];
    paths.extend(sibling_paths);
    let opened = OptionSet::open(&paths)?;
    Ok((Editor::new(opened), paths))
}

/// Apply one keystroke while in the editing screen. Returns `true` when the
/// whole program should exit.
fn handle_editing_key(state: &mut EditingState, key: Key, status: &mut Option<String>) -> bool {
    // Any key other than a repeated `q` disarms the quit confirmation --
    // see `app::confirm_quit`'s own doc for why this reset belongs to the
    // caller rather than to that function.
    if !matches!(key, Key::Char(b'q' | b'Q')) {
        state.quit_armed = false;
    }

    if let Some(session) = &mut state.session {
        match session.key(key) {
            Outcome::Continue => {}
            Outcome::Cancel => {
                state.session = None;
                *status = None;
            }
            Outcome::Commit => {
                let value = session.value().to_vec();
                // `write::check_edit` is the format-specifier refusal for
                // `T`: a no-op for every other kind, so calling it
                // unconditionally keeps the rule in one place rather than
                // an `if let Text` the caller has to remember. Checked
                // here, at commit, rather than only at save time -- a
                // sysop who learns their edit dropped a `%s` only when
                // they try to save the whole set has already left the
                // field that broke it.
                match write::check_edit(&session.kind(), session.original(), &value) {
                    Err(e) => *status = Some(format!("refused: {e:?}")),
                    Ok(()) => match state.editor.edit(value) {
                        Ok(()) => {
                            state.session = None;
                            *status = None;
                        }
                        Err(EditError::Invalid(invalid)) => *status = Some(format!("invalid: {invalid:?}")),
                        Err(EditError::NotVisible) => {
                            *status = Some("that option is no longer visible".to_string());
                            state.session = None;
                        }
                    },
                }
            }
        }
        return false;
    }

    match key {
        Key::Up => {
            state.editor.move_by(-1);
            state.editor.scroll_to_show(list_rows());
        }
        Key::Down => {
            state.editor.move_by(1);
            state.editor.scroll_to_show(list_rows());
        }
        Key::PageUp => {
            state.editor.move_by(-signed_page());
            state.editor.scroll_to_show(list_rows());
        }
        Key::PageDown => {
            state.editor.move_by(signed_page());
            state.editor.scroll_to_show(list_rows());
        }
        Key::Enter => {
            state.session = Some(EditSession::open(&state.editor));
            *status = None;
        }
        Key::Char(b's' | b'S') => {
            *status = Some(attempt_save(&state.dir, &state.paths, &mut state.editor));
        }
        Key::Char(b'q' | b'Q') => {
            if app::confirm_quit(state.editor.dirty(), state.quit_armed) {
                return true;
            }
            state.quit_armed = true;
            *status = Some("unsaved changes -- press q again to quit without saving".to_string());
        }
        _ => {}
    }
    false
}

/// Save every changed file. Reopens the file set fresh from disk first (so
/// the writer splices against the same bytes it is about to overwrite,
/// never a stale in-memory copy), computes the whole plan with
/// [`app::plan_save`] before writing anything, and only then writes -- a
/// [`cnf::write::WriteError`] anywhere in the plan means nothing here is
/// written at all.
///
/// A disk error partway through the actual writes (as opposed to a
/// `WriteError` from the plan itself) is a different, smaller hazard: by
/// that point every file's bytes are already fully computed, so at most one
/// file's `.MSG` can end up written without its matching `.MCV` -- and the
/// message says exactly that, rather than leaving a sysop staring at a
/// board that will not start with no idea why.
fn attempt_save(dir: &Path, paths: &[PathBuf], editor: &mut Editor) -> String {
    let fresh = match OptionSet::open(paths) {
        Ok(s) => s,
        Err(e) => return format!("could not reopen the files to save: {e}"),
    };
    let writes = match app::plan_save(&fresh, editor.pending()) {
        Err((name, e)) => return format!("save refused, nothing written: {name}: {e:?}"),
        Ok(writes) => writes,
    };
    if writes.is_empty() {
        return "nothing to save".to_string();
    }

    for (done, w) in writes.iter().enumerate() {
        let msg_path = dir.join(&w.file_name);
        if let Err(e) = std::fs::write(&msg_path, &w.msg) {
            return format!("disk write failed after {done}/{} file(s): {}: {e}", writes.len(), msg_path.display());
        }
        let mcv_path = app::mcv_path(&msg_path);
        if let Err(e) = std::fs::write(&mcv_path, &w.mcv) {
            return format!(
                "disk write failed after {done}/{} file(s) plus {}'s .MSG -- its .MCV is now stale: {}: {e}",
                writes.len(),
                w.file_name,
                mcv_path.display()
            );
        }
    }

    // The plan was computed against `fresh`, not `editor`'s own (possibly
    // stale) set, so `editor` is rebuilt from it: its pending edits are now
    // on disk, and this is the only way to make `dirty()` agree.
    let selected = editor.selected();
    *editor = Editor::new(fresh);
    editor.select(selected);
    format!("saved {} file(s)", writes.len())
}

fn render(app: &App, status: Option<&str>, cells: &mut Cells) {
    let layout = app::layout(cells.cols, cells.rows);
    match app {
        App::Picker(picker) => {
            picker.render(layout.list, cells);
            draw_line(cells, layout.separator_row, status.unwrap_or("").as_bytes());
            draw_line(cells, layout.help.row, b"Up/Down/PgUp/PgDn: choose   Enter: open   Esc: quit");
        }
        App::Editing(state) => match &state.session {
            None => {
                OptionList(&state.editor).render(layout.list, cells);
                draw_line(cells, layout.separator_row, status.unwrap_or("").as_bytes());
                HelpPane(&state.editor).render(layout.help, cells);
            }
            Some(session) => {
                let (spec, _) = state.editor.option_at(state.editor.selected());
                let mut header = b"Editing ".to_vec();
                header.extend_from_slice(&spec.name);
                draw_line(cells, layout.list.row, &header);

                let body = Rect {
                    row: layout.list.row + 2,
                    col: layout.list.col,
                    cols: layout.list.cols,
                    rows: layout.list.rows.saturating_sub(2),
                };
                match session {
                    EditSession::Field { editor, .. } => {
                        editor.render(Rect { rows: 1.min(body.rows), ..body }, cells);
                    }
                    EditSession::Text { editor, .. } => editor.render(body, cells),
                }

                let line = status.map(str::to_string).or_else(|| session.warning());
                draw_line(cells, layout.separator_row, line.unwrap_or_default().as_bytes());

                let hint: &[u8] = match session {
                    EditSession::Field { .. } => b"Enter: save   Esc: cancel",
                    EditSession::Text { .. } => b"Ctrl-S: save   Enter: newline   Esc: cancel",
                };
                draw_line(cells, layout.help.row, hint);
            }
        },
    }
}

fn draw_line(cells: &mut Cells, row: usize, text: &[u8]) {
    for col in 0..cells.cols {
        cells.put(row, col, b' ', 0x07);
    }
    cells.write_str(row, 0, text, 0x07, cells.cols);
}
