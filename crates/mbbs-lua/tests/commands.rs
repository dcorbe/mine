//! Script loading and command registration, exercised through `LuaExtension`.

use mbbs::extension::Verdict;
use mbbs::testing::Fixture;
use mbbs_lua::LuaExtension;

/// Creates a fresh directory under this crate's `target/` scratch area (never
/// `/tmp`, per this repository's standing rule) and writes the given
/// `(filename, contents)` pairs into it.
///
/// Each caller passes a distinct `name` so parallel tests do not collide.
fn tempdir_with(name: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    for (filename, contents) in files {
        std::fs::write(dir.join(filename), contents).expect("write script");
    }
    dir
}

#[test]
fn a_script_registers_a_command() {
    let dir = tempdir_with(
        "a_script_registers_a_command",
        &[("hello.lua", r#"mmud.command("hi", function(c) return mmud.HANDLED end)"#)],
    );
    let ext = LuaExtension::load(&dir).expect("loads");
    assert_eq!(ext.command_names(), vec!["hi"]);
}

#[test]
fn scripts_load_in_lexical_order() {
    let dir = tempdir_with(
        "scripts_load_in_lexical_order",
        &[
            ("20-b.lua", r#"mmud.command("b", function(c) end)"#),
            ("10-a.lua", r#"mmud.command("a", function(c) end)"#),
        ],
    );
    let ext = LuaExtension::load(&dir).expect("loads");
    assert_eq!(ext.command_names(), vec!["a", "b"]);
}

#[test]
fn a_syntax_error_names_the_file_and_fails_the_load() {
    let dir = tempdir_with("a_syntax_error_names_the_file_and_fails_the_load", &[("bad.lua", "this is not lua")]);
    let err = LuaExtension::load(&dir).expect_err("must not load");
    assert!(err.to_string().contains("bad.lua"), "got: {err}");
}

#[test]
fn a_throwing_handler_is_disabled_after_one_report() {
    let dir = tempdir_with(
        "a_throwing_handler_is_disabled_after_one_report",
        &[("bad.lua", r#"mmud.command("boom", function(c) error("nope") end)"#)],
    );
    let mut ext = LuaExtension::load(&dir).expect("loads");
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();
    let chan = fixture.console();

    for _ in 0..3 {
        let verdict = fixture.run_command(&mut ext, chan, "boom", &module);
        // A broken handler must never swallow the player's line.
        assert_eq!(verdict, Verdict::Pass);
    }

    let notes = fixture.host.notes();
    assert_eq!(notes.len(), 1, "got: {notes:?}");
    assert!(notes[0].contains("boom"), "got: {notes:?}");
    assert!(notes[0].contains("bad.lua"), "got: {notes:?}");
    assert!(notes[0].contains("nope"), "got: {notes:?}");
}

/// The gap Task 4's review left open: nothing yet proved, end-to-end, that a
/// handler returning `mmud.HANDLED` produces `Verdict::Handled` (only the
/// *error* path was covered), or that the context table's `c.args` and
/// `c:print` actually carry real values from Lua back into the host.
#[test]
fn a_handled_verdict_and_the_context_table_work_end_to_end() {
    let dir = tempdir_with(
        "a_handled_verdict_and_the_context_table_work_end_to_end",
        &[(
            "echo.lua",
            r#"mmud.command("echo", function(c)
                c:print("you said: " .. c.args .. "\r\n")
                return mmud.HANDLED
            end)"#,
        )],
    );
    let mut ext = LuaExtension::load(&dir).expect("loads");
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "echo hello world", &module);

    assert_eq!(verdict, Verdict::Handled);
    let out = fixture.host.gsbl_mut().drain_output(chan);
    assert_eq!(String::from_utf8_lossy(&out), "you said: hello world\r\n");
}

/// `scripts/`, at the workspace root, two levels above this crate.
fn shipped_scripts() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts")
}

#[test]
fn the_shipped_summon_script_loads_and_registers() {
    let ext = LuaExtension::load(&shipped_scripts()).expect("scripts/ must load");
    assert!(ext.command_names().contains(&"summon".to_owned()), "got: {:?}", ext.command_names());
}

#[test]
fn summon_with_no_name_prints_a_prompt_and_never_calls_into_the_module() {
    let mut ext = LuaExtension::load(&shipped_scripts()).expect("loads");
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "summon", &module);

    assert_eq!(verdict, Verdict::Handled);
    let out = fixture.host.gsbl_mut().drain_output(chan);
    assert_eq!(String::from_utf8_lossy(&out), "summon what?\r\n");
}

/// `minimal_module` exports nothing at all, so `c:summon`'s own
/// `_GET_ITEM_FROM_NAME` call is exactly the "unresolvable name" path
/// `call_export` refuses -- as close as this fixture gets to exercising
/// `summon.lua`'s real Rust glue without a real, code-bearing module (see
/// `task-6-report.md`'s "untestable" section for why a genuine match can
/// never be reached here).
#[test]
fn summon_against_a_module_with_no_export_disables_the_handler_and_names_the_symbol() {
    let mut ext = LuaExtension::load(&shipped_scripts()).expect("loads");
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "summon a rusty sword", &module);

    assert_eq!(verdict, Verdict::Pass, "a broken handler must never swallow the line");
    let notes = fixture.host.notes();
    assert_eq!(notes.len(), 1, "got: {notes:?}");
    assert!(notes[0].contains("summon"), "got: {notes:?}");
    assert!(notes[0].contains("_GET_ITEM_FROM_NAME"), "got: {notes:?}");
}

#[test]
fn the_shipped_cash_script_loads_and_registers() {
    let ext = LuaExtension::load(&shipped_scripts()).expect("scripts/ must load");
    assert!(ext.command_names().contains(&"cash".to_owned()), "got: {:?}", ext.command_names());
}

#[test]
fn cash_with_no_amount_prints_a_prompt_and_never_calls_into_the_module() {
    let mut ext = LuaExtension::load(&shipped_scripts()).expect("loads");
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "cash", &module);

    assert_eq!(verdict, Verdict::Handled);
    let out = fixture.host.gsbl_mut().drain_output(chan);
    assert_eq!(String::from_utf8_lossy(&out), "cash <copper>\r\n");
    assert!(fixture.host.notes().is_empty(), "a usage message must not touch the module at all");
}

#[test]
fn cash_with_a_fractional_amount_reports_it_honestly_and_never_calls_into_the_module() {
    let mut ext = LuaExtension::load(&shipped_scripts()).expect("loads");
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "cash 1.5", &module);

    assert_eq!(verdict, Verdict::Handled, "a bad amount is the player's mistake, not a reason to disable the command");
    let out = fixture.host.gsbl_mut().drain_output(chan);
    assert_eq!(String::from_utf8_lossy(&out), "amount must be a whole number.\r\n");
    assert!(
        fixture.host.notes().is_empty(),
        "a fractional amount must be refused before ever reaching call_export"
    );
}

/// `minimal_module` exports nothing, so a positive `cash` amount's very
/// first module call -- `CommandCtx::player_record`'s own `_GET_PLAYER` --
/// is exactly the "unresolvable name" path `call_export` refuses. This is
/// real integration coverage that the grant branch (not the deduct branch)
/// is the one a positive amount takes: if it ever called
/// `_ADDON_ADJUST_USER_WEALTH` first instead, this note would name that
/// symbol, not `_GET_PLAYER`.
#[test]
fn cash_a_positive_amount_against_a_module_with_no_export_names_get_player() {
    let mut ext = LuaExtension::load(&shipped_scripts()).expect("loads");
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "cash 100", &module);

    assert_eq!(verdict, Verdict::Pass, "a broken handler must never swallow the line");
    let notes = fixture.host.notes();
    assert_eq!(notes.len(), 1, "got: {notes:?}");
    assert!(notes[0].contains("cash"), "got: {notes:?}");
    assert!(notes[0].contains("_GET_PLAYER"), "got: {notes:?}");
}

/// The deduct branch's mirror of the test above: a negative amount's only
/// module call is `_ADDON_ADJUST_USER_WEALTH` -- it never touches
/// `_GET_PLAYER` at all (the findings file's whole point: that export loads
/// the player record itself and saves it itself). Against a module that
/// exports neither, the symbol this note names proves which branch ran.
#[test]
fn cash_a_negative_amount_against_a_module_with_no_export_names_addon_adjust_user_wealth() {
    let mut ext = LuaExtension::load(&shipped_scripts()).expect("loads");
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "cash -50", &module);

    assert_eq!(verdict, Verdict::Pass, "a broken handler must never swallow the line");
    let notes = fixture.host.notes();
    assert_eq!(notes.len(), 1, "got: {notes:?}");
    assert!(notes[0].contains("cash"), "got: {notes:?}");
    assert!(notes[0].contains("_ADDON_ADJUST_USER_WEALTH"), "got: {notes:?}");
    assert!(
        !notes[0].contains("_GET_PLAYER"),
        "a deduct must never touch _GET_PLAYER -- _ADDON_ADJUST_USER_WEALTH loads and saves the player itself; got: {notes:?}"
    );
}

#[test]
fn the_shipped_exp_script_loads_and_registers() {
    let ext = LuaExtension::load(&shipped_scripts()).expect("scripts/ must load");
    assert!(ext.command_names().contains(&"exp".to_owned()), "got: {:?}", ext.command_names());
}

#[test]
fn exp_with_no_amount_prints_a_prompt_and_never_calls_into_the_module() {
    let mut ext = LuaExtension::load(&shipped_scripts()).expect("loads");
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "exp", &module);

    assert_eq!(verdict, Verdict::Handled);
    let out = fixture.host.gsbl_mut().drain_output(chan);
    assert_eq!(String::from_utf8_lossy(&out), "exp <total>\r\n");
    assert!(fixture.host.notes().is_empty(), "a usage message must not touch the module at all");
}

#[test]
fn exp_with_a_fractional_amount_reports_it_honestly_and_never_calls_into_the_module() {
    let mut ext = LuaExtension::load(&shipped_scripts()).expect("loads");
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "exp 1.5", &module);

    assert_eq!(verdict, Verdict::Handled, "a bad amount is the player's mistake, not a reason to disable the command");
    let out = fixture.host.gsbl_mut().drain_output(chan);
    assert_eq!(String::from_utf8_lossy(&out), "amount must be a whole number.\r\n");
    assert!(
        fixture.host.notes().is_empty(),
        "a fractional amount must be refused before ever reaching call_export"
    );
}

#[test]
fn exp_with_a_negative_amount_reports_it_honestly_and_never_calls_into_the_module() {
    let mut ext = LuaExtension::load(&shipped_scripts()).expect("loads");
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "exp -50", &module);

    assert_eq!(verdict, Verdict::Handled, "a bad amount is the player's mistake, not a reason to disable the command");
    let out = fixture.host.gsbl_mut().drain_output(chan);
    assert_eq!(String::from_utf8_lossy(&out), "amount must not be negative.\r\n");
    assert!(
        fixture.host.notes().is_empty(),
        "a negative amount must be refused before ever reaching call_export -- exp sets a total, never a delta"
    );
}

/// `minimal_module` exports nothing at all, so `c:set_exp`'s own
/// `CommandCtx::set_experience` -- which calls `player_record()` first,
/// before it ever writes a byte -- fails at exactly the "unresolvable
/// `_GET_PLAYER`" path `call_export` refuses. As close as this fixture gets
/// to exercising `exp.lua`'s real Rust glue without a real, code-bearing
/// module (see `task-6-report.md`'s "untestable" section for the general
/// shape of this gap, and `task-8-report.md` for what this task's own
/// `setting_experience_writes_both_copies` proves instead, against a real
/// two-export module).
#[test]
fn exp_against_a_module_with_no_export_disables_the_handler_and_names_get_player() {
    let mut ext = LuaExtension::load(&shipped_scripts()).expect("loads");
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "exp 100", &module);

    assert_eq!(verdict, Verdict::Pass, "a broken handler must never swallow the line");
    let notes = fixture.host.notes();
    assert_eq!(notes.len(), 1, "got: {notes:?}");
    assert!(notes[0].contains("exp"), "got: {notes:?}");
    assert!(notes[0].contains("_GET_PLAYER"), "got: {notes:?}");
}
