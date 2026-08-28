//! Script loading and command registration, exercised through `LuaExtension`.

use mbbs::extension::Verdict;
use mbbs::testing::{Fixture, module_bytes_exporting};
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
    assert!(ext.command_names().contains(&"setexp".to_owned()), "got: {:?}", ext.command_names());
}

#[test]
fn exp_with_no_amount_prints_a_prompt_and_never_calls_into_the_module() {
    let mut ext = LuaExtension::load(&shipped_scripts()).expect("loads");
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "setexp", &module);

    assert_eq!(verdict, Verdict::Handled);
    let out = fixture.host.gsbl_mut().drain_output(chan);
    assert_eq!(String::from_utf8_lossy(&out), "setexp <total>\r\n");
    assert!(fixture.host.notes().is_empty(), "a usage message must not touch the module at all");
}

#[test]
fn exp_with_a_fractional_amount_reports_it_honestly_and_never_calls_into_the_module() {
    let mut ext = LuaExtension::load(&shipped_scripts()).expect("loads");
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "setexp 1.5", &module);

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

    let verdict = fixture.run_command(&mut ext, chan, "setexp -50", &module);

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
/// to exercising `setexp.lua`'s real Rust glue without a real, code-bearing
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

    let verdict = fixture.run_command(&mut ext, chan, "setexp 100", &module);

    assert_eq!(verdict, Verdict::Pass, "a broken handler must never swallow the line");
    let notes = fixture.host.notes();
    assert_eq!(notes.len(), 1, "got: {notes:?}");
    assert!(notes[0].contains("setexp"), "got: {notes:?}");
    assert!(notes[0].contains("_GET_PLAYER"), "got: {notes:?}");
}

/// `_GET_PLAYER` returning null -- AX=0, DX=0, retf, the same fixture
/// `crates/mbbs/tests/extension_seam.rs::player_record_is_an_error_when_get_player_returns_null`
/// uses -- is what "no character loaded on this channel" looks like from a
/// real, running export, as opposed to the "no such export" proxy the tests
/// above use. This is Critical #1 from the whole-branch review: `cash` and
/// `exp` used to propagate that failure through `mlua::Error::external`,
/// which would disable the handler board-wide over a condition the seam's
/// own scope (see the crate doc's "shadows any line" section) makes routine
/// -- reachable any time `cash`/`exp` gets typed before a character has
/// loaded, on a board with no per-channel state gating this seam yet. A test
/// that only checked the printed message would have passed against that
/// broken code too (`ctx.note` also produces a message, just not to the
/// player) -- the assertion that actually catches the regression is that
/// the handler is still enabled, and still answers correctly, on the second
/// and third attempt.
#[test]
fn cash_with_no_character_loaded_reports_it_and_leaves_the_handler_enabled() {
    let mut ext = LuaExtension::load(&shipped_scripts()).expect("loads");
    let mut fixture = Fixture::new();
    let code = [0xb8, 0x00, 0x00, 0xba, 0x00, 0x00, 0xcb];
    let module = fixture.host.load(&mut fixture.machine, &module_bytes_exporting("_GET_PLAYER", &code)).expect("loads");
    let chan = fixture.console();

    for attempt in 0..3 {
        let verdict = fixture.run_command(&mut ext, chan, "cash 100", &module);
        assert_eq!(verdict, Verdict::Handled, "attempt {attempt}: no character loaded is a player mistake, not a reason to disable cash");
        let out = fixture.host.gsbl_mut().drain_output(chan);
        assert_eq!(String::from_utf8_lossy(&out), "no character loaded on this channel.\r\n", "attempt {attempt}");
    }
    assert!(fixture.host.notes().is_empty(), "must never disable cash over a routine 'no character loaded' condition, got: {:?}", fixture.host.notes());
}

/// `exp`'s mirror of the `cash` test above -- see its doc comment for why
/// this specifically proves the handler survives, not just that it prints
/// the right thing once.
#[test]
fn exp_with_no_character_loaded_reports_it_and_leaves_the_handler_enabled() {
    let mut ext = LuaExtension::load(&shipped_scripts()).expect("loads");
    let mut fixture = Fixture::new();
    let code = [0xb8, 0x00, 0x00, 0xba, 0x00, 0x00, 0xcb];
    let module = fixture.host.load(&mut fixture.machine, &module_bytes_exporting("_GET_PLAYER", &code)).expect("loads");
    let chan = fixture.console();

    for attempt in 0..3 {
        let verdict = fixture.run_command(&mut ext, chan, "setexp 100", &module);
        assert_eq!(verdict, Verdict::Handled, "attempt {attempt}: no character loaded is a player mistake, not a reason to disable exp");
        let out = fixture.host.gsbl_mut().drain_output(chan);
        assert_eq!(String::from_utf8_lossy(&out), "no character loaded on this channel.\r\n", "attempt {attempt}");
    }
    assert!(fixture.host.notes().is_empty(), "must never disable exp over a routine 'no character loaded' condition, got: {:?}", fixture.host.notes());
}

/// Critical #2 from the whole-branch review, the `write_scratch` refusal
/// half: any item name over `write_scratch`'s ~125-byte budget used to raise
/// an `mlua` error and disable `summon` board-wide, over an input trivially
/// reachable by pasting or holding a key. As with the `cash`/`exp` tests
/// above, the load-bearing assertion is that the handler is still enabled on
/// a second attempt, not just that the message is right once.
#[test]
fn summon_with_a_too_long_name_reports_it_and_leaves_the_handler_enabled() {
    let mut ext = LuaExtension::load(&shipped_scripts()).expect("loads");
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();
    let chan = fixture.console();
    // COMMAND_SCRATCH_BYTES is 128; `summon` packs `name` + NUL + a 2-byte
    // count into that buffer, so anything over 125 bytes overflows it.
    let too_long = "x".repeat(126);

    for attempt in 0..2 {
        let verdict = fixture.run_command(&mut ext, chan, &format!("summon {too_long}"), &module);
        assert_eq!(verdict, Verdict::Handled, "attempt {attempt}: an over-long name is a player mistake, not a reason to disable summon");
        let out = fixture.host.gsbl_mut().drain_output(chan);
        assert_eq!(String::from_utf8_lossy(&out), "not a valid item name.\r\n", "attempt {attempt}");
    }
    assert!(fixture.host.notes().is_empty(), "must never disable summon over an over-long name, got: {:?}", fixture.host.notes());
}

/// Critical #2's other half: an embedded NUL byte in an item name used to
/// raise an `mlua` error too. Exercised directly against `c:summon`, rather
/// than through `scripts/summon.lua`'s own argument parsing, since a NUL
/// byte cannot arrive via this test's own `run_command(..., line: &str,
/// ...)` (a Rust `&str` embeds one just fine, but `split_command` and the
/// line-to-args plumbing have no reason to strip it -- the point here is
/// `c:summon`'s own defence, not how a NUL reaches it).
#[test]
fn summon_with_an_embedded_nul_reports_it_and_leaves_the_handler_enabled() {
    let dir = tempdir_with(
        "summon_with_an_embedded_nul_reports_it_and_leaves_the_handler_enabled",
        &[(
            "nul.lua",
            r#"mmud.command("nultest", function(c)
                local ok, reason = c:summon("a\0b")
                c:print(reason .. ".\r\n")
                return mmud.HANDLED
            end)"#,
        )],
    );
    let mut ext = LuaExtension::load(&dir).expect("loads");
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();
    let chan = fixture.console();

    for attempt in 0..2 {
        let verdict = fixture.run_command(&mut ext, chan, "nultest", &module);
        assert_eq!(verdict, Verdict::Handled, "attempt {attempt}: an embedded NUL is a player/script-input mistake, not a reason to disable the handler");
        let out = fixture.host.gsbl_mut().drain_output(chan);
        assert_eq!(String::from_utf8_lossy(&out), "item name must not contain a NUL byte.\r\n", "attempt {attempt}");
    }
    assert!(fixture.host.notes().is_empty(), "must never disable the handler over an embedded NUL, got: {:?}", fixture.host.notes());
}

/// Important #4 from the whole-branch review: two scripts registering the
/// same command name used to shadow silently -- `Extension::command` matches
/// the *first* registration, so the second handler would simply never run,
/// with no diagnostic anywhere. This asserts the load now fails outright and
/// names both the offending command and the file that tried to re-register
/// it.
#[test]
fn two_scripts_registering_the_same_command_name_fails_the_load() {
    let dir = tempdir_with(
        "two_scripts_registering_the_same_command_name_fails_the_load",
        &[
            ("10-first.lua", r#"mmud.command("dup", function(c) return mmud.HANDLED end)"#),
            ("20-second.lua", r#"mmud.command("dup", function(c) return mmud.HANDLED end)"#),
        ],
    );

    let err = LuaExtension::load(&dir).expect_err("a duplicate command name must fail the load");

    assert!(err.to_string().contains("dup"), "got: {err}");
    assert!(err.to_string().contains("20-second.lua"), "got: {err}");
}

/// `c:buffer(n)` and the pointer-handle primitives it hands back (`p:add`,
/// `p:u8/u16/u32`, `p:w8/w16/w32`) -- Task 1 of the declared-bindings plan.
/// `c:buffer` is the only handle source these tests need: it is a clean,
/// Rust-minted `A::Ptr` with no MajorMUD knowledge attached, exactly what
/// Task 2's `bind`-declared exports will also hand back as a `ptr`-typed
/// return.
///
/// Writes `w8=0xAB` at offset 0, `w16=0xBEEF` at offset 2, and
/// `w32=0xDEADBEEF` at offset 4 -- three different widths at three
/// non-overlapping, asymmetric offsets, with no two values equal to each
/// other or to any offset -- then reads all three back through the *same*
/// handle at the *same* offsets. A read/write pair that silently shared one
/// scratch cell, or that transposed offset and value somewhere, would show
/// up here as a wrong number, not just an error.
#[test]
fn buffer_round_trips_asymmetric_writes_and_reads_at_asymmetric_offsets() {
    let dir = tempdir_with(
        "buffer_round_trips_asymmetric_writes_and_reads_at_asymmetric_offsets",
        &[(
            "roundtrip.lua",
            r#"mmud.command("roundtrip", function(c)
                local p = c:buffer(8)
                p:w8(0, 0xAB)
                p:w16(2, 0xBEEF)
                p:w32(4, 0xDEADBEEF)
                c:print(tostring(p:u8(0)) .. "," .. tostring(p:u16(2)) .. "," .. tostring(p:u32(4)) .. "\r\n")
                return mmud.HANDLED
            end)"#,
        )],
    );
    let mut ext = LuaExtension::load(&dir).expect("loads");
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "roundtrip", &module);

    assert_eq!(verdict, Verdict::Handled);
    let out = fixture.host.gsbl_mut().drain_output(chan);
    assert_eq!(String::from_utf8_lossy(&out), format!("{},{},{}\r\n", 0xABu8, 0xBEEFu16, 0xDEADBEEFu32));
    assert!(fixture.host.notes().is_empty(), "a clean round trip must never disable the handler, got: {:?}", fixture.host.notes());
}

/// Proves two things at once, both required by the task brief:
///
/// 1. Two `c:buffer` calls in one invocation hand back the same underlying
///    region (`Host::command_scratch` is allocated once and reused -- see
///    `CommandCtx::write_scratch`'s own doc comment). Handles are
///    deliberately opaque (no raw address ever reaches Lua, by design -- see
///    `crates/mbbs-lua/src/ptr.rs`'s own module doc comment), so this cannot
///    be shown by comparing addresses the way
///    `write_scratch_reuses_the_same_buffer_across_calls`
///    (`crates/mbbs/tests/extension_seam.rs`) compares `FarPtr`s directly.
///    Instead: write through `p1` at an offset *past* `p1`'s own declared
///    size (`c:buffer` only promises to zero its first `n` bytes, not to cap
///    what a handle can reach -- bounds are enforced by `read_at`/`write_at`
///    against the real region, not by `n`), then read that same offset back
///    through `p2`, a handle from a *second*, later `c:buffer` call. If the
///    two calls got different regions, `p2` would see a freshly zeroed byte,
///    not what `p1` wrote.
/// 2. The value observed this way did not come from some per-handle Lua-side
///    cache: `p1` and `p2` are two independent Lua tables with no shared
///    Lua-visible state (see this module's own "no field a script could
///    forge" design). The only way `p2` can see what `p1` wrote is if both
///    writes and reads went through real host memory.
#[test]
fn buffer_calls_in_one_invocation_reuse_the_same_underlying_region() {
    let dir = tempdir_with(
        "buffer_calls_in_one_invocation_reuse_the_same_underlying_region",
        &[(
            "reuse.lua",
            r#"mmud.command("reuse", function(c)
                local p1 = c:buffer(2)
                p1:w8(50, 0x42)
                local p2 = c:buffer(2)
                c:print(tostring(p2:u8(50)) .. "\r\n")
                return mmud.HANDLED
            end)"#,
        )],
    );
    let mut ext = LuaExtension::load(&dir).expect("loads");
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "reuse", &module);

    assert_eq!(verdict, Verdict::Handled);
    let out = fixture.host.gsbl_mut().drain_output(chan);
    assert_eq!(String::from_utf8_lossy(&out), "66\r\n", "a second c:buffer call must reuse the first call's region");
    assert!(fixture.host.notes().is_empty(), "got: {:?}", fixture.host.notes());
}

/// `c:buffer`'s own refusal, named per this crate's own doc comment: over
/// the scratch buffer's fixed capacity is an error naming both sizes, not a
/// truncation and not a fresh unbounded allocation.
#[test]
fn buffer_refuses_a_size_over_the_scratch_capacity_and_names_both_sizes() {
    let dir = tempdir_with(
        "buffer_refuses_a_size_over_the_scratch_capacity_and_names_both_sizes",
        &[("big.lua", r#"mmud.command("big", function(c) c:buffer(4096) return mmud.HANDLED end)"#)],
    );
    let mut ext = LuaExtension::load(&dir).expect("loads");
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "big", &module);

    assert_eq!(verdict, Verdict::Pass, "a broken handler must never swallow the line");
    let notes = fixture.host.notes();
    assert_eq!(notes.len(), 1, "got: {notes:?}");
    assert!(notes[0].contains("4096"), "must name the requested size, got: {notes:?}");
    assert!(notes[0].contains("128"), "must name the scratch buffer's own capacity, got: {notes:?}");
}

/// An out-of-range write is refused, not truncated -- `w16` given a value
/// past `0xffff` is exactly the brief's own example.
#[test]
fn w16_refuses_a_value_that_does_not_fit_16_bits() {
    let dir = tempdir_with(
        "w16_refuses_a_value_that_does_not_fit_16_bits",
        &[(
            "toobig.lua",
            r#"mmud.command("toobig", function(c)
                local p = c:buffer(4)
                p:w16(0, 0x10000)
                return mmud.HANDLED
            end)"#,
        )],
    );
    let mut ext = LuaExtension::load(&dir).expect("loads");
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "toobig", &module);

    assert_eq!(verdict, Verdict::Pass, "a broken handler must never swallow the line");
    let notes = fixture.host.notes();
    assert_eq!(notes.len(), 1, "got: {notes:?}");
    assert!(notes[0].contains("65536"), "got: {notes:?}");
    assert!(notes[0].contains("16-bit"), "got: {notes:?}");
}

/// A pointer handle is a table, but nothing about it is a plain integer a
/// script could fabricate -- see `crates/mbbs-lua/src/ptr.rs`'s own module
/// doc comment. Two angles on "cannot forge":
///
/// - A bare Lua number has no `add` method at all -- indexing it errors,
///   the same as indexing any other non-table value.
/// - A script that *does* get its hands on a real handle's `add` function
///   (`p.add`, bypassing `:` sugar) and calls it with a table of its own
///   choosing as `self` learns nothing: `add`'s closure ignores `self`
///   entirely and answers only for the `A::Ptr` it closed over when `p`
///   itself was minted. This is asserted by proving the forged call reaches
///   the *same* byte a legitimate `p:add(...)` call would.
#[test]
fn a_handle_cannot_be_forged_from_a_number_or_from_a_fabricated_self() {
    let dir = tempdir_with(
        "a_handle_cannot_be_forged_from_a_number_or_from_a_fabricated_self",
        &[(
            "forge.lua",
            r#"mmud.command("forge", function(c)
                local number_ok = pcall(function() return (5):add(1) end)

                local p = c:buffer(16)
                p:w8(5, 9)
                local via_dot_call = p:add(5):u8(0)
                local fake_self = { add = function() end, u8 = function() end }
                local via_forged_self = p.add(fake_self, 5):u8(0)

                c:print(tostring(number_ok) .. "," .. tostring(via_dot_call) .. "," .. tostring(via_forged_self) .. "\r\n")
                return mmud.HANDLED
            end)"#,
        )],
    );
    let mut ext = LuaExtension::load(&dir).expect("loads");
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "forge", &module);

    assert_eq!(verdict, Verdict::Handled);
    let out = fixture.host.gsbl_mut().drain_output(chan);
    assert_eq!(
        String::from_utf8_lossy(&out),
        "false,9,9\r\n",
        "indexing a number must fail, and a fabricated self must not change which byte add() reaches"
    );
}

/// The scoped-invalidation property this whole design rests on: a handle
/// created inside one invocation's `Lua::scope` is torn down when that
/// invocation returns, so a script that stashes one in a global sees an
/// error -- never a stale read -- the next time it is used. Driven through
/// two separate `run_command` calls, matching the fixture pattern for
/// exactly this kind of cross-call state in the rest of this file.
#[test]
fn a_stashed_handle_errors_in_a_later_invocation_instead_of_reading_stale_memory() {
    let dir = tempdir_with(
        "a_stashed_handle_errors_in_a_later_invocation_instead_of_reading_stale_memory",
        &[(
            "stash.lua",
            r#"mmud.command("stash", function(c)
                STASHED = c:buffer(4)
                return mmud.HANDLED
            end)
            mmud.command("use", function(c)
                local v = STASHED:u8(0)
                c:print(tostring(v) .. "\r\n")
                return mmud.HANDLED
            end)"#,
        )],
    );
    let mut ext = LuaExtension::load(&dir).expect("loads");
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();
    let chan = fixture.console();

    let first = fixture.run_command(&mut ext, chan, "stash", &module);
    assert_eq!(first, Verdict::Handled, "stashing a handle must not itself fail");

    let second = fixture.run_command(&mut ext, chan, "use", &module);
    assert_eq!(second, Verdict::Pass, "a stashed handle used later must disable the handler, not read stale memory");
    let notes = fixture.host.notes();
    assert_eq!(notes.len(), 1, "got: {notes:?}");
    assert!(notes[0].contains("use"), "got: {notes:?}");
    assert!(notes[0].contains("destructed"), "must be mlua's own scope-invalidation error, got: {notes:?}");
}
