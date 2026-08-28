//! Script loading and command registration, exercised through `LuaExtension`.

use mbbs::abi::{Abi, ModuleMem, Wg16};
use mbbs::extension::Verdict;
use mbbs::testing::{Fixture, module_bytes_exporting, module_bytes_exporting_many};
use mbbs_lua::LuaExtension;
use mbbs_machine::m16::FarPtr;

/// Creates a fresh directory under this crate's `target/` scratch area (never
/// `/tmp`, per this repository's standing rule) and writes the given
/// `(filename, contents)` pairs into it. `filename` may include a `/`
/// (e.g. `"lib/wccmmud.lua"`, for the namespace tests below) -- its parent
/// is created first.
///
/// Each caller passes a distinct `name` so parallel tests do not collide.
fn tempdir_with(name: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    for (filename, contents) in files {
        let path = dir.join(filename);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create script's parent dir");
        }
        std::fs::write(path, contents).expect("write script");
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

/// **Superseded by Task 2's Critical fix review.** Task 1 originally proved
/// two `c:buffer` calls in one invocation hand back the *same* underlying
/// base -- true when `c:buffer` was the region's only consumer, but the
/// exact aliasing bug a Task 2 review caught between `c:buffer` and a
/// declared call's `str` arguments (`ptr::take_scratch`'s own doc comment)
/// applies equally between two `c:buffer` calls themselves: sharing offset
/// 0 always meant a second `c:buffer` silently overwrote whatever a first
/// one already held. The fix (one shared, invocation-scoped bump cursor --
/// `ptr::ScratchCursor`) closes that too, so this test now proves the
/// opposite, and stronger, property: two `c:buffer` calls in one invocation
/// get **disjoint** regions, each independently writable without the other
/// clobbering it.
///
/// Two independent Lua tables (`p1`, `p2`) with no shared Lua-visible state
/// (see this module's own "no field a script could forge" design) each get
/// their own distinct byte written at the same LOCAL offset (`0`); reading
/// both back afterward and finding each still holds its OWN value --
/// neither the other's, neither a freshly-zeroed default -- is only
/// possible if both writes and reads went through real, disjoint host
/// memory. A regression back to "always offset 0" would make `p2`'s write
/// clobber `p1`'s, and both would read back `p2`'s value.
#[test]
fn two_c_buffer_calls_in_one_invocation_get_disjoint_regions() {
    let dir = tempdir_with(
        "two_c_buffer_calls_in_one_invocation_get_disjoint_regions",
        &[(
            "disjoint.lua",
            r#"mmud.command("disjoint", function(c)
                local p1 = c:buffer(2)
                p1:w8(0, 0x42)
                local p2 = c:buffer(2)
                p2:w8(0, 0x99)
                c:print(tostring(p1:u8(0)) .. "," .. tostring(p2:u8(0)) .. "\r\n")
                return mmud.HANDLED
            end)"#,
        )],
    );
    let mut ext = LuaExtension::load(&dir).expect("loads");
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "disjoint", &module);

    assert_eq!(verdict, Verdict::Handled);
    let out = fixture.host.gsbl_mut().drain_output(chan);
    assert_eq!(
        String::from_utf8_lossy(&out),
        "66,153\r\n",
        "a second c:buffer call must not clobber the first call's own region"
    );
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

/// A read/write past the memory a handle actually owns errors -- the
/// `read_at`/`write_at` bounds check surfaces as a Lua-visible error through
/// `p:u8`, not a corrupted read. `c:buffer(4)` only promises to zero its
/// first 4 bytes; `Host::command_scratch`'s own region is
/// `COMMAND_SCRATCH_BYTES` (128) bytes, so offset 200 both (a) fits `FarPtr`'s
/// `u16` offset field with room to spare -- ruling out `checked_offset`'s own
/// "does not fit this pointer's address space" refusal, which is a *different*
/// failure this test must not accidentally exercise instead -- and (b) still
/// runs past the real 128-byte segment, landing on
/// `mbbs_machine::m16::FarPtrError::OutOfBounds`, surfaced through
/// `CommandCtx::read_at`'s own `"read_at: {e}"` wrapping. The assertion pins
/// the *segment* wording (`"128-byte segment"`, `FarPtrError::OutOfBounds`'s
/// own `Display`) and explicitly rules out `checked_offset`'s wording, so a
/// regression that accidentally routed this through the wrong check would
/// fail here, not pass for the wrong reason.
#[test]
fn a_read_past_the_owned_region_errors_via_the_bounds_check_not_the_offset_check() {
    let dir = tempdir_with(
        "a_read_past_the_owned_region_errors_via_the_bounds_check_not_the_offset_check",
        &[(
            "oob.lua",
            r#"mmud.command("oob", function(c)
                local p = c:buffer(4)
                p:u8(200)
                return mmud.HANDLED
            end)"#,
        )],
    );
    let mut ext = LuaExtension::load(&dir).expect("loads");
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "oob", &module);

    assert_eq!(verdict, Verdict::Pass, "a broken handler must never swallow the line");
    let notes = fixture.host.notes();
    assert_eq!(notes.len(), 1, "got: {notes:?}");
    assert!(notes[0].contains("128-byte segment"), "must be the real bounds check (FarPtrError::OutOfBounds), got: {notes:?}");
    assert!(
        !notes[0].contains("does not fit this pointer's address space"),
        "must not be checked_offset's own refusal -- that would mean this test exercises the wrong check, got: {notes:?}"
    );
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

// ---------------------------------------------------------------------
// Task 2: signature parser, marshaller, `mmud.bind`/`declare`.
// ---------------------------------------------------------------------

/// `AX = ptr.offset`, `DX = ptr.selector`, `retf` -- the far-pointer return
/// convention every `ptr`-returning test module below uses. Mirrors
/// `crates/mbbs/tests/extension_seam.rs`'s own `get_player_code`, duplicated
/// rather than shared per this crate family's own convention for small
/// fixture-code helpers (see `crates/mbbs/src/testing.rs`'s own
/// `wg32_skeleton` doc comment for the precedent).
fn far_ptr_return_code(ptr: FarPtr) -> Vec<u8> {
    let mut code = vec![0xb8];
    code.extend_from_slice(&ptr.offset.to_le_bytes());
    code.push(0xba);
    code.extend_from_slice(&ptr.selector.to_le_bytes());
    code.push(0xcb);
    code
}

/// A declared fn round-trips asymmetric `int`/`long` arguments through a
/// real code segment and a real `long` return.
///
/// `mov bp, sp` first (nothing sets `bp` to the call frame's own base on
/// entry -- see `Machine::call`'s own doc comment: the frame starts
/// *at* `sp`, with no prologue run for it), then reads the `int` argument
/// (one word at `bp+4`) into `ax`, zeroes `dx`, and adds the `long`
/// argument (two words at `bp+6`/`bp+8`) with carry -- `ax:dx` ends up
/// holding `int_arg + long_arg` as a genuine 32-bit sum, split the same
/// `DX:AX` way `Ret::Long`'s own conversion expects
/// (`mbbs_machine::m16::Ret::U32`'s own doc comment: "split `DX:AX` with
/// the high half in `DX`"). `int_arg=300` and `long_arg=70000` are
/// deliberately asymmetric (different widths, no shared digits) so a
/// marshaller that swapped which argument went where, or truncated the
/// `long` to 16 bits, would not produce `70300` by coincidence.
#[test]
fn a_declared_fn_round_trips_asymmetric_int_and_long_arguments() {
    let code = [
        0x89, 0xe5, // mov bp, sp
        0x8b, 0x46, 0x04, // mov ax, [bp+4]   -- int arg
        0x33, 0xd2, // xor dx, dx
        0x03, 0x46, 0x06, // add ax, [bp+6]   -- long arg, low word
        0x13, 0x56, 0x08, // adc dx, [bp+8]   -- long arg, high word (with carry)
        0xcb, // retf
    ];
    let dir = tempdir_with(
        "a_declared_fn_round_trips_asymmetric_int_and_long_arguments",
        &[(
            "roundtrip.lua",
            r#"local M = mmud.bind("TESTMOD")
            M.declare { addem = "long(int, long)" }
            mmud.command("addtest", function(c)
                c:print(tostring(M.addem(300, 70000)) .. "\r\n")
                return mmud.HANDLED
            end)"#,
        )],
    );
    let mut fixture = Fixture::new();
    let module = fixture.host.load(&mut fixture.machine, &module_bytes_exporting("ADDEM", &code)).expect("loads");
    let mut ext = LuaExtension::load_with_modules::<Wg16>(&dir, &[("TESTMOD", &module)]).expect("loads and binds");
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "addtest", &module);

    assert_eq!(verdict, Verdict::Handled);
    let out = fixture.host.gsbl_mut().drain_output(chan);
    assert_eq!(String::from_utf8_lossy(&out), "70300\r\n");
    assert!(fixture.host.notes().is_empty(), "a clean round trip must never disable the handler, got: {:?}", fixture.host.notes());
}

/// The four-spelling probe resolves a declared name against the module's
/// own EXACT NE spelling (`_GET_PLAYER`, leading underscore, upper case --
/// the fourth and last candidate tried).
///
/// This is the test that dies under the mutation the task brief requires:
/// narrowing the probe to try only the declared name verbatim (dropping
/// the `_name`/`NAME`/`_NAME` candidates) makes `get_player` resolve
/// against nothing in a module that only exports `_GET_PLAYER`, and
/// `M.declare{...}` hard-errors at load time -- `load_with_modules` itself
/// returns `Err`, so this test's own `.expect("loads and binds")` panics.
/// Verified by mutation (see this crate's Task 2 report), not just
/// asserted here.
#[test]
fn the_case_probe_resolves_the_modules_own_exact_ne_spelling() {
    let dir = tempdir_with(
        "the_case_probe_resolves_the_modules_own_exact_ne_spelling",
        &[("bind.lua", r#"mmud.bind("TESTMOD").declare { get_player = "int()" }"#)],
    );
    let mut fixture = Fixture::new();
    let module = fixture.host.load(&mut fixture.machine, &module_bytes_exporting("_GET_PLAYER", &[0xcb])).expect("loads");

    LuaExtension::load_with_modules::<Wg16>(&dir, &[("TESTMOD", &module)]).expect("loads and binds");
}

/// The probe's second candidate (`NAME`, upper case, no leading
/// underscore) resolving too -- a module exporting `GET_PLAYER` (no
/// underscore, matching neither the exact declared name nor the
/// underscore-prefixed candidates) still binds. Distinct from the test
/// above: that one exercises the fourth candidate, this one the third,
/// between them covering every non-trivial candidate the probe tries.
#[test]
fn the_case_probe_also_resolves_an_upper_case_export_with_no_leading_underscore() {
    let dir = tempdir_with(
        "the_case_probe_also_resolves_an_upper_case_export_with_no_leading_underscore",
        &[("bind.lua", r#"mmud.bind("TESTMOD").declare { get_player = "int()" }"#)],
    );
    let mut fixture = Fixture::new();
    let module = fixture.host.load(&mut fixture.machine, &module_bytes_exporting("GET_PLAYER", &[0xcb])).expect("loads");

    LuaExtension::load_with_modules::<Wg16>(&dir, &[("TESTMOD", &module)]).expect("loads and binds");
}

/// An unknown export after all four spellings is a hard error at declare
/// time, naming the declared export, the module, and every spelling
/// tried.
#[test]
fn declaring_an_unknown_export_names_the_export_the_module_and_the_spellings_tried() {
    let dir = tempdir_with(
        "declaring_an_unknown_export_names_the_export_the_module_and_the_spellings_tried",
        &[("bind.lua", r#"mmud.bind("TESTMOD").declare { ghost = "void()" }"#)],
    );
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();

    let err = LuaExtension::load_with_modules::<Wg16>(&dir, &[("TESTMOD", &module)]).expect_err("no such export");

    let msg = err.to_string();
    assert!(msg.contains("ghost"), "must name the declared export, got: {msg}");
    assert!(msg.contains("TESTMOD"), "must name the module, got: {msg}");
    assert!(msg.contains("ghost"), "must list the exact-spelling candidate tried, got: {msg}");
    assert!(msg.contains("_GHOST"), "must list the underscore+upper-case candidate tried, got: {msg}");
}

/// A signature parse error at declare time hard-errors the load, naming
/// the declaration and the bad token -- `parse_signature`'s own unit
/// tests (`bind.rs`) cover the parser in isolation; this proves the same
/// failure reaches a script author through `M.declare{...}`.
#[test]
fn a_bad_signature_hard_errors_the_load_and_names_the_declaration() {
    let dir = tempdir_with(
        "a_bad_signature_hard_errors_the_load_and_names_the_declaration",
        &[("bind.lua", r#"mmud.bind("TESTMOD").declare { get_player = "frobnicate(int)" }"#)],
    );
    let mut fixture = Fixture::new();
    let module = fixture.host.load(&mut fixture.machine, &module_bytes_exporting("_GET_PLAYER", &[0xcb])).expect("loads");

    let err = LuaExtension::load_with_modules::<Wg16>(&dir, &[("TESTMOD", &module)]).expect_err("bad signature");

    let msg = err.to_string();
    assert!(msg.contains("get_player"), "must name the declaration, got: {msg}");
    assert!(msg.contains("frobnicate"), "must name the bad token, got: {msg}");
}

/// Declaring the same name twice on one namespace is a hard error.
#[test]
fn declaring_the_same_name_twice_on_one_namespace_is_a_hard_error() {
    let dir = tempdir_with(
        "declaring_the_same_name_twice_on_one_namespace_is_a_hard_error",
        &[(
            "bind.lua",
            r#"local M = mmud.bind("TESTMOD")
            M.declare { get_player = "int()" }
            M.declare { get_player = "int()" }"#,
        )],
    );
    let mut fixture = Fixture::new();
    let module = fixture.host.load(&mut fixture.machine, &module_bytes_exporting("_GET_PLAYER", &[0xcb])).expect("loads");

    let err = LuaExtension::load_with_modules::<Wg16>(&dir, &[("TESTMOD", &module)]).expect_err("duplicate declaration");

    assert!(err.to_string().contains("get_player"), "got: {err}");
}

/// `70000` as an `int` argument is out of range and errors, naming the
/// argument position and the range; the identical value as a `long`
/// argument passes -- the task brief's own worked example, and the
/// concrete evidence that `int`/`long` marshalling actually use different
/// range checks rather than one shared one.
#[test]
fn an_out_of_range_int_argument_errors_but_the_same_value_as_a_long_passes() {
    let dir = tempdir_with(
        "an_out_of_range_int_argument_errors_but_the_same_value_as_a_long_passes",
        &[(
            "bind.lua",
            r#"local M = mmud.bind("TESTMOD")
            M.declare { asint = "int(int)", aslong = "int(long)" }
            mmud.command("asint", function(c) M.asint(70000) return mmud.HANDLED end)
            mmud.command("aslong", function(c) M.aslong(70000) return mmud.HANDLED end)"#,
        )],
    );
    let mut fixture = Fixture::new();
    let module = fixture
        .host
        .load(&mut fixture.machine, &module_bytes_exporting_many(&[("ASINT", &[0xcb]), ("ASLONG", &[0xcb])]))
        .expect("loads");
    let mut ext = LuaExtension::load_with_modules::<Wg16>(&dir, &[("TESTMOD", &module)]).expect("loads and binds");
    let chan = fixture.console();

    let bad = fixture.run_command(&mut ext, chan, "asint", &module);
    assert_eq!(bad, Verdict::Pass, "a broken handler must never swallow the line");
    let notes = fixture.host.notes();
    assert_eq!(notes.len(), 1, "got: {notes:?}");
    assert!(notes[0].contains("arg 0"), "must name the argument position, got: {notes:?}");
    assert!(notes[0].contains("range"), "must name the range, got: {notes:?}");

    let good = fixture.run_command(&mut ext, chan, "aslong", &module);
    assert_eq!(good, Verdict::Handled, "the identical value as a long must pass");
    assert_eq!(fixture.host.notes().len(), 1, "the long call must not add a second note, got: {:?}", fixture.host.notes());
}

/// A raw Lua number is refused as a `ptr` argument -- never constructed
/// into a pointer, per the brief's own explicit warning.
#[test]
fn a_ptr_argument_refuses_a_raw_number() {
    let dir = tempdir_with(
        "a_ptr_argument_refuses_a_raw_number",
        &[(
            "bind.lua",
            r#"local M = mmud.bind("TESTMOD")
            M.declare { takesptr = "int(ptr)" }
            mmud.command("ptrnum", function(c) M.takesptr(5) return mmud.HANDLED end)"#,
        )],
    );
    let mut fixture = Fixture::new();
    let module = fixture.host.load(&mut fixture.machine, &module_bytes_exporting("TAKESPTR", &[0xcb])).expect("loads");
    let mut ext = LuaExtension::load_with_modules::<Wg16>(&dir, &[("TESTMOD", &module)]).expect("loads and binds");
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "ptrnum", &module);

    assert_eq!(verdict, Verdict::Pass, "a broken handler must never swallow the line");
    let notes = fixture.host.notes();
    assert_eq!(notes.len(), 1, "got: {notes:?}");
    assert!(notes[0].contains("arg 0"), "got: {notes:?}");
    assert!(notes[0].contains("number"), "must name the offending kind, got: {notes:?}");
}

/// The registry-structural half of "a stale handle errors": a handle
/// stashed in one invocation, passed as a `ptr` argument in a *later*
/// invocation whose own registry has not yet minted anything, must not
/// resolve to a wrong pointer -- it must simply fail to resolve at all.
/// Distinct from `a_stashed_handle_errors_in_a_later_invocation_...`
/// above: that test calls a method (`:u8`) on the stashed handle, which
/// fails because `mlua::Scope` already destructed the closure. This test
/// instead passes the stashed *table* itself as an ordinary argument value
/// -- no scoped closure involved at all -- so the only thing standing
/// between it and a wrong-pointer read is the registry being empty at the
/// point of the call, exactly the "fresh, empty every invocation"
/// property `ptr::Registry`'s own doc comment describes.
#[test]
fn a_stale_handles_index_does_not_resolve_against_a_later_invocations_registry() {
    let dir = tempdir_with(
        "a_stale_handles_index_does_not_resolve_against_a_later_invocations_registry",
        &[(
            "bind.lua",
            r#"local M = mmud.bind("TESTMOD")
            M.declare { takesptr = "int(ptr)" }
            mmud.command("stash", function(c)
                STASHED = c:buffer(4)
                return mmud.HANDLED
            end)
            mmud.command("usestale", function(c)
                M.takesptr(STASHED)
                return mmud.HANDLED
            end)"#,
        )],
    );
    let mut fixture = Fixture::new();
    let module = fixture.host.load(&mut fixture.machine, &module_bytes_exporting("TAKESPTR", &[0xcb])).expect("loads");
    let mut ext = LuaExtension::load_with_modules::<Wg16>(&dir, &[("TESTMOD", &module)]).expect("loads and binds");
    let chan = fixture.console();

    let first = fixture.run_command(&mut ext, chan, "stash", &module);
    assert_eq!(first, Verdict::Handled, "stashing a handle must not itself fail");

    let second = fixture.run_command(&mut ext, chan, "usestale", &module);
    assert_eq!(second, Verdict::Pass, "a stale handle must never resolve to a live pointer in a later invocation");
    let notes = fixture.host.notes();
    assert_eq!(notes.len(), 1, "got: {notes:?}");
    assert!(notes[0].contains("stale") || notes[0].contains("invalid"), "got: {notes:?}");
}

/// Two `str` arguments in one call land at distinct, non-overlapping
/// offsets within the shared scratch region -- the chosen layout (see
/// `bind.rs`'s own "`str` argument layout" doc comment), proven by a real
/// callee that reads the FIRST BYTE of *each* string through its own far
/// pointer (`les bx, [bp+N]` then `mov al/ah, es:[bx]`) and returns both
/// bytes packed into one word. A callee that saw the second string's
/// pointer collide with the first's, or read the wrong offset, would not
/// produce the two strings' own first bytes here.
#[test]
fn two_str_arguments_in_one_call_land_at_distinct_offsets() {
    let code = [
        0x89, 0xe5, // mov bp, sp
        0xc4, 0x5e, 0x04, // les bx, [bp+4]      -- first str arg's far pointer
        0x26, 0x8a, 0x07, // mov al, es:[bx]     -- its first byte
        0xc4, 0x5e, 0x08, // les bx, [bp+8]      -- second str arg's far pointer
        0x26, 0x8a, 0x27, // mov ah, es:[bx]     -- its first byte
        0xcb, // retf
    ];
    let dir = tempdir_with(
        "two_str_arguments_in_one_call_land_at_distinct_offsets",
        &[(
            "bind.lua",
            r#"local M = mmud.bind("TESTMOD")
            M.declare { firstbytes = "int(str, str)" }
            mmud.command("twostr", function(c)
                c:print(tostring(M.firstbytes("AB", "CD")) .. "\r\n")
                return mmud.HANDLED
            end)"#,
        )],
    );
    let mut fixture = Fixture::new();
    let module = fixture.host.load(&mut fixture.machine, &module_bytes_exporting("FIRSTBYTES", &code)).expect("loads");
    let mut ext = LuaExtension::load_with_modules::<Wg16>(&dir, &[("TESTMOD", &module)]).expect("loads and binds");
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "twostr", &module);

    assert_eq!(verdict, Verdict::Handled);
    let out = fixture.host.gsbl_mut().drain_output(chan);
    // al = 'A' (0x41), ah = 'C' (0x43) -> ax = 0x4341 = 17217.
    assert_eq!(String::from_utf8_lossy(&out), "17217\r\n");
    assert!(fixture.host.notes().is_empty(), "got: {:?}", fixture.host.notes());
}

/// The Critical fix's own canonical scenario, proven end to end: a script
/// holds a `c:buffer` cell (the shape a `ptr`-typed OUT parameter takes),
/// then in the SAME call passes a `str` argument to a declared export --
/// exactly `M.get_item_from_name(name, nil, cell)`'s shape, minus the
/// `nil`. Before the fix (`ptr::ScratchCursor`, shared by `c:buffer` and
/// `str` marshalling), `cell`'s registered pointer and the `str`
/// argument's marshalled bytes were BOTH `command_scratch + 0`, so
/// marshalling the string silently overwrote `cell` before the call ever
/// ran.
///
/// Two disjoint facts, both asserted from the Rust side (not merely
/// printed and eyeballed): the callee reads the `str` argument's own first
/// byte through a real far pointer (`les`/`mov es:[bx]`, the same
/// technique `two_str_arguments_in_one_call_land_at_distinct_offsets`
/// uses) and returns it, proving the string landed at ITS OWN address with
/// the right content; `cell:u16(0)`, read back from Lua *after* the call
/// returns, proves `cell`'s own two bytes -- written before the call --
/// were never touched by the string's write.
#[test]
fn a_str_argument_and_a_live_buffer_in_one_call_do_not_collide() {
    let code = [
        0x89, 0xe5, // mov bp, sp
        0x33, 0xc0, // xor ax, ax        -- so an untouched ah reads back as 0
        0xc4, 0x5e, 0x04, // les bx, [bp+4]    -- the str arg's far pointer
        0x26, 0x8a, 0x07, // mov al, es:[bx]   -- its first byte
        0xcb, // retf
    ];
    let dir = tempdir_with(
        "a_str_argument_and_a_live_buffer_in_one_call_do_not_collide",
        &[(
            "bind.lua",
            r#"local M = mmud.bind("TESTMOD")
            M.declare { getitem = "int(str, ptr)" }
            mmud.command("canonical", function(c)
                local cell = c:buffer(2)
                cell:w16(0, 0xBEEF)
                local firstbyte = M.getitem("sword", cell)
                c:print(tostring(firstbyte) .. "," .. tostring(cell:u16(0)) .. "\r\n")
                return mmud.HANDLED
            end)"#,
        )],
    );
    let mut fixture = Fixture::new();
    let module = fixture.host.load(&mut fixture.machine, &module_bytes_exporting("GETITEM", &code)).expect("loads");
    let mut ext = LuaExtension::load_with_modules::<Wg16>(&dir, &[("TESTMOD", &module)]).expect("loads and binds");
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "canonical", &module);

    assert_eq!(verdict, Verdict::Handled);
    let out = fixture.host.gsbl_mut().drain_output(chan);
    // 's' = 0x73 = 115; 0xBEEF = 48879, unchanged by the str write.
    assert_eq!(String::from_utf8_lossy(&out), "115,48879\r\n");
    assert!(fixture.host.notes().is_empty(), "got: {:?}", fixture.host.notes());
}

/// A null `ptr` return arrives as `nil`; a non-null one arrives as a live
/// handle a script can immediately read through (`p:u16`), proving it is
/// a real, registered pointer -- not merely a non-nil value.
#[test]
fn a_null_ptr_return_is_nil_and_a_real_one_is_a_live_handle() {
    let mut fixture = Fixture::new();
    let real = Wg16::mem(&mut fixture.machine).alloc_region(16).expect("alloc real backing memory");
    Wg16::mem(&mut fixture.machine).write(real, &0xBEEFu16.to_le_bytes()).expect("seed a known value");

    let null_code = far_ptr_return_code(FarPtr { offset: 0, selector: 0 });
    let real_code = far_ptr_return_code(real);
    let dir = tempdir_with(
        "a_null_ptr_return_is_nil_and_a_real_one_is_a_live_handle",
        &[(
            "bind.lua",
            r#"local M = mmud.bind("TESTMOD")
            M.declare { getnull = "ptr()", getreal = "ptr()" }
            mmud.command("nulltest", function(c)
                c:print(tostring(M.getnull() == nil) .. "\r\n")
                return mmud.HANDLED
            end)
            mmud.command("realtest", function(c)
                local p = M.getreal()
                c:print(tostring(p:u16(0)) .. "\r\n")
                return mmud.HANDLED
            end)"#,
        )],
    );
    let module = fixture
        .host
        .load(&mut fixture.machine, &module_bytes_exporting_many(&[("GETNULL", &null_code), ("GETREAL", &real_code)]))
        .expect("loads");
    let mut ext = LuaExtension::load_with_modules::<Wg16>(&dir, &[("TESTMOD", &module)]).expect("loads and binds");
    let chan = fixture.console();

    let null_verdict = fixture.run_command(&mut ext, chan, "nulltest", &module);
    assert_eq!(null_verdict, Verdict::Handled);
    let null_out = fixture.host.gsbl_mut().drain_output(chan);
    assert_eq!(String::from_utf8_lossy(&null_out), "true\r\n");

    let real_verdict = fixture.run_command(&mut ext, chan, "realtest", &module);
    assert_eq!(real_verdict, Verdict::Handled);
    let real_out = fixture.host.gsbl_mut().drain_output(chan);
    assert_eq!(String::from_utf8_lossy(&real_out), "48879\r\n"); // 0xBEEF

    assert!(fixture.host.notes().is_empty(), "got: {:?}", fixture.host.notes());
}

/// `mmud.abi` reports `"wg16"` under a `Wg16` fixture -- the DSL's own
/// per-ABI branch point.
#[test]
fn mmud_abi_reports_wg16() {
    let dir = tempdir_with(
        "mmud_abi_reports_wg16",
        &[(
            "abi.lua",
            r#"mmud.command("abitest", function(c)
                c:print(tostring(mmud.abi) .. "\r\n")
                return mmud.HANDLED
            end)"#,
        )],
    );
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();
    let mut ext = LuaExtension::load_with_modules::<Wg16>(&dir, &[("TESTMOD", &module)]).expect("loads and binds");
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "abitest", &module);

    assert_eq!(verdict, Verdict::Handled);
    let out = fixture.host.gsbl_mut().drain_output(chan);
    assert_eq!(String::from_utf8_lossy(&out), "wg16\r\n");
}

// Task 3: bare-name namespaces (`local mud = wccmmud`), the per-script soft
// skip, and the multi-module `load_with_modules` entry point. See this
// crate's own `namespace.rs` module doc and the design doc's "The
// namespace"/"Boot-order consequence" sections.

/// The whole happy path, end to end: a script writes `local mod = testmod`,
/// `scripts/lib/testmod.lua` exists and declares a real export, and the
/// script's own command actually calls through the resolved namespace.
#[test]
fn a_script_binding_a_present_module_with_a_lib_registers_and_its_command_works() {
    let code = [0xb8, 0x2a, 0x00, 0xcb]; // mov ax, 42 ; retf
    let dir = tempdir_with(
        "a_script_binding_a_present_module_with_a_lib_registers_and_its_command_works",
        &[
            (
                "lib/testmod.lua",
                r#"local M = mmud.bind("testmod")
                M.declare { ping = "int()" }
                return M"#,
            ),
            (
                "cmd.lua",
                r#"local mod = testmod
                mmud.command("pingcmd", function(c)
                    c:print(tostring(mod.ping()) .. "\r\n")
                    return mmud.HANDLED
                end)"#,
            ),
        ],
    );
    let mut fixture = Fixture::new();
    let module = fixture.host.load(&mut fixture.machine, &module_bytes_exporting("PING", &code)).expect("loads");
    let mut ext = LuaExtension::load_with_modules::<Wg16>(&dir, &[("testmod", &module)]).expect("loads and binds");
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "pingcmd", &module);

    assert_eq!(verdict, Verdict::Handled);
    let out = fixture.host.gsbl_mut().drain_output(chan);
    assert_eq!(String::from_utf8_lossy(&out), "42\r\n");
    assert!(ext.notes().is_empty(), "a resolved namespace must not produce a skip note, got: {:?}", ext.notes());
}

/// A script binding a module that is not loaded on this machine is a soft
/// skip -- its own registrations vanish, one note names it, and a sibling
/// script in the SAME directory (no bare-name bind at all) still registers.
/// Both halves are the discriminating property: a loader that failed the
/// whole directory, or one that silently kept the ghost script's handler,
/// would each pass only one half.
#[test]
fn a_script_binding_an_absent_module_skips_with_a_note_while_a_sibling_registers() {
    let dir = tempdir_with(
        "a_script_binding_an_absent_module_skips_with_a_note_while_a_sibling_registers",
        &[
            (
                "10-ghost.lua",
                r#"local mod = ghostmod
                mmud.command("ghostcmd", function(c) return mmud.HANDLED end)"#,
            ),
            ("20-sibling.lua", r#"mmud.command("siblingcmd", function(c) return mmud.HANDLED end)"#),
        ],
    );

    let ext = LuaExtension::load_with_modules::<Wg16>(&dir, &[]).expect("a soft skip must not fail the load");

    assert_eq!(ext.command_names(), vec!["siblingcmd"], "the ghost script's own registration must be discarded");
    assert_eq!(ext.notes().len(), 1, "exactly one skip note, got: {:?}", ext.notes());
    let note = &ext.notes()[0];
    assert!(note.contains("10-ghost.lua"), "must name the script, got: {note}");
    assert!(note.contains("ghostmod"), "must name the namespace it wanted, got: {note}");
    assert!(note.contains("not loaded"), "must name the failed condition, got: {note}");
}

/// A module that IS loaded but has no `scripts/lib/<name>.lua` beside the
/// scripts is also a soft skip -- the other half of the design's "both
/// true" rule -- and the note names the exact missing path, not just the
/// module name.
#[test]
fn a_present_module_with_no_lib_skips_naming_the_missing_lib_path() {
    let dir = tempdir_with(
        "a_present_module_with_no_lib_skips_naming_the_missing_lib_path",
        &[(
            "cmd.lua",
            r#"local mod = testmod
            mmud.command("cmd", function(c) return mmud.HANDLED end)"#,
        )],
    );
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();

    let ext = LuaExtension::load_with_modules::<Wg16>(&dir, &[("testmod", &module)]).expect("a soft skip must not fail the load");

    assert!(ext.command_names().is_empty(), "got: {:?}", ext.command_names());
    assert_eq!(ext.notes().len(), 1, "got: {:?}", ext.notes());
    let note = &ext.notes()[0];
    assert!(note.contains("testmod"), "must name the namespace, got: {note}");
    assert!(
        note.contains("lib") && note.contains("testmod.lua"),
        "must name the missing lib path, got: {note}"
    );
}

/// A lib file that exists and RUNS but raises its own hard error (here:
/// `M.declare` naming an export the module does not have) must fail the
/// whole load, exactly like any other script-time error -- never caught by
/// the per-script skip machinery. This is the required mutation target: a
/// skip catch broadened to swallow every error (not just `NamespaceSkip`)
/// makes this test fail (the load would succeed instead of erroring).
#[test]
fn a_lib_files_own_hard_error_is_not_swallowed_by_the_skip_catch() {
    let dir = tempdir_with(
        "a_lib_files_own_hard_error_is_not_swallowed_by_the_skip_catch",
        &[
            (
                "lib/testmod.lua",
                r#"local M = mmud.bind("testmod")
                M.declare { ghost = "void()" }
                return M"#,
            ),
            ("cmd.lua", "local mod = testmod\n"),
        ],
    );
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();

    let err = LuaExtension::load_with_modules::<Wg16>(&dir, &[("testmod", &module)]).expect_err("a lib's own declare error must be a hard load error");

    assert!(err.to_string().contains("ghost"), "got: {err}");
}

/// Two scripts binding the same module get back the SAME namespace table --
/// the lib file's own top-level code runs exactly once per machine, not
/// once per script that binds it. Observed the way `bind.rs`'s own
/// scratch-cursor tests observe a side effect: a plain global counter the
/// lib bumps, read back through a THIRD command.
///
/// `__lib_runs` is pre-set to `0` by a script that runs FIRST (lexical
/// order), rather than the more natural `_G.x = (_G.x or 0) + 1`: reading
/// an as-yet-undefined `_G.x` would itself be an undefined-global read,
/// which this crate's own `__index` handler cannot tell apart from an
/// attempted namespace bind (see `namespace.rs`'s own doc comment, "Cost
/// accepted") -- it would raise its own `NamespaceSkip` for `x`, not
/// silently answer `nil` the way an ordinary Lua global miss does. Real
/// binding libs never hit this: `scripts/lib/<name>.lua` only ever
/// declares locals and fields on its own returned table, never bare,
/// unset globals.
#[test]
fn two_scripts_binding_the_same_module_share_one_cached_namespace() {
    let code = [0xb8, 0x2a, 0x00, 0xcb]; // mov ax, 42 ; retf
    let dir = tempdir_with(
        "two_scripts_binding_the_same_module_share_one_cached_namespace",
        &[
            ("00-init.lua", "_G.__lib_runs = 0"),
            (
                "lib/testmod.lua",
                r#"_G.__lib_runs = __lib_runs + 1
                local M = mmud.bind("testmod")
                M.declare { ping = "int()" }
                return M"#,
            ),
            ("10-a.lua", "local mod_a = testmod\nmmud.command(\"a\", function(c) return mmud.HANDLED end)"),
            (
                "20-b.lua",
                r#"local mod_b = testmod
                mmud.command("report", function(c)
                    c:print(tostring(__lib_runs) .. "\r\n")
                    return mmud.HANDLED
                end)"#,
            ),
        ],
    );
    let mut fixture = Fixture::new();
    let module = fixture.host.load(&mut fixture.machine, &module_bytes_exporting("PING", &code)).expect("loads");
    let mut ext = LuaExtension::load_with_modules::<Wg16>(&dir, &[("testmod", &module)]).expect("loads and binds");
    let chan = fixture.console();

    let verdict = fixture.run_command(&mut ext, chan, "report", &module);

    assert_eq!(verdict, Verdict::Handled);
    let out = fixture.host.gsbl_mut().drain_output(chan);
    assert_eq!(String::from_utf8_lossy(&out), "1\r\n", "the lib file's own top-level code must run exactly once");
    assert!(ext.notes().is_empty(), "got: {:?}", ext.notes());
}

/// A genuine Lua syntax error is still a hard load failure under
/// `load_with_modules`, exactly as it is under plain `load` (see
/// `a_syntax_error_names_the_file_and_fails_the_load` above) -- the
/// `__index` namespace machinery this method installs must not change that.
#[test]
fn a_syntax_error_is_still_a_hard_error_under_load_with_modules() {
    let dir = tempdir_with("a_syntax_error_is_still_a_hard_error_under_load_with_modules", &[("bad.lua", "this is not lua")]);
    let mut fixture = Fixture::new();
    let module = fixture.minimal_module();

    let err = LuaExtension::load_with_modules::<Wg16>(&dir, &[("testmod", &module)]).expect_err("must not load");

    assert!(err.to_string().contains("bad.lua"), "got: {err}");
}

/// Task 3's own "multi-module machines" requirement: a Wg16 machine can load
/// two modules together, and a single script binding BOTH bare namespaces in
/// one file resolves both, with no special wiring -- the `__index` handler
/// consults every `(name, module)` pair given to `load_with_modules`, not
/// just whichever one a particular lib happens to know about.
#[test]
fn one_script_binding_two_namespaces_on_a_multi_module_machine_resolves_both() {
    let ping_code = [0xb8, 0x01, 0x00, 0xcb]; // mov ax, 1 ; retf
    let pong_code = [0xb8, 0x02, 0x00, 0xcb]; // mov ax, 2 ; retf
    let dir = tempdir_with(
        "one_script_binding_two_namespaces_on_a_multi_module_machine_resolves_both",
        &[
            (
                "lib/first.lua",
                r#"local M = mmud.bind("first")
                M.declare { ping = "int()" }
                return M"#,
            ),
            (
                "lib/second.lua",
                r#"local M = mmud.bind("second")
                M.declare { pong = "int()" }
                return M"#,
            ),
            (
                "cmd.lua",
                r#"local a = first
                local b = second
                mmud.command("both", function(c)
                    c:print(tostring(a.ping()) .. "," .. tostring(b.pong()) .. "\r\n")
                    return mmud.HANDLED
                end)"#,
            ),
        ],
    );
    let mut fixture = Fixture::new();
    let first = fixture.host.load(&mut fixture.machine, &module_bytes_exporting("PING", &ping_code)).expect("loads");
    let second = fixture.host.load(&mut fixture.machine, &module_bytes_exporting("PONG", &pong_code)).expect("loads");
    let mut ext = LuaExtension::load_with_modules::<Wg16>(&dir, &[("first", &first), ("second", &second)]).expect("loads and binds both");
    let chan = fixture.console();

    // `run_command` takes one module to resolve calls against -- both
    // namespaces' own declared entries were resolved independently at
    // declare time (each against its OWN module), so either module handle
    // works here; `first` is passed since it is the "primary" the way
    // `Boot::modules[0]` is in `mbbs-server`.
    let verdict = fixture.run_command(&mut ext, chan, "both", &first);

    assert_eq!(verdict, Verdict::Handled);
    let out = fixture.host.gsbl_mut().drain_output(chan);
    assert_eq!(String::from_utf8_lossy(&out), "1,2\r\n");
    assert!(ext.notes().is_empty(), "got: {:?}", ext.notes());
}
