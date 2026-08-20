//! The Lua side of the extension seam: loads `*.lua` scripts from a
//! directory, lets them register `mmud.command(name, handler)` callbacks, and
//! implements `mbbs::extension::Extension<Wg16>` by dispatching a player's
//! line to the matching handler.
//!
//! `mbbs` never depends on this crate -- see `crates/mbbs/src/extension.rs`,
//! which is deliberately Lua-agnostic. The dependency runs one way:
//! `mbbs-server -> mbbs-lua -> mbbs`.

mod api;

use std::cell::RefCell;
use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::path::Path;
use std::rc::Rc;

use mbbs::Outcome;
use mbbs::abi::{Abi, Arg, Wg16};
use mbbs::extension::{CommandCtx, Extension, Verdict};
use mlua::{Function, Lua, Value};

/// Handlers registered by loaded scripts, in registration order. Shared
/// between the `mmud.command` closure (which appends to it) and
/// `LuaExtension` (which reads it) via `Rc<RefCell<_>>`, since everything
/// here runs on one thread and the whole point is that no `Send`/`Sync`
/// bound is required.
type Handlers = Rc<RefCell<Vec<(String, Function)>>>;

/// A directory of Lua scripts, loaded and ready to dispatch commands.
pub struct LuaExtension {
    lua: Lua,
    handlers: Handlers,
    /// Command names a handler has already thrown from. Checked before
    /// `handlers` is even consulted, so a disabled handler costs one hash
    /// lookup and nothing else -- see `Extension::command`'s error arm for
    /// why a handler ends up here.
    disabled: HashSet<String>,
}

impl fmt::Debug for LuaExtension {
    /// `mlua::Function` has no `Debug` impl, so this reports the one thing
    /// about a `LuaExtension` that is actually useful to see: which commands
    /// it registered.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LuaExtension").field("commands", &self.command_names()).finish()
    }
}

/// Why a script directory failed to load: which file, and what went wrong.
#[derive(Debug)]
pub struct LoadError(String);

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LoadError {}

impl LuaExtension {
    /// Loads every `*.lua` file directly inside `dir`, sorted by filename, so
    /// `10-a.lua` runs before `20-b.lua`. Each script runs top to bottom and
    /// may call `mmud.command` any number of times; the first word of a
    /// player's line is later matched against whatever names got
    /// registered.
    ///
    /// Fails on the first file that does not load -- a syntax error, or
    /// anything the script does at load time that raises -- and the error
    /// names that file.
    pub fn load(dir: &Path) -> Result<LuaExtension, LoadError> {
        let lua = Lua::new();
        let handlers: Handlers = Rc::new(RefCell::new(Vec::new()));
        api::install(&lua, Rc::clone(&handlers))
            .map_err(|source| LoadError(format!("installing the mmud table: {source}")))?;

        let mut entries: Vec<_> = fs::read_dir(dir)
            .map_err(|source| LoadError(format!("reading {}: {source}", dir.display())))?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "lua"))
            .collect();
        entries.sort();

        for path in entries {
            let file_name = path.file_name().expect("filtered by extension, so has a name").to_string_lossy().into_owned();
            let source = fs::read_to_string(&path).map_err(|source| LoadError(format!("{file_name}: {source}")))?;
            lua.load(&source)
                .set_name(&file_name)
                .exec()
                .map_err(|source| LoadError(format!("{file_name}: {source}")))?;
        }

        Ok(LuaExtension { lua, handlers, disabled: HashSet::new() })
    }

    /// Registered command names, in registration order (the order scripts
    /// ran in, and the order each called `mmud.command`).
    pub fn command_names(&self) -> Vec<String> {
        self.handlers.borrow().iter().map(|(name, _)| name.clone()).collect()
    }
}

/// Splits a command line into its first word and the remainder.
///
/// `args` is the line with the first word and any following whitespace
/// removed -- empty when there is no argument. Leading whitespace before the
/// first word is ignored, matching how a player's line is unlikely to start
/// with spaces but costs nothing to tolerate.
fn split_command(line: &str) -> (&str, &str) {
    let trimmed = line.trim_start();
    match trimmed.find(char::is_whitespace) {
        Some(i) => (&trimmed[..i], trimmed[i..].trim_start()),
        None => (trimmed, ""),
    }
}

/// Converts a handler's return value to a `Verdict`. Only the exact
/// `mmud.HANDLED` integer swallows the line; anything else -- `mmud.PASS`,
/// `nil` (what a handler that forgets to `return` produces), a string, a
/// thrown error already turned into `Ok` upstream -- passes it through. This
/// is deliberate: a handler's silence must never be mistaken for consent.
fn to_verdict(value: Value) -> Verdict {
    match value.as_i64() {
        Some(n) if n == api::HANDLED => Verdict::Handled,
        _ => Verdict::Pass,
    }
}

/// `c:summon(name)` -- look `name` up via `_GET_ITEM_FROM_NAME` and, on a
/// match, hand it to `_ADD_ITEM_TO_INVENTORY`.
///
/// The call shape (six words, three far pointers; a null return
/// disambiguated by an OUT match count; `_ADD_ITEM_TO_INVENTORY`'s own
/// `(usrnum, 0, 0, 0xfffe, item)` and its `char` return) is measured off the
/// module's own `sysop summon` handler -- see
/// `.superpowers/sdd/2026-08-20-lua-command-seam/task-6-findings.md`, which
/// corrected the task's own plan in three places: the argument count, the
/// meaning of a null return, and whether acquisition is level-gated (it is
/// not -- only encumbrance is checked here, which is why this reads
/// `_ADD_ITEM_TO_INVENTORY`'s return instead of discarding it the way the
/// module's own handler does).
///
/// Returns `(true, nil)` on success, `(false, reason)` otherwise:
/// `"no such item"`, `"ambiguous"` (the DLL has already prompted the player
/// through its own output -- the caller must print nothing more), or `"too
/// heavy or no free slot"` (`_ADD_ITEM_TO_INVENTORY` refused).
///
/// `name`'s bytes go into guest memory verbatim, the same "whatever Lua
/// handed us" contract [`CommandCtx::print`] already has for output --
/// CP437 in, CP437 out, no re-encoding at this seam.
///
/// [`CommandCtx::print`]: mbbs::extension::CommandCtx::print
fn summon(ctx: &RefCell<&mut CommandCtx<'_, Wg16>>, name: &[u8]) -> mlua::Result<(bool, Option<&'static str>)> {
    // `[name][NUL][count: u16, zero]` in one allocation: the search
    // string `_GET_ITEM_FROM_NAME` reads, immediately followed by the real
    // 2-byte scratch its OUT match-count parameter must point at -- the
    // callee writes through that pointer unconditionally, so `0,0` is not
    // an option (see the findings file's own correction on this point).
    let mut buf = name.to_vec();
    buf.push(0);
    let count_at = buf.len();
    buf.extend_from_slice(&0u16.to_le_bytes());

    let base = ctx.borrow_mut().write_scratch(&buf).map_err(mlua::Error::external)?;
    let count_ptr = Wg16::ptr_offset(base, count_at as u16);

    let outcome = ctx
        .borrow_mut()
        .call_export(
            "_GET_ITEM_FROM_NAME",
            &[Arg::Ptr(base), Arg::Ptr(Wg16::null_ptr()), Arg::Ptr(count_ptr)],
        )
        .map_err(mlua::Error::external)?;
    let (lo, hi) = match outcome {
        Outcome::Returned { lo, hi } => (lo, hi),
        Outcome::Stopped(poison) => {
            return Err(mlua::Error::RuntimeError(format!(
                "_GET_ITEM_FROM_NAME stopped the machine: {poison:?}"
            )));
        }
    };

    // The far pointer DX:AX came back in -- offset (AX) then selector (DX),
    // the same order `Abi::ptr_to_bytes` writes one in.
    let mut ptr_bytes = (lo as u16).to_le_bytes().to_vec();
    ptr_bytes.extend_from_slice(&(hi as u16).to_le_bytes());
    let item = Wg16::ptr_from_bytes(&ptr_bytes);

    if item == Wg16::null_ptr() {
        let count_bytes = ctx.borrow().read_scratch(count_ptr, 2).map_err(mlua::Error::external)?;
        let count = u16::from_le_bytes([count_bytes[0], count_bytes[1]]);
        // Nonzero: several items matched and the DLL already told the
        // player so through its own output. Zero: nothing matched at all.
        return Ok((false, Some(if count != 0 { "ambiguous" } else { "no such item" })));
    }

    // `usrnum` is exactly this channel's number -- `point_curusr_mem`
    // already pointed the global at it before this seam ever ran, so
    // reading `ctx.chan()` back is the same value a fresh memory read
    // would give, without the read.
    let usrnum = ctx.borrow().chan().number() as u16;
    let add_outcome = ctx
        .borrow_mut()
        .call_export(
            "_ADD_ITEM_TO_INVENTORY",
            &[Arg::Int(usrnum), Arg::Int(0), Arg::Int(0), Arg::Int(0xfffe), Arg::Ptr(item)],
        )
        .map_err(mlua::Error::external)?;
    match add_outcome {
        // A `char` return: only the low byte (AL) is meaningful, so mask
        // rather than compare `lo` whole -- AH is whatever a `char`-typed
        // Borland routine's caller-saved half happened to hold.
        Outcome::Returned { lo, .. } if lo & 0xff != 0 => Ok((true, None)),
        Outcome::Returned { .. } => Ok((false, Some("too heavy or no free slot"))),
        Outcome::Stopped(poison) => Err(mlua::Error::RuntimeError(format!(
            "_ADD_ITEM_TO_INVENTORY stopped the machine: {poison:?}"
        ))),
    }
}

impl Extension<Wg16> for LuaExtension {
    fn command(&mut self, ctx: &mut CommandCtx<'_, Wg16>) -> Verdict {
        let line = ctx.line().to_string();
        let (name, args) = split_command(&line);

        if self.disabled.contains(name) {
            return Verdict::Pass;
        }

        let handler = self.handlers.borrow().iter().find(|(n, _)| n == name).map(|(_, f)| f.clone());
        let Some(handler) = handler else {
            return Verdict::Pass;
        };

        let args = args.to_string();
        let chan = i64::from(ctx.chan().number());

        let result = self.lua.scope(|scope| {
            // `Rc`, not a bare `RefCell`, now that two closures below both
            // need to reach it: `scope.create_function` wants a closure
            // that *owns* what it captures (`mlua::Scope`'s own lifetime
            // bound), which is why the closure that reads this even needed
            // `move` in the first place -- and only one closure can move a
            // bare value. Cloning the `Rc` gives each its own handle to the
            // same cell -- still one `RefCell<&mut CommandCtx>`, still one
            // thread, no `Mutex` needed.
            let cell = Rc::new(RefCell::new(&mut *ctx));
            let t = self.lua.create_table()?;
            t.set("line", line.clone())?;
            t.set("args", args.clone())?;
            t.set("chan", chan)?;
            t.set("print", {
                let cell = Rc::clone(&cell);
                scope.create_function(move |_, (_this, s): (mlua::Table, mlua::String)| {
                    cell.borrow_mut().print(&s.as_bytes());
                    Ok(())
                })?
            })?;
            t.set(
                "summon",
                scope.create_function(move |_, (_this, name): (mlua::Table, mlua::String)| summon(&cell, &name.as_bytes()))?,
            )?;
            handler.call::<Value>(t)
        });

        match result {
            Ok(value) => to_verdict(value),
            Err(err) => {
                // Disable the handler and report exactly once, never once
                // per call. `note`, not `note_once` -- see a53bc964
                // (`shims::btrieve::push`), where a note reached from inside
                // a loop the module runs to completion recorded 4,962 lines
                // of the same overflow before it moved to `note_once`. A
                // command handler has the identical shape from the other
                // side: a player who keeps retyping a broken command drives
                // this same call site once per line, and without disabling
                // the handler first, every retry would report again. The
                // "exactly once" guarantee has to come from `disabled`
                // itself, not from the note channel, precisely so a mutation
                // that deletes the bookkeeping is the one thing that can
                // still make this fail.
                self.disabled.insert(name.to_string());
                ctx.note(format!("lua: command {name:?} disabled after an error in its handler: {err}"));
                Verdict::Pass
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::split_command;

    #[test]
    fn splits_the_first_word_from_the_rest() {
        assert_eq!(split_command("summon a rusty sword"), ("summon", "a rusty sword"));
    }

    #[test]
    fn a_bare_command_has_no_args() {
        assert_eq!(split_command("cash"), ("cash", ""));
    }

    #[test]
    fn leading_and_repeated_spaces_do_not_leak_into_either_half() {
        assert_eq!(split_command("  summon   a rusty sword"), ("summon", "a rusty sword"));
    }

    #[test]
    fn an_empty_line_splits_to_two_empty_strings() {
        assert_eq!(split_command(""), ("", ""));
    }

    #[test]
    fn trailing_whitespace_after_the_only_word_leaves_args_empty() {
        assert_eq!(split_command("cash   "), ("cash", ""));
    }
}
