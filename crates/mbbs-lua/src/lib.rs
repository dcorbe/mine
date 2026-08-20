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

use mbbs::abi::Wg16;
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
            let cell = RefCell::new(&mut *ctx);
            let t = self.lua.create_table()?;
            t.set("line", line.clone())?;
            t.set("args", args.clone())?;
            t.set("chan", chan)?;
            t.set(
                "print",
                scope.create_function(move |_, (_this, s): (mlua::Table, mlua::String)| {
                    cell.borrow_mut().print(&s.as_bytes());
                    Ok(())
                })?,
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
