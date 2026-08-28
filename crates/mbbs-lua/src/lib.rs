//! The Lua side of the extension seam: loads `*.lua` scripts from a
//! directory, lets them register `mmud.command(name, handler)` callbacks, and
//! implements `mbbs::extension::Extension<A>`, for any ABI, by dispatching a
//! player's line to the matching handler.
//!
//! `mbbs` never depends on this crate -- see `crates/mbbs/src/extension.rs`,
//! which is deliberately Lua-agnostic. The dependency runs one way:
//! `mbbs-server -> mbbs-lua -> mbbs`.
//!
//! This crate has no MajorMUD knowledge of its own -- no export name, no
//! record offset, no command recipe. That knowledge now lives entirely in
//! `scripts/lib/wccmmud.lua` (the declared-bindings lib file `mmud.bind`/
//! `M.declare` build) and the shipped scripts (`scripts/{summon,cash,setexp}.lua`)
//! that consume it -- see the declared-bindings design doc
//! (`docs/superpowers/specs/2026-08-27-lua-declared-bindings-design.md`) for
//! the whole shape. `bind.rs`'s own module doc covers the signature
//! mini-language and per-ABI marshalling this crate DOES own.
//!
//! # A registered command name shadows *any* line, not just in-game input
//!
//! `crates/mbbs/src/lib.rs`'s dispatch site (search for `dispatch_command`)
//! gives this seam first look at a line under one condition only: the
//! channel's status is `Gsbl::CRSTG` and an extension is installed. That
//! status fires on *every* line a channel types at *every* point in the
//! session -- login, name entry, password entry, an in-game command, all of
//! it -- because this host has no notion yet of "the module is at its login
//! prompt" versus "the module is in the game loop." Milestone 1 shipped the
//! seam this coarse on purpose, as a deliberately deferred, spec-level
//! decision (see the design docs under
//! `.superpowers/sdd/2026-08-20-lua-command-seam/`), not an oversight this
//! crate can fix on its own.
//!
//! The consequence for a script author: `mmud.command("cash", ...)` does not
//! mean "the word `cash` typed as a game command." It means "the word `cash`
//! typed as the *entire contents of any line this channel sends*, whatever
//! the module was about to do with it" -- including a player whose login
//! name or password happens to be `cash`. Pick command names accordingly,
//! and see `LuaExtension::load`'s duplicate-registration refusal for the
//! related failure mode of two scripts silently shadowing each other.
//!
//! ## It also shadows the module's OWN commands, abbreviations included
//!
//! The seam runs before the module, so a registered name wins over a built-in
//! of the same name -- silently, with nothing logged and nothing for the
//! player to notice except that a command they have always used stopped
//! working.
//!
//! This is not hypothetical. Milestone 1 shipped `exp`, which is the natural
//! abbreviation for MajorMUD's own `experience` command (`cmd_experience`,
//! ordinal 469) -- the one that SHOWS your total. A live board caught it on
//! 2026-08-20 and the script was renamed to `setexp`.
//!
//! Before naming a command, check it against the module's own list, and check
//! it is not a PREFIX of one either -- MajorMUD resolves abbreviations, so a
//! short name captures every command it prefixes:
//!
//! ```text
//! python3 re/ne_exports.py re/WCCMMUD.DLL --list | grep cmd_
//! ```
//!
//! This crate deliberately does not enforce that itself: it is module-agnostic,
//! and a hard-coded MajorMUD command list has no business in it.
//!
//! # Containment: what bounds a script, and what does not
//!
//! Once a declared export call crosses into guest code, `mbbs-machine`'s own
//! guest-CPU watchdog (`m16::watchdog`/`m32`'s equivalent) bounds it -- a
//! module that loops forever inside `_GET_PLAYER` still gets timed out and
//! refused re-entry, the same as it would for any other caller. That
//! watchdog knows nothing about Lua; it only ever sees `A::call`.
//!
//! Nothing bounds the Lua on either side of that call. A lib file's
//! boot-time top-level code (`M.declare{...}`, a stray `for do end` above
//! it) and a command handler's own body both run as plain Lua, with no
//! `debug.sethook` instruction budget, no wall-clock deadline, nothing --
//! `LuaExtension::load`/`load_with_modules` install no such hook anywhere in
//! this crate. An infinite loop that never calls a declared export runs
//! forever; an allocation that never stops growing (`t = {}; while true do
//! table.insert(t, 0) end`) runs until the process runs out of memory.
//!
//! `Extension::command`'s own error handling (see its match arm below) does
//! not help here either: it disables a handler on a THROWN Lua error, and a
//! loop that never returns never throws. A hang at boot time -- inside a
//! lib file's own top-level code, before any command is even registered --
//! is worse still: `LuaExtension::load_with_modules` never returns, so the
//! board never finishes starting, and there is no handler to disable and no
//! command yet to have misbehaved.
//!
//! This is the trust model, stated plainly, not a gap to apologize for: an
//! operator who drops a script into `--scripts` is trusting it the way
//! they'd trust a plugin -- vetted before it runs, not sandboxed once it
//! does. See `scripts/lib/README.md`'s own note on this for the version
//! aimed at a lib author, and the design doc's own scope (this file's
//! module doc, above) for why closing this gap was never part of what
//! declared bindings set out to do.
//!
//! # Where a command's business logic goes
//!
//! Nowhere in this crate, deliberately. Every command's own recipe --
//! `summon`'s two-call disambiguation, `cash`'s grant/deduct split, `setexp`'s
//! three-field write -- lives in `scripts/lib/wccmmud.lua`, built on the
//! primitives `mbbs::extension::CommandCtx` still owns
//! (`call_export`/`call_entry`, `read_at`/`write_at`, `write_scratch`) through
//! the declared-bindings marshaller (`bind.rs`) and the pointer-handle
//! primitives (`ptr.rs`). A new command's business logic belongs in a
//! `scripts/lib/<module>.lua` file, not here and not in `mbbs`: this crate's
//! job is the seam (loading scripts, dispatching a line to a handler,
//! marshalling a declared call), never the module knowledge a script author
//! puts on top of it.

mod api;
mod bind;
mod namespace;
mod ptr;

use std::cell::RefCell;
use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::path::Path;
use std::rc::Rc;

use mbbs::abi::Abi;
use mbbs::extension::{CommandCtx, Extension, Verdict};
use mlua::{Function, Lua, Value};

/// Handlers registered by loaded scripts, in registration order. Shared
/// between the `mmud.command` closure (which appends to it) and
/// `LuaExtension` (which reads it) via `Rc<RefCell<_>>`, since everything
/// here runs on one thread and the whole point is that no `Send`/`Sync`
/// bound is required.
type Handlers = Rc<RefCell<Vec<(String, Function)>>>;

// `LuaExtension` holds nothing ABI-specific -- a Lua VM, handlers, a set of
// disabled names -- so it stays non-generic; only its `Extension<A>` impl
// carries the type parameter. This assertion is the proof: it fails to
// compile if that impl is ever narrowed back to `Extension<Wg16>` alone,
// which unit tests (all of which infer `A = Wg16`) would not catch.
const _: fn() = || {
    fn assert_impl<A: mbbs::abi::Abi, E: Extension<A>>() {}
    assert_impl::<mbbs::abi::Wg16, LuaExtension>();
    assert_impl::<mbbs::abi::Wg32, LuaExtension>();
};

/// A directory of Lua scripts, loaded and ready to dispatch commands.
pub struct LuaExtension {
    lua: Lua,
    handlers: Handlers,
    /// Command names a handler has already thrown from. Checked before
    /// `handlers` is even consulted, so a disabled handler costs one hash
    /// lookup and nothing else -- see `Extension::command`'s error arm for
    /// why a handler ends up here.
    disabled: HashSet<String>,
    /// Every export a loaded `M.declare{...}` resolved, across every bound
    /// namespace -- see `bind.rs`'s own module doc comment for why these
    /// are stored ABI-erased (as bytes) rather than as `A::Ptr`, which
    /// would force this whole struct to carry an `Abi` type parameter it
    /// is deliberately built without (see the `assert_impl` check above).
    declared: bind::Declared,
    /// One line per script file whose bare namespace bind was a soft skip
    /// (see `namespace.rs`'s own doc comment and the design doc's "The
    /// namespace") -- built once, at load time, by `exec_scripts`; never
    /// grows again after that. `LuaExtension::load` never populates this
    /// (it installs no `__index` handler at all, so a `NamespaceSkip` can
    /// never be raised through it); only `load_with_modules` can.
    notes: Vec<String>,
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
        let declared: bind::Declared = Rc::new(RefCell::new(Vec::new()));
        api::install(&lua, Rc::clone(&handlers))
            .map_err(|source| LoadError(format!("installing the mmud table: {source}")))?;

        // No `mmud.bind`, no `__index` namespace resolution -- a script
        // loaded through this entry point has no declared-bindings surface
        // at all, exactly as before Task 2/3 existed. `notes` therefore
        // stays empty: `exec_scripts`'s own skip-catch is a no-op here,
        // since a `NamespaceSkip` can only ever be raised by the `__index`
        // handler `load_with_modules` installs.
        let notes = Self::exec_scripts(&lua, dir, &handlers)?;

        Ok(LuaExtension { lua, handlers, disabled: HashSet::new(), declared, notes })
    }

    /// Like [`LuaExtension::load`], but also installs `mmud.bind`/
    /// `mmud.abi` and the bare-name namespace `__index` handler (see
    /// `namespace.rs`'s own module doc), resolved against every
    /// already-loaded `(name, module)` pair in `modules`.
    ///
    /// **This is the design's real boot-order entry point.** `declare`
    /// validates a declared export against the live export table, so
    /// `modules` must already be loaded AND initialised -- calling this
    /// before that (the way Task 2's `load_with_module` provisionally did)
    /// would validate against an export table that is not fully populated
    /// yet. See this crate's own declared-bindings design doc, "Boot-order
    /// consequence", and `mbbs-server`'s `host::life`, which is the real
    /// caller.
    ///
    /// A script binding a module named here (and finding
    /// `scripts/lib/<name>.lua` beside `dir`) resolves it; a script binding
    /// anything else is a soft skip, recorded in [`LuaExtension::notes`],
    /// not a load failure -- see `namespace.rs`'s own doc comment for the
    /// mechanism, and this method's own "Errors" note below for what still
    /// IS hard.
    ///
    /// # Errors
    ///
    /// A Lua syntax error, a lib file's own hard error (an unknown
    /// `declare`d export, a bad signature -- "broken plumbing," not a
    /// missing module), or two scripts registering the same command name
    /// all still fail the whole load, exactly as [`LuaExtension::load`]'s
    /// own doc comment describes. Only a bare-name bind whose module is not
    /// loaded, or whose lib file does not exist, is soft.
    pub fn load_with_modules<A: Abi>(dir: &Path, modules: &[(&str, &A::Module)]) -> Result<LuaExtension, LoadError>
    where
        A::Module: 'static,
    {
        let lua = Lua::new();
        let handlers: Handlers = Rc::new(RefCell::new(Vec::new()));
        let declared: bind::Declared = Rc::new(RefCell::new(Vec::new()));
        api::install(&lua, Rc::clone(&handlers))
            .map_err(|source| LoadError(format!("installing the mmud table: {source}")))?;

        let owned_modules: Vec<(String, A::Module)> = modules.iter().map(|(name, module)| ((*name).to_owned(), (*module).clone())).collect();
        let module_names: Vec<String> = owned_modules.iter().map(|(name, _)| name.clone()).collect();
        bind::install::<A>(&lua, owned_modules, Rc::clone(&declared))
            .map_err(|source| LoadError(format!("installing mmud.bind: {source}")))?;

        let cache: namespace::Cache = Rc::new(RefCell::new(std::collections::HashMap::new()));
        namespace::install(&lua, dir.to_path_buf(), module_names, cache)
            .map_err(|source| LoadError(format!("installing the namespace __index handler: {source}")))?;

        let notes = Self::exec_scripts(&lua, dir, &handlers)?;

        Ok(LuaExtension { lua, handlers, disabled: HashSet::new(), declared, notes })
    }

    /// Loads every `*.lua` file directly inside `dir` into `lua`, sorted by
    /// filename, so `10-a.lua` runs before `20-b.lua` -- the file-walking
    /// half [`LuaExtension::load`] and [`LuaExtension::load_with_modules`]
    /// share; everything before this call is what differs between them
    /// (which primitives are installed before any script gets to run).
    /// Returns one operator-facing note per script whose bare namespace
    /// bind was a soft skip, in the order those scripts ran.
    ///
    /// # Per-script soft skip -- what is caught and what is not
    ///
    /// Before each file runs, `checkpoint` records how many handlers were
    /// registered so far. If the file's own `.exec()` raises a
    /// [`namespace::NamespaceSkip`] (found anywhere in [`mlua::Error::chain`],
    /// since a metamethod's error can arrive wrapped in a `CallbackError` --
    /// verified against `mlua` 0.10's own `Chain` traversal, not assumed),
    /// every handler THIS file registered before the sentinel fired is
    /// discarded (`handlers.truncate(checkpoint)`) and one note is pushed;
    /// loading moves on to the next file. Any other error -- a syntax
    /// error, a lib file's own hard error (never wrapped as
    /// `NamespaceSkip`, so `chain().find_map` never matches it), a
    /// duplicate command name -- still fails the WHOLE load immediately, as
    /// it always has.
    fn exec_scripts(lua: &Lua, dir: &Path, handlers: &Handlers) -> Result<Vec<String>, LoadError> {
        let mut entries: Vec<_> = fs::read_dir(dir)
            .map_err(|source| LoadError(format!("reading {}: {source}", dir.display())))?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "lua"))
            .collect();
        entries.sort();

        let mut notes = Vec::new();

        for path in entries {
            let file_name = path.file_name().expect("filtered by extension, so has a name").to_string_lossy().into_owned();
            let source = fs::read_to_string(&path).map_err(|source| LoadError(format!("{file_name}: {source}")))?;
            let checkpoint = handlers.borrow().len();

            if let Err(err) = lua.load(&source).set_name(&file_name).exec() {
                if let Some(skip) = err.chain().find_map(|e| e.downcast_ref::<namespace::NamespaceSkip>()) {
                    handlers.borrow_mut().truncate(checkpoint);
                    notes.push(format!("{file_name} {skip} -- script skipped"));
                    continue;
                }
                return Err(LoadError(format!("{file_name}: {err}")));
            }
        }

        Ok(notes)
    }

    /// Registered command names, in registration order (the order scripts
    /// ran in, and the order each called `mmud.command`).
    pub fn command_names(&self) -> Vec<String> {
        self.handlers.borrow().iter().map(|(name, _)| name.clone()).collect()
    }

    /// One operator-facing line per script whose bare namespace bind was a
    /// soft skip, in the order those scripts ran -- see
    /// [`LuaExtension::load_with_modules`]'s own doc comment. Always empty
    /// for a [`LuaExtension::load`]-built extension.
    pub fn notes(&self) -> &[String] {
        &self.notes
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

impl<A: Abi> Extension<A> for LuaExtension {
    fn command(&mut self, ctx: &mut CommandCtx<'_, A>) -> Verdict {
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
            // Fresh and empty every invocation -- see `ptr::Registry`'s own
            // doc comment for why that emptiness is exactly what keeps a
            // stale handle's index from resolving to a wrong pointer here.
            let registry: ptr::Registry<A> = Rc::new(RefCell::new(Vec::new()));
            // Fresh, at zero, every invocation too -- shared by `c:buffer`
            // and a declared call's own `str` arguments, so the two can
            // never land on the same scratch bytes. See
            // `ptr::ScratchCursor`'s own doc comment.
            let cursor: ptr::ScratchCursor = Rc::new(std::cell::Cell::new(0u16));
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
            t.set("buffer", ptr::install_buffer(scope, Rc::clone(&cell), Rc::clone(&registry), Rc::clone(&cursor))?)?;
            bind::rebind::<A>(scope, Rc::clone(&cell), Rc::clone(&registry), Rc::clone(&cursor), &self.declared.borrow())?;
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
