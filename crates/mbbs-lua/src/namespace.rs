//! Bare-name namespaces (`local mud = wccmmud`) and the per-script soft
//! skip -- Task 3 of the declared-bindings plan. See this crate's own
//! design doc, "The namespace" and "Boot-order consequence".
//!
//! # Why this module needs no `Abi` at all
//!
//! Resolving `wccmmud` only ever needs two facts that are NOT ABI-specific:
//! whether a module of that bare name is loaded on this machine (a plain
//! name, already known by the time [`install`] is called -- see
//! `LuaExtension::load_with_modules`), and whether `scripts/lib/<name>.lua`
//! exists on disk. Once both are true, running the lib file's own top-level
//! code does the ABI-specific work (`mmud.bind`/`M.declare{...}`, already
//! installed by `bind::install::<A>` before this module ever runs) --
//! this module itself never touches an `A::Module`, an `A::Ptr`, or
//! anything else that would force it to carry a type parameter.
//!
//! # `__index` on the REAL global table, not a per-script copy
//!
//! `LuaExtension` runs every script in one shared `Lua` VM (one `_G`), so
//! installing the `__index` handler once, directly on `lua.globals()`,
//! reaches every script equally -- there is no separate "sandboxed globals"
//! table to build or keep in sync. A key already present on `_G` (`mmud`,
//! `print`, `tonumber`, every stdlib global) is found by the ordinary
//! table lookup and never reaches this handler at all; only a truly absent
//! global -- a bare namespace name, or an ordinary typo -- does. That
//! conflation is the design's own accepted cost (see the design doc's
//! "Cost accepted" note): this module cannot and does not try to tell the
//! two apart.
//!
//! **That conflation is scoped to script files, not lib files.** [`install`]
//! takes the `__index` handler OFF `globals` for the duration of a lib
//! file's own top-level `.eval()` (a review caught the hole: without this,
//! a lib's own accidental bare-global read -- a missing `local`, above all
//! -- was misdiagnosed as the CALLING SCRIPT's own bind attempt failing,
//! wrong note and all). A lib's own undefined-global read gets ordinary Lua
//! `nil` semantics instead, so a missing `local` becomes an ordinary,
//! correctly-attributed Lua runtime error -- see [`install`]'s own doc
//! comment on the swap itself.
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::rc::Rc;

use mlua::{Lua, Result as LuaResult, Table, Value};

/// A namespace's own resolved table, once its lib file has run once --
/// shared by every script this `LuaExtension` loads, and by every
/// `Extension::command` invocation for as long as this machine's current
/// life lasts (one `LuaExtension` = one `Lua` VM = one cache; a restart
/// rebuilds a fresh `LuaExtension` and so a fresh, empty cache -- see
/// `LuaExtension::load_with_modules`).
///
/// Keyed by bare name only, with no ABI tag -- unlike `bind.rs`'s
/// `DeclaredEntry::abi_name`/`check_abi`, which guards a declared export
/// against being rebound under a different `Abi` than it was declared
/// with. Safe here for a narrower reason, not because the concern doesn't
/// apply: `namespace::install` runs once, inside `load_with_modules::<A>`,
/// for a single concrete `A` for this `LuaExtension`'s whole life, so there
/// is no path for one cache to be consulted under two different ABIs the
/// way a declared entry's *rebind* (called fresh every invocation) could
/// be. Worth re-checking if this module ever stops being a strict
/// single-`A`-per-instance cache.
pub(crate) type Cache = Rc<RefCell<HashMap<String, Table>>>;

/// Raised by the `__index` handler installed by [`install`] when a bare
/// global name looks like an attempted namespace bind but either half of
/// the design's "both true" rule fails -- see this module's own doc
/// comment and the design doc's "The namespace" section.
///
/// Crate-private on purpose: nothing outside `mbbs-lua` should ever see
/// this as a distinct type. `LuaExtension::exec_scripts` is the ONLY place
/// that looks for it (via [`mlua::Error::chain`] + `downcast_ref`), catches
/// it, and turns it into the one operator-facing note the design calls
/// for -- everything else that reaches this crate's boundary (a genuine
/// Lua syntax error, a lib file's own hard error) must never be mistaken
/// for this.
#[derive(Debug)]
pub(crate) struct NamespaceSkip {
    /// The bare name the script (or, if nested, a lib file) tried to bind.
    pub(crate) wanted: String,
    /// Which condition failed, already phrased as the tail of an English
    /// sentence starting "binds {wanted}, which ..." -- see [`fmt::Display`].
    pub(crate) reason: String,
}

impl fmt::Display for NamespaceSkip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "binds {}, which {}", self.wanted, self.reason)
    }
}

impl std::error::Error for NamespaceSkip {}

/// Installs the `__index` handler on `lua`'s real global table.
///
/// `module_names` is every module loaded on THIS machine (bare, already
/// lowercased -- see `host::life`'s own doc on how it derives these from
/// `Boot::modules`' path stems). `scripts_dir` is the exact directory
/// scripts themselves load from, so `scripts_dir/lib/<name>.lua` is
/// "beside the scripts," per the design doc. `cache` is
/// [`LuaExtension::load_with_modules`]'s own, so a second script binding
/// an already-resolved namespace gets the SAME table back without this
/// handler running at all (a plain `HashMap` lookup, not a re-read of the
/// lib file).
///
/// [`LuaExtension::load_with_modules`]: crate::LuaExtension::load_with_modules
pub(crate) fn install(lua: &Lua, scripts_dir: PathBuf, module_names: Vec<String>, cache: Cache) -> LuaResult<()> {
    let globals = lua.globals();
    let metatable = lua.create_table()?;

    let index = {
        // Cloned into the closure alongside everything else it captures --
        // `mlua::Table` clones are cheap handle copies, not deep copies, so
        // this is the SAME globals table and the SAME metatable `install`
        // installs at the bottom of this function; see the swap below for
        // why the closure needs to reach both.
        let globals = globals.clone();
        let metatable = metatable.clone();
        lua.create_function(move |lua, (_globals, key): (Table, Value)| -> LuaResult<Value> {
            // Only a string key can ever be a bare identifier a script wrote --
            // anything else (a numeric index into `_G`, say) is not this
            // handler's business; answer plain `nil`, ordinary Lua behaviour
            // for an absent key, rather than raising over it.
            let Value::String(key) = &key else {
                return Ok(Value::Nil);
            };
            let key = key.to_string_lossy();

            if let Some(cached) = cache.borrow().get(&key) {
                return Ok(Value::Table(cached.clone()));
            }

            if !module_names.contains(&key) {
                return Err(mlua::Error::external(NamespaceSkip {
                    wanted: key.clone(),
                    reason: "has no Lua surface on this machine (module not loaded)".to_owned(),
                }));
            }

            let lib_path = scripts_dir.join("lib").join(format!("{key}.lua"));
            if !lib_path.exists() {
                return Err(mlua::Error::external(NamespaceSkip {
                    wanted: key.clone(),
                    reason: format!("has no declarations lib ({} does not exist)", lib_path.display()),
                }));
            }

            // A lib file that exists but cannot even be READ (permissions, a
            // race with something deleting it) is a real host problem, not a
            // missing-plumbing soft skip -- reported plainly, not wrapped as a
            // `NamespaceSkip`, so `exec_scripts` treats it as the hard error
            // it is.
            let source = std::fs::read_to_string(&lib_path).map_err(mlua::Error::external)?;

            // Run the lib file with THIS handler taken OFF `globals`,
            // restored unconditionally (success or error) before this
            // function returns. Without this, the lib's own top-level code
            // runs under the exact same `__index` a script does, and a
            // lib's accidental bare-global read -- a missing `local`, or
            // the `X = (X or 0) + 1` first-use idiom, the single most
            // common Lua footgun -- raises `NamespaceSkip{wanted: "REC"}`
            // (say) from INSIDE this call, indistinguishable from the
            // OUTER script's own attempted bind failing. `exec_scripts`
            // would then catch it as if the calling script had failed to
            // bind `key`, discard that script's registrations, and log a
            // note naming the wrong symbol entirely -- broken lib plumbing
            // silently misreported as "this script's namespace is
            // unavailable." With the metatable off, a lib's own undefined
            // global read gets ordinary Lua `nil` semantics instead: a
            // missing `local` becomes an ordinary "attempt to index/call a
            // nil value" error, raised by the Lua VM itself (not this
            // module), correctly attributed to the lib file's own
            // `set_name` and caught by the existing hard-error path (this
            // is NOT a `NamespaceSkip`, so `exec_scripts`'s
            // `chain().find_map` never matches it).
            //
            // Reentrancy: a lib that itself reads ANOTHER bare namespace
            // name is not a supported pattern (the design doc's own
            // multi-module story is one SCRIPT binding two namespaces, not
            // one lib depending on another) -- with the handler off, such a
            // read is indistinguishable from any other undefined global:
            // plain `nil`, and whatever the lib does with that `nil` next
            // (index it, call it) is a clean, attributable Lua error, the
            // same as the missing-`local` case above. Not corrupted, not
            // silently wrong -- just not resolved.
            globals.set_metatable(None);
            let result: LuaResult<Table> = lua.load(&source).set_name(format!("lib/{key}.lua")).eval();
            globals.set_metatable(Some(metatable.clone()));
            let table = result?;

            cache.borrow_mut().insert(key.clone(), table.clone());
            Ok(Value::Table(table))
        })?
    };

    metatable.set("__index", index)?;
    globals.set_metatable(Some(metatable));
    Ok(())
}
