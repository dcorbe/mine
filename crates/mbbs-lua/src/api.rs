//! The `mmud` Lua table: command registration and verdict constants.
//!
//! Kept separate from `lib.rs` because it is the only place that touches raw
//! Lua values on the way in -- everything past `install` deals in
//! `(String, mlua::Function)` pairs.

use mlua::{Function, Lua, Result as LuaResult};

use crate::Handlers;

/// The integer a handler returns to swallow the line. Anything else --
/// including `nil`, which is what a handler that forgets to `return` at all
/// produces -- means "pass it through."
pub(crate) const HANDLED: mlua::Integer = 1;

/// Installs the `mmud` global table into `lua`: `mmud.command(name, handler)`,
/// `mmud.PASS`, `mmud.HANDLED`. `handlers` collects `(name, handler)` pairs in
/// registration order as scripts call `mmud.command`.
pub(crate) fn install(lua: &Lua, handlers: Handlers) -> LuaResult<()> {
    let mmud = lua.create_table()?;
    mmud.set("PASS", 0)?;
    mmud.set("HANDLED", HANDLED)?;

    let command = lua.create_function(move |_, (name, handler): (String, Function)| {
        handlers.borrow_mut().push((name, handler));
        Ok(())
    })?;
    mmud.set("command", command)?;

    lua.globals().set("mmud", mmud)
}
