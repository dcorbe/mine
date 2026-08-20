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

/// Turns a [`CommandCtx::call_export`] outcome this seam doesn't care about
/// the *return value* of into a plain error if the machine stopped --
/// shared by every call site below that just needs "did it run," not "what
/// did it return." `name` is the export that was called, for the error
/// message only.
///
/// [`CommandCtx::call_export`]: mbbs::extension::CommandCtx::call_export
fn expect_returned(name: &str, outcome: Outcome<Wg16>) -> mlua::Result<(u32, u32)> {
    match outcome {
        Outcome::Returned { lo, hi } => Ok((lo, hi)),
        Outcome::Stopped(poison) => Err(mlua::Error::RuntimeError(format!("{name} stopped the machine: {poison:?}"))),
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
    // A NUL inside `name` would truncate the C string the module reads at
    // that byte, silently searching for a shorter (and wrong) name instead
    // of the one the player typed -- refuse outright rather than let that
    // happen quietly. Lua strings are byte strings and do not forbid an
    // embedded NUL the way `mlua::String::to_str()`/a Rust `&str` would.
    if name.contains(&0) {
        return Err(mlua::Error::RuntimeError("summon: item name must not contain a NUL byte".to_string()));
    }

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
    let (lo, hi) = expect_returned("_GET_ITEM_FROM_NAME", outcome)?;

    // The far pointer DX:AX came back in -- offset (AX) then selector (DX),
    // the same order `Abi::ptr_to_bytes` writes one in.
    let mut ptr_bytes = (lo as u16).to_le_bytes().to_vec();
    ptr_bytes.extend_from_slice(&(hi as u16).to_le_bytes());
    let item = Wg16::ptr_from_bytes(&ptr_bytes);

    if item == Wg16::null_ptr() {
        let count_bytes = ctx.borrow().read_at(count_ptr, 2).map_err(mlua::Error::external)?;
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
    // A `char` return: only the low byte (AL) is meaningful, so mask
    // rather than compare `lo` whole -- AH is whatever a `char`-typed
    // Borland routine's caller-saved half happened to hold.
    //
    // TODO: verify against a real module. The findings file documents
    // the return as "char: 1 success, 0 failure" but does not say which
    // bits of `Outcome::Returned.lo` carry it -- this masking is my own
    // interpretation of ordinary Borland `char`-return convention, not
    // something measured off `WCCMMUD.DLL` itself (task-6-report.md's
    // "Concerns" section says the same).
    let (lo, _hi) = expect_returned("_ADD_ITEM_TO_INVENTORY", add_outcome)?;
    if lo & 0xff != 0 {
        Ok((true, None))
    } else {
        Ok((false, Some("too heavy or no free slot")))
    }
}

/// Splits a 32-bit value into its low and high 16-bit words, low word
/// first -- the shape `_ADDON_ADJUST_USER_WEALTH(usrnum, lo, hi)` wants for
/// its `CONCAT22(param_3, param_2)` amount (see [`adjust_wealth`]'s own doc
/// comment). A pure function so the word order can be tested directly,
/// without a module in the loop.
fn split_u32(value: u32) -> (u16, u16) {
    (value as u16, (value >> 16) as u16)
}

/// Adds `amount` to a two-word (`low`, `carry`) 16-bit accumulator,
/// propagating a 16-bit overflow of `low` into `carry` -- exactly what the
/// module's own `_SELL_ITEM`/`_WITHDRAW_GOLD`/`_BORROW_GOLD` bodies do to
/// their copper accumulator (`re/exports/WCCMMUD_named.c:5462-5466` et al.):
///
/// ```text
/// uVar3 = *low;
/// *low = *low + amount_lo;
/// *carry = *carry + amount_hi + CARRY2(uVar3, amount_lo);
/// ```
///
/// `CARRY2(a, b)` is 1 exactly when `a + b` overflowed 16 bits, which is
/// what [`u16::overflowing_add`] answers directly. A pure function so the
/// carry propagation can be tested directly -- [`adjust_wealth`]'s own grant
/// path cannot be exercised end to end in this fixture, since it needs a
/// real player record behind `_GET_PLAYER` to write into (see
/// `task-7-report.md`'s "untestable" section).
fn add_with_carry(low: u16, carry: u16, amount: u32) -> (u16, u16) {
    let amount_lo = amount as u16;
    let amount_hi = (amount >> 16) as u16;
    let (new_low, overflowed) = low.overflowing_add(amount_lo);
    let new_carry = carry.wrapping_add(amount_hi).wrapping_add(u16::from(overflowed));
    (new_low, new_carry)
}

/// `c:adjust_wealth(amount)` -- grant (`amount >= 0`) or deduct
/// (`amount < 0`) `amount` copper from the caller's own coin purse.
///
/// **Asymmetric on purpose.** The task's original plan called
/// `_ADDON_ADJUST_USER_WEALTH` for both directions, on the claim that the
/// amount "round-trips as a signed value." That is false: the export's
/// whole body (`re/exports/WCCMMUD_named.c:73399-73424`) forwards to
/// `_DEDUCT_CURRENCY`, gated on an affordability check, every coin write a
/// decrement -- there is no path through it that credits a player. See
/// `.superpowers/sdd/2026-08-20-lua-command-seam/task-7-findings.md`.
///
/// - `amount >= 0` grants, the way the module's own `_SELL_ITEM`,
///   `_WITHDRAW_GOLD`, `_BORROW_GOLD` and `_CMD_GET` all credit a player:
///   direct field arithmetic (see [`add_with_carry`]) on
///   [`CommandCtx::player_record`]'s copper accumulator -- low word at
///   offset `0x613`, carry word at `0x615` -- then
///   `_CLEANUP_CURRENCY(usrnum)` to normalise into higher denominations,
///   then `_SAVE_PLAYER(usrnum)`. `_CLEANUP_CURRENCY` mints
///   highest-denomination-first, which is already the minimum-coin-count
///   (and, since `_GET_COIN_WEIGHT` sums `floor(count/3)` per drawer,
///   minimum-*weight*) representation -- granting copper and letting it
///   normalise needs no manual denomination choice.
/// - `amount < 0` deducts via `_ADDON_ADJUST_USER_WEALTH(usrnum, lo, hi)`
///   (see [`split_u32`]) -- the low and high 16-bit words of
///   `amount.unsigned_abs()`, low word first, matching its own
///   `CONCAT22(param_3, param_2)`. It saves the player itself; this branch
///   does not call `_SAVE_PLAYER` again.
///
/// `amount` is `f64`, not `i64`: a fractional or absurdly large typed
/// amount is a player mistake, not a script bug, so it is reported through
/// this function's own `(false, reason)` convention instead of an `mlua`
/// argument-conversion error -- which would disable the whole `cash`
/// command (see `Extension::command`'s error arm below) over one bad line
/// of player input, exactly the "silence must never be mistaken for
/// consent" concern [`to_verdict`]'s own doc comment raises, one layer up.
///
/// Returns `(true, nil)` on success, `(false, reason)` otherwise:
/// `"amount must be a whole number"`, `"amount is too large"` (the
/// magnitude does not fit 32 bits), or `"insufficient funds"`
/// (`_ADDON_ADJUST_USER_WEALTH` refused).
///
/// [`CommandCtx::player_record`]: mbbs::extension::CommandCtx::player_record
fn adjust_wealth(ctx: &RefCell<&mut CommandCtx<'_, Wg16>>, amount: f64) -> mlua::Result<(bool, Option<&'static str>)> {
    if !amount.is_finite() || amount.fract() != 0.0 {
        return Ok((false, Some("amount must be a whole number")));
    }

    // `usrnum` is exactly this channel's number -- see `summon`'s own
    // comment on the same read.
    let usrnum = ctx.borrow().chan().number() as u16;

    if amount >= 0.0 {
        let Ok(copper) = u32::try_from(amount as i64) else {
            return Ok((false, Some("amount is too large")));
        };

        let record = ctx.borrow_mut().player_record().map_err(mlua::Error::external)?;
        let low_ptr = Wg16::ptr_offset(record, 0x613);
        let carry_ptr = Wg16::ptr_offset(record, 0x615);

        let low_bytes = ctx.borrow().read_at(low_ptr, 2).map_err(mlua::Error::external)?;
        let carry_bytes = ctx.borrow().read_at(carry_ptr, 2).map_err(mlua::Error::external)?;
        let low = u16::from_le_bytes([low_bytes[0], low_bytes[1]]);
        let carry = u16::from_le_bytes([carry_bytes[0], carry_bytes[1]]);
        let (new_low, new_carry) = add_with_carry(low, carry, copper);

        ctx.borrow_mut().write_at(low_ptr, &new_low.to_le_bytes()).map_err(mlua::Error::external)?;
        ctx.borrow_mut().write_at(carry_ptr, &new_carry.to_le_bytes()).map_err(mlua::Error::external)?;

        let outcome = ctx.borrow_mut().call_export("_CLEANUP_CURRENCY", &[Arg::Int(usrnum)]).map_err(mlua::Error::external)?;
        expect_returned("_CLEANUP_CURRENCY", outcome)?;

        let outcome = ctx.borrow_mut().call_export("_SAVE_PLAYER", &[Arg::Int(usrnum)]).map_err(mlua::Error::external)?;
        expect_returned("_SAVE_PLAYER", outcome)?;

        Ok((true, None))
    } else {
        let Ok(magnitude) = u32::try_from((-amount) as i64) else {
            return Ok((false, Some("amount is too large")));
        };
        let (lo, hi) = split_u32(magnitude);

        let outcome = ctx
            .borrow_mut()
            .call_export("_ADDON_ADJUST_USER_WEALTH", &[Arg::Int(usrnum), Arg::Int(lo), Arg::Int(hi)])
            .map_err(mlua::Error::external)?;
        let (lo_ret, _hi_ret) = expect_returned("_ADDON_ADJUST_USER_WEALTH", outcome)?;

        // A `char` return, the same convention `summon`'s own
        // `_ADD_ITEM_TO_INVENTORY` call uses above: only the low byte (AL)
        // is meaningful.
        if lo_ret & 0xff != 0 {
            Ok((true, None))
        } else {
            Ok((false, Some("insufficient funds")))
        }
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
            t.set("summon", {
                let cell = Rc::clone(&cell);
                scope.create_function(move |_, (_this, name): (mlua::Table, mlua::String)| summon(&cell, &name.as_bytes()))?
            })?;
            t.set(
                "adjust_wealth",
                scope.create_function(move |_, (_this, amount): (mlua::Table, f64)| adjust_wealth(&cell, amount))?,
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
    use super::{add_with_carry, split_command, split_u32};

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

    #[test]
    fn split_u32_puts_the_low_word_first() {
        assert_eq!(split_u32(0x1234_5678), (0x5678, 0x1234));
    }

    #[test]
    fn split_u32_of_a_value_under_64k_has_a_zero_high_word() {
        assert_eq!(split_u32(50), (50, 0));
    }

    #[test]
    fn add_with_carry_below_the_word_boundary_leaves_the_carry_word_untouched() {
        assert_eq!(add_with_carry(10, 0, 5), (15, 0));
    }

    #[test]
    fn add_with_carry_propagates_a_16_bit_overflow_into_the_carry_word() {
        // 0xfffe + 5 overflows a 16-bit word by 3, carrying 1 into the next.
        assert_eq!(add_with_carry(0xfffe, 0, 5), (3, 1));
    }

    #[test]
    fn add_with_carry_adds_the_amounts_own_high_word_too() {
        assert_eq!(add_with_carry(0, 0, 0x1_0000), (0, 1));
    }

    #[test]
    fn add_with_carry_combines_an_existing_carry_a_high_word_and_an_overflow() {
        // low: 0xffff + 1 overflows to 0, carrying 1.
        // carry: 2 (existing) + 1 (amount's high word) + 1 (the overflow) = 4.
        assert_eq!(add_with_carry(0xffff, 2, 0x1_0001), (0, 4));
    }

    #[test]
    fn add_with_carry_wraps_the_carry_word_like_the_module_itself_does() {
        assert_eq!(add_with_carry(0, 0xffff, 0x1_0000), (0, 0));
    }
}
