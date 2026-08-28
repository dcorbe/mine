//! Opaque pointer handles: `p:add(n)`, `p:u8/u16/u32(off)`, `p:w8/w16/w32(off,
//! v)`, and `c:buffer(n)`, the primitives a declared-bindings lib file
//! (Task 2) builds struct access on top of.
//!
//! # Why a table of scoped closures, not `mlua::AnyUserData`
//!
//! The obvious shape -- `impl mlua::UserData for PtrHandle`, minted through
//! [`mlua::Scope::create_userdata`] -- does not compile for `add`. `add` must
//! mint a *second* scoped value from inside a method call, but
//! `UserDataMethods::add_method`'s callback is bound `'static` regardless of
//! the userdata's own lifetime, so it cannot close over anything borrowed
//! (the invocation's `Rc<RefCell<&mut CommandCtx>>`). The only way to reach
//! `Scope::create_userdata` again from inside a method is for the userdata
//! itself to carry a `&'scope Scope<'scope, 'env>` -- which then needs `T:
//! 'env` to satisfy `create_userdata`'s own bound, while a field of type
//! `&'scope Scope<'scope, 'env>` only ever satisfies `T: 'scope`. Since
//! `Scope<'scope, 'env>` requires `'env: 'scope` (env is the *longer*
//! lifetime), the two requirements together force `'scope == 'env` -- which
//! the compiler cannot derive from a `for<'scope> FnOnce(..)` callback where
//! `'scope` is chosen after the fact by `Lua::scope` itself. Confirmed with a
//! minimal reproduction under `~/bbs-scratch/mlua-scope-poc` before writing
//! this module: `rustc` rejects exactly this shape with "argument requires
//! that `'scope` must outlive `'env`" the moment `add` tries to store `this.scope`
//! into a freshly-built `PtrHandle`.
//!
//! `Scope::create_function`, in contrast, only demands its closure outlive
//! `'scope` -- the *shorter* of the two -- so a closure built inside another
//! `'scope`-bounded closure can capture `scope` itself (a `Copy` reference)
//! with no lifetime conflict at all. A pointer handle here is therefore a
//! plain Lua table whose fields are `Scope::create_function` closures, each
//! one directly capturing its own `A::Ptr` (by value -- `Abi::Ptr: Copy`) and
//! a clone of the invocation's `Rc<RefCell<&mut CommandCtx>>`. `add` builds a
//! new such table by calling [`handle`] again, recursively, from inside its
//! own closure.
//!
//! # Unforgeable despite being "just a table"
//!
//! The brief for this task warns against "plain tables carrying integers,
//! which a script could fabricate" -- the concern being a script that reads a
//! numeric pointer back out of Lua-visible state and hands a *different*
//! number to a real accessor, bypassing every bound this module enforces.
//! This module's tables carry no such number: `A::Ptr` never crosses into Lua
//! as data at all, only as a value captured *inside* a Rust closure a script
//! cannot construct or introspect. A script that builds its own table and
//! calls a real closure with it as `self` (`p.add(fake, n)`, bypassing `:`
//! sugar) changes nothing -- every closure here ignores its `self` argument
//! entirely and answers only for the `A::Ptr` (and `Rc<RefCell<&mut
//! CommandCtx>>`) it closed over at creation time. The only way to reach a
//! *different* address is `add`, which can only walk forward from a base a
//! script already legitimately holds (originally minted by [`buffer`], or,
//! from Task 2 on, a `ptr`-typed export return) -- never conjure one from
//! nothing.
//!
//! # Dies with the invocation
//!
//! Every closure here is built through [`mlua::Scope::create_function`]
//! inside `Extension::command`'s own `Lua::scope` call, so `mlua` tears every
//! one down when that call returns -- a script that stashes a handle (or one
//! of its methods) in a Lua global and calls it from a *later* command sees
//! `mlua::Error::CallbackDestructed` ("this function has been destroyed"),
//! not a stale pointer. This is `mlua::Scope`'s own guarantee, not something
//! this module enforces by hand -- see
//! `commands.rs`'s `a_stashed_handle_errors_in_a_later_invocation` test.
//!
//! # A handle's own bound is a Wg16 segment property, not a handle property
//!
//! `read_width`/`write_width` (what `p:u8/u16/u32`/`p:w8/w16/w32` call
//! through) refuse an out-of-bounds access purely because
//! [`CommandCtx::read_at`]/[`CommandCtx::write_at`] do -- this module carries
//! no length alongside a handle's `A::Ptr` to check against; there is
//! nothing here that knows a `c:buffer(n)` handle is only supposed to be
//! `n` bytes wide once `handle` has built it.
//!
//! Under `Wg16` that omission costs nothing: `write_scratch`'s backing
//! region is its own dedicated LDT segment sized to exactly
//! `COMMAND_SCRATCH_BYTES`, and every `Wg16` far-pointer access is bounded
//! by that segment's own descriptor limit regardless of what this module
//! does or does not track -- an offset past the region simply cannot
//! resolve. **Under `Wg32` it is a real gap, not yet closed**:
//! `mbbs_machine::m32::mem::Memory::read_at`/`write_at` bounds-check
//! against the whole shared arena the scratch region was bump-allocated
//! from, not against any per-handle region, so `p:w32(off, v)` at an `off`
//! well past a handle's own logical length still resolves -- silently, into
//! whatever else the arena holds -- rather than refusing. This crate's own
//! rule ("Runtime crashes are better than undefined behavior") is violated
//! in spirit here even though nothing is memory-unsafe: the write lands
//! bounds-checked against the *wrong* bound, not against no bound at all.
//! The fix is a length-carrying handle -- `handle`/`buffer` stamping the
//! byte length they were built with onto the table, checked in
//! `read_width`/`write_width` before ever reaching `read_at`/`write_at` --
//! not yet implemented; see `scripts/lib/README.md`'s own scratch-budget
//! section for the operator-facing version of this same gap.
//!
//! # `w8`/`w16`/`w32` are unsigned only
//!
//! `v` in `p:w8/w16/w32(off, v)` must fit `0..=0xff`/`0xffff`/`0xffff_ffff`;
//! a negative value is refused the same way an over-large one is (see
//! `write_width`'s own doc comment). There is no `i16`/`i32` convenience --
//! deliberately, not an oversight. A declared binding that needs to write a
//! genuinely signed field encodes its own two's-complement bit pattern
//! before calling `w16`/`w32` (`-1` is `0xffff` at 16 bits, `0xffff_ffff` at
//! 32), the same way `p:u8/u16/u32`'s own reads hand back an unsigned value
//! a caller reinterprets itself if the field is signed.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use mbbs::abi::Abi;
use mbbs::extension::CommandCtx;
use mlua::{Function, Lua, Result as LuaResult, Scope, Table};

/// The invocation's shared `CommandCtx` -- the exact shape
/// `Extension::command`'s own `cell` variable already has (see that
/// function's own comment for why `Rc`, not a bare `RefCell`). Two
/// independent lifetimes, not one: `'p` is how long *this* reborrow of `ctx`
/// lasts (bounded by `Extension::command`'s own stack frame, since `ctx`
/// itself is read again, via `ctx.note(...)`, after the `Lua::scope` call
/// returns), and `'q` is `CommandCtx`'s own structural lifetime, fixed by
/// whoever originally built it. Forcing them equal does not typecheck --
/// `CommandCtx<'q, A>` holds `&'q mut` fields, which makes it invariant in
/// `'q`, so it cannot be silently shortened to match the shorter `'p`.
pub(crate) type Ctx<'p, 'q, A> = Rc<RefCell<&'p mut CommandCtx<'q, A>>>;

/// Every pointer [`handle`] has minted so far this invocation, in mint
/// order -- Task 2's handle -> `A::Ptr` extraction path. A handle table
/// carries its position in this list as a plain field ([`IDX_FIELD`]); the
/// declared-bindings marshaller (`crate::bind`) resolves a `ptr`-typed
/// argument by reading that field back out and indexing here, since it has
/// no other way to reach the `A::Ptr` a table's own closures keep private
/// (see this module's own "Unforgeable despite being 'just a table'"
/// section).
///
/// Built fresh, empty, once per invocation (`Extension::command` owns the
/// only `Rc::new` site), which is what keeps a *stale* handle's index from
/// resolving to a different, live pointer this invocation never actually
/// minted for it: an index into an empty (or shorter) registry is simply
/// out of bounds, not a wrong answer -- see
/// `commands.rs`'s own
/// `a_stale_handles_index_does_not_resolve_against_a_later_invocations_registry`
/// for the property this buys, and the brief's own "no new capability"
/// framing for why a *plain* field is an acceptable place to carry this
/// index at all: the worst a forged or stale index can do is name a
/// pointer Rust already minted THIS invocation, never memory a script had
/// no route to already.
pub(crate) type Registry<A> = Rc<RefCell<Vec<<A as Abi>::Ptr>>>;

/// The table field a handle's registry index lives at.
pub(crate) const IDX_FIELD: &str = "__idx";

/// A per-invocation bump cursor over [`CommandCtx::write_scratch`]'s one
/// shared, persistent scratch region -- see [`take_scratch`]'s own doc
/// comment for why every consumer of that region this invocation, `c:buffer`
/// and a declared call's own `str` arguments alike, shares exactly one of
/// these rather than each independently assuming it owns the region's
/// start. Built fresh, at zero, once per invocation (`Extension::command`
/// owns the only `Rc::new` site), mirroring [`Registry`]'s own "fresh, empty
/// every invocation" contract.
pub(crate) type ScratchCursor = Rc<Cell<u16>>;

/// Writes `bytes` into [`CommandCtx::write_scratch`]'s persistent region at
/// `cursor`'s current position, advances `cursor` past them, and returns a
/// pointer to where they landed.
///
/// # Why one shared cursor, not one caller assuming it owns offset 0
///
/// `write_scratch` itself always targets the exact same base address -- one
/// region, allocated once, reused for the `Host`'s whole lifetime (see its
/// own doc comment). Before declared bindings existed, `c:buffer` was the
/// only caller, one consumer laying out one allocation at a time -- nothing
/// else in the same invocation could also want scratch, so "always offset
/// 0" and "the one and only consumer" were the same fact. Declared bindings
/// added a second, independent writer (a declared call's `str` arguments),
/// and a review caught what that created: with both still assuming they
/// alone own offset 0, a script's `c:buffer` handle and a `str` argument's
/// marshalled bytes in the same call would land on the identical address,
/// each write undoing the other's, silently and deterministically -- the
/// exact "sword"/OUT-count-cell collision the canonical declared-bindings
/// pattern (`M.get_item_from_name(name, nil, cell)`) hits on every call.
/// Every consumer of scratch this invocation now takes its bytes from here,
/// at a running offset, so two consumers in the same call are guaranteed
/// disjoint regardless of which one runs first -- including two `c:buffer`
/// calls in the same invocation, which is why [`buffer`] no longer hands
/// back the same base on a second call the way it did before this fix (see
/// `commands.rs`'s own test on that point).
///
/// The region's real, fixed capacity is never hard-coded here or anywhere
/// else in this crate: writing past it is refused by
/// [`CommandCtx::write_at`]'s own bounds check (the real memory
/// resolution), which this function surfaces directly rather than
/// duplicating as a second, hand-maintained limit.
pub(crate) fn take_scratch<A: Abi>(ctx: &Ctx<'_, '_, A>, cursor: &ScratchCursor, bytes: &[u8]) -> LuaResult<A::Ptr> {
    let base = ctx.borrow_mut().write_scratch(&[]).map_err(mlua::Error::external)?;
    let at = checked_offset::<A>(base, i64::from(cursor.get()))?;
    ctx.borrow_mut().write_at(at, bytes).map_err(mlua::Error::external)?;
    let advance = u16::try_from(bytes.len())
        .ok()
        .and_then(|n| cursor.get().checked_add(n))
        .ok_or_else(|| mlua::Error::RuntimeError("scratch: this invocation's cursor overflowed a 16-bit offset".to_owned()))?;
    cursor.set(advance);
    Ok(at)
}

/// Resolve `off` (bytes past `ptr`, as a script wrote it) into a concrete
/// pointer, refusing rather than wrapping.
///
/// Negative offsets are refused outright: every declared binding this
/// primitive serves offsets *into* a struct a script already knows the shape
/// of (`REC.loaded`, `REC.exp_mod`, ...), never backward from one. Anything
/// that would overflow this ABI's own address space is refused by
/// [`Abi::ptr_checked_add`] itself -- see that method's own doc comment for
/// why this crate uses it here rather than [`Abi::ptr_offset`]:
/// `ptr_offset`'s own contract is "delta is already known to fit a region
/// this crate just allocated," which is true of `Host::command_scratch`'s
/// own bookkeeping but not of a number a script typed.
fn checked_offset<A: Abi>(ptr: A::Ptr, off: i64) -> LuaResult<A::Ptr> {
    let by = usize::try_from(off).map_err(|_| mlua::Error::RuntimeError(format!("offset {off} must not be negative")))?;
    A::ptr_checked_add(ptr, by).ok_or_else(|| mlua::Error::RuntimeError(format!("offset {off} does not fit this pointer's address space")))
}

/// The largest value a `width`-byte unsigned write may carry, and the
/// human-readable width used in an out-of-range error.
fn width_bits_and_max(width: usize) -> (usize, i64) {
    match width {
        1 => (8, 0xff),
        2 => (16, 0xffff),
        4 => (32, 0xffff_ffff),
        _ => unreachable!("this module only ever reads/writes 1, 2 or 4 bytes"),
    }
}

/// `p:u8/u16/u32(off)` -- read `width` little-endian bytes at `ptr + off`.
fn read_width<A: Abi>(ctx: &Ctx<'_, '_, A>, ptr: A::Ptr, off: i64, width: usize) -> LuaResult<i64> {
    let at = checked_offset::<A>(ptr, off)?;
    let bytes = ctx.borrow().read_at(at, width).map_err(mlua::Error::external)?;
    let mut buf = [0u8; 4];
    buf[..width].copy_from_slice(&bytes);
    Ok(i64::from(u32::from_le_bytes(buf)))
}

/// `p:w8/w16/w32(off, v)` -- write `v` as `width` little-endian bytes at
/// `ptr + off`. `v` out of `width`'s unsigned range is refused, not
/// truncated -- see this module's own doc comment.
fn write_width<A: Abi>(ctx: &Ctx<'_, '_, A>, ptr: A::Ptr, off: i64, width: usize, value: i64) -> LuaResult<()> {
    let (bits, max) = width_bits_and_max(width);
    if !(0..=max).contains(&value) {
        return Err(mlua::Error::RuntimeError(format!("w{bits}: value {value} does not fit an unsigned {bits}-bit write (0..={max})")));
    }
    let at = checked_offset::<A>(ptr, off)?;
    let bytes = (value as u32).to_le_bytes();
    ctx.borrow_mut().write_at(at, &bytes[..width]).map_err(mlua::Error::external)
}

/// Build one pointer handle: a table whose seven fields (`add`,
/// `u8`/`u16`/`u32`, `w8`/`w16`/`w32`) are `scope`-scoped closures over `ptr`
/// and `ctx`. See this module's own doc comment for why a table of closures,
/// not `mlua::AnyUserData`.
pub(crate) fn handle<'scope, 'env, 'p, 'q, A: Abi>(
    scope: &'scope Scope<'scope, 'env>,
    lua: &Lua,
    ctx: Ctx<'p, 'q, A>,
    registry: Registry<A>,
    ptr: A::Ptr,
) -> LuaResult<Table>
where
    'p: 'scope,
    'q: 'scope,
{
    let t = lua.create_table()?;

    // Register this pointer under the invocation's own registry and stamp
    // the resulting index onto the table -- see [`Registry`]'s own doc
    // comment for what this buys and what it deliberately does not
    // pretend to guard against.
    let idx = {
        let mut reg = registry.borrow_mut();
        reg.push(ptr);
        reg.len() - 1
    };
    t.set(IDX_FIELD, idx as i64)?;

    t.set("add", {
        let ctx = Rc::clone(&ctx);
        let registry = Rc::clone(&registry);
        scope.create_function(move |lua, (_this, n): (Table, i64)| {
            let new_ptr = checked_offset::<A>(ptr, n)?;
            handle(scope, lua, Rc::clone(&ctx), Rc::clone(&registry), new_ptr)
        })?
    })?;

    for width in [1usize, 2, 4] {
        let (bits, _) = width_bits_and_max(width);
        t.set(format!("u{bits}"), {
            let ctx = Rc::clone(&ctx);
            scope.create_function(move |_, (_this, off): (Table, i64)| read_width::<A>(&ctx, ptr, off, width))?
        })?;
        t.set(format!("w{bits}"), {
            let ctx = Rc::clone(&ctx);
            scope.create_function(move |_, (_this, off, value): (Table, i64, i64)| write_width::<A>(&ctx, ptr, off, width, value))?
        })?;
    }

    Ok(t)
}

/// `c:buffer(n) -> handle` -- `n` zeroed bytes of [`CommandCtx::write_scratch`]'s
/// persistent host scratch, taken from this invocation's own [`ScratchCursor`]
/// so a second `c:buffer` call, or a `str` argument marshalled later in the
/// same invocation, gets a disjoint slice rather than colliding with this
/// one -- see [`take_scratch`]'s own doc comment for why. Not a per-call
/// guest allocation: `write_scratch`'s own *region* is still one allocation
/// for the `Host`'s whole lifetime; only the offset *within* it advances
/// per call. Running past the region's fixed capacity is refused by the
/// real memory bounds check `take_scratch` surfaces.
fn buffer<'scope, 'env, 'p, 'q, A: Abi>(
    scope: &'scope Scope<'scope, 'env>,
    lua: &Lua,
    ctx: Ctx<'p, 'q, A>,
    registry: Registry<A>,
    cursor: ScratchCursor,
    n: i64,
) -> LuaResult<Table>
where
    'p: 'scope,
    'q: 'scope,
{
    let len = usize::try_from(n).map_err(|_| mlua::Error::RuntimeError(format!("buffer: size {n} must not be negative")))?;
    let base = take_scratch::<A>(&ctx, &cursor, &vec![0u8; len])?;
    handle(scope, lua, ctx, registry, base)
}

/// `c:buffer` itself -- a `Function` built once per invocation, the same way
/// `Extension::command`'s own `print` entry, and `bind::rebind`'s own
/// declared-export closures, are.
///
/// Takes `scope` by value (`&mut Scope`, reborrowed to `&Scope` right here,
/// at this call boundary) rather than letting the caller do it: a `let`
/// binding cannot name the caller's own `for<'scope> FnOnce(&'scope mut
/// Scope<'scope, 'env>)` lifetime to store a reborrowed `&Scope` for reuse
/// across several `t.set(...)` calls (confirmed with the same
/// `~/bbs-scratch/mlua-scope-poc` repro this module's own doc comment
/// cites), but a *function call* boundary coerces `&mut Scope` to `&Scope`
/// just fine -- exactly the coercion `Extension::command`'s own repeated
/// `scope.create_function(...)` receiver calls already rely on. Once inside
/// here, `scope`'s type is an ordinary named generic parameter, not a
/// caller's HRTB, so this closure captures it (a plain `Copy` reference) with
/// no conflict.
pub(crate) fn install_buffer<'scope, 'env, 'p, 'q, A: Abi>(
    scope: &'scope Scope<'scope, 'env>,
    ctx: Ctx<'p, 'q, A>,
    registry: Registry<A>,
    cursor: ScratchCursor,
) -> LuaResult<Function>
where
    'p: 'scope,
    'q: 'scope,
{
    scope.create_function(move |lua, (_this, n): (Table, i64)| {
        buffer(scope, lua, Rc::clone(&ctx), Rc::clone(&registry), Rc::clone(&cursor), n)
    })
}
