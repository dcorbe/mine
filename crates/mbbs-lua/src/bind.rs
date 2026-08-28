//! The signature mini-language, per-ABI marshalling, and `mmud.bind(name)` /
//! `M.declare{...}` -- Task 2 of the declared-bindings plan.
//!
//! # Why declared entries are stored as bytes, not `A::Ptr`
//!
//! [`LuaExtension`](crate::LuaExtension) is deliberately non-generic (see
//! `lib.rs`'s own compile-time assertion: one `LuaExtension` value must
//! implement `Extension<Wg16>` *and* `Extension<Wg32>`), but a declared
//! export's resolved entry is exactly an `A::Ptr` -- an ABI-specific type
//! that cannot live in a non-generic struct's own field. [`Abi::ptr_to_bytes`]/
//! [`Abi::ptr_from_bytes`] are already the crate's own answer to "a generic
//! pointer needs a storable representation" -- this module's own
//! `call_declared` uses the identical pair to hand a `ptr`-typed export
//! return back to a script; [`DeclaredEntry`] reuses that same pair rather
//! than inventing a second one. The entry is still resolved
//! exactly once, at declare time -- decoding bytes back into `A::Ptr` at
//! call time is not a second resolve, it is reading back what declare time
//! already decided.
//!
//! # Why a declared export is rebound every invocation, not built once
//!
//! `M`'s declared functions must reach the *current* invocation's
//! `CommandCtx` to do anything at all, and `CommandCtx` is borrowed, not
//! owned -- exactly the constraint `crate::ptr`'s own module doc explains
//! forces every pointer-handle closure to be `Scope`-bound rather than
//! `'static`. The same constraint applies here: [`rebind`] runs inside
//! `Extension::command`'s own `Lua::scope` call, replacing each declared
//! name's slot on its namespace table with a fresh closure over *this*
//! invocation's `Ctx`/`Registry`, the same way `crate::ptr::install_buffer`
//! replaces `c.buffer` every call. The namespace table itself (`M`) is an
//! ordinary, non-scoped table built once at `mmud.bind` time; only the
//! function *values* living in its declared slots are scope-bound and torn
//! down when the call returns.
//!
//! # `str` argument layout
//!
//! Every `str`-typed argument is copied, NUL-terminated, into
//! [`CommandCtx::write_scratch`]'s persistent scratch region through
//! [`crate::ptr::take_scratch`] -- the SAME per-invocation bump cursor
//! `c:buffer` itself now draws from (`crate::ptr::ScratchCursor`'s own doc
//! comment). This is a fix, not the original shape: an earlier version of
//! this module gave `str` marshalling its own, private offset bookkeeping,
//! independent of `c:buffer`'s -- both assumed they alone owned the
//! region's start, so the canonical declared-bindings pattern (a script
//! holds a `c:buffer` cell for an OUT parameter and passes a `str` in the
//! *same* call, e.g. `M.get_item_from_name(name, nil, cell)`) silently
//! aliased the two: marshalling `name` overwrote `cell`'s own bytes before
//! the call ever ran. Sharing one cursor between every scratch consumer
//! this invocation -- `str` arguments and `c:buffer` handles alike --
//! closes that structurally: whichever one runs first simply claims the
//! next slice, and the other cannot land on the same bytes. See
//! `commands.rs`'s own `a_str_argument_and_a_live_buffer_in_one_call_do_not_collide`
//! for the test that catches a regression back to independent bookkeeping.
//!
//! Running past the region's real, fixed capacity surfaces as
//! `write_at`'s own bounds-check error, via `take_scratch` -- this module
//! does not hard-code the buffer's size anywhere; the real memory
//! resolution is the only authority on how much room there is.

use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;

use mbbs::abi::{Abi, Arg};
use mlua::{Lua, MultiValue, Result as LuaResult, Scope, Table, Value};

use crate::ptr::{self, Ctx, Registry, ScratchCursor};

/// One argument or return type in the signature mini-language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Type {
    Int,
    Long,
    Ptr,
    Str,
    Void,
}

/// A parsed `"ret(arg, ...)"` signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Signature {
    pub(crate) ret: Type,
    pub(crate) args: Vec<Type>,
}

fn parse_type(tok: &str) -> Result<Type, String> {
    match tok {
        "int" => Ok(Type::Int),
        "long" => Ok(Type::Long),
        "ptr" => Ok(Type::Ptr),
        "str" => Ok(Type::Str),
        "void" => Ok(Type::Void),
        other => Err(format!("unknown type {other:?}")),
    }
}

/// Parses `"ret(arg, ...)"` -- types `int`/`long`/`ptr`/`str`/`void`, `void`
/// valid only as `ret` (never as an argument), and `str` refused as `ret`
/// (the marshaller's own "Return:" contract only ever names `int`/`long`/
/// `ptr`/`void` -- see this module's own doc comment; there is no defined
/// behaviour for a declared export that "returns a string").
///
/// Every error names the bad token or the whole signature string; the
/// caller ([`install`]'s own `declare` closure) prefixes the declared
/// name, since this function -- deliberately -- knows nothing about which
/// declaration it is parsing.
pub(crate) fn parse_signature(sig: &str) -> Result<Signature, String> {
    let trimmed = sig.trim();
    let Some(open) = trimmed.find('(') else {
        return Err(format!("missing '(' in {trimmed:?}"));
    };
    if !trimmed.ends_with(')') {
        return Err(format!("missing closing ')' in {trimmed:?}"));
    }

    let ret = parse_type(trimmed[..open].trim())?;
    if ret == Type::Str {
        return Err(format!("str is not a valid return type in {trimmed:?}"));
    }

    let args_str = trimmed[open + 1..trimmed.len() - 1].trim();
    let args = if args_str.is_empty() {
        Vec::new()
    } else {
        args_str.split(',').map(|t| parse_type(t.trim())).collect::<Result<Vec<_>, _>>()?
    };
    if let Some(pos) = args.iter().position(|t| *t == Type::Void) {
        return Err(format!("arg {pos}: void is not a valid argument type in {trimmed:?}"));
    }

    Ok(Signature { ret, args })
}

/// The four spellings [`probe`] tries, in order: exact, leading underscore,
/// upper case, leading underscore + upper case -- the plan's own
/// "structural decision 1," no new loader API.
fn spellings(name: &str) -> [String; 4] {
    let upper = name.to_uppercase();
    [name.to_owned(), format!("_{name}"), upper.clone(), format!("_{upper}")]
}

/// Resolves `name` against `module`'s own export table, trying
/// [`spellings`] in order and stopping at the first hit. `None` if none of
/// the four resolve; the caller ([`install`]) is the one that turns that
/// into a hard, name-and-spellings-naming error, since only it knows the
/// declared name and the module this namespace is bound to.
fn probe<A: Abi>(module: &A::Module, name: &str) -> Option<(A::Ptr, String)> {
    for candidate in spellings(name) {
        if let Some(ptr) = A::export_address(module, &mbbs_machine::module::Symbol::Name(candidate.clone())) {
            return Some((ptr, candidate));
        }
    }
    None
}

/// One `M.declare{...}` entry, resolved once at declare time.
///
/// `table` is the namespace (`M`) this name lives on; `entry_bytes` is
/// [`Abi::ptr_to_bytes`]'s own encoding of the resolved `A::Ptr` -- see
/// this module's own doc comment for why bytes rather than the pointer
/// itself. `abi_name` is [`Abi::NAME`], stamped at the same declare time
/// `entry_bytes` is -- see [`check_abi`]'s own doc comment for what it
/// guards against and why `entry_bytes` alone cannot. `spelling` is which
/// of the four [`spellings`] actually matched, kept for `Debug`/diagnostic
/// purposes -- the plan's own "record which spelling matched (the
/// namespace should be able to report it)."
pub(crate) struct DeclaredEntry {
    table: Table,
    name: String,
    entry_bytes: Vec<u8>,
    abi_name: &'static str,
    #[allow(dead_code)] // Debug/diagnostic only for now -- see this struct's own doc comment.
    spelling: String,
    signature: Signature,
}

/// Every declared export across every namespace this `LuaExtension` bound,
/// in declaration order. Lives for the extension's whole life -- `declare`
/// only ever appends, [`rebind`] only ever reads.
pub(crate) type Declared = Rc<RefCell<Vec<DeclaredEntry>>>;

/// Installs `mmud.bind`/`mmud.abi` against every `(module_name, module)`
/// pair loaded on this machine -- Task 3's real entry point (Task 2's
/// `install` took exactly one pair; see `LuaExtension::load_with_modules`'s
/// own doc comment for why this grew to a list: a Wg16 machine can load
/// WCCMMUD + WCCMMPLS together, and each gets its own binding lib).
///
/// `mmud.bind(name)` hard-errors if `name` matches none of `modules` --
/// this is lib-file plumbing, called only from inside a lib file
/// `namespace::install`'s `__index` handler has already decided IS loaded
/// on this machine (its own soft-skip already ran before a lib is ever
/// executed), so this is a defensive check, not the seam that decides
/// availability. On a match it returns a fresh namespace table `M` whose
/// `M.declare{...}` resolves each declared name via [`probe`] and appends
/// a [`DeclaredEntry`] to `declared` -- never installing a callable
/// directly, since only [`rebind`] (invocation-scoped) can build one that
/// actually reaches a `CommandCtx`.
pub(crate) fn install<A: Abi>(lua: &Lua, modules: Vec<(String, A::Module)>, declared: Declared) -> LuaResult<()>
where
    A::Module: 'static,
{
    let mmud: Table = lua.globals().get("mmud")?;
    mmud.set("abi", A::NAME)?;

    let bind = lua.create_function(move |lua, name: String| {
        let Some((_, module)) = modules.iter().find(|(n, _)| *n == name) else {
            let loaded = modules.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(", ");
            return Err(mlua::Error::RuntimeError(format!(
                "mmud.bind({name:?}): no module named {name:?} is loaded on this machine (loaded: {loaded})"
            )));
        };
        let module = module.clone();

        let m = lua.create_table()?;
        let seen: Rc<RefCell<HashSet<String>>> = Rc::new(RefCell::new(HashSet::new()));
        let declare_module = module.clone();
        let declare_declared = Rc::clone(&declared);
        let declare_table = m.clone();
        let declare_module_name = name.clone();
        let declare = lua.create_function(move |_, spec: Table| {
            for pair in spec.pairs::<String, String>() {
                let (decl_name, sig) = pair?;

                if !seen.borrow_mut().insert(decl_name.clone()) {
                    return Err(mlua::Error::RuntimeError(format!("mmud.declare: {decl_name:?} is already declared on this namespace")));
                }

                let signature = parse_signature(&sig)
                    .map_err(|reason| mlua::Error::RuntimeError(format!("mmud.declare: {decl_name:?}: bad signature {sig:?}: {reason}")))?;

                let Some((ptr, spelling)) = probe::<A>(&declare_module, &decl_name) else {
                    let tried = spellings(&decl_name).join(", ");
                    return Err(mlua::Error::RuntimeError(format!(
                        "mmud.declare: no export named {decl_name:?} in module {declare_module_name:?} (tried: {tried})"
                    )));
                };

                declare_declared.borrow_mut().push(DeclaredEntry {
                    table: declare_table.clone(),
                    name: decl_name,
                    entry_bytes: A::ptr_to_bytes(ptr),
                    abi_name: A::NAME,
                    spelling,
                    signature,
                });
            }
            Ok(())
        })?;
        m.set("declare", declare)?;

        Ok(m)
    })?;
    mmud.set("bind", bind)?;

    Ok(())
}

/// Refuses to rebind a [`DeclaredEntry`] under an `Abi` other than the one
/// it was declared against.
///
/// `entry_bytes` alone cannot catch this: [`Abi::PTR_WIDTH`] is 4 for both
/// `Wg16` and `Wg32` today, so `A::ptr_from_bytes` never fails on a
/// mismatched entry -- it just silently reinterprets a `Wg16` `FarPtr`'s
/// `offset:selector` bytes as a `Wg32` flat address, or the reverse,
/// producing a pointer that happens to typecheck and is wrong. Nothing
/// about `LuaExtension`'s own shape prevents `rebind::<A>` from ever being
/// called with a different `A` than `install::<A>` was -- Task 3's real
/// wiring is expected to keep the two paired 1:1 per machine, but "probably
/// paired by the caller" is not a structural guarantee, and this repo's own
/// rule is that a runtime error beats undefined-but-typechecking behaviour.
///
/// A pure function, not folded into [`rebind`] itself, so it can be
/// unit-tested directly against `Wg32` with no `Fixture`/`Machine` at all
/// (`Fixture<Wg32>` is off-limits outside `crates/mbbs/tests/*.rs` -- see
/// `mbbs::testing::Fixture`'s own doc comment).
fn check_abi<A: Abi>(entry_name: &str, entry_abi: &str) -> LuaResult<()> {
    if entry_abi != A::NAME {
        return Err(mlua::Error::RuntimeError(format!(
            "{entry_name}: declared against ABI {entry_abi:?} but this LuaExtension is running under {:?} -- \
             a LuaExtension's declared bindings must not be rebound under a different ABI than they were declared with",
            A::NAME
        )));
    }
    Ok(())
}

/// Rebinds every entry in `declared` onto its namespace table, fresh for
/// this invocation -- see this module's own doc comment ("Why a declared
/// export is rebound every invocation"). Refuses outright, per entry, if
/// [`check_abi`] finds it was declared against a different `Abi` than `A`.
pub(crate) fn rebind<'scope, 'env, 'p, 'q, A: Abi>(
    scope: &'scope Scope<'scope, 'env>,
    ctx: Ctx<'p, 'q, A>,
    registry: Registry<A>,
    cursor: ScratchCursor,
    declared: &[DeclaredEntry],
) -> LuaResult<()>
where
    'p: 'scope,
    'q: 'scope,
{
    for entry in declared {
        check_abi::<A>(&entry.name, entry.abi_name)?;
        let entry_ptr = A::ptr_from_bytes(&entry.entry_bytes);
        let signature = entry.signature.clone();
        let name = entry.name.clone();
        let ctx = Rc::clone(&ctx);
        let registry = Rc::clone(&registry);
        let cursor = Rc::clone(&cursor);
        let f = scope.create_function(move |lua, args: MultiValue| {
            call_declared::<A>(scope, lua, &ctx, &registry, &cursor, entry_ptr, &signature, &name, args)
        })?;
        entry.table.set(entry.name.as_str(), f)?;
    }
    Ok(())
}

/// A returned 32-bit value's true bytes, per ABI register width.
///
/// `Outcome::Returned{lo,hi}` always reports both halves (`AX`/`DX` for
/// `Wg16`, `EAX`/`EDX` for `Wg32`), but whether a genuine 32-bit `long`/
/// pointer return actually SPANS both registers is ABI-dependent -- exactly
/// mirroring [`Arg::Long`]'s own asymmetry on the argument side (`Wg16`
/// splits a `long` into two pushed words, low then high; `Wg32` pushes one
/// dword, see `abi/wg16.rs`/`abi/wg32.rs`'s own `Arg::Long` arms). A 16-bit
/// ABI's own [`Abi::INT_WIDTH`] (2, vs. 4 for a 32-bit one) is what tells
/// the two cases apart generically, without naming either `Abi`
/// concretely.
fn wide_return<A: Abi>(lo: u32, hi: u32) -> u32 {
    if A::INT_WIDTH <= 2 { (lo & 0xffff) | (hi << 16) } else { lo }
}

/// A Lua number as `f64`, accepting **either** of Lua 5.4's two number
/// subtypes -- `Value::Integer` (what a script literal with no decimal
/// point, like `70000`, actually parses as) or `Value::Number`.
/// `Value::as_f64` alone only matches `Number`, which would wrongly refuse
/// every whole-number literal a script writes for an `int`/`long`
/// argument; this is the DSL's own lenient combination of the two,
/// deliberately not extended to a numeric *string* (unlike Lua's own
/// arithmetic coercion) so a stray string argument stays an unambiguous
/// refusal rather than a surprise conversion.
fn as_number(value: &Value) -> Option<f64> {
    match value {
        Value::Integer(i) => Some(*i as f64),
        Value::Number(n) => Some(*n),
        _ => None,
    }
}

/// `int` argument marshalling -- the recorded trap this whole task exists
/// to close.
///
/// A Lua number is accepted in `-32768..=65535`: a non-negative value is
/// this ABI's own `int` bit pattern directly (zero-extends correctly on
/// either ABI, since it never sets a sign bit at 16-bit width to begin
/// with); a negative one is first truncated to its 16-bit two's-complement
/// pattern, then **sign-extended** to 32 bits before
/// [`Abi::int_from_u32`] narrows it back down to this ABI's own width. This
/// is deliberate, not incidental: `A::Int::from(0xffffu16)` (a naive
/// zero-extending build) is `-1` under `Wg16` but `65535` under `Wg32` --
/// the `int_from_u16` sentinel trap [`Abi::int_from_u32`]'s own doc comment
/// names. Sign-extending first and narrowing through `int_from_u32` gives
/// `-1` at *either* ABI's own width, which is what a script passing "the
/// same -1" to a `wccmmud`/`wccmmud32` build of the same export should
/// see happen.
///
/// A value whose magnitude does not fit 16 bits either way (`70000`, say)
/// is refused -- this DSL's `int` type is deliberately narrower than a
/// genuine 32-bit `Wg32` `int` (the whole surface this crate's signatures
/// were measured against is the 16-bit build); a script that needs the
/// full 32-bit range declares `long` instead.
fn int_arg<A: Abi>(value: &Value, pos: usize) -> LuaResult<A::Int> {
    let n = as_number(value)
        .ok_or_else(|| mlua::Error::RuntimeError(format!("arg {pos}: int must be a number, got {}", value.type_name())))?;
    if !n.is_finite() || n.fract() != 0.0 {
        return Err(mlua::Error::RuntimeError(format!("arg {pos}: int must be a whole number, got {n}")));
    }
    if !(-32768.0..=65535.0).contains(&n) {
        return Err(mlua::Error::RuntimeError(format!("arg {pos}: int {n} out of range (-32768..=65535)")));
    }

    let signed = n as i64;
    let bits32: u32 = if signed >= 0 {
        signed as u32
    } else {
        // Truncate to the 16-bit two's-complement pattern, then
        // sign-extend to 32 bits -- see this function's own doc comment.
        i32::from(signed as i16) as u32
    };
    Ok(A::int_from_u32(bits32))
}

/// `long` argument marshalling: a plain, non-negative `u32` -- no sign
/// ambiguity to resolve (unlike `int`, above), since [`Arg::Long`] is
/// already a bare `u32` regardless of ABI.
fn long_arg(value: &Value, pos: usize) -> LuaResult<u32> {
    let n = as_number(value)
        .ok_or_else(|| mlua::Error::RuntimeError(format!("arg {pos}: long must be a number, got {}", value.type_name())))?;
    if !n.is_finite() || n.fract() != 0.0 {
        return Err(mlua::Error::RuntimeError(format!("arg {pos}: long must be a whole number, got {n}")));
    }
    if !(0.0..=u32::MAX as f64).contains(&n) {
        return Err(mlua::Error::RuntimeError(format!("arg {pos}: long {n} out of range (0..={})", u32::MAX)));
    }
    Ok(n as u32)
}

/// `str` argument marshalling: the raw bytes only -- NUL-checked here (the
/// same reasoning `scripts/lib/wccmmud.lua`'s own `M.summon` documents for an
/// embedded NUL in an item name: it would silently truncate what the module
/// reads), copied into scratch by the caller ([`call_declared`]), which is
/// the one that knows this call's own running offset.
fn str_arg(value: &Value, pos: usize) -> LuaResult<Vec<u8>> {
    let s = value
        .as_string()
        .ok_or_else(|| mlua::Error::RuntimeError(format!("arg {pos}: str must be a string, got {}", value.type_name())))?;
    let bytes = s.as_bytes().to_vec();
    if bytes.contains(&0) {
        return Err(mlua::Error::RuntimeError(format!("arg {pos}: str must not contain a NUL byte")));
    }
    Ok(bytes)
}

/// `ptr` argument marshalling: `nil` maps to this ABI's own null pointer;
/// a handle table resolves through `registry` by its own [`ptr::IDX_FIELD`];
/// anything else -- a Lua number most of all -- is refused outright. See
/// `crate::ptr::Registry`'s own doc comment for what an out-of-range index
/// here means and why it is safe to treat that index as a plain, readable
/// field.
fn ptr_arg<A: Abi>(value: &Value, pos: usize, registry: &Registry<A>) -> LuaResult<A::Ptr> {
    match value {
        Value::Nil => Ok(A::null_ptr()),
        Value::Table(t) => {
            let idx: i64 = t
                .get(ptr::IDX_FIELD)
                .map_err(|_| mlua::Error::RuntimeError(format!("arg {pos}: ptr must be a pointer handle or nil")))?;
            let idx = usize::try_from(idx).map_err(|_| mlua::Error::RuntimeError(format!("arg {pos}: invalid pointer handle")))?;
            registry.borrow().get(idx).copied().ok_or_else(|| {
                mlua::Error::RuntimeError(format!("arg {pos}: stale or invalid pointer handle (no such pointer minted this invocation)"))
            })
        }
        other => Err(mlua::Error::RuntimeError(format!(
            "arg {pos}: ptr must be a pointer handle or nil, never a {} -- a pointer is never built from a raw number",
            other.type_name()
        ))),
    }
}

/// The whole call: marshal `args` per `signature.args`, invoke `entry`
/// through [`CommandCtx::call_entry`], marshal the result back per
/// `signature.ret`. Built fresh by [`rebind`] every invocation; see this
/// module's own doc comment for why.
///
/// [`CommandCtx::call_entry`]: mbbs::extension::CommandCtx::call_entry
#[allow(clippy::too_many_arguments)]
fn call_declared<'scope, 'env, 'p, 'q, A: Abi>(
    scope: &'scope Scope<'scope, 'env>,
    lua: &Lua,
    ctx: &Ctx<'p, 'q, A>,
    registry: &Registry<A>,
    cursor: &ScratchCursor,
    entry: A::Ptr,
    signature: &Signature,
    name: &str,
    args: MultiValue,
) -> LuaResult<Value>
where
    'p: 'scope,
    'q: 'scope,
{
    if args.len() != signature.args.len() {
        return Err(mlua::Error::RuntimeError(format!(
            "{name}: expected {} argument(s), got {}",
            signature.args.len(),
            args.len()
        )));
    }

    let mut marshalled = Vec::with_capacity(signature.args.len());
    for (i, (ty, value)) in signature.args.iter().zip(args).enumerate() {
        let arg = match ty {
            Type::Int => Arg::Int(int_arg::<A>(&value, i)?),
            Type::Long => Arg::Long(long_arg(&value, i)?),
            Type::Ptr => Arg::Ptr(ptr_arg::<A>(&value, i, registry)?),
            Type::Str => {
                // Shares this invocation's ONE scratch cursor with
                // `c:buffer` -- see this module's own doc comment ("`str`
                // argument layout") for why that sharing is the fix, not
                // an implementation detail.
                let mut buf = str_arg(&value, i)?;
                buf.push(0);
                let at = ptr::take_scratch::<A>(ctx, cursor, &buf)?;
                Arg::Ptr(at)
            }
            Type::Void => unreachable!("parse_signature refuses void as an argument type"),
        };
        marshalled.push(arg);
    }

    let outcome = ctx.borrow_mut().call_entry(entry, &marshalled).map_err(mlua::Error::external)?;
    let (lo, hi) = match outcome {
        mbbs::Outcome::Returned { lo, hi } => (lo, hi),
        mbbs::Outcome::Stopped(poison) => {
            return Err(mlua::Error::RuntimeError(format!("{name} stopped the machine: {poison:?}")));
        }
    };

    match signature.ret {
        Type::Void => Ok(Value::Nil),
        // "raw zero-extended" -- see this module's own doc comment on
        // `Outcome::Returned` and `ptr.rs`'s own `u8`/`u16`/`u32` reads for
        // the same convention applied elsewhere: the script sees the bit
        // pattern the register actually held, and reinterprets sign
        // itself if the field is signed.
        Type::Int => Ok(Value::Integer(i64::from(lo))),
        Type::Long => Ok(Value::Integer(i64::from(wide_return::<A>(lo, hi)))),
        Type::Ptr => {
            let raw = wide_return::<A>(lo, hi);
            let ret_ptr = A::ptr_from_bytes(&raw.to_le_bytes());
            if ret_ptr == A::null_ptr() {
                Ok(Value::Nil)
            } else {
                let t = ptr::handle(scope, lua, Rc::clone(ctx), Rc::clone(registry), ret_ptr)?;
                Ok(Value::Table(t))
            }
        }
        Type::Str => unreachable!("parse_signature refuses str as a return type"),
    }
}

#[cfg(test)]
mod tests {
    use mbbs::abi::{Abi, Wg16, Wg32};
    use mlua::Value;

    use super::{Type, check_abi, int_arg, parse_signature};

    /// [`check_abi`]'s whole reason to exist: a `LuaExtension`'s declared
    /// entries carry no compile-time `Abi` tag (see `DeclaredEntry`'s own
    /// doc comment on why -- `LuaExtension` is deliberately non-generic),
    /// so a `Wg16`-declared entry rebound under `Wg32` must be refused, not
    /// silently reinterpreted. No `Fixture<Wg32>` needed -- `check_abi` is
    /// a pure function of two strings.
    #[test]
    fn rebinding_a_declared_entry_under_a_different_abi_is_a_named_error() {
        let err = check_abi::<Wg32>("get_player", Wg16::NAME).expect_err("must refuse a cross-ABI rebind");
        let msg = err.to_string();
        assert!(msg.contains("get_player"), "must name the entry, got: {msg}");
        assert!(msg.contains("wg16"), "must name the ABI it was declared against, got: {msg}");
        assert!(msg.contains("wg32"), "must name the ABI it is being rebound under, got: {msg}");
    }

    /// The non-mismatch case must not be refused -- every existing
    /// `Wg16`-only integration test in `commands.rs` depends on this
    /// passing silently.
    #[test]
    fn rebinding_a_declared_entry_under_its_own_abi_succeeds() {
        check_abi::<Wg16>("get_player", Wg16::NAME).expect("same-ABI rebind must succeed");
        check_abi::<Wg32>("get_player", Wg32::NAME).expect("same-ABI rebind must succeed");
    }

    /// The recorded `int_from_u16` sentinel trap, closed: a negative Lua
    /// number must come out as *this ABI's own* all-ones pattern, not a
    /// naive zero-extension of its 16-bit bits. Exercised directly, with no
    /// `Fixture`/`Machine` at all -- `int_arg` is a pure function of a
    /// `Value` -- because `Fixture<Wg32>` is off-limits outside
    /// `crates/mbbs/tests/*.rs` (see `mbbs::testing::Fixture`'s own doc
    /// comment), and this is exactly the ABI-dependent half of `int_arg`
    /// no `Wg16`-only integration test could ever tell apart from a naive
    /// implementation (`Wg16::int_from_u32(0xffff)` and a naive
    /// `From<u16>(0xffff)` both happen to answer `0xffff` -- the two only
    /// diverge under `Wg32`).
    #[test]
    fn a_negative_int_argument_sign_extends_to_each_abis_own_all_ones() {
        assert_eq!(int_arg::<Wg16>(&Value::Integer(-1), 0).expect("in range"), 0xffffu16);
        assert_eq!(int_arg::<Wg32>(&Value::Integer(-1), 0).expect("in range"), 0xffff_ffffu32);
    }

    /// The other half of the same fix, proven not to overreach: an
    /// unsigned value whose 16-bit pattern happens to set the top bit
    /// (`40000`, i.e. `0x9c40`) is NOT mistaken for a negative sentinel --
    /// it must reach either ABI as plain `40000`, not sign-extended into a
    /// large 32-bit value under `Wg32`. The sign comes from the Lua
    /// number's own sign, never from inspecting the bit pattern.
    #[test]
    fn a_large_unsigned_int_argument_is_never_mistaken_for_a_negative_sentinel() {
        assert_eq!(int_arg::<Wg16>(&Value::Integer(40000), 0).expect("in range"), 40000u16);
        assert_eq!(int_arg::<Wg32>(&Value::Integer(40000), 0).expect("in range"), 40000u32);
    }

    /// `Value::Integer` (what a whole-number Lua literal like `70000`
    /// actually parses as under Lua 5.4/`mlua`'s `lua54` feature) is
    /// accepted exactly like `Value::Number` -- `as_number`'s own
    /// deliberate leniency (see that function's own doc comment). A
    /// regression back to `Value::as_f64` alone (which only matches
    /// `Number`) would refuse every whole-number literal outright.
    #[test]
    fn an_integer_valued_lua_value_is_accepted_the_same_as_a_float_one() {
        assert_eq!(int_arg::<Wg16>(&Value::Integer(5), 0).expect("in range"), 5u16);
        assert_eq!(int_arg::<Wg16>(&Value::Number(5.0), 0).expect("in range"), 5u16);
    }

    #[test]
    fn parses_a_no_arg_signature() {
        let sig = parse_signature("void()").expect("parses");
        assert_eq!(sig.ret, Type::Void);
        assert!(sig.args.is_empty());
    }

    #[test]
    fn parses_a_multi_arg_signature() {
        let sig = parse_signature("ptr(int, ptr, ptr)").expect("parses");
        assert_eq!(sig.ret, Type::Ptr);
        assert_eq!(sig.args, vec![Type::Int, Type::Ptr, Type::Ptr]);
    }

    #[test]
    fn tolerates_whitespace_around_types_and_the_whole_signature() {
        let sig = parse_signature("  int( long ,  str ) ").expect("parses");
        assert_eq!(sig.ret, Type::Int);
        assert_eq!(sig.args, vec![Type::Long, Type::Str]);
    }

    #[test]
    fn refuses_an_unknown_type_and_names_it() {
        let err = parse_signature("int(frobnicate)").expect_err("must refuse");
        assert!(err.contains("frobnicate"), "got: {err}");
    }

    #[test]
    fn refuses_void_as_an_argument_type() {
        let err = parse_signature("int(void)").expect_err("must refuse");
        assert!(err.contains("void"), "got: {err}");
    }

    #[test]
    fn refuses_str_as_a_return_type() {
        let err = parse_signature("str(int)").expect_err("must refuse");
        assert!(err.contains("str"), "got: {err}");
    }

    #[test]
    fn refuses_a_missing_open_paren() {
        let err = parse_signature("int").expect_err("must refuse");
        assert!(err.contains('('), "got: {err}");
    }

    #[test]
    fn refuses_a_missing_close_paren() {
        let err = parse_signature("int(int").expect_err("must refuse");
        assert!(err.contains(')'), "got: {err}");
    }
}
