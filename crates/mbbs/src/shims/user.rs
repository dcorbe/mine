//! The current user, and the tables a channel number indexes.
//!
//! ```text
//! curusr        20    uacoff        7
//! ```
//!
//! Both take a channel number and neither returns anything the module could
//! not have computed -- which is the point. `user[]`, `extusr[]` and the
//! account block are three arrays with one index between them, and these are
//! the two routines that hold the index still.
//!
//! # Task 5: the template file for `Call`-shaped shims
//!
//! All six routines are generic now:
//! `fn(&mut Call<A>, &mut Host<A>) -> Result<abi::Ret<A>, ShimError>`, taking
//! their arguments through [`Call`] rather than [`super::args`]'s bare
//! `Cursor`, and touching module memory through [`Call::mem`] rather than a
//! whole `&mut Machine`. Each keeps its C name for the generic core (matching
//! `docs/plans/2026-08-11-abi-abstraction-implementation.md`'s Task 5
//! "target shape"), and gets a `_wg16`-suffixed sibling that bridges it into
//! the (still concrete) [`super::Shim`] the dispatch table wants -- see
//! `shims::call`'s own doc comment for why the table itself does not go
//! generic in this task. [`getin`] was the one holdout, when this file first
//! converted -- see its own doc comment for what it was blocked on and what
//! unblocked it, in the `shims/text.rs`+`fsd.rs` and `shims/gsbl.rs`+
//! `screen.rs` commits that followed this one.

// `Machine`/`Ret` are now named only by this file's `#[cfg(test)]`
// `_wg16` bridges -- production code reaches every routine here through
// its generic `Call<A>`/`Host<A>` core instead, per `shims::mod`'s own
// `call` doc comment.
#[cfg(test)]
use mbbs_machine::m16::Ret;
use mbbs_machine::ptr::ModulePtr;

use super::ShimError;
use crate::Host;
use crate::abi::{self, Abi, Call};
use crate::gsbl::Gsbl;

/// `struct usracc *uacoff(int unum)` -- the channel's account record.
///
/// `ACCOUNT.C:126`:
///
///
/// `uablok` is never null in this host -- the block is allocated in
/// [`Host::new`] and never released -- so the null return is unreachable. An
/// out-of-range `unum` is not. `ptrblok` had no bound and would have handed
/// back the bytes after the last record; `WCCMMUD.DLL` then passes the result
/// to `obtbtvl(..., key, 0, 5, 0)` as a key, which is `userid` at offset 0 of
/// the record. Keying a Btrieve read on whatever follows the block is the exact
/// class of quiet wrongness this crate refuses, so the module stops instead.
///
/// Generic (Task 5): the only argument read is `call.int()`, widened through
/// [`Abi::Int`]'s `Into<u32>` bound and truncated back to `i16` -- the same
/// value either ABI's `int()` decodes, since a real channel number always
/// fits in 16 bits regardless of how wide this ABI's `int` is.
pub fn uacoff<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let unum = Into::<u32>::into(call.int()) as i16;
    let chan = host
        .users()
        .terms()
        .chan(unum)
        .ok_or_else(|| ShimError::Failed(format!("uacoff({unum}): there is no such channel")))?;
    Ok(abi::Ret::Ptr(host.users().account(chan)))
}

/// `void curusr(int uno)` -- make `uno` the current channel.
///
/// `MAJORBBS.C:4290`. Sets four of the six globals the original did:
///
/// | Set | |
/// |---|---|
/// | `usrnum` | the channel number itself |
/// | `usrptr` | `&user[usrnum]` |
/// | `usaptr` | `uacoff(usrnum)` |
/// | `vdaptr` | `vdaoff(usrnum)`, null until [`Host::alcvda`] has run |
///
/// `extptr` and `clingo` are not set because this host does not place them and
/// `WCCMMUD.DLL` imports neither. `mnuusr` is not set because `mnuoff`
/// (`MENUING.C:875`) indexes the menuing subsystem's `muusrs` block, which
/// this host does not have and cannot invent -- the same reason `globals.rs`
/// declines to place `ztzone`.
///
/// Out of range is a **silent no-op**, which is what `MAJORBBS.C:4293`'s
/// `if (0 <= uno && uno < nterms)` does. That is not this crate's usual
/// answer -- a shim that cannot do what it was asked normally stops the module
/// -- but here doing nothing *is* the documented behaviour and callers depend
/// on it. It is recorded in [`Host::notes`] instead, once, so that a run in
/// which it happens is not silent.
///
/// The four writes themselves are [`Host::point_curusr`] -- [`Host::connect_state`]
/// needs the identical repointing when a channel connects, and this is the
/// one of the two callers that also owns the silent-no-op behaviour, so the
/// range check stays here and the body that does not vary moved out.
///
/// Generic (Task 5): [`Host::point_curusr`](crate::Host::point_curusr)'s
/// generic core, [`Host::point_curusr_mem`](crate::Host::point_curusr_mem),
/// is what unblocked this one -- it was `impl Host<Wg16>`-only until this
/// task, following exactly the `_mem` split `Globals`/`Users` already use.
pub fn curusr<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let uno = Into::<u32>::into(call.int()) as i16;
    let Some(chan) = host.users().terms().chan(uno) else {
        host.note_once(
            "curusr",
            format!("curusr({uno}): there is no such channel, so nothing changed"),
        );
        return Ok(abi::Ret::Void);
    };
    host.point_curusr_mem(call.mem(), chan)?;
    Ok(abi::Ret::Void)
}

/// `char *getin(void)` -- get input, parse it, and hand back the first
/// argument.
///
/// `archive/galacticomm/extract/wg20/galdsrc/SRC/MAJORBBS.C:3368`:
///
///
/// **Returns `char *margv[0]`, not `void`** -- a shim answering `Ret::Void`
/// here would hand the module a null pointer it dereferences unguarded.
///
/// Takes no arguments of its own: like the original, it works off `usrnum`,
/// the channel `curusr` last made current. The sequence itself --
/// `paccin()` then `parsin()` -- is [`Host::get_input`], because
/// [`Host::poll`](crate::Host::poll) needs it too and this is the one call
/// site among the two that has an argument stack to read from at all.
///
/// Generic (unblocked by `shims/text.rs` and `crate::fsd.rs` converting):
/// [`Host::get_input`](crate::Host::get_input) was the last piece of
/// `paccin(); parsin();` still `Wg16`-only, because it called
/// `shims::text::parsin(machine, self)` -- `parsin` itself is generic now
/// (see `shims::text`'s own doc comment), and `Host::get_input_mem` is the
/// `_mem` core that calls `parsin_mem` directly. Reads no argument of its
/// own -- like [`shims::text::clrprf`]/[`parsin`] this still takes a
/// `Call<A>`, not a bare `Cursor`, matching every other converted shim in
/// this file, but unlike those two, `getin` is reached **only** through
/// module dispatch (its one `ROUTINES` entry) and never as an internal
/// helper with no call frame -- see this crate's own `entry` table -- so
/// there is no `arg_frame()` panic to guard against here the way there was
/// for `clrprf`/`parsin`.
///
/// [`shims::text::clrprf`]: crate::shims::text::clrprf
/// [`parsin`]: crate::shims::text::parsin
pub fn getin<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let usrnum = host
        .globals()
        .word_mem(call.mem(), "usrnum")
        .map_err(|e| ShimError::Failed(e.to_string()))? as i16;
    let chan = host
        .users()
        .terms()
        .chan(usrnum)
        .ok_or_else(|| ShimError::Failed(format!("getin: usrnum {usrnum} names no channel")))?;
    let margv0 = host.get_input_mem(call.mem(), chan)?;
    Ok(abi::Ret::Ptr(margv0))
}

/// `int haskey(char *lock)` -- does the current user hold the key to this lock?
///
/// `LOCKNKEY.C:254`, which is one line:
///
///
/// The current user is taken from `usrnum` rather than from anything this host
/// remembers, because that is what the original read: a module that moved
/// `curusr` gets the answer for the channel it moved to. `WCCMMUD.DLL` calls
/// this at 61 sites and imports none of the subsystem's other twenty-nine
/// routines -- it asks, never grants, and never asks about anyone else.
///
/// The expression grammar and the key test are [`crate::KeySet::evaluate`].
/// Two of `low_haskey`'s branches are answered here instead, because they are
/// about the channel rather than about the keys:
///
/// `keys == NULL` (`:194`) -- a channel nobody has logged onto -- answers
/// `class == BBSPRV`, not 0, and the check comes *before* the empty-lock check
/// that would otherwise grant. `connect_state` writes `usrcls` as 0, which is
/// neither `ONLINE` (1) nor `BBSPRV` (2, `MAJORBBS.H:163`), so it refuses; the
/// comparison is written out rather than folded into a `false` so that it
/// starts telling the truth on its own the day this host grows an internal
/// channel.
///
/// `scnpsk` (`:213`), the pseudokey scan, is **not** reproduced. It walks an
/// array `register_pseudok` (`:47`) fills, and `WCCMMUD.DLL` never calls
/// `register_pseudok` -- so the array is empty and the scan cannot return
/// anything but -1. If a second module ever registers one, this is a real gap.
///
/// # A deliberate infidelity
///
/// `low_haskey` reaches `lockbit(lock,0)`, which opens with `strupr(lock)` and
/// uppercases the caller's string **in place** -- the module's own static
/// config data. This shim does not: it reads the lock into a host-side
/// `String` and folds that, leaving module memory alone. Three reasons,
/// recorded because this is the first place this crate is knowingly
/// unfaithful to a measured byte.
///
/// Generic (Task 5): `host.class(machine, chan)` became
/// `host.class_mem(call.mem(), chan)` -- [`Host::class`](crate::Host::class)
/// was also `impl Host<Wg16>`-only until this task, for the same reason
/// [`Host::point_curusr`](crate::Host::point_curusr) was (see [`curusr`]'s
/// doc comment).
///
/// It is unobservable to this module: those lock strings live in a table at
/// `seg 0x1258` and reach `haskey` and nothing else -- no `prf`, no `strcpy`,
/// no comparison. It is not consistent even in the original, because
/// `flags&MASTER` returns before `lockbit` is reached, so a master-flagged
/// user's lock strings never get uppercased at all. And writing into a
/// module's static data from a predicate is a side effect nobody would design
/// on purpose; it is C's in-place API leaking through an interface that is
/// otherwise pure.
pub fn haskey<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let lock = call.ptr();
    // `A::Ptr::Error` has no `From` into `ShimError` for an arbitrary `A` --
    // only `Wg16`'s `FarPtrError` does (`crate::shims::ShimError`'s own
    // `impl From`) -- so this is `map_err`, not `?`, unlike the `Wg16`-only
    // original.
    let lock = lock
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let lock = String::from_utf8_lossy(&lock).into_owned();
    gen_haskey(call, host, &lock)
}

/// `int hasmkey(int mnum)` -- does the current user hold the key named in
/// message `mnum`?
///
/// `LOCKNKEY.H:193-194` (wg33src) declares it; `LOCKNKEY.C:239-243` (wg1) is
/// the whole body:
///
///
/// `re/ne_arity.py 335 <WCCMMPLS.DLL>` measures 18/18 call sites cleaning one
/// word, matching this one-`int` prototype -- `335` is `_HASMKEY`'s ordinal in
/// `crates/mbbs/data/majorbbs_wg101.tsv`.
///
/// `rawmsg` is not itself implemented here -- `shims::msg`'s own module doc
/// comment already says why: `WCCMMUD.DLL` never imports it, so there is
/// nothing pinning its behaviour against that oracle. But `rawmsg(mnum)` is
/// just "the stored text of message `mnum`, uninterpreted" -- exactly what
/// [`crate::shims::msg::message_mem`] plus a raw `read_cstr` already gives
/// [`stgopt`](crate::shims::msg::stgopt) before that routine allocates a
/// module-owned copy. This shim reads the same bytes and stops there: a lock
/// expression is evaluated host-side, never handed back to the module, so
/// there is no allocation to make.
///
/// # Everything past the lock string is [`haskey`]'s own
///
/// Same `usrnum` read, same three-case channel test (`keys == NULL` answers
/// `class == BBSPRV`, a channel naming nobody answers `false`, a real keyring
/// is [`crate::KeySet::evaluate`]), same [`Host::asked_for_key`] bookkeeping
/// -- [`gen_haskey`] is exactly `LOCKNKEY.C:239` and `:254`'s shared
/// `gen_haskey(lock,usrnum,usrptr)` tail, factored out once a second caller
/// needed it rather than copied.
///
/// # Errors
///
/// If message `mnum` cannot be read from the current message block.
pub fn hasmkey<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let mnum = Into::<u32>::into(call.int()) as u16;
    let at = crate::shims::msg::message_mem(call.mem(), host, mnum)?;
    let lock = at
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let lock = String::from_utf8_lossy(&lock).into_owned();
    gen_haskey(call, host, &lock)
}

/// `gen_haskey(lock,usrnum,usrptr)` -- [`haskey`] and [`hasmkey`]'s shared
/// tail, once the lock expression is in hand as a host-side string.
///
/// `LOCKNKEY.C:194-196`'s `usrnum`/three-case-channel logic; see [`haskey`]'s
/// own doc comment for the case-by-case account, which is unchanged by this
/// split -- only where the lock string comes from differs between the two
/// callers.
fn gen_haskey<A: Abi>(call: &mut Call<A>, host: &mut Host<A>, lock: &str) -> Result<abi::Ret<A>, ShimError> {
    // `globals()` reports `io::Error` and `ShimError` has no `From` for it, so
    // the map_err is the house pattern here -- see `shims/fsd.rs:72`.
    let unum = host
        .globals()
        .word_mem(call.mem(), "usrnum")
        .map_err(|e| ShimError::Failed(format!("haskey: usrnum: {e}")))? as i16;

    // `LOCKNKEY.C:194`. Three cases, and they are not the same one -- which is
    // why this is not a bare `false`. The outermost is "no such channel":
    // `usrnum` is -1 for as long as nobody is on one (`MAJORBBS.C:740`'s
    // sentinels exist for exactly that value), and there is nobody to hold a
    // key. **Not** an error: asking `Host::class` there would stop the module
    // over a state the real host was in whenever the board was idle.
    let answer = match host.users().terms().chan(unum) {
        None => false,
        Some(chan) => match host.users().keys(chan) {
            Some(keys) => keys.evaluate(lock),
            // A channel that exists but never logged on -- `keys == NULL`.
            // Answered by class, and `usrcls` is 0 here, so it refuses; the
            // comparison is written out rather than folded away so that it
            // starts telling the truth on its own the day this host grows an
            // internal channel.
            None => host.class_mem(call.mem(), chan)? == BBSPRV,
        },
    };
    host.asked_for_key(unum, lock, answer);
    Ok(abi::Ret::Int(A::Int::from(answer as u16)))
}

/// `INVISB`, `MAJORBBS.H:274` -- bit `0x4000` of `user.flags`. A channel with
/// this bit set answers "not here" to [`instat`]/[`onsysn`] even when the
/// state/class test and the user-id both match -- `MAJORBBS.C:3738`'s
/// `if (!(othusp->flags&INVISB))` and `:3697`'s `if (invis ||
/// !(othusp->flags&INVISB))`.
const INVISB: u32 = 0x0000_4000;

/// `othusn=n; othusp=usroff(n); othuap=uacoff(n);` -- the assignment
/// [`instat`]'s and [`onsysn`]'s loops open every iteration with,
/// `MAJORBBS.C:3694-3695`/`:3735-3736`. One function because the assignment
/// itself is identical in both; only what each does with the result differs.
///
/// Called on **every** channel the scan visits, not only a matching one --
/// see [`scan_for`]'s own doc comment for why that is the point.
fn write_oth_globals<A: Abi>(call: &mut Call<A>, host: &mut Host<A>, chan: crate::Chan) -> Result<(), ShimError> {
    let slot = host.users().slot(chan);
    let account = host.users().account(chan);
    host.globals()
        .write_int_mem(call.mem(), "othusn", chan.number() as i32 as u32)
        .map_err(|e| ShimError::Failed(format!("othusn: {e}")))?;
    host.globals()
        .write_mem(call.mem(), "othusp", &A::ptr_to_bytes(slot))
        .map_err(|e| ShimError::Failed(format!("othusp: {e}")))?;
    host.globals()
        .write_mem(call.mem(), "othuap", &A::ptr_to_bytes(account))
        .map_err(|e| ShimError::Failed(format!("othuap: {e}")))?;
    Ok(())
}

/// `sameas(uid, uacoff(chan)->userid)` -- read the account record's own copy
/// of the user-id out of module memory and fold-compare it, rather than
/// trusting it to agree with whatever built the channel's
/// [`crate::Connection`]. The two are the same bytes only because
/// [`crate::Host::connect_state`] put them there; this reads what a module
/// itself would see.
fn userid_matches<A: Abi>(
    call: &mut Call<A>,
    host: &mut Host<A>,
    chan: crate::Chan,
    uid: &[u8],
) -> Result<bool, ShimError> {
    let account = host.users().account(chan);
    let at = A::ptr_offset(account, host.users().account_layout().userid);
    let bytes = at.read_cstr(call.mem()).map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(crate::strings::sameas(uid, bytes))
}

/// The loop [`instat`] and [`onsysn`] share: walk every channel in order,
/// writing `othusn`/`othusp`/`othuap` as we go, and stop at the first one for
/// which `matches` and the `INVISB` gate (unless `invis` waives it) both
/// pass.
///
/// # The globals are written on every iteration, not only a match
///
/// `MAJORBBS.C:3689-3702`/`:3730-3743` write `othusn`/`othusp`/`othuap` at the
/// *top* of the loop body, before either test runs -- so a module reading
/// them after the call sees wherever the loop actually finished, which is not
/// always where it matched.
///
/// **On a match**, that is the matching channel -- the ordinary case, and the
/// one every caller actually wants.
///
/// **On no match**, the loop runs every channel `Terms::all` produces without
/// ever satisfying both tests, and the globals are left exactly where the
/// last iteration wrote them: `othusn == nterms - 1` (the last real channel),
/// `othusp`/`othuap` pointing at that channel's own slot -- **not** one past
/// the end, because `write_oth_globals` runs before the loop's own bound
/// check, and there is no channel numbered `nterms` to visit. A module that
/// reads them after a `FALSE` return sees the last channel this host has, the
/// same thing it would see against the real host once `othusn` has counted up
/// to `nterms` without the `for` test having anything left to admit.
///
/// **Deliberately not reset to a sentinel on `FALSE`.** There is no "clear"
/// story anywhere in `LOCKNKEY.C`/`MAJORBBS.C` for these three globals after a
/// failed scan -- inventing one here would be tidiness the vendor code does
/// not have.
fn scan_for<A: Abi>(
    call: &mut Call<A>,
    host: &mut Host<A>,
    invis: bool,
    mut matches: impl FnMut(&mut Call<A>, &mut Host<A>, crate::Chan) -> Result<bool, ShimError>,
) -> Result<bool, ShimError> {
    for chan in host.users().terms().all() {
        write_oth_globals(call, host, chan)?;
        if matches(call, host, chan)? {
            if invis {
                return Ok(true);
            }
            let flags = host.users().flags_mem(call.mem(), chan)?;
            if flags & INVISB == 0 {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// `INT instat(const CHAR *uid, INT qstate)` -- is this user-id logged onto a
/// channel currently in module state `qstate`?
///
/// `MAJORBBS.C:3730`:
///
///
/// The `othusn`/`othusp`/`othuap` side effect is [`scan_for`]'s -- see its own
/// doc comment for what a caller sees on both a match and a miss.
///
/// `state` is read through [`crate::users::UserLayout::state`], never a
/// literal offset: a C `INT`, two bytes under `Wg16` and four under `Wg32`.
/// `qstate` is read through `call.int()` at `A`'s own width and widened to
/// `i32` before the comparison, so a state number that does not fit `u16`
/// (there is no such module in practice, but nothing upstream refuses one at
/// this layer) compares correctly rather than wrapping into a false match.
///
/// `sameas` is [`crate::strings::sameas`], reused rather than reimplemented --
/// see [`sameas`](crate::shims::text::sameas)'s own doc comment for why a
/// second copy of that fold does not belong here.
///
/// # Errors
///
/// If `uid` cannot be read, or a channel's user/account record cannot be.
pub fn instat<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let uid = call.ptr();
    let qstate = Into::<u32>::into(call.int()) as i32;
    let uid = uid
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    let found = scan_for(call, host, false, |call, host, chan| {
        let state = i32::from(host.users().state_mem(call.mem(), chan)?);
        if state != qstate {
            return Ok(false);
        }
        userid_matches(call, host, chan, &uid)
    })?;

    Ok(abi::Ret::Int(A::Int::from(u16::from(found))))
}

/// `SUPIPG`, `MAJORBBS.H:224` -- "signup in progress". [`onsysn`]'s
/// `usrcls > SUPIPG` test asks for a channel that has *finished* signing up.
const SUPIPG: u16 = 3;

/// `INT onsysn(const CHAR *uid, GBOOL invis)` -- is this user-id online (and
/// past signup, not merely signing up)?
///
/// `MAJORBBS.C:3689`:
///
///
/// Same `othusn`/`othusp`/`othuap` side effect as [`instat`]; see
/// [`scan_for`]. `invis` (`TRUE` skips the `INVISB` gate outright) is
/// `onsysn`'s one difference from `instat`'s unconditional check --
/// `bootem`/`kilchn` call `onsysn(who,1)` so an operator kicking a user finds
/// them even if they asked to be hidden from ordinary lookups.
///
/// # This host never sets a channel's `usrcls` above the 0 it starts at
///
/// [`Host::connect_state`] writes `usrcls`, `state` and `substt` all as zero
/// on connect, and nothing afterwards advances `usrcls` -- there is no signup
/// flow here to finish. `SUPIPG` is 3, so `usrcls > SUPIPG` is false for every
/// channel this host has ever produced, and `onsysn` is therefore always
/// `FALSE` here regardless of `uid`/`invis`. That is not a stub: it is the
/// real comparison, against the real (if perpetually zero) field, the same
/// choice [`haskey`]'s own doc comment already explains for its `BBSPRV`
/// fallback -- written out rather than folded to a literal `false` so that it
/// starts telling the truth on its own the day this host grows real class
/// assignment.
///
/// # Errors
///
/// If `uid` cannot be read, or a channel's user/account record cannot be.
pub fn onsysn<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let uid = call.ptr();
    let invis = super::gbool_arg::<A>(call.int());
    let uid = uid
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    let found = onsysn_for(call, host, &uid, invis)?;
    Ok(abi::Ret::Int(A::Int::from(u16::from(found))))
}

/// [`onsysn`]'s scan, against a user-id the caller already has in hand.
///
/// Split out so `crate::shims::credits::crdusr` can ask the same question the
/// vendor's `crdusr` asks (`ACCOUNT.C:725`, `onsysn(keyuid,1)`) without a
/// second copy of the channel walk -- and so that when this host grows a
/// signup flow that advances `usrcls` past `SUPIPG`, both callers start
/// telling the truth on the same day. See
/// [`onsysn_is_always_false_here_because_this_host_never_advances_usrcls_past_zero`](self::tests)
/// for what that day changes.
pub(crate) fn onsysn_for<A: Abi>(
    call: &mut Call<A>,
    host: &mut Host<A>,
    uid: &[u8],
    invis: bool,
) -> Result<bool, ShimError> {
    scan_for(call, host, invis, |call, host, chan| {
        let usrcls = host.users().usrcls_mem(call.mem(), chan)?;
        if usrcls <= SUPIPG {
            return Ok(false);
        }
        userid_matches(call, host, chan, uid)
    })
}

/// `INT gen_haskey(const CHAR *lock, INT unum, struct user *uptr)` --
/// `LOCKNKEY.H:165` (recovered with `re/wgproto.py`; the declaration is
/// Galacticomm's K&R multi-line style, so a single-line grep does not find
/// it). `LOCKNKEY.C:216-231`:
///
///
/// **Fully implemented, by exposing what this host already had.** This is the
/// general form of [`haskey`], and [`crate::KeySet::evaluate`] is already that
/// general form -- the `&`/`|` fold, `low_haskey`'s empty-lock and
/// master-key branches, all of it. `haskey` and [`othkey`] have been calling
/// it since the key subsystem landed; the only thing missing was the entry
/// point that lets a module name the user itself.
///
/// So this **wraps** rather than generalises or stands separate. Writing a
/// second expression evaluator beside `KeySet::evaluate` would leave two
/// answers to one question, and the day they disagreed the module would
/// believe whichever it happened to call.
///
/// **`uptr` must agree with `unum`, and is checked rather than ignored.** The
/// vendor reads the keys out of `uptr` and uses `unum` only for the
/// pseudo-key scan, so a caller passing a mismatched pair gets the *pointer's*
/// keys there. This host holds keys per channel, indexed by number, and has
/// nowhere to put a pointer that disagrees -- so rather than silently
/// answering for `unum` and hoping, a mismatch is refused. Every real call
/// site passes `(usrnum, usrptr)` or `(othusn, othusp)`, which agree by
/// construction.
///
/// **The lock string is not written to.** The vendor NUL-terminates each term
/// in place and restores the byte afterwards, which is why its `const` is a
/// lie. Reading the string once and splitting a copy is observationally the
/// same for any caller that is not watching its own buffer mid-call, and it
/// keeps a `const CHAR *` argument genuinely const.
///
/// # Errors
///
/// If `lock` is not a valid pointer, if `unum` names no channel of this host,
/// or if `uptr` does not address that channel's own `struct user` slot.
pub fn gen_haskey_shim<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let lock = call.ptr();
    let unum = Into::<u32>::into(call.int()) as i16;
    let uptr = call.ptr();

    let lock = lock
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let lock = String::from_utf8_lossy(&lock).into_owned();

    let chan = host
        .users()
        .terms()
        .chan(unum)
        .ok_or_else(|| ShimError::Failed(format!("gen_haskey: unum {unum} names no channel")))?;

    // `uptr` is `usroff(unum)` at every real call site. A pair that disagrees
    // would have been answered from the pointer by the vendor, and this host
    // has no way to do that -- keys live per channel number.
    let slot = host.users().slot(chan);
    if uptr != slot {
        return Err(ShimError::Failed(format!(
            "gen_haskey: uptr does not address channel {unum}'s own user slot -- \
             this host holds keys per channel number and cannot answer for a \
             `struct user` that is not one of its own"
        )));
    }

    let answer = match host.users().keys(chan) {
        Some(keys) => keys.evaluate(&lock),
        None => host.class_mem(call.mem(), chan)? == BBSPRV,
    };
    host.asked_for_key(unum, &lock, answer);
    Ok(abi::Ret::Int(A::Int::from(u16::from(answer))))
}

/// `INT uhskey(const CHAR *uid, const CHAR *lock)` -- `LOCKNKEY.H:197`.
/// `LOCKNKEY.C:317-322`:
///
///
/// **Fully implemented as the branch it is**, and its two arms are not equally
/// answerable here. Online, it is [`othkey`] -- and `onsysn`'s own scan is
/// what leaves `othusn` pointing at the channel it found, which is exactly
/// how the vendor's composition works. Offline, it is [`uidkey`], which this
/// host can only answer for an empty lock; see that routine for why.
///
/// So in practice this refuses for any real lock name today, because
/// [`onsysn_for`] answers false for every channel while `usrcls` stays at
/// zero. That is the honest consequence of a gap this host already carries
/// rather than a second gap of this routine's own, and the day a signup flow
/// advances `usrcls` this routine starts answering from the online arm with
/// no change here.
///
/// # Errors
///
/// If either string is not a valid pointer, or whatever [`uidkey`] reports on
/// the offline arm.
pub fn uhskey<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let uid = call.ptr();
    let lock = call.ptr();

    let uid_bytes = uid
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    if onsysn_for(call, host, &uid_bytes, true)? {
        // `othusn` now names the channel `onsysn`'s scan stopped on, which is
        // what the vendor's `othkey(lock)` reads. Answered here rather than by
        // re-entering the `othkey` shim, whose own `Call` frame would be this
        // one's and holds two arguments rather than the one it expects.
        return othkey_for(call, host, lock);
    }
    uidkey_for(call, host, uid, lock)
}

/// [`othkey`]'s body, against a lock pointer the caller already has.
fn othkey_for<A: Abi>(
    call: &mut Call<A>,
    host: &mut Host<A>,
    lock: A::Ptr,
) -> Result<abi::Ret<A>, ShimError> {
    let lock = lock
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let lock = String::from_utf8_lossy(&lock).into_owned();

    let othusn = host
        .globals()
        .word_mem(call.mem(), "othusn")
        .map_err(|e| ShimError::Failed(format!("othkey: othusn: {e}")))? as i16;
    let chan = host
        .users()
        .terms()
        .chan(othusn)
        .ok_or_else(|| ShimError::Failed(format!("othkey: othusn {othusn} names no channel")))?;

    let answer = match host.users().keys(chan) {
        Some(keys) => keys.evaluate(&lock),
        None => host.class_mem(call.mem(), chan)? == BBSPRV,
    };
    host.asked_for_key(othusn, &lock, answer);
    Ok(abi::Ret::Int(A::Int::from(u16::from(answer))))
}

/// `INT uidkey(const CHAR *uid, const CHAR *lock)` -- `LOCKNKEY.H:210`
/// (recovered with `re/wgproto.py`; a plain header grep for `uidkey` finds
/// only a *comment*, which is why the plan names that tool as the authority).
/// `LOCKNKEY.C:339-371`:
///
///
/// **The empty lock is answered; anything else refuses.**
///
/// `lock[0] == '\0'` returns 1 before the routine touches a disk, so that
/// branch is reproduced exactly -- an empty lock is no lock and everybody
/// passes it, the same rule [`crate::KeySet`]'s own `holds` already carries.
///
/// Past that, the whole body is a database this host does not have. It opens
/// the **accounts** file (`accbb`) to find an account that is not online, then
/// reads that account's key list out of the **keys** file through `getlst`,
/// then falls back to a `&`-prefixed keyring record named after the account's
/// class. This host keeps keys as a per-channel `crate::KeySet` built at
/// connect and has no account database, no keys file, and no keyring records
/// -- so for an offline user there is nothing to consult and no honest answer
/// to give. Answering `0` would be the plausible zero this crate refuses
/// everywhere: it reads as "that user does not hold the key" when the truth
/// is "this host cannot tell".
///
/// # Errors
///
/// Always, for a non-empty lock, naming the two Btrieve files that would have
/// to exist.
pub fn uidkey<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let uid = call.ptr();
    let lock = call.ptr();
    uidkey_for(call, host, uid, lock)
}

/// [`uidkey`]'s body, against pointers the caller already has -- [`uhskey`]'s
/// offline arm is the second caller.
fn uidkey_for<A: Abi>(
    call: &mut Call<A>,
    _host: &mut Host<A>,
    uid: A::Ptr,
    lock: A::Ptr,
) -> Result<abi::Ret<A>, ShimError> {
    let lock_bytes = lock
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    if lock_bytes.is_empty() {
        // `LOCKNKEY.C:345`, before any disk access: an empty lock is no lock.
        return Ok(abi::Ret::Int(A::Int::from(1u16)));
    }

    let uid_bytes = uid
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let uid = String::from_utf8_lossy(&uid_bytes).into_owned();
    let lock = String::from_utf8_lossy(&lock_bytes).into_owned();

    Err(ShimError::Failed(format!(
        "uidkey({uid:?}, {lock:?}): this host has no offline account or key \
         database to look a user up in -- keys live only as a per-channel set \
         built at connect, so there is no `accbb` account record, no `keysbb` \
         key list and no class keyring to consult for a user who is not online; \
         see this routine's own doc comment"
    )))
}

/// `VOID nkyrec(const CHAR *uid)` -- `LOCKNKEY.H:149`. `LOCKNKEY.C:117-132`:
///
///
/// **Refuses.** Every line of the body is a write to the keys Btrieve file,
/// and this host has no such file: keys are a per-channel
/// [`crate::KeySet`] built at connect and thrown away at disconnect, with
/// nothing persistent behind them.
///
/// This is a `VOID` routine, which makes the refusal load-bearing rather than
/// cosmetic. A `VOID` that returns quietly promises the caller nothing at call
/// time -- which is exactly why returning quietly here would be wrong: the
/// caller's next act is to grant keys into the record it believes was just
/// created, and every one of those grants would land nowhere. Stopping the
/// module at the creation is the only point where the failure is still
/// attributable.
///
/// # Errors
///
/// Always, naming the keys file that would have to exist.
pub fn nkyrec<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let uid = call.ptr();
    let uid = uid
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let uid = String::from_utf8_lossy(&uid).into_owned();

    Err(ShimError::Failed(format!(
        "nkyrec({uid:?}): this host keeps no key records to create one in -- \
         keys are a per-channel set built at connect, and there is no `keysbb` \
         Btrieve file behind them for a `struct keyrec` to be written to; \
         see this routine's own doc comment"
    )))
}

/// `INT keynam(const CHAR *keyname)` -- `LOCKNKEY.H:250`. `LOCKNKEY.C:594`
/// is one line into `valkorl` (`:607-636`), which is `static` and so is
/// reproduced here rather than registered:
///
///
/// **Fully implemented.** A key name is 3 to `KEYSIZ-1` = 15 characters of
/// [`crate::strings::is_text_var_char`], plus `#` and `=` which the switch
/// lets through explicitly.
///
/// **`&` and `|` are rejected**, because `islock` is 0 here. That is the whole
/// difference between `keynam` and its sibling `loknam`: a *lock* may be an
/// expression joining several keys, and a *key* may not, which is why
/// [`gen_haskey`](gen_haskey_shim) has an expression grammar to parse at all.
///
/// The length floor is 3 and applies unconditionally for a key -- `!islock`
/// makes the `(... || len > 0)` guard true, so even the empty string is
/// rejected, unlike a lock name where empty is allowed.
///
/// # Errors
///
/// If `keyname` is not a valid pointer, or the read runs off the segment.
pub fn keynam<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    /// `KEYSIZ`, `LOCKNKEY.H:86` -- "max size of key name (and class name
    /// also)". The name itself is bounded by `KEYSIZ-1`.
    const KEYSIZ: usize = 16;

    let keyname = call.ptr();
    let name = keyname
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    let valid = name.len() >= 3
        && name.len() <= KEYSIZ - 1
        && name.iter().all(|&c| match c {
            // The switch's own two explicit passes.
            b'#' | b'=' => true,
            // `islock` is 0 for a key, so an expression operator is not a
            // legal character in one.
            b'&' | b'|' => false,
            _ => crate::strings::is_text_var_char(c),
        });

    Ok(abi::Ret::Int(A::Int::from(u16::from(valid))))
}

/// `GBOOL istxvc(INT c)` -- `SRC/api/gcommlib/ISTXVC.C:19-30`, quoted in full
/// on [`crate::strings::is_text_var_char`].
///
/// **Fully implemented**, and one no corpus module imports -- [`keynam`]
/// calls it, `GCOMM.H:339` declares it and every oracle build exports it, so
/// it is implemented on the same terms as `isuplo` and `cnclon`.
///
/// `GBOOL` is a `short` (`GCTYPDEF.H:105`), not an `INT`; see
/// `crate::shims::cnc::isuidc` for why answering as [`abi::Ret::Int`] is
/// still right.
///
/// # Errors
///
/// Never. The signature is fallible because every shim's is.
pub fn istxvc<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let c: u32 = call.int().into();
    let valid = u32::from(u8::try_from(c).is_ok_and(crate::strings::is_text_var_char));
    Ok(abi::Ret::Int(A::int_from_u32(valid)))
}

/// `INT usridx(INT chan)` -- `MAJORBBS.H:752`. `MAJORBBS.C:1587-1598`:
///
///
/// **Fully implemented.** The inverse of the `channel` table: `channel[unum]`
/// is the hardware channel number a user number sits on, and this searches it
/// backwards. `channel` is a real array here -- `crate::Host::new` writes
/// `Users::channels()` into the placed pointer -- so the walk has something to
/// walk.
///
/// **`-1` is a real answer, not a failure.** A channel number no user occupies
/// has no user number, and the vendor says so by returning `-1` rather than by
/// stopping. That is why this does not refuse on a miss: refusing would turn
/// the routine's ordinary "nobody" into a stopped module.
///
/// The search is linear and stops at the first match, exactly as the vendor's
/// does, so a `channel` table with a repeated entry answers the lowest user
/// number -- which is what the original answered too.
///
/// # Errors
///
/// If `channel` is not placed, or reading `nterms` entries from it runs off
/// the segment.
pub fn usridx<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let want = Into::<u32>::into(call.int()) as i16;

    let base = host
        .globals()
        .pointer_mem(call.mem(), "channel")
        .map_err(|e| ShimError::Failed(format!("usridx: channel: {e}")))?;
    let terms = host.users().terms().count();

    for idx in 0..terms {
        let at = A::ptr_offset(base, idx.checked_mul(A::INT_WIDTH as u16).expect("in range"));
        let bytes = at
            .resolve(call.mem(), A::INT_WIDTH)
            .map_err(|e| ShimError::Failed(format!("usridx: channel[{idx}]: {e}")))?;
        let value = Into::<u32>::into(A::int_from_bytes(bytes)) as i16;
        if value == want {
            return Ok(abi::Ret::Int(A::Int::from(idx)));
        }
    }

    // `-1` at this ABI's own int width, the same all-ones spelling
    // `crate::globals` uses for `usrnum` and for the same reason: `A::Int`
    // is built from a `u16` by zero extension, so `From<u16>` could only
    // ever produce 65535 under `Wg32`.
    Ok(abi::Ret::Int(A::int_from_u32(u32::MAX)))
}

/// `VOID rstchn(VOID)` -- `MAJORBBS.H:829`. `MAJORBBS.C:4136` onward.
///
/// **Refuses.** "Completely reset a modem channel", and every line of it is
/// hardware or a subsystem this host does not have: `btucmd(usrnum,"T")` to
/// drop the line, `shochl`/`baudat` to log the speed, `btuinj(usrnum,CYCLE)`,
/// the `lcstat`/`LSSESTB`/`LSSTERM` SPX link states, and then the
/// `(*hdlrst)()` handler chain whose default (`dftrst`, `:4165`) calls
/// `gcsprst`, `freekey`, zeroes `struct user`, `struct usrmnu` and
/// `struct usracc`, and finishes with `bturst(usrnum)`.
///
/// This host does have a disconnect path, and reaching for it here would be
/// the tempting wrong answer: `rstchn` is not "disconnect this user", it is
/// "put the hardware back the way it was found", and the two differ on
/// everything a caller would then rely on -- the menu record, the account
/// record, the key set and the line state.
///
/// It returns `VOID`, so nothing is owed at call time; what makes the refusal
/// right anyway is what the caller does next. Every real call site resets a
/// channel *in order to hand it to somebody else*, and a quiet return would
/// hand over a channel still holding the previous user's keys and account.
///
/// # Errors
///
/// Always, naming the reset chain it cannot run.
pub fn rstchn<A: Abi>(_call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    Err(ShimError::Failed(
        "rstchn: this host cannot reset a channel -- there is no modem to send \
         btucmd(\"T\") to, no SPX link state to move to LSSTERM, and no (*hdlrst)() \
         chain whose default zeroes the user, menu and account records and calls \
         bturst(); see this routine's own doc comment for why disconnecting \
         instead would be the wrong answer"
            .to_string(),
    ))
}

/// `VOID clrxrf(VOID)` -- `MAJORBBS.H:793`. `MAJORBBS.C:3437-3443`:
///
///
/// **Does nothing, and that is the vendor's own `numxrf == 0` branch rather
/// than a stub.**
///
/// `numxrf` is the number of alternate user-IDs a board lets one account
/// carry, read at `MAJORBBS.C:992` as `numopt(NUMXRF,0,MAXXRF)` -- **minimum
/// zero** -- and the very next line only allocates `xrfpos` at all when it
/// came back non-zero:
///
///
/// So a board that did not configure the cross-reference had `numxrf == 0`
/// and `xrfpos == NULL`, and this routine did nothing there either. This host
/// has no message-file parser to answer `numopt`, so it is in exactly that
/// state, and the empty answer is the complete one.
///
/// Neither `numxrf` nor `xrfpos` is placed as a host global, and neither
/// should be: `MAJORBBS.C:84` declares them in the server's own translation
/// unit and `MAJORBBS.H` does not export them, so no module can address
/// either. The macro that indexes them, `xrfidx(n)` = `usrnum*numxrf+n`
/// (`MAJORBBS.C:91`), is file-scope too.
///
/// # Errors
///
/// Never. The signature is fallible because every shim's is.
pub fn clrxrf<A: Abi>(_call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    Ok(abi::Ret::Void)
}

/// `INT hdluid(CHAR *stg)` -- `MAJORBBS.H:796`. `MAJORBBS.C:3490` onward,
/// K&R style (`hdluid(stg) CHAR *stg;`).
///
/// **Refuses.** The body is the user-ID cross-reference lookup end to end: it
/// opens `xrfbb`, tests `xrfpos[xrfidx(0)]`, pulls a record with
/// `dfaGetAbs(&uidxrf,...)`, and answers `UIDFND`/`UIDPMT` according to what
/// it found.
///
/// Unlike [`clrxrf`], there is no `numxrf == 0` branch to fall into: this
/// routine dereferences `xrfpos` unconditionally on its first line, so a
/// board that never configured the cross-reference would have faulted here on
/// a NULL. The routine presupposes the subsystem, and this host does not have
/// it -- no `xrfbb` Btrieve file, no `xrfpos` table, no `numopt` to size one
/// with.
///
/// `uidxrf` *is* placed (the 46-byte `struct` by value, `crate::globals`), so
/// the destination of the read exists; what does not exist is anything to
/// read into it. Answering `UIDPMT` -- "ask the user which ID they meant" --
/// would be the plausible answer here, and it is wrong in the way that
/// matters: the caller would prompt against a cross-reference list this host
/// never built and then act on whichever entry the user picked out of
/// nothing.
///
/// # Errors
///
/// Always, naming the cross-reference file that would have to exist.
pub fn hdluid<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let stg = call.ptr();
    let stg = stg
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let stg = String::from_utf8_lossy(&stg).into_owned();

    Err(ShimError::Failed(format!(
        "hdluid({stg:?}): this host keeps no user-ID cross-reference to \
         resolve it against -- there is no `xrfbb` Btrieve file and no \
         `xrfpos` table, because `numxrf` comes from a numopt() this host has \
         no message-file parser to answer; see this routine's own doc comment"
    )))
}

/// `INT nliniu(VOID)` -- how many of this host's channels are in use?
/// `ACCOUNT.C:1086-1097`:
///
///
/// **Fully implemented**, and it answers `0` today for every channel,
/// including connected ones.
///
/// That is not a stub. `VACANT` is `0` (`MAJORBBS.H:221`), and this host
/// never advances `usrcls` past `0` -- `Host::connect_state` writes it as
/// zero and nothing here raises it, which is the same gap
/// [`onsysn`] already carries and pins with a test of its own. A channel this
/// host considers connected is one the *vendor's* own predicate calls vacant,
/// so counting it would be inventing a signup flow that has not been built.
///
/// The loop is real rather than folded to a constant, so the day `usrcls`
/// starts moving this routine starts counting without being revisited, and
/// [`nliniu_counts_channels_whose_usrcls_left_vacant`](self::tests) fails
/// that day rather than passing quietly.
///
/// # Errors
///
/// If a channel's `usrcls` cannot be read.
pub fn nliniu<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    const VACANT: u16 = 0;

    let mut in_use = 0u16;
    for chan in host.users().terms().all() {
        if host.users().usrcls_mem(call.mem(), chan)? != VACANT {
            in_use += 1;
        }
    }
    Ok(abi::Ret::Int(A::Int::from(in_use)))
}

/// `INT othkey(const CHAR *lock)` -- does the channel `othusn` last pointed at
/// hold this key?
///
/// `LOCKNKEY.C:332`, one line:
///
///
/// [`haskey`]'s own doc comment already explains `gen_haskey`/`low_haskey` --
/// [`crate::KeySet::evaluate`] now -- and the `usrcls == BBSPRV` fallback for
/// a channel that never logged on. This is the same body, aimed at `othusn`
/// instead of `usrnum`.
///
/// # `othusn` before anything has set it
///
/// Unlike `usrnum` -- which [`crate::Globals::new`] seeds to all-ones so that
/// "nobody" is a real, checked state -- `othusn` has no such convention. It is
/// a plain global with no initialiser, so it starts at 0, exactly what a
/// genuine `INT othusn;` in Borland's BSS reads before anything ever assigns
/// it. `othkey` called before any [`instat`]/[`onsysn`] has run therefore
/// answers for channel 0, not an error -- the same answer the real
/// (uninitialised) global would have pointed at.
///
/// # Errors
///
/// If `lock` cannot be read, or `othusn` does not name a channel of this
/// host. The second is not reachable through anything this crate implements
/// -- [`instat`]/[`onsysn`] only ever write a channel [`crate::Terms::all`]
/// produced, and the zero it starts at is always channel 0 of a host with at
/// least one channel -- so it is reachable only by a test poking the global
/// directly.
pub fn othkey<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let lock = call.ptr();
    othkey_for(call, host, lock)
}

/// The null pointer, in this ABI's own representation.
///
/// Duplicated per shim file rather than shared -- `shims::stream` and
/// `shims::text` each already carry their own private copy of exactly this
/// one-liner; see [`begin_polling`]'s own doc comment for why [`Abi`] has no
/// `NULL` constant of its own to reach for instead.
fn null_ptr<A: Abi>() -> A::Ptr {
    A::ptr_from_bytes(&vec![0u8; A::PTR_WIDTH])
}

/// `CHAR *mdfgets(CHAR *buf, INT size, FILE *fp)` -- the server's own
/// `fgets()`, which speaks this host's internal line convention instead of
/// C's.
///
/// `GCOMM.H:360` / `re/wg33src/SRC/api/gcommlib/MDFGETS.C`:
///
///
/// Three ways this differs from plain `fgets`
/// ([`crate::shims::stream::fgets`]), all in the C source above and all
/// deliberate: `\r` is read and thrown away rather than stored (`i--` cancels
/// the loop's own `i++`, so the byte never lands in `buf` at all); `\n` is
/// *replaced* with `\r` as the line's terminator rather than kept -- this
/// host's own internal line convention is `\r`, the same one
/// `prfmsg`/the message parser use, not C's `\n`; and a trailing Ctrl-Z (26,
/// DOS soft end-of-file) already stored at end-of-file is trimmed back off.
///
/// # Built on the same byte source `fgets` reads, on purpose
///
/// [`crate::stream::Streams::read_mem`] reads through [`crate::stream`]'s own
/// `getc`, which *already* squeezes `\r` and treats Ctrl-Z as end-of-file --
/// but only for a stream opened in text mode; `fgets`'s own doc comment notes
/// the same fact. That is not a conflict with the switch above, it is the
/// same translation from two different places: on a text-mode stream, `getc`
/// has already done it and the `\r`/Ctrl-Z arms below simply never have
/// anything left to catch; on a binary-mode stream, `getc` hands back the raw
/// bytes and those arms do exactly what `MDFGETS.C` wrote. Building this on
/// the primitive `fgets` already uses, rather than a second raw reader, means
/// it is correct under either mode without needing to know which one a given
/// `fp` was opened with.
///
/// # Errors
///
/// If `fp` names no open, readable stream, if `size` leaves no room even for
/// a terminator (the same refusal [`fgets`](crate::shims::stream::fgets)
/// makes, for the same reason -- `MDFGETS.C` itself does not guard this, and
/// writing into a buffer the caller says has no room is exactly the silent
/// wrongness this crate refuses to reproduce), or if a read fails.
pub fn mdfgets<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let buf = call.ptr();
    let size = super::sign_extend::<A>(call.int().into());
    let fp = call.ptr();

    if size < 1 {
        return Err(ShimError::Failed(format!(
            "mdfgets with size of {size}, which leaves no room even for the terminator"
        )));
    }
    let cap = (size - 1) as usize;

    let mut out: Vec<u8> = Vec::new();
    loop {
        if out.len() >= cap {
            // Ran out of room without a `\n` or EOF: `buf[i]='\0'` at the
            // loop's own `i`, the tail below this loop in `MDFGETS.C`.
            out.push(0);
            buf.write(call.mem(), &out)
                .map_err(|e| ShimError::Failed(e.to_string()))?;
            return Ok(abi::Ret::Ptr(buf));
        }
        let byte = host
            .streams
            .read_mem(call.mem(), fp, 1)
            .map_err(|e| ShimError::Failed(format!("mdfgets: {e}")))?;
        match byte.first().copied() {
            Some(b'\r') => continue,
            Some(b'\n') => {
                out.push(b'\r');
                out.push(0);
                buf.write(call.mem(), &out)
                    .map_err(|e| ShimError::Failed(e.to_string()))?;
                return Ok(abi::Ret::Ptr(buf));
            }
            Some(c) => out.push(c),
            None => {
                if out.is_empty() {
                    return Ok(abi::Ret::Ptr(null_ptr::<A>()));
                }
                // `buf[i-1] == 26` -- a Ctrl-Z the read loop already stored,
                // trimmed back off rather than kept as part of the line.
                if out.last() == Some(&26) {
                    out.pop();
                }
                out.push(0);
                buf.write(call.mem(), &out)
                    .map_err(|e| ShimError::Failed(e.to_string()))?;
                return Ok(abi::Ret::Ptr(buf));
            }
        }
    }
}

// `BRKTHU.H:31-49` -- `btusts()` hardware status codes [`dfsthn`] exempts
// from its default action. This host has no channel-group hardware and never
// produces any of these; named here so the switch below is checked against
// the real values rather than a guess.
const CMDOK: i16 = 2;
const INBLK: i16 = 4;
const OUTMT: i16 = 5;
const OBFCLR: i16 = 6;
const ABOREQ: i16 = 7;
const CMN2OK: i16 = 12;
const CM25OK: i16 = 22;
const RCVX29: i16 = 24;
const IPXRER: i16 = 37;
const IPXUNK: i16 = 38;
/// `MAJORBBS.H:297` -- the one member of [`dfsthn`]'s exempted set this
/// host's own [`crate::Host::poll`] really does raise.
const CYCLE: i16 = 240;

/// `VOID dfsthn(VOID)` -- the default `stsrou` a module gets if it registers
/// none of its own.
///
/// `MAJORBBS.C:5202`:
///
///
/// # The `default:` branch cannot fire on this host, and that is checked here rather than assumed
///
/// `module00` is the built-in "Menuing System" module -- `MAJORBBS.C:39` puts
/// `loscar` in its `huprou` slot -- and this host has no menuing system: no
/// `mnuusr`/`muusrs` table, the same deliberate absence `curusr`'s own doc
/// comment already names. More directly, `Host::poll` (`lib.rs:2635-2652`)
/// writes the `status` global to exactly three values before a `stsrou` is
/// ever entered -- `gsbl::Gsbl::INBLK`, `::OUTMT` and `::CYCLE` -- and all
/// three are members of the `break;` set above. So whenever this host
/// actually calls a module's `stsrou`, `status` already is one of the
/// recognised codes, which makes `dfsthn`'s `default:` dead code under this
/// host's own dispatch, not merely an unlikely one. The eight `btusts()`
/// hardware codes this switch also exempts never arise at all -- this host
/// has no channel-group hardware to raise them, the same gap
/// [`crate::Host::rstchn`]'s own doc comment names for `rcdbaud`/`lincst`/
/// `bturst`.
///
/// Given that, this reproduces the `break;` half faithfully -- every status
/// this host can actually hand a module falls through as the real no-op, at
/// the real vendor constants (`BRKTHU.H:31-49`, `MAJORBBS.H:297`), not
/// invented ones -- and refuses outright on the one branch nothing in this
/// host can source, rather than inventing a body for it: there is no
/// `module00`, no `huprou` slot on it, and no `&A::Module` at a shim call
/// site to reach even a *loaded* module's `huprou` if there were one. A
/// silent no-op there would be exactly the quiet-wrongness this crate
/// refuses to ship; an error on a branch measured above to be unreachable
/// costs nothing.
///
/// # Errors
///
/// If `status` cannot be read, or (unreachably, per above) `status` is not
/// one of the recognised codes.
pub fn dfsthn<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let status = host
        .globals()
        .word_mem(call.mem(), "status")
        .map_err(|e| ShimError::Failed(format!("dfsthn: status: {e}")))? as i16;

    const RECOGNISED: &[i16] = &[
        CMDOK, INBLK, OUTMT, OBFCLR, ABOREQ, CMN2OK, CM25OK, RCVX29, IPXRER, IPXUNK, CYCLE, 251, 252, 253,
    ];
    if RECOGNISED.contains(&status) {
        return Ok(abi::Ret::Void);
    }
    Err(ShimError::Failed(format!(
        "dfsthn: status {status} is not one of the codes this host ever hands a module's \
         stsrou -- the real default branch (module00.huprou, a menuing system this host \
         does not have) has no honest answer here"
    )))
}

/// `void begin_polling(int unum, void (*rouptr)())` -- start calling `rouptr`
/// for channel `unum` every time the host comes round. `MAJORBBS.C:1183`:
///
///
/// The `inpolr` half of that guard is the one worth understanding.
/// [`Host::dopoll`] re-injects `POLSTS` when a polling routine returns still
/// polling, so a `begin_polling` issued from *inside* a polling routine would,
/// without it, queue a second status for the same tick -- and then two, and
/// then four. The queue is deliberately unbounded (`gsbl::Channel::status`), so
/// the failure mode is the machine, not a wrong answer.
///
/// # Errors
///
/// If `unum` names no channel, or `rouptr` is NULL. The original stored a NULL
/// -- making the call a `stop_polling` with one wasted status -- but all nine
/// of `WCCMMUD.DLL`'s call sites pass a real routine and the only computed one
/// (`WCCMMUD_named.c:11831`) carries a fixed non-zero selector, so a NULL here
/// is a module bug this host can name.
///
/// Generic (Task 5): the NULL check used to compare against `FarPtr::NULL`;
/// there is no such constant on [`Abi`] (a pointer's own bit pattern is not
/// part of the trait, only how to resolve/offset/en-\/decode one), so it
/// tests the pointer's own bytes instead, the same way
/// [`Users::polrou_mem`](crate::users::Users::polrou_mem) already does.
pub fn begin_polling<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let unum = Into::<u32>::into(call.int()) as i16;
    let rouptr = call.ptr();
    if A::ptr_to_bytes(rouptr).iter().all(|b| *b == 0) {
        return Err(ShimError::Failed(format!(
            "begin_polling({unum}): a null polling routine"
        )));
    }
    // One `Chan`, minted once, and then used to reach both `Users` and `Gsbl`.
    // That is the whole of the fix: these two lines used to resolve the channel
    // through `Users`' bound and then inject into `Gsbl`'s, which named the same
    // channel only for as long as the two tables were the same length -- and
    // `inject`'s `false` for "no such channel" was discarded right here.
    let chan = host
        .users()
        .terms()
        .chan(unum)
        .ok_or_else(|| ShimError::Failed(format!("begin_polling({unum}): there is no such channel")))?;
    if host.users().polrou_mem(call.mem(), chan)?.is_none() && host.inpolr != Some(chan) {
        host.gsbl_mut().inject(chan, Gsbl::POLSTS);
    }
    host.users
        .set_polrou_mem(call.mem(), chan, Some(rouptr))
        .map(|()| abi::Ret::Void)
}

/// `void stop_polling(int unum)` -- `user[unum].polrou=NULL`.
/// `MAJORBBS.C:1194`, which is that one line.
///
/// No status is withdrawn. A `POLSTS` already queued arrives with nothing to
/// call, and [`Host::dopoll`] does nothing with it -- which is the original's
/// entire handling of that case.
///
/// # Errors
///
/// If `unum` names no channel.
pub fn stop_polling<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let unum = Into::<u32>::into(call.int()) as i16;
    let chan = host
        .users()
        .terms()
        .chan(unum)
        .ok_or_else(|| ShimError::Failed(format!("stop_polling({unum}): there is no such channel")))?;
    host.users
        .set_polrou_mem(call.mem(), chan, None)
        .map(|()| abi::Ret::Void)
}

/// `struct user *usroff(int unum)` -- `&user[unum]`.
///
/// `MAJORBBS.H:345` declares the array; this is what turns a channel number
/// into a pointer at it. [`Users::slot`](crate::users::Users::slot) already
/// computes exactly that, at `A`'s own [`UserLayout`](crate::users::UserLayout)
/// stride -- this shim is a channel lookup and a [`abi::Ret::Ptr`] over it,
/// the same shape [`uacoff`] already gives the account table.
///
/// The oracle's own `usroff` is a stub that tail-calls a shared accessor
/// computing `*descriptor + WORD[*descriptor] * index + 8` -- the `+8` is a
/// block header, an allocator detail of that host's own heap. This host's
/// `Users` has no equivalent to reproduce, so it is not: no header is added
/// to what `Users::slot` returns.
///
/// **Guard the range.** `usroff(nterms)` in the real host walked off the
/// table -- the block-header arithmetic just kept going and handed back
/// whatever bytes followed the last real record. Runtime crashes beat
/// undefined behaviour, so an out-of-range `unum` stops the module here
/// instead of returning a pointer past the end.
///
/// This is also the routine that makes a wrong
/// [`UserLayout`](crate::users::UserLayout) stride *visible*: at one channel
/// every stride places channel 0 at offset 0, and only a second channel's
/// slot depends on the number being right. See
/// `crates/mbbs/tests/lunatix.rs`'s two-channel test for where that is
/// actually exercised under `Wg32`.
///
/// # Errors
///
/// If `unum` names no channel.
/// `struct usrmnu *mnuoff(INT unum)` -- `MENUING.C:867-873` -- a pointer to
/// one user's menuing state.
///
///
/// **Refused, because `muusrs` does not exist here and cannot be invented.**
/// It is `static VOID *muusrs` (`MENUING.C:32`), the menuing subsystem's own
/// per-user block array, allocated by a subsystem this host does not run.
/// This is the same deliberate absence [`crate::Host::setusr`]'s doc comment
/// already names for `mnuusr` and [`dfsthn`]'s for `module00`: no menuing
/// system, so no menuing state.
///
/// Answering null instead would be the plausible lie. `ptrblok` on a null
/// `bigptr` does answer null, so a host that wanted to look faithful could
/// return it -- but that would say "this user has no menu block", which is a
/// statement about a table that was never built, and `MENUING.C`'s callers
/// dereference the result without testing it. Stopping the module names the
/// missing subsystem at the call that needed it.
///
/// The struct itself is `MAJORBBS.H:158-167` -- current and parent page,
/// the select characters, the per-selection pages and key requirements, an
/// open `FILE *`, and the page title. Placing it is not the hard part; the
/// subsystem that fills it in is.
///
/// # Errors
///
/// Always.
pub fn mnuoff<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let unum = Into::<u32>::into(call.int()) as u16;
    Err(ShimError::Failed(format!(
        "mnuoff({unum}): the menuing subsystem's muusrs block array \
         (MENUING.C:32) is not built by this host, so there is no struct \
         usrmnu to point at -- the same absence that leaves mnuusr unset"
    )))
}

pub fn usroff<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let unum = Into::<u32>::into(call.int()) as i16;
    let chan = host
        .users()
        .terms()
        .chan(unum)
        .ok_or_else(|| ShimError::Failed(format!("usroff({unum}): there is no such channel")))?;
    Ok(abi::Ret::Ptr(host.users().slot(chan)))
}

/// `void clrmlt(void)` -- clear the multi-line broadcast buffer.
/// `GCOMM.H:473`.
///
/// # Why this is a no-op, and why that is the honest answer rather than a stub
///
/// `clrmlt` is one member of a four-routine family this host does not
/// otherwise implement: `prfmlt` (`GCOMM.H:476`, formats a message into the
/// broadcast buffer), `pmlt` (`:477`, the same with a control string) and
/// `outmlt` (`:475`, flushes that buffer to one channel) are the other
/// three, and `LUNATIX.DLL` imports none of them --
/// `docs/2026-08-12-module-import-gaps.md` counts `_CLRMLT` at 23 call sites
/// in LunatiX and the other three at zero. So nothing in this host's own
/// reach ever writes into the buffer `clrmlt` would clear: there is no
/// `prfmlt`/`pmlt` here for it to be cleaning up after, which is exactly the
/// state a fresh, always-empty buffer is in. Clearing nothing is what
/// clearing an empty buffer looks like.
///
/// **Not per-channel.** The real prototype takes no channel argument -- the
/// broadcast buffer is one buffer, not one per channel, the same way
/// `prfbuf` is one buffer shared by whichever channel is current. A no-op
/// is trivially correct regardless of which channel called it, which is
/// what this shim's own test calls it under channel 1 to show.
///
/// If a future module imports `prfmlt`/`pmlt`/`outmlt`, this stops being
/// faithful the moment the buffer they fill has real content in it, and
/// this comment is where that gap is written down rather than discovered
/// as a printed-nothing bug.
pub fn clrmlt<A: Abi>(_call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    Ok(abi::Ret::Void)
}

/// `BBSPRV`, `MAJORBBS.H:163` -- online, private class, internal to the host.
const BBSPRV: u16 = 2;

/// `VOID echonu(INT usrnum)` -- turn echo on for `usrnum`, and end any
/// secret-character-echo session `echsec` started.
///
/// `MAJORBBS.C:4548`:
///
///
/// (`echon()`, `MAJORBBS.C:4544`, is `echonu(usrnum)` against the current
/// channel; it is not itself imported, only `echonu` and `echsec` are.)
///
/// # `echtyp[grpnum[usrnum]]` is always `1` here, and that is a fact about
/// the vendor source, not a gap this host is filling in
///
/// `grpnum`/`echtyp` are per-channel-group hardware settings
/// (`MAJORBBS.C:192`/`:202`) this host never places as globals -- neither
/// symbol appears in `docs/2026-08-12-module-import-gaps.md`, so nothing
/// this host runs can ask for either by name. But this particular
/// expression does not depend on that gap: the local console's group is
/// hardcoded to 0 (`grpnum[usrnum]=0`, `MAJORBBS.C:1217`, reached with no
/// hardware channel groups configured -- exactly `crate::users::Users::new`'s
/// own shape) and `echtyp[0]=1` unconditionally, one line above it
/// (`MAJORBBS.C:1211`), before the value could depend on anything a real
/// operator configured. `1` means "echo on" -- `btuech`'s `onoff` argument --
/// so this always turns echo on, which is also the only thing the routine's
/// own name ("turn echo on utility") ever promised.
///
/// # `wid` is `struct extusr`'s, not `struct user`'s, for this ABI
///
/// GCV2 moves `wid` out of `struct user` into `struct extusr`
/// (`MAJORBBS.H:139` vs `:98`'s `#ifndef GCV2` branch), and `Wg16` is a
/// GCV2 build -- independently confirmed by its own measured 41-byte
/// `UserLayout::of::<Wg16>` stride (`crates/mbbs/src/users.rs`'s own doc
/// comment), since a non-GCV2 `struct user` would stride by 88 instead. So
/// this reads and writes [`crate::users::Users::wid_mem`]/`set_wid_mem`,
/// which resolve to `extusr[usrnum].wid` under `Wg16` and (faithfully, for
/// the day a non-GCV2 module runs here) `user[usrnum].wid` under `Wg32` --
/// see those constants' own doc comments for the two derivations. Reading
/// `usrptr->wid` as if it were still in `struct user` under `Wg16` would
/// read three bytes into `crdrat`/`polrou` instead -- the "user, usracc,
/// module, FILE" class of bug this session has already paid for four times.
///
/// # `btuchi(usrnum,NULL)` has no shim of its own to call
///
/// Nothing in this host implements `btuchi` as a callable routine at all --
/// `crate::shims::fsd::fsdcon`'s own doc comment already establishes why:
/// the whole `btuchi` family collapses to [`crate::gsbl::Channel::raw`], a
/// single shared "is this channel in character-at-a-time mode" flag, the
/// same one [`crate::shims::fsd`]'s `fsdcon`/`fsdcof` toggle directly rather
/// than through a `btuchi` shim. `btuchi(usrnum,NULL)` uninstalls whatever
/// handler currently occupies that one slot, and this host has exactly one
/// slot to clear: `ch.raw = false`, the same translation `fsdcof` already
/// makes on its own way out of an FSD session.
///
/// **What is lost**: on the real host, installing `NULL` also means no
/// handler runs on the *next* keystroke; the handler itself (`secchi`,
/// `MAJORBBS.C:4570`, the per-character `'*'`-masking routine [`echsec`]
/// installs) has no shim here -- see [`echsec`]'s own doc comment for what
/// that costs. `echsec` **is** implemented (it is what installs `wid > 0` in
/// the first place, via `raw = true`), so the branch below is live the
/// moment a channel that called `echsec` calls `echon`/`echonu` to end the
/// session -- not merely "implemented anyway, in case a module pokes `wid`
/// directly" the way it was before `echsec` landed.
///
/// # `raw` is a shared slot, and this reproduces that conflation rather than fixing it
///
/// If some *other* consumer of `Channel::raw` (FSD, or an `echsec` session
/// that has not yet ended) is holding it when `echonu` fires with `wid > 0`,
/// this clears it out from under that consumer -- exactly what the real
/// host's single `btuchi` slot would also have done, since `secchi` and
/// `fsdchi` compete for the same one handler there too. Not a fidelity gap
/// this port introduced.
///
/// # Errors
///
/// If `usrnum` names no channel, or the `wid` read/write fails.
pub fn echonu<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let usrnum = Into::<u32>::into(call.int()) as i16;
    let chan = host
        .users()
        .terms()
        .chan(usrnum)
        .ok_or_else(|| ShimError::Failed(format!("echonu({usrnum}): there is no such channel")))?;
    turn_echo_on(call, host, chan)
}

/// The body `echonu`'s own doc comment already walks through in full --
/// `btuech(usrnum, echtyp[grpnum[usrnum]])` then, if a secret-echo session
/// (`echsec`) left `wid > 0`, `btuchi(usrnum,NULL)` and `wid=0` -- pulled out
/// so [`echon`] can reach it too. Both routines resolve `usrnum` to a
/// [`crate::Chan`] their own way -- `echonu` reads it as an argument,
/// `echon` reads the global -- and hand the same channel in here.
fn turn_echo_on<A: Abi>(call: &mut Call<A>, host: &mut Host<A>, chan: crate::Chan) -> Result<abi::Ret<A>, ShimError> {
    // `btuech(usrnum, echtyp[grpnum[usrnum]])` -- always turns echo ON on
    // this host. See [`echonu`]'s own doc comment for why `1` is a fact
    // about the vendor source rather than a stand-in for missing
    // configuration.
    host.gsbl_mut().channel_mut(chan).echo = true;

    if host.users().wid_mem(call.mem(), chan)? > 0 {
        // `btuchi(usrnum,NULL)` -- see [`echonu`]'s own doc comment for why
        // that collapses to `raw = false` here.
        host.gsbl_mut().channel_mut(chan).raw = false;
        host.users_mut().set_wid_mem(call.mem(), chan, 0)?;
    }

    Ok(abi::Ret::Void)
}

/// `VOID echon(VOID)` -- turn echo on for whichever channel is current.
///
/// `MAJORBBS.C:4541`:
///
///
/// One line in the original, and this shim is not much more: [`echonu`]'s
/// own doc comment already covers everything the body does (why `echtyp[
/// grpnum[usrnum]]` is always `1` here, where `wid` lives for a GCV2 ABI,
/// and what `btuchi(usrnum,NULL)` collapses to) -- [`turn_echo_on`] is that
/// body, shared rather than copied. This shim's only job is the half
/// `echonu` did not have to do for itself: `echon` takes no argument, so the
/// channel comes from the `usrnum` global instead, read the same way
/// [`getin`]/[`haskey`] already do.
///
/// # Errors
///
/// If `usrnum` cannot be read, if it names no channel, or if the `wid`
/// read/write fails.
pub fn echon<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let usrnum = host
        .globals()
        .word_mem(call.mem(), "usrnum")
        .map_err(|e| ShimError::Failed(format!("echon: usrnum: {e}")))? as i16;
    let chan = host
        .users()
        .terms()
        .chan(usrnum)
        .ok_or_else(|| ShimError::Failed(format!("echon: usrnum {usrnum} names no channel")))?;
    turn_echo_on(call, host, chan)
}

/// `VOID echsec(CHAR ech, INT lwidth)` -- start a secret-character-echo
/// session on the current channel: echo `ech` in place of whatever the user
/// actually types, up to `lwidth` characters, the mechanism a password
/// prompt is built on.
///
/// `MAJORBBS.C:4558`:
///
///
/// Like [`echon`], this takes no channel argument -- `usrnum` names it, read
/// the same way [`getin`]/[`haskey`]/`echon` already do.
///
/// # `ech` is a byte, read as one regardless of how it was widened
///
/// `CHAR` is promoted to `int` in the calling convention (`INC/MAJORBBS.H:846`'s
/// prototype), and Borland's plain `char` is signed, so a real masking
/// character with the high bit set arrives sign-extended rather than
/// zero-extended. That does not matter here: sign- and zero-extension both
/// leave the low 8 bits exactly as the caller wrote them, so a plain
/// truncating cast recovers the original byte either way. This is
/// deliberately **not** `shims::gsbl`'s `u8_arg` -- that reader *refuses* a
/// value that does not fit a `u8`, which is right for an argument that is
/// genuinely bounded (a pause character, a flow-control byte) but wrong
/// here: a sign-extended `0xFF` char widens to `0xFFFFFFFF` under `Wg32`,
/// which does not fit a `u8` at all even though it names a perfectly good
/// masking character once truncated. `lwidth`, by contrast, is read through
/// [`super::sign_extend`] -- the same helper [`mdfgets`] uses for its `size`
/// -- because `lwidth` is a genuine signed quantity the `max(1,min(255,_))`
/// clamp below has to see the true sign of (a negative `lwidth` must clamp
/// to `1`, not wrap into a huge unsigned width).
///
/// # `col`/`ech` are written faithfully; nothing on this host reads them back
///
/// See [`Users::col_mem`](crate::users::Users::col_mem)'s own doc comment:
/// `secchi` (`MAJORBBS.C:4570`), the per-character interrupt handler that
/// would consult `col`/`wid`/`ech` on every keystroke, has no shim here --
/// [`echonu`]'s own doc comment already established that `btuchi` collapses
/// to the single shared [`crate::gsbl::Channel::raw`] flag, and that nothing
/// this host runs implements a real per-character handler at all. This shim
/// still writes all three fields at their true vendor offsets, because a
/// module (or a future `secchi` shim) reading `usrptr` directly must see
/// what the real host would have left there -- but no output this host
/// produces today is shaped by any of the three.
///
/// # What `raw = true` gets right, and what it does not
///
/// `btuchi(usrnum,secchi)` is rendered as `ch.raw = true` -- the same
/// direction [`crate::shims::fsd::fsdcon`] already turns it, and the exact
/// mirror of `echonu`'s own `ch.raw = false` for `btuchi(usrnum,NULL)`.
/// [`crate::gsbl::Gsbl::take`]'s own doc comment is what that flag actually
/// buys: every keystroke bypasses the ordinary line editor/echo pipeline
/// entirely and lands in the channel's raw input queue untouched, waking the
/// module with `CYCLE` instead of `CRSTG` -- which is a faithful rendering
/// of "control has left line mode for a character-at-a-time handler", the
/// half `secchi`'s *installation* is responsible for.
///
/// What is lost is everything `secchi` itself would have done on each of
/// those keystrokes: no `ech` character is echoed back in its place (this
/// host echoes nothing at all while `raw` is set, per `Gsbl::take`), no
/// backspace visually erases a masked character, and no `col`/`wid` gate
/// silently drops input past the configured width. On the real host, a user
/// typing a password under `echsec` sees a row of `ech` characters growing
/// and shrinking as they type; on this host today they see nothing echoed
/// at all, and the raw bytes queue up for whatever reads `chi`-style input
/// directly rather than being pre-filtered by `secchi`'s `return(c)`
/// gate. That is a real, user-visible gap -- not a naming difference -- and
/// it stays open until a `secchi` shim exists to read the fields this
/// routine faithfully writes.
///
/// # `raw` is a shared slot, same as `echonu`
///
/// If FSD is holding [`crate::gsbl::Channel::raw`] for its own reasons when
/// `echsec` fires, this claims it -- exactly what the real host's one
/// `btuchi` slot would also have done, and not a fidelity gap this port
/// introduced; see [`echonu`]'s own doc comment for the fuller discussion.
///
/// # Errors
///
/// If `usrnum` cannot be read, if it names no channel, or if any of the
/// `col`/`wid`/`ech` writes fail.
pub fn echsec<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let ech = Into::<u32>::into(call.int()) as u8;
    let lwidth = super::sign_extend::<A>(call.int().into());

    let usrnum = host
        .globals()
        .word_mem(call.mem(), "usrnum")
        .map_err(|e| ShimError::Failed(format!("echsec: usrnum: {e}")))? as i16;
    let chan = host
        .users()
        .terms()
        .chan(usrnum)
        .ok_or_else(|| ShimError::Failed(format!("echsec: usrnum {usrnum} names no channel")))?;

    // `btuech(usrnum,0)` -- echo OFF, the opposite of `echonu`'s always-on.
    host.gsbl_mut().channel_mut(chan).echo = false;
    // `usrptr->col=0`
    host.users_mut().set_col_mem(call.mem(), chan, 0)?;
    // `usrptr->wid=(CHAR)(max(1,min(255,lwidth)))`
    let wid = lwidth.clamp(1, 255) as u8;
    host.users_mut().set_wid_mem(call.mem(), chan, wid)?;
    // `usrptr->ech=ech`
    host.users_mut().set_ech_mem(call.mem(), chan, ech)?;
    // `btuchi(usrnum,secchi)` -- see this function's own doc comment for what
    // installing the real handler is lost, and why `raw = true` is the
    // faithful collapse anyway.
    host.gsbl_mut().channel_mut(chan).raw = true;

    Ok(abi::Ret::Void)
}

/// `char prmcls[KEYSIZ]`'s byte offset within `struct usracc` (`USRACC.H:29`,
/// `KEYSIZ` = 16 including the terminator). See [`swtcls`]'s own doc comment
/// for how this is derived and why it holds for both ABIs.
const PRMCLS: u16 = 0xf0; // 240

/// `char curcls[KEYSIZ]`'s byte offset. See [`PRMCLS`].
const CURCLS: u16 = 0x100; // 256

/// `unsigned fgvdys`'s byte offset -- "days since debt was last forgiven".
/// See [`PRMCLS`].
const FGVDYS: u16 = 0x116; // 278

/// `KEYSIZ` (`USRACC.H:16`) -- 16 bytes including the NUL, what `curcls`/
/// `prmcls` are each sized for.
const KEYSIZ: usize = 16;

/// `VOID swtcls(struct usracc *uacc, INT makprm, const CHAR *clsnam, INT dest,
/// INT days)` -- switch an account to another class.
///
/// `re/wg33src/SRC/server/wgserver/ACCOUNT.C:226-...` (Worldgroup 3.3, 1997)
/// / `archive/galacticomm/extract/wg1/GALDSRC/SRC/ACCOUNT.C:233-...` (wg1,
/// identical body): looks the named class up in a class table (`fndcls`),
/// **deletes the whole account** if it does not exist there, redirects to
/// `tclptr->nxtcls[DCREDIT]` instead of switching if the class's
/// `NOCRED`/`HASCRD` flag disagrees with the account's credit balance,
/// updates `clsptr->users`/`tclptr->users` counters, copies the new class
/// name into `curcls` (and, if `makprm`, into `prmcls` too, plus
/// `daystt`/`fgvdys`), resynchronises `othusn`/`othusp`/`othuap` if the
/// account is online elsewhere, and -- unless `dest >= 2` -- prints one of
/// the class's four canned messages (`clsbb`, a Btrieve file) through `pmlt`.
///
/// # Why only the account mutation is reproduced
///
/// Every other piece needs a class table (`crtclass`/`fndcls`/`struct
/// clstab`/`struct acclass`) this crate has never modeled anywhere (`grep -rl
/// fndcls crates/mbbs/src` finds nothing). Faithfully reproducing `fndcls`
/// returning `NULL` (`delacct` -- **deleting the whole account** on an
/// unrecognised class name) or the credit-redirect branch would both mean
/// inventing class-table data this host does not have, exactly the
/// fabrication "no plausible zeros" refuses -- worse, `delacct` on a name
/// this host merely failed to validate would be destructive on a guess. So
/// this accepts every `clsnam` it is given (there is no table to check it
/// against) and performs only what `ACCOUNT.C`'s own body does
/// unconditionally, past the parts that need the table:
///
/// * `curcls` is always overwritten with `clsnam` (`ACCOUNT.C:270`).
/// * `prmcls` and `fgvdys=0` are written only when `makprm` is set
///   (`:271-272`, `:279`) -- **not** `daystt`, which the vendor computes from
///   `tclptr->flags&DAYEXP` and `tclptr->dftday`, both class-table fields
///   this host cannot read; writing a guessed `daystt` would be exactly the
///   plausible-but-invented answer this crate refuses, so it stays
///   untouched -- the same "declined, not silently assumed away" choice
///   [`extoff`]'s own doc comment inherits from `onsysn`'s for `othexp`.
/// * `othusn`/`othusp`/`othuap` resynchronisation, the `clsbb` exit message,
///   and the credit-balance/class-table branches are not reproduced at all.
///
/// This makes `makprm` the one argument with an effect distinct from the
/// rest: a temporary switch (`makprm==0`) touches only `curcls`; a permanent
/// one also touches `prmcls`/`fgvdys`.
///
/// # `curcls`/`prmcls`/`fgvdys`'s offsets
///
/// Not in [`crate::users::AccountLayout`] -- that file is not this task's to
/// edit -- derived locally instead, from `USRACC.H`'s own field list and
/// cross-checked against the four offsets `AccountLayout::of` already
/// carries and this crate's own tests already confirm (`ansifl`=0xd0
/// through `scnfse`=0xd3, right where this count also puts them). Every
/// field from `userid` through `emllim` is `char`/`int`/`long`/an array of
/// one of those, Borland packs all of them with no alignment gap (every
/// running total below stays even), and `curcls`/`prmcls`/`fgvdys` sit well
/// before `spare[]` -- the one field GCV2 and non-GCV2 disagree about the
/// size of (`AccountLayout::of`'s own doc comment) -- so these offsets are
/// identical for both ABIs:
///
/// ```text
/// scnfse(1) @0xd3   age(1) sex(1) credat(2) usedat(2) csicnt(2)
///                    flags(2) access[7](14) emllim(4)  -> running total 0xf0
/// prmcls[16] @0xf0 (240)
/// curcls[16] @0x100 (256)
/// timtdy(4) @0x110   daystt(2) @0x114
/// fgvdys(2) @0x116 (278)
/// ```
///
/// # `clsnam`'s length
///
/// `KEYSIZ` (16, NUL included) bounds `curcls`/`prmcls` on disk. A `clsnam`
/// that does not fit is not a class this host's own table rejected (there is
/// none) -- it is a write past `curcls` into `timtdy`, the unchecked-overflow
/// shape this crate stops on rather than allows.
///
/// # Arity, measured rather than trusted
///
/// The header this task cites (`archive/galacticomm/extract/wg1/GALDSRC/SRC/
/// USRACC.H:174`, wg1) declares exactly **five fixed arguments, no `...`** --
/// contrary to this task's own framing, which expected the declaration to
/// end in a variadic tail. Confirmed three independent ways, not just read
/// once: the wg1 header, the identical `re/wg33src/INC/USRACC.H:70`
/// (Worldgroup 3.3) and `ACCOUNT.C`'s own definition all declare five;
/// every real call site found agrees (Elwynor's `GLOBROUS.C:3891,5014`, and
/// `re/isv_union_pe_symbols.tsv`'s `WGSERVER _swtcls 3 3`); and Rose's own
/// compiled call (`re/ne_arity.py 595 tmp/gapsurvey/rose/RCIROSE.DLL`)
/// cleans **7 words** -- exactly `uacc`(2) + `makprm`(1) + `clsnam`(2) +
/// `dest`(1) + `days`(1), a far pointer costing two words each. Rose32's PE
/// build imports it too (`tmp/gapsurvey/round2/out_rose_pe.txt`, one call),
/// both under `MAJORBBS`, so this is registered generically rather than
/// per-ABI.
///
/// # Errors
///
/// If `uacc`/`clsnam` cannot be read, or `clsnam` (with its terminator) does
/// not fit in `KEYSIZ` bytes.
pub fn swtcls<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let uacc = call.ptr();
    let makprm = super::gbool_arg::<A>(call.int());
    let clsnam = call.ptr();
    let _dest = call.int();
    let _days = call.int();

    let name = clsnam
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(format!("swtcls: clsnam: {e}")))?
        .to_vec();
    if name.len() + 1 > KEYSIZ {
        return Err(ShimError::Failed(format!(
            "swtcls: a {}-byte class name will not fit in curcls/prmcls's {KEYSIZ}",
            name.len()
        )));
    }
    let mut field = name;
    field.push(0);

    A::ptr_offset(uacc, CURCLS)
        .write(call.mem(), &field)
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    if makprm {
        A::ptr_offset(uacc, PRMCLS)
            .write(call.mem(), &field)
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        A::ptr_offset(uacc, FGVDYS)
            .write(call.mem(), &0u16.to_le_bytes())
            .map_err(|e| ShimError::Failed(e.to_string()))?;
    }

    Ok(abi::Ret::Void)
}

/// `struct extusr *extoff(int unum)` -- pointer to `extusr[unum]`.
///
/// `archive/galacticomm/extract/wg1/GALDSRC/SRC/MAJORBBS.C:4304-4309` (wg1):
///
///
/// [`crate::users::Users::extra`] already is this: the same `nterms`-slots
/// `extusr` table [`curusr`]'s own doc comment names as one of the two
/// globals it deliberately does not set (`WCCMMUD.DLL` addresses neither
/// `extusr` nor `extptr`). RTSLORD-NE (Twilight Lord) addresses both,
/// directly: `EXTOFF` is `MAJORBBS` ordinal 827, 5 real call sites
/// (`re/ne_arity.py 827 tmp/gapsurvey/tlord_ne/RTSLORD.DLL`, each cleaning 1
/// word -- the one `int unum` argument, matching the header), and `OTHEXP`
/// is ordinal 826, imported as **data** at 15 sites (the same tool reports
/// "cleans void" at every one -- the signature of a fixup with no call after
/// it, not a routine). `OTHEXP` is the caller-side assignment target
/// `othexp=extoff(othusn)` (`MAJORBBS.C:3023` &c.) writes into, the same
/// shape `onsysn`'s own doc comment already traces for it, not a second
/// routine this file owes.
///
/// **`othexp` needs a `globals.rs` entry this task's file scope does not
/// reach** (`g("othexp", PTR)`, mirroring `othuap`) -- flagged for the
/// integrator, not silently dropped. `onsysn`'s "no module in the corpus
/// addresses it" is now **wrong** -- RTSLORD-NE does, 15 times -- the exact
/// stale-comment shape the plan's Global Constraints warned would turn up,
/// and that comment needs correcting once `othexp` is placed.
///
/// GCV2-only: `struct extusr` is a GCV2 invention
/// ([`crate::users::extusr_stride`]'s own doc comment), so this refuses
/// under a non-GCV2 ABI rather than fabricating an address -- consistent
/// with registering it in `WG16_ROUTINES`, not the generic table.
///
/// # Errors
///
/// If `unum` names no channel of this host, or this ABI has no `extusr`
/// table.
pub fn extoff<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let unum = Into::<u32>::into(call.int()) as i16;
    let chan = host
        .users()
        .terms()
        .chan(unum)
        .ok_or_else(|| ShimError::Failed(format!("extoff({unum}): there is no such channel")))?;
    let ptr = host
        .users()
        .extra(chan)
        .ok_or_else(|| ShimError::Failed("extoff: this ABI has no extusr table".to_string()))?;
    Ok(abi::Ret::Ptr(ptr))
}

/// `VOID paccit(VOID)` -- "show input on modem monitor, check profanity" --
/// post-process a channel's already-read line
/// ([`crate::Host::paccin`]/[`getin`]) before the module reads it back out
/// of `margv`.
///
/// `re/wg33src/SRC/server/wgserver/MAJORBBS.C:3996-4003` (Worldgroup 3.3,
/// 1997):
///
///
/// Two halves, both gated on machinery this host does not have, for two
/// different reasons.
///
/// **`shomal_hook`** echoes the channel's raw input to the SYSOP's local
/// console ("show input"), unless `MONHID` (`MAJORBBS.H:222`, "hide input
/// from the monitor screen") is set. This is the same local-console concept
/// [`crate::Host::paccin`]'s own doc comment already declines system-wide
/// ("the modem monitor and the profanity check, both BBS-shaped and out of
/// scope") -- there is no SYSOP console to echo to, so this half is a true
/// no-op, not a gap.
///
/// **`(*setpfn)(input)`** defaults to `dftpfn` (`MAJORBBS.C:4005-4021`; no
/// module in the corpus this host was built against reassigns the hook),
/// which computes `pfnlvl=profan(input)`, clamps it against
/// `haskey(syskey)`/`pfceil`, and -- when the clamped level exceeds 1 --
/// accumulates it into `usrptr->pfnacc`. `profan` itself is a real routine
/// this host implements ([`crate::shims::mudtext::profan`]), but its scan
/// (`crate::shims::mudtext::profan_scan`) is a file-private helper of that
/// module -- reaching it from here would mean either duplicating
/// Galacticomm's word-list logic a second time (the exact "two
/// implementations that can silently diverge" shape this crate has been
/// bitten by before) or widening that helper's visibility, a change to
/// `mudtext.rs`, outside this task's file scope. **And even with a level in
/// hand there is nowhere faithful to put half of it**: `usracc`'s `pfnacc`
/// accumulator has no offset in [`crate::users::UserLayout`] at all, so the
/// reachable half of `dftpfn` (the `pfnlvl` global write) would be
/// observable while the unreachable half (`pfnacc`) stayed silently zero --
/// the same "writing three of four side-effect globals is worse than
/// writing none" reasoning [`extoff`]'s own doc comment inherits from
/// `onsysn`'s for `othexp`.
///
/// So this is a full, faithful no-op: not because nothing in `paccit`
/// matters, but because every module-observable piece of it needs either a
/// console this host does not have or a struct field this crate has not
/// placed, and inventing either would be exactly the fabrication "no
/// plausible zeros" refuses.
///
/// **Registered for both ABIs since Phase 2 Task 2.8.** It was in
/// `WG32_ROUTINES` alone -- one import, one call site each in MajorMUD NT
/// (`tmp/gapsurvey/round2/out_mmud_nt7pk.txt`/`out_mmud_nt8pj.txt`), 32-bit
/// only -- and the corpus ledger then showed HVSTW importing it off the
/// **NE** side too, where nothing served it. The same body answers both;
/// writing a second one in `shims::text` was the first thing Task 2.8 did
/// and the wrong thing, since the two would have been free to diverge.
pub fn paccit<A: Abi>(_call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    Ok(abi::Ret::Void)
}

/// `GBOOL samepatu(CHAR *sau1, CHAR *sau2, GBOOL exact)` -- do these two GCSP
/// dynapak-name strings match?
///
/// `re/wg33src/INC/GCSP.H:536` declares it; `re/wg33src/INC/GCSPSRV.H:124-125`
/// gives its only two callers, both macros:
///
///
/// # No surviving body -- semantics from the macros and their call sites, not a guess
///
/// No `GCSP*.C` implementing `samepatu` itself survives in `re/wg33src` --
/// only the header and hundreds of call sites reached through the two
/// macros above, every one matching Worldgroup's internal client/server
/// protocol token strings (`samepat("sau:irccfg",dpkstg)`,
/// `samepato("sau:",dpkstg)`, ...; `re/wg33src/SRC/icsrc/galirc/IRCAGT.C`,
/// `.../galfil/GALFILCS.C`, dozens more). The parameter names in
/// `samepato`'s own macro -- `shorts`, `longs` -- are the specification the
/// missing body cannot contradict: `exact=TRUE` (`samepat`) is a full match,
/// `exact=FALSE` (`samepato`) is "does `longs` start with `shorts`", the
/// shape every one of those call sites needs (`samepato("sau:",dpkstg)`
/// asking whether a received packet name begins with a fixed prefix). This
/// is the opposite of this task's own sample test's premise (wildcard-glob
/// matching a user-ID against `"SYS*"`) -- `samepatu` has nothing to do with
/// user IDs; it is a GCSP protocol-token comparison, and the test below is
/// written to that, not to the sample -- exactly what this task's own
/// instructions asked for when a vendor body disagrees with the premise.
///
/// **Recorded uncertainty: case sensitivity.** Every real call site compares
/// two machine-generated protocol tokens (a fixed C string literal against a
/// received dynapak name), never user input, so this compares bytes exactly
/// -- unlike [`crate::shims::text::sameas`], which this crate already keeps
/// case-insensitive specifically because it compares user-facing values
/// (user-IDs, keys). No surviving body confirms this either way for
/// `samepatu`.
///
/// MajorMUD NT is the only known importer (`re/wg_nt_ghidra/exports/
/// WCCMMUD_decompiled.c:67230`, `_samepatu()` gating a state check --
/// argument values are not visible in that decompile). 32-bit only, one call
/// site each in `wccnt7pk`/`wccnt8pj` -- registered in `WG32_ROUTINES`.
///
/// # Errors
///
/// If `sau1`/`sau2` cannot be read as NUL-terminated strings.
pub fn samepatu<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let sau1 = call.ptr();
    let sau2 = call.ptr();
    let exact = super::gbool_arg::<A>(call.int());

    let a = sau1
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(format!("samepatu: sau1: {e}")))?
        .to_vec();
    let b = sau2
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(format!("samepatu: sau2: {e}")))?
        .to_vec();

    let matched = if exact { a == b } else { b.starts_with(a.as_slice()) };
    Ok(abi::Ret::Int(A::int_from_u32(u32::from(matched))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::Wg16;
    use crate::testing::Fixture;
    use mbbs_machine::m16::FarPtr;

    #[test]
    fn uacoff_hands_back_the_channels_account_record() {
        let mut f = Fixture::new();
        let console = f.console();
        let Ret::Far(at) = f.invoke(uacoff, &[0]).expect("channel 0") else {
            panic!("uacoff returns a pointer");
        };
        assert_eq!(at, f.host.users().account(console));
    }

    #[test]
    fn uacoff_stops_the_module_on_a_channel_that_does_not_exist() {
        // `ptrblok` had no bound and would have returned the bytes after the
        // last record. The module would then have keyed a Btrieve read on them.
        // There is no answer here that is not a lie, so the module stops.
        let mut f = Fixture::new();
        assert!(f.invoke(uacoff, &[-1i16 as u16]).is_err());
        let past = f.host.users().terms().count();
        assert!(f.invoke(uacoff, &[past]).is_err());
    }

    #[test]
    fn curusr_repoints_every_global_that_names_the_current_channel() {
        let mut f = Fixture::new();
        let console = f.console();
        f.invoke(curusr, &[0]).expect("channel 0");

        let g = f.host.globals();
        assert_eq!(g.word(&f.machine, "usrnum").expect("usrnum") as i16, 0);
        assert_eq!(
            g.pointer(&f.machine, "usrptr").expect("usrptr"),
            f.host.users().slot(console)
        );
        assert_eq!(
            g.pointer(&f.machine, "usaptr").expect("usaptr"),
            f.host.users().account(console)
        );
    }

    #[test]
    fn curusr_leaves_vdaptr_null_until_alcvda_has_run() {
        // `vdaoff` reads `vdahdl`, which `alcvda` fills in after every module's
        // init. `curusr` during init therefore sets `vdaptr` to null -- and
        // that is right, because that is what the real host's `vdaoff` returned
        // at that point. `WCCMMUD.DLL` tests `usrptr` for null in two places;
        // handing it a pointer to nothing would be worse than handing it zero.
        let mut f = Fixture::new();
        let console = f.console();
        f.invoke(curusr, &[0]).expect("channel 0");
        assert_eq!(
            f.host.globals().pointer(&f.machine, "vdaptr").expect("vdaptr"),
            mbbs_machine::m16::FarPtr::NULL
        );

        f.invoke(crate::shims::system::dclvda, &[256]).expect("declared");
        f.host.alcvda(&mut f.machine).expect("allocated");
        f.invoke(curusr, &[0]).expect("channel 0 again");
        assert_eq!(
            f.host.globals().pointer(&f.machine, "vdaptr").expect("vdaptr"),
            f.host.users().vda(console).expect("allocated")
        );
    }

    #[test]
    fn curusr_on_a_channel_that_does_not_exist_changes_nothing() {
        // `MAJORBBS.C:4293` -- `if (0 <= uno && uno < nterms)`, with no else.
        // Silent, and modules rely on it: `curusr(-1)` is how the host itself
        // says "nobody" at `MAJORBBS.C:882`.
        let mut f = Fixture::new();
        f.invoke(curusr, &[0]).expect("channel 0");
        let before = f.host.globals().pointer(&f.machine, "usrptr").expect("usrptr");

        f.invoke(curusr, &[-1i16 as u16]).expect("a no-op, not an error");
        assert_eq!(f.host.globals().word(&f.machine, "usrnum").expect("usrnum") as i16, 0);
        assert_eq!(f.host.globals().pointer(&f.machine, "usrptr").expect("usrptr"), before);
    }

    #[test]
    fn a_curusr_that_did_nothing_is_recorded_rather_than_silent() {
        // The one place this crate lets a routine decline without stopping the
        // module. A run where it happened must be tellable from one where it
        // did not.
        let mut f = Fixture::new();
        f.invoke(curusr, &[99]).expect("a no-op");
        assert!(
            f.host.notes().iter().any(|n| n.contains("curusr")),
            "notes: {:?}",
            f.host.notes()
        );
    }

    #[test]
    fn getin_takes_a_ready_line_and_hands_back_its_first_argument() {
        let mut f = Fixture::new();
        let console = f.console();
        f.invoke(curusr, &[0]).expect("channel 0");
        f.host.gsbl_mut().push_input(console, b"get all gold\r");

        let Ret::Far(margv0) = f.invoke(getin, &[]).expect("ok") else {
            panic!("getin returns char *margv[0]");
        };

        // `input` holds the line, NUL-terminated -- and `getin` did not just
        // copy the bytes, it ran them through `parsin`: `margc` is right and
        // `margv[0]` is the pointer `parsin` produced, not a guess at it.
        let input = f.host.globals().address("input").expect("input");
        assert_eq!(f.machine.read_cstr(input).expect("terminated"), b"get");
        assert_eq!(f.host.globals().word(&f.machine, "margc").expect("margc"), 3);
        // `margv[0]` points at "get" itself -- the start of `input`, since
        // the first word begins right there.
        assert_eq!(margv0, input);
        assert_eq!(f.machine.read_cstr(margv0).expect("readable"), b"get");
    }

    #[test]
    fn getin_on_a_channel_with_no_ready_line_still_returns_a_readable_margv_zero() {
        // Nothing pushed, and no `\r` arrived -- there is no completed line to
        // take. `getin` must not fault, and the module still dereferences
        // `margv[0]` unguarded on whatever it gets back.
        let mut f = Fixture::new();
        f.invoke(curusr, &[0]).expect("channel 0");

        let Ret::Far(margv0) = f.invoke(getin, &[]).expect("ok") else {
            panic!("getin returns char *margv[0]");
        };
        assert_eq!(f.host.globals().word(&f.machine, "margc").expect("margc"), 0);
        assert_ne!(margv0, mbbs_machine::m16::FarPtr::NULL);
        assert_eq!(f.machine.read_cstr(margv0).expect("readable"), b"");
    }

    #[test]
    fn haskey_answers_for_the_channel_usrnum_names() {
        let mut f = crate::testing::Fixture::new();
        let console = f.console();
        f.host
            .connect_state(
                &mut f.machine,
                console,
                &crate::Connection::ansi("rangerdan").with_keys(["USER"]),
            )
            .expect("channel 0");

        let lock = f.text("USER");
        let got = f
            .invoke(super::haskey, &crate::testing::Fixture::far(lock))
            .expect("answered");
        assert_eq!(got, mbbs_machine::m16::Ret::U16(1));

        let lock = f.text("WCCSYSOP");
        let got = f
            .invoke(super::haskey, &crate::testing::Fixture::far(lock))
            .expect("answered");
        assert_eq!(got, mbbs_machine::m16::Ret::U16(0));
    }

    #[test]
    fn haskey_refuses_everything_on_a_channel_that_never_logged_on() {
        // `low_haskey`'s first check: `keys == NULL` answers `class == BBSPRV`,
        // and `connect_state` writes `usrcls` as 0. The empty lock is the case
        // that matters -- it is true for a logged-on channel holding nothing and
        // false here, because the null check comes first.
        let mut f = crate::testing::Fixture::new();
        f.host
            .globals()
            .write(&mut f.machine, "usrnum", &0i16.to_le_bytes())
            .expect("usrnum is placed");

        let lock = f.text("");
        let got = f
            .invoke(super::haskey, &crate::testing::Fixture::far(lock))
            .expect("answered");
        assert_eq!(got, mbbs_machine::m16::Ret::U16(0), "not 1 -- the null check comes first");
    }

    #[test]
    fn haskey_refuses_when_no_channel_is_current() {
        // `usrnum` is -1 for as long as nobody is on a channel. There is no
        // keyring to consult and the answer is 0, not a panic and not a stop.
        //
        // Channel 0 is connected first, holding the very key that is asked
        // about, and *then* `usrnum` is moved off it. That is what makes this
        // test say something about `usrnum` rather than only about -1: with
        // channel 0 empty, a shim that ignored `usrnum` and always read
        // channel 0 would answer 0 here too -- for the wrong reason -- and
        // this assertion would pass against it. At `nterms == 1` there is no
        // second channel to catch that with, so the discriminator has to be a
        // channel that *would* answer differently if it were the one read.
        let mut f = crate::testing::Fixture::new();
        let console = f.console();
        f.host
            .connect_state(
                &mut f.machine,
                console,
                &crate::Connection::ansi("rangerdan").with_keys(["USER"]),
            )
            .expect("channel 0");
        f.host
            .globals()
            .write(&mut f.machine, "usrnum", &(-1i16).to_le_bytes())
            .expect("usrnum is placed");

        let lock = f.text("USER");
        let got = f
            .invoke(super::haskey, &crate::testing::Fixture::far(lock))
            .expect("answered");
        assert_eq!(got, mbbs_machine::m16::Ret::U16(0));
    }

    #[test]
    fn haskey_reads_the_lock_out_of_module_memory_rather_than_assuming_one() {
        // The argument is a far pointer to a NUL-terminated string in the
        // module's own memory, pushed cdecl. A shim that read the wrong words
        // would still answer *something*, so the discriminating test is two
        // different locks with different answers through the same call path --
        // covered above -- plus an expression, which only works if the whole
        // string arrived.
        let mut f = crate::testing::Fixture::new();
        let console = f.console();
        f.host
            .connect_state(
                &mut f.machine,
                console,
                &crate::Connection::ansi("rangerdan").with_keys(["USER"]),
            )
            .expect("channel 0");

        let lock = f.text("USER|WCCSYSOP");
        let got = f
            .invoke(super::haskey, &crate::testing::Fixture::far(lock))
            .expect("answered");
        assert_eq!(got, mbbs_machine::m16::Ret::U16(1));
    }

    #[test]
    fn haskey_does_not_uppercase_the_module_s_own_string() {
        // The deliberate infidelity. `lockbit` (LOCKNKEY.C:439) opens with
        // `strupr(lock)`, mutating the caller's static config data in place; this
        // shim uppercases a host-side copy instead. Pinned so the deviation is a
        // decision with a test rather than something a later reader "fixes".
        let mut f = crate::testing::Fixture::new();
        let console = f.console();
        f.host
            .connect_state(
                &mut f.machine,
                console,
                &crate::Connection::ansi("rangerdan").with_keys(["USER"]),
            )
            .expect("channel 0");

        let lock = f.text("user");
        let got = f
            .invoke(super::haskey, &crate::testing::Fixture::far(lock))
            .expect("answered");
        assert_eq!(got, mbbs_machine::m16::Ret::U16(1), "matched case-insensitively");
        assert_eq!(f.read(lock), "user", "and left the module's string alone");
    }

    /// `hasmkey(mnum)` reaches [`haskey`]'s own [`gen_haskey`] tail once the
    /// lock string comes from a message instead of a module pointer -- this
    /// is that sharing, checked the same way
    /// [`haskey_answers_for_the_channel_usrnum_names`] checks `haskey` itself:
    /// two different answers through the same call path.
    ///
    /// `SAMPLE.MSG`'s `ACTIVATE` option is message 1, storing "DEMO" --
    /// `crates/mbbs/src/shims/msg.rs`'s own `stgopt_returns_the_whole_message`
    /// test already establishes that raw text. Reused here as a lock name
    /// rather than adding a second fixture file for the same shape of thing;
    /// message 2 (`GAMCRD`) stores a multi-word prompt that is not a key
    /// anyone holds, which is the "answers differently" half of the pair.
    #[test]
    fn hasmkey_answers_for_the_channel_usrnum_names() {
        let mut f = crate::testing::Fixture::new();
        let console = f.console();
        f.host
            .connect_state(
                &mut f.machine,
                console,
                &crate::Connection::ansi("rangerdan").with_keys(["DEMO"]),
            )
            .expect("channel 0");
        let name = f.text("SAMPLE.MSG");
        f.invoke(crate::shims::msg::opnmsg, &crate::testing::Fixture::far(name))
            .expect("opens");

        let got = f.invoke(super::hasmkey, &[1]).expect("answered");
        assert_eq!(got, mbbs_machine::m16::Ret::U16(1), "message 1 is \"DEMO\", and the channel holds it");

        let got = f.invoke(super::hasmkey, &[2]).expect("answered");
        assert_eq!(got, mbbs_machine::m16::Ret::U16(0), "message 2 is not a key this channel holds");
    }

    /// `LOCKNKEY.C:239`'s `bb == NULL` case has no counterpart for `hasmkey`
    /// -- there is no Btrieve file involved -- but the *channel* three-case
    /// test [`gen_haskey`] shares with [`haskey`] does, and this is that case:
    /// nobody on the channel `usrnum` names.
    #[test]
    fn hasmkey_refuses_when_no_channel_is_current() {
        let mut f = crate::testing::Fixture::new();
        let console = f.console();
        f.host
            .connect_state(
                &mut f.machine,
                console,
                &crate::Connection::ansi("rangerdan").with_keys(["DEMO"]),
            )
            .expect("channel 0");
        f.host
            .globals()
            .write(&mut f.machine, "usrnum", &(-1i16).to_le_bytes())
            .expect("usrnum is placed");
        let name = f.text("SAMPLE.MSG");
        f.invoke(crate::shims::msg::opnmsg, &crate::testing::Fixture::far(name))
            .expect("opens");

        let got = f.invoke(super::hasmkey, &[1]).expect("answered");
        assert_eq!(got, mbbs_machine::m16::Ret::U16(0));
    }

    /// Moved from the dead `credit::hasmkey` twin
    /// (`docs/2026-08-15-dead-twin-shims.md`), which had this case and this
    /// file's own [`hasmkey_answers_for_the_channel_usrnum_names`] did not:
    /// `mnum` naming a message when no `.MSG` block is even open --
    /// [`crate::shims::msg::message_mem`]'s own error, surfacing unchanged.
    #[test]
    fn hasmkey_refuses_with_no_message_block_open() {
        let mut f = crate::testing::Fixture::new();
        let console = f.console();
        f.host
            .connect_state(
                &mut f.machine,
                console,
                &crate::Connection::ansi("rangerdan").with_keys(["DEMO"]),
            )
            .expect("channel 0");

        assert!(f.invoke(super::hasmkey, &[1]).is_err());
    }

    /// `MAJORBBS.C:1183`. The status is what makes the channel tick; the store
    /// is what makes it tick *into the right routine*.
    #[test]
    fn begin_polling_installs_the_routine_and_injects_one_status() {
        let mut f = Fixture::new();
        let console = f.console();
        let rou = f.machine.code_ptr(0);

        f.invoke(begin_polling, &[0, rou.offset, rou.selector])
            .expect("installed");

        assert_eq!(
            f.host.users().polrou_mem(f.machine.mem(), console).expect("channel 0"),
            Some(rou)
        );
        assert_eq!(f.host.gsbl_mut().next_status(console), Some(crate::gsbl::Gsbl::POLSTS));
        assert_eq!(f.host.gsbl_mut().next_status(console), None, "exactly one");
    }

    /// The guard that keeps the status queue from doubling every tick.
    /// `dopoll` re-injects on return, so a `begin_polling` from *inside* a
    /// polling routine must not inject as well.
    #[test]
    fn begin_polling_injects_nothing_while_that_channel_is_inside_its_poll_routine() {
        let mut f = Fixture::new();
        let console = f.console();
        let rou = f.machine.code_ptr(0);
        f.host.inpolr = Some(console);

        f.invoke(begin_polling, &[0, rou.offset, rou.selector])
            .expect("installed");

        assert_eq!(
            f.host.users().polrou_mem(f.machine.mem(), console).expect("channel 0"),
            Some(rou),
            "the routine is still installed"
        );
        assert_eq!(
            f.host.gsbl_mut().next_status(console),
            None,
            "but nothing is injected -- dopoll will do that on return"
        );
    }

    /// An already-polling channel is already going to be serviced.
    #[test]
    fn begin_polling_injects_nothing_when_the_channel_is_already_polling() {
        let mut f = Fixture::new();
        let console = f.console();
        let first = f.machine.code_ptr(0);
        let second = f.machine.code_ptr(1);

        f.invoke(begin_polling, &[0, first.offset, first.selector])
            .expect("installed");
        assert_eq!(f.host.gsbl_mut().next_status(console), Some(crate::gsbl::Gsbl::POLSTS));

        f.invoke(begin_polling, &[0, second.offset, second.selector])
            .expect("replaced");

        assert_eq!(
            f.host.users().polrou_mem(f.machine.mem(), console).expect("channel 0"),
            Some(second),
            "the new routine replaces the old one"
        );
        assert_eq!(
            f.host.gsbl_mut().next_status(console),
            None,
            "and no second status is queued"
        );
    }

    #[test]
    fn stop_polling_clears_the_routine_and_injects_nothing() {
        let mut f = Fixture::new();
        let console = f.console();
        let rou = f.machine.code_ptr(0);
        f.invoke(begin_polling, &[0, rou.offset, rou.selector])
            .expect("installed");
        let _ = f.host.gsbl_mut().next_status(console);

        f.invoke(stop_polling, &[0]).expect("stopped");

        assert_eq!(
            f.host.users().polrou_mem(f.machine.mem(), console).expect("channel 0"),
            None
        );
        assert_eq!(f.host.gsbl_mut().next_status(console), None);
    }

    #[test]
    fn polling_a_channel_that_does_not_exist_is_refused() {
        let mut f = Fixture::new();
        let rou = f.machine.code_ptr(0);
        assert!(
            f.invoke(begin_polling, &[1, rou.offset, rou.selector])
                .is_err(),
            "nterms is 1, so channel 1 does not exist"
        );
        assert!(f.invoke(stop_polling, &[1]).is_err());
    }

    /// All nine call sites pass a real pointer, and the one computed pointer
    /// (`WCCMMUD_named.c:11831`) carries a fixed non-zero selector, so a whole
    /// NULL here is a module bug rather than a compact `stop_polling`.
    #[test]
    fn a_null_polling_routine_is_refused_rather_than_installed() {
        let mut f = Fixture::new();
        let console = f.console();
        assert!(f.invoke(begin_polling, &[0, 0, 0]).is_err());
        assert_eq!(
            f.host.gsbl_mut().next_status(console),
            None,
            "and nothing is injected on the way out"
        );
    }

    #[test]
    fn usroff_hands_back_the_channels_own_slot() {
        let mut f = Fixture::new();
        let console = f.console();
        let Ret::Far(at) = f.invoke(usroff, &[0]).expect("channel 0") else {
            panic!("usroff returns a pointer");
        };
        assert_eq!(at, f.host.users().slot(console));
    }

    /// The oracle's own `usroff` tail-calls a shared accessor computing
    /// `*descriptor + WORD[*descriptor] * index + 8` -- the `+8` is a block
    /// header, an allocator detail of that host's own heap, and this host's
    /// `Users` has no equivalent to reproduce. So this is exactly
    /// `Users::slot` and nothing more, and the only way to see that it
    /// strides correctly is to ask it for more than one channel.
    #[test]
    fn usroff_addresses_each_channel_at_its_own_slot() {
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(2));
        let chan0 = f.host.users().terms().chan(0).expect("channel 0");
        let chan1 = f.host.users().terms().chan(1).expect("channel 1");

        let Ret::Far(at0) = f.invoke(usroff, &[0]).expect("channel 0") else {
            panic!("usroff returns a pointer");
        };
        let Ret::Far(at1) = f.invoke(usroff, &[1]).expect("channel 1") else {
            panic!("usroff returns a pointer");
        };

        assert_eq!(at0, f.host.users().slot(chan0));
        assert_eq!(at1, f.host.users().slot(chan1));
        assert_ne!(at0, at1, "two channels must not share a slot");
    }

    /// `usroff(nterms)` in the real host walked off the table -- the block
    /// header arithmetic just kept going and handed back whatever followed
    /// it. Runtime crashes beat undefined behaviour: this host refuses
    /// instead, the same way [`uacoff`] does for the account table.
    #[test]
    fn usroff_refuses_a_channel_past_the_end_of_the_table() {
        let mut f = Fixture::new();
        let past = f.host.users().terms().count();
        assert!(f.invoke(usroff, &[past]).is_err());
        assert!(f.invoke(usroff, &[-1i16 as u16]).is_err());
    }

    /// `void clrmlt(void)` -- see [`clrmlt`]'s own doc comment for why a
    /// no-op is the honest answer. Called with channel 1 current, not
    /// channel 0, because `clrmlt` takes no channel argument at all and the
    /// one way to show that is real is to call it when the "current" channel
    /// is not the host's default.
    #[test]
    fn clrmlt_is_a_no_op_that_succeeds_regardless_of_the_current_channel() {
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(2));
        f.invoke(curusr, &[1]).expect("channel 1 current");
        assert_eq!(f.invoke(clrmlt, &[]).expect("clrmlt succeeds"), Ret::Void);
    }

    // ---- instat/onsysn/othkey/mdfgets/dfsthn -----------------------

    /// A host with two channels, both connected. `instat`/`onsysn` are
    /// meaningless at one channel -- see this module's own doc comment.
    fn two_channels() -> Fixture {
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(2));
        let chan0 = f.host.users().terms().chan(0).expect("channel 0");
        let chan1 = f.host.users().terms().chan(1).expect("channel 1");
        f.host
            .connect_state(&mut f.machine, chan0, &crate::Connection::ansi("rangerdan"))
            .expect("channel 0 connects");
        f.host
            .connect_state(&mut f.machine, chan1, &crate::Connection::ansi("kaimon"))
            .expect("channel 1 connects");
        f
    }

    /// Poke `user[chan].flags` directly -- there is no shim that sets
    /// `INVISB`, so the only way to arrange a channel that has it is to write
    /// the byte the way the vendor's own `NAKED sysop` toggle would have.
    fn set_flag_bits(f: &mut Fixture, chan: crate::Chan, bits: u32) {
        let field = f.host.users().user_layout().flags;
        let at = Wg16::ptr_offset(f.host.users().slot(chan), field.at);
        f.machine.write(at, &bits.to_le_bytes()).expect("flags fit");
    }

    /// Poke `user[chan].usrcls` directly. This host's own `connect_state`
    /// never writes anything above 0 -- see [`onsysn`]'s own doc comment --
    /// so a test of the branch that reads a class above `SUPIPG` has no
    /// shim to reach through and must set the field itself.
    fn set_usrcls(f: &mut Fixture, chan: crate::Chan, value: u16) {
        let field = f.host.users().user_layout().usrcls;
        let at = Wg16::ptr_offset(f.host.users().slot(chan), field.at);
        f.machine.write(at, &value.to_le_bytes()).expect("usrcls fits");
    }

    fn oth_globals(f: &Fixture) -> (i16, FarPtr, FarPtr) {
        let g = f.host.globals();
        (
            g.word(&f.machine, "othusn").expect("othusn") as i16,
            g.pointer(&f.machine, "othusp").expect("othusp"),
            g.pointer(&f.machine, "othuap").expect("othuap"),
        )
    }

    #[test]
    fn instat_finds_a_userid_in_the_given_state_on_a_second_channel() {
        let mut f = two_channels();
        let chan1 = f.host.users().terms().chan(1).expect("channel 1");
        f.host.users_mut().set_state_mem(f.machine.mem_mut(), chan1, 42).expect("state set");

        let uid = f.text("kaimon");
        let got = f.invoke(instat, &[uid.offset, uid.selector, 42]).expect("answered");
        assert_eq!(got, Ret::U16(1));

        // The side effect: `othusn`/`othusp`/`othuap` point at the match.
        let (othusn, othusp, othuap) = oth_globals(&f);
        assert_eq!(othusn, 1, "othusn names the matching channel");
        assert_eq!(othusp, f.host.users().slot(chan1));
        assert_eq!(othuap, f.host.users().account(chan1));
    }

    #[test]
    fn instat_is_false_when_the_state_does_not_match_and_still_leaves_the_globals_on_the_last_channel_scanned() {
        let mut f = two_channels();
        let chan1 = f.host.users().terms().chan(1).expect("channel 1");
        f.host.users_mut().set_state_mem(f.machine.mem_mut(), chan1, 42).expect("state set");

        let uid = f.text("kaimon");
        // 41, not 42: the userid matches but the state does not.
        let got = f.invoke(instat, &[uid.offset, uid.selector, 41]).expect("answered");
        assert_eq!(got, Ret::U16(0));

        // No match: the loop ran to the end and left the globals on the last
        // channel it visited, channel 1 -- not reset to anything. See
        // `scan_for`'s own doc comment.
        let (othusn, othusp, othuap) = oth_globals(&f);
        assert_eq!(othusn, 1);
        assert_eq!(othusp, f.host.users().slot(chan1));
        assert_eq!(othuap, f.host.users().account(chan1));
    }

    #[test]
    fn instat_is_false_when_the_userid_does_not_match() {
        let mut f = two_channels();
        let chan1 = f.host.users().terms().chan(1).expect("channel 1");
        f.host.users_mut().set_state_mem(f.machine.mem_mut(), chan1, 42).expect("state set");

        let uid = f.text("nobody");
        let got = f.invoke(instat, &[uid.offset, uid.selector, 42]).expect("answered");
        assert_eq!(got, Ret::U16(0));
    }

    #[test]
    fn instat_is_case_insensitive_on_the_userid() {
        let mut f = two_channels();
        let chan1 = f.host.users().terms().chan(1).expect("channel 1");
        f.host.users_mut().set_state_mem(f.machine.mem_mut(), chan1, 42).expect("state set");

        let uid = f.text("KaImOn");
        let got = f.invoke(instat, &[uid.offset, uid.selector, 42]).expect("answered");
        assert_eq!(got, Ret::U16(1));
    }

    #[test]
    fn instat_refuses_a_match_hidden_by_invisb() {
        let mut f = two_channels();
        let chan1 = f.host.users().terms().chan(1).expect("channel 1");
        f.host.users_mut().set_state_mem(f.machine.mem_mut(), chan1, 42).expect("state set");
        set_flag_bits(&mut f, chan1, INVISB);

        let uid = f.text("kaimon");
        let got = f.invoke(instat, &[uid.offset, uid.selector, 42]).expect("answered");
        assert_eq!(got, Ret::U16(0), "INVISB hides an otherwise exact match");
    }

    /// Moved from the dead `echo::instat` twin
    /// (`docs/2026-08-15-dead-twin-shims.md`), which had this case and
    /// [`instat_refuses_a_match_hidden_by_invisb`] does not: an invisible
    /// match is not the *only* match. `scan_for`'s own doc comment says the
    /// loop does not stop at an invisible hit, only continues past it -- this
    /// is the test that would fail if a future edit turned that `continue`
    /// into an early `return Ok(false)`.
    #[test]
    fn instat_skips_an_invisible_match_but_keeps_looking() {
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(3));
        let one = f.host.gsbl().terms().chan(1).expect("channel 1");
        let two = f.host.gsbl().terms().chan(2).expect("channel 2");
        f.host
            .connect_state(&mut f.machine, one, &crate::Connection::ansi("rangerdan"))
            .expect("channel 1 connected");
        f.host
            .connect_state(&mut f.machine, two, &crate::Connection::ansi("rangerdan"))
            .expect("channel 2 connected, same userid, still visible");
        set_flag_bits(&mut f, one, INVISB);

        let uid = f.text("rangerdan");
        let ret = f.invoke(instat, &[uid.offset, uid.selector, 0]).expect("instat");
        assert_eq!(
            ret,
            Ret::U16(1),
            "channel 1's match is invisible, but channel 2's is not"
        );
    }

    #[test]
    /// `gen_haskey` answers for the channel `unum` names, and really does
    /// evaluate the `&`/`|` grammar -- it is the same evaluator `haskey` has
    /// been using all along, which is the point of exposing it rather than
    /// writing a second one.
    ///
    /// Both a user who holds the key and one who does not, on both channels:
    /// a predicate tested only on the true case passes when it always returns
    /// true.
    #[test]
    fn gen_haskey_answers_for_the_channel_it_is_given() {
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(2));
        let chan0 = f.host.users().terms().chan(0).expect("channel 0");
        let chan1 = f.host.users().terms().chan(1).expect("channel 1");
        f.host
            .connect_state(&mut f.machine, chan0, &crate::Connection::ansi("rangerdan").with_keys(["USER"]))
            .expect("channel 0 connects");
        f.host
            .connect_state(&mut f.machine, chan1, &crate::Connection::ansi("kaimon").with_keys(["WCCSYSOP"]))
            .expect("channel 1 connects");

        let ask = |f: &mut Fixture, lock: &str, unum: i16| -> u16 {
            let lock = f.text(lock);
            let chan = f.host.users().terms().chan(unum).expect("a channel");
            let slot = f.host.users().slot(chan);
            let args = [lock.offset, lock.selector, unum as u16, slot.offset, slot.selector];
            let Ret::U16(n) = f.invoke(gen_haskey_shim, &args).expect("gen_haskey") else {
                panic!("gen_haskey returns an int");
            };
            n
        };

        assert_eq!(ask(&mut f, "USER", 0), 1, "channel 0 holds USER");
        assert_eq!(ask(&mut f, "USER", 1), 0, "channel 1 does not");
        assert_eq!(ask(&mut f, "WCCSYSOP", 1), 1, "channel 1 holds WCCSYSOP");
        assert_eq!(ask(&mut f, "WCCSYSOP", 0), 0, "channel 0 does not");

        // The expression grammar, which is the whole reason this entry point
        // exists rather than a bare per-key lookup.
        assert_eq!(ask(&mut f, "USER|WCCSYSOP", 0), 1, "or: channel 0 holds one of them");
        assert_eq!(ask(&mut f, "USER&WCCSYSOP", 0), 0, "and: channel 0 holds only one");
    }

    /// `uptr` must address the channel `unum` names. This host holds keys per
    /// channel number and has nowhere to put a `struct user` that disagrees,
    /// so a mismatched pair is refused rather than quietly answered for
    /// `unum`.
    #[test]
    fn gen_haskey_refuses_a_uptr_that_is_not_that_channels_slot() {
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(2));
        for n in [0i16, 1] {
            let chan = f.host.users().terms().chan(n).expect("a channel");
            f.host
                .connect_state(&mut f.machine, chan, &crate::Connection::ansi("someone").with_keys(["USER"]))
                .expect("connects");
        }
        let lock = f.text("USER");
        // Channel 1's slot, but unum 0.
        let other = f.host.users().slot(f.host.users().terms().chan(1).expect("channel 1"));
        let args = [lock.offset, lock.selector, 0, other.offset, other.selector];
        assert!(
            f.invoke(gen_haskey_shim, &args).is_err(),
            "a uptr/unum pair that disagrees has no answer here"
        );
    }

    /// `uidkey` answers the empty lock -- `LOCKNKEY.C:345` returns 1 before
    /// touching a disk -- and refuses anything else, because there is no
    /// offline account or key database to consult.
    ///
    /// The refusal is asserted to *name* the missing subsystem, not merely to
    /// be an error: a test that only checked `is_err()` would pass for a
    /// refusal that said nothing useful, or for a bad-pointer error.
    #[test]
    fn uidkey_answers_an_empty_lock_and_refuses_a_real_one() {
        let mut f = Fixture::new();
        let uid = f.text("rangerdan");

        let empty = f.text("");
        let args = [uid.offset, uid.selector, empty.offset, empty.selector];
        assert_eq!(
            f.invoke(uidkey, &args).expect("an empty lock is no lock"),
            Ret::U16(1),
            "LOCKNKEY.C:345 -- everybody passes an empty lock"
        );

        let lock = f.text("WCCSYSOP");
        let args = [uid.offset, uid.selector, lock.offset, lock.selector];
        let err = f.invoke(uidkey, &args).expect_err("a real lock cannot be answered");
        let message = err.to_string();
        assert!(message.contains("keysbb"), "the refusal names the keys file: {message}");
        assert!(message.contains("not online"), "and says why it cannot answer: {message}");
    }

    /// `nkyrec` refuses, and the refusal names the keys file it would have
    /// written to. It returns `VOID`, so a quiet return would let the caller
    /// go on granting keys into a record that was never created.
    #[test]
    fn nkyrec_refuses_and_names_the_keys_file() {
        let mut f = Fixture::new();
        let uid = f.text("rangerdan");
        let err = f
            .invoke(nkyrec, &Fixture::far(uid))
            .expect_err("there is no key record to create");
        let message = err.to_string();
        assert!(message.contains("keysbb"), "{message}");
        assert!(message.contains("rangerdan"), "and names who it was for: {message}");
    }

    /// `keynam` is `valkorl(name,0)`: 3 to 15 characters of `istxvc`, plus
    /// `#` and `=`, and **no** `&` or `|` -- those belong to lock names.
    #[test]
    fn keynam_bounds_the_length_and_rejects_expression_operators() {
        let mut f = Fixture::new();
        let mut ask = |f: &mut Fixture, name: &str| -> u16 {
            let at = f.text(name);
            let Ret::U16(n) = f.invoke(keynam, &Fixture::far(at)).expect("keynam") else {
                panic!("keynam returns an int");
            };
            n
        };

        assert_eq!(ask(&mut f, "USER"), 1);
        assert_eq!(ask(&mut f, "ABC"), 1, "three characters is the floor");
        assert_eq!(ask(&mut f, "WHO?"), 1, "'?' is an istxvc character");
        assert_eq!(ask(&mut f, "A_B#C=D"), 1, "'_' is istxvc; '#' and '=' are switch cases");
        assert_eq!(ask(&mut f, "A".repeat(15).as_str()), 1, "KEYSIZ-1 is the ceiling");

        assert_eq!(ask(&mut f, "AB"), 0, "two characters is under the floor");
        assert_eq!(ask(&mut f, ""), 0, "and a key name may not be empty, unlike a lock name");
        assert_eq!(ask(&mut f, "A".repeat(16).as_str()), 0, "one past KEYSIZ-1");
        assert_eq!(ask(&mut f, "A&B"), 0, "'&' belongs to lock names, not key names");
        assert_eq!(ask(&mut f, "A|B"), 0, "and so does '|'");
        assert_eq!(ask(&mut f, "A B"), 0, "a space is not an istxvc character");
        assert_eq!(ask(&mut f, "A.B"), 0, "nor is '.', though isuidc allows it");
    }

    /// `istxvc` is `isuidc`'s sibling with a different punctuation set: `_`
    /// and `?` here, against `. space , - _ '` there. Only `_` is in both, and
    /// the two are asserted against each other on exactly the characters that
    /// separate them -- otherwise a port could answer `isuidc` for both.
    #[test]
    fn istxvc_takes_underscore_and_question_but_not_isuidcs_punctuation() {
        let mut f = Fixture::new();
        let mut ask = |f: &mut Fixture, c: u8| -> u16 {
            let Ret::U16(n) = f.invoke(istxvc, &[u16::from(c)]).expect("istxvc") else {
                panic!("istxvc returns an int");
            };
            n
        };

        for c in [b'A', b'z', b'0', b'_', b'?'] {
            assert_eq!(ask(&mut f, c), 1, "{:?} is a text-variable character", c as char);
        }
        // The four isuidc accepts and istxvc does not -- the discriminating set.
        for c in [b'.', b' ', b',', b'-', b'\''] {
            assert_eq!(
                ask(&mut f, c),
                0,
                "{:?} is an isuidc character but NOT an istxvc one",
                c as char
            );
        }
        // Shared high ranges, at their edges.
        for c in [0x80u8, 0xa5, 0xe0, 0xef] {
            assert_eq!(ask(&mut f, c), 1, "{c:#04x} is inside ISTXVC.C:27-28's ranges");
        }
        for c in [0xa6u8, 0xdf, 0xf0] {
            assert_eq!(ask(&mut f, c), 0, "{c:#04x} is outside them");
        }
    }

    /// `uhskey` is `onsysn(uid,1) ? othkey(lock) : uidkey(uid,lock)`.
    ///
    /// `onsysn` answers false for every channel while `usrcls` stays at zero,
    /// so today this always takes the offline arm -- and therefore refuses for
    /// a real lock and answers 1 for an empty one, exactly as `uidkey` does.
    /// Pinned so that the day `usrcls` starts moving, this test fails and says
    /// the branch changed rather than the behaviour drifting silently.
    #[test]
    fn uhskey_takes_the_offline_arm_while_usrcls_stays_zero() {
        let mut f = Fixture::new();
        let chan = f.console();
        f.host
            .connect_state(&mut f.machine, chan, &crate::Connection::ansi("rangerdan").with_keys(["USER"]))
            .expect("connects");

        let uid = f.text("rangerdan");
        let lock = f.text("USER");
        let args = [uid.offset, uid.selector, lock.offset, lock.selector];
        let err = f
            .invoke(uhskey, &args)
            .expect_err("onsysn says offline, so this is uidkey");
        assert!(err.to_string().contains("keysbb"), "{err}");

        let empty = f.text("");
        let args = [uid.offset, uid.selector, empty.offset, empty.selector];
        assert_eq!(
            f.invoke(uhskey, &args).expect("an empty lock"),
            Ret::U16(1),
            "the offline arm's empty-lock branch still answers"
        );
    }

    /// `usridx` inverts the `channel` table, and `-1` on a miss is a real
    /// answer rather than a failure.
    ///
    /// Both directions are asserted: every channel number in the table finds
    /// its own user number, and one that is not in the table finds nothing.
    /// A port that always returned `-1` would pass a miss-only test, and one
    /// that returned `chan` unchanged would pass a hit-only test on a host
    /// where the two happen to coincide -- so the table is read first and the
    /// expectation taken from it.
    #[test]
    fn usridx_inverts_the_channel_table_and_answers_minus_one_on_a_miss() {
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(3));

        let base = f.host.globals().pointer(&f.machine, "channel").expect("channel");
        let mut seen = Vec::new();
        for idx in 0..3u16 {
            let at = Wg16::ptr_offset(base, idx * 2);
            let bytes = f.machine.resolve(at, 2).expect("in bounds");
            seen.push(u16::from_le_bytes([bytes[0], bytes[1]]));
        }

        // The table starts [0, -1, -1]: channel 0 is assigned and the rest
        // hold the "nobody" marker. The vendor's loop stops at the FIRST
        // match, so a repeated value answers its lowest index -- which is
        // what makes this an inverse only where the table is injective.
        for (idx, chan) in seen.iter().copied().enumerate() {
            let first = seen.iter().position(|&c| c == chan).expect("it is in there");
            let Ret::U16(n) = f.invoke(usridx, &[chan]).expect("usridx") else {
                panic!("usridx returns an int");
            };
            assert_eq!(
                n, first as u16,
                "channel[{idx}] is {chan}; the first index holding it is {first}; table {seen:?}"
            );
        }

        // A channel number nothing holds. Chosen to avoid 0xffff, which the
        // table itself uses for "nobody" and which is therefore a real hit.
        let absent = seen
            .iter()
            .copied()
            .filter(|&c| c != 0xffff)
            .max()
            .unwrap_or(0)
            + 1000;
        assert!(!seen.contains(&absent), "the test's own miss must really miss");
        let Ret::U16(n) = f.invoke(usridx, &[absent]).expect("usridx") else {
            panic!("usridx returns an int");
        };
        assert_eq!(n, 0xffff, "no user is on channel {absent}, so -1");
    }

    /// `rstchn` refuses, and the refusal names the reset chain rather than
    /// merely erroring.
    #[test]
    fn rstchn_refuses_and_names_what_it_cannot_run() {
        let mut f = Fixture::new();
        let err = f.invoke(rstchn, &[]).expect_err("there is no modem to reset");
        let message = err.to_string();
        assert!(message.contains("hdlrst"), "names the handler chain: {message}");
        assert!(message.contains("bturst"), "and the hardware reset: {message}");
    }

    /// `clrxrf` is the vendor's `numxrf == 0` branch: it does nothing, and
    /// there is nothing for it to do. Asserted against the one piece of
    /// cross-reference state this host *does* place -- `uidxrf` -- so
    /// "nothing happened" is measured rather than assumed by a bare
    /// `Ok(Void)`.
    #[test]
    fn clrxrf_touches_nothing_because_no_cross_reference_is_configured() {
        let mut f = Fixture::new();
        let uidxrf = f.host.globals().address("uidxrf").expect("uidxrf");
        let marker = [0xABu8; 8];
        f.machine.write(uidxrf, &marker).expect("seed uidxrf");

        assert!(matches!(f.invoke(clrxrf, &[]), Ok(Ret::Void)));

        assert_eq!(
            f.machine.resolve(uidxrf, 8).expect("in bounds"),
            &marker,
            "clrxrf clears xrfpos, which this host does not have -- and it must \
             not have decided to clear uidxrf instead"
        );
    }

    /// `hdluid` refuses, and the refusal names the cross-reference file.
    ///
    /// The value worth *not* returning here is `UIDPMT`: it reads as "ask the
    /// user which of their IDs they meant", and the caller would then prompt
    /// against a list this host never built.
    #[test]
    fn hdluid_refuses_and_names_the_cross_reference() {
        let mut f = Fixture::new();
        let stg = f.text("rangerdan");
        let err = f
            .invoke(hdluid, &Fixture::far(stg))
            .expect_err("there is no cross-reference to resolve against");
        let message = err.to_string();
        assert!(message.contains("xrfbb"), "names the Btrieve file: {message}");
        assert!(message.contains("numxrf"), "and the option that sizes it: {message}");
        assert!(message.contains("rangerdan"), "and what was asked: {message}");
    }

    /// `nliniu` counts channels whose `usrcls` is not `VACANT` (0).
    ///
    /// This host writes `usrcls` as 0 at connect and never raises it, and
    /// `VACANT` *is* 0, so the honest count is zero even with two channels
    /// connected. Both halves are asserted: zero while `usrcls` stays put,
    /// and a real count once it is written -- so the loop is proven to be a
    /// loop rather than a folded constant, and the day a signup flow advances
    /// `usrcls` this routine is already right.
    #[test]
    fn nliniu_counts_channels_whose_usrcls_left_vacant() {
        let mut f = two_channels();
        assert_eq!(
            f.invoke(nliniu, &[]).expect("nliniu"),
            Ret::U16(0),
            "connected, but usrcls is 0 and VACANT is 0 -- see nliniu's doc comment"
        );

        // Write usrcls on one channel the way a signup flow eventually will.
        let chan = f.host.users().terms().chan(1).expect("channel 1");
        let field = f.host.users().user_layout().usrcls;
        let at = Wg16::ptr_offset(f.host.users().slot(chan), field.at);
        f.machine.write(at, &5u16.to_le_bytes()).expect("usrcls fits");

        assert_eq!(
            f.invoke(nliniu, &[]).expect("nliniu"),
            Ret::U16(1),
            "one channel is no longer VACANT, so one line is in use"
        );

        let chan = f.host.users().terms().chan(0).expect("channel 0");
        let at = Wg16::ptr_offset(f.host.users().slot(chan), field.at);
        f.machine.write(at, &3u16.to_le_bytes()).expect("usrcls fits");
        assert_eq!(f.invoke(nliniu, &[]).expect("nliniu"), Ret::U16(2));
    }

    #[test]
    fn onsysn_is_always_false_here_because_this_host_never_advances_usrcls_past_zero() {
        // `connect_state` writes `usrcls` as 0 and nothing here ever advances
        // it -- see `onsysn`'s own doc comment. This is the honest
        // consequence of that gap, pinned so a future signup flow that starts
        // writing `usrcls` has a test here that starts failing rather than a
        // silent behaviour change.
        let mut f = two_channels();
        let uid = f.text("kaimon");
        let got = f.invoke(onsysn, &[uid.offset, uid.selector, 0]).expect("answered");
        assert_eq!(got, Ret::U16(0));
    }

    #[test]
    fn onsysn_finds_a_userid_once_usrcls_is_past_supipg() {
        let mut f = two_channels();
        let chan1 = f.host.users().terms().chan(1).expect("channel 1");
        set_usrcls(&mut f, chan1, SUPIPG + 1);

        let uid = f.text("kaimon");
        let got = f.invoke(onsysn, &[uid.offset, uid.selector, 0]).expect("answered");
        assert_eq!(got, Ret::U16(1));

        let (othusn, othusp, othuap) = oth_globals(&f);
        assert_eq!(othusn, 1);
        assert_eq!(othusp, f.host.users().slot(chan1));
        assert_eq!(othuap, f.host.users().account(chan1));
    }

    #[test]
    fn onsysn_at_exactly_supipg_is_still_signing_up_not_online() {
        // `usrcls > SUPIPG`, strictly -- a channel still at `SUPIPG` itself
        // has not finished signing up yet and must not match. The boundary
        // that tells `<=`/`>` apart from `<`/`>=`.
        let mut f = two_channels();
        let chan1 = f.host.users().terms().chan(1).expect("channel 1");
        set_usrcls(&mut f, chan1, SUPIPG);

        let uid = f.text("kaimon");
        let got = f.invoke(onsysn, &[uid.offset, uid.selector, 0]).expect("answered");
        assert_eq!(got, Ret::U16(0));
    }

    #[test]
    fn onsysn_invis_true_bypasses_the_invisb_gate_that_invis_false_respects() {
        let mut f = two_channels();
        let chan1 = f.host.users().terms().chan(1).expect("channel 1");
        set_usrcls(&mut f, chan1, SUPIPG + 1);
        set_flag_bits(&mut f, chan1, INVISB);

        let uid = f.text("kaimon");
        let hidden = f
            .invoke(onsysn, &[uid.offset, uid.selector, 0])
            .expect("answered");
        assert_eq!(hidden, Ret::U16(0), "invis=0 respects INVISB");

        let found = f
            .invoke(onsysn, &[uid.offset, uid.selector, 1])
            .expect("answered");
        assert_eq!(found, Ret::U16(1), "invis=1 (TRUE) waives INVISB outright");
    }

    #[test]
    fn othkey_answers_for_the_channel_instat_last_pointed_at() {
        let mut f = two_channels();
        let chan1 = f.host.users().terms().chan(1).expect("channel 1");
        f.host.users_mut().set_state_mem(f.machine.mem_mut(), chan1, 42).expect("state set");
        f.host.users_mut().set_keys(chan1, crate::KeySet::new(["WCCSYSOP"]));

        // Point `othusn`/`othusp` at channel 1 via `instat`.
        let uid = f.text("kaimon");
        assert_eq!(
            f.invoke(instat, &[uid.offset, uid.selector, 42]).expect("found"),
            Ret::U16(1)
        );
        // `usrnum` is deliberately moved to channel 0 afterwards, so
        // `othusn` (1) and `usrnum` (0) disagree -- `othkey` must answer for
        // channel 1, not whichever channel happens to be current.
        f.invoke(curusr, &[0]).expect("channel 0 current");

        let lock = f.text("WCCSYSOP");
        let got = f
            .invoke(othkey, &Fixture::far(lock))
            .expect("othkey answered");
        assert_eq!(got, Ret::U16(1), "channel 1's own key, not channel 0's (which has none)");

        let lock = f.text("SOMETHINGELSE");
        let got = f
            .invoke(othkey, &Fixture::far(lock))
            .expect("othkey answered");
        assert_eq!(got, Ret::U16(0));
    }

    #[test]
    fn othkey_before_anything_has_run_answers_for_channel_zero() {
        // `othusn` has no "-1 means nobody" convention -- it starts at the
        // zero a genuine uninitialised BSS global would hold, which is
        // channel 0. See `othkey`'s own doc comment.
        let mut f = two_channels();
        let chan0 = f.host.users().terms().chan(0).expect("channel 0");
        f.host.users_mut().set_keys(chan0, crate::KeySet::new(["USER"]));

        let lock = f.text("USER");
        let got = f.invoke(othkey, &Fixture::far(lock)).expect("othkey answered");
        assert_eq!(got, Ret::U16(1), "answered for channel 0, not an error");
    }

    /// `fopen(name, mode)` that must succeed, as the `FILE *` it returned.
    fn opened(f: &mut Fixture, name: &str, mode: &str) -> FarPtr {
        let path = f.text(name);
        let how = f.text(mode);
        let Ret::Far(fp) = f
            .invoke(
                crate::shims::stream::fopen,
                &[path.offset, path.selector, how.offset, how.selector],
            )
            .expect("fopen")
        else {
            panic!("fopen returns a pointer");
        };
        assert_ne!(fp, FarPtr::NULL, "{name} ({mode}) must open");
        fp
    }

    /// `mdfgets(buf, n, fp)`, as the string it left behind, or `None` for
    /// `NULL`.
    fn mdfgets_line(f: &mut Fixture, fp: FarPtr, n: u16) -> Option<Vec<u8>> {
        let buffer = f.bytes(&vec![0xffu8; usize::from(n) + 8], false);
        let ret = f
            .invoke(mdfgets, &[buffer.offset, buffer.selector, n, fp.offset, fp.selector])
            .expect("mdfgets");
        match ret {
            Ret::Far(FarPtr { offset: 0, selector: 0 }) => None,
            Ret::Far(at) => {
                assert_eq!(at, buffer, "mdfgets returns its own first argument");
                Some(f.machine.read_cstr(buffer).expect("terminated").to_vec())
            }
            _ => panic!("expected a far pointer"),
        }
    }

    #[test]
    fn mdfgets_terminates_a_line_with_carriage_return_not_newline() {
        let dir = crate::testing::scratch("mdfgets-newline");
        std::fs::write(dir.join("LINES.DAT"), b"alpha\nbeta\n").expect("scratch file");
        let mut f = Fixture::rooted(dir);
        let fp = opened(&mut f, "LINES.DAT", "rb");

        assert_eq!(mdfgets_line(&mut f, fp, 64).as_deref(), Some(&b"alpha\r"[..]));
        assert_eq!(mdfgets_line(&mut f, fp, 64).as_deref(), Some(&b"beta\r"[..]));
    }

    #[test]
    fn mdfgets_drops_a_carriage_return_rather_than_storing_it() {
        // Binary mode, deliberately: a text-mode stream's own `getc` would
        // already have squeezed this `\r` out before `mdfgets`'s switch ever
        // saw it (see `mdfgets`'s own doc comment on the two being built on
        // the same primitive) -- so only a binary stream actually exercises
        // this function's own `\r` branch rather than `getc`'s.
        let dir = crate::testing::scratch("mdfgets-cr");
        std::fs::write(dir.join("CR.DAT"), b"be\rta\n").expect("scratch file");
        let mut f = Fixture::rooted(dir);
        let fp = opened(&mut f, "CR.DAT", "rb");

        assert_eq!(mdfgets_line(&mut f, fp, 64).as_deref(), Some(&b"beta\r"[..]));
    }

    #[test]
    fn mdfgets_trims_a_control_z_sitting_exactly_at_end_of_file() {
        let dir = crate::testing::scratch("mdfgets-ctrlz-eof");
        std::fs::write(dir.join("EOFCZ.DAT"), b"abc\x1a").expect("scratch file");
        let mut f = Fixture::rooted(dir);
        let fp = opened(&mut f, "EOFCZ.DAT", "rb");

        assert_eq!(mdfgets_line(&mut f, fp, 64).as_deref(), Some(&b"abc"[..]));
    }

    #[test]
    fn mdfgets_does_not_treat_a_mid_line_control_z_specially() {
        // 26 is only special as the LAST byte stored before end-of-file
        // (`buf[i-1] == 26`); anywhere else in the line it is stored like any
        // other byte, per `MDFGETS.C`'s own `default:` arm.
        let dir = crate::testing::scratch("mdfgets-ctrlz-midline");
        std::fs::write(dir.join("MIDCZ.DAT"), b"\x1adropped\n").expect("scratch file");
        let mut f = Fixture::rooted(dir);
        let fp = opened(&mut f, "MIDCZ.DAT", "rb");

        assert_eq!(mdfgets_line(&mut f, fp, 64).as_deref(), Some(&b"\x1adropped\r"[..]));
    }

    #[test]
    fn mdfgets_returns_null_at_true_end_of_file_with_nothing_read() {
        let dir = crate::testing::scratch("mdfgets-empty");
        std::fs::write(dir.join("EMPTY.DAT"), b"").expect("scratch file");
        let mut f = Fixture::rooted(dir);
        let fp = opened(&mut f, "EMPTY.DAT", "rb");

        assert_eq!(mdfgets_line(&mut f, fp, 64), None);
    }

    #[test]
    fn mdfgets_stops_and_terminates_when_the_buffer_runs_out_of_room() {
        let dir = crate::testing::scratch("mdfgets-short-buffer");
        std::fs::write(dir.join("LONG.DAT"), b"abcdefgh\n").expect("scratch file");
        let mut f = Fixture::rooted(dir);
        let fp = opened(&mut f, "LONG.DAT", "rb");

        // size=5 leaves room for 4 bytes plus the terminator -- one short of
        // the `\n` at index 8.
        assert_eq!(mdfgets_line(&mut f, fp, 5).as_deref(), Some(&b"abcd"[..]));
    }

    #[test]
    fn mdfgets_refuses_a_size_with_no_room_for_the_terminator() {
        let mut f = Fixture::new();
        let fp = opened(&mut f, "LINES.TXT", "rb");
        let buffer = f.buffer(8);
        let e = f
            .invoke(mdfgets, &[buffer.offset, buffer.selector, 0, fp.offset, fp.selector])
            .expect_err("a refusal");
        assert!(e.to_string().contains("size of 0"), "{e}");
    }

    #[test]
    fn mdfgets_agrees_with_itself_whether_the_stream_is_binary_or_text_mode() {
        let dir = crate::testing::scratch("mdfgets-mode-agreement");
        std::fs::write(dir.join("PLAIN.DAT"), b"line\r\n").expect("scratch file");
        let mut f = Fixture::rooted(dir);

        let text = opened(&mut f, "PLAIN.DAT", "rt");
        let binary = opened(&mut f, "PLAIN.DAT", "rb");
        assert_eq!(mdfgets_line(&mut f, text, 64), mdfgets_line(&mut f, binary, 64));
    }

    #[test]
    fn dfsthn_is_a_no_op_for_every_status_this_host_can_actually_raise() {
        let mut f = Fixture::new();
        for status in [CMDOK, INBLK, OUTMT, OBFCLR, ABOREQ, CMN2OK, CM25OK, RCVX29, IPXRER, IPXUNK, CYCLE, 251, 252, 253] {
            f.host
                .globals()
                .write_int_mem(f.machine.mem_mut(), "status", status as i32 as u32)
                .expect("status set");
            assert_eq!(f.invoke(dfsthn, &[]).unwrap_or_else(|e| panic!("status {status}: {e}")), Ret::Void);
        }
    }

    #[test]
    fn dfsthn_refuses_a_status_this_host_never_hands_a_module() {
        // Measured unreachable through `Host::poll` (see `dfsthn`'s own doc
        // comment); reached directly here to prove the refusal itself works,
        // not to claim a real dispatch path exercises it.
        let mut f = Fixture::new();
        f.host
            .globals()
            .write_int_mem(f.machine.mem_mut(), "status", 1)
            .expect("status set");
        let e = f.invoke(dfsthn, &[]).expect_err("a refusal");
        assert!(e.to_string().contains("status 1"), "{e}");
    }

    #[test]
    fn echonu_turns_channel_echo_on() {
        let mut f = Fixture::new();
        let console = f.console();
        f.host.gsbl_mut().channel_mut(console).echo = false;

        f.invoke(echonu, &[0]).expect("ok");

        assert!(f.host.gsbl().channel(console).echo, "echonu(usrnum) always turns echo on");
    }

    #[test]
    fn echonu_ends_a_secret_echo_session_once_wid_is_set() {
        // Simulates what `echsec` leaves behind (and see
        // `echsec_installs_a_secret_echo_session`, below, for the same thing
        // proven through the real call rather than poked directly): a
        // nonzero `wid` and the shared `raw` flag turned on for `secchi`.
        // `echonu` is the paired teardown -- both must clear.
        let mut f = Fixture::new();
        let console = f.console();
        f.host
            .users_mut()
            .set_wid_mem(f.machine.mem_mut(), console, 40)
            .expect("wid set");
        f.host.gsbl_mut().channel_mut(console).raw = true;

        f.invoke(echonu, &[0]).expect("ok");

        assert_eq!(
            f.host.users().wid_mem(f.machine.mem(), console).expect("read"),
            0,
            "usrptr->wid=0"
        );
        assert!(!f.host.gsbl().channel(console).raw, "btuchi(usrnum,NULL) uninstalls the handler");
        assert!(f.host.gsbl().channel(console).echo, "echo is still turned on either way");
    }

    #[test]
    fn echonu_leaves_raw_alone_when_no_secret_echo_session_is_active() {
        // `wid` stays at its fresh-channel 0, so the `if (usrptr->wid > 0)`
        // guard must not fire -- and in particular must not clear `raw`,
        // which some *other* consumer (this test stands in for FSD's
        // `fsdcon`) may have turned on for an unrelated reason. A mutant
        // that dropped the `> 0` guard turns this false.
        let mut f = Fixture::new();
        let console = f.console();
        f.host.gsbl_mut().channel_mut(console).raw = true;

        f.invoke(echonu, &[0]).expect("ok");

        assert!(
            f.host.gsbl().channel(console).raw,
            "wid was never set, so echonu must not touch someone else's raw mode"
        );
        assert!(f.host.gsbl().channel(console).echo);
    }

    #[test]
    fn echonu_stops_on_a_channel_that_does_not_exist() {
        let mut f = Fixture::new();
        let past = f.host.users().terms().count();
        assert!(f.invoke(echonu, &[past]).is_err());
    }

    #[test]
    fn echon_turns_echo_on_for_whichever_channel_usrnum_names() {
        // `echon(VOID)` is `echonu(usrnum)` -- it takes no argument of its
        // own and reads the current channel out of the `usrnum` global
        // instead, the same way `getin`/`haskey` do.
        let mut f = Fixture::new();
        let console = f.console();
        f.invoke(curusr, &[0]).expect("channel 0 is current");
        f.host.gsbl_mut().channel_mut(console).echo = false;

        f.invoke(echon, &[]).expect("ok");

        assert!(f.host.gsbl().channel(console).echo, "echon() always turns echo on");
    }

    #[test]
    fn echon_stops_when_usrnum_names_no_channel() {
        // `usrnum` is -1 for as long as nobody is on a channel -- the same
        // sentinel `haskey`'s own doc comment already names.
        let mut f = Fixture::new();
        f.host
            .globals()
            .write(&mut f.machine, "usrnum", &(-1i16).to_le_bytes())
            .expect("usrnum is placed");

        assert!(f.invoke(echon, &[]).is_err());
    }

    #[test]
    fn echsec_installs_a_secret_echo_session() {
        // `MAJORBBS.C:4558`: `btuech(usrnum,0)`, `col=0`,
        // `wid=max(1,min(255,lwidth))`, `ech=ech`, `btuchi(usrnum,secchi)`.
        let mut f = Fixture::new();
        let console = f.console();
        f.invoke(curusr, &[0]).expect("channel 0 is current");
        f.host.gsbl_mut().channel_mut(console).echo = true;
        f.host
            .users_mut()
            .set_col_mem(f.machine.mem_mut(), console, 9)
            .expect("nonzero col before the call");

        f.invoke(echsec, &[b'*' as u16, 40]).expect("ok");

        assert!(!f.host.gsbl().channel(console).echo, "btuech(usrnum,0) turns echo off");
        assert_eq!(f.host.users().col_mem(f.machine.mem(), console).expect("read"), 0);
        assert_eq!(f.host.users().wid_mem(f.machine.mem(), console).expect("read"), 40);
        assert_eq!(f.host.users().ech_mem(f.machine.mem(), console).expect("read"), b'*');
        assert!(
            f.host.gsbl().channel(console).raw,
            "btuchi(usrnum,secchi) installs a handler -- see echsec's own doc comment for the collapse"
        );
    }

    #[test]
    fn echsec_clamps_lwidth_to_one_through_two_hundred_fifty_five() {
        let mut f = Fixture::new();
        let console = f.console();
        f.invoke(curusr, &[0]).expect("channel 0 is current");

        f.invoke(echsec, &[b'*' as u16, 0]).expect("ok");
        assert_eq!(
            f.host.users().wid_mem(f.machine.mem(), console).expect("read"),
            1,
            "max(1, min(255, 0)) == 1"
        );

        f.invoke(echsec, &[b'*' as u16, 9000]).expect("ok");
        assert_eq!(
            f.host.users().wid_mem(f.machine.mem(), console).expect("read"),
            255,
            "max(1, min(255, 9000)) == 255"
        );

        f.invoke(echsec, &[b'*' as u16, -5i16 as u16]).expect("ok");
        assert_eq!(
            f.host.users().wid_mem(f.machine.mem(), console).expect("read"),
            1,
            "max(1, min(255, -5)) == 1"
        );
    }

    #[test]
    fn echsec_reads_ech_as_a_byte_not_a_checked_small_int() {
        // `CHAR ech` is promoted to `int` at the call site -- Borland's plain
        // `char` is signed, so a byte like 0xFF (a real, if unusual,
        // masking character) arrives sign-extended. The low byte survives
        // either extension untouched, so a truncating cast is the right
        // reading; a `u8`-checked reader like `shims::gsbl`'s `u8_arg` would
        // wrongly refuse it.
        let mut f = Fixture::new();
        let console = f.console();
        f.invoke(curusr, &[0]).expect("channel 0 is current");

        f.invoke(echsec, &[0xFFu16, 10]).expect("ok");
        assert_eq!(f.host.users().ech_mem(f.machine.mem(), console).expect("read"), 0xFF);
    }

    #[test]
    fn echsec_stops_when_usrnum_names_no_channel() {
        let mut f = Fixture::new();
        f.host
            .globals()
            .write(&mut f.machine, "usrnum", &(-1i16).to_le_bytes())
            .expect("usrnum is placed");

        assert!(f.invoke(echsec, &[b'*' as u16, 40]).is_err());
    }

    // ---- swtcls -----------------------------------------------------------

    fn read_field(f: &Fixture, uacc: FarPtr, offset: u16, len: usize) -> Vec<u8> {
        let at = FarPtr { offset: uacc.offset + offset, selector: uacc.selector };
        f.machine.resolve(at, len).expect("field readable").to_vec()
    }

    fn write_field(f: &mut Fixture, uacc: FarPtr, offset: u16, bytes: &[u8]) {
        let at = FarPtr { offset: uacc.offset + offset, selector: uacc.selector };
        f.machine.write(at, bytes).expect("field writable");
    }

    fn cstr_field(f: &Fixture, uacc: FarPtr, offset: u16) -> Vec<u8> {
        let raw = read_field(f, uacc, offset, KEYSIZ);
        raw.split(|&b| b == 0).next().expect("at least one segment").to_vec()
    }

    #[test]
    fn swtcls_changes_curcls_and_leaves_prmcls_alone_when_makprm_is_zero() {
        let mut f = Fixture::new();
        let console = f.console();
        let uacc = f.host.users().account(console);
        write_field(&mut f, uacc, PRMCLS, b"NORMAL\0");
        write_field(&mut f, uacc, CURCLS, b"NORMAL\0");

        let cls = f.text("SYSOP");
        f.invoke(swtcls, &[uacc.offset, uacc.selector, 0, cls.offset, cls.selector, 3, 0])
            .expect("swtcls");

        assert_eq!(cstr_field(&f, uacc, CURCLS), b"SYSOP");
        // The mutation this task's own plan called out by name: a shim that
        // ignores `makprm` and always writes `prmcls` too would pass a test
        // that only checks `curcls`. `prmcls` must still read "NORMAL".
        assert_eq!(
            cstr_field(&f, uacc, PRMCLS),
            b"NORMAL",
            "makprm==0 must not touch prmcls"
        );
    }

    #[test]
    fn swtcls_with_makprm_also_sets_prmcls_and_resets_fgvdys() {
        let mut f = Fixture::new();
        let console = f.console();
        let uacc = f.host.users().account(console);
        write_field(&mut f, uacc, PRMCLS, b"NORMAL\0");
        write_field(&mut f, uacc, CURCLS, b"NORMAL\0");
        write_field(&mut f, uacc, FGVDYS, &99u16.to_le_bytes());

        let cls = f.text("SYSOP");
        f.invoke(swtcls, &[uacc.offset, uacc.selector, 1, cls.offset, cls.selector, 3, 0])
            .expect("swtcls");

        assert_eq!(cstr_field(&f, uacc, CURCLS), b"SYSOP");
        assert_eq!(cstr_field(&f, uacc, PRMCLS), b"SYSOP", "makprm==1 must also set prmcls");
        assert_eq!(
            u16::from_le_bytes(read_field(&f, uacc, FGVDYS, 2).try_into().unwrap()),
            0,
            "makprm==1 resets fgvdys"
        );
    }

    #[test]
    fn swtcls_refuses_a_class_name_too_long_for_keysiz() {
        let mut f = Fixture::new();
        let console = f.console();
        let uacc = f.host.users().account(console);
        // 15 bytes + NUL is exactly KEYSIZ and must fit; 16 bytes + NUL does
        // not.
        let name16 = "A".repeat(16);
        assert_eq!(name16.len(), 16);
        let cls = f.text(&name16);
        let err = f
            .invoke(swtcls, &[uacc.offset, uacc.selector, 0, cls.offset, cls.selector, 3, 0])
            .expect_err("a name that does not fit KEYSIZ must refuse, not overflow into timtdy");
        assert!(err.to_string().contains("swtcls"), "{err}");
    }

    #[test]
    fn swtcls_accepts_a_class_name_that_exactly_fills_keysiz() {
        let mut f = Fixture::new();
        let console = f.console();
        let uacc = f.host.users().account(console);
        let name15 = "B".repeat(15);
        assert_eq!(name15.len() + 1, KEYSIZ, "the boundary this test exists to hit");
        let cls = f.text(&name15);
        f.invoke(swtcls, &[uacc.offset, uacc.selector, 0, cls.offset, cls.selector, 3, 0])
            .expect("exactly KEYSIZ bytes including the terminator must fit");
        assert_eq!(cstr_field(&f, uacc, CURCLS), name15.as_bytes());
    }

    // ---- extoff -------------------------------------------------------------

    #[test]
    fn extoff_returns_the_channels_extra_pointer() {
        let mut f = Fixture::new();
        let console = f.console();
        let Ret::Far(at) = f.invoke(extoff, &[0]).expect("extoff") else {
            panic!("extoff returns a far pointer");
        };
        assert_eq!(
            at,
            f.host.users().extra(console).expect("Wg16 is GCV2, extusr exists"),
            "extoff(0) must be the same slot Users::extra(chan 0) is"
        );
    }

    #[test]
    fn extoff_reads_the_channel_the_argument_names_not_channel_zero() {
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(2));
        let one = f.host.gsbl().terms().chan(1).expect("channel 1");
        let Ret::Far(at) = f.invoke(extoff, &[1]).expect("extoff(1)") else {
            panic!("extoff returns a far pointer");
        };
        assert_eq!(at, f.host.users().extra(one).expect("extusr exists"));
        assert_ne!(at, f.host.users().account(one), "extusr is a different table from usracc");
    }

    #[test]
    fn extoff_refuses_a_channel_that_does_not_exist() {
        let mut f = Fixture::new();
        assert!(f.invoke(extoff, &[99]).is_err());
    }

    // ---- paccit -------------------------------------------------------------

    #[test]
    fn paccit_does_not_stop_the_module() {
        let mut f = Fixture::new();
        f.invoke(curusr, &[0]).expect("channel 0 is current");
        f.invoke(paccit, &[]).expect("paccit does not stop the machine");
    }

    #[test]
    fn paccit_touches_no_global_this_host_can_observe() {
        // A faithful no-op, not a silent gap papered over with an invented
        // side effect: pfnlvl (the one piece of dftpfn's work this host
        // *could* place a value at) must come back exactly as it went in,
        // proving nothing here fabricates a profanity score it cannot
        // actually compute.
        let mut f = Fixture::new();
        f.invoke(curusr, &[0]).expect("channel 0 is current");
        f.host
            .globals()
            .write(&mut f.machine, "pfnlvl", &7u16.to_le_bytes())
            .expect("pfnlvl is placed");

        f.invoke(paccit, &[]).expect("paccit");

        assert_eq!(f.host.globals().word(&f.machine, "pfnlvl").expect("pfnlvl"), 7);
    }

    // ---- samepatu -----------------------------------------------------------

    #[test]
    fn samepatu_exact_true_only_on_a_full_match() {
        let mut f = Fixture::new();
        let a = f.text("sau:irccfg");
        let b = f.text("sau:irccfg");
        let got = f
            .invoke(samepatu, &[a.offset, a.selector, b.offset, b.selector, 1])
            .expect("samepatu");
        assert_eq!(got, Ret::U16(1));
    }

    #[test]
    fn samepatu_exact_false_on_a_prefix_that_is_not_a_full_match() {
        let mut f = Fixture::new();
        let a = f.text("sau:");
        let b = f.text("sau:irccfg");
        let got = f
            .invoke(samepatu, &[a.offset, a.selector, b.offset, b.selector, 1])
            .expect("samepatu");
        assert_eq!(got, Ret::U16(0), "exact=TRUE must not accept a mere prefix");
    }

    #[test]
    fn samepatu_not_exact_true_when_the_first_string_prefixes_the_second() {
        // samepato(shorts,longs) == samepatu(shorts,longs,FALSE) --
        // GCSPSRV.H's own macro names: the first argument is the shorter
        // prefix, the second the string it must start.
        let mut f = Fixture::new();
        let shorts = f.text("sau:");
        let longs = f.text("sau:irccfg");
        let got = f
            .invoke(samepatu, &[shorts.offset, shorts.selector, longs.offset, longs.selector, 0])
            .expect("samepatu");
        assert_eq!(got, Ret::U16(1));
    }

    #[test]
    fn samepatu_not_exact_false_when_the_first_string_does_not_prefix_the_second() {
        let mut f = Fixture::new();
        let shorts = f.text("sauf:");
        let longs = f.text("sau:irccfg");
        let got = f
            .invoke(samepatu, &[shorts.offset, shorts.selector, longs.offset, longs.selector, 0])
            .expect("samepatu");
        assert_eq!(got, Ret::U16(0));
    }

    #[test]
    fn samepatu_is_case_sensitive() {
        // Recorded uncertainty, exercised rather than left implicit: no
        // surviving body confirms this, but every real call site compares
        // fixed protocol literals, never user input -- see this function's
        // own doc comment.
        let mut f = Fixture::new();
        let a = f.text("sau:IRCCFG");
        let b = f.text("sau:irccfg");
        let got = f
            .invoke(samepatu, &[a.offset, a.selector, b.offset, b.selector, 1])
            .expect("samepatu");
        assert_eq!(got, Ret::U16(0), "differently-cased tokens must not match");
    }

    /// `mnuoff` refuses and names the subsystem it would need.
    ///
    /// The message matters more than the failure: a refusal that only said
    /// "cannot" would be indistinguishable from a bad channel number, and the
    /// point is that `muusrs` was never built. Asserting on the text is the
    /// difference between a test that pins the reason and one that passes for
    /// a pointer error too.
    #[test]
    fn mnuoff_refuses_and_names_the_menuing_subsystem() {
        let mut f = Fixture::new();
        let err = f.invoke(mnuoff, &[0]).expect_err("there is no menuing system");
        let message = err.to_string();
        assert!(message.contains("muusrs"), "{message}");
        assert!(message.contains("usrmnu"), "{message}");
    }
}
