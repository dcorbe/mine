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
    let lock = String::from_utf8_lossy(&lock);
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
            Some(keys) => keys.evaluate(&lock),
            // A channel that exists but never logged on -- `keys == NULL`.
            // Answered by class, and `usrcls` is 0 here, so it refuses; the
            // comparison is written out rather than folded away so that it
            // starts telling the truth on its own the day this host grows an
            // internal channel.
            None => host.class_mem(call.mem(), chan)? == BBSPRV,
        },
    };
    host.asked_for_key(unum, &lock, answer);
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
    let invis = Into::<u32>::into(call.int()) != 0;
    let uid = uid
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    let found = scan_for(call, host, invis, |call, host, chan| {
        let usrcls = host.users().usrcls_mem(call.mem(), chan)?;
        if usrcls <= SUPIPG {
            return Ok(false);
        }
        userid_matches(call, host, chan, &uid)
    })?;

    Ok(abi::Ret::Int(A::Int::from(u16::from(found))))
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
    let lock = lock
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let lock = String::from_utf8_lossy(&lock);

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
        // `low_haskey`'s `keys == NULL` case, same as `haskey`'s own: a
        // channel that exists but never logged on is answered by class.
        None => host.class_mem(call.mem(), chan)? == BBSPRV,
    };
    host.asked_for_key(othusn, &lock, answer);
    Ok(abi::Ret::Int(A::Int::from(answer as u16)))
}

/// `GBOOL samend(const CHAR *longs, const CHAR *ends)` -- does `longs` end
/// with `ends`?
///
/// `GCOMM.H:387` / `re/wg33src/SRC/api/gcommlib/SAMEND.C`:
///
///
/// `ends` longer than `longs` is `FALSE` outright -- the `<=` is what guards
/// the subtraction it gates from wrapping, which is also why this reads both
/// lengths and compares them before ever slicing, rather than trusting
/// `checked_sub`/`saturating_sub` to paper over the case that guard exists
/// for.
///
/// [`crate::strings::sameas`] does the tail comparison -- the same routine
/// [`sameas`](crate::shims::text::sameas)'s own shim calls; see that
/// function's doc comment for why a second implementation of the fold does
/// not exist here.
///
/// # Errors
///
/// If either string cannot be read.
pub fn samend<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let longs = call.ptr();
    let ends = call.ptr();
    let longs = longs
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let ends = ends
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    let answer =
        ends.len() <= longs.len() && crate::strings::sameas(&ends, &longs[longs.len() - ends.len()..]);
    Ok(abi::Ret::Int(A::Int::from(u16::from(answer))))
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

    // ---- instat/onsysn/othkey/samend/mdfgets/dfsthn -----------------------

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

    #[test]
    fn samend_is_true_when_ends_matches_the_tail_case_insensitively() {
        let mut f = Fixture::new();
        let longs = f.text("/ANSI/lunatix");
        let ends = f.text("/lunatix");
        let got = f
            .invoke(samend, &[longs.offset, longs.selector, ends.offset, ends.selector])
            .expect("answered");
        assert_eq!(got, Ret::U16(1));

        let ends = f.text("/LUNATIX");
        let got = f
            .invoke(samend, &[longs.offset, longs.selector, ends.offset, ends.selector])
            .expect("answered");
        assert_eq!(got, Ret::U16(1), "sameas -- case-insensitive");
    }

    #[test]
    fn samend_is_false_when_ends_is_longer_than_longs() {
        let mut f = Fixture::new();
        let longs = f.text("hi");
        let ends = f.text("hi there");
        let got = f
            .invoke(samend, &[longs.offset, longs.selector, ends.offset, ends.selector])
            .expect("answered");
        assert_eq!(got, Ret::U16(0), "the `<=` guard, not a wrapped subtraction");
    }

    #[test]
    fn samend_is_false_when_the_tail_does_not_match() {
        let mut f = Fixture::new();
        let longs = f.text("/ANSI/lunatix");
        let ends = f.text("/majormud");
        let got = f
            .invoke(samend, &[longs.offset, longs.selector, ends.offset, ends.selector])
            .expect("answered");
        assert_eq!(got, Ret::U16(0));
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
}
