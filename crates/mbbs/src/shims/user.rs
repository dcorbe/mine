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
use mbbs16::{Machine, Ret};
use mbbs_ptr::ModulePtr;

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

/// The dispatch-table entry for [`uacoff`]: builds a [`Call<Wg16>`] over the
/// outstanding call's frame and converts its `abi::Ret<Wg16>` back into
/// `mbbs16::Ret`. See `shims::call`'s own doc comment.
#[cfg(test)]
pub fn uacoff_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    uacoff(&mut super::call(machine), host).map(Into::into)
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

/// The dispatch-table entry for [`curusr`]. See `shims::call`'s own doc
/// comment.
#[cfg(test)]
pub fn curusr_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    curusr(&mut super::call(machine), host).map(Into::into)
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

/// The dispatch-table entry for [`getin`]. See `shims::call`'s own doc
/// comment.
#[cfg(test)]
pub fn getin_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    getin(&mut super::call(machine), host).map(Into::into)
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

/// The dispatch-table entry for [`haskey`]. See `shims::call`'s own doc
/// comment.
#[cfg(test)]
pub fn haskey_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    haskey(&mut super::call(machine), host).map(Into::into)
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

/// The dispatch-table entry for [`begin_polling`]. See `shims::call`'s own
/// doc comment.
#[cfg(test)]
pub fn begin_polling_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    begin_polling(&mut super::call(machine), host).map(Into::into)
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

/// The dispatch-table entry for [`stop_polling`]. See `shims::call`'s own
/// doc comment.
#[cfg(test)]
pub fn stop_polling_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    stop_polling(&mut super::call(machine), host).map(Into::into)
}

/// `BBSPRV`, `MAJORBBS.H:163` -- online, private class, internal to the host.
const BBSPRV: u16 = 2;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;

    #[test]
    fn uacoff_hands_back_the_channels_account_record() {
        let mut f = Fixture::new();
        let console = f.console();
        let Ret::Far(at) = f.invoke(uacoff_wg16, &[0]).expect("channel 0") else {
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
        assert!(f.invoke(uacoff_wg16, &[-1i16 as u16]).is_err());
        let past = f.host.users().terms().count();
        assert!(f.invoke(uacoff_wg16, &[past]).is_err());
    }

    #[test]
    fn curusr_repoints_every_global_that_names_the_current_channel() {
        let mut f = Fixture::new();
        let console = f.console();
        f.invoke(curusr_wg16, &[0]).expect("channel 0");

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
        f.invoke(curusr_wg16, &[0]).expect("channel 0");
        assert_eq!(
            f.host.globals().pointer(&f.machine, "vdaptr").expect("vdaptr"),
            mbbs16::FarPtr::NULL
        );

        f.invoke(crate::shims::system::dclvda_wg16, &[256]).expect("declared");
        f.host.alcvda(&mut f.machine).expect("allocated");
        f.invoke(curusr_wg16, &[0]).expect("channel 0 again");
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
        f.invoke(curusr_wg16, &[0]).expect("channel 0");
        let before = f.host.globals().pointer(&f.machine, "usrptr").expect("usrptr");

        f.invoke(curusr_wg16, &[-1i16 as u16]).expect("a no-op, not an error");
        assert_eq!(f.host.globals().word(&f.machine, "usrnum").expect("usrnum") as i16, 0);
        assert_eq!(f.host.globals().pointer(&f.machine, "usrptr").expect("usrptr"), before);
    }

    #[test]
    fn a_curusr_that_did_nothing_is_recorded_rather_than_silent() {
        // The one place this crate lets a routine decline without stopping the
        // module. A run where it happened must be tellable from one where it
        // did not.
        let mut f = Fixture::new();
        f.invoke(curusr_wg16, &[99]).expect("a no-op");
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
        f.invoke(curusr_wg16, &[0]).expect("channel 0");
        f.host.gsbl_mut().push_input(console, b"get all gold\r");

        let Ret::Far(margv0) = f.invoke(getin_wg16, &[]).expect("ok") else {
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
        f.invoke(curusr_wg16, &[0]).expect("channel 0");

        let Ret::Far(margv0) = f.invoke(getin_wg16, &[]).expect("ok") else {
            panic!("getin returns char *margv[0]");
        };
        assert_eq!(f.host.globals().word(&f.machine, "margc").expect("margc"), 0);
        assert_ne!(margv0, mbbs16::FarPtr::NULL);
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
            .invoke(super::haskey_wg16, &crate::testing::Fixture::far(lock))
            .expect("answered");
        assert_eq!(got, mbbs16::Ret::U16(1));

        let lock = f.text("WCCSYSOP");
        let got = f
            .invoke(super::haskey_wg16, &crate::testing::Fixture::far(lock))
            .expect("answered");
        assert_eq!(got, mbbs16::Ret::U16(0));
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
            .invoke(super::haskey_wg16, &crate::testing::Fixture::far(lock))
            .expect("answered");
        assert_eq!(got, mbbs16::Ret::U16(0), "not 1 -- the null check comes first");
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
            .invoke(super::haskey_wg16, &crate::testing::Fixture::far(lock))
            .expect("answered");
        assert_eq!(got, mbbs16::Ret::U16(0));
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
            .invoke(super::haskey_wg16, &crate::testing::Fixture::far(lock))
            .expect("answered");
        assert_eq!(got, mbbs16::Ret::U16(1));
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
            .invoke(super::haskey_wg16, &crate::testing::Fixture::far(lock))
            .expect("answered");
        assert_eq!(got, mbbs16::Ret::U16(1), "matched case-insensitively");
        assert_eq!(f.read(lock), "user", "and left the module's string alone");
    }

    /// `MAJORBBS.C:1183`. The status is what makes the channel tick; the store
    /// is what makes it tick *into the right routine*.
    #[test]
    fn begin_polling_installs_the_routine_and_injects_one_status() {
        let mut f = Fixture::new();
        let console = f.console();
        let rou = f.machine.code_ptr(0);

        f.invoke(begin_polling_wg16, &[0, rou.offset, rou.selector])
            .expect("installed");

        assert_eq!(
            f.host.users().polrou(&f.machine, console).expect("channel 0"),
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

        f.invoke(begin_polling_wg16, &[0, rou.offset, rou.selector])
            .expect("installed");

        assert_eq!(
            f.host.users().polrou(&f.machine, console).expect("channel 0"),
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

        f.invoke(begin_polling_wg16, &[0, first.offset, first.selector])
            .expect("installed");
        assert_eq!(f.host.gsbl_mut().next_status(console), Some(crate::gsbl::Gsbl::POLSTS));

        f.invoke(begin_polling_wg16, &[0, second.offset, second.selector])
            .expect("replaced");

        assert_eq!(
            f.host.users().polrou(&f.machine, console).expect("channel 0"),
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
        f.invoke(begin_polling_wg16, &[0, rou.offset, rou.selector])
            .expect("installed");
        let _ = f.host.gsbl_mut().next_status(console);

        f.invoke(stop_polling_wg16, &[0]).expect("stopped");

        assert_eq!(
            f.host.users().polrou(&f.machine, console).expect("channel 0"),
            None
        );
        assert_eq!(f.host.gsbl_mut().next_status(console), None);
    }

    #[test]
    fn polling_a_channel_that_does_not_exist_is_refused() {
        let mut f = Fixture::new();
        let rou = f.machine.code_ptr(0);
        assert!(
            f.invoke(begin_polling_wg16, &[1, rou.offset, rou.selector])
                .is_err(),
            "nterms is 1, so channel 1 does not exist"
        );
        assert!(f.invoke(stop_polling_wg16, &[1]).is_err());
    }

    /// All nine call sites pass a real pointer, and the one computed pointer
    /// (`WCCMMUD_named.c:11831`) carries a fixed non-zero selector, so a whole
    /// NULL here is a module bug rather than a compact `stop_polling`.
    #[test]
    fn a_null_polling_routine_is_refused_rather_than_installed() {
        let mut f = Fixture::new();
        let console = f.console();
        assert!(f.invoke(begin_polling_wg16, &[0, 0, 0]).is_err());
        assert_eq!(
            f.host.gsbl_mut().next_status(console),
            None,
            "and nothing is injected on the way out"
        );
    }
}
