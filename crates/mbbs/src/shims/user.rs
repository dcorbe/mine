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

use mbbs16::{Machine, Ret};

use super::ShimError;
use crate::Host;

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
pub fn uacoff(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let unum = machine.arg_u16(0) as i16;
    let at = host
        .users()
        .account(unum)
        .ok_or_else(|| ShimError::Failed(format!("uacoff({unum}): there is no such channel")))?;
    Ok(Ret::Far(at))
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
pub fn curusr(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let uno = machine.arg_u16(0) as i16;
    if host.users().slot(uno).is_none() {
        host.note_once(
            "curusr",
            format!("curusr({uno}): there is no such channel, so nothing changed"),
        );
        return Ok(Ret::Void);
    }
    host.point_curusr(machine, uno)?;
    Ok(Ret::Void)
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
pub fn getin(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let chan = host
        .globals()
        .word(machine, "usrnum")
        .map_err(|e| ShimError::Failed(e.to_string()))? as i16;
    let margv0 = host.get_input(machine, chan)?;
    Ok(Ret::Far(margv0))
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
/// config data. This shim does not: it takes `&Machine`, folds a host-side
/// copy, and leaves module memory alone. Three reasons, recorded because this
/// is the first place this crate is knowingly unfaithful to a measured byte.
///
/// It is unobservable to this module: those lock strings live in a table at
/// `seg 0x1258` and reach `haskey` and nothing else -- no `prf`, no `strcpy`,
/// no comparison. It is not consistent even in the original, because
/// `flags&MASTER` returns before `lockbit` is reached, so a master-flagged
/// user's lock strings never get uppercased at all. And writing into a
/// module's static data from a predicate is a side effect nobody would design
/// on purpose; it is C's in-place API leaking through an interface that is
/// otherwise pure.
pub fn haskey(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let lock = machine.read_cstr(machine.arg_far(0))?.to_vec();
    let lock = String::from_utf8_lossy(&lock);
    // `globals()` reports `io::Error` and `ShimError` has no `From` for it, so
    // the map_err is the house pattern here -- see `shims/fsd.rs:72`.
    let unum = host
        .globals()
        .word(machine, "usrnum")
        .map_err(|e| ShimError::Failed(format!("haskey: usrnum: {e}")))? as i16;

    let answer = match host.users().keys(unum) {
        Some(keys) => keys.evaluate(&lock),
        // `LOCKNKEY.C:194`. Two cases arrive here and they are not the same
        // one, which is why this is not a bare `false`:
        None => match host.users().slot(unum) {
            // A channel that exists but never logged on -- `keys == NULL`.
            // Answered by class, and `usrcls` is 0 here, so it refuses; the
            // comparison is written out rather than folded away so that it
            // starts telling the truth on its own the day this host grows an
            // internal channel.
            Some(_) => host.class(machine, unum)? == BBSPRV,
            // No such channel. `usrnum` is -1 for as long as nobody is on one
            // (`MAJORBBS.C:740`'s sentinels exist for exactly that value), and
            // there is nobody to hold a key. **Not** an error: asking
            // `Host::class` here would stop the module over a state the real
            // host was in whenever the board was idle.
            None => false,
        },
    };
    host.asked_for_key(unum, &lock, answer);
    Ok(Ret::U16(answer.into()))
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
        let Ret::Far(at) = f.invoke(uacoff, &[0]).expect("channel 0") else {
            panic!("uacoff returns a pointer");
        };
        assert_eq!(at, f.host.users().account(0).expect("channel 0"));
    }

    #[test]
    fn uacoff_stops_the_module_on_a_channel_that_does_not_exist() {
        // `ptrblok` had no bound and would have returned the bytes after the
        // last record. The module would then have keyed a Btrieve read on them.
        // There is no answer here that is not a lie, so the module stops.
        let mut f = Fixture::new();
        assert!(f.invoke(uacoff, &[-1i16 as u16]).is_err());
        let past = f.host.users().terms();
        assert!(f.invoke(uacoff, &[past]).is_err());
    }

    #[test]
    fn curusr_repoints_every_global_that_names_the_current_channel() {
        let mut f = Fixture::new();
        f.invoke(curusr, &[0]).expect("channel 0");

        let g = f.host.globals();
        assert_eq!(g.word(&f.machine, "usrnum").expect("usrnum") as i16, 0);
        assert_eq!(
            g.pointer(&f.machine, "usrptr").expect("usrptr"),
            f.host.users().slot(0).expect("channel 0")
        );
        assert_eq!(
            g.pointer(&f.machine, "usaptr").expect("usaptr"),
            f.host.users().account(0).expect("channel 0")
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
        f.invoke(curusr, &[0]).expect("channel 0");
        assert_eq!(
            f.host.globals().pointer(&f.machine, "vdaptr").expect("vdaptr"),
            mbbs16::FarPtr::NULL
        );

        f.invoke(crate::shims::system::dclvda, &[256]).expect("declared");
        f.host.alcvda(&mut f.machine).expect("allocated");
        f.invoke(curusr, &[0]).expect("channel 0 again");
        assert_eq!(
            f.host.globals().pointer(&f.machine, "vdaptr").expect("vdaptr"),
            f.host.users().vda(0).expect("channel 0")
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
        f.invoke(curusr, &[0]).expect("channel 0");
        f.host.gsbl_mut().push_input(0, b"get all gold\r");

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
        assert_ne!(margv0, mbbs16::FarPtr::NULL);
        assert_eq!(f.machine.read_cstr(margv0).expect("readable"), b"");
    }

    #[test]
    fn haskey_answers_for_the_channel_usrnum_names() {
        let mut f = crate::testing::Fixture::new();
        f.host
            .connect_state(
                &mut f.machine,
                0,
                &crate::Connection::ansi("rangerdan").with_keys(["USER"]),
            )
            .expect("channel 0");

        let lock = f.text("USER");
        let got = f
            .invoke(super::haskey, &crate::testing::Fixture::far(lock))
            .expect("answered");
        assert_eq!(got, mbbs16::Ret::U16(1));

        let lock = f.text("WCCSYSOP");
        let got = f
            .invoke(super::haskey, &crate::testing::Fixture::far(lock))
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
            .invoke(super::haskey, &crate::testing::Fixture::far(lock))
            .expect("answered");
        assert_eq!(got, mbbs16::Ret::U16(0), "not 1 -- the null check comes first");
    }

    #[test]
    fn haskey_refuses_when_no_channel_is_current() {
        // `usrnum` is -1 for as long as nobody is on a channel. There is no
        // keyring to consult and the answer is 0, not a panic and not a stop.
        let mut f = crate::testing::Fixture::new();
        f.host
            .globals()
            .write(&mut f.machine, "usrnum", &(-1i16).to_le_bytes())
            .expect("usrnum is placed");

        let lock = f.text("USER");
        let got = f
            .invoke(super::haskey, &crate::testing::Fixture::far(lock))
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
        f.host
            .connect_state(
                &mut f.machine,
                0,
                &crate::Connection::ansi("rangerdan").with_keys(["USER"]),
            )
            .expect("channel 0");

        let lock = f.text("USER|WCCSYSOP");
        let got = f
            .invoke(super::haskey, &crate::testing::Fixture::far(lock))
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
        f.host
            .connect_state(
                &mut f.machine,
                0,
                &crate::Connection::ansi("rangerdan").with_keys(["USER"]),
            )
            .expect("channel 0");

        let lock = f.text("user");
        let got = f
            .invoke(super::haskey, &crate::testing::Fixture::far(lock))
            .expect("answered");
        assert_eq!(got, mbbs16::Ret::U16(1), "matched case-insensitively");
        assert_eq!(f.read(lock), "user", "and left the module's string alone");
    }
}
