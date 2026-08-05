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
pub fn curusr(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let uno = machine.arg_u16(0) as i16;
    let Some(slot) = host.users().slot(uno) else {
        host.note_once(
            "curusr",
            format!("curusr({uno}): there is no such channel, so nothing changed"),
        );
        return Ok(Ret::Void);
    };
    let account = host
        .users()
        .account(uno)
        .expect("in range, so it has a record");
    let vda = host.users().vda(uno).unwrap_or(mbbs16::FarPtr::NULL);

    let globals = host.globals();
    let mut set = |name: &str, bytes: &[u8]| {
        globals
            .write(machine, name, bytes)
            .map_err(|e| ShimError::Failed(format!("curusr: {e}")))
    };
    set("usrnum", &uno.to_le_bytes())?;
    set("usrptr", &slot.to_bytes())?;
    set("usaptr", &account.to_bytes())?;
    set("vdaptr", &vda.to_bytes())?;
    Ok(Ret::Void)
}

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
}
