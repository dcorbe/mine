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
}
