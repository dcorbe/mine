//! Billing, and this host's decision not to do any.
//!
//! ```text
//! otstcrd 3   odedcrd 3
//! ```
//!
//! MajorBBS metered paying customers. `struct usracc` carries a `creds` balance
//! (`USRACC.H:52`, "credits available or debt (if negative)"), a class table
//! carries a debt limit, and modules charge against both. `WCCMMUD.DLL` imports
//! two of the thirteen routines that family exposes.
//!
//! **This host answers both unconditionally: every user can spare it, and every
//! deduction succeeds.** Nothing here keeps a balance, and nothing here is going
//! to. The goal is running a module headless
//! (`docs/plans/2026-08-03-16bit-module-execution.md`, "Scope"); a credit
//! ledger is a billing system for a business that has not existed since the
//! nineties, and a host that faked one would have to invent the class table,
//! the debt limits and the rates that make its answers mean anything.
//!
//! That is a *decision*, not an omission, which is why it is a module of its own
//! rather than two functions filed next to `uacoff`. It is also the one place
//! this crate deliberately answers a question it has not computed -- everywhere
//! else, a shim that cannot answer stops the module rather than returning a
//! plausible zero (`shims/mod.rs`). The difference is that "yes" here is a
//! complete answer to what the module asked, and the same one a real board gave
//! any account whose class carried `CRDXMT` (credit-exempt, `USRACC.H:124`).
//!
//! # What the module does with the answers
//!
//! Five call sites, and they divide cleanly. `re/ne_arity.py` measures three
//! for each ordinal; two of `otstcrd`'s and three of `odedcrd`'s have a
//! decompiled form, and `otstcrd`'s third does not.
//!
//! | Where | Call | On zero |
//! |---|---|---|
//! | `seg 3:0x6049` | `otstcrd(usrnum, DS:[0x16], 0)` | bounced back to the pre-game menu |
//! | `_SLOW_UPDATE_CHARACTER` (`:19203`) | `otstcrd(unum, DS:[0x16], 0)` | saved, four "out of credits" lines, `stop_polling`, ejected |
//! | `_DEDUCT_EXEMPT_CREDITS` (`:19287`) | `odedcrd(unum, DS:[0x18], 1, 1)` | the same ejection |
//! | `_BORROW_GOLD` (`:6261`/`:6264`) | `otstcrd(unum, amt, 1)` then `odedcrd` | the loan is refused |
//! | `_REPAY_GOLD` (`:6322`) | `odedcrd(unum, -amt, ..)` | ignored |
//!
//! The first of those is why this exists: `E`, sent as a channel's second
//! command, walks eight host calls past `stop_polling` and stops on `otstcrd`.
//! Answering it is what lets the module past the paywall and into the realm.
//!
//! **`_BORROW_GOLD` is the one place this leaks into the game rather than out of
//! the billing system.** The bank sells in-game gold for BBS credits at a
//! configured rate (`re/docs/economy.md` §7.1), so a host with infinite credits
//! is a host whose bank lends without limit. That is a consequence of the
//! decision above, recorded rather than hidden: there is no answer here that
//! both skips billing and keeps the bank honest, because the bank's price *is*
//! the billing system.
//!
//! # Where the definitions come from
//!
//! `ACCOUNT.C`, not `MAJORBBS.C`, and declared in `USRACC.H` rather than
//! `MAJORBBS.H` -- the recovered WG 1.0, WG 2.0 and MBBS 6.25 kits carry
//! identical code. Both are one-line wrappers around a low-level form:
//!
//!
//! Both return `int`, and in both the low-level form starts `retval=0` and only
//! ever sets it to 1 -- `ltstcrd` (`:624`) when the balance covers `amt`,
//! `ldedcrd` (`:473`) as `retval=(uptr->creds >= -tabptr->dbtlmt)` after
//! deducting. So **non-zero means yes**, and that is what both shims answer.
//!
//! The 32-bit MajorMUD Plus decompile confirms the reading independently: it has
//! these by name rather than by ordinal, calls `otstcrd(x,amt,1)` and
//! `odedcrd(x,amt,1,0)`, and branches on `== 0` as the failure.

// `Machine`/`Ret` are now named only by this file's `#[cfg(test)]`
// `_wg16` bridges -- production code reaches every routine here through
// its generic `Call<A>`/`Host<A>` core instead, per `shims::mod`'s own
// `call` doc comment.
#[cfg(test)]
use mbbs_machine::m16::Ret;

use super::ShimError;
use crate::Host;
use crate::abi::{self, Abi, Call};

/// The answer both routines give: yes.
///
/// Named because `Ret::U16(1)` at two call sites is two magic numbers, and
/// because the thing worth writing down is not the value but that it is the
/// same value for both and never computed.
const YES: u16 = 1;

/// `int otstcrd(int unum, long amt, int real)` -- can this user spare `amt`
/// credits? `ACCOUNT.C:589`.
///
/// Always yes. See the module docs for why, and for what the module does with
/// a no at each of its three call sites.
///
/// `real` is read and discarded. It selects between "real credits only" and
/// "debt and credit-exemption count too", which is a distinction between two
/// ledgers this host does not keep; a board where every class carried `CRDXMT`
/// answered yes to both.
///
/// # Errors
///
/// If `unum` names no channel. Not ceremony: `unum` is the only argument whose
/// value this host can check, so it is the only thing standing between a
/// mis-declared `Cleans` -- or an argument read at the wrong stack word -- and
/// a shim that cheerfully answers yes forever to a question it misread.
///
/// Generic (Task 5): no memory is touched, so this is the plain
/// `Call<A>`/`Host<A>` shape with nothing to reborrow.
pub fn otstcrd<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let unum = Into::<u32>::into(call.int()) as i16;
    let _amt = call.long();
    let _real = call.int();
    host.users()
        .terms()
        .chan(unum)
        .ok_or_else(|| ShimError::Failed(format!("otstcrd({unum}): there is no such channel")))?;
    Ok(abi::Ret::Int(A::Int::from(YES)))
}

/// `int odedcrd(int unum, long amt, int real, int asmuch)` -- take `amt`
/// credits off this user. `ACCOUNT.C:429`.
///
/// Always succeeds, and takes nothing, because there is nothing to take it
/// from. `1` is `ldedcrd`'s "the account is still solvent", which is what
/// `_DEDUCT_EXEMPT_CREDITS` tests before ejecting a player mid-game.
///
/// A **negative** `amt` is a refund rather than a charge -- `ldedcrd`'s
/// `amt <= 0` branch adds it back -- and `_REPAY_GOLD` is the caller that uses
/// it that way. Both directions are the same no-op here, and both answer yes.
///
/// # Errors
///
/// If `unum` names no channel; see [`otstcrd`].
///
/// Generic (Task 5): same shape as [`otstcrd`].
pub fn odedcrd<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let unum = Into::<u32>::into(call.int()) as i16;
    let _amt = call.long();
    let _real = call.int();
    let _asmuch = call.int();
    host.users()
        .terms()
        .chan(unum)
        .ok_or_else(|| ShimError::Failed(format!("odedcrd({unum}): there is no such channel")))?;
    Ok(abi::Ret::Int(A::Int::from(YES)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;

    /// The answer that gets a player past the paywall. Zero from either of
    /// these is what bounces them back to the pre-game menu.
    #[test]
    fn both_routines_answer_yes() {
        let mut f = Fixture::new();
        // otstcrd(0, 500, real=0) -- a `long` is two words, low half first.
        assert_eq!(
            f.invoke(otstcrd, &[0, 500, 0, 0]).expect("otstcrd"),
            Ret::U16(1),
            "otstcrd must be non-zero or the module refuses to let the player in"
        );
        // odedcrd(0, 500, real=1, asmuch=1)
        assert_eq!(
            f.invoke(odedcrd, &[0, 500, 0, 1, 1]).expect("odedcrd"),
            Ret::U16(1),
            "odedcrd's zero is what ejects a player mid-game"
        );
    }

    /// A charge of zero, of everything, and a refund all answer the same way.
    /// There is no balance for any of them to be measured against, and
    /// `_REPAY_GOLD` passes a negative `amt` deliberately.
    #[test]
    fn no_amount_real_flag_or_direction_changes_the_answer() {
        let mut f = Fixture::new();
        let amounts: [(u16, u16); 4] = [
            (0, 0),           // nothing
            (500, 0),         // an ordinary charge
            (0xffff, 0xffff), // -1: a refund, which is what _REPAY_GOLD sends
            (0xffff, 0x7fff), // as much as a long can carry
        ];
        for (low, high) in amounts {
            for real in [0, 1] {
                assert_eq!(
                    f.invoke(otstcrd, &[0, low, high, real]).expect("otstcrd"),
                    Ret::U16(1),
                    "otstcrd({low:#x}:{high:#x}, real={real})"
                );
                for asmuch in [0, 1] {
                    assert_eq!(
                        f.invoke(odedcrd, &[0, low, high, real, asmuch])
                            .expect("odedcrd"),
                        Ret::U16(1),
                        "odedcrd({low:#x}:{high:#x}, real={real}, asmuch={asmuch})"
                    );
                }
            }
        }
    }

    /// The one thing these can get wrong, so the one thing they check.
    ///
    /// A shim that answers a constant cannot be caught reading its arguments
    /// from the wrong place -- unless it reads something it can bound. `unum` is
    /// the first word of both, so a stack frame off by a word turns channel 0
    /// into whatever the caller pushed next, and this is what notices.
    #[test]
    fn a_channel_that_does_not_exist_stops_the_module() {
        let mut f = Fixture::new();
        let past = f.host.users().terms().count();
        assert!(f.invoke(otstcrd, &[past, 500, 0, 0]).is_err());
        assert!(f.invoke(odedcrd, &[past, 500, 0, 1, 1]).is_err());
        assert!(f.invoke(otstcrd, &[-1i16 as u16, 500, 0, 0]).is_err());
        assert!(f.invoke(odedcrd, &[-1i16 as u16, 500, 0, 1, 1]).is_err());
    }
}
