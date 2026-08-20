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

use mbbs_machine::ptr::ModulePtr;

use super::ShimError;
use crate::Host;
use crate::abi::{self, Abi, Call};

/// The answer every routine in this file (and [`rtstcrd`]) gives: yes.
///
/// Named because `Ret::U16(1)` at several call sites is several magic
/// numbers, and because the thing worth writing down is not the value but
/// that it is the same value for all of them and never computed.
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

/// `int rtstcrd(long amt)` -- does the *current* user have `amt` **real**
/// credits to spare? `ACCOUNT.C:582-586` in the wg1 archive
/// (`archive/galacticomm/extract/wg1/GALDSRC/SRC/ACCOUNT.C`); the identical
/// body is also in `re/wg33src/SRC/server/wgserver/ACCOUNT.C:572-577`:
///
///
/// **[`crate::shims::credit::tstcrd`] with `real` set, and the same answer
/// for the same reason** -- exactly the relationship
/// [`crate::shims::credit::rdedcrd`] has to `dedcrd`, which is the precedent
/// this follows (see that pair's own doc comments in `credit.rs`). `tstcrd`
/// passes `real=0` to `ltstcrd`; `rtstcrd` passes `real=1`. That argument
/// selects whether a class's debt limit and `CRDXMT` credit-exemption
/// (`USRACC.H:124`, cited on this module's own doc comment) are allowed to
/// make a shortfall pass anyway -- a distinction between two ledgers this
/// host does not keep, the same reasoning [`otstcrd`]'s own doc comment gives
/// for its `real` argument. With no balance, no class table and no debt limit
/// behind either call, the distinction has nothing left to distinguish, so
/// both answer yes.
///
/// Answering this differently from `tstcrd` would be the incoherent choice,
/// not the careful one: a module testing through `tstcrd` would proceed and
/// the identical module testing through `rtstcrd` would stop, over a balance
/// neither of them ever measured.
///
/// # Why this is implemented here rather than in `credit.rs`
///
/// `rtstcrd` reads `usrnum` implicitly (`usaptr`, no `unum` argument) -- the
/// shape [`crate::shims::credit::tstcrd`]/`dedcrd`/`rdedcrd` share, not the
/// explicit-`unum` shape the rest of *this* file's routines take ([`otstcrd`],
/// [`odedcrd`], [`crdusr`], [`addcrd`]). By the line this crate already splits
/// `credit.rs` (current user, implicit `usrnum`) from `credits.rs` (named
/// user, explicit `unum`), `rtstcrd` belongs beside `tstcrd` in `credit.rs`.
/// It is filed here anyway, at the repository owner's explicit instruction,
/// because of how this change was assigned rather than because this is where
/// it reads best.
///
/// # Errors
///
/// If `usrnum` does not name a channel of this host -- in particular, if
/// nobody is current at all; see [`crate::shims::credit::dedcrd`]'s own
/// `# Errors` for what that means concretely.
pub fn rtstcrd<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let _amt = call.long();
    host.current_channel_mem(call.mem())?;
    Ok(abi::Ret::Int(A::Int::from(YES)))
}

/// `int crdusr(char *keyuid, const char *tckstg, int real, int affall)` --
/// post credits to a named account. `ACCOUNT.C:712-762`.
///
/// The vendor looks `keyuid` up in the accounts file, adds `atol(tckstg)` to
/// `creds` (and to `totcreds`/`totpaid` when `affall`), and may switch the
/// account's class if the posting takes it out of the red. It answers `-1`
/// when there is no such account or it is flagged for deletion, and otherwise
/// whether that user is currently online.
///
/// **Nothing is posted, and the answer is the online-ness this host can
/// actually measure.** This is the deduction side's decision applied to the
/// grant side: see the module docs above and
/// [`YES`]. There is no `creds` field in this host's
/// `struct usracc` (`crate::users::AccountLayout` models `userid` and the
/// four screen-preference bytes and nothing else), no class table for
/// `fndcls` to search, and no `sv2` statistics block -- so every one of the
/// vendor's writes lands nowhere, and refusing instead would stop a module
/// over a balance that would not have moved either way.
///
/// **It never answers `-1`.** That value means "this account does not exist",
/// and this host cannot establish it: `onsysn` sees the channels that are
/// connected right now, and there is no offline account database behind them
/// to prove a name absent. Answering `-1` for every user who happens not to
/// be online would report deletion-flagged and merely-offline accounts
/// alike, and a module that treats `-1` as "bad user-ID" would reject a
/// perfectly good one. `0` -- "posted; that user is not online" -- is the
/// answer this host can stand behind.
///
/// `tckstg` is read rather than ignored, because the vendor reads it as a
/// number and a caller passing a malformed one deserves the same treatment
/// here as the argument frame it occupies.
///
/// # Errors
///
/// If either string argument is not a valid pointer, or a read runs off the
/// segment.
pub fn crdusr<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let keyuid = call.ptr();
    let tckstg = call.ptr();
    let _real = call.int();
    let _affall = call.int();
    let online = posted_to::<A>(call, host, keyuid, tckstg)?;
    Ok(abi::Ret::Int(A::Int::from(u16::from(online))))
}

/// `int addcrd(char *keyuid, const char *tckstg, int real)` -- post credits
/// and announce it on the console. `ACCOUNT.C:691-708`:
///
///
/// **[`crdusr`] plus the console announcement, which this host really does
/// emit** -- `shocst` is implemented (`crate::shims::system::shocst`), so the
/// sysop console gets the same two lines the original wrote, with the same
/// `PAID`/`FREE` wording chosen by `real`.
///
/// **The `sv2` running totals are not kept.** `sv2.paidpst`/`sv2.freepst` are
/// fields of the system-statistics block this host does not model, so the
/// pair of `+=` is the one part of this body that goes nowhere. Nothing reads
/// those totals except the vendor's own sysop statistics screen, which is
/// also not here; they are named in this comment rather than silently
/// dropped so the omission is discoverable from the code.
///
/// **`real` is the third parameter and is a `GBOOL`, not an `INT`.**
/// `INC/USRACC.H:87` and the later `VCPROJ/GCOMMLIB/USRACC.H` disagree on
/// exactly this, and `INC/` is the generation the NE modules compiled
/// against. It costs nothing at the call frame -- `GCTYPDEF.H:105` makes
/// `GBOOL` a `short`, and this host reads the argument at `INT` width because
/// that is what a 16-bit cdecl caller pushes for either -- but the
/// disagreement is recorded because it is the exact trap this plan's own
/// citation rule exists for.
///
/// # Errors
///
/// If either string argument is not a valid pointer, or a read runs off the
/// segment.
pub fn addcrd<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let keyuid = call.ptr();
    let tckstg = call.ptr();
    let real = super::gbool_arg::<A>(call.int());

    let online = posted_to::<A>(call, host, keyuid, tckstg)?;

    // `crdusr`'s answer is never negative here, so the vendor's `>= 0` guard
    // is always taken and the announcement always happens. See `crdusr` for
    // why -1 is not an answer this host can give.
    let uid = read_string::<A>(call, keyuid)?;
    let ticks = read_string::<A>(call, tckstg)?;
    let title = format!("{} CREDITS POSTED", if real { "PAID" } else { "FREE" });
    let line = format!("User-ID: {uid:<29} Credits posted: {ticks:>7}");
    crate::shims::system::shocst_line(host, &title, &line);

    Ok(abi::Ret::Int(A::Int::from(u16::from(online))))
}

/// The part [`addcrd`] and [`crdusr`] share: read both strings so a bad
/// pointer is caught, then answer whether `keyuid` is online.
///
/// `onsysn(keyuid,1)` is the vendor's own test (`ACCOUNT.C:725`), with
/// `invis=1` so an invisible user still counts -- posting credits is not a
/// social act and the original does not let the `INVISB` flag hide an account
/// from it.
fn posted_to<A: Abi>(
    call: &mut Call<A>,
    host: &mut Host<A>,
    keyuid: A::Ptr,
    tckstg: A::Ptr,
) -> Result<bool, ShimError> {
    let uid = read_string::<A>(call, keyuid)?;
    // Read and discarded: there is no `creds` field for `atol(tckstg)` to be
    // added to. Read anyway so a caller passing a bad pointer is told here
    // rather than at whatever reads it next.
    let _ticks = read_string::<A>(call, tckstg)?;

    crate::shims::user::onsysn_for(call, host, uid.as_bytes(), true)
}

/// One NUL-terminated argument string.
fn read_string<A: Abi>(call: &mut Call<A>, at: A::Ptr) -> Result<String, ShimError> {
    let bytes = at
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// `void howbuy(void)` -- emit the "how to buy credits" message.
/// `ACCOUNT.C:1383-1391`:
///
///
/// **Does nothing, because `pester` is off, and the vendor's own body does
/// nothing when it is.** This is a real branch of the real routine rather
/// than a stub: `if (pester)` guards the entire body, so a board with the
/// option clear emitted no message either.
///
/// `pester` is not a host global a module can see or set -- `ACCOUNT.C:63`
/// declares it file-scope, and `:113` fills it from `ynopt(PESTER)`, a
/// message-file option this host has no parser for. What settles its value
/// here is not the missing parser but the decision above it: **a host that
/// bills nobody has nothing to pester anybody about.** Every routine in this
/// module answers as though every account were credit-exempt, and "do not
/// nag this user to buy more credits" is the same answer in the same voice.
///
/// The alternative was to refuse, and that would have been the wrong kind of
/// honest. Refusing says "this host cannot answer"; the truth is that it can,
/// and the answer is the empty one. What this host genuinely could not do is
/// emit the message *if `pester` were set*: `HOWBUY` lives in `wgsacct.mcv`,
/// reached through `acnmb` (`MAJORBBS.H:428`, opened at `ACCOUNT.C:101`),
/// which is the **server's own** message file and not a module's -- this host
/// loads module message files and has none of its own. That is why `pester`
/// being off is load-bearing and is stated here rather than left implicit.
///
/// # Errors
///
/// Never. The signature is fallible because every shim's is.
pub fn howbuy<A: Abi>(_call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    Ok(abi::Ret::Void)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;

    /// Two connected channels, so `crdusr`'s scan has something to walk.
    fn two_channels() -> Fixture {
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(2));
        for (n, uid) in [(0i16, "rangerdan"), (1, "kaimon")] {
            let chan = f.host.users().terms().chan(n).expect("a channel");
            f.host
                .connect_state(&mut f.machine, chan, &crate::Connection::ansi(uid))
                .expect("connects");
        }
        f
    }

    /// One connected channel, made *current* -- what [`rtstcrd`] and
    /// `crate::shims::credit::tstcrd` both need, since neither takes a
    /// channel argument. Mirrors `credit.rs`'s own private `connect` test
    /// helper (same fixture shape, duplicated here because that one is not
    /// `pub`).
    fn connect(f: &mut Fixture) -> crate::Chan {
        let console = f.console();
        f.host
            .connect_state(
                &mut f.machine,
                console,
                &crate::Connection::ansi("rangerdan"),
            )
            .expect("channel 0");
        console
    }

    /// A `long amt` argument as the two little-endian words a 16-bit cdecl
    /// caller pushes, low half first -- matching `credit.rs`'s own
    /// `long_words` test helper.
    fn long_words(v: i64) -> [u16; 2] {
        let v = v as u32;
        [v as u16, (v >> 16) as u16]
    }

    /// `addcrd` writes the console line the vendor writes (`ACCOUNT.C:703`),
    /// with `real` choosing the `PAID`/`FREE` wording. This host really does
    /// emit it -- `shocst` is implemented -- so it is the one observable
    /// effect of the routine and the one worth asserting.
    #[test]
    fn addcrd_announces_the_posting_on_the_console() {
        let mut f = two_channels();
        let uid = f.text("rangerdan");
        let ticks = f.text("500");

        let args = [uid.offset, uid.selector, ticks.offset, ticks.selector, 1];
        assert!(matches!(f.invoke(addcrd, &args), Ok(Ret::U16(_))));

        let audit = f.host.audit().last().expect("a console line").clone();
        assert!(audit.starts_with("PAID CREDITS POSTED: "), "{audit}");
        assert!(audit.contains("rangerdan"), "{audit}");
        assert!(audit.contains("500"), "{audit}");

        // `real=0` is the other wording, and the same line otherwise.
        let args = [uid.offset, uid.selector, ticks.offset, ticks.selector, 0];
        assert!(matches!(f.invoke(addcrd, &args), Ok(Ret::U16(_))));
        let audit = f.host.audit().last().expect("a console line").clone();
        assert!(audit.starts_with("FREE CREDITS POSTED: "), "{audit}");
    }

    /// `crdusr` answers whether the named user is online, and **never** -1.
    ///
    /// -1 means "no such account", which this host cannot establish: there is
    /// no offline account database behind the connected channels to prove a
    /// name absent. A user nobody has heard of gets `0` -- "posted, and that
    /// user is not online" -- not a rejection.
    #[test]
    fn crdusr_never_answers_minus_one_for_an_unknown_user() {
        let mut f = two_channels();
        let uid = f.text("nobody-by-that-name");
        let ticks = f.text("100");

        let args = [uid.offset, uid.selector, ticks.offset, ticks.selector, 1, 1];
        assert_eq!(
            f.invoke(crdusr, &args).expect("crdusr"),
            Ret::U16(0),
            "not online, but not rejected either -- -1 is not an answer this host can give"
        );
    }

    /// A connected user is still reported offline, because `crdusr` asks
    /// `onsysn`, and `onsysn` requires `usrcls > SUPIPG` -- which this host
    /// never sets.
    ///
    /// Pinned as the honest consequence rather than papered over: the day a
    /// signup flow advances `usrcls`, this test fails and says so, instead of
    /// `crdusr` silently starting to answer differently.
    #[test]
    fn crdusr_reports_a_connected_user_offline_while_usrcls_stays_zero() {
        let mut f = two_channels();
        let uid = f.text("rangerdan");
        let ticks = f.text("100");

        let args = [uid.offset, uid.selector, ticks.offset, ticks.selector, 1, 1];
        assert_eq!(
            f.invoke(crdusr, &args).expect("crdusr"),
            Ret::U16(0),
            "rangerdan IS connected; onsysn still says no because usrcls is 0"
        );
    }

    /// `howbuy` emits nothing, because `pester` is off -- the vendor's own
    /// body does nothing in that state (`ACCOUNT.C:1386`). Asserted against
    /// the audit trail so "nothing happened" is measured rather than assumed.
    #[test]
    fn howbuy_says_nothing_because_this_host_pesters_nobody() {
        let mut f = Fixture::new();
        let before = f.host.audit().len();
        assert!(matches!(f.invoke(howbuy, &[]), Ok(Ret::Void)));
        assert_eq!(f.host.audit().len(), before, "howbuy wrote nothing anywhere");
    }

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

    /// `rtstcrd` is `tstcrd` with `real` set, and answers the same way.
    /// Asserted side by side with `crate::shims::credit::tstcrd` over the
    /// identical argument, because the failure worth catching is the two
    /// disagreeing -- a module testing through one would proceed and through
    /// the other would stop, over a balance neither of them ever measured.
    /// Mirrors `credit.rs`'s own `rdedcrd_answers_exactly_as_dedcrd_does`.
    #[test]
    fn rtstcrd_answers_exactly_as_tstcrd_does() {
        let mut f = Fixture::new();
        connect(&mut f);

        for amt in [0, 500, -500] {
            let args = long_words(amt);
            assert_eq!(
                f.invoke(rtstcrd, &args).expect("rtstcrd"),
                f.invoke(crate::shims::credit::tstcrd, &args).expect("tstcrd"),
                "rtstcrd and tstcrd must agree on {amt}"
            );
            assert_eq!(f.invoke(rtstcrd, &args).expect("rtstcrd"), Ret::U16(1));
        }
    }

    /// With nobody current, `rtstcrd` refuses rather than answering yes --
    /// the real `usaptr` would be pointing at whatever `usrnum=-1` names,
    /// nothing. The same guard `tstcrd`/`dedcrd`/`rdedcrd` all carry.
    #[test]
    fn rtstcrd_refuses_when_nobody_is_the_current_user() {
        let mut f = Fixture::new();
        assert!(
            f.invoke(rtstcrd, &long_words(500)).is_err(),
            "usrnum is -1 before anyone connects"
        );
    }

    /// A charge of zero and a refund answer the same way as an ordinary
    /// charge -- there is no balance for any of them to be measured against.
    #[test]
    fn rtstcrd_takes_a_refund_and_a_zero_charge_the_same_way() {
        let mut f = Fixture::new();
        connect(&mut f);
        for amt in [0, -500] {
            assert_eq!(
                f.invoke(rtstcrd, &long_words(amt)).expect("rtstcrd"),
                Ret::U16(1),
                "amt={amt}"
            );
        }
    }
}
