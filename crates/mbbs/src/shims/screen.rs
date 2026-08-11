//! `rstrxf` -- "restore screen-length to usracc setting" -- and the account
//! field it reads.
//!
//! ```text
//! rstrxf 1
//! ```
//!
//! One import, one call site (`re/ne_arity.py 512 re/WCCMMUD.DLL`), one
//! symptom before this landed: `Stopped(Unimplemented { module: "MAJORBBS",
//! symbol: "rstrxf, called from seg 3:0x6470" })`, reached once a channel has
//! created a couple of characters -- see the registration table comment in
//! `crates/mbbs/src/shims/mod.rs`, next to the three GALGSBL entries this
//! file's routines need, for the MAJORBBS/GSBL symbol inventory this task
//! also owes.
//!
//! `rstrxf` is `MAJORBBS.C:3776` in the **wg1** Galacticomm source kit --
//! deliberately wg1 and not wg20, whose line numbers differ and would cite
//! the wrong function -- declared `MAJORBBS.H:727`:
//!
//!
//! # Where the one call site actually leads
//!
//! The plan that scheduled this task worried about a specific shape --
//! `FSDBBS.C:107-113`'s FSD teardown, `echon(); ...; rstrxf();
//! btutsw(usrnum,usaptr->scnwid);` -- because stopping at `rstrxf` would mean
//! the `btutsw` right after it never runs, silently un-restoring the wrap
//! width (`crate::gsbl::Channel::width`, guarded off entirely at zero).
//! **That shape is not what `WCCMMUD.DLL` reaches.** Two independent facts
//! rule it out:
//!
//! 1. `fsdcon`/`fsdcof`, the routines `FSDBBS.C:107-113` names, are **not**
//!    `MAJORBBS.EXE` exports -- `crates/mbbs/data/majorbbs_wg101.tsv` has no
//!    entry for either, while every *other* FSDBBS.C routine the module can
//!    reach does (`_FSDBKG` 238, `_FSDEGO` 241, `_FSDPPC` 256, `_FSDNFY` 250,
//!    `_FSDCHI` 1066, `_FSDQOE` 259). They are file-static helpers of the real
//!    host's own `fsdego`, unreachable by any module, ours included. This
//!    host's own FSD engine replaces that whole mechanism instead of
//!    reimplementing it: `crate::shims::fsd::goback` (the exit path every FSD
//!    session this host drives takes, line mode and ANSI alike) calls
//!    `crate::shims::fsd::fsdcof` directly and unconditionally, in Rust, and
//!    that function sets `width` itself without ever calling `rstrxf`. FSD
//!    teardown in this host does not go anywhere near this file.
//! 2. The one real call site is not FSD-adjacent at all. `re/ne_arity.py 512
//!    re/WCCMMUD.DLL` finds a single far call, `seg 3 0x6471`, cleaning void
//!    (a `void` return, matching the declaration), with **another** unresolved
//!    far call immediately following it (`next=9a ff ff 00`, no push between
//!    the two -- both nullary). Reading `WCCMMUD.DLL`'s own relocation table
//!    for segment 3 (the fixup at file-segment offset `0x6476`, the second
//!    call's operand) names it directly: **MAJORBBS ordinal 510, `_RSTMBK`**
//!    -- `rstmbk`, already implemented (`crate::shims::msg::rstmbk`,
//!    registered `crate::shims::mod`). `WCCMMUD.DLL`'s own code pairs
//!    "restore screen length" with "restore message base", not with "restore
//!    wrap width" -- a bracket around some earlier `setmbk`-scoped block this
//!    host has no other trace of, not the Galacticomm FSD idiom the plan's
//!    citation was drawn from.
//!
//! So the plan's specific worry does not apply to the one site this module
//! has: nothing observably regresses if `rstrxf` here does less than a
//! faithful `btutsw` restore, because there is no `btutsw` waiting on the
//! other side of it. What *is* faithful, and what this file implements
//! anyway, is `rstrxf` itself -- because the next module past this one might
//! call it from a genuine FSD-shaped site, and "the one call site we measured
//! doesn't need it" is not the same claim as "correct."
//!
//! # How much of the pause-key/paging machinery this implements
//!
//! **None of it acts.** `btuxnf`, `btuhpk`, `btupbc` and `btucpc` all record
//! state (`crate::gsbl::Channel::page_lines`/`page_message`/`pause_char`/
//! `clear_pause_char`/`pause_handler_installed`) and none of it is ever read
//! back to actually pause a channel's output. That is not a shortcut unique
//! to `rstrxf` -- `btuxnf`'s own doc comment made the same call for page mode
//! before this task existed -- but it is worth re-justifying with MajorMUD's
//! own evidence rather than inheriting the precedent on faith:
//!
//! * `WCCMMUD.DLL` imports `btuxnf` at 14 call sites and **never once** passes
//!   a negative `xoff` -- every site this crate's own test fixtures and
//!   `re/exports/imports.txt` cross-check pass positive flow-control values,
//!   which is the same shape `btuxnf`'s existing doc comment already
//!   describes. Page mode, as the module itself drives it, is unreached.
//! * `btuhpk`/`btupbc`/`btucpc` are not module imports **at all** -- the only
//!   caller either could ever have in this host is `rstrxf`, below. A module
//!   that never enters page mode has no reason to ever receive a
//!   screen-pause keystroke, so the handler `btuhpk` would install never
//!   runs regardless of whether this host remembers it.
//! * MajorMUD is a telnet-native module built for scroll-and-go clients, not
//!   the page-at-a-time text UI 1990s dial-up terminals wanted; nothing in
//!   `re/exports/WCCMMUD_named.c` implements a "more" prompt of its own
//!   either, which is the other half of the same design choice, one layer up.
//!
//! **What would show this is wrong:** a live session where output visibly
//! pauses waiting for a keystroke the host is not modelling, or a module
//! import of `btuxnf` with a negative `xoff` this crate has not measured.
//! Neither has been observed. If either turns up, the state these four
//! routines already record (`page_lines`, `page_message`, `pause_char`,
//! `clear_pause_char`, `pause_handler_installed`) is exactly what a real
//! pagination implementation would need to start from -- recording it now is
//! what makes that later work additive instead of a rewrite.

use mbbs16::{FarPtr, Machine, Ret};

use super::ShimError;
use super::gsbl::{apply_cpc, apply_hpk, apply_pbc, apply_xnf};
use crate::Host;
use crate::chan::Chan;

/// `MAJORBBS.H:31`: `#define CTNUOS 2` -- "screen length code used for
/// 'continuous'", i.e. no pausing. `rstrxf` subtracts it from the account's
/// `scnbrk` to get `btuxnf`'s `cnt` argument.
const CTNUOS: i16 = 2;

/// `scnpaus[extptr->lingo]` -- the page-mode pause message, ordinarily loaded
/// from the host's message catalog at startup (`MAJORBBS.C:630-637`,
/// `scnpaus[clingo]=alcdup(rawmsg(SCNPAUS))`) and indexed by the connecting
/// user's configured language. This host has no message catalog to load it
/// from and no language table to index -- `extptr->lingo` is not modelled at
/// all, only ever the implicit single language a host with one `scnpaus`
/// entry would have. This is a literal placeholder, not data read from
/// anywhere, and it is never shown to a user: see this module's own doc
/// comment on why `page_message` is recorded and not acted on.
const PAUSE_MESSAGE: &[u8] = b"Press any key to continue...";

/// `usaptr->scnbrk`, as a signed byte -- `struct usracc`'s `char scnbrk` is
/// genuinely signed in Borland's default, and `rstrxf` computes
/// `scnbrk-CTNUOS` as a *signed* subtraction (`MAJORBBS.C:3778`), so an
/// unsigned read here would turn a legitimately negative `cnt` into a huge
/// positive one for the wrong reason.
fn account_scnbrk(machine: &Machine, host: &Host, chan: Chan) -> Result<i8, ShimError> {
    let account = host.users().account(chan);
    let at = FarPtr {
        offset: account.offset + crate::users::usracc::SCNBRK as u16,
        selector: account.selector,
    };
    Ok(machine.resolve(at, 1)?[0] as i8)
}

/// `void rstrxf(void)` -- restore screen-length to the account setting.
/// `MAJORBBS.C:3776` (wg1). See this module's own doc comment for what it
/// does and does not do in this host, and for where its one real call site
/// actually leads.
///
/// # `scnbrk`'s default in this host
///
/// `crate::users::usracc::SCNBRK`'s own doc comment: `Host::connect_state`
/// never writes this byte, so it reads whatever the account's memory already
/// held -- ordinarily zero, since nothing else writes it either. `0-CTNUOS`
/// is `-2`, and that negative `cnt` lands in `Channel::page_lines` as
/// `0xfffe` the same way a real negative `int` argument would land in a
/// 16-bit `cnt` parameter -- harmless, because `page_lines` is never acted
/// on (see [`crate::shims::gsbl::apply_xnf`]'s doc comment). This is `rstrxf`
/// computed faithfully against a host that does not model `scnbrk`, not a
/// special case carved out for it.
pub fn rstrxf(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let chan = host.current_channel(machine)?;
    let scnbrk = account_scnbrk(machine, host, chan)?;
    let cnt = (i16::from(scnbrk) - CTNUOS) as u16;

    let g = host.gsbl_mut();
    apply_xnf(g, chan, 0, -19, Some((cnt, PAUSE_MESSAGE.to_vec())));
    apply_hpk(g, chan);
    apply_pbc(g, chan, 20);
    apply_cpc(g, chan, 19);

    Ok(Ret::Void)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;

    /// Point `usrnum` at the fixture's own console -- the same helper
    /// `crate::shims::fsd`'s tests use, for the same reason: `rstrxf` asks
    /// [`Host::current_channel`], and `Fixture::new` deliberately leaves
    /// `usrnum` at `-1` until something points it somewhere.
    fn current(f: &mut Fixture) -> Chan {
        let chan = f.console();
        f.host
            .point_curusr(&mut f.machine, chan)
            .expect("channel 0 is current");
        chan
    }

    fn write_scnbrk(f: &mut Fixture, chan: Chan, value: i8) {
        let account = f.host.users().account(chan);
        let at = FarPtr {
            offset: account.offset + crate::users::usracc::SCNBRK as u16,
            selector: account.selector,
        };
        f.machine.write(at, &[value as u8]).expect("account memory");
    }

    #[test]
    fn rstrxf_restores_the_pause_and_page_state_from_the_account() {
        let mut f = Fixture::new();
        let chan = current(&mut f);
        write_scnbrk(&mut f, chan, 24);

        f.invoke(rstrxf, &[]).expect("rstrxf does not stop the machine");

        let c = f.host.gsbl().channel(chan);
        assert_eq!((c.xon, c.xoff), (0, 0xed), "0, -19 as btuxnf would store it");
        assert_eq!(c.page_lines, 22, "scnbrk(24) - CTNUOS(2)");
        assert_eq!(c.page_message.as_deref(), Some(PAUSE_MESSAGE));
        assert!(c.pause_handler_installed);
        assert_eq!(c.pause_char, 20, "btupbc(usrnum,20)");
        assert_eq!(c.clear_pause_char, 19, "btucpc(usrnum,19)");
    }

    #[test]
    fn rstrxf_subtracts_signed_so_an_unset_scnbrk_goes_negative_not_huge() {
        // scnbrk defaults to 0 in this host (see SCNBRK's own doc comment,
        // and account_scnbrk's) -- 0-CTNUOS is -2, not 254. A shim that read
        // scnbrk as unsigned would report 254-2=252 instead.
        let mut f = Fixture::new();
        let chan = current(&mut f);
        // scnbrk left at its default -- no write_scnbrk call.

        f.invoke(rstrxf, &[]).expect("rstrxf does not stop the machine");

        let c = f.host.gsbl().channel(chan);
        assert_eq!(c.page_lines, 0xfffe, "-2 as the u16 btuxnf's cnt would hold");
    }

    #[test]
    fn rstrxf_reads_scnbrk_as_a_signed_byte_not_unsigned() {
        // The unset-default test above (0-CTNUOS=-2) cannot tell a signed
        // read from an unsigned one -- 0i8 and 0u8 both sign-extend to the
        // same i16. A *negative* scnbrk is the case that actually
        // distinguishes them: read unsigned, -5 (byte 0xfb, 251 as u8) would
        // compute 251-2=249; read signed, as `MAJORBBS.C:3778`'s own `char
        // scnbrk` is, it computes -5-2=-7.
        let mut f = Fixture::new();
        let chan = current(&mut f);
        write_scnbrk(&mut f, chan, -5);

        f.invoke(rstrxf, &[]).expect("rstrxf does not stop the machine");

        assert_eq!(
            f.host.gsbl().channel(chan).page_lines,
            (-7i16) as u16,
            "signed -5 - CTNUOS(2) = -7, not the unsigned reading's 249"
        );
    }

    #[test]
    fn rstrxf_reads_the_channel_it_is_current_on_not_channel_zero() {
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(2));
        let one = f.host.gsbl().terms().chan(1).expect("channel 1");
        f.host
            .point_curusr(&mut f.machine, one)
            .expect("channel 1 is current");
        write_scnbrk(&mut f, one, 10);

        f.invoke(rstrxf, &[]).expect("rstrxf does not stop the machine");

        let zero = f.host.gsbl().terms().chan(0).expect("channel 0");
        assert_eq!(
            f.host.gsbl().channel(zero).page_lines,
            0,
            "channel 0 was never current and rstrxf must not touch it"
        );
        assert_eq!(f.host.gsbl().channel(one).page_lines, 8, "10 - CTNUOS(2)");
    }
}
