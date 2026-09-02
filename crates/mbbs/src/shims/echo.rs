//! Two routines named at `MAJORBBS.H:679-733`, cited throughout against the
//! **wg1** tree (`archive/galacticomm/extract/wg1/GALDSRC/SRC`) -- wg20
//! renumbers every one of these lines, see `crate::shims::gsbl`'s sibling
//! doc comment on citing wg1.
//!
//! # This file used to hold four more routines, all dead duplicates
//!
//! `echon`, `echsec`, `instat` and `btuxmn` were removed 2026-08-15
//! (`docs/2026-08-15-dead-twin-shims.md`): each had a twin registered
//! elsewhere (`shims::user::{echon,echsec,instat}`, `shims::gsbl::btuxmn`)
//! that `mod.rs` actually dispatches to, and this crate never called any of
//! the four copies here. `btuxmn`'s twin disagreement is worth naming: this
//! file's dead copy transmitted *raw*, unwrapped bytes (citing MBBSEmu's
//! independent reimplementation and the `dftinj` call site), while the
//! registered `shims::gsbl::btuxmn` transmits word-wrapped, matching
//! `btuxmt`. The primary source settles it -- `.scratch/gsbl_guide.txt`
//! (the extracted GSBL Library Reference Guide, page 187): `btuxmn()` behaves like `btuxmt()` except that what it queues survives `btuclo()` -- the *only* documented
//! difference is the `btuclo`-proof block marking, not the output mode.
//! MBBSEmu's reimplementation is wrong on this point.
//!
//! # What neither surviving routine can do, and why
//!
//! `injacr` and `hdlinp` both end, in the vendor, by calling `hdlcri()`
//! (`MAJORBBS.C:2666`, `STATIC`) **synchronously, before returning to the
//! module that asked**: `hdlcri` reads `module[usrptr->state]->sttrou` (or
//! `lonrou`/`lofrou`) and calls it directly. Dispatching to a module entry
//! point needs the loaded module (`A::Module`) -- `Host::run` takes one, and
//! every place this host reaches `sttrou` (`Host::poll_with_chan`) has one in
//! hand. A shim never does: `Call<A>` (`crates/mbbs/src/abi.rs:626`) holds
//! only `cpu: &'a mut A::Cpu` and the raw argument frame, and the two
//! parameters every shim in this crate is given --
//! `&mut Call<A>`/`&mut Host<A>` -- carry no module between them either. So
//! **no shim in this crate can call into module code**, and that is a
//! property of the type signature every routine in this file (and every
//! other shim) is written against, not a gap specific to these two.
//!
//! [`injacr`] approximates its synchronous call with a deferred one -- see
//! its own doc comment for why that substitution is honest for the one way
//! the vendor tree actually calls it. [`hdlinp`] does not attempt the same
//! substitution -- see its own doc comment for why the substitution would be
//! actively wrong for the one way the vendor tree actually calls *it*.

#[cfg(test)]
use mbbs_machine::m16::Ret;

use super::ShimError;
use crate::Host;
use crate::abi::{self, Abi, Call};
use crate::gsbl::Gsbl;

/// `void injacr(void)` -- `MAJORBBS.C:2559-2567`:
///
/// **Implemented as an approximation, not a synchronous re-entry** -- see
/// this file's module doc comment for why a shim cannot call `hdlcri`
/// (which is what `hdlinp` ultimately reaches) at all, only defer it. The
/// approximation: queue `CRSTG` for the current channel exactly as
/// [`crate::shims::gsbl::btuinj`] would (`host.gsbl_mut().inject(chan,
/// Gsbl::CRSTG)`), and rely on [`Host::poll`]'s existing `CRSTG` handling to
/// reach `sttrou` on its own next pass.
///
/// This is a faithful-enough substitute for `injacr` specifically, for two
/// reasons neither of which is true of [`hdlinp`] (see that routine's own
/// doc comment for the contrast):
///
/// 1. **`clrinp()`'s effect is reproduced for free.** `clrinp` zeroes
///    `input[0]`, so the state routine it re-enters sees an empty line --
///    "re-prompt current text" is the vendor's own comment for what this
///    accomplishes. [`Host::get_input_mem`] (`crates/mbbs/src/lib.rs:1970`)
///    is what actually fills `input` on the deferred pass, and it does
///    `self.gsbl_mut().take_line(chan).unwrap_or_default()` -- an
///    unmatched `CRSTG` (one queued with no line behind it in
///    `Channel::ready`, which is exactly what this injects) takes the
///    `unwrap_or_default()` branch and writes an empty string, the same
///    observable result `clrinp()` produces.
/// 2. **Every real caller of `injacr` in the wg1 tree is fire-and-forget.**
///    `MAJORBBS.C:2504-2531` (the `CRSTG`/`OBFCLR`/`ABOREQ` cases of the
///    status switch `injacr` itself is reached from) and
///    `GALNOTE.C:145-161`'s `notests` all call `injacr()` and then either
///    fall out of a `switch` or `return` -- nothing inspects channel state
///    immediately afterward the way [`hdlinp`]'s own callers do. A caller
///    that does not look at the result synchronously cannot tell the
///    difference between the result landing now and landing on the next
///    poll.
///
/// **What is still not reproduced, named precisely:**
///
/// - **Timing.** The vendor's `hdlcri()` runs before `injacr` returns to its
///   caller; this host's runs on `Host::poll`'s next pass. Any caller that
///   *did* inspect state synchronously (none does, in wg1) would see this.
/// - **`INJOIP`.** Left untouched, deliberately, rather than set-then-
///   immediately-cleared: the vendor's bracketing exists to mark a window
///   around the synchronous call this host cannot make, and setting a flag
///   for a window that has not actually happened yet (the deferred
///   dispatch has not run) would assert something false. This is also
///   inert either way: `re/exports/WCCMMUD_named.c` has zero references to
///   `INJOIP` -- `WCCMMUD.DLL` (MajorMUD) never reads it, so there is no
///   fidelity this host is trading away for a module that actually cares.
/// - **Queue ordering under pipelined input.** `crate::gsbl::Channel::ready`
///   can hold more than one completed line at once (see its own doc
///   comment) if a client pipelines. In that case this injected `CRSTG`
///   goes to the *back* of `status`, behind any already-queued real line's
///   own `CRSTG` -- so the re-prompt this produces is dispatched *after*
///   that pipelined line, where the vendor's synchronous call would run
///   before it. Not reachable through `mmc` or ordinary telnet input;
///   recorded because it is a real divergence, not because it is expected
///   to matter.
///
/// # Errors
///
/// If `usrnum` does not name a channel of this host.
pub fn injacr<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = host.current_channel_mem(call.mem())?;
    host.gsbl_mut().inject(chan, Gsbl::CRSTG);
    Ok(abi::Ret::Void)
}

/// `void hdlinp(void)` -- `MAJORBBS.C:2657-2664`:
///
/// **Not implementable with a faithful approximation -- implemented as a
/// documented no-op.** This file's module doc comment covers why no shim
/// can reach `hdlcri` at all; [`injacr`]'s own doc comment covers why
/// queueing `CRSTG` and deferring is nonetheless an honest stand-in *for
/// that routine*. Neither escape applies here, for reasons specific to how
/// the wg1 tree actually calls `hdlinp` directly (as opposed to through
/// `injacr`):
///
/// (`EMULATE.C:388-395`'s `entcht` -- "enter sysop chat mode now" -- is the
/// same five lines verbatim.) Both real callers:
///
/// 1. **Write into `input`/`margc`/`margv` themselves before calling**,
///    simulating a user who typed `"x"` and pressed return, *without*
///    going through the channel's byte stream at all. A deferred `CRSTG`
///    is answered by [`Host::get_input_mem`] re-reading
///    `Channel::take_line`, which would silently discard whatever the
///    caller just wrote into `input` and substitute either a real queued
///    line or an empty one -- not an approximation of "simulated input",
///    the opposite of it.
/// 2. **Loop, inspecting `usrptr->state` immediately after each call
///    returns**, to decide whether to call again. This is the case
///    [`injacr`]'s own doc comment says has no real caller in wg1 -- here
///    it is the *only* real caller. A deferred dispatch cannot make
///    `usrptr->state` reflect a call that has not run yet; a loop written
///    against this shim would see its own stale value every iteration and
///    either spin `XTRIES` times for nothing or (if the caller trusted the
///    loop bound rather than re-checking) exit having asked for five
///    module dispatches and gotten zero of them.
///
/// Queueing `CRSTG` here anyway -- reusing `injacr`'s approximation --
/// would be exactly the "fake it" this crate's standing instruction
/// forbids: it produces a result that *looks* like a normal shim (`Ret`
/// comes back, nothing panics) while being wrong for the one real use this
/// symbol has. Doing nothing but recording that this happened is the
/// honest answer: a caller relying on `hdlinp` to actually run the target
/// state routine will see no state change and can be diagnosed from the
/// note, rather than see a state change that does not correspond to what
/// happened.
///
/// **The `entstt`/`"x"` auto-exit guard is separately unavailable** even in
/// principle: `extptr->entstt` is `struct extusr`'s `entstt` field
/// (`MAJORBBS.H:104`), and (see [`echsec`]'s own doc comment) this host has
/// placed no fields inside `EXTUSR` at all.
///
/// # Errors
///
/// Never -- there is no module memory this touches. `usrnum` is read only
/// to make the note identify a channel; if it cannot be read, the note says
/// so instead of naming one.
pub fn hdlinp<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = host.current_channel_mem(call.mem()).ok();
    host.note(match chan {
        Some(chan) => format!(
            "hdlinp: channel {chan} asked to dispatch simulated input synchronously; \
             not implemented -- no shim can call into module code, and no available \
             approximation is faithful to how this symbol is actually called (see \
             this routine's own doc comment)"
        ),
        None => "hdlinp: called with usrnum naming no channel; not implemented, and \
                  no channel to name in this note either"
            .to_owned(),
    });
    Ok(abi::Ret::Void)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;

    #[test]
    fn injacr_queues_crstg_for_the_current_channel() {
        let mut f = Fixture::new();
        let console = f.console();
        f.host.point_curusr(&mut f.machine, console).expect("channel 0 is current");
        assert_eq!(f.host.gsbl_mut().next_status(console), None, "nothing queued yet");

        let ret = f.invoke(injacr, &[]).expect("injacr");
        assert_eq!(ret, Ret::Void);
        assert_eq!(
            f.host.gsbl_mut().next_status(console),
            Some(Gsbl::CRSTG),
            "the deferred stand-in for hdlcri's synchronous dispatch"
        );
    }

    #[test]
    fn injacr_with_no_current_channel_is_an_error_not_a_panic() {
        let mut f = Fixture::new();
        assert!(f.invoke(injacr, &[]).is_err(), "usrnum starts at -1, naming no channel");
    }

    #[test]
    fn hdlinp_leaves_the_dispatch_queue_untouched_and_notes_why() {
        let mut f = Fixture::new();
        let console = f.console();
        f.host.point_curusr(&mut f.machine, console).expect("channel 0 is current");
        let notes_before = f.host.notes().len();

        let ret = f.invoke(hdlinp, &[]).expect("hdlinp");
        assert_eq!(ret, Ret::Void);
        assert_eq!(
            f.host.gsbl_mut().next_status(console),
            None,
            "no approximation is attempted -- see this routine's own doc comment"
        );
        assert!(f.host.notes().len() > notes_before, "the gap is recorded, not silent");
        assert!(f.host.notes().last().unwrap().contains("hdlinp"));
    }
}
