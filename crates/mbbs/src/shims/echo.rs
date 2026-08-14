//! Six routines named at `MAJORBBS.H:679-733` and `BRKTHU.H:185`, cited
//! throughout against the **wg1** tree
//! (`archive/galacticomm/extract/wg1/GALDSRC/SRC`) -- wg20 renumbers every
//! one of these lines, see `crate::shims::gsbl`'s sibling doc comment on
//! citing wg1.
//!
//! Five of the six are `MAJORBBS.C` routines that read `usrnum` implicitly
//! rather than taking a channel argument (`echon`, `echsec`, `injacr`,
//! `hdlinp`, `instat` -- the last takes a `char *uid` to search *for*, which
//! is a different thing from a channel to act *on*). The sixth, `btuxmn`,
//! is the one genuine `GALGSBL` import here, and is grouped with these
//! rather than filed in `crate::shims::gsbl` because its only vendor context
//! is a call site inside `MAJORBBS.C` (`dftinj`, see [`btuxmn`]'s own doc
//! comment) -- `GALGSBL`'s own source was never recovered (no `.C` file for
//! it exists anywhere under `archive/`), so there is no companion routine of
//! its own to sit next to.
//!
//! # What none of these six can do, and why
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

use mbbs_machine::ptr::ModulePtr;
#[cfg(test)]
use mbbs_machine::m16::Ret;

use super::ShimError;
use super::gsbl::OUT_OF_RANGE;
use crate::Host;
use crate::abi::{self, Abi, Call};
use crate::gsbl::Gsbl;
use crate::users::{user, usracc};

/// `void echon(void)` -- `MAJORBBS.C:3840-3844`:
///
///
/// Fully implemented, as a straight call on `usrnum`. Not literally a call
/// to [`crate::shims::gsbl::echonu`] -- that function reads its channel
/// argument off the module's own argument frame with `call.int()`, and
/// `echon` has no argument frame to forward (`void echon(void)`); the
/// channel it means is `usrnum`, read back the way
/// [`Host::current_channel_mem`] always does. So this restates `echonu`'s
/// one line of *behaviour* against a [`Chan`](crate::chan::Chan) it already
/// has, rather than fabricate an argument frame to call through. Every
/// simplification `echonu`'s own doc comment records -- no `echtyp`/`grpnum`
/// table, so every channel's group echo type is "on" -- applies here
/// unchanged, for the same reason: this host is what it is regardless of
/// which of the two routines asks.
///
/// # Errors
///
/// If `usrnum` does not name a channel of this host (propagated from
/// [`Host::current_channel_mem`]).
pub fn echon<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = host.current_channel_mem(call.mem())?;
    host.gsbl_mut().channel_mut(chan).echo = true;
    Ok(abi::Ret::Void)
}

/// `void echsec(char ech,int lwidth)` -- `MAJORBBS.C:3857-3867`:
///
///
/// **Partially implemented: only the first line.** `btuech(usrnum,0)` turns
/// ordinary echo off, and that much this host has -- it is
/// [`crate::gsbl::Channel::echo`], the exact field
/// [`crate::shims::gsbl::btuech`] sets. The other four lines are the actual
/// point of the routine -- masking each keystroke as `ech` (`'*'` in every
/// real caller) instead of showing nothing -- and none of the three things
/// they need exist in this host:
///
/// - `extptr->col`/`wid`/`ech` are fields of `struct extusr`
///   (`MAJORBBS.H:94-107`). This host's `EXTUSR` block (`crate::users`,
///   `EXTUSR: u16 = 22`) is sized correctly but has **no fields placed in
///   it** -- `crates/mbbs/src/users.rs:29-35`'s own doc comment: "neither
///   `extusr` nor `extptr`" are named, because nothing this host has loaded
///   addresses them. There is nowhere to write `col`, `wid` or `ech` without
///   inventing an offset into that block myself, which is not a
///   simplification, it is fabricating a struct layout with no vendor
///   source and no measurement behind it.
/// - `secchi` (`MAJORBBS.C:3869-3901`, `STATIC`) is the per-character
///   interceptor `btuchi` installs, and it is what actually substitutes
///   `ech` for the typed character on the way out. `crate::gsbl::Channel`
///   has no interception point at all: input is cooked (backspace handling,
///   line assembly, echo) entirely inside `Channel::take`, invisibly to
///   every shim in this crate, and there is no `btuchi` shim anywhere in
///   this host for the same reason `crate::shims::gsbl`'s own doc comment
///   gives for `btuhpk`/`btupbc`/`btucpc` being registered without being
///   imported: unlike those three, `btuchi` is not even in that list,
///   because nothing in this host could act on the far pointer it takes.
///
/// So this clears the one bit that has somewhere to go and stops. A caller
/// that typed a password under this host would see **nothing** echoed back,
/// not asterisks -- degraded, not wrong in the sense of showing the
/// password, and not silently pretending to be the real thing either.
///
/// **This does not make [`crate::shims::gsbl::echonu`]'s "unreachable
/// branch" reachable.** That note says `extptr->wid` can never be positive
/// because nothing sets it; this routine is the *only* thing in the vendor
/// that ever would, and it is exactly the write this implementation cannot
/// make, for the reason above. `wid` stays permanently absent, so
/// `echonu`'s `if (extptr->wid > 0)` teardown remains dead code in this host
/// even after this function exists -- unlike a routine that was merely
/// unregistered, no future registration of `echsec` would change that
/// without `EXTUSR` first growing a real `wid` field, which is a
/// `users.rs`-owned change this file does not make.
///
/// # Arguments
///
/// Neither `ech` nor `lwidth` is read off the call frame: there is nowhere
/// in this host that could hold either one (see above), so reading them
/// into local bindings nothing does anything with would document nothing
/// [`btuhpk`](crate::shims::gsbl::btuhpk)'s own doc comment does not already
/// say about its own unread argument. Silent for the same reason: `echsec`
/// is `Cleans::Caller` like every routine in this table, so the module
/// itself pops both words regardless of whether this function ever reads
/// them.
///
/// # Errors
///
/// If `usrnum` does not name a channel of this host.
pub fn echsec<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = host.current_channel_mem(call.mem())?;
    host.gsbl_mut().channel_mut(chan).echo = false;
    Ok(abi::Ret::Void)
}

/// `void injacr(void)` -- `MAJORBBS.C:2559-2567`:
///
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
///
/// **Not implementable with a faithful approximation -- implemented as a
/// documented no-op.** This file's module doc comment covers why no shim
/// can reach `hdlcri` at all; [`injacr`]'s own doc comment covers why
/// queueing `CRSTG` and deferring is nonetheless an honest stand-in *for
/// that routine*. Neither escape applies here, for reasons specific to how
/// the wg1 tree actually calls `hdlinp` directly (as opposed to through
/// `injacr`):
///
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

/// `int instat(char *uid,int qstate)` -- `MAJORBBS.C:3057-3072`:
///
///
/// **Fully implemented.** Every piece this needs is already something this
/// host places and a shim can read: `user[i].state`
/// ([`crate::users::Users::state_mem`]), `uacoff(i)->userid`
/// ([`crate::users::Users::account`] offset by
/// [`crate::users::usracc::USERID`]) and `user[i].flags`
/// ([`crate::users::Users::slot`] offset by [`crate::users::user::FLAGS`]).
/// `othexp` (`extoff(othusn)`, the extra-user pointer) is read by the
/// vendor and never used inside the loop body -- dead in the original, so
/// there is nothing to reproduce.
///
/// `sameas` (`MAJORBBS.C`, case-insensitive) is
/// [`crate::strings::sameas`], the same free function
/// [`crate::shims::text::sameas`] calls through.
///
/// `INVISB` is `0x00004000L` (`MAJORBBS.H:214`) -- bit 14 of the 4-byte
/// little-endian `flags`, which is bit 6 of the *second* byte
/// (`FLAGS + 1`), by the same per-byte addressing
/// `crates/mbbs/src/users.rs`'s own `the_master_flag_lands_on_the_bit_
/// majorbbs_h_names` test measures for `MASTER` (`0x40`, bit 6 of the
/// *first* byte, `FLAGS + 0`) -- a different bit of the same field, read
/// the same way, not guessed at.
///
/// A match whose owner *is* invisible does not return 0 immediately: the
/// vendor's loop falls through to the next channel rather than stopping,
/// in case some other channel matches with `INVISB` clear. This function's
/// loop does the same -- there is no early return in the invisible case,
/// only the absence of one, so the `for` simply continues.
///
/// # Errors
///
/// If `uid` is not a valid pointer, or if any channel's `state` cannot be
/// read (both would mean the module handed this a bad argument, or this
/// host's own tables are inconsistent -- either way the caller should stop,
/// not guess).
pub fn instat<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let uid_ptr = call.ptr();
    let qstate = Into::<u32>::into(call.int()) as u16;
    let uid = uid_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    for chan in host.gsbl().terms().all() {
        let state = host.users().state_mem(call.mem(), chan)?;
        if state != qstate {
            continue;
        }

        let account = host.users().account(chan);
        let userid_ptr = A::ptr_offset(account, usracc::USERID as u16);
        let userid = userid_ptr
            .read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        if !crate::strings::sameas(&uid, userid) {
            continue;
        }

        let slot = host.users().slot(chan);
        let flags1 = A::ptr_offset(slot, user::FLAGS + 1);
        let byte = flags1
            .resolve(call.mem(), 1)
            .map_err(|e| ShimError::Failed(e.to_string()))?[0];
        if byte & 0x40 == 0 {
            return Ok(abi::Ret::Int(A::Int::from(1u16)));
        }
    }
    Ok(abi::Ret::Int(A::Int::from(0u16)))
}

/// `int btuxmn(int chan,char *datstg)` -- `BRKTHU.H:185`.
///
/// **`GALGSBL`'s own source was never recovered**: no `.C` file under
/// `archive/` implements it, unlike `MAJORBBS.C` for the host proper --
/// `crate::shims::gsbl`'s own module doc comment notes the same absence for
/// every routine in that file. What is available instead:
///
/// 1. Its one call site in the wg1 tree, `MAJORBBS.C:3933-3939`'s `dftinj`
///    ("default injection routine" -- what runs when a module's own
///    `injrou` is absent):
///
///
///    `prfbuf` is the module's formatted-output buffer -- an ASCIIZ string,
///    the same shape `btuxmt` takes -- being pushed into `othusn`'s channel
///    as an *injected* message (a page/talk-style interrupt), immediately
///    followed by `btuoes` (raise status on buffer-empty) rather than
///    anything wrap-related.
/// 2. `docs/mirrors/github-mbbsemu-MBBSEmu`'s independent reimplementation
///    (`MBBSEmu/HostProcess/ExportedModules/Galgsbl.cs:712-725`), an MIT
///    project with no shared authorship with this host, cross-checked
///    rather than trusted alone:
///
///
///    Compared with the same file's own `btuxmt` (`:525-542`), which reads
///    an ASCIIZ string the identical way and then runs it through
///    `FormatOutput` (word wrap, ANSI, text variables) before sending --
///    `btuxmn` skips that step and sends the raw bytes. Both sources agree:
///    an ASCIIZ string, sent to an explicit channel, bypassing whatever
///    output formatting `btuxmt` applies.
///
/// **Implemented as `btuxmt`'s cstr-read paired with `btuxct`'s raw
/// transmit**: [`crate::gsbl::Gsbl::transmit`] (what `btuxmt` calls) is the
/// one that word-wraps at `Channel::width`; [`crate::gsbl::Gsbl::
/// transmit_raw`] (what `btuxct` calls) sends the bytes exactly as given
/// and is what both sources above describe `btuxmn` doing. The length
/// comes from a NUL scan (`btuxmt`'s convention -- `char *datstg`, not
/// `btuxct`'s explicit `nbyt`), so this reads like `btuxmt` and transmits
/// like `btuxct`.
///
/// `-11` (out of range) is the only refusal this host can raise, for the
/// reason every other `GALGSBL` routine in this crate gives:
/// `crate::shims::gsbl`'s module doc comment on why `-10` is unreachable.
pub fn btuxmn<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    let at = call.ptr();
    let Some(chan) = host.gsbl().terms().chan(chan) else {
        return Ok(abi::Ret::Int(A::Int::from(OUT_OF_RANGE)));
    };
    let text = at
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    host.gsbl_mut().transmit_raw(chan, &text);
    Ok(abi::Ret::Int(A::Int::from(0u16)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::Wg16;
    use crate::testing::Fixture;

    #[test]
    fn echon_restores_echo_on_the_current_channel() {
        let mut f = Fixture::new();
        let console = f.console();
        f.host.point_curusr(&mut f.machine, console).expect("channel 0 is current");
        f.host.gsbl_mut().channel_mut(console).echo = false;

        let ret = f.invoke(echon, &[]).expect("echon");
        assert_eq!(ret, Ret::Void);
        assert!(f.host.gsbl().channel(console).echo);
    }

    #[test]
    fn echsec_turns_ordinary_echo_off_and_nothing_else() {
        // The vendor's whole point -- masking each keystroke as `ech` -- is
        // not implemented (see this function's own doc comment), so this
        // only pins the one line this host can do: echo off. There is
        // nowhere to assert `ech`/`lwidth` landed, because nothing records
        // them.
        let mut f = Fixture::new();
        let console = f.console();
        f.host.point_curusr(&mut f.machine, console).expect("channel 0 is current");
        assert!(f.host.gsbl().channel(console).echo, "the default");

        let ret = f.invoke(echsec, &[u16::from(b'*'), 40]).expect("echsec");
        assert_eq!(ret, Ret::Void);
        assert!(!f.host.gsbl().channel(console).echo);
    }

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

    #[test]
    fn instat_finds_a_matching_userid_in_the_matching_state() {
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(3));
        let zero = f.host.gsbl().terms().chan(0).expect("channel 0");
        let one = f.host.gsbl().terms().chan(1).expect("channel 1");

        f.host
            .connect_state(&mut f.machine, zero, &crate::users::Connection::ansi("kaimon"))
            .expect("channel 0 connected");
        f.host
            .connect_state(&mut f.machine, one, &crate::users::Connection::ansi("rangerdan"))
            .expect("channel 1 connected");
        // `connect_state` writes `state` as zero for both -- see its own doc
        // comment -- so both channels start in the same state and the
        // userid is what distinguishes the search.
        assert_eq!(f.host.users().state_mem(Wg16::mem(&mut f.machine), zero).unwrap(), 0);

        f.host.point_curusr(&mut f.machine, zero).expect("current");
        let uid = f.text("rangerdan");
        let ret = f.invoke(instat, &[uid.offset, uid.selector, 0]).expect("instat");
        assert_eq!(ret, Ret::U16(1), "rangerdan is on channel 1, in state 0");

        let missing = f.text("nobody");
        let ret = f
            .invoke(instat, &[missing.offset, missing.selector, 0])
            .expect("instat");
        assert_eq!(ret, Ret::U16(0), "no channel has this userid");
    }

    #[test]
    fn instat_refuses_a_userid_found_only_in_the_wrong_state() {
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(2));
        let one = f.host.gsbl().terms().chan(1).expect("channel 1");
        f.host
            .connect_state(&mut f.machine, one, &crate::users::Connection::ansi("rangerdan"))
            .expect("channel 1 connected");
        f.host
            .users
            .set_state_mem(Wg16::mem(&mut f.machine), one, 5)
            .expect("state set");

        f.host.point_curusr(&mut f.machine, one).expect("current");
        let uid = f.text("rangerdan");

        let ret = f
            .invoke(instat, &[uid.offset, uid.selector, 0])
            .expect("instat against the wrong state");
        assert_eq!(ret, Ret::U16(0), "rangerdan is in state 5, not 0");

        let ret = f
            .invoke(instat, &[uid.offset, uid.selector, 5])
            .expect("instat against the right state");
        assert_eq!(ret, Ret::U16(1));
    }

    #[test]
    fn instat_skips_an_invisible_match_but_keeps_looking() {
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(3));
        let one = f.host.gsbl().terms().chan(1).expect("channel 1");
        let two = f.host.gsbl().terms().chan(2).expect("channel 2");
        f.host
            .connect_state(&mut f.machine, one, &crate::users::Connection::ansi("rangerdan"))
            .expect("channel 1 connected");
        f.host
            .connect_state(&mut f.machine, two, &crate::users::Connection::ansi("rangerdan"))
            .expect("channel 2 connected, same userid, still visible");

        // `INVISB` is `0x00004000` (`MAJORBBS.H:214`): bit 6 of `FLAGS + 1`,
        // by the same per-byte addressing `users.rs`'s own master-flag test
        // measures for `MASTER` at `FLAGS + 0`. Channel 1 alone is marked
        // invisible.
        let slot = f.host.users().slot(one);
        let flags1 = mbbs_machine::m16::FarPtr {
            offset: slot.offset + user::FLAGS + 1,
            selector: slot.selector,
        };
        let was = f.machine.resolve(flags1, 1).expect("in bounds")[0];
        f.machine.write(flags1, &[was | 0x40]).expect("in bounds");

        f.host.point_curusr(&mut f.machine, one).expect("current");
        let uid = f.text("rangerdan");
        let ret = f.invoke(instat, &[uid.offset, uid.selector, 0]).expect("instat");
        assert_eq!(
            ret,
            Ret::U16(1),
            "channel 1's match is invisible, but channel 2's is not"
        );
    }

    #[test]
    fn btuxmn_transmits_raw_and_ignores_the_wrap_width() {
        let mut f = Fixture::new();
        let console = f.console();
        // A width narrow enough that btuxmt would have wrapped this text --
        // see `crate::shims::gsbl`'s own
        // `btuxmt_transmits_and_btutsw_is_what_wraps_it` test for the
        // routine this is deliberately unlike.
        f.host.gsbl_mut().channel_mut(console).width = 10;
        let text = f.text("the quick brown fox");
        f.invoke(btuxmn, &[0, text.offset, text.selector]).expect("transmitted");
        assert_eq!(
            f.host.gsbl_mut().drain_output(console),
            b"the quick brown fox".to_vec(),
            "sent exactly as given, no wrap applied despite the width set above"
        );
    }

    #[test]
    fn btuxmn_refuses_a_channel_out_of_range() {
        let mut f = Fixture::new();
        let past = f.host.gsbl().terms().count();
        let text = f.text("paged");
        let ret = f
            .invoke(btuxmn, &[past, text.offset, text.selector])
            .expect("refused, not an error");
        assert_eq!(ret, Ret::U16(OUT_OF_RANGE));
    }
}
