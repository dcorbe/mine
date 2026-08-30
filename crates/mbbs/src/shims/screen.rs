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
//! back to actually pause a channel's output. **This is reached, not
//! hypothetical: long room descriptions, `look` output and `help` text will
//! scroll straight past without pausing, on paths an ordinary player reaches
//! every session.** An earlier draft of this comment claimed `btuxnf` "never
//! once passes a negative `xoff`" and that page mode was unreached. That was
//! wrong -- it also contradicted `btuxnf`'s own doc comment in
//! `shims/gsbl.rs`, which already said "eight others (page mode)" before
//! this file existed, while citing that comment as agreeing. Here is what is
//! actually measured:
//!
//! * `re/ne_arity.py`'s `call_sites(data, 60, want_module='GALGSBL')` finds
//!   all 14 of `WCCMMUD.DLL`'s `btuxnf` (GALGSBL ordinal 60) call sites and
//!   splits them by the stack cleanup that follows: **6 sites clean 6
//!   bytes** (3 words -- plain flow control, `xon`/`xoff` only) and **8
//!   sites clean 12 bytes** (6 words -- the page-mode shape, because a
//!   negative `xoff` pushes two more arguments, `cnt` and the far pointer
//!   `stg`). **Eight of fourteen select page mode.**
//! * Two of the eight are visible with full arguments in
//!   `re/exports/WCCMMUD_named.c`: **line 37977** and **line 62401**, both
//!   passing `0xffed` -- **-19** as a signed 16-bit value, the same -19
//!   `rstrxf` itself passes. Their enclosing functions are verified: line
//!   37977 is inside `_DISPLAY_LONG_TEXT` (declared line 37949), the
//!   module's paginated-text primitive behind room/protected-room messages
//!   and item/monster descriptions; line 62401 is inside `_CMD_SYSOP`
//!   (declared line 61289), which is at least admin-gated.
//! * Three more are traced to an enclosing function without that same
//!   full-argument confirmation: line 35993 to `_DISPLAY_DESC_FROM_FILE`
//!   (reached from `_DISPLAY_ROOM_DESC`, i.e. the `look` command), line
//!   44741 to `_HELP_TEXT` (the player's `help` command), and line 12020 to
//!   `_END_RELEASE_NOTE_LISTING` (rare/administrative). **Four of the eight
//!   page-mode call sites were not identified at all** -- this is not a
//!   complete map of where MajorMUD enters page mode, and it should not be
//!   read as one.
//! * `btuhpk`/`btupbc`/`btucpc` are still not `WCCMMUD.DLL` imports
//!   themselves -- the module drives page mode through `btuxnf` alone, and
//!   the only caller either of the other three could ever have in this host
//!   is `rstrxf`, below. How a genuine board wires up the pause handler and
//!   pause/clear-pause characters for a module that never imports the
//!   routines that set them is not measured here -- presumably part of the
//!   real host's own connection setup, upstream of anything `WCCMMUD.DLL`
//!   calls.
//! * MajorMUD has no "more" prompt of its own in
//!   `re/exports/WCCMMUD_named.c` -- it delegates pause-and-continue
//!   entirely to the host through `btuxnf`'s page-mode arguments, which is
//!   what makes this host's non-implementation observable rather than inert.
//!
//! **Why the stub stands anyway.** The goal of this host is running a
//! module headless, not reproducing MajorBBS, and scroll-without-pause
//! degrades presentation without breaking play -- the text still arrives,
//! in order, complete, to a client that has its own scrollback. Pagination
//! means a driver loop that holds output, counts lines and waits for a
//! keystroke across room entry, `look`, `help` and sysop text, for a return
//! that is purely cosmetic against a modern client. That trade is approved
//! and is not being reversed by this task -- what was wrong was calling
//! those paths "unreached" instead of naming what a player actually sees.
//!
//! **What would show this is wrong:** nothing further needs to turn up --
//! it already has. The concrete next step, if this is ever revisited, is
//! finishing the map above: the four page-mode call sites `re/ne_arity.py`
//! located but this pass did not identify. Until then, the state these four
//! routines already record (`page_lines`, `page_message`, `pause_char`,
//! `clear_pause_char`, `pause_handler_installed`) is what a real pagination
//! implementation would start from -- recording it now is what makes that
//! later work additive instead of a rewrite.

use mbbs_machine::ptr::ModulePtr;

use super::ShimError;
use super::gsbl::{apply_cpc, apply_hpk, apply_pbc, apply_xnf};
use crate::Host;
use crate::abi::{self, Abi, Call, Wg16};
use crate::chan::Chan;

/// `VIDAPI.H:193` (Worldgroup 3.3): `#define GVIDSCNSIZ 4000` -- bytes per
/// 80x25 screen image, 2 per cell (character, attribute). What [`iniscn`]
/// reads and, when `where` is non-null, writes.
const GVIDSCNSIZ: usize = 4000;

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
fn account_scnbrk<A: Abi>(mem: &A::Mem, host: &Host<A>, chan: Chan) -> Result<i8, ShimError> {
    let account = host.users().account(chan);
    let at = A::ptr_offset(account, host.users().account_layout().scnbrk);
    let byte = at
        .resolve(mem, 1)
        .map_err(|e| ShimError::Failed(e.to_string()))?[0];
    Ok(byte as i8)
}

/// `void rstrxf(void)` -- restore screen-length to the account setting.
/// `MAJORBBS.C:3776` (wg1). See this module's own doc comment for what it
/// does and does not do in this host, and for where its one real call site
/// actually leads.
///
/// # `scnbrk`'s default in this host
///
/// [`AccountLayout::scnbrk`](crate::users::AccountLayout)'s own doc comment:
/// `Host::connect_state`
/// never writes this byte, so it reads whatever the account's memory already
/// held -- ordinarily zero, since nothing else writes it either. `0-CTNUOS`
/// is `-2`, and that negative `cnt` lands in `Channel::page_lines` as
/// `0xfffe` the same way a real negative `int` argument would land in a
/// 16-bit `cnt` parameter -- harmless, because `page_lines` is never acted
/// on (see [`crate::shims::gsbl::apply_xnf`]'s doc comment). This is `rstrxf`
/// computed faithfully against a host that does not model `scnbrk`, not a
/// special case carved out for it.
///
/// Generic: reads no argument of its own. Reached **only** through module
/// dispatch (its one `ROUTINES` entry, and its own module doc comment's "one
/// real call site") -- never as an internal helper with no call frame -- so
/// there is no `arg_frame()` panic to guard against the way `clrprf`/`parsin`
/// had to (`shims::text`'s own doc comment).
pub fn rstrxf<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = host.current_channel_mem(call.mem())?;
    restore_screen(host, call.mem(), chan)?;
    Ok(abi::Ret::Void)
}

/// `rstrxf`'s body, for the two callers that need it: the shim above, and
/// [`crate::Host::connect_state`] -- the host's own `figlang`
/// (`MAJORBBS.C:2465-2468`) calls `rstrxf()` for every channel at login, so
/// a connecting channel has these settings before the module sees it.
///
/// # Errors
///
/// If the account's `scnbrk` cannot be read.
pub(crate) fn restore_screen<A: Abi>(host: &mut Host<A>, mem: &A::Mem, chan: Chan) -> Result<(), ShimError> {
    let scnbrk = account_scnbrk(mem, host, chan)?;
    let cnt = (i16::from(scnbrk) - CTNUOS) as u16;

    let g = host.gsbl_mut();
    apply_xnf(g, chan, 0, -19, Some((cnt, PAUSE_MESSAGE.to_vec())));
    apply_hpk(g, chan);
    apply_pbc(g, chan, 20);
    apply_cpc(g, chan, 19);
    Ok(())
}

/// `void explode(char *sctptr, int wulx, int wuly, int wlrx, int wlry)` --
/// pop a shadowed window onto the SYSOP's local console, animated.
///
/// `re/wg33src/SRC/api/gcommlib/EXPLODE.C:36-45` (Worldgroup 3.3, 1997):
/// `explode(sctptr,wulx,wuly,wlrx,wlry)` is
/// `explodell(sctptr,wulx,wuly,wlrx,wlry,wulx,wuly,1)` -- the private
/// `explodell` worker, called with the "from" and "to" rectangles the same
/// (no repositioning) and shadowing on. `explodell` itself
/// (`EXPLODE.C:73-163`) reads `sctptr` as an 80x25 CGA/VGA text-mode screen
/// image (2 bytes/cell) and grows a rectangle of it, cell by cell, onto the
/// SYSOP's own local console video memory (`scn2scn`/`mem2scn`, `gvscnoff`),
/// with a one-cell drop shadow along the bottom and right edges once the
/// growth finishes, paced by `gcdelay(10)` between frames.
///
/// # Why this is a no-op here, not a partial reproduction
///
/// Every one of `explodell`'s primitives -- `scn2scn`, `mem2scn`,
/// `gvscnoff`, `scngetc`/`scnputc`, `gcdelay` -- addresses a local
/// text-mode video buffer this host does not have and, by design, never
/// will: [`Host::paccin`](crate::Host::paccin)'s own doc comment already
/// declines the "modem monitor" (the SYSOP's local console) as "BBS-shaped
/// and out of scope" for a headless host, and this is the same console.
/// There is no CRT to draw a window on and no SYSOP sitting in front of one,
/// so the closest faithful behaviour is what a real Worldgroup running with
/// no local console attached would produce: no visible effect, and no
/// error. The routine's whole purpose (a cosmetic local-console animation)
/// is unreachable by construction on this host, not merely unimplemented.
///
/// `explodeto`/`nsexploto`, `explodell`'s other two callers, are not
/// imported by any of the ten surveyed builds and are not added here.
///
/// # What is still checked
///
/// A non-null `sctptr` is read (one byte, thrown away) so a module passing
/// a genuinely bad pointer stops here rather than appearing to have drawn a
/// window it did not. A null `sctptr` is accepted without reading it --
/// `explodell` itself branches on `sptr == 0` to mean "read from the live
/// screen instead of a memory image", a legitimate argument this host has
/// no live screen to honour either way, so there is nothing to read.
///
/// One import, one call site: Rose (`re/ne_arity.py 198
/// tmp/gapsurvey/rose/RCIROSE.DLL` cleans 6 words -- one far pointer plus
/// four ints, matching the header). 16-bit only
/// (`tmp/gapsurvey/round2/out_rose_pe.txt` does not import it), so this is
/// generic rather than `WG16_ROUTINES`-only: nothing here depends on a
/// GCV2-only structure the way [`crate::shims::user::extoff`] does, so a
/// future 32-bit importer would already be served.
///
/// # Errors
///
/// If `sctptr` is non-null and not even one byte of it can be read.
pub fn explode<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let sctptr = call.ptr();
    let _wulx = call.int();
    let _wuly = call.int();
    let _wlrx = call.int();
    let _wlry = call.int();

    if sctptr != A::null_ptr() {
        sctptr
            .resolve(call.mem(), 1)
            .map_err(|e| ShimError::Failed(format!("explode: sctptr: {e}")))?;
    }

    Ok(abi::Ret::Void)
}

/// `void iniscn(char *filnam, void *where)` -- load a `.SCN` binary screen
/// image file, either into a caller's buffer or (if `where` is null) onto
/// the local console screen directly.
///
/// `re/wg33src/SRC/api/gcommlib/INISCN.C:18-40` (Worldgroup 3.3, 1997):
///
///
/// # What this host reproduces, and why
///
/// The file I/O, the exact byte count ([`GVIDSCNSIZ`], 4000 -- 80x25 cells
/// at 2 bytes each, `re/wg33src/INC/VIDAPI.H:193`), and both `catastro`
/// paths are faithful: refusing (stopping the module) rather than
/// fabricating success on a missing or short file is what the vendor's own
/// `catastro` does too -- a hard stop, just a fatal one instead of a
/// refusal. `cvtscn` (`re/wg33src/SRC/api/gcommlib/CVTSCN.C:19-55`) is
/// reproduced as the no-op it always is on a modern, colour-capable board:
/// its entire body is gated on `if (!color)` -- monochrome-only, remapping
/// cell attributes for a screen mode this host does not have -- so a
/// `color` build (every board this host has ever measured or could plausibly
/// serve over telnet) runs `cvtscn` and changes nothing. Drawing to the
/// local console when `where` is null is the same "no CRT to draw on" case
/// [`explode`]'s own doc comment covers: the file is still opened and its
/// 4000 bytes still validated (a bad file is still a refusal either way),
/// but nothing visible happens, because nothing here has a screen either
/// way.
///
/// One import, one call site: Rose (`re/ne_arity.py 346
/// tmp/gapsurvey/rose/RCIROSE.DLL` cleans 4 words -- one far pointer per
/// argument, matching the header). 16-bit only, and generic for the same
/// reason [`explode`]'s own doc comment gives.
///
/// # Errors
///
/// If `filnam` cannot be read, names a file this host will not open or does
/// not find, or that file is shorter than [`GVIDSCNSIZ`] bytes.
pub fn iniscn<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let filnam = call.ptr();
    let dest = call.ptr();

    let named = String::from_utf8_lossy(
        filnam
            .read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(format!("iniscn: filnam: {e}")))?,
    )
    .into_owned();
    let name = Host::<Wg16>::dos_name(&named).map_err(ShimError::Failed)?;
    let path = host.find(&name).ok_or_else(|| {
        ShimError::Failed(format!("iniscn: \"{named}\" not found -- INISCN UNABLE TO OPEN"))
    })?;
    let bytes = std::fs::read(&path)
        .map_err(|e| ShimError::Failed(format!("iniscn: \"{named}\" -- INISCN UNABLE TO OPEN: {e}")))?;
    if bytes.len() < GVIDSCNSIZ {
        return Err(ShimError::Failed(format!(
            "iniscn: \"{named}\" is {} bytes -- INISCN ERROR READING (need {GVIDSCNSIZ})",
            bytes.len()
        )));
    }

    if dest != A::null_ptr() {
        dest.write(call.mem(), &bytes[..GVIDSCNSIZ])
            .map_err(|e| ShimError::Failed(e.to_string()))?;
    }
    // `cvtscn(where)`: a no-op under `color`, which this host always is --
    // see this function's own doc comment.

    Ok(abi::Ret::Void)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;
    use mbbs_machine::m16::FarPtr;

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
            offset: account.offset + f.host.users().account_layout().scnbrk,
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
        // `MAJORBBS.C:4490` is `btuxnf(usrnum,0,-19,...)` followed two lines
        // later by `btucpc(usrnum,19)`, and `hpkrou` just below it has
        // `case 19: /* XOFF char (CTRL-S) */`. So 19 is the character and
        // `-19`'s sign is the page-mode flag, nothing more -- which is why
        // this asserts the magnitude and not `-19`'s two's-complement bits.
        //
        // It used to assert `0xed`, with the comment "-19 as btuxnf would
        // store it". That was the bug wearing its own explanation: 237 is a
        // byte no terminal sends, and it disagreed with the
        // `clear_pause_char == 19` four lines below it -- the same character,
        // asserted two different ways in one test.
        assert_eq!((c.xon, c.xoff), (0, 19), "btuxnf(0,-19) -- CTRL-S, page mode on");
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

    // ---- explode --------------------------------------------------------

    #[test]
    fn explode_does_not_stop_the_module() {
        // No local console to draw on -- the whole point of the routine is
        // unreachable here, so the only thing to prove is that a module
        // calling it keeps running.
        let mut f = Fixture::new();
        let img = f.bytes(&[0x41, 0x07, 0x42, 0x07], false);
        f.invoke(explode, &[img.offset, img.selector, 0, 0, 79, 24])
            .expect("explode does not stop the machine");
    }

    #[test]
    fn explode_accepts_a_null_sctptr() {
        // `sptr == 0` means "read from the live screen" in the vendor body
        // -- a legitimate argument this host has no screen to honour either
        // way, not a bad pointer.
        let mut f = Fixture::new();
        f.invoke(explode, &[0, 0, 0, 0, 79, 24])
            .expect("a null sctptr is accepted");
    }

    #[test]
    fn explode_refuses_an_unreadable_sctptr() {
        // A module passing a genuinely bad pointer must stop here, not
        // silently appear to have drawn a window it did not.
        let mut f = Fixture::new();
        f.invoke(explode, &[0x9999, 0x9999, 0, 0, 79, 24])
            .expect_err("an unresolvable sctptr is refused");
    }

    // ---- iniscn -----------------------------------------------------------

    #[test]
    fn iniscn_loads_a_full_scn_file_into_the_supplied_buffer() {
        // GVIDSCNSIZ (4000 bytes) exactly -- not the plan's own sample
        // test's 512-byte buffer, which would have been an under-allocation
        // this routine writes straight past (memory note: round-trip tests
        // are blind to under-allocation; a 4000-byte destination is the only
        // one this routine's own vendor body ever writes).
        let root = crate::testing::scratch("screen-iniscn-full");
        let mut f = Fixture::rooted(root.clone());
        let mut image = vec![0u8; GVIDSCNSIZ];
        for (i, b) in image.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        std::fs::write(root.join("TEST.SCN"), &image).expect("fixture");

        let path = f.text("TEST.SCN");
        let dest = f.buffer(GVIDSCNSIZ as u16);
        f.invoke(iniscn, &[path.offset, path.selector, dest.offset, dest.selector])
            .expect("iniscn");

        let at = FarPtr { offset: dest.offset, selector: dest.selector };
        let got = f.machine.resolve(at, GVIDSCNSIZ).expect("dest is readable");
        assert_eq!(got, image.as_slice(), "every one of the 4000 bytes must round-trip, not just the first few");
    }

    #[test]
    fn iniscn_on_a_missing_file_is_refused() {
        let mut f = Fixture::rooted(crate::testing::scratch("screen-iniscn-missing"));
        let path = f.text("NOSUCH.SCN");
        let dest = f.buffer(GVIDSCNSIZ as u16);
        f.invoke(iniscn, &[path.offset, path.selector, dest.offset, dest.selector])
            .expect_err("a refusal");
    }

    #[test]
    fn iniscn_on_a_short_file_is_refused_not_padded() {
        // The vendor's own `catastro` on a short read is fatal, not
        // tolerant -- a short `.SCN` is not the "vendor tolerates" case.
        let root = crate::testing::scratch("screen-iniscn-short");
        let mut f = Fixture::rooted(root.clone());
        std::fs::write(root.join("SHORT.SCN"), vec![0x41u8; GVIDSCNSIZ - 1]).expect("fixture");

        let path = f.text("SHORT.SCN");
        let dest = f.buffer(GVIDSCNSIZ as u16);
        f.invoke(iniscn, &[path.offset, path.selector, dest.offset, dest.selector])
            .expect_err("a refusal, not a short/zero-padded load");
    }

    #[test]
    fn iniscn_with_a_null_where_still_validates_the_file_but_writes_nothing() {
        // `where == 0` means "draw straight onto the local console" in the
        // vendor body. There is no console here, so the only observable
        // behaviour left is the file validation itself.
        let root = crate::testing::scratch("screen-iniscn-null-where");
        let mut f = Fixture::rooted(root.clone());
        std::fs::write(root.join("TEST.SCN"), vec![0x41u8; GVIDSCNSIZ]).expect("fixture");
        let path = f.text("TEST.SCN");
        f.invoke(iniscn, &[path.offset, path.selector, 0, 0])
            .expect("a null where is accepted once the file itself is valid");

        // And a missing file is still refused even with where == 0 --
        // proving the file check runs regardless of where the bytes would
        // have gone.
        let missing = f.text("NOSUCH.SCN");
        f.invoke(iniscn, &[missing.offset, missing.selector, 0, 0])
            .expect_err("a missing file is refused even with a null where");
    }
}
