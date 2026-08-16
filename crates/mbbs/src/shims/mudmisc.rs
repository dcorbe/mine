//! One odd one out: an ASCII file lister that cannot honour its own
//! completion callback.
//!
//! ```text
//! listing  1
//! ```
//!
//! One call site, measured with `re/ne_arity.py` against the symbol's
//! ordinal in `crates/mbbs/data/majorbbs_wg101.tsv` (421) -- it agrees with
//! the vendor prototype's own argument count, cited below.
//!
//! # This file used to hold six more routines, all dead duplicates
//!
//! `injacr`, `byenow`, `locate`, `curcurx`, `curcury` and `msgscan` were
//! removed 2026-08-15 (`docs/2026-08-15-dead-twin-shims.md`): each had a
//! twin registered elsewhere (`shims::echo::injacr`, `shims::misc::byenow`,
//! `shims::output::{locate,curcurx,curcury}`, `shims::misc::msgscan`) that
//! `mod.rs` actually dispatches to, and this crate never called any of the
//! six copies here. Two are worth naming because they were not mere
//! duplication:
//!
//! - **`locate`/`curcurx`/`curcury`, here, treated the routine as
//!   remote-channel cursor control** -- emitting an ANSI CUP escape to the
//!   user's own terminal and reading back `Channel::column`. The registered
//!   `shims::output` twins get this right: `GCOMM.H:427`'s own comment files
//!   `locate`/`curcurx`/`curcury` (with `prat`) under `/* old MBBST.LIB
//!   prototype section */` -- the **local sysop console**, not any remote
//!   channel. MBBSEmu reaches the same conclusion independently (`LOCATE`
//!   sits in its own ignore list, "moves cursor (local screen, not telnet
//!   session)"). This host has no local console to move a cursor on, so the
//!   registered twins are no-ops (`curcury`, additionally, an explicit
//!   refusal) rather than fabricated remote positioning.
//! - **`injacr`, here, called `clrinp()` explicitly** before queueing
//!   `CRSTG`. The registered `shims::echo::injacr` omits that call
//!   deliberately, and argues why it is redundant rather than missing: an
//!   unmatched `CRSTG` (queued with no line behind it) is answered by
//!   [`crate::Host::get_input_mem`] taking `Channel::take_line`'s
//!   `unwrap_or_default()` branch, which writes an empty `input` -- the same
//!   observable effect `clrinp()` produces. See that routine's own doc
//!   comment for the full argument.
//!
//! `byenow`, `curcurx` and `msgscan` agreed with their registered twins (or,
//! for `byenow`, lost to a twin that refuses for a documented architectural
//! reason -- see `shims::misc::byenow`'s own doc comment) and were deleted
//! without any behavioural correction needed.
//!
//! # `hrtval` used to be here too, at the wrong tick rate
//!
//! Removed earlier the same day (`00805d7`), before the twin-shim sweep that
//! found the other six: a second `hrtval`, never registered, deriving ticks
//! at the PC BIOS rate of 1_193_182/65536 Hz (≈18.2065). `shims::misc::hrtval`
//! is the registered one and uses 65536 Hz. They disagreed by a factor of
//! about 3600.
//!
//! `BRKTHU.H:88` settles it outright: `volatile unsigned long btuhrt;`
//! `/* increments 65536 times a second */`. The deleted version's own doc
//! comment claimed no header stated the rate, which was simply a miss --
//! and then reasoned to 18.2 Hz from `MAJORBBS.C:232`'s `LOGONPOL
//! (65535L/10)`, on the grounds that 6553.5 ticks at 18.2 Hz is exactly
//! 360 seconds. Six minutes looks like a logon timeout, so the coincidence
//! read as corroboration.
//!
//! The use site shows it is not one. `MAJORBBS.C:4005` is
//! `if (hrtval()-routime > LOGONPOL) begin_polling(...)` -- a hog detector
//! on a single logon-phase call, switching it to polled mode when it blocks
//! too long. At 65536 Hz that threshold is 0.1 s, which is what a
//! cooperatively scheduled host wants. At 18.2 Hz it is six minutes, by
//! which time the board is dead. The exact-looking match was arithmetic
//! coincidence, not evidence.

use mbbs_machine::ptr::ModulePtr;

use super::ShimError;
use crate::Host;
use crate::abi::{self, Abi, Call};

/// `void listing(char *path, void (*whndun)())` -- "list an ASCII file to
/// the user's screen"; `whndun`'s "optional argument": "1=list completed
/// 0=interrupted". `FILEXFER.H:78` (wg1); body `FILEXFER.C:937-955` (wg1):
///
///
/// # What is reproduced
///
/// The real body's own machinery -- `ftgnew`/`ftgptr`/`tshlst`/`ftgsbm`, the
/// tagspec file-transfer engine (`FILEXFER.C`'s own `tshlst`, reproduced
/// nowhere in this crate) -- exists to fit file listing into the same
/// download-manager UI as a real file transfer: paging, a "more/abort"
/// prompt, permission checks. None of that is modelled here, and none of
/// it is this routine's *observable contract* to a module -- the contract
/// is "the file's text reaches the user's screen, then `whndun` is told
/// how it went". This reproduces the visible half of that: `path` is
/// resolved the same way `shims::msg::opnmsg` resolves a message file name
/// (`Host::find`, matching MajorBBS's own case-insensitive, backslash- or
/// forward-slash-separated DOS paths) and, if found, its bytes are sent to
/// the current channel whole, with no pause-and-continue -- the same
/// "headless, not a MajorBBS reproduction" trade-off
/// `shims::screen::rstrxf`'s own doc comment already makes and defends for
/// page mode generally.
///
/// # What cannot be reproduced, and why this is not a "not implemented yet"
///
/// `whndun` cannot be called, in either branch, by design rather than by
/// gap: a `Shim<A>` is `fn(&mut Call<A>, &mut Host<A>) -> ...` -- it never
/// receives `&A::Module`, and every mechanism this crate has for calling
/// *into* module code needs one. `Host::run` (`lib.rs:2134`, `pub fn run`)
/// takes `module: &A::Module` as an explicit parameter; its one shim-side
/// caller with a comparable job, `crate::shims::fsd::fsdprc`'s callback
/// into `fldvfy` (that file's own "The callback discipline" doc comment),
/// is for exactly that reason **not** a `Shim<A>` -- it is `pub(crate) fn
/// fsdprc(machine, host, module, chan)`, reached through the FSD's own
/// native dispatch slot, which is handed a module reference by its caller
/// that an ordinary import-table entry never is. `listing` is registered
/// as an ordinary `MAJORBBS` import (this file's own module doc comment's
/// registration table), so it has no route to one either. This is a
/// signature-level fact, not a missing feature: adding one would mean
/// changing what a `Shim<A>` is handed, which is outside this file's
/// ownership and this task's scope.
///
/// So this always ends in [`ShimError::Failed`] after doing the printable
/// part, in both the found and not-found cases -- the real body calls
/// `whndun` unconditionally either way, so there is no branch where this
/// routine could complete successfully without the call this host cannot
/// make.
///
/// # Errors
///
/// If no channel is current, if `path` cannot be read as a string, or if a
/// resolved file cannot be read -- and, unconditionally past that point,
/// [`ShimError::Failed`] naming the `whndun` gap above.
///
/// Generic: reads its two fixed pointer arguments (`path`, `whndun`),
/// matching the prototype -- `whndun` is read as a pointer for arity's sake
/// even though it is never called through.
pub fn listing<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let path = call.ptr();
    let whndun = call.ptr();
    let named = String::from_utf8_lossy(
        path.read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();
    let chan = host.current_channel_mem(call.mem())?;

    if let Some(at) = host.find(&named) {
        let bytes = std::fs::read(&at)
            .map_err(|e| ShimError::Failed(format!("listing({named}): {}: {e}", at.display())))?;
        host.gsbl_mut().transmit(chan, &bytes);
    }

    Err(ShimError::Failed(format!(
        "listing({named}): the file half is done, but whndun at {whndun} cannot be called -- a \
         Shim<A> is never handed &A::Module, which every callback-into-module-code mechanism \
         this crate has needs; see shims::mudmisc::listing's own doc comment"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;

    fn current(f: &mut Fixture) -> crate::chan::Chan {
        let chan = f.console();
        f.host
            .point_curusr(&mut f.machine, chan)
            .expect("channel 0 is current");
        chan
    }

    // ---- listing ------------------------------------------------------------

    #[test]
    fn listing_prints_the_file_then_refuses_the_whndun_call() {
        let root = crate::testing::scratch("mudmisc-listing-found");
        std::fs::write(root.join("NEWS.TXT"), b"stop the presses").expect("a file");
        let mut f = Fixture::rooted(root);
        let chan = current(&mut f);
        let path = f.text("NEWS.TXT");

        let err = f
            .invoke(listing, &[path.offset, path.selector, 0x1234, 0x5678])
            .expect_err("listing always ends in the whndun refusal");
        assert!(format!("{err}").contains("whndun"));

        let out: Vec<u8> = f.host.gsbl().channel(chan).output.iter().copied().collect();
        assert_eq!(out, b"stop the presses", "the file half still ran");
    }

    #[test]
    fn listing_on_a_missing_file_still_refuses_but_prints_nothing() {
        let root = crate::testing::scratch("mudmisc-listing-missing");
        let mut f = Fixture::rooted(root);
        let chan = current(&mut f);
        let path = f.text("NOPE.TXT");

        let err = f
            .invoke(listing, &[path.offset, path.selector, 0, 0])
            .expect_err("listing always ends in the whndun refusal");
        assert!(format!("{err}").contains("whndun"));
        assert!(f.host.gsbl().channel(chan).output.is_empty());
    }
}
