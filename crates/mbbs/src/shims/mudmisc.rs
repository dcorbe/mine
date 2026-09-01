//! One odd one out: an ASCII file lister whose completion callback is a
//! call back into the module.
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
/// # `whndun` is deferred, not called here
///
/// A `Shim<A>` is `fn(&mut Call<A>, &mut Host<A>) -> ...` -- it never
/// receives the `&A::Module` that [`Host::run`] needs -- so this cannot
/// call `whndun` itself. It records the call with [`Host::defer`] and
/// `Host::cycle` makes it on its next pass, with this channel current and
/// `prfbuf` flushed afterwards. That is also the real host's order of
/// events: `listing` hands the file to the tagspec engine and returns, and
/// `tshlst`'s `TSHFIN` calls `whndun` from a later pass of the main loop,
/// after the module's own `sttrou` has returned. Until 2026-08-31 this
/// routine refused instead, on the premise that no shim could arrange a
/// call into module code -- `Host::kicks` (`rtkick`) had been exactly that
/// for months, and MajorMUD's sysop menu `N` (release notes,
/// `WCCMMUD.NOT`) stopped the module on the refusal.
///
/// `whndun`'s argument is `(int)ftfscb->actfil` at `TSHFIN`: 1 when the
/// file was listed, 0 when it could not be. A missing file is the latter;
/// `ftgnew()` failing (no free transfer slot) is not modelled, so the
/// synchronous `whndun(0)` branch never runs.
///
/// # Errors
///
/// If no channel is current, if `path` cannot be read as a string, or if a
/// resolved file cannot be read.
///
/// Generic: reads its two fixed pointer arguments (`path`, `whndun`),
/// matching the prototype.
pub fn listing<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let path = call.ptr();
    let whndun = call.ptr();
    let named = String::from_utf8_lossy(
        path.read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();
    let chan = host.current_channel_mem(call.mem())?;

    let listed = match host.find(&named) {
        Some(at) => {
            let bytes = std::fs::read(&at)
                .map_err(|e| ShimError::Failed(format!("listing({named}): {}: {e}", at.display())))?;
            host.gsbl_mut().transmit(chan, &bytes);
            1
        }
        None => {
            host.note(format!("listing: {named} not found; whndun told 0"));
            0
        }
    };
    host.defer(chan, whndun, vec![abi::Arg::Int(A::Int::from(listed))]);
    Ok(abi::Ret::Void)
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

    /// The one `whndun` call `listing` queued: `(channel, entry, ok)`.
    fn queued(f: &Fixture) -> (crate::chan::Chan, mbbs_machine::m16::FarPtr, u32) {
        let [call] = f.host.deferred.as_slice() else {
            panic!("exactly one deferred call, got {}", f.host.deferred.len());
        };
        let [abi::Arg::Int(ok)] = call.args.as_slice() else {
            panic!("whndun takes one int");
        };
        (call.chan, call.entry, (*ok).into())
    }

    #[test]
    fn listing_prints_the_file_and_defers_whndun_1_on_its_channel() {
        let root = crate::testing::scratch("mudmisc-listing-found");
        std::fs::write(root.join("NEWS.TXT"), b"stop the presses").expect("a file");
        let mut f = Fixture::rooted(root);
        let chan = current(&mut f);
        let path = f.text("NEWS.TXT");

        f.invoke(listing, &[path.offset, path.selector, 0x1234, 0x5678]).expect("listed");

        let out: Vec<u8> = f.host.gsbl().channel(chan).output.iter().copied().collect();
        assert_eq!(out, b"stop the presses");
        let whndun = mbbs_machine::m16::FarPtr { offset: 0x1234, selector: 0x5678 };
        assert_eq!(queued(&f), (chan, whndun, 1), "whndun(1): the file was listed");
    }

    #[test]
    fn listing_on_a_missing_file_prints_nothing_and_defers_whndun_0() {
        let root = crate::testing::scratch("mudmisc-listing-missing");
        let mut f = Fixture::rooted(root);
        let chan = current(&mut f);
        let path = f.text("NOPE.TXT");

        f.invoke(listing, &[path.offset, path.selector, 0x1234, 0x5678]).expect("nothing to refuse");

        assert!(f.host.gsbl().channel(chan).output.is_empty());
        let whndun = mbbs_machine::m16::FarPtr { offset: 0x1234, selector: 0x5678 };
        assert_eq!(queued(&f), (chan, whndun, 0), "whndun(0): interrupted, nothing listed");
    }
}
