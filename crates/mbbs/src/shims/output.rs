//! Print-buffer flush and local-console cursor routines: `outprf`, `clrmlt`,
//! `outmlt`, `prat`, `locate`, `curcurx`, `curcury`.
//!
//! Signatures and line numbers from `GCOMM.H` in
//! `archive/galacticomm/extract/wg1/GALDSRC/SRC/GCOMM.H` -- the wg1 tree,
//! never wg20 (`docs/`-adjacent memory: the same files have different line
//! numbers there and a wg20 citation would silently point at the wrong
//! line).
//!
//! These seven split cleanly into two families, and the split is the whole
//! of this file's design:
//!
//! * [`outprf`] and [`outmlt`] flush `prfbuf` to a channel. `GCOMM.H:447`
//!   declares `outprf` with no body anywhere in this repo's copy of the
//!   source -- it is host-internal, never one of `WCCMMUD.DLL`'s own
//!   imports (`re/wccmmud_majorbbs_named.tsv` has no row for either
//!   ordinal 463 or 785), so Galacticomm never had to ship one. It is
//!   reconstructed from `powprf` (`MAJORBBS.C:1791-1795`), which says
//!   outright what it stands in for. [`crate::shims::fsd`] already carries
//!   a private, `Chan`-taking twin of this same logic
//!   (`crates/mbbs/src/shims/fsd.rs:1503`, used by the FSD flush path,
//!   which already has a resolved channel in hand and no module stack to
//!   read); this file's version is the ABI-callable form that reads `chan`
//!   off `call.int()`, the shape every routine actually registered in
//!   `shims::mod`'s dispatch table takes. The two cannot share code as
//!   written: `fsd::outprf` is a private `fn` of a different module, and
//!   its whole reason to exist is that it is *not* reached through
//!   `Call<A>`. Both are transcriptions of the same three lines of
//!   `powprf`, and a change to one is a change that belongs in the other
//!   too.
//!
//! * [`clrmlt`], [`prat`], [`locate`], [`curcurx`] and [`curcury`] have no
//!   real body in the wg1 tree either, and for a different reason each:
//!   `clrmlt`'s is a genuinely absent subsystem (see its own doc comment);
//!   the other four are the local sysop console, which this host does not
//!   have at all -- see their own doc comments, and
//!   `docs/`-adjacent memory `mbbs-headless-module-scope`: this host runs a
//!   module headless, with no local console screen to speak of.

use mbbs_machine::ptr::ModulePtr;
#[cfg(test)]
use mbbs_machine::m16::Ret;

use super::ShimError;
use crate::Host;
use crate::abi::{self, Abi, Call};
use crate::chan::Chan;

/// `void outprf(int chan)` -- `GCOMM.H:447`. Flush whatever `prf`/`prfmsg`
/// have queued in `prfbuf` to `chan`, then clear the buffer.
///
/// Reconstructed from `powprf` (`MAJORBBS.C:1791-1795`):
///
///
/// `powprf` is `outprf` plus one more call (`btucli`, flushing input) --
/// exactly the "power" the name claims, which is how we know what the two
/// statements it shares with plain `outprf` do on their own: transmit
/// `prfbuf`, then clear it the way [`crate::shims::text::clrprf`]
/// (`clrprf()`) does.
///
/// **Not a `WCCMMUD.DLL` import** -- `re/wccmmud_majorbbs_named.tsv` has no
/// row for ordinal 463 (`_OUTPRF`), so nothing in MajorMUD calls this
/// directly by name. It exists here as the ABI-callable form of the same
/// logic [`crate::shims::fsd`]'s own private, `Chan`-taking `outprf`
/// (`crates/mbbs/src/shims/fsd.rs:1503`) already carries for the FSD flush
/// path -- registered by name (per `shims::mod`'s own dispatch table shape)
/// so that any module import that does resolve to this ordinal, now or in a
/// module this host has not yet met, has a real routine to reach rather
/// than an unresolved import.
///
/// Out of range: `outprf` is `void`, so there is no status code to answer
/// with. [`crate::shims::gsbl::echonu`] sets the precedent for a `void`
/// routine given a channel past `nterms` -- note it and return, rather than
/// treat it as an error the caller could observe.
pub fn outprf<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    outprf_core(call, host)
}

/// `void outmlt(int chan)` -- `GCOMM.H:475`, "Multilingual version of
/// outprf()" (the phrase is MBBSEmu's own comment on its identical
/// collapse, `MBBSEmu/HostProcess/ExportedModules/Majorbbs.cs:4824`:
/// `private void outmlt() => outprf();`).
///
/// `outmlt` is part of the "mlt" family declared together at
/// `GCOMM.H:468-477` -- `prfbuffers`, `prfpointers`, `linuse`, `mltflg`,
/// `inimlt`, `clrmlt`, `cklonl`, `outmlt`, `prfmlt`, `pmlt` -- Worldgroup's
/// answer to serving more than one language from one module: a *pool* of
/// print buffers, one per active language, selected by `mltflg`/`linuse`,
/// so `prfmlt`/`pmlt` can format a message in whichever buffer the current
/// user's language points at while `outprf`'s single global `prfbuf`
/// carries on unaffected.
///
/// **This host places no `mltflg`, `linuse`, `prfbuffers` or
/// `prfpointers`** -- `crate::globals` has no row for any of the four, so
/// there is no buffer pool for `outmlt` to pick a member of. That is not a
/// simplification made for this task alone: MBBSEmu, the one other
/// independent MajorBBS host reimplementation this repo has for
/// comparison, made exactly the same call for exactly the same reason (its
/// own `outmlt`/`clrmlt` are literal one-line aliases onto `outprf`/
/// `clrprf`). With no second buffer to flush, `outmlt(chan)` and
/// `outprf(chan)` flush the same one -- so this shares [`outprf_core`]
/// rather than re-deriving the same three steps.
pub fn outmlt<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    outprf_core(call, host)
}

/// The body [`outprf`] and [`outmlt`] share: read `chan` off the frame,
/// resolve it, and flush.
fn outprf_core<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    match host.gsbl().terms().chan(chan) {
        Some(chan) => outprf_mem(call.mem(), host, chan)?,
        None => host.note(format!("outprf: channel {chan} is out of range; nothing flushed")),
    }
    Ok(abi::Ret::Void)
}

/// The mutation [`outprf_core`] performs once `chan` is resolved: read
/// `prfbuf`, transmit it, then clear it the way
/// [`crate::shims::text::clrprf_mem`] does.
///
/// Mirrors [`crate::shims::fsd`]'s private `outprf`
/// (`crates/mbbs/src/shims/fsd.rs:1503`) byte for byte -- both read
/// `prfbuf` fresh, transmit, then call `clrprf_mem` -- but is not the same
/// function: that one is not `pub` and takes a `Chan` its caller already
/// resolved from `A::Cpu`, not a `Call<A>` it could read one off itself.
fn outprf_mem<A: Abi>(mem: &mut A::Mem, host: &mut Host<A>, chan: Chan) -> Result<(), ShimError> {
    let start = host
        .globals()
        .pointer_mem(mem, "prfbuf")
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let text = start
        .read_cstr(mem)
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    host.gsbl_mut().transmit(chan, &text);
    crate::shims::text::clrprf_mem(mem, host)?;
    Ok(())
}

/// `void clrmlt(void)` -- `GCOMM.H:473`. Throw away whatever the "mlt"
/// family's current buffer holds, without transmitting it.
///
/// The same absent subsystem [`outmlt`]'s own doc comment measures applies
/// here: no `mltflg`/`linuse`/`prfbuffers`/`prfpointers` are placed, so
/// there is only the one buffer `clrprf` already clears -- and MBBSEmu's
/// own `clrmlt` (`MBBSEmu/HostProcess/ExportedModules/Majorbbs.cs:4043`:
/// `private void clrmlt() => clrprf();`) makes the identical collapse.
/// [`crate::shims::text::clrprf_mem`] is called directly rather than
/// through [`crate::shims::text::clrprf`]'s own `Call<A>`-taking wrapper --
/// `clrmlt`, like `clrprf`, reads no argument of its own, and
/// [`crate::shims::text::clrprf_mem`]'s own doc comment is the precedent
/// for going straight to the `_mem` core instead of routing a no-argument
/// call through a second `Call<A>` layer that has nothing to read.
pub fn clrmlt<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    crate::shims::text::clrprf_mem(call.mem(), host)?;
    Ok(abi::Ret::Void)
}

/// `void prat()` -- `GCOMM.H:314`, in the block `GCOMM.H:427` itself labels
/// `/* old MBBST.LIB prototype section */` together with `locate`,
/// `curcurx` and `curcury` (below). Declared with empty, K&R-style
/// parentheses -- unlike every other routine in this file, `GCOMM.H` does
/// not say how many arguments it takes.
///
/// The one call site with its arguments visible, `PLSTUFF.C:219`:
///
///
/// -- `prat(x, y, fmt, ...)`: position, then a `prf`-style format, onto the
/// **local console screen**. The comment on the line above is Galacticomm's
/// own: "this is only good for WGSERVER.EXE", i.e. a video display attached
/// to the machine the host process is running on, not any remote channel.
///
/// `WCCMMUD.DLL` imports this four times (`re/wccmmud_majorbbs_named.tsv`,
/// ordinal 471, count 4), and one call site is fully legible once its
/// ordinals are resolved by hand against `re/exports/functions.txt`
/// (Ghidra never named these calls -- `re/exports/WCCMMUD_named.c` has no
/// `_PRAT`/`_LOCATE`/`_CURCURX`/`_CURCURY` symbol at all, only raw
/// `Ordinal_147`/`Ordinal_148`/`Ordinal_392`/`Ordinal_471` thunks):
/// `re/exports/WCCMMUD_named.c:14246-14288`, `FUN_1010_aa00`:
///
///
/// Save cursor, print a rotating "still working" indicator and a status
/// line at fixed console coordinates, restore the cursor -- the textbook
/// shape of a status readout on the sysop's own screen, gated behind a flag
/// that skips all four calls whenever it is unset. Nothing about it reaches
/// a remote channel; `prf`/`btuxmt` are MajorMUD's whole remote output
/// path (`crate::shims::gsbl::btuxmt`'s own doc comment), and this is not
/// on it.
///
/// **No counterpart exists in this host** -- `mbbs-headless-module-scope`
/// (project memory): the goal is running a module headless, with no local
/// console screen to write to at all.
///
/// **But the text is not nothing, and this does not throw it away.**
/// `GCOMM.H:314`'s `void prat();` is an old K&R declaration with no
/// parameters listed, which makes the routine look argument-less. The one
/// surviving vendor call site says otherwise:
///
///
/// So `prat` is *print at*: `prat(x, y, ctlstg, ...)`, a `printf` whose
/// output lands at a fixed console coordinate. The coordinate is the part
/// this host cannot honour; the **formatted string is ordinary content**,
/// and a host with no console still has somewhere to put it. Discarding it
/// would lose exactly the operator status line the sysop was meant to read
/// -- `WCCMMUD.DLL` writes one at four sites.
///
/// So the coordinate is dropped (recorded in the note, not silently) and
/// the text goes to [`Host::note`], the same channel every other
/// "the operator should know this" fact in this host travels on. That is a
/// deliberate substitution of one output device for another, not fidelity:
/// a real console would overwrite row `y` in place, and a log appends. The
/// difference is visible to nobody but the operator, and only one of the
/// two survives being run headless.
pub fn prat<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let x = Into::<u32>::into(call.int()) as i16;
    let y = Into::<u32>::into(call.int()) as i16;
    let ctlstg = call.ptr();
    let (text, _) = crate::fmt::format_call(call, ctlstg)?;
    host.note(format!(
        "prat({x},{y}): {}",
        String::from_utf8_lossy(&text).trim_end()
    ));
    Ok(abi::Ret::Void)
}

/// `void locate(int x,int y)` -- `GCOMM.H:434`. Move the local console's
/// cursor to `(x, y)`.
///
/// Same "old MBBST.LIB" block as [`prat`], [`curcurx`] and [`curcury`], and
/// the same call site (`re/exports/WCCMMUD_named.c:14285`,
/// `Ordinal_392(0x1290,uVar1,uVar3)`) is the *restore* half of the
/// save/print/restore pattern [`prat`]'s own doc comment quotes in full:
/// this is what puts the sysop's console cursor back where `curcurx`/
/// `curcury` found it, after the status line has been written.
///
/// MBBSEmu reaches the identical conclusion independently: `LOCATE` sits in
/// its own ignore list, commented "moves cursor (local screen, not telnet
/// session)" (`MBBSEmu/HostProcess/ExportedModules/Majorbbs.cs:605`), next
/// to `RSTWIN`/`SETWIN`/`SSTATR`/`SCBLANK` -- the rest of the same local
/// video group `GCOMM.H`'s own "old MBBST.LIB" comment names.
///
/// **No counterpart in this host**, for the reason [`prat`]'s doc comment
/// gives in full: there is no local console to move a cursor on. `x` and
/// `y` are still read off the call frame, in order, even though neither is
/// used -- `void locate(int x,int y)` is a fixed, two-argument prototype
/// (unlike `prat`'s undeclared one), so reading both keeps this shim
/// correct regardless of which stack-cleanup convention the registration
/// this file's caller adds ends up choosing.
pub fn locate<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let _x = call.int();
    let _y = call.int();
    Ok(abi::Ret::Void)
}

/// `int curcurx(void)` -- `GCOMM.H:436`. The local console cursor's current
/// column.
///
/// Same block, same reasoning as [`prat`] and [`locate`]: the one resolved
/// call site is `Ordinal_147()` in `re/exports/WCCMMUD_named.c:14258`,
/// saving the console cursor's column before [`prat`] overwrites it with a
/// status line, so [`locate`] can put it back afterwards. **No counterpart
/// exists in this host** -- see [`prat`]'s doc comment for why that is a
/// genuine architecture difference (no local console) rather than a gap
/// left for later.
///
/// Unlike the two `void` routines in this group, `curcurx` has a real
/// return value the caller does read straight back
/// (`Ordinal_392(0x1290,uVar1,uVar3)` -- `uVar1` is this call's own
/// result). There is no truthful column to answer with, so this returns a
/// fixed `0` -- documented as an arbitrary placeholder, not a measurement,
/// and safe against the one call site this repo can see in full: `locate`
/// discards both of its arguments regardless of value (its own doc
/// comment), so a `curcurx`/`curcury` pair that always answers `(0, 0)`
/// restores exactly as much as a pair that answered anything else would.
pub fn curcurx<A: Abi>(_call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    Ok(abi::Ret::Int(A::Int::from(0u16)))
}

/// `int curcury(void)` -- `GCOMM.H:437`. The local console cursor's current
/// row. [`curcurx`]'s own doc comment covers the reasoning in full; this is
/// its row-valued twin.
///
/// One correction worth recording on its own: the resolved call site reads
/// `uVar3 = Ordinal_148(0x1290,uVar3);` -- Ghidra renders this as a
/// two-argument call, but `GCOMM.H` declares `curcury(void)`, and
/// `ghidra-export-arity-is-not-a-prototype` (project memory) already
/// measured that this decompiler infers arity *per call site*, not from
/// the real prototype: `0x1290` and the stale `uVar3` are leftovers from
/// neighbouring stack slots the decompiler folded into a fabricated
/// argument list, not bytes `curcury` itself reads. This shim takes no
/// argument, matching the header rather than the one site's inferred
/// signature.
pub fn curcury<A: Abi>(_call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    Ok(abi::Ret::Int(A::Int::from(0u16)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;

    #[test]
    fn outprf_transmits_prfbuf_and_clears_it() {
        let mut f = Fixture::new();
        let console = f.console();
        let template = f.text("<%d>");
        f.invoke(crate::shims::text::prf, &[template.offset, template.selector, 7])
            .expect("queued");

        let buffer = f.host.globals().prf_buffer();
        assert_eq!(f.read(buffer), "<7>", "queued before the flush");

        f.invoke(outprf, &[0]).expect("flushed");

        assert_eq!(
            f.host.gsbl_mut().drain_output(console),
            b"<7>".to_vec(),
            "outprf transmits what prf queued"
        );
        assert_eq!(f.read(buffer), "", "and clears the buffer the way clrprf does");
    }

    #[test]
    fn outprf_on_a_channel_out_of_range_notes_rather_than_transmits() {
        let mut f = Fixture::new();
        let console = f.console();
        let past = f.host.gsbl().terms().count();
        let template = f.text("hello");
        f.invoke(crate::shims::text::prf, &[template.offset, template.selector])
            .expect("queued");

        f.invoke(outprf, &[past]).expect("void, even out of range");

        assert!(
            f.host.gsbl_mut().drain_output(console).is_empty(),
            "nothing was transmitted to the real channel"
        );
    }

    #[test]
    fn outmlt_flushes_the_same_buffer_outprf_does() {
        // No lingo buffer pool exists in this host (see outmlt's own doc
        // comment), so it is outprf in every observable way.
        let mut f = Fixture::new();
        let console = f.console();
        let template = f.text("multilingual, in name only");
        f.invoke(crate::shims::text::prf, &[template.offset, template.selector])
            .expect("queued");

        f.invoke(outmlt, &[0]).expect("flushed");

        assert_eq!(
            f.host.gsbl_mut().drain_output(console),
            b"multilingual, in name only".to_vec()
        );
    }

    #[test]
    fn clrmlt_discards_the_buffer_without_transmitting() {
        let mut f = Fixture::new();
        let console = f.console();
        let template = f.text("thrown away");
        f.invoke(crate::shims::text::prf, &[template.offset, template.selector])
            .expect("queued");

        let buffer = f.host.globals().prf_buffer();
        f.invoke(clrmlt, &[]).expect("cleared");
        assert_eq!(f.read(buffer), "");

        f.invoke(outprf, &[0]).expect("flushed (nothing left)");
        assert!(
            f.host.gsbl_mut().drain_output(console).is_empty(),
            "clrmlt threw the text away before outprf could send it"
        );
    }

    /// `locate` has no content to keep -- only a coordinate -- so it stays a
    /// no-op. `prat` does NOT: `PLSTUFF.C:219`'s `prat(42,20,"%8.8s",...)`
    /// shows it carries a formatted string, and this host keeps that text
    /// even though it cannot honour the coordinate. See `prat`'s own doc.
    #[test]
    fn locate_is_a_no_op_and_prat_keeps_its_text_instead_of_discarding_it() {
        let mut f = Fixture::new();
        let console = f.console();

        assert_eq!(f.invoke(locate, &[40, 12]).expect("void"), Ret::Void);
        assert!(
            f.host.notes().is_empty(),
            "a bare cursor move is not worth a note"
        );

        let at = f.text("players online: %d");
        assert_eq!(
            f.invoke(prat, &[42, 20, at.offset, at.selector, 7]).expect("void"),
            Ret::Void
        );
        let notes = f.host.notes().to_vec();
        assert_eq!(notes.len(), 1, "prat's text is kept, not discarded: {notes:?}");
        assert!(
            notes[0].contains("players online: 7"),
            "the note carries the FORMATTED text, not the template: {:?}",
            notes[0]
        );
        assert!(notes[0].contains("42,20"), "and names the coordinate it could not honour");

        assert!(
            f.host.gsbl_mut().drain_output(console).is_empty(),
            "neither writes to any real channel"
        );
    }

    #[test]
    fn curcurx_and_curcury_answer_a_fixed_zero() {
        let mut f = Fixture::new();
        assert_eq!(f.invoke(curcurx, &[]).expect("int"), Ret::U16(0));
        assert_eq!(f.invoke(curcury, &[]).expect("int"), Ret::U16(0));
    }
}
