//! The Galacticomm Client/Server Protocol (GCSP) server-side handler API --
//! `GCSPSRV.H`, cited throughout this file from
//! `archive/galacticomm/extract/wg1/GALDSRC/SRC/GCSPSRV.H` (the wg1 tree,
//! never wg20 -- see the repo's own citation-safety note: the same file in
//! wg20 has different line numbers and would make every citation below
//! silently wrong).
//!
//! Full evidence and methodology for the unreachability argument below
//! live in `docs/2026-08-14-gcsp-reachability.md`; this comment carries
//! the summary a reader of the code needs without leaving the file.
//! Registering a proven-unreachable refusal is not a compromise:
//! `re/importgaps.py` reports these seven as served, and "served" there
//! means this host has a named answer for the symbol, not that the answer
//! reproduces the vendor's real behaviour -- the same distinction `dfsthn`
//! and `onsysn` already established.
//!
//! # What GCSP is, and why none of the seven routines here can run
//!
//! GCSP is the wire protocol between the host and a genuine **Worldgroup
//! client** -- the GUI program, not a telnet/ANSI terminal. A user connected
//! through it carries `ISGCSU` (`MAJORBBS.H:283`, `0x00800000L`) in their
//! `flags`, and the host exchanges typed binary records called *dynapaks*
//! with the client instead of a text stream: a module registers a
//! server-side *agent* (`GCSPSRV.H:20-27`, `struct agent`) under an `appid`,
//! and the transport/data-link/API layers (`GCSP.H`'s `phXXX`/`dlXXX`/
//! `trXXX`/`apXXX` families) hand the agent's `read`/`write`/`xferdone`/
//! `abort` vectors a dynapak whenever the client asks for or sends one under
//! that `appid`.
//!
//! **This host implements none of that transport.** It serves telnet users
//! only -- see this crate's own top-level docs and
//! `crate::shims::system::register_agent`'s doc comment, which already says
//! so for the one GCSP entry point this crate wires up:
//!
//! > **Nothing dispatches to these vectors**, because dispatching needs a
//! > client and this host has none.
//!
//! Confirmed independently three ways, all measured rather than assumed:
//!
//! 1. `grep -rn ISGCSU crates/mbbs/src` finds nothing. No `Channel`/`Users`
//!    state in this crate can ever carry the flag, so no session this host
//!    creates is ever a GCSU one.
//! 2. There is no `rqdptr`/`usdptr`/`curcsu`/`curreq` anywhere in this
//!    crate -- the per-request and per-user C/S state `GCSPSRV.H:39-78`
//!    declares as the context every one of these seven routines reads or
//!    writes. `register_agent` records an `Agent<A>`'s four vectors and
//!    nothing ever calls them (same file, same doc comment).
//! 3. `WCCMMUD.DLL` genuinely imports all seven (`re/wccmmud_majorbbs_named.tsv`,
//!    ordinals 1129/942/938/940/943/974/960) and calls them from exactly two
//!    places, both measured in `re/exports/WCCMMUD_named.c`:
//!
//!    - Its own registered agent's `read` and `write` vectors --
//!      `FUN_10c8_0069` (`WCCMMUD_named.c:68329`, three parameters:
//!      `direction, dpknam:2`, matching `GCSPSRV.H:131`'s read vector
//!      exactly) and `FUN_10c8_016b` (`:68376`, five parameters:
//!      `dpknam:2, length, value:2`, matching the write vector). Segment
//!      `0x10c8` is the same segment `FUN_10c8_0000` (`:68290`, "Segment:
//!      26, Offset: 000aa400") calls `register_agent` from -- the very
//!      call `register_agent`'s own doc comment cites for its "only an
//!      all-zero pointer is refused" example. These two functions are
//!      never reached unless something dispatches a dynapak to the
//!      `WCCMMUD` agent, which nothing here does.
//!    - `_TELL_USER` (`:65778`), MajorMUD's entire output path
//!      (`crate::shims::gsbl::btuxmt`'s own doc comment: "677 sites").
//!      Its first line reads `user[chan].flags & ISGCSU` at struct offset
//!      `0x16` (`uVar7 = *(uint *)(user + param_1*0x29 + 0x16) & 0x80` --
//!      byte offset `0x16` is two bytes into the four-byte `flags` long
//!      that starts at `0x14`, so testing bit `0x80` of its low byte is
//!      exactly `flags & 0x00800000L`, bit 23, `ISGCSU`). `uVar7 == 0` is
//!      taken by every session this host creates and runs the ordinary
//!      `btuxmt`/`btuxct` path (`:65972` and the `if` block above it).
//!      `stp4cs`/`senddpk` (`:65979`, `:65989`) sit in the `else`
//!      (`:65974` on), which requires `ISGCSU` set -- dead code here by
//!      the same measurement as point 1.
//!
//! So every one of the seven is reachable in principle, from real call
//! sites this module has, gated behind a condition (`ISGCSU`, or "a client
//! sent a dynapak to this agent") this host can never make true. That is a
//! genuine architecture difference, not a gap: implementing full GCSP --
//! the physical/data-link/transport/API layers plus a Worldgroup client
//! decoder -- to serve seven routines nothing telnet-side will ever call is
//! out of scope for a host that exists to run modules headlessly over
//! telnet (`crate::shims` sibling docs, `mbbs-headless-module-scope`).
//!
//! # Why every one refuses rather than fabricates
//!
//! `GCSPSRV.C` itself -- the file that would define these seven, as opposed
//! to declaring them -- does not survive in any archive this repo has
//! access to. `archive/galacticomm/extract/wg1/GALDSRC/SRC/` ships
//! `GCSPSRV.H` and `GCSPSRV.LIB` (the compiled object), never the `.C`; the
//! same is true of `re/wg33src`. Every fact this file states about these
//! routines' behaviour is reconstructed from callers, not read out of a
//! definition -- sound enough to say what a routine's *contract* is, not
//! sound enough to fabricate its internals.
//!
//! Given that, and given no live control-flow path in this host can ever
//! reach any of the seven for real, a shim that refused only when its
//! precondition failed and answered plausible values otherwise would be
//! answering questions about state -- the current request, the current C/S
//! user, a live dynapak transport -- that simply is not there. A `0`/`TRUE`/
//! null-buffer answer would be **indistinguishable from a real one** to the
//! calling module, and it would be wrong: this crate's own standing
//! principle is that a plausible fabricated success is the exact failure
//! mode it exists to avoid (`shims::system::register_module`'s and
//! `catastro`'s doc comments make the same call). Every routine below
//! refuses loudly with [`ShimError::Failed`] instead -- if one is ever
//! actually reached, that means this host grew real GCSP dispatch (point 2
//! above stopped being true) without this file being told, which is exactly
//! the kind of silent divergence a crash is supposed to catch.

use super::ShimError;
use crate::Host;
use crate::abi::{self, Abi, Call};

/// `BOOL stdmchk(int mnum)` -- `GCSPSRV.H:135` -- "does the current C/S
/// session hold the module's key, numbered by message `mnum`?"
///
/// The GCSP counterpart to `stdchk(char *key)` (`GCSPSRV.H:134`), which takes
/// a literal string instead of a `.MSG` message number -- `GCSGAGT.C:92`'s
/// generic agent uses the string form (`stdchk(gagtkey)`) and
/// `GALP&QA.C:80,197`'s poll agent uses this one (`stdmchk(MAINKEY)`), both
/// as the very first line of their `read`/`write` vectors, both rejecting the
/// request outright on failure. `WCCMMUD.DLL`'s own agent does the same:
/// `Ordinal_1129(0x1290,10,uVar6)` opens both `FUN_10c8_0069` (read,
/// `WCCMMUD_named.c:68342`) and `FUN_10c8_016b` (write, `:68390`), each
/// falling straight through to `rejectreq()` when it answers false.
///
/// What it reads to answer is per-user C/S state (`GCSPSRV.H:59-78`'s
/// `usdptr`) this host has never had a reason to grow, because nothing can
/// ever reach a call to it -- see this module's own doc comment, point 2:
/// both call sites that exist are inside a `read`/`write` vector nothing
/// dispatches to.
///
/// # Errors
///
/// Always. There is no held-key state to consult, and no request in
/// progress to consult it on behalf of -- see the module doc comment for the
/// choice between refusing and fabricating an answer.
pub fn stdmchk<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let mnum = Into::<u32>::into(call.int());
    Err(ShimError::Failed(format!(
        "stdmchk({mnum}): no GCSP session exists to hold a module key against -- \
         this host has no C/S transport, and every real call site is inside a \
         dynapak read/write vector nothing here ever dispatches to"
    )))
}

/// `void rejectreq(void)` -- `GCSPSRV.H:136` -- "answer the request in
/// progress with a denial."
///
/// The universal escape hatch every GCSP agent example falls back to: it is
/// what a `stdmchk`/`stdchk` failure calls
/// (`GCSGAGT.C:96`, `GCSASYS.C:516-517`), what an unrecognised dynapak name
/// calls (`BBSMAINM.C:238,263,303,...` -- forty-plus sites in that one file
/// alone), and what `WCCMMUD.DLL`'s own agent calls when neither branch of
/// its read (`Ordinal_942(0x1290)` at `WCCMMUD_named.c:68367`) or write
/// (`:68393`) vector recognises the request. It answers via `rqdptr`
/// (`GCSPSRV.H:40-54`), the engine's *current request* -- there is no
/// argument because there is nothing to name: the engine already knows which
/// request is in progress before it calls into the agent.
///
/// # Errors
///
/// Always. There is no current request -- `rqdptr` names state this host has
/// never had a reason to grow (see this module's doc comment), and the two
/// real call sites for it in `WCCMMUD.DLL` are both inside the same
/// never-dispatched vectors [`stdmchk`]'s doc comment cites.
pub fn rejectreq<A: Abi>(_: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    Err(ShimError::Failed(
        "rejectreq: no GCSP request is in progress to reject -- this host has no \
         dynapak transport, and reaching this call means something dispatched to \
         an agent vector that was supposed to be unreachable"
            .to_owned(),
    ))
}

/// `void rsp2read(struct saunam *name, unsigned length, void *value)` --
/// `GCSPSRV.H:131` -- "answer the read request in progress with this much
/// data."
///
/// `name` re-states which dynapak is being answered (`r2rprf`, `GCSPSRV.H:144`,
/// is the shorthand for "reuse the name I was asked to read" -- `GCSASYS.C:526`
/// uses it right next to a real `rsp2read` at `:521`:
/// `rsp2read(dpknam,STGLEN,spr("Y%s",supappid))`). `STGLEN` (`GCSP.H:16`,
/// `0xFFFF`) as `length` means "NUL-terminated, measure it yourself" --
/// `GCSGAGT.C`'s generic agent never calls this at all (`garead`,
/// `:87-97`, either delegates to `r2rgdp` or rejects), so the fullest
/// surviving example is `GCSASYS.C`'s own, above. `WCCMMUD.DLL`'s agent
/// calls it twice from its read vector, both answering a "who's online"
/// style query: `Ordinal_938(0x1048,param_2,param_3,0x7ce,uVar6,uVar3)`
/// (`WCCMMUD_named.c:68351` and `:68360`), reached only after
/// [`stdmchk`] passes and [`cnvs2d`] has matched the request's dynapak name
/// against a suffix this file cannot recover (see [`cnvs2d`]'s doc comment).
///
/// The response goes out through the API/transport/data-link/physical layers
/// (`GCSP.H`'s `apXXX`/`trXXX`/`dlXXX`/`phXXX` families) to a connected
/// Worldgroup client -- none of which this host implements.
///
/// # Errors
///
/// Always, for the same reason as [`rejectreq`]: no request is in progress,
/// and the data this would need to send has nowhere real to go.
pub fn rsp2read<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let name = call.ptr();
    let length = Into::<u32>::into(call.int());
    let value = call.ptr();
    Err(ShimError::Failed(format!(
        "rsp2read(name={name:?}, length={length:#x}, value={value:?}): no GCSP \
         request is in progress to answer, and no dynapak transport exists to \
         carry the answer to a client this host cannot have"
    )))
}

/// `void rsp2write(BOOL ok, unsigned length, void *data)` -- `GCSPSRV.H:133`
/// -- "answer the write request in progress: accepted or not, with this much
/// data of my own to send back."
///
/// The write-side twin of [`rsp2read`]. `ok=TRUE, length=0, data=NULL` is the
/// ordinary acknowledgement -- `GCSASYS.C:1690,1743,1802` and
/// `GCSGAGT.C:141,157` (`gawrite`/`gaxdone`) all answer it exactly that way;
/// `GCSASYS.C:1643`'s `rsp2write(sameas(value,msysid),STGLEN,rsptmp)` is the
/// one surviving example that both refuses conditionally and talks back.
/// `WCCMMUD.DLL`'s write vector calls it twice: `Ordinal_940(0x10b0,1,0,0,0)`
/// (`WCCMMUD_named.c:68408`, immediately after `_CMD_QUIT` -- a Worldgroup
/// client's own "quit" control acknowledged the same way a menu command
/// would be) and `Ordinal_940(0x1290,1,uVar5,uVar2,uVar6)` (`:68425`, the
/// vector's fall-through path). Both are inside `FUN_10c8_016b`, the same
/// never-dispatched write vector [`stdmchk`]'s doc comment measures.
///
/// # Errors
///
/// Always, for the same reason as [`rsp2read`].
pub fn rsp2write<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let ok = Into::<u32>::into(call.int());
    let length = Into::<u32>::into(call.int());
    let data = call.ptr();
    Err(ShimError::Failed(format!(
        "rsp2write(ok={ok}, length={length:#x}, data={data:?}): no GCSP request \
         is in progress to answer, and no dynapak transport exists to carry the \
         answer to a client this host cannot have"
    )))
}

/// `void senddpk(int chan, char *dstapp, int priority, struct saunam *dpknam,
/// unsigned length, void *value)` -- `GCSPSRV.H:137-138` -- push an
/// *unsolicited* dynapak to a channel's client, outside of any request it
/// made.
///
/// The one routine of these seven that is not agent-callback-only: it is a
/// general "tell this channel's Worldgroup client something" primitive,
/// called from ordinary module code the same way `btuxmt` is called for a
/// telnet one. `MAJORBBS.C:4728-4732`'s `byenow` is the clearest surviving
/// example, and it is explicit about the gate:
///
///
/// `WCCMMUD.DLL`'s own output path reproduces exactly this shape.
/// `_TELL_USER` (`WCCMMUD_named.c:65778`) opens by testing `ISGCSU`
/// (see this module's own doc comment for the bit-offset arithmetic); the
/// branch that takes runs `btuxmt`/`btuxct` the way `crate::shims::gsbl`
/// already implements, and the branch that does not -- `ISGCSU` set --
/// ends `Ordinal_960(...)` (`stp4cs`, `:65979`) then
/// `Ordinal_943(0x1290,param_1,10000,0x11f0,3,_Ordinal_1144,_Ordinal_1144,iVar6+0x1f)`
/// (`senddpk`, `:65989`). This host never sets `ISGCSU` on any user (grepped,
/// zero hits in `crates/mbbs/src`), so `_TELL_USER` always takes the
/// `btuxmt`/`btuxct` branch and never reaches this call -- the same
/// `ISGCSU`-gated dead code `byenow` shows in the surviving host source.
///
/// Even granting a request in progress, sending anything requires the
/// data-link and physical layers (`GCSP.H`'s `dlXXX`/`phXXX` families) this
/// host does not implement -- there is no socket for a Worldgroup client to
/// answer on in the first place.
///
/// # Errors
///
/// Always: no connected GCSP client exists on any channel this host serves,
/// so there is nowhere for an unsolicited dynapak to go.
pub fn senddpk<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = Into::<u32>::into(call.int()) as i16;
    let dstapp = call.ptr();
    let priority = Into::<u32>::into(call.int()) as i16;
    let dpknam = call.ptr();
    let length = Into::<u32>::into(call.int());
    let value = call.ptr();
    Err(ShimError::Failed(format!(
        "senddpk(chan={chan}, dstapp={dstapp:?}, priority={priority}, \
         dpknam={dpknam:?}, length={length:#x}, value={value:?}): no channel \
         this host serves carries a connected GCSP client -- every user here \
         is telnet, ISGCSU is never set, and there is no dynapak transport \
         to send on regardless"
    )))
}

/// `char *cnvs2d(struct saunam *saunam)` -- `GCSPSRV.H:146` -- format a
/// dynapak name as a "display" string, into a buffer the engine owns.
///
/// Universally the first thing a `read`/`write` vector does once
/// [`stdmchk`]/`stdchk` passes, and every surviving agent routes on the
/// *string* it returns rather than the struct's fields directly --
/// `BBSMAINM.C:209-236` (real host source, `mmuread`, the main menu's own
/// read vector):
///
///
/// and `GCSASYS.C:499-529` (`sysread`, also real host source):
///
///
/// `WCCMMUD.DLL`'s own agent does the same thing with the same shape:
/// `Ordinal_974(0x1290,param_2,param_3)` (`WCCMMUD_named.c:68344` in the read
/// vector, `:68396` in the write vector) feeds straight into `sameas_520`
/// calls against fixed string constants, exactly like `sameas`/`samepato`
/// above.
///
/// **The letter-prefix grammar these examples show (`s`/`a`/`u`/`f` before a
/// colon, apparently marking which of sysid/appid/usrid/file-flag the rest
/// of the string speaks to) is real -- five independent call sites agree it
/// exists and route on it -- but its exact rule is not recoverable from
/// them.** `SIDSIZ` is 5 (`GCSP.H:18`, four characters and a NUL), yet
/// `"s:supappid"` puts an eight-character value after a lone `s:`, and
/// `"sau:announce "` puts three letters before a single word with no visible
/// separator for the other two fields' values. Both readings that would
/// resolve that -- "the letters name which fields are present, values are
/// concatenated in some order" vs. "the letters name which fields compare
/// against the *engine's own current defaults*, and only the one field given
/// explicitly is printed" -- fit the five examples equally well, and nothing
/// in any surviving header or source picks between them. `GCSPSRV.C`, the
/// file that would settle it, does not survive in this archive or
/// `re/wg33src` -- only `GCSPSRV.H` (the declaration) and `GCSPSRV.LIB` (the
/// compiled object) do.
///
/// # Errors
///
/// Always. Guessing the grammar and formatting a string anyway is exactly
/// the fabricated-plausible-success this module's own doc comment refuses to
/// do -- a caller comparing the result against a suffix constant would get a
/// silently wrong match or non-match, indistinguishable from a correct
/// `cnvs2d` unless someone already knew the real grammar to check it against.
/// Unreachable regardless (see the module doc comment), so refusing costs
/// nothing today and stops a wrong guess from ever mattering later.
pub fn cnvs2d<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let saunam = call.ptr();
    Err(ShimError::Failed(format!(
        "cnvs2d(saunam={saunam:?}): the display-string grammar cnvs2d builds is \
         not recoverable from any surviving source -- GCSPSRV.C does not exist \
         in this archive, and every caller only shows what the format is used \
         for, not what it is; this host also has no GCSP request in progress \
         for the result to serve"
    )))
}

/// `char *stp4cs(char *buf)` -- `GCSPSRV.H:148` -- prepare a formatted
/// message buffer "for client/server": presumed, from every call site's
/// position, to translate or strip the `|`-pipe colour codes `prf`/`prfmsg`
/// leave in `buf` into whatever plain or in-band form a Worldgroup client's
/// display expects, in place, returning the same buffer it was given (every
/// call site immediately reuses the return value as if it were `buf` itself
/// -- `depad(stp4cs(prfbuf))`, `GALFILUT.C:952` among six sites, chains it
/// straight into another in-place string routine).
///
/// The clearest surviving evidence for that reading is `_TELL_USER`
/// (`WCCMMUD_named.c:65778`) itself, which this module's own doc comment
/// already cites for [`senddpk`]: its `ISGCSU`-false branch hand-strips `|`
/// pipe codes character by character out of `prfbuf` before handing the
/// result to `btuxct` (`:65790` onward -- the `local_d`/`'|'` comparison
/// loop); its `ISGCSU`-true branch does no such loop and instead calls
/// `Ordinal_960(0x1290,_prfbuf_475,_prfbuf_475)` (`stp4cs`, `:65979`)
/// directly on the same unstripped `prfbuf`, immediately before `senddpk`
/// sends it (`:65989`). Two different mechanisms converting the identical
/// input for the two different transports is exactly what a GCSP-native
/// counterpart to the ANSI path's own pipe-stripping loop would look like.
///
/// **That is a plausible reading of the evidence, not a specification.** The
/// exact substitution table -- does a `|07` become nothing, a space, or a
/// GCSP in-band colour record; are the two-digit codes even parsed the same
/// way `_TELL_USER`'s own loop parses them -- is defined by `GCSPSRV.C`,
/// which does not survive (see [`cnvs2d`]'s doc comment for the same gap).
///
/// # Errors
///
/// Always, for the same reason as [`cnvs2d`]: formatting `buf` by a guessed
/// rule would hand the module text that looks transformed and is wrong,
/// worse than not transforming it at all because nothing downstream could
/// tell the difference. Unreachable regardless -- every call site this host
/// could take is inside `ISGCSU`-gated code, and `ISGCSU` is never set here.
pub fn stp4cs<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let buf = call.ptr();
    Err(ShimError::Failed(format!(
        "stp4cs(buf={buf:?}): the client/server text transform stp4cs performs \
         is not recoverable from any surviving source -- GCSPSRV.C does not \
         exist in this archive -- and every real call site is reached only \
         when ISGCSU is set, which this host, serving telnet only, never does"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;

    /// All seven refuse unconditionally -- there is no input that makes any
    /// of them succeed, because none of the state their contract depends on
    /// (`rqdptr`, `usdptr`, a connected GCSP client, `GCSPSRV.C`'s own
    /// string grammar) exists in this host. Asserted once per routine, the
    /// same shape `shims::gsbl`'s
    /// `every_routine_refuses_a_channel_out_of_range` uses for its own
    /// uniform refusal.
    #[test]
    fn every_routine_refuses_unconditionally() {
        let mut f = Fixture::new();
        for (name, result) in [
            ("stdmchk", f.invoke(stdmchk, &[10])),
            ("rejectreq", f.invoke(rejectreq, &[])),
            ("rsp2read", f.invoke(rsp2read, &[0x1234, 0x5678, 0xffff, 0x9abc, 0xdef0])),
            ("rsp2write", f.invoke(rsp2write, &[1, 0, 0, 0])),
            (
                "senddpk",
                f.invoke(senddpk, &[0, 0x1111, 0x2222, 3, 0x3333, 0x4444, 0xffff, 0x5555, 0x6666]),
            ),
            ("cnvs2d", f.invoke(cnvs2d, &[0x1234, 0x5678])),
            ("stp4cs", f.invoke(stp4cs, &[0x1234, 0x5678])),
        ] {
            assert!(
                matches!(result, Err(ShimError::Failed(_))),
                "{name} answered instead of refusing: {result:?}"
            );
        }
    }
}
