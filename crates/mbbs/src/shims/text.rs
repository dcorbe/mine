//! Strings, numbers and the print buffer.
//!
//! Everything here is a leaf: it computes, and it touches no host state a
//! module can observe later except the memory it was pointed at. `prf` and
//! `clrprf` are the exception that proves it -- they move `prfptr`, which is a
//! host global the module reads back.
//!
//! Signatures from `GCOMM.H`. Semantics from Galacticomm's own use of them
//! where the header does not say: `GALFILUT.C:73` passes `stzcpy`'s result
//! straight to `checkdir`, which is how we know it returns the destination and
//! not the terminator.
//!
//! [`append`] is where `crate::ifansi::process` runs for `prf` and `prfmsg`
//! -- see its doc comment -- so the `ESC[[ansi|ascii]` construct is consumed
//! before any of it reaches `prfbuf`. It is not the only way text reaches a
//! channel: `shims::gsbl::btuxmt` is handed strings the module never passed
//! through `prf`, and consumes the construct itself (its doc comment carries
//! the trace that found it).

use mbbs_machine::m16::Machine;
// `Ret` is now named only by this file's `#[cfg(test)]` `_wg16` bridges --
// production code reaches every routine here through its generic
// `Call<A>`/`Host<A>` core instead, per `shims::mod`'s own `call` doc comment.
#[cfg(test)]
use mbbs_machine::m16::Ret;
use mbbs_machine::ptr::ModulePtr;

use crate::Host;
use crate::abi::{self, Abi, Call, Wg16};
use crate::fmt::{Spec, format_call, integer};
use crate::shims::ShimError;

/// Bytes in one of `spr`'s rotating buffers.
pub const SPR_BYTES: u16 = 1024;

/// How many buffers `spr` rotates through.
///
/// Four, and it is observable: `prf("%s and %s", spr(...), spr(...))` needs
/// both results alive at once, and a module that nests more than four deep
/// gets the oldest one back. Galacticomm's own rotating-buffer idiom is
/// `cycle=((cycle+1)&3)` (`GALFILUT.C:73`), and MBBSEmu independently reads the
/// same count out of the binary.
pub const SPR_BUFFERS: usize = 4;

/// `char *spr(char *fmat, ...)` -- format into a buffer the host owns.
///
/// The module keeps the pointer, so the buffer has to outlive the call and the
/// rotation has to be wide enough that the next few calls do not tread on it.
///
/// Generic (Task 5): [`crate::fmt::format_call`] replaces `format`/
/// `Args::Call` -- `ctlstg` is `call.ptr()`, and by the time it is read,
/// `call`'s position already marks where the varargs begin.
pub fn spr<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let ctlstg = call.ptr();
    let (text, _) = format_call(call, ctlstg)?;
    let at = host.next_spr_buffer();
    write_cstr_mem::<A>(call.mem(), at, &text, SPR_BYTES)?;
    Ok(abi::Ret::Ptr(at))
}

/// Bytes in one of `l2as`'s rotating buffers.
///
/// A signed 32-bit decimal is at most 11 characters -- `i32::MIN` prints
/// `-2147483648` -- plus the NUL [`write_cstr`] appends. 12 is that number
/// exactly, not headroom.
pub const L2AS_BYTES: u16 = 12;

/// How many buffers `l2as` rotates through.
///
/// Every call site this shim is known to serve
/// (`re/exports/WCCMMUD_named.c:8023-8068`, `:21410-21460`) feeds its result
/// straight to the very next `prf` before calling `l2as` again, so one buffer
/// would cover everything measured. Matching [`SPR_BUFFERS`]'s width anyway:
/// nothing rules out a format string built from more than one `l2as` result at
/// once, the way `prf("%s and %s", spr(...), spr(...))` already does for
/// `spr`, and four buffers of 12 bytes is 48 bytes total -- cheap insurance
/// against a call shape the measured sites do not happen to show.
pub const L2AS_BUFFERS: usize = 4;

/// `char *l2as(long longin)` -- render a signed 32-bit decimal into a buffer
/// the host owns.
///
/// `GCOMM.H:319` declares the signature -- one `long` in, a far `char *` out
/// -- and `#define ltoa(a) l2as(a)` (`GCOMM.H:254`) redirects `ltoa` straight
/// onto it, which is why `ltoa`'s well-known contract (radix 10, no thousands
/// separator -- that is `commas`, `GCOMM.H:488`, a separate post-processing
/// routine -- a leading `-` for negative values, `0` prints as `"0"`) applies
/// here too. `wg1/GALDSRC/SRC/ACCOUNT.C:329` calls `l2as(tclptr->dbtlmt*-1L)`
/// to display a debt as a positive number, which only makes sense if `l2as`
/// would otherwise have printed the sign; `wg1/GALDSRC/SRC/GALFILUT.C:183-186`
/// special-cases zero in the *caller*, which only makes sense if `l2as` itself
/// renders a plain `"0"`.
///
/// The 14 relocation sites `re/ne_arity.py` finds (ordinal 377) all clean 2
/// words, matching a single `long` argument -- not the five-argument shape
/// `re/exports/WCCMMUD_named.c` shows, which is a Ghidra artifact of an
/// unresolved import folding nearby stack slots into a fabricated argument
/// list.
///
/// [`Machine::arg_u32`], not `arg_u16`: a `long` is two words, and reading
/// only the low one would silently misformat every value at or above 65536
/// while still looking right on anything smaller. The 32 bits are read as
/// **signed** -- `ul2as` (`GCOMM.H:320`) is the separate unsigned variant --
/// and `i32::unsigned_abs` gets the magnitude without the negation overflow
/// `-value` would hit at `i32::MIN`.
///
/// Formatting itself is [`integer`], the same converter `%d`/`%ld` use, not a
/// second implementation -- see `fmt`'s module doc for why that matters.
///
/// Generic (Task 5): the only argument read is `call.long()`, which is
/// [`Abi::LONG_WIDTH`] bytes in every ABI met so far -- no width to get wrong
/// the way an `int` read has.
pub fn l2as<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let value = call.long() as i32;
    let negative = value < 0;
    let magnitude = u64::from(value.unsigned_abs());
    let text = integer(magnitude, negative, 10, false, &Spec::default());
    let at = host.next_l2as_buffer();
    write_cstr_mem::<A>(call.mem(), at, &text, L2AS_BYTES)?;
    Ok(abi::Ret::Ptr(at))
}

/// `char *ul2as(unsigned long ulongin)` -- [`l2as`] for a value that has no
/// sign.
///
/// `%lu`, not `%ld`: `0xFFFFFFFF` prints as `4294967295`, where [`l2as`]
/// prints `-1`. That is the entire difference between the two, and
/// `L2AS.C`'s own header comment states the ranges -- `l2as` answers
/// `"-2147483648"` through `"2147483647"`, `ul2as` answers `"0"` through
/// `"4294967296"` (sic; the true ceiling is 4294967295).
///
/// **The rotation is shared with [`l2as`], not a second one.** The vendor has
/// one `static INT cycle` and one `static CHAR tkastg[4][16]`
/// (`L2AS.C:27-28`) and both functions in the file advance and index them --
/// so four calls in any mix answer four distinct buffers and the fifth
/// overwrites the first. `Host::next_l2as_buffer` is that one rotation, which
/// is why this routine calls it rather than allocating a pool of its own: a
/// module that survives the overwrite in the real host must meet it here too.
///
/// Formatting is [`integer`], the same converter `%lu` itself goes through,
/// rather than a second implementation -- see `fmt`'s module doc.
///
/// # Errors
///
/// If the rendered value and its terminator will not fit [`L2AS_BYTES`].
/// Ten digits and a NUL is eleven bytes, so the widest `ULONG` fits.
pub fn ul2as<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let value = call.long();
    let text = integer(u64::from(value), false, 10, false, &Spec::default());


    let at = host.next_l2as_buffer();
    write_cstr_mem::<A>(call.mem(), at, &text, L2AS_BYTES)?;
    Ok(abi::Ret::Ptr(at))
}

/// `int sprintf(char *buf, char *fmat, ...)` -- format into the caller's
/// buffer, and return how many bytes that took.
///
/// How big the buffer is, only the caller knows. The bounds check is the
/// segment's, which is the only limit the host can see.
///
/// Generic (Task 5): [`crate::fmt::format_call`] replaces `format`/
/// `Args::Call` -- `buffer` and `template` are `call.ptr()`, same as always,
/// and by the time both are read, `call`'s position already marks where the
/// varargs begin.
pub fn sprintf<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let buffer = call.ptr();
    let template = call.ptr();
    let (text, _) = format_call(call, template)?;
    fill::<A>(call.mem(), buffer, &text)?;
    // The length at `A`'s own int width. `as u16` wrapped a format longer
    // than 65535 bytes into a small, plausible, wrong count.
    Ok(abi::Ret::Int(A::int_from_u32(text.len() as u32)))
}

/// `int vsprintf(char *buf, const char *fmat, va_list ap)` -- format into the
/// caller's buffer from an argument list it was handed, and return how many
/// bytes that took.
///
/// [`sprintf`] with the arguments somewhere else, and deliberately nothing
/// more: both go through the same [`crate::fmt::format`], so a conversion that
/// is right in one is right in the other.
///
/// Borland's `va_list` is `void *`, far under the huge model, which is why both
/// of MajorMUD's call sites clean six words rather than five. What it points at
/// is the caller's own frame in `SS` -- `va_start` is `lea ax,[bp+0x0a]` at
/// `seg 32:0x0b79`, the word past the last fixed argument -- so the words
/// behind it are laid out exactly as this routine's own would be.
///
/// Generic (Task 5): [`crate::fmt::format_va_list`] replaces `format`/
/// `Args::List` -- `list` names the caller's own frame, not this call's, so
/// it is read through `call.mem()` on demand rather than through `call`'s
/// position, same as the `Wg16`-concrete original.
pub fn vsprintf<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let buffer = call.ptr();
    let template = call.ptr();
    let list = call.ptr();
    let (text, _) = crate::fmt::format_va_list(call, template, list)?;
    fill::<A>(call.mem(), buffer, &text)?;
    // The length at `A`'s own int width. `as u16` wrapped a format longer
    // than 65535 bytes into a small, plausible, wrong count.
    Ok(abi::Ret::Int(A::int_from_u32(text.len() as u32)))
}

/// `void prf(char *fmat, ...)` -- append to the channel's output.
///
/// `prfbuf` and `prfptr` are `char *` globals, not the buffer (`GCOMM.H:449`).
/// **`prfptr` is read back out of module memory every time**, never remembered:
/// the module moves it itself, and a host that cached it would append over
/// whatever the module had written.
///
/// Generic (Task 5): [`crate::fmt::format_call`] and [`append_mem`] replace
/// `format`/`Args::Call` and `append`.
pub fn prf<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let fmat = call.ptr();
    let (text, _) = format_call(call, fmat)?;
    // `MBBS_TRACE_SHIMS`: the text the module composed, before `outprf`
    // decides whether it is ever transmitted. A module that formats a message
    // and never sends it is otherwise indistinguishable from one that never
    // had anything to say -- which is exactly what a wedged move looks like.
    if super::traced() {
        eprintln!("mbbs-trace: PRF {:?}", String::from_utf8_lossy(&text));
    }
    append_mem(call.mem(), host, &text)?;
    Ok(abi::Ret::Void)
}

/// Put `text` where `prfptr` points, and move `prfptr` past it.
///
/// Shared with `prfmsg`, which is this and a template that came out of a
/// message file rather than out of the module. That sharing is exactly what
/// makes `append` this host's `FormatOutput`
/// (`ExportedModuleBase.cs:1133-1138`): [`crate::ifansi::process`] runs here,
/// over the whole of `text`, before a byte of it is written into `prfbuf` --
/// **not** in the transport, and never after [`crate::gsbl`]'s wrap.
/// `btutsw`'s wrap arithmetic counts every byte toward the column; running
/// this after that count has already happened would shrink the string GSBL
/// wrapped without telling it, which is a wrap bug wearing an IF-ANSI
/// costume, not a genuine fix. `shims::gsbl::btuxmt` applies the same rule
/// to the strings it is handed directly, ahead of the same wrap.
///
/// **Never called with a construct split across two calls, for
/// `WCCMMUD.DLL`.** `prf` and `prfmsg` each call [`format`] exactly once and
/// hand the *entire* formatted string to this function in one call --
/// `format` builds one `Vec<u8>` and returns it whole, it does not stream a
/// template out piece by piece. Measured over the module: all 269
/// `ESC[[...]` constructs in `WCCMMUD.DLL` close inside their own
/// NUL-terminated string, so there is no construct for this function to ever
/// see arrive half from one call and half from the next. A module without
/// that property would need `append` to carry state across calls the way
/// [`crate::ifansi`] alone cannot; this one does not need to, and does not.
///
/// See [`channel_ansi`] for how the ANSI/ASCII branch is chosen.
///
/// Generic (Task 5): [`channel_ansi_mem`], [`Globals::pointer_mem`] and
/// [`write_cstr_mem`] replace their `Wg16`-only namesakes; [`Host::prf_end`]
/// never touched a `Machine`. The offset arithmetic that used to build a
/// moved `FarPtr` by hand is [`Abi::ptr_offset`] instead, the same read
/// [`shims::user::begin_polling`](crate::shims::user::begin_polling) already
/// established for a computed pointer.
///
/// Kept under its original name and `&mut Machine` signature as a `Wg16`
/// facade: `shims::fsd` calls this directly (not through `Fixture::invoke`),
/// and does not convert in this task. `shims::msg::prfmsg` used to as well --
/// it calls [`append_mem`] directly now that it is generic.
pub fn append(machine: &mut Machine, host: &mut Host<Wg16>, text: &[u8]) -> Result<(), ShimError> {
    append_mem(machine.mem_mut(), host, text)
}

/// The generic core [`append`] delegates into.
///
/// Where the *bound* comes from is different from [`write_cstr_mem`]'s other
/// callers, and worth spelling out: the old `Wg16`-only body computed
/// `capacity = end - at.offset` by hand, subtracting a pointer's own
/// `.offset` field from [`Host::prf_end`] -- and `Abi` has no operation that
/// subtracts two pointers of an arbitrary ABI (only [`Abi::ptr_offset`],
/// which adds), so that arithmetic cannot be expressed generically without
/// assuming `Wg16`'s own byte layout. It does not need to be: `prfbuf` is
/// allocated as its own dedicated region of exactly [`crate::globals::OUTBSZ`]
/// bytes (`Globals::new`), and [`Host::prf_end`] is that same constant --
/// so a write that runs past `prf_end` is *exactly* a write that runs past
/// the region [`ModulePtr::write`] already refuses on its own. Letting that
/// write fail on its own bound, instead of re-deriving the identical bound by
/// hand, is what stays correct for an ABI whose pointer has no
/// `Wg16`-shaped `.offset` to read.
pub fn append_mem<A: Abi>(mem: &mut A::Mem, host: &mut Host<A>, text: &[u8]) -> Result<(), ShimError> {
    let ansi = channel_ansi_mem(mem, host);
    let text = crate::ifansi::process(text, ansi);
    // After IF-ANSI, per `FormatOutput`'s own order
    // (`ExportedModuleBase.cs:1133-1138`) -- see [`normalize_newlines`] for
    // why, and for the order test that catches a swap.
    let text = &normalize_newlines(&text);

    let at = host
        .globals()
        .pointer_mem(mem, "prfptr")
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    let mut bytes = text.to_vec();
    bytes.push(0);
    at.write(mem, &bytes).map_err(|e| {
        ShimError::Failed(format!(
            "prf would put {} bytes past the end of the {}-byte buffer: {e}",
            text.len(),
            host.prf_end()
        ))
    })?;

    let moved = A::ptr_offset(at, text.len() as u16);
    host.globals()
        .write_mem(mem, "prfptr", &A::ptr_to_bytes(moved))
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(())
}

/// `FormatNewLineCarriageReturn`, MBBSEmu's second `FormatOutput` stage
/// (`ExportedModuleBase.cs:971-1004`), ported literally: every bare `\r` or
/// `\n` becomes `\r\n`. If the very next byte would have completed the pair
/// the other way round -- `\r` then `\n`, or `\n` then `\r` -- that byte is
/// consumed too, so a line ending the module already spelled out in full
/// does not double. Anything else passes through untouched.
///
/// Runs in [`append`], after [`crate::ifansi::process`] and before a byte
/// reaches `prfbuf` -- both required by `FormatOutput`'s own order
/// (`ExportedModuleBase.cs:1133-1138`) and by `crate::gsbl::Channel::transmit`'s
/// wrap arithmetic, which counts every byte toward `column`: inserting a
/// `\r` downstream of that count would desynchronise the column tracker from
/// the wire, the same trap this function's sibling stage avoided (`append`'s
/// own doc comment).
///
/// # The oracle does not carve out an exception -- once `re/oracle/` is read
/// correctly
///
/// The plan this function implements
/// (`docs/plans/2026-08-11-live-session-defects.md`, Task 2) measured
/// "18,601 bare `\n` survive on the genuine wire" and read that as meaning
/// the rule cannot be "every `\n` becomes `\r\n`". That measurement counted
/// all 214 files under `re/oracle/` as one corpus of wire bytes. They are
/// not. `tools/oracle/mudlib.py:20,39-41` shows `Session.raw` is opened once
/// and written the *exact* bytes `socket.recv()` returned, nothing else --
/// genuinely the wire, and that is every `.raw` file. The `.log`/`.json`
/// files are a second, derived artifact: `tools/oracle/oracle_blur_duration.py:31-32,70`
/// strips ANSI and decodes CP437 before writing, one record per captured
/// chunk, terminated by a `\n` **the logging tool adds itself**
/// (`logf.write(f"{t:.3f} RX {ln}\n")`) -- a record separator with no wire
/// byte behind it at all.
///
/// Filtered to the 120 files that are actually the wire, `re/oracle/`
/// contains 117,987 `\r\n` and **zero** bare `\n`. The 97 bare `\r` that
/// remain are not a counterexample either -- every one sits inside an FSD
/// field repaint, immediately before an `ESC[` cursor address (e.g.
/// `Zinvar\r\x1b[0;1m\x1b[23;1f...`, `re/oracle/oracle_blur_duration.raw`
/// offset 8773), which is an FSD field repaint written straight to the wire
/// via `host.gsbl_mut().transmit(...)` (`crate::shims::fsd::fsd_cycle`,
/// `fsd_drain_edge`, `outprf` -- `crates/mbbs/src/shims/fsd.rs:1314,1656,1683,1804`)
/// and never passes through `append` at all -- see [`append`]'s own doc
/// comment for why nothing this function does could have touched it. So the oracle,
/// read as the wire rather than as "everything the directory holds", agrees
/// with MBBSEmu's own algorithm exactly: there is no carve-out to find. The
/// plan's warning to let the oracle override the mirror when they disagree
/// is followed here by finding that they do not disagree -- the apparent
/// conflict was the measurement, not the code.
///
/// `crates/mbbs/tests/newline_oracle.rs` pins this against `re/oracle/`
/// directly, filtered the same way, so a future `.raw` capture that
/// contradicts it fails a test rather than waiting to be noticed by eye.
///
/// # No memory across calls
///
/// This function, like the MBBSEmu method it ports, keeps no state between
/// invocations: a line ending split across two separate `append` calls --
/// trailing `\r` in one, leading `\n` in the next -- becomes two `\r\n`, not
/// one. `append`'s own doc comment measures that no `ESC[[...]` construct in
/// `WCCMMUD.DLL` ever needs cross-call memory; the equivalent claim is not
/// measured here for a bare `\r`/`\n`. See
/// `append_has_no_memory_of_a_line_ending_split_across_two_calls` in this
/// module's tests, which pins today's (unfixed) behaviour rather than
/// asserting the gap away.
fn normalize_newlines(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() + 8);
    let mut i = 0;
    while i < text.len() {
        let byte = text[i];
        if byte == b'\r' || byte == b'\n' {
            out.push(b'\r');
            out.push(b'\n');
            if let Some(&next) = text.get(i + 1)
                && ((byte == b'\r' && next == b'\n') || (byte == b'\n' && next == b'\r'))
            {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        out.push(byte);
        i += 1;
    }
    out
}

/// Whether `append`'s caller is writing for a channel whose terminal
/// understands ANSI, so [`crate::ifansi::process`] knows which of a
/// construct's two forms to keep.
///
/// `prfbuf`/`prfptr` are one buffer for the whole host (`GCOMM.H:449`), not
/// one per channel: MajorBBS is cooperatively single-threaded, so exactly one
/// channel's module code is ever running, and [`Host::current_channel`]
/// (reading `usrnum` back out of module memory) names it. That is the same
/// question every FSD shim already asks of the host --
/// `crate::shims::fsd::fsdroom`'s `if let Ok(chan) = host.current_channel(...)`
/// is the precedent for tolerating "no channel is current" rather than
/// treating it as an error -- so this is not the "awkward to reach" case the
/// plan this module implements warns about: `append` has exactly the
/// `&Machine`/`&Host` pair `current_channel` needs, with no extra plumbing
/// and no signature change to `prf` or `prfmsg`.
///
/// The flag itself lives in module memory, not in this host's own state:
/// `Host::connect_state` writes `who.ansi` into `usracc.ansifl` bit `ANSON`
/// (`AccountLayout::ansifl`) when a channel connects, and this reads it back
/// the same way the module's own `_EDIT_CHARACTER_STATS` fork does
/// (`WCCMMUD_decompiled.c:1799-1805`, cited in `users::Connection::line_mode`).
///
/// Defaults to `true` -- the ANSI form -- when no channel is current, or when
/// the account record cannot be read at all. The first is reachable during a
/// module's own init routine and by every shim-level test in this crate that
/// calls `prf`/`prfmsg` without pointing `usrnum` anywhere first; the second
/// should not be reachable once a host has finished starting up, and `true`
/// is the same answer as the first default rather than a second guess to
/// keep track of. Neither default is invented for this function: it is what
/// MBBSEmu's own `ProcessIfANSI` always answers -- it takes an `isAnsi`
/// parameter and never reads it -- so a caller with nothing to ask degrades
/// to the one behaviour every `re/oracle/` capture already exhibits.
///
/// Generic (Task 5): [`Host::current_channel_mem`] and
/// [`Abi::ptr_offset`] replace `Host::current_channel` and the hand-built
/// `FarPtr` -- the same reading `Host::class_mem` already offsets `usrcls`
/// off a channel's slot.
pub(crate) fn channel_ansi_mem<A: Abi>(mem: &A::Mem, host: &Host<A>) -> bool {
    let Ok(chan) = host.current_channel_mem(mem) else {
        return true;
    };
    ansi_of_mem(mem, host, chan)
}

/// `chan`'s own `usracc.ansifl` bit -- [`channel_ansi_mem`] for a channel
/// the caller names rather than the current one. `btuxmt` is why this is
/// separate: it is handed a channel and writes to *that* player without
/// `curusr`ing first (`shims::gsbl::btuxmt`'s three-channel test), so the
/// ANSI/ASCII choice for what it carries belongs to its target, which need
/// not agree with the channel the module is running as.
pub(crate) fn ansi_of_mem<A: Abi>(mem: &A::Mem, host: &Host<A>, chan: crate::chan::Chan) -> bool {
    let account = host.users().account(chan);
    let ansifl = A::ptr_offset(account, host.users().account_layout().ansifl);
    match ansifl.resolve(mem, 1) {
        Ok(bytes) => bytes[0] & 1 != 0,
        Err(_) => true,
    }
}

/// `VOID stansi(VOID)` -- `MAJORBBS.H:843`. `MAJORBBS.C:4536-4540`:
///
/// **Fully implemented, and it has nothing to do** -- which is a statement
/// about this host's design rather than a gap, and is the reason it is not a
/// refusal.
///
/// The routine exists because the vendor's GSBL keeps its **own** per-channel
/// ANSI toggle, separate from the account record: `btucmd(chan,"[")` turns
/// GSBL's on and `"]"` turns it off (`BRKTHU.H:151`). `stansi` is the one
/// call that copies `usracc.ansifl`'s `ANSON` bit into that second place, and
/// it is needed precisely *because* there are two places.
///
/// **This host has one place.** [`channel_ansi_mem`] reads
/// `usaptr->ansifl & ANSON` out of the account record live, on every single
/// call to [`append_mem`], and that is what decides which half of every
/// `ESC[[ansi|ascii]` construct is emitted (`crate::ifansi`). There is no
/// copy to keep in step, so the synchronisation this routine performs is
/// already permanently in effect -- before the call, during it, and after.
///
/// That makes the empty body a *complete* answer to what the module asked:
/// after `stansi()`, ANSI handling matches the `usracc` setting, which is
/// what the routine promises. [`stansi_leaves_output_following_the_account_setting`](self::tests)
/// tests the promise rather than the emptiness, by flipping `ansifl` and
/// checking what actually comes out both ways.
///
/// If this host ever grows a GSBL-side ANSI flag of its own, this routine
/// stops being empty on the same day, and that test is where it will say so.
///
/// # Errors
///
/// Never. The signature is fallible because every shim's is.
pub fn stansi<A: Abi>(_call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    Ok(abi::Ret::Void)
}

/// `void clrprf(void)` -- throw away whatever `prf` has queued.
pub fn clrprf<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    clrprf_mem(call.mem(), host).map(|()| abi::Ret::Void)
}

/// The generic core [`clrprf`] delegates into, against memory directly.
/// `void clrprf(void)` reads no arguments, so unlike every other shim in this
/// file, its "generic core" and "no-argument body" are the same split
/// `shims::fsd::fsdapr` needs: `fsdapr` calls this by name once it converts
/// (a different file, out of this task's scope), reusing its own `call.mem()`
/// rather than being handed a `Call<A>` shaped for a routine that has no
/// arguments of its own to read.
pub fn clrprf_mem<A: Abi>(mem: &mut A::Mem, host: &mut Host<A>) -> Result<(), ShimError> {
    let start = host
        .globals()
        .pointer_mem(mem, "prfbuf")
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    start
        .write(mem, &[0])
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    host.globals()
        .write_mem(mem, "prfptr", &A::ptr_to_bytes(start))
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(())
}

/// `char *stzcpy(char *dst, char *src, unsigned num)` -- copy, bounded,
/// always terminated.
///
/// Not `strncpy`. `num` is the size of the destination, so at most `num - 1`
/// characters are copied and the NUL always fits; `strncpy` would copy `num`
/// and leave an unterminated buffer, which is the bug this routine exists to
/// avoid.
///
/// **It zero-fills**, which is the `z` in the name and what separates it from
/// [`stlcpy`]. `STZCPY.C:27-32` is two loops -- copy until `num-1` or the
/// source's terminator, then run the index out to `num` writing zeroes -- so
/// exactly `num` bytes are written on every call and the destination's tail
/// is cleared whether or not the copy needed it. Measured against a genuine
/// `MAJORBBS.EXE` in `tests/oracle_gate.rs`
/// (`stzcpy_zero_fills_the_whole_destination`), because a NUL-trimmed read
/// cannot tell a cleared tail from an untouched one -- which is how this host
/// shipped without the fill.
pub fn stzcpy<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let dst = call.ptr();
    let src = call.ptr();
    let num = Into::<u32>::into(call.int()) as u16;

    if num == 0 {
        // Nowhere to put even the terminator. Copying nothing is the only
        // thing that cannot overrun.
        //
        // The vendor does something else entirely here: `num-1` is `UINT`, so
        // a zero wraps to 65535, the copy runs to the source's terminator and
        // the fill loop then runs `i` out to 65535 -- a 64K overrun of a
        // buffer the caller said had no room at all. That is not behaviour to
        // reproduce; refusing to write is the only answer that cannot corrupt
        // whatever follows `dst`.
        return Ok(abi::Ret::Ptr(dst));
    }
    let text = src
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    fill_to_width::<A>(call.mem(), dst, &text, num)?;
    Ok(abi::Ret::Ptr(dst))
}

/// `char *stlcpy(char *dst, const char *src, unsigned num)` -- copy,
/// bounded, always terminated, and **nothing more**.
///
/// `num` is the size of the destination and counts the terminator, so at most
/// `num - 1` characters are copied -- the same contract as [`stzcpy`], which
/// sits beside it in `GCOMM.H` and differs in exactly one way: `stzcpy`'s
/// second loop clears the destination out to `num` and this routine's bare
/// `*cp='\0'` does not. The `l` is "limit"; the `z` is "zero fill". Anything
/// past the terminator is left as the caller had it, which
/// [`stlcpy_does_not_zero_fill_the_way_stzcpy_does`](self::tests) pins.
///
/// # Errors
///
/// If `src` is unterminated or unreadable, or the copy will not fit the
/// segment `dst` names.
pub fn stlcpy<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let dst = call.ptr();
    let src = call.ptr();
    let num = Into::<u32>::into(call.int()) as u16;

    if num == 0 {
        // As in `stzcpy`: `num-1` is `UINT`, so the vendor's loop bound wraps
        // to 65535 and it copies the whole source into a buffer the caller
        // said had no room. Writing nothing is the only answer that cannot
        // corrupt what follows `dst`.
        return Ok(abi::Ret::Ptr(dst));
    }
    let text = src
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let take = text.len().min(usize::from(num) - 1);
    write_cstr_mem::<A>(call.mem(), dst, &text[..take], num)?;
    Ok(abi::Ret::Ptr(dst))
}

/// `char *stzcat(char *dst, const char *src, unsigned num)` -- append, within
/// a budget that counts what is already there.
///
/// `num` is the size of the whole destination, not the room remaining, so the
/// append gets `num - dstlen` bytes and the result is at most `num - 1`
/// characters and a terminator. It is a [`stzcpy`] onto the end of what is
/// already there, so it inherits the zero fill: between the two calls every
/// byte of the destination up to `num` ends up written.
///
/// **`num - dstlen` is `UINT` arithmetic and underflows.** When the
/// destination already holds `num` characters or more, the vendor hands
/// `stzcpy` a `num` near 65535 and its fill loop runs that far past a buffer
/// the caller declared much shorter. This host refuses instead, naming the
/// underflow: reproducing a 64K overrun serves no module, and clamping it to
/// "append nothing" would turn a caller's arithmetic bug into a silent no-op
/// that looks like success.
///
/// # Errors
///
/// If either string is unterminated or unreadable, if the destination already
/// holds `num` characters or more, or if the append will not fit the segment.
pub fn stzcat<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let dst = call.ptr();
    let src = call.ptr();
    let num = Into::<u32>::into(call.int()) as u16;

    let dstlen = dst
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .len();
    if dstlen >= usize::from(num) {
        return Err(ShimError::Failed(format!(
            "stzcat(.., {num}): the destination already holds {dstlen} characters, \
             so the vendor's num-dstlen underflows and would fill {} bytes past a \
             buffer the caller sized at {num}",
            usize::from(num).wrapping_sub(dstlen) & 0xffff
        )));
    }
    let text = src
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let end = at::<A>(dst, dstlen)?;


    // `dstlen < num` was just checked, so this subtraction cannot wrap.
    fill_to_width::<A>(call.mem(), end, &text, num - dstlen as u16)?;
    Ok(abi::Ret::Ptr(dst))
}

/// Copy at most `num - 1` bytes of `text` to `at` and clear the rest, writing
/// exactly `num` bytes.
///
/// The shared core of [`stzcpy`] and [`stzcat`] -- `stzcat` is defined in the
/// vendor as a `stzcpy` onto the end of what is already there
/// (`STZCPY.C:44-45`), so the two must not be able to disagree about the
/// fill.
fn fill_to_width<A: Abi>(
    mem: &mut A::Mem,
    at: A::Ptr,
    text: &[u8],
    num: u16,
) -> Result<(), ShimError> {
    let take = text.len().min(usize::from(num) - 1);
    let mut bytes = text[..take].to_vec();
    bytes.resize(usize::from(num), 0);
    at.write(mem, &bytes).map_err(|e| ShimError::Failed(e.to_string()))
}

/// `char *strcpy(char *dst, char *src)`.
pub fn strcpy<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let dst = call.ptr();
    let src = call.ptr();
    let text = src
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let len = text.len() as u16 + 1;
    write_cstr_mem::<A>(call.mem(), dst, &text, len)?;
    Ok(abi::Ret::Ptr(dst))
}

/// `unsigned strlen(char *s)`.
pub fn strlen<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let s = call.ptr();
    let text = s
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    // The length at `A`'s own int width. `as u16` wrapped a format longer
    // than 65535 bytes into a small, plausible, wrong count.
    Ok(abi::Ret::Int(A::int_from_u32(text.len() as u32)))
}

/// `void rmvwht(char *string)` -- remove every whitespace character, in place.
///
/// See [`strings::rmvwht`](crate::strings::rmvwht), which is the transcription;
/// this is only the read and the write-back. The result is never longer than
/// what was read, so the original's capacity always holds it.
pub fn rmvwht<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let at = call.ptr();
    let text = at
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let tight = crate::strings::rmvwht(&text);
    let capacity = text.len() as u16 + 1;
    write_cstr_mem::<A>(call.mem(), at, &tight, capacity)?;
    Ok(abi::Ret::Void)
}

/// `char *skpwht(char *cp)` -- past the leading spaces.
///
/// The answer is a pointer *into* the caller's own buffer, so the selector is
/// the one that arrived. See [`strings::skpwht`](crate::strings::skpwht) for
/// why a tab does not count.
pub fn skpwht<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let cp = call.ptr();
    let text = cp
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let n = crate::strings::skpwht(text);
    Ok(abi::Ret::Ptr(at::<A>(cp, n)?))
}

/// `char *skpwrd(char *cp)` -- past this word, to the space that ends it.
pub fn skpwrd<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let cp = call.ptr();
    let text = cp
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let n = crate::strings::skpwrd(text);
    Ok(abi::Ret::Ptr(at::<A>(cp, n)?))
}

/// `int depad(char *cp)` -- strip trailing whitespace, answer how much went.
pub fn depad<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let at = call.ptr();
    let text = at
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let (kept, removed) = crate::strings::depad(&text);
    let capacity = text.len() as u16 + 1;
    write_cstr_mem::<A>(call.mem(), at, &text[..kept], capacity)?;
    Ok(abi::Ret::Int(A::Int::from(removed)))
}

/// `UIDSIZ`, `INC/GCSP.H:27` -- 30. [`zonkhl`] pads its argument out to this
/// many bytes, so a caller's buffer must be at least that big; see its own
/// doc comment.
const UIDSIZ: u16 = 30;

/// `void stripb(char *stg)` -- `SIGNUP.C:826-834`:
///
/// **Fully implemented.** [`depad`] with one extra step: when the caller
/// passed `input` *itself*, `inplen` is brought back into agreement with it.
///
/// **The `stg == input` test is a pointer comparison, not a content one.**
/// A caller passing a copy of `input`'s text gets the trim and leaves
/// `inplen` alone; only the global's own address triggers the fix-up. That is
/// reproduced exactly -- comparing the strings instead would update `inplen`
/// on calls the vendor does not, and `inplen` is what `parsin` and `rstrin`
/// both bound themselves by.
///
/// # Errors
///
/// If `stg` is not a valid pointer, if `input` or `inplen` is not placed, or
/// if the read or write runs off the segment.
pub fn stripb<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let stg = call.ptr();
    stripb_mem::<A>(call.mem(), host, stg)?;
    Ok(abi::Ret::Void)
}

/// [`stripb`]'s core, so [`makhdl`] can call it the way the vendor does
/// (`SIGNUP.C:841`) rather than repeating it.
fn stripb_mem<A: Abi>(mem: &mut A::Mem, host: &Host<A>, stg: A::Ptr) -> Result<(), ShimError> {
    let text = stg
        .read_cstr(mem)
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let (kept, _) = crate::strings::depad(&text);
    let capacity = text.len() as u16 + 1;
    write_cstr_mem::<A>(mem, stg, &text[..kept], capacity)?;

    let input = host
        .globals()
        .address("input")
        .ok_or_else(|| ShimError::Failed("input is not placed".into()))?;
    if stg == input {
        let len = u16::try_from(kept).map_err(|_| {
            ShimError::Failed(format!("input is {kept} bytes, which will not fit in inplen"))
        })?;
        host.globals()
            .write_int_mem(mem, "inplen", u32::from(len))
            .map_err(|e| ShimError::Failed(e.to_string()))?;
    }
    Ok(())
}

/// `int isuplo(char *stg)` -- `SIGNUP.C:871-893`:
///
/// **Fully implemented.** "Is uniformly cased": 1 when the string's letters
/// are all lower **or** all upper, 0 when they are mixed. A string with no
/// letters at all answers 1, both loops having run to the terminator.
///
/// Not one of the four routines Phase 2's plan named, and implemented anyway
/// because [`zonkhl`] calls it, it is declared in `MAJORBBS.H:985`, and every
/// oracle build exports it -- the same reason `cnclon` and `cncsig` are in
/// `shims::cnc`.
///
/// **Why `zonkhl` asks.** A user who typed `"McDonald"` meant the capital D;
/// one who typed `"mcdonald"` or `"MCDONALD"` did not choose a case at all,
/// so the host is free to impose its own. This is the test that tells those
/// apart, and it is why `zonkhl` leaves mixed-case names alone.
///
/// # Errors
///
/// If `stg` is not a valid pointer, or the read runs off the segment.
pub fn isuplo<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let stg = call.ptr();
    let text = stg
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Int(A::int_from_u32(u32::from(is_uniform_case(
        text,
    )))))
}

/// [`isuplo`]'s answer as a `bool`, so [`zonkhl`] can ask without a `Call`.
fn is_uniform_case(text: &[u8]) -> bool {
    let letters = || text.iter().copied().filter(u8::is_ascii_alphabetic);
    letters().all(|c| c.is_ascii_lowercase()) || letters().all(|c| c.is_ascii_uppercase())
}

/// `void zonkhl(char *stg)` -- `SIGNUP.C:844-868`:
///
/// **Fully implemented.** Title-cases a uniformly-cased name -- first letter
/// of each blank-delimited word up, the rest down -- and leaves a mixed-case
/// one exactly as typed, per [`isuplo`].
///
/// **It writes `UIDSIZ` bytes, not `strlen(stg)+1`.** The trailing `while`
/// runs *past* the terminator the `for` stopped on and zeroes everything up
/// to `stg[UIDSIZ-1]`. So a caller's buffer must be at least 30 bytes even
/// to pass a three-letter name -- which is the point, since the name is on
/// its way into a fixed-width Btrieve key field and the vendor wants the tail
/// deterministic rather than whatever the stack held.
///
/// That is reproduced rather than trimmed to the string's length: a Btrieve
/// record written from a buffer this host had left dirty would differ from
/// the original's byte for byte, in a field a key is built over. A caller
/// that passes a shorter buffer gets a `ShimError` here where the original
/// silently corrupted whatever followed -- the one place this port is
/// deliberately louder than its source, because the alternative is undefined
/// behaviour rather than a different answer.
///
/// **The `space` flag starts set**, so the very first character is the one
/// upper-cased; and a run of several blanks leaves it set, so `"van  der"`
/// capitalises `d` and not the second blank.
///
/// # Errors
///
/// If `stg` is not a valid pointer, or if writing `UIDSIZ` bytes at it runs
/// off the segment.
pub fn zonkhl<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let stg = call.ptr();
    zonkhl_mem::<A>(call.mem(), host, stg)?;
    Ok(abi::Ret::Void)
}

/// [`zonkhl`]'s core, so [`makhdl`] can call it the way the vendor does
/// (`SIGNUP.C:842`).
fn zonkhl_mem<A: Abi>(mem: &mut A::Mem, _host: &Host<A>, stg: A::Ptr) -> Result<(), ShimError> {
    let text = stg
        .read_cstr(mem)
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    // The whole `UIDSIZ` field, so the tail past the terminator is written
    // too -- see this routine's doc comment for why that is the point.
    let mut out = vec![0u8; usize::from(UIDSIZ)];
    let len = text.len().min(out.len());
    out[..len].copy_from_slice(&text[..len]);

    if is_uniform_case(&text) {
        let mut space = true;
        for byte in out[..len].iter_mut() {
            if *byte == b' ' {
                space = true;
            } else if space {
                *byte = crate::strings::toupper(*byte);
                space = false;
            } else {
                *byte = crate::strings::tolower(*byte);
            }
        }
    }

    stg.write(mem, &out).map_err(|e| {
        ShimError::Failed(format!("zonkhl pads its argument out to {UIDSIZ} bytes: {e}"))
    })
}

/// `void makhdl(char *stg)` -- `SIGNUP.C:836-842`:
///
/// **Fully implemented**, and the most demanded routine in Phase 2 -- six of
/// the corpus's modules import it.
///
/// Trailing blanks off, then title-cased and padded to `UIDSIZ`: a name in
/// the exact shape a Btrieve key field wants it. Both halves are called
/// through their own `_mem` cores rather than through their `Call<A>`
/// wrappers, because those wrappers would read `makhdl`'s own frame looking
/// for an argument that is already in hand.
///
/// **Order matters and is not interchangeable.** `stripb` first, so the
/// blanks are gone before [`zonkhl`] decides where words begin; running them
/// the other way would leave a trailing blank inside the padded field and set
/// `space` on a word that never comes.
///
/// # Errors
///
/// Whatever [`stripb`] or [`zonkhl`] reports -- in particular, a buffer
/// shorter than `UIDSIZ`.
pub fn makhdl<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let stg = call.ptr();
    stripb_mem::<A>(call.mem(), host, stg)?;
    zonkhl_mem::<A>(call.mem(), host, stg)?;
    Ok(abi::Ret::Void)
}

/// `int issupc(int c)` -- `SIGNUP.C:1147-1167`:
///
/// **Fully implemented.** The signup-time tightening of
/// [`crate::strings::is_uid_char`]: the same alphabet, minus whatever the
/// board's two configuration switches disallow.
///
/// **`'_'` is not in the switch.** `isuidc` accepts it and `issupc` reaches
/// it through the `default:` arm, so an underscore is allowed at signup
/// whatever `fulalw` says -- while `'.'`, `','`, `'-'`, `'\''` and `' '` are
/// gated. That asymmetry looks like an oversight in the vendor and is
/// reproduced, because a module's own signup validation was written against
/// it.
///
/// Both switches are read live from module memory on every call rather than
/// cached, because a module may write either of them.
///
/// # Errors
///
/// If `fulalw` or `digalw` is not placed.
pub fn issupc<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let c: u32 = call.int().into();
    let byte = u8::try_from(c).ok();

    let mut read = |name: &str| {
        host.globals()
            .word_mem(call.mem(), name)
            .map_err(|e| ShimError::Failed(e.to_string()))
    };

    let valid = match byte {
        Some(b'.' | b' ' | b',' | b'-' | b'\'') => read("fulalw")? != 0,
        // `isuidc(c) && (digalw || !isdigit(c))`. A value that is not a byte
        // at all fails `isuidc` in C too, so it fails here.
        Some(byte) => {
            crate::strings::is_uid_char(byte) && (read("digalw")? != 0 || !byte.is_ascii_digit())
        }
        None => false,
    };

    Ok(abi::Ret::Int(A::int_from_u32(u32::from(valid))))
}

/// `VOID clrinp(VOID)` -- `MAJORBBS.H:788`. `MAJORBBS.C:3204-3210`:
///
/// **Fully implemented.** Four writes to four placed globals, and all four
/// matter: `margv[0]=input` is the one a plausible implementation drops.
/// Clearing the buffer without re-pointing `margv[0]` at it leaves the first
/// parsed word addressing whatever the last line left behind, and `bgncnc`
/// (`CNCUTL.C:29`) opens with `nxtcmd=margv[0]` -- so a stale `margv[0]`
/// walks the concatenation cursor into freed text on the next command rather
/// than at an empty string.
///
/// # Errors
///
/// If any of `input`, `margv`, `inplen` or `margc` is not placed, or a write
/// runs off the segment.
pub fn clrinp<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let globals = host.globals();
    let input = globals
        .address("input")
        .ok_or_else(|| ShimError::Failed("input is not placed".into()))?;

    // `input[0]='\0'`: the buffer's first byte, not the whole buffer. The
    // vendor leaves the rest as it was.
    globals
        .write_mem(call.mem(), "input", &[0])
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    // `margv[0]=input`.
    globals
        .write_mem(call.mem(), "margv", &A::ptr_to_bytes(input))
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    globals
        .write_int_mem(call.mem(), "inplen", 0)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    globals
        .write_int_mem(call.mem(), "margc", 0)
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    Ok(abi::Ret::Void)
}

/// `VOID xltctls(CHAR *txtbuf)` -- `MAJORBBS.H:751`. `MAJORBBS.C:1564-1584`:
///
/// **Fully implemented**, in place and shrinking: `^A` becomes the single
/// byte `0x01`, and `^^` becomes a literal `^`.
///
/// Three details a rewrite gets wrong:
///
/// - **The fold is `c & ~0x40`, not "uppercase then subtract 64".** So `^a`
///   is `0x61 & ~0x40` = `0x21`, an exclamation mark, not `0x01`. The vendor
///   does not upper-case first and neither does this.
/// - **A trailing `^` survives.** The `case '\0'` arm breaks out of the
///   switch without touching anything, so a buffer ending in `^` keeps it.
/// - **`^^` leaves one `^`, and the loop's `cp++` steps over it**, so `^^^^`
///   becomes `^^` rather than collapsing further.
///
/// The result is never longer than the input, so it is written back over the
/// caller's own buffer at the length it arrived with.
///
/// # Errors
///
/// If `txtbuf` is not a valid pointer, or the read or write runs off the
/// segment.
pub fn xltctls<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let at = call.ptr();
    let text = at
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    let mut out: Vec<u8> = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        if text[i] != b'^' {
            out.push(text[i]);
            i += 1;
            continue;
        }
        match text.get(i + 1) {
            // `case '\0'`: nothing is done, and the trailing '^' stands.
            None => {
                out.push(b'^');
                i += 1;
            }
            // `case '^'`: the pair collapses to one, and `cp++` steps past it.
            Some(b'^') => {
                out.push(b'^');
                i += 2;
            }
            // `default`: the control character, and the letter is consumed.
            Some(&c) => {
                out.push(c & !0x40);
                i += 2;
            }
        }
    }

    // Never longer than what came in, so it fits where it came from.
    let capacity = text.len() as u16 + 1;
    write_cstr_mem::<A>(call.mem(), at, &out, capacity)?;
    Ok(abi::Ret::Void)
}

/// `void parsin(void)` -- parse `input` into `margv[]`.
///
/// **Not in the v6 host source.** `MAJORBBS.C`'s `getin()` folds this
/// parsing inline; the routine `WCCMMUD.DLL` imports is Worldgroup's own,
/// split out at
/// `archive/galacticomm/extract/wg20/galdsrc/SRC/MAJORBBS.C:3376`:
///
/// Four things this does that a from-scratch splitter would not, and each is
/// load-bearing:
///
/// 1. **It fills `margn[]`, not just `margv[]`.** `margn[i]` points at the NUL
///    that replaced word `i`'s separator. [`rstrin`] already reads `margn` to
///    put the spaces back, at **every** exit -- including the early `return`
///    inside the inner loop, which is the common case: a line with no
///    trailing whitespace never reaches the function's tail at all.
/// 2. **It sets `inplen`** to the offset of the last word's terminator from
///    the start of `input`.
/// 3. **It zeroes the tail of `input`** past the last word -- but only on the
///    path that falls through to the function's end. That path is reached
///    only when the line has trailing whitespace after its last word; the
///    early return does not run it, because there is nothing stale left to
///    clear when the word ended at the buffer's own terminator.
/// 4. **On an empty line it sets `margv[0]` to an empty string, not to
///    null.** The module reads `margv[0]` unguarded, so this host keeps one
///    NUL byte of its own for the purpose -- see [`Host::empty`].
///
/// Generic (Task 5): reads no argument of its own (matching
/// `shims::user::getin`'s prototype, which is what this shim unblocks -- see
/// this file's own commit message), and [`Globals::address`]/[`size`] never
/// touched a `Machine` to begin with. `Call<A>` is still the signature this
/// takes, matching every other converted shim's shape, even though its
/// `call.mem()` is all that gets used.
///
/// [`size`]: crate::globals::Globals::size
pub fn parsin<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    parsin_mem(call.mem(), host).map(|()| abi::Ret::Void)
}

/// The generic core [`parsin`] delegates into, against memory directly.
///
/// **Why this exists separately from [`parsin`]:** `void parsin(void)` reads
/// no arguments, so it was tempting to give it only the `Call<A>`-taking
/// shape every other converted shim gets -- but [`Host::get_input`] calls
/// this directly, from [`Host::poll`] as well as from `getin`, and `poll`
/// runs with **no outstanding module call on the machine at all**. A
/// `Call<A>`-taking `parsin` reaches it only through `shims::call`, which
/// unconditionally reads `Machine::arg_frame()` -- and that panics outside a
/// real dispatch ("arg_frame() with no outstanding call to read from"),
/// which is exactly what four of this crate's own `poll` tests caught the
/// first time this shim tried to route `get_input` through the `_wg16`
/// facade instead of through this `_mem` core. `shims::text::clrprf` needed
/// the identical split for the identical reason -- see its own doc comment.
pub fn parsin_mem<A: Abi>(mem: &mut A::Mem, host: &mut Host<A>) -> Result<(), ShimError> {
    let input = host
        .globals()
        .address("input")
        .ok_or_else(|| ShimError::Failed("input is not placed".into()))?;
    let size = usize::from(
        host.globals()
            .size("input")
            .ok_or_else(|| ShimError::Failed("input is not placed".into()))?,
    );
    let margv = host
        .globals()
        .address("margv")
        .ok_or_else(|| ShimError::Failed("margv is not placed".into()))?;
    let margn = host
        .globals()
        .address("margn")
        .ok_or_else(|| ShimError::Failed("margn is not placed".into()))?;

    let mut buf = input
        .resolve(mem, size)
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    let mut margv_ends: Vec<u16> = Vec::new(); // offsets into `buf`
    let mut margn_ends: Vec<u16> = Vec::new(); // offsets into `buf`

    // `inpptr = input - 1`. Every step below pre-increments before testing,
    // exactly as the C does, which is not a stylistic match: after a
    // separator is overwritten with a NUL, the outer loop's own
    // `while (*++inpptr == ' ')` has to step *past* that NUL before it looks
    // at anything, or it reads the byte it just wrote and mistakes it for the
    // end of the line.
    let mut i: isize = -1;

    loop {
        // `while (*++inpptr == ' ') {}`
        loop {
            i += 1;
            if buf.get(i as usize) != Some(&b' ') {
                break;
            }
        }
        // `if (*inpptr == '\0') { break; }`
        if buf.get(i as usize).copied().unwrap_or(0) == 0 {
            break;
        }
        // `margv[margc] = inpptr;`
        margv_ends.push(i as u16);

        // `while (*++inpptr != ' ') { if (*inpptr == '\0') { ...; return; } }`
        loop {
            i += 1;
            match buf.get(i as usize).copied() {
                Some(b' ') => break,
                None | Some(0) => {
                    // The early return. A word that runs straight into the
                    // buffer's own terminator, with no separator of its own
                    // to turn into one -- so `setmem` never runs, and
                    // nothing past this NUL is touched.
                    //
                    // R18: `None` and `Some(0)` are not the same event.
                    // `Some(0)` is the normal case, hitting `input`'s own
                    // terminator. `None` is `i` having walked off the end of
                    // `buf` with no terminator in it at all -- reachable only
                    // if the module wrote `input` itself and called `parsin`
                    // directly, since `Host::get_input` always terminates
                    // within `size - 1`. The C this is transcribed from was
                    // worse: it had no bound at all and would have walked
                    // arbitrarily far past the buffer looking for a NUL that
                    // might not exist. Here `i` cannot exceed `buf.len()` --
                    // the very first out-of-bounds index returns `None` and
                    // this arm returns immediately -- so `margn[margc-1]`
                    // lands at `input`'s own end, which is `margv[0]`'s own
                    // low byte: `globals.rs:565` places `margv` immediately
                    // after `input`.
                    margn_ends.push(i as u16);
                    return write_parse(
                        mem,
                        host,
                        input,
                        margv,
                        margn,
                        &buf,
                        &margv_ends,
                        &margn_ends,
                        i as u16,
                    );
                }
                Some(_) => {}
            }
        }
        // `*inpptr = '\0'; margn[margc++] = inpptr;`
        buf[i as usize] = 0;
        margn_ends.push(i as u16);
    }

    let inplen = match margn_ends.last().copied() {
        Some(last) => {
            for byte in &mut buf[usize::from(last)..] {
                *byte = 0;
            }
            last
        }
        None => 0,
    };
    write_parse(
        mem,
        host,
        input,
        margv,
        margn,
        &buf,
        &margv_ends,
        &margn_ends,
        inplen,
    )
}

/// The tail every exit of [`parsin`] shares: write the (possibly modified)
/// input buffer back, then `margc`, `inplen`, `margv[]` and `margn[]`.
///
/// Generic (Task 5): each `margv[n]`/`margn[n]` slot is [`Abi::PTR_WIDTH`]
/// bytes apart, not a hardcoded 4 -- the stride a hand-built `FarPtr` used to
/// take for granted.
#[allow(clippy::too_many_arguments)]
fn write_parse<A: Abi>(
    mem: &mut A::Mem,
    host: &mut Host<A>,
    input: A::Ptr,
    margv: A::Ptr,
    margn: A::Ptr,
    buf: &[u8],
    margv_ends: &[u16],
    margn_ends: &[u16],
    inplen: u16,
) -> Result<(), ShimError> {
    input.write(mem, buf).map_err(|e| ShimError::Failed(e.to_string()))?;

    let margc = margv_ends.len() as u16;
    host.globals()
        .write_mem(mem, "margc", &margc.to_le_bytes())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    host.globals()
        .write_mem(mem, "inplen", &inplen.to_le_bytes())
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    if margc == 0 {
        let empty = host.empty_string();
        margv
            .write(mem, &A::ptr_to_bytes(empty))
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        return Ok(());
    }

    for (n, &offset) in margv_ends.iter().enumerate() {
        let word = at::<A>(input, usize::from(offset))?;
        let slot = at::<A>(margv, n * A::PTR_WIDTH)?;
        slot.write(mem, &A::ptr_to_bytes(word))
            .map_err(|e| ShimError::Failed(e.to_string()))?;
    }
    for (n, &offset) in margn_ends.iter().enumerate() {
        let end = at::<A>(input, usize::from(offset))?;
        let slot = at::<A>(margn, n * A::PTR_WIDTH)?;
        slot.write(mem, &A::ptr_to_bytes(end))
            .map_err(|e| ShimError::Failed(e.to_string()))?;
    }
    Ok(())
}

/// `void rstrin(void)` -- put back the separators that parsing overwrote.
///
/// MajorBBS tokenises a command line in place: each separator becomes a `\0`,
/// `margv` points at the words and `margn` at where each one ended.
/// `MAJORBBS.H:384` says so -- "array of ptrs to word ends, for rstrin()" --
/// and this walks that array writing a space back at each.
///
/// **The bound is `margc - 1` and the comparison is signed**, which is why a
/// `margc` of zero writes nothing rather than looping 65,535 times. Read off
/// `seg 4:0x5bde` in `MAJORBBS.EXE`; the routine sets up no `bp` frame at all,
/// which is what settles that it takes no arguments -- the whole of its input
/// is these two globals.
///
/// Generic (Task 5): each `margn[n]` slot is [`Abi::PTR_WIDTH`] bytes apart,
/// not a hardcoded 4, same as [`write_parse`].
pub fn rstrin<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    rstrin_mem(call.mem(), host)?;
    Ok(abi::Ret::Void)
}

/// [`rstrin`] against memory directly, for host code that needs the whole
/// line back after `parsin` -- the editor's `bgncnc()` (`shims::editor`).
///
/// # Errors
///
/// If `margc` or `margn` is not placed, or a write runs off the segment.
pub(crate) fn rstrin_mem<A: Abi>(mem: &mut A::Mem, host: &Host<A>) -> Result<(), ShimError> {
    let margc = host
        .globals()
        .word_mem(mem, "margc")
        .map_err(|e| ShimError::Failed(e.to_string()))? as i16;
    let margn = host
        .globals()
        .address("margn")
        .ok_or_else(|| ShimError::Failed("margn is not placed".into()))?;

    for i in 0..(margc - 1).max(0) as u16 {
        let slot = at::<A>(margn, usize::from(i) * A::PTR_WIDTH)?;
        // `resolve` is how this crate reads raw bytes out of module memory --
        // `read_cstr` is for strings and there is no buffer-filling `read`.
        let bytes = slot
            .resolve(mem, A::PTR_WIDTH)
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        let end = A::ptr_from_bytes(bytes);
        end.write(mem, b" ")
            .map_err(|e| ShimError::Failed(e.to_string()))?;
    }
    Ok(())
}

/// `long atol(char *s)`.
///
/// Leading whitespace, an optional sign, then digits until something that is
/// not one. No error: C says the value is undefined on overflow and Borland
/// wraps, so this wraps.
pub fn atol<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let s = call.ptr();
    let text = s
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let mut rest = text;

    while rest.first().is_some_and(u8::is_ascii_whitespace) {
        rest = &rest[1..];
    }
    let negative = match rest.first() {
        Some(b'-') => {
            rest = &rest[1..];
            true
        }
        Some(b'+') => {
            rest = &rest[1..];
            false
        }
        _ => false,
    };

    let mut value = 0i32;
    while let Some(&byte) = rest.first().filter(|b| b.is_ascii_digit()) {
        value = value.wrapping_mul(10).wrapping_add(i32::from(byte - b'0'));
        rest = &rest[1..];
    }
    if negative {
        value = value.wrapping_neg();
    }
    Ok(abi::Ret::Long(value as u32))
}

/// `int sameas(char *stg1,char *stg2)` -- equal, ignoring case.
///
/// **1 is equal**, which is the opposite of [`strcmp`] and the reason this
/// family is worth reading twice. See
/// [`strings::sameas`](crate::strings::sameas).
pub fn sameas<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let stg1 = call.ptr();
    let stg2 = call.ptr();
    let a = stg1
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let b = stg2
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Int(A::Int::from(u16::from(crate::strings::sameas(&a, b)))))
}

/// `int sameto(char *shorts,char *longs)` -- a prefix test, short one first.
pub fn sameto<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let shorts_ptr = call.ptr();
    let longs_ptr = call.ptr();
    let shorts = shorts_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let longs = longs_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Int(A::Int::from(u16::from(crate::strings::sameto(&shorts, longs)))))
}

/// `int samein(char *shorts,char *longs)` -- a substring test, short one first.
pub fn samein<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let shorts_ptr = call.ptr();
    let longs_ptr = call.ptr();
    let shorts = shorts_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let longs = longs_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Int(A::Int::from(u16::from(crate::strings::samein(&shorts, longs)))))
}

/// `char *lastwd(char *string)` -- the last word, in the caller's own buffer.
///
/// See [`strings::lastwd`](crate::strings::lastwd). It writes nothing, and the
/// selector it answers is the one that arrived.
pub fn lastwd<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let s = call.ptr();
    let text = s
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let n = crate::strings::lastwd(text);
    Ok(abi::Ret::Ptr(at::<A>(s, n)?))
}

/// `void sortstgs(char *stgs[],int num)` -- sort an array of `char *` in place.
///
/// `num` is a signed `int` and the original's `gap = num / 2` is tested with a
/// signed compare, so **anything below two returns before the array is read**.
/// That is why a `num` of zero with a null array is not an error here either --
/// the real one never dereferences it.
///
/// The pointers move; the strings do not. See
/// [`strings::sortstgs`](crate::strings::sortstgs) for why the sort is
/// transcribed rather than delegated.
pub fn sortstgs<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let array = call.ptr();
    let num = Into::<u32>::into(call.int()) as i16;
    if num < 2 {
        return Ok(abi::Ret::Void);
    }
    let num = usize::from(num as u16);

    let slots = array
        .resolve(call.mem(), num * A::PTR_WIDTH)
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let mut items: Vec<(A::Ptr, Vec<u8>)> = Vec::with_capacity(num);
    for slot in slots.chunks_exact(A::PTR_WIDTH) {
        let ptr = A::ptr_from_bytes(slot);
        let text = ptr
            .read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?
            .to_vec();
        items.push((ptr, text));
    }
    crate::strings::sortstgs(&mut items, |a, b| crate::strings::strcmp(&a.1, &b.1));

    let out: Vec<u8> = items
        .iter()
        .flat_map(|(ptr, _)| A::ptr_to_bytes(*ptr))
        .collect();
    array.write(call.mem(), &out).map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Void)
}

/// `char *strtok(char *s,char *delim)` -- the next token, destructively.
///
/// Ordinal 585, `seg 1:0x24f4`. Three things worth naming:
///
/// * **The state is the host's.** A non-null `s` sets it, a null `s` continues
///   from it, and nothing the module can address holds it. See
///   [`Host::strtok`].
/// * **It writes into the caller's string**, putting a terminator over the
///   delimiter that ended each token. What it answers is a pointer into that
///   same buffer.
/// * **A run of delimiters is one gap**, because the leading-delimiter skip and
///   the token scan are separate loops; a string of nothing else answers
///   `NULL`.
///
/// The original walks a byte at a time through `les bx,[0x18a8]`. Reading the
/// remainder once with [`Machine::read_cstr`] is the same bytes and one bounds
/// check -- and it is what turns a cursor left dangling by a `galfree` into
/// [`ShimError::BadPointer`] rather than a token made of rubbish.
///
/// Generic (Task 5): the null check on `s` is [`is_null`], not `!= FarPtr::NULL`
/// -- `A::Ptr` has no such comparison and is opaque to a generic caller, the
/// same reading [`shims::user::begin_polling`](crate::shims::user::begin_polling)
/// already established.
pub fn strtok<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let s = call.ptr();
    let delim = call.ptr();
    let delims = delim
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    if !is_null::<A>(s) {
        host.strtok = s;
    }

    let cursor = host.strtok;
    let rest = cursor
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let Some(start) = rest.iter().position(|b| !delims.contains(b)) else {
        // Nothing but delimiters. The cursor ends on the terminator, so every
        // later call answers NULL too.
        host.strtok = at::<A>(cursor, rest.len())?;
        return Ok(abi::Ret::Ptr(null_ptr::<A>()));
    };
    let token_len = rest[start..].len();
    let ends_at = rest[start..].iter().position(|b| delims.contains(b));

    let token = at::<A>(cursor, start)?;
    match ends_at {
        Some(n) => {
            let end = at::<A>(token, n)?;
            end.write(call.mem(), &[0])
                .map_err(|e| ShimError::Failed(e.to_string()))?;
            host.strtok = at::<A>(end, 1)?;
        }
        None => host.strtok = at::<A>(token, token_len)?,
    }
    Ok(abi::Ret::Ptr(token))
}

/// `char *strchr(char *s,int c)`.
///
/// Ordinal 572, `seg 1:0xcf62`. Two things the prototype hides. `c` arrives as
/// an `int` and is compared as `mov bl,[bp+0xa]`, so **only its low byte
/// counts**. And the scan compares each byte *before* it tests for the end
/// (`lodsb / cmp al,bl / jz ... / and al,al / jnz`), so `strchr(s, 0)` answers
/// a pointer to the terminator rather than `NULL`.
pub fn strchr<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let s = call.ptr();
    let want = Into::<u32>::into(call.int()) as u8;
    let text = s
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    if want == 0 {
        return Ok(abi::Ret::Ptr(at::<A>(s, text.len())?));
    }
    match text.iter().position(|&b| b == want) {
        Some(i) => Ok(abi::Ret::Ptr(at::<A>(s, i)?)),
        None => Ok(abi::Ret::Ptr(null_ptr::<A>())),
    }
}

/// `char *strstr(char *hay,char *needle)`.
///
/// Ordinal 584, `seg 1:0x2896`. **An empty needle answers the haystack** --
/// the routine's first instruction after the frame is `cmp byte [es:bx],0` on
/// the needle, and the path it takes returns `hay` **without reading it**, so
/// the check comes before the haystack does here too. A needle that is not
/// there answers `NULL`.
pub fn strstr<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let hay = call.ptr();
    let needle_ptr = call.ptr();
    let needle = needle_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    if needle.is_empty() {
        return Ok(abi::Ret::Ptr(hay));
    }
    let text = hay
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    if needle.len() > text.len() {
        return Ok(abi::Ret::Ptr(null_ptr::<A>()));
    }
    let found = (0..=text.len() - needle.len()).find(|&i| text[i..].starts_with(&needle));
    match found {
        Some(i) => Ok(abi::Ret::Ptr(at::<A>(hay, i)?)),
        None => Ok(abi::Ret::Ptr(null_ptr::<A>())),
    }
}

/// `char *strcat(char *dst,char *src)`.
///
/// Ordinal 571, `seg 1:0x26d0`. How much room `dst` has, only the caller knows,
/// so the bound is the segment's -- the same limit [`fill`] applies to
/// `sprintf`, and for the same reason.
pub fn strcat<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let dst = call.ptr();
    let src = call.ptr();
    let end = dst
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .len();
    let text = src
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    fill::<A>(call.mem(), at::<A>(dst, end)?, &text)?;
    Ok(abi::Ret::Ptr(dst))
}

/// `char *strncat(char *dst,char *src,int maxlen)`.
///
/// Ordinal 580, `seg 1:0x236a`: `strlen`, `strlen`, clamp to `maxlen`, `movmem`,
/// then a terminator the routine writes itself at `dst[dstlen + n]`. So at most
/// `maxlen + 1` bytes land past the end of `dst` and -- unlike [`strncpy`] --
/// the result is always terminated.
pub fn strncat<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // Hoisted to frame order (0, 2, 4): the original read word 4 (`max`)
    // before word 2 (`src`), which `re/argscan.py` flags OUT-OF-ORDER,SKIPS
    // and which a forward-only cursor cannot reproduce. `Call::ptr`/`int` are
    // infallible -- they pull bytes off the frame and cannot fail or
    // branch -- so which of the three is decoded first is not observable;
    // only `read_cstr` can fail, and it still runs exactly where it always
    // did, after every argument is in hand.
    let dst = call.ptr();
    let src = call.ptr();
    // `int maxlen`, at `A`'s own width: `as u16` truncated any 32-bit bound
    // above 65535 into a much smaller one, silently shortening the copy.
    let max = Into::<u32>::into(call.int()) as usize;
    let end = dst
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .len();
    let text = src
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let text = text[..text.len().min(max)].to_vec();
    fill::<A>(call.mem(), at::<A>(dst, end)?, &text)?;
    Ok(abi::Ret::Ptr(dst))
}

/// `char *strncpy(char *dst,char *src,unsigned n)`.
///
/// Ordinal 582, `seg 1:0x2815`, and **not** [`stzcpy`] -- which is
/// Galacticomm's answer to this routine's one flaw. `strncpy` copies at most
/// `n` bytes and pads the rest of `n` with NUL, so a source of `n` characters
/// or more leaves the destination **unterminated**. Exactly `n` bytes are
/// written every time, which is what makes the bound checkable at all.
///
/// **The source need not be terminated.** `repne scasb` is issued with
/// `cx = n`, so the scan reads at most `n` bytes and stops; a blank-padded
/// fixed-width field with no NUL in it is precisely what this routine is for,
/// and refusing one would stop a module the real host served.
pub fn strncpy<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // Hoisted to frame order (0, 2, 4): the original read word 4 (`n`)
    // before word 2 (`src`), which `re/argscan.py` flags OUT-OF-ORDER,SKIPS.
    // `Call::ptr`/`int` are infallible reads off the frame, so decoding
    // `src` before checking `n == 0` is not observable -- `ptr()` never
    // resolves or dereferences anything, it only pulls bytes out of the
    // argument frame. The `n == 0` early return below still runs before
    // `src` is ever *read from* (via `resolve`/`read_cstr`), which is the
    // property that made the original safe on a source that is not there.
    let dst = call.ptr();
    let src = call.ptr();
    // `unsigned n`, at `A`'s own width -- see `strncat`'s own note.
    let n = Into::<u32>::into(call.int()) as usize;
    if n == 0 {
        // All three `rep` prefixes are no-ops, so the original dereferences
        // neither pointer. Same reason `stzcpy` returns early on a zero.
        return Ok(abi::Ret::Ptr(dst));
    }

    // What the scan could touch. `n` bytes if they are all inside the segment;
    // otherwise the original only got away with it because a terminator
    // stopped it first, and `read_cstr` is the reader that insists on one.
    let text = match src.resolve(call.mem(), n) {
        Ok(bytes) => bytes,
        Err(_) => src.read_cstr(call.mem()).map_err(|e| ShimError::Failed(e.to_string()))?,
    };
    let take = text
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(text.len())
        .min(n);

    let mut out = vec![0u8; n];
    out[..take].copy_from_slice(&text[..take]);
    dst.write(call.mem(), &out).map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Ptr(dst))
}

/// `int strcmp(char *s1,char *s2)` -- **0 is equal**, unlike [`sameas`].
///
/// See [`strings::strcmp`](crate::strings::strcmp): the result is the unsigned
/// byte difference, not a sign, and MajorMUD's 48 sites test it both ways.
pub fn strcmp<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let a_ptr = call.ptr();
    let b_ptr = call.ptr();
    let a = a_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let b = b_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Int(A::Int::from(crate::strings::strcmp(&a, b) as u16)))
}

/// `char *strlwr(char *s)` -- fold a string to lower case, in place.
///
/// [`crate::shims::cnc::strupr`]'s mirror, and deliberately built from the
/// same pair: [`crate::strings::tolower`] is the exact per-byte fold
/// `sameas`/`sameto`/`samein` already share, where `strupr` uses
/// [`crate::strings::toupper`]. (`strupr` lives in `shims::cnc` for
/// historical reasons rather than because it belongs there; the fold is what
/// matters and it is shared.)
///
/// **ASCII `A`-`Z` only.** Nothing locale-aware, matching what Borland's own
/// `strlwr` did under a `char` that is one byte regardless of `A`. That is
/// not a simplification -- it is load-bearing here, because MajorMUD's text
/// is full of CP437 high-bit bytes (box drawing, accented letters) and a fold
/// that touched them would corrupt every room description that uses one.
///
/// **Length never changes**, so the write fits back exactly where the read
/// came from: `capacity` is `text.len() + 1`, one byte for the terminator
/// that was already there.
///
/// # Errors
///
/// If `s` is not a valid pointer, or the read or write runs off the segment.
pub fn strlwr<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let s = call.ptr();
    let original = s
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let lower: Vec<u8> = original.iter().map(|&b| crate::strings::tolower(b)).collect();
    let capacity = lower.len() as u16 + 1;
    write_cstr_mem::<A>(call.mem(), s, &lower, capacity)?;
    Ok(abi::Ret::Ptr(s))
}

/// `int strncmp(const char *s1, const char *s2, size_t n)` -- compare at most
/// `n` bytes.
///
/// Stops at the first difference **or at a terminator**, whichever comes
/// first. The case that separates a real port from one that merely limits the
/// loop is `n` larger than both strings: the comparison has to stop at the
/// NUL rather than read on into whatever follows it, which under this host
/// would be another module's bytes.
///
/// The answer is the difference of the first differing pair, read as
/// **unsigned** bytes -- ISO C compares `unsigned char` regardless of whether
/// plain `char` is signed, which decides the sign for any byte over 127.
/// Same shape as [`crate::shims::crt::stricmp`]'s.
///
/// # Errors
///
/// If either pointer is unreadable or unterminated.
pub fn strncmp<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let a_ptr = call.ptr();
    let b_ptr = call.ptr();
    let n = Into::<u32>::into(call.int()) as usize;

    let a = a_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let b = b_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    Ok(abi::Ret::Int(A::int_from_u32(
        bounded_compare(&a, &b, n, |c| c) as u32,
    )))
}

/// `int strnicmp(const char *s1, const char *s2, size_t n)` -- [`strncmp`]
/// ignoring case.
///
/// The fold is the same ASCII-only one [`strlwr`] uses, applied to both sides
/// before the comparison, so a high-bit CP437 byte compares as itself.
///
/// # Errors
///
/// If either pointer is unreadable or unterminated.
pub fn strnicmp<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let a_ptr = call.ptr();
    let b_ptr = call.ptr();
    let n = Into::<u32>::into(call.int()) as usize;

    let a = a_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let b = b_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    Ok(abi::Ret::Int(A::int_from_u32(
        bounded_compare(&a, &b, n, crate::strings::tolower) as u32,
    )))
}

/// The shared core of [`strncmp`] and [`strnicmp`]: compare at most `n`
/// bytes, each passed through `fold`, stopping at a difference or a
/// terminator.
///
/// `a` and `b` arrive without their terminators (that is what `read_cstr`
/// gives), so indexing past the end yields `0` -- which is the terminator,
/// and makes "one string is a prefix of the other" fall out as a comparison
/// against NUL rather than needing a length case of its own.
fn bounded_compare(a: &[u8], b: &[u8], n: usize, fold: fn(u8) -> u8) -> i32 {
    for i in 0..n {
        let ca = fold(a.get(i).copied().unwrap_or(0));
        let cb = fold(b.get(i).copied().unwrap_or(0));
        if ca != cb {
            return i32::from(ca) - i32::from(cb);
        }
        if ca == 0 {
            // Both terminated here, so they are equal and the rest of `n`
            // cannot change the answer.
            //
            // **This is a bound on work, not on memory.** What keeps a large
            // `n` from reading past either string is `read_cstr` above, which
            // hands back only the bytes up to the terminator; past that, the
            // `unwrap_or(0)` supplies the terminator itself and the loop
            // compares NUL against NUL for as long as `n` says. Deleting this
            // `break` changes no answer -- checked by mutation -- and costs
            // `n` iterations where the vendor's loop costs a handful.
            break;
        }
    }
    0
}

/// `long strtol(const char *nptr, char **endptr, int base)` -- parse a long,
/// and report where parsing stopped.
///
/// Three things a rewrite gets wrong, in the order it gets them wrong:
///
/// 1. **`endptr` is written through.** It is a `char **`, and the caller's
///    whole reason for passing it is to find out where the number ended --
///    a tokeniser calls `strtol` in a loop and advances by it. A null
///    `endptr` is legal and means "do not report".
/// 2. **Base 0 infers the radix from the prefix**: `0x`/`0X` is hexadecimal,
///    a leading `0` is octal, anything else decimal. Bases 2..=36 are
///    explicit, and base 16 also accepts an optional `0x`.
/// 3. **Nothing consumed means `endptr` gets `nptr` itself**, unchanged, and
///    the answer is 0 -- including when the sign or the `0x` was consumed but
///    no digit followed it.
///
/// Leading whitespace is skipped, then an optional `+`/`-`. Digits run while
/// they are valid for the radix; letters count from `a`/`A` = 10, so base 36
/// reaches `z`.
///
/// Overflow saturates at `LONG_MAX`/`LONG_MIN`, which is what ISO C's
/// `strtol` does (and it sets `errno`, which this host does not model -- said
/// here rather than left to look like an oversight).
///
/// # Errors
///
/// If `nptr` is unreadable, or `endptr` names memory that cannot be written.
pub fn strtol<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let nptr = call.ptr();
    let endptr = call.ptr();
    let base = Into::<u32>::into(call.int()) as i32;

    let text = nptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    let (value, consumed) = parse_long(&text, base);

    if !is_null::<A>(endptr) {
        let stopped = at::<A>(nptr, consumed)?;
        endptr
            .write(call.mem(), &A::ptr_to_bytes(stopped))
            .map_err(|e| ShimError::Failed(format!("strtol: endptr: {e}")))?;
    }
    Ok(abi::Ret::Long(value as u32))
}

/// [`strtol`]'s parse: the value, and how many bytes of `text` it consumed.
///
/// A consumed count of zero means no conversion was performed, which is what
/// makes `endptr == nptr` the caller's signal for "that was not a number".
fn parse_long(text: &[u8], base: i32) -> (i32, usize) {
    let mut i = 0;
    while text.get(i).is_some_and(u8::is_ascii_whitespace) {
        i += 1;
    }
    let negative = match text.get(i) {
        Some(b'-') => {
            i += 1;
            true
        }
        Some(b'+') => {
            i += 1;
            false
        }
        _ => false,
    };

    // Base 0 infers; base 16 tolerates the prefix it implies.
    let mut radix = base;
    if (base == 0 || base == 16)
        && text.get(i) == Some(&b'0')
        && matches!(text.get(i + 1), Some(b'x' | b'X'))
    {
        radix = 16;
        i += 2;
    } else if base == 0 {
        radix = if text.get(i) == Some(&b'0') { 8 } else { 10 };
    }

    let digits_at = i;
    let mut value: i64 = 0;
    let mut overflowed = false;
    while let Some(digit) = text.get(i).and_then(|&c| (c as char).to_digit(36)) {
        if digit >= radix as u32 {
            break;
        }
        value = value * i64::from(radix) + i64::from(digit);
        if value > i64::from(i32::MAX) + 1 {
            overflowed = true;
            value = i64::from(i32::MAX) + 1;
        }
        i += 1;
    }

    if i == digits_at {
        // No digits: nothing was converted, so nothing was consumed -- not
        // even the sign or the `0x` that was skipped over to get here.
        return (0, 0);
    }

    let value = if negative { -value } else { value };
    let clamped = if overflowed || value > i64::from(i32::MAX) {
        if negative { i32::MIN } else { i32::MAX }
    } else if value < i64::from(i32::MIN) {
        i32::MIN
    } else {
        value as i32
    };
    (clamped, i)
}

/// `int toupper(int c)`.
///
/// **Not a macro here.** Borland's macro is `_toupper`; `toupper` is a real
/// routine in the runtime, which is why `WCCMMUD.DLL` has 530 *call sites* for
/// ordinal 604 rather than 530 inlined subtractions.
///
/// Two things the prototype does not say, both read off `seg 1:0x54a9`. `-1` is
/// compared *before* the ctype table is indexed and returned unchanged, so EOF
/// survives as a full word. Everything else is `mov al,cl; mov ah,0` -- cut to
/// its low byte and zero-extended back -- so `toupper(0x161)` is `toupper('a')`
/// and answers `0x41`, not `0x141`.
pub fn toupper<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let c: u32 = call.int().into();
    Ok(abi::Ret::Int(A::int_from_u32(fold::<A>(
        c,
        crate::strings::toupper,
    ))))
}

/// `int tolower(int c)` -- [`toupper`]'s mirror, and the routine `sameas`,
/// `sameto` and `samein` fold with.
pub fn tolower<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let c: u32 = call.int().into();
    Ok(abi::Ret::Int(A::int_from_u32(fold::<A>(
        c,
        crate::strings::tolower,
    ))))
}

/// The `int` wrapper both case-folding routines share: EOF through untouched,
/// everything else truncated to a byte and zero-extended back.
///
/// # `EOF` is `-1` at `A`'s width, not at 16 bits
///
/// This used to take and return a `u16`, with `EOF` spelled `-1i16 as u16`.
/// Under `Wg16` that is exactly the `cmp cx,0xffff` the disassembly shows.
/// Under `Wg32` it broke the C idiom it exists to serve: a module calling
/// `toupper(EOF)` passes a full 32-bit `0xFFFFFFFF`, the old code narrowed
/// it to `0xFFFF`, recognised *that* as its own EOF, and answered
/// `A::Int::from(0xFFFFu16)` -- which zero-extends to `0x0000FFFF`. The
/// module's own `if (toupper(c) == EOF)` then compared `65535` against `-1`
/// and took the wrong branch, silently.
///
/// Both the comparison and the answer are now at `A::INT_WIDTH`, so `-1`
/// goes in and `-1` comes back out under either ABI.
fn fold<A: Abi>(c: u32, by: fn(u8) -> u8) -> u32 {
    // All ones at `A`'s own int width: `0xFFFF` for a 2-byte int (the
    // `cmp cx,0xffff` the 16-bit disassembly shows), `0xFFFFFFFF` for a
    // 4-byte one.
    let eof = u32::MAX >> (32 - A::INT_WIDTH * 8);

    if c == eof {
        eof
    } else {
        u32::from(by(c as u8))
    }
}

/// Put `text` and its terminator where a caller's `char *` points.
///
/// How big the buffer is, only the caller knows -- `sprintf` and `vsprintf` are
/// told an address and nothing else. The bounds check is therefore the
/// segment's, which is the only limit the host can see, and it is one check
/// because the terminator goes out in the same write as the text. That is not
/// only tidier: computing the terminator's own address means adding to a `u16`
/// offset, and a buffer near the end of its segment wraps that addition round
/// to the front.
///
/// [`write_cstr`] is the other half of this pair, for the buffers this host
/// owns and whose capacity it therefore knows enough to refuse.
///
/// # Errors
///
/// If the text and its terminator do not fit in the segment `at` names.
fn fill<A: Abi>(mem: &mut A::Mem, at: A::Ptr, text: &[u8]) -> Result<(), ShimError> {
    let mut bytes = text.to_vec();
    bytes.push(0);
    at.write(mem, &bytes).map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(())
}

/// A pointer `n` bytes into the string `ptr` names.
///
/// The one piece of arithmetic every routine here that answers a `char *`
/// does. An earlier version of this comment argued it away as never needing
/// a check: "`ptr.offset + n` never passes the terminator of a string that
/// has already been read... a segment is at most 64 KiB, and so the sum is
/// at most `0xffff`". That is true, but it is a **`Wg16` fact, not an `Abi`
/// one** -- it is [`crate::abi::Wg16`]'s own segment that tops out at 64 KiB,
/// not the notion of a module's address space in general.
/// [`crate::abi::Wg32`] is a flat 32-bit space with no such ceiling: a
/// `Wg32` string of 64 KiB or more is entirely legal, and every call site
/// here builds `n` from a length or a scan position measured against the
/// string actually read (`text.len()`, `rest.len()`, `position(...)`, and so
/// on) -- there is nothing about *that* arithmetic that stays under
/// `0xffff` just because it once did under `Wg16`. Capping `n` at `u16`
/// before it reached [`Abi::ptr_offset`], the way this function used to,
/// would silently wrap such a length round to a small one, and the wrapped
/// pointer would still *resolve* -- landing somewhere plausible and wrong
/// inside the module's own memory, with nothing to catch it.
///
/// So this is checked: [`Abi::ptr_checked_add`] refuses whatever this ABI's
/// own pointer cannot represent (`Wg16`'s `u16` offset overflowing; a future
/// ABI's own bound overflowing) instead of wrapping it, and this function
/// turns that refusal into a [`ShimError`] naming the byte count that would
/// not fit, rather than propagating a silent wraparound to the module.
///
/// The selector is the caller's own. Rebuilding it from anywhere else would
/// hand the module an address into the wrong segment.
///
/// # Errors
///
/// If `ptr` plus `n` bytes would leave the address space this ABI's own
/// pointer can name.
pub(crate) fn at<A: Abi>(ptr: A::Ptr, n: usize) -> Result<A::Ptr, ShimError> {
    A::ptr_checked_add(ptr, n).ok_or_else(|| {
        ShimError::Failed(format!(
            "{n} bytes past this pointer overflows the address space this ABI's own pointer can name"
        ))
    })
}

/// The null pointer, in this ABI's own representation.
///
/// Same reasoning as `shims::stream::null_ptr`, which this mirrors: `Abi` has
/// no `NULL` constant, but [`Abi::ptr_from_bytes`] over [`Abi::PTR_WIDTH`]
/// zero bytes is the null representation both ABIs already agree on.
fn null_ptr<A: Abi>() -> A::Ptr {
    A::ptr_from_bytes(&vec![0u8; A::PTR_WIDTH])
}

/// Whether `ptr` is the null pointer, in this ABI's own representation --
/// tested on its own bytes rather than `FarPtr`'s `selector`/`offset`
/// fields, since `A::Ptr` is opaque to a generic caller. Same reading
/// `shims::user::begin_polling`'s own null check takes.
fn is_null<A: Abi>(ptr: A::Ptr) -> bool {
    A::ptr_to_bytes(ptr).iter().all(|&b| b == 0)
}

/// Write `text` and its terminator at `at`, refusing to exceed `capacity`,
/// against memory directly rather than a whole `Machine`.
///
/// No `Wg16` facade under a `write_cstr` name: `shims::msg` (`stgopt`) and
/// `shims::system` were its last two `&mut Machine`-taking callers, and both
/// call this directly now that they are generic.
pub fn write_cstr_mem<A: Abi>(
    mem: &mut A::Mem,
    at: A::Ptr,
    text: &[u8],
    capacity: u16,
) -> Result<(), ShimError> {
    if text.len() + 1 > usize::from(capacity) {
        return Err(ShimError::Failed(format!(
            "{} bytes and a terminator will not fit in {capacity}",
            text.len()
        )));
    }
    let mut bytes = text.to_vec();
    bytes.push(0);
    at.write(mem, &bytes).map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::Wg16;
    use crate::testing::Fixture;
    use mbbs_machine::m16::FarPtr;

    /// `toupper(EOF)` must answer `EOF`, at whatever width `A`'s `int` is.
    ///
    /// This is the C idiom the routine exists to serve --
    /// `if (toupper(c) == EOF)` -- and the one the 16-bit-shaped `fold` broke
    /// under `Wg32`: it narrowed the incoming `0xFFFFFFFF` to `0xFFFF`,
    /// matched its own 16-bit sentinel, and answered `0x0000FFFF`, so the
    /// module compared `65535` against `-1` and took the wrong branch in
    /// silence.
    ///
    /// Tested on `fold` directly rather than through a `Call`: the frame
    /// decoding is [`crate::abi::Cursor`]'s and already width-tested, and
    /// building a `Wg32` `Call` here would need a real `m32::Machine`, which
    /// arms this thread's fault recovery and so cannot happen inside `--lib`.
    #[test]
    fn eof_survives_case_folding_at_both_int_widths() {
        use crate::abi::Wg32;

        // Every-bit-set at each width is that ABI's own `EOF`.
        assert_eq!(fold::<Wg16>(0xFFFF, crate::strings::toupper), 0xFFFF);
        assert_eq!(fold::<Wg32>(0xFFFF_FFFF, crate::strings::toupper), 0xFFFF_FFFF);
        assert_eq!(fold::<Wg16>(0xFFFF, crate::strings::tolower), 0xFFFF);
        assert_eq!(fold::<Wg32>(0xFFFF_FFFF, crate::strings::tolower), 0xFFFF_FFFF);

        // And `0xFFFF` under `Wg32` is *not* EOF -- it is 65535, an ordinary
        // out-of-byte-range value, folded to its low byte like any other.
        // This is the case the old code could not tell apart from EOF.
        assert_eq!(
            fold::<Wg32>(0x0000_FFFF, crate::strings::toupper),
            u32::from(crate::strings::toupper(0xFF)),
        );

        // Ordinary letters are unaffected by any of this.
        assert_eq!(fold::<Wg16>(u32::from(b'a'), crate::strings::toupper), u32::from(b'A'));
        assert_eq!(fold::<Wg32>(u32::from(b'a'), crate::strings::toupper), u32::from(b'A'));

        // `toupper(0x161)` is `toupper('a')` -- the low-byte truncation the
        // disassembly shows -- and stays so at both widths.
        assert_eq!(fold::<Wg16>(0x161, crate::strings::toupper), u32::from(b'A'));
        assert_eq!(fold::<Wg32>(0x161, crate::strings::toupper), u32::from(b'A'));
    }

    /// `at`'s own offset used to be `u16`, capped at exactly the width
    /// [`crate::abi::Wg16`]'s segment allows -- correct for `Wg16`, but a
    /// silent wraparound for [`crate::abi::Wg32`], whose flat address space
    /// has no 64 KiB ceiling to cap `n` at. `0x1_0000` (65536) is the
    /// smallest offset that demonstrates the difference: as a `u16` it
    /// wraps to `0`, so the old, unchecked `at` would have answered the
    /// *same pointer it started from* -- wrong, and not even a byte away
    /// from where it should be, let alone caught.
    ///
    /// Tested on `at` directly, over bare `A::Ptr` values, for the reason
    /// [`eof_survives_case_folding_at_both_int_widths`] gives for testing
    /// `fold` the same way: a real `Wg32` `Call`/`Machine` cannot be built
    /// inside this crate's `--lib` tests.
    #[test]
    fn at_refuses_an_offset_wg16_cannot_name_but_wg32_accepts_it() {
        use crate::abi::Wg32;

        let base16 = FarPtr {
            offset: 0,
            selector: 0x38,
        };
        assert!(
            at::<Wg16>(base16, 0x1_0000).is_err(),
            "a Wg16 segment is at most 64 KiB; there is no offset in it \
             65536 bytes from the start"
        );

        let base32 = mbbs_machine::m32::Flat32Ptr(0);
        let moved = at::<Wg32>(base32, 0x1_0000).expect("Wg32 has no 64 KiB ceiling to refuse this at");
        assert_eq!(
            moved,
            mbbs_machine::m32::Flat32Ptr(0x1_0000),
            "moved the full 65536 bytes, not wrapped back to the start"
        );

        // The boundary itself: exactly 64 KiB into a Wg16 segment is still
        // one byte past the last one it can name (offsets 0..=0xffff), so
        // this refuses too, one below where the case above starts.
        assert!(at::<Wg16>(base16, 0x1_0001).is_err());
        // But the very last in-range offset succeeds.
        assert_eq!(
            at::<Wg16>(base16, 0xffff).expect("the last offset in range"),
            FarPtr {
                offset: 0xffff,
                selector: 0x38
            }
        );
    }

    #[test]
    fn lastwd_answers_a_pointer_into_the_callers_own_string() {
        let mut f = Fixture::new();
        let s = f.text("SHORT MESSAGES LONG");
        let Ret::Far(p) = f.invoke(lastwd, &Fixture::far(s)).expect("ok") else {
            panic!("lastwd returns char *");
        };
        assert_eq!(p.selector, s.selector);
        assert_eq!(f.read(p), "LONG");
        assert_eq!(f.read(s), "SHORT MESSAGES LONG", "and changes nothing");
    }

    #[test]
    fn lastwd_leaves_the_trailing_padding_where_it_found_it() {
        let mut f = Fixture::new();
        let s = f.text("go north  ");
        let Ret::Far(p) = f.invoke(lastwd, &Fixture::far(s)).expect("ok") else {
            panic!("char *")
        };
        assert_eq!(f.read(p), "north  ", "skipped, not stripped");
    }

    #[test]
    fn sortstgs_rewrites_the_array_of_pointers_in_place() {
        let mut f = Fixture::new();
        let pear = f.text("pear");
        let apple = f.text("apple");
        let fig = f.text("fig");
        let array = f.words(&[
            pear.offset,
            pear.selector,
            apple.offset,
            apple.selector,
            fig.offset,
            fig.selector,
        ]);

        assert!(matches!(
            f.invoke(sortstgs, &[array.offset, array.selector, 3]),
            Ok(Ret::Void)
        ));
        let bytes = f.machine.resolve(array, 12).expect("readable").to_vec();
        let got: Vec<FarPtr> = bytes
            .chunks_exact(4)
            .map(|c| FarPtr::from_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        assert_eq!(
            got,
            vec![apple, fig, pear],
            "the pointers moved, not the text"
        );
    }

    #[test]
    fn sortstgs_of_fewer_than_two_reads_nothing_at_all() {
        // `gap = num/2` under a signed compare, so 1, 0 and any negative return
        // before the array is touched. That is why a null array is not an
        // error here -- the real one never dereferences it either.
        let mut f = Fixture::new();
        for num in [0u16, 1, (-4i16) as u16] {
            assert!(matches!(f.invoke(sortstgs, &[0, 0, num]), Ok(Ret::Void)));
        }
    }

    #[test]
    fn sortstgs_refuses_a_slot_that_names_nothing() {
        // The array itself is readable and one of the strings in it is not.
        // Sorting by a comparison the host cannot make is exactly the
        // plausible answer this crate refuses.
        let mut f = Fixture::new();
        let one = f.text("only");
        let array = f.words(&[one.offset, one.selector, 0, 0]);
        assert!(
            f.invoke(sortstgs, &[array.offset, array.selector, 2])
                .is_err()
        );
    }

    #[test]
    fn sortstgs_refuses_an_array_that_leaves_its_segment() {
        let mut f = Fixture::new();
        let one = f.text("only");
        let array = f.words(&[one.offset, one.selector]);
        // Two pointers named, one present, and the rest of the segment is not
        // the module's to claim.
        assert!(
            f.invoke(sortstgs, &[array.offset, array.selector, 900])
                .is_err()
        );
    }

    #[test]
    fn strtok_walks_a_line_and_then_says_there_is_no_more() {
        // The state is the host's -- `MAJORBBS.EXE` keeps one far pointer at
        // `DGROUP:0x18a8` and no module can see it -- so the later calls pass
        // NULL and the host has to remember where it got to.
        let mut f = Fixture::new();
        let line = f.text("go  north now");
        let delim = f.text(" ");
        let first = [line.offset, line.selector, delim.offset, delim.selector];
        let again = [0, 0, delim.offset, delim.selector];

        let Ret::Far(one) = f.invoke(strtok, &first).expect("ok") else {
            panic!("strtok returns char *");
        };
        assert_eq!(f.read(one), "go");

        let Ret::Far(two) = f.invoke(strtok, &again).expect("ok") else {
            panic!("char *")
        };
        assert_eq!(f.read(two), "north", "a run of two spaces is one gap");

        let Ret::Far(three) = f.invoke(strtok, &again).expect("ok") else {
            panic!("char *")
        };
        assert_eq!(f.read(three), "now");

        assert_eq!(
            f.invoke(strtok, &again).expect("ok"),
            Ret::Far(FarPtr::NULL)
        );
        assert_eq!(
            f.invoke(strtok, &again).expect("ok"),
            Ret::Far(FarPtr::NULL),
            "and it stays exhausted"
        );
    }

    #[test]
    fn strtok_writes_a_terminator_over_the_delimiter_it_consumed() {
        // It is destructive, and the module depends on that: the token it
        // answers is a pointer into the caller's own buffer, terminated in
        // place by `mov byte [es:bx],0x0`.
        let mut f = Fixture::new();
        let line = f.text("a,b");
        let delim = f.text(",");

        f.invoke(strtok,
            &[line.offset, line.selector, delim.offset, delim.selector],
        )
        .expect("ok");
        assert_eq!(
            f.machine.resolve(line, 4).expect("readable"),
            b"a\0b\0",
            "the comma became a terminator"
        );
    }

    #[test]
    fn strtok_of_nothing_but_delimiters_answers_null() {
        let mut f = Fixture::new();
        let line = f.text(",,,");
        let delim = f.text(",");
        assert_eq!(
            f.invoke(strtok,
                &[line.offset, line.selector, delim.offset, delim.selector]
            )
            .expect("ok"),
            Ret::Far(FarPtr::NULL)
        );
    }

    #[test]
    fn strtok_restarts_when_it_is_given_a_string() {
        let mut f = Fixture::new();
        let first = f.text("a b");
        let second = f.text("c d");
        let delim = f.text(" ");

        f.invoke(strtok,
            &[first.offset, first.selector, delim.offset, delim.selector],
        )
        .expect("ok");
        let Ret::Far(p) = f
            .invoke(strtok,
                &[second.offset, second.selector, delim.offset, delim.selector],
            )
            .expect("ok")
        else {
            panic!("char *")
        };
        assert_eq!(f.read(p), "c", "a non-null string replaces the cursor");
    }

    #[test]
    fn strtok_with_no_delimiters_answers_the_whole_string() {
        // The delimiter walk is `while (*p != 0)`, so an empty set exits at
        // once and nothing is ever a delimiter: one token, the whole line.
        let mut f = Fixture::new();
        let line = f.text("go north");
        let empty = f.text("");
        let Ret::Far(p) = f
            .invoke(strtok,
                &[line.offset, line.selector, empty.offset, empty.selector],
            )
            .expect("ok")
        else {
            panic!("char *")
        };
        assert_eq!(f.read(p), "go north");
        assert_eq!(
            f.invoke(strtok, &[0, 0, empty.offset, empty.selector])
                .expect("ok"),
            Ret::Far(FarPtr::NULL),
            "and then there is no more"
        );
    }

    #[test]
    fn strtok_with_no_previous_call_refuses_rather_than_inventing_a_token() {
        // The real one reads through whatever `DGROUP:0x18a8` happens to hold.
        // Here that starts null, and a pointer naming nothing is an error.
        let mut f = Fixture::new();
        let delim = f.text(" ");
        assert!(
            f.invoke(strtok, &[0, 0, delim.offset, delim.selector])
                .is_err()
        );
    }

    #[test]
    fn strchr_finds_a_byte_or_answers_null() {
        let mut f = Fixture::new();
        let s = f.text("go north");
        assert_eq!(
            f.invoke(strchr, &[s.offset, s.selector, u16::from(b'n')])
                .expect("ok"),
            Ret::Far(at::<Wg16>(s, 3).expect("within the segment"))
        );
        assert_eq!(
            f.invoke(strchr, &[s.offset, s.selector, u16::from(b'z')])
                .expect("ok"),
            Ret::Far(FarPtr::NULL),
            "absent is NULL, not the terminator"
        );
    }

    #[test]
    fn strchr_of_nul_answers_the_terminator_and_ignores_the_high_byte() {
        // `mov bl,[bp+0xa]` -- only the low byte of the `int` is compared --
        // and the scan tests each byte before it checks for the end, so
        // searching for `\0` finds it rather than failing.
        let mut f = Fixture::new();
        let s = f.text("abc");
        assert_eq!(
            f.invoke(strchr, &[s.offset, s.selector, 0]).expect("ok"),
            Ret::Far(at::<Wg16>(s, 3).expect("within the segment"))
        );
        assert_eq!(
            f.invoke(strchr, &[s.offset, s.selector, 0xff62])
                .expect("ok"),
            Ret::Far(at::<Wg16>(s, 1).expect("within the segment")),
            "0xff62 is searched for as 'b'"
        );
    }

    #[test]
    fn strstr_finds_a_run_and_an_empty_needle_finds_the_start() {
        let mut f = Fixture::new();
        let hay = f.text("go north now");
        let needle = f.text("north");
        let empty = f.text("");
        let missing = f.text("south");
        let pair = |a: FarPtr, b: FarPtr| [a.offset, a.selector, b.offset, b.selector];

        assert_eq!(
            f.invoke(strstr, &pair(hay, needle)).expect("ok"),
            Ret::Far(at::<Wg16>(hay, 3).expect("within the segment"))
        );
        assert_eq!(
            f.invoke(strstr, &pair(hay, empty)).expect("ok"),
            Ret::Far(hay),
            "the routine's first test is on the needle"
        );
        assert_eq!(
            f.invoke(strstr, &pair(hay, missing)).expect("ok"),
            Ret::Far(FarPtr::NULL)
        );
        assert_eq!(
            f.invoke(strstr, &pair(needle, hay)).expect("ok"),
            Ret::Far(FarPtr::NULL),
            "a needle longer than the haystack"
        );
    }

    #[test]
    fn strcat_appends_and_returns_the_destination() {
        let mut f = Fixture::new();
        let dst = f.buffer(32);
        f.machine.write(dst, b"go \0").expect("seeded");
        let src = f.text("north");

        let args = [dst.offset, dst.selector, src.offset, src.selector];
        assert_eq!(f.invoke(strcat, &args).expect("ok"), Ret::Far(dst));
        assert_eq!(f.read(dst), "go north");
    }

    #[test]
    fn strncpy_pads_to_n_and_does_not_terminate_a_full_buffer() {
        // The difference from `stzcpy`, which is Galacticomm's answer to this
        // routine: `stzcpy` always terminates and `strncpy` does not.
        let mut f = Fixture::new();
        let dst = f.bytes(&[b'#'; 8], false);
        let src = f.text("abcdefgh");
        let args = [dst.offset, dst.selector, src.offset, src.selector, 4];

        assert_eq!(f.invoke(strncpy, &args).expect("ok"), Ret::Far(dst));
        assert_eq!(
            f.machine.resolve(dst, 8).expect("readable"),
            b"abcd####",
            "four copied, no terminator, and the rest of the buffer untouched"
        );
    }

    #[test]
    fn strncpy_fills_the_whole_of_n_when_the_source_is_shorter() {
        let mut f = Fixture::new();
        let dst = f.bytes(&[b'#'; 8], false);
        let src = f.text("ab");
        let args = [dst.offset, dst.selector, src.offset, src.selector, 6];

        f.invoke(strncpy, &args).expect("ok");
        assert_eq!(
            f.machine.resolve(dst, 8).expect("readable"),
            b"ab\0\0\0\0##",
            "six bytes written, the last four of them NUL"
        );
    }

    #[test]
    fn strncpy_does_not_require_the_source_to_be_terminated() {
        // `repne scasb` with `cx = n` reads **at most n bytes**. A source with
        // no terminator in it is the case this routine exists for -- a
        // blank-padded fixed-width field -- and refusing one would stop a
        // module the real host served.
        let mut f = Fixture::new();
        let dst = f.bytes(&[b'#'; 8], false);
        let scratch = dst.selector;

        // Six non-zero bytes hard against the end of a 4,096-byte segment, so
        // there is no terminator between the source and the end of what it
        // names.
        let src = FarPtr {
            offset: 4090,
            selector: scratch,
        };
        f.machine.write(src, &[b'x'; 6]).expect("fits exactly");

        let args = [dst.offset, dst.selector, src.offset, src.selector, 4];
        assert_eq!(f.invoke(strncpy, &args).expect("ok"), Ret::Far(dst));
        assert_eq!(f.machine.resolve(dst, 8).expect("readable"), b"xxxx####");
    }

    #[test]
    fn strncpy_of_nothing_touches_neither_pointer() {
        // `rep` with `cx = 0` is a no-op three times over, so the original
        // dereferences nothing at all -- the same reason `stzcpy` returns
        // early on a `num` of zero.
        let mut f = Fixture::new();
        assert_eq!(
            f.invoke(strncpy, &[0, 0, 0, 0, 0]).expect("wrote nothing"),
            Ret::Far(FarPtr::NULL)
        );
    }

    #[test]
    fn strncpy_still_refuses_a_source_it_would_have_to_read_past() {
        // The other half of the same rule: the scan is bounded by `n`, so an
        // `n` that reaches past the end of the source's segment with no
        // terminator in the way is a read the original could not have made
        // either.
        let mut f = Fixture::new();
        let dst = f.buffer(64);
        let src = FarPtr {
            offset: 4090,
            selector: dst.selector,
        };
        f.machine.write(src, &[b'x'; 6]).expect("fits exactly");
        assert!(
            f.invoke(strncpy,
                &[dst.offset, dst.selector, src.offset, src.selector, 32]
            )
            .is_err()
        );
    }

    #[test]
    fn strncat_clamps_the_source_and_terminates_it_itself() {
        let mut f = Fixture::new();
        let dst = f.buffer(32);
        f.machine.write(dst, b"go \0").expect("seeded");
        let src = f.text("northwards");

        let args = [dst.offset, dst.selector, src.offset, src.selector, 5];
        assert_eq!(f.invoke(strncat, &args).expect("ok"), Ret::Far(dst));
        assert_eq!(f.read(dst), "go north", "five of the source, then a NUL");
    }

    #[test]
    fn strncat_clamps_unsigned_despite_its_int_prototype() {
        // The clamp is `cmp ax,[bp+0xe] / jna` -- an UNSIGNED compare, though
        // `GCOMM.H` calls the argument an `int`. Reading it signed would make
        // a large `maxlen` negative and clamp the copy to nothing.
        let mut f = Fixture::new();
        let dst = f.buffer(32);
        f.machine.write(dst, b"go \0").expect("seeded");
        let src = f.text("north");

        let args = [dst.offset, dst.selector, src.offset, src.selector, 0x8000];
        f.invoke(strncat, &args).expect("ok");
        assert_eq!(f.read(dst), "go north", "0x8000 is 32,768, not -32,768");
    }

    #[test]
    fn strncat_of_nothing_writes_only_a_terminator_already_there() {
        // `maxlen` of zero copies nothing, and the terminator the routine
        // writes itself goes at `dst[dstlen + n]` -- which with `n` of zero is
        // the terminator `dst` already had. So nothing past the string moves,
        // and in particular the byte *after* it is not cleared.
        let mut f = Fixture::new();
        let dst = f.bytes(b"go \0##", false);
        let src = f.text("north");

        let args = [dst.offset, dst.selector, src.offset, src.selector, 0];
        f.invoke(strncat, &args).expect("ok");
        assert_eq!(f.machine.resolve(dst, 6).expect("readable"), b"go \0##");
    }

    #[test]
    fn strchr_on_an_empty_string_finds_only_its_terminator() {
        let mut f = Fixture::new();
        let s = f.text("");
        assert_eq!(
            f.invoke(strchr, &[s.offset, s.selector, 0]).expect("ok"),
            Ret::Far(s),
            "the terminator is at offset zero"
        );
        assert_eq!(
            f.invoke(strchr, &[s.offset, s.selector, u16::from(b'a')])
                .expect("ok"),
            Ret::Far(FarPtr::NULL)
        );
    }

    #[test]
    fn the_writers_refuse_to_run_off_the_end_of_a_segment() {
        // How much room a destination has, only the caller knows -- so the
        // only bound the host can apply is the segment's, and it must be an
        // error rather than a truncated copy or a wrapped offset.
        let mut f = Fixture::new();
        let src = f.text("overlong");
        let scratch = src.selector;
        let near_end = FarPtr {
            offset: 4090,
            selector: scratch,
        };
        f.machine.write(near_end, b"go\0").expect("still inside");

        assert!(
            f.invoke(strncpy,
                &[
                    near_end.offset,
                    near_end.selector,
                    src.offset,
                    src.selector,
                    100
                ]
            )
            .is_err(),
            "100 bytes at 4090 leaves a 4096-byte segment"
        );
        assert!(
            f.invoke(strcat,
                &[near_end.offset, near_end.selector, src.offset, src.selector]
            )
            .is_err(),
            "and so does `go` plus `overlong`"
        );
        assert!(
            f.invoke(strncat,
                &[
                    near_end.offset,
                    near_end.selector,
                    src.offset,
                    src.selector,
                    100
                ]
            )
            .is_err(),
            "and so does appending a clamped copy of it"
        );
    }

    #[test]
    fn strcmp_returns_the_difference_and_zero_for_equal() {
        let mut f = Fixture::new();
        let short = f.text("kobold");
        let long = f.text("koboldy");
        let same = f.text("kobold");
        let pair = |a: FarPtr, b: FarPtr| [a.offset, a.selector, b.offset, b.selector];

        assert_eq!(
            f.invoke(strcmp, &pair(short, long)).expect("ok"),
            Ret::U16((-121i16) as u16),
            "the terminator against 'y'"
        );
        assert_eq!(
            f.invoke(strcmp, &pair(long, short)).expect("ok"),
            Ret::U16(121)
        );
        assert_eq!(
            f.invoke(strcmp, &pair(short, same)).expect("ok"),
            Ret::U16(0)
        );
    }

    #[test]
    fn the_same_family_answers_one_for_equal_not_strcmps_zero() {
        // `sameas` is 1 for equal; `strcmp` is 0 for equal. Returning the
        // wrong sense compiles, runs, and diverges 500 sites later.
        let mut f = Fixture::new();
        let long = f.text("LONG");
        let lower = f.text("long");
        let longer = f.text("longer");

        let pair = |a: FarPtr, b: FarPtr| [a.offset, a.selector, b.offset, b.selector];
        assert_eq!(
            f.invoke(sameas, &pair(long, lower)).expect("ok"),
            Ret::U16(1)
        );
        assert_eq!(
            f.invoke(sameas, &pair(long, longer)).expect("ok"),
            Ret::U16(0)
        );
    }

    #[test]
    fn sameto_takes_the_prefix_first_and_samein_takes_the_needle_first() {
        let mut f = Fixture::new();
        let long = f.text("long");
        let longer = f.text("longer");
        let ong = f.text("ONG");

        let pair = |a: FarPtr, b: FarPtr| [a.offset, a.selector, b.offset, b.selector];
        assert_eq!(
            f.invoke(sameto, &pair(long, longer)).expect("ok"),
            Ret::U16(1),
            "sameto(shorts, longs): `longer` begins with `long`"
        );
        assert_eq!(
            f.invoke(sameto, &pair(longer, long)).expect("ok"),
            Ret::U16(0),
            "and not the other way round"
        );
        assert_eq!(
            f.invoke(samein, &pair(ong, longer)).expect("ok"),
            Ret::U16(1),
            "samein(shorts, longs): `ONG` is inside `longer`"
        );
        assert_eq!(
            f.invoke(samein, &pair(longer, ong)).expect("ok"),
            Ret::U16(0)
        );
    }

    #[test]
    fn the_same_family_refuses_a_pointer_naming_nothing() {
        let mut f = Fixture::new();
        let s = f.text("x");
        for shim in [
            sameas as crate::shims::Shim<Wg16>,
            sameto,
            samein,
        ] {
            assert!(f.invoke(shim, &[s.offset, s.selector, 0, 0]).is_err());
            assert!(f.invoke(shim, &[0, 0, s.offset, s.selector]).is_err());
        }
    }

    #[test]
    fn toupper_folds_a_letter_and_leaves_everything_else() {
        let mut f = Fixture::new();
        for (input, want) in [
            (u16::from(b'a'), u16::from(b'A')),
            (u16::from(b'A'), u16::from(b'A')),
            (u16::from(b'7'), u16::from(b'7')),
            (0, 0),
        ] {
            assert_eq!(f.invoke(toupper, &[input]).expect("folded"), Ret::U16(want));
        }
        assert_eq!(
            f.invoke(tolower, &[u16::from(b'Z')]).expect("folded"),
            Ret::U16(u16::from(b'z'))
        );
    }

    #[test]
    fn toupper_passes_eof_through_and_truncates_everything_else() {
        // `cmp cx,0xffff` happens before the table is indexed, so EOF is the
        // one argument that survives as a full word. Every other `int` is cut
        // to its low byte: `toupper(0x161)` is `toupper('a')`.
        let mut f = Fixture::new();
        assert_eq!(f.invoke(toupper, &[0xffff]).expect("EOF"), Ret::U16(0xffff));
        assert_eq!(f.invoke(tolower, &[0xffff]).expect("EOF"), Ret::U16(0xffff));
        assert_eq!(f.invoke(toupper, &[0x161]).expect("cut"), Ret::U16(0x41));
        assert_eq!(f.invoke(tolower, &[0xff41]).expect("cut"), Ret::U16(0x61));
    }

    #[test]
    fn case_folding_agrees_with_the_ctype_table_the_host_placed() {
        // Two sources of case-folding is a bug waiting to happen. The module
        // indexes `_ctype` itself -- it imports it as the `__CTYPE` datum --
        // and the real `toupper` reads that same table. This sweeps all 256
        // bytes and asserts the transcription and the placed bytes agree, so
        // that a change to either is caught here rather than 500 sites later.
        let f = Fixture::new();
        let at = f
            .host
            .globals()
            .address("_ctype")
            .expect("_ctype is placed");
        let table = f.machine.resolve(at, 257).expect("257 bytes").to_vec();
        for c in 0..=255u8 {
            let bits = table[usize::from(c) + 1];
            assert_eq!(
                bits & 0x08 != 0,
                crate::strings::toupper(c) != c,
                "_IS_LOW disagrees about {c:#04x}"
            );
            assert_eq!(
                bits & 0x04 != 0,
                crate::strings::tolower(c) != c,
                "_IS_UPP disagrees about {c:#04x}"
            );
        }
    }

    #[test]
    fn stzcpy_truncates_and_always_terminates() {
        let mut f = Fixture::new();
        let dst = f.buffer(16);
        let src = f.text("Newhaven");

        // Five bytes of room means four characters and the NUL. `strncpy`
        // would put five characters and no NUL, which is the difference.
        let args = [dst.offset, dst.selector, src.offset, src.selector, 5];
        assert_eq!(f.invoke(stzcpy, &args).expect("copied"), Ret::Far(dst));
        assert_eq!(f.read(dst), "Newh");
    }

    #[test]
    fn stzcpy_returns_the_destination() {
        // `GALFILUT.C:73` passes the result straight to `checkdir`, so it is
        // the string that was written and not its terminator.
        let mut f = Fixture::new();
        let dst = f.buffer(16);
        let src = f.text("hi");
        let args = [dst.offset, dst.selector, src.offset, src.selector, 16];
        assert_eq!(f.invoke(stzcpy, &args).expect("copied"), Ret::Far(dst));
        assert_eq!(f.read(dst), "hi");
    }

    /// `strlwr` folds ASCII `A`-`Z` and nothing else, in place, returning its
    /// argument.
    ///
    /// The two high-bit bytes are the point: `0xC4` and `0xE0` are CP437 box
    /// drawing and a Greek alpha, and MajorMUD's text is full of them. A fold
    /// that treated them as letters would corrupt every room description that
    /// draws a line.
    #[test]
    fn strlwr_folds_ascii_only_and_returns_its_argument() {
        let mut f = Fixture::new();
        let at = f.bytes(b"AbC\xC4\xE0Z", true);
        assert_eq!(f.invoke(strlwr, &Fixture::far(at)).expect("strlwr"), Ret::Far(at));
        assert_eq!(
            f.machine.read_cstr(at).expect("readable"),
            b"abc\xC4\xE0z",
            "0xC4 and 0xE0 are CP437 text, not letters to fold"
        );
    }

    /// `strncmp` compares at most `n` bytes and stops at a terminator.
    ///
    /// The `n`-past-the-end case is what separates a real port from one that
    /// reads on into whatever follows the NUL.
    #[test]
    fn strncmp_stops_at_n_and_at_the_terminator() {
        let mut f = Fixture::new();
        let a = f.text("kobold");
        let b = f.text("kobolt");
        let pair =
            |x: FarPtr, y: FarPtr, n: u16| [x.offset, x.selector, y.offset, y.selector, n];

        assert_eq!(
            f.invoke(strncmp, &pair(a, b, 5)).expect("ok"),
            Ret::U16(0),
            "the first five bytes are equal"
        );
        assert_ne!(
            f.invoke(strncmp, &pair(a, b, 6)).expect("ok"),
            Ret::U16(0),
            "the sixth differs"
        );

        // `n` far past both terminators must still answer equal for equal
        // strings, which it can only do by stopping at the NUL.
        let c = f.text("kobold");
        assert_eq!(
            f.invoke(strncmp, &pair(a, c, 500)).expect("ok"),
            Ret::U16(0),
            "the comparison stops at the NUL, it does not read 500 bytes"
        );

        // A prefix is less than the string that extends it.
        let short = f.text("kob");
        let cmp = f.invoke(strncmp, &pair(short, a, 500)).expect("ok");
        assert_ne!(cmp, Ret::U16(0), "a prefix is not equal to the whole");
    }

    /// `n == 0` compares nothing at all and answers equal, whatever the
    /// strings are.
    #[test]
    fn strncmp_of_zero_bytes_is_always_equal() {
        let mut f = Fixture::new();
        let a = f.text("alpha");
        let b = f.text("omega");
        assert_eq!(
            f.invoke(strncmp, &[a.offset, a.selector, b.offset, b.selector, 0])
                .expect("ok"),
            Ret::U16(0)
        );
    }

    /// `strnicmp` is `strncmp` with the same ASCII-only fold, so case stops
    /// mattering and high-bit bytes still do.
    #[test]
    fn strnicmp_ignores_case_but_not_high_bit_bytes() {
        let mut f = Fixture::new();
        let upper = f.text("KOBOLD");
        let lower = f.text("kobold");
        let pair =
            |x: FarPtr, y: FarPtr, n: u16| [x.offset, x.selector, y.offset, y.selector, n];

        assert_eq!(f.invoke(strnicmp, &pair(upper, lower, 6)).expect("ok"), Ret::U16(0));
        assert_ne!(
            f.invoke(strncmp, &pair(upper, lower, 6)).expect("ok"),
            Ret::U16(0),
            "and strncmp still tells them apart -- otherwise this proves nothing"
        );

        // 0xC4 folds to itself, so it stays different from an ASCII letter.
        let a = f.bytes(b"\xC4", true);
        let b = f.bytes(b"\xE4", true);
        assert_ne!(f.invoke(strnicmp, &pair(a, b, 1)).expect("ok"), Ret::U16(0));
    }

    /// `strtol` writes the first unconsumed character through `endptr`, and
    /// base 0 infers the radix from the prefix.
    #[test]
    fn strtol_reports_where_it_stopped_and_infers_base_zero() {
        let mut f = Fixture::new();
        let src = f.text("0x1Frest");
        let end = f.buffer(4);
        let args = [src.offset, src.selector, end.offset, end.selector, 0];
        assert_eq!(f.invoke(strtol, &args).expect("strtol"), Ret::U32(0x1F));

        let stopped = FarPtr::from_bytes(
            f.machine.resolve(end, 4).expect("in bounds").try_into().expect("4 bytes"),
        );
        assert_eq!(
            f.machine.read_cstr(stopped).expect("readable"),
            b"rest",
            "endptr names the first character strtol did not consume"
        );
    }

    /// Base 0's three cases, and the sign.
    #[test]
    fn strtol_base_zero_reads_hex_octal_and_decimal() {
        let mut f = Fixture::new();
        let mut ask = |f: &mut Fixture, s: &str, base: u16| -> u32 {
            let at = f.text(s);
            let Ret::U32(n) = f
                .invoke(strtol, &[at.offset, at.selector, 0, 0, base])
                .expect("strtol")
            else {
                panic!("strtol returns a long");
            };
            n
        };
        assert_eq!(ask(&mut f, "0x2A", 0), 42, "0x is hexadecimal");
        assert_eq!(ask(&mut f, "052", 0), 42, "a leading zero is octal");
        assert_eq!(ask(&mut f, "42", 0), 42, "and anything else is decimal");
        assert_eq!(ask(&mut f, "  -42", 0), (-42i32) as u32, "whitespace then a sign");
        assert_eq!(ask(&mut f, "2A", 16), 42, "an explicit base needs no prefix");
        assert_eq!(ask(&mut f, "0x2A", 16), 42, "and tolerates one");
        assert_eq!(ask(&mut f, "z", 36), 35, "base 36 reaches z");
        // Base 10 stops at a digit the radix does not have.
        assert_eq!(ask(&mut f, "12x34", 10), 12);
    }

    /// Nothing converted means `endptr` gets `nptr` back unchanged, which is
    /// the caller's only signal that the text was not a number.
    #[test]
    fn strtol_that_converts_nothing_answers_zero_and_does_not_move_endptr() {
        let mut f = Fixture::new();
        let src = f.text("  not a number");
        let end = f.buffer(4);
        let args = [src.offset, src.selector, end.offset, end.selector, 10];
        assert_eq!(f.invoke(strtol, &args).expect("strtol"), Ret::U32(0));

        let stopped = FarPtr::from_bytes(
            f.machine.resolve(end, 4).expect("in bounds").try_into().expect("4 bytes"),
        );
        assert_eq!(stopped, src, "endptr is nptr itself, whitespace and all");

        // A sign with no digits after it converts nothing either.
        let lone = f.text("-");
        let args = [lone.offset, lone.selector, end.offset, end.selector, 10];
        assert_eq!(f.invoke(strtol, &args).expect("strtol"), Ret::U32(0));
        let stopped = FarPtr::from_bytes(
            f.machine.resolve(end, 4).expect("in bounds").try_into().expect("4 bytes"),
        );
        assert_eq!(stopped, lone, "the sign is not consumed if no digit follows");
    }

    /// A null `endptr` is legal: the conversion still happens and nothing is
    /// written.
    #[test]
    fn strtol_accepts_a_null_endptr() {
        let mut f = Fixture::new();
        let src = f.text("7");
        assert_eq!(
            f.invoke(strtol, &[src.offset, src.selector, 0, 0, 10]).expect("strtol"),
            Ret::U32(7)
        );
    }

    /// `stlcpy` copies at most `num-1` bytes and always terminates
    /// (`STLCPY.C:27-31`). The truncation case is the one that proves the
    /// bound was ported rather than assumed.
    #[test]
    fn stlcpy_truncates_at_num_minus_one_and_always_terminates() {
        let mut f = Fixture::new();
        let dst = f.buffer(16);
        let src = f.text("abcdefghij");

        // num = 5: four characters and a NUL.
        let args = [dst.offset, dst.selector, src.offset, src.selector, 5];
        assert_eq!(f.invoke(stlcpy, &args).expect("stlcpy"), Ret::Far(dst));
        assert_eq!(f.machine.read_cstr(dst).expect("readable"), b"abcd");

        // A source shorter than num copies whole, and still terminates.
        let short = f.text("ab");
        let args = [dst.offset, dst.selector, short.offset, short.selector, 5];
        assert!(matches!(f.invoke(stlcpy, &args), Ok(Ret::Far(_))));
        assert_eq!(f.machine.read_cstr(dst).expect("readable"), b"ab");
    }

    /// `stlcpy` writes the copy and **one** terminator, and stops.
    ///
    /// This is the whole difference from [`stzcpy`], whose second loop clears
    /// the destination out to `num` (`STZCPY.C:30-32`). `STLCPY.C:31` is a
    /// bare `*cp='\0'` with no fill loop after it, so the bytes past the
    /// terminator are whatever the caller left there. A port that shared one
    /// body between the two routines would be wrong in one direction or the
    /// other, and only this assertion says which.
    #[test]
    fn stlcpy_does_not_zero_fill_the_way_stzcpy_does() {
        let mut f = Fixture::new();
        let dst = f.bytes(b"AAAAAAAA", false);
        let src = f.text("ab");

        let args = [dst.offset, dst.selector, src.offset, src.selector, 8];
        assert_eq!(f.invoke(stlcpy, &args).expect("stlcpy"), Ret::Far(dst));
        assert_eq!(
            f.machine.resolve(dst, 8).expect("in bounds"),
            b"ab\0AAAAA",
            "stlcpy terminates and stops; only stzcpy clears the tail"
        );
    }

    /// `stzcat` appends within a total budget of `num` bytes *including* what
    /// is already there (`STZCPY.C:44-45`:
    /// `stzcpy(&dst[dstlen], src, num-dstlen)`).
    #[test]
    fn stzcat_appends_within_the_whole_buffers_budget() {
        let mut f = Fixture::new();
        let dst = f.buffer(32);
        f.machine.write(dst, b"abc\0").expect("seed");
        let src = f.text("defghij");

        // num = 6: "abc" is 3, so 2 more characters and a NUL.
        let args = [dst.offset, dst.selector, src.offset, src.selector, 6];
        assert_eq!(f.invoke(stzcat, &args).expect("stzcat"), Ret::Far(dst));
        assert_eq!(f.machine.read_cstr(dst).expect("readable"), b"abcde");
    }

    /// `stzcat` inherits `stzcpy`'s fill, because the vendor defines it as a
    /// `stzcpy` onto the end of what is already there. The budget it fills to
    /// is `num-dstlen`, measured from the append point -- so the whole `num`
    /// bytes of the destination end up written between the two.
    #[test]
    fn stzcat_zero_fills_the_tail_it_appends_into() {
        let mut f = Fixture::new();
        let dst = f.bytes(b"abcXXXXX", false);
        f.machine.write(dst, b"abc\0").expect("seed a terminator at 3");
        let src = f.text("d");

        let args = [dst.offset, dst.selector, src.offset, src.selector, 8];
        assert_eq!(f.invoke(stzcat, &args).expect("stzcat"), Ret::Far(dst));
        assert_eq!(
            f.machine.resolve(dst, 8).expect("in bounds"),
            b"abcd\0\0\0\0",
            "the append clears everything from the new terminator to num"
        );
    }

    /// `stzcat` refuses when the destination is already at or past `num`.
    ///
    /// `num-dstlen` is `UINT` arithmetic in the vendor (`STZCPY.C:45`), so it
    /// wraps: `stzcat(dst, src, 4)` on a destination already holding 10
    /// characters passes `stzcpy` a `num` of 65530, and the fill loop then
    /// runs 65530 bytes past a buffer the caller said was 4 bytes long.
    ///
    /// That is not behaviour to reproduce, and it is not a case to clamp
    /// silently either -- a clamp would turn a caller's arithmetic bug into a
    /// quiet no-op. The refusal names the underflow.
    #[test]
    fn stzcat_refuses_when_the_destination_already_exceeds_num() {
        let mut f = Fixture::new();
        let dst = f.buffer(32);
        f.machine.write(dst, b"0123456789\0").expect("seed");
        let src = f.text("more");

        let args = [dst.offset, dst.selector, src.offset, src.selector, 4];
        let err = f.invoke(stzcat, &args).expect_err("10 characters do not fit in 4");
        let message = err.to_string();
        assert!(message.contains("stzcat"), "{message}");
        assert!(message.contains("underflow"), "{message}");
    }

    /// `ul2as` is unsigned: a value above `LONG_MAX` prints as itself, not as
    /// a negative. That is the whole difference from `l2as`, and the only
    /// test that distinguishes the two.
    #[test]
    fn ul2as_prints_the_unsigned_value() {
        let mut f = Fixture::new();
        // 0xFFFFFFFF -- -1 as a signed long, 4294967295 as an unsigned one.
        let Ret::Far(at) = f.invoke(ul2as, &[0xffff, 0xffff]).expect("ul2as") else {
            panic!("ul2as returns char *");
        };
        assert_eq!(f.machine.read_cstr(at).expect("readable"), b"4294967295");
    }

    /// `ul2as` and `l2as` share one rotation, because in the vendor they share
    /// one `cycle` and one `tkastg[4][16]` (`L2AS.C:27-28`) -- they are two
    /// functions in one file over one pair of statics.
    ///
    /// So four calls in any mix of the two answer four different buffers and
    /// the fifth reuses the first. A host that gave `ul2as` a rotation of its
    /// own would let a module hold eight live results where the real host
    /// gives it four, and the overwrite it was written to survive would stop
    /// happening -- the failure would appear only in the module that relied
    /// on it, long after.
    #[test]
    fn ul2as_shares_l2ass_rotation_rather_than_minting_a_second() {
        let mut f = Fixture::new();
        let mut seen = Vec::new();
        for n in 0..2u16 {
            let Ret::Far(at) = f.invoke(ul2as, &[n, 0]).expect("ul2as") else {
                panic!("char *");
            };
            seen.push(at);
        }
        for n in 0..2i32 {
            let Ret::Far(at) = f.invoke(l2as, &long(n)).expect("l2as") else {
                panic!("char *");
            };
            seen.push(at);
        }
        // The fifth call -- whichever routine makes it -- wraps onto the first.
        let Ret::Far(fifth) = f.invoke(ul2as, &[9, 0]).expect("ul2as") else {
            panic!("char *");
        };

        let mut offsets: Vec<u16> = seen.iter().map(|p| p.offset).collect();
        offsets.sort_unstable();
        offsets.dedup();
        assert_eq!(offsets.len(), 4, "four distinct slots across the two: {seen:?}");
        assert_eq!(fifth, seen[0], "the fifth call reuses the first slot");
    }

    /// `stzcpy` clears the destination's tail -- the `z` in its name.
    ///
    /// `STZCPY.C:27-32` is two loops, not one: the copy stops at `num-1` or
    /// the source's terminator, and then a second loop runs the index out to
    /// `num` writing zeroes. Exactly `num` bytes are written on every call.
    ///
    /// Measured against a genuine `MAJORBBS.EXE`, not inferred: see
    /// `tests/oracle_gate.rs`'s `stzcpy_zero_fills_the_whole_destination`,
    /// which prefills the destination with `0xAA` and watches the real host
    /// clear all eight bytes. This host shipped without the fill, and none of
    /// the three tests above could see it -- every one of them reads back
    /// through a NUL-trimming helper, which stops at the terminator and so
    /// cannot distinguish a cleared tail from an untouched one.
    ///
    /// It is observable: a module that `stzcpy`s a short name into a
    /// fixed-width record field and writes that record to a file gets the
    /// previous occupant's bytes in the tail instead of zeroes.
    #[test]
    fn stzcpy_zero_fills_the_rest_of_the_destination() {
        let mut f = Fixture::new();
        let dst = f.bytes(b"AAAAAAAA", false);
        let src = f.text("ab");

        let args = [dst.offset, dst.selector, src.offset, src.selector, 8];
        assert_eq!(f.invoke(stzcpy, &args).expect("copied"), Ret::Far(dst));
        assert_eq!(
            f.machine.resolve(dst, 8).expect("in bounds"),
            b"ab\0\0\0\0\0\0",
            "the tail is cleared, not left holding what was there"
        );
    }

    #[test]
    fn stzcpy_with_no_room_writes_nothing() {
        let mut f = Fixture::new();
        let dst = f.bytes(b"keep", true);
        let src = f.text("overwrite me");
        let args = [dst.offset, dst.selector, src.offset, src.selector, 0];
        f.invoke(stzcpy, &args).expect("copied nothing");
        assert_eq!(f.read(dst), "keep", "not even a terminator fits in zero");
    }

    #[test]
    fn strcpy_and_strlen() {
        let mut f = Fixture::new();
        let dst = f.buffer(16);
        let src = f.text("kobold");
        let args = [dst.offset, dst.selector, src.offset, src.selector];
        assert_eq!(f.invoke(strcpy, &args).expect("copied"), Ret::Far(dst));
        assert_eq!(f.read(dst), "kobold");

        let mut f = Fixture::new();
        let at = f.text("kobold");
        assert_eq!(
            f.invoke(strlen, &Fixture::far(at)).expect("ok"),
            Ret::U16(6)
        );
    }

    #[test]
    fn atol_reads_a_long_out_of_a_string() {
        let cases = [
            ("100000", 100_000i32),
            ("  -42abc", -42),
            ("+7", 7),
            ("", 0),
            ("not a number", 0),
        ];
        for (text, expect) in cases {
            let mut f = Fixture::new();
            let at = f.text(text);
            assert_eq!(
                f.invoke(atol, &Fixture::far(at)).expect("parsed"),
                Ret::U32(expect as u32),
                "{text:?}"
            );
        }
    }

    #[test]
    fn spr_rotates_far_enough_to_keep_four_results_alive() {
        // `prf("%s and %s", spr(...), spr(...))` needs both, so the rotation
        // is observable. Four calls must land in four different places, and
        // the fifth must come back to the first.
        let mut f = Fixture::new();
        let template = f.text("%d");
        let mut seen = Vec::new();
        for n in 0..=SPR_BUFFERS {
            let args = [template.offset, template.selector, n as u16];
            let Ret::Far(at) = f.invoke(spr, &args).expect("formatted") else {
                panic!("spr returns a pointer");
            };
            seen.push(at);
        }

        let mut offsets: Vec<u16> = seen[..SPR_BUFFERS].iter().map(|p| p.offset).collect();
        offsets.sort_unstable();
        offsets.dedup();
        assert_eq!(offsets.len(), SPR_BUFFERS, "{seen:?}");
        assert_eq!(seen[SPR_BUFFERS], seen[0], "the fifth reuses the first");

        // And the fourth is still readable after the fifth overwrote the first.
        assert_eq!(f.read(seen[3]), "3");
    }

    /// Argument words for a `long`, laid out the way [`Machine::arg_u32`]
    /// reads them back: low word first, then high.
    fn long(v: i32) -> [u16; 2] {
        let v = v as u32;
        [v as u16, (v >> 16) as u16]
    }

    #[test]
    fn l2as_renders_zero_as_a_bare_zero() {
        let mut f = Fixture::new();
        let Ret::Far(at) = f.invoke(l2as, &long(0)).expect("formatted") else {
            panic!("l2as returns a pointer");
        };
        assert_eq!(f.machine.read_cstr(at).expect("terminated"), b"0");
    }

    #[test]
    fn l2as_prefixes_negative_values_with_a_minus() {
        let mut f = Fixture::new();
        let Ret::Far(at) = f.invoke(l2as, &long(-42)).expect("formatted") else {
            panic!("l2as returns a pointer");
        };
        assert_eq!(f.machine.read_cstr(at).expect("terminated"), b"-42");
    }

    #[test]
    fn l2as_reads_the_full_32_bits_not_just_the_low_word() {
        // >= 65536 is the one magnitude an `arg_u16` mistake gets wrong while
        // still passing on anything smaller.
        let mut f = Fixture::new();
        let Ret::Far(at) = f.invoke(l2as, &long(100_000)).expect("formatted") else {
            panic!("l2as returns a pointer");
        };
        assert_eq!(f.machine.read_cstr(at).expect("terminated"), b"100000");
    }

    #[test]
    fn l2as_renders_i32_min_without_negation_overflow() {
        // `i32::MIN`'s magnitude has no positive `i32` counterpart -- `-value`
        // overflows. `unsigned_abs` is the one way to get here without it.
        let mut f = Fixture::new();
        let Ret::Far(at) = f.invoke(l2as, &long(i32::MIN)).expect("formatted") else {
            panic!("l2as returns a pointer");
        };
        assert_eq!(f.machine.read_cstr(at).expect("terminated"), b"-2147483648");
    }

    #[test]
    fn l2as_renders_i32_max() {
        let mut f = Fixture::new();
        let Ret::Far(at) = f.invoke(l2as, &long(i32::MAX)).expect("formatted") else {
            panic!("l2as returns a pointer");
        };
        assert_eq!(f.machine.read_cstr(at).expect("terminated"), b"2147483647");
    }

    #[test]
    fn l2as_rotates_through_its_own_pool_and_wraps_after_l2as_buffers() {
        let mut f = Fixture::new();
        let mut seen = Vec::new();
        for n in 0..=L2AS_BUFFERS {
            let Ret::Far(at) = f.invoke(l2as, &long(n as i32)).expect("formatted") else {
                panic!("l2as returns a pointer");
            };
            seen.push(at);
        }

        let mut offsets: Vec<u16> = seen[..L2AS_BUFFERS].iter().map(|p| p.offset).collect();
        offsets.sort_unstable();
        offsets.dedup();
        assert_eq!(offsets.len(), L2AS_BUFFERS, "{seen:?}");
        assert_eq!(seen[L2AS_BUFFERS], seen[0], "the wrap reuses the first");

        // The third result is still readable after the wrap overwrote the
        // first.
        assert_eq!(f.machine.read_cstr(seen[2]).expect("terminated"), b"2");
    }

    #[test]
    fn l2as_rotates_independently_of_sprs_pool() {
        // If `l2as` shared `spr`'s rotation, the three `spr` calls between
        // these two `l2as` calls would move `l2as`'s next buffer by three
        // slots instead of one -- exactly the coupling `Host::l2as`'s doc
        // comment says a separate pool exists to avoid.
        let mut f = Fixture::new();
        let template = f.text("%d");

        let Ret::Far(first) = f.invoke(l2as, &long(1)).expect("formatted") else {
            panic!("l2as returns a pointer");
        };

        for n in 0..3u16 {
            let args = [template.offset, template.selector, n];
            f.invoke(spr, &args).expect("formatted");
        }

        let Ret::Far(second) = f.invoke(l2as, &long(2)).expect("formatted") else {
            panic!("l2as returns a pointer");
        };

        assert_eq!(
            second.offset - first.offset,
            L2AS_BYTES,
            "three intervening spr calls moved l2as's rotation by more than one slot"
        );
        assert_eq!(f.machine.read_cstr(first).expect("terminated"), b"1");
        assert_eq!(f.machine.read_cstr(second).expect("terminated"), b"2");
    }

    #[test]
    fn sprintf_writes_into_the_callers_buffer_and_returns_the_length() {
        let mut f = Fixture::new();
        let dst = f.buffer(32);
        let template = f.text("%s/%d");
        let text = f.text("gold");
        let args = [
            dst.offset,
            dst.selector,
            template.offset,
            template.selector,
            text.offset,
            text.selector,
            9,
        ];
        assert_eq!(f.invoke(sprintf, &args).expect("ok"), Ret::U16(6));
        assert_eq!(f.read(dst), "gold/9");
    }

    #[test]
    fn prf_appends_and_clrprf_starts_over() {
        let mut f = Fixture::new();
        let template = f.text("<%d>");

        f.invoke(prf, &[template.offset, template.selector, 1])
            .expect("first");
        f.invoke(prf, &[template.offset, template.selector, 2])
            .expect("second");

        let buffer = f.host.globals().prf_buffer();
        assert_eq!(f.read(buffer), "<1><2>", "the second call appends");

        f.invoke(clrprf, &[]).expect("cleared");
        assert_eq!(f.read(buffer), "");
        assert_eq!(
            f.host
                .globals()
                .pointer(&f.machine, "prfptr")
                .expect("prfptr"),
            buffer,
            "clrprf puts prfptr back at the start"
        );
    }

    #[test]
    fn prf_reads_prfptr_back_rather_than_remembering_it() {
        // The module moves `prfptr` itself -- it writes into the buffer and
        // advances the pointer without telling anyone. A host that remembered
        // where it last wrote would append over that, and the damage would
        // show up as scrambled output much later.
        let mut f = Fixture::new();
        let template = f.text("%d");
        f.invoke(prf, &[template.offset, template.selector, 1])
            .expect("first");

        let buffer = f.host.globals().prf_buffer();
        let moved = FarPtr {
            offset: buffer.offset + 8,
            selector: buffer.selector,
        };
        f.host
            .globals()
            .write(&mut f.machine, "prfptr", &moved.to_bytes())
            .expect("moved");

        f.invoke(prf, &[template.offset, template.selector, 2])
            .expect("second");
        assert_eq!(f.read(moved), "2", "prf wrote where prfptr now points");
        assert_eq!(f.read(buffer), "1", "and left the earlier text alone");
    }

    #[test]
    fn prf_refuses_to_run_past_the_end_of_the_buffer() {
        let mut f = Fixture::new();
        let template = f.text("%s");
        let long = f.bytes(&vec![b'x'; 2000], true);

        // Twice over is more than the 4 KiB buffer holds. The real one would
        // simply write past it.
        f.invoke(prf,
            &[
                template.offset,
                template.selector,
                long.offset,
                long.selector,
            ],
        )
        .expect("the first fits");
        let second = f.invoke(prf,
            &[
                template.offset,
                template.selector,
                long.offset,
                long.selector,
            ],
        );
        assert!(second.is_ok(), "two of these still fit");

        let third = f.invoke(prf,
            &[
                template.offset,
                template.selector,
                long.offset,
                long.selector,
            ],
        );
        assert!(third.is_err(), "the third would overrun");
    }

    /// `\x1b[[\x1b[1;37m|X]TAIL` -- ANSI form `\x1b[1;37m`, ASCII form `X`,
    /// then ordinary text that must survive on either branch. Not one of the
    /// 269 real constructs Task 1's review measured inside `WCCMMUD.DLL` --
    /// just small enough to read at a glance and exercise both forms.
    const IFANSI_FIXTURE: &[u8] = b"\x1b[[\x1b[1;37m|X]TAIL";

    #[test]
    fn prf_strips_ifansi_to_the_ansi_form_on_an_ansi_channel() {
        let mut f = Fixture::new();
        let chan = f.console();
        f.host
            .connect_state(&mut f.machine, chan, &crate::users::Connection::ansi("player"))
            .expect("connected");

        let template = f.bytes(IFANSI_FIXTURE, true);
        f.invoke(prf, &Fixture::far(template)).expect("prf");

        let buffer = f.host.globals().prf_buffer();
        assert_eq!(f.read(buffer), "\x1b[1;37mTAIL");
    }

    #[test]
    fn prf_strips_ifansi_to_the_ascii_form_on_a_line_mode_channel() {
        let mut f = Fixture::new();
        let chan = f.console();
        f.host
            .connect_state(
                &mut f.machine,
                chan,
                &crate::users::Connection::line_mode("player"),
            )
            .expect("connected");

        let template = f.bytes(IFANSI_FIXTURE, true);
        f.invoke(prf, &Fixture::far(template)).expect("prf");

        let buffer = f.host.globals().prf_buffer();
        assert_eq!(f.read(buffer), "XTAIL");
    }

    #[test]
    fn prfmsg_converges_on_the_same_ifansi_stripping_as_prf() {
        // `prf` and `prfmsg` share `append` -- the whole point of Task 2 --
        // so a message-file template must be stripped exactly as a module
        // string is.
        let dir = crate::testing::scratch("text-ifansi-prfmsg");
        let mut contents = b"LEVEL0 {IFANSI}\r\n\r\nIFMSG {".to_vec();
        contents.extend_from_slice(IFANSI_FIXTURE);
        contents.extend_from_slice(b"} T\r\n");
        std::fs::write(dir.join("IFANSI.MSG"), &contents).expect("fixture written");

        let mut f = Fixture::rooted(dir);
        let chan = f.console();
        f.host
            .connect_state(&mut f.machine, chan, &crate::users::Connection::ansi("player"))
            .expect("connected");

        let name = f.text("IFANSI.MSG");
        f.invoke(crate::shims::msg::opnmsg, &Fixture::far(name))
            .expect("opened");
        // `IFMSG` is message 1: `LEVEL0` itself is message 0, exactly as
        // `SAMPLE.MSG`'s `FMT` is message 8 -- see
        // `prfmsg_appends_to_the_print_buffer_the_way_prf_does` in
        // `shims/msg.rs`.
        f.invoke(crate::shims::msg::prfmsg, &[1]).expect("prfmsg");

        let buffer = f.host.globals().prf_buffer();
        assert_eq!(f.read(buffer), "\x1b[1;37mTAIL");
    }

    #[test]
    fn prf_with_no_channel_current_defaults_to_the_ansi_form() {
        // `Fixture::new` leaves `usrnum` at -1 (`MAJORBBS.C:882`) until
        // something points it somewhere -- exactly the state every *other*
        // `prf` test in this file already runs in, since none of them call
        // `point_curusr` or `connect_state`. Defaulting to the ANSI form is
        // what keeps every one of those tests green: none of their templates
        // contain an IF-ANSI construct, so the default has never shown
        // before now.
        let mut f = Fixture::new();
        let template = f.bytes(IFANSI_FIXTURE, true);
        f.invoke(prf, &Fixture::far(template)).expect("prf");

        let buffer = f.host.globals().prf_buffer();
        assert_eq!(f.read(buffer), "\x1b[1;37mTAIL");
    }

    #[test]
    fn channel_ansi_follows_whichever_channel_is_current_not_always_the_first_one() {
        // Every test above has exactly one channel, so a flag-reader that
        // hardcoded channel zero -- or cached whichever channel it saw first
        // -- would pass every one of them. Two channels, one ANSI and one
        // line-mode, with the *second* one current when `prf` runs, is what
        // tells "reads the current channel" apart from "reads a channel".
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(2));
        let a = f.host.users().terms().chan(0).expect("channel 0");
        let b = f.host.users().terms().chan(1).expect("channel 1");

        f.host
            .connect_state(&mut f.machine, a, &crate::users::Connection::ansi("ann"))
            .expect("a connected");
        f.host
            .connect_state(
                &mut f.machine,
                b,
                &crate::users::Connection::line_mode("bob"),
            )
            .expect("b connected"); // leaves b current

        let template = f.bytes(IFANSI_FIXTURE, true);
        f.invoke(prf, &Fixture::far(template)).expect("prf for b");
        let buffer = f.host.globals().prf_buffer();
        assert_eq!(f.read(buffer), "XTAIL", "b is line-mode, so the ASCII form");

        f.host
            .point_curusr(&mut f.machine, a)
            .expect("a is current now");
        f.invoke(clrprf, &[]).expect("cleared");
        f.invoke(prf, &Fixture::far(template)).expect("prf for a");
        assert_eq!(
            f.read(buffer),
            "\x1b[1;37mTAIL",
            "a is ansi, so the ANSI form"
        );
    }

    // -- Task 2: newline normalisation --------------------------------------
    //
    // `append` -- MBBSEmu's `FormatOutput` -- runs `crate::ifansi::process`
    // then `normalize_newlines`, and it is `normalize_newlines` these tests
    // are about: bare `\r`/`\n` becoming `\r\n`, without doubling a line
    // ending the module already wrote out in full. Every one of these calls
    // `append` directly rather than going through `prf`'s `%`-format parser
    // -- the function under test is `append`, and going around `format`
    // means a `%` inside a fixture (none here happen to have one) could never
    // make a newline test fail for a format-string reason instead of a
    // newline reason.

    #[test]
    fn append_turns_a_bare_lf_into_crlf() {
        let mut f = Fixture::new();
        append(&mut f.machine, &mut f.host, b"A\nB").expect("appended");
        let buffer = f.host.globals().prf_buffer();
        assert_eq!(f.machine.read_cstr(buffer).expect("terminated"), b"A\r\nB");
    }

    #[test]
    fn append_turns_a_bare_cr_into_crlf() {
        // The `.MCV` hard-paragraph-break case (`msg.rs:238-245`): a bare
        // `\r` with no `\n` of its own.
        let mut f = Fixture::new();
        append(&mut f.machine, &mut f.host, b"A\rB").expect("appended");
        let buffer = f.host.globals().prf_buffer();
        assert_eq!(f.machine.read_cstr(buffer).expect("terminated"), b"A\r\nB");
    }

    #[test]
    fn append_does_not_double_a_crlf_the_module_already_wrote() {
        // 38 of the ten recovered `.MCV` files' line endings are already
        // `\r\n` (a blank line inside a value, `msg.rs:245`) -- these must
        // reach the wire as one line break, not two.
        let mut f = Fixture::new();
        append(&mut f.machine, &mut f.host, b"A\r\nB").expect("appended");
        let buffer = f.host.globals().prf_buffer();
        assert_eq!(
            f.machine.read_cstr(buffer).expect("terminated"),
            b"A\r\nB",
            "not A\\r\\n\\r\\nB"
        );
    }

    #[test]
    fn append_does_not_collapse_two_bare_lfs_into_one_break() {
        // The shape a naive "runs of \r/\n become one \r\n" implementation
        // would get wrong: two consecutive bare `\n` (a blank line, in the
        // `.MCV` soft-wrap encoding) is two line breaks, not one. Dedup only
        // ever consumes a *complementary* neighbour -- `\r` next to `\n` or
        // `\n` next to `\r` -- never a second `\n` after a `\n`.
        let mut f = Fixture::new();
        append(&mut f.machine, &mut f.host, b"A\n\nB").expect("appended");
        let buffer = f.host.globals().prf_buffer();
        assert_eq!(
            f.machine.read_cstr(buffer).expect("terminated"),
            b"A\r\n\r\nB",
            "a blank line stays a blank line"
        );
    }

    #[test]
    fn append_normalizes_after_ifansi_not_before() {
        // `\x1b[[A\n|B]\rC` on an ANSI channel: `ifansi::process` selects the
        // ANSI form `A\n` and concatenates it with the trailing `\rC`,
        // producing the intermediate string `A\n\rC` -- a bare LF directly
        // touching a bare CR *only because ifansi already discarded
        // everything between them* (the `|B]` the ASCII form and the closer
        // took with it). Normalizing that intermediate string dedups the
        // `\n\r` at the join into one `\r\n`: `A\r\nC`.
        //
        // Run the two stages in the wrong order and the answer changes.
        // Normalizing the *raw* input first sees `\n` followed by `|` (no
        // complementary byte -- the `|B]` is still there) and emits a `\r\n`
        // with nothing to dedup, then later sees the `\r` before `C` with
        // nothing after it to dedup either -- two independent `\r\n`s, both
        // still present after `ifansi::process` runs on that already-normalized
        // text and merely relocates them: `A\r\n\r\nC`. Same fixture, one
        // extra blank line, and the only variable is which stage ran first.
        let mut f = Fixture::new();
        append(&mut f.machine, &mut f.host, b"\x1b[[A\n|B]\rC").expect("appended");
        let buffer = f.host.globals().prf_buffer();
        assert_eq!(
            f.machine.read_cstr(buffer).expect("terminated"),
            b"A\r\nC",
            "ifansi must run first, or this doubles"
        );
    }

    #[test]
    fn append_composes_with_gsbl_transmit_into_exactly_one_crlf() {
        // `append` has already turned the module's bare `\n` into `\r\n` by
        // the time this reaches the GSBL. `Channel::transmit`'s own line
        // handling (`gsbl.rs`'s `emit_one`) turns a bare `\r` into `\r\n` and
        // swallows the `\n` immediately after it as the other half of that
        // *same* pair -- so the two rules have to compose into exactly one
        // `\r\n` on the wire, not two.
        let mut f = Fixture::new();
        let console = f.console();
        append(&mut f.machine, &mut f.host, b"before\nafter").expect("appended");

        let buffer = f.host.globals().prf_buffer();
        let normalized = f.machine.read_cstr(buffer).expect("terminated").to_vec();
        assert_eq!(normalized, b"before\r\nafter", "append's own half of the job");

        f.host.gsbl_mut().transmit(console, &normalized);
        assert_eq!(
            f.host.gsbl_mut().drain_output(console),
            b"before\r\nafter".to_vec(),
            "exactly one CRLF reached the wire, not two"
        );
    }

    #[test]
    fn rmvwht_rewrites_the_callers_buffer_in_place() {
        // It returns void, so the only observable effect is the buffer.
        let mut f = Fixture::new();
        let at = f.text("  the quick brown fox  ");
        assert!(matches!(f.invoke(rmvwht, &Fixture::far(at)), Ok(Ret::Void)));
        assert_eq!(f.machine.read_cstr(at).expect("a string"), b"thequickbrownfox");
    }

    #[test]
    fn rmvwht_handles_a_string_that_is_entirely_whitespace() {
        let mut f = Fixture::new();
        let at = f.text(" \t\r\n ");
        f.invoke(rmvwht, &Fixture::far(at)).expect("void");
        assert_eq!(f.machine.read_cstr(at).expect("a string"), b"");
    }

    #[test]
    fn skpwht_answers_a_pointer_into_the_string_it_was_given() {
        // The return is a far pointer, and its selector must be the caller's --
        // a shim that rebuilt it from somewhere else would hand back an address
        // into the wrong segment and the module would read rubbish.
        let mut f = Fixture::new();
        let at = f.text("   abc");
        let Ret::Far(p) = f.invoke(skpwht, &Fixture::far(at)).expect("a pointer") else {
            panic!("skpwht returns char *");
        };
        assert_eq!(p.selector, at.selector);
        assert_eq!(p.offset, at.offset + 3);
        assert_eq!(f.machine.read_cstr(p).expect("a string"), b"abc");
    }

    #[test]
    fn skpwht_stops_at_a_tab_because_the_original_tests_one_byte() {
        let mut f = Fixture::new();
        let at = f.text("\tabc");
        let Ret::Far(p) = f.invoke(skpwht, &Fixture::far(at)).expect("a pointer") else {
            panic!("skpwht returns char *");
        };
        assert_eq!(p.offset, at.offset, "a tab is not 0x20");
    }

    #[test]
    fn skpwrd_answers_the_space_that_ended_the_word() {
        let mut f = Fixture::new();
        let at = f.text("word rest");
        let Ret::Far(p) = f.invoke(skpwrd, &Fixture::far(at)).expect("a pointer") else {
            panic!("skpwrd returns char *");
        };
        assert_eq!(p.offset, at.offset + 4);
        assert_eq!(f.machine.read_cstr(p).expect("a string"), b" rest");
    }

    #[test]
    fn depad_truncates_the_buffer_and_returns_the_count() {
        let mut f = Fixture::new();
        let at = f.text("text   ");
        let Ret::U16(n) = f.invoke(depad, &Fixture::far(at)).expect("a count") else {
            panic!("depad returns an int");
        };
        assert_eq!(n, 3, "three characters went");
        assert_eq!(f.machine.read_cstr(at).expect("a string"), b"text");
    }

    #[test]
    fn depad_leaves_a_string_that_needs_nothing_alone() {
        let mut f = Fixture::new();
        let at = f.text("  text");
        let Ret::U16(n) = f.invoke(depad, &Fixture::far(at)).expect("a count") else {
            panic!("depad returns an int");
        };
        assert_eq!(n, 0, "leading padding is not padding");
        assert_eq!(f.machine.read_cstr(at).expect("a string"), b"  text");
    }

    /// `stansi` promises that ANSI handling matches the `usracc` setting.
    ///
    /// The body is empty, so testing the body would test nothing. This tests
    /// the **promise**: flip `ansifl`'s `ANSON` bit both ways, call `stansi`,
    /// and check which half of an `ESC[[ansi|ascii]` construct actually comes
    /// out. That is what the vendor's `btucmd(usrnum,"[")`/`"]"` exists to
    /// arrange, and here it is already arranged because `channel_ansi_mem`
    /// reads the account record live.
    ///
    /// If this host ever grows a GSBL-side ANSI flag that `stansi` has to
    /// copy into, this test fails the day it stops being kept in step.
    #[test]
    fn stansi_leaves_output_following_the_account_setting() {
        let mut f = Fixture::new();
        let chan = f.console();
        f.host
            .connect_state(&mut f.machine, chan, &crate::Connection::ansi("rangerdan"))
            .expect("connects");

        let ansifl = Wg16::ptr_offset(
            f.host.users().account(chan),
            f.host.users().account_layout().ansifl,
        );

        let emit = |f: &mut Fixture| -> Vec<u8> {
            assert!(matches!(f.invoke(clrprf, &[]), Ok(Ret::Void)));
            let at = f.text("\x1b[[colour|plain]");
            assert!(matches!(f.invoke(prf, &Fixture::far(at)), Ok(Ret::Void)));
            let prfbuf = f.host.globals().prf_buffer();
            f.machine.read_cstr(prfbuf).expect("readable").to_vec()
        };

        // ANSON set: the ANSI form survives.
        f.machine.write(ansifl, &[1]).expect("ansifl");
        assert!(matches!(f.invoke(stansi, &[]), Ok(Ret::Void)));
        assert_eq!(emit(&mut f), b"colour".to_vec(), "ANSON set, so the ANSI form");

        // ANSON clear: the ASCII form does.
        f.machine.write(ansifl, &[0]).expect("ansifl");
        assert!(matches!(f.invoke(stansi, &[]), Ok(Ret::Void)));
        assert_eq!(emit(&mut f), b"plain".to_vec(), "ANSON clear, so the ASCII form");
    }

    /// `clrinp` empties the input buffer and re-points `margv[0]` at it.
    ///
    /// The `margv[0]=input` half is the one a plausible implementation drops,
    /// so it is asserted directly: `bgncnc` opens with `nxtcmd=margv[0]`, and
    /// a stale `margv[0]` would send the concatenation cursor into the
    /// previous line's text.
    #[test]
    fn clrinp_empties_the_buffer_and_repoints_margv_zero() {
        let mut f = Fixture::new();
        f.host.globals().write(&mut f.machine, "input", b"look here now").expect("input");
        assert!(matches!(f.invoke(parsin, &[]), Ok(Ret::Void)));
        assert_eq!(f.host.globals().word(&f.machine, "margc").expect("margc"), 3);

        // Point margv[0] somewhere else entirely, the way a previous command
        // would have left it.
        let elsewhere = f.text("stale");
        let margv = f.host.globals().address("margv").expect("margv");
        f.machine.write(margv, &FarPtr::to_bytes(elsewhere)).expect("margv seeded");

        assert!(matches!(f.invoke(clrinp, &[]), Ok(Ret::Void)));

        let input = f.host.globals().address("input").expect("input");
        assert_eq!(f.machine.read_cstr(input).expect("readable"), b"", "input[0] is NUL");
        assert_eq!(f.host.globals().word(&f.machine, "inplen").expect("inplen"), 0);
        assert_eq!(f.host.globals().word(&f.machine, "margc").expect("margc"), 0);

        let margv0 = FarPtr::from_bytes(
            f.machine.resolve(margv, 4).expect("in bounds").try_into().expect("4 bytes"),
        );
        assert_eq!(margv0, input, "margv[0] points back at input, not at the stale word");
    }

    /// `xltctls` turns `^A` into `0x01` and `^^` into a literal `^`, in place
    /// (`MAJORBBS.C:1564`).
    ///
    /// The three cases a rewrite gets wrong are each asserted: the fold is
    /// `c & ~0x40` rather than "uppercase then subtract", a trailing `^`
    /// survives, and `^^^^` becomes `^^` rather than collapsing further.
    #[test]
    fn xltctls_folds_caret_sequences_into_control_characters() {
        let mut f = Fixture::new();
        let mut run = |f: &mut Fixture, s: &str| -> Vec<u8> {
            let at = f.text(s);
            assert!(matches!(f.invoke(xltctls, &Fixture::far(at)), Ok(Ret::Void)));
            f.machine.read_cstr(at).expect("readable").to_vec()
        };

        assert_eq!(run(&mut f, "^A"), vec![0x01]);
        assert_eq!(run(&mut f, "a^Mb"), vec![b'a', 0x0d, b'b']);
        assert_eq!(run(&mut f, "^^"), b"^".to_vec(), "a doubled caret is a literal one");
        assert_eq!(run(&mut f, "^^^^"), b"^^".to_vec(), "cp++ steps over the survivor");
        assert_eq!(run(&mut f, "no carets"), b"no carets".to_vec());

        // `c & ~0x40` on a lowercase letter is NOT a control character: 'a' is
        // 0x61, and 0x61 & ~0x40 is 0x21. The vendor does not upper-case first.
        assert_eq!(run(&mut f, "^a"), b"!".to_vec(), "0x61 & ~0x40 == 0x21 == '!'");

        // `case '\0'` breaks out of the switch without touching anything.
        assert_eq!(run(&mut f, "end^"), b"end^".to_vec(), "a trailing caret survives");
    }

    /// A `UIDSIZ`-wide zeroed buffer holding `s`, which is what `zonkhl` and
    /// `makhdl` require of their caller -- see `zonkhl`'s doc comment.
    fn uid_buffer(f: &mut Fixture, s: &str) -> FarPtr {
        assert!(s.len() < usize::from(UIDSIZ), "the test's own string must fit");
        let at = f.buffer(UIDSIZ);
        f.machine.write(at, s.as_bytes()).expect("fits");
        at
    }

    /// `stripb` is `depad` plus an `inplen` fix-up (`SIGNUP.C:826`). Trailing
    /// blanks go; leading ones are not padding and stay.
    #[test]
    fn stripb_trims_only_trailing_blanks() {
        let mut f = Fixture::new();
        let at = f.text("  Ranger Dan   ");
        assert!(matches!(f.invoke(stripb, &Fixture::far(at)), Ok(Ret::Void)));
        assert_eq!(f.machine.read_cstr(at).expect("a string"), b"  Ranger Dan");
    }

    /// The `stg == input` test is a **pointer** comparison (`SIGNUP.C:830`),
    /// so `inplen` moves only when the caller passed the global itself. A
    /// copy of the same text leaves it alone.
    ///
    /// This is the assertion that fails if the port compares contents: both
    /// halves use the same text, and only the address differs.
    #[test]
    fn stripb_updates_inplen_only_for_input_itself() {
        let mut f = Fixture::new();
        f.host.globals().write(&mut f.machine, "input", b"look  ").expect("input");
        f.host.globals().write(&mut f.machine, "inplen", &99u16.to_le_bytes()).expect("inplen");

        // A different buffer holding the identical text: inplen must not move.
        let copy = f.text("look  ");
        assert!(matches!(f.invoke(stripb, &Fixture::far(copy)), Ok(Ret::Void)));
        assert_eq!(f.machine.read_cstr(copy).expect("a string"), b"look");
        assert_eq!(
            f.host.globals().word(&f.machine, "inplen").expect("inplen"),
            99,
            "a copy of input's text is not input"
        );

        // `input` itself: inplen becomes its new length.
        let input = f.host.globals().address("input").expect("input");
        assert!(matches!(f.invoke(stripb, &Fixture::far(input)), Ok(Ret::Void)));
        assert_eq!(f.machine.read_cstr(input).expect("a string"), b"look");
        assert_eq!(f.host.globals().word(&f.machine, "inplen").expect("inplen"), 4);
    }

    /// `isuplo` answers 1 for a string whose letters are all one case and 0
    /// for a mixed one (`SIGNUP.C:871`). The mixed case is the whole point --
    /// a routine that always answered 1 would pass a test of the other two.
    #[test]
    fn isuplo_accepts_uniform_case_and_rejects_mixed() {
        let mut f = Fixture::new();
        for (text, want) in [
            ("rangerdan", 1u16),
            ("RANGERDAN", 1),
            ("RangerDan", 0),
            ("ranger dan", 1),
            ("12345", 1),        // no letters at all
            ("", 1),             // and neither has the empty string
            ("aB", 0),
        ] {
            let at = f.text(text);
            assert_eq!(
                f.invoke(isuplo, &Fixture::far(at)).expect("isuplo"),
                Ret::U16(want),
                "isuplo({text:?})"
            );
        }
    }

    /// `zonkhl` title-cases a uniformly-cased name and leaves a mixed-case one
    /// exactly as typed (`SIGNUP.C:844`). Both halves are needed: a port that
    /// always title-cased would pass the first assertion and fail the second.
    #[test]
    fn zonkhl_title_cases_uniform_names_and_leaves_mixed_ones() {
        let mut f = Fixture::new();

        let at = uid_buffer(&mut f, "ranger dan");
        assert!(matches!(f.invoke(zonkhl, &Fixture::far(at)), Ok(Ret::Void)));
        assert_eq!(f.machine.read_cstr(at).expect("a string"), b"Ranger Dan");

        let at = uid_buffer(&mut f, "RANGER DAN");
        assert!(matches!(f.invoke(zonkhl, &Fixture::far(at)), Ok(Ret::Void)));
        assert_eq!(f.machine.read_cstr(at).expect("a string"), b"Ranger Dan");

        // Mixed case: the user chose it, so it stands.
        let at = uid_buffer(&mut f, "McDonald");
        assert!(matches!(f.invoke(zonkhl, &Fixture::far(at)), Ok(Ret::Void)));
        assert_eq!(f.machine.read_cstr(at).expect("a string"), b"McDonald");

        // A run of blanks leaves `space` set, so the next letter still rises.
        let at = uid_buffer(&mut f, "van  der berg");
        assert!(matches!(f.invoke(zonkhl, &Fixture::far(at)), Ok(Ret::Void)));
        assert_eq!(f.machine.read_cstr(at).expect("a string"), b"Van  Der Berg");
    }

    /// `zonkhl`'s trailing `while` runs past the terminator and zeroes out to
    /// `UIDSIZ` (`SIGNUP.C:865-867`), because the name is on its way into a
    /// fixed-width Btrieve key field. A port that stopped at the NUL would
    /// leave the tail holding whatever was there before, and the record
    /// written from it would differ from the original's byte for byte.
    #[test]
    fn zonkhl_zero_fills_the_whole_uidsiz_field() {
        let mut f = Fixture::new();
        let at = f.buffer(UIDSIZ);
        // Dirty the whole field first, so zeroing it is observable.
        f.machine.write(at, &[b'#'; 30]).expect("fits");
        f.machine.write(at, b"dan\0").expect("fits");

        assert!(matches!(f.invoke(zonkhl, &Fixture::far(at)), Ok(Ret::Void)));

        let field = f.machine.resolve(at, usize::from(UIDSIZ)).expect("in bounds").to_vec();
        assert_eq!(&field[..3], b"Dan");
        assert!(
            field[3..].iter().all(|&b| b == 0),
            "the tail past the terminator is zeroed too: {field:?}"
        );
    }

    /// A buffer shorter than `UIDSIZ` is refused rather than silently
    /// overrunning. The original corrupted whatever followed; this is the one
    /// place the port is deliberately louder than its source.
    #[test]
    fn zonkhl_refuses_a_buffer_shorter_than_uidsiz() {
        let mut f = Fixture::new();
        // Four bytes from the end of the scratch segment: room for the string
        // and nothing like room for thirty.
        let at = FarPtr { offset: u16::MAX - 4, selector: f.text("x").selector };
        assert!(
            f.invoke(zonkhl, &Fixture::far(at)).is_err(),
            "writing UIDSIZ bytes off the end of the segment must be an error"
        );
    }

    /// `makhdl` is `stripb` then `zonkhl`, in that order (`SIGNUP.C:836`).
    /// The trailing blanks must be gone *before* the title-casing runs, so
    /// the padded field ends in zeros rather than in a blank.
    #[test]
    fn makhdl_strips_then_zonks() {
        let mut f = Fixture::new();
        let at = uid_buffer(&mut f, "ranger dan   ");
        assert!(matches!(f.invoke(makhdl, &Fixture::far(at)), Ok(Ret::Void)));

        let field = f.machine.resolve(at, usize::from(UIDSIZ)).expect("in bounds").to_vec();
        assert_eq!(&field[..10], b"Ranger Dan");
        assert!(
            field[10..].iter().all(|&b| b == 0),
            "stripb ran first, so no blank survives into the padded tail: {field:?}"
        );
    }

    /// `issupc` is `isuidc` narrowed by the board's two switches
    /// (`SIGNUP.C:1147`): `fulalw` gates the punctuation and the space,
    /// `digalw` gates the digits. Both are flipped here, because a predicate
    /// tested at one setting passes when it ignores the switch entirely.
    #[test]
    fn issupc_gates_punctuation_on_fulalw_and_digits_on_digalw() {
        let mut f = Fixture::new();
        let mut ask = |f: &mut Fixture, c: u8| {
            let Ret::U16(n) = f.invoke(issupc, &[u16::from(c)]).expect("issupc") else {
                panic!("issupc returns an int");
            };
            n
        };

        // Both switches are 1 by default.
        for c in [b'A', b'z', b'.', b' ', b',', b'-', b'\'', b'5', b'_'] {
            assert_eq!(ask(&mut f, c), 1, "{:?} with both switches set", c as char);
        }
        assert_eq!(ask(&mut f, b'!'), 0, "'!' is not a user-ID character at all");

        f.host.globals().write(&mut f.machine, "fulalw", &0u16.to_le_bytes()).expect("fulalw");
        for c in [b'.', b' ', b',', b'-', b'\''] {
            assert_eq!(ask(&mut f, c), 0, "{:?} is gated by fulalw", c as char);
        }
        assert_eq!(
            ask(&mut f, b'_'),
            1,
            "'_' reaches the default arm, so fulalw does not gate it -- \
             the vendor's own asymmetry"
        );
        assert_eq!(ask(&mut f, b'A'), 1, "letters are never gated");

        f.host.globals().write(&mut f.machine, "digalw", &0u16.to_le_bytes()).expect("digalw");
        assert_eq!(ask(&mut f, b'5'), 0, "digits are gated by digalw");
        assert_eq!(ask(&mut f, b'A'), 1, "and letters still are not");
    }

    #[test]
    fn rstrin_puts_back_the_separators_that_parsing_replaced() {
        // `margn` holds pointers to where each word ended -- the bytes that
        // were spaces before the parser wrote NULs over them. `rstrin` restores
        // margc-1 of them, which is one per gap between margc words.
        let mut f = Fixture::new();
        let line = f.text("look\0at\0this");
        let margn = f.host.globals().address("margn").expect("margn");

        // Two separators, at offsets 4 and 7.
        let ends = [line.offset + 4, line.offset + 7];
        for (i, off) in ends.iter().enumerate() {
            let slot = mbbs_machine::m16::FarPtr {
                offset: margn.offset + (i as u16) * 4,
                selector: margn.selector,
            };
            let bytes = [
                off.to_le_bytes()[0],
                off.to_le_bytes()[1],
                line.selector.to_le_bytes()[0],
                line.selector.to_le_bytes()[1],
            ];
            f.machine.write(slot, &bytes).expect("margn slot");
        }
        f.host
            .globals()
            .write(&mut f.machine, "margc", &3u16.to_le_bytes())
            .expect("margc");

        assert!(matches!(f.invoke(rstrin, &[]), Ok(Ret::Void)));
        assert_eq!(f.machine.read_cstr(line).expect("a string"), b"look at this");
    }

    #[test]
    fn rstrin_with_nothing_parsed_writes_nothing() {
        // The original's bound is `margc - 1` under a SIGNED compare, so a
        // margc of zero writes nothing. Unsigned, it would loop 65,535 times
        // and scribble over whatever margn happened to contain.
        let mut f = Fixture::new();
        f.host
            .globals()
            .write(&mut f.machine, "margc", &0u16.to_le_bytes())
            .expect("margc");
        assert!(matches!(f.invoke(rstrin, &[]), Ok(Ret::Void)));
    }

    /// A far pointer, read out of module memory at `at`.
    fn read_ptr(machine: &mbbs_machine::m16::Machine, at: FarPtr) -> FarPtr {
        let bytes = machine.resolve(at, 4).expect("readable");
        FarPtr::from_bytes(bytes.try_into().expect("4 bytes"))
    }

    /// The `n`th slot of `margv` or `margn`, each an array of far pointers.
    fn slot(base: FarPtr, n: u16) -> FarPtr {
        FarPtr {
            offset: base.offset + n * 4,
            selector: base.selector,
        }
    }

    #[test]
    fn parsin_splits_the_input_buffer_into_margv() {
        let mut f = Fixture::new();
        f.host
            .globals()
            .write(&mut f.machine, "input", b"get all gold")
            .expect("input");
        assert!(matches!(f.invoke(parsin, &[]), Ok(Ret::Void)));

        assert_eq!(f.host.globals().word(&f.machine, "margc").expect("margc"), 3);
        let margv = f.host.globals().address("margv").expect("margv");
        assert_eq!(f.read(read_ptr(&f.machine, slot(margv, 0))), "get");
        assert_eq!(f.read(read_ptr(&f.machine, slot(margv, 1))), "all");
        assert_eq!(f.read(read_ptr(&f.machine, slot(margv, 2))), "gold");
    }

    #[test]
    fn parsin_collapses_runs_of_separators() {
        // "get   all" is two arguments, not four -- the three spaces between
        // them are one gap, not three empty ones.
        let mut f = Fixture::new();
        f.host
            .globals()
            .write(&mut f.machine, "input", b"get   all")
            .expect("input");
        assert!(matches!(f.invoke(parsin, &[]), Ok(Ret::Void)));

        assert_eq!(f.host.globals().word(&f.machine, "margc").expect("margc"), 2);
        let margv = f.host.globals().address("margv").expect("margv");
        assert_eq!(f.read(read_ptr(&f.machine, slot(margv, 0))), "get");
        assert_eq!(f.read(read_ptr(&f.machine, slot(margv, 1))), "all");
    }

    #[test]
    fn parsin_on_an_empty_line_points_margv_zero_at_an_empty_string() {
        // The module reads `margv[0]` unguarded, so it must be a readable
        // pointer -- never null, and never a stack temporary that stops being
        // valid after this call returns.
        let mut f = Fixture::new();
        f.host
            .globals()
            .write(&mut f.machine, "input", b"")
            .expect("input");
        assert!(matches!(f.invoke(parsin, &[]), Ok(Ret::Void)));

        assert_eq!(f.host.globals().word(&f.machine, "margc").expect("margc"), 0);
        let margv = f.host.globals().address("margv").expect("margv");
        let at = read_ptr(&f.machine, slot(margv, 0));
        assert_ne!(at, FarPtr::NULL, "margv[0] must not be null");
        assert_eq!(f.machine.read_cstr(at).expect("readable"), b"");
    }

    #[test]
    fn parsin_records_where_each_word_ended_so_rstrin_can_undo_it() {
        // margn[i] is the NUL that replaced word i's separator -- offset 3 for
        // the space after "get", offset 7 for the one after "all".
        let mut f = Fixture::new();
        let input = f.host.globals().address("input").expect("input");
        f.host
            .globals()
            .write(&mut f.machine, "input", b"get all gold")
            .expect("input");
        assert!(matches!(f.invoke(parsin, &[]), Ok(Ret::Void)));

        let margn = f.host.globals().address("margn").expect("margn");
        let end0 = read_ptr(&f.machine, slot(margn, 0));
        let end1 = read_ptr(&f.machine, slot(margn, 1));
        assert_eq!(end0.offset - input.offset, 3);
        assert_eq!(end1.offset - input.offset, 7);

        // margn[margc-1] -- the slot the early-return path inside the inner
        // loop is the one that fills, because "gold" runs straight into
        // `input`'s own terminator with no trailing separator of its own.
        // `rstrin` reads exactly this slot for the last gap; miss it here and
        // a test can be self-consistent while `rstrin` still writes a space
        // through a stale pointer.
        let end2 = read_ptr(&f.machine, slot(margn, 2));
        assert_eq!(end2.offset - input.offset, 12, "the early-return path's margn write");

        // The other way margn[margc-1] gets filled: trailing whitespace after
        // the last word, which the *outer* tail reaches instead of the inner
        // loop's early return. Same slot, different path -- both must land on
        // the true separator, not on whatever the early-return path would
        // have written.
        let mut f = Fixture::new();
        let input = f.host.globals().address("input").expect("input");
        f.host
            .globals()
            .write(&mut f.machine, "input", b"get all gold  ")
            .expect("input");
        assert!(matches!(f.invoke(parsin, &[]), Ok(Ret::Void)));
        assert_eq!(f.host.globals().word(&f.machine, "margc").expect("margc"), 3);

        let margn = f.host.globals().address("margn").expect("margn");
        let end2 = read_ptr(&f.machine, slot(margn, 2));
        assert_eq!(end2.offset - input.offset, 12, "the outer-tail path's margn write");
    }

    #[test]
    fn rstrin_puts_back_exactly_what_parsin_took_apart() {
        // The round trip, and the test that catches a `parsin` which is
        // self-consistent but disagrees with the `rstrin` already shipped:
        // parse "get all gold", call `rstrin`, and read `input` back as one
        // string.
        let mut f = Fixture::new();
        let input = f.host.globals().address("input").expect("input");
        f.host
            .globals()
            .write(&mut f.machine, "input", b"get all gold")
            .expect("input");
        assert!(matches!(f.invoke(parsin, &[]), Ok(Ret::Void)));
        assert!(matches!(f.invoke(rstrin, &[]), Ok(Ret::Void)));

        assert_eq!(f.machine.read_cstr(input).expect("a string"), b"get all gold");
    }

    #[test]
    fn parsin_sets_inplen_to_the_length_it_consumed() {
        let mut f = Fixture::new();
        f.host
            .globals()
            .write(&mut f.machine, "input", b"get all gold")
            .expect("input");
        assert!(matches!(f.invoke(parsin, &[]), Ok(Ret::Void)));

        // The offset of the terminating NUL from the start of `input` -- the
        // early-return path inside the inner loop is what sets this, since
        // "gold" has no trailing space.
        assert_eq!(f.host.globals().word(&f.machine, "inplen").expect("inplen"), 12);
    }

    #[test]
    fn parsin_zeros_the_tail_of_input_past_trailing_whitespace_and_stale_bytes() {
        // Reachable only through the *outer* tail -- `if (margc != 0) { ...
        // setmem(...) }` -- and not through the inner loop's early return,
        // because trailing spaces after the last word mean the terminating
        // NUL is only found once the outer loop resumes skipping spaces.
        // `input` is 256 bytes and nothing clears it between commands, so a
        // shorter line leaves the previous, longer one sitting past its own
        // terminator; a `parsin` that forgot the `setmem` would leave that
        // stale tail for the module to read as though it were part of this
        // line.
        let mut f = Fixture::new();
        let input = f.host.globals().address("input").expect("input");
        let size = usize::from(f.host.globals().size("input").expect("input"));
        let mut buf = vec![0xffu8; size];
        buf[..7].copy_from_slice(b"gold   ");
        buf[7] = 0;
        f.machine.write(input, &buf).expect("input with a stale tail");

        assert!(matches!(f.invoke(parsin, &[]), Ok(Ret::Void)));

        assert_eq!(f.host.globals().word(&f.machine, "margc").expect("margc"), 1);
        assert_eq!(f.host.globals().word(&f.machine, "inplen").expect("inplen"), 4);
        let bytes = f.machine.resolve(input, size).expect("readable");
        assert_eq!(&bytes[..4], b"gold");
        assert!(
            bytes[4..].iter().all(|&b| b == 0),
            "trailing spaces and everything stale past them are zeroed"
        );
    }

    #[test]
    fn vsprintf_formats_from_the_list_it_is_handed() {
        let mut f = Fixture::new();
        let out = f.buffer(64);
        let template = f.text("%s the %s, level %d");
        let who = f.text("rangerdan");
        let what = f.text("Ranger");
        let list = f.words(&[who.offset, who.selector, what.offset, what.selector, 21]);

        let ret = f
            .invoke(vsprintf,
                &[
                    out.offset,
                    out.selector,
                    template.offset,
                    template.selector,
                    list.offset,
                    list.selector,
                ],
            )
            .expect("formatted");

        assert_eq!(f.read(out), "rangerdan the Ranger, level 21");
        assert!(matches!(ret, Ret::U16(30)), "{ret:?}");
    }

    #[test]
    fn vsprintf_terminates_what_it_wrote() {
        // The buffer starts full of a byte that is not a terminator, so a
        // missing NUL would be visible rather than papered over by a fixture
        // that happened to hand out zeroed memory.
        let mut f = Fixture::new();
        let out = f.bytes(&[b'#'; 16], false);
        let template = f.text("%d");
        let list = f.words(&[7]);

        f.invoke(vsprintf,
            &[
                out.offset,
                out.selector,
                template.offset,
                template.selector,
                list.offset,
                list.selector,
            ],
        )
        .expect("formatted");

        assert_eq!(f.read(out), "7");
    }

    #[test]
    fn vsprintf_refuses_a_list_it_cannot_follow() {
        let mut f = Fixture::new();
        let out = f.buffer(16);
        let template = f.text("%d");
        let args = [
            out.offset,
            out.selector,
            template.offset,
            template.selector,
            0,
            0,
        ];
        assert!(f.invoke(vsprintf, &args).is_err());
    }
}
