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
//! [`append`] is also where `crate::ifansi::process` runs -- see its doc
//! comment. `prf` and `prfmsg` both call it, which is why this is the one
//! place in the host that can consume the `ESC[[ansi|ascii]` construct before
//! any of it reaches `prfbuf`, the GSBL, or the wire.

use mbbs16::Machine;
// `Ret` is now named only by this file's `#[cfg(test)]` `_wg16` bridges --
// production code reaches every routine here through its generic
// `Call<A>`/`Host<A>` core instead, per `shims::mod`'s own `call` doc comment.
#[cfg(test)]
use mbbs16::Ret;
use mbbs_ptr::ModulePtr;

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
    Ok(abi::Ret::Int(A::Int::from(text.len() as u16)))
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
    Ok(abi::Ret::Int(A::Int::from(text.len() as u16)))
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
    if std::env::var_os("MBBS_TRACE_SHIMS").is_some() {
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
/// **not** downstream in the GSBL or the transport. `btutsw`'s wrap
/// arithmetic in `crate::gsbl` counts every byte toward the column; running
/// this after that count has already happened would shrink the string GSBL
/// wrapped without telling it, which is a wrap bug wearing an IF-ANSI
/// costume, not a genuine fix.
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
/// (`users::usracc::ANSIFL`) when a channel connects, and this reads it back
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
fn channel_ansi_mem<A: Abi>(mem: &A::Mem, host: &Host<A>) -> bool {
    let Ok(chan) = host.current_channel_mem(mem) else {
        return true;
    };
    let account = host.users().account(chan);
    let ansifl = A::ptr_offset(account, crate::users::usracc::ANSIFL as u16);
    match ansifl.resolve(mem, 1) {
        Ok(bytes) => bytes[0] & 1 != 0,
        Err(_) => true,
    }
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
pub fn stzcpy<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let dst = call.ptr();
    let src = call.ptr();
    let num = Into::<u32>::into(call.int()) as u16;

    if num == 0 {
        // Nowhere to put even the terminator. Copying nothing is the only
        // thing that cannot overrun.
        return Ok(abi::Ret::Ptr(dst));
    }
    let text = src
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let take = text.len().min(usize::from(num) - 1);
    let text = text[..take].to_vec();

    write_cstr_mem::<A>(call.mem(), dst, &text, num)?;
    Ok(abi::Ret::Ptr(dst))
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
    Ok(abi::Ret::Int(A::Int::from(text.len() as u16)))
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
    let n = crate::strings::skpwht(text) as u16;
    Ok(abi::Ret::Ptr(at::<A>(cp, n)))
}

/// `char *skpwrd(char *cp)` -- past this word, to the space that ends it.
pub fn skpwrd<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let cp = call.ptr();
    let text = cp
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let n = crate::strings::skpwrd(text) as u16;
    Ok(abi::Ret::Ptr(at::<A>(cp, n)))
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

/// `void parsin(void)` -- parse `input` into `margv[]`.
///
/// **Not in the v6 host source.** `MAJORBBS.C`'s `getin()` folds this
/// parsing inline; the routine `WCCMMUD.DLL` imports is Worldgroup's own,
/// split out at
/// `archive/galacticomm/extract/wg20/galdsrc/SRC/MAJORBBS.C:3376`:
///
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
        let word = at::<A>(input, offset);
        let slot = at::<A>(margv, n as u16 * A::PTR_WIDTH as u16);
        slot.write(mem, &A::ptr_to_bytes(word))
            .map_err(|e| ShimError::Failed(e.to_string()))?;
    }
    for (n, &offset) in margn_ends.iter().enumerate() {
        let end = at::<A>(input, offset);
        let slot = at::<A>(margn, n as u16 * A::PTR_WIDTH as u16);
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
    let margc = host
        .globals()
        .word_mem(call.mem(), "margc")
        .map_err(|e| ShimError::Failed(e.to_string()))? as i16;
    let margn = host
        .globals()
        .address("margn")
        .ok_or_else(|| ShimError::Failed("margn is not placed".into()))?;

    for i in 0..(margc - 1).max(0) as u16 {
        let slot = at::<A>(margn, i * A::PTR_WIDTH as u16);
        // `resolve` is how this crate reads raw bytes out of module memory --
        // `read_cstr` is for strings and there is no buffer-filling `read`.
        let bytes = slot
            .resolve(call.mem(), A::PTR_WIDTH)
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        let end = A::ptr_from_bytes(bytes);
        end.write(call.mem(), b" ")
            .map_err(|e| ShimError::Failed(e.to_string()))?;
    }
    Ok(abi::Ret::Void)
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
    let n = crate::strings::lastwd(text) as u16;
    Ok(abi::Ret::Ptr(at::<A>(s, n)))
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
        host.strtok = at::<A>(cursor, rest.len() as u16);
        return Ok(abi::Ret::Ptr(null_ptr::<A>()));
    };
    let token_len = rest[start..].len();
    let ends_at = rest[start..].iter().position(|b| delims.contains(b));

    let token = at::<A>(cursor, start as u16);
    match ends_at {
        Some(n) => {
            let end = at::<A>(token, n as u16);
            end.write(call.mem(), &[0])
                .map_err(|e| ShimError::Failed(e.to_string()))?;
            host.strtok = at::<A>(end, 1);
        }
        None => host.strtok = at::<A>(token, token_len as u16),
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
        return Ok(abi::Ret::Ptr(at::<A>(s, text.len() as u16)));
    }
    Ok(match text.iter().position(|&b| b == want) {
        Some(i) => abi::Ret::Ptr(at::<A>(s, i as u16)),
        None => abi::Ret::Ptr(null_ptr::<A>()),
    })
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
    Ok(match found {
        Some(i) => abi::Ret::Ptr(at::<A>(hay, i as u16)),
        None => abi::Ret::Ptr(null_ptr::<A>()),
    })
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
        .len() as u16;
    let text = src
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    fill::<A>(call.mem(), at::<A>(dst, end), &text)?;
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
    let max = usize::from(Into::<u32>::into(call.int()) as u16);
    let end = dst
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .len() as u16;
    let text = src
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let text = text[..text.len().min(max)].to_vec();
    fill::<A>(call.mem(), at::<A>(dst, end), &text)?;
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
    let n = usize::from(Into::<u32>::into(call.int()) as u16);
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
    let c = Into::<u32>::into(call.int()) as u16;
    Ok(abi::Ret::Int(A::Int::from(fold(c, crate::strings::toupper))))
}

/// `int tolower(int c)` -- [`toupper`]'s mirror, and the routine `sameas`,
/// `sameto` and `samein` fold with.
pub fn tolower<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let c = Into::<u32>::into(call.int()) as u16;
    Ok(abi::Ret::Int(A::Int::from(fold(c, crate::strings::tolower))))
}

/// The `int` wrapper both case-folding routines share: EOF through untouched,
/// everything else truncated to a byte and zero-extended back.
fn fold(c: u16, by: fn(u8) -> u8) -> u16 {
    /// What `cmp cx,0xffff` compares against, and the one argument that is not
    /// truncated.
    const EOF: u16 = -1i16 as u16;

    if c == EOF {
        EOF
    } else {
        u16::from(by(c as u8))
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
/// The one piece of arithmetic every routine here that answers a `char *` does,
/// and the reason it does not need checking: **`ptr.offset + n` never passes
/// the terminator of a string that has already been read**. A successful
/// [`Machine::read_cstr`] puts that terminator inside the segment, a segment is
/// at most 64 KiB, and so the sum is at most `0xffff`. That covers `n` taken
/// from a string's length and equally the
/// `at(end, 1)` in [`strtok`], where `end` is a delimiter -- strictly before
/// the terminator, so one past it still is not past.
///
/// The selector is the caller's own. Rebuilding it from anywhere else would
/// hand the module an address into the wrong segment.
fn at<A: Abi>(ptr: A::Ptr, n: u16) -> A::Ptr {
    A::ptr_offset(ptr, n)
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
    use mbbs16::FarPtr;

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
            Ret::Far(at::<Wg16>(s, 3))
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
            Ret::Far(at::<Wg16>(s, 3))
        );
        assert_eq!(
            f.invoke(strchr, &[s.offset, s.selector, 0xff62])
                .expect("ok"),
            Ret::Far(at::<Wg16>(s, 1)),
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
            Ret::Far(at::<Wg16>(hay, 3))
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
    fn append_dedups_a_reversed_lf_cr_pair_too() {
        // `FormatNewLineCarriageReturn` checks both orderings
        // (`ExportedModuleBase.cs:991-992`) -- unreached by anything
        // `WCCMMUD.DLL`'s `.MCV` files produce, but this is a port of that
        // routine, not a rewrite of it.
        let mut f = Fixture::new();
        append(&mut f.machine, &mut f.host, b"A\n\rB").expect("appended");
        let buffer = f.host.globals().prf_buffer();
        assert_eq!(f.machine.read_cstr(buffer).expect("terminated"), b"A\r\nB");
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
    fn append_reproduces_the_oracles_bytes_for_the_lawfulness_paragraph() {
        // The exact symptom the plan names
        // (`docs/plans/2026-08-11-live-session-defects.md`, Task 2): the
        // "truly 'lawful' citizen" paragraph, checked against a real capture
        // rather than a string this test made up. `re/oracle/oracle_m1.raw`
        // is a `Session.raw` dump (`tools/oracle/mudlib.py:20,39-41`) --
        // unmodified bytes off the socket, not one of the cleaned `.log`
        // transcripts `normalize_newlines`'s own doc comment explains why to
        // distrust for this question.
        //
        // Note: the plan's own Task 2 acceptance criterion names
        // `re/oracle/oracle_bank2.raw` for this check, but that file has no
        // "lawful" text in it at all -- the paragraph lives in
        // `oracle_m1.raw`, which is what this test reads below. Follow this
        // citation, not the plan's.
        let oracle = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../re/oracle/oracle_m1.raw"),
        )
        .expect("re/oracle/oracle_m1.raw is tracked in git");
        let found = oracle
            .windows(b"lawful".len())
            .position(|w| w == b"lawful")
            .expect("the lawfulness paragraph is in this capture");
        let expected = &oracle[found - 10..found + 400];
        assert!(
            expected.windows(2).filter(|w| *w == b"\r\n").count() >= 3,
            "sanity: the slice should span several real line breaks"
        );

        // What the module would have handed the host before this fix: the
        // `.MCV` encoding (`msg.rs:238-245`) never writes `\r\n` together,
        // only a bare `\r` (hard break) or a bare `\n` (soft wrap). Standing
        // every one of the oracle's line breaks up as a bare `\n` is a
        // strictly harder input than `.MCV` would actually produce, since it
        // puts every occurrence through this function's "no complementary
        // byte" branch at once, with nothing to dedup anywhere in the slice.
        let mut module_input = Vec::with_capacity(expected.len());
        let mut i = 0;
        while i < expected.len() {
            if expected[i..].starts_with(b"\r\n") {
                module_input.push(b'\n');
                i += 2;
            } else {
                module_input.push(expected[i]);
                i += 1;
            }
        }

        let mut f = Fixture::new();
        append(&mut f.machine, &mut f.host, &module_input).expect("appended");
        let buffer = f.host.globals().prf_buffer();
        assert_eq!(
            f.machine.read_cstr(buffer).expect("terminated"),
            expected,
            "byte-identical to the genuine board's wire"
        );
    }

    #[test]
    fn append_has_no_memory_of_a_line_ending_split_across_two_calls() {
        // The shape every newline test above shares: each hands `append` one
        // complete, already-joined byte string in a single call. None of
        // them can tell "no state carries between calls" apart from "correct
        // state carries between calls", because none of them ever cross a
        // call boundary at all -- go break that.
        //
        // `normalize_newlines` -- like MBBSEmu's `FormatNewLineCarriageReturn`,
        // which takes a `ReadOnlySpan<byte>` and keeps nothing between calls
        // -- has no memory either. A module that ended one `prf` call with a
        // bare `\r` and began the next with the `\n` meant to complete it
        // gets **two** line breaks, not one: this call's trailing `\r` has no
        // next byte to dedup against, so it becomes its own `\r\n`; the next
        // call's leading `\n` has no *previous* byte to dedup against
        // either, so it becomes a second, independent `\r\n`.
        //
        // Documented rather than silently accepted: `append`'s own doc
        // comment measures, over the whole of `WCCMMUD.DLL`, that every
        // `ESC[[...]` construct closes inside the single call that produced
        // it. Nothing here measures the same claim for a bare `\r`/`\n` --
        // this test pins today's actual behaviour (a doubled break) so a
        // reader who needs to know stumbles on it here rather than in a live
        // session, and so that a change which fixes it changes this
        // assertion on purpose rather than by accident.
        let mut f = Fixture::new();
        append(&mut f.machine, &mut f.host, b"text\r").expect("first call");
        append(&mut f.machine, &mut f.host, b"\nmore").expect("second call");

        let buffer = f.host.globals().prf_buffer();
        assert_eq!(
            f.machine.read_cstr(buffer).expect("terminated"),
            b"text\r\n\r\nmore",
            "current, documented behaviour: a \\r\\n split across two append() \
             calls becomes two line breaks, not one"
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
            let slot = mbbs16::FarPtr {
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
    fn read_ptr(machine: &mbbs16::Machine, at: FarPtr) -> FarPtr {
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
