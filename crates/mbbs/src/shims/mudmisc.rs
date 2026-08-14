//! Eight odds and ends: the logoff entry point, an input re-prompt, a
//! high-resolution clock read, an ASCII file lister, and the video-driver
//! cursor primitives `WCCMMUD.DLL` imports but never gets a body for in any
//! recovered source tree.
//!
//! ```text
//! hrtval   2    injacr   2    byenow   1    listing  1
//! locate   1    msgscan  1    curcurx  1    curcury  1
//! ```
//!
//! Ten call sites total, measured with `re/ne_arity.py` against each
//! symbol's ordinal in `crates/mbbs/data/majorbbs_wg101.tsv` (862, 347, 91,
//! 386, 392, 421, 147, 148 respectively) -- every one of them agrees with
//! the vendor prototype's own argument count, cited per routine below.
//!
//! # Three different kinds of "cannot reproduce", named rather than blurred
//!
//! This file has all three shapes the project's method calls for, and they
//! are not interchangeable:
//!
//! 1. **Faithful.** [`hrtval`], [`injacr`], [`byenow`] and [`locate`] have
//!    real vendor bodies (`byenow`'s cited from `MAJORBBS.C`, the other
//!    three either bodied there too or reproducible from state this host
//!    already keeps) and are implemented against them, with the specific
//!    omissions named in each routine's own doc comment.
//! 2. **Provably-always-one-answer**, the `onsysn`/`dfsthn` model from
//!    `shims::user`. [`curcurx`] answers real, sourced state
//!    ([`crate::gsbl::Channel::column`]). [`msgscan`] answers `NULL`
//!    always -- not a guess, but the one answer the header itself declares
//!    safe for "not found", and the only one this host's `.MSG` reader
//!    (which structurally discards option names, `crate::msg::MsgFile`'s
//!    own doc comment) can ever produce.
//! 3. **Hard refusal.** [`curcury`] has no backing state anywhere in this
//!    host to answer from -- not even a divergent approximation -- and a
//!    fixed constant would be exactly the fabrication the method forbids.
//!    [`listing`] partially refuses: the file-list half is real, but the
//!    `whndun` callback cannot be invoked at all, for a reason stronger
//!    than "not implemented yet" -- see that routine's own doc comment.
//!
//! # `byenow`, and what actually tears a channel down here
//!
//! `byenow`'s own doc comment covers the routine itself; this is the answer
//! to the question the task brief asks directly. **The host already
//! implements the chain `lib.rs:170-234`'s `Vector` doc comment traces**:
//! `Host::logoff` runs the module's `lofrou` and then unconditionally
//! resets the channel (`Host::disconnect`, `lib.rs:3486`) -- that reset does
//! not check any per-channel "going away" flag, so it is not waiting on
//! anything `byenow` could set. The real `byenow`'s `setbbye()` half
//! (`user[usrnum].flags|=BYEBYE; extoff(usrnum)->byecnt=2;`) exists to make
//! a *later*, host-internal per-second sweep (`imdrop`, not in this file's
//! symbol set and not modelled anywhere in this crate) eventually call
//! `huprou` once the goodbye message has drained. This host's
//! `Host::disconnect` does not poll for that flag -- it is driven
//! externally, by the driver calling `Host::logoff`/`Host::hangup` once the
//! module's own vector returns or carrier is lost -- so nothing in this
//! host's disconnect path is waiting on `BYEBYE`/`byecnt` and nothing is
//! lost by not modelling them. `byenow` here does the part that is
//! observable to the player (the goodbye message, the channel going deaf
//! and mute) and leaves the actual teardown to the mechanism that already
//! exists and already runs. See [`byenow`]'s own doc comment for the
//! itemised C-to-Rust mapping.

use mbbs_machine::ptr::ModulePtr;

use super::ShimError;
use crate::Host;
use crate::abi::{self, Abi, Call};
use crate::gsbl::Gsbl;

/// The null pointer, in this ABI's own representation.
///
/// Same helper as `shims::stream::null_ptr`/`shims::text::null_ptr`, which
/// this mirrors rather than shares -- see either's own doc comment for why
/// `Abi::ptr_from_bytes` over `Abi::PTR_WIDTH` zero bytes is the
/// established idiom for "no `Abi::NULL` constant exists".
fn null_ptr<A: Abi>() -> A::Ptr {
    A::ptr_from_bytes(&vec![0u8; A::PTR_WIDTH])
}

/// PC BIOS timer rate: the 1.193182 MHz crystal divided by the 8253's
/// 16-bit reload count, `1_193_182 / 65536` ≈ 18.2065 Hz -- the standard
/// IBM PC/XT `INT 1A` tick rate `btuhrt` counts in.
///
/// Not directly stated by any recovered header or body -- neither survives
/// with a numeric tick rate attached -- but corroborated by the one nearby
/// constant that does survive: `MAJORBBS.C:232` (wg1), `#define LOGONPOL
/// (65535L/10)` "max time in btuhrt ticks for a logon cycle", 6553.5 ticks.
/// At this rate that is 6553.5 / 18.2065 ≈ 360.0 seconds, exactly six
/// minutes -- not an approximate match, an exact one, which is why this is
/// treated as measured-by-corroboration rather than invented.
const PC_TIMER_HZ_NUM: u64 = 1_193_182;
const PC_TIMER_HZ_DEN: u64 = 65_536;

/// `unsigned long hrtval(void)` -- "get btuhrt in a safe manner (dsairp)".
/// `MAJORBBS.H:728` (wg1); body `MAJORBBS.C:3784-3793` (wg1):
///
///
/// # What is reproduced, and what is not
///
/// `dsairp()`/`enairp()` bracket the read against `btuhrt` being updated by
/// the hardware-timer interrupt mid-read -- a genuine torn-read hazard on a
/// 16-bit CPU incrementing a 32-bit counter from IRQ context. This host has
/// no IRQ context and no concurrent writer of anything a shim reads: a
/// shim runs to completion on the one thread that would ever touch this
/// value (this crate is single-threaded by force). So the bracket has
/// nothing to protect here and is correctly omitted rather than reproduced
/// as a no-op.
///
/// `btuhrt` itself (`GALGSBL` ordinal 66) is not modelled as a host global
/// anywhere in this crate -- nothing places it, so a module reading it
/// directly (as opposed to through this routine) would find nothing. What
/// this returns instead is derived from [`Host::clock`], the same "the
/// clock" every other time-reading shim in `shims::system` already reads
/// from, converted to ticks at the rate [`PC_TIMER_HZ_NUM`]/
/// [`PC_TIMER_HZ_DEN`] -- see that constant's own doc comment for why this
/// rate and not an invented one. [`crate::clock::Clock::epoch`] only
/// answers in whole seconds, so this has one second's resolution where the
/// real 18.2 Hz counter had roughly 55 ms -- coarser, but the same
/// direction of error `shims::system::now`/`today` already accept from the
/// same clock, not a new one this routine introduces.
///
/// Wrapping (`as u32`) is deliberate and matches the real counter: a real
/// `unsigned long` `btuhrt` wraps every `2^32` ticks (about 7.6 years), and
/// every real use of `hrtval` is a *difference* between two reads, which
/// unsigned wraparound arithmetic answers correctly either side of a wrap.
/// This is not read from an absolute "since boot" origin -- it is read from
/// the Unix epoch -- but nothing about the two real call sites' arity (both
/// `void`, per this file's own module doc) suggests either reads it as
/// anything but such a difference.
///
/// # Errors
///
/// If the host's clock cannot say what time it is (`Clock::epoch`'s own
/// contract -- a system clock before 1970).
///
/// Generic: reads no argument of its own, matching `shims::system::now`.
pub fn hrtval<A: Abi>(_: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let seconds = host.clock().epoch().map_err(ShimError::Failed)?;
    let ticks = (u64::from(seconds) * PC_TIMER_HZ_NUM / PC_TIMER_HZ_DEN) as u32;
    Ok(abi::Ret::Long(ticks))
}

/// `clrinp()`'s own body, `MAJORBBS.C:2569-2576` (wg1):
///
///
/// Inlined here rather than called, because `clrinp` is its own MAJORBBS
/// ordinal (112, `crates/mbbs/data/majorbbs_wg101.tsv:140`) outside this
/// task's eight symbols and this file registers nothing for it -- see
/// [`injacr`]'s own doc comment for why reproducing its effect inline,
/// rather than inventing a `pub(crate)` export of a routine nobody asked
/// for, is the narrower change.
///
/// `input`, `margv`, `margc` and `inplen` are all real, placed
/// `MAJORBBS` globals (`crate::globals`'s own table; confirmed live by
/// `shims::text::parsin_mem`/`rstrin`, which already read three of the
/// same four), so every line of the C above has a real address to write
/// through -- nothing here is invented state.
fn clrinp<A: Abi>(mem: &mut A::Mem, host: &mut Host<A>) -> Result<(), ShimError> {
    let input = host
        .globals()
        .address("input")
        .ok_or_else(|| ShimError::Failed("clrinp: input is not placed".into()))?;
    input
        .write(mem, &[0])
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    host.globals()
        .write_mem(mem, "margv", &A::ptr_to_bytes(input))
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    host.globals()
        .write_mem(mem, "margc", &vec![0u8; A::INT_WIDTH])
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    host.globals()
        .write_mem(mem, "inplen", &vec![0u8; A::INT_WIDTH])
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(())
}

/// `void injacr(void)` -- "inject a `<CR>` to current channel (re-prompt
/// current text)". `MAJORBBS.H:679` (wg1); body `MAJORBBS.C:2559-2567`
/// (wg1):
///
///
/// # What this host does instead of `hdlinp()`, and why it is the same idea
///
/// The real body clears the input line ([`clrinp`], reproduced above) and
/// then calls `hdlinp()` *synchronously* -- a direct C function call that
/// re-enters the module's current-state routine immediately, before
/// `injacr` returns, exactly the way `hdlcri()`'s own default case would
/// dispatch a genuine CR-terminated line (`MAJORBBS.C:2692-2723`, wg1).
///
/// This host's shims never call back into module dispatch synchronously --
/// see [`listing`]'s own doc comment for exactly why that is not merely
/// unusual here but, for an ordinary `Shim<A>`, structurally impossible.
/// What this host has instead, already established for the identical
/// purpose (`begin_polling`/`POLSTS`, `crate::gsbl::Gsbl::CYCLE`'s own doc
/// comment), is: queue a status and let the driver's own dispatch loop
/// deliver the re-entry on its next pass. `crate::gsbl::Gsbl::CRSTG` is not
/// a substitute chosen for convenience -- it is the *real* status a
/// CR-terminated line arriving raises, and `status=CRSTG` is the exact
/// line the C body itself sets, so injecting it is the asynchronous form of
/// the same synchronous act: `Host::poll`'s own dispatch already sends
/// `CRSTG` to `sttrou` (`lib.rs:2633`, `PollTarget::Entry(1)`), the same
/// entry point `hdlcri`'s default case reaches. The one real difference is
/// timing -- the module sees its own re-prompt on the *next* dispatch pass
/// rather than before `injacr` itself returns -- which is a return-value
/// change no caller of a `void` routine can observe.
///
/// # `INJOIP` is not reproduced
///
/// `usrptr->flags` is a real, addressable field
/// (`crate::users::user::FLAGS`), but nothing in this host ever reads
/// `INJOIP` back -- there is no `condex`-equivalent here gating on it, and
/// this crate does not carry `INJOIP`'s own bit position forward from any
/// recovered header. Setting an unconfirmed bit in a word this host
/// otherwise treats as meaningful (other bits of the same `flags` word are
/// load-bearing elsewhere) for no consumer to ever read is exactly the
/// "recorded but not measured" shape this project's method warns against
/// when there is no reader to justify the write -- unlike
/// `shims::screen::rstrxf`'s recorded-but-inert page-mode fields, which
/// *are* backed by real `Channel` state this crate already owns and tests
/// against. So this is omitted rather than guessed at.
///
/// # Errors
///
/// If no channel is current (`Host::current_channel_mem`'s contract), or if
/// [`clrinp`] cannot reach the globals it writes.
///
/// Generic: reads no argument of its own.
pub fn injacr<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = host.current_channel_mem(call.mem())?;
    clrinp(call.mem(), host)?;
    host.gsbl_mut().inject(chan, Gsbl::CRSTG);
    Ok(abi::Ret::Void)
}

/// `param to byenow() for "no message"` -- `MAJORBBS.H:227` (wg1),
/// `#define NOMSG 0`.
const NOMSG: i32 = 0;

/// `param to byenow() for "prf()'d already"` -- `MAJORBBS.H:228` (wg1),
/// `#define PAMSG -1`.
const PAMSG: i32 = -1;

/// `void byenow(int msgnum, ...)` -- "log-off a user w/ message utility".
/// `MAJORBBS.H:712` (wg1, declared old-style: `void byenow();`); body
/// `MAJORBBS.C:4716-4760` (wg1):
///
///
/// See this file's own module doc comment ("`byenow`, and what actually
/// tears a channel down here") for the disconnect-chain question the task
/// brief asks about; this comment is the line-by-line mapping.
///
/// # The `ISGCSU` branch: omitted, and provably so -- the `onsysn` model
///
/// `ISGCSU` (`MAJORBBS.H:223`, wg1: `0x00800000L`, "user is a C/S client")
/// marks a Worldgroup native-client session, reached over `senddpk`'s own
/// binary packet protocol. This host serves Telnet only -- there is no
/// GCSU wire format anywhere in this crate to send `senddpk` through, and
/// nothing here ever sets the bit. Exactly `shims::user::onsysn`'s own
/// situation: not merely unimplemented, but unreachable *for this host* by
/// construction, so only the `else` branch below is implemented.
///
/// # The `else` branch, mapped
///
/// * `btulok(usrnum,1)` -> `Channel::locked = true` (the same field
///   `crate::shims::gsbl::btulok` itself sets).
/// * `btubsz(usrnum,INPSIZ,OUTSIZ)` -- **omitted**. `Channel`'s input and
///   output are unbounded `VecDeque`s (`crate::gsbl`'s own doc comment);
///   there is no fixed-size buffer anywhere in this host for a byte count
///   to configure, and `btubsz` itself is not implemented by this crate at
///   all (not one of `shims::gsbl`'s fourteen).
/// * `btucli(usrnum)` -> clears `input`/`line`/`ready`, the same three
///   fields `crate::shims::gsbl::btucli` clears.
/// * `btuclo(usrnum)` -> clears `output` and resets `column` to 0, the same
///   two fields `crate::shims::gsbl::btuclo` clears.
/// * `btuoes(usrnum,1)` -> `Channel::oes = true`, the same field
///   `crate::shims::gsbl::btuoes` sets.
/// * The `bdelay` pause-message branch (`BYEDLY`, under `mjrmb`) --
///   **omitted**. `mjrmb` is the *host's own* message catalog, loaded at
///   `MAJORBBS.C:630-637` in the real host; this crate has no message
///   catalog to load it from at all (the identical gap
///   `shims::screen::rstrxf`'s own doc comment already names for
///   `scnpaus`), so there is no `BYEDLY` text to print even if `bdelay`
///   could be asked.
/// * `outprf(usrnum); clrprf();` -> reproduced: flush `prfbuf` to the
///   channel via [`crate::gsbl::Gsbl::transmit`], then
///   [`crate::shims::text::clrprf_mem`] -- the same two steps
///   `crate::shims::fsd`'s own (private) `outprf` helper performs, inlined
///   here because that helper is not `pub(crate)` and this file owns
///   nothing in `shims::fsd`.
/// * `if (btuoba(usrnum)==OUTSIZ-1) btuinj(usrnum,OUTMT);` -- **omitted**,
///   and provably unreachable rather than merely skipped: this is real
///   hardware's "the output ring buffer is exactly one byte from full"
///   edge case, and `Channel::output` is an unbounded `VecDeque` that is
///   never at any fixed capacity, let alone exactly one short of it.
///
/// # `prfmsg(msgnum,p1,p2,p3)`, reproduced inline
///
/// Rather than a bare guard and a skipped call, the formatting itself is
/// reproduced: `msgnum`'s message text is looked up under `curmbk`
/// ([`crate::shims::msg::message_mem`], the same call
/// [`crate::shims::msg::prfmsg`] itself makes) and formatted against
/// whatever varargs follow on the *same* argument frame
/// ([`crate::fmt::format_call`], again the same call `prfmsg` makes), then
/// appended to `prfbuf` ([`crate::shims::text::append_mem`]). This is not
/// a call to `prfmsg` -- `prfmsg`'s own shim re-reads `msgnum` off `call`
/// from the start, and this routine has already consumed that word to
/// decide whether to format at all -- so the three calls `prfmsg` itself
/// makes are inlined here instead, in the same order, against the same
/// cursor position.
///
/// # `setbbye()`
///
/// Not reproduced -- see this file's own module doc comment.
///
/// # `ASSERTM`
///
/// A debug-build developer assertion (`msgnum` is never anything but
/// `NOMSG`, `PAMSG` or positive), not user-visible behaviour. Not
/// reproduced; `msgnum > 0` is tested directly instead; a violation is
/// silently outside the routine's real domain rather than fatal.
///
/// # Errors
///
/// If no channel is current, if `msgnum > 0` names no message under
/// `curmbk`, or if formatting/appending fails.
///
/// Generic: reads exactly one fixed argument (`msgnum`), matching the
/// prototype's one non-vararg parameter -- the same shape
/// [`crate::shims::msg::prfmsg`] and `tokopt` already have in
/// `crates/mbbs/tests/argument_widths.rs`'s `EXAMINED` ledger, with no
/// `EXPECTED_COUNT_MISMATCHES` entry needed for the same reason theirs
/// needs none.
pub fn byenow<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let msgnum = super::sign_extend::<A>(Into::<u32>::into(call.int()));
    let chan = host.current_channel_mem(call.mem())?;

    if msgnum != NOMSG && msgnum != PAMSG && msgnum > 0 {
        let at = crate::shims::msg::message_mem(call.mem(), host, msgnum as u16)?;
        let (text, _) = crate::fmt::format_call(call, at)?;
        crate::shims::text::append_mem(call.mem(), host, &text)?;
    }

    // The `else` (non-`ISGCSU`) branch. See this routine's own doc comment,
    // "The `else` branch, mapped", for each line's C original.
    {
        let c = host.gsbl_mut().channel_mut(chan);
        c.locked = true; // btulok(usrnum,1)
        c.input.clear(); // btucli(usrnum)
        c.line.clear();
        c.ready.clear();
        c.output.clear(); // btuclo(usrnum)
        c.column = 0;
        c.oes = true; // btuoes(usrnum,1)
    }

    if msgnum != NOMSG {
        let prfbuf = host
            .globals()
            .pointer_mem(call.mem(), "prfbuf")
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        let text = prfbuf
            .read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?
            .to_vec();
        host.gsbl_mut().transmit(chan, &text);
        crate::shims::text::clrprf_mem(call.mem(), host)?;
    }

    Ok(abi::Ret::Void)
}

/// `void locate(int x, int y)` -- "move cursor to x,y position (0=left
/// margin / 0=top line)". `GCOMM.H:434` (wg1). No body survives in any
/// recovered source tree -- it is a video-driver primitive, not host
/// application logic, and `GALDSRC` never included the driver.
///
/// # What is reproduced
///
/// The observable contract: an ANSI cursor-position (`CUP`) escape,
/// `\x1b[{y+1};{x+1}f`, one-based and `f`-terminated -- the exact form this
/// crate's own FSD engine already emits for the identical purpose
/// (`crate::shims::fsd`, e.g. `format!("\x1b[{row};1f")`), and the form
/// Galacticomm's own `FSD.C:368` (wg1) builds by hand for the same reason:
/// `sprintf(fsdscb->hlpgto,"\x1B[%d;%df",curcury()+1,curcurx()+1)`. This
/// host is Telnet-only, so an ANSI escape is not an approximation of the
/// real video driver's behaviour -- it is the whole of what a real board's
/// video driver would do once its output reached an ANSI terminal.
///
/// [`crate::gsbl::Channel::column`] is also updated to `x`, **not** left to
/// [`crate::gsbl::Gsbl::transmit`]'s own CSI-aware accounting (which
/// correctly leaves it untouched -- the escape bytes are invisible, per
/// that method's own doc comment on `column`). The escape genuinely moves
/// where the next visible byte lands, so leaving `column` at its
/// pre-`locate` value would make [`curcurx`] wrong the instant a module
/// called this. `column` is `pub(crate)`, and this write is exactly what
/// its own doc comment describes it as recording -- "how far along the
/// current output line the terminal's cursor is" -- true before and after
/// this call either way.
///
/// There is no row-tracking field anywhere in `Channel` for the `y` half to
/// update -- see [`curcury`]'s own doc comment.
///
/// # Errors
///
/// If no channel is current.
///
/// Generic: reads its two fixed `int` arguments in order, matching the
/// prototype.
pub fn locate<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let x = Into::<u32>::into(call.int()) as u16;
    let y = Into::<u32>::into(call.int()) as u16;
    let chan = host.current_channel_mem(call.mem())?;

    let seq = format!("\x1b[{};{}f", y + 1, x + 1);
    host.gsbl_mut().transmit(chan, seq.as_bytes());
    host.gsbl_mut().channel_mut(chan).column = x;

    Ok(abi::Ret::Void)
}

/// `int curcurx(void)` -- "get current cursor x coord". `GCOMM.H:436`
/// (wg1). No body survives -- see [`locate`]'s own doc comment; same video
/// driver, same gap in the recovered source.
///
/// # What answers it: real, sourced state
///
/// [`crate::gsbl::Channel::column`] -- "how far along the current output
/// line the terminal's cursor is", the same field [`locate`] keeps in step
/// with every cursor jump and [`crate::gsbl::Gsbl::transmit`] already
/// advances on every visible byte and resets on every line break. This is
/// the `onsysn` model, not the `dfsthn` one: not a stub, a real answer
/// backed by state this crate already owns, tests, and updates for reasons
/// that have nothing to do with this routine existing.
///
/// # Errors
///
/// If no channel is current.
///
/// Generic: reads no argument of its own.
pub fn curcurx<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let chan = host.current_channel_mem(call.mem())?;
    let column = host.gsbl().channel(chan).column;
    Ok(abi::Ret::Int(A::Int::from(column)))
}

/// `int curcury(void)` -- "get current cursor y coord". `GCOMM.H:437`
/// (wg1). No body survives -- see [`locate`]'s own doc comment.
///
/// # A hard refusal, and why this one gets a different answer than `curcurx`
///
/// `Channel` tracks `column` (an x position) and nothing else about cursor
/// position -- no row, no line count, no scroll-region state. There is no
/// field this file could read, not even an imperfect one, and this file
/// owns no other module it could add one to. A fixed answer (`0`, or any
/// other constant) would not be "the one answer this host's contract
/// allows" the way [`msgscan`]'s `NULL` is -- a cursor row genuinely varies
/// with everything printed before it, so a constant would be exactly the
/// "plausible fabrication" this project's method forbids, not a documented
/// limit of what this host models.
///
/// Whether `WCCMMUD.DLL`'s one real call site (`re/ne_arity.py 148
/// re/WCCMMUD.DLL`, `seg 3 0xaa21`, paired with `curcurx` at `0xaa19` eight
/// bytes earlier -- the shape of `int x=curcurx(); int y=curcury();`) is
/// reached in ordinary MajorMUD play was not established; unlike
/// `shims::btrieve`'s `aabbtv`/`qrybtv`, this is not claimed unreachable,
/// only unanswerable.
///
/// # Errors
///
/// Always: `ShimError::Failed`, naming exactly this gap.
///
/// Generic: reads no argument of its own.
pub fn curcury<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let _chan = host.current_channel_mem(call.mem())?;
    Err(ShimError::Failed(
        "curcury: this host tracks a channel's output column but no row -- there is no state \
         anywhere in this crate a cursor y-coordinate could be read from, and a fixed answer \
         would be fabricated rather than measured; see shims::mudmisc::curcury's own doc comment"
            .into(),
    ))
}

/// `char *msgscan(char *msgfil, char *vblnam)` -- "scan for vblnam in
/// msgfil, no 'T'/'S'"; "return NULL if vblnam not found". `GCOMM.H:358`
/// (wg1). No body survives in any recovered source tree, and its sibling
/// `mstscan` (`GCOMM.H:359`, "'S' and 'T' type compatible msgscan") does
/// not either.
///
/// # Always `NULL` -- the `onsysn` model, not a refusal
///
/// This is not a hard error like [`curcury`], because `NULL` is not a
/// fabricated value here -- it is the routine's own documented answer for
/// "not found", and every well-formed caller already has to handle it. Two
/// independent facts make it the *only* answer this host can ever give,
/// not merely a convenient default:
///
/// 1. **No grammar to scan by.** The one .MSG grammar this crate has ever
///    measured, [`crate::msg::MsgFile::parse`], keeps `messages:
///    Vec<Vec<u8>>` -- text only, addressed purely by *position*
///    (`crate::msg`'s own module doc comment: "`stgopt(N)` indexes by
///    position"). Option **names** are consumed and discarded while
///    parsing; they are never stored anywhere this host could scan back
///    through. `msgscan`'s whole job is a name-to-value lookup, and the
///    name half of that pair does not survive parsing.
/// 2. **No real grammar for a second reader to reproduce faithfully.**
///    Even setting (1) aside, no vendor body for `msgscan` survives to
///    measure a scan grammar from -- unlike `crate::msg::MsgFile`'s own
///    grammar, which `crates/mbbs/tests/msgfile.rs` cross-checks against
///    ten real `.MSG`/`.MCV` pairs (10,569 messages, byte for byte). A
///    second, independent `.MSG` reader written for this one routine alone,
///    with no comparable measurement to check it against, is exactly the
///    "invent behaviour you cannot source" this project's method forbids --
///    and it would fork the one grammar this crate has already measured
///    into two copies free to disagree.
///
/// This file does not even attempt (1)'s file resolution as a gesture:
/// doing the lookup's first half and then discarding the answer would
/// suggest a scan is happening when it never can be.
///
/// # Errors
///
/// Never -- `NULL` is always a legal answer for this routine.
///
/// Generic: reads its two fixed pointer arguments, matching the prototype,
/// even though neither is used for anything beyond that -- so a caller
/// passing a bad pointer for either is not itself an error here, the same
/// as every other "reads its arguments and answers a constant" shim in
/// this crate.
pub fn msgscan<A: Abi>(call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let _msgfil = call.ptr();
    let _vblnam = call.ptr();
    Ok(abi::Ret::Ptr(null_ptr::<A>()))
}

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
    use mbbs_machine::m16::Ret;

    fn current(f: &mut Fixture) -> crate::chan::Chan {
        let chan = f.console();
        f.host
            .point_curusr(&mut f.machine, chan)
            .expect("channel 0 is current");
        chan
    }

    // ---- hrtval -------------------------------------------------------------

    #[test]
    fn hrtval_derives_ticks_from_the_pinned_clock_at_the_pc_timer_rate() {
        let mut f = Fixture::new();
        f.host.set_clock(crate::clock::Clock::pinned(3600));
        current(&mut f);

        let Ret::U32(ticks) = f.invoke(hrtval, &[]).expect("hrtval") else {
            panic!("hrtval returns a long");
        };
        assert_eq!(ticks, (3600u64 * PC_TIMER_HZ_NUM / PC_TIMER_HZ_DEN) as u32);
    }

    /// Mutation check: replacing `PC_TIMER_HZ_NUM`/`_DEN` with `1`/`1`
    /// (i.e. seconds instead of ticks) must change the answer for a
    /// pinned clock far from zero -- confirms the test above is not
    /// vacuously true for every rate.
    #[test]
    fn hrtval_ticks_are_not_the_same_as_bare_seconds() {
        let mut f = Fixture::new();
        f.host.set_clock(crate::clock::Clock::pinned(3600));
        current(&mut f);

        let Ret::U32(ticks) = f.invoke(hrtval, &[]).expect("hrtval") else {
            panic!("hrtval returns a long");
        };
        assert_ne!(u64::from(ticks), 3600, "must scale by the tick rate, not pass seconds through");
    }

    // ---- injacr ---------------------------------------------------------------

    #[test]
    fn injacr_clears_the_input_globals_and_queues_crstg() {
        let mut f = Fixture::new();
        let chan = current(&mut f);

        // Seed non-empty input/margc/inplen so the clear is observable.
        let input = f.host.globals().address("input").expect("input placed");
        f.machine.write(input, b"north\0").expect("seed input");
        f.host
            .globals()
            .write_mem(f.machine.mem_mut(), "margc", &2u16.to_le_bytes())
            .expect("seed margc");
        f.host
            .globals()
            .write_mem(f.machine.mem_mut(), "inplen", &5u16.to_le_bytes())
            .expect("seed inplen");

        f.invoke(injacr, &[]).expect("injacr does not stop the machine");

        assert_eq!(
            f.host
                .globals()
                .word_mem(f.machine.mem(), "margc")
                .expect("margc"),
            0,
            "margc=0"
        );
        assert_eq!(
            f.host
                .globals()
                .word_mem(f.machine.mem(), "inplen")
                .expect("inplen"),
            0,
            "inplen=0"
        );
        let byte = input.resolve(f.machine.mem(), 1).expect("input[0]")[0];
        assert_eq!(byte, 0, "input[0]='\\0'");

        assert_eq!(
            f.host.gsbl_mut().next_status(chan),
            Some(crate::gsbl::Gsbl::CRSTG),
            "status=CRSTG queued for the driver's next pass"
        );
    }

    /// Mutation check: if `injacr` queued `POLSTS` instead of `CRSTG` (an
    /// easy status-constant swap), this must fail -- `CRSTG` is the one
    /// that reaches `sttrou`, matching the real `hdlcri` default case.
    #[test]
    fn injacr_queues_crstg_specifically_not_some_other_status() {
        let mut f = Fixture::new();
        let chan = current(&mut f);
        f.invoke(injacr, &[]).expect("injacr does not stop the machine");
        assert_eq!(f.host.gsbl_mut().next_status(chan), Some(crate::gsbl::Gsbl::CRSTG));
    }

    // ---- byenow ---------------------------------------------------------------

    #[test]
    fn byenow_nomsg_locks_and_clears_the_channel_without_printing() {
        let mut f = Fixture::new();
        let chan = current(&mut f);
        f.host.gsbl_mut().channel_mut(chan).input.push_back(b'x');
        f.host.gsbl_mut().channel_mut(chan).output.push_back(b'y');

        f.invoke(byenow, &[0]).expect("byenow(NOMSG) does not stop the machine");

        let c = f.host.gsbl().channel(chan);
        assert!(c.locked, "btulok(usrnum,1)");
        assert!(c.oes, "btuoes(usrnum,1)");
        assert!(c.input.is_empty(), "btucli(usrnum)");
        assert!(c.output.is_empty(), "btuclo(usrnum)");
    }

    #[test]
    fn byenow_with_a_real_message_prints_it_to_the_channel() {
        let root = crate::testing::scratch("mudmisc-byenow");
        // Message 0 is reserved (`NOMSG`), so the target text is the
        // *second* option in the file -- message index 1 -- with a dummy
        // first option ahead of it, the same "index, not the constant
        // name" convention `shims::msg`'s own `prfmsg` tests already use.
        std::fs::write(
            root.join("TEST.MSG"),
            b"DUMMY {unused}S 0\nBYEMSG {Goodbye!}S 0\n",
        )
        .expect("a .MSG file");
        let mut f = Fixture::rooted(root);
        let chan = current(&mut f);
        let path = f.text("TEST.MSG");
        f.invoke(crate::shims::msg::opnmsg, &[path.offset, path.selector])
            .expect("opnmsg");

        f.invoke(byenow, &[1]).expect("byenow(1) does not stop the machine");

        let c = f.host.gsbl().channel(chan);
        assert!(c.locked);
        let out: Vec<u8> = c.output.iter().copied().collect();
        assert!(
            out.windows(b"Goodbye!".len()).any(|w| w == b"Goodbye!"),
            "the message text reached the channel, got {out:?}"
        );
    }

    /// Mutation check: if the channel-state block ran unconditionally
    /// AFTER the print instead of before, or `msgnum > 0`'s guard were
    /// dropped, `NOMSG` would also attempt a lookup and stop the machine
    /// instead of quietly locking the channel -- this is what catches
    /// that.
    #[test]
    fn byenow_nomsg_never_touches_the_message_catalog() {
        let mut f = Fixture::new();
        current(&mut f);
        // No message file opened at all -- if byenow(NOMSG) tried to look
        // up a message it would fail; it must not try.
        f.invoke(byenow, &[0]).expect("byenow(NOMSG) must not need a message catalog");
    }

    // ---- locate / curcurx / curcury --------------------------------------------

    #[test]
    fn locate_emits_a_cup_escape_and_updates_column() {
        let mut f = Fixture::new();
        let chan = current(&mut f);

        f.invoke(locate, &[12, 5]).expect("locate does not stop the machine");

        let c = f.host.gsbl().channel(chan);
        let out: Vec<u8> = c.output.iter().copied().collect();
        assert_eq!(out, b"\x1b[6;13f", "y+1;x+1, matching FSD.C's own %d;%df form");
        assert_eq!(c.column, 12, "column tracks locate's x argument");
    }

    /// Mutation check: swapping the row/col order (`\x1b[{x};{y}f`) would
    /// still emit *an* escape of the right length, so a bytes-non-empty
    /// assertion would not catch it -- exact-content comparison does.
    #[test]
    fn locate_does_not_swap_x_and_y() {
        let mut f = Fixture::new();
        let chan = current(&mut f);
        f.invoke(locate, &[1, 2]).expect("locate");
        let out: Vec<u8> = f.host.gsbl().channel(chan).output.iter().copied().collect();
        assert_eq!(out, b"\x1b[3;2f");
    }

    #[test]
    fn curcurx_reads_back_what_locate_set() {
        let mut f = Fixture::new();
        current(&mut f);
        f.invoke(locate, &[7, 0]).expect("locate");
        let Ret::U16(x) = f.invoke(curcurx, &[]).expect("curcurx") else {
            panic!("curcurx returns an int");
        };
        assert_eq!(x, 7);
    }

    #[test]
    fn curcurx_tracks_ordinary_output_column_without_locate() {
        let mut f = Fixture::new();
        let chan = current(&mut f);
        f.host.gsbl_mut().transmit(chan, b"hello");
        let Ret::U16(x) = f.invoke(curcurx, &[]).expect("curcurx") else {
            panic!("curcurx returns an int");
        };
        assert_eq!(x, 5, "column after five visible bytes");
    }

    #[test]
    fn curcury_is_a_named_refusal_not_a_fabricated_constant() {
        let mut f = Fixture::new();
        current(&mut f);
        let err = f.invoke(curcury, &[]).expect_err("curcury cannot answer");
        assert!(format!("{err}").contains("curcury"));
    }

    // ---- msgscan ----------------------------------------------------------------

    #[test]
    fn msgscan_always_answers_null() {
        let mut f = Fixture::new();
        current(&mut f);
        let a = f.text("SOME.MSG");
        let b = f.text("VBLNAM");
        let Ret::Far(at) = f
            .invoke(msgscan, &[a.offset, a.selector, b.offset, b.selector])
            .expect("msgscan never errors")
        else {
            panic!("msgscan returns a pointer");
        };
        assert_eq!(at, mbbs_machine::m16::FarPtr::NULL);
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
