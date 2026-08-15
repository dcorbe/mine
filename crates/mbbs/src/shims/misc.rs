//! Nine routines with nothing in common except that nothing had implemented
//! them yet: a default status handler, a high-resolution clock read, an
//! ASCII file pager, an immediate hang-up, a by-name `.MSG` lookup, the 6.X
//! messaging compatibility shim, two binary/C string converters, and a
//! profanity check.
//!
//! # Two shapes of gap
//!
//! Three of these ([`dfsthn`], [`hrtval`], [`msgscan`]) are implementable,
//! in whole or in the overwhelming common case, and are implemented below.
//! Two ([`b2ccpy`], [`c2bcpy`]) are implemented from call-site evidence
//! rather than surviving source, with the uncertainty that entails written
//! down rather than hidden.
//!
//! Four ([`byenow`], [`listing`], [`oldsend`], [`profan`]) refuse outright,
//! and each refuses for a different, specific reason rather than a shared
//! excuse:
//!
//! - [`byenow`] and [`listing`] both need to call *back into a module
//!   routine* -- `module00.huprou` and `whndun` respectively -- and no shim
//!   can: [`crate::abi::Call`] holds only `cpu`, and [`Host`] never stores a
//!   loaded module's own selector/section map (`A::Module`, what
//!   [`Host::run`] resolves an entry point against). Only
//!   `crates/mbbs-server/src/host.rs`'s driver thread has one, because it is
//!   the caller of [`crate::abi::Abi::load`] in the first place.
//! - [`listing`] and [`oldsend`] each depend on a whole subsystem this host
//!   does not implement at all -- the File Transfer Framework and the
//!   Galacticomm Messaging Engine, respectively -- so even setting the
//!   callback problem aside, there is no engine here to drive.
//! - [`profan`] depends on a compiled-in word list that shipped inside the
//!   real host's binary and was never part of any recovered source kit.
//!   There is no way to answer the question at all, honestly.
//!
//! Every refusal below explains its own gap in full; this is the index, not
//! the excuse.

use mbbs_machine::ptr::ModulePtr;

use crate::Host;
use crate::abi::{self, Abi, Call, Wg16};
use crate::shims::ShimError;
use crate::shims::text::{SPR_BYTES, write_cstr_mem};

/// `void dfsthn(void)` -- `MAJORBBS.H:751` -- the default status handler.
///
/// (`MAJORBBS.C:4487-4499`). `status` is `GCOMM.H`'s own scalar global -- the
/// GSBL completion code most recently posted -- already in this crate's
/// [`crate::globals::GLOBALS`] table as `gi("status")`, which is what makes
/// the harmless half of this routine answerable at all.
///
/// The fourteen listed codes are every status the original treats as
/// ordinary traffic and answers with a no-op: `CMDOK=2`, `INBLK=4`,
/// `OUTMT=5`, `OBFCLR=6`, `ABOREQ=7`, `CMN2OK=12`, `CM25OK=22`, `RCVX29=24`
/// (all `BRKTHU.H:16-26`), `IPXRER=37`, `IPXUNK=38` (`BRKTHU.H:32-33`),
/// `CYCLE=240` (`MAJORBBS.H:236`), and the three bare literals `251`, `252`,
/// `253` the header never names at all. This shim reads `status` and
/// answers `Void` unchanged for exactly these fourteen -- the same
/// behaviour the original has, not an approximation of it.
///
/// # What this host cannot do
///
/// Every other `status` value reaches the original's `default:` arm: a
/// status the channel's own state machine did not expect, answered by
/// hanging the channel up via `module00.huprou` (guarded by `recurs` against
/// a `huprou` that itself posts a status `dfsthn` would have to answer
/// again). That call needs `A::Module` -- see this module's own doc comment
/// for the general shape of the gap -- and no shim has one.
///
/// So for the one case this routine's whole reason to exist is written for,
/// this shim refuses rather than silently doing nothing: a caller falling
/// through to `dfsthn`'s `default:` arm is relying on it to end a channel
/// that is behaving unexpectedly, and answering `Void` unanswered would
/// leave that channel running exactly as if nothing were wrong -- the
/// "plausible zero" this crate's whole refusal discipline exists to catch.
pub fn dfsthn<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let status = host
        .globals()
        .word_mem(call.mem(), "status")
        .map_err(|e| ShimError::Failed(format!("dfsthn: {e}")))?;

    const HARMLESS: [u16; 14] = [
        2, 4, 5, 6, 7, // CMDOK INBLK OUTMT OBFCLR ABOREQ
        12, 22, 24, // CMN2OK CM25OK RCVX29
        37, 38, // IPXRER IPXUNK
        240, // CYCLE
        251, 252, 253,
    ];
    if HARMLESS.contains(&status) {
        return Ok(abi::Ret::Void);
    }

    Err(ShimError::Failed(format!(
        "dfsthn: status {status} is not one of the fourteen codes this host \
         can silently ignore (MAJORBBS.C:4488-4499); the original's default \
         arm hangs the channel up via module00.huprou, which this shim \
         cannot reach -- see this function's own doc comment for exactly \
         what is missing"
    )))
}

/// `unsigned long hrtval(void)` -- `MAJORBBS.H:728` -- read `btuhrt` "in a
/// safe manner".
///
/// (`MAJORBBS.C:3784-3792`). `btuhrt` is `volatile unsigned long btuhrt;
/// /* increments 65536 times a second */` (`BRKTHU.H:88`) -- a free-running
/// hardware tick counter GSBL's own interrupt handler advances, and
/// `dsairp`/`enairp` (disable/enable async receive interrupt processing)
/// exist only so a 32-bit read cannot land torn across that interrupt. This
/// host dispatches every channel on one thread with no interrupt to race
/// it, so that half of the contract costs nothing here -- the read genuinely
/// cannot tear.
///
/// # The precision this host does not have
///
/// `btuhrt` ticks 65536 times a second -- roughly every 15 microseconds --
/// and [`crate::clock::Clock`]'s only public read is whole seconds
/// ([`crate::clock::Clock::epoch`]). This answers `epoch_seconds *
/// 65536`, the only honest translation available without adding a
/// sub-second accessor to `clock.rs`, which is outside this file. **Every
/// call within the same wall-clock second returns the identical value.** A
/// caller measuring a genuinely sub-second interval -- `MAJORBBS.C:232`'s
/// `#define LOGONPOL (65535L/10)`, a tenth of a second of `hrtval` ticks
/// used as a logon timeout -- sees either "no time has passed" (most reads)
/// or a jump of a full 65536 (whenever the wall second rolls over between
/// two reads), never the smooth count the real hardware produced. That is a
/// real fidelity loss, named rather than hidden. It costs nothing measured
/// so far: `hrtval` has zero call sites in `WCCMMUD.DLL`.
///
/// The multiplication is `wrapping_mul`: `btuhrt` is a free-running counter
/// with no stated ceiling ("increments... a second", not "and then stops"),
/// so wrapping here reproduces the real counter's own eventual overflow
/// rather than introducing a new failure this host did not have to.
pub fn hrtval<A: Abi>(_: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let seconds = host.clock().epoch().map_err(ShimError::Failed)?;
    Ok(abi::Ret::Long(seconds.wrapping_mul(65536)))
}

/// `char *msgscan(char *msgfil,char *vblnam)` -- `GCOMM.H:358` -- the value
/// of one named variable out of a `.MSG` file, by name rather than by
/// position.
///
/// One real call site survives, and it is the whole of the evidence for
/// what this returns: `strcpy(chkkey, msgscan("galme.msg","FORSYS"))`
/// (`BBSRPT.C:826` and `:1412`, both wg1 and wg20). No `.C` implementing
/// `msgscan` itself survives. `MSGRDR.H` -- the header for whatever reader
/// this shares an engine with -- only names the pieces: `#define OPTLEN 8`
/// (`:13`, the byte size the real reader's own name buffer allows) and
/// `extern char msgnam[OPTLEN+1];` (`:38`, "message name" -- a scratch slot
/// for exactly the name this routine would compare against).
///
/// # Grammar, on loan from a different reader
///
/// [`crate::msg::MsgFile::parse`]'s own module doc is where this repo's one
/// *measured* `.MSG` grammar lives: `<comments> NAME {value} [type] [args]`,
/// names made only of digits and upper-case letters, `~~` a literal tilde
/// and `~}` a literal closing brace inside a value, bare `\r` dropped. That
/// reader is **positional** -- `MsgFile::get(n)` answers the Nth `{value}`,
/// which is what `stgopt(N)` and its siblings need -- and its own doc
/// comment explains why it deliberately does not keep the name that went
/// with each one: nothing else in this crate has ever needed it. `msgscan`
/// needs exactly the thing that reader throws away, so [`scan_named`] below
/// is a second, independent walk of the same five states, kept name-and-all,
/// rather than a change to `MsgFile` -- which this task's brief does not
/// authorise touching in any case.
///
/// **Not applied here:** `crate::msg`'s `line_endings` post-pass, which
/// turns a value's bare `\n` into `\r` unless the next character continues a
/// sentence. That pass exists for `getmsg`'s user-facing prose, which wraps
/// over several visual lines; every measured `.MSG` construct that is a
/// *variable* rather than a *message* -- `FORSYS`'s value included -- is one
/// unwrapped token with no embedded line break to reformat. If some
/// `vblnam` value somewhere does contain a raw `\n`, this returns it exactly
/// as struck rather than reformatted the way a multi-paragraph message
/// would be -- a named simplification, not a silent one.
///
/// # Not found
///
/// No source says what an absent name answers. `NULL` is the ordinary C
/// idiom this crate's own `strchr`/`strstr` already use for "not there"
/// (`crates/mbbs/src/shims/text.rs`), and nothing about `msgscan`'s
/// signature suggests otherwise, so this answers the same way -- by analogy
/// with this crate's own convention, not by measurement of `msgscan` itself,
/// and named as such here rather than presented as settled.
///
/// # Errors
///
/// If `msgfil` cannot be found under [`Host::find`], cannot be read, or
/// contains the one construct this reader refuses outright: a `{` where a
/// name should be -- the identical refusal
/// [`crate::msg::MsgError::Unexpected`] makes, whose own doc comment
/// measures it firing zero times across the 91 recovered `.MSG` files, so a
/// file that trips it here resembles none of them.
pub fn msgscan<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let msgfil_ptr = call.ptr();
    let vblnam_ptr = call.ptr();
    let msgfil = String::from_utf8_lossy(
        msgfil_ptr
            .read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();
    let vblnam = vblnam_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    let name = Host::<Wg16>::dos_name(&msgfil).map_err(ShimError::Failed)?;
    let path = host
        .find(&name)
        .ok_or_else(|| ShimError::Failed(format!("msgscan: no {msgfil} under {:?}", host.root)))?;
    let bytes = std::fs::read(&path)
        .map_err(|e| ShimError::Failed(format!("msgscan: {}: {e}", path.display())))?;

    match scan_named(&msgfil, &bytes, &vblnam)? {
        Some(text) => {
            let at = host.next_spr_buffer();
            write_cstr_mem::<A>(call.mem(), at, &text, SPR_BYTES)?;
            Ok(abi::Ret::Ptr(at))
        }
        None => Ok(abi::Ret::Ptr(A::ptr_from_bytes(&vec![0u8; A::PTR_WIDTH]))),
    }
}

/// The name-tracking twin of [`crate::msg::MsgFile::parse`]'s five-state
/// walk -- see [`msgscan`]'s own doc comment for why this is a second copy
/// rather than a change to that reader. Stops and answers as soon as an
/// option named `want` closes; answers `None` having seen the whole file
/// and no such name.
fn scan_named(file: &str, bytes: &[u8], want: &[u8]) -> Result<Option<Vec<u8>>, ShimError> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        PreName,
        Name,
        PostName,
        Value,
        PostValue,
    }

    fn is_name(byte: u8) -> bool {
        byte.is_ascii_digit() || byte.is_ascii_uppercase()
    }

    let mut state = State::PreName;
    let mut option: Vec<u8> = Vec::new();
    let mut value: Vec<u8> = Vec::new();
    let mut previous = 0u8;

    for (offset, &byte) in bytes.iter().enumerate() {
        let mut consumed = byte;
        match state {
            State::PreName => {
                if byte == b'{' {
                    return Err(ShimError::Failed(format!(
                        "msgscan: {file} has a '{{' at byte {offset} where an \
                         option name should be"
                    )));
                }
                if is_name(byte) {
                    state = State::Name;
                    option.push(byte);
                }
            }
            State::Name => {
                if is_name(byte) {
                    option.push(byte);
                } else if byte == b'{' {
                    state = State::Value;
                } else {
                    state = State::PostName;
                }
            }
            State::PostName => {
                if byte == b'{' {
                    state = State::Value;
                } else if is_name(byte) {
                    state = State::Name;
                    option.clear();
                    option.push(byte);
                }
            }
            State::Value => match byte {
                b'}' if previous == b'~' => {
                    // `~}` is a literal brace, and the tilde is not part of
                    // the text.
                    value.pop();
                    value.push(b'}');
                    consumed = 0;
                }
                b'}' => {
                    if option == want {
                        return Ok(Some(value));
                    }
                    option.clear();
                    value.clear();
                    state = State::PostValue;
                    consumed = 0;
                }
                // `~~` is a literal tilde: the first is kept, the second is
                // what marked it as literal.
                b'~' if previous == b'~' => consumed = 0,
                b'\r' => consumed = 0,
                _ => value.push(byte),
            },
            State::PostValue => {
                if byte == b'\n' {
                    state = State::PreName;
                }
            }
        }
        previous = consumed;
    }

    Ok(None)
}

/// `void c2bcpy(char *dest,char *src,unsigned length)` -- `GCOMM.H:332` --
/// copy a C string into a fixed-width binary field, `length` bytes wide,
/// NUL-padding whatever the string does not fill.
///
/// No `.C` survives for this or [`b2ccpy`]; both are read off their call
/// sites, of which around eighty survive across `BBSMAINM.C`, `CSEFU.C`,
/// `CSMJRTLC.C`, `GALP&QA.C`, `CSEML.C` and `GCSASYS.C` -- every one a
/// client/server structure field (`csmodpg->appid`, `dmsg->fornam`,
/// `sysinfvb->sysname`, ...) being filled from an ordinary C string for
/// transmission to the Worldgroup graphical client.
///
/// **`length` is the *destination* field's width**, read off the "reserve a
/// byte" pattern several call sites share: `c2bcpy(finf->userid,
/// usaptr->userid, UIDSIZ-1)` (`CSMJRTLC.C:559`) passes one less than the
/// field's own declared size (`UIDSIZ`), which only has a purpose if
/// `length` bytes are written in full and the caller wants one guaranteed
/// left over. That purpose is a terminator: if `length` were filled with a
/// source string exactly that long, a dest read back as a C string later
/// would have no NUL inside its own field at all unless the routine's pad
/// byte is NUL and one byte of headroom is reserved for it. Not every call
/// site subtracts one (`c2bcpy(sysinfvb->sysname,fldr_sysname(),TTLSIZ)`,
/// `GCSASYS.C:1063`, does not) -- consistent with `length` being the
/// caller's own choice of exactly how many bytes to fill, not a capacity
/// this routine infers, the same freedom [`super::text::strncpy`]'s own `n`
/// already has for the identical reason (see that routine's own doc
/// comment). This shim is that routine's behaviour under a different name:
/// `length` bytes written every time, the string truncated if it is longer,
/// NUL-padded if it is shorter.
pub fn c2bcpy<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let dest = call.ptr();
    let src = call.ptr();
    let length = Into::<u32>::into(call.int()) as usize;

    let text = src
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    let take = text.len().min(length);
    let mut out = vec![0u8; length];
    out[..take].copy_from_slice(&text[..take]);

    dest.write(call.mem(), &out)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Void)
}

/// `void b2ccpy(char *dest,char *src,unsigned length)` -- `GCOMM.H:331` --
/// [`c2bcpy`]'s inverse: read a fixed-width binary field and hand back an
/// ordinary NUL-terminated C string.
///
/// **`length` is the *source* field's width, not the destination's
/// capacity** -- the opposite convention from `c2bcpy`, and settled by the
/// one call site whose `length` is not a manifest constant:
/// `regwrite(struct saunam *dpknam, unsigned length /* length of dynapak
/// value */, void *value)` calls `b2ccpy(prostg,(char *)value,length+1)`
/// (`CSREGIS.C:210-238`) -- `length` there is documented, by the parameter's
/// own comment, as the length of `value` (`src`), and `prostg`'s own
/// declared size (`PROSIZ+SUMSIZ+1`, `CSREGIS.C:226`) is unrelated to it.
/// `length+1` gives the scan one byte of headroom past the payload's own
/// stated length to find a terminator the sender may have included; every
/// other call site passes a plain manifest field-size constant
/// (`b2ccpy(uid,finf->userid,UIDSIZ)`, `CSMJRTLC.C:532`) consistent with the
/// same reading, since a field's declared size and its own content width
/// coincide there too.
///
/// So this reads exactly `length` bytes from `src` -- bounded, since a
/// binary field packed for wire transmission is not guaranteed to carry a
/// terminator of its own within that span -- stops at the first embedded
/// NUL if there is one, and writes that much of a proper C string (plus its
/// own terminator) to `dest`. How much room `dest` has is the caller's
/// affair, the same convention [`super::text::strcpy`]/[`super::text::strcat`]
/// already use.
pub fn b2ccpy<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let dest = call.ptr();
    let src = call.ptr();
    let length = Into::<u32>::into(call.int()) as usize;

    let text = {
        let field = src
            .resolve(call.mem(), length)
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
        field[..end].to_vec()
    };

    write_cstr_mem::<A>(call.mem(), dest, &text, text.len() as u16 + 1)?;
    Ok(abi::Ret::Void)
}

/// `int profan(char *string)` -- `GCOMM.H:460` -- how profane is this text?
///
/// Real call sites: `setpfn` (`MAJORBBS.C:3330-3336`, gates every line of
/// chat input against `pfceil`) and `profane` (`GALFILU.C:2923-2937`, the
/// file area's own softer gate against `pfnceil`). Both treat a non-zero
/// answer as a severity to clamp, not a yes/no -- `profane` clamps to
/// `pfnceil` (`0..=3`, `GALFIL.C:354`'s `numopt(PFNCEIL,0,3)`), so the
/// contract is a graded score, not a boolean.
///
/// # What is missing, and why this refuses rather than guessing
///
/// No `.C` implementing `profan` itself survives anywhere in the recovered
/// archive -- only its two callers. What it would score text against is
/// Galacticomm's own compiled-in profanity word list, which shipped inside
/// the binary and is not part of any recovered source kit. There is no way
/// to reconstruct the list, so there is no way to answer this question
/// honestly for any input at all.
///
/// MBBSEmu answers `0` unconditionally
/// (`MBBSEmu/HostProcess/ExportedModules/Majorbbs.cs`'s `profan`: "MBBSEmu
/// doesn't support multiple profanity levels, so the default value of 0 is
/// returned", confirmed by its own `profan_Tests.cs`, which asserts exactly
/// `AX == 0`). That is precisely the fabricated success this crate's design
/// refuses to produce: `0` means "clean," every caller treats a clean
/// answer as permission to proceed un-gated, and a host that always says
/// "clean" has silently disabled every profanity filter downstream of it
/// without saying so anywhere a caller could notice -- `setpfn`'s
/// `usrptr->pfnacc` accumulator never grows, `profane`'s `PFNCEIL` clamp
/// never has anything to clamp, and a sysop who configured either gets a
/// board that silently ignores it. This shim refuses loudly instead, per
/// this whole task's brief.
pub fn profan<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let stg = call.ptr();
    let text = String::from_utf8_lossy(
        stg.read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();
    let sample: String = text.chars().take(80).collect();

    Err(ShimError::Failed(format!(
        "profan({sample:?}): this host has no copy of Galacticomm's \
         compiled-in profanity word list -- no source for the routine \
         itself survives, only its two callers -- so there is no honest \
         severity to answer with. Answering 0 (as MBBSEmu does) would \
         silently disable every profanity gate downstream (setpfn's \
         pfnacc accumulator, profane's PFNCEIL clamp) without telling \
         anyone; this shim refuses instead."
    )))
}

/// `void listing(char *path, void (*whndun)())` -- `FILEXFER.H:78-82` --
/// page an ASCII file to the user's screen, then call `whndun(1)` once it
/// has all been shown or `whndun(0)` if the user aborted partway through.
///
/// (`FILEXFER.C:936-951`). This is not a synchronous "dump the file"
/// routine under an odd name: `ftgnew`/`ftgsbm` hand the whole job to the
/// **File Transfer Framework**, the same subsystem that drives every
/// download/upload protocol. `tshlst` (`FILEXFER.C:908-932`) is a tagspec
/// handler the FTF calls back across as many polling passes as it takes to
/// page the file and read a keystroke between screens, and its `TSHFIN` arm
/// is what finally runs `lstptr->whndun((int)ftfscb->actfil)` -- on
/// whichever pass the transfer actually finishes, not this call's own.
///
/// # What this host does not have, twice over
///
/// This host implements no File Transfer Framework at all: `ftgnew`,
/// `ftgsbm`, `struct ftfpsp`, `ftfscb` and the tagspec-handler protocol they
/// imply have no counterpart anywhere in this crate (checked; zero hits).
/// Building one is a subsystem, not a shim.
///
/// And even a deliberately simplified stand-in -- dump the whole file into
/// `prfbuf` in one pass and skip the paging -- could not finish the
/// contract regardless, because the last step is calling `whndun`, a
/// **module** routine, and no shim can call into module code: see this
/// module's own doc comment for the general shape of that gap (`A::Module`,
/// which only `crates/mbbs-server/src/host.rs`'s driver thread holds).
///
/// So this refuses outright rather than shipping a partial listing whose
/// completion callback never runs: a caller told nothing ran to completion
/// by a routine whose entire second half is telling it exactly that would
/// be left waiting on a callback that is never coming.
pub fn listing<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let path = call.ptr();
    let whndun = call.ptr();
    let name = String::from_utf8_lossy(
        path.read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();

    Err(ShimError::Failed(format!(
        "listing({name:?}, {whndun}): this host has no File Transfer \
         Framework (ftgnew/ftgsbm/the tagspec-handler protocol) for a \
         listing to run on, and no way to call whndun back even if it did \
         -- see this function's own doc comment"
    )))
}

/// `void byenow(int msgnum, long p1, long p2, long p3)` -- log this channel
/// off, now, with an optional `.MSG`-file message.
///
/// `MAJORBBS.H:712` declares it untyped (`void byenow();`, pre-ANSI K&R
/// style -- no prototype at all); the real signature is the definition's
/// own, confirmed by `WGSERVER!_byenow`'s measured PE import arity (7/7
/// words: one `int` plus three `long`s, exactly):
///
/// (`MAJORBBS.C:4715-4761`; `NOMSG`/`PAMSG` at `MAJORBBS.H:227-228`).
///
/// **`byenow` does not hang the channel up itself.** Its whole visible
/// effect on the user record is `setbbye()`'s two flags --
/// `user[usrnum].flags|=BYEBYE; extoff(usrnum)->byecnt=2;`
/// (`MAJORBBS.C:4770-4774`). The actual disconnect is a *later* pass:
/// `imdrop` (`MAJORBBS.C:3423`, called from the main polling loop, never
/// from here) is what notices `BYEBYE`, counts `byecnt` down, and *then*
/// calls `module00.huprou` -- `loscar` -> `aschup` -> `rstchn`, the same
/// chain this crate's own `Vector` enum documents (`lib.rs`, near
/// [`Host::hangup`]).
///
/// # What this host lacks, precisely
///
/// Two separate gaps, both of which would need to close for `byenow` to be
/// more than a refusal:
///
/// 1. **No `imdrop`-equivalent poll pass.** [`Host`] has no
///    `BYEBYE`/`byecnt`-shaped field, and nothing in [`Host::cycle`] or
///    [`Host::poll`] drains one. The shape that would fill this gap already
///    exists once, for a different deferred action:
///    [`crate::shims::system::rtkick`]'s `host.kicks`, documented there as
///    "a debt rather than a lie" because `rtkick` returns `void` and
///    promises nothing about *when*. A `pending_hangup: Vec<Chan>` field,
///    pushed here and drained by `crates/mbbs-server/src/host.rs`'s driver
///    loop the same way it already calls [`Host::hangup`] for a lost
///    carrier, is the identical shape applied to this case. That field
///    would live in `lib.rs`, which this task's brief does not authorise
///    editing.
/// 2. **Even a synchronous shortcut needs `A::Module`.** However the
///    disconnect eventually gets triggered, actually running `huprou` --
///    [`Host::hangup`]'s own job -- takes `&A::Module`. No shim has one;
///    see this module's own doc comment for the general account, which is
///    the identical gap [`dfsthn`] and [`listing`] hit.
///
/// `byenow` promises the calling module nothing at call time -- it is
/// `void`, and MajorBBS's own callers of the pattern (`byenow(SEEYA)` and
/// its kin, in the logoff chain `lib.rs`'s own `Vector` doc comment
/// diagrams) do not check anything afterward, trusting the channel to
/// actually go away. **That is exactly why this cannot silently do nothing
/// and return:** a caller that believes the channel is ending and receives
/// an ordinary `Void` return will keep running on it -- sending further
/// output, taking further input -- on a channel every one of its own
/// callers believes is already gone. Formatting the goodbye message and
/// then refusing would not be less dishonest, only slower to notice, so
/// this refuses immediately instead.
pub fn byenow<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let msgnum = crate::shims::sign_extend::<A>(call.int().into());
    let p1 = call.long() as i32;
    let p2 = call.long() as i32;
    let p3 = call.long() as i32;

    Err(ShimError::Failed(format!(
        "byenow({msgnum}, {p1}, {p2}, {p3}): this host cannot hang up a \
         channel from inside a shim -- see this function's own doc comment \
         for exactly what is missing (a pending-hangup queue this shim \
         could push onto, and A::Module access for whatever eventually \
         drains it)"
    )))
}

/// `BOOL _oldsend(struct oldmsg *msg, char *to)` -- `GME.H:1266-1270` --
/// send a message through the 6.X-compatible interface, translated into the
/// Galacticomm Messaging Engine's own format and queued for real.
///
/// (`AAEFU.C:2406-2419`). `old2new` (`AAEFU.C:2421-2470`) is the whole of
/// the work: it resolves `to` against a forum or a user, copies eleven
/// fields of `struct oldmsg` (`GME.H:345-358`) into the GME's own `struct
/// message`, and for a message with an attachment (`FILATT`) opens, reads
/// and `unlink`s a side-channel file naming the real attachment path.
/// `simpsnd` then queues the translated message into the messaging engine's
/// own Btrieve-backed store.
///
/// # The double underscore, resolved
///
/// Ordinal 30 of `GALME` -- confirmed by this crate's own
/// `galme_ordinal_30_is_the_messaging_engines_6x_compatibility_entry` test
/// in `crates/mbbs/src/exports.rs` -- names it `_oldsend`, which is `GME.H`'s
/// own C spelling (`_oldsend`, with the leading underscore *in the
/// identifier itself*) after Borland's cdecl adds one more ahead of it
/// (`__OLDSEND`) and [`crate::exports::c_name`] strips exactly one back off.
/// **This host must register this function under the name `"_oldsend"`,
/// not `"oldsend"`**: stripping a second underscore would collide it with a
/// hypothetical unrelated `oldsend` symbol, the exact failure
/// [`crate::exports::c_name`]'s own doc comment names `_ctype`/`ctype` as
/// the reason exactly one comes off.
///
/// # What is missing
///
/// The entire Galacticomm Messaging Engine -- forums, the `struct message`
/// store, `simpsnd`, attachment files, `getfid` -- has no implementation
/// anywhere in this crate (checked; zero hits for `simpsnd`, `getfid`,
/// `struct message`, or `gme` outside this file's own citations of vendor
/// source). [`crate::msg`] is a different, unrelated thing: static
/// `.MSG`/`.MCV` *configuration and prompt text*, read-only, keyed by
/// position or (via [`msgscan`]) by name -- not the dynamic, writable,
/// forum-addressed mail store `_oldsend` queues into. Building that store
/// is a subsystem, not a shim, so this refuses rather than fabricating a
/// `TRUE`/`FALSE` that answers a question this host has no way to act on
/// either way.
pub fn oldsend<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let msg = call.ptr();
    let to_ptr = call.ptr();
    let to = String::from_utf8_lossy(
        to_ptr
            .read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();

    Err(ShimError::Failed(format!(
        "_oldsend({msg}, {to:?}): this host has no Galacticomm Messaging \
         Engine (forums, the struct message store, simpsnd) for a 6.X-style \
         message to be translated into and queued -- see this function's \
         own doc comment"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mbbs_machine::m16::{FarPtr, Ret};

    use crate::testing::{Fixture, scratch};

    fn long(ret: Ret) -> u32 {
        match ret {
            Ret::U32(n) => n,
            _ => panic!("expected a long"),
        }
    }

    fn pointer(ret: Ret) -> FarPtr {
        match ret {
            Ret::Far(at) => at,
            _ => panic!("expected a far pointer"),
        }
    }

    // ---- dfsthn -------------------------------------------------------------

    fn set_status(f: &mut Fixture, value: u16) {
        f.host
            .globals()
            .write(&mut f.machine, "status", &value.to_le_bytes())
            .expect("status");
    }

    #[test]
    fn dfsthn_is_a_noop_for_all_fourteen_harmless_status_codes() {
        // MAJORBBS.C:4488-4499's own `switch`, quoted whole in `dfsthn`'s
        // doc comment: CMDOK, INBLK, OUTMT, OBFCLR, ABOREQ, CMN2OK, CM25OK,
        // RCVX29, IPXRER, IPXUNK, CYCLE, 251, 252, 253.
        const HARMLESS: [u16; 14] = [2, 4, 5, 6, 7, 12, 22, 24, 37, 38, 240, 251, 252, 253];
        let mut f = Fixture::new();
        for code in HARMLESS {
            set_status(&mut f, code);
            assert!(
                matches!(f.invoke(dfsthn, &[]).expect("dfsthn"), Ret::Void),
                "status {code} should be a silent no-op"
            );
        }
    }

    #[test]
    fn dfsthn_refuses_a_status_none_of_the_fourteen_codes_names() {
        let mut f = Fixture::new();
        set_status(&mut f, 99);
        let e = f.invoke(dfsthn, &[]).expect_err("a refusal");
        assert!(e.to_string().contains("99"), "{e}");
    }

    #[test]
    fn dfsthn_refuses_at_254_just_past_the_three_literal_harmless_codes() {
        // 251, 252 and 253 are harmless; 254 is the very next status and is
        // not one of them -- catches an off-by-one in the HARMLESS table.
        let mut f = Fixture::new();
        set_status(&mut f, 254);
        let e = f.invoke(dfsthn, &[]).expect_err("a refusal");
        assert!(e.to_string().contains("254"), "{e}");
    }

    // ---- hrtval ---------------------------------------------------------------

    #[test]
    fn hrtval_is_the_epoch_second_times_65536() {
        let mut f = Fixture::new();
        f.host.set_clock(crate::Clock::pinned(1));
        assert_eq!(long(f.invoke(hrtval, &[]).expect("hrtval")), 65536);

        f.host.set_clock(crate::Clock::pinned(100));
        assert_eq!(long(f.invoke(hrtval, &[]).expect("hrtval")), 6_553_600);
    }

    #[test]
    fn hrtval_wraps_like_the_free_running_hardware_counter_would() {
        // 65536 seconds * 65536 = 2**32, which wraps to 0 -- `wrapping_mul`,
        // not a saturating or panicking multiply. See `hrtval`'s own doc
        // comment on why wrapping is the honest answer here.
        let mut f = Fixture::new();
        f.host.set_clock(crate::Clock::pinned(65536));
        assert_eq!(long(f.invoke(hrtval, &[]).expect("hrtval")), 0);
    }

    // ---- msgscan --------------------------------------------------------------

    fn msgscan_(f: &mut Fixture, file: &str, name: &str) -> Result<Ret, ShimError> {
        let file_p = f.text(file);
        let name_p = f.text(name);
        f.invoke(
            msgscan,
            &[file_p.offset, file_p.selector, name_p.offset, name_p.selector],
        )
    }

    #[test]
    fn msgscan_returns_the_value_of_the_named_option() {
        // BBSRPT.C:826's own call site: msgscan("galme.msg","FORSYS").
        let root = scratch("misc-msgscan-found");
        std::fs::write(root.join("GALME.MSG"), b"FORSYS{myserver}\n").expect("a file");
        let mut f = Fixture::rooted(root);

        let ret = msgscan_(&mut f, "galme.msg", "FORSYS").expect("msgscan");
        let at = pointer(ret);
        assert_eq!(f.machine.read_cstr(at).expect("readable"), b"myserver");
    }

    #[test]
    fn msgscan_returns_null_when_the_name_is_not_present() {
        let root = scratch("misc-msgscan-absent");
        std::fs::write(root.join("GALME.MSG"), b"OTHER{val}\n").expect("a file");
        let mut f = Fixture::rooted(root);

        let ret = msgscan_(&mut f, "galme.msg", "FORSYS").expect("msgscan");
        assert_eq!(pointer(ret), FarPtr::NULL, "no source says what an absent name answers -- see msgscan's own doc comment");
    }

    #[test]
    fn msgscan_resolves_tilde_and_brace_escapes_inside_the_value() {
        // `~~` is a literal tilde, `~}` is a literal closing brace.
        let root = scratch("misc-msgscan-escapes");
        std::fs::write(root.join("GALME.MSG"), b"ESCAPE{a~~b~}c}\n").expect("a file");
        let mut f = Fixture::rooted(root);

        let ret = msgscan_(&mut f, "galme.msg", "ESCAPE").expect("msgscan");
        let at = pointer(ret);
        assert_eq!(f.machine.read_cstr(at).expect("readable"), b"a~b}c");
    }

    #[test]
    fn msgscan_refuses_a_stray_open_brace_before_any_option_name() {
        let root = scratch("misc-msgscan-stray-brace");
        std::fs::write(root.join("GALME.MSG"), b"{oops}\n").expect("a file");
        let mut f = Fixture::rooted(root);

        let e = msgscan_(&mut f, "galme.msg", "ANYTHING").expect_err("a refusal");
        assert!(e.to_string().contains("byte 0"), "{e}");
    }

    // ---- c2bcpy -----------------------------------------------------------

    /// A buffer pre-filled with a non-zero sentinel, so a test can tell
    /// "the shim wrote a real NUL here" from "this byte was already zero".
    fn sentinel_buffer(f: &mut Fixture, len: u16) -> FarPtr {
        let at = f.buffer(len);
        f.machine.write(at, &vec![0xFFu8; len as usize]).expect("sentinel");
        at
    }

    fn c2bcpy_(f: &mut Fixture, dest: FarPtr, src: &str, length: u16) -> Result<Ret, ShimError> {
        let src_p = f.text(src);
        f.invoke(
            c2bcpy,
            &[dest.offset, dest.selector, src_p.offset, src_p.selector, length],
        )
    }

    #[test]
    fn c2bcpy_pads_a_short_string_with_nuls_to_fill_the_destination_field() {
        // No `.C` survives for c2bcpy -- this pins the behaviour read off
        // call sites (see c2bcpy's own doc comment), not a measured
        // correctness against vendor source.
        let mut f = Fixture::new();
        let dest = sentinel_buffer(&mut f, 5);
        c2bcpy_(&mut f, dest, "hi", 5).expect("c2bcpy");
        assert_eq!(f.machine.resolve(dest, 5).expect("in bounds"), b"hi\0\0\0");
    }

    #[test]
    fn c2bcpy_truncates_a_longer_string_with_no_guaranteed_terminator() {
        // Pins behaviour, not measured correctness -- see this file's own
        // doc comment on c2bcpy/b2ccpy's provenance.
        let mut f = Fixture::new();
        let dest = sentinel_buffer(&mut f, 4);
        c2bcpy_(&mut f, dest, "abcdef", 4).expect("c2bcpy");
        assert_eq!(
            f.machine.resolve(dest, 4).expect("in bounds"),
            b"abcd",
            "all 4 bytes are the source's own, no room left for a NUL"
        );
    }

    // ---- b2ccpy -----------------------------------------------------------

    #[test]
    fn b2ccpy_stops_at_an_embedded_nul_within_the_fixed_width_field() {
        // Pins behaviour, not measured correctness -- see this file's own
        // doc comment on c2bcpy/b2ccpy's provenance.
        //
        // `f.read(dest)` alone would NOT catch a mutant that copied the
        // whole 5-byte field ("ab\0cd") instead of stopping at the embedded
        // NUL: `read_cstr` stops at the first NUL either way, and "ab" comes
        // back either way. The sentinel bytes past the true 3-byte answer
        // ("ab\0") are what actually prove the "cd" was never written.
        let mut f = Fixture::new();
        let src = f.bytes(b"ab\0cd", false);
        let dest = sentinel_buffer(&mut f, 8);
        f.invoke(b2ccpy, &[dest.offset, dest.selector, src.offset, src.selector, 5])
            .expect("b2ccpy");
        assert_eq!(f.read(dest), "ab");
        assert_eq!(
            f.machine.resolve(dest, 8).expect("in bounds"),
            b"ab\0\xff\xff\xff\xff\xff",
            "nothing past the embedded NUL's own terminator was written"
        );
    }

    #[test]
    fn b2ccpy_reads_the_full_field_when_there_is_no_embedded_terminator() {
        // Pins behaviour, not measured correctness -- see this file's own
        // doc comment on c2bcpy/b2ccpy's provenance.
        let mut f = Fixture::new();
        let src = f.bytes(b"abcde", false);
        let dest = f.buffer(16);
        f.invoke(b2ccpy, &[dest.offset, dest.selector, src.offset, src.selector, 5])
            .expect("b2ccpy");
        assert_eq!(f.read(dest), "abcde");
    }

    // ---- the loud refusals --------------------------------------------------

    #[test]
    fn profan_refuses_rather_than_fabricating_a_clean_score() {
        let mut f = Fixture::new();
        let text = f.text("damn you");
        let e = f.invoke(profan, &Fixture::far(text)).expect_err("a refusal");
        let msg = e.to_string();
        assert!(msg.contains("profan("), "{msg}");
        assert!(msg.contains("damn you"), "{msg}");
    }

    #[test]
    fn listing_refuses_rather_than_running_a_file_transfer_framework_this_host_lacks() {
        let mut f = Fixture::new();
        let path = f.text("SOMEFILE.LST");
        let ret = f.invoke(
            listing,
            &[path.offset, path.selector, 0x1234, 0x0000],
        );
        let e = ret.expect_err("a refusal");
        let msg = e.to_string();
        assert!(msg.contains("listing("), "{msg}");
        assert!(msg.contains("SOMEFILE.LST"), "{msg}");
    }

    #[test]
    fn byenow_refuses_rather_than_silently_leaving_the_channel_running() {
        let mut f = Fixture::new();
        // msgnum=5, p1=100, p2=200, p3=300 -- long args as [lo, hi] words.
        let e = f
            .invoke(byenow, &[5, 100, 0, 200, 0, 300, 0])
            .expect_err("a refusal");
        assert!(e.to_string().contains("byenow(5, 100, 200, 300)"), "{e}");
    }

    #[test]
    fn oldsend_refuses_rather_than_fabricating_a_queued_message() {
        let mut f = Fixture::new();
        let to = f.text("someone");
        let e = f
            .invoke(oldsend, &[0x0010, 0x0020, to.offset, to.selector])
            .expect_err("a refusal");
        let msg = e.to_string();
        assert!(msg.contains("_oldsend("), "{msg}");
        assert!(msg.contains("someone"), "{msg}");
    }
}
