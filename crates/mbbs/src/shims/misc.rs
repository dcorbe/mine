//! Six routines with nothing in common except that nothing had implemented
//! them yet: a default status handler, a high-resolution clock read, an
//! ASCII file pager, an immediate hang-up, and a by-name `.MSG` lookup.
//!
//! # Two shapes of gap
//!
//! Three of these ([`dfsthn`], [`hrtval`], [`msgscan`]) are implementable,
//! in whole or in the overwhelming common case, and are implemented below.
//!
//! Three ([`byenow`], [`listing`], [`oldsend`]) refuse outright, and each
//! refuses for a different, specific reason rather than a shared excuse:
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
//!
//! Every refusal below explains its own gap in full; this is the index, not
//! the excuse.
//!
//! # `c2bcpy`, `b2ccpy`, `profan` and `listing` used to be here too
//!
//! Removed 2026-08-15 (`docs/2026-08-15-dead-twin-shims.md`), as dead
//! duplicates of routines actually registered in `shims::mudtext`
//! (`c2bcpy`/`b2ccpy`/`profan`) and `shims::mudmisc` (`listing`).
//!
//! `c2bcpy`/`b2ccpy` here had no vendor `.C` at hand and were read off call
//! sites; `shims::mudtext`'s twins turned out to have real vendor bodies
//! after all (`re/wg33src/SRC/api/gcommlib/C2BCPY.C` and `B2CCPY.C`, both
//! extracted since this file's own comment was written) and match them
//! byte for byte. `profan` here refused outright, arguing (correctly, as
//! far as it went) that no compiled-in word list survives -- but
//! `shims::mudtext::profan` has one anyway, reconstructed from
//! `re/wg33src/SRC/api/gcommlib/PROFAN.C`'s own embedded table, which this
//! file's doc comment simply predates.
//!
//! `listing` was the one true duplicate found only by re-reading this file
//! against the registration table by hand, not by the twin-finding script
//! `docs/2026-08-15-dead-twin-shims.md` documents: that script's `path not
//! in modrs` check is a bare substring test, and `"misc::listing"` is
//! literally a substring of `"mudmisc::listing"` (`mud` + `misc::listing`),
//! so it never flagged this pair. This file's `listing` refused
//! unconditionally, doing none of the file-read work
//! `shims::mudmisc::listing` (the registered twin) actually does before its
//! own, narrower refusal (calling `whndun`) -- strictly less complete, no
//! vendor disagreement to settle.

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
///    the identical gap [`dfsthn`] and `shims::mudmisc::listing` hit.
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
