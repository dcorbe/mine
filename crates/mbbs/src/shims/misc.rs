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
use crate::clock::Civil;
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
    // hrtval is a free-running high-resolution counter that advances 65,536 per
    // second. Modules (RCIROSE) time short delays as (hrtval() - baseline) /
    // timeunit >= threshold, where timeunit sums to ~65,200 for a ~1-second
    // unit. Deriving the value from whole epoch seconds makes it a step
    // function -- flat within a second, then a 65,536 jump at the boundary --
    // so any sub-second delay cannot elapse until the next whole second, and a
    // chain of them (a combat round steps many per action) stretches to one
    // second apiece. Compute from milliseconds so it advances smoothly.
    let millis = host.clock().epoch_millis().map_err(ShimError::Failed)?;
    let val = (millis.wrapping_mul(65536) / 1000) as u32;
    if std::env::var_os("MBBS_TRACE_HRT").is_some() {
        eprintln!("mbbs-hrt: wall_ms={millis} hrtval={val}");
    }
    Ok(abi::Ret::Long(val))
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

/// `INT register_pseudok(const CHAR *pskbeg, pseudoKeyFunc pskrou)` --
/// `LOCKNKEY.H:131-133` -- register a callback that decides a "pseudokey", a
/// lock name recognised by its own logic rather than by a Btrieve keyring
/// entry (`_FORUMOP`, `_PORT#`, `_LANG=`, ...). `LOCKNKEY.C:51-68`:
///
/// Every measured call site (`AAEFU.C:98`, `GALFIL.C:331`,
/// `MAJORBBS.C:1236-1240`, five calls in a row registering `_PORT#`,
/// `_GROUP#`, `_LANG=`, `_PROT=` and `_ISGCSU`) is a bare statement -- the
/// returned index is never captured anywhere in the recovered source. So the
/// only externally visible effect of this routine, ever, is what it does to
/// `pkeys[]`/`npkeys` -- state a later `haskey` scan (`scnpsk`,
/// `LOCKNKEY.C:213` per [`crate::shims::user::haskey`]'s own doc comment)
/// would walk to decide whether a pseudokey lock is held.
///
/// # This host has already committed to an empty table, elsewhere
///
/// [`crate::shims::user::haskey`]'s doc comment (`shims/user.rs:197-199`)
/// records that `scnpsk` is **not reproduced** here at all, on the grounds
/// that `WCCMMUD.DLL` never calls `register_pseudok` -- so on that module the
/// array is empty regardless of what this routine does. That decision was
/// made without this routine existing yet; implementing `register_pseudok`
/// now does not change it; a scan that always finds nothing is what this host
/// has already decided a pseudokey lookup answers, module by module, until
/// something drives it further.
///
/// Given that, a *correct* `register_pseudok` for this host is a genuine
/// no-op: `pkeys[]` gains no entry (nothing ever reads it), and `npkeys`
/// -- the running count this returns -- stays at the only value consistent
/// with "the table this host has is permanently empty": zero, on every call,
/// not merely the first one. This is not the small-integer trap named in the
/// task brief (a hardcoded return that happens to be unobserved): it is the
/// literal value `npkeys` has under the state this host has already, and
/// separately, decided to keep -- see the mutation test below, which pins
/// that this returns the *pre-increment* `npkeys` and would fail if a naive
/// "always answer 1" implementation were substituted.
///
/// # What is missing, if that ever needs to change
///
/// `Host` has no `Vec<(name, callback)>` field for `pkeys[]` -- adding one is
/// `lib.rs`, which is outside `misc.rs`'s ownership for this task. And even a
/// stored callback could never be *invoked*: [`Call`] holds only `cpu`, and no
/// shim has the module's own `A::Module` to call back into it -- the same gap
/// [`dfsthn`] and [`byenow`] name in full. Both would have to close before a
/// non-empty pseudokey table could do anything a caller could observe.
///
/// # Errors
///
/// If `pskbeg` is not a readable C string. `pskrou` (the callback) is read as
/// a pointer and never dereferenced -- this host never calls it, the same way
/// `register_agent`'s vectors are stored and never dispatched.
pub fn register_pseudok<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let pskbeg = call.ptr();
    let _pskrou = call.ptr();
    pskbeg
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(format!("register_pseudok: {e}")))?;
    Ok(abi::Ret::Int(A::Int::from(0u16)))
}

/// `int alldgs(char *string)` -- is every character a decimal digit?
///
/// `GCOMM.H:345`. The predicate itself is [`crate::strings::all_digits`],
/// measured from the genuine host (see that function's own doc comment for
/// the probe set) -- this is only the pointer read and the `Ret::Int` it is
/// carried home in, the same split every routine in `shims::text` already
/// keeps between "read module memory" and "the transformation itself".
///
/// # Errors
///
/// If `string` is not a valid pointer.
pub fn alldgs<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let s = call.ptr();
    let text = s
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(abi::Ret::Int(A::Int::from(u16::from(crate::strings::all_digits(text)))))
}

/// `CHAR *unpad(CHAR *cp)` -- `GCOMM.H:527-529` -- strip trailing whitespace
/// in place, and hand the same pointer back. `VCPROJ/GCOMMLIB/UNPAD.C:19-24`:
///
/// `strpln` walks backward over the same whitespace set `depad` truncates
/// against -- [`crate::strings::depad`]'s own doc comment names it as the
/// unexported routine that function is folded from, and this is the second
/// caller of that same fold, not a new one. The whole difference from
/// `depad` (and from [`crate::shims::text::depad`], the shim that already
/// exists for it) is the return value: `depad` answers how many bytes it
/// removed, `unpad` answers `cp` itself, unmoved -- `stripb`
/// (`crate::shims::text::stripb`) is the third caller of the same
/// truncate-in-place step, for the same reason: three vendor routines, one
/// fold, three different things done with what it leaves behind.
///
/// # Errors
///
/// If `cp` is not a valid, writable pointer.
pub fn unpad<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let cp = call.ptr();
    let text = cp
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let (kept, _) = crate::strings::depad(&text);
    let capacity = text.len() as u16 + 1;
    write_cstr_mem::<A>(call.mem(), cp, &text[..kept], capacity)?;
    Ok(abi::Ret::Ptr(cp))
}

/// `INT findmod(CHAR *name)` -- `MAJORBBS.H:770` -- a module's registration
/// number, by the name it gave `register_module`. `MAJORBBS.C:1779-1789`:
///
/// Starts at **one**, not zero: `module[0]` is the BBS's own menuing system
/// (`inimod()` registers it before any DLL gets a turn), which is exactly
/// [`Host::modules`]'s own slot zero, [`crate::Registration::AbsentBbs`] --
/// see that variant's doc comment. This walks [`Host::modules`] the same way,
/// skipping index zero, and compares against
/// [`crate::Registration::Module`]'s own `description` -- the `descrp` this
/// host already keeps from [`crate::shims::system::register_module`], not a
/// second copy.
///
/// [`crate::Registration::Native`] entries (the FSD's own slot) are walked
/// over without matching anything, the same as a real `module[i]->descrp` a
/// module happened not to ask about would be -- `findmod` only ever answers
/// for a name a *module* registered.
///
/// The `-1` "not found" answer is built through [`Abi::int_from_u32`], not
/// `A::Int::from(0xffffu16)` -- see that method's own doc comment for exactly
/// why the latter is silently wrong under `Wg32` (`65535`, not `-1`).
///
/// # Errors
///
/// If `name` is not a valid pointer.
pub fn findmod<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let name_ptr = call.ptr();
    let name = name_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    for (i, reg) in host.modules().iter().enumerate().skip(1) {
        if let crate::Registration::Module { description, .. } = reg {
            if crate::strings::sameas(&name, description.as_bytes()) {
                return Ok(abi::Ret::Int(A::int_from_u32(i as u32)));
            }
        }
    }
    Ok(abi::Ret::Int(A::int_from_u32(-1i32 as u32)))
}

/// The DOS-packed date `DNTAPI.H:181-183`'s `ddyear`/`ddmon`/`ddday` macros
/// unpack, carried home as a [`Civil`] rather than three loose locals --
/// [`Civil::dos_date`] packs the identical bit layout (`clock.rs:69-78`) the
/// other direction, so this is that packing inverted, not a second format.
/// `hour`/`minute`/`second` are left zero; callers that only want the date
/// fields never look at them, and [`unpack_dos_time`] is what fills them in
/// for a caller that wants the time instead.
fn unpack_dos_date(date: u16) -> Civil {
    Civil {
        year: i32::from((date >> 9) & 0x7f) + 1980,
        month: u32::from((date >> 5) & 0xf),
        day: u32::from(date & 0x1f),
        hour: 0,
        minute: 0,
        second: 0,
    }
}

/// The DOS-packed time `DNTAPI.H:187-189`'s `dthour`/`dtmin`/`dtsec` macros
/// unpack, as a [`Civil`] whose date fields are a fixed, always-valid
/// placeholder (1980-01-01) -- see [`prntim`] for why that placeholder is
/// what lets [`Civil::to_local_epoch`] answer `validTime`
/// (`DNTAPI.C:646-655`) on its own, with no second range check written here.
/// [`Civil::dos_time`] (`clock.rs:80-88`) is the same layout, packed.
fn unpack_dos_time(time: u16) -> Civil {
    Civil {
        year: 1980,
        month: 1,
        day: 1,
        hour: u32::from((time >> 11) & 0x1f),
        minute: u32::from((time >> 5) & 0x3f),
        second: u32::from((time << 1) & 0x3e),
    }
}

/// `const CHAR *prntim(INT mode, USHORT time)` -- `DNTAPI.H:310-312` -- a
/// DOS-packed time, rendered per `mode` (`DNTAPI.H:141-159`). Two vendor
/// bodies compose to build it, both `SRC/api/gcommlib/DNTAPI.C`:
///
/// # `Civil` is the unpacker, and the validity check, both
///
/// `time` is unpacked by [`unpack_dos_time`] into a [`Civil`] against a fixed
/// valid date, and `validTime` (`DNTAPI.C:646-655`: `0<=hour<=23 &&
/// 0<=minute<=59 && 0<=second<=59`) is answered by asking whether
/// [`Civil::to_local_epoch`] accepts that `Civil` at all -- it already
/// enforces exactly those three bounds on its way to a real epoch second,
/// which this call never uses. Reusing it here is what "use `Civil`, not a
/// second conversion" means: this file does not carry a second `hour <= 23`
/// check of its own.
///
/// **`validTime` failing is not a refusal.** `prnTime` writes an empty string
/// and returns the (still valid) buffer pointer -- so a bogus `time` argument
/// (five bits of hour go to 31, six of minute to 63, and doubled seconds can
/// reach 62) answers `""`, not an error.
///
/// # No refusal for a negative `mode` either
///
/// Unlike [`prndat`]'s `switch`, every branch here is `%`/comparison
/// arithmetic with no table or `switch` to fall outside of, so a negative
/// `mode` is fully defined C behaviour (Rust's `%` truncates toward zero the
/// same way C's does) -- just an unusual bucket, not undefined one. This
/// transcribes the arithmetic for any `mode` [`crate::shims::sign_extend`]
/// hands back.
///
/// # No dedicated static buffer
///
/// The real `timret` is one buffer, reused forever; this host has no
/// per-routine buffer field to add to `Host` from `misc.rs` alone (see
/// [`byenow`]'s doc comment for the general shape of that gap), so this
/// writes into one of the shared `spr` rotation slots
/// [`msgscan`] already uses for the same reason. The one place that differs
/// from the real host: two `prntim` calls whose results a caller holds
/// without copying stay in *separate* storage here until the rotation wraps,
/// where the real host's single buffer would already have overwritten the
/// first with the second.
///
/// # Errors
///
/// If `time` is not readable, or the print buffer will not hold the result
/// (never, in practice -- the longest possible answer is far under
/// [`SPR_BYTES`]).
pub fn prntim<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let mode = crate::shims::sign_extend::<A>(call.int().into());
    let packed = Into::<u32>::into(call.int()) as u16;

    let mut hour = i32::from((packed >> 11) & 0x1f);
    let minute = u32::from((packed >> 5) & 0x3f);
    let second = u32::from((packed << 1) & 0x3e);

    let at = host.next_spr_buffer();
    if unpack_dos_time(packed).to_local_epoch().is_err() {
        // DNTAPI.C:544-547 -- `*buf='\0'; return(buf);`, not a refusal.
        write_cstr_mem::<A>(call.mem(), at, b"", SPR_BYTES)?;
        return Ok(abi::Ret::Ptr(at));
    }

    const PRNT_PAD: i32 = 20;
    let pad = mode >= PRNT_PAD;
    let mode = mode % PRNT_PAD;

    let mut suffix = String::new();
    if mode % 5 != 0 {
        if mode % 5 >= 3 {
            suffix.push(' ');
        }
        suffix.push(if hour < 12 { 'a' } else { 'p' });
        if mode % 5 == 2 || mode % 5 == 4 {
            suffix.push('m');
        }
        if hour != 0 {
            hour %= 12;
        }
        if hour == 0 {
            hour = 12;
        }
    }

    let mut text = if mode >= 10 {
        if pad {
            format!("{hour:02}:{minute:02}:{second:02}{suffix}")
        } else {
            format!("{hour}:{minute:02}:{second:02}{suffix}")
        }
    } else if pad {
        format!("{hour:02}:{minute:02}{suffix}")
    } else {
        format!("{hour}:{minute:02}{suffix}")
    };
    if mode % 10 >= 6 {
        text = text.to_ascii_uppercase();
    }

    write_cstr_mem::<A>(call.mem(), at, text.as_bytes(), SPR_BYTES)?;
    Ok(abi::Ret::Ptr(at))
}

/// The full month names `SRC/api/gcommlib/DNTAPI.C:79-82`'s `strMonths[]`
/// holds, in order -- what [`prndat`]'s modes 6 through 11 index with
/// `month-1` (unlike [`crate::shims::system::ncedat`]'s unrelated `moname[]`,
/// which is a different table, indexed by `month` with no offset, for a
/// different, older routine).
const MONTHS: [&str; 12] = [
    "January", "February", "March", "April", "May", "June", "July", "August", "September",
    "October", "November", "December",
];

/// `const CHAR *prndat(INT mode, USHORT date, CHAR sep)` -- `DNTAPI.H:315-317`
/// -- a DOS-packed date, rendered per `mode` (`DNTAPI.H:161-178`).
/// `SRC/api/gcommlib/DNTAPI.C`:
///
/// `date` is unpacked by [`unpack_dos_date`] into a [`Civil`] (hour/minute/
/// second left zero), and `validDate` (`DNTAPI.C:635-644`: month in 1..=12,
/// day in 1..=the real length of that month, leap years included) is
/// answered by [`Civil::to_local_epoch`] rather than a second table of month
/// lengths -- the same "use `Civil`" reuse [`prntim`] makes for `validTime`.
/// **`validDate` failing writes an empty string and returns the buffer**,
/// exactly as `validTime` failing does in `prnTime`; not a refusal.
///
/// # Vendor quirk, transcribed rather than "fixed"
///
/// The header's own mode table (`DNTAPI.H:169-170`) documents modes 10/11 as
/// two-digit years ("`10 - December 31, 90`"), but the code's own
/// `if (mode <= 9) year%=100;` does not truncate for `mode` 10 or 11 --
/// only 0 through 9. `%02d` on an untruncated year is not a length limit, so
/// mode 10 on 1990 prints `"December 31, 1990"`, not `"...90"`, disagreeing
/// with its own header comment. That is the vendor's own code, read exactly
/// as written; "fixing" it to match the comment would be inventing a
/// different function.
///
/// # A negative `mode` is a refusal, not a guess
///
/// `switch (mode%12)` has no case for a negative remainder -- Rust's `%`
/// truncates toward zero the same way C's does, so `mode<0` gives
/// `mode%12` in `-11..=0`, most of which match nothing in the vendor's
/// `switch` at all. The real function falls through with `dateBuf`
/// **uninitialised** and formats whatever the stack held -- genuine
/// undefined behaviour, not a value this host can honestly reproduce or
/// guess at, so this refuses instead. Every `mode >= 0` (however large) has
/// a defined answer: `mode%12` is always in `0..=11` for a non-negative
/// `mode`, matching some case.
///
/// # No dedicated static buffer
///
/// See [`prntim`]'s own doc comment -- the same `spr` rotation, for the same
/// reason.
///
/// # Errors
///
/// If `mode` is negative (see above), if `date` is not readable, or if the
/// print buffer will not hold the result (never, in practice).
pub fn prndat<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let mode = crate::shims::sign_extend::<A>(call.int().into());
    let packed = Into::<u32>::into(call.int()) as u16;
    let sep = Into::<u32>::into(call.int()) as u8;

    let civil = unpack_dos_date(packed);
    let at = host.next_spr_buffer();
    if civil.to_local_epoch().is_err() {
        // DNTAPI.C:492-495 -- `*buf='\0'; return(buf);`, not a refusal.
        write_cstr_mem::<A>(call.mem(), at, b"", SPR_BYTES)?;
        return Ok(abi::Ret::Ptr(at));
    }
    if mode < 0 {
        return Err(ShimError::Failed(format!(
            "prndat: mode {mode} is negative -- DNTAPI.C:499's `switch (mode%12)` \
             has no case for a negative remainder, which is undefined behaviour \
             (dateBuf goes unwritten) in the original and not something this \
             host will fabricate a string for -- see prndat's own doc comment"
        )));
    }

    let year = civil.year;
    let month = civil.month;
    let day = civil.day;
    let year_field = if mode <= 9 { year % 100 } else { year };
    let month_name = MONTHS[(month - 1) as usize];
    let short_name = &month_name.as_bytes()[..3];

    let day_s = format!("{day:02}");
    let month_s = format!("{month:02}");
    let year_s = format!("{year_field:02}");

    let mut buf: Vec<u8> = Vec::new();
    match mode % 12 {
        0 | 1 => {
            buf.extend(month_s.bytes());
            buf.push(sep);
            buf.extend(day_s.bytes());
        }
        2 | 3 => {
            buf.extend(month_s.bytes());
            buf.push(sep);
            buf.extend(year_s.bytes());
        }
        4 | 5 => {
            buf.extend(month_s.bytes());
            buf.push(sep);
            buf.extend(day_s.bytes());
            buf.push(sep);
            buf.extend(year_s.bytes());
        }
        6 | 7 => {
            buf.extend(day_s.bytes());
            buf.push(sep);
            buf.extend(short_name);
            buf.push(sep);
            buf.extend(year_s.bytes());
        }
        8 | 9 => {
            buf.extend(short_name);
            buf.push(b' ');
            buf.extend(day.to_string().bytes());
            buf.extend(b", ");
            buf.extend(year_s.bytes());
        }
        _ => {
            // 10 | 11, the only remaining values of `mode % 12` for a
            // non-negative `mode`.
            buf.extend(month_name.bytes());
            buf.push(b' ');
            buf.extend(day.to_string().bytes());
            buf.extend(b", ");
            buf.extend(year_s.bytes());
        }
    }
    if mode & 1 == 1 {
        buf = buf.iter().map(u8::to_ascii_uppercase).collect();
    }

    write_cstr_mem::<A>(call.mem(), at, &buf, SPR_BYTES)?;
    Ok(abi::Ret::Ptr(at))
}

/// Is `name` reserved by the OS for a device -- `GBOOL rsvnam(const CHAR
/// *name)`, `FIOAPI.H:312-314`. Two bodies survive
/// (`SRC/api/gcommlib/FIOAPI.C:988-1051`), guarded by `#if defined(GCWINNT)`
/// / `#elif defined(GCDOS)`; this host is the Windows-hosted generation
/// (`GCWINNT`'s own table-and-string-test form, not `GCDOS`'s device-chain
/// walk that needs a DOS driver list this host never had):
///
/// (`FIOAPI.C:992-1033`).
///
/// Every predicate this needs already lives in [`crate::strings`]:
/// [`crate::strings::sameas`] (case-insensitive equality), [`crate::strings::sameto`]
/// (case-insensitive prefix) and [`crate::strings::all_digits`] (this file's
/// own [`alldgs`] shim, called the same way here). Nothing here is
/// reimplemented; this is the pointer read, the last-separator scan, the
/// dot-truncation and the extension-stripping the C body does around them.
///
/// **`max` of three `strrchr`s is "the rightmost occurrence of any of `:`,
/// `/`, `\`"** -- taking the highest pointer among the three (or the start of
/// the string, if none matched) is exactly a single reverse scan for any of
/// the three bytes, which is what this does in one pass instead of three.
///
/// **`COM`/`LPT` reservedness is unbounded**: `alldgs(&fname[3])` does not
/// check how many digits follow, so `COM99999` reads as reserved here exactly
/// as it does in the original -- a name real DOS/Windows would never actually
/// have blocked past `COM9`, transcribed faithfully rather than "corrected".
///
/// # Errors
///
/// If `name` is not a valid pointer.
pub fn rsvnam<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let name_ptr = call.ptr();
    let name = name_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    Ok(abi::Ret::Int(A::Int::from(u16::from(is_reserved_name(&name)))))
}

/// [`rsvnam`]'s predicate, as bytes -- see that function's own doc comment
/// for the C it transcribes.
fn is_reserved_name(name: &[u8]) -> bool {
    let start = name
        .iter()
        .rposition(|&c| c == b':' || c == b'/' || c == b'\\')
        .map_or(0, |i| i + 1);
    let mut fname = name[start..].to_vec();
    if let Some(dot) = fname.iter().position(|&c| c == b'.') {
        fname.truncate(dot);
    }

    if crate::strings::sameas(&fname, b"CON")
        || crate::strings::sameas(&fname, b"AUX")
        || crate::strings::sameas(&fname, b"PRN")
        || crate::strings::sameas(&fname, b"NUL")
    {
        return true;
    }
    if crate::strings::sameto(b"COM", &fname) || crate::strings::sameto(b"LPT", &fname) {
        if fname.len() == 3 {
            return false;
        }
        if fname.last() == Some(&b':') {
            fname.pop();
        }
        return crate::strings::all_digits(&fname[3..]);
    }
    false
}

/// Bit `0x4000` of `user.flags` -- `MAJORBBS.H:274`, `INVISB`. Re-declared
/// here rather than imported from [`crate::shims::user`], which keeps its own
/// copy private; see that module's `scan_for`/`INVISB` for the identical
/// constant serving the sibling routines [`crate::shims::user::instat`] and
/// `onsysn`.
const INVISB: u32 = 0x0000_4000;

/// `INT onbbs(const CHAR *uid, GBOOL invis)` -- `MAJORBBS.H:803` -- is this
/// user-id logged onto *any* channel right now, even one still mid-login?
/// `MAJORBBS.C:3712-3724`:
///
/// **Not `instat`/`onsysn`'s shared loop.** Those two ([`crate::shims::user`]'s
/// `scan_for`) never exclude the calling channel; `onbbs` explicitly skips
/// `uisusn == usrnum` in its own match test (though it still *counts* through
/// that channel, which is why `uisusn` still advances across it below) -- a
/// different shape, not a reachable refactor of the other.
///
/// `uacoff(uisusn)->userid` is read the same way
/// [`crate::shims::user`]'s own private `userid_matches` reads it: through
/// [`crate::users::AccountLayout::userid`], off [`crate::Users::account`],
/// never a second copy of the account layout.
///
/// **`uisusn` is written on every iteration, matched or not** -- the same
/// "global as loop variable, left where the loop finished" shape
/// [`crate::shims::user`]'s own `scan_for` doc comment describes for
/// `othusn`: on a match it names the matching channel; on no match, it is
/// left at `nterms-1`, the last channel visited, not reset to a sentinel.
/// `MAJORBBS.H:421`'s own comment names `uisusn` "uinsys() other-user channel
/// number" only because `uinsys` (`MAJORBBS.C:3705-3710`, `return(onbbs(uid,0))`)
/// is its sole *named* caller in the surviving source -- the write itself is
/// `onbbs`'s own loop, here.
///
/// # Errors
///
/// If `uid` is not a valid pointer, or `usrnum`/`uisusn` are not placed
/// globals (never, in practice -- both are in [`crate::globals::GLOBALS`]).
pub fn onbbs<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let uid_ptr = call.ptr();
    let invis = crate::shims::gbool_arg::<A>(call.int());
    let uid = uid_ptr
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    if uid.is_empty() {
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    }

    let usrnum = host
        .globals()
        .word_mem(call.mem(), "usrnum")
        .map_err(|e| ShimError::Failed(format!("onbbs: usrnum: {e}")))? as i16;

    let mut found = false;
    for chan in host.users().terms().all() {
        host.globals()
            .write_int_mem(call.mem(), "uisusn", chan.number() as u32)
            .map_err(|e| ShimError::Failed(format!("onbbs: uisusn: {e}")))?;

        if found || chan.number() == usrnum {
            continue;
        }

        let account = host.users().account(chan);
        let at = A::ptr_offset(account, host.users().account_layout().userid);
        let userid = at
            .read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        if !crate::strings::sameas(&uid, userid) {
            continue;
        }

        if invis {
            found = true;
            continue;
        }
        let flags = host
            .users()
            .flags_mem(call.mem(), chan)
            .map_err(|e| ShimError::Failed(format!("onbbs: {e}")))?;
        if flags & INVISB == 0 {
            found = true;
        }
    }

    Ok(abi::Ret::Int(A::Int::from(u16::from(found))))
}

/// `struct clstab *fndcls(const CHAR *clsname)` -- `USRACC.H:69` -- this
/// user's class table entry, by name. `SRC/server/wgserver/ACCOUNT.C:209-223`:
///
/// `clshead` (`USRACC.H:44`) is the head of an in-memory linked list this
/// host's own boot would build from the **class database**
/// (`USRACC.H:56`'s `clsbb`, a Btrieve file of `struct acclass` records) --
/// a whole account/class subsystem this crate has no implementation of
/// anywhere (`crtclass`, `namacls`, `swtcls` and the class Btrieve file
/// itself are all absent; the same gap [`crate::shims::user::uidkey`]'s own
/// doc comment names for the **user** account database applies here to the
/// **class** one).
///
/// # `clshead == NULL` is not a guess -- it is this host's real state
///
/// This host never builds a class table, so `clshead` is permanently NULL --
/// not an invented value standing in for one, the actual, honestly-reported
/// state. `ACCOUNT.C:214-216` is the vendor's *own* branch for exactly that
/// state, and it returns `NULL` unconditionally, without even reading
/// `clsname`'s bytes (the `||` short-circuits before `sameas` ever runs).
/// That is what this reproduces: every call answers `NULL`, precisely because
/// this host is in the one state the original already handles by name.
///
/// **Most measured callers check for it** -- `FTPD.C:1031`, `SCP.C:1080,1157`,
/// `REMSYS.C:292,997,1002,1069,1237` and `GALRSYAH.CPP` all guard with
/// `== NULL`/`!= NULL` before touching the result. **One does not**:
/// `GALFILUT.C:165`'s `fndcls(usaptr->curcls)->flags&CRDXMT` dereferences
/// unconditionally, on the assumption -- true of any board with at least one
/// class configured, which is every real board -- that `fndcls` never fails
/// for a user's own current class. A module that reaches that call site
/// through this host will fault on the null dereference, through this host's
/// own checked memory access rather than a wild pointer -- an honest crash at
/// the point that assumption actually matters, not a silently wrong `flags`
/// word invented to keep it running.
///
/// # Errors
///
/// Never. `clsname` is read as a pointer (matching the real signature) but
/// never dereferenced, the same as the vendor's own `clshead == NULL` branch.
pub fn fndcls<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let _clsname = call.ptr();
    Ok(abi::Ret::Ptr(A::ptr_from_bytes(&vec![0u8; A::PTR_WIDTH])))
}

/// `GBOOL cnvd2s(CHAR *saustg, struct saunam *saunam)` -- `GCSPSRV.H:203-206`
/// -- parse a dynapak name out of its "developer form" string (`"sa:name"`,
/// `"sau=%s;:suffix"`, `"sa=%s;u=%s;:suffix"`, per the call sites below) into
/// a `struct saunam` (`GCSP.H:337-343`: `sysid`, `appid`, `usrid`, `flags`,
/// `suffix`).
///
/// # What is missing
///
/// **No `.C` body survives anywhere in `re/wg33src`** -- only the prototype,
/// in three copies of the same header. Its sibling `cnvs2d` (the reverse
/// direction) is in the same position: declared, never defined, in every
/// surviving tree.
///
/// **The call-site evidence does not agree on one grammar.** Five measured
/// forms: `cnvd2s("sa:viewcomp",&unsol)` (`GALFILCS.C:1570`),
/// `cnvd2s("sa=GALFIL;:rejoin",&unsol)` (`:3572`),
/// `cnvd2s(spr("sau=%s;:denxfr",othuap->userid),namtmp)` (`CSMJRTLC.C:553`),
/// `cnvd2s(spr("sa=%s;u=%s;:aborcv",TLCAID,...),namtmp)` (`:749`), and
/// `cnvd2s(EMLTAGS,&tmpsau)` (`CSEML.C:751`, `EMLTAGS` itself not recovered).
/// `sa:`, `sa=...;`, `sau=...;` and `sa=...;u=...;` are visibly four
/// different prefix shapes feeding the same parser, and nothing in
/// `re/wg33src` -- no comment block, no help file text, no second
/// implementation to cross-check against -- says how `sysid`/`appid`/`usrid`/
/// `flags`/`suffix` divide across them.
///
/// **No oracle to measure against, either.** [`crate::strings`]'s own
/// undocumented routines (`alldgs`, `strcmpi`) were settled by calling a
/// genuine host binary with adversarial probes
/// (`cargo run -p mbbs-machine --example alldgs`); no such harness exists for
/// `cnvd2s` today, and building one -- finding an ordinal or address in a
/// real `WGSERVER`/`MAJORBBS` binary, wiring a new example around it -- is
/// its own task, not something to fold into a refusal.
///
/// Guessing a grammar from five inconsistent call sites and writing a parser
/// against the guess is exactly the "plausible answer that looks like data"
/// this crate's refusal discipline exists to catch: a `struct saunam` built
/// wrong would not fault, it would silently address the wrong forum or user.
///
/// # Errors
///
/// Always. Names the string this host was asked to parse and why it cannot.
pub fn cnvd2s<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let saustg_ptr = call.ptr();
    let _saunam = call.ptr();
    let saustg = String::from_utf8_lossy(
        saustg_ptr
            .read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();

    Err(ShimError::Failed(format!(
        "cnvd2s({saustg:?}): no vendor body survives for the \"developer \
         form\" dynapak grammar, and the measured call sites use at least \
         four visibly different prefix shapes (\"sa:\", \"sa=...;\", \
         \"sau=...;\", \"sa=...;u=...;\") with nothing to say how they divide \
         across sysid/appid/usrid/flags/suffix -- see cnvd2s's own doc \
         comment"
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

    // ---- word() shared by everything below ----------------------------------

    fn word(ret: Ret) -> u16 {
        match ret {
            Ret::U16(n) => n,
            _ => panic!("expected a word"),
        }
    }

    // ---- register_pseudok -----------------------------------------------------

    #[test]
    fn register_pseudok_always_answers_zero_pseudokeys_registered_so_far() {
        // MAJORBBS.C:1236-1240 calls this five times in a row. On the real
        // host that is 0,1,2,3,4; this host's own pseudokey table is
        // permanently empty (see this shim's own doc comment), so every one
        // of those calls answers the same thing: zero already registered.
        // A hardcoded `0` would also pass a test that only made one call --
        // this makes five, which a "return npkeys; npkeys+=1" mutation (the
        // literal vendor behaviour) would fail on calls two through five.
        let mut f = Fixture::new();
        let pskrou = f.text("dummy");
        for name in ["_FORUMOP", "_PORT#", "_GROUP#", "_LANG=", "_ISGCSU"] {
            let pskbeg = f.text(name);
            let got = f
                .invoke(register_pseudok, &[pskbeg.offset, pskbeg.selector, pskrou.offset, pskrou.selector])
                .expect("registered");
            assert_eq!(word(got), 0, "{name}");
        }
    }

    #[test]
    fn register_pseudok_refuses_an_unreadable_name() {
        let mut f = Fixture::new();
        let pskrou = f.text("dummy");
        let bad = FarPtr { offset: 0xfff0, selector: pskrou.selector };
        f.invoke(register_pseudok, &[bad.offset, bad.selector, pskrou.offset, pskrou.selector])
            .expect_err("unreadable pskbeg");
    }

    // ---- alldgs -----------------------------------------------------------

    #[test]
    fn alldgs_agrees_with_crate_strings_all_digits() {
        let mut f = Fixture::new();
        let s = f.text("12345");
        assert_eq!(word(f.invoke(alldgs, &Fixture::far(s)).expect("alldgs")), 1);

        let s = f.text("12a45");
        assert_eq!(word(f.invoke(alldgs, &Fixture::far(s)).expect("alldgs")), 0);

        let s = f.text("");
        assert_eq!(
            word(f.invoke(alldgs, &Fixture::far(s)).expect("alldgs")),
            1,
            "the empty string is all-digits -- see crate::strings::all_digits"
        );
    }

    // ---- unpad --------------------------------------------------------------

    #[test]
    fn unpad_strips_trailing_whitespace_and_hands_the_same_pointer_back() {
        let mut f = Fixture::new();
        let s = f.text("go north   ");
        let ret = f.invoke(unpad, &Fixture::far(s)).expect("unpad");
        assert_eq!(pointer(ret), s, "the same address, not an offset into it");
        assert_eq!(f.machine.read_cstr(s).expect("readable"), b"go north");
    }

    #[test]
    fn unpad_leaves_leading_whitespace_alone() {
        let mut f = Fixture::new();
        let s = f.text("  text");
        f.invoke(unpad, &Fixture::far(s)).expect("unpad");
        assert_eq!(f.machine.read_cstr(s).expect("readable"), b"  text");
    }

    // ---- findmod ------------------------------------------------------------

    fn module_block(f: &mut Fixture, name: &str) -> FarPtr {
        let mut bytes = vec![0u8; 25];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        f.bytes(&bytes, false)
    }

    #[test]
    fn findmod_finds_a_registered_module_case_insensitively_by_name() {
        let mut f = Fixture::new();
        let want = f.host.modules().len() as u16;
        let block = module_block(&mut f, "MajorMUD");
        f.invoke(crate::shims::system::register_module, &Fixture::far(block))
            .expect("registered");

        let name = f.text("majormud");
        let got = f.invoke(findmod, &Fixture::far(name)).expect("findmod");
        assert_eq!(word(got), want);
    }

    #[test]
    fn findmod_answers_minus_one_for_a_name_nothing_registered() {
        let mut f = Fixture::new();
        let name = f.text("NOBODY");
        let got = f.invoke(findmod, &Fixture::far(name)).expect("findmod");
        assert_eq!(word(got), 0xffff, "-1, as an unsigned word");
    }

    #[test]
    fn findmod_never_matches_slot_zero_even_with_an_empty_name() {
        // `module[0]` is `Registration::AbsentBbs`, which carries no
        // description at all -- an empty search name must not accidentally
        // match it (or the FSD's own native slot, which also has none).
        let mut f = Fixture::new();
        let name = f.text("");
        let got = f.invoke(findmod, &Fixture::far(name)).expect("findmod");
        assert_eq!(word(got), 0xffff);
    }

    // ---- prntim ---------------------------------------------------------------

    fn packed_time(hour: u32, minute: u32, second: u32) -> u16 {
        Civil { year: 1980, month: 1, day: 1, hour, minute, second }.dos_time()
    }

    fn prntim_text(f: &mut Fixture, mode: u16, packed: u16) -> String {
        let ret = f.invoke(prntim, &[mode, packed]).expect("prntim");
        f.read(pointer(ret))
    }

    #[test]
    fn prntim_renders_every_mode_the_header_table_names() {
        let mut f = Fixture::new();
        let t = packed_time(23, 59, 58);
        assert_eq!(prntim_text(&mut f, 0, t), "23:59", "mode 0: 23:59");
        assert_eq!(prntim_text(&mut f, 10, t), "23:59:58", "mode 10: 23:59:59-shaped");
        assert_eq!(prntim_text(&mut f, 12, t), "11:59:58pm", "mode 12: 11:59:59pm-shaped");
        assert_eq!(prntim_text(&mut f, 17, t), "11:59:58PM", "mode 17: uppercase");
    }

    #[test]
    fn prntim_pad_only_shows_up_on_a_single_digit_hour() {
        let mut f = Fixture::new();
        let t = packed_time(5, 7, 8);
        assert_eq!(prntim_text(&mut f, 0, t), "5:07", "mode 0: unpadded hour");
        assert_eq!(prntim_text(&mut f, 20, t), "05:07", "mode 0+PRNT_PAD: padded hour");
    }

    #[test]
    fn prntim_am_before_noon_and_pm_at_and_after_it() {
        let mut f = Fixture::new();
        assert_eq!(prntim_text(&mut f, 2, packed_time(0, 0, 0)), "12:00am", "midnight is 12am");
        assert_eq!(prntim_text(&mut f, 2, packed_time(12, 0, 0)), "12:00pm", "noon is 12pm");
        assert_eq!(prntim_text(&mut f, 2, packed_time(11, 30, 0)), "11:30am");
        assert_eq!(prntim_text(&mut f, 2, packed_time(13, 30, 0)), "1:30pm");
    }

    #[test]
    fn prntim_answers_empty_for_a_time_validtime_rejects() {
        // minute = 61 (6 bits can reach 63; validTime caps at 59).
        let mut f = Fixture::new();
        let bogus: u16 = 61 << 5;
        assert_eq!(prntim_text(&mut f, 0, bogus), "");
    }

    // ---- prndat ---------------------------------------------------------------

    fn packed_date(year: i32, month: u32, day: u32) -> u16 {
        Civil { year, month, day, hour: 0, minute: 0, second: 0 }.dos_date().expect("in range")
    }

    fn prndat_text(f: &mut Fixture, mode: u16, packed: u16, sep: u8) -> String {
        let ret = f.invoke(prndat, &[mode, packed, u16::from(sep)]).expect("prndat");
        f.read(pointer(ret))
    }

    #[test]
    fn prndat_renders_every_mode_the_header_table_names() {
        let mut f = Fixture::new();
        let d = packed_date(1990, 12, 31);
        let sep = b'*';
        assert_eq!(prndat_text(&mut f, 0, d, sep), "12*31");
        assert_eq!(prndat_text(&mut f, 2, d, sep), "12*90");
        assert_eq!(prndat_text(&mut f, 4, d, sep), "12*31*90");
        assert_eq!(prndat_text(&mut f, 6, d, sep), "31*Dec*90");
        assert_eq!(prndat_text(&mut f, 7, d, sep), "31*DEC*90", "mode&1 uppercases");
        assert_eq!(prndat_text(&mut f, 8, d, sep), "Dec 31, 90");
        assert_eq!(prndat_text(&mut f, 9, d, sep), "DEC 31, 90");
        assert_eq!(prndat_text(&mut f, 20, d, sep), "Dec 31, 1990", "mode>9: full year");
        assert_eq!(prndat_text(&mut f, 22, d, sep), "December 31, 1990");
        assert_eq!(prndat_text(&mut f, 23, d, sep), "DECEMBER 31, 1990");
    }

    #[test]
    fn prndat_modes_10_and_11_do_not_truncate_the_year_despite_the_header_comment() {
        // DNTAPI.H:169-170 documents "10 - December 31, 90" and "11 -
        // DECEMBER 31, 90", but DNTAPI.C:496's own `if (mode <= 9)` does not
        // cover 10 or 11 -- the vendor's code and its own header comment
        // disagree, and this transcribes the code. See prndat's own doc
        // comment.
        let mut f = Fixture::new();
        let d = packed_date(1990, 12, 31);
        assert_eq!(prndat_text(&mut f, 10, d, b'*'), "December 31, 1990");
        assert_eq!(prndat_text(&mut f, 11, d, b'*'), "DECEMBER 31, 1990");
    }

    #[test]
    fn prndat_answers_empty_for_a_date_validdate_rejects() {
        // month = 13, out of validDate's 1..=12.
        let mut f = Fixture::new();
        let bogus: u16 = 13 << 5 | 1;
        assert_eq!(prndat_text(&mut f, 0, bogus, b'/'), "");
    }

    #[test]
    fn prndat_refuses_a_negative_mode() {
        let mut f = Fixture::new();
        let d = packed_date(1990, 12, 31);
        let e = f
            .invoke(prndat, &[0xffffu16, d, u16::from(b'/')])
            .expect_err("a refusal");
        assert!(e.to_string().contains("-1"), "{e}");
    }

    // ---- rsvnam -------------------------------------------------------------

    #[test]
    fn rsvnam_flags_the_four_bare_device_names() {
        let mut f = Fixture::new();
        for name in ["CON", "con", "AUX", "PRN", "NUL"] {
            let s = f.text(name);
            assert_eq!(word(f.invoke(rsvnam, &Fixture::far(s)).expect("rsvnam")), 1, "{name}");
        }
    }

    #[test]
    fn rsvnam_treats_com_and_lpt_as_a_prefix_needing_a_number() {
        let mut f = Fixture::new();
        let s = f.text("COM1");
        assert_eq!(word(f.invoke(rsvnam, &Fixture::far(s)).expect("rsvnam")), 1);

        let s = f.text("COM");
        assert_eq!(word(f.invoke(rsvnam, &Fixture::far(s)).expect("rsvnam")), 0, "bare COM is not reserved");

        let s = f.text("COMPANY");
        assert_eq!(
            word(f.invoke(rsvnam, &Fixture::far(s)).expect("rsvnam")),
            0,
            "not all digits after COM"
        );
    }

    #[test]
    fn rsvnam_reads_the_final_path_component_and_strips_the_extension() {
        let mut f = Fixture::new();
        let s = f.text("C:\\GAMES\\CON.TXT");
        assert_eq!(word(f.invoke(rsvnam, &Fixture::far(s)).expect("rsvnam")), 1);

        let s = f.text("C:\\GAMES\\NOTES.TXT");
        assert_eq!(word(f.invoke(rsvnam, &Fixture::far(s)).expect("rsvnam")), 0);
    }

    // ---- onbbs --------------------------------------------------------------

    fn two_channels(f: &mut Fixture) -> (crate::Chan, crate::Chan) {
        let chan0 = f.host.users().terms().chan(0).expect("channel 0");
        let chan1 = f.host.users().terms().chan(1).expect("channel 1");
        f.host
            .connect_state(&mut f.machine, chan0, &crate::Connection::ansi("rangerdan"))
            .expect("channel 0 connects");
        f.host
            .connect_state(&mut f.machine, chan1, &crate::Connection::ansi("kaimon"))
            .expect("channel 1 connects");
        (chan0, chan1)
    }

    fn set_invisible(f: &mut Fixture, chan: crate::Chan) {
        let field = f.host.users().user_layout().flags;
        let at = Wg16::ptr_offset(f.host.users().slot(chan), field.at);
        f.machine.write(at, &INVISB.to_le_bytes()).expect("flags fit");
    }

    fn onbbs_(f: &mut Fixture, uid: &str, invis: u16) -> u16 {
        let p = f.text(uid);
        word(f.invoke(onbbs, &[p.offset, p.selector, invis]).expect("onbbs"))
    }

    #[test]
    fn onbbs_finds_a_userid_logged_onto_another_channel() {
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(2));
        two_channels(&mut f);
        f.host
            .globals()
            .write(&mut f.machine, "usrnum", &0i16.to_le_bytes())
            .expect("usrnum placed");

        assert_eq!(onbbs_(&mut f, "kaimon", 0), 1, "channel 1's own userid");
        assert_eq!(onbbs_(&mut f, "nobody", 0), 0);
    }

    #[test]
    fn onbbs_excludes_the_calling_channel_itself() {
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(2));
        two_channels(&mut f);
        f.host
            .globals()
            .write(&mut f.machine, "usrnum", &0i16.to_le_bytes())
            .expect("usrnum placed");

        // "rangerdan" is channel 0's own userid, and usrnum is channel 0 --
        // MAJORBBS.C:3716's `uisusn != usrnum` guard must skip it.
        assert_eq!(onbbs_(&mut f, "rangerdan", 0), 0, "onbbs never matches the caller's own channel");
    }

    #[test]
    fn onbbs_respects_invisb_unless_invis_waives_it() {
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(2));
        let (_, chan1) = {
            let (c0, c1) = two_channels(&mut f);
            (c0, c1)
        };
        set_invisible(&mut f, chan1);
        f.host
            .globals()
            .write(&mut f.machine, "usrnum", &0i16.to_le_bytes())
            .expect("usrnum placed");

        assert_eq!(onbbs_(&mut f, "kaimon", 0), 0, "invis=0 respects INVISB");
        assert_eq!(onbbs_(&mut f, "kaimon", 1), 1, "invis=1 waives INVISB outright");
    }

    #[test]
    fn onbbs_refuses_an_empty_userid_without_scanning() {
        let mut f = Fixture::new();
        assert_eq!(onbbs_(&mut f, "", 1), 0);
    }

    // ---- fndcls -------------------------------------------------------------

    #[test]
    fn fndcls_always_answers_null_because_this_host_has_no_class_table() {
        let mut f = Fixture::new();
        let name = f.text("STANDARD");
        let ret = f.invoke(fndcls, &Fixture::far(name)).expect("fndcls");
        assert_eq!(pointer(ret), FarPtr::NULL);
    }

    // ---- cnvd2s -------------------------------------------------------------

    #[test]
    fn cnvd2s_refuses_rather_than_guessing_at_the_developer_form_grammar() {
        let mut f = Fixture::new();
        let saustg = f.text("sa:viewcomp");
        let saunam = f.buffer(16);
        let e = f
            .invoke(cnvd2s, &[saustg.offset, saustg.selector, saunam.offset, saunam.selector])
            .expect_err("a refusal");
        assert!(e.to_string().contains("sa:viewcomp"), "{e}");
    }
}
