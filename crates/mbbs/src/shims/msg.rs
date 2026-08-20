//! Message files, and the options a module reads out of them.
//!
//! Signatures from `MCVAPI.H`, except `prfmsg` which is `GCOMM.H:811`:
//! `opnmsg` `:54`, `clsmsg` `:66`, `rstmbk` `:74`, `numopt` `:89`, `ynopt`
//! `:95`, `stgopt` `:103`, `tokopt` `:112`. `setmbk` has no prototype of its
//! own there -- `:43` declares the `curmbk` it sets.
//!
//!
//! The file format and what a value is are [`crate::msg`]'s; this is the part
//! that knows about the module. `rawmsg` and `getasc` are both implemented:
//! The Rose imports `getasc` at six sites, and this host serves an API
//! surface rather than one module's needs, which is reason enough for
//! `rawmsg` on its own. `listing` -- despite the name -- is `FILEXFER.H:78`,
//! listing an ASCII file to the user's screen, and belongs with file
//! transfer.
//!
//! # A misconfigured board is refused, not guessed at
//!
//! `numopt` outside its floor and ceiling, `ynopt` on something that is not yes
//! or no, `tokopt` on a token that is in no list: the real host had an answer
//! for each of these and every answer was a number the module could not tell
//! from a real one. Here they stop the module and name the option, which is the
//! same rule the rest of the crate is under. It is a deliberate difference from
//! the real host, and the only one in this file.

// `Machine`/`Ret` are now named only by this file's `#[cfg(test)]`
// `_wg16` bridges -- production code reaches every routine here through
// its generic `Call<A>`/`Host<A>` core instead, per `shims::mod`'s own
// `call` doc comment.
#[cfg(test)]
use mbbs_machine::m16::{Machine, Ret};

// `FarPtr` is named by exactly one item now -- the `#[cfg(test)]` [`message`]
// facade below -- so the import follows it rather than sitting unused in a
// release build. The `_wg16` siblings deal in `Machine` and `Ret` and never
// spell a pointer type: that is the conversion working.
#[cfg(test)]
use mbbs_machine::m16::FarPtr;
use mbbs_machine::ptr::ModulePtr;

use crate::Host;
use crate::abi::{self, Abi, Call};
// Named only by the same `#[cfg(test)]` `message` facade `FarPtr` above is.
#[cfg(test)]
use crate::abi::Wg16;
use crate::fmt::format_call;
use crate::msg::{MsgFile, value};
use crate::shims::{ShimError, text};

/// `FILE *opnmsg(char *mcvfil)` -- open a module's message file, and read
/// options from it from now on.
///
/// The module names it without a path and in whatever case it likes, which is
/// what [`Host::find`] is for. The result is opaque to the module: it goes to
/// `setmbk` and to `clsmsg` and nowhere else.
///
/// **Opening makes it current, exactly as `setmbk` would.** Nothing in
/// `GCOMM.H` says so and `MSGUTL.C` does not survive, but Galacticomm's own
/// code settles it: `ACCOUNT.C:107` opens `bbsacct.mcv` and then reads
/// `ynopt(PESTER)` and four `numopt`s off it without a `setmbk` anywhere
/// between. MajorMUD relies on the other half of the same fact -- its
/// initialisation opens a file, reads it, and calls `rstmbk` to put back what
/// was current before, which only balances if opening saved it.
///
/// Generic (Task 5): [`Messages::open_mem`](crate::msg::Messages::open_mem)
/// is already `impl<A: Abi> Messages<A>` -- converting this routine is
/// routing through that generic core instead of its `Wg16` facade
/// ([`Messages::open`](crate::msg::Messages::open)). `host.find`/`host.root`
/// have no `A`-dependent behaviour at all (`Host<A>::find` was already
/// `impl<A: Abi> Host<A>`, and `root` is a bare `PathBuf`).
pub fn opnmsg<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let mcvfil = call.ptr();
    let named = String::from_utf8_lossy(
        mcvfil
            .read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();
    let name = source_name(&named);

    let path = host.find(&name).ok_or_else(|| {
        ShimError::Failed(format!(
            "the module asked for {named}; no {name} in {}",
            host.root.display()
        ))
    })?;
    let bytes = std::fs::read(&path)
        .map_err(|e| ShimError::Failed(format!("{}: {e}", path.display())))?;
    let file = MsgFile::parse(&name, &bytes).map_err(|e| ShimError::Failed(e.to_string()))?;

    let cookie = host
        .messages
        .open_mem(call.mem(), &name, &file)
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    let previous = current_mem(call.mem(), host)?;
    host.messages.push(previous);
    set_current_mem(call.mem(), host, cookie)?;
    Ok(abi::Ret::Ptr(cookie))
}

/// The file to read for the message file a module named.
///
/// `opnmsg(char *mcvfil)` names the **compiled** file, and means it: MajorMUD's
/// initialisation asks for `WCCMMHLP.MCV`. What ships beside the module is
/// `WCCMMHLP.MSG`, because the real host compiled one into the other when the
/// sysop installed it and MajorMUD's distribution predates that step.
///
/// So the name is translated and the format is not implemented. A module that
/// ships only a `.MCV` gets a refusal naming both what it asked for and what
/// was looked for, which is the accurate account of what this host is missing.
fn source_name(named: &str) -> String {
    let stem = named.rsplit_once('.').map_or(named, |(stem, _)| stem);
    format!("{stem}.MSG")
}

/// `void clsmsg(FILE *mb)` -- close a message file.
///
/// Generic (Task 5): [`Messages::close`](crate::msg::Messages::close) never
/// touched a `Machine`, so this was already `impl<A: Abi> Messages<A>`
/// before this task.
pub fn clsmsg<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let cookie = call.ptr();
    let current = current_mem(call.mem(), host)?;
    let was_current = host
        .messages
        .close(current, cookie)
        .map_err(ShimError::Failed)?;
    // `curmbk` named the block that was just closed, so it names nothing now.
    // Writing the null is the whole reason closing the current block is
    // allowed at all -- see `Messages::close`. Left unwritten it would point
    // at a block this host has no record of, and every option read afterwards
    // would refuse about the wrong file.
    if was_current {
        set_current_mem(call.mem(), host, A::null_ptr())?;
    }
    Ok(abi::Ret::Void)
}

/// `void setmbk(FILE *mb)` -- read options from this file until told otherwise.
///
/// `curmbk` is written in module memory, not remembered here. What is
/// remembered is the value it held, so that `rstmbk` has something to put back.
///
/// Generic (Task 5): [`Messages::name`](crate::msg::Messages::name) and
/// [`Messages::push`](crate::msg::Messages::push) never touched a `Machine`;
/// only [`current_mem`]/[`set_current_mem`] read and write module memory.
pub fn setmbk<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let cookie = call.ptr();

    // Checked before anything is changed: a `setmbk` of a block that was never
    // opened would otherwise leave `curmbk` naming nothing and the refusal
    // would land on whichever option was read next.
    host.messages.name(cookie).map_err(ShimError::Failed)?;

    let previous = current_mem(call.mem(), host)?;
    host.messages.push(previous);
    set_current_mem(call.mem(), host, cookie)?;
    Ok(abi::Ret::Void)
}

/// `void rstmbk(void)` -- go back to the message file that was current before.
///
/// Generic (Task 5): [`Messages::pop`](crate::msg::Messages::pop) never
/// touched a `Machine`; only [`set_current_mem`] writes module memory.
pub fn rstmbk<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let previous = host.messages.pop().map_err(ShimError::Failed)?;
    set_current_mem(call.mem(), host, previous)?;
    Ok(abi::Ret::Void)
}

/// `char *stgopt(int msgnum)` -- a message's text, whole.
///
/// **The string is the module's, from the module's heap, and the module may
/// free it.** That is not what this looked like from the header, and it is not
/// what this originally did -- it returned a pointer into the host's own
/// message arena, on the reasoning that a stable address could only be safer
/// than the real host's shared `msgbuf`.
///
/// MajorMUD settled it by calling `galfree` on the result. Its initialisation
/// reads `DATADIR` -- message 62, and empty in this distribution -- builds the
/// path template `.\%s` from it, and hands the pointer straight back. A host
/// that had returned its own memory would have had to either refuse or let the
/// module free the host's arena. MBBSEmu allocates here too, which is a second
/// reading of the same binaries arriving at the same place.
///
/// Most call sites never free what they get -- `ACCOUNT.C` and `BBSRIP.C` put
/// these in globals that live for the run -- so this leaks by design, exactly
/// as the real one did.
///
/// Generic: [`text::write_cstr_mem`] is what [`text::write_cstr`]'s `Wg16`
/// facade delegates into now that `text.rs` has converted; [`message_mem`]
/// replaces [`message`] and [`Heap::reserve`](crate::heap::Heap::reserve)
/// (already generic) replaces `Heap::alloc`'s `Wg16` facade.
pub fn stgopt<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let msgnum = Into::<u32>::into(call.int()) as u16;
    let at = message_mem(call.mem(), host, msgnum)?;
    let text = at
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    let size = u16::try_from(text.len() + 1)
        .map_err(|_| ShimError::Failed(format!("a {}-byte message", text.len())))?;
    let out = host
        .heap
        .reserve(call.mem(), size)
        .map_err(|e| ShimError::Failed(format!("stgopt: {e}")))?;
    text::write_cstr_mem::<A>(call.mem(), out, &text, size)?;
    Ok(abi::Ret::Ptr(out))
}

/// `char *rawmsg(int msgnum)` -- a message's text, compact, host-owned.
///
/// `re/wg33src/SRC/api/gcommlib/MCVAPI.C:178-191` (Worldgroup 3.3) reads the
/// message into `msgbuf`, a buffer the host owns and reuses on the very next
/// call -- the module must not free what this returns, and every other
/// option reader in that file (`chropt`, `stgopt`, `pthopt`, `lngopt`) is
/// built by calling `rawmsg` and reading or copying its result immediately.
/// This host already interns each message's text at a stable address --
/// [`message_mem`], the same one [`stgopt`] and [`numopt`] read from -- so
/// `rawmsg` hands that address straight back rather than copying through a
/// scratch buffer of its own. That is a deliberate improvement over the real
/// host, not a plausible zero: the address stays valid instead of being
/// silently overwritten by the module's next message-file call.
///
/// Generic: [`message_mem`] is already `impl<A: Abi>`.
pub fn rawmsg<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let msgnum = Into::<u32>::into(call.int()) as u16;
    let at = message_mem(call.mem(), host, msgnum)?;
    Ok(abi::Ret::Ptr(at))
}


/// `char *getasc(int msgnum)` -- [`rawmsg`]'s text with every line break
/// doubled to `\r\n`.
///
/// `re/wg33src/SRC/api/gcommlib/GETASC.C:22-57` (Worldgroup 3.3) is `rawmsg`
/// with the substitution done character-by-character while reading, writing
/// into the same host-owned `msgbuf`. The transform itself is
/// [`crate::msg::getasc`] -- this is the shim that reaches it by message
/// number, per this task's own `Consumes` line, and does not duplicate it.
///
/// Unlike [`rawmsg`], the result cannot be [`message_mem`]'s address handed
/// back unchanged: that address holds the compact form other option readers
/// still rely on, and overwriting it in place would corrupt them. So this
/// gives the module a fresh block from [`crate::heap::Heap`], the same
/// mechanism [`stgopt`] already uses for a computed string -- a deliberate
/// point of divergence from the real host's single reused `msgbuf`, recorded
/// here rather than silently matched: this host has no equivalent scratch
/// buffer, and a fresh block per call is safe where a reused one would only
/// be an aliasing hazard.
///
/// Generic: [`read_mem`] is already `impl<A: Abi>`;
/// [`Heap::reserve`](crate::heap::Heap::reserve) and
/// [`text::write_cstr_mem`] are the same generic pair [`stgopt`] uses.
pub fn getasc<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let msgnum = Into::<u32>::into(call.int()) as u16;
    let compact = read_mem(call.mem(), host, msgnum)?;
    let expanded = crate::msg::getasc(&compact);

    let size = u16::try_from(expanded.len() + 1)
        .map_err(|_| ShimError::Failed(format!("a {}-byte message", expanded.len())))?;
    let out = host
        .heap
        .reserve(call.mem(), size)
        .map_err(|e| ShimError::Failed(format!("getasc: {e}")))?;
    text::write_cstr_mem::<A>(call.mem(), out, &expanded, size)?;
    Ok(abi::Ret::Ptr(out))
}

/// `int numopt(int msgnum,int floor,int ceiling)`.
///
/// The bounds are the module's own, and real: `ACCOUNT.C:117` asks for
/// `numopt(HWTLOG,-32767,32767)`. A value outside them is a board someone
/// configured wrongly, so it is named rather than clamped.
///
/// Generic (Task 5): the three `int` arguments are `call.int()`, widened and
/// narrowed through [`Abi::Int`]'s `Into<u32>` bound exactly as
/// `shims::user::uacoff` does; [`read_mem`]/[`option_mem`] read module memory.
pub fn numopt<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let number = Into::<u32>::into(call.int()) as u16;
    let floor = Into::<u32>::into(call.int()) as i16;
    let ceiling = Into::<u32>::into(call.int()) as i16;

    let text = read_mem(call.mem(), host, number)?;
    let name = option_mem(call.mem(), host, number)?;
    let text = String::from_utf8_lossy(value(&text)).into_owned();

    let parsed: i32 = text
        .parse()
        .map_err(|_| ShimError::Failed(format!("{name} is {text:?}, which is not a number")))?;
    if parsed < i32::from(floor) || parsed > i32::from(ceiling) {
        return Err(ShimError::Failed(format!(
            "{name} is {parsed}, outside the {floor}..={ceiling} this module accepts"
        )));
    }
    host.recorded_numeric_option(number, parsed);
    Ok(abi::Ret::Int(A::Int::from(parsed as i16 as u16)))
}

/// `long lngopt(int msgnum, long floor, long ceiling)` -- [`numopt`]'s
/// `long` sibling.
///
/// `MCVAPI.H:75-79` (wg33src):
///
///
/// No surviving `.C` body -- `MCVAPI.H` is a prototype header with nothing to
/// quote, the same gap [`numopt`]'s own citation does not have. But
/// `GCOMM.H:289`'s declaration and every real call site
/// (`GALFIL.C:359`'s `lngopt(THRESH,1,1000)*1024L*1024L`,
/// `MAJORBBS.C:596`'s `gpslmt=(unsigned)lngopt(GPSLMT,1L,50000L)`) agree with
/// `numopt`'s own shape one word wider: read the option's trailing value,
/// parse it, and refuse a sysop-misconfigured board rather than clamp or
/// wrap it silently -- the same rule this file's own module doc comment
/// states once for the whole family.
///
/// `re/ne_arity.py 389 <WCCMMPLS.DLL>` measures 4/4 call sites cleaning five
/// words (one `int` plus two `long`s, 2+4+4=10 bytes), matching this
/// prototype exactly -- `389` is `_LNGOPT`'s ordinal in
/// `crates/mbbs/data/majorbbs_wg101.tsv`.
///
/// Generic: `call.long()` reads a `long` at `A::LONG_WIDTH` regardless of
/// `A`, the same as [`prfmsg`]'s varargs cursor already relies on; the parsed
/// value is narrowed into [`abi::Ret::Long`], which -- like `Call::long` --
/// carries no `A`-dependent width at all (see `abi::Ret`'s own doc comment).
pub fn lngopt<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let number = Into::<u32>::into(call.int()) as u16;
    let floor = call.long() as i32;
    let ceiling = call.long() as i32;

    let text = read_mem(call.mem(), host, number)?;
    let name = option_mem(call.mem(), host, number)?;
    let text = String::from_utf8_lossy(value(&text)).into_owned();

    let parsed: i64 = text
        .parse()
        .map_err(|_| ShimError::Failed(format!("{name} is {text:?}, which is not a number")))?;
    if parsed < i64::from(floor) || parsed > i64::from(ceiling) {
        return Err(ShimError::Failed(format!(
            "{name} is {parsed}, outside the {floor}..={ceiling} this module accepts"
        )));
    }
    Ok(abi::Ret::Long(parsed as i32 as u32))
}

/// `int ynopt(int msgnum)`.
///
/// Across the 91 recovered `.MSG` files every one of the 267 `B` options ends
/// in `YES` or `NO`, so anything else is not a spelling this has to guess at.
///
/// Generic (Task 5): [`read_mem`]/[`option_mem`] read module memory; the
/// answer is built through [`Abi::Int::from`], the same as
/// `shims::user::haskey`'s boolean.
pub fn ynopt<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let number = Into::<u32>::into(call.int()) as u16;
    let text = read_mem(call.mem(), host, number)?;
    match value(&text) {
        v if v.eq_ignore_ascii_case(b"YES") => Ok(abi::Ret::Int(A::Int::from(1u16))),
        v if v.eq_ignore_ascii_case(b"NO") => Ok(abi::Ret::Int(A::Int::from(0u16))),
        other => Err(ShimError::Failed(format!(
            "{} is {:?}, which is neither YES nor NO",
            option_mem(call.mem(), host, number)?,
            String::from_utf8_lossy(other)
        ))),
    }
}

/// `int chropt(int msgnum)` -- an option that is one character.
///
/// Generic (Task 5): [`read_mem`]/[`option_mem`] read module memory.
pub fn chropt<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let number = Into::<u32>::into(call.int()) as u16;
    let text = read_mem(call.mem(), host, number)?;
    match value(&text) {
        [character, ..] => Ok(abi::Ret::Int(A::Int::from(u16::from(*character)))),
        [] => Err(ShimError::Failed(format!(
            "{} is empty, and a character option needs a character",
            option_mem(call.mem(), host, number)?
        ))),
    }
}

/// `int tokopt(int msgnum, char *tok, ..., NULL)` -- which of these the option
/// says.
///
/// One-based, which is what the call sites need: `BBSRIP.C:194` reads
/// `tokopt(CHKSGN,"LOGON","LOGOFF","BOTH",NULL)` and compares the result
/// against `#define LOGON 1`, `LOGOFF 2`, `BOTH 3`.
///
/// The list is varargs and terminated by a null pointer, so how many there are
/// is only discoverable by walking it.
///
/// Generic (Task 5): the null terminator that ends the list is tested on the
/// pointer's own bytes ([`Abi::ptr_to_bytes`]), not `FarPtr`'s
/// `selector`/`offset` fields -- the same reading `shims::user::begin_polling`
/// tests a null routine pointer, since `A::Ptr` is opaque to a generic caller.
pub fn tokopt<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // The list's length isn't known up front, so every pointer is pulled off
    // `call` first -- still sequential, just without the `1 + n * 2` word
    // arithmetic `Call::ptr` does on its own -- and only then walked to read
    // each one's string.
    let number = Into::<u32>::into(call.int()) as u16;
    let mut pointers = Vec::new();
    loop {
        let at = call.ptr();
        if A::ptr_to_bytes(at).iter().all(|&b| b == 0) {
            break;
        }
        pointers.push(at);
    }

    let text = read_mem(call.mem(), host, number)?;
    let wanted = value(&text).to_ascii_uppercase();

    let mut tokens = Vec::new();
    for at in pointers {
        let bytes = at
            .read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(e.to_string()))?;
        tokens.push(bytes.to_ascii_uppercase());
    }

    match tokens.iter().position(|t| *t == wanted) {
        Some(at) => Ok(abi::Ret::Int(A::Int::from(at as u16 + 1))),
        None => Err(ShimError::Failed(format!(
            "{} is {:?}, which is none of {:?}",
            option_mem(call.mem(), host, number)?,
            String::from_utf8_lossy(&wanted),
            tokens
                .iter()
                .map(|t| String::from_utf8_lossy(t).into_owned())
                .collect::<Vec<_>>()
        ))),
    }
}

/// `void prfmsg(int msg,...)` -- append a message to the channel's output.
///
/// `prf` with the template coming from the current message block instead of
/// from the module. The arguments start at word 1, because `msg` is an `int`
/// and not the far pointer `prf`'s first argument is.
///
/// Generic: [`crate::fmt::format_call`] replaces `format`/`Args::Call { first:
/// 1 }` -- once `msgnum` is read with `call.int()`, `call`'s position already
/// marks where the varargs begin, matching `shocst`'s own substitution
/// (`shims::system`). [`text::append_mem`] is what [`text::append`]'s `Wg16`
/// facade delegates into now that `text.rs` has converted.
pub fn prfmsg<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let msgnum = Into::<u32>::into(call.int()) as u16;
    let at = message_mem(call.mem(), host, msgnum)?;
    let (text, _) = format_call(call, at)?;
    text::append_mem(call.mem(), host, &text)?;
    Ok(abi::Ret::Void)
}

/// `VOID dspmsg(INT msgno, CHAR *parm1, CHAR *parm2, CHAR *parm3)` --
/// `BBSUTILS.C:32-39` -- print a message, picking the ANSI variant when the
/// caller's account wants ANSI.
///
///
/// **The ANSI variant is the message *after* it.** `ANSON` is 1
/// (`INC/UStructs.h:60`), and the convention the `.MSG` file follows is that
/// an ANSI-capable message is written as a pair, plain first. So a module
/// that hands `dspmsg` message *n* is really naming two messages, and getting
/// the direction wrong prints the wrong one for every ANSI user rather than
/// failing.
///
/// Three fixed `CHAR *` parameters, not a vararg tail -- but they reach the
/// format through exactly the same [`crate::fmt::format_call`] path
/// [`prfmsg`] uses, because after `msgno` is read the call's cursor is
/// already sitting on them and the format string decides how many it
/// consumes.
///
/// # Errors
///
/// If the chosen message is not in the current block, or formatting fails.
pub fn dspmsg<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let msgno = Into::<u32>::into(call.int()) as u16;
    let ansi = text::channel_ansi_mem(call.mem(), host);
    let chosen = if ansi { msgno.wrapping_add(1) } else { msgno };

    let at = message_mem(call.mem(), host, chosen)?;
    let (rendered, _) = format_call(call, at)?;
    text::append_mem(call.mem(), host, &rendered)?;
    Ok(abi::Ret::Void)
}

/// `VOID inimsg(UINT maxsiz)` -- `MCVAPI.C:37-51` -- make sure the message
/// buffer is at least this big.
///
///
/// **Monotonic**: a smaller request after a larger one does nothing at all,
/// which is the whole of the `mxmssz < maxsiz` guard and the one behaviour
/// worth pinning.
///
/// The vendor keeps a single shared `msgbuf` that `rawmsg` reads each message
/// into. This host interns each message at its own exact length instead
/// ([`crate::messages`]), so there is no one buffer to allocate -- the size is
/// recorded rather than acted on. That is not a stub: `inimsg`'s promise to
/// the module is "there is room for a message this big", and a host whose
/// messages are individually sized keeps that promise for every value.
///
/// # Errors
///
/// Never.
pub fn inimsg<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let maxsiz = Into::<u32>::into(call.int()) as u16;
    host.grow_msgbuf(maxsiz);
    Ok(abi::Ret::Void)
}


/// `MAXCHG` (`SETCNF.C:44`) -- how many `setcnf` changes fit before the
/// vendor calls `catastro`.
const MAXCHG: usize = 100;

/// `VOID setcnf(CHAR *optnam, CHAR *optval)` -- `SETCNF.C:56-76` -- record a
/// configuration change for a later `applyem`.
///
///
/// Pure bookkeeping: nothing is written to any file until [`applyem`] runs.
/// The first `setcnf` after an `applyem` clears the list, which is what the
/// `applied` flag is for -- so the changes accumulate in rounds rather than
/// forever.
///
/// **The bound is enforced one change earlier than the vendor's.** `onams`
/// and `ovals` are `[MAXCHG]`, so writing `onams[nchgs]` with `nchgs == 100`
/// is already one past the end -- the vendor stores out of bounds and *then*
/// calls `catastro` on the next line. The overrun is the bug; the `catastro`
/// is the intent. This refuses on the 101st change without writing, which
/// reaches the same "the board stops" outcome the vendor's `catastro`
/// reaches, without reproducing the write.
///
/// # Errors
///
/// If either string is unreadable, or this is the 101st change of a round.
pub fn setcnf<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let optnam = call.ptr();
    let optval = call.ptr();

    let name = optnam
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(format!("setcnf: {e}")))?
        .to_vec();
    let value = optval
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(format!("setcnf: {e}")))?
        .to_vec();

    if !host.record_setcnf(name, value, MAXCHG) {
        return Err(ShimError::Failed(format!(
            "setcnf: TOO MANY CHANGES -- more than MAXCHG ({MAXCHG}) options \
             set without an applyem between them, which is where the vendor \
             calls catastro (SETCNF.C:74)"
        )));
    }
    Ok(abi::Ret::Void)
}

/// `VOID applyem(CHAR *filnam)` -- `SETCNF.C:78-139` -- rewrite a `.MSG` file
/// with everything [`setcnf`] has recorded.
///
/// **Refused: it is the MSGRDR subsystem, and this host has none of it.** The
/// body is sixty lines over `inilingo`, `inimsgrdr`, `rdmsg`, `scanalt`,
/// `litopts`, `lotype`, `putval` and `loadtv` -- a `.MSG` reader/writer that
/// parses the file's option syntax, walks its alternate-language blocks, and
/// rewrites it through a temporary file. Not one of those exists here.
///
/// **`setcnf` without `applyem` accumulates settings nobody reads**, and that
/// is worth saying plainly rather than leaving to look like an oversight: a
/// module that calls `setcnf` and then `applyem` will be stopped at the
/// `applyem`, which is the honest place to stop it. Answering `Ok` would
/// leave the module believing its configuration had been written to disk.
///
/// # Errors
///
/// Always.
pub fn applyem<A: Abi>(call: &mut Call<A>, _: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let filnam = call.ptr();
    let name = filnam
        .read_cstr(call.mem())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .unwrap_or_else(|_| "?".to_owned());
    Err(ShimError::Failed(format!(
        "applyem({name:?}): rewriting a .MSG file needs the MSGRDR subsystem \
         -- inilingo, inimsgrdr, rdmsg, scanalt, litopts, lotype, putval and \
         loadtv (SETCNF.C:88-131) -- and this host implements none of it. The \
         setcnf changes recorded so far have therefore not been written \
         anywhere"
    )))
}

/// `UINT hexopt(INT msgnum, UINT floor, UINT ceiling)` -- `MCVAPI.C:252-266`
/// -- a hexadecimal option from the current message file.
///
///
/// [`numopt`]'s shape with base 16, and it reaches the message text the same
/// way -- the plan this was written against expected `rawmsg` to be missing
/// and `hexopt` to depend on implementing it first; `rawmsg` is in fact
/// already registered (`shims/mod.rs`), and the value is read through the
/// same [`read_mem`]/[`crate::msg::value`] pair every other `*opt` uses.
///
/// Both of the vendor's `catastro` calls are errors -- a malformed value and
/// an out-of-range one -- and `catastro` stops the board there too, so they
/// are refusals here rather than an invented default.
///
/// # Errors
///
/// If the message is missing, its value is not hexadecimal, or it falls
/// outside `floor..=ceiling`.
pub fn hexopt<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let number = Into::<u32>::into(call.int()) as u16;
    let floor = Into::<u32>::into(call.int()) as u16;
    let ceiling = Into::<u32>::into(call.int()) as u16;

    let text = read_mem(call.mem(), host, number)?;
    let name = option_mem(call.mem(), host, number)?;
    let text = String::from_utf8_lossy(crate::msg::value(&text)).into_owned();

    // `%lx` reads an unsigned hexadecimal run; a leading `0x` is not part of
    // it, and neither is a sign.
    let digits = text.trim();
    let parsed = i64::from_str_radix(digits, 16).map_err(|_| {
        ShimError::Failed(format!("{name} is {text:?}, which is not hexadecimal"))
    })?;

    if parsed < i64::from(floor) || parsed > i64::from(ceiling) {
        return Err(ShimError::Failed(format!(
            "{name} is {parsed:#x}, outside the {floor:#x}..={ceiling:#x} this \
             module accepts"
        )));
    }
    Ok(abi::Ret::Int(A::Int::from(parsed as u16)))
}

/// `BUFSIZ` -- how long a `.MDF` line [`scnmdf`] will read, and so how big
/// the buffer it answers out of has to be.
///
/// The vendor reads with `fgets(tmpbuf,BUFSIZ,fp)` (`MDFUTL.C:88`) into a
/// shared `BUFSIZ` scratch buffer, and Borland's `BUFSIZ` is 512.
pub(crate) const SCNMDF_BYTES: u16 = 512;

/// `CHAR *scnmdf(CHAR *mdfnam, CHAR *linpfx)` -- `MDFUTL.C:76-97` -- the
/// value of one prefixed line in a `.MDF` file.
///
///
/// **The empty string is the answer for a prefix that is not there**, not an
/// error: `retval=""` is set before the loop and survives it. Only failing to
/// *open* the file is fatal, and that is `catastro`, so it is a refusal here.
///
/// `sameto` is a case-insensitive prefix match, so `Language:` finds
/// `LANGUAGE:`; `unpad` strips trailing whitespace from the whole line and
/// `skpwht` skips leading whitespace after the prefix, which together mean
/// the value comes back trimmed at both ends but keeps its interior spacing.
///
/// **`mdfodmd` (`MDFUTL.C:99-116`) is folded in rather than registered**: it
/// tries the name as given and, if that is not a file, replaces the extension
/// with `.dmd` and tries again, `catastro`-ing if neither exists. No oracle
/// build exports it, so it is this routine's helper here as it is there.
///
/// The answer is a pointer into a host-owned line buffer that the next
/// `scnmdf` overwrites. That is the vendor's behaviour too -- its `retval`
/// points into the shared `tmpbuf` -- so a caller that wants to keep the
/// value has to copy it, in both hosts.
///
/// # Errors
///
/// If either argument is unreadable, if neither the named file nor its `.dmd`
/// sibling exists, or if the line will not fit [`SCNMDF_BYTES`].
pub fn scnmdf<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let mdfnam = call.ptr();
    let linpfx = call.ptr();

    let named = String::from_utf8_lossy(
        mdfnam
            .read_cstr(call.mem())
            .map_err(|e| ShimError::Failed(format!("scnmdf: {e}")))?,
    )
    .into_owned();
    let prefix = linpfx
        .read_cstr(call.mem())
        .map_err(|e| ShimError::Failed(format!("scnmdf: {e}")))?
        .to_vec();

    // `mdfodmd`: the name as given, or the same stem with `.dmd`.
    let path = host.find(&named).or_else(|| {
        let stem = named.rsplit_once('.').map_or(named.as_str(), |(stem, _)| stem);
        host.find(&format!("{stem}.dmd"))
    });
    let path = path.ok_or_else(|| {
        ShimError::Failed(format!(
            "scnmdf: CAN'T OPEN {named:?} -- neither it nor its .dmd sibling is \
             under {} (MDFUTL.C:107-113)",
            host.root.display()
        ))
    })?;

    let bytes = std::fs::read(&path)
        .map_err(|e| ShimError::Failed(format!("scnmdf: {}: {e}", path.display())))?;

    let mut value: &[u8] = b"";
    for line in bytes.split(|&b| b == b'\n') {
        if line.len() >= prefix.len()
            && line[..prefix.len()].eq_ignore_ascii_case(&prefix)
        {
            // `unpad` then `skpwht(tmpbuf+strlen(linpfx))`: trailing
            // whitespace off the whole line, then leading whitespace off what
            // follows the prefix. `\r` counts as trailing whitespace, which is
            // what makes this work on a CRLF file.
            let rest = &line[prefix.len()..];
            let end = rest
                .iter()
                .rposition(|b| !b.is_ascii_whitespace())
                .map_or(0, |i| i + 1);
            let start = rest[..end]
                .iter()
                .position(|b| !b.is_ascii_whitespace())
                .unwrap_or(end);
            value = &rest[start..end];
            break;
        }
    }

    let at = host.scnmdf_buffer();
    text::write_cstr_mem::<A>(call.mem(), at, value, SCNMDF_BYTES)?;
    Ok(abi::Ret::Ptr(at))
}

/// What `curmbk` holds, read back out of module memory every time.
///
/// Generic core (Task 5). No `Wg16` facade under the old `current` name: only
/// [`message_mem`] called it, and that has its own facade -- see
/// [`message`]'s doc comment.
fn current_mem<A: Abi>(mem: &A::Mem, host: &Host<A>) -> Result<A::Ptr, ShimError> {
    host.globals()
        .pointer_mem(mem, "curmbk")
        .map_err(|e| ShimError::Failed(e.to_string()))
}

/// Generic core (Task 5). No `Wg16` facade under the old `set_current` name,
/// for the same reason [`current_mem`] has none.
fn set_current_mem<A: Abi>(mem: &mut A::Mem, host: &Host<A>, block: A::Ptr) -> Result<(), ShimError> {
    host.globals()
        .write_mem(mem, "curmbk", &A::ptr_to_bytes(block))
        .map_err(|e| ShimError::Failed(e.to_string()))
}

/// Where message `n` of the current block was interned.
///
/// Generic core (Task 5); see [`message`] for the `Wg16` facade, which
/// `shims::fsd`'s tests call directly by this exact name and signature.
pub(crate) fn message_mem<A: Abi>(mem: &A::Mem, host: &Host<A>, n: u16) -> Result<A::Ptr, ShimError> {
    let block = current_mem(mem, host)?;
    host.messages.text(block, n).map_err(ShimError::Failed)
}

/// The `Wg16` facade over [`message_mem`], kept under its original name and
/// signature because `shims::fsd`'s tests call it directly rather than through
/// `Fixture::invoke`.
///
/// `#[cfg(test)]` because that is now its whole audience. [`stgopt`] and
/// [`prfmsg`] were its only production callers and both went generic, so in a
/// non-test build it is dead — and saying so with `cfg` is the honest form of
/// that, where an `allow(dead_code)` would have hidden it. If a production
/// caller ever comes back, this attribute is what will stop it compiling and
/// make someone decide deliberately.
#[cfg(test)]
pub(crate) fn message(machine: &Machine, host: &Host<Wg16>, n: u16) -> Result<FarPtr, ShimError> {
    message_mem(machine.mem(), host, n)
}

/// The text of message `n` of the current block.
///
/// Generic core (Task 5). No `Wg16` facade by this exact old name -- nothing
/// outside this file called the old `read` directly (unlike [`message`]).
fn read_mem<A: Abi>(mem: &A::Mem, host: &Host<A>, n: u16) -> Result<Vec<u8>, ShimError> {
    let at = message_mem(mem, host, n)?;
    at.read_cstr(mem)
        .map(|s| s.to_vec())
        .map_err(|e| ShimError::Failed(e.to_string()))
}

/// How to name message `n` in a refusal.
///
/// The file and the number. A `.MSG` does not carry option names into what the
/// module sees, and the module knows `n` as a constant whose name lives only in
/// its own header -- so the file and the number is as close as the host can get,
/// and it is enough to find the line.
///
/// Generic core (Task 5); [`numopt`]/[`ynopt`]/[`chropt`]/[`tokopt`] all call
/// this by name -- there is no separate `Wg16` facade, since nothing outside
/// this file called the old `option` directly (unlike [`message`]).
fn option_mem<A: Abi>(mem: &A::Mem, host: &Host<A>, n: u16) -> Result<String, ShimError> {
    let block = current_mem(mem, host)?;
    let name = host.messages.name(block).map_err(ShimError::Failed)?;
    Ok(format!("message {n} of {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;

    /// Open `SAMPLE.MSG` and make it current, as a module would.
    /// Open a file, which also makes it current.
    fn open(f: &mut Fixture, name: &str) -> FarPtr {
        let at = f.text(name);
        let Ret::Far(cookie) = f.invoke(opnmsg, &Fixture::far(at)).expect("opens") else {
            panic!("opnmsg returns a pointer");
        };
        cookie
    }

    /// `SAMPLE.MSG`, open and current, as a module would have it.
    fn opened(f: &mut Fixture) -> FarPtr {
        open(f, "SAMPLE.MSG")
    }

    /// What the module can see of which block is current.
    fn curmbk(f: &Fixture) -> FarPtr {
        f.host
            .globals()
            .pointer(&f.machine, "curmbk")
            .expect("curmbk")
    }

    #[test]
    fn opnmsg_finds_the_file_whatever_case_the_module_named_it_in() {
        let mut f = Fixture::new();
        let name = f.text("sample.msg");
        assert!(matches!(
            f.invoke(opnmsg, &Fixture::far(name)).expect("opens"),
            Ret::Far(_)
        ));
    }

    #[test]
    fn opnmsg_names_a_file_it_cannot_find() {
        let mut f = Fixture::new();
        let name = f.text("NOSUCH.MSG");
        let e = f.invoke(opnmsg, &Fixture::far(name)).expect_err("no file");
        assert!(e.to_string().contains("NOSUCH.MSG"), "{e}");
    }

    #[test]
    fn opening_a_file_makes_it_current_and_rstmbk_puts_back_what_was() {
        // `ACCOUNT.C:107` opens `bbsacct.mcv` and reads options straight off it
        // with no `setmbk`, and MajorMUD's initialisation opens each of its
        // three files and calls `rstmbk` after each -- which only balances if
        // opening saved what was current.
        let mut f = Fixture::new();
        let nothing = curmbk(&f);

        let first = open(&mut f, "SAMPLE.MSG");
        assert_eq!(curmbk(&f), first, "opening made it current");

        let second = open(&mut f, "OTHER.MSG");
        assert_ne!(first, second, "two files are two blocks");
        assert_eq!(curmbk(&f), second);

        f.invoke(rstmbk, &[]).expect("back to the first");
        assert_eq!(curmbk(&f), first);
        f.invoke(rstmbk, &[]).expect("back to none");
        assert_eq!(curmbk(&f), nothing);
    }

    #[test]
    fn setmbk_moves_curmbk_in_module_memory_and_nowhere_else() {
        let mut f = Fixture::new();
        let first = opened(&mut f);
        let second = open(&mut f, "OTHER.MSG");

        f.invoke(setmbk, &Fixture::far(first)).expect("set");
        assert_eq!(curmbk(&f), first);
        f.invoke(rstmbk, &[]).expect("restored");
        assert_eq!(curmbk(&f), second, "back to what opening OTHER made current");
    }

    #[test]
    fn setmbk_of_a_block_that_was_never_opened_refuses() {
        let mut f = Fixture::new();
        let before = curmbk(&f);
        let nonsense = FarPtr {
            offset: 0x40,
            selector: f.host.globals().selector(),
        };
        assert!(f.invoke(setmbk, &Fixture::far(nonsense)).is_err());
        assert_eq!(curmbk(&f), before, "and left curmbk where it was");
    }

    #[test]
    fn rstmbk_with_nothing_to_undo_refuses() {
        // Rather than leaving `curmbk` at whatever seemed likely -- after which
        // every option read would come from that guess.
        let mut f = Fixture::new();
        assert!(f.invoke(rstmbk, &[]).is_err());
    }

    #[test]
    fn stgopt_returns_the_whole_message() {
        let mut f = Fixture::new();
        opened(&mut f);
        let Ret::Far(at) = f.invoke(stgopt, &[1]).expect("read") else {
            panic!("stgopt returns a pointer");
        };
        assert_eq!(f.read(at), "DEMO");
    }

    #[test]
    fn a_stgopt_string_is_the_modules_own_and_it_may_free_it() {
        // MajorMUD frees what stgopt returns. If this handed back a pointer
        // into the host's message arena, the module would be freeing the
        // host's memory -- and the host would have to refuse, five calls into
        // initialisation.
        let mut f = Fixture::new();
        opened(&mut f);
        let Ret::Far(at) = f.invoke(stgopt, &[1]).expect("read") else {
            panic!("stgopt returns a pointer")
        };
        assert_eq!(f.read(at), "DEMO");
        assert_eq!(
            f.host.heap().block(at),
            Some(5),
            "four characters and a terminator, from the module's heap"
        );
        f.invoke(crate::shims::memory::galfree, &Fixture::far(at))
            .expect("the module owns it");
    }

    #[test]
    fn a_stgopt_pointer_stays_valid_across_everything_else() {
        // Whatever else happens, the string the module was given is still
        // there: nothing the host does later writes over a live heap block.
        let mut f = Fixture::new();
        opened(&mut f);
        let Ret::Far(first) = f.invoke(stgopt, &[1]).expect("read") else {
            panic!("stgopt returns a pointer")
        };

        f.invoke(stgopt, &[2]).expect("another option");
        let other = f.text("OTHER.MSG");
        f.invoke(opnmsg, &Fixture::far(other)).expect("another file");
        let template = f.text("noise %d");
        f.invoke(text::prf, &[template.offset, template.selector, 7])
            .expect("some output");

        assert_eq!(f.read(first), "DEMO", "the first pointer still reads");
    }

    #[test]
    fn numopt_reads_the_number_off_the_end_of_the_prompt() {
        let mut f = Fixture::new();
        opened(&mut f);
        assert_eq!(f.invoke(numopt, &[2, 0, 32767]).expect("read"), Ret::U16(60));
    }

    /// Call `scnmdf(mdfnam, linpfx)` and read back what it answered.
    fn scan(f: &mut Fixture, mdfnam: &str, linpfx: &str) -> Vec<u8> {
        let name = f.text(mdfnam);
        let prefix = f.text(linpfx);
        let Ret::Far(at) = f
            .invoke(scnmdf, &[name.offset, name.selector, prefix.offset, prefix.selector])
            .expect("scnmdf")
        else {
            panic!("scnmdf returns char *");
        };
        f.machine.read_cstr(at).expect("readable").to_vec()
    }

    /// `scnmdf` answers what follows the prefix, trimmed at both ends.
    ///
    /// `unpad` takes the trailing whitespace off the line -- including the
    /// `\r` of a CRLF file -- and `skpwht` takes the leading whitespace off
    /// what follows the prefix (`MDFUTL.C:89-92`). The interior space in
    /// `Sample Module` has to survive both.
    #[test]
    fn scnmdf_answers_the_value_after_the_prefix() {
        let mut f = Fixture::new();
        assert_eq!(scan(&mut f, "SAMPLE.MDF", "Module Name:"), b"Sample Module");
        assert_eq!(scan(&mut f, "SAMPLE.MDF", "Developer:"), b"nobody");
    }

    /// The prefix match is case-insensitive, because `sameto` is
    /// (`MDFUTL.C:89`).
    #[test]
    fn scnmdf_matches_the_prefix_without_regard_to_case() {
        let mut f = Fixture::new();
        assert_eq!(scan(&mut f, "SAMPLE.MDF", "MODULE NAME:"), b"Sample Module");
        assert_eq!(scan(&mut f, "SAMPLE.MDF", "module name:"), b"Sample Module");
    }

    /// **A prefix that is not in the file answers the empty string**, not an
    /// error: `retval=""` is set before the loop and survives it
    /// (`MDFUTL.C:87`). A module distinguishes "absent" from "present but
    /// blank" by nothing at all, in either host.
    #[test]
    fn scnmdf_answers_an_empty_string_for_a_prefix_that_is_absent() {
        let mut f = Fixture::new();
        assert_eq!(scan(&mut f, "SAMPLE.MDF", "Nosuchkey:"), b"");
    }

    /// Only failing to open is fatal, and it is `catastro` in the vendor
    /// (`MDFUTL.C:85`) -- so a refusal here, naming the file.
    #[test]
    fn scnmdf_refuses_a_file_that_is_not_there() {
        let mut f = Fixture::new();
        let name = f.text("NOSUCH.MDF");
        let prefix = f.text("Module Name:");
        let e = f
            .invoke(scnmdf, &[name.offset, name.selector, prefix.offset, prefix.selector])
            .expect_err("no such file");
        assert!(e.to_string().contains("NOSUCH.MDF"), "{e}");
        assert!(e.to_string().contains(".dmd"), "{e}");
    }

    /// The first matching line wins and the scan stops there (`break`,
    /// `MDFUTL.C:93`).
    ///
    /// `DLLs:` and `MSGs:` are adjacent lines with the same shape, so asking
    /// for the earlier one must not answer the later one's value.
    #[test]
    fn scnmdf_stops_at_the_first_line_that_matches() {
        let mut f = Fixture::new();
        assert_eq!(scan(&mut f, "SAMPLE.MDF", "DLLs:"), b"SAMPLE");
        assert_eq!(scan(&mut f, "SAMPLE.MDF", "MSGs:"), b"SAMPLE");
    }

    /// `hexopt` reads the same last word `numopt` does, in base 16.
    ///
    /// Message 2 of `SAMPLE.MSG` is `GAMCRD`, whose value is `60`. As a
    /// decimal that is sixty -- what `numopt` answers just above -- and as
    /// hexadecimal it is 0x60, ninety-six. **The same message read two ways
    /// giving two different numbers is what proves the radix is real** rather
    /// than a base-10 parse with a different name.
    #[test]
    fn hexopt_reads_the_same_word_numopt_does_but_in_base_sixteen() {
        let mut f = Fixture::new();
        opened(&mut f);
        assert_eq!(f.invoke(numopt, &[2, 0, 32767]).expect("read"), Ret::U16(60));
        assert_eq!(f.invoke(hexopt, &[2, 0, 0xFFFF]).expect("read"), Ret::U16(0x60));
    }

    /// Out of range is a refusal that names the value, the same way `numopt`'s
    /// is -- the vendor's `catastro` (`MCVAPI.C:262`) stops the board there.
    #[test]
    fn hexopt_outside_its_bounds_refuses_and_names_the_message() {
        let mut f = Fixture::new();
        opened(&mut f);
        let e = f.invoke(hexopt, &[2, 0, 0x5F]).expect_err("0x60 is over 0x5f");
        assert!(e.to_string().contains("0x60"), "{e}");
        assert!(e.to_string().contains("SAMPLE.MSG"), "{e}");
    }

    /// A value that is not hexadecimal at all is the other `catastro`
    /// (`MCVAPI.C:259`, the `sscanf` returning 0).
    #[test]
    fn hexopt_refuses_a_value_that_is_not_hexadecimal() {
        let mut f = Fixture::new();
        opened(&mut f);
        // Message 3 is `YESOPT`, whose value is `YES` -- `Y` and `S` are not
        // hex digits, though `E` is, so this also checks the whole word is
        // parsed rather than a leading run of it.
        let e = f.invoke(hexopt, &[3, 0, 0xFFFF]).expect_err("YES is not hex");
        assert!(e.to_string().contains("YES"), "{e}");
    }

    /// `inimsg` only ever grows (`MCVAPI.C:42`, `if (mxmssz < maxsiz)`).
    ///
    /// The smaller second request is the assertion that matters: a port that
    /// simply assigned would shrink the buffer a module had already been
    /// promised.
    #[test]
    fn inimsg_grows_the_message_buffer_and_never_shrinks_it() {
        let mut f = Fixture::new();
        assert_eq!(f.host.msgbuf_size(), 0, "nothing has asked yet");

        assert!(matches!(f.invoke(inimsg, &[4096]), Ok(Ret::Void)));
        assert_eq!(f.host.msgbuf_size(), 4096);

        assert!(matches!(f.invoke(inimsg, &[1024]), Ok(Ret::Void)));
        assert_eq!(f.host.msgbuf_size(), 4096, "a smaller request does nothing");

        assert!(matches!(f.invoke(inimsg, &[8192]), Ok(Ret::Void)));
        assert_eq!(f.host.msgbuf_size(), 8192);
    }


    /// `setcnf` records the pair it was given, in order.
    #[test]
    fn setcnf_records_the_name_and_value() {
        let mut f = Fixture::new();
        let name = f.text("MAXIMUM PLAYERS");
        let value = f.text("64");
        f.invoke(setcnf, &[name.offset, name.selector, value.offset, value.selector])
            .expect("setcnf");

        assert_eq!(
            f.host.setcnf_changes(),
            [(b"MAXIMUM PLAYERS".to_vec(), b"64".to_vec())]
        );
    }

    /// The 101st change of a round is refused.
    ///
    /// `onams`/`ovals` are `[MAXCHG]` and `MAXCHG` is 100 (`SETCNF.C:44`), so
    /// the vendor's `onams[nchgs]=` with `nchgs == 100` writes one past the
    /// end and only *then* reaches its `catastro`. The overrun is the bug and
    /// the `catastro` is the intent, so this stops one change earlier --
    /// without writing -- and reaches the same outcome.
    #[test]
    fn setcnf_refuses_the_hundred_and_first_change() {
        let mut f = Fixture::new();
        let value = f.text("x");
        for i in 0..MAXCHG {
            let name = f.text(&format!("OPT{i}"));
            f.invoke(setcnf, &[name.offset, name.selector, value.offset, value.selector])
                .unwrap_or_else(|e| panic!("change {i} of {MAXCHG}: {e}"));
        }
        assert_eq!(f.host.setcnf_changes().len(), MAXCHG);

        let name = f.text("ONE TOO MANY");
        let e = f
            .invoke(setcnf, &[name.offset, name.selector, value.offset, value.selector])
            .expect_err("MAXCHG is a bound, not a suggestion");
        assert!(e.to_string().contains("TOO MANY CHANGES"), "{e}");
        assert_eq!(
            f.host.setcnf_changes().len(),
            MAXCHG,
            "and the refused change was not recorded"
        );
    }

    /// `applyem` refuses, naming MSGRDR.
    ///
    /// Asserting the message rather than `is_err()`: a refusal that only said
    /// "no" would pass for an unreadable filename too, and the point is that
    /// the whole `.MSG` reader/writer is absent.
    #[test]
    fn applyem_refuses_and_names_the_msgrdr_subsystem() {
        let mut f = Fixture::new();
        let name = f.text("SAMPLE.MSG");
        let e = f.invoke(applyem, &Fixture::far(name)).expect_err("no MSGRDR here");
        let message = e.to_string();
        assert!(message.contains("MSGRDR"), "{message}");
        assert!(message.contains("SAMPLE.MSG"), "{message}");
    }

    /// `setcnf` without `applyem` accumulates settings nobody reads, and the
    /// pairing is worth pinning so it does not read as an oversight later.
    #[test]
    fn setcnf_changes_survive_an_applyem_that_refused() {
        let mut f = Fixture::new();
        let name = f.text("OPT");
        let value = f.text("1");
        f.invoke(setcnf, &[name.offset, name.selector, value.offset, value.selector])
            .expect("setcnf");

        let file = f.text("SAMPLE.MSG");
        f.invoke(applyem, &Fixture::far(file)).expect_err("refuses");

        assert_eq!(
            f.host.setcnf_changes().len(),
            1,
            "nothing applied them, so they are still pending"
        );
    }

    /// `dspmsg` picks `msgno+1` when the account wants ANSI and `msgno` when
    /// it does not -- **both**, because a port that always picked one would
    /// pass a single-case test.
    #[test]
    fn dspmsg_picks_the_ansi_variant_only_when_the_account_wants_ansi() {
        let mut f = Fixture::new();
        opened(&mut f);
        let chan = f.console();
        f.host
            .connect_state(&mut f.machine, chan, &crate::Connection::ansi("rangerdan"))
            .expect("connects");
        let ansifl = Wg16::ptr_offset(
            f.host.users().account(chan),
            f.host.users().account_layout().ansifl,
        );

        // Message 3 is `YESOPT` and message 4 is `NOOPT`; their bodies hold
        // `YES` and `NO`, so which one was printed is visible in the output.
        // ANSON clear takes msgno, ANSON set takes msgno+1.
        for (flag, expected) in [(0u8, &b"YES"[..]), (1, &b"NO"[..])] {
            f.machine.write(ansifl, &[flag]).expect("ansifl");
            assert!(matches!(f.invoke(text::clrprf, &[]), Ok(Ret::Void)));
            f.invoke(dspmsg, &[3, 0, 0, 0, 0, 0, 0]).expect("dspmsg");

            let prfbuf = f.host.globals().prf_buffer();
            let printed = f.machine.read_cstr(prfbuf).expect("readable").to_vec();
            assert!(
                printed.windows(expected.len()).any(|w| w == expected),
                "ansifl={flag} printed {:?}, expected the message holding {:?}",
                String::from_utf8_lossy(&printed),
                String::from_utf8_lossy(expected)
            );
        }
    }

    #[test]
    fn numopt_outside_its_bounds_refuses_and_names_the_message() {
        let mut f = Fixture::new();
        opened(&mut f);
        let e = f.invoke(numopt, &[2, 0, 50]).expect_err("60 is over 50");
        assert!(e.to_string().contains("60"), "{e}");
        assert!(e.to_string().contains("SAMPLE.MSG"), "{e}");
    }

    #[test]
    fn numopt_reads_a_negative_bound_as_negative() {
        // `ACCOUNT.C:117` passes -32767 as a floor. Read as unsigned it is
        // 32,769, and every negative option would be refused.
        let mut f = Fixture::new();
        opened(&mut f);
        let floor = (-32767i16) as u16;
        assert_eq!(
            f.invoke(numopt, &[5, floor, 32767]).expect("read"),
            Ret::U16((-5i16) as u16)
        );
    }

    #[test]
    fn lngopt_reads_the_number_off_the_end_of_the_prompt() {
        let mut f = Fixture::new();
        opened(&mut f);
        assert_eq!(f.invoke(lngopt, &[2, 0, 0, 32767, 0]).expect("read"), Ret::U32(60));
    }

    #[test]
    fn lngopt_outside_its_bounds_refuses_and_names_the_message() {
        let mut f = Fixture::new();
        opened(&mut f);
        let e = f.invoke(lngopt, &[2, 0, 0, 50, 0]).expect_err("60 is over 50");
        assert!(e.to_string().contains("60"), "{e}");
        assert!(e.to_string().contains("SAMPLE.MSG"), "{e}");
    }

    /// A bound wider than `numopt`'s own `i16` could ever hold -- the whole
    /// reason `lngopt` exists alongside it. `THRESH` in `GALFIL.C:359`
    /// reads `lngopt(THRESH,1,1000)`, but `FTPZWINDOW`
    /// (`FILEXFER.C:229`) reads up to `1000000000L`, which does not fit an
    /// `i16` floor/ceiling at all -- proving the argument really is 32 bits
    /// wide, not truncated to 16 and sign-extended back.
    #[test]
    fn lngopt_accepts_a_ceiling_that_does_not_fit_a_16_bit_int() {
        let mut f = Fixture::new();
        opened(&mut f);
        let ceiling = 1_000_000_000i32;
        assert_eq!(
            f.invoke(
                lngopt,
                &[2, 0, 0, ceiling as u16, (ceiling >> 16) as u16]
            )
            .expect("read"),
            Ret::U32(60)
        );
    }

    #[test]
    fn lngopt_reads_a_negative_bound_as_negative() {
        // The same discrimination `numopt_reads_a_negative_bound_as_negative`
        // makes, one word wider: `msg 5` (`NEGOPT`) is -5, and read as
        // unsigned a -32767 floor would refuse every negative option.
        let mut f = Fixture::new();
        opened(&mut f);
        let floor = -32767i32;
        assert_eq!(
            f.invoke(
                lngopt,
                &[5, floor as u16, (floor >> 16) as u16, 32767, 0]
            )
            .expect("read"),
            Ret::U32((-5i32) as u32)
        );
    }

    #[test]
    fn ynopt_and_chropt() {
        let mut f = Fixture::new();
        opened(&mut f);
        assert_eq!(f.invoke(ynopt, &[3]).expect("read"), Ret::U16(1));
        assert_eq!(f.invoke(ynopt, &[4]).expect("read"), Ret::U16(0));
        assert_eq!(
            f.invoke(chropt, &[6]).expect("read"),
            Ret::U16(u16::from(b'='))
        );
    }

    #[test]
    fn ynopt_on_something_that_is_neither_refuses() {
        let mut f = Fixture::new();
        opened(&mut f);
        assert!(f.invoke(ynopt, &[1]).is_err(), "DEMO is not yes or no");
    }

    #[test]
    fn tokopt_is_one_based_and_refuses_a_token_in_no_list() {
        let mut f = Fixture::new();
        opened(&mut f);
        let high = f.text("HIGH");
        let medium = f.text("MEDIUM");
        let none = f.text("NONE");

        // Message 7 is `NONE`, the third of three.
        let args = [
            7,
            high.offset,
            high.selector,
            medium.offset,
            medium.selector,
            none.offset,
            none.selector,
            0,
            0,
        ];
        assert_eq!(f.invoke(tokopt, &args).expect("matched"), Ret::U16(3));

        let short = [7, high.offset, high.selector, medium.offset, medium.selector, 0, 0];
        assert!(f.invoke(tokopt, &short).is_err(), "NONE is in neither");
    }

    #[test]
    fn prfmsg_appends_to_the_print_buffer_the_way_prf_does() {
        let mut f = Fixture::new();
        opened(&mut f);

        // Message 8 is `<%d>`.
        f.invoke(prfmsg, &[8, 1]).expect("first");
        f.invoke(prfmsg, &[8, 2]).expect("second");

        let buffer = f.host.globals().prf_buffer();
        assert_eq!(f.read(buffer), "<1><2>");
        assert_eq!(
            f.host.globals().pointer(&f.machine, "prfptr").expect("ptr"),
            FarPtr {
                offset: buffer.offset + 6,
                selector: buffer.selector,
            },
            "prfptr moved past what was written"
        );
    }

    #[test]
    fn an_option_past_the_end_of_the_file_refuses() {
        let mut f = Fixture::new();
        opened(&mut f);
        let e = f.invoke(stgopt, &[9999]).expect_err("no such message");
        assert!(e.to_string().contains("SAMPLE.MSG"), "{e}");
    }

    #[test]
    fn reading_an_option_with_no_block_set_refuses() {
        let mut f = Fixture::new();
        assert!(f.invoke(stgopt, &[0]).is_err(), "nothing is current");
    }

    /// Closing a block waiting under the current one keeps the `rstmbk` stack
    /// the same depth, and the restore lands on "nothing current".
    ///
    /// LunatiX's `finrou` does this: it closes `cwdlunat.MSG` while current
    /// and then `cwdrooms.MSG` from under it. Refusing stopped the machine;
    /// *removing* the entry would be worse than either, because `rstmbk` pairs
    /// one pop per unmatched `setmbk` and a shorter stack re-points every
    /// later restore at the wrong block.
    #[test]
    fn clsmsg_nulls_a_block_waiting_under_the_current_one_and_keeps_the_depth() {
        let mut f = Fixture::new();
        let first = opened(&mut f);
        let second = open(&mut f, "OTHER.MSG");

        f.invoke(clsmsg, &Fixture::far(first)).expect("closing from under is allowed");

        // Still one pop for the one unmatched `setmbk`, not zero.
        f.invoke(rstmbk, &[]).expect("the depth is unchanged");
        assert!(
            f.invoke(stgopt, &[0]).is_err(),
            "the restore landed on the null, so nothing is current -- rather than \
             on a block that had been closed"
        );

        f.invoke(rstmbk, &[]).expect("back to none");
        f.invoke(clsmsg, &Fixture::far(second)).expect("no longer in use");
        assert!(
            f.invoke(setmbk, &Fixture::far(second)).is_err(),
            "a closed block is not one to set"
        );
    }

    /// A module closing the block it is currently reading is ordinary
    /// teardown, not an error -- and `curmbk` stops naming it.
    ///
    /// LunatiX's `finrou` does exactly this on the way out. Refusing it
    /// stopped the machine mid-shutdown, which is how it was found: the stop
    /// only became reachable once this host started dispatching `finrou` at
    /// all, so no survey could have seen it.
    #[test]
    fn clsmsg_closes_the_current_block_and_leaves_nothing_current() {
        let mut f = Fixture::new();
        let only = opened(&mut f);

        f.invoke(clsmsg, &Fixture::far(only)).expect("closing the current block is allowed");

        assert!(
            f.invoke(stgopt, &[0]).is_err(),
            "nothing is current now, so an option read refuses -- rather than \
             reading through a `curmbk` that still names a closed block"
        );
        assert!(
            f.invoke(setmbk, &Fixture::far(only)).is_err(),
            "and the closed block is not one to set again"
        );
    }

    #[test]
    fn rawmsg_returns_the_compact_text_by_message_number() {
        let mut f = Fixture::new();
        opened(&mut f);
        let Ret::Far(at) = f.invoke(rawmsg, &[1]).expect("read") else {
            panic!("rawmsg returns a pointer");
        };
        assert_eq!(f.read(at), "DEMO");
    }

    #[test]
    fn rawmsg_names_the_same_address_message_mem_already_does() {
        // Real GETASC.C/MCVAPI.C both hand back a pointer into a host-owned
        // buffer the module must not free, unlike stgopt's fresh copy. This
        // host already keeps each message at a stable address; rawmsg names
        // it directly rather than copying through a scratch buffer of its
        // own.
        let mut f = Fixture::new();
        opened(&mut f);
        let Ret::Far(at) = f.invoke(rawmsg, &[2]).expect("read") else {
            panic!("rawmsg returns a pointer");
        };
        let expected = message(&f.machine, &f.host, 2).expect("message_mem");
        assert_eq!(at, expected);
    }

    #[test]
    fn rawmsg_with_no_message_block_current_is_refused() {
        let mut f = Fixture::new();
        assert!(f.invoke(rawmsg, &[1]).is_err(), "no block current is a refusal");
    }



    /// A `.MSG` file with one option whose value has an embedded line break
    /// that survives `MsgFile::parse`'s `line_endings` as a bare `\n` -- the
    /// break is followed by an alphanumeric character (`l` of "line two"),
    /// which `line_endings` keeps literal rather than turning into `\r`. See
    /// `crate::msg::line_endings`. Message 0 is `TESTMSG`, the only option.
    fn open_multiline(f: &mut Fixture) {
        let dir = crate::testing::scratch("getasc-shim");
        std::fs::write(
            dir.join("MULTI.MSG"),
            b"TESTMSG {line one\nline two} S 30 whatever\n",
        )
        .expect("write a test .MSG file");
        *f = Fixture::rooted(dir);
        let name = f.text("MULTI.MSG");
        f.invoke(opnmsg, &Fixture::far(name)).expect("opens");
    }

    #[test]
    fn getasc_expands_bare_newlines_the_way_the_msg_helper_does() {
        // char *getasc(int msgnum) -- GCOMM.H:283. The transform itself is
        // crate::msg::getasc; this asserts the shim reaches it by message
        // number and returns a pointer to the expanded text.
        let mut f = Fixture::new();
        open_multiline(&mut f);
        let Ret::Far(p) = f.invoke(getasc, &[0]).expect("getasc") else {
            panic!("getasc returns a pointer");
        };
        assert_eq!(f.read(p), "line one\r\nline two");
    }

    #[test]
    fn getasc_with_no_message_block_current_is_refused() {
        let mut f = Fixture::new();
        assert!(f.invoke(getasc, &[1]).is_err(), "no block current is a refusal");
    }

    #[test]
    fn getasc_result_is_the_modules_own_fresh_block() {
        // Unlike rawmsg, which names the host's stable per-message address
        // directly, getasc cannot: that address holds the compact form
        // other option readers still rely on. Confirm it is a heap block
        // like stgopt's, not message_mem's own address.
        let mut f = Fixture::new();
        opened(&mut f);
        let Ret::Far(p) = f.invoke(getasc, &[1]).expect("getasc") else {
            panic!("getasc returns a pointer");
        };
        assert_eq!(f.host.heap().block(p), Some(5), "DEMO plus a terminator");
    }
}
