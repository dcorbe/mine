//! Message files, and the options a module reads out of them.
//!
//! Signatures from `MCVAPI.H`, except `prfmsg` which is `GCOMM.H:811`:
//! `opnmsg` `:54`, `clsmsg` `:66`, `rstmbk` `:74`, `numopt` `:89`, `ynopt`
//! `:95`, `stgopt` `:103`, `tokopt` `:112`. `setmbk` has no prototype of its
//! own there -- `:43` declares the `curmbk` it sets.
//!
//!
//! The file format and what a value is are [`crate::msg`]'s; this is the part
//! that knows about the module. `rawmsg` and `getasc` are not imported by
//! `WCCMMUD.DLL` and are absent on purpose, as is `listing` -- which despite the
//! name is `FILEXFER.H:78`, listing an ASCII file to the user's screen, and
//! belongs with file transfer.
//!
//! # A misconfigured board is refused, not guessed at
//!
//! `numopt` outside its floor and ceiling, `ynopt` on something that is not yes
//! or no, `tokopt` on a token that is in no list: the real host had an answer
//! for each of these and every answer was a number the module could not tell
//! from a real one. Here they stop the module and name the option, which is the
//! same rule the rest of the crate is under. It is a deliberate difference from
//! the real host, and the only one in this file.

use mbbs16::{FarPtr, Machine, Ret};
use mbbs_ptr::ModulePtr;

use crate::Host;
use crate::abi::{self, Abi, Call};
use crate::fmt::{Args, format};
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

/// The dispatch-table entry for [`opnmsg`]. See `shims::call`'s own doc
/// comment.
pub fn opnmsg_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    opnmsg(&mut super::call(machine), host).map(Into::into)
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
    host.messages
        .close(current, cookie)
        .map_err(ShimError::Failed)?;
    Ok(abi::Ret::Void)
}

/// The dispatch-table entry for [`clsmsg`]. See `shims::call`'s own doc
/// comment.
pub fn clsmsg_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    clsmsg(&mut super::call(machine), host).map(Into::into)
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

/// The dispatch-table entry for [`setmbk`]. See `shims::call`'s own doc
/// comment.
pub fn setmbk_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    setmbk(&mut super::call(machine), host).map(Into::into)
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

/// The dispatch-table entry for [`rstmbk`]. See `shims::call`'s own doc
/// comment.
pub fn rstmbk_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    rstmbk(&mut super::call(machine), host).map(Into::into)
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
/// # Did not go generic (Task 5)
///
/// [`text::write_cstr`] takes `&mut Machine`, not `&mut A::Mem` -- `text.rs`
/// is a different file, out of this task's scope (the next one, taken
/// together with `fsd.rs`). [`Heap::reserve`](crate::heap::Heap::reserve) is
/// already generic, so the *allocation* half of this routine is not what
/// blocks it -- only the write into the block that follows.
pub fn stgopt(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let mut args = super::args(machine);
    let msgnum = args.int();
    let at = message(machine, host, msgnum)?;
    let text = machine.read_cstr(at)?.to_vec();

    let size = u16::try_from(text.len() + 1)
        .map_err(|_| ShimError::Failed(format!("a {}-byte message", text.len())))?;
    let out = host
        .heap
        .alloc(machine, size)
        .map_err(|e| ShimError::Failed(format!("stgopt: {e}")))?;
    text::write_cstr(machine, out, &text, size)?;
    Ok(Ret::Far(out))
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
    Ok(abi::Ret::Int(A::Int::from(parsed as i16 as u16)))
}

/// The dispatch-table entry for [`numopt`]. See `shims::call`'s own doc
/// comment.
pub fn numopt_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    numopt(&mut super::call(machine), host).map(Into::into)
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

/// The dispatch-table entry for [`ynopt`]. See `shims::call`'s own doc
/// comment.
pub fn ynopt_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    ynopt(&mut super::call(machine), host).map(Into::into)
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

/// The dispatch-table entry for [`chropt`]. See `shims::call`'s own doc
/// comment.
pub fn chropt_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    chropt(&mut super::call(machine), host).map(Into::into)
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

/// The dispatch-table entry for [`tokopt`]. See `shims::call`'s own doc
/// comment.
pub fn tokopt_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    tokopt(&mut super::call(machine), host).map(Into::into)
}

/// `void prfmsg(int msg,...)` -- append a message to the channel's output.
///
/// `prf` with the template coming from the current message block instead of
/// from the module. The arguments start at word 1, because `msg` is an `int`
/// and not the far pointer `prf`'s first argument is.
///
/// # Did not go generic (Task 5)
///
/// Only half unblocked: [`crate::fmt::format_call`] removes the *formatting*
/// blocker this routine used to have -- once `msgnum` is read with
/// `call.int()`, `call`'s position already marks where the varargs begin, so
/// `format_call(call, template)` could replace `format(machine, at,
/// Args::Call { first: 1 })` outright. What still blocks it is
/// [`text::append`], which takes `&mut Machine` and reaches
/// `channel_ansi`/`normalize_newlines`/`Host::current_channel` -- all
/// `text.rs`-private or `Wg16`-only, out of this task's scope (the next one,
/// taken together with `fsd.rs`, which touches `text.rs` and could unblock
/// this then).
pub fn prfmsg(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let mut args = super::args(machine);
    let msgnum = args.int();
    let at = message(machine, host, msgnum)?;
    let (text, _) = format(machine, at, Args::Call { first: 1 })?;
    text::append(machine, host, &text)?;
    Ok(Ret::Void)
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

/// The `Wg16` facade [`message_mem`] delegates into -- kept under its
/// original name and signature: `shims::fsd`'s tests call this directly
/// (not through `Fixture::invoke`), and [`stgopt`]/[`prfmsg`] still call it
/// as `(&Machine, &Host, u16)`.
pub(crate) fn message(machine: &Machine, host: &Host, n: u16) -> Result<FarPtr, ShimError> {
    message_mem(machine.mem(), host, n)
}

/// The text of message `n` of the current block.
///
/// Generic core (Task 5); see the `Wg16` facade [`stgopt`]/[`prfmsg`] still
/// need -- there is none by this exact old name, because nothing outside this
/// file called the old `read` directly (unlike [`message`]).
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
        let Ret::Far(cookie) = f.invoke(opnmsg_wg16, &Fixture::far(at)).expect("opens") else {
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
            f.invoke(opnmsg_wg16, &Fixture::far(name)).expect("opens"),
            Ret::Far(_)
        ));
    }

    #[test]
    fn opnmsg_names_a_file_it_cannot_find() {
        let mut f = Fixture::new();
        let name = f.text("NOSUCH.MSG");
        let e = f.invoke(opnmsg_wg16, &Fixture::far(name)).expect_err("no file");
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

        f.invoke(rstmbk_wg16, &[]).expect("back to the first");
        assert_eq!(curmbk(&f), first);
        f.invoke(rstmbk_wg16, &[]).expect("back to none");
        assert_eq!(curmbk(&f), nothing);
    }

    #[test]
    fn setmbk_moves_curmbk_in_module_memory_and_nowhere_else() {
        let mut f = Fixture::new();
        let first = opened(&mut f);
        let second = open(&mut f, "OTHER.MSG");

        f.invoke(setmbk_wg16, &Fixture::far(first)).expect("set");
        assert_eq!(curmbk(&f), first);
        f.invoke(rstmbk_wg16, &[]).expect("restored");
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
        assert!(f.invoke(setmbk_wg16, &Fixture::far(nonsense)).is_err());
        assert_eq!(curmbk(&f), before, "and left curmbk where it was");
    }

    #[test]
    fn rstmbk_with_nothing_to_undo_refuses() {
        // Rather than leaving `curmbk` at whatever seemed likely -- after which
        // every option read would come from that guess.
        let mut f = Fixture::new();
        assert!(f.invoke(rstmbk_wg16, &[]).is_err());
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
        f.invoke(crate::shims::memory::galfree_wg16, &Fixture::far(at))
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
        f.invoke(opnmsg_wg16, &Fixture::far(other)).expect("another file");
        let template = f.text("noise %d");
        f.invoke(text::prf_wg16, &[template.offset, template.selector, 7])
            .expect("some output");

        assert_eq!(f.read(first), "DEMO", "the first pointer still reads");
    }

    #[test]
    fn numopt_reads_the_number_off_the_end_of_the_prompt() {
        let mut f = Fixture::new();
        opened(&mut f);
        assert_eq!(f.invoke(numopt_wg16, &[2, 0, 32767]).expect("read"), Ret::U16(60));
    }

    #[test]
    fn numopt_outside_its_bounds_refuses_and_names_the_message() {
        let mut f = Fixture::new();
        opened(&mut f);
        let e = f.invoke(numopt_wg16, &[2, 0, 50]).expect_err("60 is over 50");
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
            f.invoke(numopt_wg16, &[5, floor, 32767]).expect("read"),
            Ret::U16((-5i16) as u16)
        );
    }

    #[test]
    fn ynopt_and_chropt() {
        let mut f = Fixture::new();
        opened(&mut f);
        assert_eq!(f.invoke(ynopt_wg16, &[3]).expect("read"), Ret::U16(1));
        assert_eq!(f.invoke(ynopt_wg16, &[4]).expect("read"), Ret::U16(0));
        assert_eq!(
            f.invoke(chropt_wg16, &[6]).expect("read"),
            Ret::U16(u16::from(b'='))
        );
    }

    #[test]
    fn ynopt_on_something_that_is_neither_refuses() {
        let mut f = Fixture::new();
        opened(&mut f);
        assert!(f.invoke(ynopt_wg16, &[1]).is_err(), "DEMO is not yes or no");
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
        assert_eq!(f.invoke(tokopt_wg16, &args).expect("matched"), Ret::U16(3));

        let short = [7, high.offset, high.selector, medium.offset, medium.selector, 0, 0];
        assert!(f.invoke(tokopt_wg16, &short).is_err(), "NONE is in neither");
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

    #[test]
    fn clsmsg_will_not_forget_a_block_that_is_still_in_use() {
        let mut f = Fixture::new();
        let first = opened(&mut f);
        let second = open(&mut f, "OTHER.MSG");

        // `second` is current and `first` is what the next `rstmbk` goes back
        // to. Forgetting either leaves `curmbk` naming a block the host has no
        // record of, and every option read after that is a refusal about the
        // wrong thing.
        assert!(f.invoke(clsmsg_wg16, &Fixture::far(second)).is_err());
        assert!(f.invoke(clsmsg_wg16, &Fixture::far(first)).is_err());

        f.invoke(rstmbk_wg16, &[]).expect("back to the first");
        f.invoke(rstmbk_wg16, &[]).expect("back to none");

        f.invoke(clsmsg_wg16, &Fixture::far(second)).expect("no longer in use");
        assert!(
            f.invoke(setmbk_wg16, &Fixture::far(second)).is_err(),
            "a closed block is not one to set"
        );
    }
}
