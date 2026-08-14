//! `prfmlt`, `pmlt` and `getmsg` -- the "mlt" print-buffer family and the
//! message accessor that feeds it.
//!
//! # The "mlt" family, and why this file does not reinvent
//! [`crate::shims::output`]'s answer
//!
//! `GCOMM.H:468-477` (`archive/galacticomm/extract/wg1/GALDSRC/SRC/GCOMM.H`
//! -- the wg1 tree, never wg20: the same file has different line numbers
//! there and a wg20 citation would silently point at the wrong line)
//! declares the whole family together:
//!
//!
//! It is Worldgroup's answer to serving more than one language from one
//! module: a *pool* of print buffers, one per active language, picked by
//! `mltflg`/`linuse`, so `prfmlt`/`pmlt` format into whichever buffer the
//! current user's language points at while plain `prf`/`prfmsg`'s single
//! `prfbuf` carries on unaffected.
//!
//! [`crate::shims::output`] already measured, for `outmlt` and `clrmlt`,
//! that **this host places none of `prfbuffers`, `prfpointers`, `linuse` or
//! `mltflg`** (`crate::globals` has no row for any of the four) -- and that
//! MBBSEmu, the one other independent host reimplementation available for
//! comparison, made the identical call for the identical reason (its own
//! `outmlt`/`clrmlt` are one-line aliases onto `outprf`/`clrprf`,
//! `MBBSEmu/HostProcess/ExportedModules/Majorbbs.cs:4824,4043`). With no
//! second buffer to pick a member of, there is only the one buffer `prf`/
//! `prfmsg` already format into and `outprf`/`clrprf` already flush and
//! clear -- so [`prfmlt`] and [`pmlt`] below collapse onto
//! [`crate::shims::msg::prfmsg`] and [`crate::shims::text::prf`] exactly the
//! way `outmlt`/`clrmlt` collapse onto `outprf`/`clrprf`. This is not a
//! second, independent simplification arrived at by guessing; it is the same
//! one, applied to the two members of the family `output.rs` did not cover
//! because they take arguments `outmlt`/`clrmlt` do not.
//!
//! # What Tele-Arena's own source settles that the header alone does not
//!
//! `GCOMM.H`'s prototypes leave two things ambiguous that matter for a
//! correct call frame: whether `prfmlt` takes a message *number* (like
//! `prfmsg`) or a format *string* (like `prf`), and the reverse question for
//! `pmlt`. Tele-Arena 5.6d's real source (`re/tasrc/tsgarn-*.c`, a shipping
//! module that calls these, not host source) settles both by direct
//! evidence, at every one of its own call sites:
//!
//! * `prfmlt` is always called with a bare identifier in argument position
//!   one -- `prfmlt(INVFUL)` (`re/tasrc/tsgarn-4.c:59`), `prfmlt(GETOTH2,
//!   usaptr->userid)` (`re/tasrc/tsgarn-4.c:95`) -- the same shape `prfmsg`'s
//!   own call sites take (a `.MSG`-file constant, never a quoted string).
//!   909 call sites in `re/tasrc/*.c` alone (measured: `grep -c 'prfmlt('
//!   re/tasrc/*.c`, summed). **`prfmlt` is `prfmsg`'s twin, not `prf`'s.**
//! * `pmlt` is always called with a quoted C string literal in argument
//!   position one -- `pmlt("\r")` (`re/tasrc/tsgarn-2.c:104`), `pmlt("***\r%s
//!   %s\r",usaptr->userid,margv[1])` (`re/tasrc/tsgarn-2.c:938`) -- the same
//!   shape `prf`'s own call sites take. 74 call sites (measured the same
//!   way). **`pmlt` is `prf`'s twin, not `prfmsg`'s.**
//!
//! # `getmsg`
//!
//! `MAJORBBS.H:752` (`char *getmsg(int msgnum);`) gives the prototype but not
//! the body. The body survives in
//! `archive/galacticomm/extract/wg1/GALDSRC/SRC/MAJORBBS.C:4517-4522`:
//!
//!
//! `rawmsg(int msgnum)` (`GCOMM.H:265`, in the "MSGUTL.C prototypes" block
//! next to `opnmsg`/`clsmsg`) is the message-block text lookup -- the same
//! job [`crate::shims::msg::message_mem`] already does for `prfmsg`/`stgopt`.
//! `xlttxv(char *buffer,int size)` (`MAJORBBS.H:794`, defined
//! `MENUING.C:1134-1155`) walks the raw text in place, expanding any
//! embedded text-variable marker (byte value `1`, `SOH`) via `grbtxv`, and
//! returns the same buffer it was given:
//!
//!
//! `mxmssz` (`GCOMM.H:270`) sizes the one shared buffer `rawmsg` reads
//! messages into -- the real host's `getmsg` mutates and returns *that*
//! buffer, not a fresh copy, which is why every caller must consume the
//! result before the next `getmsg` call.
//!
//! **This host implements no text-variable subsystem, and that is not a new
//! decision -- [`crate::shims::msg::stgopt`] already made it.** Its own doc
//! comment settles a message's text as coming straight out of the interned
//! message-block storage [`crate::shims::msg::message_mem`] resolves, with
//! no `%`-style substitution layer of any kind. [`getmsg`] follows the same
//! line, one step earlier: it hands back [`crate::shims::msg::message_mem`]'s
//! pointer directly, un-translated -- the same simplification `stgopt`
//! already carries, not a second one invented here. No `.MSG` file this repo
//! has decoded (`crates/mbbs/tests/data/SAMPLE.MSG`, and nothing Tele-Arena
//! ships as source) is known to contain byte `1` in a message body to
//! translate in the first place.
//!
//! Unlike [`crate::shims::msg::stgopt`], [`getmsg`] does **not** heap-allocate
//! a copy the module can `galfree`. Every one of the 46 Tele-Arena call sites
//! (`grep -c 'getmsg(' re/tasrc/*.c`, summed) either hands the result straight
//! to `strcpy`/`pmlt` in the same statement or reads it once and moves on --
//! e.g. `strcpy(od,getmsg(tods[arnarr[othusn].invent[in]]));`
//! (`re/tasrc/tsgarn-5.c:145`) and `pmlt(" %s(%d)",getmsg(tods[in]),chg[i])`
//! (`re/tasrc/tsgarn-4.c:108`) -- never assigning it to a variable that
//! outlives the statement, and never freeing it. That matches the real
//! `getmsg`'s own contract (a pointer into a buffer the *host* owns, good
//! only until overwritten) far better than `stgopt`'s module-owned-heap
//! contract would, so this returns the message block's own storage rather
//! than reaching for [`crate::heap::Heap::reserve`] the way `stgopt` does.
//! One respect in which this is *more* permissive than the real `getmsg`,
//! never less: because each message is interned at its own address rather
//! than copied through one shared `rawmsg` buffer, an earlier `getmsg`
//! result stays readable after a later call, where the real host's would
//! already have been overwritten. No measured call site relies on that
//! earlier invalidation, so widening it is safe.
//!
//! # `othuap` -- a datum, not a routine, and not implemented in this file
//!
//! `USRACC.H:73-76` (`archive/galacticomm/extract/wg1/GALDSRC/SRC/USRACC.H`):
//!
//!
//! One `extern` statement, three declarators -- and only the first two carry
//! their own `*`. `acctmp` has none, so it is a plain `struct usracc` value
//! (301+ bytes), not a pointer; `othuap`, like `usaptr`, is a `struct usracc
//! *`, four bytes under both ABIs. `othuap` is a module-memory *slot*
//! (`crate::globals::Globals`'s kind of global -- something a module's own
//! fixups read and write directly, never a routine this crate dispatches a
//! call to), so there is no `pub fn othuap` here: nothing calls it, and a
//! function with nothing to do would be theatre. See this task's final
//! report for the exact `globals.rs` row and the evidence for what sets and
//! reads it.

use super::ShimError;
use crate::Host;
use crate::abi::{self, Abi, Call};

/// `void prfmlt(int msgno,...)` -- `GCOMM.H:476`. `prfmsg`'s twin: append the
/// named message, formatted with the arguments that follow, to the channel's
/// output.
///
/// See this file's own module doc for the evidence (909 Tele-Arena call
/// sites, always a bare message identifier in the first argument) that
/// settles `prfmlt` as `prfmsg`'s twin and not `prf`'s, and for why -- with
/// no `prfbuffers`/`prfpointers`/`linuse`/`mltflg` pool placed in this host
/// -- collapsing onto [`crate::shims::msg::prfmsg`] is the same call
/// [`crate::shims::output::outmlt`] already made for the sibling that flushes
/// this buffer rather than fills it.
///
/// A multi-argument call site, to show the varargs plumbing is exercised and
/// not just the zero-argument shape: `prfmlt(GETOTH,usaptr->userid,objdes)`
/// (`re/tasrc/tsgarn-4.c:131`) -- `msgno` first, then the substitutions,
/// exactly [`crate::shims::msg::prfmsg`]'s own argument order.
pub fn prfmlt<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    super::msg::prfmsg(call, host)
}

/// `void pmlt(char *ctlstg,...)` -- `GCOMM.H:477`. `prf`'s twin: append a
/// module-supplied format, filled in with the arguments that follow, to the
/// channel's output.
///
/// See this file's own module doc for the evidence (74 Tele-Arena call
/// sites, always a quoted C string in the first argument) that settles
/// `pmlt` as `prf`'s twin and not `prfmsg`'s, and for why collapsing onto
/// [`crate::shims::text::prf`] is the same call
/// [`crate::shims::output::outmlt`] already made for the sibling that
/// flushes this buffer.
///
/// A multi-argument call site: `pmlt("***\r%s %s\r",usaptr->userid,
/// margv[1])` (`re/tasrc/tsgarn-2.c:938`) -- `ctlstg` first, then the
/// substitutions, exactly [`crate::shims::text::prf`]'s own argument order.
pub fn pmlt<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    super::text::prf(call, host)
}

/// `char *getmsg(int msgnum)` -- `MAJORBBS.H:752`. A message's text, in
/// place -- no template-variable translation, no heap copy; see this file's
/// own module doc for why both are safe simplifications rather than gaps.
///
/// 46 Tele-Arena call sites, every one reading the result once and moving on
/// -- e.g. `strcpy(wd,getmsg(tods[w]))` (`re/tasrc/tsgarn-5.c:208`) and,
/// chained straight into [`pmlt`], `pmlt(", %s",getmsg(tods[it]))`
/// (`re/tasrc/tsgarn-2.c:1126`).
pub fn getmsg<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let msgnum = Into::<u32>::into(call.int()) as u16;
    let at = super::msg::message_mem(call.mem(), host, msgnum)?;
    Ok(abi::Ret::Ptr(at))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;
    use mbbs_machine::m16::{FarPtr, Ret};

    /// Open `SAMPLE.MSG` and make it current, as a module would. Mirrors
    /// `shims::msg`'s own test helper of the same name -- this file has no
    /// access to it (`#[cfg(test)]`, private to that module), so it is
    /// reproduced rather than imported.
    fn opened(f: &mut Fixture) -> FarPtr {
        let at = f.text("SAMPLE.MSG");
        let Ret::Far(cookie) = f.invoke(crate::shims::msg::opnmsg, &Fixture::far(at)).expect("opens")
        else {
            panic!("opnmsg returns a pointer");
        };
        cookie
    }

    #[test]
    fn prfmlt_appends_the_named_message_like_prfmsg_does() {
        // Message 8 of SAMPLE.MSG is `<%d>` -- the same fixture
        // `shims::msg::tests::prfmsg_appends_to_the_print_buffer_the_way_prf_does`
        // uses, so a passing test here is directly comparable to that one.
        let mut f = Fixture::new();
        opened(&mut f);

        f.invoke(prfmlt, &[8, 1]).expect("first");
        f.invoke(prfmlt, &[8, 2]).expect("second");

        let buffer = f.host.globals().prf_buffer();
        assert_eq!(f.read(buffer), "<1><2>");
    }

    #[test]
    fn pmlt_appends_a_module_supplied_format_like_prf_does() {
        let mut f = Fixture::new();
        let template = f.text("<%d>");

        f.invoke(pmlt, &[template.offset, template.selector, 7]).expect("queued");

        let buffer = f.host.globals().prf_buffer();
        assert_eq!(f.read(buffer), "<7>");
    }

    #[test]
    fn pmlt_and_prfmlt_share_the_one_buffer_prf_and_prfmsg_already_use() {
        // The whole point of collapsing onto `prf`/`prfmsg`: a `pmlt` and a
        // `prfmlt` back to back land in the same buffer, in order, the way
        // they would if a real per-language pool held only one member.
        let mut f = Fixture::new();
        opened(&mut f);
        let template = f.text("[%s]");

        f.invoke(pmlt, &[template.offset, template.selector, template.offset, template.selector])
            .expect("pmlt queued first");
        // Message 8 is `<%d>`.
        f.invoke(prfmlt, &[8, 9]).expect("prfmlt queued second");

        let buffer = f.host.globals().prf_buffer();
        assert_eq!(f.read(buffer), "[[%s]]<9>");
    }

    #[test]
    fn getmsg_returns_the_named_messages_text() {
        // Message 1 of SAMPLE.MSG (`ACTIVATE`) is `DEMO`.
        let mut f = Fixture::new();
        opened(&mut f);

        let Ret::Far(at) = f.invoke(getmsg, &[1]).expect("read") else {
            panic!("getmsg returns a pointer");
        };
        assert_eq!(f.read(at), "DEMO");
    }

    #[test]
    fn getmsg_feeding_pmlt_matches_the_tele_arena_call_shape() {
        // `pmlt(", %s",getmsg(tods[it]))` -- `re/tasrc/tsgarn-2.c:1126`.
        let mut f = Fixture::new();
        opened(&mut f);
        let template = f.text(", %s");

        let Ret::Far(word) = f.invoke(getmsg, &[1]).expect("read") else {
            panic!("getmsg returns a pointer");
        };
        f.invoke(
            pmlt,
            &[template.offset, template.selector, word.offset, word.selector],
        )
        .expect("queued");

        let buffer = f.host.globals().prf_buffer();
        assert_eq!(f.read(buffer), ", DEMO");
    }

    #[test]
    fn getmsg_with_no_block_set_refuses() {
        // Mirrors `shims::msg::tests::reading_an_option_with_no_block_set_refuses`:
        // nothing is current, so there is no message-block storage to answer
        // message 1 out of.
        let mut f = Fixture::new();
        assert!(f.invoke(getmsg, &[1]).is_err(), "nothing is current");
    }

    #[test]
    fn getmsg_past_the_end_of_the_file_refuses() {
        let mut f = Fixture::new();
        opened(&mut f);
        let e = f.invoke(getmsg, &[9999]).expect_err("no such message");
        assert!(e.to_string().contains("SAMPLE.MSG"), "{e}");
    }
}
