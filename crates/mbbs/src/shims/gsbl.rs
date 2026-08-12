//! The GSBL routines `WCCMMUD.DLL` actually imports.
//!
//! ```text
//! btutsw 21   btuxct 16   btuxnf 14   btuxmt  8   btuoes  3   btuclo  3
//! btulok  2   btucli  2   btuinj  2   btutrg  2   btuech  1   btumil  1
//! btuibw  1   btuica  1
//! ```
//!
//! Fourteen routines and seventy-seven call sites, and **not one of them in
//! segment 21**, where initialisation lives -- which is the mechanical reason
//! `_INIT__WCCMMUD` could run to completion without any of this existing.
//!
//! Every one is thin. The state is [`crate::gsbl`]; these read arguments,
//! bound-check the channel and delegate. The return codes are the guide's:
//! `-10` channel not defined, `-11` out of range, `0` all is well. **`-10` is
//! unreachable here** -- `Host::new` allocates every channel and there is no
//! `btudef` -- so out of range is the only refusal.
//!
//! `bturno`, the fifteenth import, is not here: it is a datum, placed in
//! `globals.rs`, and the module reads it directly at 1,096 fixups.
//!
//! Three more live here without being an import at all: `btuhpk`, `btupbc`
//! and `btucpc`, `WCCMMUD.DLL` never asks for -- `re/exports/imports.txt` has
//! no site for any of them (Task 1 of `docs/plans/2026-08-11-live-session-defects.md`
//! is the inventory). They exist because `MAJORBBS.C:3776`'s `rstrxf`
//! (`crate::shims::screen`) needs their behaviour, and every other GALGSBL
//! routine lives here rather than wherever its one caller happens to be.
//! `rstrxf` does not call through this table -- there is no module far call
//! to dispatch and no stack to read arguments off -- it calls each `apply_*`
//! function directly with values it already has.

use mbbs16::{Machine, Ret};

use super::ShimError;
use crate::Host;
use crate::chan::Chan;
use crate::gsbl::Gsbl;

/// `-11`: "channel number is out of range". See the module docs for why `-10`
/// cannot happen.
pub(crate) const OUT_OF_RANGE: u16 = -11i16 as u16;

/// Run `body` against a channel, or answer `-11`.
///
/// Every one of the fourteen begins this way, so it is written once. The
/// alternative -- fourteen copies of the same bound check -- is fourteen places
/// for one of them to be missing.
///
/// `body` is handed the [`Chan`] this minted rather than being left to find the
/// channel again from the raw number. Every one of these used to do that, and
/// every one of them ended `.expect("in range")` -- fourteen assertions that the
/// check two lines above had happened, which is what having the check and the
/// use in different types buys you.
fn on_channel<T>(
    host: &mut Host,
    chan: i16,
    body: impl FnOnce(&mut crate::gsbl::Gsbl, Chan) -> T,
) -> Option<T> {
    let chan = host.gsbl().terms().chan(chan)?;
    Some(body(host.gsbl_mut(), chan))
}

/// `int btutsw(int chan, int width)` -- output word-wrap width. Zero disables.
pub fn btutsw(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let mut args = super::args(machine);
    let chan = args.int() as i16;
    let width = args.int();
    Ok(match on_channel(host, chan, |g, chan| {
        g.channel_mut(chan).width = width;
    }) {
        Some(()) => Ret::U16(0),
        None => Ret::U16(OUT_OF_RANGE),
    })
}

/// `int btumil(int chan, int maxinl)` -- maximum input line length. Zero
/// disables the limit.
pub fn btumil(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let mut args = super::args(machine);
    let chan = args.int() as i16;
    let maxinl = args.int();
    Ok(match on_channel(host, chan, |g, chan| {
        g.channel_mut(chan).maxinl = maxinl;
    }) {
        Some(()) => Ret::U16(0),
        None => Ret::U16(OUT_OF_RANGE),
    })
}

/// `int btuech(int chan, int onoff)` -- echo input back to the terminal.
pub fn btuech(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let mut args = super::args(machine);
    let chan = args.int() as i16;
    let onoff = args.int();
    Ok(match on_channel(host, chan, |g, chan| {
        g.channel_mut(chan).echo = onoff != 0;
    }) {
        Some(()) => Ret::U16(0),
        None => Ret::U16(OUT_OF_RANGE),
    })
}

/// `int btulok(int chan, int onoff)` -- input lockout: arriving bytes are
/// discarded while locked.
pub fn btulok(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let mut args = super::args(machine);
    let chan = args.int() as i16;
    let onoff = args.int();
    Ok(match on_channel(host, chan, |g, chan| {
        g.channel_mut(chan).locked = onoff != 0;
    }) {
        Some(()) => Ret::U16(0),
        None => Ret::U16(OUT_OF_RANGE),
    })
}

/// `int btuoes(int chan, int onoff)` -- raise status 5 when the output buffer
/// empties.
pub fn btuoes(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let mut args = super::args(machine);
    let chan = args.int() as i16;
    let onoff = args.int();
    Ok(match on_channel(host, chan, |g, chan| {
        g.channel_mut(chan).oes = onoff != 0;
    }) {
        Some(()) => Ret::U16(0),
        None => Ret::U16(OUT_OF_RANGE),
    })
}

/// `int btutrg(int chan, int nbyt)` -- byte-count input trigger. Zero is ASCII
/// mode; non-zero switches to binary mode and sets the block size.
pub fn btutrg(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let mut args = super::args(machine);
    let chan = args.int() as i16;
    let nbyt = args.int();
    Ok(match on_channel(host, chan, |g, chan| {
        g.channel_mut(chan).trigger = nbyt;
    }) {
        Some(()) => Ret::U16(0),
        None => Ret::U16(OUT_OF_RANGE),
    })
}

/// `int btuxnf(int chan, int xon, int xoff, ...)` -- the XON and XOFF
/// characters, and (R5, guide `btuxnf` page 193) page mode. A **negative**
/// `xoff` selects page mode and adds two more arguments: `cnt`, the number of
/// lines to show before pausing, and `stg`, the pause message -- which is why
/// the module cleans 3 words at six call sites (plain flow control) and 6 at
/// eight others (page mode). Those two are only read when `xoff` says to
/// expect them, never a blind read of the variadic tail.
///
/// Page mode itself is **not implemented** -- see `Channel::page_lines`.
/// `cnt` and the pause message are recorded so they are not lost, and
/// pagination is a driver problem (Batch C of this plan), not a GSBL one.
pub fn btuxnf(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let mut args = super::args(machine);
    let chan = args.int() as i16;
    let xon = args.int();
    let xoff = args.int() as i16;
    // The two page-mode arguments are read only when xoff says to expect
    // them -- see this function's own doc comment. The cursor reads them in
    // frame order regardless of which branch runs, same as `arg_u16(3)`/
    // `arg_far(4)` did: the reads that happen, happen sequentially.
    let page = if xoff < 0 {
        let cnt = args.int();
        let stg = args.ptr();
        Some((cnt, machine.read_cstr(stg)?.to_vec()))
    } else {
        None
    };
    Ok(match on_channel(host, chan, |g, chan| apply_xnf(g, chan, xon, xoff, page)) {
        Some(()) => Ret::U16(0),
        None => Ret::U16(OUT_OF_RANGE),
    })
}

/// The mutation [`btuxnf`] performs, apart from reading the module's stack --
/// so that [`crate::shims::screen::rstrxf`] (`MAJORBBS.C:3778`) can drive the
/// same channel-state update with values it already has in hand, rather than
/// a second copy of these four lines that could drift from the first.
pub(crate) fn apply_xnf(
    g: &mut Gsbl,
    chan: Chan,
    xon: u16,
    xoff: i16,
    page: Option<(u16, Vec<u8>)>,
) {
    let c = g.channel_mut(chan);
    c.xon = xon as u8;
    c.xoff = xoff as u8;
    if let Some((cnt, message)) = page {
        c.page_lines = cnt;
        c.page_message = Some(message);
    }
}

/// `int btuhpk(int chan, int far (*hpkrou)(int chan, char c))` -- install the
/// routine called for each keystroke received while a channel is in
/// screen-pause mode (guide `btuhpk`, page 99).
///
/// **Not registered as a `WCCMMUD.DLL` import** -- see the module doc comment
/// on `crate::shims::gsbl` and the inventory in `crate::shims::screen` --
/// this exists so [`crate::shims::screen::rstrxf`] (the one caller this host
/// has) has a real GSBL routine to call, the same way every other GALGSBL
/// entry in the registration table does, and so it is independently testable
/// through the same `Fixture::invoke` every other one of these fourteen is.
///
/// The second argument -- the far pointer to the handler -- is deliberately
/// never read: see [`crate::gsbl::Channel::pause_handler_installed`] for why
/// a `bool` is the whole of what this host records.
pub fn btuhpk(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let mut args = super::args(machine);
    let chan = args.int() as i16;
    Ok(match on_channel(host, chan, apply_hpk) {
        Some(()) => Ret::U16(0),
        None => Ret::U16(OUT_OF_RANGE),
    })
}

/// The mutation [`btuhpk`] performs. See [`apply_xnf`] for why this is
/// factored out.
pub(crate) fn apply_hpk(g: &mut Gsbl, chan: Chan) {
    g.channel_mut(chan).pause_handler_installed = true;
}

/// `int btupbc(int chan, char pausch)` -- set the screen-pause character
/// (guide `btupbc`, page 133): transmitting it puts the channel into
/// screen-pause mode. Zero disables it. The Major BBS uses Control-T (20).
///
/// Not a `WCCMMUD.DLL` import today -- see [`btuhpk`]'s doc comment, which
/// applies here unchanged.
pub fn btupbc(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let mut args = super::args(machine);
    let chan = args.int() as i16;
    let pausch = args.int() as u8;
    Ok(match on_channel(host, chan, |g, chan| apply_pbc(g, chan, pausch)) {
        Some(()) => Ret::U16(0),
        None => Ret::U16(OUT_OF_RANGE),
    })
}

/// The mutation [`btupbc`] performs. See [`apply_xnf`] for why this is
/// factored out.
pub(crate) fn apply_pbc(g: &mut Gsbl, chan: Chan, pausch: u8) {
    g.channel_mut(chan).pause_char = pausch;
}

/// `int btucpc(int chan, char cpchar)` -- set the clear-pause-counter
/// character (guide `btucpc`, page 81): discovered in the output stream, it
/// resets the pending-lines counter to zero without being transmitted. The
/// Major BBS uses Control-S (19) to suppress a pause at strategic points.
///
/// Not a `WCCMMUD.DLL` import today -- see [`btuhpk`]'s doc comment, which
/// applies here unchanged.
pub fn btucpc(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let mut args = super::args(machine);
    let chan = args.int() as i16;
    let cpchar = args.int() as u8;
    Ok(match on_channel(host, chan, |g, chan| apply_cpc(g, chan, cpchar)) {
        Some(()) => Ret::U16(0),
        None => Ret::U16(OUT_OF_RANGE),
    })
}

/// The mutation [`btucpc`] performs. See [`apply_xnf`] for why this is
/// factored out.
pub(crate) fn apply_cpc(g: &mut Gsbl, chan: Chan, cpchar: u8) {
    g.channel_mut(chan).clear_pause_char = cpchar;
}

/// `int btuclo(int chan)` -- throw away output that has not gone out yet.
pub fn btuclo(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let mut args = super::args(machine);
    let chan = args.int() as i16;
    Ok(match on_channel(host, chan, |g, chan| {
        let c = g.channel_mut(chan);
        c.output.clear();
        c.column = 0;
    }) {
        Some(()) => Ret::U16(0),
        None => Ret::U16(OUT_OF_RANGE),
    })
}

/// `int btucli(int chan)` -- throw away input that has not been taken yet.
///
/// **Leaves the status FIFO alone.** The guide's CAUTIONS for `btucli`: calling
/// it "can cause inconsistencies between the status buffer contents and the
/// input buffer contents" -- a CR-terminated string's status can remain queued
/// with no string behind it. That inconsistency is documented behaviour, not a
/// bug to fix; a "helpful" implementation that also drained `status` would
/// diverge from every real board.
pub fn btucli(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let mut args = super::args(machine);
    let chan = args.int() as i16;
    Ok(match on_channel(host, chan, |g, chan| {
        let c = g.channel_mut(chan);
        c.input.clear();
        c.line.clear();
        c.ready.clear();
    }) {
        Some(()) => Ret::U16(0),
        None => Ret::U16(OUT_OF_RANGE),
    })
}

/// `int btuinj(int chan, int status)` -- inject a status code into the FIFO.
pub fn btuinj(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let mut args = super::args(machine);
    let chan = args.int() as i16;
    let status = args.int() as i16;
    Ok(match on_channel(host, chan, |g, chan| {
        g.inject(chan, status);
    }) {
        Some(()) => Ret::U16(0),
        None => Ret::U16(OUT_OF_RANGE),
    })
}

/// `int btuibw(int chan)` -- input bytes waiting.
///
/// Everything not yet handed to the module: raw binary-mode bytes, the line
/// still being typed, and every completed line nobody has taken yet (R3: more
/// than one can queue up). The guide's use case is peeking at keystrokes without consuming them, which is only answerable if a half-typed line
/// counts.
///
/// Finding 11 (not fixed): this undercounts a queued line by one relative to
/// real GSBL, which keeps the CR in its buffer; this host stores lines
/// without their terminator. Only matters if the module compares the count
/// against a length it computed itself -- it does not.
pub fn btuibw(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let mut args = super::args(machine);
    let chan = args.int() as i16;
    let Some(chan) = host.gsbl().terms().chan(chan) else {
        return Ok(Ret::U16(OUT_OF_RANGE));
    };
    let c = host.gsbl().channel(chan);
    let waiting: usize =
        c.input.len() + c.line.len() + c.ready.iter().map(Vec::len).sum::<usize>();
    Ok(Ret::U16(waiting as u16))
}

/// `int btuxmt(int chan, char *datstg)` -- transmit an ASCIIZ string.
///
/// This is MajorMUD's whole output path. It has no `outprf`: it formats with
/// `prf` into `prfbuf` and calls `btuxmt(chan, prfbuf)` itself, through
/// `_TELL_USER` at 677 sites.
pub fn btuxmt(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let mut args = super::args(machine);
    let chan = args.int() as i16;
    let at = args.ptr();
    let Some(chan) = host.gsbl().terms().chan(chan) else {
        return Ok(Ret::U16(OUT_OF_RANGE));
    };
    let text = machine.read_cstr(at)?.to_vec();
    host.gsbl_mut().transmit(chan, &text);
    Ok(Ret::U16(0))
}

/// `int btuxct(int chan, int nbyt, const char *datstg)` -- transmit `nbyt`
/// bytes.
///
/// Binary: the length is given rather than scanned for, so an embedded NUL is
/// data. None of the ASCII output features apply -- the guide is explicit that
/// word wrap and XON/XOFF "are not in effect when you use btuxct()".
pub fn btuxct(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let mut args = super::args(machine);
    let chan = args.int() as i16;
    let nbyt = args.int();
    let at = args.ptr();
    let Some(chan) = host.gsbl().terms().chan(chan) else {
        return Ok(Ret::U16(OUT_OF_RANGE));
    };
    let data = machine.resolve(at, usize::from(nbyt))?.to_vec();
    host.gsbl_mut().transmit_raw(chan, &data);
    Ok(Ret::U16(0))
}

/// `int btuica(int chan, char *rdbptr, int max)` -- take up to `max` bytes of
/// count-triggered input, and return how many were taken.
///
/// R12: resolve the destination *before* draining the channel. Draining
/// first and writing second means a bad pointer's `?` propagates only after
/// the bytes are already gone from `input` -- a write that never happened,
/// having destroyed the data it was supposed to deliver. `machine.resolve`
/// with the exact length `machine.write` will use validates the same bounds
/// without mutating anything, so if it succeeds, the write after the drain
/// cannot fail.
pub fn btuica(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let mut args = super::args(machine);
    let chan = args.int() as i16;
    let at = args.ptr();
    let max = args.int();
    let Some(chan) = host.gsbl().terms().chan(chan) else {
        return Ok(Ret::U16(OUT_OF_RANGE));
    };
    let c = host.gsbl().channel(chan);
    let take = usize::from(max).min(c.input.len());

    machine.resolve(at, take)?;

    let c = host.gsbl_mut().channel_mut(chan);
    let bytes: Vec<u8> = c.input.drain(..take).collect();
    machine
        .write(at, &bytes)
        .expect("resolve above already validated this exact pointer and length");
    Ok(Ret::U16(take as u16))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;

    /// Every one of the fourteen refuses the same way, so this is asserted once
    /// per routine rather than reasoned about once.
    #[test]
    fn every_routine_refuses_a_channel_out_of_range() {
        let mut f = Fixture::new();
        let past = f.host.gsbl().terms().count();
        for (name, ret) in [
            ("btutsw", f.invoke(btutsw, &[past, 80])),
            ("btumil", f.invoke(btumil, &[past, 40])),
            ("btuech", f.invoke(btuech, &[past, 1])),
            ("btulok", f.invoke(btulok, &[past, 1])),
            ("btuoes", f.invoke(btuoes, &[past, 1])),
            ("btutrg", f.invoke(btutrg, &[past, 4])),
            ("btuinj", f.invoke(btuinj, &[past, 3])),
            ("btuclo", f.invoke(btuclo, &[past])),
            ("btucli", f.invoke(btucli, &[past])),
            ("btuibw", f.invoke(btuibw, &[past])),
            ("btuhpk", f.invoke(btuhpk, &[past, 0, 0])),
            ("btupbc", f.invoke(btupbc, &[past, 20])),
            ("btucpc", f.invoke(btucpc, &[past, 19])),
        ] {
            assert_eq!(
                ret.expect(name),
                Ret::U16(OUT_OF_RANGE),
                "{name} on a channel past nterms"
            );
        }
    }

    #[test]
    fn btuxmt_transmits_and_btutsw_is_what_wraps_it() {
        let mut f = Fixture::new();
        let console = f.console();
        f.invoke(btutsw, &[0, 10]).expect("width set");
        let text = f.text("the quick brown fox");
        f.invoke(btuxmt, &[0, text.offset, text.selector])
            .expect("transmitted");
        assert_eq!(
            f.host.gsbl_mut().drain_output(console),
            b"the quick\r\nbrown fox".to_vec()
        );
    }

    #[test]
    fn btuxmt_writes_to_the_channel_it_was_given_and_not_the_current_one() {
        // MajorMUD's entire cross-user output path. `_TELL_USER(chan)`
        // (`re/exports/WCCMMUD_named.c:65778`) is handed a channel number,
        // reads *that* player's filter bits out of `user[chan]`, and
        // transmits. It never calls `curusr`, so the channel `btuxmt` is given
        // is routinely not the channel the module is running as -- and every
        // other test in this file, and the two-channel acceptance test in
        // `tests/wccmmud.rs`, share a shape that hides the difference.
        //
        // Three channels, not two; the module runs as channel 2 and writes to
        // channel 1. Under any two-channel arrangement a shim that transmitted
        // to `usrnum`, and a shim that always transmitted to channel zero, are
        // each indistinguishable from a correct one for some assignment of the
        // two roles. Here every one of the three rings answers separately.
        let mut f = Fixture::rooted_with_terms(crate::testing::data(), crate::Terms::new(3));
        let terms = f.host.gsbl().terms();
        let zero = terms.chan(0).expect("channel 0");
        let one = terms.chan(1).expect("channel 1");
        let two = terms.chan(2).expect("channel 2");

        // The module is running as channel 2: `usrnum`, `usrptr`, `usaptr` and
        // `vdaptr` all name it, exactly as `Host::poll` leaves them before a
        // dispatch.
        f.host
            .point_curusr(&mut f.machine, two)
            .expect("channel 2 is current");

        let text = f.text("Kaimon just entered the Realm.");
        f.invoke(btuxmt, &[1, text.offset, text.selector])
            .expect("transmitted");

        assert_eq!(
            [
                f.host.gsbl_mut().drain_output(zero),
                f.host.gsbl_mut().drain_output(one),
                f.host.gsbl_mut().drain_output(two),
            ],
            [
                Vec::new(),
                b"Kaimon just entered the Realm.".to_vec(),
                Vec::new()
            ],
            "the argument names the ring -- not the current channel, and not zero"
        );
    }

    #[test]
    fn btuxct_sends_the_byte_count_it_was_given_and_no_terminator() {
        // Binary: the length is an argument, not a NUL scan, so an embedded
        // zero is data.
        let mut f = Fixture::new();
        let console = f.console();
        let data = f.bytes(&[b'a', 0, b'b'], false);
        f.invoke(btuxct, &[0, 3, data.offset, data.selector])
            .expect("transmitted");
        assert_eq!(f.host.gsbl_mut().drain_output(console), vec![b'a', 0, b'b']);
    }

    #[test]
    fn btuibw_counts_what_is_waiting_and_btucli_throws_it_away() {
        let mut f = Fixture::new();
        let console = f.console();
        f.host.gsbl_mut().channel_mut(console).trigger = 99;
        f.host.gsbl_mut().push_input(console, b"abcd");
        assert_eq!(f.invoke(btuibw, &[0]).expect("counted"), Ret::U16(4));
        f.invoke(btucli, &[0]).expect("cleared");
        assert_eq!(f.invoke(btuibw, &[0]).expect("counted"), Ret::U16(0));
    }

    /// Raw mode's bytes are ordinary input as far as these three are
    /// concerned, which is the whole reason `Channel::raw` collects into
    /// `input` rather than a buffer of its own.
    ///
    /// Here rather than in `crate::gsbl`'s tests, and the difference is not
    /// cosmetic. The version this replaces lived there and asserted `btuica`
    /// and `btucli` by calling `input.drain(..)` and `input.clear()` itself --
    /// which measures `VecDeque`, not the shims, and would have survived any
    /// mutation to either of them. The routines are reachable from here.
    ///
    /// The bytes are chosen so the answer would change if raw mode were not
    /// in force: `\x1b` and `\n` are both dropped by the input translate
    /// table, so a channel out of raw mode counts three of these five.
    ///
    /// The `btuibw` after the partial `btuica` is the second half of
    /// `gsbl::tests::leaving_raw_mode_restores_line_assembly_and_keeps_what_was_not_drained`:
    /// bytes raw mode collected and nobody drained keep being counted, which
    /// is the price of `fsdcof` not clearing input and is asserted rather than
    /// left to be discovered.
    #[test]
    fn raw_bytes_are_what_btuica_takes_btuibw_counts_and_btucli_throws_away() {
        let mut f = Fixture::new();
        let console = f.console();
        f.host.gsbl_mut().channel_mut(console).raw = true;
        f.host.gsbl_mut().push_input(console, b"a\x1b[A\n");

        assert_eq!(
            f.invoke(btuibw, &[0]).expect("counted"),
            Ret::U16(5),
            "all five keystrokes are waiting, ESC and LF included"
        );

        let buf = f.buffer(16);
        let ret = f
            .invoke(btuica, &[0, buf.offset, buf.selector, 3])
            .expect("copied");
        assert_eq!(ret, Ret::U16(3));
        assert_eq!(
            f.machine.resolve(buf, 3).expect("in bounds"),
            b"a\x1b[",
            "in arrival order, uncooked"
        );
        assert_eq!(
            f.invoke(btuibw, &[0]).expect("counted"),
            Ret::U16(2),
            "and what the FSD did not take is still waiting to be asked for"
        );

        f.invoke(btucli, &[0]).expect("cleared");
        assert_eq!(
            f.invoke(btuibw, &[0]).expect("counted"),
            Ret::U16(0),
            "btucli reaches raw bytes -- it is how fsdcon drops type-ahead"
        );
    }

    #[test]
    fn btuclo_throws_away_output_that_has_not_gone_out() {
        let mut f = Fixture::new();
        let console = f.console();
        let text = f.text("wasted");
        f.invoke(btuxmt, &[0, text.offset, text.selector])
            .expect("transmitted");
        f.invoke(btuclo, &[0]).expect("cleared");
        assert!(f.host.gsbl_mut().drain_output(console).is_empty());
    }

    #[test]
    fn btuinj_puts_a_status_where_the_host_will_find_it() {
        let mut f = Fixture::new();
        let console = f.console();
        f.invoke(btuinj, &[0, 3]).expect("injected");
        assert_eq!(f.host.gsbl_mut().next_status(console), Some(3));
    }

    #[test]
    fn btuica_copies_what_is_waiting_up_to_the_maximum_it_was_given() {
        let mut f = Fixture::new();
        let console = f.console();
        f.host.gsbl_mut().channel_mut(console).trigger = 99;
        f.host.gsbl_mut().push_input(console, b"abcdef");
        let buf = f.buffer(16);
        let ret = f
            .invoke(btuica, &[0, buf.offset, buf.selector, 4])
            .expect("copied");
        assert_eq!(ret, Ret::U16(4), "the count copied, not the count waiting");
        assert_eq!(
            f.machine.resolve(buf, 4).expect("in bounds"),
            b"abcd",
            "and only four bytes landed"
        );
        assert_eq!(
            f.invoke(btuibw, &[0]).expect("counted"),
            Ret::U16(2),
            "what was copied is consumed"
        );
    }

    #[test]
    fn btuica_does_not_drain_input_when_the_destination_pointer_is_bad() {
        // R12: draining before validating the write destination meant a bad
        // pointer's error arrived after the bytes it was supposed to deliver
        // were already gone. Selector 0xdead names no segment of this
        // module's, so resolve (and the write it would otherwise attempt)
        // must fail -- and the bytes must still be waiting to be asked for
        // again.
        let mut f = Fixture::new();
        let console = f.console();
        f.host.gsbl_mut().channel_mut(console).trigger = 99;
        f.host.gsbl_mut().push_input(console, b"abcd");
        let ret = f.invoke(btuica, &[0, 0, 0xdead, 4]);
        assert!(ret.is_err(), "a destination that resolves to nothing must fail");
        assert_eq!(
            f.invoke(btuibw, &[0]).expect("counted"),
            Ret::U16(4),
            "nothing was drained -- the bytes are still there to ask for again"
        );
    }

    #[test]
    fn btuxnf_with_a_negative_xoff_records_the_page_parameters_without_paginating() {
        // R5, guide btuxnf page 193: a negative xoff selects page mode and
        // adds cnt/stg -- measured from the DLL's own six-word call sites:
        // btuxnf(usrnum, 0, 0xffed, 0x16, <far ptr to "Hit any key...">).
        // Pagination is deliberately not implemented; this only pins that
        // the parameters are not lost.
        let mut f = Fixture::new();
        let console = f.console();
        let msg = f.text("Hit any key to continue...");
        f.invoke(btuxnf, &[0, 0, 0xffed, 22, msg.offset, msg.selector])
            .expect("ok");
        let c = f.host.gsbl().channel(console);
        assert_eq!(c.xoff, 0xed, "the low byte still lands, negative or not");
        assert_eq!(c.page_lines, 22);
        assert_eq!(
            c.page_message.as_deref(),
            Some(b"Hit any key to continue...".as_slice())
        );
    }

    #[test]
    fn btuxnf_with_a_positive_xoff_records_no_page_parameters() {
        let mut f = Fixture::new();
        let console = f.console();
        f.invoke(btuxnf, &[0, 0, 19]).expect("ok");
        let c = f.host.gsbl().channel(console);
        assert_eq!(c.page_lines, 0);
        assert_eq!(c.page_message, None);
    }

    #[test]
    fn btuhpk_records_that_a_handler_was_installed() {
        let mut f = Fixture::new();
        let console = f.console();
        assert!(
            !f.host.gsbl().channel(console).pause_handler_installed,
            "nothing installed one yet"
        );
        f.invoke(btuhpk, &[0, 0x1234, 0x5678]).expect("ok");
        assert!(f.host.gsbl().channel(console).pause_handler_installed);
    }

    #[test]
    fn btupbc_and_btucpc_record_their_characters() {
        let mut f = Fixture::new();
        let console = f.console();
        f.invoke(btupbc, &[0, 20]).expect("ok");
        f.invoke(btucpc, &[0, 19]).expect("ok");
        let c = f.host.gsbl().channel(console);
        assert_eq!(c.pause_char, 20, "Control-T, the guide's own example");
        assert_eq!(c.clear_pause_char, 19, "Control-S, the guide's own example");
    }

    #[test]
    fn the_settings_reach_the_channel() {
        let mut f = Fixture::new();
        let console = f.console();
        f.invoke(btutsw, &[0, 80]).expect("ok");
        f.invoke(btumil, &[0, 40]).expect("ok");
        f.invoke(btuech, &[0, 0]).expect("ok");
        f.invoke(btulok, &[0, 1]).expect("ok");
        f.invoke(btuoes, &[0, 1]).expect("ok");
        f.invoke(btutrg, &[0, 8]).expect("ok");
        f.invoke(btuxnf, &[0, 17, 19]).expect("ok");

        let c = f.host.gsbl().channel(console);
        assert_eq!(c.width, 80);
        assert_eq!(c.maxinl, 40);
        assert!(!c.echo, "btuech(chan, 0) turns echo off");
        assert!(c.locked);
        assert!(c.oes);
        assert_eq!(c.trigger, 8);
        assert_eq!((c.xon, c.xoff), (17, 19));
    }

    #[test]
    fn btucli_leaves_a_status_queued_with_no_string_behind_it() {
        // The guide's own CAUTIONS. Clearing the status too would be tidier
        // and would not be GSBL.
        let mut f = Fixture::new();
        let console = f.console();
        f.host.gsbl_mut().push_input(console, b"look\r");
        f.invoke(btucli, &[0]).expect("cleared");
        assert_eq!(f.host.gsbl_mut().next_status(console), Some(crate::gsbl::Gsbl::CRSTG));
        assert_eq!(f.host.gsbl_mut().take_line(console), None);
    }
}
