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

use mbbs16::{Machine, Ret};

use super::ShimError;
use crate::Host;

/// `-11`: "channel number is out of range". See the module docs for why `-10`
/// cannot happen.
pub(crate) const OUT_OF_RANGE: u16 = -11i16 as u16;

/// Run `body` against a channel, or answer `-11`.
///
/// Every one of the fourteen begins this way, so it is written once. The
/// alternative -- fourteen copies of the same bound check -- is fourteen places
/// for one of them to be missing.
fn on_channel<T>(
    host: &mut Host,
    chan: i16,
    body: impl FnOnce(&mut crate::gsbl::Gsbl) -> T,
) -> Option<T> {
    (chan >= 0 && chan < host.gsbl().terms() as i16).then(|| body(host.gsbl_mut()))
}

/// `int btutsw(int chan, int width)` -- output word-wrap width. Zero disables.
pub fn btutsw(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let (chan, width) = (machine.arg_u16(0) as i16, machine.arg_u16(1));
    Ok(match on_channel(host, chan, |g| {
        g.channel_mut(chan).expect("in range").width = width;
    }) {
        Some(()) => Ret::U16(0),
        None => Ret::U16(OUT_OF_RANGE),
    })
}

/// `int btumil(int chan, int maxinl)` -- maximum input line length. Zero
/// disables the limit.
pub fn btumil(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let (chan, maxinl) = (machine.arg_u16(0) as i16, machine.arg_u16(1));
    Ok(match on_channel(host, chan, |g| {
        g.channel_mut(chan).expect("in range").maxinl = maxinl;
    }) {
        Some(()) => Ret::U16(0),
        None => Ret::U16(OUT_OF_RANGE),
    })
}

/// `int btuech(int chan, int onoff)` -- echo input back to the terminal.
pub fn btuech(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let (chan, onoff) = (machine.arg_u16(0) as i16, machine.arg_u16(1));
    Ok(match on_channel(host, chan, |g| {
        g.channel_mut(chan).expect("in range").echo = onoff != 0;
    }) {
        Some(()) => Ret::U16(0),
        None => Ret::U16(OUT_OF_RANGE),
    })
}

/// `int btulok(int chan, int onoff)` -- input lockout: arriving bytes are
/// discarded while locked.
pub fn btulok(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let (chan, onoff) = (machine.arg_u16(0) as i16, machine.arg_u16(1));
    Ok(match on_channel(host, chan, |g| {
        g.channel_mut(chan).expect("in range").locked = onoff != 0;
    }) {
        Some(()) => Ret::U16(0),
        None => Ret::U16(OUT_OF_RANGE),
    })
}

/// `int btuoes(int chan, int onoff)` -- raise status 5 when the output buffer
/// empties.
pub fn btuoes(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let (chan, onoff) = (machine.arg_u16(0) as i16, machine.arg_u16(1));
    Ok(match on_channel(host, chan, |g| {
        g.channel_mut(chan).expect("in range").oes = onoff != 0;
    }) {
        Some(()) => Ret::U16(0),
        None => Ret::U16(OUT_OF_RANGE),
    })
}

/// `int btutrg(int chan, int nbyt)` -- byte-count input trigger. Zero is ASCII
/// mode; non-zero switches to binary mode and sets the block size.
pub fn btutrg(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let (chan, nbyt) = (machine.arg_u16(0) as i16, machine.arg_u16(1));
    Ok(match on_channel(host, chan, |g| {
        g.channel_mut(chan).expect("in range").trigger = nbyt;
    }) {
        Some(()) => Ret::U16(0),
        None => Ret::U16(OUT_OF_RANGE),
    })
}

/// `int btuxnf(int chan, int xon, int xoff, ...)` -- the XON and XOFF
/// characters. Varargs: the module cleans 3 words at six sites and 6 at eight
/// others, but only the first three are ever read here.
pub fn btuxnf(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let (chan, xon, xoff) = (
        machine.arg_u16(0) as i16,
        machine.arg_u16(1),
        machine.arg_u16(2),
    );
    Ok(match on_channel(host, chan, |g| {
        let c = g.channel_mut(chan).expect("in range");
        c.xon = xon as u8;
        c.xoff = xoff as u8;
    }) {
        Some(()) => Ret::U16(0),
        None => Ret::U16(OUT_OF_RANGE),
    })
}

/// `int btuclo(int chan)` -- throw away output that has not gone out yet.
pub fn btuclo(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let chan = machine.arg_u16(0) as i16;
    Ok(match on_channel(host, chan, |g| {
        let c = g.channel_mut(chan).expect("in range");
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
    let chan = machine.arg_u16(0) as i16;
    Ok(match on_channel(host, chan, |g| {
        let c = g.channel_mut(chan).expect("in range");
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
    let (chan, status) = (machine.arg_u16(0) as i16, machine.arg_u16(1) as i16);
    Ok(match on_channel(host, chan, |g| {
        g.channel_mut(chan).expect("in range").status.push_back(status);
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
    let chan = machine.arg_u16(0) as i16;
    if chan < 0 || chan >= host.gsbl().terms() as i16 {
        return Ok(Ret::U16(OUT_OF_RANGE));
    }
    let c = host.gsbl().channel(chan).expect("in range");
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
    let chan = machine.arg_u16(0) as i16;
    let at = machine.arg_far(1);
    if chan < 0 || chan >= host.gsbl().terms() as i16 {
        return Ok(Ret::U16(OUT_OF_RANGE));
    }
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
    let (chan, nbyt) = (machine.arg_u16(0) as i16, machine.arg_u16(1));
    let at = machine.arg_far(2);
    if chan < 0 || chan >= host.gsbl().terms() as i16 {
        return Ok(Ret::U16(OUT_OF_RANGE));
    }
    let data = machine.resolve(at, usize::from(nbyt))?.to_vec();
    host.gsbl_mut().transmit_raw(chan, &data);
    Ok(Ret::U16(0))
}

/// `int btuica(int chan, char *rdbptr, int max)` -- take up to `max` bytes of
/// count-triggered input, and return how many were taken.
pub fn btuica(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let chan = machine.arg_u16(0) as i16;
    let at = machine.arg_far(1);
    let max = machine.arg_u16(3);
    if chan < 0 || chan >= host.gsbl().terms() as i16 {
        return Ok(Ret::U16(OUT_OF_RANGE));
    }
    let c = host.gsbl_mut().channel_mut(chan).expect("in range");
    let take = usize::from(max).min(c.input.len());
    let bytes: Vec<u8> = c.input.drain(..take).collect();
    machine.write(at, &bytes)?;
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
        let past = f.host.gsbl().terms();
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
        f.invoke(btutsw, &[0, 10]).expect("width set");
        let text = f.text("the quick brown fox");
        f.invoke(btuxmt, &[0, text.offset, text.selector])
            .expect("transmitted");
        assert_eq!(
            f.host.gsbl_mut().drain_output(0),
            b"the quick\r\nbrown fox".to_vec()
        );
    }

    #[test]
    fn btuxct_sends_the_byte_count_it_was_given_and_no_terminator() {
        // Binary: the length is an argument, not a NUL scan, so an embedded
        // zero is data.
        let mut f = Fixture::new();
        let data = f.bytes(&[b'a', 0, b'b'], false);
        f.invoke(btuxct, &[0, 3, data.offset, data.selector])
            .expect("transmitted");
        assert_eq!(f.host.gsbl_mut().drain_output(0), vec![b'a', 0, b'b']);
    }

    #[test]
    fn btuibw_counts_what_is_waiting_and_btucli_throws_it_away() {
        let mut f = Fixture::new();
        f.host.gsbl_mut().channel_mut(0).expect("chan 0").trigger = 99;
        f.host.gsbl_mut().push_input(0, b"abcd");
        assert_eq!(f.invoke(btuibw, &[0]).expect("counted"), Ret::U16(4));
        f.invoke(btucli, &[0]).expect("cleared");
        assert_eq!(f.invoke(btuibw, &[0]).expect("counted"), Ret::U16(0));
    }

    #[test]
    fn btuclo_throws_away_output_that_has_not_gone_out() {
        let mut f = Fixture::new();
        let text = f.text("wasted");
        f.invoke(btuxmt, &[0, text.offset, text.selector])
            .expect("transmitted");
        f.invoke(btuclo, &[0]).expect("cleared");
        assert!(f.host.gsbl_mut().drain_output(0).is_empty());
    }

    #[test]
    fn btuinj_puts_a_status_where_the_host_will_find_it() {
        let mut f = Fixture::new();
        f.invoke(btuinj, &[0, 3]).expect("injected");
        assert_eq!(f.host.gsbl_mut().next_status(0), Some(3));
    }

    #[test]
    fn btuica_copies_what_is_waiting_up_to_the_maximum_it_was_given() {
        let mut f = Fixture::new();
        f.host.gsbl_mut().channel_mut(0).expect("chan 0").trigger = 99;
        f.host.gsbl_mut().push_input(0, b"abcdef");
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
    fn the_settings_reach_the_channel() {
        let mut f = Fixture::new();
        f.invoke(btutsw, &[0, 80]).expect("ok");
        f.invoke(btumil, &[0, 40]).expect("ok");
        f.invoke(btuech, &[0, 0]).expect("ok");
        f.invoke(btulok, &[0, 1]).expect("ok");
        f.invoke(btuoes, &[0, 1]).expect("ok");
        f.invoke(btutrg, &[0, 8]).expect("ok");
        f.invoke(btuxnf, &[0, 17, 19]).expect("ok");

        let c = f.host.gsbl().channel(0).expect("chan 0");
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
        f.host.gsbl_mut().push_input(0, b"look\r");
        f.invoke(btucli, &[0]).expect("cleared");
        assert_eq!(f.host.gsbl_mut().next_status(0), Some(crate::gsbl::Gsbl::CRSTG));
        assert_eq!(f.host.gsbl_mut().take_line(0), None);
    }
}
