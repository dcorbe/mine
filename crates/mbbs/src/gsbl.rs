//! The per-channel terminal layer, and the state a byte stream needs to become
//! a line.
//!
//! GSBL -- Galacticomm's Software Breakthrough Library -- is the layer between
//! a module and a terminal. On a real board it drove modems; here a channel is
//! a byte stream and nothing else. What survives that reduction is everything
//! that matters to a module: an input buffer that cooks raw bytes into a
//! CR-terminated line, an output buffer, per-channel settings, and a status
//! FIFO the host polls.
//!
//! This holds no I/O. `push_input` and `drain_output` are the whole boundary,
//! so a tokio task owning a socket and a test holding a `&[u8]` drive exactly
//! the same code.
//!
//! Semantics are from the Worldgroup 1.0 GSBL Development Guide
//! (`archive/tooling/reference-documents/`), which has a page per routine.

use std::collections::VecDeque;

/// How much a channel can hold in each direction.
///
/// The real host sized these with `btusiz`/`btulsz` from `INPSIZ` and `OUTSIZ`
/// in `MAJORBBS.C`. `WCCMMUD.DLL` imports neither sizing routine, so it never
/// asks and never finds out -- these are the host's to choose.
const INPSIZ: usize = 1024;
const OUTSIZ: usize = 8192;

/// One terminal's worth of state.
pub struct Channel {
    /// Raw bytes that have arrived and not yet been cooked into a line.
    pub(crate) input: VecDeque<u8>,
    /// The line being assembled, without its terminator.
    pub(crate) line: Vec<u8>,
    /// Completed lines, oldest first, waiting for `btuinp` to take them.
    ///
    /// More than one can queue up: a client that pipelines -- a paste, a
    /// macro, or this repo's own `mmc` -- can land two CR-terminated lines in
    /// one `push_input` call. A single `Option` here would let the second
    /// line silently overwrite the first before the module ever saw it.
    pub(crate) ready: VecDeque<Vec<u8>>,
    /// Bytes queued for the terminal.
    pub(crate) output: VecDeque<u8>,
    /// Statuses waiting for `btusts`, oldest first. The guide calls this a
    /// first-in-first-out structure and says so explicitly.
    ///
    /// Finding 13 (not fixed): real GSBL's status buffer holds 31 bytes and
    /// overflows to status 254 once it fills. This one is unbounded. That is
    /// the safer failure of the two -- growing a `VecDeque` never loses a
    /// status the module is going to wait on forever, where a fixed cap would
    /// have to choose something to drop.
    pub(crate) status: VecDeque<i16>,
    /// Bytes received in binary mode (`btutrg`) since the last `INBLK` status
    /// was queued. Counts toward the *next* block, independent of how much of
    /// `input` the module has actually drained -- see R4.
    pub(crate) since_trigger: u16,
    /// How far along the current output line the terminal's cursor is.
    ///
    /// Per channel and not per call. MajorMUD builds a screen from many `prf`
    /// calls flushed by many `btuxmt`s, so a wrap decided from the length of
    /// one call alone would be decided from the wrong number.
    pub(crate) column: u16,

    /// `btutsw` -- output word-wrap width. Zero means no wrapping.
    pub width: u16,
    /// `btumil` -- maximum input line length. Zero means no limit.
    pub maxinl: u16,
    /// `btuech` -- whether input is echoed back.
    pub echo: bool,
    /// `btulok` -- input lockout: arriving bytes are discarded.
    pub locked: bool,
    /// `btutrg` -- the byte-count trigger. Zero is ASCII mode; non-zero is
    /// binary mode and the block size that raises status 4.
    pub trigger: u16,
    /// `btuoes` -- whether draining the output buffer raises status 5.
    pub oes: bool,
    /// `btuxnf` -- the XON and XOFF characters. Recorded because the module
    /// sets them at 14 sites; flow control itself is meaningless on a socket,
    /// which never asks the far end to pause.
    pub xon: u8,
    pub xoff: u8,

    /// `btuxnf`'s page-mode parameters (R5, guide page 193): a negative
    /// `xoff` selects page mode, and `cnt` is how many lines to show before
    /// pausing. Recorded so the values are not lost, but **pagination itself
    /// is not implemented** -- it needs the driver Batch C of this plan
    /// builds, which decides when a screen's worth of lines has gone out.
    pub(crate) page_lines: u16,
    /// `btuxnf`'s page-mode parameters (R5, guide page 193): the pause
    /// message shown between screens, e.g. `"Hit any key to continue..."`.
    /// Recorded, not acted on -- see `page_lines`.
    pub(crate) page_message: Option<Vec<u8>>,

    /// Set when the last byte written was a CR whose LF this host supplied, so
    /// that a module sending an explicit `\r\n` does not get two linefeeds.
    /// On `Channel` rather than local to `transmit` because the pair can arrive
    /// in two calls -- MajorMUD flushes whatever `prf` happened to accumulate.
    pub(crate) supplied_lf: bool,
}

impl Default for Channel {
    fn default() -> Self {
        Self {
            input: VecDeque::new(),
            line: Vec::new(),
            ready: VecDeque::new(),
            output: VecDeque::new(),
            status: VecDeque::new(),
            since_trigger: 0,
            column: 0,
            width: 0,
            maxinl: 0,
            echo: true,
            locked: false,
            trigger: 0,
            oes: false,
            xon: 0,
            xoff: 0,
            page_lines: 0,
            page_message: None,
            supplied_lf: false,
        }
    }
}

/// Every channel this host has.
pub struct Gsbl {
    channels: Vec<Channel>,
}

impl Gsbl {
    /// `terms` channels, each with GSBL's own defaults.
    pub fn new(terms: u16) -> Self {
        Self {
            channels: (0..terms).map(|_| Channel::default()).collect(),
        }
    }

    /// How many channels there are.
    pub fn terms(&self) -> u16 {
        self.channels.len() as u16
    }

    /// One channel, or `None` if `chan` names none.
    ///
    /// Every channel in range is *defined* -- `Host::new` allocates them all and
    /// this host has no `btudef` -- so the guide's `-10` "channel is not
    /// defined" is unreachable and `-11` "out of range" is the only refusal a
    /// shim can make.
    pub fn channel(&self, chan: i16) -> Option<&Channel> {
        usize::try_from(chan).ok().and_then(|i| self.channels.get(i))
    }

    /// One channel, mutably.
    pub fn channel_mut(&mut self, chan: i16) -> Option<&mut Channel> {
        usize::try_from(chan)
            .ok()
            .and_then(|i| self.channels.get_mut(i))
    }

    /// `CRSTG` -- a CR-terminated input string is available (guide, `btusts`
    /// page 155, status 3).
    pub const CRSTG: i16 = 3;

    /// `INBLK` -- byte-count-triggered input data is available (status 4).
    pub const INBLK: i16 = 4;

    /// `OUTMT` -- the output buffer went from not-empty to empty (status 5).
    /// Only ever raised when `btuoes` has enabled it.
    pub const OUTMT: i16 = 5;

    /// `OVRFLW` -- data output circular-buffer overflow (status 253). Guide,
    /// `btuxmt` CAUTIONS, page 191: when the string does not fit in the output buffer, btuxmt returns 0, queues status 253 for btusts, and outputs none of the string `btuxct`
    /// (page 182) says the same of a block that will not fit.
    pub const OVRFLW: i16 = 253;

    /// Bytes have arrived from the terminal.
    ///
    /// This is half of the boundary: a tokio task reading a socket and a test
    /// holding a literal both arrive here, and there is no second path to keep
    /// honest.
    ///
    /// A channel that does not exist silently discards, because the caller is
    /// the host's own transport rather than the module -- there is nobody to
    /// return an error code to, and a socket for a channel that was never
    /// allocated is the transport's bug, not the module's.
    pub fn push_input(&mut self, chan: i16, bytes: &[u8]) {
        let Some(c) = self.channel_mut(chan) else {
            return;
        };
        for &byte in bytes {
            c.take(byte);
        }
    }

    /// The next status for a channel, oldest first, or `None`.
    ///
    /// This is `btusts`. The guide: the status buffer is a FIFO, so btusts hands back codes in the order they arose.
    pub fn next_status(&mut self, chan: i16) -> Option<i16> {
        self.channel_mut(chan)?.status.pop_front()
    }

    /// The oldest completed line, taken -- this is what `btuinp` hands the
    /// module. If more than one line is queued, the rest wait their turn.
    pub fn take_line(&mut self, chan: i16) -> Option<Vec<u8>> {
        self.channel_mut(chan)?.ready.pop_front()
    }

    /// Everything queued for the terminal, taken.
    ///
    /// The other half of the boundary. Raises `OUTMT` if `btuoes` asked for it
    /// and this drain is what emptied the buffer.
    ///
    /// Safe to call at any point, including mid-line. It was not always: while
    /// [`Channel::wrap`] recovered a trailing partial word by looking back
    /// into `output`, a drain landing between two `btuxmt` calls moved the
    /// break, and the bytes a channel emitted depended on when a socket task
    /// happened to run. `transmit` now wraps inside a buffer of its own and
    /// commits once, so there is nothing here to disturb.
    pub fn drain_output(&mut self, chan: i16) -> Vec<u8> {
        let Some(c) = self.channel_mut(chan) else {
            return Vec::new();
        };
        if c.output.is_empty() {
            return Vec::new();
        }
        let out: Vec<u8> = c.output.drain(..).collect();
        if c.oes {
            c.status.push_back(Self::OUTMT);
        }
        out
    }

    /// The first channel with a status waiting, or `None`.
    ///
    /// This is `btuscn`. The guide: it finds channels whose status code is non-zero and answers -1 when there are none. The `-1` is
    /// left to the caller; `None` is what Rust says.
    pub fn scan(&self) -> Option<i16> {
        self.channels
            .iter()
            .position(|c| !c.status.is_empty())
            .map(|i| i as i16)
    }

    /// `btuxmt` -- ASCII output, word-wrapped at the `btutsw` width.
    ///
    /// Silently discards for a channel that does not exist; the shim checks the
    /// range and returns `-11` before ever reaching here.
    pub fn transmit(&mut self, chan: i16, bytes: &[u8]) {
        let Some(c) = self.channel_mut(chan) else {
            return;
        };
        c.transmit(bytes);
    }

    /// `btuxct` -- binary output, exactly as given.
    ///
    /// R6, guide page 182: a block that will not fit is not truncated into
    /// what room remains -- none of it goes out, and status 253 (`OVRFLW`) is
    /// queued instead.
    pub fn transmit_raw(&mut self, chan: i16, bytes: &[u8]) {
        let Some(c) = self.channel_mut(chan) else {
            return;
        };
        if c.output.len() + bytes.len() > OUTSIZ {
            c.status.push_back(Self::OVRFLW);
            return;
        }
        c.output.extend(bytes.iter().copied());
    }
}

/// The default input translate table, `btuxlt` page 184.
///
/// In force whether or not anyone calls `btuxlt` -- which `WCCMMUD.DLL` never
/// does. `None` is a character the table drops entirely: every control
/// character except backspace and CR, once the high bit (which the guide says
/// is "always translated to 0") has already been stripped. This is also why a
/// bare LF never reaches the terminator match below -- LF is a dropped
/// control character, not a special case of it.
fn translate(byte: u8) -> Option<u8> {
    // the high bit is always cleared, before anything else
    match byte & 0x7f {
        0x08 => Some(0x08),         // backspace, as itself
        0x0d => Some(0x0d),         // carriage return, as itself
        0x7f => Some(0x08),         // RUBOUT is a backspace on terminals without one
        b @ 0x20..=0x7e => Some(b), // printable, as themselves
        _ => None,                  // every other control character is ignored
    }
}

impl Channel {
    /// One byte, through the guide's ASCII input pipeline.
    ///
    /// The guide (`btuchi`) numbers eleven steps. Four of them have no setter
    /// `WCCMMUD.DLL` calls and no meaning on a socket -- parity and framing
    /// checks, XON/XOFF, and the output-abort character -- so what is left is
    /// lockout, mode, **the default translate table**, backspace, terminator,
    /// length limit, capacity and echo, **in that order**. The order is the
    /// guide's, and it is why a backspace can be echoed while a byte past
    /// `maxinl` is not, and why DEL becomes a backspace before the backspace
    /// step ever sees it.
    fn take(&mut self, byte: u8) {
        // 2. Input lockout. The byte never happened.
        if self.locked {
            return;
        }

        // 3. Binary mode. None of the ASCII processing applies -- a CR in
        //    binary mode is a byte like any other.
        if self.trigger != 0 {
            if self.input.len() < INPSIZ {
                self.input.push_back(byte);
            }
            // R4, guide btutrg page 167: every further nbyt input bytes raise the same status again -- one INBLK per block
            // of `trigger` bytes received, not one for every byte for as
            // long as the buffer happens to hold at least `trigger` bytes.
            // The `while` (not `if`) is what makes a block of `2 * trigger`
            // bytes arriving in one push_input queue two statuses.
            self.since_trigger += 1;
            while self.since_trigger >= self.trigger {
                self.status.push_back(Gsbl::INBLK);
                self.since_trigger -= self.trigger;
            }
            return;
        }

        // 6. The default input translate table. Not optional: it is what
        //    turns DEL into a backspace for terminals without one, drops
        //    every other control character (a telnet client's CR NUL would
        //    otherwise leak a NUL into the next command), and strips the
        //    high bit (telnet IAC, 0xFF, would otherwise land in the line).
        let Some(byte) = translate(byte) else {
            return;
        };

        match byte {
            // 7. Backspace. At column zero there is nothing to erase and
            //    nothing to echo -- the guide's default is to leave the
            //    terminal alone rather than move its cursor off the line.
            0x08 => {
                if self.line.pop().is_some() && self.echo {
                    self.output.extend(b"\x08 \x08");
                }
            }

            // 8. Line terminator. The line is complete.
            b'\r' => {
                self.ready.push_back(std::mem::take(&mut self.line));
                self.status.push_back(Gsbl::CRSTG);
                if self.echo {
                    self.output.extend(b"\r\n");
                }
            }

            _ => {
                // 9. Line length limit, then 10. buffer capacity. A byte
                //    that does not fit is dropped -- neither stored nor
                //    echoed. R8: the guide (`btumil`, page 122) says this
                //    also queues status 251 ("Data Input Circular-Buffer
                //    Overflow", page 163), which this host does not queue.
                //    That is a legitimate omission, not a reading of the
                //    spec -- the guide itself calls 251 a condition that
                //    "can be safely ignored" (page 163), not one the module
                //    depends on hearing about.
                if self.maxinl != 0 && self.line.len() >= usize::from(self.maxinl) {
                    return;
                }
                if self.line.len() >= INPSIZ {
                    return;
                }
                self.line.push(byte);

                // 11. Echo, last, so that only a byte actually accepted is
                //     shown back.
                if self.echo {
                    self.output.push_back(byte);
                }
            }
        }
    }

    /// ASCII output, wrapped at `width`.
    ///
    /// R6, guide `btuxmt` CAUTIONS page 191: an oversized call is atomic.
    /// Either the whole transformed block -- CRLF expansion, wrap breaks and
    /// all -- fits in `OUTSIZ`, or none of it is committed and `OVRFLW` is
    /// queued instead. That is why bytes are pushed below without a
    /// per-byte capacity check and measured only once, at the end, against a
    /// snapshot to roll back to.
    fn transmit(&mut self, bytes: &[u8]) {
        // Built here and committed at the end, rather than pushed straight at
        // `self.output`. Two things fall out of that, and the second is the
        // reason:
        //
        // 1. R6's all-or-nothing overflow is a length check on `out` instead
        //    of cloning the whole ring to restore from.
        // 2. `wrap` looks back for the trailing partial word **inside `out`**,
        //    which nothing else can touch. It used to look back into
        //    `self.output`, which `drain_output` empties whenever the
        //    transport runs -- so the same input produced different bytes
        //    depending on when a socket task was scheduled.
        //
        // That this is also what real GSBL does was worked out from the
        // capture rather than assumed. A streaming wrapper that held only a
        // pending space would break mid-word, and `re/oracle/accept-run1.raw`
        // shows it does not: the line ending `...ards. You hear the` (77
        // characters) is followed by `clash`, not by a split word. So GSBL
        // knew the whole word's length -- which it can, because `btuxmt` is
        // handed a complete string. It wraps within that string, carrying
        // only `column` across calls.
        //
        // The limitation that buys: a word split across two `btuxmt` calls
        // cannot be rejoined, so it breaks at the call boundary. MajorMUD
        // flushes whole `prfbuf` blocks through `_TELL_USER`, so it does not
        // arise -- and a deterministic break is worth more than an
        // opportunistic one that a drain can move.
        let mut out: Vec<u8> = Vec::with_capacity(bytes.len() + 8);
        let mut column = self.column;
        let mut supplied_lf = self.supplied_lf;

        for &byte in bytes {
            match byte {
                b'\r' => {
                    // R1 -- guide, `btulfd` page 114: the default on channel
                    // initialisation is that an explicit LF is necessary
                    // after every CR to move to the next line, and
                    // `WCCMMUD.DLL` never calls `btulfd` or `btuhcr`, so the
                    // default stands. `supplied_lf` remembers that this LF is
                    // ours, so a module byte stream that already spells out
                    // `\r\n` -- even split across two `transmit` calls --
                    // does not get a second one.
                    out.push(b'\r');
                    out.push(b'\n');
                    column = 0;
                    supplied_lf = true;
                    continue;
                }
                b'\n' if supplied_lf => {
                    // The other half of a module's own explicit `\r\n` --
                    // already on the wire as the LF we supplied above.
                    supplied_lf = false;
                    continue;
                }
                b'\n' => {
                    out.push(b'\n');
                    continue;
                }
                _ => {}
            }
            supplied_lf = false;
            if self.width != 0 && column >= self.width {
                Self::wrap(&mut out, &mut column, self.width);
                if byte == b' ' {
                    // R9, guide `btutsw` page 172: word wrap works by turning a space into a carriage return -- the space
                    // *becomes* the break `wrap()` just inserted, so it is
                    // consumed here rather than carried onto the new line as
                    // a leading indent.
                    continue;
                }
            }
            out.push(byte);
            // R10: with the default width of 0, wrap() is never called and
            // nothing but a CR ever resets column -- so a long enough
            // channel-lifetime of unwrapped output must not panic once it
            // passes u16::MAX bytes since the last CR.
            column = column.saturating_add(1);
        }

        // R6, guide `btuxmt` CAUTIONS page 191: a string that will not fit is
        // not output *at all*, and a status 253 is queued. Nothing above this
        // line has touched the channel, so there is nothing to roll back.
        if self.output.len() + out.len() > OUTSIZ {
            self.status.push_back(Gsbl::OVRFLW);
            return;
        }
        self.output.extend(out);
        self.column = column;
        self.supplied_lf = supplied_lf;
    }

    /// Break the line, moving a partial word down with it.
    ///
    /// Word wrap rather than a hard break: the guide calls `btutsw` wrapping output at word boundaries, and a host that broke mid-word would split every name the
    /// module printed near the margin.
    ///
    /// Finding 7 (not fixed) -- **invariant: do not drain `output` mid-line
    /// while `width != 0`.** This recovers the trailing partial word by
    /// popping it back off `output` itself, so whatever the current line has
    /// written so far has to still be there. Nothing drains mid-line today --
    /// [`Gsbl::drain_output`] always takes the whole buffer, and that only
    /// ever happens after any wrap for the text so far has already run -- so
    /// this is correct as the host is driven now. A transport that flushes to
    /// a socket on its own schedule rather than only when the module finishes
    /// a line would make this look-back scheduling-dependent, and the bytes
    /// it emits would stop being deterministic. Every obvious fix trades one
    /// bug for another: holding the pending word never sends a prompt lacking
    /// a trailing CR (`[HP=100]:`), and draining only complete lines has the
    /// same problem. Real GSBL gets away with this because a 2400-baud UART
    /// never empties the buffer faster than the module fills it. Leave the
    /// fix to whoever builds the transport.
    fn wrap(out: &mut Vec<u8>, column: &mut u16, width: u16) {
        let mut word = Vec::new();
        while let Some(&back) = out.last() {
            if back == b' ' || back == b'\n' || back == b'\r' {
                break;
            }
            word.push(back);
            out.pop();
            // A word as long as the whole line has no boundary to break on, so
            // break it where the margin falls -- losing it would be worse.
            if word.len() >= usize::from(width) {
                for byte in word.drain(..).rev() {
                    out.push(byte);
                }
                break;
            }
        }
        while out.last() == Some(&b' ') {
            out.pop();
        }
        out.extend(b"\r\n");
        *column = 0;
        for byte in word.into_iter().rev() {
            out.push(byte);
            *column += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bytes a channel emits do not depend on when the transport ran.
    ///
    /// This is the test the original wrap could not pass. `wrap` recovered the
    /// trailing partial word by popping it back off `output` -- so a drain
    /// landing between two `btuxmt` calls took the word away and the break
    /// moved. Under a tokio transport that is a socket task's scheduling
    /// deciding what the user sees, which would have looked like a flaky test
    /// rather than a design fault.
    ///
    /// The halves matter. A word has to *straddle* the boundary for the drain
    /// to be able to steal it -- `"the quick " + "brown fox"` breaks on a space
    /// that lives in the second half either way, and passes even on the broken
    /// implementation. Here `"wor"` is in the first half and `"ldsomething"` in
    /// the second, so the old `wrap` could only move down the part it could
    /// still see.
    #[test]
    fn output_is_the_same_whether_or_not_the_transport_drained_mid_line() {
        let halves: [&[u8]; 2] = [b"hello wor", b"ldsomethinglong end"];

        // Drained only at the end.
        let mut whole = Gsbl::new(1);
        whole.channel_mut(0).expect("channel 0").width = 20;
        for half in halves {
            whole.transmit(0, half);
        }
        let undrained = whole.drain_output(0);

        // Drained between the two calls, then concatenated.
        let mut split = Gsbl::new(1);
        split.channel_mut(0).expect("channel 0").width = 20;
        let mut drained = Vec::new();
        for half in halves {
            split.transmit(0, half);
            drained.extend(split.drain_output(0));
        }

        assert_eq!(
            String::from_utf8_lossy(&drained),
            String::from_utf8_lossy(&undrained),
            "a drain between two btuxmt calls changed the bytes"
        );
    }

    #[test]
    fn a_fresh_channel_has_the_defaults_gsbl_gave_it() {
        let g = Gsbl::new(1);
        let c = g.channel(0).expect("channel 0");
        assert_eq!(c.width, 0, "btutsw default: no word wrap");
        assert_eq!(c.maxinl, 0, "btumil default: no line limit");
        assert!(c.echo, "btuech default: echo on");
        assert!(!c.locked, "btulok default: input not locked out");
        assert_eq!(c.trigger, 0, "btutrg default: ASCII mode");
    }

    #[test]
    fn a_channel_outside_nterms_is_out_of_range() {
        let g = Gsbl::new(1);
        assert!(g.channel(1).is_none());
        assert!(g.channel(-1).is_none());
    }

    #[test]
    fn a_line_is_ready_only_once_the_terminator_arrives() {
        let mut g = Gsbl::new(1);
        g.push_input(0, b"loo");
        assert_eq!(g.next_status(0), None, "no status until the CR");
        g.push_input(0, b"k\r");
        assert_eq!(g.next_status(0), Some(Gsbl::CRSTG));
        assert_eq!(g.take_line(0).as_deref(), Some(&b"look"[..]));
    }

    #[test]
    fn the_status_fifo_is_drained_in_order_and_only_once() {
        // R3: this test used to pass while silently destroying "a" -- it
        // asserted the two statuses and never the lines, so a `ready` that
        // let the second line overwrite the first went unnoticed. Both lines
        // must survive, in order.
        let mut g = Gsbl::new(1);
        g.push_input(0, b"a\rb\r");
        assert_eq!(g.next_status(0), Some(Gsbl::CRSTG));
        assert_eq!(g.next_status(0), Some(Gsbl::CRSTG));
        assert_eq!(g.next_status(0), None, "two lines, two statuses, no more");
        assert_eq!(
            g.take_line(0).as_deref(),
            Some(&b"a"[..]),
            "the first line must still be here, not overwritten by the second"
        );
        assert_eq!(g.take_line(0).as_deref(), Some(&b"b"[..]));
        assert_eq!(g.take_line(0), None);
    }

    #[test]
    fn a_linefeed_after_a_return_is_not_a_second_line() {
        // A telnet client sends CRLF. Treating the LF as a terminator would
        // hand the module an empty command after every real one.
        let mut g = Gsbl::new(1);
        g.push_input(0, b"look\r\n");
        assert_eq!(g.next_status(0), Some(Gsbl::CRSTG));
        assert_eq!(g.next_status(0), None);
    }

    #[test]
    fn backspace_removes_a_byte_and_does_nothing_at_column_zero() {
        let mut g = Gsbl::new(1);
        g.push_input(0, b"\x08");
        g.push_input(0, b"lookk\x08\r");
        assert_eq!(g.take_line(0).as_deref(), Some(&b"look"[..]));
    }

    #[test]
    fn del_is_translated_to_backspace() {
        // R2, guide btuxlt page 184: RUBOUT (ASCII 127) becomes BACKSPACE, a concession to old terminals without a backspace key. Every modern terminal emulator's Backspace key
        // sends 0x7F.
        let mut g = Gsbl::new(1);
        g.push_input(0, b"lookx\x7f\x7f\r");
        assert_eq!(g.take_line(0).as_deref(), Some(&b"loo"[..]));
    }

    #[test]
    fn control_characters_other_than_backspace_and_cr_are_ignored() {
        // R2, guide btuxlt page 184: every other control character is dropped. An RFC 854 client's CR NUL would otherwise leak the NUL
        // into the next command.
        let mut g = Gsbl::new(1);
        g.push_input(0, b"lo\x00\x07\x1bok\r"); // NUL, BEL, ESC
        assert_eq!(g.take_line(0).as_deref(), Some(&b"look"[..]));
    }

    #[test]
    fn the_high_bit_is_stripped_before_translation() {
        // R2, guide btuxlt page 184: the high bit is always cleared. Telnet IAC (0xFF) would otherwise land in the
        // command line; here a stray high-bit byte becomes the ASCII
        // character underneath it (0xE9 & 0x7F == 0x69 == 'i').
        let mut g = Gsbl::new(1);
        g.push_input(0, b"look\xe9ng\r");
        assert_eq!(g.take_line(0).as_deref(), Some(&b"looking"[..]));
    }

    #[test]
    fn a_locked_channel_discards_what_arrives() {
        let mut g = Gsbl::new(1);
        g.channel_mut(0).expect("channel 0").locked = true;
        g.push_input(0, b"look\r");
        assert_eq!(g.next_status(0), None);
        assert_eq!(g.take_line(0), None);
    }

    #[test]
    fn btumil_drops_what_would_not_fit_rather_than_truncating_the_line() {
        let mut g = Gsbl::new(1);
        g.channel_mut(0).expect("channel 0").maxinl = 4;
        g.push_input(0, b"lookout\r");
        assert_eq!(g.take_line(0).as_deref(), Some(&b"look"[..]));
    }

    #[test]
    fn echo_puts_what_arrived_back_on_the_wire_and_silence_does_not() {
        let mut g = Gsbl::new(1);
        g.push_input(0, b"hi");
        assert_eq!(g.drain_output(0), b"hi".to_vec());

        g.channel_mut(0).expect("channel 0").echo = false;
        g.push_input(0, b"hi");
        assert!(g.drain_output(0).is_empty());
    }

    #[test]
    fn an_echoed_backspace_erases_the_character_on_the_terminal() {
        let mut g = Gsbl::new(1);
        g.push_input(0, b"a\x08");
        assert_eq!(g.drain_output(0), b"a\x08 \x08".to_vec());
    }

    #[test]
    fn a_byte_count_trigger_raises_status_four_and_leaves_the_bytes_raw() {
        // Binary mode: none of the ASCII processing applies, not even the
        // terminator -- a CR is just a byte.
        const INBLK: i16 = 4;
        let mut g = Gsbl::new(1);
        g.channel_mut(0).expect("channel 0").trigger = 3;
        g.push_input(0, b"a\rb");
        assert_eq!(g.next_status(0), Some(INBLK));
        assert_eq!(g.take_line(0), None, "binary input is not a line");
    }

    #[test]
    fn status_four_is_raised_once_per_block_not_once_per_buffered_byte() {
        // R4, guide btutrg page 167: every further nbyt input bytes raise the same status again. 100 bytes at a 20-byte trigger is five
        // blocks and five statuses -- not eighty-one, which is what
        // `input.len() >= trigger` re-firing on every byte past the
        // threshold used to produce.
        let mut g = Gsbl::new(1);
        g.channel_mut(0).expect("channel 0").trigger = 20;
        g.push_input(0, &[0u8; 100]);
        let mut count = 0;
        while let Some(status) = g.next_status(0) {
            assert_eq!(status, Gsbl::INBLK);
            count += 1;
        }
        assert_eq!(count, 5);
    }

    #[test]
    fn pushing_to_a_channel_that_does_not_exist_is_a_no_op() {
        let mut g = Gsbl::new(1);
        g.push_input(9, b"look\r");
        assert_eq!(g.next_status(9), None);
    }

    #[test]
    fn ascii_output_with_no_width_is_passed_through_unchanged() {
        let mut g = Gsbl::new(1);
        g.transmit(0, b"the quick brown fox");
        assert_eq!(g.drain_output(0), b"the quick brown fox".to_vec());
    }

    #[test]
    fn ascii_output_wraps_on_a_word_boundary_at_the_btutsw_width() {
        let mut g = Gsbl::new(1);
        g.channel_mut(0).expect("channel 0").width = 10;
        g.transmit(0, b"the quick brown fox");
        assert_eq!(g.drain_output(0), b"the quick\r\nbrown fox".to_vec());
    }

    #[test]
    fn a_word_longer_than_the_width_is_broken_rather_than_lost() {
        let mut g = Gsbl::new(1);
        g.channel_mut(0).expect("channel 0").width = 4;
        g.transmit(0, b"abcdefg");
        assert_eq!(g.drain_output(0), b"abcd\r\nefg".to_vec());
    }

    #[test]
    fn a_space_that_lands_on_the_wrap_boundary_is_consumed_not_carried() {
        // R9, guide btutsw page 172: word wrap works by turning a space into a carriage return -- so when the space itself is the byte
        // that pushes the column past the width, it must become the break,
        // not survive as a leading-space indent on the new line. This is the
        // one case where the byte that triggers `wrap()` is a space rather
        // than the next word's first letter.
        let mut g = Gsbl::new(1);
        g.channel_mut(0).expect("channel 0").width = 10;
        g.transmit(0, b"0123456789 abc");
        assert_eq!(g.drain_output(0), b"0123456789\r\nabc".to_vec());
    }

    #[test]
    fn an_explicit_return_resets_the_column() {
        let mut g = Gsbl::new(1);
        g.channel_mut(0).expect("channel 0").width = 10;
        g.transmit(0, b"ab\r\ncd ef");
        assert_eq!(g.drain_output(0), b"ab\r\ncd ef".to_vec());
    }

    #[test]
    fn binary_output_ignores_the_width_entirely() {
        // The guide, btuxmt page 189: none of these features apply to btuxct.
        let mut g = Gsbl::new(1);
        g.channel_mut(0).expect("channel 0").width = 4;
        g.transmit_raw(0, b"abcdefg");
        assert_eq!(g.drain_output(0), b"abcdefg".to_vec());
    }

    #[test]
    fn a_bare_cr_from_the_module_reaches_the_wire_as_crlf() {
        // R1, guide `btulfd` page 114: the default on channel init is that an
        // explicit LF is required after every CR, and WCCMMUD.DLL never
        // calls btulfd/btuhcr to change that default.
        let mut g = Gsbl::new(1);
        g.transmit(0, b"line\r");
        assert_eq!(g.drain_output(0), b"line\r\n".to_vec());
    }

    #[test]
    fn an_explicit_crlf_from_the_module_does_not_become_crlf_lf() {
        let mut g = Gsbl::new(1);
        g.transmit(0, b"line\r\n");
        assert_eq!(g.drain_output(0), b"line\r\n".to_vec());
    }

    #[test]
    fn an_explicit_crlf_split_across_two_transmit_calls_does_not_double_the_lf() {
        // MajorMUD flushes whatever `prf` happened to accumulate, so the CR
        // and its LF are not guaranteed to arrive in the same btuxmt() call.
        let mut g = Gsbl::new(1);
        g.transmit(0, b"line\r");
        g.transmit(0, b"\n");
        assert_eq!(g.drain_output(0), b"line\r\n".to_vec());
    }

    #[test]
    fn column_does_not_overflow_when_width_is_unset() {
        // R10: width stays 0 (the default), so wrap() is never called and
        // nothing resets column -- a plain `column += 1` would panic on
        // overflow (debug builds check this) long before finishing a call
        // this large. The call itself is bigger than OUTSIZ and rolls back
        // (R6), which is not what this test is about; it only cares that
        // accumulating column that far did not panic on the way there.
        let mut g = Gsbl::new(1);
        let long = vec![b'x'; 70_000];
        g.transmit(0, &long);
        assert_eq!(g.next_status(0), Some(Gsbl::OVRFLW));
    }

    #[test]
    fn an_oversized_ascii_write_emits_nothing_and_queues_overflow() {
        // R6, guide btuxmt CAUTIONS page 191: btuxmt returns 0, queues status 253 for btusts, and outputs none of the string. Not truncated to what room remains -- nothing at all.
        let mut g = Gsbl::new(1);
        let huge = vec![b'x'; OUTSIZ + 1];
        g.transmit(0, &huge);
        assert!(g.drain_output(0).is_empty());
        assert_eq!(g.next_status(0), Some(Gsbl::OVRFLW));
    }

    #[test]
    fn an_oversized_binary_write_emits_nothing_and_queues_overflow_too() {
        // guide btuxct CAUTIONS page 182-183: the same rule for btuxct().
        let mut g = Gsbl::new(1);
        let huge = vec![b'x'; OUTSIZ + 1];
        g.transmit_raw(0, &huge);
        assert!(g.drain_output(0).is_empty());
        assert_eq!(g.next_status(0), Some(Gsbl::OVRFLW));
    }

    #[test]
    fn an_overflowing_write_does_not_disturb_what_was_already_buffered() {
        let mut g = Gsbl::new(1);
        g.transmit(0, b"still here");
        let huge = vec![b'x'; OUTSIZ + 1];
        g.transmit(0, &huge);
        assert_eq!(g.next_status(0), Some(Gsbl::OVRFLW));
        assert_eq!(g.drain_output(0), b"still here".to_vec());
    }

    #[test]
    fn draining_an_empty_buffer_raises_nothing_even_with_btuoes_on() {
        // Status 5 is "the output data buffer makes a transition from being
        // not empty to being empty". No transition, no status.
        let mut g = Gsbl::new(1);
        g.channel_mut(0).expect("channel 0").oes = true;
        assert!(g.drain_output(0).is_empty());
        assert_eq!(g.next_status(0), None);

        g.transmit(0, b"x");
        let _ = g.drain_output(0);
        assert_eq!(g.next_status(0), Some(Gsbl::OUTMT));
    }
}
