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
//!
//! Page citations here (and in `crate::shims::gsbl`, `crate::shims::screen`)
//! are the guide's own printed page number -- `GSBL-NNN`, or "guide page
//! NNN" -- never a `gsblref.pdf` viewer page computed from it. **The two are
//! not a constant offset apart.** Measured by rendering actual pages: `+7`
//! holds through the guide's roughly 80-170 range (PDF 156 is GSBL-149
//! `btusiz`; PDF 175 is GSBL-168 `btutrg`; PDF 165 is GSBL-158 `btusts`), and
//! `+6` only near `btuxnf`'s p.193. Assuming either offset and applying it
//! elsewhere lands on the wrong routine -- "+6" against `btuhpk`/`btupbc`/
//! `btucpc`'s cited pages 99/133/81 lands on `btuhit`/`btuolk`/`btucmd`
//! instead. Checking a citation means rendering that guide page directly,
//! never computing a PDF page from one.

use std::collections::VecDeque;

use crate::chan::{Chan, Terms};

/// How much a channel can hold in each direction.
///
/// The real host sized these with `btusiz`/`btulsz` from `INPSIZ` and `OUTSIZ`
/// in `MAJORBBS.C`. `WCCMMUD.DLL` imports neither sizing routine, so it never
/// asks and never finds out -- these are the host's to choose.
const INPSIZ: usize = 1024;
const OUTSIZ: usize = 8192;

/// [`Channel::transmit`]'s scanner state for CSI (`ESC` `[` ... final byte),
/// carried on [`Channel`] rather than kept local to one call for the same
/// reason `column` and `supplied_lf` are: a sequence can straddle two
/// `transmit()` calls, since MajorMUD flushes whatever `prf` happened to
/// accumulate rather than one escape at a time.
///
/// CSI -- Control Sequence Introducer, ECMA-48 section 5.4 -- is the ANSI
/// grammar every colour code and cursor move `WCCMMUD.DLL` writes uses:
/// `ESC` `[`, zero or more parameter bytes (0x30-0x3F) and intermediate
/// bytes (0x20-0x2F), then exactly one final byte (0x40-0x7E). Galacticomm's
/// own `IF-ANSI` (`ESC[[ansi|ascii]`, see `ifansi.rs`) is a Galacticomm
/// construct layered *on top of* a CSI opener, not a different grammar --
/// `ifansi.rs` resolves that construct before a byte ever reaches
/// `transmit`, so by the time bytes get here every escape is an ordinary
/// CSI. Only `ESC` `[` opens one; a bare `ESC` not followed by `[` is not a
/// case this host needs to render specially, so it is left exactly as
/// `transmit` always treated it (see `Text`'s doc, below).
///
/// **Why this matters at all**: measured against `re/oracle/oracle_bank2.raw`
/// (search "make- shift"), the genuine host's `btutsw(chan, 0x4f)` (79) wraps
/// a room description at 79, 75, 77, 78, 72, 78 *visible* columns, and 79 is
/// the hard ceiling across all 298 lines of that capture. Its first line is
/// 97 raw bytes -- `\x1b[79D` (5), `\x1b[K` (3) and `\x1b[0;37;40m` (10), 18
/// bytes of CSI, none of them visible -- but only 79 columns wide. Before
/// this fix, every one of those 18 bytes counted as a column here too, and
/// the wrap fired up to 18 characters early.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum CsiScan {
    /// Not inside anything. A byte here that is `ESC` (0x1B) moves to
    /// [`CsiScan::Esc`] without yet being emitted or counted -- see that
    /// variant for why the decision waits.
    #[default]
    Text,
    /// `ESC` has arrived and is being held, unemitted, while its meaning is
    /// still undecided: the very next byte says whether this was the start
    /// of a CSI (`[`) or just an opaque byte that happens to be `ESC`.
    ///
    /// Deferred rather than emitted-then-corrected because correcting would
    /// mean either mutating a byte already placed in `out` (impossible once
    /// `wrap()` may have moved it) or double-emitting it. The cost is that
    /// one byte can sit unwritten across a call boundary if nothing ever
    /// follows it -- bounded to that one byte, and closed by the next byte
    /// this channel is ever given. `WCCMMUD.DLL` never ends a channel's
    /// output on a bare trailing `ESC`, so in practice the window always
    /// closes.
    Esc,
    /// `ESC` `[` has been confirmed and both bytes emitted, uncounted.
    /// Every subsequent parameter/intermediate byte (0x20-0x3F) is emitted
    /// uncounted and this state holds; a final byte (0x40-0x7E) is emitted
    /// uncounted and returns to `Text`; anything else cannot appear in a
    /// well-formed CSI, so it aborts the sequence -- see `transmit`'s match
    /// arm for the rule that follows from that.
    Csi,
}

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
    /// `fsdcon` -- character-at-a-time mode: deliver bytes uncooked.
    ///
    /// While set, [`Channel::take`] appends to `input` and does nothing else:
    /// no line assembly, no `maxinl`, no backspace cooking, no echo, no
    /// `CRSTG`. The FSD's entry engine wants keystrokes, and a CR is one of
    /// them rather than the end of anything.
    ///
    /// This is one flag where the original makes eight `btu*` calls
    /// (`fsdcon`, `FSDBBS.C:91`): `btuche`, `btulfd`, `btuscr`, `btuchi`,
    /// `btuech`, `btucli`, `btuxnf`, `btupbc`. The load-bearing one is
    /// `btuchi(usrnum,fsdchi)`, which installs an interrupt-level character
    /// handler; this host has no interrupt level, so there is nothing to
    /// install and the handler's job -- take the byte, wake the module --
    /// is what the flag does directly.
    ///
    /// Of the other seven, four are terminal-driver knobs -- `btulfd`
    /// (LF after CR), `btuscr` (soft CR), `btupbc` (pause character) and
    /// `btuxnf` (XON/XOFF) -- and three are not:
    ///
    /// * `btuech(usrnum,0)` turns echo off; this host's [`Channel::echo`]. The
    ///   FSD draws its own fields, so a driver echoing keystrokes underneath
    ///   it would write over the form.
    /// * `btucli(usrnum)` throws away input that arrived **before** the FSD
    ///   started, so type-ahead left at the previous prompt is not read as the
    ///   form's first keystrokes. It is called on the way *in* only: `fsdcof`
    ///   (`FSDBBS.C:104`) does not call it, so anything this host collected in
    ///   `input` and nobody drained outlives the flag being cleared.
    /// * `btuche(usrnum,1)` is the **other half of `btuchi`**, not a driver
    ///   knob at all: it asks for the same handler to be called again, with
    ///   `c == -1`, when the echo/quick-output buffer drains. That is why
    ///   `fsdchi` (`FSDBBS.C:329`) opens with `if (c == -1) { fsdqoe(); }`,
    ///   and `fsdqoe` (`FSD.C:1960`) is "Report that the quick output buffer
    ///   has gone empty" -- the FSD defers cursor shuffling (`FSDSHN`) until
    ///   its own output is truly out, and `fsdqoe` is what performs the
    ///   deferred work. `fsdcof` turns it back off with `btuche(usrnum,0)`.
    ///   **This host has no equivalent** -- [`Channel::oes`] (`btuoes`, which
    ///   `fsdbkg` also uses) raises `OUTMT` on the same event but reaches the
    ///   module through `stsrou` rather than through the character handler.
    ///   Stage 3 owes the `fsdqoe` path one way or the other.
    ///
    /// `echo` and `width` are the module's to set, and it does not set them
    /// from the same place. Echo is symmetric around the session: `fsdcon`
    /// clears it, `fsdcof` restores it with `echon()`. The **width is set on
    /// the way in too**, just not by `fsdcon`: `fsdbkg` (`FSDBBS.C:186`) does
    /// `btutsw(usrnum,0)` -- wrapping off -- on the line before
    /// `btulok(usrnum,1)`, and `fsdcof` restores it with
    /// `btutsw(usrnum,usaptr->scnwid)`.
    ///
    /// Stage 3 has to do the same, and this is the concrete reason:
    /// [`Channel::transmit`] word-wraps at `width`, so painting a full-screen
    /// template while `width` still holds the account's `scnwid` would break
    /// every row that reaches the margin and destroy the box drawing.
    pub raw: bool,
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

    /// `btupbc` -- the screen-pause character (guide `btupbc`, page 133):
    /// when transmitted in the output stream, output pauses and the channel
    /// goes into screen-pause mode (page 99). Zero disables it. Recorded for
    /// the same reason as `page_lines` -- **screen-pause mode itself is not
    /// implemented**, so no transmitted byte is ever compared against this.
    /// `Channel::transmit` sends every byte the module gives it straight
    /// through, `pause_char` included.
    pub(crate) pause_char: u8,

    /// `btucpc` -- the clear-pause-counter character (guide `btucpc`, page
    /// 81): discovered in the output stream, it resets the pending-lines
    /// counter to zero without itself being transmitted. The Major BBS uses
    /// it to insert Control-S at strategic points and suppress a pause that
    /// would otherwise land there. **Not acted on**, for the same reason as
    /// `pause_char`: there is no pending-lines counter to reset, because
    /// there is no pagination.
    pub(crate) clear_pause_char: u8,

    /// `btuhpk` -- whether a screen-pause keystroke handler has been
    /// installed (guide `btuhpk`, page 99). The real call installs a far
    /// pointer to the routine that will be handed each keystroke received
    /// while paused; this host has exactly one caller of `btuhpk`
    /// ([`crate::shims::screen::rstrxf`]) and it always installs the same
    /// routine, `MAJORBBS.C:3793`'s `hpkrou` -- there is only ever one value
    /// this could hold, so a `bool` records "installed" rather than a far
    /// pointer nothing would ever call through. **What would reveal this is
    /// wrong:** the day screen-pause mode is implemented, a "continue"/"go
    /// nonstop"/"abort" keystroke sent during a pause would have nothing to
    /// dispatch to -- this field says a handler exists, not what it is.
    pub(crate) pause_handler_installed: bool,

    /// Set when the last byte written was a CR whose LF this host supplied, so
    /// that a module sending an explicit `\r\n` does not get two linefeeds.
    /// On `Channel` rather than local to `transmit` because the pair can arrive
    /// in two calls -- MajorMUD flushes whatever `prf` happened to accumulate.
    pub(crate) supplied_lf: bool,

    /// [`Channel::transmit`]'s CSI scanner state. See [`CsiScan`] for why
    /// this lives on the channel rather than local to one call.
    pub(crate) csi: CsiScan,
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
            raw: false,
            trigger: 0,
            oes: false,
            xon: 0,
            xoff: 0,
            page_lines: 0,
            page_message: None,
            pause_char: 0,
            clear_pause_char: 0,
            pause_handler_installed: false,
            supplied_lf: false,
            csi: CsiScan::Text,
        }
    }
}

/// Every channel this host has.
pub struct Gsbl {
    /// The bound these channels were built from, and the only thing that mints
    /// a [`Chan`] for them. Held rather than recovered from `channels.len()` so
    /// that it is *the same value* [`Users`](crate::Users) was sized by -- see
    /// [`crate::chan`] for what those two agreeing by convention cost.
    terms: Terms,
    channels: Vec<Channel>,
    /// Where the next [`Gsbl::scan`] starts looking.
    ///
    /// `btuscn`'s own rotation. The guide (`btuscn`, page 144) says a scan
    /// "resume[s] scanning with the channel immediately following, so that all
    /// channels have the same priority", and `MAJORBBS.C:419-427` corroborates
    /// it: `lstunm` is "last user-number returned by `btuscn()`"
    /// (`MAJORBBS.C:325`), and `if (newunm <= lstunm) (*syscyc)()` fires the
    /// system cycle on the *wrap*, a test that means nothing unless the scan
    /// rotates.
    ///
    /// Lives here rather than on `Host` because it is GSBL's state, not the
    /// main loop's -- the original kept its own cursor and handed out the
    /// result.
    next: u16,
}

impl Gsbl {
    /// One channel for each terminal `terms` names, with GSBL's own defaults.
    pub fn new(terms: Terms) -> Self {
        Self {
            terms,
            channels: (0..terms.count()).map(|_| Channel::default()).collect(),
            next: 0,
        }
    }

    /// How many channels there are -- and the only thing that names one.
    pub fn terms(&self) -> Terms {
        self.terms
    }

    /// One channel.
    ///
    /// Infallible, because a [`Chan`] is the proof that the bound was asked.
    /// Every channel is also *defined* -- `Host::new` allocates them all and
    /// this host has no `btudef` -- so the guide's `-10` "channel is not
    /// defined" is unreachable, and `-11` "out of range" is the only refusal a
    /// shim can make. A shim makes it by failing to mint a `Chan` at all.
    ///
    /// # Panics
    ///
    /// If `chan` came from a larger [`Terms`] than this `Gsbl` was built from.
    /// That is not an out-of-range channel number; it is two bounds inside one
    /// host, which is the thing [`crate::chan`] exists to make unrepresentable.
    /// A panic naming it beats an `Option` that call sites discard -- which is
    /// exactly what the old signature got.
    pub fn channel(&self, chan: Chan) -> &Channel {
        &self.channels[chan.index()]
    }

    /// One channel, mutably. Infallible for the same reason as
    /// [`Gsbl::channel`], and panics for the same one.
    pub fn channel_mut(&mut self, chan: Chan) -> &mut Channel {
        &mut self.channels[chan.index()]
    }

    /// `CRSTG` -- a CR-terminated input string is available (guide, `btusts`
    /// page 155, status 3).
    pub const CRSTG: i16 = 3;

    /// `CYCLE` -- the "cycle-thru-other-users" pseudo-status, `MAJORBBS.H:236`.
    ///
    /// What a module injects at itself to be called back on the next pass.
    /// `fsdnfy()` (`FSDBBS.C:368`) is its whole body:
    ///
    ///
    /// It reaches `stsrou`, not `sttrou`: `susing()` (`MAJORBBS.C:2478`) names
    /// `POLSTS`, the hangup statuses, `CRSTG`, `OBFCLR`, `ABOREQ` and `OUTMT`
    /// as cases and lets everything else fall to
    /// `default: (*(module[usrptr->state]->stsrou))()`.
    pub const CYCLE: i16 = 240;

    /// `INBLK` -- byte-count-triggered input data is available (status 4).
    pub const INBLK: i16 = 4;

    /// `OUTMT` -- the output buffer went from not-empty to empty (status 5).
    /// Only ever raised when `btuoes` has enabled it.
    pub const OUTMT: i16 = 5;

    /// `OVRFLW` -- data output circular-buffer overflow (status 253). Guide,
    /// `btuxmt` CAUTIONS, page 191: when the string does not fit in the output buffer, btuxmt returns 0, queues status 253 for btusts, and outputs none of the string `btuxct`
    /// (page 182) says the same of a block that will not fit.
    pub const OVRFLW: i16 = 253;

    /// `POLSTS` -- the polling status code, `MAJORBBS.H:232`, "like CYCLE, but
    /// auto". `begin_polling` injects one and `dopoll` re-injects after every
    /// call, which is the whole mechanism by which a polling channel ticks.
    pub const POLSTS: i16 = 192;

    /// Bytes have arrived from the terminal.
    ///
    /// This is half of the boundary: a tokio task reading a socket and a test
    /// holding a literal both arrive here, and there is no second path to keep
    /// honest.
    ///
    /// A socket for a channel that was never allocated is the transport's bug
    /// rather than the module's, and it is now caught one step earlier: the
    /// transport has to mint a [`Chan`] from [`Gsbl::terms`] before it can call
    /// this at all, and that is where a channel that does not exist is refused.
    pub fn push_input(&mut self, chan: Chan, bytes: &[u8]) {
        let c = self.channel_mut(chan);
        let before = c.input.len();
        for &byte in bytes {
            c.take(byte);
        }
        // Raw mode queues no status of its own inside `take`, so nothing would
        // ever wake the loop for these bytes. One `CYCLE` per delivery, and only
        // if one is not already waiting: the handler drains `input` completely
        // on the pass it runs, so a second status would dispatch into an empty
        // buffer, and a pipelining client would otherwise grow the queue once
        // per socket read.
        //
        // Here rather than in `take` because `take` runs per byte and the
        // wake-up is per delivery.
        //
        // The condition is that a byte **landed**, not that one was offered.
        // `take` accepts nothing while `locked`, and drops everything past
        // `INPSIZ`; asking `!bytes.is_empty()` woke the module for both. The
        // locked case is the FSD's ordinary traffic rather than a curiosity:
        // `fsdbkg` (`FSDBBS.C:186`) does `btulok(usrnum,1)` -- "Turn off
        // keyboard till all displayed" -- so the channel is locked *and* raw
        // for the whole of every screen paint, and a wake-up per socket read
        // through all of it is an entry into `stsrou` with an empty buffer
        // every time.
        if c.raw && c.input.len() > before && !c.status.contains(&Gsbl::CYCLE) {
            c.status.push_back(Gsbl::CYCLE);
        }
    }

    /// The next status for a channel, oldest first, or `None` if none is
    /// waiting.
    ///
    /// This is `btusts`. The guide: the status buffer is a FIFO, so btusts hands back codes in the order they arose.
    pub fn next_status(&mut self, chan: Chan) -> Option<i16> {
        self.channel_mut(chan).status.pop_front()
    }

    /// Put a status where [`Gsbl::scan`] will find it.
    ///
    /// This is `btuinj`, reached two ways: the module calls it through the shim
    /// of that name, and the host calls it directly to re-arm a polling channel
    /// (`MAJORBBS.C:3267`). One method rather than two copies of the push, so
    /// they cannot come to disagree about what "inject" means.
    ///
    /// It used to answer `bool` -- `false` for a channel `Gsbl` did not have --
    /// and both host-side callers dropped the answer on the floor. They were
    /// right to, in the sense that the case could not arise; they were wrong to
    /// in the sense that nothing said so. There is no answer to drop now,
    /// because a [`Chan`] cannot name a channel this `Gsbl` lacks.
    pub fn inject(&mut self, chan: Chan, status: i16) {
        self.channel_mut(chan).status.push_back(status);
    }

    /// The oldest completed line, taken -- this is what `btuinp` hands the
    /// module. If more than one line is queued, the rest wait their turn.
    pub fn take_line(&mut self, chan: Chan) -> Option<Vec<u8>> {
        self.channel_mut(chan).ready.pop_front()
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
    pub fn drain_output(&mut self, chan: Chan) -> Vec<u8> {
        let c = self.channel_mut(chan);
        if c.output.is_empty() {
            return Vec::new();
        }
        let out: Vec<u8> = c.output.drain(..).collect();
        if c.oes {
            c.status.push_back(Self::OUTMT);
        }
        out
    }

    /// The next channel needing service, advancing the rotation.
    ///
    /// This is `btuscn`. The guide: it finds channels whose status code is non-zero and answers -1 when there are none. The `-1` is
    /// left to the caller; `None` is what Rust says.
    ///
    /// Each answer moves the cursor past the channel it named, so a channel
    /// that always has work cannot hold the others out -- the guide again,
    /// `btuscn` page 144: each later call resumes the scan at the channel after the last one reported, so no channel outranks another. See [`Gsbl::next`] for the corroborating C.
    ///
    /// Takes `&mut self` because the rotation is the point. To ask *whether*
    /// anything is waiting without consuming a turn, use [`Gsbl::pending`].
    ///
    /// The [`Chan`] it hands back is minted from this `Gsbl`'s own [`Terms`],
    /// so a channel found here is a channel every other table keyed by the same
    /// `Terms` also has. That is the whole point: `Host::poll` used to scan with
    /// `Gsbl`'s bound and then index `Users` with the result, which was correct
    /// only for as long as the two bounds happened to match.
    pub fn scan(&mut self) -> Option<Chan> {
        let index = self.peek()?;
        // Past the channel that *required service*, not past wherever this scan
        // started looking. With an idle channel between two busy ones the two
        // differ, and advancing from the cursor would leave it short by the size
        // of the gap -- so the channel past the gap would take two turns a
        // round. Both spellings pass a test suite whose channels are adjacent,
        // which is how this survived review once.
        self.next = (index + 1) % self.terms.count();
        // Through the same mint every other caller uses, rather than a private
        // constructor: `index` is below `terms.count()`, so this cannot refuse
        // -- and if it ever does, the two have come apart and that is worth a
        // panic.
        Some(
            self.terms
                .chan(index as i16)
                .expect("scan indexed its own channels"),
        )
    }

    /// Whether any channel has a status waiting, without advancing the rotation.
    ///
    /// [`Host::cycle`](crate::Host::cycle) asks this to decide whether it is
    /// idle. Were the question to advance the cursor, every second channel
    /// would be skipped -- a starvation bug introduced by the fix for a
    /// starvation bug.
    ///
    /// Answering a wrong `false` is the dangerous direction: the host reports
    /// [`Ended::Idle`](crate::Ended) and stops while a channel still holds a
    /// queued status.
    #[must_use]
    pub fn pending(&self) -> bool {
        self.peek().is_some()
    }

    /// Whether this channel already has a `POLSTS` waiting.
    ///
    /// [`crate::Host::refill_polls`] asks before injecting one. Arming a
    /// channel that is already armed adds a status the rotation will dispatch
    /// twice, and since a refill happens on every driver wake, the queue would
    /// grow without bound for as long as the channel polls.
    ///
    /// This is the same question `begin_polling` asks as `polrou == NULL`
    /// (`MAJORBBS.C:1183`) before its own injection, asked of the queue rather
    /// than of the routine, because the host arms channels the module has
    /// already told it about.
    #[must_use]
    pub fn polling_armed(&self, chan: Chan) -> bool {
        self.channel(chan)
            .status
            .iter()
            .any(|&status| status == Self::POLSTS)
    }

    /// The channel [`Gsbl::scan`] would name, without naming it.
    ///
    /// The rotation's search with the cursor move left out, so that `scan` and
    /// [`Gsbl::pending`] cannot come to disagree about what counts as work.
    /// They spelled the predicate separately once, and a `pending` that read
    /// only channel zero passed all 739 tests.
    ///
    /// `self.next + step` cannot overflow: [`Terms::new`] caps a count at
    /// `i16::MAX`, so both terms are below 32,767 and the sum is below
    /// `u16::MAX`. That cap is three units of headroom away from being
    /// load-bearing, and it lives in another module -- hence this sentence.
    pub(crate) fn peek(&self) -> Option<u16> {
        let count = self.terms.count();
        (0..count)
            .map(|step| (self.next + step) % count)
            .find(|&index| !self.channels[usize::from(index)].status.is_empty())
    }

    /// `bturst` -- reset a channel to its initial default conditions.
    ///
    /// The guide, `bturst` page 138: it returns the channel, hardware and software alike, to its power-on defaults; because the default switch-hook state is on-hook, it is also the documented way to hang up.
    ///
    /// The hardware half does not exist here -- no Xecom, Hayes, X.25 or LAN
    /// board -- which is also why the routine's return value is dropped rather
    /// than reproduced: it is a hardware-category discriminant
    /// (`MAJORBBS.C:3503`) that the real host switches on only to pick the baud
    /// rate, handshake and protocol calls that follow. The software half is
    /// every byte and every setting on this [`Channel`], and that is what this
    /// restores.
    ///
    /// # Why a channel that keeps its buffers is a bug
    ///
    /// `dftrst` calls `bturst(usrnum)` at `MAJORBBS.C:3503`, after the three
    /// `setmem` clears that [`Host::rstchn`](crate::Host::rstchn) reproduces.
    /// Leaving it out means a recycled channel carries the previous player's
    /// half-assembled input line, undrained output, queued statuses, column
    /// position, and their `btutsw` width / `btumil` / `btuech` / `btulok`
    /// settings into the next player's session -- their half-typed command
    /// arriving as somebody else's first input. At one channel there is never
    /// a next player, which is why this was invisible.
    pub fn reset(&mut self, chan: Chan) {
        *self.channel_mut(chan) = Channel::default();
    }

    /// `btuxmt` -- ASCII output, word-wrapped at the `btutsw` width.
    pub fn transmit(&mut self, chan: Chan, bytes: &[u8]) {
        self.channel_mut(chan).transmit(bytes);
    }

    /// `btuxct` -- binary output, exactly as given.
    ///
    /// R6, guide page 182: a block that will not fit is not truncated into
    /// what room remains -- none of it goes out, and status 253 (`OVRFLW`) is
    /// queued instead.
    pub fn transmit_raw(&mut self, chan: Chan, bytes: &[u8]) {
        let c = self.channel_mut(chan);
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
    ///
    /// [`Channel::raw`] short-circuits all of it, ahead of even the translate
    /// table -- it stands in for the `btuchi` handler `fsdcon` installs, which
    /// in the original runs at interrupt level and therefore before any of
    /// these eleven steps too.
    fn take(&mut self, byte: u8) {
        // 2. Input lockout. The byte never happened.
        if self.locked {
            return;
        }

        // Raw mode, before everything: a keystroke is a keystroke, and the FSD
        // wants the CR and the backspace as bytes rather than as instructions.
        // Before the translate table above all, which drops ESC -- the first
        // byte of every arrow key, and the FSD steers on arrow keys. Ahead of
        // the `trigger` branch because `raw` is the host's own doing and
        // `trigger` is the module's; nothing sets both.
        if self.raw {
            if self.input.len() < INPSIZ {
                self.input.push_back(byte);
            }
            return;
        }

        // 3. Binary mode. None of the ASCII processing applies -- a CR in
        //    binary mode is a byte like any other.
        if self.trigger != 0 {
            // The comment above says "nothing sets both", and this is where
            // that stops being an assertion: the branch is reachable only with
            // `raw` clear, because the `raw` branch returned. A build where the
            // two have swapped places arrives here holding an FSD keystroke and
            // says so, instead of quietly counting it toward an `INBLK` nobody
            // asked for.
            //
            // Here rather than at the top of `take`, deliberately. An assert
            // ahead of both branches fires identically whichever order they are
            // in, which would make the ordering unobservable and leave
            // `raw_mode_wins_over_the_byte_count_trigger` unable to tell a
            // correct build from the mutation it exists to catch.
            debug_assert!(
                !self.raw,
                "raw mode is handled ahead of binary mode: a raw keystroke \
                 reached the byte-count trigger"
            );
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
        let mut csi = self.csi;

        for &byte in bytes {
            match csi {
                CsiScan::Text => Self::dispatch_normal(
                    &mut out,
                    &mut column,
                    &mut supplied_lf,
                    &mut csi,
                    self.width,
                    byte,
                ),
                CsiScan::Esc => {
                    if byte == b'[' {
                        // Confirmed: this is a CSI. Both bytes were withheld
                        // exactly for this moment -- emit them now, uncounted.
                        out.push(0x1B);
                        out.push(byte);
                        csi = CsiScan::Csi;
                    } else {
                        // Not a CSI after all. The withheld ESC is an
                        // ordinary byte, counted exactly as it always was
                        // before this fix -- then the current byte is
                        // dispatched fresh, since it was never held back and
                        // may itself open a new escape.
                        Self::emit_one(&mut out, &mut column, &mut supplied_lf, self.width, 0x1B);
                        csi = CsiScan::Text;
                        Self::dispatch_normal(
                            &mut out,
                            &mut column,
                            &mut supplied_lf,
                            &mut csi,
                            self.width,
                            byte,
                        );
                    }
                }
                CsiScan::Csi => {
                    if (0x40..=0x7E).contains(&byte) {
                        // The final byte. Emitted uncounted, like everything
                        // else in the sequence; the CSI is complete.
                        out.push(byte);
                        csi = CsiScan::Text;
                    } else if (0x20..=0x3F).contains(&byte) {
                        // A parameter or intermediate byte. Still inside a
                        // well-formed CSI.
                        out.push(byte);
                    } else {
                        // Malformed: this byte cannot appear in a CSI at all
                        // (not 0x20-0x7E). The house rule -- matching how a
                        // real terminal's parser behaves -- is that a byte
                        // which cannot continue the sequence aborts it and is
                        // then handled exactly as if no escape were in
                        // progress. Nothing already emitted as the aborted
                        // prefix is revisited; only this byte, and everything
                        // after it, gets ordinary treatment. That keeps the
                        // rule simple and, crucially, keeps every byte on the
                        // wire -- nothing is ever buffered pending a final
                        // byte that might never come, so there is nothing to
                        // lose and nothing that can hang.
                        csi = CsiScan::Text;
                        Self::dispatch_normal(
                            &mut out,
                            &mut column,
                            &mut supplied_lf,
                            &mut csi,
                            self.width,
                            byte,
                        );
                    }
                }
            }
        }

        // R6, guide `btuxmt` CAUTIONS page 191: a string that will not fit is
        // not output *at all*, and a status 253 is queued. Nothing above this
        // line has touched the channel, so there is nothing to roll back --
        // `csi` included: a rejected call must not leave the channel
        // believing it is mid-CSI on the strength of bytes that never
        // reached the wire.
        if self.output.len() + out.len() > OUTSIZ {
            self.status.push_back(Gsbl::OVRFLW);
            return;
        }
        self.output.extend(out);
        self.column = column;
        self.supplied_lf = supplied_lf;
        self.csi = csi;
    }

    /// `Text`-state dispatch: either the byte opens a possible CSI, or it is
    /// ordinary output. Its own function because two of [`Channel::transmit`]'s
    /// three [`CsiScan`] arms resolve mid-byte to "handle this byte as if
    /// nothing were in progress" and need to run the same two-way branch the
    /// main `Text` arm does.
    fn dispatch_normal(
        out: &mut Vec<u8>,
        column: &mut u16,
        supplied_lf: &mut bool,
        csi: &mut CsiScan,
        width: u16,
        byte: u8,
    ) {
        if byte == 0x1B {
            // Held, not emitted -- see `CsiScan::Esc`'s doc for why.
            *csi = CsiScan::Esc;
        } else {
            Self::emit_one(out, column, supplied_lf, width, byte);
        }
    }

    /// One byte's worth of the pre-CSI-fix `transmit` body: CRLF expansion
    /// (R1), the wrap check (R9), and the column count (R10). Used for every
    /// byte `transmit` decides is *not* part of a CSI -- which, before this
    /// fix, was every byte.
    fn emit_one(out: &mut Vec<u8>, column: &mut u16, supplied_lf: &mut bool, width: u16, byte: u8) {
        match byte {
            b'\r' => {
                // R1 -- guide, `btulfd` page 114: the default on channel
                // initialisation is that an explicit LF is necessary after
                // every CR to move to the next line, and `WCCMMUD.DLL` never
                // calls `btulfd` or `btuhcr`, so the default stands.
                // `supplied_lf` remembers that this LF is ours, so a module
                // byte stream that already spells out `\r\n` -- even split
                // across two `transmit` calls -- does not get a second one.
                out.push(b'\r');
                out.push(b'\n');
                *column = 0;
                *supplied_lf = true;
                return;
            }
            b'\n' if *supplied_lf => {
                // The other half of a module's own explicit `\r\n` -- already
                // on the wire as the LF we supplied above.
                *supplied_lf = false;
                return;
            }
            b'\n' => {
                out.push(b'\n');
                return;
            }
            _ => {}
        }
        *supplied_lf = false;
        // Backspace (0x08) is deliberately not special-cased here: it falls
        // through and costs a column like any other byte, exactly as it did
        // before this fix. The oracle cannot settle whether that is right --
        // all 36 backspace-bearing lines in `oracle_bank2.raw` are 22-31
        // visible columns, nowhere near the 79-column wrap boundary, so
        // there is no captured line where it would show. Left alone rather
        // than guessed at.
        if width != 0 && *column >= width && Self::wrap(out, column, width, byte) {
            // R9, guide `btutsw` page 172: word wrap works by turning a space into a carriage return -- the space
            // *becomes* the break `wrap()` just inserted, so it is
            // consumed here rather than carried onto the new line as a
            // leading indent.
            //
            // `wrap()` reports this only when the trigger byte is a
            // space and either nothing was carried, or the word it found
            // already filled the line to exactly `width` on its own --
            // see `wrap()`'s own doc for why those are the only two
            // cases R9 may fire in.
            //
            // This host used to cite the specific words that surfaced
            // the *first* half of this bug -- `thisis`, `andthese`,
            // `Streetslead`, from `re/oracle/oracle_bank2.raw`'s Town
            // Square description, glued together because an early `wrap`
            // consumed a triggering space that belonged to a word it had
            // genuinely carried. The CSI fix moved every wrap point in
            // that paragraph, and a second, narrower bug -- `wrap`
            // carrying a word that had already fit exactly at `width`,
            // rather than recognising it needed no carry at all --
            // surfaced only once wrap points started landing on the
            // paragraph's real 79-column boundaries. See
            // `crates/mbbs/tests/wccmmud.rs`,
            // `a_returning_player_entering_the_realm`, for the citations
            // measured against the oracle after both fixes.
            return;
        }
        out.push(byte);
        // R10: with the default width of 0, wrap() is never called and
        // nothing but a CR ever resets column -- so a long enough
        // channel-lifetime of unwrapped output must not panic once it passes
        // u16::MAX bytes since the last CR.
        *column = column.saturating_add(1);
    }

    /// Break the line, moving a partial word down with it -- unless the word
    /// already fit, in which case nothing moves at all.
    ///
    /// Word wrap rather than a hard break: the guide calls `btutsw` wrapping output at word boundaries, and a host that broke mid-word would split every name the
    /// module printed near the margin.
    ///
    /// Returns **whether the caller's triggering byte was consumed** rather
    /// than needing to be written. Only a SPACE can be consumed (R9, guide
    /// `btutsw` page 172: word wrap works by turning a space into a carriage return), and only in the two cases where that SPACE really
    /// is the break this call just inserted:
    ///
    /// 1. **Nothing was carried.** The back-scan below hit the start of
    ///    `out`, or a word at least `width` long that had no boundary to
    ///    break on and was pushed back to break at the margin instead. Either
    ///    way there is no partial word on the new line for the SPACE to
    ///    glue itself to.
    /// 2. **A word was found, but it already reached exactly `width` on its
    ///    own.** This is the case Finding 7's fix (below) missed: back-scan
    ///    finds a complete word bounded by a real separator, and the old rule
    ///    carried it unconditionally, unable to tell "this word doesn't fit"
    ///    apart from "this word already fit, and only the byte *after* it
    ///    didn't". Measured against `re/oracle/oracle_bank2.raw` (search
    ///    "make- shift"): the genuine host's `btutsw(chan, 0x4f)` (79) keeps
    ///    `shift` on the line it already filled to column 79 and opens the
    ///    next line with `stalls`; this host used to carry `shift` down
    ///    whole, splitting `make- shift` instead of `shift stalls`. The
    ///    Galacticomm guide's own worked example (`GSBL-174`/`GSBL-175`,
    ///    `archive/galacticomm/gsblref.pdf`) needs the same rule: `btutsw`
    ///    caps each line to `width - 1` characters ("to prevent the user's
    ///    terminal from doing its own line wrapping", `GSBL-172`) so that a
    ///    `btutsw(chan, 20)` example's word `to` filling a line to column 19
    ///    exactly stays there rather than being carried -- see
    ///    `the_guides_own_worked_example_renders_the_way_the_guide_prints_it`,
    ///    which cannot reproduce the manual's own printed screen without this
    ///    rule.
    ///
    /// If a word was found and carried for any other reason -- it doesn't
    /// fit at all, or the trigger byte was not a SPACE and so cannot be R9's
    /// break regardless -- the caller always writes the trigger byte itself.
    ///
    /// A word at least `width` long has no boundary to break on, so it is
    /// pushed back and broken at the margin, carrying nothing. Short of that,
    /// a carried word is always below `width` bytes, so the SPACE a caller
    /// writes after it always fits on the new line without itself
    /// re-triggering the wrap.
    ///
    /// Finding 7, **fixed**. This looks back into the `out` buffer its caller
    /// owns, not into `self.output`, so a drain cannot move a line break.
    /// [`Gsbl::drain_output`] is safe at any point, including mid-line, and a
    /// transport may flush on whatever schedule it likes.
    ///
    /// It was not always so. While the look-back popped from `self.output`,
    /// the bytes a channel emitted depended on when a socket task happened to
    /// run. `transmit` building a private buffer and committing once is what
    /// fixed it; see its own comment for why that shape was chosen.
    fn wrap(out: &mut Vec<u8>, column: &mut u16, width: u16, byte: u8) -> bool {
        let mut word = Vec::new();
        // `found_delimiter` distinguishes "the back-scan hit a real SPACE,
        // LF or CR inside `out`" from "the back-scan ran off the start of
        // `out` with no delimiter in sight". Only the first can prove a word
        // already fits: the second means the word's beginning is outside
        // this `transmit()` call's own buffer (an earlier call committed it),
        // so its true length is unknown and it is carried exactly as before
        // -- a known, narrow limitation of chopping one paragraph across
        // several `transmit()` calls that genuine GSBL, handed one whole
        // string, never faces. See
        // `a_second_call_can_carry_a_word_it_began_itself`.
        let mut found_delimiter = false;
        while let Some(&back) = out.last() {
            if back == b' ' || back == b'\n' || back == b'\r' {
                found_delimiter = true;
                break;
            }
            word.push(back);
            out.pop();
            // A word as long as the whole line has no boundary to break on, so
            // break it where the margin falls -- losing it would be worse.
            // This is orthogonal to the fit-check below: an unbreakable word
            // is never "already fit", so it always falls through to the
            // shared tail and reports consumed only via the ordinary
            // nothing-carried rule.
            if word.len() >= usize::from(width) {
                for b in word.drain(..).rev() {
                    out.push(b);
                }
                break;
            }
        }

        if found_delimiter && byte == b' ' && !word.is_empty() {
            // The word back-scan found is bounded by a real separator on
            // both sides and reached exactly `width` -- it already fits.
            // Put it back untouched (nothing was moved) and break right
            // where the triggering SPACE would have gone. No trailing-space
            // strip is needed here the way the shared tail below needs one:
            // `word` can never contain a space (the scan above stops the
            // instant it sees one), so putting it back always leaves `out`
            // ending on a non-space byte.
            for b in word.into_iter().rev() {
                out.push(b);
            }
            out.extend(b"\r\n");
            *column = 0;
            return true;
        }

        // Every other case: nothing carried (word is empty, whether because
        // `out` ran out or because the back-scan hit a delimiter
        // immediately), a word too long to have a boundary, or a word that
        // does not fit and must move down. All three carry `word` as-is --
        // zero bytes in the first two -- exactly as before this fix.
        while out.last() == Some(&b' ') {
            out.pop();
        }
        out.extend(b"\r\n");
        *column = 0;
        let carried = word.len();
        for b in word.into_iter().rev() {
            out.push(b);
            *column += 1;
        }
        byte == b' ' && carried == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-channel `Gsbl`, which is what every test here wants.
    fn one() -> Gsbl {
        Gsbl::new(Terms::new(1))
    }

    /// Its only channel. Minted from a `Terms` of the same size `one()` builds,
    /// so it indexes that `Gsbl` -- the pairing these tests used to make by
    /// writing the literal `0` and trusting it.
    fn chan() -> Chan {
        Terms::new(1).chan(0).expect("a one-channel host has channel zero")
    }

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
        let mut whole = one();
        whole.channel_mut(chan()).width = 20;
        for half in halves {
            whole.transmit(chan(), half);
        }
        let undrained = whole.drain_output(chan());

        // Drained between the two calls, then concatenated.
        let mut split = one();
        split.channel_mut(chan()).width = 20;
        let mut drained = Vec::new();
        for half in halves {
            split.transmit(chan(), half);
            drained.extend(split.drain_output(chan()));
        }

        assert_eq!(
            String::from_utf8_lossy(&drained),
            String::from_utf8_lossy(&undrained),
            "a drain between two btuxmt calls changed the bytes"
        );
    }

    #[test]
    fn a_fresh_channel_has_the_defaults_gsbl_gave_it() {
        let g = one();
        let c = g.channel(chan());
        assert_eq!(c.width, 0, "btutsw default: no word wrap");
        assert_eq!(c.maxinl, 0, "btumil default: no line limit");
        assert!(c.echo, "btuech default: echo on");
        assert!(!c.locked, "btulok default: input not locked out");
        assert_eq!(c.trigger, 0, "btutrg default: ASCII mode");
    }

    /// The refusal moved out of `Gsbl` and into the mint, so this is where it
    /// is asserted now -- there is no longer a `Gsbl` method that can be handed
    /// a channel it does not have.
    #[test]
    fn a_channel_outside_nterms_cannot_even_be_named() {
        let terms = one().terms();
        assert!(terms.chan(1).is_none());
        assert!(terms.chan(-1).is_none());
        assert!(terms.chan(0).is_some(), "and channel zero still is");
    }

    #[test]
    fn a_line_is_ready_only_once_the_terminator_arrives() {
        let mut g = one();
        g.push_input(chan(), b"loo");
        assert_eq!(g.next_status(chan()), None, "no status until the CR");
        g.push_input(chan(), b"k\r");
        assert_eq!(g.next_status(chan()), Some(Gsbl::CRSTG));
        assert_eq!(g.take_line(chan()).as_deref(), Some(&b"look"[..]));
    }

    #[test]
    fn the_status_fifo_is_drained_in_order_and_only_once() {
        // R3: this test used to pass while silently destroying "a" -- it
        // asserted the two statuses and never the lines, so a `ready` that
        // let the second line overwrite the first went unnoticed. Both lines
        // must survive, in order.
        let mut g = one();
        g.push_input(chan(), b"a\rb\r");
        assert_eq!(g.next_status(chan()), Some(Gsbl::CRSTG));
        assert_eq!(g.next_status(chan()), Some(Gsbl::CRSTG));
        assert_eq!(g.next_status(chan()), None, "two lines, two statuses, no more");
        assert_eq!(
            g.take_line(chan()).as_deref(),
            Some(&b"a"[..]),
            "the first line must still be here, not overwritten by the second"
        );
        assert_eq!(g.take_line(chan()).as_deref(), Some(&b"b"[..]));
        assert_eq!(g.take_line(chan()), None);
    }

    #[test]
    fn a_linefeed_after_a_return_is_not_a_second_line() {
        // A telnet client sends CRLF. Treating the LF as a terminator would
        // hand the module an empty command after every real one.
        let mut g = one();
        g.push_input(chan(), b"look\r\n");
        assert_eq!(g.next_status(chan()), Some(Gsbl::CRSTG));
        assert_eq!(g.next_status(chan()), None);
    }

    #[test]
    fn backspace_removes_a_byte_and_does_nothing_at_column_zero() {
        let mut g = one();
        g.push_input(chan(), b"\x08");
        g.push_input(chan(), b"lookk\x08\r");
        assert_eq!(g.take_line(chan()).as_deref(), Some(&b"look"[..]));
    }

    #[test]
    fn del_is_translated_to_backspace() {
        // R2, guide btuxlt page 184: RUBOUT (ASCII 127) becomes BACKSPACE, a concession to old terminals without a backspace key. Every modern terminal emulator's Backspace key
        // sends 0x7F.
        let mut g = one();
        g.push_input(chan(), b"lookx\x7f\x7f\r");
        assert_eq!(g.take_line(chan()).as_deref(), Some(&b"loo"[..]));
    }

    #[test]
    fn control_characters_other_than_backspace_and_cr_are_ignored() {
        // R2, guide btuxlt page 184: every other control character is dropped. An RFC 854 client's CR NUL would otherwise leak the NUL
        // into the next command.
        let mut g = one();
        g.push_input(chan(), b"lo\x00\x07\x1bok\r"); // NUL, BEL, ESC
        assert_eq!(g.take_line(chan()).as_deref(), Some(&b"look"[..]));
    }

    #[test]
    fn the_high_bit_is_stripped_before_translation() {
        // R2, guide btuxlt page 184: the high bit is always cleared. Telnet IAC (0xFF) would otherwise land in the
        // command line; here a stray high-bit byte becomes the ASCII
        // character underneath it (0xE9 & 0x7F == 0x69 == 'i').
        let mut g = one();
        g.push_input(chan(), b"look\xe9ng\r");
        assert_eq!(g.take_line(chan()).as_deref(), Some(&b"looking"[..]));
    }

    #[test]
    fn a_locked_channel_discards_what_arrives() {
        let mut g = one();
        g.channel_mut(chan()).locked = true;
        g.push_input(chan(), b"look\r");
        assert_eq!(g.next_status(chan()), None);
        assert_eq!(g.take_line(chan()), None);
    }

    #[test]
    fn btumil_drops_what_would_not_fit_rather_than_truncating_the_line() {
        let mut g = one();
        g.channel_mut(chan()).maxinl = 4;
        g.push_input(chan(), b"lookout\r");
        assert_eq!(g.take_line(chan()).as_deref(), Some(&b"look"[..]));
    }

    #[test]
    fn echo_puts_what_arrived_back_on_the_wire_and_silence_does_not() {
        let mut g = one();
        g.push_input(chan(), b"hi");
        assert_eq!(g.drain_output(chan()), b"hi".to_vec());

        g.channel_mut(chan()).echo = false;
        g.push_input(chan(), b"hi");
        assert!(g.drain_output(chan()).is_empty());
    }

    #[test]
    fn an_echoed_backspace_erases_the_character_on_the_terminal() {
        let mut g = one();
        g.push_input(chan(), b"a\x08");
        assert_eq!(g.drain_output(chan()), b"a\x08 \x08".to_vec());
    }

    #[test]
    fn a_byte_count_trigger_raises_status_four_and_leaves_the_bytes_raw() {
        // Binary mode: none of the ASCII processing applies, not even the
        // terminator -- a CR is just a byte.
        const INBLK: i16 = 4;
        let mut g = one();
        g.channel_mut(chan()).trigger = 3;
        g.push_input(chan(), b"a\rb");
        assert_eq!(g.next_status(chan()), Some(INBLK));
        assert_eq!(g.take_line(chan()), None, "binary input is not a line");
    }

    #[test]
    fn status_four_is_raised_once_per_block_not_once_per_buffered_byte() {
        // R4, guide btutrg page 167: every further nbyt input bytes raise the same status again. 100 bytes at a 20-byte trigger is five
        // blocks and five statuses -- not eighty-one, which is what
        // `input.len() >= trigger` re-firing on every byte past the
        // threshold used to produce.
        let mut g = one();
        g.channel_mut(chan()).trigger = 20;
        g.push_input(chan(), &[0u8; 100]);
        let mut count = 0;
        while let Some(status) = g.next_status(chan()) {
            assert_eq!(status, Gsbl::INBLK);
            count += 1;
        }
        assert_eq!(count, 5);
    }

    /// The transport used to be able to call `push_input(9, ..)` on a
    /// one-channel host and have it quietly vanish. It cannot reach the call at
    /// all now: there is no channel 9 to name.
    #[test]
    fn a_transport_cannot_push_to_a_channel_that_does_not_exist() {
        let g = one();
        assert!(g.terms().chan(9).is_none());
    }

    #[test]
    fn ascii_output_with_no_width_is_passed_through_unchanged() {
        let mut g = one();
        g.transmit(chan(), b"the quick brown fox");
        assert_eq!(g.drain_output(chan()), b"the quick brown fox".to_vec());
    }

    #[test]
    fn ascii_output_wraps_on_a_word_boundary_at_the_btutsw_width() {
        let mut g = one();
        g.channel_mut(chan()).width = 10;
        g.transmit(chan(), b"the quick brown fox");
        assert_eq!(g.drain_output(chan()), b"the quick\r\nbrown fox".to_vec());
    }

    #[test]
    fn a_word_longer_than_the_width_is_broken_rather_than_lost() {
        let mut g = one();
        g.channel_mut(chan()).width = 4;
        g.transmit(chan(), b"abcdefg");
        assert_eq!(g.drain_output(chan()), b"abcd\r\nefg".to_vec());
    }

    #[test]
    fn a_space_that_lands_on_the_wrap_boundary_is_consumed_not_carried() {
        // R9, guide btutsw page 172: word wrap works by turning a space into a carriage return -- so when the space itself is the byte
        // that pushes the column past the width, it must become the break,
        // not survive as a leading-space indent on the new line. This is the
        // one case where the byte that triggers `wrap()` is a space rather
        // than the next word's first letter.
        let mut g = one();
        g.channel_mut(chan()).width = 10;
        g.transmit(chan(), b"0123456789 abc");
        assert_eq!(g.drain_output(chan()), b"0123456789\r\nabc".to_vec());
    }

    #[test]
    fn the_guides_own_worked_example_renders_the_way_the_guide_prints_it() {
        // Printed pages 174-175: Galacticomm set `btutsw(chan,20)`, transmitted
        // a known paragraph, and printed the expected screen. It is the only
        // assertion in this file answerable from the specification rather than
        // from this host measuring itself, and nothing used it until a review
        // went looking.
        //
        // The guide's example also sets `btuhcr(chan,13)` and `btuscr(chan,10)`,
        // making its `\n`s *soft* carriage returns -- and its own rule is that
        // "when output word wrap has taken place in a paragraph, all subsequent
        // soft carriage returns are converted into spaces". This host has
        // neither `btuhcr` nor `btuscr` (`WCCMMUD.DLL` imports neither), so the
        // soft CRs are supplied here already converted, which is the same input
        // the guide's own machinery would hand the wrapper.
        //
        // This is the assertion that fails on the code as it stood before the
        // carry fix: the old `transmit` produced `theEngelmann` and
        // `westernNorth`. The defect was never MajorMUD-specific -- it failed
        // Galacticomm's published example.
        //
        // `width` is set to 19 by hand here, not to the 20 the manual's
        // example passes `btutsw()`. That gap is a real discrepancy between
        // the guide and the genuine board, and it is recorded here rather
        // than resolved -- do not "tidy" it away in either direction:
        //
        // - Page `GSBL-172` (`archive/galacticomm/gsblref.pdf`) says "to
        //   prevent the user's terminal from doing its own line wrapping,
        //   each line is actually limited to width-1 characters", and the
        //   worked example on `GSBL-174/175` duly prints 19-column lines for
        //   its `btutsw(chan, 20)`. The manual is self-consistent.
        // - The genuine board is not consistent *with the manual*.
        //   `WCCMMUD.DLL` calls `btutsw(chan, 0x4f)` (79), and
        //   `re/oracle/oracle_bank2.raw` wraps at 79 visible columns -- not
        //   78. Argument and capacity are the same number on the real wire.
        // - This host follows the board, because the board is the oracle:
        //   `btutsw` stores its argument verbatim
        //   (`crates/mbbs/src/shims/gsbl.rs:56`), so `Channel::width` *is*
        //   the raw argument and `transmit` fills every one of its columns.
        //   `the_oracle_s_own_paragraph_wraps_at_its_own_six_line_lengths`
        //   is the test that pins that, against real captured bytes.
        //
        // So this test cannot both call `btutsw(chan, 20)` and reproduce the
        // guide's printed screen; it sets the capacity that screen is
        // actually rendered at and exercises the wrap algorithm against it,
        // which is the part of the example worth having. Whether some GSBL
        // revision really did subtract one and MajorMUD was built against one
        // that did not is open -- settle it with a capture, not with this
        // comment.
        //
        // That the word-fit half of `wrap()`'s rule (this task's fix, not the
        // carry fix above) is exercised even by Galacticomm's own example was
        // not expected going in: the paragraph's `to` (`"...native to"`) fills
        // line 3 to column 19 exactly, and only stays there rather than being
        // carried because of that rule. At `width = 20` -- the value this test
        // used to carry -- the *old*, buggy `wrap()` reproduced this screen by
        // coincidence, because always carrying a found word happens to agree
        // with capping every line one column short when the two are off by
        // exactly the same one. Nineteen removes the coincidence: the pre-fix
        // `wrap()` cannot reproduce this screen at this width, only the fixed
        // one can.
        let mut g = one();
        g.channel_mut(chan()).width = 19;
        g.transmit(chan(), b"The blue form of the Engelmann Spruce ");
        g.transmit(chan(), b"is native to the mountains of western ");
        g.transmit(chan(), b"North America.");
        assert_eq!(
            String::from_utf8_lossy(&g.drain_output(chan())),
            "The blue form of\r\nthe Engelmann\r\nSpruce is native to\r\nthe mountains of\r\nwestern North\r\nAmerica.",
            "the guide's printed rendering, pages 174-175, at the width its own \
             width-1 rule actually produces"
        );
    }

    #[test]
    fn only_a_space_becomes_the_break_and_a_tab_is_part_of_the_word() {
        // Guide page 172 defines a word as a run of non-space characters,
        // so a TAB belongs to the word and has to survive the wrap. Widening
        // the predicate to `is_ascii_whitespace()` reads as a tidy
        // generalisation, eats the TAB, and passed all 765 tests before this
        // existed.
        let mut g = one();
        g.channel_mut(chan()).width = 10;
        g.transmit(chan(), b"0123456789\tabc");
        assert_eq!(
            String::from_utf8_lossy(&g.drain_output(chan())),
            "0123456789\r\n\tabc",
            "only 0x20 is the character word wrap is allowed to convert"
        );
    }

    #[test]
    fn every_trailing_space_is_stripped_at_the_break_not_merely_one() {
        // `wrap`'s strip loop is `while`, not `if`, and the carry fix makes its
        // territory more reachable: a space this host now *keeps* can be
        // followed by another space arriving at the margin. Weakening the loop
        // to a single pop puts a trailing space on the wire and passed all 765
        // tests.
        let mut g = one();
        g.channel_mut(chan()).width = 10;
        g.transmit(chan(), b"abcdefgh  x");
        assert_eq!(
            String::from_utf8_lossy(&g.drain_output(chan())),
            "abcdefgh\r\nx",
            "no line goes out with a trailing space"
        );
    }

    #[test]
    fn wrap_does_not_pop_a_line_ending_back_into_the_word_it_carries() {
        // `wrap`'s look-back stops on `\n` and `\r` as well as on a space, and
        // that guard is live rather than defensive: `transmit`'s bare-LF arm
        // pushes the byte *without* resetting `column`, so `out` can hold a
        // line ending mid-line. Drop the two line-ending cases and `wrap` pops
        // its own CRLF back into a "word" -- green across all 765 tests.
        let mut g = one();
        g.channel_mut(chan()).width = 10;
        g.transmit(chan(), b"abc\ndefghijk");
        assert_eq!(
            String::from_utf8_lossy(&g.drain_output(chan())),
            "abc\n\r\ndefghijk",
            "the break lands after the LF, not inside the text before it"
        );
    }

    #[test]
    fn a_word_that_fills_the_line_exactly_is_not_carried_down() {
        // This task's fix, in its smallest reproduction. `this` ends at
        // column 10 exactly (the fifth byte of `12345 `, then four more for
        // `this`), so the line is already full when the next byte -- the
        // space before `is` -- arrives. That word already fit; nothing needs
        // to move. Measured against `re/oracle/oracle_bank2.raw` (search
        // "make- shift"): the genuine host keeps `shift` on the line it fills
        // to column 79 and opens the next with `stalls`, not `make-` /
        // `shift stalls`. See `wrap()`'s doc for the full citation.
        //
        // Before this fix, `wrap()` could not tell "this word doesn't fit"
        // apart from "this word already fit, and only the byte after it
        // didn't" -- it back-scanned to the space before `this`, found a
        // complete word, and carried it unconditionally, producing
        // `12345\r\nthis is`. This test used to pin exactly that output, under
        // the name `a_word_carried_down_by_the_wrap_keeps_the_space_that_followed_it`,
        // with a comment explaining why keeping the space was right *given*
        // the carry -- which was true, but the carry itself was the bug. A
        // word genuinely carried across a `transmit()` call boundary still
        // keeps its trailing space exactly that way; see
        // `a_second_call_can_carry_a_word_it_began_itself`, which is now the
        // only place in this file where a word both straddles the width
        // boundary and gets carried.
        //
        // Asserted as a string rather than the byte vector the tests above use:
        // the whole difference is one 0x20, and a `[49, 50, ...]` diff does not
        // show it.
        let mut g = one();
        g.channel_mut(chan()).width = 10;
        g.transmit(chan(), b"12345 this is");
        assert_eq!(
            String::from_utf8_lossy(&g.drain_output(chan())),
            "12345 this\r\nis",
            "a word that already fills the line to width is not carried"
        );
    }

    #[test]
    fn a_word_carried_down_by_the_wrap_is_not_glued_to_a_following_letter() {
        // The same carry as above, but the byte that triggered the wrap is not a
        // space -- so R9 never applied and this shape was always right. Pinned
        // because the fix is a condition on that byte, and a fix written the
        // wrong way round (`carried != 0` consuming instead of keeping) would
        // eat this `e` and lose a letter rather than a space.
        let mut g = one();
        g.channel_mut(chan()).width = 10;
        g.transmit(chan(), b"12345 abcdefgh");
        assert_eq!(
            String::from_utf8_lossy(&g.drain_output(chan())),
            "12345\r\nabcdefgh",
            "the trigger byte was a letter, so it is carried, never consumed"
        );
    }

    #[test]
    fn a_single_byte_word_that_fills_the_line_exactly_is_not_carried_either() {
        // The smallest instance of this task's fix: a carry only one byte
        // long. `9` lands on column 10 exactly (`12345678 ` is nine bytes),
        // so it already fits and stays; only the trailing `x` opens the new
        // line.
        //
        // Before this fix, `wrap()` found `9` bounded by a real space on both
        // sides and carried it regardless -- one byte is still a word as far
        // as the back-scan is concerned. This test used to pin that carry,
        // under the name `a_single_byte_word_carried_down_by_the_wrap_keeps_its_space`,
        // guarding against a fix that read `wrap`'s one-byte report as
        // "nothing carried" and glued `9x`. That failure mode no longer
        // applies -- `wrap()` no longer reports a byte count the caller must
        // interpret, only whether it consumed the trigger -- so there is
        // nothing left to guard against here beyond the fit rule itself.
        let mut g = one();
        g.channel_mut(chan()).width = 10;
        g.transmit(chan(), b"12345678 9 x");
        assert_eq!(
            String::from_utf8_lossy(&g.drain_output(chan())),
            "12345678 9\r\nx",
            "a one-byte word that fills the line exactly is not carried"
        );
    }

    #[test]
    fn the_longest_word_that_can_still_be_found_is_not_carried_either() {
        // The largest instance of this task's fix. A word `wrap()` can still
        // recover by back-scanning to a real delimiter is at most `width - 1`
        // bytes -- one byte more and it has no boundary to break on, and takes
        // the different, unaffected `word.len() >= width` path tested by
        // `a_word_longer_than_the_width_is_broken_rather_than_lost`. Here
        // `abcdefghi` is exactly `width - 1` (9 of 10) bytes, preceded by a
        // single leading space, so it fills the line to column 10 exactly and
        // is the longest word this rule ever applies to.
        //
        // Nothing moves: the leading space and `abcdefghi` both stay on line
        // one untouched, and the trigger space in front of `jk` is consumed,
        // not carried. Before this fix -- under the name
        // `the_longest_possible_carry_leaves_room_for_the_space_it_kept` --
        // `wrap()` carried `abcdefghi` down, stripped the now-dangling leading
        // space along with it, and needed a *second* wrap event (immediately,
        // on `j`, against the space it had just written back) to arrive at the
        // same two lines this fix now reaches directly: `\r\nabcdefghi\r\njk`.
        // That the two paths used to land on the same bytes is exactly the
        // coincidence `wrap()`'s doc comment warns about -- it did not hold at
        // `width = 79`, which is the whole reason this task exists.
        let mut g = one();
        g.channel_mut(chan()).width = 10;
        g.transmit(chan(), b" abcdefghi jk");
        assert_eq!(
            String::from_utf8_lossy(&g.drain_output(chan())),
            " abcdefghi\r\njk",
            "a width-1 word that fills the line exactly is not carried, and its \
             leading space is undisturbed"
        );
    }

    #[test]
    fn two_wraps_in_one_call_need_not_be_the_same_kind() {
        // One `transmit` can wrap many times, and `column` is not reset between
        // them -- so a fix that only got one of the two rules right would still
        // mishandle the rest of a paragraph. `this` fills the line to column 10
        // exactly and is not carried (this task's fix); `abcd` does not fit at
        // all and is carried, keeping the space that followed it (the earlier
        // carry fix, still exercised by `a_word_carried_down_by_the_wrap_is_not_glued_to_a_following_letter`
        // and `a_second_call_can_carry_a_word_it_began_itself`). A regression in
        // either rule changes this test.
        //
        // Before this fix -- under the name
        // `two_wraps_in_one_call_each_keep_their_own_separator`, with input
        // `"12345 this is here"` -- both of this call's wraps happened to be
        // the carry kind, since `wrap()` could not produce the other kind at
        // all. That input no longer wraps twice: `this` now fits and is not
        // carried, so `"this is here"` (13 bytes) fits on the second line
        // without ever reaching column 10 again.
        let mut g = one();
        g.channel_mut(chan()).width = 10;
        g.transmit(chan(), b"12345 this abcdefgh is");
        assert_eq!(
            String::from_utf8_lossy(&g.drain_output(chan())),
            "12345 this\r\nabcdefgh\r\nis",
            "the first wrap consumes its trigger space (exact fit), the second \
             carries and keeps it (genuine overflow)"
        );
    }

    #[test]
    fn the_space_a_wrap_restores_occupies_a_column_like_any_other() {
        // The space is *written*, not merely not-swallowed, so it takes a column
        // and the next break falls one byte earlier than it otherwise would.
        //
        // This is the one thing none of the tests above can see. A fix that
        // pushed the byte and forgot the `column += 1` -- an easy one to write,
        // since the path it replaces was a `continue` that skipped the
        // increment -- produces byte-identical output for every input where the
        // line wraps only once more, and was measured passing all seven of
        // them. Two wraps after the restored space is what exposes it: at the
        // second wrap the line reads `thisx is ok`, ten columns exactly, so `ok`
        // is carried and the break lands before it. Under-count the space and
        // the line is allowed an eleventh column and the break lands after it.
        //
        // `this` widened to `thisx` (and unchanged since, other than that one
        // letter): this task's fix makes a genuine four-letter carry ambiguous
        // with an exact-fit non-carry depending on exactly what precedes it,
        // and `this` here would fill line one to column 10 exactly and not be
        // carried at all -- see
        // `a_word_that_fills_the_line_exactly_is_not_carried_down`, which now
        // owns that case. `thisx` guarantees a genuine, five-byte-too-long
        // carry, keeping this test's actual subject -- the restored space's
        // column cost -- isolated from the fit rule.
        let mut g = one();
        g.channel_mut(chan()).width = 10;
        g.transmit(chan(), b"12345 thisx is ok now");
        assert_eq!(
            String::from_utf8_lossy(&g.drain_output(chan())),
            "12345\r\nthisx is\r\nok now",
            "the restored space is a column of the new line"
        );
    }

    #[test]
    fn a_second_call_can_carry_a_word_it_began_itself() {
        // The companion to the test below, and the correction to a tempting
        // over-generalisation: "`out` is fresh per call, so a cross-call wrap
        // can never carry" is FALSE. A fresh `out` only guarantees nothing to
        // carry when the wrap fires on a call's *first* byte. Here the second
        // call writes `s` before reaching the margin, so `wrap` finds a partial
        // word of its own making and carries it.
        //
        // The mid-word split at the boundary (`thi` | `s`) is the documented
        // `transmit` limitation -- GSBL was handed whole strings and this host
        // is handed whatever `prf` accumulated. The carry fix improves it
        // rather than causing it: before the fix this produced `sis`.
        let mut g = one();
        g.channel_mut(chan()).width = 10;
        g.transmit(chan(), b"12345 thi");
        g.transmit(chan(), b"s is");
        assert_eq!(
            String::from_utf8_lossy(&g.drain_output(chan())),
            "12345 thi\r\ns is",
            "a word begun in this call is carried like any other"
        );
    }

    #[test]
    fn a_wrap_at_the_start_of_a_second_call_still_consumes_its_space() {
        // `column` crosses a `transmit` boundary but `out` does not: the second
        // call's `wrap` looks back into an empty buffer, finds no partial word,
        // and carries nothing -- so R9 holds and the space becomes the break.
        // That is the right answer here and not merely a limitation: the first
        // call filled the line to the width exactly, so the space really is at
        // the margin.
        //
        // Pinned because it is the one wrap where nothing can be carried for a
        // reason other than the word's length, and the fix must not start
        // emitting a leading space on the new line.
        let mut g = one();
        g.channel_mut(chan()).width = 10;
        g.transmit(chan(), b"12345 this");
        g.transmit(chan(), b" is");
        assert_eq!(
            String::from_utf8_lossy(&g.drain_output(chan())),
            "12345 this\r\nis",
            "nothing to carry across the call boundary, so R9 still applies"
        );
    }

    #[test]
    fn a_carried_word_does_not_disturb_the_module_s_own_crlf() {
        // R1's `supplied_lf` is cleared before the width check, so a wrap that
        // now writes a space instead of swallowing one must not leave the CR/LF
        // bookkeeping in a state that doubles the module's own linefeed.
        //
        // `this` widened to `thisx`, as in the test above and for the same
        // reason: this test's subject is `supplied_lf`, not the fit rule, and
        // `this` here would fill line one to column 10 exactly and not be
        // carried at all.
        let mut g = one();
        g.channel_mut(chan()).width = 10;
        g.transmit(chan(), b"12345 thisx is\r\nx");
        assert_eq!(
            String::from_utf8_lossy(&g.drain_output(chan())),
            "12345\r\nthisx is\r\nx",
            "the module's explicit CRLF is still emitted exactly once"
        );
    }

    #[test]
    fn a_second_space_at_the_wrap_survives_as_an_indent_on_the_new_line() {
        // R9 consumes the space that *becomes* the break, and only that one. A
        // second space behind it is at column 0 of the new line, below the
        // width, and is written like any other byte. Unchanged by the fix --
        // pinned so that "the space is kept when a word was carried" is not
        // mistaken for "spaces at a wrap are kept".
        let mut g = one();
        g.channel_mut(chan()).width = 10;
        g.transmit(chan(), b"0123456789  x");
        assert_eq!(
            String::from_utf8_lossy(&g.drain_output(chan())),
            "0123456789\r\n x",
            "one space became the break; the other is ordinary output"
        );
    }

    #[test]
    fn two_spaces_at_an_exact_fit_boundary_both_disappear() {
        // A narrower edge case inside this task's fix: the byte that fills
        // the line to `width` can itself be a SPACE, not a letter -- `9`
        // fills `123456789` to column 9, then the *first* of the two spaces
        // fills column 10 exactly, legitimately, with no trigger (column was
        // 9, still under width, when it was pushed). The *second* space is
        // what triggers `wrap()`.
        //
        // Back-scan finds that first space immediately -- `found_delimiter`
        // is true, but the recovered word is empty, not "a word that already
        // fit". `wrap()`'s new rule only fires on a *non-empty* word for
        // exactly this reason: an empty word has nothing to "put back
        // untouched", and skipping the strip step some other path already
        // does correctly. Two lines of the paragraph in
        // `re/oracle/oracle_bank2.raw`'s Town Square description touch this
        // exact case (see the oracle test below).
        let mut g = one();
        g.channel_mut(chan()).width = 10;
        g.transmit(chan(), b"123456789  x");
        assert_eq!(
            String::from_utf8_lossy(&g.drain_output(chan())),
            "123456789\r\nx",
            "the space that already filled column 10, and the one that \
             triggered the wrap, both disappear -- neither is a real word"
        );
    }

    #[test]
    fn the_oracle_s_own_paragraph_wraps_at_its_own_six_line_lengths() {
        // The measurement this task exists to satisfy, read from the capture
        // rather than retyped: `re/oracle/oracle_bank2.raw`'s Town Square
        // description wraps at 79, 75, 77, 78, 72, 78 visible columns on the
        // genuine board (`btutsw(chan, 0x4f)`, see `wrap()`'s doc), with
        // `shift` ending line 1 and `stalls` opening line 2.
        //
        // The oracle's own six wrapped lines, rejoined with a single space
        // each, reconstruct the paragraph `WCCMMUD.DLL` actually handed
        // `btuxmt` -- word wrap works by turning a space into a carriage return (`btutsw`, guide page 172), so undoing a wrap is exactly
        // replacing its `\r\n` with the one SPACE it replaced, regardless of
        // whether that wrap consumed the SPACE outright (this task's fix) or
        // carried a word and stripped the SPACE ahead of it (the earlier
        // carry fix) -- either way exactly one SPACE from the original text
        // becomes each break. Feeding that reconstruction back through this
        // host's own `btutsw(chan, 79)` at `width = 79` must reproduce the
        // oracle's own six lines exactly: same words, same six lengths.
        //
        // Before this task's fix, this reconstruction wraps at 73, 74, 73,
        // 78, 74, 75 and spills an unwanted seventh line -- the measurement
        // `crates/mbbs/tests/wccmmud.rs`'s doc comment used to (wrongly)
        // claim agreed with the oracle.
        let raw = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../re/oracle/oracle_bank2.raw"
        ));
        let start_marker = b"\x1b[0;37;40m    As can be seen";
        let start = raw
            .windows(start_marker.len())
            .position(|w| w == start_marker)
            .expect("the Town Square description is in the oracle capture");
        let end_marker = b"a manhole can be seen\r\n";
        let end_at = raw[start..]
            .windows(end_marker.len())
            .position(|w| w == end_marker)
            .expect("the description ends at its sixth line");
        let end = start + end_at + end_marker.len();
        let chunk = &raw[start..end];

        let ansi_prefix = b"\x1b[0;37;40m";
        let mut lines: Vec<&[u8]> = chunk.split(|&b| b == b'\n').map(|l| {
            // `split(b'\n')` leaves each line's trailing `\r` on -- strip it
            // back off so `lines` holds exactly what a bare `\r\n` split
            // would, without pulling in an extra dependency for that split.
            l.strip_suffix(b"\r").unwrap_or(l)
        }).collect();
        assert_eq!(lines.pop(), Some(&b""[..]), "the chunk ends on its own \\r\\n");
        assert_eq!(lines.len(), 6, "the six lines the oracle measures: {lines:?}");
        lines[0] = lines[0]
            .strip_prefix(ansi_prefix)
            .expect("line 1 opens with the module's own colour code");

        let oracle_columns: Vec<usize> = lines.iter().map(|l| l.len()).collect();
        assert_eq!(
            oracle_columns,
            vec![79, 75, 77, 78, 72, 78],
            "the oracle's own measured visible columns, read from the capture \
             rather than retyped"
        );

        let unwrapped = lines.join(&b' ');

        let mut g = one();
        g.channel_mut(chan()).width = 79;
        g.transmit(chan(), &unwrapped);
        let output = g.drain_output(chan());
        let wrapped: Vec<&[u8]> = output.split(|&b| b == b'\n').map(|l| {
            l.strip_suffix(b"\r").unwrap_or(l)
        }).collect();

        let our_columns: Vec<usize> = wrapped.iter().map(|l| l.len()).collect();
        assert_eq!(
            our_columns,
            vec![79, 75, 77, 78, 72, 78],
            "this host's own wrap, run over the oracle's reconstructed \
             paragraph at the oracle's own width, must match the oracle's \
             six visible-column lengths exactly: {:?}",
            wrapped.iter().map(|l| String::from_utf8_lossy(l)).collect::<Vec<_>>()
        );
        assert_eq!(
            wrapped, lines,
            "same six lengths is not enough on its own -- the same words \
             must land on the same lines, `shift`/`stalls` included"
        );
    }

    #[test]
    fn an_explicit_return_resets_the_column() {
        let mut g = one();
        g.channel_mut(chan()).width = 10;
        g.transmit(chan(), b"ab\r\ncd ef");
        assert_eq!(g.drain_output(chan()), b"ab\r\ncd ef".to_vec());
    }

    #[test]
    fn binary_output_ignores_the_width_entirely() {
        // The guide, btuxmt page 189: none of these features apply to btuxct.
        let mut g = one();
        g.channel_mut(chan()).width = 4;
        g.transmit_raw(chan(), b"abcdefg");
        assert_eq!(g.drain_output(chan()), b"abcdefg".to_vec());
    }

    #[test]
    fn a_bare_cr_from_the_module_reaches_the_wire_as_crlf() {
        // R1, guide `btulfd` page 114: the default on channel init is that an
        // explicit LF is required after every CR, and WCCMMUD.DLL never
        // calls btulfd/btuhcr to change that default.
        let mut g = one();
        g.transmit(chan(), b"line\r");
        assert_eq!(g.drain_output(chan()), b"line\r\n".to_vec());
    }

    #[test]
    fn an_explicit_crlf_from_the_module_does_not_become_crlf_lf() {
        let mut g = one();
        g.transmit(chan(), b"line\r\n");
        assert_eq!(g.drain_output(chan()), b"line\r\n".to_vec());
    }

    #[test]
    fn an_explicit_crlf_split_across_two_transmit_calls_does_not_double_the_lf() {
        // MajorMUD flushes whatever `prf` happened to accumulate, so the CR
        // and its LF are not guaranteed to arrive in the same btuxmt() call.
        let mut g = one();
        g.transmit(chan(), b"line\r");
        g.transmit(chan(), b"\n");
        assert_eq!(g.drain_output(chan()), b"line\r\n".to_vec());
    }

    #[test]
    fn column_does_not_overflow_when_width_is_unset() {
        // R10: width stays 0 (the default), so wrap() is never called and
        // nothing resets column -- a plain `column += 1` would panic on
        // overflow (debug builds check this) long before finishing a call
        // this large. The call itself is bigger than OUTSIZ and rolls back
        // (R6), which is not what this test is about; it only cares that
        // accumulating column that far did not panic on the way there.
        let mut g = one();
        let long = vec![b'x'; 70_000];
        g.transmit(chan(), &long);
        assert_eq!(g.next_status(chan()), Some(Gsbl::OVRFLW));
    }

    // -- CSI (ESC `[` ... final byte 0x40-0x7E) is invisible to the column
    // count -----------------------------------------------------------------
    //
    // Measured against `re/oracle/oracle_bank2.raw` (search "make- shift"):
    // the Town Square description wraps at 79, 75, 77, 78, 72, 78 *visible*
    // columns against a `btutsw(chan, 0x4f)` (79) width, and 79 is the hard
    // ceiling across all 298 lines of that capture. Its first line is 97 raw
    // bytes but 79 visible -- `\x1b[79D` (5), `\x1b[K` (3) and `\x1b[0;37;40m`
    // (10), 18 bytes total, excluded from the count. Before this fix, this
    // host counted every one of those 18 bytes as a column and wrapped up to
    // 18 characters early.

    #[test]
    fn a_csi_sequence_does_not_advance_the_wrap_column() {
        let mut g = one();
        g.channel_mut(chan()).width = 5;
        g.transmit(chan(), b"\x1b[31mABCDE");
        assert_eq!(
            g.drain_output(chan()),
            b"\x1b[31mABCDE".to_vec(),
            "the 5-byte CSI is emitted but counts as zero columns, so the 5 \
             visible letters that follow fill the width exactly without \
             wrapping"
        );
    }

    #[test]
    fn a_csi_split_immediately_after_the_esc_is_still_not_counted() {
        let mut g = one();
        g.channel_mut(chan()).width = 5;
        g.transmit(chan(), b"\x1b");
        g.transmit(chan(), b"[31mABCDE");
        assert_eq!(g.drain_output(chan()), b"\x1b[31mABCDE".to_vec());
    }

    #[test]
    fn a_csi_split_immediately_after_the_bracket_is_still_not_counted() {
        let mut g = one();
        g.channel_mut(chan()).width = 5;
        g.transmit(chan(), b"\x1b[");
        g.transmit(chan(), b"31mABCDE");
        assert_eq!(g.drain_output(chan()), b"\x1b[31mABCDE".to_vec());
    }

    #[test]
    fn a_csi_split_mid_parameter_is_still_not_counted() {
        let mut g = one();
        g.channel_mut(chan()).width = 5;
        g.transmit(chan(), b"\x1b[3");
        g.transmit(chan(), b"1mABCDE");
        assert_eq!(g.drain_output(chan()), b"\x1b[31mABCDE".to_vec());
    }

    #[test]
    fn a_lone_esc_not_starting_a_csi_still_counts_toward_the_column() {
        // Only `ESC [` opens a CSI. WCCMMUD.DLL never emits a bare ESC --
        // every escape it writes is a complete CSI (see the IF-ANSI work in
        // `ifansi.rs`) -- so this is scope discipline, not a case this host
        // needs to render well: a stray ESC keeps exactly the pre-fix
        // behaviour of being just another opaque byte that costs a column.
        let mut g = one();
        g.channel_mut(chan()).width = 5;
        g.transmit(chan(), b"\x1bABCDE");
        assert_eq!(
            g.drain_output(chan()),
            b"\x1bABCD\r\nE".to_vec(),
            "ESC, A, B, C, D fill the five columns; E wraps"
        );
    }

    #[test]
    fn an_esc_with_no_follow_up_yet_is_held_pending_not_lost() {
        // The deferred half of the scanner: whether ESC counts -- and
        // whether it is even the start of a CSI -- is not decided until the
        // next byte is seen, so ESC is not committed to the wire until then
        // either. This mirrors `supplied_lf`, which already defers a
        // decision (whether an LF is the module's own or this host's
        // supplied one) across a call boundary.
        //
        // The window this opens is one byte wide and closes as soon as
        // another byte arrives, from this call or a later one. WCCMMUD.DLL
        // never ends a channel's output on a bare trailing ESC, so in
        // practice it always closes.
        let mut g = one();
        g.transmit(chan(), b"\x1b");
        assert!(
            g.drain_output(chan()).is_empty(),
            "held pending, not dropped, until the next byte resolves it"
        );
        g.transmit(chan(), b"A");
        assert_eq!(
            g.drain_output(chan()),
            b"\x1bA".to_vec(),
            "resolved as not a CSI: both bytes are now on the wire, in order"
        );
    }

    #[test]
    fn a_malformed_csi_aborts_on_a_control_byte_and_that_byte_gets_ordinary_treatment() {
        // A C0 control byte is never a CSI parameter, intermediate or final
        // byte (0x20-0x7E), so it cannot belong to the sequence. The house
        // rule, chosen because a real terminal's parser works the same way:
        // a byte that cannot continue the CSI aborts it and is then handled
        // exactly as if no escape were in progress -- so a stray CR mid-CSI
        // still moves the wire to the next line rather than being eaten or
        // hanging the scanner. Nothing already emitted as part of the
        // aborted prefix is revisited or uncounted-turned-counted; only the
        // aborting byte, and everything after it, gets ordinary treatment.
        let mut g = one();
        g.transmit(chan(), b"\x1b[3\rX");
        assert_eq!(g.drain_output(chan()), b"\x1b[3\r\nX".to_vec());
    }

    #[test]
    fn an_unterminated_csi_holds_state_across_calls_without_losing_bytes() {
        // No final byte (0x40-0x7E) ever arrives in this call. Every byte is
        // still emitted -- nothing is buffered and held back to be lost --
        // and none of them advance the column, since every one of them is a
        // valid CSI parameter byte (0x30-0x3F) and the scanner has no reason
        // to abort. This cannot hang: the loop is bounded by `bytes.len()`
        // regardless of what state it ends in.
        let mut g = one();
        g.channel_mut(chan()).width = 5;
        g.transmit(chan(), b"\x1b[123456789");
        assert_eq!(
            g.drain_output(chan()),
            b"\x1b[123456789".to_vec(),
            "an escape that never closes still puts every byte on the wire, \
             and cannot trigger a wrap since none of it counts"
        );

        // The final byte can arrive in a later call and still closes the
        // sequence correctly.
        g.transmit(chan(), b"m");
        assert_eq!(g.drain_output(chan()), b"m".to_vec());

        // Ordinary bytes after the close count again.
        g.transmit(chan(), b"AB");
        assert_eq!(g.drain_output(chan()), b"AB".to_vec());
    }

    #[test]
    fn an_overflowing_call_does_not_commit_a_half_open_csi_either() {
        // R6's atomicity is per commit, not per byte: a call rejected for
        // overflow must leave the channel exactly as if it had never been
        // made, including where the CSI scanner was. Committing the scan
        // state anyway would leave a channel that thinks it is still inside
        // a CSI begun by bytes that never reached the wire.
        //
        // A width and five more letters, not just `m` alone: the rejected
        // call's own bytes happen to resolve its *local* scan state back to
        // `Text` before it overflows (a run of `x`s closes the CSI the
        // moment the first one lands as a final byte), so a mutant that
        // commits scan state on the overflow path anyway produces the exact
        // same bytes for `m` alone as the correct code -- the same blind
        // spot the two `resume_being_counted` tests above exist for. Five
        // letters after `m` force the same wrap-or-not distinction: they
        // only fit without wrapping if `m` closed the *first* call's CSI
        // uncounted, not if the rejected call's `Text` state leaked through
        // and made `m` an ordinary, counted byte.
        let mut g = one();
        g.channel_mut(chan()).width = 5;
        g.transmit(chan(), b"\x1b[3");
        let huge = vec![b'x'; OUTSIZ + 1];
        g.transmit(chan(), &huge);
        assert_eq!(g.next_status(chan()), Some(Gsbl::OVRFLW));
        g.transmit(chan(), b"mABCDE");
        assert_eq!(g.drain_output(chan()), b"\x1b[3mABCDE".to_vec());
    }

    #[test]
    fn the_oracle_s_town_square_line_fits_at_width_79_once_the_csi_prefix_is_excluded() {
        let mut g = one();
        g.channel_mut(chan()).width = 79;
        let line = b"\x1b[79D\x1b[K\x1b[0;37;40m    The market is crowded this morning and every stall along the square is busy";
        assert_eq!(line.len(), 97, "the oracle's own raw byte count for this line");
        g.transmit(chan(), line);
        assert_eq!(
            g.drain_output(chan()),
            line.to_vec(),
            "97 raw bytes, 79 of them visible, and no wrap triggered within \
             them -- matching the oracle, where this line runs the full 79 \
             columns before the break"
        );
    }

    // -- Column-resumption: every test above shares a blind spot ------------
    //
    // Every CSI test that asserts exact bytes with no wrap in reach proves
    // *at most* that the scanner did not overcount -- undercounting (a
    // scanner stuck believing it is still inside a CSI after it closed or
    // aborted) is silent under that shape, because a missed wrap looks
    // exactly like a correctly-suppressed one until something forces the
    // column past the width. These two force it.

    #[test]
    fn after_a_well_formed_csi_closes_ordinary_bytes_resume_being_counted() {
        // Complements `a_csi_sequence_does_not_advance_the_wrap_column`,
        // which cannot tell "the CSI cost zero columns" apart from "the
        // scanner never left `CsiScan::Csi`, so *nothing* after it costs a
        // column either" -- both produce the same unbroken output for five
        // letters at width 5. A sixth letter is the difference: it only
        // wraps if the five before it, and it, were actually counted after
        // the CSI's final byte returned the scanner to ordinary text.
        let mut g = one();
        g.channel_mut(chan()).width = 5;
        g.transmit(chan(), b"\x1b[31mABCDEF");
        assert_eq!(
            g.drain_output(chan()),
            b"\x1b[31mABCDE\r\nF".to_vec(),
            "five columns fill the width exactly; the sixth wraps"
        );
    }

    #[test]
    fn after_an_aborted_csi_ordinary_bytes_resume_being_counted() {
        // Same blind spot, for the abort path this time:
        // `a_malformed_csi_aborts_on_a_control_byte...` and
        // `an_unterminated_csi_holds_state_across_calls_without_losing_bytes`
        // both only check short follow-ups, whose bytes are identical
        // whether the scanner correctly returned to `CsiScan::Text` or stayed
        // stuck in `Csi`. Six ordinary bytes after the abort force the same
        // wrap-or-not distinction as the test above.
        let mut g = one();
        g.channel_mut(chan()).width = 5;
        g.transmit(chan(), b"\x1b[3\rABCDEF");
        assert_eq!(
            g.drain_output(chan()),
            b"\x1b[3\r\nABCDE\r\nF".to_vec(),
            "the CR resets the column to zero, and the wrap still lands \
             exactly where five *counted* columns put it"
        );
    }

    // -- CSI grammar boundaries -----------------------------------------------
    //
    // 0x20/0x3F bound the parameter/intermediate class and 0x40/0x7E bound
    // the final-byte class. An off-by-one on any of the four routes that one
    // byte through the wrong arm -- which, for a single ordinary byte
    // following it, produces identical output either way (see the blind
    // spot above). `width = 1` closes that gap cheaply: at width 1, *any*
    // byte this scanner miscounts sets `column` to something `>= width`,
    // and the very next byte -- an ordinary letter that would otherwise
    // sail through untouched -- wraps because of it.

    #[test]
    fn the_final_byte_boundary_0x40_costs_no_column() {
        let mut g = one();
        g.channel_mut(chan()).width = 1;
        g.transmit(chan(), b"\x1b[@X");
        assert_eq!(g.drain_output(chan()), b"\x1b[@X".to_vec());
    }

    #[test]
    fn the_final_byte_boundary_0x7e_costs_no_column() {
        let mut g = one();
        g.channel_mut(chan()).width = 1;
        g.transmit(chan(), b"\x1b[~X");
        assert_eq!(g.drain_output(chan()), b"\x1b[~X".to_vec());
    }

    #[test]
    fn the_parameter_byte_boundary_0x20_costs_no_column() {
        let mut g = one();
        g.channel_mut(chan()).width = 1;
        g.transmit(chan(), b"\x1b[ mX");
        assert_eq!(g.drain_output(chan()), b"\x1b[ mX".to_vec());
    }

    #[test]
    fn the_parameter_byte_boundary_0x3f_costs_no_column() {
        let mut g = one();
        g.channel_mut(chan()).width = 1;
        g.transmit(chan(), b"\x1b[?mX");
        assert_eq!(g.drain_output(chan()), b"\x1b[?mX".to_vec());
    }

    #[test]
    fn an_oversized_ascii_write_emits_nothing_and_queues_overflow() {
        // R6, guide btuxmt CAUTIONS page 191: btuxmt returns 0, queues status 253 for btusts, and outputs none of the string. Not truncated to what room remains -- nothing at all.
        let mut g = one();
        let huge = vec![b'x'; OUTSIZ + 1];
        g.transmit(chan(), &huge);
        assert!(g.drain_output(chan()).is_empty());
        assert_eq!(g.next_status(chan()), Some(Gsbl::OVRFLW));
    }

    #[test]
    fn an_oversized_binary_write_emits_nothing_and_queues_overflow_too() {
        // guide btuxct CAUTIONS page 182-183: the same rule for btuxct().
        let mut g = one();
        let huge = vec![b'x'; OUTSIZ + 1];
        g.transmit_raw(chan(), &huge);
        assert!(g.drain_output(chan()).is_empty());
        assert_eq!(g.next_status(chan()), Some(Gsbl::OVRFLW));
    }

    #[test]
    fn an_overflowing_write_does_not_disturb_what_was_already_buffered() {
        let mut g = one();
        g.transmit(chan(), b"still here");
        let huge = vec![b'x'; OUTSIZ + 1];
        g.transmit(chan(), &huge);
        assert_eq!(g.next_status(chan()), Some(Gsbl::OVRFLW));
        assert_eq!(g.drain_output(chan()), b"still here".to_vec());
    }

    #[test]
    fn draining_an_empty_buffer_raises_nothing_even_with_btuoes_on() {
        // Status 5 is "the output data buffer makes a transition from being
        // not empty to being empty". No transition, no status.
        let mut g = one();
        g.channel_mut(chan()).oes = true;
        assert!(g.drain_output(chan()).is_empty());
        assert_eq!(g.next_status(chan()), None);

        g.transmit(chan(), b"x");
        let _ = g.drain_output(chan());
        assert_eq!(g.next_status(chan()), Some(Gsbl::OUTMT));
    }

    /// `inject` no longer answers whether the channel existed, because it can
    /// no longer be asked about one that does not. The two host-side callers
    /// -- `begin_polling` and `Host::dopoll` -- discarded that answer, which is
    /// the loose thread this type was introduced to cut.
    #[test]
    fn a_status_can_be_injected_from_the_host_side() {
        let mut g = one();
        g.inject(chan(), Gsbl::POLSTS);
        assert_eq!(g.next_status(chan()), Some(Gsbl::POLSTS));
        assert_eq!(g.next_status(chan()), None, "one inject, one status");
    }

    #[test]
    fn two_busy_channels_are_served_alternately_rather_than_by_number() {
        // The guide, `btuscn`: subsequent calls resume at the channel after the last one reported, so no channel outranks another. First-fit passes every other test in this file and starves
        // channel 1 here, which is the whole reason this one exists.
        let terms = Terms::new(2);
        let mut gsbl = Gsbl::new(terms);
        let zero = terms.chan(0).expect("channel 0");
        let one = terms.chan(1).expect("channel 1");

        // Both channels permanently have work, which is the starvation case.
        for _ in 0..4 {
            gsbl.inject(zero, Gsbl::CRSTG);
            gsbl.inject(one, Gsbl::CRSTG);
        }

        let served: Vec<u16> = (0..4)
            .map(|_| {
                let chan = gsbl.scan().expect("a channel with a status");
                gsbl.next_status(chan).expect("the status scan just found");
                chan.number() as u16
            })
            .collect();
        assert_eq!(served, vec![0, 1, 0, 1], "equal priority, not first-fit");
    }

    #[test]
    fn the_rotation_wraps_and_skips_channels_with_nothing_queued() {
        let terms = Terms::new(3);
        let mut gsbl = Gsbl::new(terms);
        let zero = terms.chan(0).expect("channel 0");
        let two = terms.chan(2).expect("channel 2");

        gsbl.inject(zero, Gsbl::CRSTG);
        gsbl.inject(two, Gsbl::CRSTG);
        gsbl.inject(zero, Gsbl::CRSTG);

        assert_eq!(gsbl.scan().map(Chan::number), Some(0));
        gsbl.next_status(zero).expect("popped");
        // Channel 1 has nothing, so the scan passes over it rather than stalling.
        assert_eq!(gsbl.scan().map(Chan::number), Some(2));
        gsbl.next_status(two).expect("popped");
        // Past the end, so it wraps to nought.
        assert_eq!(gsbl.scan().map(Chan::number), Some(0));
        gsbl.next_status(zero).expect("popped");
        assert_eq!(gsbl.scan(), None, "every queue is empty");
    }

    #[test]
    fn a_channel_other_than_the_first_is_enough_to_be_pending() {
        // `pending` is the whole of `Host::cycle`'s idle test: answering "no"
        // while a channel still holds a status is how the host stops with work
        // queued. At one channel the only channel *is* channel 0, so an
        // implementation that looks no further is indistinguishable there --
        // and wrong the moment there are two. A `pending` reading only
        // `channels[0]` passed all 739 tests before this existed, because the
        // one test that touched it injected into channel 0 as well, and
        // nothing anywhere asserted `pending()` was ever false.
        let terms = Terms::new(3);
        let mut gsbl = Gsbl::new(terms);
        let two = terms.chan(2).expect("channel 2");

        assert!(!gsbl.pending(), "a fresh host has nothing to service");
        gsbl.inject(two, Gsbl::CRSTG);
        assert!(gsbl.pending(), "channel 2's status is work like any other");
        gsbl.next_status(two).expect("popped");
        assert!(!gsbl.pending(), "and it stops being work once taken");
    }

    #[test]
    fn the_cursor_resumes_after_the_channel_it_returned_not_where_it_started() {
        // Guide, `btuscn` page 144: subsequent calls resume at the channel after the last one reported -- following the channel that *required
        // service*, not following wherever this scan began looking. With an
        // idle channel between two busy ones, advancing from the old cursor
        // instead leaves it short by the size of the gap, and the channel past
        // the gap takes two turns a round.
        //
        // Every other rotation test here uses adjacent channels, where
        // `next + 1` and `index + 1` are the same number, or drains its queues
        // so the divergence never changes an answer. This one keeps both
        // channels busy across a gap, which is the only shape that tells them
        // apart.
        let terms = Terms::new(3);
        let mut gsbl = Gsbl::new(terms);
        let zero = terms.chan(0).expect("channel 0");
        let two = terms.chan(2).expect("channel 2");

        for _ in 0..6 {
            gsbl.inject(zero, Gsbl::CRSTG);
            gsbl.inject(two, Gsbl::CRSTG);
        }

        let served: Vec<i16> = (0..6)
            .map(|_| {
                let chan = gsbl.scan().expect("a channel with a status");
                gsbl.next_status(chan).expect("the status scan just found");
                chan.number()
            })
            .collect();
        assert_eq!(served, vec![0, 2, 0, 2, 0, 2], "one turn each, per round");
    }

    #[test]
    fn asking_whether_anything_is_pending_does_not_advance_the_rotation() {
        // `Host::cycle` tests before `Host::poll` takes. If the test advanced
        // the cursor, every other channel would be skipped -- a starvation bug
        // introduced by the fix for a starvation bug.
        let terms = Terms::new(2);
        let mut gsbl = Gsbl::new(terms);
        let zero = terms.chan(0).expect("channel 0");
        let one = terms.chan(1).expect("channel 1");
        gsbl.inject(zero, Gsbl::CRSTG);
        gsbl.inject(one, Gsbl::CRSTG);

        assert!(gsbl.pending());
        assert!(gsbl.pending());
        assert!(gsbl.pending());
        assert_eq!(
            gsbl.scan().map(Chan::number),
            Some(0),
            "three tests did not consume channel 0's turn"
        );
    }

    /// Two channels, because a query that reads only channel zero passes every
    /// test written with one. `peek`'s own doc records that exact mutation
    /// surviving 739 tests.
    #[test]
    fn polling_armed_answers_per_channel() {
        let terms = Terms::new(2);
        let zero = terms.chan(0).expect("channel 0");
        let one = terms.chan(1).expect("channel 1");
        let mut g = Gsbl::new(terms);

        assert!(!g.polling_armed(zero));
        assert!(!g.polling_armed(one));

        g.inject(one, Gsbl::POLSTS);
        assert!(!g.polling_armed(zero), "channel 0 was not armed");
        assert!(g.polling_armed(one), "channel 1 was");

        // A status that is not POLSTS is not an arming.
        g.inject(zero, Gsbl::CRSTG);
        assert!(!g.polling_armed(zero), "a waiting line is not a waiting poll");

        assert_eq!(g.next_status(one), Some(Gsbl::POLSTS));
        assert!(!g.polling_armed(one), "taken, so no longer armed");

        // A POLSTS behind another status is still an arming. This is the
        // ordinary case in the Realm, not a corner: a channel whose player
        // typed a line holds CRSTG ahead of its poll, and `refill_polls` runs
        // on every driver wake. A front-only reading would answer `false`
        // here, inject a second POLSTS, and grow the queue by one per wake --
        // which is the whole leak this query exists to prevent.
        g.inject(zero, Gsbl::POLSTS);
        assert!(
            g.polling_armed(zero),
            "CRSTG is queued ahead of it, and it is armed all the same"
        );
    }

    /// `MAJORBBS.H:236`. The value matters because a module injects it by
    /// number through `btuinj`, and `fsdnfy()` (`FSDBBS.C:368`) is nothing but
    /// `btuinj(usrnum, CYCLE)`.
    #[test]
    fn cycle_is_the_number_the_module_injects() {
        assert_eq!(Gsbl::CYCLE, 240);
    }

    /// While `raw` is set, nothing is cooked: no line is assembled, no `CRSTG`
    /// is queued, no echo is produced, and `maxinl` does not apply. The bytes
    /// land in `input`, which is where `btuica` already looks for them.
    ///
    /// The byte sequence is chosen so that the *order* of the bypass is
    /// measured and not just its presence. `a b \r c \x08` -- the obvious
    /// sample -- passes through [`translate`] completely unchanged, so a
    /// bypass placed after the translate table instead of before it delivers
    /// exactly the same bytes and this test cannot see the difference. These
    /// four can:
    ///
    /// * `\x1b` is dropped by the table. It is also the first byte of every
    ///   arrow key, and the FSD's full-screen entry engine steers on arrow
    ///   keys -- losing ESC is losing the feature this flag exists for.
    /// * `\n` is dropped, so a client sending CR LF would deliver one byte.
    /// * `\x00` is dropped, so a telnet client's CR NUL would deliver one.
    /// * `\xff` is telnet IAC. The table strips the high bit, making it
    ///   `\x7f`, which the table then rewrites to a **backspace** -- a byte
    ///   that arrives as something else entirely rather than merely going
    ///   missing.
    #[test]
    fn raw_mode_delivers_bytes_uncooked() {
        let mut g = one();
        g.channel_mut(chan()).raw = true;
        g.channel_mut(chan()).maxinl = 2;

        g.push_input(chan(), b"a\x1b[Ab\r\n\x00\xffc\x08");

        let c = g.channel(chan());
        assert_eq!(
            c.input.iter().copied().collect::<Vec<u8>>(),
            b"a\x1b[Ab\r\n\x00\xffc\x08".to_vec(),
            "every byte arrives: ESC, LF, NUL, IAC, CR and backspace, \
             none dropped and none rewritten by the translate table"
        );
        assert!(c.line.is_empty(), "no line is assembled");
        assert!(c.ready.is_empty(), "no completed line is offered");
        assert!(c.output.is_empty(), "raw mode does not echo");
        assert!(
            !c.status.contains(&Gsbl::CRSTG),
            "a CR in raw mode is a byte, not a line terminator"
        );
    }

    /// A byte arriving in raw mode wakes the loop, because nothing else will.
    /// One `CYCLE` per delivery and not per byte: the handler drains `input`
    /// completely on the pass it runs, so a second status would dispatch into
    /// an empty buffer.
    #[test]
    fn raw_mode_queues_one_cycle_per_delivery() {
        let mut g = one();
        g.channel_mut(chan()).raw = true;

        g.push_input(chan(), b"abc");
        g.push_input(chan(), b"def");

        assert_eq!(
            g.channel(chan()).status.iter().filter(|&&s| s == Gsbl::CYCLE).count(),
            1,
            "six bytes over two deliveries is one wake-up, not six and not two"
        );
    }

    /// A locked channel accepts nothing, raw or not -- and is not woken for
    /// what it did not accept.
    ///
    /// Two assertions because they catch two different edits, and both edits
    /// used to be invisible:
    ///
    /// * `input` empty pins that the lockout step is **ahead** of the raw
    ///   bypass. Move the `raw` block above the `locked` check in
    ///   [`Channel::take`] -- inverting the order its own comment justifies --
    ///   and the bytes land here.
    /// * `status` empty pins that [`Gsbl::push_input`]'s wake-up asks whether
    ///   a byte landed and not whether one was offered. Go back to
    ///   `!bytes.is_empty()` and a `CYCLE` appears with nothing behind it.
    ///
    /// Neither is hypothetical. `fsdbkg` (`FSDBBS.C:186`) does
    /// `btulok(usrnum,1)` -- "Turn off keyboard till all displayed" -- for the
    /// whole of every full-screen paint, so a locked raw channel is the FSD's
    /// normal condition, not an edge of it. A host that woke the module anyway
    /// would enter `stsrou` once per socket read all the way through the paint,
    /// every time with an empty buffer.
    #[test]
    fn a_locked_raw_channel_accepts_nothing_and_is_not_woken() {
        let mut g = one();
        let c = g.channel_mut(chan());
        c.raw = true;
        c.locked = true;

        g.push_input(chan(), b"abc");

        let c = g.channel(chan());
        assert!(
            c.input.is_empty(),
            "input lockout is ahead of the raw bypass: a locked channel takes nothing"
        );
        assert!(
            c.status.is_empty(),
            "no byte landed, so there is nothing to wake the module for"
        );
    }

    /// Raw mode stops at `INPSIZ`, and a delivery that lands nothing there
    /// wakes nothing either.
    ///
    /// The buffer is filled in one delivery (which does wake the module once,
    /// because bytes did land), the status queue is emptied the way a dispatch
    /// would empty it, and then one more byte is offered to a full buffer. That
    /// second delivery is the case the old guard got wrong.
    ///
    /// A raw channel really can fill: nothing drains `input` until `stsrou`
    /// runs and calls `btuica`, and a paste or a key-repeat arrives in whatever
    /// size the socket hands over.
    #[test]
    fn raw_mode_stops_at_inpsiz_and_a_full_buffer_is_not_woken() {
        let mut g = one();
        g.channel_mut(chan()).raw = true;

        g.push_input(chan(), &vec![b'x'; INPSIZ + 16]);
        assert_eq!(
            g.channel(chan()).input.len(),
            INPSIZ,
            "the sixteen bytes past capacity are dropped, not stored"
        );
        assert_eq!(
            g.channel(chan()).status.iter().filter(|&&s| s == Gsbl::CYCLE).count(),
            1,
            "bytes did land, so one wake-up is owed"
        );

        // What a dispatch would have done to the FIFO, without running one.
        g.channel_mut(chan()).status.clear();
        g.push_input(chan(), b"y");

        let c = g.channel(chan());
        assert_eq!(c.input.len(), INPSIZ, "a full buffer stays full");
        assert!(
            c.status.is_empty(),
            "the byte was dropped, so the module has nothing to be woken for"
        );
    }

    /// `raw` is handled ahead of the byte-count trigger.
    ///
    /// The third of the three orderings [`Channel::take`]'s comment claims and
    /// nothing measured. `a_locked_raw_channel_accepts_nothing_and_is_not_woken`
    /// pins `locked` before `raw`; this pins `raw` before `trigger`.
    ///
    /// Both flags set is a state the host does not produce -- `raw` is the
    /// host's, `trigger` is the module's `btutrg` -- and the point of the test
    /// is that the code has an answer for it anyway, in one specific direction.
    /// Move the `raw` block after the `trigger` branch and this goes red twice
    /// over: on the `debug_assert!` in that branch, and (in a release build,
    /// where the assert is compiled out) on `INBLK`.
    #[test]
    fn raw_mode_wins_over_the_byte_count_trigger() {
        let mut g = one();
        let c = g.channel_mut(chan());
        c.raw = true;
        c.trigger = 2;

        g.push_input(chan(), b"abcd");

        let c = g.channel(chan());
        assert_eq!(
            c.input.iter().copied().collect::<Vec<u8>>(),
            b"abcd".to_vec(),
            "the bytes land either way -- it is everything else that differs"
        );
        assert!(
            !c.status.contains(&Gsbl::INBLK),
            "the trigger branch never ran, so no block status was raised"
        );
        assert_eq!(c.since_trigger, 0, "and nothing was counted toward the next one");
        assert_eq!(
            c.status.iter().copied().collect::<Vec<i16>>(),
            vec![Gsbl::CYCLE],
            "raw mode's own wake-up is the only status the delivery produced"
        );
    }

    /// Clearing `raw` puts line assembly back, and **keeps** what raw mode
    /// collected that nobody drained.
    ///
    /// The keep is a decision, and `fsdcof` (`FSDBBS.C:104`) is what decides
    /// it. `fsdcof` uninstalls the handler, restores echo, the LF and soft-CR
    /// characters, the transmit rules and the width -- and does not touch the
    /// input buffer. The FSD's one `btucli` is in `fsdcon` (`FSDBBS.C:91`), on
    /// the way *in*, so type-ahead left at the previous prompt is not read as
    /// the form's first keystrokes. Draining on the way out would be this host
    /// calling a `btucli` the original does not, at a moment the original does
    /// not have one.
    ///
    /// The original never has bytes to strand, because its handler consumed
    /// each one at interrupt level as it arrived; this host batches, so the
    /// leftovers are real and they are not free. `input` is not what line
    /// assembly reads -- that is `line`, which is why the `hi` below is
    /// unaffected -- but the strays are still counted by `btuibw` and still
    /// handed to the next `btuica`. That is asserted in
    /// `shims::gsbl::raw_bytes_are_what_btuica_takes_btuibw_counts_and_btucli_throws_away`,
    /// where those routines are reachable.
    ///
    /// Reachable in the real FSD: `goback()` (`FSDBBS.C:223`) calls `fsdcof()`
    /// and nothing else clears input. Stage 3 therefore owes the entry-side
    /// `btucli` that `fsdcon` specifies; it does not owe an exit-side one.
    #[test]
    fn leaving_raw_mode_restores_line_assembly_and_keeps_what_was_not_drained() {
        let mut g = one();
        g.channel_mut(chan()).raw = true;
        g.push_input(chan(), b"xy");
        g.channel_mut(chan()).raw = false;

        g.push_input(chan(), b"hi\r");

        assert_eq!(
            g.take_line(chan()),
            Some(b"hi".to_vec()),
            "line assembly is back, and the strays are not part of the line"
        );
        assert_eq!(
            g.channel(chan()).input.iter().copied().collect::<Vec<u8>>(),
            b"xy".to_vec(),
            "what raw mode collected and nobody drained is still there: \
             `fsdcof` clears no input, so neither does this"
        );
    }
}
