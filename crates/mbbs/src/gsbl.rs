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

use crate::chan::{Chan, Terms};

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
            raw: false,
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
    fn peek(&self) -> Option<u16> {
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
                let carried = Self::wrap(&mut out, &mut column, self.width);
                if byte == b' ' && carried == 0 {
                    // R9, guide `btutsw` page 172: word wrap works by turning a space into a carriage return -- the space
                    // *becomes* the break `wrap()` just inserted, so it is
                    // consumed here rather than carried onto the new line as
                    // a leading indent.
                    //
                    // Only when `wrap()` carried nothing, though. When it moved
                    // a partial word down, this space is not the break: it is
                    // the separator *after* the word that just moved, and
                    // consuming it glues that word to the next one. Measured
                    // against the real module as `thisis`, `andthese`,
                    // `Streetslead` -- one space lost per wrapped line of the
                    // first paragraph of world text this host ever drew.
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
    /// Returns **how many bytes it carried onto the new line**, which the
    /// caller needs in order to decide the fate of the byte that triggered the
    /// wrap: only a wrap that carried nothing may swallow a triggering SPACE
    /// (R9). A word at least `width` long has no boundary to break on, so it is
    /// pushed back and broken at the margin, carrying nothing -- which means
    /// the answer is always below `width`, and the SPACE a caller writes after
    /// a carried word therefore always fits on the new line without itself
    /// re-triggering the wrap.
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
    fn wrap(out: &mut Vec<u8>, column: &mut u16, width: u16) -> u16 {
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
        // The loop above counted the carried word into `*column` from zero, so
        // the new column *is* the carried length. Reported rather than left for
        // the caller to recompute: it cannot be re-derived from `out` once the
        // caller has pushed the triggering byte onto it.
        *column
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
        let mut g = one();
        g.channel_mut(chan()).width = 20;
        g.transmit(chan(), b"The blue form of the Engelmann Spruce ");
        g.transmit(chan(), b"is native to the mountains of western ");
        g.transmit(chan(), b"North America.");
        assert_eq!(
            String::from_utf8_lossy(&g.drain_output(chan())),
            "The blue form of\r\nthe Engelmann\r\nSpruce is native to\r\nthe mountains of\r\nwestern North\r\nAmerica.",
            "the guide's printed rendering, pages 174-175"
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
    fn a_word_carried_down_by_the_wrap_keeps_the_space_that_followed_it() {
        // The other half of R9, and the half that was wrong. When `wrap` carries
        // a partial word onto the new line, the space that triggered the wrap is
        // the separator *after* that word -- consuming it glues the next word
        // on. Measured against the real module: a MajorMUD room description came
        // out "thisis the centre of Silvermere."
        //
        // Asserted as a string rather than the byte vector the tests above use:
        // the whole difference is one 0x20, and a `[49, 50, ...]` diff does not
        // show it.
        let mut g = one();
        g.channel_mut(chan()).width = 10;
        g.transmit(chan(), b"12345 this is");
        assert_eq!(
            String::from_utf8_lossy(&g.drain_output(chan())),
            "12345\r\nthis is",
            "the carried word keeps its trailing separator"
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
    fn a_single_byte_word_carried_down_by_the_wrap_keeps_its_space() {
        // The smallest carry there is: one byte. `wrap` reports 1, and a fix
        // that reported the carry off by one would read that as nothing carried
        // and glue `9x`.
        let mut g = one();
        g.channel_mut(chan()).width = 10;
        g.transmit(chan(), b"12345678 9 x");
        assert_eq!(
            String::from_utf8_lossy(&g.drain_output(chan())),
            "12345678\r\n9 x",
            "a one-byte carry is still a carry"
        );
    }

    #[test]
    fn the_longest_possible_carry_leaves_room_for_the_space_it_kept() {
        // The largest carry there is. A carried word is at most `width - 1`
        // bytes -- a word `width` long or longer is pushed back and broken at
        // the margin, carrying nothing -- so the space this now keeps can always
        // be written without itself re-triggering the wrap. Here the carry is
        // exactly 9 of a width of 10: the space lands on the last column, and it
        // is the *next* byte that wraps, where `wrap` finds a line ending in a
        // space, carries nothing, and R9 applies again.
        //
        // The leading `\r\n` is not this fix: `wrap` strips the trailing spaces
        // of what is left after it lifts the word off, and here that is the
        // line's only other byte. It comes out identically without the fix.
        let mut g = one();
        g.channel_mut(chan()).width = 10;
        g.transmit(chan(), b" abcdefghi jk");
        assert_eq!(
            String::from_utf8_lossy(&g.drain_output(chan())),
            "\r\nabcdefghi\r\njk",
            "a width-1 carry plus its space fills the line exactly"
        );
    }

    #[test]
    fn two_wraps_in_one_call_each_keep_their_own_separator() {
        // One `transmit` can wrap many times, and `column` is not reset between
        // them -- so a fix that only got the first wrap right would still glue
        // the rest of a paragraph. This is the reduced form of what the real
        // module drew: three wraps, three lost spaces.
        let mut g = one();
        g.channel_mut(chan()).width = 10;
        g.transmit(chan(), b"12345 this is here");
        assert_eq!(
            String::from_utf8_lossy(&g.drain_output(chan())),
            "12345\r\nthis is\r\nhere",
            "two wraps, and neither eats a separator it did not create"
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
        // second wrap the line reads `this is ok`, ten columns exactly, so `ok`
        // is carried and the break lands before it. Under-count the space and
        // the line is allowed an eleventh column and the break lands after it.
        let mut g = one();
        g.channel_mut(chan()).width = 10;
        g.transmit(chan(), b"12345 this is ok now");
        assert_eq!(
            String::from_utf8_lossy(&g.drain_output(chan())),
            "12345\r\nthis is\r\nok now",
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
        let mut g = one();
        g.channel_mut(chan()).width = 10;
        g.transmit(chan(), b"12345 this is\r\nx");
        assert_eq!(
            String::from_utf8_lossy(&g.drain_output(chan())),
            "12345\r\nthis is\r\nx",
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

    /// Clearing `raw` puts the channel back exactly as it was.
    #[test]
    fn leaving_raw_mode_restores_line_assembly() {
        let mut g = one();
        g.channel_mut(chan()).raw = true;
        g.push_input(chan(), b"xy");
        g.channel_mut(chan()).raw = false;

        g.push_input(chan(), b"hi\r");

        assert_eq!(g.take_line(chan()), Some(b"hi".to_vec()));
    }
}
