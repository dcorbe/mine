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
    /// A completed line, waiting for `btuinp` to take it.
    pub(crate) ready: Option<Vec<u8>>,
    /// Bytes queued for the terminal.
    pub(crate) output: VecDeque<u8>,
    /// Statuses waiting for `btusts`, oldest first. The guide calls this a
    /// first-in-first-out structure and says so explicitly.
    pub(crate) status: VecDeque<i16>,

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
}

impl Default for Channel {
    fn default() -> Self {
        Self {
            input: VecDeque::new(),
            line: Vec::new(),
            ready: None,
            output: VecDeque::new(),
            status: VecDeque::new(),
            width: 0,
            maxinl: 0,
            echo: true,
            locked: false,
            trigger: 0,
            oes: false,
            xon: 0,
            xoff: 0,
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
