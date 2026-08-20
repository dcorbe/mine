//! The extension seam: where behaviour that is neither this host nor the
//! module gets to participate.
//!
//! Deliberately Lua-agnostic. Everything here names host concepts -- a
//! channel, a line of input, a verdict -- so the dispatch contract can be
//! tested with a plain Rust fake, and so `mbbs` never grows a dependency on
//! whatever scripting layer sits above it.

use crate::Chan;
use crate::abi::Abi;

/// What an extension decided about an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Carry on as though no extension existed.
    Pass,
    /// The extension dealt with it; the module must not see it.
    Handled,
}

/// What a `command` handler is given.
///
/// Borrows the host for the duration of the call rather than copying state
/// out, because a handler that wants to answer a question about the world
/// must be able to ask it now.
pub struct CommandCtx<'a, A: Abi> {
    pub(crate) chan: Chan,
    pub(crate) line: String,
    pub(crate) host: &'a mut crate::Host<A>,
}

impl<'a, A: Abi> CommandCtx<'a, A> {
    /// The channel that typed the line.
    pub fn chan(&self) -> Chan {
        self.chan
    }

    /// The line, exactly as the player typed it.
    pub fn line(&self) -> &str {
        &self.line
    }

    /// Send bytes to this channel.
    ///
    /// **CP437 bytes, not UTF-8.** This goes to the same `transmit` the
    /// module's own output uses, and translation happens in the socket task
    /// above it -- so a handler that wants a box-drawing character writes the
    /// CP437 code point, not the Unicode one.
    ///
    /// Bypasses `prfbuf` entirely: that buffer belongs to the module, and a
    /// handler writing into it would interleave with output the module has
    /// composed but not yet sent.
    pub fn print(&mut self, bytes: &[u8]) {
        self.host.gsbl_mut().transmit(self.chan, bytes);
    }

    /// Report something the module cannot be told. See [`crate::Host::notes`].
    ///
    /// Forwards to the host's own note channel rather than keeping a private
    /// list here, so a test (or an operator's log) reads a handler's reports
    /// the same way it reads every other note the host makes -- one channel,
    /// not two.
    pub fn note(&mut self, message: String) {
        self.host.note(message);
    }
}

/// Something that participates in the host's events.
pub trait Extension<A: Abi> {
    /// A player typed a line. Answer `Handled` to swallow it.
    fn command(&mut self, ctx: &mut CommandCtx<'_, A>) -> Verdict;
}
