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
}

/// Something that participates in the host's events.
pub trait Extension<A: Abi> {
    /// A player typed a line. Answer `Handled` to swallow it.
    fn command(&mut self, ctx: &mut CommandCtx<'_, A>) -> Verdict;
}
