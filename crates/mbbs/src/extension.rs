//! The extension seam: where behaviour that is neither this host nor the
//! module gets to participate.
//!
//! Deliberately Lua-agnostic. Everything here names host concepts -- a
//! channel, a line of input, a verdict -- so the dispatch contract can be
//! tested with a plain Rust fake, and so `mbbs` never grows a dependency on
//! whatever scripting layer sits above it.

use std::io;

use mbbs_machine::ptr::ModulePtr;

use crate::Chan;
use crate::abi::{Abi, Arg, ModuleMem};

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
///
/// `machine` and `module` arrived in the same task as
/// [`CommandCtx::call_export`], not in the seam's first cut -- there was
/// nothing to borrow them *for* until a handler could call into the module
/// itself, and a borrow added before its feature exists is a borrow nobody
/// can point to a reason for. [`crate::Host::run`] needs both to place and
/// execute a call, so both live here now, alongside `host`.
pub struct CommandCtx<'a, A: Abi> {
    pub(crate) chan: Chan,
    pub(crate) line: String,
    pub(crate) host: &'a mut crate::Host<A>,
    pub(crate) machine: &'a mut A::Cpu,
    pub(crate) module: &'a A::Module,
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

    /// Call `name`, an export of the loaded module, servicing its imports
    /// until it stops -- a thin resolve-then-delegate to
    /// [`crate::Host::run`], the same service loop `Host::poll` itself
    /// calls into for every module entry point.
    ///
    /// # Errors
    ///
    /// If `name` names no export the module's own tables answer for. The
    /// message names the symbol, never a silent no-op -- a handler that
    /// mistypes an export finds out immediately, the same way a Rust
    /// caller of a function that does not exist finds out at compile time,
    /// rather than the line quietly doing nothing at run time.
    ///
    /// Otherwise, as [`crate::Host::run`]'s own `# Errors`.
    ///
    /// # A faulting export ends the board
    ///
    /// `Host::run` has no resume point for a terminal exit (see its own doc
    /// comment on `Exit::Stopped`): a module export that faults, overruns,
    /// or asks for something this host does not implement poisons the
    /// machine for good, and every later call on every channel sees the
    /// same poison. There is no catching that here -- `Outcome::Stopped`
    /// just names why.
    ///
    /// This is why the seam stops here rather than reaching further:
    /// observation hooks (milestone 2a) watch what the module already did,
    /// they do not get to *ask* it to do something and risk ending the
    /// board on its behalf. A command handler, which a sysop chose to
    /// install, is a different trust level than a hook every module call
    /// runs through.
    pub fn call_export(&mut self, name: &str, args: &[Arg<A>]) -> io::Result<crate::Outcome<A>> {
        let symbol = mbbs_machine::module::Symbol::Name(name.to_owned());
        let entry = A::export_address(self.module, &symbol)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no such export: {name:?}")))?;
        self.host.run(self.machine, self.module, entry, args, Some(self.chan))
    }

    /// Give the module a fresh block of memory holding `bytes`, and return a
    /// pointer to it -- for a handler that needs to pass
    /// [`CommandCtx::call_export`] something the module has to be able to
    /// read, such as a search string.
    ///
    /// One-shot, with no matching free: [`crate::abi::ModuleMem::alloc_region`]
    /// offers no way to give a region back, only to hand out more (see its
    /// own doc comment). A handler that calls this on every invocation
    /// grows the module's address space by one region per call for as long
    /// as the board runs -- acceptable for a command a player types
    /// occasionally, not for anything on a hot path.
    ///
    /// # Errors
    ///
    /// If there is no room left to place `bytes`, or the write itself runs
    /// off the region just allocated (which would mean `alloc_region`
    /// answered a region smaller than it was asked for).
    pub fn write_scratch(&mut self, bytes: &[u8]) -> io::Result<A::Ptr> {
        let ptr = A::mem(self.machine)
            .alloc_region(bytes.len())
            .map_err(|e| io::Error::other(format!("write_scratch: {e}")))?;
        ptr.write(A::mem(self.machine), bytes)
            .map_err(|e| io::Error::other(format!("write_scratch: {e}")))?;
        Ok(ptr)
    }

    /// Read `len` bytes back out of module memory at `ptr` -- the read half
    /// of [`CommandCtx::write_scratch`], for an OUT parameter a call just
    /// wrote through (a match count, say).
    ///
    /// # Errors
    ///
    /// If `ptr`, or `ptr` plus `len`, resolves against no memory this
    /// module owns.
    pub fn read_scratch(&self, ptr: A::Ptr, len: usize) -> io::Result<Vec<u8>> {
        ptr.resolve(A::mem_ref(self.machine), len)
            .map(<[u8]>::to_vec)
            .map_err(|e| io::Error::other(format!("read_scratch: {e}")))
    }
}

/// Something that participates in the host's events.
pub trait Extension<A: Abi> {
    /// A player typed a line. Answer `Handled` to swallow it.
    fn command(&mut self, ctx: &mut CommandCtx<'_, A>) -> Verdict;
}
