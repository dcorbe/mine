//! The extension seam: where behaviour that is neither this host nor the
//! module gets to participate.
//!
//! Deliberately Lua-agnostic. Everything here names host concepts -- a
//! channel, a line of input, a verdict -- so the dispatch contract can be
//! tested with a plain Rust fake, and so `mbbs` never grows a dependency on
//! whatever scripting layer sits above it.
//!
//! **This seam sees every line, not just in-game commands.** The call site
//! that reaches [`Extension::command`] (`crate::Host::poll_with_chan`,
//! guarded on `status == gsbl::Gsbl::CRSTG`) fires on *every* line a channel
//! sends at *every* point in its session -- login, name entry, password
//! entry, all of it -- because nothing here yet distinguishes "the module is
//! at a prompt" from "the module is in the game loop." A registered command
//! name is a word an extension can intercept anywhere a player can type,
//! not only where a sysop imagined a command running. This is a known,
//! deliberately deferred scope decision, not an oversight; see
//! `mbbs-lua`'s own crate doc for the fuller account and what it means for
//! a script author picking a command name.
//!
//! Where a new command's business logic should live -- a
//! `scripts/lib/<module>.lua` declared-bindings file, never here -- is also
//! written down, in `mbbs-lua`'s own crate doc, not repeated here. This
//! module carries no module-specific knowledge of its own: no export name,
//! no record offset, no command recipe. [`CommandCtx`] is the marshaller's
//! engine (`call_export`/`call_entry`, `read_at`/`write_at`,
//! `write_scratch`), generic over `A: Abi` and otherwise inert -- a record
//! layout that differs by ABI (this repo has direct precedent: `struct
//! fsdfld` is 23 bytes in the 16-bit build and 36 bytes in the 32-bit build
//! of the same product, `crate::fsd`/`abi.rs`'s `FsdField`) is exactly the
//! kind of fact that belongs in a lib file's own `REC` table, gated on
//! `mmud.abi`, not hard-coded in this generic-over-`Abi` Rust module.

use std::io;

use mbbs_machine::ptr::ModulePtr;

use crate::Chan;
use crate::abi::{Abi, Arg, ModuleMem};

/// The most bytes [`CommandCtx::write_scratch`] will ever place. A `str`-typed
/// declared-binding argument plus a `c:buffer` cell together, this seam's
/// only callers today, need an item search name plus a trailing NUL plus a
/// 2-byte OUT match count; 128 bytes is generous headroom over any real
/// `WCCITEMS.VIR` item name. See `write_scratch`'s own doc comment for why
/// this is a fixed, reused buffer rather than an unbounded allocation per
/// call.
const COMMAND_SCRATCH_BYTES: usize = 128;

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
        self.call_entry(entry, args)
    }

    /// [`CommandCtx::call_export`]'s sibling for a caller that already has
    /// `entry` in hand -- a declared-bindings namespace (`mmud-lua`'s Task
    /// 2), which resolves each declared name to an [`Abi::Ptr`] once, at
    /// declare time (see that crate's own module doc for why: the four-
    /// spelling probe and the "hard error if this build has no such export"
    /// rule both belong at declare time, not at every call), and must not
    /// pay `A::export_address`'s lookup again on every invocation.
    /// `call_export` is now this plus the resolve step, not a separate
    /// implementation -- so the two can never drift on what "calling an
    /// export" means.
    ///
    /// # Errors
    ///
    /// As [`crate::Host::run`]'s own `# Errors`, and its `# A faulting
    /// export ends the board` note applies here identically -- `entry` is
    /// trusted to be a real, resolvable address; nothing here re-validates
    /// it.
    pub fn call_entry(&mut self, entry: A::Ptr, args: &[Arg<A>]) -> io::Result<crate::Outcome<A>> {
        self.host.run(self.machine, self.module, entry, args, Some(self.chan))
    }

    /// Give the module `bytes`, written into this seam's own persistent
    /// scratch buffer ([`crate::Host::command_scratch`]), and return a
    /// pointer to it -- for a handler that needs to pass
    /// [`CommandCtx::call_export`] something the module has to be able to
    /// read, such as a search string.
    ///
    /// One buffer for the seam's whole lifetime, not one allocation per
    /// call: [`crate::abi::ModuleMem::alloc_region`]'s `Wg16` backing is
    /// `Machine::alloc_segment`, a real LDT descriptor -- a finite, shared
    /// resource [`crate::heap::Heap::reserve`] also draws from to grow the
    /// module's own heap. A command a player can retype as often as they
    /// like must not cost the board one of those every time it runs; this
    /// reuses the same region on every call instead, allocated once on
    /// first use, the same pattern [`crate::Host::fsd_scratch`] and
    /// [`crate::Host::cnc_statics`] already establish for exactly this
    /// reason. See those two fields' own doc comments for why reuse, not a
    /// matching free, is the right shape here -- `ModuleMem` offers no free
    /// at all, and none is needed once nothing allocates more than once.
    ///
    /// # Errors
    ///
    /// If `bytes` is longer than [`COMMAND_SCRATCH_BYTES`] -- refused
    /// outright rather than silently truncated or served by a fresh,
    /// unbounded allocation, since either of those would either corrupt
    /// what the module reads or reopen the exhaustion this buffer exists to
    /// close.
    ///
    /// Otherwise, if there is no room to allocate the buffer at all (the
    /// first call only), or the write itself runs off it.
    pub fn write_scratch(&mut self, bytes: &[u8]) -> io::Result<A::Ptr> {
        if bytes.len() > COMMAND_SCRATCH_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "write_scratch: {} bytes does not fit the {COMMAND_SCRATCH_BYTES}-byte \
                     command scratch buffer",
                    bytes.len()
                ),
            ));
        }
        let ptr = match self.host.command_scratch {
            Some(ptr) => ptr,
            None => {
                let ptr = A::mem(self.machine)
                    .alloc_region(COMMAND_SCRATCH_BYTES)
                    .map_err(|e| io::Error::other(format!("write_scratch: {e}")))?;
                self.host.command_scratch = Some(ptr);
                ptr
            }
        };
        ptr.write(A::mem(self.machine), bytes)
            .map_err(|e| io::Error::other(format!("write_scratch: {e}")))?;
        Ok(ptr)
    }

    /// Read `len` bytes out of module memory at `ptr`.
    ///
    /// Generic over `ptr`'s origin -- unlike [`CommandCtx::write_scratch`],
    /// which always writes through this seam's own persistent buffer, this
    /// resolves *any* pointer, module-owned or seam-owned alike: the read
    /// half of `write_scratch` for an OUT parameter a call just wrote
    /// through (a match count, say), and equally the way a declared
    /// binding's `p:u8/u16/u32` reads a field out of a struct pointer it
    /// resolved through `M.declare{...}`.
    ///
    /// # Errors
    ///
    /// If `ptr`, or `ptr` plus `len`, resolves against no memory this
    /// module owns.
    pub fn read_at(&self, ptr: A::Ptr, len: usize) -> io::Result<Vec<u8>> {
        ptr.resolve(A::mem_ref(self.machine), len)
            .map(<[u8]>::to_vec)
            .map_err(|e| io::Error::other(format!("read_at: {e}")))
    }

    /// Write `bytes` into module memory at `ptr` -- [`CommandCtx::read_at`]'s
    /// write counterpart, and [`CommandCtx::write_scratch`]'s generic
    /// sibling: `write_scratch` always targets this seam's own persistent
    /// buffer, while this targets whatever pointer the caller already has in
    /// hand, such as a field inside a declared binding's own struct pointer.
    ///
    /// # Errors
    ///
    /// If `ptr`, or `ptr` plus `bytes.len()`, resolves against no memory
    /// this module owns.
    pub fn write_at(&mut self, ptr: A::Ptr, bytes: &[u8]) -> io::Result<()> {
        ptr.write(A::mem(self.machine), bytes).map_err(|e| io::Error::other(format!("write_at: {e}")))
    }
}

/// Something that participates in the host's events.
pub trait Extension<A: Abi> {
    /// A player typed a line. Answer `Handled` to swallow it.
    fn command(&mut self, ctx: &mut CommandCtx<'_, A>) -> Verdict;
}
