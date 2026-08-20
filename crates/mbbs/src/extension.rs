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

/// The most bytes [`CommandCtx::write_scratch`] will ever place. `mbbs-lua`'s
/// `summon`, this seam's only caller today, needs an item search name plus
/// a trailing NUL plus a 2-byte OUT match count; 128 bytes is generous
/// headroom over any real `WCCITEMS.VIR` item name. See `write_scratch`'s
/// own doc comment for why this is a fixed, reused buffer rather than an
/// unbounded allocation per call.
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
    /// through (a match count, say), and equally the way
    /// [`CommandCtx::player_record`]'s caller reads a coin field out of the
    /// player record itself.
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
    /// hand, such as a field inside [`CommandCtx::player_record`]'s record.
    ///
    /// # Errors
    ///
    /// If `ptr`, or `ptr` plus `bytes.len()`, resolves against no memory
    /// this module owns.
    pub fn write_at(&mut self, ptr: A::Ptr, bytes: &[u8]) -> io::Result<()> {
        ptr.write(A::mem(self.machine), bytes).map_err(|e| io::Error::other(format!("write_at: {e}")))
    }

    /// The calling channel's own player record: `_GET_PLAYER(usrnum)`,
    /// through [`CommandCtx::call_export`].
    ///
    /// Introduced here because two tasks need the same base pointer --
    /// `cash`'s coin-field arithmetic and a later task's own read of the
    /// same record -- and a pointer this fundamental should be derived once,
    /// not re-derived per caller.
    ///
    /// # `_GET_PLAYER` takes one argument, not two
    ///
    /// `re/exports/WCCMMUD_named.c:29982` declares it
    /// `_GET_PLAYER(int param_1)` -- one parameter -- and its body only ever
    /// reads `param_1`. Most call sites in the same file render as
    /// `_GET_PLAYER(param_1,0x1280)`, but several do not
    /// (`re/exports/WCCMMUD_named.c:1802,1839,2853,4483`, each a bare
    /// `_GET_PLAYER(param_1)`), against the same binary and the same
    /// definition -- a real second argument could not be optional call site
    /// to call site. `0x1280` is also identical at every two-argument call
    /// site regardless of context, which is not how a real per-call-site
    /// argument behaves. Both facts point the same way: `0x1280` is a
    /// decompiler artefact (most likely a data-segment value Ghidra
    /// misattributed as a pushed argument ahead of a far call), not a
    /// genuine parameter. This method calls it with one argument, `usrnum`.
    ///
    /// # Errors
    ///
    /// As [`CommandCtx::call_export`], if `_GET_PLAYER` is not an export the
    /// module's own tables answer for, or if the call stops the machine.
    ///
    /// If `_GET_PLAYER` answers with a null far pointer -- the player is not
    /// loaded on this channel -- that is an error naming the channel, never
    /// a silent no-op: a caller that went on to write through a null pointer
    /// would corrupt segment 0 of whatever the selector half happened to be.
    pub fn player_record(&mut self) -> io::Result<A::Ptr> {
        let usrnum = A::Int::from(self.chan.number() as u16);
        let outcome = self.call_export("_GET_PLAYER", &[Arg::Int(usrnum)])?;
        let (lo, hi) = match outcome {
            crate::Outcome::Returned { lo, hi } => (lo, hi),
            crate::Outcome::Stopped(poison) => {
                return Err(io::Error::other(format!("_GET_PLAYER stopped the machine: {poison}")));
            }
        };
        let mut bytes = (lo as u16).to_le_bytes().to_vec();
        bytes.extend_from_slice(&(hi as u16).to_le_bytes());
        let ptr = A::ptr_from_bytes(&bytes);
        if ptr == A::null_ptr() {
            return Err(io::Error::other(format!(
                "_GET_PLAYER({}) returned a null pointer -- no player loaded on this channel",
                self.chan
            )));
        }
        Ok(ptr)
    }

    /// Overwrite (not add to) the caller's own total experience.
    ///
    /// # No export sets experience -- the 591-entry table was searched
    ///
    /// The spec's tier-1 rule prefers a module accessor over an offset poke.
    /// One does not exist here: every export touching experience was
    /// checked (case-insensitively, for `EXP`/`XP`/`ADJUST`/`ADDON_`/`GAIN`/
    /// `AWARD`/`LEVEL`/`SET`; `GAIN` and `AWARD` have zero matches anywhere
    /// in the whole table). What exists instead:
    ///
    /// - `_ADD_EXPERIENCE` (ordinal 12), `_ADD_QUEST_EXP` (572),
    ///   `_DISTRIBUTE_EXPERIENCE` (383) -- all additive, taking a delta, not
    ///   a total.
    /// - `_CALC_EXP_NEEDED` (63), `_NEW_CALC_EXP_NEEDED` (564) -- pure
    ///   calculators, no side effect.
    /// - `_CMD_EXPERIENCE` (469) -- only displays.
    /// - `_RESTRUCTURE_EXPERIENCE` (565) -- writes the field, but takes only
    ///   a player pointer, no amount: a migration routine, not a setter.
    ///
    /// So writing by offset is the correct route here, not a shortcut
    /// around the rule -- it is what the rule's own escape hatch is for
    /// once the search comes up empty. Do not repeat this search; if a
    /// setter is ever added to the module, this comment is now wrong and
    /// should be replaced with a call to it.
    ///
    /// # Three fields, six words -- the module's own invariant, replicated
    ///
    /// The record stores experience in THREE places, not two:
    /// `0x3c`/`0x3e` (32-bit, low word first) is the raw total; `0x46f`/
    /// `0x471` is that same total **modulo 1,000,000,000**; `0x46b`/`0x46d`
    /// is the **count of billions** (the quotient). This is not this
    /// method's own invention -- it is exactly what
    /// `_RESTRUCTURE_EXPERIENCE` computes, in full
    /// (`re/exports/WCCMMUD_named.c:72415-72442`):
    ///
    ///
    /// An earlier version of this comment (and this method) read only the
    /// first three lines and concluded `_RESTRUCTURE_EXPERIENCE` performs a
    /// flat copy -- **that reading was wrong.** It performs a copy AND a
    /// reduction; the `while` loop is not incidental cleanup, it is the
    /// step that keeps `0x46f`/`0x471` a bounded remainder rather than an
    /// unbounded total, and it is what every other writer in the module
    /// (`_ADD_EXPERIENCE`'s own delta-processing loop,
    /// `re/exports/WCCMMUD_named.c:1378-1401`, subtracts the identical
    /// `0x3b9aca00` and increments the identical `0x46b`/`0x46d` counter)
    /// already agrees with. This method now replicates the full
    /// three-field invariant: `0x3c`/`0x3e` = `exp`, `0x46f`/`0x471` =
    /// `exp % 1_000_000_000`, `0x46b`/`0x46d` = `exp / 1_000_000_000`. No
    /// clamping, no rejecting large values -- `exp` is `u32` and every value
    /// it can hold is handled, the same way `_RESTRUCTURE_EXPERIENCE`
    /// itself handles every value already on a record it is given.
    ///
    /// **Neither `0x3c`/`0x3e` nor `0x46f`/`0x471`/`0x46b`/`0x46d` is
    /// authoritative alone.** `_RESTRUCTURE_EXPERIENCE` runs from five
    /// places -- `_LOAD_PLAYER` itself (`:318-320`, the load-bearing one:
    /// every character load runs it), `_SHOW_STATUS` (`:32438`),
    /// `_CMD_EXPERIENCE` (`:54425`), `_CMD_SYSOP` (`:63219`),
    /// `_GENERATE_TOP_LIST` (`:76200`) -- each guarded by a per-record flag
    /// (`base + 0x7b8` bit `0x20`) that is set once restructuring has run.
    /// On a record whose flag is still clear, writing only
    /// `0x46f`/`0x471`/`0x46b`/`0x46d` is silently reverted back to
    /// `0x3c`/`0x3e` (reduced afresh) the next time the character loads. On
    /// a record whose flag is already set -- the normal state of any
    /// actively played character, since `_LOAD_PLAYER` restructures
    /// unconditionally the first time -- writing only `0x3c`/`0x3e` does
    /// nothing live: **`_SHOW_STATUS` formats `0x46b`/`0x46d`/`0x46f`/
    /// `0x471` straight to the player's status screen with no
    /// re-normalisation when the flag is set** (`:32438-32455`), so a stale
    /// or under-written value there is visible on the player's very next
    /// `st`, not deferred to some later event. Writing all three fields
    /// unconditionally is correct in either flag state, which is why this
    /// never branches on the flag itself.
    ///
    /// A prior session's own live-board measurement
    /// (`majormud-character-record-layout` memory, verified twice against
    /// real characters) independently reaches part of the same requirement
    /// from the opposite direction: "`0x46f` -- the live value `st`
    /// displays... [p]atching only `0x03c` silently fails." That
    /// measurement predates this comment's correction and did not exercise
    /// a total past 1,000,000,000, so it does not by itself confirm the
    /// `0x46b`/`0x46d` billions field -- the decompile above is this
    /// method's authority for that field.
    ///
    /// # Persistence
    ///
    /// A raw offset write with no save leaves the change in memory only, so
    /// this ends with `_SAVE_PLAYER(usrnum)` -- the same export
    /// [`CommandCtx::player_record`]'s own caller (`cash`'s grant path,
    /// Task 7) already relies on for exactly this reason.
    ///
    /// # Errors
    ///
    /// As [`CommandCtx::player_record`], if the caller's own record cannot
    /// be resolved. As [`CommandCtx::write_at`], if any of the six writes
    /// runs off the resolved record (should never happen against a real
    /// 1998-byte record, but never silently skipped either way). As
    /// [`CommandCtx::call_export`]/[`CommandCtx::player_record`]'s own
    /// pattern, if `_SAVE_PLAYER` is not an export the module answers for,
    /// or stops the machine.
    pub fn set_experience(&mut self, exp: u32) -> io::Result<()> {
        /// `_RESTRUCTURE_EXPERIENCE`'s own reduction modulus
        /// (`0x3b9aca00`, `re/exports/WCCMMUD_named.c:72426-72439`) --
        /// named so the three field computations below read as "the same
        /// one number," not three independent literals that could drift
        /// apart under a later edit.
        const BILLION: u32 = 1_000_000_000;

        let record = self.player_record()?;
        let write_u32 = |ctx: &mut Self, delta: u16, value: u32| -> io::Result<()> {
            ctx.write_at(A::ptr_offset(record, delta), &(value as u16).to_le_bytes())?;
            ctx.write_at(A::ptr_offset(record, delta + 2), &((value >> 16) as u16).to_le_bytes())
        };

        write_u32(self, 0x3c, exp)?;
        write_u32(self, 0x46f, exp % BILLION)?;
        write_u32(self, 0x46b, exp / BILLION)?;

        let usrnum = A::Int::from(self.chan.number() as u16);
        match self.call_export("_SAVE_PLAYER", &[Arg::Int(usrnum)])? {
            crate::Outcome::Returned { .. } => Ok(()),
            crate::Outcome::Stopped(poison) => {
                Err(io::Error::other(format!("_SAVE_PLAYER stopped the machine: {poison}")))
            }
        }
    }
}

/// Something that participates in the host's events.
pub trait Extension<A: Abi> {
    /// A player typed a line. Answer `Handled` to swallow it.
    fn command(&mut self, ctx: &mut CommandCtx<'_, A>) -> Verdict;
}
