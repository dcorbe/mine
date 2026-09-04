//! Btrieve: opening a module's data files, and which one is current.
//!
//! Every Btrieve import `WCCMMUD.DLL` has, with call-site counts:
//!
//! ```text
//! rstbtv  176    absbtv   43    clsbtv   20    invbtv    4
//! setbtv  148    dinsbtv  36    opnbtv   18    cntrbtv   2
//! obtbtvl 112    gabbtvl  34    delbtv   15    omdbtv    1
//! stpbtvl  45    qrybtv   24    aabbtv    8
//!                dupdbtv  23    qnpbtv    7
//! ```
//!
//! Seventeen symbols over 716 sites, and all seventeen are here: opening and
//! choosing a file, reading records out of it, the two guards that answer
//! rather than write, `dinsbtv`/`dupdbtv`, which write, and `clsbtv`, which
//! flushes the index and gives four allocations back.
//!
//! **Initialisation uses six of the twelve, and reads exactly one record's
//! worth**, measured by `crates/mbbs/tests/wccmmud.rs` against the module
//! itself: `omdbtv` once, `opnbtv` fifteen times, then -- after the whole
//! configuration read -- `setbtv`, `cntrbtv` and a single `qlobtv(0)` on
//! `WCCUSERS.DAT`, which holds no characters and answers no. Everything else
//! below is exercised against MajorMUD's own files by
//! `crates/mbbs/tests/btrieve.rs` rather than by the module, because the module
//! does not get to it until a user is on a channel.
//!
//! The signatures are `BTVSTF.H:135-173`; the implementation they have to agree
//! with is Galacticomm's own `PLBTVSTF.C`, which is quoted rather than
//! paraphrased wherever it decided something.
//!
//! # `dinsbtv`, `dupdbtv` and `delbtv` write; `invbtv` still only says it
//! # would
//!
//! A module that saves a character now gets an honest insert or update --
//! [`dinsbtv`] calls [`Block::insert`](crate::btrieve::Block::insert) and
//! [`dupdbtv`] calls [`Block::update`](crate::btrieve::Block::update) -- and
//! one that deletes gets an honest delete, [`delbtv`] through
//! [`Block::delete`](crate::btrieve::Block::delete). `invbtv` does not write
//! yet, so a module that reaches it with a file current gets a refusal rather
//! than a host that appears to work and loses the data.
//!
//! `delbtv` was the last of the four to land, and it landed because a board
//! built fresh from its `.VIR` templates reaches it during login where a warm
//! one never did -- MajorMUD prunes `WCCACMSR.DAT` on the way in, and the
//! refusal stopped the module every time. Nothing about the refusal was
//! wrong; it had simply outlived its own stated reason ("nothing in this host
//! writes to a Btrieve file"), which stopped being true when `dinsbtv` and
//! `dupdbtv` landed.
//!
//! [`invbtv`] and [`delbtv`] are nonetheless *present*, because refusing is
//! only half of what the real host did. Both are guarded with
//! `if (bb == NULL) { return; }` -- `PLBTVSTF.C:584` and `:623` -- so with no
//! file current they wrote nothing and said nothing, and reproducing that is
//! not a lie. **Initialisation depends on it**: call 130 is an `invbtv` with a
//! null `bb`, and the real host discarded it too.
//!
//! *Why* `bb` is null there is a separate and still-open question. It is not
//! the missing `WCCVACN.DAT` -- staging that file in gives a sixteenth
//! `opnbtv` and the same null two calls later, measured in
//! `crates/mbbs/tests/wccmmud.rs` -- and it is not the ten-deep `setbtv` stack
//! overflowing either, because that surfaces in `rstbtv` and this is a
//! `setbtv` handed a null. Whichever module-side pointer is still zero, the
//! guard is the same guard and the insert is discarded either way.
//!
//! With a file current, `invbtv` refuses and names it, and `delbtv` deletes.
//! `dinsbtv` and `dupdbtv` have no guard at all -- `:603` and `:555` read
//! `bb->reclen` first, so the real host faulted with no file current rather
//! than answering. This host stops the module instead of faulting, which is
//! the same outcome honestly reached and a deliberately different shape from
//! `invbtv`/`delbtv`'s quiet no-op.
//!
//! # What every routine does when no file is current
//!
//! `PLBTVSTF.C` opens **eleven** of its routines with the same three lines --
//! `if (bb == NULL) { return 0; }` -- and a module written against that host is
//! entitled to ask a question with no file current and be told there is no
//! answer. Six of them are here, and all six answer rather than refuse:
//!
//! ```text
//! qrybtv  :262  0        gabbtvl :452  nothing (it is void)
//! qnpbtv  :287  0        aabbtvl :476  0
//! obtbtvl :357  0        absbtv  :426  0L
//! ```
//!
//! **Two do not, and for two different reasons.** `stpbtvl` (`:509`) has no
//! guard and dereferences `bb` twice before it checks anything, so the real
//! host faulted and there is nothing to reproduce. `cntrbtv` (`:681`) has no
//! guard because it never reads `bb` -- it asks the Btrieve TSR about whatever
//! file *it* is positioned on, and this host has no TSR to ask. Both refuse,
//! and each says which of the two it is.
//!
//! Four more guards belong to routines this host does not implement,
//! recorded here so the step that adds one does not derive them again:
//! `getbtvl` (`:318`, returns), `anpbtvlk` (`:406`, 0), `invbtv` (`:584`,
//! returns), `delbtv` (`:623`, returns). Note that `dupdbtv` and `dinsbtv`
//! have *no* guard and read `bb->reclen` immediately, which is the `stpbtvl`
//! shape again.
//!
//! [`upvbtv`] (`:534-536`, also a quiet return) used to be on this list; it is
//! implemented now, but not for `WCCMMUD.DLL` -- that module never imports
//! it, only `WCCMMPLS.DLL` (MajorMUD Plus) does, alongside [`clsbb`], which
//! has no `PLBTVSTF.C` guard to cite at all (see that routine's own doc
//! comment for why). Both stay in this file because this is where the
//! Btrieve engine and its `Cursor`/`duplicate_key` machinery already live,
//! not because either is part of the seventeen-symbol/716-site `WCCMMUD.DLL`
//! survey above.
//!
//! # This is where matching the original beats refusing
//!
//! Everywhere else in this crate, a host that cannot answer honestly stops the
//! module. `setbtv`'s stack is the exception, and deliberately: it is ten deep,
//! it *shifts*, and overflowing or underflowing it has a defined result that
//! modules were built against. See [`crate::btrieve::Btrieve::set`] and
//! [`restore`](crate::btrieve::Btrieve::restore) -- the original's answer there
//! is not a lie, it is a documented limit, and reproducing it is what keeps a
//! module that was working as designed working.
//!
//! # Generic (`fn foo<A: Abi>(...)`), as of this task
//!
//! Every routine below takes [`Call<A>`]/[`Host<A>`] rather than a raw
//! `&mut Machine`, and each keeps its C name for the generic core plus a
//! `_wg16`-suffixed sibling built from `shims::call(machine)`, the same
//! bridge convention every other generic-shaped file in this crate uses (see
//! `shims::mod`'s `call` doc comment) -- kept, not deleted, because
//! `crate::testing::Fixture::invoke` drives a real `mbbs_machine::m16::Machine` and so
//! can only ever run one ABI's routine, and every one of this file's own
//! tests still calls a `_wg16` bridge by name.
//!
//! This file stopped one commit short of generic for exactly as long as
//! [`Host<A>::btrieve`](crate::Host::btrieve) elided its own `A` --
//! `crates/mbbs/src/lib.rs` declared the field bare `btrieve::Btrieve`
//! rather than `btrieve::Btrieve<A>`, and a bare struct name in a *type*
//! position takes its default (`Wg16`) unconditionally, independent of the
//! `Host<A>` it sits inside. So `host.btrieve` was `Btrieve<Wg16>` inside
//! *any* `Host<A>`, and `call.ptr()`'s `A::Ptr` had no way to reach it --
//! not a limitation of the engine, which [`crate::btrieve::Btrieve`] and
//! [`crate::btrieve::Block`] had already made properly generic over `A`.
//! Once that one field grew its parameter, every routine below converted
//! the same way the rest of this crate's shim layer already had:
//!
//! - Arguments are read through [`Call::ptr`]/[`Call::int`]/[`Call::long`]
//!   instead of a word-indexed `arg_far`/`arg_u16`.
//! - Memory is reached through [`Call::mem`] (`&mut A::Mem`) and pointers
//!   resolve/write/read a C string through [`mbbs_machine::ptr::ModulePtr`]'s own
//!   methods (`ptr.resolve(mem, len)`, not `mem.resolve(ptr, len)` -- the
//!   inherent `Segments` methods this file called directly before are
//!   `Wg16`-only and do not exist on a generic `A::Mem`).
//! - `opnbtv`'s `btrieve.open`/`clsbtv`'s `btrieve.close` take `call.mem()`
//!   rather than the `call.cpu`/`&mut mbbs_machine::m16::Machine` this file used to
//!   reach them with -- `crate::btrieve::Btrieve::open`/`close` themselves
//!   now take `mem: &mut A::Mem`, not a whole machine.
//! - `Position`/`Request`, the two structs [`absolute`]/[`locate`] bundle
//!   their many parameters into, both grew an `A: Abi` parameter of their
//!   own -- every module-address field on either (`into`, `block`, `value`)
//!   is `A::Ptr`.
//! - Two width conversions, not one: [`i16_arg`] is the reinterpreting cast
//!   `call.int() as i16` used to be, for every argument `BTVSTF.H` declares
//!   plain `int` (`omdbtv`'s `mode`, `qrybtv`'s `keynum`/`qryopt`, `qnpbtv`'s
//!   `getopt`, `obtbtvl`'s `keynum`/`obtopt`/`loktyp`, `stpbtvl`'s
//!   `stpopt`/`loktyp`, `aabbtv`'s `keynum`, `gabbtvl`'s `keynum`/`loktyp`)
//!   -- `A::Int` is not a primitive `rustc` will cast, so the cast now goes
//!   through `u32` first (`Into<u32>`, then `as i16`), which is bit-for-bit
//!   the same reinterpretation `u16 as i16` already was on every value
//!   `Wg16` can produce. [`u16_arg`] is `opnbtv`'s `maxlen` alone: read with
//!   no cast at all before this file went generic (`Call<Wg16>::int()`
//!   already returned `u16`), and it becomes
//!   [`crate::btrieve::Btrieve::open`]'s own `maxlen: u16` -- a Btrieve wire
//!   width, not an ABI one -- so this refuses rather than truncates a value
//!   that does not fit, instead of reinterpreting one that always does.
//!
//! `crates/mbbs/tests/no_direct_farptr.rs`'s `ALLOWED` list no longer names
//! this file: every `FarPtr`/`Machine` mention left is inside
//! `#[cfg(test)] mod tests` or a `_wg16` bridge, which that test's own
//! scanner does not count.

// `FarPtr`/`Machine`/`Ret`/`Wg16` are now named only by this file's own
// `#[cfg(test)] mod tests` and its `_wg16` bridges -- production code
// reaches every routine here through the generic `Call<A>`/`Host<A>`
// instead, per this file's own module doc comment.
#[cfg(test)]
use crate::abi::Wg16;
#[cfg(test)]
use mbbs_machine::m16::{FarPtr, Ret};

use mbbs_machine::ptr::ModulePtr;

use crate::Host;
use crate::abi::{self, Abi, Call};
use crate::btrieve::AbiMem;
use crate::btrieve::{Btrieve, Cursor, Geometry, Step};
// Aliased: this file's own `Op` (below) is the BTVSTF.H opcode enum
// `qrybtv`'s family parses from a module-supplied number, a different type
// from the engine's -- they share variant names because both describe the
// same nine Btrieve "get key" operations, not because they are the same
// type.
use crate::btrieve::Op as EngineOp;
use crate::shims::ShimError;

/// Read the next argument as a 16-bit signed `int`, [`Abi`]-generic.
///
/// Every argument this file reads this way -- `omdbtv`'s `mode`, `qrybtv`'s
/// `keynum`/`qryopt`, `qnpbtv`'s `getopt`, `obtbtvl`'s `keynum`/`obtopt`/
/// `loktyp`, `stpbtvl`'s `stpopt`/`loktyp`, `aabbtv`'s `keynum`, `gabbtvl`'s
/// `keynum`/`loktyp` -- is declared plain `int` in `BTVSTF.H`, never
/// `unsigned`/`UINT`, so every one of these was already `as i16` before this
/// file went generic; this is that same reinterpreting cast, done once.
///
/// `A::Int` is `u16` for `Wg16` and `u32` for `Wg32` -- [`Abi::Int`]'s own
/// doc comment -- so a bare `as i16` stopped compiling the moment the read
/// went generic (`A::Int` is an associated type, not a primitive `rustc`
/// will cast). Going through `u32` first is not a width change: `Into<u32>`
/// zero-extends `Wg16`'s `u16`, and `as i16` then truncates to the low 16
/// bits and reinterprets them as signed -- bit-for-bit the same answer
/// `u16 as i16` gave before, for every value `Wg16` can produce. `Wg32`'s
/// `u32` truncates to the same low 16 bits before reinterpreting, which is
/// the only generic reading of "the low 16 bits of this argument, signed"
/// available without a wider `mode`/`keynum`/`loktyp` this wire protocol has
/// never had, on any `Abi` this crate has met so far.
pub(crate) fn i16_arg<A: Abi>(v: A::Int) -> i16 {
    let wide: u32 = v.into();
    wide as i16
}

/// Read the next argument as an unsigned 16-bit `int`, refusing rather than
/// truncating if it does not fit.
///
/// `opnbtv`'s `maxlen` is the one argument this file reads this way:
/// `BTVSTF.H` declares `BTVFILE *opnbtv(char *filnam, int maxlen)`, but
/// `PLBTVSTF.C:150` (`bb->reclen=maxlen`) and every comparison against it
/// treat it as unsigned throughout, and it flows straight into
/// [`crate::btrieve::Btrieve::open`]'s own `maxlen: u16` -- a Btrieve wire
/// width, not an ABI one: `RECLEN` is two bytes in a `struct btvblk`
/// regardless of which `Abi` opened the file. Before this file went
/// generic, `Call<Wg16>::int()` already returned `u16` and this argument was
/// used with no cast at all -- so this is that same unsigned read, done
/// generically. Unlike [`i16_arg`], a value that does not fit in 16 bits is
/// refused rather than reinterpreted: silently truncating a module's own
/// declared record length would size its record buffer wrong without
/// telling anyone.
///
/// # Errors
///
/// If the widened value does not fit in a `u16`.
pub(crate) fn u16_arg<A: Abi>(v: A::Int, who: &str) -> Result<u16, ShimError> {
    let wide: u32 = v.into();
    u16::try_from(wide)
        .map_err(|_| ShimError::Failed(format!("{who}: {wide}, which does not fit in 16 bits")))
}

/// Read the next argument as a `USHORT` the vendor *declared* -- sixteen
/// bits, masked, not range-checked.
///
/// # Why this is not [`u16_arg`], which it otherwise looks exactly like
///
/// The two families this file serves differ in their headers, and the
/// difference decides which reader is correct:
///
/// - `btv*` has no C prototype at all (`BTVSTF.H:23` is K&R:
///   `BTVFILE *opnbtv();`), and its *definition* is
///   `opnbtv(char *filnam, int maxlen)` (`PLBTVSTF.C:110-112`). `int` is
///   genuinely thirty-two bits under `Wg32`, so a value above 65535 is a
///   real out-of-range argument and [`u16_arg`] is right to refuse it.
/// - `dfa*` is fully prototyped and spells these parameters `USHORT`
///   (`DFAAPI.H:219, 309, 322, 352, 388`). The parameter is sixteen bits
///   wide, so the top half of a `Wg32` stack slot holding one is not the
///   caller's to promise -- the vendor's own prologue reads it with `movzx`
///   and cannot see it. There is no out-of-range value to reject, because
///   the upper half was never part of the value.
///
/// This is the same distinction `shims::memory`'s `ushort_arg` documents
/// (and the same defect: reading `alcblok`'s `USHORT qty` at full width
/// asked for 1.15 TB and stopped MajorMUD-NT's init). Here it is quieter
/// and would have been harder to find -- a valid `dfaOpen`/`dfaInsertV`
/// would be refused, intermittently and data-dependently, with an error
/// naming the module's own record length as the culprit.
pub(crate) fn ushort_arg<A: Abi>(v: A::Int) -> u16 {
    Into::<u32>::into(v) as u16
}

/// The five modes `BTVSTF.H:41-45` defines for `omdbtv`.
///
/// All five describe how Btrieve should treat *writes*, which is why nothing
/// here does anything with the mode yet beyond keeping it. What it is kept for
/// is the step that writes: opening a file read-only and then updating it is a
/// module bug the host will be able to name.
const MODES: [i16; 5] = [0, -1, -2, -3, -4];

/// `void omdbtv(int mode)` -- how the next `opnbtv` should open its file.
///
/// One call site in the whole module, and it is the first Btrieve call
/// initialisation makes -- before the fifteen opens it applies to.
///
/// A mode outside the five is refused. The real host stored whatever it was
/// given and passed it to Btrieve as an open flag; here it would be a number
/// kept and never used, which is the shape of a value that turns out to have
/// meant something.
pub fn omdbtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let mode = i16_arg::<A>(call.int());
    if !MODES.contains(&mode) {
        return Err(ShimError::Failed(format!(
            "omdbtv({mode}), which is none of the five modes BTVSTF.H defines"
        )));
    }
    host.btrieve.set_mode(mode);
    Ok(abi::Ret::Void)
}

/// `BTVFILE *opnbtv(char *filnam, int maxlen)` -- open a Btrieve file.
///
/// **Opening makes the file current**, exactly as `opnmsg` does, and that is
/// twice now: it should be the default assumption for any MajorBBS `opn*`
/// routine rather than something to be caught by a refusal a third time.
///
/// # It pushes itself, and that is not a typo
///
/// `PLBTVSTF.C:145`:
///
/// The allocation writes the global `bb` directly, so by the time `setbtv` runs
/// there is nothing left of what was current: `opnbtv` pushes the block it just
/// made and **discards the file that was current before it**. `opnmsg` saves
/// the previous block; this does not.
///
/// That is a difference with a consequence -- a module that opens a file and
/// then calls `rstbtv` gets the file it just opened back, and needs a second
/// `rstbtv` to reach what it had before -- so it is reproduced rather than
/// tidied up. `WCCMMUD.DLL` has 176 `rstbtv` sites balanced against a host that
/// behaved this way.
///
/// It also has a consequence for the ten-deep stack, and initialisation reaches
/// it: **fifteen opens in a row push fifteen entries**, so the first five files
/// have fallen off the bottom before the module has finished opening them. The
/// real host did that too, and a host that had refused on overflow instead
/// would have stopped MajorMUD at its eleventh data file.
pub fn opnbtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let filnam = call.ptr();
    let maxlen = u16_arg::<A>(call.int(), "opnbtv")?;
    let named = String::from_utf8_lossy(filnam.read_cstr(call.mem()).map_err(|e| ShimError::Failed(e.to_string()))?).into_owned();
    let name = Host::<A>::dos_name(&named).map_err(ShimError::Failed)?;

    let path = host.btrieve_file(&name).map_err(ShimError::Failed)?;
    let geometry = Geometry::read(&name, &path).map_err(|e| ShimError::Failed(e.to_string()))?;

    // `PLBTVSTF.C:150` -- `bb->reclen=maxlen`, the module's number and not the
    // file's. They are allowed to differ, and **the two directions are not the
    // same thing**, which is why they are reported differently.
    //
    // Opening for *more* than a **variable-length** file's logical record is
    // not a mismatch at all -- it is the only correct thing to do.
    // `WCCTEXT.DAT`'s logical record is 22 bytes and every one of its records
    // is 22 plus a 2,000-byte fragment; MajorMUD opens it for exactly 2,022.
    // `movmem(gpbptr,recptr,dbflen)` copies what Btrieve returned, and so does
    // [`deliver`], and what Btrieve returns is the reassembled record. So this
    // is reported as the arithmetic it is rather than as a divergence -- which
    // is what it was noted as while only the fixed part was read.
    //
    // Opening for *less* is where this host and the original part company.
    // Btrieve answered a read on a too-short buffer with status 22;
    // `posbtverr` (`:746`) declined to `catastro` because the status was 22,
    // wrote `gpbptr[bb->reclen-1]='\0'`, and only then let the copy run. This
    // host truncates and writes no terminator. No module has done it yet --
    // fifteen of MajorMUD's opens match exactly and the sixteenth is `WCCTEXT`
    // -- so the divergence is recorded rather than implemented, and this note
    // is what would say it had become live.
    if maxlen < geometry.reclen {
        host.note(format!(
            "{name} holds {}-byte records and the module opened it for only \
             {maxlen}, so a read is truncated -- where the real host would also \
             have terminated it at byte {}, per PLBTVSTF.C:750",
            geometry.reclen,
            maxlen.saturating_sub(1)
        ));
    } else if maxlen > geometry.reclen {
        host.note(match geometry.variable {
            true => format!(
                "{name} holds variable-length records of {} fixed bytes and a fragment \
                 chain, and the module opened it for {maxlen} -- room for {} bytes of \
                 body",
                geometry.reclen,
                maxlen - geometry.reclen
            ),
            false => format!(
                "{name} holds {}-byte records and the module opened it for {maxlen}",
                geometry.reclen
            ),
        });
    }

    let block = {
        let Host { btrieve, heap, .. } = host;
        btrieve
            .open(call.mem(), heap, &name, &path, geometry, maxlen)
            .map_err(|e| ShimError::Failed(format!("opnbtv({name}): {e}")))?
    };

    // `bb = the new block` and *then* `setbtv(bb)`, in that order, because that
    // is the order `PLBTVSTF.C:145` and `:167` do it in and the order is the
    // whole of the difference: it is what makes the open push itself.
    set_current(call, host, block)?;
    push(call, host, block)?;
    Ok(abi::Ret::Ptr(block))
}

/// `void setbtv(struct btvblk *bbptr)` -- work on this file until told
/// otherwise.
///
/// `bb` is written in module memory, not remembered here. What is remembered is
/// the stack behind it, which the real host also kept where the module could
/// not see it.
///
/// A null pointer is allowed, because [`rstbtv`] produces one and `PLBTVSTF.C`
/// checks for it everywhere. A pointer that is neither null nor a file this
/// host opened is refused: the real host would have handed it to Btrieve as a
/// position block and read 128 bytes of whatever it was.
pub fn setbtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let block = call.ptr();
    if block != Btrieve::<AbiMem<A>>::null() {
        host.btrieve.block(block).map_err(ShimError::Failed)?;
    }
    push(call, host, block)?;
    Ok(abi::Ret::Void)
}

/// `void rstbtv(void)` -- go back to the file that was current before.
///
/// Underflow is not an error here, which is the one place this crate follows
/// the original rather than refusing. See
/// [`Btrieve::restore`](crate::btrieve::Btrieve::restore) for why.
pub fn rstbtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let (restored, empty) = host.btrieve.restore();
    if empty {
        host.note(
            "rstbtv with nothing to restore, so the current Btrieve file is now \
             null -- which is what the real host does, and what every routine in \
             PLBTVSTF.C checks for"
                .to_owned(),
        );
    }
    set_current(call, host, restored)?;
    Ok(abi::Ret::Void)
}

/// `long cntrbtv(void)` -- how many records the current file holds.
///
/// The one Btrieve routine initialisation reads anything with, and what it
/// reads is a field of the file control record rather than a record.
/// `PLBTVSTF.C:680` gets it from Btrieve's `STAT` operation, whose reply
/// carries the same number the file's first page does.
///
/// **A count of zero is an answer**, not a failure: `WCCUSERS.DAT` on a fresh
/// board genuinely has no records in it.
///
/// # With no file current, and why the refusal is not the null-`bb` one
///
/// `cntrbtv` is one of two routines in `PLBTVSTF.C` that this host implements
/// and that has **no** `bb == NULL` guard, and unlike `stpbtvl` it has not got
/// one because it does not need one: `:681-694` never mentions `bb` at all. It
/// asks Btrieve for a `STAT` on whatever file the TSR is positioned on and
/// returns `GIBP->fs.numofr`. On a real board with no `setbtv` in force that
/// answered about *some* file -- the last one touched -- rather than faulting.
///
/// The refusal here survives for a different reason. **This host has no Btrieve
/// TSR holding a position**; it reads the file itself, so "which file" comes
/// from `bb` and from nowhere else. With none current the question has no
/// referent, and 0 would be a count of a file this host cannot name.
pub fn cntrbtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let block = positioned(call, host, "cntrbtv")?.ok_or_else(|| {
        ShimError::Failed(
            "cntrbtv with no Btrieve file current -- PLBTVSTF.C:681 would have \
             counted whatever file Btrieve was last positioned on, and this \
             host has no such position to fall back on"
                .to_owned(),
        )
    })?;
    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    Ok(abi::Ret::Long(file.geometry().records))
}

/// `void invbtv(void *recptr, int length)` -- insert a new record.
///
/// Four call sites, and **initialisation reaches one of them**: call 130,
/// straight after the `obtbtvl` that answered "there is no such record".
///
/// # It answers when there is no file, and refuses when there is
///
/// The two are not the same thing and this is the one routine so far where the
/// difference is load-bearing. `PLBTVSTF.C:584` opens with the same guard the
/// six reads have:
///
/// With no file current the real host inserted nothing and returned, so
/// answering nothing is reproducing it rather than pretending. **That is all
/// initialisation needs**, and it needs it without this host having written a
/// byte.
///
/// With a file current it is a real insert, and nothing in this crate writes to
/// a Btrieve file. That is a refusal, and it is the refusal the whole design
/// exists for: a module told its insert worked and then finding the character
/// gone is the failure nothing else catches.
pub fn invbtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let recptr = call.ptr();
    let length = ushort_arg::<A>(call.int());
    let Some(block) = positioned(call, host, "invbtv")? else {
        note_no_file(host, "invbtv");
        return Ok(abi::Ret::Void);
    };
    insert_record(call, host, "invbtv", block, recptr, length, true)?;
    Ok(abi::Ret::Void)
}

/// `void delbtv(void)` -- delete the record the file is positioned on.
///
/// Fifteen call sites, and initialisation reaches none of them. Here because it
/// is the same guard as [`invbtv`] -- `PLBTVSTF.C:623` -- and reproducing one
/// without the other would leave a module that deletes stopped for a reason
/// that has nothing to do with deleting.
///
/// No arguments at all, which is worth stating because the rest of this family
/// takes a record pointer: the record is whichever one the current file is
/// positioned on, and `:626` passes `bb->lastkn` to say in which key's order.
///
/// Answers nothing with no file current -- `:623`'s own `if (bb == NULL)
/// return;` -- and otherwise deletes, through [`Block::delete`].
///
/// # Currency after a delete
///
/// The cursor is set to [`Cursor::Nowhere`], because after opcode 4 there is
/// no current record to name. Leaving it alone would be worse than useless:
/// an [`Cursor::Ordered`] cursor holds an *index into the key's order*, and
/// removing a record shifts every index after it, so a carried-forward
/// cursor would quietly start naming the record that took the deleted one's
/// place -- a silently wrong `qnpbtv`, which is exactly the class of bug
/// this crate keeps finding.
///
/// **This is a decision, not a measurement.** Real Btrieve's post-delete
/// currency is not something this host has put to the Wine oracle
/// (`tools/btrieve-oracle/`), and the two candidate behaviours -- "no
/// current record" versus "the key path remembers where the deleted record
/// sat, so Get Next still steps from it" -- are distinguishable by a probe
/// nobody has written. `Nowhere` is the conservative half: it refuses to
/// answer rather than answering from a position whose meaning changed.
/// [`Block::delete`]'s own doc comment reasons the other way, about the
/// *model* rather than the cursor, and the two are not in conflict.
pub fn delbtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let Some(block) = positioned(call, host, "delbtv")? else {
        note_no_file(host, "delbtv");
        return Ok(abi::Ret::Void);
    };
    delete_record(host, "delbtv", block)?;
    Ok(abi::Ret::Void)
}

/// `int dinsbtv(void *recptr)` -- insert a new record into the current file.
///
/// `PLBTVSTF.C:598`:
///
/// # No `bb == NULL` guard
///
/// Unlike [`invbtv`] and [`delbtv`], `:598` reads `bb->reclen` before
/// checking anything, so the real host faulted with no file current. This
/// host stops the module and says so instead -- the same outcome honestly
/// reached, and a deliberately different shape from the two routines that do
/// answer quietly with no file current.
///
/// # Length, and the one difference from `dupdbtv`
///
/// `length` is `bb->reclen` -- [`Block::maxlen`](crate::btrieve::Block::maxlen),
/// the number the *module* passed to `opnbtv`, not the file's own record
/// length; the two are allowed to differ. The Btrieve call always passes key
/// number 0. [`dupdbtv`] passes `bb->lastkn` instead, and that is the only
/// difference between the two calls.
///
/// # The return convention
///
/// 1 for success, 0 for Btrieve status 5 -- a duplicate-key violation on a key
/// that does not permit them -- and everything else `catastro`'d, so this
/// host stops the module on anything else. `_GENERATE_TOP_LIST` branches on
/// the 0/1, so answering 0 rather than refusing is the only way a module that
/// legitimately collides keeps running. [`duplicate_key`] is where this host
/// re-derives the same answer Btrieve's TSR would have: it has no TSR to ask,
/// so it asks whether a record with this value is already in that key's
/// order.
pub fn dinsbtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let recptr = call.ptr();
    let block = positioned(call, host, "dinsbtv")?.ok_or_else(|| {
        ShimError::Failed(
            "dinsbtv with no Btrieve file current -- PLBTVSTF.C:598 has no \
             guard and reads bb->reclen before checking anything, so the \
             real host faulted here rather than answering"
                .to_owned(),
        )
    })?;
    // `bb->reclen`, which this host holds as `maxlen`. `dinsbtv` takes no
    // length argument of its own -- `PLBTVSTF.C:598` reads it off the block.
    let length = host.btrieve.block(block).map_err(ShimError::Failed)?.maxlen();
    // `false`: `DFAAPI.C:637-638`'s case-5 branch is the whole point of the
    // `d` in `dinsbtv`, so a duplicate answers 0 rather than refusing.
    let inserted = insert_record(call, host, "dinsbtv", block, recptr, length, false)?;
    Ok(abi::Ret::Int(A::Int::from(u16::from(inserted))))
}

/// `int dupdbtv(void *recptr)` -- update the record the file is positioned
/// on.
///
/// `PLBTVSTF.C:550` -- identical to [`dinsbtv`] except opcode 3, and the
/// Btrieve call's fourth argument is `bb->lastkn` rather than a hardcoded 0.
/// That argument names which key's position Btrieve's own bookkeeping
/// continues from; it plays no part in *which record* gets rewritten or in
/// which keys are checked for a collision; the record is always the one the
/// cursor names and every key that forbids duplicates is checked, exactly as
/// in [`dinsbtv`]. So the difference has nothing left to reproduce once
/// there is no Btrieve TSR to hand it to, and this host does not thread it
/// through anywhere -- see [`duplicate_key`].
///
/// # Opcode 3 updates the record the file is positioned on
///
/// Unlike `dinsbtv`, which makes a new record, this rewrites the one
/// [`Cursor`] names. `Cursor::Nowhere` stops the module: nothing has
/// positioned the file, so there is no record to update, and writing to a
/// guessed one is exactly the failure mode this crate exists to prevent.
/// `Cursor::Ordered`/`Cursor::Physical` resolve through
/// [`Block::current`](crate::btrieve::Block::current) to a file position,
/// which is what [`Block::update`](crate::btrieve::Block::update) takes.
///
/// This is what `_GENERATE_TOP_LIST` does: `absbtv` to learn the position,
/// `gabbtv` to position the file there, then `dupdbtv`.
///
/// # No `bb == NULL` guard, and the same return convention as `dinsbtv`
///
/// `:555` reads `bb->reclen` before checking anything, the same shape as
/// `dinsbtv`'s `:603` -- see that routine's doc for why this host stops the
/// module rather than faulting. 1 for success, 0 for a duplicate-key
/// violation, everything else `catastro`'d.
///
/// # A file opened for more than its own `reclen` cannot be written here
///
/// `WCCTEXT.DAT` holds 22-byte records and the module opens it for 2,022 --
/// see [`opnbtv`]'s doc comment on the two directions that number can
/// diverge from a file's own record length. Reading through that gap is
/// ordinary: the extra bytes are the buffer a variable-length read needs.
/// Writing through it is not: [`Block::update`](crate::btrieve::Block::update)
/// refuses a buffer that is not exactly the file's own `reclen`, because it
/// has no way to know how many of the buffer's bytes are the record this
/// module meant to write and how many are read-buffer padding it should not
/// commit to disk. This host does not write variable-length records at all,
/// and that refusal is not hypothetical -- **a live session hit it.**
///
/// `re/ne_arity.py 180` (`dupdbtv`'s ordinal, from `re/ordinal_map.tsv`)
/// finds 23 real call sites for it in `WCCMMUD.DLL`, one at seg 21:0x3354
/// cleaning the two words `dupdbtv`'s four cdecl arguments clean down to.
/// `re/exports/WCCMMUD_named.c` shows the path that reaches it:
/// `_AUTOMATIC_UPDATE_POLLING_ROUTINE` calls `FUN_10a0_3765`, which switches
/// on a type byte; case 9 `setbtv`s to the handle opened at `maxlen` `0x7e6`
/// (2,022 -- `WCCTEXT`'s own number, from the paragraph above) and falls
/// through to `FUN_10a0_32fa`, which calls `dupdbtv`. A board that took this
/// path stopped with exactly that call: `dupdbtv (WCCTEXT.DAT: ... 2,022-byte
/// buffer ...), called from seg 21:0x3353` -- one byte off `ne_arity.py`'s
/// reported site, the expected fixup-vs-return-address difference. The guard
/// above is what turned that into a stopped module instead of an unlinked
/// fragment chain nobody noticed until the next read.
///
/// An earlier version of this comment claimed no such call existed, without
/// having run `ne_arity.py` to check. An absence claim nobody checked is a
/// search result wearing the clothes of a fact. The corrected shape: name
/// the tool and what it found (or didn't), rather than asserting the thing
/// itself.
pub fn dupdbtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let recptr = call.ptr();
    let block = positioned(call, host, "dupdbtv")?.ok_or_else(|| {
        ShimError::Failed(
            "dupdbtv with no Btrieve file current -- PLBTVSTF.C:550 has no \
             guard and reads bb->reclen before checking anything, so the \
             real host faulted here rather than answering"
                .to_owned(),
        )
    })?;
    // `bb->reclen`, which this host holds as `maxlen`; `dupdbtv` takes no
    // length argument of its own.
    let length = host.btrieve.block(block).map_err(ShimError::Failed)?.maxlen();
    // `true`: the case-5 branch is the `d` in `dupdbtv`. See `update_variable`.
    let wrote = update_variable(call, host, "dupdbtv", block, recptr, length, true)?;
    Ok(abi::Ret::Int(A::Int::from(u16::from(wrote))))
}


/// `void clsbtv(struct btvblk *bbp)` -- close a Btrieve file.
///
/// `PLBTVSTF.C:632`, quoted in full because every line of it does something:
///
/// # `bb=bbp` happens first, and it is unconditional
///
/// `&&` only short-circuits its *right* operand, so `bb=bbp` runs as part of
/// evaluating `goodptr(bb=bbp)` whichever way the guard then goes. Closing a
/// file makes it current on the way out -- and when the guard succeeds, `bb`
/// is left naming a block this call is about to free. That is reproduced
/// rather than tidied up: [`Btrieve::close`](crate::btrieve::Btrieve::close)
/// takes `at` as a plain argument and never reads `bb` itself, precisely so
/// this routine can write `bb` before anything decides whether there is a
/// file to close. A later `setbtv` on the stale pointer then fails to find
/// an open file -- a module bug getting caught, rather than silently
/// resolving to whatever this host puts in that slot next.
///
/// # The ten-deep `setbtv` stack is not purged either
///
/// Only `bb` is written here -- nothing in [`Btrieve`](crate::btrieve::Btrieve)
/// touches its stack on a close. If an earlier `setbtv` pushed this block's
/// pointer there before some other `setbtv` made a different file current,
/// closing this one now leaves that pointer sitting in the stack, unexamined.
/// A later `rstbtv` that pops down to it -- see
/// [`Btrieve::restore`](crate::btrieve::Btrieve::restore) -- writes it into
/// `bb` with no check that the block it names still exists, for the same
/// reason `restore` hands back an empty stack's null without complaint: the
/// original never validated either end of that call. Whichever routine reads
/// `bb` next gets the same "not an open Btrieve file" the paragraph above
/// describes -- a module bug getting caught, rather than silently resolving
/// to whatever this host puts in that slot next.
///
/// # The guard is a re-entrancy guard, and fifteen closes in a row need it
///
/// `bb->filnam != NULL` is the second half of the guard, and it is what
/// makes a second `clsbtv` of the same block do nothing at all --
/// [`Btrieve::close`](crate::btrieve::Btrieve::close) nulls the field before
/// it frees anything, and a second read of the same bytes still finds it
/// null. `_LJNGAME_FINROU` (`re/exports/WCCMMUD_named.c:10688`) closes
/// fifteen files back to back, so double-close is a shape the original
/// expected rather than a bug to guard against.
///
/// # The index is rebuilt here, and this is the flush point
///
/// `(*btvuptr)(1,0,0,0,0)` is Btrieve's own Close, which flushed whatever the
/// TSR had buffered. This host has no TSR and buffers nothing -- every write
/// [`dinsbtv`] and [`dupdbtv`] make lands on disk immediately -- except the
/// one thing deliberately deferred: the B-tree index, marked
/// [`dirty`](crate::btrieve::Block::dirty) by both of them and left stale
/// until now. [`Btrieve::close`](crate::btrieve::Btrieve::close) rebuilds it
/// exactly when the block is dirty, and stops the module if that fails -- a
/// file leaving this host's reach with an index that disagrees with its data
/// is exactly what [`reindex`](crate::btrieve::Block::reindex) exists to
/// prevent.
///
/// A block that was never written is never reindexed, and that is not
/// merely tidy: [`pages::index_pages`](crate::btrieve::pages::index_pages)
/// refuses any key needing more than one leaf page, which is nine of the
/// eleven shipped files that hold records -- `WCCITEMS`, `WCCTEXT` and
/// `WCCSPELS` among them. Reindexing an untouched `WCCITEMS` on close would
/// stop the module the first time it closed one; the `dirty` flag is what
/// keeps a clean close from ever asking.
///
/// # Four allocations come back
///
/// The key buffer, the record buffer, the file name and the block itself --
/// all four came off the module's heap in [`opnbtv`], and all four go back
/// here rather than leaking a tiled descriptor per close, which would fail a
/// long-running board rather than this one.
pub fn clsbtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let bbp = call.ptr();

    // Unconditional, and before anything below decides whether there is a
    // file to close -- see this routine's doc comment.
    set_current(call, host, bbp)?;

    let Host { btrieve, heap, .. } = host;
    btrieve
        .close(call.mem(), heap, bbp)
        .map_err(|e| ShimError::Failed(format!("clsbtv: {e}")))?;
    Ok(abi::Ret::Void)
}

/// `void clsbb(void)` -- close the Btrieve file `setbtv` currently has in
/// force.
///
/// # No surviving prototype, and what stands in for one
///
/// `_CLSBB` is a genuine `MAJORBBS.DEF` export (`archive/galacticomm/extract/wg1/GALDSRC/DLIB/MAJORBBS.DEF:119`,
/// ordinal 116) with no declaration anywhere in `re/wg33src/INC/`'s 198
/// headers or `archive/galacticomm/extract/wg1/GALDSRC/SRC/`'s surviving
/// `.C`/`.H` files -- every hit for the bare identifier `clsbb` in either
/// tree is the *variable* `BTVFILE *clsbb` (`ACCOUNT.C:24`, `REMSYS.C:81`,
/// and their `wg33src`/`mbbs625sdk` counterparts), Galacticomm's own class
/// database file pointer, unrelated by anything but spelling.
///
/// So this is not sourced from a header the way every other routine in this
/// crate is. What stands in for one, converging from three directions:
///
/// - **Arity, measured.** `re/ne_arity.py 116 <WCCMMPLS.DLL>` finds 10 real
///   call sites and every one cleans zero bytes after the far call returns.
///   Every other `MAJORBBS` entry in this table is caller-cleans/cdecl, so
///   "cleans nothing" here can only mean "nothing was pushed" -- a
///   zero-argument routine -- not a deferred cleanup, which would have to
///   show up as a *sometimes*-zero pattern the way [`upvbtv`]'s own
///   measurement does, not a *uniform* one across all 10 sites.
/// - **Ordinal placement.** `_CLSBB` (@116) sits directly between `_CLS`
///   (@115, `MAJORBBS.H:818`, clear screen) and `_CLSBTV` (@117,
///   `BTVSTF.H:166`, close a *named* file) in the export table -- the
///   ordinary Galacticomm convention of grouping a family alphabetically by
///   what it does, and the one export between "clear" and "close a named
///   file" that a zero-argument close naturally is.
/// - **The `bb` global itself.** [`clsbtv`]'s own quoted body opens with
///   `goodptr(bb=bbp)` -- `bb` (`PLBTVSTF.C:31`, `struct btvblk *bb; /*
///   current btvu file pointer set */`) is a plain module-DGROUP global,
///   the exact one [`current`]/[`set_current`] in this file already read and
///   write for `setbtv`/`rstbtv`. A zero-argument sibling of "close this
///   named file" that needs no argument at all can only mean "close
///   whichever file is current" -- `clsbtv(bb)` with `bb` supplied by the
///   host instead of the caller.
///
/// This shim is that: [`clsbtv`]'s own body, called against [`current`]
/// instead of a module-supplied argument. If `_CLSBB` ever turns out to do
/// something else, the reasoning above -- not a citation -- is exactly what
/// a reader should distrust, and this paragraph is where that would be
/// found.
///
/// `bb == NULL` (nothing current) is not a special case here either: the
/// null branch of `clsbtv`'s own `goodptr` check already covers it, and
/// [`Btrieve::close`](crate::btrieve::Btrieve::close) already answers `Ok(false)`
/// for a null pointer -- see that method's own doc comment, `"goodptr(bb=bbp)
/// is false for a null bbp"`.
pub fn clsbb<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let bbp = current(call, host)?;
    set_current(call, host, bbp)?;

    let Host { btrieve, heap, .. } = host;
    btrieve
        .close(call.mem(), heap, bbp)
        .map_err(|e| ShimError::Failed(format!("clsbb: {e}")))?;
    Ok(abi::Ret::Void)
}

/// Whether `bytes` collides with an existing record on a key that does not
/// permit duplicates.
///
/// Returns the colliding key's number and the value that collided, or `None`
/// if there is no collision. `exclude`, for [`dupdbtv`], is the file position
/// of the record being replaced -- its own current key values are not a
/// collision with themselves; [`dinsbtv`] has no such record and passes
/// `None`.
///
/// `PLBTVSTF.C` never computes this: it hands the record to Btrieve and reads
/// back status 5 if the TSR already had one. This host has no TSR, so it asks
/// the engine the same question through [`Block::query`](crate::btrieve::Block::query)
/// -- a record with this value is a collision if an `Op::Equal` search on the
/// key finds one.
///
/// **Not `Block::records()`.** An earlier version asked
/// [`Records::seek`](crate::btrieve::Records::seek)/
/// [`Records::matches`](crate::btrieve::Records::matches) directly, which
/// meant calling `Block::records()` first -- materialising this file's
/// *entire* record model on every insert and update regardless of whether
/// [`Block::v6_fast_reads`](crate::btrieve::Block) applies, exactly the
/// per-operation whole-file read the page cache exists to make unnecessary.
/// `Block::query` already rides that fast path; this is a read-only check,
/// so the cursor `query` moves on a match is restored before returning,
/// unconditionally, so a caller of this function never observes it moved.
///
/// The caller is the one who notes it -- see [`note_duplicate_key`] -- because
/// only the caller knows whether this is an insert or an update.
pub(crate) fn duplicate_key<A: Abi>(
    host: &mut Host<A>,
    block: A::Ptr,
    bytes: &[u8],
    exclude: Option<u32>,
) -> Result<Option<(u16, Vec<u8>)>, ShimError> {
    let file = host.btrieve.block_mut(block).map_err(ShimError::Failed)?;
    let keys = file.keys().to_vec();
    let saved = file.cursor();

    // Both fallible calls in the loop below report their own error into
    // `outcome` and `break` rather than using `?` directly -- an early
    // return from inside the loop would skip the `file.seek_to(saved)`
    // after it, leaving the cursor wherever the last successful `query`
    // left it. Restoring only on the loop's normal exit was exactly that
    // bug (found in this task's own re-review): a `Block::query`/`Block::
    // get_position` failure mid-scan moved this read-only check's cursor
    // and never put it back.
    let mut collision = None;
    let mut outcome = Ok(());
    for key in &keys {
        if key.duplicates {
            continue;
        }
        // Extract the key off the *keyed* record, not the bare bytes: a key's
        // `offset` field is measured from the physical slot, so on v6 it sits
        // two bytes ahead of `Record::bytes`. `Block::keyed` pads that gap --
        // the same shift `insert_v6` applies before it computes the very key
        // this pre-check races (`lib.rs`, `value = key.extract(keyed_bytes)`).
        // Without it a v6 key landed two bytes late, read past the record into
        // zero padding, and reported an all-zero key that collided with
        // nothing that was really there -- which is what turned The Rose's
        // first character save into a spurious `dfaInsert` duplicate.
        let keyed = file.keyed(bytes);
        let value = key.extract(&keyed);
        let found = match file.query(key.number, EngineOp::Equal, &value) {
            Ok(found) => found,
            Err(e) => {
                outcome = Err(ShimError::Failed(e.to_string()));
                break;
            }
        };
        if !found {
            continue;
        }
        let existing = match file.get_position() {
            Ok(existing) => existing,
            Err(e) => {
                outcome = Err(ShimError::Failed(e.to_string()));
                break;
            }
        };
        if Some(existing) == exclude {
            continue;
        }
        collision = Some((key.number, value));
        break;
    }
    file.seek_to(saved);
    outcome?;
    Ok(collision)
}

/// Say that a duplicate-key collision made a write answer 0 instead of
/// happening.
///
/// A duplicate-key answer of 0 is exactly the case where `_GENERATE_TOP_LIST`
/// silently skips a character -- see [`duplicate_key`], whose result this
/// reports. Every call here names a different key and a different colliding
/// value, so this is [`Host::note`] rather than [`Host::note_once`]: the
/// `note_once` routines ([`note_no_file`], the setbtv-stack-overflow note in
/// [`push`]) exist to collapse *identical* lines a tight loop would otherwise
/// repeat thousands of times, and this is neither identical from one call to
/// the next nor called anywhere near that often -- `_GENERATE_TOP_LIST` calls
/// [`dinsbtv`]/[`dupdbtv`] at most once per character on the board. The value
/// is printed as raw bytes, the same `{:02x?}` this crate already uses for a
/// file-control-record mismatch in [`crate::btrieve::Btrieve::open`], because
/// a key can be text, a number, or several segments of both.
pub(crate) fn note_duplicate_key<A: Abi>(host: &mut Host<A>, who: &str, name: &str, key: u16, value: &[u8]) {
    host.note(format!(
        "{who} on {name} refused a record: key {key} already holds {value:02x?}, \
         and that key does not permit duplicates -- this call answers 0 rather \
         than writing, and whichever record it was is silently skipped by \
         whoever asked for the write"
    ));
}

/// What a Btrieve operation code asks for.
///
/// The numbers are Btrieve's own and they arrive from three directions:
/// `qrybtv` is handed 55 to 63 by the `q*btv` macros, `qnpbtv` is handed 56 or
/// 57 and subtracts 50, and `obtbtvl` is handed 5 to 13 by the `a*btv` macros.
/// So 5 and 55 are the same request -- "equal" -- differing only in whether the
/// record comes back with it, and that is why they are one enum here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Op {
    /// The first record whose key is exactly this value.
    Equal,
    /// The next record in key order.
    Next,
    /// The previous record in key order.
    Previous,
    /// The first record whose key is above this value.
    Greater,
    /// The first record whose key is at least this value.
    AtLeast,
    /// The last record whose key is below this value.
    Less,
    /// The last record whose key is at most this value.
    AtMost,
    /// The lowest key in the file.
    Lowest,
    /// The highest key in the file.
    Highest,
}

impl Op {
    /// The operation a code names, or `None` for one no macro produces.
    pub(crate) fn of(code: i16) -> Option<Self> {
        match code {
            5 => Some(Self::Equal),
            6 => Some(Self::Next),
            7 => Some(Self::Previous),
            8 => Some(Self::Greater),
            9 => Some(Self::AtLeast),
            10 => Some(Self::Less),
            11 => Some(Self::AtMost),
            12 => Some(Self::Lowest),
            13 => Some(Self::Highest),
            _ => None,
        }
    }

    /// Whether this operation needs the key value the module supplied.
    ///
    /// `Next`, `Previous`, `Lowest` and `Highest` move relative to where the
    /// file already is, and `PLBTVSTF.C`'s macros pass `NULL` for their key.
    pub(crate) fn wants_value(self) -> bool {
        matches!(
            self,
            Self::Equal | Self::Greater | Self::AtLeast | Self::Less | Self::AtMost
        )
    }

    /// The identical variant of the engine's own `Op` (`crate::btrieve::Op`,
    /// aliased `EngineOp` in this file) -- this type exists to parse a
    /// module-supplied opcode number into one of Btrieve's nine "get key"
    /// operations, and the engine's `Block::query` is what actually answers
    /// one; [`locate`] is the one place that needs both.
    pub(crate) fn as_engine(self) -> EngineOp {
        match self {
            Self::Equal => EngineOp::Equal,
            Self::Next => EngineOp::Next,
            Self::Previous => EngineOp::Previous,
            Self::Greater => EngineOp::Greater,
            Self::AtLeast => EngineOp::AtLeast,
            Self::Less => EngineOp::Less,
            Self::AtMost => EngineOp::AtMost,
            Self::Lowest => EngineOp::Lowest,
            Self::Highest => EngineOp::Highest,
        }
    }
}

/// `int qrybtv(void *key, int keynum, int qryopt)` -- position the file without
/// reading a record.
///
/// The `q*btv` macros are all this: `qeqbtv(key,n)` is `qrybtv(key,n,55)`,
/// `qlobtv(n)` is `qrybtv(NULL,n,62)`. 55 to 63 are Btrieve's *get key*
/// operations -- the same nine as 5 to 13, answering with the key rather than
/// with the record -- which is why the option is 50 more than the acquire
/// family's.
///
/// **Returning zero is an answer, not a refusal.** `PLBTVSTF.C:274` maps
/// Btrieve's status 4 (no such key) and 9 (end of file) to a return of 0, and
/// every call site is written for it: initialisation's very first read is
/// `qlobtv(0)` on `WCCUSERS.DAT`, which holds no records at all, and 0 is what
/// tells the module the board has no characters yet.
///
/// **With no file current it is the same zero**, per the guard at
/// `PLBTVSTF.C:262`. That indistinguishability is the point: a module could
/// never tell "no such record" from "no such file" and none was written to.
pub fn qrybtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // The guard is the first thing `PLBTVSTF.C:262` does -- before the key, the
    // key number or the option are looked at -- so it is the first thing here.
    let Some(block) = positioned(call, host, "qrybtv")? else {
        note_no_file(host, "qrybtv");
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    };

    let value = call.ptr();
    let keynum = i16_arg::<A>(call.int());
    let opt = i16_arg::<A>(call.int());

    // `qrybtv` takes the *get key* codes, fifty above the acquire family's.
    let op = Op::of(opt - 50).ok_or_else(|| {
        ShimError::Failed(format!(
            "qrybtv with option {opt}, which is none of the nine BTVSTF.H's q-macros produce"
        ))
    })?;
    Ok(abi::Ret::Int(A::Int::from(u16::from(locate(
        call,
        host,
        Request {
            who: "qrybtv",
            block,
            op,
            keynum,
            value,
            into: None,
            // `qrybtv` has no `loktyp` at either layer -- `int qrybtv(void
            // *key, int keynum, int qryopt)`, three arguments -- so there is
            // nothing to lock. See `ops.rs`'s "Locking" doc section.
            lock: 0,
        },
    )?))))
}

/// `int qnpbtv(int getopt)` -- step in key order, *and* read the record.
///
/// Despite living with the query family, this one fetches: `PLBTVSTF.C:296`
/// ends with `movmem(gpbptr,bb->data,bb->reclen)`. `qnxbtv()` is `qnpbtv(56)`
/// and `qprbtv()` is `qnpbtv(57)`, and the routine subtracts the fifty itself
/// -- so the operations really are Get Next and Get Previous with data.
///
/// The pattern the two make together is what MajorMUD uses them for: `qeqbtv`
/// to find where a group of records starts, then `qnxbtv` along it.
pub fn qnpbtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `PLBTVSTF.C:287`, and it has to be before `bb->data` is read for the same
    // reason the C puts it there: there is no `bb->data` to read.
    let Some(block) = positioned(call, host, "qnpbtv")? else {
        note_no_file(host, "qnpbtv");
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    };

    let opt = i16_arg::<A>(call.int());
    let op = Op::of(opt - 50).ok_or_else(|| {
        ShimError::Failed(format!("qnpbtv with option {opt}, which is not a get operation"))
    })?;

    // `bb->lastkn`: which key the last positioning used. Passed as -1 so that
    // `locate` reads it back rather than changing it, exactly as the C does.
    let into = data_buffer(host, block)?;
    Ok(abi::Ret::Int(A::Int::from(u16::from(locate(
        call,
        host,
        Request {
            who: "qnpbtv",
            block,
            op,
            keynum: -1,
            value: Btrieve::<AbiMem<A>>::null(),
            into: Some(into),
            // `int qnpbtv(int getopt)` -- one argument, no `loktyp`.
            lock: 0,
        },
    )?))))
}

/// `int obtbtvl(void *recptr, void *key, int keynum, int obtopt, int loktyp)`
/// -- acquire a record by key.
///
/// The whole `a*btv` family: `acqbtv(rec,key,n)` is `obtbtvl(rec,key,n,5,0)`,
/// `ahibtv(rec,n)` is `obtbtvl(rec,NULL,n,13,0)`. 112 call sites in
/// `WCCMMUD.DLL`, which is more than any other Btrieve import and is what makes
/// this the weight of the step.
///
/// `recptr` may be null, and then the record goes to `bb->data` --
/// `PLBTVSTF.C:360`.
///
/// `loktyp` is taken as a lock at the position `locate` finds, once it finds
/// one -- see `ops.rs`'s "Locking" module doc section and [`take_lock`].
/// `WCCMMUD.DLL`'s own 112 call sites all push a literal zero (measured,
/// `docs/lock-oracle-answer.md`), so this is unreachable for MajorMUD today;
/// it is honoured anyway, on the repository owner's standing instruction not
/// to skip a real Btrieve feature merely because this module never asks for
/// it.
///
/// **With no file current it answers 0**, per `PLBTVSTF.C:357` -- and this is
/// the one initialisation actually reaches. Call 128 of `_INIT__WCCMMUD` is an
/// `obtbtvl` after a `setbtv(NULL)`, and it is entitled to be told there is no
/// record rather than stopped.
pub fn obtbtvl<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // `:357` guards, and only then does `:360` default `recptr` to `bb->data`.
    // The order is the whole of it: `bb->data` cannot be read from a null `bb`,
    // so a guard placed after that default never runs.
    let Some(block) = positioned(call, host, "obtbtvl")? else {
        note_no_file(host, "obtbtvl");
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    };

    let into = call.ptr();
    let value = call.ptr();
    let keynum = i16_arg::<A>(call.int());
    let opt = i16_arg::<A>(call.int());
    let lock = i16_arg::<A>(call.int());

    let op = Op::of(opt).ok_or_else(|| {
        ShimError::Failed(format!(
            "obtbtvl with option {opt}, which is none of the nine BTVSTF.H's a-macros produce"
        ))
    })?;
    let into = match into == Btrieve::<AbiMem<A>>::null() {
        true => data_buffer(host, block)?,
        false => into,
    };
    Ok(abi::Ret::Int(A::Int::from(u16::from(locate(
        call,
        host,
        Request {
            who: "obtbtvl",
            block,
            op,
            keynum,
            value,
            into: Some(into),
            lock,
        },
    )?))))
}

/// `int stpbtvl(void *recptr, int stpopt, int loktyp)` -- walk the file in the
/// order the pages hold it.
///
/// No key at all. `snxbtv(rec)` is `stpbtvl(rec,24,0)`, and 33, 24, 34 and 35
/// are Btrieve's Step First, Step Next, Step Last and Step Previous.
///
/// This is how a module reads a whole file when the order does not matter --
/// and it is *not* the same sequence a keyed walk gives. `WCCRACE` holds
/// thirteen races whose first record is number 10.
///
/// # The one step routine that refuses on a null `bb`
///
/// Eleven routines in `PLBTVSTF.C` open with `if (bb == NULL) return 0;` and
/// this is not one of them. `:509` goes straight to work:
///
/// Two dereferences before anything is checked. A real board that stepped with
/// no file current took the fault there, so there is no answer to reproduce and
/// refusing is the honest translation of what happened.
pub fn stpbtvl<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    // Before `recptr` is defaulted, so that the refusal names `stpbtvl` rather
    // than coming out of a `bb->data` lookup on a null block.
    let block = positioned(call, host, "stpbtvl")?.ok_or_else(|| {
        ShimError::Failed(
            "stpbtvl with no Btrieve file current -- PLBTVSTF.C:509 has no \
             guard for that and dereferences bb twice, so the real host faulted \
             here rather than answering"
                .to_owned(),
        )
    })?;

    let into = call.ptr();
    let opt = i16_arg::<A>(call.int());
    let lock = i16_arg::<A>(call.int());

    let into = match into == Btrieve::<AbiMem<A>>::null() {
        true => data_buffer(host, block)?,
        false => into,
    };

    // 33/34/24/35 are Btrieve's Step First/Last/Next/Previous -- see this
    // function's own doc comment.
    let step = match opt {
        33 => Step::First,
        34 => Step::Last,
        24 => Step::Next,
        35 => Step::Previous,
        _ => {
            return Err(ShimError::Failed(format!(
                "stpbtvl with option {opt}, which is none of 24, 33, 34 and 35"
            )));
        }
    };

    load(host, block)?;
    let file = host.btrieve.block_mut(block).map_err(ShimError::Failed)?;
    let name = file.name().to_owned();

    // `Block::step_position` (`crates/btrieve::ops`) is `Block::step`'s own
    // positioning, fast-path-aware (`Block::v6_fast_reads`) and already
    // measured oracle-correct for the keyed-cursor-to-physical translation
    // this function used to compute by hand against `Block::records()` --
    // Task 12's own correction (a `qrybtv`/`gabbtvl` positions the file
    // physically too, so a step-family call after a keyed one continues
    // from there rather than refusing) lives in `physical_of`
    // (`crates/btrieve::ops`) now, exercised identically either way. Not
    // `Block::step` itself: that also takes a lock and delivers a record,
    // both of which need a `LockTable` this session keeps to itself (only
    // `Btrieve::take_lock` reaches it) -- `step_position` is the same split
    // `Block::cursor_for` already makes for `insert_record`/
    // `update_variable`'s currency, so this function keeps its own
    // `take_lock`/`deliver` calls below unchanged.
    //
    // **Not `Block::records()`.** This is how a module reads a whole file
    // when key order does not matter (this function's own doc comment),
    // which makes it the natural idiom for a mass migration that walks
    // every record -- exactly `WCCMP002.DAT`'s own "Automatic Database
    // Update" -- and `Block::records()` unconditionally, on every single
    // step, is precisely the whole-file read the page cache exists to
    // avoid paying more than once per open.
    let at = file
        .step_position(step)
        .map_err(|e| ShimError::Failed(format!("stpbtvl({opt}) on {name}: {e}")))?;
    if at.is_none() {
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    }
    take_lock(host, block, lock)?;
    deliver(call, host, block, into)?;
    Ok(abi::Ret::Int(A::Int::from(1u16)))
}

/// `long absbtv(void)` -- where the current record is in the file.
///
/// Btrieve's Get Position. The number is a byte offset and it is the record's
/// identity: `gabbtvl` and `aabbtv` take it back, and `gcrbtv` is defined as
/// `gabbtvl(rec,absbtv(),n,0)` -- re-read where you already are.
///
/// `PLBTVSTF.C:426` returns `0L` when no file is current, and that is what this
/// gives -- a `long` zero, in `DX:AX`, because `absbtv` is declared `long` and
/// the return type should say so.
///
/// **A file that is current but not positioned is still a refusal.** The two
/// cases are not the same: the real host's Btrieve answered a Get Position on
/// an unpositioned file with status 8 and `btverr` turned that into a
/// `catastro`, so there was never a zero to reproduce there. Zero is also a
/// real file offset in the sense that matters -- the module hands it straight
/// back to `gabbtvl` -- and answering it would name the file control record.
pub fn absbtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let Some(block) = positioned(call, host, "absbtv")? else {
        note_no_file(host, "absbtv");
        return Ok(abi::Ret::Long(0));
    };
    Ok(abi::Ret::Long(current_position(host, "absbtv", block)?))
}

/// `int aabbtv(void *recptr, long abspos, int keynum)` -- acquire the record at
/// a file position.
///
/// **Three arguments, not four.** `BTVSTF.H:155` declares this and `aabbtvl`
/// separately, and they are separate exports -- ordinals 51 and 1100.
/// `WCCMMUD.DLL` imports 51 at eight sites and 1100 at none, and every one of
/// the eight cleans `add sp,10`: five words, which is `recptr` and `abspos` and
/// `keynum` and nothing else.
///
/// So there is no `loktyp` word to read, and reading one got the caller's
/// lowest local instead -- which was then read as a lock type the module
/// never asked for. It shared [`absolute`] with `gabbtvl`, which really
/// does take four (`add sp,12` at all 34 of its sites), and that is how it
/// survived: the helper was right for one caller and wrong for the other.
///
/// `PLBTVSTF.C:466` is where the zero comes from -- `aabbtv` is a one-line
/// wrapper that passes `loktyp` as 0.
///
/// And `gabbtvl`, which `:445` defines as `aabbtvl` plus "stop the board if it
/// was not there": the same routine with `fatal` set, which is the difference
/// between a module that expects a record to be missing and one that does not.
///
/// It also establishes the key path, so a `qnxbtv` after it continues in
/// `keynum`'s order from wherever the position landed.
///
/// With no file current it answers 0, per the guard at `:476`.
pub fn aabbtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let into = call.ptr();
    let position = call.long();
    let keynum = i16_arg::<A>(call.int());
    // `absolute` no longer looks the file up itself -- the `dfa*`
    // spelling of this routine finds it a different way. Same guard as
    // before, in the caller that owns it.
    let Some(block) = positioned(call, host, "aabbtv")? else {
        note_no_file(host, "aabbtv");
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    };
    Ok(abi::Ret::Int(A::Int::from(u16::from(absolute(
        call,
        host,
        Position {
            who: "aabbtv",
            block,
            negative_keynum: NegativeKey::Note,
            fatal: false,
            lock: UNLOCKED,
            into,
            position,
            keynum,
        },
    )?))))
}

/// The lock type `aabbtv` has instead of an argument.
///
/// `PLBTVSTF.C:466` -- `return(aabbtvl(recptr,abspos,keynum,0))`. Named rather
/// than written as a bare 0 at the call site, because a 0 there reads as "no
/// lock was asked for" when what it means is "there was never a word to ask in".
pub(crate) const UNLOCKED: i16 = 0;

/// `void gabbtvl(void *recptr, long abspos, int keynum, int loktyp)` -- get the
/// record at a file position, or stop.
///
/// Four arguments, unlike [`aabbtv`], and confirmed the same way: `add sp,12` at
/// all 34 call sites.
///
/// **The one routine of the six that answers with nothing.** `PLBTVSTF.C:452`
/// is `if (bb == NULL) { return; }` in a `void` function, so with no file
/// current it does not fail, does not stop the module, and above all does not
/// write into the module's record buffer -- which is the whole of what a caller
/// could observe.
///
/// # The one shim in this file a single cursor can't read verbatim
///
/// `loktyp` is this routine's fourth and *last* argument -- word 5, past the
/// three (`recptr`, `abspos`, `keynum`) [`absolute`] also reads for
/// [`aabbtv`], which has no fourth argument at all: its frame ends at word 4.
/// A `Cursor` only moves forward, so there is no way to read word 5 without
/// first reading past words 0-4, and `absolute` cannot do that generically
/// for both callers without reading a word `aabbtv`'s frame does not have.
///
/// So this cursor walks all four of gabbtvl's words itself, in true stack
/// order, and `absolute` takes `into`/`position`/`keynum` already read
/// instead of reading them a second time off a cursor that has moved past
/// them. `lock` is still computed here, before the call to `absolute` -- not
/// inside it -- so `absolute` still receives it as a plain value and still
/// consults it with [`unlocked`] immediately after [`positioned`]'s
/// no-file-current guard, exactly as before this file read its arguments
/// through a cursor. See `absolute`'s own doc comment for why that guard,
/// then lock, then everything else ordering is load-bearing and was kept.
pub fn gabbtvl<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let into = call.ptr();
    let position = call.long();
    let keynum = i16_arg::<A>(call.int());
    let lock = i16_arg::<A>(call.int());
    // `absolute` no longer looks the file up itself -- the `dfa*`
    // spelling of this routine finds it a different way. Same guard as
    // before, in the caller that owns it.
    let Some(block) = positioned(call, host, "gabbtvl")? else {
        note_no_file(host, "gabbtvl");
        return Ok(abi::Ret::Void);
    };
    absolute(
        call,
        host,
        Position {
            who: "gabbtvl",
            block,
            negative_keynum: NegativeKey::Note,
            fatal: true,
            lock,
            into,
            position,
            keynum,
        },
    )?;
    Ok(abi::Ret::Void)
}

/// What `aabbtv` and `gabbtvl` supply to [`absolute`], bundled into one type
/// rather than passed as six more parameters -- clippy already has an opinion
/// about `absolute` at seven, and the file already has a precedent for this
/// shape in [`Request`], below.
/// What a negative key number means to whoever asked -- see
/// [`Position::negative_keynum`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NegativeKey {
    /// Tolerate it and say so once: what `PLBTVSTF.C:483` did.
    Note,
    /// Refuse: what `DFAAPI.C`'s own ASSERT says.
    Refuse,
}

pub(crate) struct Position<A: Abi> {
    /// The routine asking, for anything it has to refuse or note by name.
    pub(crate) who: &'static str,

    /// The file, resolved by the caller. Passed in rather than looked up here
    /// because the `btv*` and `dfa*` spellings of this routine find it two
    /// different ways -- `positioned` off the `btv` current block,
    /// `dfa_required` off the `dfa` one -- and that is the only thing that ever
    /// differed between them. See [`absolute`].
    pub(crate) block: A::Ptr,

    /// What a negative key number means to this caller.
    ///
    /// The two spellings genuinely disagree and both cite a source, so this is
    /// a real parameter and not a wrinkle to flatten: `PLBTVSTF.C:483` stores
    /// `lastkn` unchecked, so `aabbtv`/`gabbtvl` tolerate and note; `DFAAPI.C`
    /// ASSERTs `keynum >= 0`, so the `dfa*` spellings refuse.
    pub(crate) negative_keynum: NegativeKey,

    /// Whether a position naming no record is a refusal ([`gabbtvl`]) or a
    /// quiet `false` ([`aabbtv`]). See [`absolute`]'s own doc comment.
    pub(crate) fatal: bool,

    /// **The caller's**, not read here -- the two callers don't have the same
    /// arguments; see [`aabbtv`]'s doc comment for why `gabbtvl` has a fourth
    /// word to read and `aabbtv` does not.
    pub(crate) lock: i16,

    /// Where the record goes, or the module's null for `bb->data`.
    pub(crate) into: A::Ptr,

    /// The file position to acquire -- Btrieve's Get Position number, what
    /// [`absbtv`] hands back.
    pub(crate) position: u32,

    /// Which key's order the position lands in, negative for `bb->lastkn`.
    pub(crate) keynum: i16,
}

/// The body of `aabbtv` and `gabbtvl`. Returns whether a record was delivered.
///
/// `false` covers both of the original's non-answers: no file current
/// (`PLBTVSTF.C:476`) and no record at that position. They differ for
/// `gabbtvl`, which `:455` sends to `posbtverr` in the second case only -- so
/// `fatal` turns the second into a refusal and never the first.
///
/// **Every field of [`Position`] is the caller's**, not read here. `lock`
/// always was -- the two callers don't have the same arguments, see
/// [`aabbtv`]. `into`/`position`/`keynum` joined it once this file started
/// reading arguments through a cursor: `gabbtvl`'s cursor has already walked
/// past these three by the time it reaches its own `loktyp` (see that
/// routine's doc comment), so it reads them itself rather than asking this
/// function to read the same bytes again off a cursor that has moved on.
/// `aabbtv` now reads its own three the same way, so both callers share one
/// shape instead of one reading through `absolute` and the other around it.
pub(crate) fn absolute<A: Abi>(call: &mut Call<A>, host: &mut Host<A>, req: Position<A>) -> Result<bool, ShimError> {
    let Position {
        who,
        block,
        negative_keynum,
        fatal,
        lock,
        into,
        position,
        keynum,
    } = req;

    let into = match into == Btrieve::<AbiMem<A>>::null() {
        true => data_buffer(host, block)?,
        false => into,
    };
    load(host, block)?;

    // **`PLBTVSTF.C:483` is `bb->lastkn=keynum;` and nothing else** -- the only
    // place in the file that stores a key number without either resolving a
    // negative one or bounds-checking it. So the real `aabbtv(rec,pos,-1)`
    // stored -1, and the next `qnxbtv` asked Btrieve for key number -1.
    //
    // `key_number` reads `lastkn` when the number is negative and refuses one
    // past the file's key count, which is what every other routine in
    // `PLBTVSTF.C` does. Kept deliberately: storing -1 as a key number is a bug
    // with no defined consequence to reproduce.
    //
    // Unreachable for MajorMUD -- neither of `aabbtv`'s eight call sites nor
    // `gabbtvl`'s thirty-four pushes a negative key number -- and noted rather
    // than refused for the same reason the `keylns` case is.
    if keynum < 0 {
        match negative_keynum {
            NegativeKey::Refuse => {
                return Err(ShimError::Failed(format!(
                    "{who} with key number {keynum} -- DFAAPI.C ASSERTs keynum >= 0 \
                     here (unlike aabbtv/gabbtvl, which tolerate and store a \
                     negative one), so a negative key number is a module bug this \
                     host refuses rather than reproduces"
                )));
            }
            NegativeKey::Note => host.note_once(
                "lastkn",
                format!(
                    "{who} was given key number {keynum}, and PLBTVSTF.C:483 would \
                     have stored it in bb->lastkn unchecked. Read lastkn instead"
                ),
            ),
        }
    }
    let key = key_number(call, host, block, keynum)?;

    let file = host.btrieve.block_mut(block).map_err(ShimError::Failed)?;
    let name = file.name().to_owned();

    // `Block::cursor_for` (`crates/btrieve::ops`) -- the same fast-path-
    // aware position resolution `insert_record`/`update_variable`'s
    // currency step rides -- not `Block::records()`, which this used to
    // call on *every* `aabbtv`/`gabbtvl` (34 call sites for the latter
    // alone, per this function's own doc comment), regardless of whether
    // `Block::v6_fast_reads` applied. The position names a record; the key
    // number says which order a later step should continue in, exactly
    // what `cursor_for` answers.
    let cursor = file
        .cursor_for(key, position)
        .map_err(|e| ShimError::Failed(format!("{who} on {name}: {e}")))?;
    let Some(cursor) = cursor else {
        if fatal {
            return Err(ShimError::Failed(format!(
                "{who} of {name}, which has no record at file position {position}",
            )));
        }
        return Ok(false);
    };
    file.seek_to(cursor);
    take_lock(host, block, lock)?;

    // `:484` passes `bb->keyseg`, so Btrieve left the found record's key there.
    answer_with_key(call, host, block, key)?;
    deliver(call, host, block, into)?;
    Ok(true)
}

/// One positioning request: which file, what to find in it, and where the
/// record goes.
///
/// The query, acquire and key families differ in exactly these fields and in
/// nothing else, which is what makes [`locate`] one routine.
pub(crate) struct Request<'a, A: Abi> {
    /// The routine asking, for anything it has to refuse by name.
    pub(crate) who: &'a str,

    /// The file. The caller's rather than read from `bb` here, because the
    /// caller has already had to decide what a null `bb` means to it -- see
    /// [`positioned`].
    pub(crate) block: A::Ptr,

    /// What to find.
    pub(crate) op: Op,

    /// Which key to find it by, or negative for `bb->lastkn`.
    pub(crate) keynum: i16,

    /// The module's key value, or null for an operation that needs none.
    pub(crate) value: A::Ptr,

    /// Where the record goes, or `None` for a query, which reads none.
    pub(crate) into: Option<A::Ptr>,

    /// The lock type to take once a record is found, or `0` for none --
    /// `0` for `qrybtv`/`qnpbtv`, which have no `loktyp` at either layer.
    pub(crate) lock: i16,
}

/// Position the file a [`Request`] names, and hand back the record if asked.
///
/// Returns whether a record was found.
pub(crate) fn locate<A: Abi>(call: &mut Call<A>, host: &mut Host<A>, req: Request<'_, A>) -> Result<bool, ShimError> {
    let Request {
        who,
        block,
        op,
        keynum,
        value,
        into,
        lock,
    } = req;
    load(host, block)?;
    let key = key_number(call, host, block, keynum)?;

    // `PLBTVSTF.C:266` -- the module's key value is copied into `bb->key`
    // before anything else, and that is where it is read from afterwards. So a
    // module may pass the buffer it was given last time and mean "the same key
    // again", which only works if the copy really happens.
    if value != Btrieve::<AbiMem<A>>::null() {
        // **The original measured this copy with the key number as passed**,
        // before `:268` resolved a negative one to `bb->lastkn`:
        //
        // `keylns` is at offset 144 of the block and `lastkn` at 142, so
        // `keylns[-1]` *is* `lastkn` -- the real host copied a key-number's
        // worth of bytes. That is an out-of-bounds read with a citation, not a
        // behaviour to reproduce, so this measures with the resolved key.
        //
        // Unreachable for MajorMUD: no `qrybtv` or `obtbtvl` call site in
        // `WCCMMUD.DLL` pushes a negative key number, and every site that
        // disassembles pushes a small constant. Noted rather than refused
        // because the host's answer here is the *better* one -- stopping a
        // module over a case handled correctly would be the wrong trade -- and
        // because an unreachable divergence should announce itself if it ever
        // stops being unreachable.
        if keynum < 0 {
            host.note_once(
                "keylns",
                format!(
                    "{who} passed a key value with key number {keynum}, and \
                     PLBTVSTF.C:266 would have measured the copy with \
                     bb->keylns[{keynum}] -- which is bb->lastkn. Measured with \
                     key {key} instead"
                ),
            );
        }
        let length = key_length(host, block, key)?;
        let bytes = value
            .resolve(call.mem(), usize::from(length))
            .map_err(|e| ShimError::Failed(e.to_string()))?
            .to_vec();
        let buffer = host
            .btrieve
            .block(block)
            .map_err(ShimError::Failed)?
            .key();
        buffer
        .write(call.mem(), &bytes)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    }

    let wanted = match op.wants_value() {
        false => Vec::new(),
        true => {
            let length = key_length(host, block, key)?;
            let buffer = host
                .btrieve
                .block(block)
                .map_err(ShimError::Failed)?
                .key();
            buffer
                .resolve(call.mem(), usize::from(length))
                .map_err(|e| ShimError::Failed(e.to_string()))?
                .to_vec()
        }
    };

    let file = host.btrieve.block_mut(block).map_err(ShimError::Failed)?;
    let name = file.name().to_owned();

    // `Block::query` (`crates/btrieve::ops`) is the engine's own 9-way `Op`
    // dispatch -- fast-path-aware (`Block::v6_fast_reads`), and already
    // measured against genuine Btrieve 6.15 for every corner this function
    // used to reimplement by hand against `Block::records()`:
    //
    //   - `S6` -- `Get Equal` on key 0, then `Get Next` on key 1: refused
    //     (`OpError::DifferentKey`, real Btrieve status 7), not translated
    //     into key 1's order the way an earlier version of this function
    //     did through `Records::place_in`.
    //   - `S4`/`S4b` -- `Step First`, then `Get Next` on *either* key:
    //     refused (`OpError::NoKeyEstablished`, status 8) -- a step
    //     establishes no key context at all.
    //   - `S1`/`S1c` -- an unpositioned `Get Next` answers as `Get Lowest`
    //     would (status 0); an unpositioned `Get Previous` answers "not
    //     found" (status 9) rather than refusing either way.
    //
    // `Block::query` sets the cursor itself on a match (`Cursor::Ordered {
    // key, at }`) and leaves it untouched on a miss -- the same "not found
    // leaves the file where it was" contract this function's own callers
    // depend on, so there is nothing left for this function to do with the
    // position once `query` returns.
    //
    // **Not `Block::records()`.** The engine's own doc comment on
    // `OpError::DifferentKey` names this exact function's *old* body as
    // "the divergence [`here_for`] exists to avoid reproducing" -- this
    // finishes that: reimplementing `Op`'s nine cases against the whole-file
    // model here meant calling `Block::records()` regardless of
    // `Block::v6_fast_reads`, on every `qrybtv`/`dfaQuery`/`obtbtvl`/
    // `aabbtvl` call a module makes, which on a fixed-length v6 file with a
    // page cache attached is exactly the whole-file read that fast path
    // exists to avoid paying per operation.
    let found = file
        .query(key, op.as_engine(), &wanted)
        .map_err(|e| ShimError::Failed(format!("{who} on {name}: {e}")))?;

    if super::btrieve_traced() {
        eprintln!(
            "mbbs-btv: {who} {name} {op:?} key={key} value={:02x?} -> {}",
            &wanted[..wanted.len().min(16)],
            if found { "FOUND" } else { "not-found" },
        );
    }

    // Not found leaves the file where it was, which is what Btrieve does: a
    // failed Get Equal does not lose the position a successful one established.
    if !found {
        return Ok(false);
    }
    take_lock(host, block, lock)?;
    answer_with_key(call, host, block, key)?;

    if let Some(into) = into {
        deliver(call, host, block, into)?;
    }
    Ok(true)
}

/// Leave the key of the record the file is now positioned on in `bb->key`.
///
/// Btrieve wrote the found key back into whatever buffer an operation named,
/// and **every read operation names `bb->keyseg`** -- `qrybtv` at
/// `PLBTVSTF.C:274`, `qnpbtv` at `:290`, `obtbtvl` at `:372`, `aabbtvl` at
/// `:484`. So after any of them a module reading `bb->key` sees the key it
/// landed on rather than the value it searched for.
///
/// The one that does not is `stpbtvl` (`:512`), which passes `NULL` for the key
/// buffer -- a step has no key -- and so leaves whatever was there.
///
/// Shared rather than written twice: the absolute-position family had it
/// missing for exactly as long as this was inline in [`locate`].
pub(crate) fn answer_with_key<A: Abi>(
    call: &mut Call<A>,
    host: &mut Host<A>,
    block: A::Ptr,
    key: u16,
) -> Result<(), ShimError> {
    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    let record = file
        .current()
        .ok_or_else(|| ShimError::Failed(format!("{} is not positioned", file.name())))?;
    let bytes = file
        .keys()
        .get(usize::from(key))
        .ok_or_else(|| ShimError::Failed(format!("{} has no key {key}", file.name())))?
        // Padded: a key's `offset` is measured from the physical slot, and a
        // v6 record's bytes start two bytes into it. Without this, every
        // opcode that fills the module's key buffer -- `qrybtv`, `qnpbtv`,
        // `obtbtvl`, `aabbtvl`, `gabbtvl` -- hands back the wrong bytes on a
        // v6 file, and no byte-for-byte record test can see it because the
        // record body it compares is right.
        .extract(&file.keyed(&record.bytes));
    let buffer = file.key();
    buffer
        .write(call.mem(), &bytes)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(())
}

/// Copy the record the cursor names into the module's memory.
///
/// At most `bb->reclen` bytes -- the length the *module* opened the file for,
/// not the file's. A record longer than that is truncated to what the module
/// asked for and a record shorter leaves the rest of the buffer alone.
///
/// The C is `movmem(gpbptr,recptr,btvdatptr->dbflen)`, and `dbflen` is **the
/// length Btrieve returned**, not the one the module asked for: `btvu` sets it
/// to `rlen` on the way in (`:794`) and reads back whatever the TSR left there
/// (`:812`). The two agree for a fixed-length file opened at its own record
/// length, which is every file MajorMUD opens. Where they would not is a module
/// opening a file for *less* than its record length -- real Btrieve answers
/// status 22 and `posbtverr` (`:746`) truncates with a NUL at `bb->reclen-1`
/// before the copy runs, where this truncates silently. `opnbtv` already notes
/// the mismatch that would make it live.
///
/// # `lastlen`, for [`llnbtv`]
///
/// This is the one chokepoint every read routine in this file already
/// funnels a successful positioning through -- `locate`/`absolute`'s own
/// `into.is_some()` call, `stpbtv`/`stpbtvl`'s direct one -- so it is also
/// where [`crate::btrieve::Btrieve::set_lastlen`] is fed: `take`, the number
/// of bytes actually copied, is exactly `PLBTVSTF.C:812`'s own
/// `lastlen=btvdatptr->dbflen` for the shape this host reproduces. See the
/// engine's own `lastlen` field doc comment for the scoping this shares with
/// [`crate::btrieve::Btrieve::dfa_last_len`]'s identical simplification.
pub(crate) fn deliver<A: Abi>(
    call: &mut Call<A>,
    host: &mut Host<A>,
    block: A::Ptr,
    into: A::Ptr,
) -> Result<(), ShimError> {
    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    let record = file
        .current()
        .ok_or_else(|| ShimError::Failed(format!("{} is not positioned", file.name())))?;
    let take = usize::from(file.maxlen()).min(record.bytes.len());
    let bytes = record.bytes[..take].to_vec();
    into.write(call.mem(), &bytes)
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    host.btrieve.set_lastlen(take as u16);
    Ok(())
}

/// Which key an operation works on, honouring `bb->lastkn`.
///
/// `PLBTVSTF.C:268`: a negative key number means "the one last used", and any
/// other means "this one, and remember it". `lastkn` is a field of the block in
/// module memory, so it is read and written there rather than kept here.
pub(crate) fn key_number<A: Abi>(
    call: &mut Call<A>,
    host: &Host<A>,
    block: A::Ptr,
    keynum: i16,
) -> Result<u16, ShimError> {
    let at = A::ptr_offset(block, btrieve::Layout::of::<AbiMem<A>>().lastkn);
    if keynum < 0 {
        let bytes = at.resolve(call.mem(), 2).map_err(|e| ShimError::Failed(e.to_string()))?;
        return Ok(u16::from_le_bytes([bytes[0], bytes[1]]));
    }

    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    let keys = file.keys().len();
    if usize::from(keynum as u16) >= keys {
        return Err(ShimError::Failed(format!(
            "{} has {keys} keys, and the module asked for key {keynum}",
            file.name()
        )));
    }
    at.write(call.mem(), &(keynum as u16).to_le_bytes())
        .map_err(|e| ShimError::Failed(e.to_string()))?;
    Ok(keynum as u16)
}

// `lastkn`'s offset is NOT a constant here any more. It was --
// `pub(crate) const LASTKN: u16 = 142` -- and that second, independent copy of
// a layout `crate::btrieve` already owned is precisely what broke MajorMUD-NT:
// 142 is `lastkn` under the packed 16-bit layout and the *top half of `data`*
// under `DFAAPI.H`'s `GCWINNT` one, so writing a key number through it
// silently truncated the record buffer pointer the module then dereferenced.
// `btrieve::Layout` is the one source; see `BlockAbi` for why there are two
// answers to ask it for.

/// How many bytes of the module's buffer are a key value.
pub(crate) fn key_length<A: Abi>(host: &Host<A>, block: A::Ptr, key: u16) -> Result<u16, ShimError> {
    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    file.keys()
        .get(usize::from(key))
        .map(|k| k.length())
        .ok_or_else(|| {
            ShimError::Failed(format!("{} has no key {key}", file.name()))
        })
}

/// Read a file's records, if this is the first time anything has asked.
///
/// The one place a load happens, so that the one thing worth saying about a
/// freshly loaded file gets said once: how many of its records share a key with
/// their neighbour. That is the only part of the order this host cannot check
/// against the file's own index pages -- see
/// [`Records::ties`](crate::btrieve::Records::ties) -- so it is counted and
/// reported rather than left silent.
///
/// **Skipped entirely on [`Block::fast_reads`].** This used to be
/// unconditional but for `file.loaded().is_some()`, which answers "is
/// `Block::records()` already cached" -- true only until the *next* write,
/// because every insert/update/delete on a fast-path v6 block clears that
/// cache deliberately (`Block::v6_invalidate_keys`), having never needed it
/// in the first place. Every caller of this function (`stpbtvl`/`stpbtv`/
/// `dfaStepLock`, `absolute`, `locate`) now positions through `Block::
/// query`/`Block::step_position`/`Block::cursor_for` instead of `Block::
/// records()`, so nothing downstream of this call needs the populate side
/// effect any more either -- calling it here regardless of `fast_reads`
/// would mean this diagnostic note alone reintroduces the whole-file read
/// on every single write-then-position pair a mass update makes, which is
/// exactly the defect this task found and every other function above this
/// one was fixed to stop making.
pub(crate) fn load<A: Abi>(host: &mut Host<A>, block: A::Ptr) -> Result<(), ShimError> {
    let file = host.btrieve.block_mut(block).map_err(ShimError::Failed)?;
    if file.loaded().is_some() || file.fast_reads() {
        return Ok(());
    }
    let name = file.name().to_owned();
    let records = file.records().map_err(|e| ShimError::Failed(e.to_string()))?;
    let ties: Vec<(u16, usize)> = records
        .ties()
        .iter()
        .enumerate()
        .filter(|(_, tied)| **tied > 0)
        .map(|(key, tied)| (key as u16, *tied))
        .collect();
    for (key, tied) in ties {
        host.note(format!(
            "{name} has {tied} records sharing key {key} with their neighbour, \
             and this host orders those by file position where Btrieve orders \
             them by insertion -- the one part of the order its index pages \
             cannot be checked against"
        ));
    }
    Ok(())
}

/// Delete the record `block` is positioned on, shared by every routine that
/// deletes.
///
/// # Why this is a core and not two bodies
///
/// `delbtv` and `dfaDelete` are one export renamed -- `GALPORT.C`'s own
/// `{"delbtv", "dfaDelete"}` -- and they were two transcriptions of one
/// decision: find the current position, delete it, then invalidate the cursor
/// so a deleted record does not stay reachable as "current"
/// (`crates/btrieve/src/btrcall.rs:576` states that reasoning for the raw
/// opcode-4 path, which is the third transcription).
///
/// The third step is the one that got dropped. `dfaDelete` shipped without it
/// (`ce64fbbe`), so a second `dfaDelete` acted on a freed position, and the
/// only reason `delbtv` was right is that somebody wrote the same decision
/// correctly twice. One core removes the opportunity.
///
/// `who` names the caller in the refusal, because "not positioned on a record"
/// is a real upstream mistake and the module author needs to know which
/// routine saw it.
///
/// # Errors
///
/// Nothing positioned, or an engine refusal from the delete itself.
pub(crate) fn delete_record<A: Abi>(
    host: &mut Host<A>,
    who: &str,
    block: A::Ptr,
) -> Result<(), ShimError> {
    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    let position = file
        .current()
        .ok_or_else(|| {
            ShimError::Failed(format!(
                "{who} on {}, which is not positioned on a record -- opcode 4 \
                 deletes the record the file is positioned on, and nothing has \
                 positioned this one",
                file.name()
            ))
        })?
        .position;

    let file = host.btrieve.block_mut(block).map_err(ShimError::Failed)?;
    file.delete(position).map_err(|e| ShimError::Failed(e.to_string()))?;
    // Never separable from the delete above: see this function's own doc.
    file.seek_to(Cursor::Nowhere);
    Ok(())
}

/// The file position of the record `block` is positioned on.
///
/// Shared by `absbtv` and `dfaAbs`, which `GALPORT.C` names one routine. Both
/// were the same two steps -- read `current()`, refuse if there is none -- and
/// the only difference was where the file came from, so that is the parameter.
///
/// # Errors
///
/// Nothing positioned on a record.
pub(crate) fn current_position<A: Abi>(
    host: &Host<A>,
    who: &str,
    block: A::Ptr,
) -> Result<u32, ShimError> {
    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    let record = file.current().ok_or_else(|| {
        ShimError::Failed(format!("{who} on {}, which is not positioned on a record", file.name()))
    })?;
    Ok(record.position)
}

/// Insert one record into `block`, shared by every routine that inserts.
///
/// `refuse_on_duplicate` is the whole difference between the family's members:
/// `dfaInsertDup`/`dinsbtv` have the vendor's own case-5 branch for a
/// duplicate key and answer false, while `dfaInsertV`/`dfaInsert`/`invbtv`/
/// `insbtv` have no such exception and must not silently discard the write.
///
/// # Why this lives here and not in `shims::dfa`
///
/// Because `btv*` and `dfa*` are the same exports renamed, not two APIs.
/// Galacticomm's own porting tool says so outright -- `SRC/devutils/galport/
/// GALPORT.C:66` is a literal `{"invbtv", "dfaInsertV"}` table covering the
/// whole family -- and `re/ordinal-renames.tsv` shows the pairs sharing one
/// ordinal. This body was written on the `dfa` side first and `invbtv`/`insbtv`
/// sat next to it refusing outright, which is exactly how `dfaDelete` came to
/// drop the cursor invalidation `delbtv` performs (`ce64fbbe`). One insert, one
/// implementation, in the lower of the two modules so the dependency runs
/// `dfa -> btv` the way it already does.
///
/// # Errors
///
/// An unresolvable record pointer, a duplicate key when `refuse_on_duplicate`,
/// or an engine refusal from the write itself.
pub(crate) fn insert_record<A: Abi>(
    call: &mut Call<A>,
    host: &mut Host<A>,
    who: &str,
    block: A::Ptr,
    recptr: A::Ptr,
    length: u16,
    refuse_on_duplicate: bool,
) -> Result<bool, ShimError> {
    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    let recptr = match recptr == Btrieve::<AbiMem<A>>::null() {
        true => file.data(),
        false => recptr,
    };
    let bytes = recptr
        .resolve(call.mem(), usize::from(length))
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    if super::btrieve_traced() {
        let name = host.btrieve.block(block).map_err(ShimError::Failed)?.name().to_owned();
        eprintln!("mbbs-btv: {who} INSERT {name} len={length} bytes={:02x?}", &bytes[..bytes.len().min(16)]);
    }

    if let Some((key, value)) = duplicate_key(host, block, &bytes, None)? {
        let name = host.btrieve.block(block).map_err(ShimError::Failed)?.name().to_owned();
        if refuse_on_duplicate {
            return Err(ShimError::Failed(format!(
                "{who} on {name} collided with an existing record on key {key} \
                 ({value:02x?}), which does not permit duplicates -- unlike \
                 dfaInsertDup's own case-5 branch (DFAAPI.C:637-638), {who}'s underlying \
                 call has no exception for a duplicate, so this refuses instead of \
                 answering false and silently discarding the write"
            )));
        }
        note_duplicate_key(host, who, &name, key, &value);
        return Ok(false);
    }

    let file = host.btrieve.block_mut(block).map_err(ShimError::Failed)?;
    let position = file.insert(&bytes).map_err(|e| ShimError::Failed(e.to_string()))?;
    if super::btrieve_traced() {
        eprintln!("mbbs-btv: {who} INSERT -> position {position}");
    }

    // Currency on the record just inserted, key 0's order -- see
    // [`dinsbtv`]'s own doc comment for why key 0 specifically.
    //
    // `Block::cursor_for` rather than `Block::records()`: the latter
    // materialises this file's *entire* record model regardless of whether
    // `Block::v6_fast_reads` applies, which turned every insert into a
    // whole-file read -- exactly the per-operation cost the page cache
    // exists to avoid paying more than once per open. `cursor_for` rides
    // the same fast path `Block::query`/`Block::step` already do.
    let cursor = file
        .cursor_for(0, position)
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .expect("insert just wrote this position");
    file.seek_to(cursor);
    Ok(true)
}

/// The current file, or `None` if there is none.
///
/// **Not an error.** `PLBTVSTF.C` opens eleven of its routines with
/// `if (bb == NULL) { return 0; }` and each caller knows what its own zero is:
/// an `int` 0, a `long` 0, or nothing at all. So the decision belongs to the
/// caller and this only reports.
///
/// A pointer that is neither null nor a file this host opened *is* a refusal,
/// which is [`setbtv`]'s contract and unrelated to the null case.
pub(crate) fn positioned<A: Abi>(call: &mut Call<A>, host: &Host<A>, who: &str) -> Result<Option<A::Ptr>, ShimError> {
    let block = current(call, host)?;
    if block == Btrieve::<AbiMem<A>>::null() {
        return Ok(None);
    }
    host.btrieve
        .block(block)
        .map_err(|e| ShimError::Failed(format!("{who}: {e}")))?;
    Ok(Some(block))
}

/// Say once that a routine was asked something with no Btrieve file current.
///
/// Answering 0 is what the real host did, and it is also what an upstream
/// mistake looks like -- a `rstbtv` too many, a `setbtv` of something that was
/// never opened. This is neither an answer nor a refusal: it does not stop the
/// module, and a test can assert on it.
///
/// Once per routine. `obtbtvl` inside a loop would otherwise fill
/// [`Host::notes`](crate::Host::notes) with thousands of identical lines.
pub(crate) fn note_no_file<A: Abi>(host: &mut Host<A>, who: &str) {
    host.note_once(
        who,
        format!(
            "{who} with no Btrieve file current, answered as PLBTVSTF.C does \
             -- nothing found. A null bb is legitimate, and is also what a \
             rstbtv too many leaves behind"
        ),
    );
}

/// Where `bb->data` points, for a file the caller has already established.
pub(crate) fn data_buffer<A: Abi>(host: &Host<A>, block: A::Ptr) -> Result<A::Ptr, ShimError> {
    Ok(host
        .btrieve
        .block(block)
        .map_err(ShimError::Failed)?
        .data())
}

/// Take `lock` at `block`'s current position, once `locate`/`absolute`/
/// `stpbtvl` have already positioned it there.
///
/// # Task 5, reversed
///
/// `docs/plans/2026-08-12-btrieve-finish.md` Task 5 first answered "do not
/// build this": all **191** lock-capable call sites in `WCCMMUD.DLL` --
/// `obtbtvl` 112, `gabbtv`/`gabbtvl` 34, `stpbtvl` 45 -- push a literal zero
/// for `loktyp`, established twice by methods sharing no code. **The
/// repository owner reversed that**: "we're not going to skip over
/// implementing functionality because wccmmud won't need it." A routine
/// with no counterpart at all is a legitimate empty slot; a routine that
/// exists and is merely unexercised by the one module under test is not,
/// and locks were the second kind. `crates/mbbs/src/btrieve/ops.rs`'s own
/// "Locking" module doc section is the full account, including what stays
/// out of scope and why (cross-client conflict, statuses 84/85 -- a
/// deferral, not an absence) and the one thing measured but deliberately
/// not reproduced (a wait-lock inside a transaction deadlocking the real
/// engine).
///
/// This function is now a thin call into [`crate::btrieve::Btrieve::
/// take_lock`], which delegates to [`crate::btrieve::ops::LockTable::
/// acquire`] -- the actual state machine, ABI-independent and tested on its
/// own in `ops.rs`. `lock == 0` is always `Ok(())`.
///
/// # This function must run only after positioning has already succeeded
///
/// Every caller places this after its own `seek_to`, never before -- moving
/// it earlier would take a lock ahead of knowing whether a record was even
/// found, contradicting the measured "an operation that fails takes no
/// lock". This mirrors [`crate::btrieve::ops::Block::get`]'s own ordering
/// exactly, and for the same reason.
///
/// # The two by-value pins this replaces
///
/// The refusal this function used to be was load-bearing for
/// `a_lock_this_host_cannot_take_is_refused_rather_than_ignored` (`obtbtvl`'s
/// lock word, by value) and `gabbtvl_takes_its_lock_from_word_five_by_value`
/// (`gabbtvl`'s word 5, by value). Both are re-pinned below on the new
/// observable this function creates -- a lock is now readable state, so each
/// asserts "the engine recorded this lock type at this position" rather than
/// "the call was refused naming this lock type". Same words, same
/// discrimination by value, checked the hard way (mutate the shim to read
/// the adjacent word, confirm the test fails) -- see each test's own doc
/// comment.
pub(crate) fn take_lock<A: Abi>(host: &mut Host<A>, block: A::Ptr, lock: i16) -> Result<(), ShimError> {
    host.btrieve.take_lock(block, lock).map_err(ShimError::Failed)
}

/// Push what is current and make `block` current, as `setbtv` does.
fn push<A: Abi>(call: &mut Call<A>, host: &mut Host<A>, block: A::Ptr) -> Result<(), ShimError> {
    let previous = current(call, host)?;
    if let Some(dropped) = host.btrieve.set(previous) {
        // `note_once`, not `note`. This overflow is not a fault: the stack is
        // ten deep and shifts, and reproducing that is the whole point of the
        // "matching the original beats refusing" section at the top of this
        // file. A module built against the limit hits it continuously -- one
        // measured session into the Realm recorded 4,962 of this one note --
        // so reporting every occurrence buries every other note the host has
        // to make. Once per run says the same thing.
        //
        // The key is the condition, not the message, so the FIRST file to
        // fall off names itself and later ones stay silent. That is
        // `note_once`'s documented behaviour and it is the right trade here:
        // which file was dropped is a detail of a defined, expected outcome,
        // and a caller who needs the full sequence wants `Btrieve::set`'s
        // return value, not the note channel.
        //
        // Not the bare routine name, which is what `note_no_file` keys on for
        // every other routine in this file. `setbtv` is not in that set today
        // -- it is the routine that makes a file current, so it has no
        // "no file current" case -- but two unrelated conditions sharing one
        // key would mean the first to fire silences the other, and that is a
        // trap to design out rather than to rely on staying true.
        host.note_once(
            "setbtv-overflow",
            format!(
                "the setbtv stack is ten deep and overflowed, so {dropped} fell off \
                 the bottom -- exactly as it would have on the real host (reported \
                 once per run; it recurs by design)"
            ),
        );
    }
    set_current(call, host, block)
}

/// What `bb` holds, read back out of module memory every time.
fn current<A: Abi>(call: &mut Call<A>, host: &Host<A>) -> Result<A::Ptr, ShimError> {
    host.globals()
        .pointer_mem(call.mem(), "bb")
        .map_err(|e| ShimError::Failed(e.to_string()))
}

fn set_current<A: Abi>(call: &mut Call<A>, host: &Host<A>, block: A::Ptr) -> Result<(), ShimError> {
    host.globals()
        .write_mem(call.mem(), "bb", &A::ptr_to_bytes(block))
        .map_err(|e| ShimError::Failed(e.to_string()))
}

// ---------------------------------------------------------------------------
// The eight plain routines below (`getbtv`, `obtbtv`, `anpbtv`, `gabbtv`,
// `stpbtv`, `updbtv`, `upvbtv`, `insbtv`) round out `BTVSTF.H:144-164`.
// `WCCMMUD.DLL` imports none of them -- `re/exports/imports.txt` has no
// entry for any of the eight, unlike every routine above this point, which
// was implemented because the module calls it. These are implemented
// anyway, on the same standing instruction [`take_lock`]'s own doc comment
// records: a routine that exists in `PLBTVSTF.C` is not skipped merely
// because the one module under test does not reach it.
//
// Four of the eight (`obtbtv`, `stpbtv`, `gabbtv`, and `anpbtv`, in the loose
// sense that its ancestor `anpbtvlk` calls `obtbtvl`) are pure tail calls in
// the vendor source onto an "l" sibling already implemented above, fixing
// `loktyp` at 0 -- the same shape [`aabbtv`] is to [`gabbtvl`]. The other
// four (`getbtv`, `updbtv`, `upvbtv`, `insbtv`) have no implemented "l"
// sibling to call through: `getbtvl` and `anpbtvlk` are named but not built
// in this file (see the module doc comment's "remaining five guards"
// section), and `updbtv`/`insbtv` are themselves the tail calls (onto
// `upvbtv`/`invbtv`), not routines with siblings at all.

/// `void getbtv(void *recptr, void *key, int keynum, int getopt)` -- get a
/// record by key, or stop.
///
/// `PLBTVSTF.C:300-308` is a pure tail call fixing `loktyp` at 0:
///
/// `getbtvl` (`:310-337`) is not implemented elsewhere in this file -- see
/// the module doc comment's "remaining five guards" list, which already
/// named it (`:318`) as one of the routines this host does not build. This
/// is that routine's body, with `loktyp` fixed the way `getbtv` fixes it,
/// four words rather than five -- the same shape `obtbtv` (below) is to the
/// already-implemented [`obtbtvl`].
///
/// # `getbtv` is `obtbtvl`'s twin with one convention inverted
///
/// `getbtvl` (`:310-337`) and `obtbtvl` (`:349-380`) read their five
/// arguments identically, copy the key the same way, resolve `keynum` the
/// same way, and issue the same underlying Btrieve call
/// (`(*btvuptr)(getopt+loktyp,...)` vs `(*btvuptr)(obtopt+loktyp,...)`,
/// same opcode range 5-13). **They diverge in exactly one place**, and nowhere
/// else:
///
/// `obtbtvl` treats "no such key" (status 4), "end of file" (status 9) and a
/// lock conflict (`wslbtv()`) as legitimate answers and returns 0 without
/// ever reaching `posbtverr`. `getbtvl` has no such case: **every** nonzero
/// status, not-found included, goes straight to `posbtverr`, which
/// `catastro`s unless the status is specifically 22 (a too-short buffer,
/// unrelated to whether a record was found). So a module written against
/// `getbtv` is entitled to assume the record is there; one written against
/// `obtbtv` is not. That is the whole of the difference between the "Get"
/// and "Obtain/Acquire" families this header groups by name, and it is why
/// [`locate`]'s `false` becomes a refusal here and a quiet 0 in [`obtbtv`].
///
/// # `bb == NULL` is still the quiet case
///
/// `:318-320` guards exactly like every other routine that has no record to
/// answer about: nothing found, nothing refused, nothing written. That part
/// of the convention is shared with `obtbtvl`; only the *found-a-file, still
/// no record* case differs.
pub fn getbtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let Some(block) = positioned(call, host, "getbtv")? else {
        note_no_file(host, "getbtv");
        return Ok(abi::Ret::Void);
    };

    let into = call.ptr();
    let value = call.ptr();
    let keynum = i16_arg::<A>(call.int());
    let opt = i16_arg::<A>(call.int());

    let op = Op::of(opt).ok_or_else(|| {
        ShimError::Failed(format!(
            "getbtv with option {opt}, which is none of the nine BTVSTF.H's g-macros produce"
        ))
    })?;
    let into = match into == Btrieve::<AbiMem<A>>::null() {
        true => data_buffer(host, block)?,
        false => into,
    };
    let found = locate(
        call,
        host,
        Request {
            who: "getbtv",
            block,
            op,
            keynum,
            value,
            into: Some(into),
            lock: 0,
        },
    )?;
    if !found {
        let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
        return Err(ShimError::Failed(format!(
            "getbtv found no record in {} -- PLBTVSTF.C:333-335 sends any \
             nonzero status straight to posbtverr(\"GET\"), unlike obtbtvl's \
             status-4/9/wslbtv special case (:373), so this refuses instead \
             of answering 0",
            file.name()
        )));
    }
    Ok(abi::Ret::Void)
}

/// `int obtbtv(void *recptr, void *key, int keynum, int obtopt)` -- acquire
/// a record by key.
///
/// `PLBTVSTF.C:339-347`:
///
/// A pure tail call fixing `loktyp` at 0 -- four words rather than
/// [`obtbtvl`]'s five, the same shape [`aabbtv`] is to [`gabbtvl`]. Every
/// other line of this function is [`obtbtvl`]'s own body, because `:357-379`
/// is unconditionally what `obtbtv` calls, with `loktyp` never present to
/// read.
///
/// Same error convention as `obtbtvl`: `bb == NULL` and a not-found key
/// (status 4/9, or a lock conflict) both answer 0 rather than refusing --
/// see [`getbtv`]'s doc comment for why `getbtv` does not get to make the
/// same claim.
pub fn obtbtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let Some(block) = positioned(call, host, "obtbtv")? else {
        note_no_file(host, "obtbtv");
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    };

    let into = call.ptr();
    let value = call.ptr();
    let keynum = i16_arg::<A>(call.int());
    let opt = i16_arg::<A>(call.int());

    let op = Op::of(opt).ok_or_else(|| {
        ShimError::Failed(format!(
            "obtbtv with option {opt}, which is none of the nine BTVSTF.H's a-macros produce"
        ))
    })?;
    let into = match into == Btrieve::<AbiMem<A>>::null() {
        true => data_buffer(host, block)?,
        false => into,
    };
    Ok(abi::Ret::Int(A::Int::from(u16::from(locate(
        call,
        host,
        Request {
            who: "obtbtv",
            block,
            op,
            keynum,
            value,
            into: Some(into),
            lock: 0,
        },
    )?))))
}

/// `int anpbtv(void *recptr, int anpopt)` -- step to the next/previous
/// record and say whether it is still in the same key group.
///
/// `PLBTVSTF.C:382-388`:
///
/// A pure tail call fixing `chkcas` at 1 (case-sensitive) and `loktyp` at 0.
/// `anpbtvl`/`anpbtvlk` -- the routines that let either vary -- are neither
/// asked for by this task nor implemented separately in this file (the
/// module doc comment's "remaining five guards" section already named
/// `anpbtvlk` at `:406`); this is `anpbtvlk`'s body with both fixed.
///
/// # What `anpbtvlk` does, per `PLBTVSTF.C:399-415`
///
/// It saves the *current* key value into `bb->data` -- borrowing the record
/// buffer as scratch, before the step below can touch it -- then steps with
/// [`obtbtvl`]'s own semantics: `recptr` may default to `bb->data`, the key
/// argument is `NULL` so nothing is written to `bb->key` on the way in, and
/// the key number is -1 so the step continues in whichever key `bb->lastkn`
/// already names. A successful step refreshes `bb->key` with the record it
/// landed on -- [`answer_with_key`], same as every other read op -- so the
/// final comparison is "does the key of the record we just stepped to match
/// the key we were on before the step", which is how `WCCMMUD.DLL` would
/// walk a group of same-keyed records and learn when it has walked off the
/// end of it, if it called this at all.
///
/// **If `recptr` is null, the comparison is not what it looks like.**
/// `obtbtvl` then defaults its own `recptr` to `bb->data` too, and delivers
/// the newly found record there -- overwriting the old-key scratch this
/// routine just wrote, before the comparison reads it. That makes the
/// comparison "does the new record start with the same bytes as its own
/// key", which agrees with the group-boundary check only when the key sits
/// at the record's own first bytes. Reproduced rather than corrected: it is
/// the order `PLBTVSTF.C` runs in, not a bug this host gets to fix.
///
/// # `bb == NULL` is the quiet 0, same as `obtbtvl`
///
/// `:406-408` is exactly `obtbtvl`'s own guard, read the same way here --
/// [`positioned`]/[`note_no_file`], answering 0 rather than refusing. A step
/// that finds no record is the same quiet 0, because `anpbtvlk` only ever
/// forwards `obtbtvl`'s own return in that case ([`locate`] returning
/// `false`) -- there is nothing left to compare.
///
/// # The `strcmp`, bounded
///
/// Real `strcmp` scans as far as it must to find a NUL in either operand,
/// with no length limit. This host has no undefined memory on the other
/// side of either buffer to scan into, so [`strcmp_eq`] is bounded to the
/// key's own length -- `bb->keylns[bb->lastkn]`, the same span `:409`'s own
/// `movmem` used to write the scratch copy in the first place -- and
/// compares C-string-style within that span. A key that legitimately holds
/// no NUL before that boundary is compared as a fixed-length buffer, which
/// is what `strcmp` would also have done as long as the byte immediately
/// past it was not itself where the two diverged; reading past a buffer this
/// host does not own is exactly the case "runtime crashes are better than
/// undefined behaviour" rules out, so this stops at the boundary instead of
/// guessing what lies beyond it.
pub fn anpbtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let recptr = call.ptr();
    let anpopt = i16_arg::<A>(call.int());

    let Some(block) = positioned(call, host, "anpbtv")? else {
        note_no_file(host, "anpbtv");
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    };

    // `:409` -- `movmem(bb->key,bb->data,bb->keylns[bb->lastkn])`, read
    // before the step below can overwrite either buffer.
    let key = key_number(call, host, block, -1)?;
    let key_len = key_length(host, block, key)?;
    let key_buffer = host.btrieve.block(block).map_err(ShimError::Failed)?.key();
    let old = key_buffer
        .resolve(call.mem(), usize::from(key_len))
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let data_buf = data_buffer(host, block)?;
    data_buf
        .write(call.mem(), &old)
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    // `:410` -- `obtbtvl(recptr,NULL,-1,anpopt,loktyp)`, `loktyp` fixed at 0
    // by `anpbtv`'s own `:387` tail call.
    let op = Op::of(anpopt).ok_or_else(|| {
        ShimError::Failed(format!("anpbtv with option {anpopt}, which is not a get operation"))
    })?;
    let into = match recptr == Btrieve::<AbiMem<A>>::null() {
        true => data_buffer(host, block)?,
        false => recptr,
    };
    let found = locate(
        call,
        host,
        Request {
            who: "anpbtv",
            block,
            op,
            keynum: -1,
            value: Btrieve::<AbiMem<A>>::null(),
            into: Some(into),
            lock: 0,
        },
    )?;
    if !found {
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    }

    // `:411-412` -- compare the scratch copy against the key the step just
    // refreshed. Read fresh, not from `old`/`into` above: if `recptr` was
    // null, the step just overwrote what was saved at `bb->data` -- see this
    // routine's own doc comment on why that is reproduced, not corrected.
    let data_buf = data_buffer(host, block)?;
    let now = data_buf
        .resolve(call.mem(), usize::from(key_len))
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let key_buffer = host.btrieve.block(block).map_err(ShimError::Failed)?.key();
    let landed = key_buffer
        .resolve(call.mem(), usize::from(key_len))
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    Ok(abi::Ret::Int(A::Int::from(u16::from(strcmp_eq(&now, &landed)))))
}

/// Compare two byte buffers the way C's `strcmp` compares two NUL-terminated
/// strings: byte-for-byte up to the first NUL in either, with a shorter
/// terminated prefix unequal to a longer one that only agrees up to that
/// point. See [`anpbtv`]'s own doc comment for why the scan is bounded to
/// `a`/`b`'s own length instead of following C's convention of continuing
/// arbitrarily far past it.
pub(crate) fn strcmp_eq(a: &[u8], b: &[u8]) -> bool {
    let a = match a.iter().position(|&byte| byte == 0) {
        Some(nul) => &a[..nul],
        None => a,
    };
    let b = match b.iter().position(|&byte| byte == 0) {
        Some(nul) => &b[..nul],
        None => b,
    };
    a == b
}

/// `void gabbtv(void *recptr, long abspos, int keynum)` -- get the record at
/// a file position, or stop.
///
/// `PLBTVSTF.C:436-443`:
///
/// A pure tail call fixing `loktyp` at 0 -- three words, not [`gabbtvl`]'s
/// four, the same shape [`aabbtv`] is to `gabbtvl` itself (see that
/// routine's own doc comment for why a four-word cursor cannot be shared
/// with a three-word caller). Unlike `aabbtv`, though, `gabbtv` keeps
/// `gabbtvl`'s `fatal: true`: a position that names no record is a refusal
/// here exactly as it is for `gabbtvl`, and the only thing `gabbtv` changes
/// is `loktyp`.
///
/// `re/exports/imports.txt` has no `gabbtv` entry -- `WCCMMUD.DLL` imports
/// `gabbtvl` (34 sites) and not this. `re/ordinal_map.tsv`'s `gabbtv` row
/// (ordinal 999) is that tooling's own placeholder for a symbol it could not
/// map to a real export, not evidence of a genuine import. Implemented
/// anyway, on the same standing instruction [`take_lock`]'s own doc comment
/// records.
pub fn gabbtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let into = call.ptr();
    let position = call.long();
    let keynum = i16_arg::<A>(call.int());
    // `absolute` no longer looks the file up itself -- the `dfa*`
    // spelling of this routine finds it a different way. Same guard as
    // before, in the caller that owns it.
    let Some(block) = positioned(call, host, "gabbtv")? else {
        note_no_file(host, "gabbtv");
        return Ok(abi::Ret::Void);
    };
    absolute(
        call,
        host,
        Position {
            who: "gabbtv",
            block,
            negative_keynum: NegativeKey::Note,
            fatal: true,
            lock: UNLOCKED,
            into,
            position,
            keynum,
        },
    )?;
    Ok(abi::Ret::Void)
}

/// `int stpbtv(void *recptr, int stpopt)` -- walk the file in the order the
/// pages hold it, or stop.
///
/// `PLBTVSTF.C:495-501`:
///
/// A pure tail call fixing `loktyp` at 0 -- two words rather than
/// [`stpbtvl`]'s three. Duplicated rather than shared through a common
/// helper: `stpbtvl` (`:503-522`) is one function with no separable core the
/// way `obtbtvl`/`getbtv` share [`locate`] or `aabbtv`/`gabbtvl` share
/// [`absolute`], and this task's own instructions are to append rather than
/// restructure an existing, already-tested routine. What follows is
/// `stpbtvl`'s body verbatim with `lock` replaced by the literal 0 `stpbtv`
/// supplies instead of a sixth argument.
///
/// # No guard, same as `stpbtvl`
///
/// `stpbtv` itself does not check `bb` before tail-calling `stpbtvl`, and
/// `stpbtvl`'s own `:504-511` has no guard either -- it dereferences `bb`
/// twice (`bb->data`, `bb->reclen`) before anything is checked. A real board
/// that stepped with no file current faulted there, so this refuses by name
/// rather than reproducing the fault -- exactly [`stpbtvl`]'s own doc
/// comment's reasoning, one level removed.
pub fn stpbtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let block = positioned(call, host, "stpbtv")?.ok_or_else(|| {
        ShimError::Failed(
            "stpbtv with no Btrieve file current -- PLBTVSTF.C:495-501 tail-calls \
             stpbtvl, whose :504-511 has no guard and dereferences bb twice, so \
             the real host faulted here rather than answering"
                .to_owned(),
        )
    })?;

    let into = call.ptr();
    let opt = i16_arg::<A>(call.int());
    let into = match into == Btrieve::<AbiMem<A>>::null() {
        true => data_buffer(host, block)?,
        false => into,
    };

    // Same four codes `stpbtvl` parses -- see that routine's own doc
    // comment.
    let step = match opt {
        33 => Step::First,
        34 => Step::Last,
        24 => Step::Next,
        35 => Step::Previous,
        _ => {
            return Err(ShimError::Failed(format!(
                "stpbtv with option {opt}, which is none of 24, 33, 34 and 35"
            )));
        }
    };

    load(host, block)?;
    let file = host.btrieve.block_mut(block).map_err(ShimError::Failed)?;
    let name = file.name().to_owned();

    // `Block::step_position` -- see `stpbtvl`'s own doc comment for why,
    // not `Block::records()`. `stpbtv` is unreachable for MajorMUD
    // (`WCCMMUD.DLL` imports none of the eight plain routines this one
    // belongs to), but it is the identical bug either way, and it is no
    // longer a hand-duplicated body once both routines share the engine's
    // own positioning.
    let at = file
        .step_position(step)
        .map_err(|e| ShimError::Failed(format!("stpbtv({opt}) on {name}: {e}")))?;
    if at.is_none() {
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    }
    take_lock(host, block, 0)?;
    deliver(call, host, block, into)?;
    Ok(abi::Ret::Int(A::Int::from(1u16)))
}

/// `void updbtv(void *recptr)` -- update the record the file is positioned
/// on, at the module's own record length.
///
/// `PLBTVSTF.C:524-529`:
///
/// # No guard of its own, and it reads `bb` before `upvbtv` ever checks it
///
/// `:528` is `bb->reclen` -- a dereference of `bb`, evaluated to build
/// `upvbtv`'s second argument, **before control ever reaches `upvbtv`'s own
/// `:536-538` guard**. A real board with no file current faulted right here,
/// the same shape [`dinsbtv`]/[`dupdbtv`] read `bb->reclen` unguarded, and
/// unlike [`upvbtv`] itself (whose *own* guard this host does honour once
/// it is reached) or [`insbtv`]/`invbtv`'s quiet no-op. So this refuses by
/// name on a missing file rather than delegating to `upvbtv`'s ordinarily
/// quiet convention, which never gets the chance to run.
///
/// # Once a file is current, this is `upvbtv`'s own write
///
/// `length` is `bb->reclen` -- [`Block::maxlen`](crate::btrieve::Block::maxlen),
/// the module's own declared record length, the same number [`dinsbtv`] and
/// [`dupdbtv`] use. Everything past that point is [`update_variable`], the
/// body `upvbtv` and `updbtv` share -- see that function's doc comment for
/// the write itself and its error convention.
pub fn updbtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let recptr = call.ptr();
    let block = positioned(call, host, "updbtv")?.ok_or_else(|| {
        ShimError::Failed(
            "updbtv with no Btrieve file current -- PLBTVSTF.C:528 reads \
             bb->reclen with no guard of its own, before upvbtv's own guard \
             at :536 is ever reached, so the real host faulted here rather \
             than answering"
                .to_owned(),
        )
    })?;
    let length = host.btrieve.block(block).map_err(ShimError::Failed)?.maxlen();
    update_variable(call, host, "updbtv", block, recptr, length, false)?;
    Ok(abi::Ret::Void)
}

/// `void upvbtv(void *recptr, int length)` -- update the record the file is
/// positioned on, at a module-supplied length.
///
/// `PLBTVSTF.C:531-547`, quoted in full:
///
/// # `bb == NULL` is the quiet no-op, same as `invbtv`/`delbtv`
///
/// `:536-538` answers nothing with no file current -- [`positioned`]/
/// [`note_no_file`], same convention as [`invbtv`]/[`delbtv`], and unlike
/// [`dinsbtv`]/[`dupdbtv`]'s unguarded fault. `upvbtv` itself is the one
/// with the guard; it is `updbtv` (above), reading `bb->reclen` before ever
/// calling this, that does not have one.
///
/// # Opcode 3, same as `dupdbtv` -- and the one place the two disagree
///
/// `:544` is `(*btvuptr)(3,gpbseg,bb->keyseg,bb->lastkn,length)`, the
/// identical Btrieve call [`dupdbtv`] makes at its own `:561`. **The
/// difference is what happens to a nonzero status.** `dupdbtv`'s `:561-569`
/// switches on it: 0 succeeds, 5 (a duplicate-key violation) answers 0
/// quietly, anything else `catastro`s. `upvbtv`'s `:544-546` has no switch
/// at all -- **every** nonzero status, duplicate-key included, goes straight
/// to `(*btverrptr)("UPDATE")`. So a module that collides on a key without
/// duplicates gets a discarded write and a running program from `dupdbtv`,
/// and a stopped one from `upvbtv`. [`update_variable`] is what this and
/// [`updbtv`] share, and it refuses on that collision rather than answering
/// 0, for exactly this reason -- see its own doc comment.
///
/// # Length is the module's, not necessarily the file's
///
/// Unlike `dupdbtv`/`dinsbtv`, which always use `bb->reclen`, `upvbtv` takes
/// `length` as an argument -- this is the "variable-length" member of the
/// pair, per its own name. [`Block::update`](crate::btrieve::Block::update)
/// still refuses a buffer that is not exactly the file's own `reclen`, per
/// [`dupdbtv`]'s own doc comment on why this host does not write
/// variable-length records at all; a `length` that does not match is
/// refused there rather than accepted here, so nothing above duplicates that
/// check.
///
/// `int`, per `BTVSTF.H:160` -- signed in the declaration, but read the way
/// [`opnbtv`]'s `maxlen` is (via [`u16_arg`]) rather than [`i16_arg`]:
/// `length` flows into exactly the same "how many bytes" role `maxlen` does
/// (`maksur(length)`, `movmem(...,length)`, and the Btrieve call's own `rlen`
/// argument), never a value that is compared or branched on as negative, so
/// this refuses rather than reinterprets a value that would not fit as a
/// byte count.
///
/// # Arity, measured
///
/// `re/ne_arity.py 622 <WCCMMPLS.DLL>` finds 2 call sites; one cleans three
/// words (`68 c0 03; 6a 00; 6a 00` -- push `length=0x3c0`, push a far-null
/// `recptr` -- then `add sp,6`), matching `(void *, int)` exactly and the
/// vendor's own `upvbtv(NULL,length)` idiom seen throughout `GALFILU.C`/
/// `GALFILCS.C`. The other cleans nothing directly after the call because
/// control leaves through an unconditional `jmp` to a shared cleanup point a
/// few bytes on (`eb 13`) rather than falling through to one -- the deferred
/// case that tool's own module doc comment names, not a second arity. `622`
/// is `_UPVBTV`'s ordinal in `crates/mbbs/data/majorbbs_wg101.tsv`.
pub fn upvbtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let recptr = call.ptr();
    let length = u16_arg::<A>(call.int(), "upvbtv")?;

    let Some(block) = positioned(call, host, "upvbtv")? else {
        note_no_file(host, "upvbtv");
        return Ok(abi::Ret::Void);
    };
    update_variable(call, host, "upvbtv", block, recptr, length, false)?;
    Ok(abi::Ret::Void)
}

/// The write [`upvbtv`] and [`updbtv`] share: opcode 3 at a module-supplied
/// length, on the record the file is positioned on, refusing rather than
/// quietly discarding a duplicate-key collision.
///
/// This is [`dupdbtv`]'s own body (`:601-736`'s update path -- resolve the
/// buffer, check every non-duplicate-permitting key, write, re-derive
/// currency) with one change: where `dupdbtv` answers a collision with a
/// quiet `0`, this refuses. See [`upvbtv`]'s own doc comment for why that
/// difference is the vendor's, not this host's invention -- `:544-546` has
/// no `case 5` branch at all, unlike `dupdbtv`'s `:564-565`.
///
/// `who` and `block` are the caller's, already past its own `bb == NULL`
/// question (`upvbtv`'s own guard, or `updbtv`'s refusal on the unguarded
/// dereference that precedes this). `length` is `upvbtv`'s own argument or
/// `updbtv`'s `bb->reclen` -- either way, the number of bytes this call
/// resolves out of `recptr` and hands to
/// [`Block::update`](crate::btrieve::Block::update), which is the one place
/// that number is actually checked against the file's own record length.
pub(crate) fn update_variable<A: Abi>(
    call: &mut Call<A>,
    host: &mut Host<A>,
    who: &str,
    block: A::Ptr,
    recptr: A::Ptr,
    length: u16,
    tolerate_duplicate: bool,
) -> Result<bool, ShimError> {
    let recptr = match recptr == Btrieve::<AbiMem<A>>::null() {
        true => data_buffer(host, block)?,
        false => recptr,
    };
    let bytes = recptr
        .resolve(call.mem(), usize::from(length))
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    let position = file
        .current()
        .ok_or_else(|| {
            ShimError::Failed(format!(
                "{who} on {}, which is not positioned on a record -- opcode 3 \
                 updates the record the file is positioned on, and nothing has \
                 positioned this one",
                file.name()
            ))
        })?
        .position;
    if super::btrieve_traced() {
        eprintln!(
            "mbbs-btv: {who} UPDATE {} position {position} len={length}",
            file.name(),
        );
    }

    if let Some((key, value)) = duplicate_key(host, block, &bytes, Some(position))? {
        let name = host.btrieve.block(block).map_err(ShimError::Failed)?.name().to_owned();
        // `tolerate_duplicate` is the whole difference between this family's
        // members, and it is the `d` in `dupdbtv`/`dfaUpdateDup`:
        // `PLBTVSTF.C:564-565` is their case-5 branch, answering 0 rather than
        // reporting. Everyone else -- `upvbtv`'s own `:544-546` -- sends every
        // nonzero status to `btverrptr("UPDATE")` with no exception for a
        // duplicate, so refusing is what they must do rather than answer 0 and
        // silently discard the write.
        if !tolerate_duplicate {
            return Err(ShimError::Failed(format!(
                "{who} on {name} collided with an existing record on key {key} \
                 ({value:02x?}), which does not permit duplicates"
            )));
        }
        note_duplicate_key(host, who, &name, key, &value);
        return Ok(false);
    }

    let file = host.btrieve.block_mut(block).map_err(ShimError::Failed)?;
    file.update(position, &bytes).map_err(|e| ShimError::Failed(e.to_string()))?;

    // Currency maintenance, identical to `dupdbtv`'s own tail -- see that
    // routine's doc comment for why a keyed cursor is re-derived rather than
    // carried forward, and why `Physical` needs no correction.
    //
    // Both keyed cursors: `Cursor::Ordered` is v5's rank (which the update's
    // key change may have shifted); `Cursor::Positioned` is v6's position
    // (stable across a fixed-length update, so this re-derivation is a no-op
    // for it, but kept uniform). `Block::cursor_for` rather than
    // `Block::records()`: see `insert_record`'s identical tail for why -- the
    // same whole-file read this update's own `duplicate_key` call above no
    // longer pays for either.
    let keyed = match file.cursor() {
        Cursor::Ordered { key, .. } | Cursor::Positioned { key, .. } => Some(key),
        Cursor::Physical { .. } | Cursor::Nowhere => None,
    };
    if let Some(key) = keyed {
        let cursor = file
            .cursor_for(key, position)
            .map_err(|e| ShimError::Failed(e.to_string()))?
            .expect("update just wrote this position");
        file.seek_to(cursor);
    }
    Ok(true)
}

/// `void insbtv(void *recptr)` -- insert a new record, at the module's own
/// record length.
///
/// `PLBTVSTF.C:572-577`:
///
/// # No guard of its own, and it reads `bb` before `invbtv` ever checks it
///
/// `:576` is `bb->reclen`, a dereference of `bb` evaluated to build
/// `invbtv`'s second argument, **before control ever reaches [`invbtv`]'s
/// own `:584-586` guard** -- the identical shape [`updbtv`] has relative to
/// [`upvbtv`], and for the identical reason: a real board with no file
/// current faulted right here, rather than reaching `invbtv`'s ordinarily
/// quiet no-op. So this refuses by name on a missing file, where `invbtv`
/// called directly answers nothing.
///
/// # With a file current, this is `invbtv`'s own refusal
///
/// `recptr` is read and discarded rather than resolved: [`invbtv`] itself
/// -- the routine this tail-calls, once a file is known current -- never
/// reads `recptr` or `length` either, because it refuses unconditionally
/// once `bb` is non-null (nothing in this host writes a variable-length
/// insert; see `invbtv`'s own doc comment). Resolving `recptr`'s bytes first
/// would risk failing on a bad pointer *before* naming the real reason this
/// call cannot succeed, which is a worse error for the same outcome.
pub fn insbtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let recptr = call.ptr();
    let block = positioned(call, host, "insbtv")?.ok_or_else(|| {
        ShimError::Failed(
            "insbtv with no Btrieve file current -- PLBTVSTF.C:576 reads \
             bb->reclen with no guard of its own, before invbtv's own guard \
             at :584 is ever reached, so the real host faulted here rather \
             than answering"
                .to_owned(),
        )
    })?;
    // `PLBTVSTF.C:576`: `insbtv(recptr)` IS `invbtv(recptr, bb->reclen)`. The
    // length this host uses for that is `maxlen`, the same one `dinsbtv` reads
    // for the identical reason.
    let length = host.btrieve.block(block).map_err(ShimError::Failed)?.maxlen();
    insert_record(call, host, "insbtv", block, recptr, length, true)?;
    Ok(abi::Ret::Void)
}

// ---------------------------------------------------------------------------
// Task 3 (docs/plans/2026-08-15-host-api-surface-track-b.md): `bxabtv`/
// `exabtv`, thin wrappers over the transaction engine `Btrieve::begin`/
// `Btrieve::end` already implement, reached today by the registered
// `dfaBegTrans`/`dfaEndTrans`. Neither is declared in MajorBBS 6.25's
// `BTVSTF.H` at all -- Worldgroup 1.0's `BTVSTF.H:140-141` is the only
// recovered generation that has them, and its `PLBTVSTF.C` the only one
// with bodies.
// ---------------------------------------------------------------------------

/// `void bxabtv(int loktyp)` -- begin a Btrieve transaction.
///
/// `PLBTVSTF.C:239-246` (Worldgroup 1.0 only; not declared in MajorBBS
/// 6.25's `BTVSTF.H` at all), quoted in full:
///
/// Op 19 plus `loktyp` -- `WAITBV` (0) or `NOWTBV` (200), `BTVSTF.H:48-49`
/// -- exactly matches `dfaBegTrans`'s own `19+loktyp` (`shims/dfa.rs`,
/// citing `DFAAPI.C:201-209`), and both reach the identical
/// [`crate::btrieve::Btrieve::begin`]. **This task's own instruction is
/// that they must agree, not each invent an answer** -- two wrappers over
/// one engine disagreeing about the same state would be worse than either
/// choice alone. `loktyp` is read and discarded for the identical reason
/// `dfaBegTrans` discards it: `Btrieve::begin`'s own doc comment records
/// that the real engine showed no observable difference between `WAITBV`
/// and `NOWTBV` with a single client (`xactprobe`'s `loktyp` scenario), and
/// this host is single-process and single-threaded by construction, so
/// there is never a second session to wait on or not.
///
/// A nonzero status here goes to `(*btverrptr)("BEGIN-XACTION")`, a
/// `catastro` -- the identical fate `dfaBegTrans`'s own `ShimError`
/// produces for [`TransactionError::AlreadyActive`](crate::btrieve::TransactionError),
/// so a begin-while-open stops the module here exactly as it does through
/// `dfaBegTrans`.
pub fn bxabtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let _loktyp = i16_arg::<A>(call.int());
    host.btrieve
        .begin()
        .map_err(|e| ShimError::Failed(format!("bxabtv: {e}")))?;
    Ok(abi::Ret::Void)
}

/// `void exabtv(void)` -- end (commit) the current Btrieve transaction,
/// keeping every write made since [`bxabtv`].
///
/// `PLBTVSTF.C:248-254` (Worldgroup 1.0 only; same generation gap as
/// [`bxabtv`]), quoted in full:
///
/// Op 20, no arguments -- exactly `dfaEndTrans` (`shims/dfa.rs`, citing
/// `DFAAPI.C:219-225`) -- and both reach the identical
/// [`crate::btrieve::Btrieve::end`]. A second `exabtv` with nothing open
/// gives `TransactionError::NoneActive` (`crate::btrieve::TransactionError`),
/// refused the same way `dfaEndTrans` refuses it -- one engine, one answer,
/// per this task's own instruction.
pub fn exabtv<A: Abi>(_call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    host.btrieve
        .end()
        .map_err(|e| ShimError::Failed(format!("exabtv: {e}")))?;
    Ok(abi::Ret::Void)
}

// ---------------------------------------------------------------------------
// Task 4: the locking variants -- `getbtvl`, `anpbtvl`, `anpbtvlk`,
// `aabbtvl`, `unlbtv`.
//
// **Locks are modelled, for real** -- the first of the three answers Task 4
// asks to establish before writing anything. `crate::btrieve::ops::LockTable`
// already exists, reached from this file through [`take_lock`], and
// [`obtbtvl`]/[`stpbtvl`]/[`gabbtvl`] already thread a `loktyp` through it.
// This is not the "locks are not modelled, single-threaded, so unlbtv is a
// no-op" branch: what IS true of a single-threaded, single-client host is
// narrower than that -- no lock this table records can ever be *contended*,
// because there is only ever one client to contend with itself. See
// [`wslbtv`]'s own doc comment for exactly where that narrower fact matters
// (it does, for one routine) and `ops.rs`'s own "Cross-client conflict" doc
// section for the full reasoning this defers to rather than repeats.
// ---------------------------------------------------------------------------

/// `void getbtvl(void *recptr, void *key, int keynum, int getopt, int
/// loktyp)` -- get a record by key, taking a lock once it is found.
///
/// [`getbtv`]'s own doc comment already quotes this routine's full body
/// (`PLBTVSTF.C:310-337`, Worldgroup 1.0 -- MajorBBS 6.25 has no `getbtvl`
/// at all) and its one-place divergence from [`obtbtvl`] (every nonzero
/// status refuses here, where `obtbtvl` answers 0 on status 4/9/a lock
/// conflict). This is exactly what `getbtv` tail-calls with `loktyp` fixed
/// at 0 (`PLBTVSTF.C:300-308`) -- five words instead of four, the fifth
/// read after `getopt` and passed straight into [`locate`]'s own `lock`
/// field, the same slot [`obtbtvl`] already reads its own fifth word into.
///
/// `lock` is taken only once a record is actually found: `locate`'s own
/// `take_lock` call runs after `Cursor::seek_to`, never before -- see
/// [`take_lock`]'s doc comment for why that ordering is load-bearing.
pub fn getbtvl<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let Some(block) = positioned(call, host, "getbtvl")? else {
        note_no_file(host, "getbtvl");
        return Ok(abi::Ret::Void);
    };

    let into = call.ptr();
    let value = call.ptr();
    let keynum = i16_arg::<A>(call.int());
    let opt = i16_arg::<A>(call.int());
    let lock = i16_arg::<A>(call.int());

    let op = Op::of(opt).ok_or_else(|| {
        ShimError::Failed(format!(
            "getbtvl with option {opt}, which is none of the nine BTVSTF.H's g-macros produce"
        ))
    })?;
    let into = match into == Btrieve::<AbiMem<A>>::null() {
        true => data_buffer(host, block)?,
        false => into,
    };
    let found = locate(
        call,
        host,
        Request {
            who: "getbtvl",
            block,
            op,
            keynum,
            value,
            into: Some(into),
            lock,
        },
    )?;
    if !found {
        let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
        return Err(ShimError::Failed(format!(
            "getbtvl found no record in {} -- PLBTVSTF.C:333-335 sends any \
             nonzero status straight to posbtverr(\"GET\"), unlike obtbtvl's \
             status-4/9/wslbtv special case (:373), so this refuses instead \
             of answering 0",
            file.name()
        )));
    }
    Ok(abi::Ret::Void)
}

/// `int anpbtvl(void *recptr, int chkcas, int anpopt)` -- step to the
/// next/previous record, with `chkcas` left to the caller rather than
/// [`anpbtv`]'s own fixed `1`.
///
/// `PLBTVSTF.C:390-397` (Worldgroup 1.0; MajorBBS 6.25 has no `anpbtvl`/
/// `anpbtvlk` split at all -- its own `anpbtvl` is the routine [`anpbtv`]'s
/// doc comment already quotes in full, calling `obtbtv` rather than
/// `obtbtvl` because 6.25 has neither locking variant), quoted in full:
///
/// A pure tail call fixing `loktyp` at 0. [`anpbtvlk`] is this routine's own
/// body, with `loktyp` read as a fourth argument instead of fixed.
pub fn anpbtvl<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let recptr = call.ptr();
    let chkcas = i16_arg::<A>(call.int());
    let anpopt = i16_arg::<A>(call.int());
    let Some(block) = positioned(call, host, "anpbtvl")? else {
        note_no_file(host, "anpbtvl");
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    };
    // Both spellings answer 0 for "no record" and for "found but the key
    // moved", which is why the core keeps them apart and this does not.
    let equal = acquire_next_prev(
        call, host, "anpbtvl", block, recptr, chkcas != 0, anpopt, 0,
    )?
    .unwrap_or(false);
    Ok(abi::Ret::Int(A::Int::from(u16::from(equal))))
}

/// `int anpbtvlk(void *recptr, int chkcas, int anpopt, int loktyp)` -- step
/// to the next/previous record, checking case and taking a lock exactly as
/// the module chooses.
///
/// `PLBTVSTF.C:399-415` (Worldgroup 1.0; not in MajorBBS 6.25 at all -- see
/// [`anpbtvl`]'s own doc comment). [`anpbtv`]'s own doc comment already
/// quotes this routine's full body while explaining what `anpbtv`'s own
/// fixed-`chkcas=1,loktyp=0` tail call does to it; this is that body with
/// both left free, through the shared [`anp`] helper [`anpbtv`] itself does
/// **not** use -- this file's own established convention
/// ([`stpbtv`]/[`stpbtvl`]'s doc comment: "duplicated rather than shared...
/// append rather than restructure an existing, already-tested routine")
/// keeps `anpbtv` exactly as it was; only `anpbtvl` and `anpbtvlk` are new
/// here, and sharing code between the two of them is not restructuring
/// anything already tested.
pub fn anpbtvlk<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let recptr = call.ptr();
    let chkcas = i16_arg::<A>(call.int());
    let anpopt = i16_arg::<A>(call.int());
    let lock = i16_arg::<A>(call.int());
    let Some(block) = positioned(call, host, "anpbtvlk")? else {
        note_no_file(host, "anpbtvlk");
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    };
    // Both spellings answer 0 for "no record" and for "found but the key
    // moved", which is why the core keeps them apart and this does not.
    let equal = acquire_next_prev(
        call, host, "anpbtvlk", block, recptr, chkcas != 0, anpopt, lock,
    )?
    .unwrap_or(false);
    Ok(abi::Ret::Int(A::Int::from(u16::from(equal))))
}

/// The body [`anpbtvl`] and [`anpbtvlk`] share -- [`anpbtv`]'s own body
/// (`PLBTVSTF.C:399-415`) with `chkcas`/`loktyp` taken as parameters
/// instead of the literal `1`/`0` its own tail call fixes them at. See
/// [`anpbtv`]'s own doc comment for the full accounting of what this does
/// and why, including the ordering hazard when `recptr` is null -- every
/// word of that reasoning applies here unchanged; only the two fixed
/// constants became parameters.
/// Acquire next/prev and report whether the key still matches, shared by every
/// spelling of that routine.
///
/// `block` is the caller's because that is the only thing the two spellings
/// ever disagreed about: `anpbtvl`/`anpbtvlk` find the file through
/// `positioned`, `dfaAcqNPLock` through `dfa_positioned`. `GALPORT.C` names
/// `anpbtvlk`/`dfaAcqNPLock` one routine, and `shims::dfa` used to carry a
/// second transcription of everything below.
///
/// The two transcriptions had already grown apart in one place without
/// breaking: this one lower-cased both buffers and called [`strcmp_eq`], the
/// other called a `stricmp_eq` of its own that truncated at the NUL first.
/// Those agree -- lowering a NUL leaves it a NUL, so it cannot move where the
/// scan stops -- which is the state that precedes a divergence rather than one.
///
/// `Ok(None)` means the step found no record at all, and `Ok(Some(equal))`
/// means it found one and this is whether the key still matches. The two are
/// deliberately separate: both `btv*` spellings answer 0 either way, but
/// `dfaAcqNPLock` records `dfa->lastlen` on *found* regardless of the
/// comparison, and folding them together silently dropped that -- caught while
/// extracting this, by re-reading the transcription being replaced.
///
/// # Errors
///
/// An option that is not a get operation, or an unresolvable buffer.
pub(crate) fn acquire_next_prev<A: Abi>(
    call: &mut Call<A>,
    host: &mut Host<A>,
    who: &'static str,
    block: A::Ptr,
    recptr: A::Ptr,
    chkcas: bool,
    anpopt: i16,
    lock: i16,
) -> Result<Option<bool>, ShimError> {

    // `:409` -- `movmem(bb->key,bb->data,bb->keylns[bb->lastkn])`, read
    // before the step below can overwrite either buffer.
    let key = key_number(call, host, block, -1)?;
    let key_len = key_length(host, block, key)?;
    let key_buffer = host.btrieve.block(block).map_err(ShimError::Failed)?.key();
    let old = key_buffer
        .resolve(call.mem(), usize::from(key_len))
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let data_buf = data_buffer(host, block)?;
    data_buf
        .write(call.mem(), &old)
        .map_err(|e| ShimError::Failed(e.to_string()))?;

    // `:410` -- `obtbtvl(recptr,NULL,-1,anpopt,loktyp)`.
    let op = Op::of(anpopt).ok_or_else(|| {
        ShimError::Failed(format!("{who} with option {anpopt}, which is not a get operation"))
    })?;
    let into = match recptr == Btrieve::<AbiMem<A>>::null() {
        true => data_buffer(host, block)?,
        false => recptr,
    };
    let found = locate(
        call,
        host,
        Request {
            who,
            block,
            op,
            keynum: -1,
            value: Btrieve::<AbiMem<A>>::null(),
            into: Some(into),
            lock,
        },
    )?;
    if !found {
        return Ok(None);
    }

    // `:411-412` -- compare the scratch copy against the key the step just
    // refreshed, `strcmp` or `stricmp` depending on `chkcas`. See
    // [`strcmp_eq`]'s own doc comment for why the scan is bounded to the
    // key's own length rather than following C's unbounded convention;
    // lowercasing first is safe against that bound because ASCII-lowering a
    // NUL byte is still a NUL byte, so it cannot move where the scan stops.
    let data_buf = data_buffer(host, block)?;
    let now = data_buf
        .resolve(call.mem(), usize::from(key_len))
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let key_buffer = host.btrieve.block(block).map_err(ShimError::Failed)?.key();
    let landed = key_buffer
        .resolve(call.mem(), usize::from(key_len))
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();

    Ok(Some(if chkcas {
        strcmp_eq(&now, &landed)
    } else {
        strcmp_eq(&now.to_ascii_lowercase(), &landed.to_ascii_lowercase())
    }))
}

/// `int aabbtvl(void *recptr, long abspos, int keynum, int loktyp)` --
/// acquire the record at a file position, taking a lock once it is found.
///
/// `PLBTVSTF.C:469-493` (Worldgroup 1.0; not in MajorBBS 6.25, whose
/// `aabbtv` IS this routine's own body with no `loktyp` word at all -- the
/// same generation gap [`aabbtv`]'s own doc comment already records for
/// `gabbtvl`). [`aabbtv`]'s own doc comment quotes the one-line tail call
/// this is the target of (`:466`: `return(aabbtvl(recptr,abspos,keynum,0))`)
/// and explains at length why a single cursor cannot read both this
/// routine's four words and `aabbtv`'s own three verbatim -- the same
/// problem [`gabbtvl`]'s own doc comment names for the identical shape on
/// the `gabbtv`/`gabbtvl` side. `aabbtvl` reads exactly [`gabbtvl`]'s own
/// four words (`recptr`, `abspos`, `keynum`, `loktyp`) in the same order and
/// passes them into [`absolute`] with `fatal: false` -- `aabbtv`'s own
/// answer-with-nothing convention, not `gabbtvl`'s refusal -- because
/// `aabbtvl` and `gabbtvl` differ in exactly the one field [`Position::
/// fatal`] exists to carry, and nowhere else.
pub fn aabbtvl<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let into = call.ptr();
    let position = call.long();
    let keynum = i16_arg::<A>(call.int());
    let lock = i16_arg::<A>(call.int());
    // `absolute` no longer looks the file up itself -- the `dfa*`
    // spelling of this routine finds it a different way. Same guard as
    // before, in the caller that owns it.
    let Some(block) = positioned(call, host, "aabbtvl")? else {
        note_no_file(host, "aabbtvl");
        return Ok(abi::Ret::Int(A::Int::from(0u16)));
    };
    Ok(abi::Ret::Int(A::Int::from(u16::from(absolute(
        call,
        host,
        Position {
            who: "aabbtvl",
            block,
            negative_keynum: NegativeKey::Note,
            fatal: false,
            lock,
            into,
            position,
            keynum,
        },
    )?))))
}

/// `void unlbtv(long abspos, int keynum)` -- release a lock.
///
/// `PLBTVSTF.C:713-728` (Worldgroup 1.0 only -- not in MajorBBS 6.25),
/// quoted in full:
///
/// Op 27, "Unlock", flavoured entirely by `keynum`. `BTVSTF.H:125-128`
/// names the only three flavours a module can reach this with:
///
/// The C body itself only branches on `keynum == -1` versus everything
/// else -- `0` and `-2` both fall into the same `else` arm and are told
/// apart purely by which raw `keynum` the real low-level Btrieve call
/// receives, a distinction this host has to make explicit because it has
/// no low-level call underneath to make it implicitly:
///
/// - `keynum == -1`: release the lock at `abspos`, an explicit file
///   position -- [`crate::btrieve::Btrieve::unlock_at`].
/// - `keynum == -2`: release every lock this session holds on the current
///   file -- [`crate::btrieve::Btrieve::unlock_all`], the module-callable
///   form of what [`crate::btrieve::Btrieve::close`] already does for every
///   file it closes.
/// - `keynum == 0`: release the lock at wherever the file is currently
///   positioned -- [`crate::btrieve::Btrieve::unlock_current`].
/// - Anything else: refused. `BTVSTF.H`'s own macros never produce a fourth
///   value, and the real host's `else` arm would have handed Btrieve a
///   `keynum` none of its own documented flavours name.
///
/// # No guard of its own, and this host supplies a refusal anyway
///
/// `unlbtv` itself never tests `bb` -- but `btvu()` (`PLBTVSTF.C:792-813`,
/// `btvdatptr->posp38seg=bb->realseg`) unconditionally dereferences it to
/// build the low-level parameter block, on every call including this one.
/// So a real board that called `unlbtv` with no file current faulted inside
/// `btvu`, one level down from `unlbtv`'s own body -- the same shape
/// [`stpbtvl`]'s own doc comment already documents for a routine with no
/// guard of its own. This refuses by name rather than reproducing the
/// fault.
pub fn unlbtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let position = call.long();
    let keynum = i16_arg::<A>(call.int());

    let block = positioned(call, host, "unlbtv")?.ok_or_else(|| {
        ShimError::Failed(
            "unlbtv with no Btrieve file current -- unlbtv itself never tests \
             bb, but btvu() (PLBTVSTF.C:792-813) unconditionally dereferences it \
             to build the low-level parameter block, so the real host faulted \
             one level down from here rather than answering"
                .to_owned(),
        )
    })?;

    match keynum {
        -1 => host.btrieve.unlock_at(block, position).map_err(ShimError::Failed)?,
        -2 => host.btrieve.unlock_all(block).map_err(ShimError::Failed)?,
        0 => host.btrieve.unlock_current(block).map_err(ShimError::Failed)?,
        _ => {
            return Err(ShimError::Failed(format!(
                "unlbtv with key number {keynum}, which is none of the three \
                 flavours BTVSTF.H's ul-macros produce (0 = ulsbtv, -1 = \
                 ulmbtv/ulobtv, -2 = ulabtv)"
            )));
        }
    }
    Ok(abi::Ret::Void)
}

// ---------------------------------------------------------------------------
// Task 5: variable-length records -- `sttbtv`, `rlenbtv`, `wslbtv`,
// `llnbtv`. Three of the four turn out to be accessors over state this file
// or the engine already computes; the fourth (`sttbtv`) has no vendor body
// anywhere to be an accessor over.
// ---------------------------------------------------------------------------

/// `void sttbtv(int len)` -- **no vendor body exists to cite.**
///
/// Declared at `BTVSTF.H:169` (Worldgroup-era numbering; MajorBBS 6.25's own
/// header has no `sttbtv` at all) and implemented in **none** of the three
/// recovered `PLBTVSTF.C` generations -- MajorBBS 6.25, Worldgroup 1.0,
/// Worldgroup 2.0 (Task 1's own finding). No macro in any recovered
/// `BTVSTF.H` references it, and nothing else in `archive/` or `re/` calls
/// it either (`grep -a -rn sttbtv archive/ re/`: zero hits outside the two
/// header declarations). Implemented from the declaration alone, per this
/// task's own instruction, with the uncertainty recorded here rather than
/// papered over with a citation to a file that does not contain it.
///
/// See the engine's own `stt_length` field doc comment
/// ([`crate::btrieve::Btrieve`]) for the full, honest account of what is and
/// is not known about this routine's purpose, and why the right
/// implementation is "store the argument, wire nothing to it yet" rather
/// than a guess at which write path was meant to consume it. `len` is read
/// the way [`upvbtv`]'s own `length` is (via [`u16_arg`] rather than
/// [`i16_arg`]) on the same reasoning: both are declared plain `int` but
/// name a byte count, the one role every other `int len`/`length` argument
/// in this file plays.
pub fn sttbtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let len = u16_arg::<A>(call.int(), "sttbtv")?;
    host.btrieve.set_stt_length(len);
    Ok(abi::Ret::Void)
}

/// `int rlenbtv(void)` -- the current file's own fixed record length.
///
/// `PLBTVSTF.C:696-710` (MajorBBS 6.25; identical body in Worldgroup 1.0/2.0
/// modulo line numbers), quoted in full:
///
/// The identical shape [`cntrbtv`] already has for `fs.numofr` -- same
/// Btrieve `STAT` call (op 15), same reply struct, a different field. See
/// [`cntrbtv`]'s own doc comment for the full account of why this has no
/// `bb == NULL` guard at all (`:696-709` never mentions `bb`) and why the
/// refusal here is nonetheless this host's own rather than a reproduction
/// of one: with no file current there is no file for "whatever Btrieve is
/// positioned on" to resolve to, on a host with no Btrieve TSR holding a
/// position in the first place. Answered from [`crate::btrieve::Geometry::
/// reclen`], the field this host already reads directly off the file
/// control record rather than through an emulated `STAT` reply, the same
/// substitution `cntrbtv` already makes for `numofr`.
///
/// **Not fed by [`sttbtv`], despite sitting beside it in `BTVSTF.H`'s
/// list.** `fs.reclen` is a Btrieve `STAT` reply field describing the file
/// itself, fixed at `crtbtv` time; `sttbtv`'s own argument is per-call
/// session state with no recovered consumer at all -- see the engine's own
/// `stt_length` field doc comment. The test in this file's own `mod tests`
/// that might look like a round trip between the two is deliberately not
/// written that way, for this exact reason.
pub fn rlenbtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let block = positioned(call, host, "rlenbtv")?.ok_or_else(|| {
        ShimError::Failed(
            "rlenbtv with no Btrieve file current -- PLBTVSTF.C:696-709 would \
             have asked Btrieve to STAT whatever file the TSR was last \
             positioned on, and this host has no such position to fall back on"
                .to_owned(),
        )
    })?;
    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    Ok(abi::Ret::Int(A::Int::from(file.geometry().reclen)))
}

/// `int wslbtv(void)` -- **despite sitting in `BTVSTF.H`'s list beside the
/// variable-length family, this has nothing to do with variable-length
/// records.** The name suggests "was short last"; the body says otherwise
/// -- exactly the "names are not evidence" trap this task's own
/// instructions warn about.
///
/// `PLBTVSTF.C:730-739` (Worldgroup 1.0; not in MajorBBS 6.25, which has no
/// lock-conflict statuses to report because it has no locking variants at
/// all), quoted in full:
///
/// "Was status Locked" -- checked against the module-static `status` every
/// `btvu()` call leaves behind, the same variable [`llnbtv`]'s own
/// `lastlen` sits beside in `PLBTVSTF.C`'s file scope. [`obtbtvl`]/
/// [`stpbtvl`] both already call this internally (`PLBTVSTF.C:373`/`:513`,
/// quoted in [`obtbtvl`]'s own doc comment) to fold a lock conflict into
/// the same quiet 0 a not-found key gets.
///
/// # Always answers 0 here, and says why rather than leaving a reader to wonder
///
/// This host cannot produce Btrieve status 84 or 85 at all: both are
/// **cross-client** lock conflicts, and `crate::btrieve::ops`'s own
/// "Locking" module doc section -- "Cross-client conflict (statuses 84/85)
/// is deferred, not architecturally absent" -- already establishes that
/// this host has exactly one Btrieve client, so no lock any operation takes
/// can ever be contended (`mbbs-single-threaded-by-force`). Locks
/// themselves ARE modelled here -- [`crate::btrieve::ops::LockTable`],
/// reached through [`take_lock`] -- so this is not Task 4's "locks are not
/// modelled at all" branch; it is the narrower gap `ops.rs`'s own doc
/// comment already named and reasoned through at length. Answered as a
/// routine rather than refused, because a module asking "was I just
/// refused for a lock" is entitled to the honest answer "no, nothing here
/// can refuse you for that reason" -- the vendor's own defined answer for
/// the one case that can never arise on this host, not an invented one.
pub fn wslbtv<A: Abi>(_call: &mut Call<A>, _host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    Ok(abi::Ret::Int(A::Int::from(0u16)))
}

/// `int llnbtv(void)` -- the length of the last record actually delivered.
///
/// `PLBTVSTF.C:352-356` (MajorBBS 6.25; identical body in Worldgroup 1.0/2.0
/// modulo line numbers), quoted in full:
///
/// `lastlen` is `PLBTVSTF.C`'s own file-scope static, set inside `btvu()`
/// (`:687` in 6.25's own numbering) after *every* low-level call -- see the
/// engine's own `lastlen` field doc comment ([`crate::btrieve::Btrieve`])
/// for where this host updates its counterpart instead ([`deliver`], the
/// one chokepoint every read routine in this file already funnels a
/// successful positioning through), and why that scoping is the identical
/// simplification already applied to `dfaLastLen`. `llnbtv` has zero call
/// sites anywhere in this crate's survey corpus (this file's own module doc
/// comment names `WCCMMUD.DLL`'s seventeen imports, and this is not one of
/// them), so it is implemented on the same standing instruction as every
/// other unexercised routine this task covers ([`take_lock`]'s own doc
/// comment) rather than left out because nothing on hand calls it.
pub fn llnbtv<A: Abi>(_call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    Ok(abi::Ret::Int(A::Int::from(host.btrieve.lastlen())))
}

// ---------------------------------------------------------------------------
// Task 6: `crtbtv` -- create a file from a module's own request. The engine
// half (`crate::btrieve::create`, `btrieve/create.rs`) already exists and is
// fully tested; this is the marshalling from the module's raw buffer into
// its `FileSpec`.
// ---------------------------------------------------------------------------

/// `void crtbtv(char *filnam, void *databuf, int lendbuf, int keyno)` --
/// create a new Btrieve file from a module's own request.
///
/// `PLBTVSTF.C:571-597` (MajorBBS 6.25; Worldgroup 1.0/2.0's own `:650-676`
/// wraps every `movmem` in this file in a `goodblk()` bounds macro this one
/// does not have -- the same textual difference every other routine this
/// file cites from both generations shows, and no difference in what either
/// generation actually does), quoted in full:
///
/// Op 14, Create -- the same opcode [`crate::btrieve::create`] (this
/// crate's own engine half) already writes a v5 file for. This routine's
/// whole job is marshalling `databuf`/`lendbuf` -- `lendbuf` bytes at
/// `databuf`, a Btrieve file specification block -- into that engine's
/// [`FileSpec`](crate::btrieve::FileSpec)/[`KeySpec`](crate::btrieve::KeySpec)/
/// [`SegmentSpec`](crate::btrieve::SegmentSpec).
///
/// # The buffer layout, measured against the Programmer's Reference
///
/// `archive/tooling/reference-documents/Btrieve_Programmers_Reference_1998.pdf`,
/// Table 2-1 ("Data Buffer Structure for Create Operation", printed pages
/// 51-52 -- confirmed with `pdftotext -layout`): one 16-byte File
/// Specification (`reclen: u16, pagsiz: u16, numofx: u16, reserved: [u8;
/// 4], flags: u16, "number of duplicate pointers to reserve": u8, unused:
/// u8, allocation: u16`) followed by one 16-byte Key Specification per key
/// **segment** (`keypos: u16, keylen: u16, keyflags: u16, reserved: [u8;
/// 4], ext_type: u8, null_value: u8, unused: [u8;2], manual_keyno: u8,
/// acs_number: u8`).
///
/// This is exactly `PLBTVSTF.C`'s own `struct filspc`/`struct keyspc` (this
/// file's own top-of-file comment quotes both) -- the same 16+16-byte
/// structures [`cntrbtv`]/[`rlenbtv`] already read a *reply* to op 15
/// (`STAT`) as -- with a few fields neither of those routines happens to
/// name (`filspc.reserved`/`unupag`; `keyspc.numofk`/`dontcare`/`reserved`)
/// because they never read them, not because the buffer is shaped
/// differently for a Create than for a Stat reply. `BTVSTF.H`'s own
/// `#define ANOSEG 0x10` -- "key has another segment" -- is `keyspc.flags`
/// bit 4, the identical bit `DFASF_SEGMENT` names in the richer structure
/// `shims/dfa.rs`'s `dfaCreate` decodes from `DFAAPI.H`. **Two independent
/// derivations -- this task's own PDF citation against a 1990s C struct,
/// and `dfaCreate`'s own doc comment against `DFAAPI.H` and a live oracle
/// run for Worldgroup's `dfaCreateSpec`  -- land on the identical
/// 16+16-byte layout.** Not a shared implementation: `dfa.rs`'s own
/// `decode_create_buffer` is private to its module, and this task's own
/// file list forbids reaching into `shims/dfa.rs` to change that. The
/// decoder below is the same wire format decoded a second time,
/// independently, and agreeing.
///
/// # `keyno` is an overwrite selector, not a key count
///
/// Real Btrieve's `B_CREATE` `keynum` argument is `0` (replace an existing
/// file) or `-1` (refuse if one exists) -- the identical fact [`dfaCreate`]'s
/// own doc comment establishes for the same argument on the `dfa*` side of
/// this API. [`crate::btrieve::create`] never overwrites regardless of
/// `keyno` (its own doc comment), so this refuses any `keyno` outside
/// `{0, -1}` rather than reinterpreting it as a key count, and `keyno == 0`
/// on a file that already exists is refused the same honest way
/// `keyno == -1` would be.
///
/// # What this refuses, and why none of it is new
///
/// Every limit [`crate::btrieve::create`]'s own doc comment names --
/// variable-length records, more than one duplicate-permitting key, a key
/// segment type this crate's reader cannot order, and so on -- is refused
/// there, through that function's own `Result`, and surfaces here rather
/// than being reimplemented. A nonzero `flags` word or an `allocation`
/// other than 0/1 is refused in the decode below, the identical refusal
/// [`dfaCreate`]'s own doc comment documents for the identical fields,
/// because [`FileSpec`](crate::btrieve::FileSpec) has no representation for
/// either.
///
/// # Unverified against a live engine
///
/// Like [`dfaCreate`], this marshalling is derived from the Programmer's
/// Reference and cross-checked against `DFAAPI.H`'s independent structure,
/// not measured against a live create through *this* wrapper --
/// `tools/btrieve-oracle/crtprobe.c` exercises `crate::btrieve::create`
/// directly, one layer below this marshalling. Stated as a fact about
/// confidence, not smoothed over.
pub fn crtbtv<A: Abi>(call: &mut Call<A>, host: &mut Host<A>) -> Result<abi::Ret<A>, ShimError> {
    let filnam = call.ptr();
    let databuf = call.ptr();
    let lendbuf = u16_arg::<A>(call.int(), "crtbtv")?;
    let keyno = i16_arg::<A>(call.int());

    let named = String::from_utf8_lossy(
        filnam.read_cstr(call.mem()).map_err(|e| ShimError::Failed(e.to_string()))?,
    )
    .into_owned();
    let name = Host::<A>::dos_name(&named).map_err(ShimError::Failed)?;

    if keyno != 0 && keyno != -1 {
        return Err(ShimError::Failed(format!(
            "crtbtv({name}) with keyno {keyno}, which real Btrieve's B_CREATE \
             takes as an overwrite selector (0 = replace an existing file, -1 = \
             refuse if one exists), not a key count"
        )));
    }

    let bytes = databuf
        .resolve(call.mem(), usize::from(lendbuf))
        .map_err(|e| ShimError::Failed(e.to_string()))?
        .to_vec();
    let spec = decode_file_spec(&bytes)?;

    let path = host.root.join(&name);
    crate::btrieve::create(&path, &spec)
        .map_err(|e| ShimError::Failed(format!("crtbtv({name}): {e}")))?;
    host.note(format!("created {name} via crtbtv"));
    Ok(abi::Ret::Void)
}

/// Decode one Btrieve file-specification buffer (16-byte File Specification
/// + N 16-byte Key Specifications -- [`crtbtv`]'s own doc comment) into a
/// [`FileSpec`](crate::btrieve::FileSpec). Not shared with `shims/dfa.rs`'s
/// own `decode_create_buffer`: that function is private to its module and
/// this task's own file list forbids editing `shims/dfa.rs` to export it --
/// but independently derived from the same wire format and checked to
/// agree; see [`crtbtv`]'s own doc comment for both derivations side by
/// side.
fn decode_file_spec(bytes: &[u8]) -> Result<crate::btrieve::FileSpec, ShimError> {
    use crate::btrieve::{FileSpec, KeySpec, SegmentSpec};

    const FILE_SPEC: usize = 16;
    const KEY_SPEC: usize = 16;
    const DUPLICATE: u16 = 1;
    const MODIFIABLE: u16 = 2;
    const MANUAL: u16 = 8;
    const NULL_KEY: u16 = 512;
    const ANOSEG: u16 = 16;
    const ALTCOLLATE: u16 = 32;
    const DESCENDING: u16 = 64;

    if bytes.len() < FILE_SPEC {
        return Err(ShimError::Failed(format!(
            "a create buffer of {} bytes, shorter than one 16-byte File \
             Specification (Btrieve Programmer's Reference, Table 2-1)",
            bytes.len()
        )));
    }
    let word = |at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]);

    let record_length = word(0);
    let page_size = word(2);
    let n_keys = word(4);
    let flags = word(10);
    let allocation = word(14);

    if flags != 0 {
        return Err(ShimError::Failed(format!(
            "create flags {flags:#06x} -- this engine's FileSpec has no \
             representation for any file-flags bit, so any nonzero flags word \
             is refused rather than silently ignored"
        )));
    }
    if allocation > 1 {
        return Err(ShimError::Failed(format!(
            "an Allocation of {allocation} -- this engine always pre-allocates \
             exactly one data page, so anything else cannot be honoured"
        )));
    }

    let mut keys: Vec<KeySpec> = Vec::new();
    let mut segments: Vec<SegmentSpec> = Vec::new();
    let mut duplicates = false;
    let mut modifiable = false;
    let mut at = FILE_SPEC;
    let mut seen_keys = 0u16;

    while seen_keys < n_keys {
        if at + KEY_SPEC > bytes.len() {
            return Err(ShimError::Failed(format!(
                "a create buffer with {n_keys} keys declared, but the key spec \
                 at byte {at} runs past the buffer's own {} bytes",
                bytes.len()
            )));
        }
        let position = word(at);
        let length = word(at + 2);
        let seg_flags = word(at + 4);
        let ext_type = bytes[at + 10];

        if seg_flags & ALTCOLLATE != 0 {
            return Err(ShimError::Failed(
                "a key segment with an alternate collating sequence bit set -- \
                 this host has no ACS file to read one from"
                    .to_owned(),
            ));
        }
        if seg_flags & (MANUAL | NULL_KEY) != 0 {
            return Err(ShimError::Failed(format!(
                "a key with flags {seg_flags:#06x} setting a manually-assigned \
                 key number and/or a null value -- unsupported on the read side \
                 (keys::parse's own UNSUPPORTED table), so refused here rather \
                 than written and discovered broken later"
            )));
        }

        duplicates = seg_flags & DUPLICATE != 0;
        modifiable = seg_flags & MODIFIABLE != 0;

        segments.push(SegmentSpec {
            offset: position.checked_sub(1).ok_or_else(|| {
                ShimError::Failed(
                    "a key segment at wire position 0, which is not valid -- \
                     positions are 1-based"
                        .to_owned(),
                )
            })?,
            length,
            kind: ext_type,
            descending: seg_flags & DESCENDING != 0,
        });

        let more_segments = seg_flags & ANOSEG != 0;
        at += KEY_SPEC;
        if !more_segments {
            keys.push(KeySpec {
                segments: std::mem::take(&mut segments),
                duplicates,
                modifiable,
                // `ALT_COLLATING` is refused above rather than passed
                // through: this host has no table to hand `create` for a
                // module's own sequence.
                acs: false,
            });
            seen_keys += 1;
        }
    }

    Ok(FileSpec {
        record_length,
        page_size,
        keys,
        acs: None,
        variable: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::Wg32;
    use crate::testing::Fixture;

    /// The two 16-bit readers this file offers answer *differently* on the
    /// same bits, and which one a call site picks is decided by the vendor's
    /// declaration -- see `ushort_arg`'s own doc comment.
    ///
    /// `0x4052_02ef` is not invented: it is the literal `qty` slot
    /// MajorMUD-NT's own module init produced for `alcblok`, a stale address
    /// in the top half of a slot holding a `USHORT`. `dfa*`'s parameters sit
    /// in exactly such slots.
    #[test]
    fn ushort_arg_masks_where_u16_arg_refuses() {
        // Declared USHORT (`dfa*`): the upper half is not part of the value.
        assert_eq!(ushort_arg::<Wg32>(0x4052_02ef), 751);
        assert_eq!(ushort_arg::<Wg32>(70_000), 4464);
        assert_eq!(ushort_arg::<Wg32>(4096), 4096);

        // Declared int (`btv*`): the same bits ARE a real out-of-range value.
        assert!(u16_arg::<Wg32>(0x4052_02ef, "opnbtv").is_err());
        assert!(u16_arg::<Wg32>(70_000, "opnbtv").is_err());
        assert_eq!(u16_arg::<Wg32>(4096, "opnbtv").expect("in range"), 4096);
    }

    /// Under `Wg16` there is no upper half for either reader to disagree
    /// about, so the fix must be a `Wg32` correction and not a behaviour
    /// change on the ABI that was already right.
    #[test]
    fn the_two_readers_agree_on_everything_wg16_can_produce() {
        for v in [0u16, 1, 4096, u16::MAX] {
            assert_eq!(ushort_arg::<Wg16>(v), v);
            assert_eq!(u16_arg::<Wg16>(v, "opnbtv").expect("always in range"), v);
        }
    }

    /// Open `SAMPLE.DAT`, as a module would.
    fn open(f: &mut Fixture, name: &str, maxlen: u16) -> FarPtr {
        let at = f.text(name);
        let Ret::Far(block) = f
            .invoke(opnbtv, &[at.offset, at.selector, maxlen])
            .expect("opens")
        else {
            panic!("opnbtv returns a pointer");
        };
        block
    }

    /// What the module can see of which file is current.
    fn bb(f: &Fixture) -> FarPtr {
        f.host.globals().pointer(&f.machine, "bb").expect("bb")
    }

    /// A word of a `struct btvblk`, read the way the module would.
    fn field(f: &Fixture, block: FarPtr, offset: u16) -> u16 {
        let at = FarPtr {
            offset: block.offset + offset,
            selector: block.selector,
        };
        let bytes = f.machine.resolve(at, 2).expect("inside the block");
        u16::from_le_bytes([bytes[0], bytes[1]])
    }

    #[test]
    fn opnbtv_hands_back_a_block_the_module_can_read_its_record_length_out_of() {
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);

        // `reclen` at 132 and `filnam` at 128, per BTVSTF.H with PHARLAP.
        assert_eq!(field(&f, block, 132), 64);
        let filnam = FarPtr {
            offset: field(&f, block, 128),
            selector: field(&f, block, 130),
        };
        assert_eq!(f.read(filnam), "SAMPLE.DAT");

        // The position block is Btrieve's, and zeroed rather than absent: a
        // module that reads it gets zeros instead of a fault.
        assert_eq!(field(&f, block, 0), 0);
    }

    #[test]
    fn opening_a_file_makes_it_current() {
        let mut f = Fixture::new();
        assert_eq!(bb(&f), Btrieve::<AbiMem<Wg16>>::null(), "nothing is current to begin with");
        let block = open(&mut f, "SAMPLE.DAT", 64);
        assert_eq!(bb(&f), block);
    }

    #[test]
    fn opnbtv_pushes_itself_so_the_first_rstbtv_changes_nothing() {
        // `PLBTVSTF.C:145` writes `bb` before calling `setbtv(bb)`, so what the
        // open pushes is the block it just made. A module that opens a file and
        // restores gets that same file back, and needs a second `rstbtv` to
        // reach what was current before. Reproduced deliberately; a host that
        // saved the previous block would be one level out of step with a module
        // built against the real one.
        let mut f = Fixture::new();
        let first = open(&mut f, "SAMPLE.DAT", 64);
        let second = open(&mut f, "OTHER.DAT", 32);
        assert_ne!(first, second, "two files are two blocks");

        f.invoke(rstbtv, &[]).expect("restores");
        assert_eq!(bb(&f), second, "the file it had just opened");
        f.invoke(rstbtv, &[]).expect("restores");
        assert_eq!(bb(&f), first, "and now the one before it");
    }

    #[test]
    fn setbtv_and_rstbtv_round_trip_through_module_memory() {
        let mut f = Fixture::new();
        let first = open(&mut f, "SAMPLE.DAT", 64);
        let second = open(&mut f, "OTHER.DAT", 32);

        f.invoke(setbtv, &Fixture::far(first)).expect("set");
        assert_eq!(bb(&f), first);
        f.invoke(rstbtv, &[]).expect("restored");
        assert_eq!(bb(&f), second);
    }

    #[test]
    fn setbtv_of_a_block_that_was_never_opened_refuses() {
        let mut f = Fixture::new();
        let before = bb(&f);
        let nonsense = FarPtr {
            offset: 0x40,
            selector: f.host.globals().selector(),
        };
        assert!(f.invoke(setbtv, &Fixture::far(nonsense)).is_err());
        assert_eq!(bb(&f), before, "and left bb where it was");
    }

    #[test]
    fn the_stack_is_ten_deep_and_the_eleventh_drops_the_oldest() {
        // The real host's `movmem(bbstk,bbstk+1,...)` shifts rather than
        // indexes, so this neither refuses nor grows: it loses the outermost
        // file, and says so.
        let mut f = Fixture::new();
        let first = open(&mut f, "SAMPLE.DAT", 64);
        let other = open(&mut f, "OTHER.DAT", 32);

        // Eleven pushes on top of what the two opens already pushed.
        for _ in 0..11 {
            f.invoke(setbtv, &Fixture::far(other)).expect("set");
        }
        assert!(
            f.host.notes().iter().any(|n| n.contains("fell off")),
            "the overflow is reported: {:?}",
            f.host.notes()
        );

        // Unwinding the whole stack never reaches the first file again.
        for _ in 0..10 {
            f.invoke(rstbtv, &[]).expect("restores");
        }
        assert_ne!(bb(&f), first, "the outermost entry is gone for good");
    }

    #[test]
    fn rstbtv_past_the_bottom_yields_null_rather_than_refusing() {
        // The one place this crate follows the original instead of refusing.
        // `bbstk` starts as ten null pointers and `PLBTVSTF.C` checks
        // `bb == NULL` at the top of every routine, so null is the answer the
        // module was written to expect.
        let mut f = Fixture::new();
        f.invoke(rstbtv, &[]).expect("not an error");
        assert_eq!(bb(&f), Btrieve::<AbiMem<Wg16>>::null());
        assert!(
            f.host.notes().iter().any(|n| n.contains("rstbtv")),
            "and it is reported"
        );

        // And what null costs: nothing can be counted.
        assert!(f.invoke(cntrbtv, &[]).is_err());
    }

    #[test]
    fn cntrbtv_counts_the_current_file_and_a_setbtv_between_opens_changes_it() {
        let mut f = Fixture::new();
        let sample = open(&mut f, "SAMPLE.DAT", 64);
        open(&mut f, "OTHER.DAT", 32);

        // `OTHER.DAT` has three records and `SAMPLE.DAT` seven.
        assert_eq!(f.invoke(cntrbtv, &[]).expect("counts"), Ret::U32(3));
        f.invoke(setbtv, &Fixture::far(sample)).expect("set");
        assert_eq!(f.invoke(cntrbtv, &[]).expect("counts"), Ret::U32(7));
    }

    #[test]
    fn cntrbtv_reports_an_empty_file_as_empty_rather_than_failing() {
        // `WCCUSERS.DAT` on a board nobody has played on holds no records, and
        // zero is the right answer rather than a parse that went wrong.
        let mut f = Fixture::new();
        open(&mut f, "EMPTY.DAT", 64);
        assert_eq!(f.invoke(cntrbtv, &[]).expect("counts"), Ret::U32(0));
    }

    #[test]
    fn opnbtv_of_something_that_is_not_btrieve_refuses_by_name() {
        // Rather than handing back a block whose `reclen` is two bytes of
        // whatever the file happens to start with.
        let mut f = Fixture::new();
        let at = f.text("SAMPLE.MSG");
        let e = f
            .invoke(opnbtv, &[at.offset, at.selector, 64])
            .expect_err("a .MSG is not a Btrieve file");
        assert!(e.to_string().contains("SAMPLE.MSG"), "{e}");
    }

    #[test]
    fn opnbtv_names_a_file_it_can_neither_find_nor_install() {
        let mut f = Fixture::new();
        let at = f.text("NOSUCH.DAT");
        let e = f
            .invoke(opnbtv, &[at.offset, at.selector, 64])
            .expect_err("no file");
        assert!(e.to_string().contains("NOSUCH.DAT"), "{e}");
        assert!(e.to_string().contains("NOSUCH.VIR"), "{e}");
    }

    #[test]
    fn a_module_may_name_its_own_directory_and_no_other() {
        // `DATADIR` is empty in MajorMUD's `.MSG`, so what `spr` builds is
        // `.\NAME.DAT`.
        let mut f = Fixture::new();
        let here = f.text(".\\SAMPLE.DAT");
        assert!(f.invoke(opnbtv, &[here.offset, here.selector, 64]).is_ok());

        let elsewhere = f.text("D:\\MUD\\SAMPLE.DAT");
        let e = f
            .invoke(opnbtv, &[elsewhere.offset, elsewhere.selector, 64])
            .expect_err("that is not this host's directory");
        assert!(e.to_string().contains("D:\\MUD\\SAMPLE.DAT"), "{e}");
    }

    #[test]
    fn a_virgin_copy_is_installed_once_and_the_installation_is_reported() {
        // Fifteen of the sixteen files MajorMUD opens ship only as `.VIR`, so
        // without this the module opens nothing at all. It is an install step
        // and it says so; what it must never do is invent a file.
        let mut f = Fixture::rooted(crate::testing::scratch_with(
            "btrieve-install",
            &["VIRGIN.VIR"],
        ));
        assert!(f.host.find("VIRGIN.DAT").is_none(), "not installed yet");

        let block = open(&mut f, "VIRGIN.DAT", 64);
        assert_eq!(f.host.installed(), ["VIRGIN.DAT"]);
        assert!(f.host.find("VIRGIN.DAT").is_some(), "and now it is");
        assert!(
            f.host.notes().iter().any(|n| n.contains("VIRGIN.VIR")),
            "the copy is reported: {:?}",
            f.host.notes()
        );

        // Opening it again finds what was installed rather than installing a
        // second time -- which on a board that had been played on would throw
        // every character away.
        let again = open(&mut f, "VIRGIN.DAT", 64);
        assert_ne!(again, block, "a second open is a second block");
        assert_eq!(f.host.installed().len(), 1, "and not a second install");
    }

    #[test]
    fn opening_a_file_for_a_record_length_it_does_not_have_is_recorded() {
        // `bb->reclen` is the module's number, not the file's. The two
        // disagreeing is legitimate -- a module may read a prefix of a record --
        // but it is also what a mismatched data file looks like, so it is
        // visible rather than silent.
        //
        // **The two directions are reported differently**, because only one of
        // them diverges from the original: opening short is where Btrieve
        // answered status 22 and `posbtverr` wrote a terminator this host does
        // not. Opening long is what `WCCTEXT.DAT` does and agrees exactly.
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 32);
        let short = f.host.notes().last().expect("noted").clone();
        assert!(short.contains("SAMPLE.DAT"), "{short}");
        assert!(short.contains("only 32"), "the short direction: {short}");
        assert!(short.contains("truncated"), "and what it costs: {short}");

        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 128);
        let long = f.host.notes().last().expect("noted").clone();
        assert!(long.contains("SAMPLE.DAT"), "{long}");
        assert!(!long.contains("truncated"), "nothing is lost either way: {long}");

        // And on a *variable-length* file, opening long is not a mismatch at
        // all: the extra bytes are where the fragment chain goes. `WCCTEXT` is
        // 22 and 2,000; this is the same arithmetic on a smaller file.
        let dir = crate::testing::scratch("btv-shim-variable-note");
        variable_file(&dir, "VARIABLE.DAT", &[1u8, 0, 0, 0, 0, 0, 0, 0], b"a body");
        let mut f = Fixture::rooted(dir);
        open(&mut f, "VARIABLE.DAT", 14);
        let variable = f.host.notes().last().expect("noted").clone();
        assert!(variable.contains("fragment chain"), "{variable}");
        assert!(variable.contains("6 bytes of body"), "{variable}");
    }

    #[test]
    fn omdbtv_keeps_the_mode_and_refuses_one_that_is_not_a_mode() {
        let mut f = Fixture::new();
        assert_eq!(f.host.btrieve().mode(), 0, "PRIMBV until told otherwise");

        f.invoke(omdbtv, &[(-2i16) as u16]).expect("RONLBV");
        assert_eq!(f.host.btrieve().mode(), -2);

        assert!(f.invoke(omdbtv, &[7]).is_err(), "7 is not a mode");
        assert_eq!(f.host.btrieve().mode(), -2, "and it did not take");
    }
    /// The two-byte key of the record a read left in a buffer.
    fn got(f: &Fixture, at: FarPtr) -> u16 {
        let bytes = f.machine.resolve(at, 2).expect("readable");
        u16::from_le_bytes([bytes[0], bytes[1]])
    }

    /// `qrybtv` with no key value: the lowest, highest, next or previous.
    fn query(f: &mut Fixture, keynum: i16, opt: i16) -> bool {
        f.invoke(qrybtv, &[0, 0, keynum as u16, opt as u16])
            .expect("queries")
            == Ret::U16(1)
    }

    /// `obtbtvl(NULL, key, keynum, opt, 0)` -- acquire into `bb->data`.
    fn acquire(f: &mut Fixture, key: Option<u16>, keynum: i16, opt: i16) -> bool {
        let value = match key {
            Some(n) => f.bytes(&n.to_le_bytes(), false),
            None => Btrieve::<AbiMem<Wg16>>::null(),
        };
        f.invoke(obtbtvl,
            &[0, 0, value.offset, value.selector, keynum as u16, opt as u16, 0],
        )
        .expect("acquires")
            == Ret::U16(1)
    }

    /// Where `bb->data` is, for a file the test just opened.
    fn buffer(f: &Fixture, block: FarPtr) -> FarPtr {
        f.host.btrieve().block(block).expect("open").data()
    }

    /// A whole variable-length Btrieve file, three pages, holding one record
    /// whose body lives in a fragment on the third.
    ///
    /// The shape `WCCTEXT.DAT` has, scaled down: a fixed part, four bytes of
    /// pointer to a page and a fragment, and a variable page whose one
    /// fragment starts at `0x0c`. Written rather than copied because
    /// `WCCTEXT.DAT` is MajorMUD's and not in the repository.
    fn variable_file(dir: &std::path::Path, name: &str, fixed: &[u8], body: &[u8]) {
        const PAGE: usize = 512;
        let reclen = fixed.len() as u16;
        let physical = reclen + 4;
        let mut out = vec![0u8; PAGE * 3];

        out[6] = 0;
        out[7] = 4;
        out[0x08..0x0a].copy_from_slice(&(PAGE as u16).to_le_bytes());
        out[0x10..0x14].copy_from_slice(&[0xff; 4]); // an empty free list
        out[0x14..0x16].copy_from_slice(&1u16.to_le_bytes());
        out[0x16..0x18].copy_from_slice(&reclen.to_le_bytes());
        out[0x18..0x1a].copy_from_slice(&physical.to_le_bytes());
        out[0x1c..0x1e].copy_from_slice(&1u16.to_le_bytes()); // one record
        out[0x38] = 0xff;
        out[0x106..0x108].copy_from_slice(&1u16.to_le_bytes()); // variable-length

        // One key: two bytes at offset 0, the same definition the record
        // tests use.
        let key = 0x110;
        out[key + 0x08..key + 0x0a].copy_from_slice(&(1u16 << 8).to_le_bytes());
        out[key + 0x16..key + 0x18].copy_from_slice(&2u16.to_le_bytes());
        out[key + 0x1c] = 0x0f;

        // Page 1: a data page, holding the fixed part and a pointer to page 2.
        out[PAGE + 5] |= 0x80;
        out[PAGE + 6..PAGE + 6 + fixed.len()].copy_from_slice(fixed);
        let pointer = PAGE + 6 + fixed.len();
        out[pointer..pointer + 4].copy_from_slice(&[0x00, 0x02, 0x00, 0x00]);

        // Page 2: a variable page, one fragment, starting at 0x0c.
        let at = PAGE * 2;
        out[at..at + 2].copy_from_slice(&0u16.to_le_bytes());
        out[at + 2..at + 4].copy_from_slice(&2u16.to_le_bytes());
        out[at + 6..at + 10].copy_from_slice(&[0xff; 4]);
        out[at + 0x0a..at + 0x0c].copy_from_slice(&1u16.to_le_bytes());
        out[at + 0x0c..at + 0x0c + body.len()].copy_from_slice(body);
        out[at + PAGE - 2..at + PAGE].copy_from_slice(&0x000cu16.to_le_bytes());
        let end = 0x0cu16 + body.len() as u16;
        out[at + PAGE - 4..at + PAGE - 2].copy_from_slice(&end.to_le_bytes());

        std::fs::write(dir.join(name), out).expect("written");
    }

    /// **The whole point of following the fragment chain**: what reaches the
    /// module's buffer is the fixed part *and* the body, at the length the
    /// module opened the file for.
    ///
    /// `WCCTEXT.DAT` is 22 bytes of fixed record and 2,000 of fragment, and
    /// `opnbtv("WCCTEXT.DAT", 2022)` is what MajorMUD asks for -- the two agree
    /// exactly, which is an independent check on the reassembly: 2,018 or 2,026
    /// would mean the four-byte next-pointer prefix was handled wrong by one
    /// hop. This is that arithmetic in miniature, end to end through `obtbtvl`.
    #[test]
    fn a_variable_length_record_reaches_the_module_whole_and_not_just_its_fixed_part() {
        let dir = crate::testing::scratch("btv-shim-variable");
        let fixed = [0x01u8, 0x00, b'h', b'e', b'a', b'd', 0x00, 0x00];
        let body = b"and the rest of it, on another page";
        variable_file(&dir, "VARIABLE.DAT", &fixed, body);

        let mut f = Fixture::rooted(dir);
        let maxlen = (fixed.len() + body.len()) as u16;
        let block = open(&mut f, "VARIABLE.DAT", maxlen);

        assert!(acquire(&mut f, Some(1), 0, 5), "the record with key 1");

        let at = buffer(&f, block);
        let got = f.machine.resolve(at, maxlen.into()).expect("the module's buffer");
        assert_eq!(
            &got[..fixed.len()],
            &fixed,
            "the fixed part is unchanged"
        );
        assert_eq!(
            &got[fixed.len()..],
            body,
            "and the fragment follows it, rather than zeros"
        );
    }

    #[test]
    fn the_first_read_of_an_empty_file_says_there_is_nothing_rather_than_refusing() {
        // Initialisation's very first read is `qlobtv(0)` on `WCCUSERS.DAT`,
        // which has no records at all. Zero is the answer that tells the module
        // the board has no characters yet, and a refusal here would stop
        // MajorMUD on a board that is merely new.
        let mut f = Fixture::new();
        open(&mut f, "EMPTY.DAT", 64);
        assert!(!query(&mut f, 0, 62), "no lowest key in an empty file");
        assert!(!query(&mut f, 0, 63), "and no highest");
    }

    #[test]
    fn a_keyed_walk_is_in_key_order_and_a_step_is_in_page_order() {
        // `SAMPLE.DAT` holds seven records whose keys are 4, 1, 7, 2, 6, 3, 5
        // in the order the pages hold them -- the shape `WCCRACE` has. A host
        // that answered either question with the other's order would hand the
        // module the wrong record and nothing would say so.
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        let into = buffer(&f, block);

        let mut keyed = vec![];
        assert!(acquire(&mut f, None, 0, 12), "lowest");
        keyed.push(got(&f, into));
        for _ in 0..6 {
            assert!(acquire(&mut f, None, -1, 6), "next");
            keyed.push(got(&f, into));
        }
        assert_eq!(keyed, [1, 2, 3, 4, 5, 6, 7]);
        assert!(!acquire(&mut f, None, -1, 6), "and then the end");

        let mut stepped = vec![];
        assert_eq!(f.invoke(stpbtvl, &[0, 0, 33, 0]).expect("step first"), Ret::U16(1));
        stepped.push(got(&f, into));
        while f.invoke(stpbtvl, &[0, 0, 24, 0]).expect("step next") == Ret::U16(1) {
            stepped.push(got(&f, into));
        }
        assert_eq!(stepped, [4, 1, 7, 2, 6, 3, 5], "the order the pages hold");
    }

    #[test]
    fn acquiring_by_key_finds_the_record_with_that_key() {
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        let into = buffer(&f, block);

        assert!(acquire(&mut f, Some(5), 0, 5), "equal to 5");
        assert_eq!(got(&f, into), 5);
        assert_eq!(
            f.read(FarPtr {
                offset: into.offset + 2,
                selector: into.selector
            }),
            "Troll",
            "and the whole record came with it, not just the key"
        );

        assert!(!acquire(&mut f, Some(99), 0, 5), "there is no 99");
        assert_eq!(got(&f, into), 5, "and the buffer was left alone");
    }

    #[test]
    fn the_comparisons_either_side_of_a_key_are_all_different() {
        // Greater, at-least, less and at-most differ only at the boundary, and
        // an off-by-one in any of them is a record the module never sees.
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        let into = buffer(&f, block);

        for (opt, want, what) in [(8, 5, "greater than 4"), (9, 4, "at least 4"),
                                  (10, 3, "less than 4"), (11, 4, "at most 4")] {
            assert!(acquire(&mut f, Some(4), 0, opt), "{what}");
            assert_eq!(got(&f, into), want, "{what}");
        }

        // And at the ends, where there is nothing on one side.
        assert!(!acquire(&mut f, Some(1), 0, 10), "nothing below the lowest");
        assert!(!acquire(&mut f, Some(7), 0, 8), "nothing above the highest");
    }

    #[test]
    fn a_query_positions_without_reading_and_the_step_after_it_reads() {
        // `qeqbtv` then `qnxbtv` is the pattern MajorMUD uses to walk a group
        // of records: the first finds where the group starts and the second
        // brings them back one at a time.
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        let into = buffer(&f, block);

        assert!(f.invoke(qrybtv, &[0, 0, 0, 62]).expect("lowest") == Ret::U16(1));
        assert_eq!(got(&f, into), 0, "a query reads no record");

        assert_eq!(f.invoke(qnpbtv, &[56]).expect("next"), Ret::U16(1));
        assert_eq!(got(&f, into), 2, "and the step after it does");
    }

    #[test]
    fn a_query_leaves_the_key_it_found_in_the_modules_key_buffer() {
        // A Btrieve get-key operation answers *with the key*, in the same
        // buffer the search value went into. `bb->key` is where a module looks
        // for it, and it was null until this step.
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        let key = f.host.btrieve().block(block).expect("open").key();
        assert_ne!(key, Btrieve::<AbiMem<Wg16>>::null(), "opnbtv allocates it");

        assert!(query(&mut f, 0, 63), "highest");
        assert_eq!(got(&f, key), 7);
    }

    #[test]
    fn absbtv_names_a_record_and_gabbtvl_finds_it_again() {
        // `gcrbtv(rec,n)` is `gabbtvl(rec,absbtv(),n,0)` -- re-read where you
        // already are -- so these two have to agree exactly.
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        let into = buffer(&f, block);

        assert!(acquire(&mut f, Some(6), 0, 5), "equal to 6");
        let Ret::U32(position) = f.invoke(absbtv, &[]).expect("position") else {
            panic!("absbtv returns a long");
        };

        assert!(acquire(&mut f, None, 0, 12), "somewhere else entirely");
        assert_eq!(got(&f, into), 1);

        f.invoke(gabbtvl, &[0, 0, position as u16, (position >> 16) as u16, 0, 0])
            .expect("back to where it was");
        assert_eq!(got(&f, into), 6);

        // And the key path came with it: the next record in key order is 7.
        assert!(acquire(&mut f, None, -1, 6), "next");
        assert_eq!(got(&f, into), 7);
    }

    #[test]
    fn a_position_no_record_has_is_a_refusal_for_gabbtvl_and_a_no_for_aabbtv() {
        // The two differ in exactly this, which is why the module has both:
        // `PLBTVSTF.C:455` sends `gabbtvl`'s failure to `catastro`.
        //
        // Note the argument counts, which differ too: five words and six.
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 64);
        assert_eq!(
            f.invoke(aabbtv, &[0, 0, 7, 0, 0]).expect("answers"),
            Ret::U16(0)
        );
        assert!(f.invoke(gabbtvl, &[0, 0, 7, 0, 0, 0]).is_err());
    }

    #[test]
    fn the_absolute_family_leaves_the_found_key_in_the_key_buffer() {
        // `PLBTVSTF.C:484` passes `bb->keyseg` to Btrieve, which writes the
        // found record's key back into it -- exactly as the query and acquire
        // families do at `:274` and `:372`. This host did it for those two and
        // not for this one, so a module reading `bb->key` after a `gcrbtv` saw
        // whatever the last search had put there.
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        let key = f.host.btrieve().block(block).expect("open").key();

        assert!(acquire(&mut f, Some(6), 0, 5), "equal to 6");
        let Ret::U32(position) = f.invoke(absbtv, &[]).expect("position") else {
            panic!("absbtv returns a long");
        };

        // Somewhere else, so the key buffer holds something wrong to begin with.
        assert!(acquire(&mut f, None, 0, 12), "lowest");
        assert_eq!(got(&f, key), 1);

        f.invoke(aabbtv, &[0, 0, position as u16, (position >> 16) as u16, 0])
            .expect("back to where it was");
        assert_eq!(got(&f, key), 6, "aabbtv answers with the key it landed on");

        assert!(acquire(&mut f, None, 0, 12), "lowest again");
        f.invoke(gabbtvl,
            &[0, 0, position as u16, (position >> 16) as u16, 0, 0],
        )
        .expect("and gabbtvl too");
        assert_eq!(got(&f, key), 6);
    }

    #[test]
    fn a_second_key_orders_the_same_records_differently() {
        // `OTHER.DAT` is keyed by a name at offset 2 rather than by the number
        // at offset 0, so its key order is alphabetical: alpha, beta, gamma.
        let mut f = Fixture::new();
        let block = open(&mut f, "OTHER.DAT", 32);
        let into = buffer(&f, block);

        let mut names = vec![];
        assert!(acquire(&mut f, None, 0, 12), "lowest");
        names.push(f.read(FarPtr { offset: into.offset + 2, selector: into.selector }));
        while acquire(&mut f, None, -1, 6) {
            names.push(f.read(FarPtr { offset: into.offset + 2, selector: into.selector }));
        }
        assert_eq!(names, ["alpha", "beta", "gamma"]);
    }

    /// **This test used to assert the opposite, and the opposite was wrong.**
    ///
    /// Its reasoning was that "the record after nowhere" is not a record and
    /// that returning the first one would be answering a different question.
    /// That is a good argument and it is not what genuine Btrieve 6.15 does.
    /// `crates/mbbs/tests/btrieve.rs::position_ops_oracle_scenarios` `S1`
    /// measured a `Get Next` on a freshly opened, never-positioned file
    /// returning **status 0 and the first record** -- it behaves as
    /// `Get Lowest`.
    ///
    /// The old behaviour was the most damaging kind of divergence available
    /// here: a host error, which stops the module, in a case where the
    /// original answered normally. A module that opens a file and steps
    /// straight into `qnxbtv` was killed by this host and served by the real
    /// one.
    ///
    /// `S1c` measured the mirror case and it is **not** symmetric: an
    /// unpositioned `Get Previous` gives status 9, which this layer turns
    /// into a zero -- "no such record", an answer -- rather than a refusal.
    #[test]
    fn an_unpositioned_next_answers_with_the_lowest_record() {
        // What the record *is* is a property of the fixture, so this asks the
        // question that actually matters instead of naming a record: does an
        // unpositioned Get Next land where an explicit Get Lowest lands?
        // Hard-coding the answer here would pass just as well if `Next`
        // returned some other record for some other reason.
        let lowest = {
            let mut f = Fixture::new();
            let block = open(&mut f, "SAMPLE.DAT", 64);
            let into = buffer(&f, block);
            assert!(acquire(&mut f, None, 0, 12), "an explicit Get Lowest");
            f.machine.resolve(into, 64).expect("readable").to_vec()
        };

        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        let into = buffer(&f, block);
        assert_eq!(
            f.invoke(qnpbtv, &[56]).expect("answers"),
            Ret::U16(1),
            "S1: an unpositioned Get Next answers rather than refusing"
        );
        assert_eq!(
            f.machine.resolve(into, 64).expect("readable"),
            &lowest[..],
            "and it answers with the same record an explicit Get Lowest gives"
        );
    }

    /// `S6`: a `Get Equal` in one key's order followed by a `Get Next` in
    /// another's is refused by real Btrieve with status 7, "different key
    /// number". This host used to translate between the two orders through
    /// `Records::place_in` and answer.
    ///
    /// Needs a file with two keys, which `SAMPLE.DAT` is not -- it has
    /// exactly one. So the fixture is built by this crate's own
    /// [`crate::btrieve::create`], the Btrieve `Create` this task added, with
    /// the two keys deliberately ordering the same three records
    /// *oppositely*: key 0 ascending 1,2,3 is key 1 descending 3,2,1. That
    /// way a translation would not merely be unmeasured, it would land on a
    /// visibly different record, so this test fails loudly rather than
    /// coincidentally passing.
    #[test]
    fn a_next_in_another_keys_order_refuses_rather_than_translating() {
        let (mut f, _) = two_key_file("btv-shim-crosskey");

        assert!(
            acquire(&mut f, Some(2), 0, 5),
            "positioned by key 0, on the record whose key 0 is 2"
        );
        assert!(
            f.invoke(obtbtvl, &[0, 0, 0, 0, 1, 6, 0]).is_err(),
            "S6: a Get Next in key 1's order is refused, not translated"
        );
    }

    /// A two-key file holding three records whose keys order them
    /// **oppositely**: by key 0 they ascend 1, 2, 3 and by key 1 they ascend
    /// 3, 2, 1. That opposition is the point -- it means a test can tell
    /// which key an operation actually followed, instead of only that it
    /// answered.
    ///
    /// Built by this crate's own [`crate::btrieve::create`], because
    /// `SAMPLE.DAT` has exactly one key and nothing else in the tree has a
    /// two-key fixture.
    fn two_key_file(scratch: &str) -> (Fixture, FarPtr) {
        use crate::btrieve::{FileSpec, KeySpec, SegmentSpec, create};

        let key = |offset: u16| KeySpec {
            segments: vec![SegmentSpec {
                offset,
                length: 2,
                kind: 0x01,
                descending: false,
            }],
            duplicates: false,
            modifiable: false,
            acs: false,
        };

        let dir = crate::testing::scratch(scratch);
        create(
            &dir.join("TWOKEY.DAT"),
            &FileSpec {
                record_length: 8,
                page_size: 512,
                keys: vec![key(0), key(2)],
                acs: None,
                variable: false,
            },
        )
        .expect("creates a two-key file");

        let mut f = Fixture::rooted(dir);
        let block = open(&mut f, "TWOKEY.DAT", 8);

        for (first, second) in [(1u16, 3u16), (2, 2), (3, 1)] {
            let mut record = [0u8; 8];
            record[0..2].copy_from_slice(&first.to_le_bytes());
            record[2..4].copy_from_slice(&second.to_le_bytes());
            let at = f.bytes(&record, false);
            f.invoke(dinsbtv, &Fixture::far(at)).expect("inserts");
        }

        (f, block)
    }

    /// Where `gabbtvl`'s `keynum` goes, proved by what a following `qnxbtv`
    /// answers.
    ///
    /// **This pair exists because the seam it covers was covered by nothing.**
    /// The `abi` session measured it on the merged tree: no test anywhere did
    /// a `gabbtvl` followed by a `qnxbtv`, and all six `gabbtvl` invocations
    /// passed `keynum = 0` -- so the key-path half of `absolute()`'s argument
    /// list was pinned by nothing at all, exactly as `loktyp` had been before
    /// `c6e1e17` pinned word 5. The hole did not move; what changed is that
    /// [`locate`] now *refuses* a cross-key `Get Next` instead of translating
    /// it, which made the unpinned word start to matter.
    ///
    /// Neither of the pair can pass for the wrong reason:
    ///
    /// - if the wrong word were read for `keynum`, the **same-key** case
    ///   turns into a refusal;
    /// - if the `S6` refusal regressed to translating, the **cross-key** case
    ///   turns into an answer.
    ///
    /// This one is the same-key case, which is MajorMUD's own usage. It
    /// checks *which* record comes back rather than merely that one does:
    /// from the record whose keys are `(2, 2)`, key 1's next is `(1, 3)` and
    /// key 0's next is `(3, 1)`, so the first field alone says which order
    /// was followed. `S5` measured genuine Btrieve establishing the key path
    /// from Get Direct's key number, which is what makes answering correct
    /// here.
    #[test]
    fn a_get_direct_establishes_its_key_and_a_next_on_that_key_answers() {
        let (mut f, block) = two_key_file("btv-shim-direct-same");
        let into = buffer(&f, block);

        assert!(
            acquire(&mut f, Some(2), 0, 5),
            "learn where the record whose key 0 is 2 lives, through key 0"
        );
        let Ret::U32(position) = f.invoke(absbtv, &[]).expect("has a position") else {
            panic!("absbtv answers with a position");
        };

        // The same record, but reached through key ONE -- so the cursor this
        // leaves behind is key 1's, not the key 0 the acquire above used.
        f.invoke(gabbtvl,
            &[0, 0, position as u16, (position >> 16) as u16, 1, 0],
        )
        .expect("get direct, establishing key 1");

        assert_eq!(
            f.invoke(qnpbtv, &[56]).expect("answers"),
            Ret::U16(1),
            "a Get Next on the key gabbtvl established is not a cross-key ask"
        );

        let record = f.machine.resolve(into, 4).expect("readable");
        assert_eq!(
            u16::from_le_bytes([record[0], record[1]]),
            1,
            "and it followed KEY 1's order to (1,3) -- key 0's next would be (3,1)"
        );
    }

    /// The other half of the pair: same setup, but the `Get Next` names a
    /// different key than `gabbtvl` established, and is refused. See
    /// [`a_get_direct_establishes_its_key_and_a_next_on_that_key_answers`].
    #[test]
    fn a_get_direct_on_one_key_then_a_next_on_another_refuses() {
        let (mut f, _) = two_key_file("btv-shim-direct-cross");

        assert!(acquire(&mut f, Some(2), 0, 5), "learn where (2,2) lives");
        let Ret::U32(position) = f.invoke(absbtv, &[]).expect("has a position") else {
            panic!("absbtv answers with a position");
        };

        f.invoke(gabbtvl,
            &[0, 0, position as u16, (position >> 16) as u16, 1, 0],
        )
        .expect("get direct, establishing key 1");

        assert!(
            f.invoke(obtbtvl, &[0, 0, 0, 0, 0, 6, 0]).is_err(),
            "S6: a Get Next in key 0's order, from a key 1 position, refuses"
        );
    }

    /// `S4`/`S4b`: a step establishes no key context, so a `Get Next`
    /// afterwards is refused by real Btrieve with status 8 -- on *either*
    /// key of the two-key fixture the oracle scenario used, which is what
    /// rules out "it just means a different key".
    ///
    /// This host used to translate the physical position into key order
    /// through `Records::place_in` and answer. That produced a *plausible*
    /// record, which is worse than a refusal: nothing downstream can tell
    /// that the question was one the original would not have answered.
    #[test]
    fn a_next_after_a_step_refuses_rather_than_translating_the_position() {
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 64);

        assert!(
            f.invoke(stpbtvl, &[0, 0, 33, 0]).is_ok(),
            "step to the first record in physical order"
        );
        assert!(
            f.invoke(qnpbtv, &[56]).is_err(),
            "S4: and a Get Next afterwards is refused, not translated"
        );
    }

    /// `absbtv` on a never-positioned file is the one refusal of the three
    /// that the oracle **confirms**: `S1b` measured real Btrieve answering
    /// status 8, "invalid positioning", for a `Get Position` on a freshly
    /// opened file. So this one stays a refusal.
    ///
    /// The step in the middle is deliberately left as it was and is **not**
    /// claimed to be oracle-confirmed. `S1d` recorded a `Step Next` on a
    /// nominally unpositioned file answering with status 0, which would make
    /// this refusal wrong too -- but that scenario ran on a position block
    /// that earlier scenarios in the same handle had already moved, so what
    /// it measured may be "step from where S1 left the file" rather than
    /// "step from nowhere". Answering that needs a scenario with its own
    /// fresh handle, which has not been run. Recorded rather than acted on,
    /// because changing a refusal on an ambiguous measurement is exactly the
    /// mistake the other three fixes were correcting.
    #[test]
    fn a_cold_step_next_is_the_first_record_but_a_cold_position_refuses() {
        // The fresh-handle measurement the old refusal's own note asked for:
        // `tools/btrieve-oracle` `stepcold` opens a file and immediately
        // `B_STEP_NEXT` (24) -- genuine Btrieve 6.15 answers status 0 with the
        // first record (status 9 on an empty file), so a cold Step-Next is the
        // first record, not a refusal. `Get Position` (`absbtv`) from a fresh
        // open is still status 8 -- "invalid positioning" -- because there is
        // no current record to report the position of.
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 64);
        assert!(
            f.invoke(stpbtvl, &[0, 0, 24, 0]).is_ok(),
            "a cold Step-Next answers the first record, not a refusal"
        );
        // A second file, freshly opened, to keep `absbtv`'s check cold.
        let mut g = Fixture::new();
        open(&mut g, "SAMPLE.DAT", 64);
        assert!(g.invoke(absbtv, &[]).is_err(), "Get Position from nowhere has no position");
    }

    #[test]
    fn a_negative_key_number_with_a_key_value_measures_by_the_resolved_key() {
        // `PLBTVSTF.C:266` measures the copy with the key number as passed, so
        // `keylns[-1]` -- which is `lastkn`, two bytes below `keylns` in the
        // block. The real host copied a key-number's worth of bytes.
        //
        // This host resolves first and copies the key's real length. Not
        // reproducing an out-of-bounds read, and not refusing over it either:
        // the answer here is the better one. What it does owe is a note.
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        let key = f.host.btrieve().block(block).expect("open").key();

        // Establish key 0 as `lastkn`, then search it again by name.
        assert!(acquire(&mut f, Some(5), 0, 5), "equal to 5");
        assert!(acquire(&mut f, Some(3), -1, 5), "equal to 3, by the last key");
        assert_eq!(got(&f, key), 3, "the whole two-byte key value was copied");

        assert!(
            f.host.notes().iter().any(|n| n.contains("keylns")),
            "the divergence is recorded: {:?}",
            f.host.notes()
        );
    }

    #[test]
    fn a_negative_key_number_reads_lastkn_rather_than_being_stored_as_one() {
        // `PLBTVSTF.C:483` stores it unchecked -- the only place in the file
        // that does -- so the real `aabbtv(rec,pos,-1)` left -1 in `lastkn` and
        // the next keyed read asked Btrieve for key number -1.
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        let into = buffer(&f, block);

        assert!(acquire(&mut f, Some(6), 0, 5), "equal to 6, so lastkn is 0");
        let Ret::U32(position) = f.invoke(absbtv, &[]).expect("position") else {
            panic!("absbtv returns a long");
        };
        assert!(acquire(&mut f, None, 0, 12), "somewhere else entirely");

        let minus_one = -1i16 as u16;
        f.invoke(aabbtv,
            &[0, 0, position as u16, (position >> 16) as u16, minus_one],
        )
        .expect("a negative key number reads lastkn");
        assert_eq!(got(&f, into), 6);
        assert!(
            f.host.notes().iter().any(|n| n.contains("lastkn")),
            "and is recorded: {:?}",
            f.host.notes()
        );

        // And the key path really is key 0's, not key -1's: the next record in
        // that order is 7.
        assert!(acquire(&mut f, None, -1, 6), "next");
        assert_eq!(got(&f, into), 7);
    }

    #[test]
    fn a_key_the_file_does_not_have_is_refused() {
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 64);
        let e = f
            .invoke(qrybtv, &[0, 0, 3, 62])
            .expect_err("SAMPLE.DAT has one key");
        assert!(e.to_string().contains("key 3"), "{e}");
    }

    #[test]
    fn an_option_no_macro_produces_is_refused() {
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 64);
        assert!(f.invoke(qrybtv, &[0, 0, 0, 5]).is_err(), "5 is an acquire code");
        assert!(f.invoke(obtbtvl, &[0, 0, 0, 0, 0, 62, 0]).is_err(), "62 is a query code");
        assert!(f.invoke(stpbtvl, &[0, 0, 99, 0]).is_err());
    }

    /// **Replaces `a_lock_this_host_cannot_take_is_refused_rather_than_
    /// ignored`, retired now that Task 5 honours locks instead of refusing
    /// them** (`docs/lock-oracle-answer.md`; see [`take_lock`]'s own doc
    /// comment for the reversal). The old test asserted a refusal message
    /// naming "100"; a lock is now readable state instead of a rejection, so
    /// this asserts the engine recorded it -- same word (`obtbtvl`'s word 6,
    /// `loktyp`), same by-value discrimination, different observable.
    ///
    /// `obtopt = 12` (Lowest, word 5) and `loktyp = 100` (SLWTBV, word 6) are
    /// two different nonzero values on purpose: reading word 5 for the lock
    /// instead of word 6 would record lock type 12, not 100, so this fails
    /// on the wrong word rather than merely on the call failing to error.
    ///
    /// **Verified the hard way**: changing `obtbtvl`'s `let lock =
    /// machine.arg_u16(6)` to `arg_u16(5)` makes this test FAIL --
    /// `left: Some(12), right: Some(100)` -- confirming it discriminates by
    /// value rather than by the call merely succeeding either way.
    #[test]
    fn obtbtvl_records_its_lock_type_by_value() {
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);

        f.invoke(obtbtvl, &[0, 0, 0, 0, 0, 12, 100])
            .expect("Lowest, single lock with wait -- both are real Btrieve values");

        assert_eq!(
            f.host.btrieve().lock_at_current(block).expect("open"),
            Some(100),
            "word 6 is the lock; reading word 5 would have recorded lock type 12 (the opt)"
        );
    }

    /// `gabbtvl` reads its lock from **word 5**, and this proves it by value
    /// rather than by the call merely failing.
    ///
    /// **Retains its name and its word-5 pin across the mechanism change**
    /// (`docs/plans/2026-08-12-btrieve-finish.md`'s Task 5 acceptance
    /// criterion: "the mechanism changes; 'word 5, by value' must not").
    /// What changed is the observable: a refusal message used to be the only
    /// way to see which word was read; now the lock is state this test reads
    /// back, so it asserts on that instead.
    ///
    /// The frame carries `keynum = 1` in word 4 and `loktyp = 3` in word 5,
    /// two *different* nonzero values, and the assertion names the 3.
    /// Reading word 4 instead would record lock type 1, not 3 -- and could
    /// not even reach that far on `SAMPLE.DAT` (the fixture the old version
    /// of this test used), which has one key: a `keynum` of 3 misread from
    /// word 5 would refuse with `NoSuchKey` before any lock is recorded at
    /// all. This version uses [`two_key_file`] and a real, oracle-shaped
    /// position instead, so the wrong-word case fails on the *value*
    /// (`Some(1)` instead of `Some(3)`) rather than on an unrelated key
    /// error masking the question this test exists to answer.
    ///
    /// **Verified the hard way**: changing `gabbtvl`'s `let lock =
    /// machine.arg_u16(5)` to `arg_u16(4)` makes this test FAIL -- `left:
    /// Some(1), right: Some(3)`.
    ///
    /// **Why this exists separately from the `gabbtvl` key-path tests**
    /// (`a_get_direct_establishes_its_key_and_a_next_on_that_key_answers`,
    /// `a_get_direct_on_one_key_then_a_next_on_another_refuses`). Those two
    /// used to catch a lock read from word 4 *transitively*: they pass
    /// `keynum = 1`, so a misread lock became 1, and the old blanket refusal
    /// caught it as a side effect. That mechanism is gone now that locks are
    /// honoured -- both words would read `1`, a single lock would be taken
    /// without complaint, and both tests would carry on passing with the
    /// wrong word, exactly as `docs/plans/2026-08-12-btrieve-finish.md`
    /// warned. This test is what carries the pin now; the two key-path tests
    /// are not expected to, and are not changed to try.
    ///
    /// The `abi` session has an equivalent test on its own branch
    /// (`c6e1e17`). Deliberately named differently so the two merge as two
    /// tests rather than as a conflict; both pin the same word and neither is
    /// redundant until someone decides so on purpose.
    #[test]
    fn gabbtvl_takes_its_lock_from_word_five_by_value() {
        let (mut f, block) = two_key_file("btv-shim-gabbtvl-lock-word-five");

        assert!(
            acquire(&mut f, Some(2), 0, 5),
            "find the record whose key 0 is 2, to get a real position to lock"
        );
        let Ret::U32(position) = f.invoke(absbtv, &[]).expect("has a position") else {
            panic!("absbtv answers with a position");
        };

        f.invoke(gabbtvl,
            &[0, 0, position as u16, (position >> 16) as u16, 1, 3],
        )
        .expect("get direct, then take the lock");

        assert_eq!(
            f.host.btrieve().lock_at_current(block).expect("open"),
            Some(3),
            "word 5 is the lock; reading word 4 would have recorded lock type 1"
        );
    }

    // # With no Btrieve file current
    //
    // Six routines answer and two refuse, and which is which comes from
    // `PLBTVSTF.C` rather than from what is convenient. One test per routine
    // deliberately: a shared one would pass with five of the six still
    // refusing.

    /// A host on which `bb` is null, which is where a module starts and where a
    /// `rstbtv` too many puts it back.
    fn nothing_current() -> Fixture {
        let f = Fixture::new();
        assert_eq!(bb(&f), Btrieve::<AbiMem<Wg16>>::null(), "nothing is current to begin with");
        f
    }

    #[test]
    fn qrybtv_with_no_file_current_answers_nothing_found() {
        let mut f = nothing_current();
        assert_eq!(
            f.invoke(qrybtv, &[0, 0, 0, 62]).expect("answers"),
            Ret::U16(0)
        );
    }

    #[test]
    fn qnpbtv_with_no_file_current_answers_nothing_found() {
        // And in particular does not fail looking for `bb->data` to read into,
        // which is a null block away.
        let mut f = nothing_current();
        assert_eq!(f.invoke(qnpbtv, &[56]).expect("answers"), Ret::U16(0));
    }

    #[test]
    fn obtbtvl_with_no_file_current_answers_nothing_found() {
        // Call 128 of `_INIT__WCCMMUD`, and the reason this step exists. The
        // null `recptr` is the module's own: `alobtv`/`ahibtv` pass NULL, so
        // the guard has to come before `recptr` is defaulted to `bb->data`.
        let mut f = nothing_current();
        assert_eq!(
            f.invoke(obtbtvl, &[0, 0, 0, 0, 0, 12, 0]).expect("answers"),
            Ret::U16(0)
        );
    }

    #[test]
    fn aabbtv_with_no_file_current_answers_nothing_found() {
        // Five argument words, per `BTVSTF.H:155`.
        let mut f = nothing_current();
        assert_eq!(
            f.invoke(aabbtv, &[0, 0, 7, 0, 0]).expect("answers"),
            Ret::U16(0)
        );
    }

    #[test]
    fn absbtv_with_no_file_current_answers_a_long_zero() {
        // `PLBTVSTF.C:427` is `return(0L)`, and `absbtv` is declared `long`, so
        // the answer occupies `DX:AX` and not just `AX`. A `Ret::U16(0)` here
        // would pass a test that only compared the low half.
        let mut f = nothing_current();
        assert_eq!(f.invoke(absbtv, &[]).expect("answers"), Ret::U32(0));
    }

    /// `lock` is word 5 and `keynum` is word 4, and nothing else here tells
    /// them apart.
    ///
    /// Every other `gabbtvl` test passes `keynum = 0, lock = 0`, so trading the
    /// two reads is invisible -- measured, not supposed: swapping them during
    /// the cursor conversion of this file failed nothing at all, 1274/0 and
    /// 19/0. That is a hole exactly where this file is least able to afford
    /// one, because `gabbtvl` is the one routine whose reads used to span two
    /// functions and so the one whose argument order was restructured rather
    /// than merely rewritten.
    ///
    /// A non-zero lock has to be refused *by value*, which pins word 5
    /// specifically: read word 4 instead and this call succeeds silently.
    ///
    /// # If you are here because this test failed after you changed `unlocked`
    ///
    /// Then you have made this host accept a lock it used to refuse, which is
    /// the point of `docs/plans/2026-08-12-btrieve-finish.md`'s Task 5, and
    /// this test failed **loudly and on purpose** rather than quietly losing
    /// what it was holding. Measured, not assumed: making `unlocked` return
    /// `Ok(())` for every lock fails this test and
    /// `a_lock_this_host_cannot_take_is_refused_rather_than_ignored`, and
    /// nothing else.
    ///
    /// **Do not repair it by dropping the assertion or by passing a lock the
    /// new code still refuses.** Either turns it back into a test that cannot
    /// tell word 4 from word 5, and this is the only thing that can: the two
    /// are adjacent, the same width, and every other `gabbtvl` test passes
    /// zero for both.
    ///
    /// Repair it by re-pinning on whatever observable replaced the refusal. A
    /// lock that is *tracked* rather than refused is readable state, so assert
    /// that the engine recorded lock type 3 against this position. The
    /// mechanism changes; "word 5, by value" must not.
    #[test]
    fn gabbtvl_reads_its_lock_from_word_five_and_not_from_keynum() {
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        let into = buffer(&f, block);
        assert!(acquire(&mut f, Some(6), 0, 5), "equal to 6");
        let Ret::U32(position) = f.invoke(absbtv, &[]).expect("position") else {
            panic!("absbtv returns a long");
        };

        f.invoke(gabbtvl,
            &[0, 0, position as u16, (position >> 16) as u16, 0, 3],
        )
        .expect("get direct, then take the lock");

        // `keynum` is 0 here, so a read from word 4 records NO lock at all
        // rather than the wrong one -- `None` against `Some(3)`. That is a
        // different failure signature from
        // `gabbtvl_takes_its_lock_from_word_five_by_value`, which passes
        // `keynum = 1` and so fails as `Some(1)`. Both pin word 5; keeping
        // both means the defect is caught whichever way the neighbouring
        // word happens to be set at the call site.
        assert_eq!(
            f.host.btrieve().lock_at_current(block).expect("open"),
            Some(3),
            "word 5 is the lock; reading word 4 would have recorded nothing"
        );

        // And the record still arrived, so the lock did not cost the read.
        assert_eq!(got(&f, into), 6);
    }

    #[test]
    fn gabbtvl_with_no_file_current_answers_with_nothing_at_all() {
        // The odd one out in a family that otherwise returns an int: `:452`
        // returns from a `void`. What a caller can actually observe is the
        // record buffer, so that is what this checks -- a test on the return
        // value alone would not notice it scribbling.
        let mut f = nothing_current();
        let into = f.bytes(&[0xAA; 8], false);
        assert_eq!(
            f.invoke(gabbtvl,
                &[into.offset, into.selector, 0, 0, 0, 0]
            )
            .expect("answers"),
            Ret::Void
        );
        assert_eq!(
            f.machine.resolve(into, 8).expect("readable"),
            [0xAA; 8],
            "and left the module's buffer alone"
        );
    }

    #[test]
    fn the_null_bb_zero_is_the_same_zero_as_not_found() {
        // This is the argument the whole step rests on, so it is a test rather
        // than a paragraph. The rule everywhere else in this crate is that a
        // host which cannot answer stops the module; answering 0 here is not an
        // exception to it, because the module already gets this exact 0 from a
        // perfectly good file and every call site tests for it.
        let mut f = Fixture::new();
        open(&mut f, "EMPTY.DAT", 64);
        let not_found = f.invoke(qrybtv, &[0, 0, 0, 62]).expect("empty file");

        f.invoke(rstbtv, &[]).expect("restores");
        f.invoke(rstbtv, &[]).expect("and past the bottom");
        assert_eq!(bb(&f), Btrieve::<AbiMem<Wg16>>::null(), "nothing current now");
        let no_file = f.invoke(qrybtv, &[0, 0, 0, 62]).expect("no file");

        assert_eq!(not_found, no_file, "the module cannot tell them apart");
    }

    #[test]
    fn stpbtvl_with_no_file_current_refuses_by_name() {
        // The one step routine with no guard in `PLBTVSTF.C`. It dereferences
        // `bb` twice before checking anything, so the real host faulted and
        // there is no answer to reproduce.
        let mut f = nothing_current();
        let e = f.invoke(stpbtvl, &[0, 0, 33, 0]).expect_err("no file");
        assert!(e.to_string().contains("stpbtvl"), "{e}");

        // With a null `recptr` too, which is the path that used to refuse from
        // inside a `bb->data` lookup and so named the block rather than itself.
        let e = f.invoke(stpbtvl, &[0, 0, 24, 0]).expect_err("no file");
        assert!(e.to_string().contains("stpbtvl"), "{e}");
    }

    #[test]
    fn cntrbtv_with_no_file_current_refuses_by_name() {
        // Right refusal, different reason: `:681` never reads `bb` and would
        // have counted whatever Btrieve was positioned on. This host has no
        // such position, so there is nothing to count rather than nothing to
        // dereference.
        let mut f = nothing_current();
        let e = f.invoke(cntrbtv, &[]).expect_err("no file");
        assert!(e.to_string().contains("cntrbtv"), "{e}");
    }

    #[test]
    fn invbtv_with_no_file_current_inserts_nothing_and_says_so() {
        // `PLBTVSTF.C:584` is the same guard the six reads have, in a `void`
        // function: with no file current the real host inserted nothing and
        // returned. Call 130 of `_INIT__WCCMMUD` is exactly this.
        let mut f = nothing_current();
        assert_eq!(f.invoke(invbtv, &[0, 0, 64]).expect("answers"), Ret::Void);
        assert!(
            f.host.notes().iter().any(|n| n.contains("invbtv")),
            "and it is recorded: {:?}",
            f.host.notes()
        );
    }

    /// `invbtv` inserts, and the record survives a reopen.
    ///
    /// This test replaces one that asserted the opposite -- that `invbtv`
    /// refuses because "nothing in this host writes to a Btrieve file". That
    /// stopped being true when the v6 write path landed (2026-08-16), and the
    /// stale refusal is what stopped a real 16-bit MajorMUD booting: init
    /// calls `invbtv` into `WGSGEN2.DAT`. Its `dfa` twin `dfaInsertV` had been
    /// inserting successfully the whole time -- same export slot @357,
    /// `GALPORT.C:66`'s own `{"invbtv", "dfaInsertV"}` -- which is the cost of
    /// one routine having two bodies.
    ///
    /// Re-read through a fresh host, like `dinsbtv`'s own insert test: an
    /// in-memory model that agrees with itself proves nothing.
    #[test]
    fn invbtv_inserts_a_record_and_it_survives_a_reopen() {
        let dir = crate::testing::scratch_with("invbtv-insert", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir.clone());
        open(&mut f, "SAMPLE.DAT", 64);
        let recptr = f.bytes(&sample_record(97, "Vixen"), false);

        let mut args = Fixture::far(recptr).to_vec();
        args.push(64); // the length invbtv takes and insbtv reads off the block
        f.invoke(invbtv, &args).expect("inserts");

        let mut g = Fixture::rooted(dir);
        let block = open(&mut g, "SAMPLE.DAT", 64);
        let into = buffer(&g, block);
        assert!(acquire(&mut g, Some(97), 0, 5), "the new record is on disk");
        assert_eq!(
            g.read(FarPtr { offset: into.offset + 2, selector: into.selector }),
            "Vixen"
        );
    }

    /// A duplicate key must stop the module rather than answer, because
    /// `invbtv`'s underlying call has no case-5 branch -- unlike `dinsbtv`,
    /// whose whole `d` is that exception.
    #[test]
    fn invbtv_refuses_a_record_colliding_on_a_key_without_duplicates() {
        let dir = crate::testing::scratch_with("invbtv-dup", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir);
        open(&mut f, "SAMPLE.DAT", 64);
        let recptr = f.bytes(&sample_record(5, "Troll"), false);
        let mut args = Fixture::far(recptr).to_vec();
        args.push(64);
        let e = f.invoke(invbtv, &args).expect_err("5 is already Troll");
        assert!(e.to_string().contains("invbtv"), "{e}");
        assert!(e.to_string().contains("collided"), "{e}");
    }

    #[test]
    fn delbtv_with_no_file_current_deletes_nothing_and_says_so() {
        // `PLBTVSTF.C:623`, the same guard again.
        let mut f = nothing_current();
        assert_eq!(f.invoke(delbtv, &[]).expect("answers"), Ret::Void);
        assert!(
            f.host.notes().iter().any(|n| n.contains("delbtv")),
            "and it is recorded: {:?}",
            f.host.notes()
        );
    }

    #[test]
    fn delbtv_with_a_file_open_but_unpositioned_refuses_and_names_the_file() {
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 64);
        let e = f.invoke(delbtv, &[]).expect_err("open, but not positioned");
        assert!(e.to_string().contains("delbtv"), "{e}");
        assert!(e.to_string().contains("SAMPLE.DAT"), "{e}");
    }

    // # `dinsbtv`, which does write
    //
    // `SAMPLE.DAT` has one key -- a two-byte signed number at offset 0 -- and
    // it does not permit duplicates, which is what makes it enough to test a
    // collision against.

    /// A 64-byte `SAMPLE.DAT`-shaped record: the key at offset 0, a
    /// NUL-terminated name from offset 2, the rest zero.
    fn sample_record(key: i16, name: &str) -> Vec<u8> {
        let mut bytes = vec![0u8; 64];
        bytes[..2].copy_from_slice(&key.to_le_bytes());
        let name = name.as_bytes();
        bytes[2..2 + name.len()].copy_from_slice(name);
        bytes
    }

    #[test]
    fn dinsbtv_inserts_a_record_and_it_is_readable_afterwards() {
        let dir = crate::testing::scratch_with("dinsbtv-insert", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir.clone());
        open(&mut f, "SAMPLE.DAT", 64);
        let recptr = f.bytes(&sample_record(99, "Zorro"), false);

        assert_eq!(
            f.invoke(dinsbtv, &Fixture::far(recptr)).expect("inserts"),
            Ret::U16(1)
        );

        // Re-read from disk with a fresh host, which is the check that
        // matters -- an in-memory model that agrees with itself proves
        // nothing.
        let mut g = Fixture::rooted(dir);
        let block = open(&mut g, "SAMPLE.DAT", 64);
        let into = buffer(&g, block);
        assert!(acquire(&mut g, Some(99), 0, 5), "the new record is there");
        assert_eq!(
            g.read(FarPtr {
                offset: into.offset + 2,
                selector: into.selector
            }),
            "Zorro"
        );
    }

    #[test]
    fn dinsbtv_refuses_a_record_colliding_on_a_key_without_duplicates() {
        // `PLBTVSTF.C:610` maps Btrieve status 5 to a 0, not a `catastro` --
        // `_GENERATE_TOP_LIST` branches on the 0/1, so a collision has to be
        // an answer rather than a refusal.
        let dir = crate::testing::scratch_with("dinsbtv-collide", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir);
        open(&mut f, "SAMPLE.DAT", 64);
        let recptr = f.bytes(&sample_record(5, "Imposter"), false);

        assert_eq!(
            f.invoke(dinsbtv, &Fixture::far(recptr)).expect("answers"),
            Ret::U16(0),
            "key 5 already belongs to Troll"
        );
        assert_eq!(
            f.invoke(cntrbtv, &[]).expect("counts"),
            Ret::U32(7),
            "and nothing was written"
        );
    }

    /// Important: a duplicate-key answer of 0 is exactly the case where
    /// `_GENERATE_TOP_LIST` silently skips a character, and before this
    /// `duplicate_key` computed which key collided and both callers threw
    /// it away with `.is_some()` -- nothing said which file, which key, or
    /// what value collided. This crate's convention elsewhere (`note_no_file`,
    /// the `ties` note, the `setbtv` overflow note) is to report exactly
    /// this class of quiet divergence -- see `note_duplicate_key`.
    #[test]
    fn dinsbtv_notes_which_key_and_value_collided() {
        let dir = crate::testing::scratch_with("dinsbtv-collide-notes", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir);
        open(&mut f, "SAMPLE.DAT", 64);
        let recptr = f.bytes(&sample_record(5, "Imposter"), false);

        assert_eq!(
            f.invoke(dinsbtv, &Fixture::far(recptr)).expect("answers"),
            Ret::U16(0),
            "key 5 already belongs to Troll"
        );

        // SAMPLE.DAT's one key is key 0, and 5 as a little-endian i16 is
        // `[05, 00]` -- the same `{:02x?}` this crate already uses for raw
        // bytes in `crate::btrieve::Btrieve::open`'s file-control-record note.
        assert_eq!(
            f.host.notes(),
            &[
                "dinsbtv on SAMPLE.DAT refused a record: key 0 already holds \
                 [05, 00], and that key does not permit duplicates -- this \
                 call answers 0 rather than writing, and whichever record it \
                 was is silently skipped by whoever asked for the write"
            ]
        );
    }

    /// Same as `dinsbtv_notes_which_key_and_value_collided`, but through
    /// `dupdbtv`'s opcode-3 path -- the note names the routine that made the
    /// call, so the two must read differently.
    #[test]
    fn dupdbtv_notes_which_key_and_value_collided() {
        let dir = crate::testing::scratch_with("dupdbtv-collide-notes", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir);
        open(&mut f, "SAMPLE.DAT", 64);

        assert!(acquire(&mut f, Some(5), 0, 5), "equal to 5, which is Troll");
        let recptr = f.bytes(&sample_record(6, "Imposter"), false);

        assert_eq!(
            f.invoke(dupdbtv, &Fixture::far(recptr)).expect("answers"),
            Ret::U16(0),
            "key 6 already belongs to Elf"
        );

        assert_eq!(
            f.host.notes(),
            &[
                "dupdbtv on SAMPLE.DAT refused a record: key 0 already holds \
                 [06, 00], and that key does not permit duplicates -- this \
                 call answers 0 rather than writing, and whichever record it \
                 was is silently skipped by whoever asked for the write"
            ]
        );
    }

    /// Important: `dinsbtv` used to leave the cursor wherever it happened to
    /// be, rather than moving it onto the record it just inserted. Probed
    /// both directions, because the bug was direction-dependent: inserting a
    /// key that sorts before the cursor happened to land the (untouched)
    /// cursor on the new record by accident, and inserting one that sorts
    /// after it left the cursor on the old record, which is wrong. Btrieve's
    /// Insert establishes currency on the new record in both cases.
    #[test]
    fn dinsbtv_establishes_currency_on_the_new_record_regardless_of_sort_direction() {
        for key in [0u16, 9u16] {
            let dir = crate::testing::scratch_with(
                &format!("dinsbtv-currency-{key}"),
                &["SAMPLE.DAT"],
            );
            let mut f = Fixture::rooted(dir.clone());
            open(&mut f, "SAMPLE.DAT", 64);
            assert!(acquire(&mut f, Some(5), 0, 5), "equal to 5, which is Troll");

            let recptr = f.bytes(&sample_record(key as i16, "Newcomer"), false);
            assert_eq!(
                f.invoke(dinsbtv, &Fixture::far(recptr)).expect("inserts"),
                Ret::U16(1)
            );
            let Ret::U32(after) = f.invoke(absbtv, &[]).expect("position") else {
                panic!("absbtv returns a long");
            };

            // Independent of the cursor this test is checking: a fresh
            // fixture over the same directory, positioned on the new record
            // by its own key -- `dinsbtv` writes to disk immediately, so
            // this reads back exactly what landed there.
            let mut g = Fixture::rooted(dir);
            open(&mut g, "SAMPLE.DAT", 64);
            assert!(
                acquire(&mut g, Some(key), 0, 5),
                "the record dinsbtv just inserted, found by its own key"
            );
            let Ret::U32(expected) = g.invoke(absbtv, &[]).expect("position") else {
                panic!("absbtv returns a long");
            };

            assert_eq!(
                after, expected,
                "key {key}: dinsbtv must leave the cursor on the record it just \
                 inserted, not wherever it happened to be positioned before"
            );
        }
    }

    #[test]
    fn dinsbtv_with_no_file_current_stops_the_module() {
        // `PLBTVSTF.C:598` has no `bb == NULL` guard and reads `bb->reclen`
        // immediately, so the real host faulted with no file current. This
        // host stops the module instead of faulting -- the same outcome
        // honestly reached, and a different shape from `invbtv`/`delbtv`,
        // which answer quietly with no file current.
        let mut f = nothing_current();
        let e = f.invoke(dinsbtv, &[0, 0]).expect_err("no file current");
        assert!(e.to_string().contains("dinsbtv"), "{e}");
    }

    // # `dupdbtv`, which updates the record the cursor names
    //
    // `SAMPLE.DAT`'s seven records, keyed 1 through 7: Human, Gnome,
    // Halfling, Dwarf, Troll, Elf, Half-Ogre.

    #[test]
    fn dupdbtv_updates_the_record_the_cursor_names_and_it_is_readable_afterwards() {
        let dir = crate::testing::scratch_with("dupdbtv-update", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir.clone());
        open(&mut f, "SAMPLE.DAT", 64);

        assert!(acquire(&mut f, Some(5), 0, 5), "equal to 5, which is Troll");
        let Ret::U32(before) = f.invoke(absbtv, &[]).expect("position") else {
            panic!("absbtv returns a long");
        };

        let recptr = f.bytes(&sample_record(5, "TROLLX"), false);
        assert_eq!(
            f.invoke(dupdbtv, &Fixture::far(recptr)).expect("updates"),
            Ret::U16(1)
        );

        // An update is in place: `absbtv` answers the same before and after.
        let Ret::U32(after) = f.invoke(absbtv, &[]).expect("position") else {
            panic!("absbtv returns a long");
        };
        assert_eq!(before, after, "opcode 3 rewrites the record in place");

        // Re-read from disk with a fresh host, which is the check that
        // matters -- an in-memory model that agrees with itself proves
        // nothing.
        let mut g = Fixture::rooted(dir);
        let block = open(&mut g, "SAMPLE.DAT", 64);
        let into = buffer(&g, block);
        assert!(acquire(&mut g, Some(5), 0, 5), "still key 5");
        assert_eq!(
            g.read(FarPtr {
                offset: into.offset + 2,
                selector: into.selector
            }),
            "TROLLX"
        );
        assert_eq!(g.invoke(cntrbtv, &[]).expect("counts"), Ret::U32(7));
    }

    /// Critical: `Cursor::Ordered { key, at }` is an ordinal into a key's
    /// *sorted* order, and `Block::update` (via `Records::update`)
    /// re-sorts that order every time it runs -- so an ordinal left
    /// standing from before the write is a bet that the update did not
    /// change where the record sorts. Renaming Troll's key from 5 to
    /// something that sorts after every other record (Half-Ogre is the
    /// highest at 7) loses that bet: before the fix, `absbtv` after this
    /// `dupdbtv` answered Elf's position, because index 4 of key order --
    /// where Troll used to sit -- is Elf's slot once Troll has moved to the
    /// end.
    #[test]
    fn dupdbtv_maintains_currency_on_the_record_it_rewrote_even_when_its_key_moves() {
        let dir = crate::testing::scratch_with(
            "dupdbtv-currency-follows-the-move",
            &["SAMPLE.DAT"],
        );
        // `SAMPLE.DAT`'s key declares attributes 0x0100 -- not modifiable --
        // and this test's whole point is an update that moves the key, which
        // `Block::update` now refuses on such a key because genuine Btrieve
        // answers status 10 and `dupdbtv`'s own wrapper turns that into a
        // catastro. The subject here is cursor currency, not that rule, so the
        // scratch copy is made modifiable; the shared fixture is untouched.
        crate::testing::make_keys_modifiable(&dir.join("SAMPLE.DAT"));
        let mut f = Fixture::rooted(dir);
        open(&mut f, "SAMPLE.DAT", 64);

        assert!(acquire(&mut f, Some(5), 0, 5), "equal to 5, which is Troll");
        let Ret::U32(troll) = f.invoke(absbtv, &[]).expect("position") else {
            panic!("absbtv returns a long");
        };

        // 8 sorts after every one of SAMPLE.DAT's keys (1..=7), so Troll
        // moves from the middle of key order to the very end.
        let recptr = f.bytes(&sample_record(8, "TrollX"), false);
        assert_eq!(
            f.invoke(dupdbtv, &Fixture::far(recptr)).expect("updates"),
            Ret::U16(1)
        );

        let Ret::U32(after) = f.invoke(absbtv, &[]).expect("position") else {
            panic!("absbtv returns a long");
        };
        assert_eq!(
            after, troll,
            "opcode 3 maintains currency on the record it rewrote, wherever \
             its key now sorts -- not on whatever else landed on the old ordinal"
        );
    }

    #[test]
    fn dupdbtv_refuses_when_the_new_key_collides_with_a_different_record() {
        // Positioned on Troll (key 5); the buffer to write back names Elf's
        // key (6) instead. `exclude` in `duplicate_key` only excuses a
        // record from colliding with *itself* -- Elf is a different record,
        // so this is a real duplicate-key violation.
        let dir = crate::testing::scratch_with("dupdbtv-collide", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir);
        let block = open(&mut f, "SAMPLE.DAT", 64);
        let into = buffer(&f, block);

        assert!(acquire(&mut f, Some(5), 0, 5), "equal to 5, which is Troll");
        let recptr = f.bytes(&sample_record(6, "Imposter"), false);

        assert_eq!(
            f.invoke(dupdbtv, &Fixture::far(recptr)).expect("answers"),
            Ret::U16(0),
            "key 6 already belongs to Elf"
        );

        // Nothing was written: Troll is still findable by its own key.
        assert!(acquire(&mut f, Some(5), 0, 5), "Troll is unchanged");
        assert_eq!(
            f.read(FarPtr {
                offset: into.offset + 2,
                selector: into.selector
            }),
            "Troll"
        );
        assert_eq!(f.invoke(cntrbtv, &[]).expect("counts"), Ret::U32(7));
    }

    #[test]
    fn dupdbtv_with_nothing_positioned_stops_the_module() {
        // Cursor::Nowhere: the file is current but nothing has positioned it,
        // so there is no record for opcode 3 to update. Writing to a guessed
        // one is exactly the failure this crate exists to prevent.
        let dir = crate::testing::scratch_with("dupdbtv-unpositioned", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir);
        open(&mut f, "SAMPLE.DAT", 64);
        let recptr = f.bytes(&sample_record(1, "Nobody"), false);

        let e = f
            .invoke(dupdbtv, &Fixture::far(recptr))
            .expect_err("nothing has positioned the file");
        assert!(e.to_string().contains("dupdbtv"), "{e}");
    }

    #[test]
    fn dupdbtv_with_no_file_current_stops_the_module() {
        // `PLBTVSTF.C:550` has the same no-guard shape as `dinsbtv`.
        let mut f = nothing_current();
        let e = f.invoke(dupdbtv, &[0, 0]).expect_err("no file current");
        assert!(e.to_string().contains("dupdbtv"), "{e}");
    }

    // # `upvbtv`, `dupdbtv`'s variable-length sibling

    /// A delete leaves the file positioned [`Cursor::Nowhere`], asserted here
    /// as well as on the `dfaDelete` side.
    ///
    /// Both names share `delete_record` now, so one test would cover the
    /// core -- but only this one covers *this wrapper actually calling it*.
    /// Worth having for a second reason: when `delete_record` was extracted, a
    /// mutation removing the invalidation was caught by
    /// `dfadelete_leaves_the_file_positioned_nowhere` and by nothing on this
    /// side. `delbtv` was the transcription that had it right from the start
    /// and the property was never pinned here.
    #[test]
    fn delbtv_leaves_the_file_positioned_nowhere() {
        let dir = crate::testing::scratch_with("delbtv-cursor", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir);
        open(&mut f, "SAMPLE.DAT", 64);
        assert!(acquire(&mut f, Some(5), 0, 5), "positioned on Troll");
        f.invoke(delbtv, &[]).expect("deletes");

        let e = f
            .invoke(delbtv, &[])
            .expect_err("the cursor is Nowhere, so there is nothing to delete");
        assert!(
            e.to_string().contains("not positioned on a record"),
            "a delete must not leave the deleted record current: {e}"
        );
    }

    /// The record the cursor names is gone from the file on disk, and the
    /// count drops with it. Re-read through a fresh `Fixture` on purpose --
    /// an in-memory model that agrees with itself proves nothing.
    #[test]
    fn delbtv_deletes_the_record_the_cursor_names() {
        let dir = crate::testing::scratch_with("delbtv-delete", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir.clone());
        open(&mut f, "SAMPLE.DAT", 64);

        assert!(acquire(&mut f, Some(5), 0, 5), "equal to 5, which is Troll");
        assert_eq!(f.invoke(cntrbtv, &[]).expect("counts"), Ret::U32(7));

        f.invoke(delbtv, &[]).expect("deletes");

        let mut g = Fixture::rooted(dir);
        open(&mut g, "SAMPLE.DAT", 64);
        assert_eq!(g.invoke(cntrbtv, &[]).expect("counts"), Ret::U32(6));
        assert!(!acquire(&mut g, Some(5), 0, 5), "key 5 is gone from the file");
    }

    /// Opcode 4 deletes *the record the file is positioned on*. With nothing
    /// positioned there is no such record, and this refuses rather than
    /// picking one -- the same shape [`upvbtv`] already refuses with.
    #[test]
    fn delbtv_with_nothing_positioned_stops_the_module() {
        let dir = crate::testing::scratch_with("delbtv-unpositioned", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir);
        open(&mut f, "SAMPLE.DAT", 64);
        let e = f.invoke(delbtv, &[]).expect_err("nothing positioned");
        assert!(e.to_string().contains("delbtv"), "{e}");
    }

    #[test]
    fn upvbtv_updates_the_record_the_cursor_names_at_a_caller_given_length() {
        let dir = crate::testing::scratch_with("upvbtv-update", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir.clone());
        open(&mut f, "SAMPLE.DAT", 64);

        assert!(acquire(&mut f, Some(5), 0, 5), "equal to 5, which is Troll");
        let recptr = f.bytes(&sample_record(5, "TROLLX"), false);

        f.invoke(upvbtv, &[recptr.offset, recptr.selector, 64])
            .expect("updates");

        // Re-read from disk with a fresh host, the check that matters -- an
        // in-memory model that agrees with itself proves nothing.
        let mut g = Fixture::rooted(dir);
        let block = open(&mut g, "SAMPLE.DAT", 64);
        let into = buffer(&g, block);
        assert!(acquire(&mut g, Some(5), 0, 5), "still key 5");
        assert_eq!(
            g.read(FarPtr {
                offset: into.offset + 2,
                selector: into.selector
            }),
            "TROLLX"
        );
        assert_eq!(g.invoke(cntrbtv, &[]).expect("counts"), Ret::U32(7));
    }

    /// If this hard-coded `file.maxlen()` the way [`dupdbtv`] does instead of
    /// reading its own `length` argument, a deliberately wrong length would
    /// still succeed. `Block::update` refuses a fixed-length file a buffer
    /// that is not exactly its own `reclen` (64), so a 32-byte call only
    /// fails if `length` genuinely came from the argument.
    #[test]
    fn upvbtv_reads_its_own_length_argument_rather_than_the_files_reclen() {
        let dir = crate::testing::scratch_with("upvbtv-length-argument", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir);
        open(&mut f, "SAMPLE.DAT", 64);
        assert!(acquire(&mut f, Some(5), 0, 5), "equal to 5, which is Troll");
        let half = &sample_record(5, "TROLLX")[..32];
        let recptr = f.bytes(half, false);

        let e = f
            .invoke(upvbtv, &[recptr.offset, recptr.selector, 32])
            .expect_err("a 32-byte write to a 64-byte fixed-length file");
        assert!(e.to_string().contains("64"), "{e}");
    }

    /// The behavioural difference from [`dupdbtv`]: `PLBTVSTF.C:539` sends
    /// *any* nonzero status to `btverrptr` unconditionally -- there is no
    /// `switch` carving status 5 (duplicate key) into a quiet `0` the way
    /// `dupdbtv`'s own body does. A collision through `upvbtv` stops the
    /// module.
    #[test]
    fn upvbtv_refuses_a_duplicate_key_rather_than_answering_zero() {
        let dir = crate::testing::scratch_with("upvbtv-collide", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir);
        open(&mut f, "SAMPLE.DAT", 64);
        assert!(acquire(&mut f, Some(5), 0, 5), "equal to 5, which is Troll");
        let recptr = f.bytes(&sample_record(6, "Imposter"), false);

        let e = f
            .invoke(upvbtv, &[recptr.offset, recptr.selector, 64])
            .expect_err("key 6 already belongs to Elf");
        assert!(e.to_string().contains("upvbtv"), "{e}");
    }

    #[test]
    fn upvbtv_with_nothing_positioned_stops_the_module() {
        // Cursor::Nowhere: the file is current but nothing has positioned it,
        // so there is no record for opcode 3 to update.
        let dir = crate::testing::scratch_with("upvbtv-unpositioned", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir);
        open(&mut f, "SAMPLE.DAT", 64);
        let recptr = f.bytes(&sample_record(1, "Nobody"), false);

        let e = f
            .invoke(upvbtv, &[recptr.offset, recptr.selector, 64])
            .expect_err("nothing has positioned the file");
        assert!(e.to_string().contains("upvbtv"), "{e}");
    }

    /// The other behavioural difference from [`dupdbtv`]/[`dinsbtv`]:
    /// `PLBTVSTF.C:534-536` has a `bb == NULL` guard where those two do not,
    /// so no file current answers with nothing rather than stopping the
    /// module -- the same "answer rather than refuse" shape
    /// `qrybtv`/`obtbtvl`/etc. already get, shaped as `void`'s own version of
    /// `0`.
    #[test]
    fn upvbtv_with_no_file_current_is_a_quiet_no_op() {
        let mut f = nothing_current();
        let recptr = f.bytes(&sample_record(1, "Nobody"), false);
        f.invoke(upvbtv, &[recptr.offset, recptr.selector, 64])
            .expect("a quiet no-op, not a stop");
        let noted = f.host.notes().iter().filter(|n| n.contains("upvbtv")).count();
        assert_eq!(noted, 1, "{:?}", f.host.notes());
    }

    // # `clsbtv`, which rebuilds the index and gives four allocations back
    //
    // `SAMPLE.DAT` and `OTHER.DAT` are hand-built fixtures with no real index
    // root -- `key 0`'s root page is `0`, which `reindex` refuses rather than
    // write over the file control record. That is fine for every test below:
    // none of them ever dirties a block before closing it, so `reindex` is
    // never asked to run. The case where it *is* asked -- a dirty block with
    // a real root -- is `close_reindexes_a_dirty_block_but_never_a_clean_one`
    // in `crate::btrieve`'s own tests, which has `seed_indexed`'s properly
    // rooted fixture to use instead.

    #[test]
    fn clsbtv_closes_a_file_and_gives_its_four_allocations_back() {
        let dir = crate::testing::scratch_with("clsbtv-close", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir);
        let block = open(&mut f, "SAMPLE.DAT", 64);

        let key = f.host.btrieve.block(block).expect("open").key();
        let data = f.host.btrieve.block(block).expect("open").data();
        let filnam = FarPtr {
            offset: field(&f, block, 128),
            selector: field(&f, block, 130),
        };
        assert!(f.host.heap.block(key).is_some(), "the key buffer is allocated");
        assert!(f.host.heap.block(data).is_some(), "the record buffer is allocated");
        assert!(f.host.heap.block(filnam).is_some(), "the name is allocated");
        assert!(f.host.heap.block(block).is_some(), "the block itself is allocated");

        f.invoke(clsbtv, &Fixture::far(block)).expect("closes");

        assert!(
            f.host.btrieve.files().iter().all(|b| b.block() != block),
            "the block is gone from the open files"
        );
        assert_eq!(
            bb(&f),
            block,
            "closing a file makes it current on the way out, per PLBTVSTF.C:637"
        );

        assert!(f.host.heap.block(key).is_none(), "the key buffer came back");
        assert!(f.host.heap.block(data).is_none(), "the record buffer came back");
        assert!(f.host.heap.block(filnam).is_none(), "the name came back");
        assert!(f.host.heap.block(block).is_none(), "the block itself came back");
    }

    #[test]
    fn clsbtv_on_an_already_closed_block_does_nothing() {
        let dir = crate::testing::scratch_with("clsbtv-double-close", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir);
        let block = open(&mut f, "SAMPLE.DAT", 64);

        f.invoke(clsbtv, &Fixture::far(block)).expect("closes");
        // A second close of the same pointer: `filnam` is already null, so
        // `PLBTVSTF.C:637`'s guard is false and nothing runs -- in
        // particular nothing tries to free what the first close already
        // gave back, which would be a double free if it did.
        f.invoke(clsbtv, &Fixture::far(block))
            .expect("a no-op, not an error");
        assert_eq!(
            bb(&f),
            block,
            "bb is written whether or not there was anything to close"
        );
    }

    #[test]
    fn clsbtv_leaves_a_clean_block_completely_untouched() {
        // `OTHER.DAT` is never written to, so a close of it must leave the
        // file byte-for-byte as it was -- not merely unchanged in meaning,
        // but never opened for writing at all. `index_pages` refuses any
        // key needing more than one leaf page, which is most of the files
        // MajorMUD ships records in, and `dirty` is the only thing standing
        // between a clean close and that refusal -- see
        // `close_reindexes_a_dirty_block_but_never_a_clean_one` for the case
        // where the block *is* dirty.
        let dir = crate::testing::scratch_with("clsbtv-clean-untouched", &["OTHER.DAT"]);
        let path = dir.join("OTHER.DAT");
        let before = std::fs::read(&path).expect("read before");

        let mut f = Fixture::rooted(dir);
        let other = open(&mut f, "OTHER.DAT", 32);
        f.invoke(clsbtv, &Fixture::far(other)).expect("closes");

        let after = std::fs::read(&path).expect("read after");
        assert_eq!(before, after, "a clean close never touches the file");
    }

    // # `clsbb`, `clsbtv`'s zero-argument sibling -- see that shim's own doc
    // comment for why it reads `clsbtv(bb)` rather than a source citation.

    #[test]
    fn clsbb_closes_whatever_file_setbtv_left_current() {
        let dir = crate::testing::scratch_with("clsbb-close", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir);
        let block = open(&mut f, "SAMPLE.DAT", 64);
        assert_eq!(bb(&f), block, "opening made it current");

        f.invoke(clsbb, &[]).expect("closes");

        assert!(
            f.host.btrieve.files().iter().all(|b| b.block() != block),
            "the block is gone from the open files"
        );
        assert!(f.host.heap.block(block).is_none(), "the block itself came back");
    }

    #[test]
    fn clsbb_with_nothing_current_is_a_quiet_no_op() {
        let mut f = nothing_current();
        f.invoke(clsbb, &[]).expect("a no-op, not an error");
    }

    /// The discriminator against a shim that closes "whatever `opnbtv` last
    /// returned" instead of "whatever `bb` names": open two files, `setbtv`
    /// back to the first, and check `clsbb` takes the one `setbtv` actually
    /// left current -- not the second, more-recently-opened one.
    #[test]
    fn clsbb_closes_the_current_file_not_merely_the_last_one_opened() {
        let dir = crate::testing::scratch_with("clsbb-current-not-last", &["SAMPLE.DAT", "OTHER.DAT"]);
        let mut f = Fixture::rooted(dir);
        let first = open(&mut f, "SAMPLE.DAT", 64);
        let second = open(&mut f, "OTHER.DAT", 32);
        f.invoke(setbtv, &Fixture::far(first)).expect("set back to the first");
        assert_eq!(bb(&f), first, "setbtv moved current back to the first file");

        f.invoke(clsbb, &[]).expect("closes");

        assert!(
            f.host.btrieve.files().iter().all(|b| b.block() != first),
            "the block setbtv left current is the one that closed"
        );
        assert!(
            f.host.btrieve.files().iter().any(|b| b.block() == second),
            "the other file, not current, stays open"
        );
    }

    #[test]
    fn the_missing_file_is_noted_once_however_often_it_is_asked() {
        // A null `bb` is legitimate and is also what an upstream mistake looks
        // like. The note is the only channel that says so -- and one identical
        // line per iteration of a module's loop is a channel nobody reads.
        let mut f = nothing_current();
        for _ in 0..50 {
            assert_eq!(
                f.invoke(qrybtv, &[0, 0, 0, 62]).expect("answers"),
                Ret::U16(0)
            );
        }
        let noted: Vec<&String> = f
            .host
            .notes()
            .iter()
            .filter(|n| n.contains("qrybtv"))
            .collect();
        assert_eq!(noted.len(), 1, "{:?}", f.host.notes());

        // Per routine, not per host: a second routine has its own to say.
        f.invoke(obtbtvl, &[0, 0, 0, 0, 0, 12, 0]).expect("answers");
        assert!(
            f.host.notes().iter().any(|n| n.contains("obtbtvl")),
            "{:?}",
            f.host.notes()
        );
    }

    #[test]
    fn a_block_that_names_no_open_file_is_still_a_refusal() {
        // Answering 0 is for a *null* `bb` -- the value `rstbtv` produces and
        // `PLBTVSTF.C` checks for. A non-null pointer to nothing is a different
        // thing entirely, and `setbtv` already refuses it; this pins that the
        // routines behind it do too, in case anything ever writes `bb`
        // directly.
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        let nonsense = FarPtr {
            offset: block.offset,
            selector: f.host.globals().selector(),
        };
        f.host
            .globals()
            .write(&mut f.machine, "bb", &nonsense.to_bytes())
            .expect("bb");

        for who in ["qrybtv", "obtbtvl", "absbtv", "cntrbtv"] {
            let e = match who {
                "qrybtv" => f.invoke(qrybtv, &[0, 0, 0, 62]),
                "obtbtvl" => f.invoke(obtbtvl, &[0, 0, 0, 0, 0, 12, 0]),
                "absbtv" => f.invoke(absbtv, &[]),
                _ => f.invoke(cntrbtv, &[]),
            }
            .expect_err("{who} on a block that was never opened");
            assert!(e.to_string().contains(who), "{who}: {e}");
        }
    }

    // -----------------------------------------------------------------
    // Task 3: `bxabtv`/`exabtv`.
    // -----------------------------------------------------------------

    #[test]
    fn bxabtv_then_exabtv_commits_and_leaves_no_transaction_open() {
        let dir = crate::testing::scratch_with("bxabtv-commit", &["SAMPLE.DAT"]);
        let mut f = Fixture::rooted(dir.clone());
        open(&mut f, "SAMPLE.DAT", 64);
        let recptr = f.bytes(&sample_record(99, "Zorro"), false);

        f.invoke(bxabtv, &[0]).expect("begin");
        assert_eq!(
            f.invoke(dinsbtv, &Fixture::far(recptr)).expect("inserts"),
            Ret::U16(1)
        );
        f.invoke(exabtv, &[]).expect("end (commit)");

        // A second end with nothing open must be refused the same way
        // dfaEndTrans refuses it -- one engine, one answer.
        let e = f.invoke(exabtv, &[]).expect_err("no transaction is open");
        assert!(e.to_string().contains("NoneActive") || e.to_string().to_lowercase().contains("no"), "{e}");

        // The commit is real, not merely in-memory: a fresh host reading the
        // same file from disk still finds the record.
        let mut g = Fixture::rooted(dir);
        open(&mut g, "SAMPLE.DAT", 64);
        assert!(acquire(&mut g, Some(99), 0, 5), "Zorro survived the commit");
    }

    #[test]
    fn bxabtv_twice_is_refused_exactly_as_dfabegtrans_is() {
        let mut f = Fixture::new();
        f.invoke(bxabtv, &[0]).expect("begin");
        let e = f.invoke(bxabtv, &[0]).expect_err("already open");
        assert!(e.to_string().contains("Already") || e.to_string().to_lowercase().contains("already"), "{e}");
    }

    // -----------------------------------------------------------------
    // Task 4: `getbtvl`, `anpbtvl`, `anpbtvlk`, `aabbtvl`, `unlbtv`.
    // -----------------------------------------------------------------

    #[test]
    fn getbtvl_reads_the_same_record_getbtv_does() {
        // The locking variant differs from the unlocked one only in the lock
        // it takes -- if this host cannot contend a lock, the RECORD must
        // still match exactly. A divergence here would be a bug in the
        // argument frame, since getbtvl reads one more argument than getbtv.
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 64);
        let key = f.bytes(&5i16.to_le_bytes(), false);
        let into_a = f.bytes(&[0u8; 64], false);
        let into_b = f.bytes(&[0u8; 64], false);

        f.invoke(getbtv, &[into_a.offset, into_a.selector, key.offset, key.selector, 0, 5])
            .expect("gets");
        f.invoke(getbtvl,
            &[into_b.offset, into_b.selector, key.offset, key.selector, 0, 5, 0],
        )
        .expect("gets, locked");

        let a = f.machine.resolve(into_a, 64).expect("readable").to_vec();
        let b = f.machine.resolve(into_b, 64).expect("readable").to_vec();
        assert_eq!(a, b, "getbtvl must deliver the same record getbtv does");
    }

    /// Verified the hard way, same discipline as `obtbtvl_records_its_
    /// lock_type_by_value`: `keynum = 0` (word 5) and `opt = 5` (word 6) are
    /// both different from `lock = 100` (word 7), so reading the wrong word
    /// for the lock records the wrong value rather than merely succeeding.
    #[test]
    fn getbtvl_records_its_lock_type_by_value() {
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        let key = f.bytes(&5i16.to_le_bytes(), false);

        f.invoke(getbtvl, &[0, 0, key.offset, key.selector, 0, 5, 100])
            .expect("equal to 5, single lock with wait");

        assert_eq!(
            f.host.btrieve().lock_at_current(block).expect("open"),
            Some(100),
            "word 7 is the lock; reading word 6 would have recorded 5 (opt)"
        );
    }

    #[test]
    fn getbtvl_with_no_file_current_answers_nothing_at_all() {
        let mut f = nothing_current();
        // void, so success with no write is the whole of the answer.
        f.invoke(getbtvl, &[0, 0, 0, 0, 0, 5, 0]).expect("answers");
    }

    fn anp_setup() -> (Fixture, FarPtr) {
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        assert!(acquire(&mut f, Some(4), 0, 5), "equal to 4");
        (f, block)
    }

    #[test]
    fn anpbtvl_and_anpbtvlk_agree_with_anpbtv_at_their_default_arguments() {
        let (mut a, _) = anp_setup();
        let want = a.invoke(anpbtv, &[0, 0, 6]).expect("acquire-next");

        let (mut b, _) = anp_setup();
        let got_l = b.invoke(anpbtvl, &[0, 0, 1, 6]).expect("chkcas=1, acquire-next");

        let (mut c, _) = anp_setup();
        let got_lk = c.invoke(anpbtvlk, &[0, 0, 1, 6, 0]).expect("chkcas=1, loktyp=0, acquire-next");

        assert_eq!(want, got_l, "anpbtvl(recp,1,opt) must match anpbtv(recp,opt)");
        assert_eq!(want, got_lk, "anpbtvlk(recp,1,opt,0) must match anpbtv(recp,opt)");
    }

    #[test]
    fn anpbtvlk_records_its_lock_type_by_value() {
        let (mut f, block) = anp_setup();
        f.invoke(anpbtvlk, &[0, 0, 1, 6, 100]).expect("acquire-next, locked");
        assert_eq!(
            f.host.btrieve().lock_at_current(block).expect("open"),
            Some(100),
            "word 5 is the lock, not chkcas (word 3) or anpopt (word 4)"
        );
    }

    #[test]
    fn anpbtvl_with_no_file_current_answers_nothing_found() {
        let mut f = nothing_current();
        assert_eq!(
            f.invoke(anpbtvl, &[0, 0, 1, 6]).expect("answers"),
            Ret::U16(0)
        );
    }

    #[test]
    fn aabbtvl_records_its_lock_type_by_value() {
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        assert!(acquire(&mut f, Some(6), 0, 5), "equal to 6");
        let Ret::U32(position) = f.invoke(absbtv, &[]).expect("position") else {
            panic!("absbtv returns a long");
        };

        f.invoke(aabbtvl,
            &[0, 0, position as u16, (position >> 16) as u16, 0, 100],
        )
        .expect("acquires, locked");

        assert_eq!(
            f.host.btrieve().lock_at_current(block).expect("open"),
            Some(100),
            "word 6 is the lock, not keynum (word 5)"
        );
    }

    #[test]
    fn aabbtvl_answers_zero_rather_than_refusing_when_nothing_is_at_the_position() {
        // aabbtvl shares aabbtv's fatal:false convention (a quiet no), not
        // gabbtvl's refusal -- the two differ in exactly Position::fatal.
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 64);
        assert_eq!(
            f.invoke(aabbtvl, &[0, 0, 0xff, 0xff, 0, 0]).expect("answers"),
            Ret::U16(0)
        );
    }

    #[test]
    fn aabbtvl_with_no_file_current_answers_nothing_found() {
        let mut f = nothing_current();
        assert_eq!(
            f.invoke(aabbtvl, &[0, 0, 7, 0, 0, 0]).expect("answers"),
            Ret::U16(0)
        );
    }

    #[test]
    fn unlbtv_releases_the_lock_at_the_current_position_with_keynum_zero() {
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        f.invoke(obtbtvl, &[0, 0, 0, 0, 0, 12, 100]).expect("lowest, single lock");
        assert_eq!(f.host.btrieve().lock_at_current(block).expect("open"), Some(100));

        f.invoke(unlbtv, &[0, 0, 0]).expect("unlocks");
        assert_eq!(f.host.btrieve().lock_at_current(block).expect("open"), None);
    }

    #[test]
    fn unlbtv_releases_a_lock_at_an_explicit_position_with_keynum_minus_one() {
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        f.invoke(obtbtvl, &[0, 0, 0, 0, 0, 12, 100]).expect("lowest, single lock");
        let Ret::U32(position) = f.invoke(absbtv, &[]).expect("position") else {
            panic!("absbtv returns a long");
        };

        let minus_one = -1i16 as u16;
        f.invoke(unlbtv, &[position as u16, (position >> 16) as u16, minus_one])
            .expect("unlocks at the explicit position");
        assert_eq!(f.host.btrieve().lock_at_current(block).expect("open"), None);
    }

    #[test]
    fn unlbtv_releases_every_lock_even_when_positioned_elsewhere_with_keynum_minus_two() {
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        f.invoke(obtbtvl, &[0, 0, 0, 0, 0, 12, 300]).expect("lowest, multiple lock");
        let Ret::U32(position) = f.invoke(absbtv, &[]).expect("position") else {
            panic!("absbtv returns a long");
        };
        // Move elsewhere, taking no new lock (loktyp 0) -- so the file is no
        // longer positioned where the lock above was taken.
        assert!(acquire(&mut f, None, 0, 13), "highest, no lock");

        let minus_two = -2i16 as u16;
        f.invoke(unlbtv, &[0, 0, minus_two]).expect("unlocks everything");

        f.invoke(aabbtv, &[0, 0, position as u16, (position >> 16) as u16, 0])
            .expect("re-acquire the earlier, locked position");
        assert_eq!(
            f.host.btrieve().lock_at_current(block).expect("open"),
            None,
            "keynum -2 released a lock held somewhere other than the current position"
        );
    }

    #[test]
    fn unlbtv_with_no_file_current_refuses_by_name() {
        let mut f = Fixture::new();
        let e = f.invoke(unlbtv, &[0, 0, 0]).expect_err("no file current");
        assert!(e.to_string().contains("unlbtv"), "{e}");
    }

    #[test]
    fn unlbtv_with_an_unrecognised_keynum_is_refused() {
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 64);
        let e = f.invoke(unlbtv, &[0, 0, 7]).expect_err("7 is none of the three flavours");
        assert!(e.to_string().contains("flavours"), "{e}");
    }

    // -----------------------------------------------------------------
    // Task 5: `sttbtv`, `rlenbtv`, `wslbtv`, `llnbtv`.
    // -----------------------------------------------------------------

    #[test]
    fn sttbtv_stores_the_argument_it_is_given() {
        let mut f = Fixture::new();
        f.invoke(sttbtv, &[300]).expect("stores");
        assert_eq!(f.host.btrieve().stt_length(), 300);
    }

    #[test]
    fn rlenbtv_answers_the_files_own_fixed_record_length_not_sttbtvs() {
        // sttbtv and rlenbtv sit beside each other in BTVSTF.H's list, but
        // rlenbtv's real body (PLBTVSTF.C, both generations) queries the
        // file's own STAT reply, unrelated to whatever sttbtv was last told.
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 64);
        f.invoke(sttbtv, &[9999]).expect("stores, irrelevant to rlenbtv");
        assert_eq!(f.invoke(rlenbtv, &[]).expect("answers"), Ret::U16(64));
    }

    #[test]
    fn rlenbtv_with_no_file_current_refuses_by_name() {
        let mut f = Fixture::new();
        let e = f.invoke(rlenbtv, &[]).expect_err("no file current");
        assert!(e.to_string().contains("rlenbtv"), "{e}");
    }

    #[test]
    fn wslbtv_always_answers_zero() {
        // This host cannot produce Btrieve status 84/85 at all -- see
        // wslbtv's own doc comment -- so there is no call sequence on hand
        // that makes this answer anything else.
        let mut f = Fixture::new();
        assert_eq!(f.invoke(wslbtv, &[]).expect("answers"), Ret::U16(0));
        open(&mut f, "SAMPLE.DAT", 64);
        assert!(!acquire(&mut f, Some(9999), 0, 5), "no such key");
        assert_eq!(f.invoke(wslbtv, &[]).expect("still zero"), Ret::U16(0));
    }

    #[test]
    fn llnbtv_answers_the_length_deliver_last_copied() {
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 64);
        assert_eq!(f.invoke(llnbtv, &[]).expect("answers"), Ret::U16(0), "nothing read yet");
        assert!(acquire(&mut f, Some(5), 0, 5), "equal to 5");
        assert_eq!(
            f.invoke(llnbtv, &[]).expect("answers"),
            Ret::U16(64),
            "SAMPLE.DAT's own record length, the whole record delivered"
        );
    }

    // -----------------------------------------------------------------
    // Task 6: `crtbtv`.
    // -----------------------------------------------------------------

    /// Build a Btrieve create buffer: one 16-byte File Specification and one
    /// 16-byte Key Specification per key, per `crtbtv`'s own doc comment.
    fn file_spec_block(reclen: u16, page: u16, keys: &[(u16, u16, u8, bool)]) -> Vec<u8> {
        let mut out = vec![0u8; 16 + 16 * keys.len()];
        out[0..2].copy_from_slice(&reclen.to_le_bytes());
        out[2..4].copy_from_slice(&page.to_le_bytes());
        out[4..6].copy_from_slice(&(keys.len() as u16).to_le_bytes());
        // flags (10..12) and allocation (14..16) left zero.
        let mut at = 16;
        for &(offset, length, kind, duplicates) in keys {
            out[at..at + 2].copy_from_slice(&(offset + 1).to_le_bytes()); // 1-based
            out[at + 2..at + 4].copy_from_slice(&length.to_le_bytes());
            let flags: u16 = if duplicates { 1 } else { 0 };
            out[at + 4..at + 6].copy_from_slice(&flags.to_le_bytes());
            out[at + 10] = kind;
            at += 16;
        }
        out
    }

    #[test]
    fn crtbtv_creates_a_file_the_hosts_own_reader_can_open() {
        let dir = crate::testing::scratch("crtbtv-create");
        let mut f = Fixture::rooted(dir.clone());
        let name = f.text("MADE.DAT");
        let spec = file_spec_block(64, 512, &[(0, 4, 0x0e, false)]);
        let spec_ptr = f.bytes(&spec, false);

        f.invoke(crtbtv,
            &[name.offset, name.selector, spec_ptr.offset, spec_ptr.selector, spec.len() as u16, 0],
        )
        .expect("creates");

        let g = crate::btrieve::Geometry::read("MADE.DAT", &dir.join("MADE.DAT")).expect("opens");
        assert_eq!((g.page, g.reclen, g.keys), (512, 64, 1));
    }

    #[test]
    fn crtbtv_refuses_a_keyno_that_is_not_an_overwrite_selector() {
        let dir = crate::testing::scratch("crtbtv-bad-keyno");
        let mut f = Fixture::rooted(dir);
        let name = f.text("MADE2.DAT");
        let spec = file_spec_block(64, 512, &[(0, 4, 0x0e, false)]);
        let spec_ptr = f.bytes(&spec, false);

        let e = f.invoke(crtbtv,
            &[name.offset, name.selector, spec_ptr.offset, spec_ptr.selector, spec.len() as u16, 7],
        )
        .expect_err("7 is neither 0 nor -1");
        assert!(e.to_string().contains("overwrite"), "{e}");
    }

    #[test]
    fn crtbtv_creates_a_two_key_file_with_the_right_geometry() {
        let dir = crate::testing::scratch("crtbtv-two-keys");
        let mut f = Fixture::rooted(dir.clone());
        let name = f.text("MADE3.DAT");
        let spec = file_spec_block(8, 512, &[(0, 4, 0x0e, false), (4, 4, 0x0e, true)]);
        let spec_ptr = f.bytes(&spec, false);

        f.invoke(crtbtv,
            &[name.offset, name.selector, spec_ptr.offset, spec_ptr.selector, spec.len() as u16, 0],
        )
        .expect("creates");

        let g = crate::btrieve::Geometry::read("MADE3.DAT", &dir.join("MADE3.DAT")).expect("opens");
        assert_eq!(g.keys, 2, "two keys declared in the buffer");
        assert_eq!(g.reclen, 8);
    }
}
