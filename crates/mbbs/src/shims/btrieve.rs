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
//! # `dinsbtv` and `dupdbtv` write; `invbtv` and `delbtv` still only say they
//! # would
//!
//! A module that saves a character now gets an honest insert or update --
//! [`dinsbtv`] calls [`Block::insert`](crate::btrieve::Block::insert) and
//! [`dupdbtv`] calls [`Block::update`](crate::btrieve::Block::update).
//! `invbtv` and `delbtv` do not write yet, so a module that reaches either of
//! them with a file current gets a refusal rather than a host that appears to
//! work and loses the data.
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
//! With a file current, `invbtv` and `delbtv` refuse and name it. `dinsbtv`
//! and `dupdbtv` have no guard at all -- `:603` and `:555` read `bb->reclen`
//! first, so the real host faulted with no file current rather than
//! answering. This host stops the module instead of faulting, which is the
//! same outcome honestly reached and a deliberately different shape from
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
//! The remaining five guards belong to routines this host does not implement,
//! recorded here so the step that adds one does not derive them again:
//! `getbtvl` (`:318`, returns), `anpbtvlk` (`:406`, 0), `upvbtv` (`:536`,
//! returns), `invbtv` (`:584`, returns), `delbtv` (`:623`, returns). Note that
//! `dupdbtv` and `dinsbtv` have *no* guard and read `bb->reclen` immediately,
//! which is the `stpbtvl` shape again.
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
//! # Task 5: `Call<Wg16>`, not `Call<A>`
//!
//! Every routine below now takes a [`Call<Wg16>`] rather than a raw
//! `&mut Machine`, matching the shape the rest of the shim layer converted
//! to. **It stops there rather than going on to `fn foo<A: Abi>(...)`.**
//! `Host<A>::btrieve` is `crate::btrieve::Btrieve` -- concrete, not
//! `Btrieve<A>` -- keyed throughout by `mbbs16::FarPtr` and, for `open`/
//! `close`, taking a real `&mut mbbs16::Machine` directly
//! (`crates/mbbs/src/btrieve.rs`'s own doc comment: "stays concrete: it is
//! out of scope here"). A generic body would need to hand that engine an
//! `A::Ptr` and an `&mut A::Cpu` for an arbitrary `A`, and there is no
//! generic way to turn either into the `FarPtr`/`Machine` the engine
//! actually wants -- `Wg32`'s pointer is a flat `u32`, not a segment:offset,
//! and `Wg32Cpu` holds an `mbbs32::Machine`, not an `mbbs16::Machine`. So
//! genuine `A`-genericity here is blocked on generifying the Btrieve engine
//! itself, which is a separate, larger piece of work this task does not do.
//!
//! What this conversion buys anyway: arguments are read through
//! [`Call::ptr`]/[`Call::int`]/[`Call::long`] instead of a word-indexed
//! `arg_far`/`arg_u16`, and memory is reached through [`Call::mem`]
//! (`mbbs16::Segments`, the same type `Machine`'s own facade delegates to)
//! rather than a bare `&mut Machine` -- everywhere except the two calls that
//! must reach the concrete engine (`opnbtv`'s `btrieve.open`, `clsbtv`'s
//! `btrieve.close`), which take `call.cpu` -- `Call`'s public field, typed
//! `&mut mbbs16::Machine` because `Wg16::Cpu = mbbs16::Machine` -- directly.
//! Each routine keeps its C name for this Wg16-concrete core and gets a
//! `_wg16`-suffixed sibling built from `shims::call(machine)`, the same
//! bridge convention every generic-shaped file already uses (see
//! `shims::mod`'s `call` doc comment); the only difference is that here the
//! core itself, not just the bridge, is pinned to one `Abi`.
//!
//! `crates/mbbs/tests/no_direct_farptr.rs`'s `ALLOWED` list keeps this file
//! (and `crates/mbbs/src/btrieve.rs`) regardless of this conversion, for
//! exactly the reason above: `FarPtr` is still this file's block identity,
//! key value and record-pointer type throughout, because the engine behind
//! it still is one.

use mbbs16::FarPtr;
// `Machine`/`Ret` are now named only by this file's `#[cfg(test)]` `_wg16`
// bridges -- production code reaches every routine here through `Call<Wg16>`/
// `Host<Wg16>` instead, per this file's own module doc comment.
#[cfg(test)]
use mbbs16::{Machine, Ret};

use crate::Host;
use crate::abi::{self, Call, Wg16};
use crate::btrieve::{Btrieve, Cursor, Geometry};
use crate::shims::ShimError;

/// The five modes `BTVSTF.H:41-45` defines for `omdbtv`.
///
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
pub fn omdbtv(call: &mut Call<Wg16>, host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let mode = call.int() as i16;
    if !MODES.contains(&mode) {
        return Err(ShimError::Failed(format!(
            "omdbtv({mode}), which is none of the five modes BTVSTF.H defines"
        )));
    }
    host.btrieve.set_mode(mode);
    Ok(abi::Ret::Void)
}

/// The dispatch-table entry for [`omdbtv`]. See `shims::call`'s own doc
/// comment.
#[cfg(test)]
pub fn omdbtv_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    omdbtv(&mut super::call(machine), host).map(Into::into)
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
pub fn opnbtv(call: &mut Call<Wg16>, host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let filnam = call.ptr();
    let maxlen = call.int();
    let named = String::from_utf8_lossy(call.mem().read_cstr(filnam)?).into_owned();
    let name = Host::dos_name(&named).map_err(ShimError::Failed)?.to_owned();

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

/// The dispatch-table entry for [`opnbtv`]. See `shims::call`'s own doc
/// comment.
#[cfg(test)]
pub fn opnbtv_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    opnbtv(&mut super::call(machine), host).map(Into::into)
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
pub fn setbtv(call: &mut Call<Wg16>, host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let block = call.ptr();
    if block != Btrieve::<Wg16>::null() {
        host.btrieve.block(block).map_err(ShimError::Failed)?;
    }
    push(call, host, block)?;
    Ok(abi::Ret::Void)
}

/// The dispatch-table entry for [`setbtv`]. See `shims::call`'s own doc
/// comment.
#[cfg(test)]
pub fn setbtv_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    setbtv(&mut super::call(machine), host).map(Into::into)
}

/// `void rstbtv(void)` -- go back to the file that was current before.
///
/// Underflow is not an error here, which is the one place this crate follows
/// the original rather than refusing. See
/// [`Btrieve::restore`](crate::btrieve::Btrieve::restore) for why.
pub fn rstbtv(call: &mut Call<Wg16>, host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
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

/// The dispatch-table entry for [`rstbtv`]. See `shims::call`'s own doc
/// comment.
#[cfg(test)]
pub fn rstbtv_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    rstbtv(&mut super::call(machine), host).map(Into::into)
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
pub fn cntrbtv(call: &mut Call<Wg16>, host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
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

/// The dispatch-table entry for [`cntrbtv`]. See `shims::call`'s own doc
/// comment.
#[cfg(test)]
pub fn cntrbtv_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    cntrbtv(&mut super::call(machine), host).map(Into::into)
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
pub fn invbtv(call: &mut Call<Wg16>, host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let Some(block) = positioned(call, host, "invbtv")? else {
        note_no_file(host, "invbtv");
        return Ok(abi::Ret::Void);
    };
    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    Err(ShimError::Failed(format!(
        "invbtv into {}, and nothing in this host writes to a Btrieve file",
        file.name()
    )))
}

/// The dispatch-table entry for [`invbtv`]. See `shims::call`'s own doc
/// comment.
#[cfg(test)]
pub fn invbtv_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    invbtv(&mut super::call(machine), host).map(Into::into)
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
/// Answers nothing with no file current, refuses with one, for exactly the
/// reasons in [`invbtv`].
pub fn delbtv(call: &mut Call<Wg16>, host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let Some(block) = positioned(call, host, "delbtv")? else {
        note_no_file(host, "delbtv");
        return Ok(abi::Ret::Void);
    };
    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    Err(ShimError::Failed(format!(
        "delbtv from {}, and nothing in this host writes to a Btrieve file",
        file.name()
    )))
}

/// The dispatch-table entry for [`delbtv`]. See `shims::call`'s own doc
/// comment.
#[cfg(test)]
pub fn delbtv_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    delbtv(&mut super::call(machine), host).map(Into::into)
}

/// `int dinsbtv(void *recptr)` -- insert a new record into the current file.
///
/// `PLBTVSTF.C:598`:
///
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
pub fn dinsbtv(call: &mut Call<Wg16>, host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let recptr = call.ptr();
    let block = positioned(call, host, "dinsbtv")?.ok_or_else(|| {
        ShimError::Failed(
            "dinsbtv with no Btrieve file current -- PLBTVSTF.C:598 has no \
             guard and reads bb->reclen before checking anything, so the \
             real host faulted here rather than answering"
                .to_owned(),
        )
    })?;

    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    let length = file.maxlen();
    let recptr = match recptr == Btrieve::<Wg16>::null() {
        true => file.data(),
        false => recptr,
    };
    let bytes = call.mem().resolve(recptr, usize::from(length))?.to_vec();

    if let Some((key, value)) = duplicate_key(host, block, &bytes, None)? {
        let name = host.btrieve.block(block).map_err(ShimError::Failed)?.name().to_owned();
        note_duplicate_key(host, "dinsbtv", &name, key, &value);
        return Ok(abi::Ret::Int(0));
    }

    let file = host.btrieve.block_mut(block).map_err(ShimError::Failed)?;
    let position = file.insert(&bytes).map_err(|e| ShimError::Failed(e.to_string()))?;

    // Btrieve's Insert establishes currency on the record it just created --
    // `PLBTVSTF.C:626` passes a hardcoded key number of 0 to the underlying
    // Btrieve call (unlike dupdbtv, which threads `bb->lastkn` through), so
    // this positions in key 0's order specifically. Before this, `dinsbtv`
    // never touched the cursor, so the file stayed wherever it happened to
    // be positioned before the insert -- accidentally right when the new
    // record sorted before the cursor, and wrong when it sorted after.
    let records = file.records().map_err(|e| ShimError::Failed(e.to_string()))?;
    let physical = records
        .find_physical(position)
        .expect("insert just wrote this position");
    let cursor = match records.place_in(0, physical) {
        Some(at) => Cursor::Ordered { key: 0, at },
        None => Cursor::Physical { at: physical },
    };
    file.seek_to(cursor);

    Ok(abi::Ret::Int(1))
}

/// The dispatch-table entry for [`dinsbtv`]. See `shims::call`'s own doc
/// comment.
#[cfg(test)]
pub fn dinsbtv_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    dinsbtv(&mut super::call(machine), host).map(Into::into)
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
pub fn dupdbtv(call: &mut Call<Wg16>, host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let recptr = call.ptr();
    let block = positioned(call, host, "dupdbtv")?.ok_or_else(|| {
        ShimError::Failed(
            "dupdbtv with no Btrieve file current -- PLBTVSTF.C:550 has no \
             guard and reads bb->reclen before checking anything, so the \
             real host faulted here rather than answering"
                .to_owned(),
        )
    })?;

    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    let position = file
        .current()
        .ok_or_else(|| {
            ShimError::Failed(format!(
                "dupdbtv on {}, which is not positioned on a record -- \
                 opcode 3 updates the record the file is positioned on, and \
                 nothing has positioned this one",
                file.name()
            ))
        })?
        .position;
    let length = file.maxlen();
    let recptr = match recptr == Btrieve::<Wg16>::null() {
        true => file.data(),
        false => recptr,
    };
    let bytes = call.mem().resolve(recptr, usize::from(length))?.to_vec();

    if let Some((key, value)) = duplicate_key(host, block, &bytes, Some(position))? {
        let name = host.btrieve.block(block).map_err(ShimError::Failed)?.name().to_owned();
        note_duplicate_key(host, "dupdbtv", &name, key, &value);
        return Ok(abi::Ret::Int(0));
    }

    let file = host.btrieve.block_mut(block).map_err(ShimError::Failed)?;
    file.update(position, &bytes).map_err(|e| ShimError::Failed(e.to_string()))?;

    // Btrieve's opcode 3 maintains currency on the record it just rewrote.
    // `Cursor::Ordered` is an ordinal into a key's *sorted* order, and
    // `Block::update` (via `Records::update`) just re-sorted every key's
    // order as part of the write -- so the ordinal the cursor held before
    // the call is very likely to name a different record now (see this
    // test module's `dupdbtv_maintains_currency_on_the_record_it_rewrote_...`
    // for a measured example: index 4 of key order was Troll before an
    // update moved Troll to index 6, and after the update it was Elf).
    // `position` itself did not move -- an update rewrites in place -- so
    // the cursor is re-derived from it rather than carried forward:
    // `find_physical` gets back to physical order, and `place_in` re-derives
    // the ordinal in whichever key the cursor was already following. A
    // `Physical` cursor needs no correction, because physical order is
    // insertion order and an update does not touch it -- but it is still
    // fine to fall through to `Physical` below if the key the cursor was on
    // is not one `place_in` recognises.
    if let Cursor::Ordered { key, .. } = file.cursor() {
        let records = file.records().map_err(|e| ShimError::Failed(e.to_string()))?;
        let physical = records
            .find_physical(position)
            .expect("update just wrote this position");
        let cursor = match records.place_in(key, physical) {
            Some(at) => Cursor::Ordered { key, at },
            None => Cursor::Physical { at: physical },
        };
        file.seek_to(cursor);
    }

    Ok(abi::Ret::Int(1))
}

/// The dispatch-table entry for [`dupdbtv`]. See `shims::call`'s own doc
/// comment.
#[cfg(test)]
pub fn dupdbtv_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    dupdbtv(&mut super::call(machine), host).map(Into::into)
}

/// `void clsbtv(struct btvblk *bbp)` -- close a Btrieve file.
///
/// `PLBTVSTF.C:632`, quoted in full because every line of it does something:
///
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
pub fn clsbtv(call: &mut Call<Wg16>, host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
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

/// The dispatch-table entry for [`clsbtv`]. See `shims::call`'s own doc
/// comment.
#[cfg(test)]
pub fn clsbtv_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    clsbtv(&mut super::call(machine), host).map(Into::into)
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
/// the same question of the records already read into memory -- a record
/// with this value is a collision if [`Records::seek`](crate::btrieve::Records::seek)
/// lands on one that [`Records::matches`](crate::btrieve::Records::matches) it exactly.
///
/// The caller is the one who notes it -- see [`note_duplicate_key`] -- because
/// only the caller knows whether this is an insert or an update.
fn duplicate_key(
    host: &mut Host,
    block: FarPtr,
    bytes: &[u8],
    exclude: Option<u32>,
) -> Result<Option<(u16, Vec<u8>)>, ShimError> {
    let file = host.btrieve.block_mut(block).map_err(ShimError::Failed)?;
    let keys = file.keys().to_vec();
    let records = file.records().map_err(|e| ShimError::Failed(e.to_string()))?;

    for key in &keys {
        if key.duplicates {
            continue;
        }
        let value = key.extract(bytes);
        let at = records.seek(&keys, key.number, &value);
        if !records.matches(&keys, key.number, at, &value) {
            continue;
        }
        let existing = records.ordered(key.number, at).expect("just matched");
        if Some(existing.position) == exclude {
            continue;
        }
        return Ok(Some((key.number, value)));
    }
    Ok(None)
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
fn note_duplicate_key(host: &mut Host, who: &str, name: &str, key: u16, value: &[u8]) {
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
enum Op {
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
    fn of(code: i16) -> Option<Self> {
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
    fn wants_value(self) -> bool {
        matches!(
            self,
            Self::Equal | Self::Greater | Self::AtLeast | Self::Less | Self::AtMost
        )
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
pub fn qrybtv(call: &mut Call<Wg16>, host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    // The guard is the first thing `PLBTVSTF.C:262` does -- before the key, the
    // key number or the option are looked at -- so it is the first thing here.
    let Some(block) = positioned(call, host, "qrybtv")? else {
        note_no_file(host, "qrybtv");
        return Ok(abi::Ret::Int(0));
    };

    let value = call.ptr();
    let keynum = call.int() as i16;
    let opt = call.int() as i16;

    // `qrybtv` takes the *get key* codes, fifty above the acquire family's.
    let op = Op::of(opt - 50).ok_or_else(|| {
        ShimError::Failed(format!(
            "qrybtv with option {opt}, which is none of the nine BTVSTF.H's q-macros produce"
        ))
    })?;
    Ok(abi::Ret::Int(u16::from(locate(
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
    )?)))
}

/// The dispatch-table entry for [`qrybtv`]. See `shims::call`'s own doc
/// comment.
#[cfg(test)]
pub fn qrybtv_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    qrybtv(&mut super::call(machine), host).map(Into::into)
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
pub fn qnpbtv(call: &mut Call<Wg16>, host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    // `PLBTVSTF.C:287`, and it has to be before `bb->data` is read for the same
    // reason the C puts it there: there is no `bb->data` to read.
    let Some(block) = positioned(call, host, "qnpbtv")? else {
        note_no_file(host, "qnpbtv");
        return Ok(abi::Ret::Int(0));
    };

    let opt = call.int() as i16;
    let op = Op::of(opt - 50).ok_or_else(|| {
        ShimError::Failed(format!("qnpbtv with option {opt}, which is not a get operation"))
    })?;

    // `bb->lastkn`: which key the last positioning used. Passed as -1 so that
    // `locate` reads it back rather than changing it, exactly as the C does.
    let into = data_buffer(host, block)?;
    Ok(abi::Ret::Int(u16::from(locate(
        call,
        host,
        Request {
            who: "qnpbtv",
            block,
            op,
            keynum: -1,
            value: Btrieve::<Wg16>::null(),
            into: Some(into),
            // `int qnpbtv(int getopt)` -- one argument, no `loktyp`.
            lock: 0,
        },
    )?)))
}

/// The dispatch-table entry for [`qnpbtv`]. See `shims::call`'s own doc
/// comment.
#[cfg(test)]
pub fn qnpbtv_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    qnpbtv(&mut super::call(machine), host).map(Into::into)
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
pub fn obtbtvl(call: &mut Call<Wg16>, host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    // `:357` guards, and only then does `:360` default `recptr` to `bb->data`.
    // The order is the whole of it: `bb->data` cannot be read from a null `bb`,
    // so a guard placed after that default never runs.
    let Some(block) = positioned(call, host, "obtbtvl")? else {
        note_no_file(host, "obtbtvl");
        return Ok(abi::Ret::Int(0));
    };

    let into = call.ptr();
    let value = call.ptr();
    let keynum = call.int() as i16;
    let opt = call.int() as i16;
    let lock = call.int() as i16;

    let op = Op::of(opt).ok_or_else(|| {
        ShimError::Failed(format!(
            "obtbtvl with option {opt}, which is none of the nine BTVSTF.H's a-macros produce"
        ))
    })?;
    let into = match into == Btrieve::<Wg16>::null() {
        true => data_buffer(host, block)?,
        false => into,
    };
    Ok(abi::Ret::Int(u16::from(locate(
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
    )?)))
}

/// The dispatch-table entry for [`obtbtvl`]. See `shims::call`'s own doc
/// comment.
#[cfg(test)]
pub fn obtbtvl_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    obtbtvl(&mut super::call(machine), host).map(Into::into)
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
///
/// Two dereferences before anything is checked. A real board that stepped with
/// no file current took the fault there, so there is no answer to reproduce and
/// refusing is the honest translation of what happened.
pub fn stpbtvl(call: &mut Call<Wg16>, host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
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
    let opt = call.int() as i16;
    let lock = call.int() as i16;

    let into = match into == Btrieve::<Wg16>::null() {
        true => data_buffer(host, block)?,
        false => into,
    };
    load(host, block)?;
    let file = host.btrieve.block_mut(block).map_err(ShimError::Failed)?;
    let count = file.records().map_err(|e| ShimError::Failed(e.to_string()))?.len();

    // Where the walk goes next, from where it is now.
    let at = match (opt, file.cursor()) {
        (33, _) => 0,
        (34, _) if count > 0 => count - 1,
        (34, _) => return Ok(abi::Ret::Int(0)),
        (24, Cursor::Physical { at }) => at + 1,
        (35, Cursor::Physical { at }) if at > 0 => at - 1,
        (35, Cursor::Physical { .. }) => return Ok(abi::Ret::Int(0)),
        // Stepping from a keyed position. **Correction, found driving
        // character creation's real duplicate-name check against
        // `WCCMMUD.DLL` (Task 12):** an earlier version of this arm treated
        // this as a module bug and refused outright. Real Btrieve keeps
        // exactly one cursor per open file, in *physical* terms, regardless
        // of whether a keyed query or a step last moved it there -- a
        // `qrybtv`/`gabbtvl` positions the file physically same as a step
        // does, it just also remembers which key ordinal that physical slot
        // was found at. So a step-family call (`stpbtvl`, "no key at all",
        // this function's own doc comment) after a keyed one is not a module
        // bug at all; it is the ordinary way a real board reads a few
        // records by key and then walks the rest of the file by position.
        // The translation is the one `obtbtvl`'s own `here` resolution
        // already trusts for the opposite direction (an `Ordered` cursor
        // read in a *different* key's order, above) -- the record a key
        // ordinal names has a physical position like any other, found the
        // same way.
        (24 | 35, Cursor::Ordered { key, at }) => {
            let records = file.records().map_err(|e| ShimError::Failed(e.to_string()))?;
            let physical = records
                .ordered(key, at)
                .and_then(|record| records.find_physical(record.position))
                .ok_or_else(|| {
                    ShimError::Failed(format!(
                        "stpbtvl({opt}) on {}: the ordered cursor (key {key}, {at}) does \
                         not resolve to a physical record -- the file changed under it",
                        file.name()
                    ))
                })?;
            match opt {
                24 => physical + 1,
                _ if physical > 0 => physical - 1,
                _ => return Ok(abi::Ret::Int(0)),
            }
        }
        (24 | 35, Cursor::Nowhere) => {
            return Err(ShimError::Failed(format!(
                "stpbtvl({opt}) on {}, which is positioned Nowhere -- nothing has \
                 positioned it yet, by a key or by a step",
                file.name()
            )));
        }
        _ => {
            return Err(ShimError::Failed(format!(
                "stpbtvl with option {opt}, which is none of 24, 33, 34 and 35"
            )));
        }
    };

    if at >= count {
        return Ok(abi::Ret::Int(0));
    }
    file.seek_to(Cursor::Physical { at });
    take_lock(host, block, lock)?;
    deliver(call, host, block, into)?;
    Ok(abi::Ret::Int(1))
}

/// The dispatch-table entry for [`stpbtvl`]. See `shims::call`'s own doc
/// comment.
#[cfg(test)]
pub fn stpbtvl_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    stpbtvl(&mut super::call(machine), host).map(Into::into)
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
pub fn absbtv(call: &mut Call<Wg16>, host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let Some(block) = positioned(call, host, "absbtv")? else {
        note_no_file(host, "absbtv");
        return Ok(abi::Ret::Long(0));
    };
    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    let record = file.current().ok_or_else(|| {
        ShimError::Failed(format!(
            "absbtv on {}, which is not positioned on a record",
            file.name()
        ))
    })?;
    Ok(abi::Ret::Long(record.position))
}

/// The dispatch-table entry for [`absbtv`]. See `shims::call`'s own doc
/// comment.
#[cfg(test)]
pub fn absbtv_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    absbtv(&mut super::call(machine), host).map(Into::into)
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
pub fn aabbtv(call: &mut Call<Wg16>, host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let into = call.ptr();
    let position = call.long();
    let keynum = call.int() as i16;
    Ok(abi::Ret::Int(u16::from(absolute(
        call,
        host,
        Position {
            who: "aabbtv",
            fatal: false,
            lock: UNLOCKED,
            into,
            position,
            keynum,
        },
    )?)))
}

/// The dispatch-table entry for [`aabbtv`]. See `shims::call`'s own doc
/// comment.
#[cfg(test)]
pub fn aabbtv_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    aabbtv(&mut super::call(machine), host).map(Into::into)
}

/// The lock type `aabbtv` has instead of an argument.
///
/// `PLBTVSTF.C:466` -- `return(aabbtvl(recptr,abspos,keynum,0))`. Named rather
/// than written as a bare 0 at the call site, because a 0 there reads as "no
/// lock was asked for" when what it means is "there was never a word to ask in".
const UNLOCKED: i16 = 0;

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
pub fn gabbtvl(call: &mut Call<Wg16>, host: &mut Host<Wg16>) -> Result<abi::Ret<Wg16>, ShimError> {
    let into = call.ptr();
    let position = call.long();
    let keynum = call.int() as i16;
    let lock = call.int() as i16;
    absolute(
        call,
        host,
        Position {
            who: "gabbtvl",
            fatal: true,
            lock,
            into,
            position,
            keynum,
        },
    )?;
    Ok(abi::Ret::Void)
}

/// The dispatch-table entry for [`gabbtvl`]. See `shims::call`'s own doc
/// comment.
#[cfg(test)]
pub fn gabbtvl_wg16(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    gabbtvl(&mut super::call(machine), host).map(Into::into)
}

/// What `aabbtv` and `gabbtvl` supply to [`absolute`], bundled into one type
/// rather than passed as six more parameters -- clippy already has an opinion
/// about `absolute` at seven, and the file already has a precedent for this
/// shape in [`Request`], below.
struct Position {
    /// The routine asking, for anything it has to refuse or note by name.
    who: &'static str,

    /// Whether a position naming no record is a refusal ([`gabbtvl`]) or a
    /// quiet `false` ([`aabbtv`]). See [`absolute`]'s own doc comment.
    fatal: bool,

    /// **The caller's**, not read here -- the two callers don't have the same
    /// arguments; see [`aabbtv`]'s doc comment for why `gabbtvl` has a fourth
    /// word to read and `aabbtv` does not.
    lock: i16,

    /// Where the record goes, or the module's null for `bb->data`.
    into: FarPtr,

    /// The file position to acquire -- Btrieve's Get Position number, what
    /// [`absbtv`] hands back.
    position: u32,

    /// Which key's order the position lands in, negative for `bb->lastkn`.
    keynum: i16,
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
fn absolute(call: &mut Call<Wg16>, host: &mut Host<Wg16>, req: Position) -> Result<bool, ShimError> {
    let Position {
        who,
        fatal,
        lock,
        into,
        position,
        keynum,
    } = req;

    // `:452` and `:476` both guard before `:479` defaults `recptr` to
    // `bb->data`. Same ordering point as `obtbtvl`: with no file current the
    // original returned before it looked at anything, including `lock`, so
    // `take_lock` runs later -- only once a record has actually been found
    // (below) -- not here.
    let Some(block) = positioned(call, host, who)? else {
        note_no_file(host, who);
        return Ok(false);
    };

    let into = match into == Btrieve::<Wg16>::null() {
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
        host.note_once(
            "lastkn",
            format!(
                "{who} was given key number {keynum}, and PLBTVSTF.C:483 would \
                 have stored it in bb->lastkn unchecked. Read lastkn instead"
            ),
        );
    }
    let key = key_number(call, host, block, keynum)?;

    let file = host.btrieve.block_mut(block).map_err(ShimError::Failed)?;
    let records = file.records().map_err(|e| ShimError::Failed(e.to_string()))?;
    let Some(physical) = records.find_physical(position) else {
        if fatal {
            return Err(ShimError::Failed(format!(
                "gabbtvl of {}, which has no record at file position {position}",
                file.name()
            )));
        }
        return Ok(false);
    };

    // The position names a record; the key number says which order a later
    // step should continue in.
    let cursor = match records.place_in(key, physical) {
        Some(at) => Cursor::Ordered { key, at },
        None => Cursor::Physical { at: physical },
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
struct Request<'a> {
    /// The routine asking, for anything it has to refuse by name.
    who: &'a str,

    /// The file. The caller's rather than read from `bb` here, because the
    /// caller has already had to decide what a null `bb` means to it -- see
    /// [`positioned`].
    block: FarPtr,

    /// What to find.
    op: Op,

    /// Which key to find it by, or negative for `bb->lastkn`.
    keynum: i16,

    /// The module's key value, or null for an operation that needs none.
    value: FarPtr,

    /// Where the record goes, or `None` for a query, which reads none.
    into: Option<FarPtr>,

    /// The lock type to take once a record is found, or `0` for none --
    /// `0` for `qrybtv`/`qnpbtv`, which have no `loktyp` at either layer.
    lock: i16,
}

/// Position the file a [`Request`] names, and hand back the record if asked.
///
/// Returns whether a record was found.
fn locate(call: &mut Call<Wg16>, host: &mut Host<Wg16>, req: Request) -> Result<bool, ShimError> {
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
    if value != Btrieve::<Wg16>::null() {
        // **The original measured this copy with the key number as passed**,
        // before `:268` resolved a negative one to `bb->lastkn`:
        //
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
        let bytes = call.mem().resolve(value, usize::from(length))?.to_vec();
        let buffer = host
            .btrieve
            .block(block)
            .map_err(ShimError::Failed)?
            .key();
        call.mem().write(buffer, &bytes)?;
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
            call.mem().resolve(buffer, usize::from(length))?.to_vec()
        }
    };

    let file = host.btrieve.block_mut(block).map_err(ShimError::Failed)?;
    let name = file.name().to_owned();
    let definitions = file.keys().to_vec();
    let cursor = file.cursor();
    let records = file.records().map_err(|e| ShimError::Failed(e.to_string()))?;
    let count = records
        .ordered_len(key)
        .ok_or_else(|| ShimError::Failed(format!("{who} on {name} by key {key}, which it has not")))?;

    // Where the file is now, in this key's order -- and **only** `Next` and
    // `Previous` may ask, because they are the only two operations whose
    // answer depends on where the file already is. A `Get Equal` does not
    // care what the cursor holds, so it must not be refused for holding the
    // wrong sort of cursor.
    //
    // **A cursor from another key, or from a step, is refused rather than
    // translated.** An earlier version translated one through
    // `Records::place_in` on the reasoning that the two orders describe the
    // same records. Genuine Btrieve 6.15 does not do that, measured in
    // `crates/mbbs/tests/btrieve.rs::position_ops_oracle_scenarios`:
    //
    //   - `S6` -- `Get Equal` on key 0, then `Get Next` on key 1: status 7,
    //     "different key number". Not an answer in key 1's order.
    //   - `S4`/`S4b` -- `Step First`, then `Get Next` on *either* key:
    //     status 8. A step establishes no key context at all.
    //
    // Both are error statuses rather than the 4/9 this layer turns into a
    // zero, so both stop the module, which is what `PLBTVSTF.C` does with a
    // status it has no mapping for. Translating produced a *plausible*
    // record instead, which is the worse failure: the module cannot tell it
    // asked a question the original would have refused.
    let here: Result<Option<usize>, String> = match cursor {
        Cursor::Ordered { key: had, at } if had == key => Ok(Some(at)),
        Cursor::Ordered { key: had, .. } => Err(format!(
            "{who} asked {name} for the next record in key {key}'s order, but \
             the file is positioned in key {had}'s. Real Btrieve refuses this \
             with status 7, \"different key number\", rather than translating \
             between the two orders -- measured, S6"
        )),
        Cursor::Physical { .. } => Err(format!(
            "{who} asked {name} for the next record in key {key}'s order, but \
             the file was positioned by a step, which establishes no key at \
             all. Real Btrieve refuses this with status 8 -- measured, S4"
        )),
        Cursor::Nowhere => Ok(None),
    };

    let found = match op {
        Op::Lowest => (count > 0).then_some(0),
        Op::Highest => count.checked_sub(1),
        Op::Equal => {
            let at = records.seek(&definitions, key, &wanted);
            records.matches(&definitions, key, at, &wanted).then_some(at)
        }
        Op::AtLeast => Some(records.seek(&definitions, key, &wanted)).filter(|at| *at < count),
        Op::Greater => {
            // Past every record equal to the value, which is not `seek + 1`:
            // a duplicate key may have many.
            let mut at = records.seek(&definitions, key, &wanted);
            while records.matches(&definitions, key, at, &wanted) {
                at += 1;
            }
            Some(at).filter(|at| *at < count)
        }
        Op::AtMost => {
            let mut at = records.seek(&definitions, key, &wanted);
            while records.matches(&definitions, key, at, &wanted) {
                at += 1;
            }
            at.checked_sub(1)
        }
        Op::Less => records.seek(&definitions, key, &wanted).checked_sub(1),
        Op::Next => match here.map_err(ShimError::Failed)? {
            Some(at) => Some(at + 1).filter(|at| *at < count),
            // **An unpositioned `Get Next` is not an error -- it answers.**
            // `S1` measured genuine Btrieve returning status 0 and the
            // *first* record for a `Get Next` on a freshly opened file that
            // nothing has positioned: it behaves as `Get Lowest`.
            //
            // This used to refuse, which stopped the module. That is the
            // most damaging shape a divergence can take here -- the other
            // two in this function make the host more permissive than the
            // original and merely lose a refusal, where this one invented a
            // fatal error in a case the original answered normally.
            None => (count > 0).then_some(0),
        },
        Op::Previous => match here.map_err(ShimError::Failed)? {
            Some(at) => at.checked_sub(1),
            // `S1c`: the mirror of `S1` is *not* symmetric. An unpositioned
            // `Get Previous` measured status 9, "end of file" -- which this
            // layer turns into a zero, an answer meaning "no such record",
            // rather than into a refusal.
            None => None,
        },
    };

    // Not found leaves the file where it was, which is what Btrieve does: a
    // failed Get Equal does not lose the position a successful one established.
    let Some(at) = found else {
        return Ok(false);
    };
    file.seek_to(Cursor::Ordered { key, at });
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
fn answer_with_key(
    call: &mut Call<Wg16>,
    host: &mut Host<Wg16>,
    block: FarPtr,
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
    call.mem().write(buffer, &bytes)?;
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
fn deliver(
    call: &mut Call<Wg16>,
    host: &mut Host<Wg16>,
    block: FarPtr,
    into: FarPtr,
) -> Result<(), ShimError> {
    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    let record = file
        .current()
        .ok_or_else(|| ShimError::Failed(format!("{} is not positioned", file.name())))?;
    let take = usize::from(file.maxlen()).min(record.bytes.len());
    let bytes = record.bytes[..take].to_vec();
    call.mem().write(into, &bytes)?;
    Ok(())
}

/// Which key an operation works on, honouring `bb->lastkn`.
///
/// `PLBTVSTF.C:268`: a negative key number means "the one last used", and any
/// other means "this one, and remember it". `lastkn` is a field of the block in
/// module memory, so it is read and written there rather than kept here.
fn key_number(
    call: &mut Call<Wg16>,
    host: &Host<Wg16>,
    block: FarPtr,
    keynum: i16,
) -> Result<u16, ShimError> {
    let at = FarPtr {
        offset: block.offset + LASTKN,
        selector: block.selector,
    };
    if keynum < 0 {
        let bytes = call.mem().resolve(at, 2)?;
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
    call.mem().write(at, &(keynum as u16).to_le_bytes())?;
    Ok(keynum as u16)
}

/// Where `lastkn` sits in a `struct btvblk`.
const LASTKN: u16 = 142;

/// How many bytes of the module's buffer are a key value.
fn key_length(host: &Host, block: FarPtr, key: u16) -> Result<u16, ShimError> {
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
fn load(host: &mut Host, block: FarPtr) -> Result<(), ShimError> {
    let file = host.btrieve.block_mut(block).map_err(ShimError::Failed)?;
    if file.loaded().is_some() {
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

/// The current file, or `None` if there is none.
///
/// **Not an error.** `PLBTVSTF.C` opens eleven of its routines with
/// `if (bb == NULL) { return 0; }` and each caller knows what its own zero is:
/// an `int` 0, a `long` 0, or nothing at all. So the decision belongs to the
/// caller and this only reports.
///
/// A pointer that is neither null nor a file this host opened *is* a refusal,
/// which is [`setbtv`]'s contract and unrelated to the null case.
fn positioned(call: &mut Call<Wg16>, host: &Host<Wg16>, who: &str) -> Result<Option<FarPtr>, ShimError> {
    let block = current(call, host)?;
    if block == Btrieve::<Wg16>::null() {
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
fn note_no_file(host: &mut Host, who: &str) {
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
fn data_buffer(host: &Host, block: FarPtr) -> Result<FarPtr, ShimError> {
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
fn take_lock(host: &mut Host, block: FarPtr, lock: i16) -> Result<(), ShimError> {
    host.btrieve.take_lock(block, lock).map_err(ShimError::Failed)
}

/// Push what is current and make `block` current, as `setbtv` does.
fn push(call: &mut Call<Wg16>, host: &mut Host<Wg16>, block: FarPtr) -> Result<(), ShimError> {
    let previous = current(call, host)?;
    if let Some(dropped) = host.btrieve.set(previous) {
        host.note(format!(
            "the setbtv stack is ten deep and overflowed, so {dropped} fell off \
             the bottom -- exactly as it would have on the real host"
        ));
    }
    set_current(call, host, block)
}

/// What `bb` holds, read back out of module memory every time.
fn current(call: &mut Call<Wg16>, host: &Host<Wg16>) -> Result<FarPtr, ShimError> {
    host.globals()
        .pointer_mem(call.mem(), "bb")
        .map_err(|e| ShimError::Failed(e.to_string()))
}

fn set_current(call: &mut Call<Wg16>, host: &Host<Wg16>, block: FarPtr) -> Result<(), ShimError> {
    host.globals()
        .write_mem(call.mem(), "bb", &block.to_bytes())
        .map_err(|e| ShimError::Failed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;

    /// Open `SAMPLE.DAT`, as a module would.
    fn open(f: &mut Fixture, name: &str, maxlen: u16) -> FarPtr {
        let at = f.text(name);
        let Ret::Far(block) = f
            .invoke(opnbtv_wg16, &[at.offset, at.selector, maxlen])
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
        assert_eq!(bb(&f), Btrieve::<Wg16>::null(), "nothing is current to begin with");
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

        f.invoke(rstbtv_wg16, &[]).expect("restores");
        assert_eq!(bb(&f), second, "the file it had just opened");
        f.invoke(rstbtv_wg16, &[]).expect("restores");
        assert_eq!(bb(&f), first, "and now the one before it");
    }

    #[test]
    fn setbtv_and_rstbtv_round_trip_through_module_memory() {
        let mut f = Fixture::new();
        let first = open(&mut f, "SAMPLE.DAT", 64);
        let second = open(&mut f, "OTHER.DAT", 32);

        f.invoke(setbtv_wg16, &Fixture::far(first)).expect("set");
        assert_eq!(bb(&f), first);
        f.invoke(rstbtv_wg16, &[]).expect("restored");
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
        assert!(f.invoke(setbtv_wg16, &Fixture::far(nonsense)).is_err());
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
            f.invoke(setbtv_wg16, &Fixture::far(other)).expect("set");
        }
        assert!(
            f.host.notes().iter().any(|n| n.contains("fell off")),
            "the overflow is reported: {:?}",
            f.host.notes()
        );

        // Unwinding the whole stack never reaches the first file again.
        for _ in 0..10 {
            f.invoke(rstbtv_wg16, &[]).expect("restores");
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
        f.invoke(rstbtv_wg16, &[]).expect("not an error");
        assert_eq!(bb(&f), Btrieve::<Wg16>::null());
        assert!(
            f.host.notes().iter().any(|n| n.contains("rstbtv")),
            "and it is reported"
        );

        // And what null costs: nothing can be counted.
        assert!(f.invoke(cntrbtv_wg16, &[]).is_err());
    }

    #[test]
    fn cntrbtv_counts_the_current_file_and_a_setbtv_between_opens_changes_it() {
        let mut f = Fixture::new();
        let sample = open(&mut f, "SAMPLE.DAT", 64);
        open(&mut f, "OTHER.DAT", 32);

        // `OTHER.DAT` has three records and `SAMPLE.DAT` seven.
        assert_eq!(f.invoke(cntrbtv_wg16, &[]).expect("counts"), Ret::U32(3));
        f.invoke(setbtv_wg16, &Fixture::far(sample)).expect("set");
        assert_eq!(f.invoke(cntrbtv_wg16, &[]).expect("counts"), Ret::U32(7));
    }

    #[test]
    fn cntrbtv_reports_an_empty_file_as_empty_rather_than_failing() {
        // `WCCUSERS.DAT` on a board nobody has played on holds no records, and
        // zero is the right answer rather than a parse that went wrong.
        let mut f = Fixture::new();
        open(&mut f, "EMPTY.DAT", 64);
        assert_eq!(f.invoke(cntrbtv_wg16, &[]).expect("counts"), Ret::U32(0));
    }

    #[test]
    fn opnbtv_of_something_that_is_not_btrieve_refuses_by_name() {
        // Rather than handing back a block whose `reclen` is two bytes of
        // whatever the file happens to start with.
        let mut f = Fixture::new();
        let at = f.text("SAMPLE.MSG");
        let e = f
            .invoke(opnbtv_wg16, &[at.offset, at.selector, 64])
            .expect_err("a .MSG is not a Btrieve file");
        assert!(e.to_string().contains("SAMPLE.MSG"), "{e}");
    }

    #[test]
    fn opnbtv_names_a_file_it_can_neither_find_nor_install() {
        let mut f = Fixture::new();
        let at = f.text("NOSUCH.DAT");
        let e = f
            .invoke(opnbtv_wg16, &[at.offset, at.selector, 64])
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
        assert!(f.invoke(opnbtv_wg16, &[here.offset, here.selector, 64]).is_ok());

        let elsewhere = f.text("D:\\MUD\\SAMPLE.DAT");
        let e = f
            .invoke(opnbtv_wg16, &[elsewhere.offset, elsewhere.selector, 64])
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

        f.invoke(omdbtv_wg16, &[(-2i16) as u16]).expect("RONLBV");
        assert_eq!(f.host.btrieve().mode(), -2);

        assert!(f.invoke(omdbtv_wg16, &[7]).is_err(), "7 is not a mode");
        assert_eq!(f.host.btrieve().mode(), -2, "and it did not take");
    }
    /// The two-byte key of the record a read left in a buffer.
    fn got(f: &Fixture, at: FarPtr) -> u16 {
        let bytes = f.machine.resolve(at, 2).expect("readable");
        u16::from_le_bytes([bytes[0], bytes[1]])
    }

    /// `qrybtv` with no key value: the lowest, highest, next or previous.
    fn query(f: &mut Fixture, keynum: i16, opt: i16) -> bool {
        f.invoke(qrybtv_wg16, &[0, 0, keynum as u16, opt as u16])
            .expect("queries")
            == Ret::U16(1)
    }

    /// `obtbtvl(NULL, key, keynum, opt, 0)` -- acquire into `bb->data`.
    fn acquire(f: &mut Fixture, key: Option<u16>, keynum: i16, opt: i16) -> bool {
        let value = match key {
            Some(n) => f.bytes(&n.to_le_bytes(), false),
            None => Btrieve::<Wg16>::null(),
        };
        f.invoke(
            obtbtvl_wg16,
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
        assert_eq!(f.invoke(stpbtvl_wg16, &[0, 0, 33, 0]).expect("step first"), Ret::U16(1));
        stepped.push(got(&f, into));
        while f.invoke(stpbtvl_wg16, &[0, 0, 24, 0]).expect("step next") == Ret::U16(1) {
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

        assert!(f.invoke(qrybtv_wg16, &[0, 0, 0, 62]).expect("lowest") == Ret::U16(1));
        assert_eq!(got(&f, into), 0, "a query reads no record");

        assert_eq!(f.invoke(qnpbtv_wg16, &[56]).expect("next"), Ret::U16(1));
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
        assert_ne!(key, Btrieve::<Wg16>::null(), "opnbtv allocates it");

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
        let Ret::U32(position) = f.invoke(absbtv_wg16, &[]).expect("position") else {
            panic!("absbtv returns a long");
        };

        assert!(acquire(&mut f, None, 0, 12), "somewhere else entirely");
        assert_eq!(got(&f, into), 1);

        f.invoke(gabbtvl_wg16, &[0, 0, position as u16, (position >> 16) as u16, 0, 0])
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
            f.invoke(aabbtv_wg16, &[0, 0, 7, 0, 0]).expect("answers"),
            Ret::U16(0)
        );
        assert!(f.invoke(gabbtvl_wg16, &[0, 0, 7, 0, 0, 0]).is_err());
    }

    #[test]
    fn aabbtv_takes_three_arguments_and_never_reads_a_fourth() {
        // `BTVSTF.H:155` declares `int aabbtv(void*, long, int)` -- five
        // argument words -- and all eight of `WCCMMUD.DLL`'s call sites clean
        // `add sp,10`, which is those five and no more. `aabbtvl`, the
        // four-argument form, is a separate export the module never imports.
        //
        // This host used to read a sixth word as `loktyp` because it shared a
        // helper with `gabbtvl`, which really does take four. The sixth word
        // was the caller's, and any nonzero garbage there used to be refused
        // as a lock the module never asked for -- fixed by `UNLOCKED`
        // (`aabbtv`'s own doc comment), which passes a hardcoded `0` instead
        // of reading a word that is not there.
        //
        // Invoked with exactly five words, which is what gives this teeth: the
        // word above them is the outer frame's return offset and is not zero.
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        let into = buffer(&f, block);

        assert!(acquire(&mut f, Some(6), 0, 5), "equal to 6");
        let Ret::U32(position) = f.invoke(absbtv_wg16, &[]).expect("position") else {
            panic!("absbtv returns a long");
        };
        assert!(acquire(&mut f, None, 0, 12), "somewhere else entirely");

        assert_eq!(
            f.invoke(aabbtv_wg16, &[0, 0, position as u16, (position >> 16) as u16, 0])
                .expect("five argument words are all there are"),
            Ret::U16(1)
        );
        assert_eq!(got(&f, into), 6, "and it read the record it was sent to");
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
        let Ret::U32(position) = f.invoke(absbtv_wg16, &[]).expect("position") else {
            panic!("absbtv returns a long");
        };

        // Somewhere else, so the key buffer holds something wrong to begin with.
        assert!(acquire(&mut f, None, 0, 12), "lowest");
        assert_eq!(got(&f, key), 1);

        f.invoke(aabbtv_wg16, &[0, 0, position as u16, (position >> 16) as u16, 0])
            .expect("back to where it was");
        assert_eq!(got(&f, key), 6, "aabbtv answers with the key it landed on");

        assert!(acquire(&mut f, None, 0, 12), "lowest again");
        f.invoke(
            gabbtvl_wg16,
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
            f.invoke(qnpbtv_wg16, &[56]).expect("answers"),
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
            f.invoke(obtbtvl_wg16, &[0, 0, 0, 0, 1, 6, 0]).is_err(),
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
        };

        let dir = crate::testing::scratch(scratch);
        create(
            &dir.join("TWOKEY.DAT"),
            &FileSpec {
                record_length: 8,
                page_size: 512,
                keys: vec![key(0), key(2)],
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
            f.invoke(dinsbtv_wg16, &Fixture::far(at)).expect("inserts");
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
        let Ret::U32(position) = f.invoke(absbtv_wg16, &[]).expect("has a position") else {
            panic!("absbtv answers with a position");
        };

        // The same record, but reached through key ONE -- so the cursor this
        // leaves behind is key 1's, not the key 0 the acquire above used.
        f.invoke(
            gabbtvl_wg16,
            &[0, 0, position as u16, (position >> 16) as u16, 1, 0],
        )
        .expect("get direct, establishing key 1");

        assert_eq!(
            f.invoke(qnpbtv_wg16, &[56]).expect("answers"),
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
        let Ret::U32(position) = f.invoke(absbtv_wg16, &[]).expect("has a position") else {
            panic!("absbtv answers with a position");
        };

        f.invoke(
            gabbtvl_wg16,
            &[0, 0, position as u16, (position >> 16) as u16, 1, 0],
        )
        .expect("get direct, establishing key 1");

        assert!(
            f.invoke(obtbtvl_wg16, &[0, 0, 0, 0, 0, 6, 0]).is_err(),
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
            f.invoke(stpbtvl_wg16, &[0, 0, 33, 0]).is_ok(),
            "step to the first record in physical order"
        );
        assert!(
            f.invoke(qnpbtv_wg16, &[56]).is_err(),
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
    fn a_step_or_a_position_with_nothing_to_be_next_to_refuses() {
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 64);
        assert!(f.invoke(stpbtvl_wg16, &[0, 0, 24, 0]).is_err());
        assert!(f.invoke(absbtv_wg16, &[]).is_err(), "and nowhere has no position");
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
        let Ret::U32(position) = f.invoke(absbtv_wg16, &[]).expect("position") else {
            panic!("absbtv returns a long");
        };
        assert!(acquire(&mut f, None, 0, 12), "somewhere else entirely");

        let minus_one = -1i16 as u16;
        f.invoke(
            aabbtv_wg16,
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
            .invoke(qrybtv_wg16, &[0, 0, 3, 62])
            .expect_err("SAMPLE.DAT has one key");
        assert!(e.to_string().contains("key 3"), "{e}");
    }

    #[test]
    fn an_option_no_macro_produces_is_refused() {
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 64);
        assert!(f.invoke(qrybtv_wg16, &[0, 0, 0, 5]).is_err(), "5 is an acquire code");
        assert!(f.invoke(obtbtvl_wg16, &[0, 0, 0, 0, 0, 62, 0]).is_err(), "62 is a query code");
        assert!(f.invoke(stpbtvl_wg16, &[0, 0, 99, 0]).is_err());
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

        f.invoke(obtbtvl_wg16, &[0, 0, 0, 0, 0, 12, 100])
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
        let Ret::U32(position) = f.invoke(absbtv_wg16, &[]).expect("has a position") else {
            panic!("absbtv answers with a position");
        };

        f.invoke(
            gabbtvl_wg16,
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
        assert_eq!(bb(&f), Btrieve::<Wg16>::null(), "nothing is current to begin with");
        f
    }

    #[test]
    fn qrybtv_with_no_file_current_answers_nothing_found() {
        let mut f = nothing_current();
        assert_eq!(
            f.invoke(qrybtv_wg16, &[0, 0, 0, 62]).expect("answers"),
            Ret::U16(0)
        );
    }

    #[test]
    fn qnpbtv_with_no_file_current_answers_nothing_found() {
        // And in particular does not fail looking for `bb->data` to read into,
        // which is a null block away.
        let mut f = nothing_current();
        assert_eq!(f.invoke(qnpbtv_wg16, &[56]).expect("answers"), Ret::U16(0));
    }

    #[test]
    fn obtbtvl_with_no_file_current_answers_nothing_found() {
        // Call 128 of `_INIT__WCCMMUD`, and the reason this step exists. The
        // null `recptr` is the module's own: `alobtv`/`ahibtv` pass NULL, so
        // the guard has to come before `recptr` is defaulted to `bb->data`.
        let mut f = nothing_current();
        assert_eq!(
            f.invoke(obtbtvl_wg16, &[0, 0, 0, 0, 0, 12, 0]).expect("answers"),
            Ret::U16(0)
        );
    }

    #[test]
    fn aabbtv_with_no_file_current_answers_nothing_found() {
        // Five argument words, per `BTVSTF.H:155`.
        let mut f = nothing_current();
        assert_eq!(
            f.invoke(aabbtv_wg16, &[0, 0, 7, 0, 0]).expect("answers"),
            Ret::U16(0)
        );
    }

    #[test]
    fn absbtv_with_no_file_current_answers_a_long_zero() {
        // `PLBTVSTF.C:427` is `return(0L)`, and `absbtv` is declared `long`, so
        // the answer occupies `DX:AX` and not just `AX`. A `Ret::U16(0)` here
        // would pass a test that only compared the low half.
        let mut f = nothing_current();
        assert_eq!(f.invoke(absbtv_wg16, &[]).expect("answers"), Ret::U32(0));
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
        let Ret::U32(position) = f.invoke(absbtv_wg16, &[]).expect("position") else {
            panic!("absbtv returns a long");
        };

        f.invoke(
            gabbtvl_wg16,
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
            f.invoke(
                gabbtvl_wg16,
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
        let not_found = f.invoke(qrybtv_wg16, &[0, 0, 0, 62]).expect("empty file");

        f.invoke(rstbtv_wg16, &[]).expect("restores");
        f.invoke(rstbtv_wg16, &[]).expect("and past the bottom");
        assert_eq!(bb(&f), Btrieve::<Wg16>::null(), "nothing current now");
        let no_file = f.invoke(qrybtv_wg16, &[0, 0, 0, 62]).expect("no file");

        assert_eq!(not_found, no_file, "the module cannot tell them apart");
    }

    #[test]
    fn stpbtvl_with_no_file_current_refuses_by_name() {
        // The one step routine with no guard in `PLBTVSTF.C`. It dereferences
        // `bb` twice before checking anything, so the real host faulted and
        // there is no answer to reproduce.
        let mut f = nothing_current();
        let e = f.invoke(stpbtvl_wg16, &[0, 0, 33, 0]).expect_err("no file");
        assert!(e.to_string().contains("stpbtvl"), "{e}");

        // With a null `recptr` too, which is the path that used to refuse from
        // inside a `bb->data` lookup and so named the block rather than itself.
        let e = f.invoke(stpbtvl_wg16, &[0, 0, 24, 0]).expect_err("no file");
        assert!(e.to_string().contains("stpbtvl"), "{e}");
    }

    #[test]
    fn cntrbtv_with_no_file_current_refuses_by_name() {
        // Right refusal, different reason: `:681` never reads `bb` and would
        // have counted whatever Btrieve was positioned on. This host has no
        // such position, so there is nothing to count rather than nothing to
        // dereference.
        let mut f = nothing_current();
        let e = f.invoke(cntrbtv_wg16, &[]).expect_err("no file");
        assert!(e.to_string().contains("cntrbtv"), "{e}");
    }

    #[test]
    fn invbtv_with_no_file_current_inserts_nothing_and_says_so() {
        // `PLBTVSTF.C:584` is the same guard the six reads have, in a `void`
        // function: with no file current the real host inserted nothing and
        // returned. Call 130 of `_INIT__WCCMMUD` is exactly this.
        let mut f = nothing_current();
        assert_eq!(f.invoke(invbtv_wg16, &[0, 0, 64]).expect("answers"), Ret::Void);
        assert!(
            f.host.notes().iter().any(|n| n.contains("invbtv")),
            "and it is recorded: {:?}",
            f.host.notes()
        );
    }

    #[test]
    fn invbtv_with_a_file_current_refuses_and_names_the_file() {
        // The other half, and the more important one. Nothing in this host
        // writes to a Btrieve file, so an insert into a real file must stop the
        // module rather than appear to work -- a module told its insert
        // succeeded and then finding the record gone is the failure mode this
        // whole crate is shaped around.
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 64);
        let e = f.invoke(invbtv_wg16, &[0, 0, 64]).expect_err("nothing here writes");
        assert!(e.to_string().contains("invbtv"), "{e}");
        assert!(e.to_string().contains("SAMPLE.DAT"), "{e}");
    }

    #[test]
    fn delbtv_with_no_file_current_deletes_nothing_and_says_so() {
        // `PLBTVSTF.C:623`, the same guard again.
        let mut f = nothing_current();
        assert_eq!(f.invoke(delbtv_wg16, &[]).expect("answers"), Ret::Void);
        assert!(
            f.host.notes().iter().any(|n| n.contains("delbtv")),
            "and it is recorded: {:?}",
            f.host.notes()
        );
    }

    #[test]
    fn delbtv_with_a_file_current_refuses_and_names_the_file() {
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 64);
        let e = f.invoke(delbtv_wg16, &[]).expect_err("nothing here writes");
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
            f.invoke(dinsbtv_wg16, &Fixture::far(recptr)).expect("inserts"),
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
            f.invoke(dinsbtv_wg16, &Fixture::far(recptr)).expect("answers"),
            Ret::U16(0),
            "key 5 already belongs to Troll"
        );
        assert_eq!(
            f.invoke(cntrbtv_wg16, &[]).expect("counts"),
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
            f.invoke(dinsbtv_wg16, &Fixture::far(recptr)).expect("answers"),
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
            f.invoke(dupdbtv_wg16, &Fixture::far(recptr)).expect("answers"),
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
                f.invoke(dinsbtv_wg16, &Fixture::far(recptr)).expect("inserts"),
                Ret::U16(1)
            );
            let Ret::U32(after) = f.invoke(absbtv_wg16, &[]).expect("position") else {
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
            let Ret::U32(expected) = g.invoke(absbtv_wg16, &[]).expect("position") else {
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
        let e = f.invoke(dinsbtv_wg16, &[0, 0]).expect_err("no file current");
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
        let Ret::U32(before) = f.invoke(absbtv_wg16, &[]).expect("position") else {
            panic!("absbtv returns a long");
        };

        let recptr = f.bytes(&sample_record(5, "TROLLX"), false);
        assert_eq!(
            f.invoke(dupdbtv_wg16, &Fixture::far(recptr)).expect("updates"),
            Ret::U16(1)
        );

        // An update is in place: `absbtv` answers the same before and after.
        let Ret::U32(after) = f.invoke(absbtv_wg16, &[]).expect("position") else {
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
        assert_eq!(g.invoke(cntrbtv_wg16, &[]).expect("counts"), Ret::U32(7));
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
        let mut f = Fixture::rooted(dir);
        open(&mut f, "SAMPLE.DAT", 64);

        assert!(acquire(&mut f, Some(5), 0, 5), "equal to 5, which is Troll");
        let Ret::U32(troll) = f.invoke(absbtv_wg16, &[]).expect("position") else {
            panic!("absbtv returns a long");
        };

        // 8 sorts after every one of SAMPLE.DAT's keys (1..=7), so Troll
        // moves from the middle of key order to the very end.
        let recptr = f.bytes(&sample_record(8, "TrollX"), false);
        assert_eq!(
            f.invoke(dupdbtv_wg16, &Fixture::far(recptr)).expect("updates"),
            Ret::U16(1)
        );

        let Ret::U32(after) = f.invoke(absbtv_wg16, &[]).expect("position") else {
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
            f.invoke(dupdbtv_wg16, &Fixture::far(recptr)).expect("answers"),
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
        assert_eq!(f.invoke(cntrbtv_wg16, &[]).expect("counts"), Ret::U32(7));
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
            .invoke(dupdbtv_wg16, &Fixture::far(recptr))
            .expect_err("nothing has positioned the file");
        assert!(e.to_string().contains("dupdbtv"), "{e}");
    }

    #[test]
    fn dupdbtv_with_no_file_current_stops_the_module() {
        // `PLBTVSTF.C:550` has the same no-guard shape as `dinsbtv`.
        let mut f = nothing_current();
        let e = f.invoke(dupdbtv_wg16, &[0, 0]).expect_err("no file current");
        assert!(e.to_string().contains("dupdbtv"), "{e}");
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

        f.invoke(clsbtv_wg16, &Fixture::far(block)).expect("closes");

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

        f.invoke(clsbtv_wg16, &Fixture::far(block)).expect("closes");
        // A second close of the same pointer: `filnam` is already null, so
        // `PLBTVSTF.C:637`'s guard is false and nothing runs -- in
        // particular nothing tries to free what the first close already
        // gave back, which would be a double free if it did.
        f.invoke(clsbtv_wg16, &Fixture::far(block))
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
        f.invoke(clsbtv_wg16, &Fixture::far(other)).expect("closes");

        let after = std::fs::read(&path).expect("read after");
        assert_eq!(before, after, "a clean close never touches the file");
    }

    #[test]
    fn the_missing_file_is_noted_once_however_often_it_is_asked() {
        // A null `bb` is legitimate and is also what an upstream mistake looks
        // like. The note is the only channel that says so -- and one identical
        // line per iteration of a module's loop is a channel nobody reads.
        let mut f = nothing_current();
        for _ in 0..50 {
            assert_eq!(
                f.invoke(qrybtv_wg16, &[0, 0, 0, 62]).expect("answers"),
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
        f.invoke(obtbtvl_wg16, &[0, 0, 0, 0, 0, 12, 0]).expect("answers");
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
                "qrybtv" => f.invoke(qrybtv_wg16, &[0, 0, 0, 62]),
                "obtbtvl" => f.invoke(obtbtvl_wg16, &[0, 0, 0, 0, 0, 12, 0]),
                "absbtv" => f.invoke(absbtv_wg16, &[]),
                _ => f.invoke(cntrbtv_wg16, &[]),
            }
            .expect_err("{who} on a block that was never opened");
            assert!(e.to_string().contains(who), "{who}: {e}");
        }
    }
}
