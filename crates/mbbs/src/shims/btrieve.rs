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
//! Seventeen symbols over 716 sites. Twelve are here: opening and choosing a
//! file, and reading records out of it. The five that are not are the ones that
//! *write* -- `dinsbtv`, `dupdbtv`, `invbtv`, `delbtv` -- and `clsbtv`.
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
//! # Nothing here writes
//!
//! A module that saves a character gets a refusal naming `dinsbtv` or
//! `dupdbtv`, rather than a host that appears to work and loses the data. That
//! is the whole reason the write family is absent rather than stubbed.
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

use mbbs16::{FarPtr, Machine, Ret};

use crate::Host;
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
pub fn omdbtv(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let mode = machine.arg_u16(0) as i16;
    if !MODES.contains(&mode) {
        return Err(ShimError::Failed(format!(
            "omdbtv({mode}), which is none of the five modes BTVSTF.H defines"
        )));
    }
    host.btrieve.set_mode(mode);
    Ok(Ret::Void)
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
pub fn opnbtv(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let named = String::from_utf8_lossy(machine.read_cstr(machine.arg_far(0))?).into_owned();
    let maxlen = machine.arg_u16(2);
    let name = Host::dos_name(&named).map_err(ShimError::Failed)?.to_owned();

    let path = host.btrieve_file(&name).map_err(ShimError::Failed)?;
    let geometry = Geometry::read(&name, &path).map_err(|e| ShimError::Failed(e.to_string()))?;

    // `PLBTVSTF.C:150` -- `bb->reclen=maxlen`, the module's number and not the
    // file's. They are allowed to differ, and **the two directions are not the
    // same thing**, which is why they are reported differently.
    //
    // Opening for *more* is ordinary: `WCCTEXT.DAT` holds variable-length
    // records up to 22 bytes and MajorMUD opens it for 2022, which is the
    // buffer a variable-length read needs. `movmem(gpbptr,recptr,dbflen)`
    // copies what Btrieve returned, and so does [`deliver`]. They agree.
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
        host.note(format!(
            "{name} holds {}-byte records and the module opened it for {maxlen}",
            geometry.reclen
        ));
    }

    let block = {
        let Host { btrieve, heap, .. } = host;
        btrieve
            .open(machine, heap, &name, &path, geometry, maxlen)
            .map_err(|e| ShimError::Failed(format!("opnbtv({name}): {e}")))?
    };

    // `bb = the new block` and *then* `setbtv(bb)`, in that order, because that
    // is the order `PLBTVSTF.C:145` and `:167` do it in and the order is the
    // whole of the difference: it is what makes the open push itself.
    set_current(machine, host, block)?;
    push(machine, host, block)?;
    Ok(Ret::Far(block))
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
pub fn setbtv(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let block = machine.arg_far(0);
    if block != Btrieve::null() {
        host.btrieve.block(block).map_err(ShimError::Failed)?;
    }
    push(machine, host, block)?;
    Ok(Ret::Void)
}

/// `void rstbtv(void)` -- go back to the file that was current before.
///
/// Underflow is not an error here, which is the one place this crate follows
/// the original rather than refusing. See
/// [`Btrieve::restore`](crate::btrieve::Btrieve::restore) for why.
pub fn rstbtv(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let (restored, empty) = host.btrieve.restore();
    if empty {
        host.note(
            "rstbtv with nothing to restore, so the current Btrieve file is now \
             null -- which is what the real host does, and what every routine in \
             PLBTVSTF.C checks for"
                .to_owned(),
        );
    }
    set_current(machine, host, restored)?;
    Ok(Ret::Void)
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
pub fn cntrbtv(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let block = positioned(machine, host, "cntrbtv")?.ok_or_else(|| {
        ShimError::Failed(
            "cntrbtv with no Btrieve file current -- PLBTVSTF.C:681 would have \
             counted whatever file Btrieve was last positioned on, and this \
             host has no such position to fall back on"
                .to_owned(),
        )
    })?;
    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    Ok(Ret::U32(file.geometry().records))
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
pub fn qrybtv(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    // The guard is the first thing `PLBTVSTF.C:262` does -- before the key, the
    // key number or the option are looked at -- so it is the first thing here.
    let Some(block) = positioned(machine, host, "qrybtv")? else {
        note_no_file(host, "qrybtv");
        return Ok(Ret::U16(0));
    };

    let value = machine.arg_far(0);
    let keynum = machine.arg_u16(2) as i16;
    let opt = machine.arg_u16(3) as i16;

    // `qrybtv` takes the *get key* codes, fifty above the acquire family's.
    let op = Op::of(opt - 50).ok_or_else(|| {
        ShimError::Failed(format!(
            "qrybtv with option {opt}, which is none of the nine BTVSTF.H's q-macros produce"
        ))
    })?;
    Ok(Ret::U16(u16::from(locate(
        machine,
        host,
        Request {
            who: "qrybtv",
            block,
            op,
            keynum,
            value,
            into: None,
        },
    )?)))
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
pub fn qnpbtv(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    // `PLBTVSTF.C:287`, and it has to be before `bb->data` is read for the same
    // reason the C puts it there: there is no `bb->data` to read.
    let Some(block) = positioned(machine, host, "qnpbtv")? else {
        note_no_file(host, "qnpbtv");
        return Ok(Ret::U16(0));
    };

    let opt = machine.arg_u16(0) as i16;
    let op = Op::of(opt - 50).ok_or_else(|| {
        ShimError::Failed(format!("qnpbtv with option {opt}, which is not a get operation"))
    })?;

    // `bb->lastkn`: which key the last positioning used. Passed as -1 so that
    // `locate` reads it back rather than changing it, exactly as the C does.
    let into = data_buffer(host, block)?;
    Ok(Ret::U16(u16::from(locate(
        machine,
        host,
        Request {
            who: "qnpbtv",
            block,
            op,
            keynum: -1,
            value: Btrieve::null(),
            into: Some(into),
        },
    )?)))
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
/// `loktyp` is read and refused if it is not zero. Record locking is a
/// multi-user concern this host has no second user for yet, and a lock silently
/// not taken is the kind of difference that shows up as two channels writing
/// over each other much later.
///
/// **With no file current it answers 0**, per `PLBTVSTF.C:357` -- and this is
/// the one initialisation actually reaches. Call 128 of `_INIT__WCCMMUD` is an
/// `obtbtvl` after a `setbtv(NULL)`, and it is entitled to be told there is no
/// record rather than stopped.
pub fn obtbtvl(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    // `:357` guards, and only then does `:360` default `recptr` to `bb->data`.
    // The order is the whole of it: `bb->data` cannot be read from a null `bb`,
    // so a guard placed after that default never runs.
    let Some(block) = positioned(machine, host, "obtbtvl")? else {
        note_no_file(host, "obtbtvl");
        return Ok(Ret::U16(0));
    };

    let into = machine.arg_far(0);
    let value = machine.arg_far(2);
    let keynum = machine.arg_u16(4) as i16;
    let opt = machine.arg_u16(5) as i16;
    let lock = machine.arg_u16(6) as i16;
    unlocked("obtbtvl", lock)?;

    let op = Op::of(opt).ok_or_else(|| {
        ShimError::Failed(format!(
            "obtbtvl with option {opt}, which is none of the nine BTVSTF.H's a-macros produce"
        ))
    })?;
    let into = match into == Btrieve::null() {
        true => data_buffer(host, block)?,
        false => into,
    };
    Ok(Ret::U16(u16::from(locate(
        machine,
        host,
        Request {
            who: "obtbtvl",
            block,
            op,
            keynum,
            value,
            into: Some(into),
        },
    )?)))
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
pub fn stpbtvl(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    // Before `recptr` is defaulted, so that the refusal names `stpbtvl` rather
    // than coming out of a `bb->data` lookup on a null block.
    let block = positioned(machine, host, "stpbtvl")?.ok_or_else(|| {
        ShimError::Failed(
            "stpbtvl with no Btrieve file current -- PLBTVSTF.C:509 has no \
             guard for that and dereferences bb twice, so the real host faulted \
             here rather than answering"
                .to_owned(),
        )
    })?;

    let into = machine.arg_far(0);
    let opt = machine.arg_u16(2) as i16;
    let lock = machine.arg_u16(3) as i16;
    unlocked("stpbtvl", lock)?;

    let into = match into == Btrieve::null() {
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
        (34, _) => return Ok(Ret::U16(0)),
        (24, Cursor::Physical { at }) => at + 1,
        (35, Cursor::Physical { at }) if at > 0 => at - 1,
        (35, Cursor::Physical { .. }) => return Ok(Ret::U16(0)),
        // Stepping from a keyed position, or from no position at all. Btrieve
        // keeps one cursor per file and a step reads it as a physical one, so
        // this is a module bug rather than something to answer: the honest
        // reading of "next" here does not exist.
        (24 | 35, cursor) => {
            return Err(ShimError::Failed(format!(
                "stpbtvl({opt}) on {}, which is positioned {cursor:?} -- \
                 a step continues a step, and nothing has stepped yet",
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
        return Ok(Ret::U16(0));
    }
    file.seek_to(Cursor::Physical { at });
    deliver(machine, host, block, into)?;
    Ok(Ret::U16(1))
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
pub fn absbtv(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let Some(block) = positioned(machine, host, "absbtv")? else {
        note_no_file(host, "absbtv");
        return Ok(Ret::U32(0));
    };
    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    let record = file.current().ok_or_else(|| {
        ShimError::Failed(format!(
            "absbtv on {}, which is not positioned on a record",
            file.name()
        ))
    })?;
    Ok(Ret::U32(record.position))
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
/// lowest local instead -- which [`unlocked`] then refused as a lock type the
/// module never asked for. It shared [`absolute`] with `gabbtvl`, which really
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
pub fn aabbtv(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    Ok(Ret::U16(u16::from(absolute(
        machine, host, "aabbtv", false, UNLOCKED,
    )?)))
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
pub fn gabbtvl(machine: &mut Machine, host: &mut Host) -> Result<Ret, ShimError> {
    let lock = machine.arg_u16(5) as i16;
    absolute(machine, host, "gabbtvl", true, lock)?;
    Ok(Ret::Void)
}

/// The body of `aabbtv` and `gabbtvl`. Returns whether a record was delivered.
///
/// `false` covers both of the original's non-answers: no file current
/// (`PLBTVSTF.C:476`) and no record at that position. They differ for
/// `gabbtvl`, which `:455` sends to `posbtverr` in the second case only -- so
/// `fatal` turns the second into a refusal and never the first.
///
/// **`lock` is the caller's** rather than read here, because the two callers do
/// not have the same arguments. See [`aabbtv`].
fn absolute(
    machine: &mut Machine,
    host: &mut Host,
    who: &str,
    fatal: bool,
    lock: i16,
) -> Result<bool, ShimError> {
    // `:452` and `:476` both guard before `:479` defaults `recptr` to
    // `bb->data`. Same ordering point as `obtbtvl`, and the lock is refused
    // after it for the same reason: with no file current the original returned
    // before it looked at anything.
    let Some(block) = positioned(machine, host, who)? else {
        note_no_file(host, who);
        return Ok(false);
    };
    unlocked(who, lock)?;

    let into = machine.arg_far(0);
    let position = machine.arg_u32(2);
    let keynum = machine.arg_u16(4) as i16;

    let into = match into == Btrieve::null() {
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
    let key = key_number(machine, host, block, keynum)?;

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

    // `:484` passes `bb->keyseg`, so Btrieve left the found record's key there.
    answer_with_key(machine, host, block, key)?;
    deliver(machine, host, block, into)?;
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
}

/// Position the file a [`Request`] names, and hand back the record if asked.
///
/// Returns whether a record was found.
fn locate(machine: &mut Machine, host: &mut Host, req: Request) -> Result<bool, ShimError> {
    let Request {
        who,
        block,
        op,
        keynum,
        value,
        into,
    } = req;
    load(host, block)?;
    let key = key_number(machine, host, block, keynum)?;

    // `PLBTVSTF.C:266` -- the module's key value is copied into `bb->key`
    // before anything else, and that is where it is read from afterwards. So a
    // module may pass the buffer it was given last time and mean "the same key
    // again", which only works if the copy really happens.
    if value != Btrieve::null() {
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
        let bytes = machine.resolve(value, usize::from(length))?.to_vec();
        let buffer = host
            .btrieve
            .block(block)
            .map_err(ShimError::Failed)?
            .key();
        machine.write(buffer, &bytes)?;
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
            machine.resolve(buffer, usize::from(length))?.to_vec()
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

    // Where the file is now, in this key's order. A cursor left by a step, or
    // by a query on a different key, is translated through the record's place
    // rather than reused as an index -- the two orders have nothing to do with
    // each other.
    let here = match cursor {
        Cursor::Ordered { key: had, at } if had == key => Some(at),
        Cursor::Ordered { key: had, at } => records
            .ordered(had, at)
            .and_then(|r| records.find_physical(r.position))
            .and_then(|physical| records.place_in(key, physical)),
        Cursor::Physical { at } => records.place_in(key, at),
        Cursor::Nowhere => None,
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
        Op::Next => match here {
            Some(at) => Some(at + 1).filter(|at| *at < count),
            None => {
                return Err(ShimError::Failed(format!(
                    "{who} asked {name} for the next record and nothing has \
                     positioned it, so there is no record to be next to"
                )));
            }
        },
        Op::Previous => match here {
            Some(at) => at.checked_sub(1),
            None => {
                return Err(ShimError::Failed(format!(
                    "{who} asked {name} for the previous record and nothing has \
                     positioned it"
                )));
            }
        },
    };

    // Not found leaves the file where it was, which is what Btrieve does: a
    // failed Get Equal does not lose the position a successful one established.
    let Some(at) = found else {
        return Ok(false);
    };
    file.seek_to(Cursor::Ordered { key, at });
    answer_with_key(machine, host, block, key)?;

    if let Some(into) = into {
        deliver(machine, host, block, into)?;
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
    machine: &mut Machine,
    host: &mut Host,
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
        .extract(&record.bytes);
    let buffer = file.key();
    machine.write(buffer, &bytes)?;
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
    machine: &mut Machine,
    host: &mut Host,
    block: FarPtr,
    into: FarPtr,
) -> Result<(), ShimError> {
    let file = host.btrieve.block(block).map_err(ShimError::Failed)?;
    let record = file
        .current()
        .ok_or_else(|| ShimError::Failed(format!("{} is not positioned", file.name())))?;
    let take = usize::from(file.maxlen()).min(record.bytes.len());
    let bytes = record.bytes[..take].to_vec();
    machine.write(into, &bytes)?;
    Ok(())
}

/// Which key an operation works on, honouring `bb->lastkn`.
///
/// `PLBTVSTF.C:268`: a negative key number means "the one last used", and any
/// other means "this one, and remember it". `lastkn` is a field of the block in
/// module memory, so it is read and written there rather than kept here.
fn key_number(
    machine: &mut Machine,
    host: &Host,
    block: FarPtr,
    keynum: i16,
) -> Result<u16, ShimError> {
    let at = FarPtr {
        offset: block.offset + LASTKN,
        selector: block.selector,
    };
    if keynum < 0 {
        let bytes = machine.resolve(at, 2)?;
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
    machine.write(at, &(keynum as u16).to_le_bytes())?;
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
fn positioned(machine: &Machine, host: &Host, who: &str) -> Result<Option<FarPtr>, ShimError> {
    let block = current(machine, host)?;
    if block == Btrieve::null() {
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

/// Refuse a lock type this host cannot honour.
///
/// `BTVSTF.H:52` defines four: single or multiple, waiting or not. All four
/// exist so that two channels reading the same record do not tread on each
/// other, and this host runs one thing at a time -- so a lock is never
/// contended and never needed. **Taking that as licence to ignore the argument
/// is the trap**: the day a second channel exists, every lock the module asked
/// for will have been silently not taken, and what it protects is a character's
/// inventory.
fn unlocked(who: &str, lock: i16) -> Result<(), ShimError> {
    if lock == 0 {
        return Ok(());
    }
    Err(ShimError::Failed(format!(
        "{who} asked for lock type {lock}, and this host has no locking to give it"
    )))
}

/// Push what is current and make `block` current, as `setbtv` does.
fn push(machine: &mut Machine, host: &mut Host, block: FarPtr) -> Result<(), ShimError> {
    let previous = current(machine, host)?;
    if let Some(dropped) = host.btrieve.set(previous) {
        host.note(format!(
            "the setbtv stack is ten deep and overflowed, so {dropped} fell off \
             the bottom -- exactly as it would have on the real host"
        ));
    }
    set_current(machine, host, block)
}

/// What `bb` holds, read back out of module memory every time.
fn current(machine: &Machine, host: &Host) -> Result<FarPtr, ShimError> {
    host.globals()
        .pointer(machine, "bb")
        .map_err(|e| ShimError::Failed(e.to_string()))
}

fn set_current(machine: &mut Machine, host: &Host, block: FarPtr) -> Result<(), ShimError> {
    host.globals()
        .write(machine, "bb", &block.to_bytes())
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
        assert_eq!(bb(&f), Btrieve::null(), "nothing is current to begin with");
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
        assert_eq!(bb(&f), Btrieve::null());
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
            None => Btrieve::null(),
        };
        f.invoke(
            obtbtvl,
            &[0, 0, value.offset, value.selector, keynum as u16, opt as u16, 0],
        )
        .expect("acquires")
            == Ret::U16(1)
    }

    /// Where `bb->data` is, for a file the test just opened.
    fn buffer(f: &Fixture, block: FarPtr) -> FarPtr {
        f.host.btrieve().block(block).expect("open").data()
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
        assert_ne!(key, Btrieve::null(), "opnbtv allocates it");

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
    fn aabbtv_takes_three_arguments_and_never_reads_a_fourth() {
        // `BTVSTF.H:155` declares `int aabbtv(void*, long, int)` -- five
        // argument words -- and all eight of `WCCMMUD.DLL`'s call sites clean
        // `add sp,10`, which is those five and no more. `aabbtvl`, the
        // four-argument form, is a separate export the module never imports.
        //
        // This host read a sixth word as `loktyp` because it shared a helper
        // with `gabbtvl`, which really does take four. The sixth word is the
        // caller's, and `unlocked` refused anything nonzero in it -- so the
        // failure was a lock the module never asked for.
        //
        // Invoked with exactly five words, which is what gives this teeth: the
        // word above them is the outer frame's return offset and is not zero.
        let mut f = Fixture::new();
        let block = open(&mut f, "SAMPLE.DAT", 64);
        let into = buffer(&f, block);

        assert!(acquire(&mut f, Some(6), 0, 5), "equal to 6");
        let Ret::U32(position) = f.invoke(absbtv, &[]).expect("position") else {
            panic!("absbtv returns a long");
        };
        assert!(acquire(&mut f, None, 0, 12), "somewhere else entirely");

        assert_eq!(
            f.invoke(aabbtv, &[0, 0, position as u16, (position >> 16) as u16, 0])
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
        f.invoke(
            gabbtvl,
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

    #[test]
    fn a_next_with_nothing_to_be_next_to_refuses() {
        // Btrieve would have answered with whatever its position block happened
        // to hold. There is no honest answer: "the record after nowhere" is not
        // a record, and returning the first one would be a different question's
        // answer.
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 64);
        assert!(f.invoke(qnpbtv, &[56]).is_err());
        assert!(f.invoke(stpbtvl, &[0, 0, 24, 0]).is_err());
        assert!(f.invoke(absbtv, &[]).is_err(), "and nowhere has no position");
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
        f.invoke(
            aabbtv,
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

    #[test]
    fn a_lock_this_host_cannot_take_is_refused_rather_than_ignored() {
        // One channel is never contended, so every lock would appear to work.
        // The day there are two, they would all have been silently skipped.
        let mut f = Fixture::new();
        open(&mut f, "SAMPLE.DAT", 64);
        let e = f
            .invoke(obtbtvl, &[0, 0, 0, 0, 0, 12, 100])
            .expect_err("SLWTBV is a single record lock with wait");
        assert!(e.to_string().contains("100"), "{e}");
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
        assert_eq!(bb(&f), Btrieve::null(), "nothing is current to begin with");
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
                gabbtvl,
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
        assert_eq!(bb(&f), Btrieve::null(), "nothing current now");
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
}
