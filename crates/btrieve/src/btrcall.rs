//! The numeric BTRCALL entry point, and the status codes it answers with.
//!
//! Both Btrieve edges this host serves are single-entry-point interfaces --
//! `int 7Bh` and `wbtrv32.dll!BTRCALL` each hand over one parameter block and
//! expect one status word. This module is the one place a number becomes a
//! typed operation, so neither edge grows a second copy of that translation.
//!
//! # Why a status and a gap are different types
//!
//! A Btrieve caller's only channel is a status word, which makes it easy and
//! disastrous to answer a hole in this engine with a plausible Btrieve number.
//! A [`Status`] is a real answer the engine computed. A [`Gap`] is an
//! operation this engine does not model, and it never reaches a guest: it
//! stops the run and names itself, the way an unimplemented import already
//! does. Folding the two would let a differential harness score a gap as a
//! passing disagreement, and let a guest branch on a lie.

use crate::mem::{Alloc, Mem};
use crate::ops::{Op, OpError, Step};

/// A real Btrieve status word. Zero is success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status(pub i16);

impl Status {
    /// The operation succeeded.
    pub const OK: Status = Status(0);
}

/// An operation this engine does not model.
///
/// Deliberately not a status code: see this module's own doc comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    /// What was asked for, in words a person can act on.
    pub what: String,
}

/// The real Btrieve status for a typed refusal, or a [`Gap`] where this
/// engine has no answer to give.
///
/// **The match is total, with no `_` arm, deliberately.** A new [`OpError`]
/// variant should be a compile error here rather than a silent mapping to
/// whatever the catch-all happened to say. A wrong status is not a crash; it
/// is a guest taking a branch it should never have taken.
///
/// # Errors
///
/// If the refusal names something this engine does not model, in which case
/// no Btrieve status describes it and inventing one would be a lie.
pub fn status_of(e: &OpError) -> Result<Status, Gap> {
    match e {
        OpError::NoSuchKey(_) => Ok(Status(6)),
        OpError::LockModeMixed { .. } => Ok(Status(93)),
        OpError::NotPositioned => Ok(Status(8)),
        OpError::DifferentKey { .. } => Ok(Status(7)),
        OpError::NoKeyEstablished => Ok(Status(8)),
        OpError::NotAllowedDuringTransaction => Ok(Status(41)),
        OpError::OwnerAlreadySet => Ok(Status(50)),
        OpError::OwnerNameInvalid { .. } => Ok(Status(51)),
        OpError::InvalidDirectory => Ok(Status(35)),
        OpError::ObsoleteOperation => Ok(Status(1)),
        OpError::PreV6Chunk => Ok(Status(107)),
        OpError::ChunkOffsetTooBig => Ok(Status(103)),
        OpError::InvalidRecordAddress => Ok(Status(43)),
        OpError::DuplicateKey { .. } => Ok(Status(5)),
        OpError::AlreadyInContinuousOperation { .. } => Ok(Status(88)),
        OpError::EndOfFile => Ok(Status(9)),

        // The three the enum itself says no status names. Each variant's doc
        // comment gives the full account; none is a vendor refusal, all three
        // are structural holes in this engine.
        OpError::NccUnsupported => Err(Gap {
            what: "Get Next/Prev Extended with no-currency-change (NCC): this \
                   engine's cursor is one value, not independent physical and \
                   logical currencies"
                .to_owned(),
        }),
        OpError::ConcurrentTransactionUnsupported => Err(Gap {
            what: "concurrent transaction (op 1019): this engine models one \
                   exclusive transaction, and no Btrieve status names the \
                   difference"
                .to_owned(),
        }),
        OpError::IndexMutationUnsupported => Err(Gap {
            what: "Create Index / Drop Index (ops 31/32): the order this \
                   engine queries by is rebuilt only inside `records`, which \
                   `ops` cannot reach"
                .to_owned(),
        }),

        // Measured behaviour does not exist for these two. `CursorStale` is
        // documented as defensive rather than reachable on a single-threaded
        // host, and `Records` wraps a read failure rather than an operation
        // refusal. Answering either with a plausible number would be
        // inventing evidence; a gap says so and stops.
        OpError::CursorStale => Err(Gap {
            what: "a stale cursor: documented as unreachable on this host, so \
                   its real Btrieve status was never measured"
                .to_owned(),
        }),
        OpError::Records(why) => Err(Gap {
            what: format!("the records could not be read: {why}"),
        }),
    }
}

/// What one Btrieve operation code names.
///
/// The families delegate to the engine's own tables rather than restating
/// them: [`Op::from_get`], [`Op::from_query`] and [`Step::from_code`] were
/// each verified against `shims/btrieve.rs`, and the Get codes are not in
/// numeric order, so a second table here would be a second chance to get that
/// wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Op 0.
    Open,
    /// Op 1.
    Close,
    /// Op 2.
    Insert,
    /// Op 3.
    Update,
    /// Op 4.
    Delete,
    /// Op 15.
    Stat,
    /// Op 22, `dfaAbs`: where the file is currently positioned, as a
    /// physical position.
    AbsolutePosition,
    /// Op 23, `dfaAcqAbsLock`: position at an absolute physical position and
    /// deliver that record.
    AcquireAbsolute,
    /// Op 25 -- close every file and release everything.
    Stop,
    /// Ops 5-13: a keyed read.
    Get(Op),
    /// Ops 55-63: the same nine comparisons without reading the record.
    Query(Op),
    /// Ops 24, 33-35: physical order, no key.
    Step(Step),
    /// An operation code this engine does not model, carried so a caller can
    /// name it rather than report a bare failure.
    Unmodelled(u16),
}

/// What operation code `op` names.
#[must_use]
pub fn describe(op: u16) -> Outcome {
    if let Ok(code) = i16::try_from(op) {
        if let Some(o) = Op::from_get(code) {
            return Outcome::Get(o);
        }
        if let Some(o) = Op::from_query(code) {
            return Outcome::Query(o);
        }
        if let Some(s) = Step::from_code(code) {
            return Outcome::Step(s);
        }
    }
    match op {
        0 => Outcome::Open,
        1 => Outcome::Close,
        2 => Outcome::Insert,
        3 => Outcome::Update,
        4 => Outcome::Delete,
        15 => Outcome::Stat,
        22 => Outcome::AbsolutePosition,
        23 => Outcome::AcquireAbsolute,
        25 => Outcome::Stop,
        other => Outcome::Unmodelled(other),
    }
}

/// One BTRCALL's arguments, already marshalled out of whichever guest made it.
///
/// This is the parameter block both edges carry, in host terms: the real-mode
/// edge reads it out of a 28-byte `btvdat` at `DS:DX`, and the Win32 edge
/// reads it off a stdcall stack. Neither shape appears here.
pub struct Call<'a> {
    /// The Btrieve operation code.
    pub op: u16,

    /// The guest's 128-byte position block.
    ///
    /// **This engine does not serialise its own state here.** Its private
    /// state is far larger than 128 bytes and would never match genuine
    /// Btrieve's layout anyway. Instead Open writes this session's file
    /// pointer into the first `M::PTR_WIDTH` bytes and every later operation
    /// reads it back, so the block is a handle rather than a snapshot.
    ///
    /// That relies on the guest keeping **one stable position block per open
    /// file**, which Galacticomm's own `DFAAPI.C` does -- it passes
    /// `dfa->posblk`, a field of a heap-allocated `DFAFILE`. A guest that
    /// copied a position block elsewhere and kept using it would be told the
    /// file is not open.
    pub posblk: &'a mut [u8; 128],

    /// The data buffer: the record in, or the record out.
    pub databuf: &'a mut Vec<u8>,

    /// How many bytes of `databuf` the caller offered, and how many this
    /// engine used. Written back on every operation that delivers a record.
    pub datalen: &'a mut u32,

    /// The key buffer -- the value to search for, or the filename on Open.
    pub keybuf: &'a mut Vec<u8>,

    /// How many bytes of `keybuf` are meaningful. `DFAAPI.C` always passes
    /// `255`.
    pub keylen: u8,

    /// Which key to work by. Negative numbers name the Btrieve options that
    /// are not keys at all.
    pub keynum: i8,
}

/// Answer one BTRCALL.
///
/// # Errors
///
/// [`Gap`] where this engine does not model what was asked. A gap is never a
/// status: see this module's own doc comment.
pub fn btrcall<M: Mem>(
    session: &mut crate::Btrieve<M>,
    memory: &mut M::Memory,
    heap: &mut impl Alloc<M>,
    call: Call<'_>,
) -> Result<Status, Gap> {
    match describe(call.op) {
        Outcome::Open => open(session, memory, heap, call),
        Outcome::Close => close(session, memory, heap, call),
        Outcome::Get(op) => get(session, op, call),
        Outcome::Step(step) => step_op(session, step, call),
        Outcome::Insert => insert(session, call),
        Outcome::Update => update(session, call),
        Outcome::Delete => delete(session, call),
        Outcome::Stat => stat(session, call),
        Outcome::AbsolutePosition => absolute_position(session, call),
        Outcome::AcquireAbsolute => acquire_absolute(session, call),
        Outcome::Query(_) | Outcome::Stop => Err(Gap {
            what: format!("operation {} is named but not yet dispatched", call.op),
        }),
        Outcome::Unmodelled(n) => Err(Gap {
            what: format!("operation code {n} is not modelled by this engine"),
        }),
    }
}

fn open<M: Mem>(
    session: &mut crate::Btrieve<M>,
    memory: &mut M::Memory,
    heap: &mut impl Alloc<M>,
    call: Call<'_>,
) -> Result<Status, Gap> {
    // Btrieve's Open takes the filename in the key buffer, NUL-terminated.
    let end = call.keybuf.iter().position(|b| *b == 0).unwrap_or(call.keybuf.len());
    let name = String::from_utf8_lossy(&call.keybuf[..end]).into_owned();
    let path = std::path::PathBuf::from(&name);
    let leaf = path
        .file_name()
        .map_or_else(|| name.clone(), |s| s.to_string_lossy().into_owned());

    let geometry = match crate::Geometry::read(&leaf, &path) {
        Ok(g) => g,
        // A file that will not open is a real Btrieve answer: status 12,
        // "the MicroKernel cannot find the specified file".
        Err(_) => return Ok(Status(12)),
    };
    let maxlen = u16::try_from(*call.datalen).unwrap_or(u16::MAX);

    match session.open(memory, heap, &leaf, &path, geometry, maxlen) {
        Ok(at) => {
            let bytes = M::ptr_to_bytes(at);
            call.posblk[..bytes.len()].copy_from_slice(&bytes);
            Ok(Status::OK)
        }
        Err(why) => Err(Gap {
            what: format!("opening {leaf}: {why}"),
        }),
    }
}

/// How many bytes of record *this* call can take back.
///
/// The buffer itself, not `*call.datalen`. The two agree on every edge --
/// each sizes `databuf` from the guest's own declared length before dispatch
/// -- but `datalen` is an in/out field this dispatch overwrites on the way
/// out, and `databuf` is the thing actually written back to the guest. Op 15
/// (`stat`) has always measured its own truncation this way; the delivering
/// ops now do too.
///
/// Not [`crate::Block::maxlen`], which is the length a *module* named once at
/// `opnbtv(filnam, maxlen)` and belongs to the shim edge -- see
/// [`crate::Block::deliver_current`]'s own doc comment for why a ceiling
/// taken at Open is a number genuine Btrieve's wire never had (its Open
/// carries `datalen: 0`), and for the guest-buffer overrun that followed from
/// using one.
fn offered(call: &Call<'_>) -> u16 {
    u16::try_from(call.databuf.len()).unwrap_or(u16::MAX)
}

/// The file handle Open recorded in the position block.
fn handle_of<M: Mem>(posblk: &[u8; 128]) -> M::Ptr {
    M::ptr_from_bytes(&posblk[..M::PTR_WIDTH])
}

/// Close the file Open recorded in `call.posblk`.
///
/// [`crate::Btrieve::close`] answers `Ok(false)` for a pointer that names no
/// open file -- a second close of the same block, or one that never opened.
/// `PLBTVSTF.C` cannot tell those two apart either, and neither the shim
/// edge (`clsbtv`, which discards the bool outright) nor any measured
/// Btrieve status distinguishes them from an ordinary close, so both bools
/// answer [`Status::OK`] here. Only [`BtvError`](crate::BtvError) -- the
/// block still holding an unflushed transaction pre-image, or a failed
/// allocation free -- is a hole this table does not name a status for, and
/// becomes a [`Gap`].
fn close<M: Mem>(
    session: &mut crate::Btrieve<M>,
    memory: &mut M::Memory,
    heap: &mut impl Alloc<M>,
    call: Call<'_>,
) -> Result<Status, Gap> {
    let at = handle_of::<M>(call.posblk);
    match session.close(memory, heap, at) {
        Ok(_) => Ok(Status::OK),
        Err(why) => Err(Gap {
            what: format!("closing: {why}"),
        }),
    }
}

fn get<M: Mem>(
    session: &mut crate::Btrieve<M>,
    op: Op,
    call: Call<'_>,
) -> Result<Status, Gap> {
    let at = handle_of::<M>(call.posblk);
    let index = session.find(at).map_err(|why| Gap { what: why })?;
    let key = u16::try_from(call.keynum.max(0)).unwrap_or(0);
    let value = &call.keybuf[..usize::from(call.keylen).min(call.keybuf.len())];

    match session.open[index].get(key, op, value, 0, &mut session.locks, offered(&call)) {
        Ok(Some(d)) => {
            *call.datalen = u32::try_from(d.bytes.len()).unwrap_or(u32::MAX);
            call.databuf.clear();
            call.databuf.extend_from_slice(&d.bytes);
            if let Some(k) = d.key {
                call.keybuf.clear();
                call.keybuf.extend_from_slice(&k);
            }
            // A record that did not fit the caller's buffer is a success with
            // a truncated answer, not a failure -- real Btrieve status 22.
            Ok(if d.truncated { Status(22) } else { Status::OK })
        }
        // No record matched. Genuine Btrieve distinguishes a keyed `Get
        // Equal` miss -- status 4, "the application cannot find the key
        // value" -- from every other Get's miss, which stays status 9, "end
        // of file". Measured directly, not inferred: `update_and_delete.
        // fixture` (a `Get Equal` for a just-deleted key) and `status_ten_
        // refusal_and_same_value_rewrite.fixture` (a `Get Equal` for a key
        // that was never written) both answer 4, while
        // `insert_get_step_stat.fixture`'s `Get Next`/`Get Previous` misses
        // and its Step family's own exhaustion both answer 9. No fixture
        // exercises a miss on `Greater`/`AtLeast`/`Less`/`AtMost`/`Lowest`/
        // `Highest`, so those keep answering 9 rather than guessing beyond
        // what was measured -- see Task 12's report.
        Ok(None) => Ok(if op == Op::Equal { Status(4) } else { Status(9) }),
        Err(e) => status_of(&e),
    }
}

/// Op 15: report a file's shape and key definitions in Btrieve's own reply
/// format.
///
/// **Not a byte layout invented here.** [`crate::stat::Stat::read`] and
/// [`crate::stat::Stat::wire`] already build the full reply -- see that
/// module's own doc comment for the provenance: every field measured against
/// genuine Pervasive Btrieve 6.15 under Wine, not inferred from the vendor
/// header. This is the numeric door onto that already-built and already-
/// tested reply, the same shape every other arm in this file is: delegate,
/// never restate. [`crate::stat::deliver`] then trims the full reply to
/// whatever the caller's own buffer can hold, exactly the way [`get`] trims a
/// record it delivers.
fn stat<M: Mem>(session: &crate::Btrieve<M>, call: Call<'_>) -> Result<Status, Gap> {
    let at = handle_of::<M>(call.posblk);
    let index = session.find(at).map_err(|why| Gap { what: why })?;
    let block = &session.open[index];

    let built = crate::stat::Stat::read(&block.name, &block.path, &block.geometry, &block.keys)
        .map_err(|e| Gap {
            what: format!("STAT on {}: {e}", block.name),
        })?;
    let full = built.wire(block.geometry.version, call.keynum);
    let (bytes, short) = crate::stat::deliver(&full, call.databuf.len());

    *call.datalen = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    call.databuf.clear();
    call.databuf.extend_from_slice(bytes);

    // A reply cut short of the full one is a success with a truncated
    // answer, not a failure -- the same real Btrieve status 22 `get` answers
    // for the same reason. See `crate::stat::deliver`'s own doc comment for
    // what "short" means here: whole 16-byte units only, nothing narrower.
    Ok(if short { Status(22) } else { Status::OK })
}

/// Op 22, `dfaAbs`: where the file is currently positioned.
///
/// [`crate::ops::Block::get_position`] already computes this -- another case
/// where the numeric door was simply never opened onto an existing, already-
/// tested method, the same shape [`stat`] wires in. `re/wg33src/SRC/api/
/// gcommlib/DFAAPI.C:453`'s `dfaAbs` calls `btvu(22,&abspos,NULL,0,
/// sizeof(LONG))`: the position comes back through the data buffer as a
/// four-byte value, not the position block, so that is where this writes it.
fn absolute_position<M: Mem>(session: &crate::Btrieve<M>, call: Call<'_>) -> Result<Status, Gap> {
    let at = handle_of::<M>(call.posblk);
    let index = session.find(at).map_err(|why| Gap { what: why })?;
    match session.open[index].get_position() {
        Ok(position) => {
            call.databuf.clear();
            call.databuf.extend_from_slice(&position.to_le_bytes());
            *call.datalen = 4;
            Ok(Status::OK)
        }
        Err(e) => status_of(&e),
    }
}

/// Op 23, `dfaAcqAbsLock`: position at an absolute physical position and
/// deliver that record, establishing `keynum`'s key path.
///
/// `re/wg33src/SRC/api/gcommlib/DFAAPI.C:483`'s own calling convention is the
/// mirror of [`absolute_position`]'s: `dfaAcqAbsLock` writes `*(LONG
/// *)recptr = abspos` into the record buffer **before** calling `BTRCALL`,
/// then hands that same buffer as `dataBuffer` -- the position goes in where
/// the record comes back out. [`crate::ops::Block::acquire_absolute`]
/// already computes this; wiring it in is the same shape [`stat`] and
/// [`absolute_position`] are.
///
/// Lock bias is hardcoded to `0`, matching [`get`]'s own precedent: neither
/// this crate's op table nor `describe` decodes a `loktyp` offset out of the
/// operation code today, so a locked Acquire Absolute (op 123/223/323/423)
/// falls to [`Outcome::Unmodelled`] rather than silently taking the wrong
/// lock -- the same gap `get`'s own hardcoded `0` already leaves open for
/// every keyed read.
fn acquire_absolute<M: Mem>(session: &mut crate::Btrieve<M>, call: Call<'_>) -> Result<Status, Gap> {
    let at = handle_of::<M>(call.posblk);
    let index = session.find(at).map_err(|why| Gap { what: why })?;
    if call.databuf.len() < 4 {
        return Err(Gap {
            what: format!(
                "Acquire Absolute: {} data bytes offered, need at least 4 to carry the position",
                call.databuf.len()
            ),
        });
    }
    let position = u32::from_le_bytes(call.databuf[..4].try_into().expect("checked above"));
    let key = u16::try_from(call.keynum.max(0)).unwrap_or(0);

    match session.open[index].acquire_absolute(position, key, 0, &mut session.locks, offered(&call)) {
        Ok(Some(d)) => {
            *call.datalen = u32::try_from(d.bytes.len()).unwrap_or(u32::MAX);
            call.databuf.clear();
            call.databuf.extend_from_slice(&d.bytes);
            if let Some(k) = d.key {
                call.keybuf.clear();
                call.keybuf.extend_from_slice(&k);
            }
            // Truncated, not failed -- the same convention `get` and `stat`
            // use for a record too big for the caller's own buffer.
            Ok(if d.truncated { Status(22) } else { Status::OK })
        }
        // The position names no record: `Block::acquire_absolute`'s own doc
        // comment calls this "not an error", matching `Block::query`'s
        // not-found contract -- the same shape `get` already answers with
        // status 9 for a search that comes up empty.
        //
        // Task 12 left this at 9 deliberately rather than folding it into
        // `get`'s new `Get Equal` -> 4 split: an absolute position is not a
        // keyed value search, and no fixture exercises Acquire Absolute at
        // all, so there is no measurement to answer 4 from here either.
        Ok(None) => Ok(Status(9)),
        Err(e) => status_of(&e),
    }
}

/// Ops 24, 33-35: physical order, no key. Same shape as [`get`], but
/// [`crate::ops::Block::step`] takes no search value and its
/// [`crate::ops::Delivery::key`] is always `None` -- a step has no key at
/// all.
fn step_op<M: Mem>(
    session: &mut crate::Btrieve<M>,
    step: Step,
    call: Call<'_>,
) -> Result<Status, Gap> {
    let at = handle_of::<M>(call.posblk);
    let index = session.find(at).map_err(|why| Gap { what: why })?;

    match session.open[index].step(step, 0, &mut session.locks, offered(&call)) {
        Ok(Some(d)) => {
            *call.datalen = u32::try_from(d.bytes.len()).unwrap_or(u32::MAX);
            call.databuf.clear();
            call.databuf.extend_from_slice(&d.bytes);
            Ok(if d.truncated { Status(22) } else { Status::OK })
        }
        Ok(None) => Ok(Status(9)),
        Err(e) => status_of(&e),
    }
}

/// Op 2: append `call.databuf` as a new record.
///
/// Real Btrieve establishes currency on the record an insert just created;
/// this engine's [`crate::ops::Block::insert`] does not move
/// [`crate::Cursor`] at all, so a `Get Next`/`Get Previous` issued right
/// after an insert sees wherever the file was positioned before it, not the
/// new record. No test in this task exercises that difference; it is a
/// known gap, not a decision.
fn insert<M: Mem>(session: &mut crate::Btrieve<M>, call: Call<'_>) -> Result<Status, Gap> {
    let at = handle_of::<M>(call.posblk);
    let index = session.find(at).map_err(|why| Gap { what: why })?;
    let len = usize::try_from(*call.datalen).unwrap_or(0).min(call.databuf.len());

    match session.open[index].insert(&call.databuf[..len]) {
        Ok(_) => Ok(Status::OK),
        Err(why) => Err(Gap {
            what: format!("inserting: {why}"),
        }),
    }
}

/// Op 3: rewrite the record the file is currently positioned on.
///
/// Btrieve's Update always targets *the current record*, never a position
/// the caller names -- the same convention `mbbs`'s `dupdbtv` shim reads out
/// of [`crate::ops::Block::current`]. No record positioned is real Btrieve
/// status 8, the same status [`OpError::NotPositioned`] and
/// [`OpError::NoKeyEstablished`] already answer with in [`status_of`].
///
/// Before writing, this checks
/// [`crate::Block::would_change_unmodifiable_key`] the same way genuine
/// Btrieve does -- refuse before touching the file -- and answers status 10
/// rather than falling through to [`crate::Block::update`]'s stringly-typed
/// [`crate::BtvError`], which this dispatcher has no way to distinguish from
/// any other update refusal.
fn update<M: Mem>(session: &mut crate::Btrieve<M>, call: Call<'_>) -> Result<Status, Gap> {
    let at = handle_of::<M>(call.posblk);
    let index = session.find(at).map_err(|why| Gap { what: why })?;
    let Some(position) = session.open[index].current().map(|r| r.position) else {
        return Ok(Status(8));
    };
    let len = usize::try_from(*call.datalen).unwrap_or(0).min(call.databuf.len());
    let bytes = &call.databuf[..len];

    match session.open[index].would_change_unmodifiable_key(position, bytes) {
        Ok(Some(_key)) => return Ok(Status(10)),
        Ok(None) => {}
        Err(why) => {
            return Err(Gap {
                what: format!("checking key modifiability before update: {why}"),
            })
        }
    }

    match session.open[index].update(position, bytes) {
        Ok(()) => Ok(Status::OK),
        Err(why) => Err(Gap {
            what: format!("updating: {why}"),
        }),
    }
}

/// Op 4: delete the record the file is currently positioned on.
///
/// Same currency rule as [`update`]: no record positioned is status 8. After
/// a successful delete, `mbbs`'s `delbtv` shim seeks the block to
/// [`crate::Cursor::Nowhere`] -- documented there as a decision rather than
/// a measurement, because what real Btrieve leaves current after a delete
/// was never put to the Wine oracle. This dispatch follows the same
/// decision so a deleted record does not stay reachable as "current".
fn delete<M: Mem>(session: &mut crate::Btrieve<M>, call: Call<'_>) -> Result<Status, Gap> {
    let at = handle_of::<M>(call.posblk);
    let index = session.find(at).map_err(|why| Gap { what: why })?;
    let Some(position) = session.open[index].current().map(|r| r.position) else {
        return Ok(Status(8));
    };

    match session.open[index].delete(position) {
        Ok(()) => {
            session.open[index].seek_to(crate::Cursor::Nowhere);
            Ok(Status::OK)
        }
        Err(why) => Err(Gap {
            what: format!("deleting: {why}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::{LockMode, Op, OpError, Step};

    /// The statuses each variant's own doc comment records, measured against
    /// the Programmer's Reference and `BtrieveStatusCodes.pdf`.
    #[test]
    fn a_modelled_refusal_maps_to_its_measured_status() {
        assert_eq!(status_of(&OpError::DuplicateKey { key: 0 }), Ok(Status(5)));
        assert_eq!(status_of(&OpError::EndOfFile), Ok(Status(9)));
        assert_eq!(status_of(&OpError::NoSuchKey(7)), Ok(Status(6)));
        assert_eq!(status_of(&OpError::NotPositioned), Ok(Status(8)));
        assert_eq!(status_of(&OpError::NoKeyEstablished), Ok(Status(8)));
        assert_eq!(
            status_of(&OpError::DifferentKey { current: 0, wanted: 1 }),
            Ok(Status(7))
        );
        assert_eq!(status_of(&OpError::NotAllowedDuringTransaction), Ok(Status(41)));
        assert_eq!(status_of(&OpError::OwnerAlreadySet), Ok(Status(50)));
        assert_eq!(status_of(&OpError::OwnerNameInvalid { len: 9 }), Ok(Status(51)));
        assert_eq!(status_of(&OpError::InvalidDirectory), Ok(Status(35)));
        assert_eq!(status_of(&OpError::ObsoleteOperation), Ok(Status(1)));
        assert_eq!(status_of(&OpError::PreV6Chunk), Ok(Status(107)));
        assert_eq!(status_of(&OpError::ChunkOffsetTooBig), Ok(Status(103)));
        assert_eq!(status_of(&OpError::InvalidRecordAddress), Ok(Status(43)));
        assert_eq!(
            status_of(&OpError::AlreadyInContinuousOperation { file: "A.DAT".into() }),
            Ok(Status(88))
        );
        assert_eq!(
            status_of(&OpError::LockModeMixed {
                held: LockMode::Single,
                wanted: LockMode::Multiple,
            }),
            Ok(Status(93))
        );
    }

    /// A hole in this engine is not a Btrieve answer. Folding the two lets a
    /// differential harness report a gap as a passing disagreement.
    #[test]
    fn a_structural_hole_is_a_gap_not_a_status() {
        for e in [
            OpError::NccUnsupported,
            OpError::ConcurrentTransactionUnsupported,
            OpError::IndexMutationUnsupported,
        ] {
            let gap = status_of(&e).expect_err("no Btrieve status names this");
            assert!(!gap.what.is_empty(), "a gap has to say what it was: {e:?}");
        }
    }

    /// Two variants whose real status was never measured. Answering them with
    /// a plausible number would be inventing evidence; both are documented as
    /// unreachable-today rather than as known behaviour.
    #[test]
    fn an_unmeasured_refusal_is_a_gap_too() {
        assert!(status_of(&OpError::CursorStale).is_err());
        assert!(status_of(&OpError::Records(crate::BtvError {
            file: "SAMPLE.DAT".to_owned(),
            why: "unreadable".to_owned()
        }))
        .is_err());
    }

    /// The Get family is the engine's own table, not a second copy of it.
    /// `11` being `AtMost` rather than `Lowest` is the trap this guards.
    #[test]
    fn the_get_family_delegates_to_the_engines_own_table() {
        assert_eq!(describe(5), Outcome::Get(Op::Equal));
        assert_eq!(describe(6), Outcome::Get(Op::Next));
        assert_eq!(describe(11), Outcome::Get(Op::AtMost));
        assert_eq!(describe(12), Outcome::Get(Op::Lowest));
        assert_eq!(describe(13), Outcome::Get(Op::Highest));
    }

    /// The Query family is the same nine comparisons, fifty apart.
    #[test]
    fn the_query_family_is_the_get_family_plus_fifty() {
        assert_eq!(describe(55), Outcome::Query(Op::Equal));
        assert_eq!(describe(62), Outcome::Query(Op::Lowest));
    }

    /// Step is physical order and has its own four codes, which are not
    /// contiguous: 24 is Next, 33/34/35 are First/Last/Previous.
    #[test]
    fn the_step_family_keeps_its_own_discontiguous_codes() {
        assert_eq!(describe(24), Outcome::Step(Step::Next));
        assert_eq!(describe(33), Outcome::Step(Step::First));
        assert_eq!(describe(34), Outcome::Step(Step::Last));
        assert_eq!(describe(35), Outcome::Step(Step::Previous));
    }

    /// The file-level operations.
    #[test]
    fn the_file_operations_are_named() {
        assert_eq!(describe(0), Outcome::Open);
        assert_eq!(describe(1), Outcome::Close);
        assert_eq!(describe(2), Outcome::Insert);
        assert_eq!(describe(3), Outcome::Update);
        assert_eq!(describe(4), Outcome::Delete);
        assert_eq!(describe(15), Outcome::Stat);
        assert_eq!(describe(25), Outcome::Stop);
    }

    /// An operation code this engine does not model is named rather than
    /// guessed at, and carries the number so a caller can report it.
    #[test]
    fn an_unmodelled_operation_names_its_own_number() {
        assert_eq!(describe(60_000), Outcome::Unmodelled(60_000));
        assert_eq!(describe(31), Outcome::Unmodelled(31), "Create Index");
    }

    use crate::testing::{Flat, FlatHeap, FlatMem};
    use crate::{create, Btrieve, FileSpec, Geometry, KeySpec, SegmentSpec};
    use std::path::Path;

    /// The whole round trip through numbers: open a real file, read its
    /// lowest record by key 0, and close it -- without naming a single typed
    /// operation at the call site.
    #[test]
    fn a_file_opens_reads_and_closes_through_numbers_alone() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut session: Btrieve<Flat> = Btrieve::default();

        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../mbbs/tests/data/SAMPLE.DAT");

        let mut posblk = [0u8; 128];
        let mut databuf = Vec::new();
        let mut datalen = 64u32;
        let mut keybuf = path.to_string_lossy().as_bytes().to_vec();
        keybuf.push(0);

        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 0,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut datalen,
                keybuf: &mut keybuf,
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Open is modelled");
        assert_eq!(status, Status::OK, "the file opened");
        assert_ne!(posblk[..4], [0, 0, 0, 0], "Open recorded a handle");

        // Op 12 is Get First -- the lowest key, not "the twelfth get".
        let mut databuf = vec![0u8; 64];
        let mut datalen = 64u32;
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 12,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut datalen,
                keybuf: &mut Vec::new(),
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Get First is modelled");
        assert_eq!(status, Status::OK, "a record came back");
        assert!(datalen > 0, "and its length was reported back");

        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 1,
                posblk: &mut posblk,
                databuf: &mut Vec::new(),
                datalen: &mut 0,
                keybuf: &mut Vec::new(),
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Close is modelled");
        assert_eq!(status, Status::OK, "the file closed");
    }

    /// An unmodelled operation is a gap, not a fabricated status.
    #[test]
    fn an_unmodelled_operation_is_a_gap() {
        let mut mem = FlatMem::new(1024);
        let mut heap = FlatHeap::new(0x100);
        let mut session: Btrieve<Flat> = Btrieve::default();
        let gap = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 31, // Create Index
                posblk: &mut [0u8; 128],
                databuf: &mut Vec::new(),
                datalen: &mut 0,
                keybuf: &mut Vec::new(),
                keylen: 255,
                keynum: 0,
            },
        )
        .expect_err("Create Index is not modelled");
        assert!(gap.what.contains("31") || gap.what.contains("ndex"));
    }

    /// A read past the end of the file is status 9, not a fabricated
    /// success. Task 3 Step 7's second mutation -- `get`'s `Ok(None) =>
    /// Ok(Status(9))` collapsed to `Ok(Status::OK)` -- made every other test
    /// in this module pass anyway; this is the test that closes that gap.
    #[test]
    fn a_get_past_the_end_of_the_file_answers_status_nine() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut session: Btrieve<Flat> = Btrieve::default();

        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../mbbs/tests/data/SAMPLE.DAT");
        let mut posblk = [0u8; 128];
        let mut keybuf = path.to_string_lossy().as_bytes().to_vec();
        keybuf.push(0);

        btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 0,
                posblk: &mut posblk,
                databuf: &mut Vec::new(),
                datalen: &mut 64,
                keybuf: &mut keybuf,
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Open is modelled");

        // Op 13 is Get Last -- the highest key -- so the very next Get Next
        // has nowhere left to go.
        let mut databuf = vec![0u8; 64];
        let mut datalen = 64u32;
        btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 13,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut datalen,
                keybuf: &mut Vec::new(),
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Get Last is modelled");

        let mut databuf = vec![0u8; 64];
        let mut datalen = 64u32;
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 6, // Get Next
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut datalen,
                keybuf: &mut Vec::new(),
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Get Next is modelled");
        assert_eq!(status, Status(9), "no record past the last one");
    }

    /// A fresh, empty, single-key file this task's tests can insert into,
    /// update and delete freely -- unlike `SAMPLE.DAT`, which is a shared
    /// fixture other tests read and must not be mutated.
    ///
    /// One key: an unsigned-binary 4-byte value at offset 0. Record length
    /// 8 -- the 4-byte key plus a 4-byte payload -- is enough to prove a
    /// value round-trips without needing a real MajorMUD record shape.
    fn scratch_file(name: &str) -> std::path::PathBuf {
        let path = crate::testing::scratch(name).join("SCRATCH.DAT");
        let spec = FileSpec {
            record_length: 8,
            page_size: 512,
            keys: vec![KeySpec {
                segments: vec![SegmentSpec {
                    offset: 0,
                    length: 4,
                    kind: 0x0e, // DFAST_UNSIGNED_BINARY
                    descending: false,
                }],
                duplicates: false,
                modifiable: false,
            }],
        };
        create(&path, &spec).expect("creates a scratch Btrieve file");
        path
    }

    /// Open `path` through `btrcall` op 0 and hand back the position block
    /// it recorded -- every test below starts here, through the numeric
    /// interface, exactly like a real guest would.
    fn open_scratch(
        session: &mut Btrieve<Flat>,
        mem: &mut FlatMem,
        heap: &mut FlatHeap,
        path: &std::path::Path,
    ) -> [u8; 128] {
        let mut posblk = [0u8; 128];
        let mut keybuf = path.to_string_lossy().as_bytes().to_vec();
        keybuf.push(0);
        let status = btrcall(
            session,
            mem,
            heap,
            Call {
                op: 0,
                posblk: &mut posblk,
                databuf: &mut Vec::new(),
                datalen: &mut 64,
                keybuf: &mut keybuf,
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Open is modelled");
        assert_eq!(status, Status::OK, "the scratch file opened");
        posblk
    }

    /// Insert, Get, Update, Get, Delete, Get -- every write-path dispatch
    /// arm (`insert`, `update`, `delete`) proven through the numeric
    /// interface, never by calling the typed engine directly.
    #[test]
    fn insert_update_and_delete_round_trip_through_numbers_alone() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut session: Btrieve<Flat> = Btrieve::default();
        let path = scratch_file("insert-update-delete-round-trip");
        let mut posblk = open_scratch(&mut session, &mut mem, &mut heap, &path);

        // Insert (op 2): key 42, payload [1, 2, 3, 4].
        let mut databuf = vec![42, 0, 0, 0, 1, 2, 3, 4];
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 2,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut 8,
                keybuf: &mut Vec::new(),
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Insert is modelled");
        assert_eq!(status, Status::OK, "the record was inserted");

        // Get Equal (op 5) by key 42: the inserted record comes back, and
        // this also establishes currency for the Update below.
        let mut databuf = vec![0u8; 8];
        let mut datalen = 8u32;
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 5,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut datalen,
                keybuf: &mut vec![42, 0, 0, 0],
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Get Equal is modelled");
        assert_eq!(status, Status::OK, "the inserted record was found");
        assert_eq!(databuf, vec![42, 0, 0, 0, 1, 2, 3, 4], "the bytes round-tripped");

        // Update (op 3): same key, new payload [9, 9, 9, 9].
        let mut databuf = vec![42, 0, 0, 0, 9, 9, 9, 9];
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 3,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut 8,
                keybuf: &mut Vec::new(),
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Update is modelled");
        assert_eq!(status, Status::OK, "the record was updated");

        // Get Equal again: the update landed, and this re-establishes
        // currency for the Delete below.
        let mut databuf = vec![0u8; 8];
        let mut datalen = 8u32;
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 5,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut datalen,
                keybuf: &mut vec![42, 0, 0, 0],
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Get Equal is modelled");
        assert_eq!(status, Status::OK, "the updated record was found");
        assert_eq!(databuf, vec![42, 0, 0, 0, 9, 9, 9, 9], "the update landed");

        // Delete (op 4): the record Get just positioned on.
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 4,
                posblk: &mut posblk,
                databuf: &mut Vec::new(),
                datalen: &mut 0,
                keybuf: &mut Vec::new(),
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Delete is modelled");
        assert_eq!(status, Status::OK, "the record was deleted");

        // Get Equal once more: nothing answers key 42 any longer -- status
        // 4, "key value not found", not 9 ("end of file"; that status names
        // sequential exhaustion, not a keyed Get Equal miss -- Task 12's
        // fix to `get`, measured against `update_and_delete.fixture`).
        let mut databuf = vec![0u8; 8];
        let mut datalen = 8u32;
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 5,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut datalen,
                keybuf: &mut vec![42, 0, 0, 0],
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Get Equal is modelled");
        assert_eq!(status, Status(4), "the deleted record is gone");
    }

    /// Task 7b: real Btrieve refuses an update that would change a key that
    /// does not declare itself modifiable, with status 10 -- and this has to
    /// be an `Ok`, not the `Gap` a caller can't tell apart from any other
    /// hole in the engine. `scratch_file`'s one key is already declared
    /// `modifiable: false`, so an update that moves it is exactly the
    /// condition `wccmmutl.exe -recover`'s op 3 against `WCCMP002.DAT` hit.
    #[test]
    fn an_update_that_moves_a_non_modifiable_key_answers_status_ten() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut session: Btrieve<Flat> = Btrieve::default();
        let path = scratch_file("update-moves-unmodifiable-key");
        let mut posblk = open_scratch(&mut session, &mut mem, &mut heap, &path);

        // Insert (op 2): key 42, payload [1, 2, 3, 4].
        let mut databuf = vec![42, 0, 0, 0, 1, 2, 3, 4];
        btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 2,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut 8,
                keybuf: &mut Vec::new(),
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Insert is modelled");

        // Get Equal (op 5) by key 42 establishes currency for the Update.
        let mut databuf = vec![0u8; 8];
        let mut datalen = 8u32;
        btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 5,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut datalen,
                keybuf: &mut vec![42, 0, 0, 0],
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Get Equal is modelled");

        // Update (op 3): key 42 -> 99. The engine detects this exactly
        // (`Block::would_change_unmodifiable_key`); the dispatcher must
        // answer a real status, not a Gap.
        let mut databuf = vec![99, 0, 0, 0, 1, 2, 3, 4];
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 3,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut 8,
                keybuf: &mut Vec::new(),
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("a key-field update is a modelled refusal, not a Gap");
        assert_eq!(status, Status(10), "the key field is not modifiable");

        // And the record was not touched: key 42 still answers, key 99
        // still does not.
        let mut databuf = vec![0u8; 8];
        let mut datalen = 8u32;
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 5,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut datalen,
                keybuf: &mut vec![42, 0, 0, 0],
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Get Equal is modelled");
        assert_eq!(status, Status::OK, "a refused update writes nothing");
        assert_eq!(databuf, vec![42, 0, 0, 0, 1, 2, 3, 4], "the record is unchanged");
    }

    /// The boundary a naive "did the record change" check gets wrong:
    /// rewriting a non-modifiable key with the same value it already holds,
    /// while changing the rest of the record, is allowed --
    /// `Block::unmodifiable_key_changed`'s doc comment at `lib.rs:1235`
    /// records this as measured against genuine Btrieve 6.15. If the op-3
    /// dispatch arm checked "does this update touch the key bytes at all"
    /// instead of "does it change the key's *value*", this would wrongly
    /// answer status 10.
    #[test]
    fn an_update_that_rewrites_the_key_with_its_own_value_still_succeeds() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut session: Btrieve<Flat> = Btrieve::default();
        let path = scratch_file("update-key-unchanged-still-succeeds");
        let mut posblk = open_scratch(&mut session, &mut mem, &mut heap, &path);

        // Insert (op 2): key 42, payload [1, 2, 3, 4].
        let mut databuf = vec![42, 0, 0, 0, 1, 2, 3, 4];
        btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 2,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut 8,
                keybuf: &mut Vec::new(),
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Insert is modelled");

        // Get Equal (op 5) by key 42 establishes currency for the Update.
        let mut databuf = vec![0u8; 8];
        let mut datalen = 8u32;
        btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 5,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut datalen,
                keybuf: &mut vec![42, 0, 0, 0],
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Get Equal is modelled");

        // Update (op 3): key stays 42, payload changes to [9, 9, 9, 9].
        let mut databuf = vec![42, 0, 0, 0, 9, 9, 9, 9];
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 3,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut 8,
                keybuf: &mut Vec::new(),
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Update is modelled");
        assert_eq!(status, Status::OK, "touching the key without changing its value is allowed");

        // Get Equal again: the payload update landed.
        let mut databuf = vec![0u8; 8];
        let mut datalen = 8u32;
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 5,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut datalen,
                keybuf: &mut vec![42, 0, 0, 0],
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Get Equal is modelled");
        assert_eq!(status, Status::OK);
        assert_eq!(databuf, vec![42, 0, 0, 0, 9, 9, 9, 9], "the payload update landed");
    }

    /// Step First, Step Next, Step Next past the end -- `step_op` proven
    /// through the numeric interface, walking physical (insertion) order.
    #[test]
    fn step_first_and_next_walk_physical_order_then_answer_status_nine() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut session: Btrieve<Flat> = Btrieve::default();
        let path = scratch_file("step-first-and-next");
        let mut posblk = open_scratch(&mut session, &mut mem, &mut heap, &path);

        for record in [vec![100, 0, 0, 0, 1, 1, 1, 1], vec![200, 0, 0, 0, 2, 2, 2, 2]] {
            let mut databuf = record;
            let status = btrcall(
                &mut session,
                &mut mem,
                &mut heap,
                Call {
                    op: 2,
                    posblk: &mut posblk,
                    databuf: &mut databuf,
                    datalen: &mut 8,
                    keybuf: &mut Vec::new(),
                    keylen: 255,
                    keynum: 0,
                },
            )
            .expect("Insert is modelled");
            assert_eq!(status, Status::OK);
        }

        // Step First (op 33): the record inserted first, in physical order.
        let mut databuf = vec![0u8; 8];
        let mut datalen = 8u32;
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 33,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut datalen,
                keybuf: &mut Vec::new(),
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Step First is modelled");
        assert_eq!(status, Status::OK);
        assert_eq!(databuf, vec![100, 0, 0, 0, 1, 1, 1, 1], "the first-inserted record");

        // Step Next (op 24): the second record.
        let mut databuf = vec![0u8; 8];
        let mut datalen = 8u32;
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 24,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut datalen,
                keybuf: &mut Vec::new(),
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Step Next is modelled");
        assert_eq!(status, Status::OK);
        assert_eq!(databuf, vec![200, 0, 0, 0, 2, 2, 2, 2], "the second-inserted record");

        // Step Next again: nowhere left to go.
        let mut databuf = vec![0u8; 8];
        let mut datalen = 8u32;
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 24,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut datalen,
                keybuf: &mut Vec::new(),
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Step Next is modelled");
        assert_eq!(status, Status(9), "no third record to step to");
    }

    /// Close, then the same position block answers a Gap rather than
    /// silently succeeding -- `close` proven through the numeric interface:
    /// the block really left `session.open`, not just returned a status.
    #[test]
    fn close_removes_the_file_so_a_later_operation_on_the_same_posblk_is_a_gap() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut session: Btrieve<Flat> = Btrieve::default();
        let path = scratch_file("close-then-gap");
        let mut posblk = open_scratch(&mut session, &mut mem, &mut heap, &path);

        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 1,
                posblk: &mut posblk,
                databuf: &mut Vec::new(),
                datalen: &mut 0,
                keybuf: &mut Vec::new(),
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Close is modelled");
        assert_eq!(status, Status::OK, "the file closed");

        let gap = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 5, // Get Equal
                posblk: &mut posblk,
                databuf: &mut vec![0u8; 8],
                datalen: &mut 8,
                keybuf: &mut vec![42, 0, 0, 0],
                keylen: 255,
                keynum: 0,
            },
        )
        .expect_err("a closed file's handle names nothing this session has open");
        assert!(
            gap.what.contains("open Btrieve file") || gap.what.contains("not"),
            "{}",
            gap.what
        );
    }

    /// Stat (op 15), proven through the numeric interface rather than only
    /// through `crate::stat`'s own unit tests -- those cover `Stat::read`/
    /// `wire`/`deliver` directly, but never `btrcall`'s dispatch arm, which
    /// is the part this task added. A freshly opened scratch file has one
    /// key, is not variable-length, and starts with zero records.
    #[test]
    fn stat_reports_the_open_files_shape_through_numbers_alone() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut session: Btrieve<Flat> = Btrieve::default();
        let path = scratch_file("stat-through-numbers");
        let mut posblk = open_scratch(&mut session, &mut mem, &mut heap, &path);

        // A buffer larger than any real reply gets the whole thing back
        // untruncated: the file spec (16 bytes) plus one key spec (16 bytes)
        // for the scratch file's single key.
        let mut databuf = vec![0u8; 1024];
        let mut datalen = 1024u32;
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 15,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut datalen,
                keybuf: &mut Vec::new(),
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Stat is modelled");
        assert_eq!(status, Status::OK, "the whole reply fit");
        assert_eq!(datalen, 32, "one file spec plus one key spec, 16 bytes each");
        let reclen = u16::from_le_bytes([databuf[0], databuf[1]]);
        assert_eq!(reclen, 8, "the scratch file's own record length");

        // Now offer only the file spec's own 16 bytes: a whole unit, but
        // short of the full 32-byte reply -- status 22, the same truncated-
        // but-not-failed convention `get` uses, and the key spec must not
        // appear at all.
        let mut databuf = vec![0u8; 16];
        let mut datalen = 16u32;
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 15,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut datalen,
                keybuf: &mut Vec::new(),
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Stat is modelled");
        assert_eq!(status, Status(22), "short of the full reply by one key spec");
        assert_eq!(datalen, 16, "the file spec alone, no partial key spec");
    }

    /// Absolute Position (op 22), `dfaAbs`: not positioned yet is status 8,
    /// then a Get Equal establishes currency and the position comes back as
    /// a four-byte value in the data buffer -- `re/wg33src/SRC/api/gcommlib/
    /// DFAAPI.C:453`'s own calling convention, not the position block.
    #[test]
    fn absolute_position_answers_not_positioned_then_a_real_position() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut session: Btrieve<Flat> = Btrieve::default();
        let path = scratch_file("absolute-position-through-numbers");
        let mut posblk = open_scratch(&mut session, &mut mem, &mut heap, &path);

        let abs = |session: &mut Btrieve<Flat>, mem: &mut FlatMem, heap: &mut FlatHeap, posblk: &mut [u8; 128]| {
            let mut databuf = vec![0xffu8; 4];
            let mut datalen = 4u32;
            let status = btrcall(
                session,
                mem,
                heap,
                Call {
                    op: 22,
                    posblk,
                    databuf: &mut databuf,
                    datalen: &mut datalen,
                    keybuf: &mut Vec::new(),
                    keylen: 255,
                    keynum: 0,
                },
            )
            .expect("Absolute Position is modelled");
            (status, databuf, datalen)
        };

        let (status, _, _) = abs(&mut session, &mut mem, &mut heap, &mut posblk);
        assert_eq!(status, Status(8), "nothing has positioned this file yet");

        let mut databuf = vec![7, 0, 0, 0, 1, 2, 3, 4];
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 2,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut 8,
                keybuf: &mut Vec::new(),
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Insert is modelled");
        assert_eq!(status, Status::OK);

        let mut databuf = vec![0u8; 8];
        let mut datalen = 8u32;
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 5, // Get Equal
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut datalen,
                keybuf: &mut vec![7, 0, 0, 0],
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Get Equal is modelled");
        assert_eq!(status, Status::OK, "positioned on the record just inserted");

        let (status, databuf, datalen) = abs(&mut session, &mut mem, &mut heap, &mut posblk);
        assert_eq!(status, Status::OK);
        assert_eq!(datalen, 4, "a LONG, per DFAAPI.C's own sizeof(LONG)");
        let position = u32::from_le_bytes(databuf.try_into().expect("4 bytes"));
        assert_ne!(position, 0, "a real physical position, not the fill byte pattern read back");
    }

    /// Acquire Absolute (op 23), `dfaAcqAbsLock`: insert two records, read
    /// the first one's own position back with op 22, then use op 23 to jump
    /// straight to it by that position and get the very record back -- the
    /// full round trip real `DFAAPI.C` code performs to revisit a record it
    /// once positioned on. A position naming nothing answers status 9, the
    /// same "not found" convention `get` already uses.
    #[test]
    fn acquire_absolute_jumps_straight_to_a_position_and_delivers_the_record() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut session: Btrieve<Flat> = Btrieve::default();
        let path = scratch_file("acquire-absolute-through-numbers");
        let mut posblk = open_scratch(&mut session, &mut mem, &mut heap, &path);

        for record in [vec![11, 0, 0, 0, 1, 1, 1, 1], vec![22, 0, 0, 0, 2, 2, 2, 2]] {
            let mut databuf = record;
            let status = btrcall(
                &mut session,
                &mut mem,
                &mut heap,
                Call {
                    op: 2,
                    posblk: &mut posblk,
                    databuf: &mut databuf,
                    datalen: &mut 8,
                    keybuf: &mut Vec::new(),
                    keylen: 255,
                    keynum: 0,
                },
            )
            .expect("Insert is modelled");
            assert_eq!(status, Status::OK);
        }

        // Get Equal on the first record establishes currency, then op 22
        // reads back its own physical position.
        let mut databuf = vec![0u8; 8];
        let mut datalen = 8u32;
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 5, // Get Equal
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut datalen,
                keybuf: &mut vec![11, 0, 0, 0],
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Get Equal is modelled");
        assert_eq!(status, Status::OK);

        let mut posbuf = vec![0u8; 4];
        let mut poslen = 4u32;
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 22,
                posblk: &mut posblk,
                databuf: &mut posbuf,
                datalen: &mut poslen,
                keybuf: &mut Vec::new(),
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Absolute Position is modelled");
        assert_eq!(status, Status::OK);

        // Get Next moves currency onto the second record, so this Acquire
        // Absolute really does jump rather than merely re-reading whatever
        // was already current.
        let mut databuf = vec![0u8; 8];
        let mut datalen = 8u32;
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 6, // Get Next
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut datalen,
                keybuf: &mut Vec::new(),
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Get Next is modelled");
        assert_eq!(status, Status::OK);
        assert_eq!(databuf, vec![22, 0, 0, 0, 2, 2, 2, 2], "currency moved to the second record");

        // Acquire Absolute (op 23): the position goes in as the first four
        // bytes of the data buffer, and the found record replaces them.
        let mut databuf = vec![0u8; 8];
        posbuf.resize(8, 0);
        databuf[..4].copy_from_slice(&posbuf[..4]);
        let mut datalen = 8u32;
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 23,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut datalen,
                keybuf: &mut Vec::new(),
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Acquire Absolute is modelled");
        assert_eq!(status, Status::OK);
        assert_eq!(databuf, vec![11, 0, 0, 0, 1, 1, 1, 1], "jumped back to the first record");

        // A position naming nothing at all: not found, status 9.
        let mut databuf = vec![0xffu8; 8];
        databuf[..4].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
        let mut datalen = 8u32;
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 23,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut datalen,
                keybuf: &mut Vec::new(),
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Acquire Absolute is modelled");
        assert_eq!(status, Status(9), "no record at that position");
    }

    /// Open with a small buffer, Get with a large one -- the shape no guest
    /// measured so far exercises, and the one the truncation ceiling used to
    /// get wrong in both directions.
    ///
    /// Genuine Btrieve's own wire Open carries `datalen: 0` (every recorded
    /// fixture), so an Open that declared a buffer at all was already more
    /// than the real engine asks for; tying every later Get to it meant a
    /// faithful replay of a genuine `0` starved every read that followed.
    /// The ceiling is the caller's buffer for *this* call, so an Open of 1
    /// byte constrains nothing.
    #[test]
    fn a_get_is_bounded_by_its_own_buffer_not_the_one_open_declared() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut session: Btrieve<Flat> = Btrieve::default();
        let path = scratch_file("get-bounded-by-its-own-buffer");

        let mut posblk = [0u8; 128];
        let mut keybuf = path.to_string_lossy().as_bytes().to_vec();
        keybuf.push(0);
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 0,
                posblk: &mut posblk,
                databuf: &mut Vec::new(),
                // One byte, and an empty buffer -- less than a single 8-byte
                // record, and less than the Get below offers.
                datalen: &mut 1,
                keybuf: &mut keybuf,
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Open is modelled");
        assert_eq!(status, Status::OK, "the scratch file opened");

        let mut databuf = vec![7, 0, 0, 0, 1, 2, 3, 4];
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 2,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut 8,
                keybuf: &mut Vec::new(),
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Insert is modelled");
        assert_eq!(status, Status::OK, "the record was inserted");

        let mut databuf = vec![0u8; 8];
        let mut datalen = 8u32;
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 5,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut datalen,
                keybuf: &mut vec![7, 0, 0, 0],
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Get Equal is modelled");
        assert_eq!(
            status,
            Status::OK,
            "a buffer big enough for the record is not truncated by what Open said"
        );
        assert_eq!(datalen, 8, "the whole record came back");
        assert_eq!(databuf, vec![7, 0, 0, 0, 1, 2, 3, 4]);
    }

    /// The other direction, and the one that reaches past a guest's own
    /// memory: Open with a generous buffer, Get with a small one. The
    /// delivery must be cut to the small one and answer status 22 -- both
    /// guest edges write the delivered bytes straight back to the guest's
    /// `databuf` pointer without re-checking the length, so over-delivering
    /// here is an overrun there.
    #[test]
    fn a_get_with_a_smaller_buffer_than_open_declared_is_truncated() {
        let mut mem = FlatMem::new(64 * 1024);
        let mut heap = FlatHeap::new(0x100);
        let mut session: Btrieve<Flat> = Btrieve::default();
        let path = scratch_file("get-smaller-buffer-than-open");
        // `open_scratch` declares 64 bytes, eight times the record length.
        let mut posblk = open_scratch(&mut session, &mut mem, &mut heap, &path);

        let mut databuf = vec![9, 0, 0, 0, 5, 6, 7, 8];
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 2,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut 8,
                keybuf: &mut Vec::new(),
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Insert is modelled");
        assert_eq!(status, Status::OK, "the record was inserted");

        let mut databuf = vec![0u8; 4];
        let mut datalen = 4u32;
        let status = btrcall(
            &mut session,
            &mut mem,
            &mut heap,
            Call {
                op: 5,
                posblk: &mut posblk,
                databuf: &mut databuf,
                datalen: &mut datalen,
                keybuf: &mut vec![9, 0, 0, 0],
                keylen: 255,
                keynum: 0,
            },
        )
        .expect("Get Equal is modelled");
        assert_eq!(status, Status(22), "a record longer than this call's buffer");
        assert_eq!(datalen, 4, "and only what the buffer holds came back");
        assert_eq!(databuf, vec![9, 0, 0, 0]);
    }
}
