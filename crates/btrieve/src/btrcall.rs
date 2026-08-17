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
        Outcome::Query(_) | Outcome::Stat | Outcome::Stop => Err(Gap {
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

    match session.open[index].get(key, op, value, 0, &mut session.locks) {
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
        // No record matched: status 9, end of file.
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

    match session.open[index].step(step, 0, &mut session.locks) {
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
fn update<M: Mem>(session: &mut crate::Btrieve<M>, call: Call<'_>) -> Result<Status, Gap> {
    let at = handle_of::<M>(call.posblk);
    let index = session.find(at).map_err(|why| Gap { what: why })?;
    let Some(position) = session.open[index].current().map(|r| r.position) else {
        return Ok(Status(8));
    };
    let len = usize::try_from(*call.datalen).unwrap_or(0).min(call.databuf.len());

    match session.open[index].update(position, &call.databuf[..len]) {
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
    use crate::{Btrieve, Geometry};
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
}
