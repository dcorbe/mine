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

use crate::ops::OpError;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::{LockMode, OpError};

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
}
