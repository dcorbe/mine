//! What crosses the boundary between the async edge and the host thread.

use mbbs::Connection;
use tokio::sync::{mpsc, oneshot};

use crate::pool::Routed;

/// Into the host thread. One queue for every connection, because the host
/// thread has to be able to block on exactly one thing.
///
/// `chan` fields carry [`Routed`], not a bare `mbbs::Chan` -- see
/// `crate::pool`'s module doc. Today every `Routed` in a running process
/// shares the same `MachineId` (only one machine boots), but the type is the
/// process-wide connection identity regardless.
pub enum In {
    Connect {
        who: Connection,
        out: mpsc::Sender<Out>,
        reply: oneshot::Sender<Option<Routed>>,
    },
    Input {
        chan: Routed,
        bytes: Vec<u8>,
    },
    Disconnect {
        chan: Routed,
    },
    /// A deadline the driver itself asked for has passed -- see
    /// `crate::alarm`. Carries nothing: the timer task never learns *why* it
    /// was armed, only *when*, and `Host::cycle`'s own clock-anchored
    /// catch-up (`tcklst`) is what decides whether anything was actually
    /// due. A stale or duplicate `Alarm` is not a bug -- see `alarm`'s own
    /// module doc for why this message is deliberately sloppy.
    Alarm,
}

/// Out of the host thread, to one connection.
pub enum Out {
    Bytes(Vec<u8>),
    Close,
}
