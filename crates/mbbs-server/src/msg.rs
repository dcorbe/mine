//! What crosses the boundary between the async edge and the host thread.

use mbbs::{Chan, Connection};
use tokio::sync::{mpsc, oneshot};

/// Into the host thread. One queue for every connection, because the host
/// thread has to be able to block on exactly one thing.
pub enum In {
    Connect {
        who: Connection,
        out: mpsc::Sender<Out>,
        reply: oneshot::Sender<Option<Chan>>,
    },
    Input {
        chan: Chan,
        bytes: Vec<u8>,
    },
    Disconnect {
        chan: Chan,
    },
    /// Shut this machine's module down and end the host thread.
    ///
    /// A message rather than an `AtomicBool` the driver polls, because the
    /// driver spends nearly all of its life blocked in `rx.recv()` (see
    /// `host::wake`) and a flag would not be noticed until something else
    /// happened to wake it -- which on an idle board is the next kick, up to
    /// a whole second away, and on a board with no kicks outstanding is
    /// never.
    ///
    /// `done` fires once the module's `finrou` sweep has finished, so the
    /// process can wait for shutdown to actually complete instead of
    /// guessing. Dropping it (a host thread that died on the way) reads as
    /// completion too: the waiter cannot tell the difference and there is
    /// nothing useful it could do differently.
    Shutdown {
        done: oneshot::Sender<()>,
    },

    /// Run daily maintenance now: hang everyone up, sweep every module's
    /// `mcurou` and `finrou`, and boot the modules again in a fresh life.
    /// Sent by `SIGUSR1`. Carries nothing: the deadline path inside `life`
    /// reaches the same code without a message at all.
    Maintain,

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
