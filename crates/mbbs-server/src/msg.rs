//! What crosses the boundary between the async edge and the host thread.

use mbbs::{Chan, Login, Refusal, Terminal};
use tokio::sync::{mpsc, oneshot};

/// Into the host thread. One queue for every connection, because the host
/// thread has to be able to block on exactly one thing.
pub enum In {
    /// A caller asking to be let on, with what the listener claims about
    /// who they are and what they are looking at.
    ///
    /// The listener sends a *claim*, never a decision: it is the host that
    /// reads the account file, so it is the host that says who this is and
    /// which keys they hold. `reply` carries that answer back -- a `Chan`
    /// the caller now owns, or the one [`Refusal`] the listener turns into
    /// one line on the wire (`crate::conn::refusal_line`).
    Connect {
        login: Login,
        terminal: Terminal,
        out: mpsc::Sender<Out>,
        reply: oneshot::Sender<Result<Chan, Refusal>>,
    },
    Input {
        chan: Chan,
        bytes: Vec<u8>,
    },
    Disconnect {
        chan: Chan,
    },

    /// One `mbbs-user` command that arrived over the admin socket
    /// (`crate::admin::serve`). The host thread applies it with
    /// `crate::admin::apply` against the account files it already has
    /// open, and `reply` carries the answer back to the socket task. A
    /// dropped `reply` is a client that went away, and is ignored the way
    /// a dropped `Connect` reply is.
    Admin {
        request: crate::admin::Request,
        reply: oneshot::Sender<crate::admin::Reply>,
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
