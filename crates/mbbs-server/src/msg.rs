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
}

/// Out of the host thread, to one connection.
pub enum Out {
    Bytes(Vec<u8>),
    Close,
}
