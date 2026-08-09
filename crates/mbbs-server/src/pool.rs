//! The fixed set of channels a connection borrows for its lifetime.
//!
//! `nterms` is fixed at `Host::new` -- there is no channel this host can mint
//! that was not counted into every per-channel table at construction. So the
//! pool is exactly that many [`Chan`]s, handed out one per connection and
//! given back on disconnect. A connection arriving when the pool is empty is
//! refused rather than queued: the honest telnet translation of a modem that
//! did not answer.

use mbbs::{Chan, Terms};

/// The free channels, LIFO.
///
/// A stack rather than a queue: [`crate::host`]'s driver resets a channel
/// synchronously before returning it (`Host::hangup`), so nothing is gained
/// by spacing reuse out, and a stack is the one obvious way to hold a free
/// list.
pub struct Pool {
    free: Vec<Chan>,
}

impl Pool {
    /// Every channel of `terms`, all free.
    #[must_use]
    pub fn new(terms: Terms) -> Self {
        Self {
            free: terms.all().collect(),
        }
    }

    /// A free channel, or `None` if every line is busy.
    pub fn take(&mut self) -> Option<Chan> {
        self.free.pop()
    }

    /// Return a channel a connection is done with.
    pub fn give_back(&mut self, chan: Chan) {
        self.free.push(chan);
    }
}

#[cfg(test)]
mod tests {
    use super::Pool;
    use mbbs::Terms;

    #[test]
    fn a_pool_hands_out_every_channel_once_and_then_refuses() {
        let terms = Terms::new(2);
        let mut pool = Pool::new(terms);
        let a = pool.take().expect("first");
        let b = pool.take().expect("second");
        assert_ne!(a, b, "two connections must not share a channel");
        assert!(pool.take().is_none(), "all lines busy");

        pool.give_back(a);
        assert_eq!(pool.take(), Some(a), "a hung-up line is reusable");
    }
}
