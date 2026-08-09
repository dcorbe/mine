//! The fixed set of channels a connection borrows for its lifetime.
//!
//! `nterms` is fixed at `Host::new` -- there is no channel this host can mint
//! that was not counted into every per-channel table at construction. So the
//! pool is exactly that many [`Chan`]s, handed out one per connection and
//! given back on disconnect. A connection arriving when the pool is empty is
//! refused rather than queued: the honest telnet translation of a modem that
//! did not answer.

use std::collections::VecDeque;

use mbbs::{Chan, Terms};

/// The free channels, **oldest free first**.
///
/// A queue rather than a stack, for a reason particular to this codebase
/// rather than a general one. Reuse is safe either way -- the driver resets a
/// channel synchronously through `Host::hangup` before giving it back, so a
/// channel that was freed a moment ago is no different from one freed an hour
/// ago.
///
/// What differs is which channels a running board actually uses. A stack
/// hands back the channel it just took, so a board with light traffic runs
/// almost entirely on one channel -- and "almost entirely on channel zero" is
/// the exact configuration that hides a per-channel bug. This crate's history
/// is made of them: `btuxmt` writing to the current channel instead of its
/// argument, `vdaptr` always reading channel zero's, `rstchn` resetting every
/// channel instead of the one it was given, `refill_polls` sweeping only the
/// first. Every one passed a full suite because nothing exercised a second
/// channel.
///
/// A queue rotates, so those bugs show up in use instead of waiting for a
/// test to think of them. It also means the first connection gets channel
/// zero, which is what every fixture and doc in `crates/mbbs` assumes.
pub struct Pool {
    free: VecDeque<Chan>,
}

impl Pool {
    /// Every channel of `terms`, all free, lowest first.
    #[must_use]
    pub fn new(terms: Terms) -> Self {
        Self {
            free: terms.all().collect(),
        }
    }

    /// A free channel, or `None` if every line is busy.
    pub fn take(&mut self) -> Option<Chan> {
        self.free.pop_front()
    }

    /// Return a channel a connection is done with, behind everything already
    /// free.
    pub fn give_back(&mut self, chan: Chan) {
        self.free.push_back(chan);
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

    /// The first connection lands on channel zero, and reuse rotates.
    ///
    /// The test above cannot tell a queue from a stack: it gives one channel
    /// back while the other is still out, so there is only one answer either
    /// way. This one can, and the difference is the whole reason the policy
    /// was chosen -- see [`super::Pool`].
    #[test]
    fn channels_are_reused_oldest_first_and_the_first_caller_gets_zero() {
        let terms = Terms::new(3);
        let mut pool = Pool::new(terms);

        let first = pool.take().expect("a free channel");
        assert_eq!(
            first,
            terms.chan(0).expect("channel 0"),
            "the first caller gets channel zero, as every fixture in mbbs assumes"
        );
        let second = pool.take().expect("a free channel");
        let third = pool.take().expect("a free channel");
        assert!(pool.take().is_none(), "all lines busy");

        // All three hang up, in the order they connected.
        pool.give_back(first);
        pool.give_back(second);
        pool.give_back(third);

        assert_eq!(pool.take(), Some(first), "oldest free first");
        assert_eq!(pool.take(), Some(second));
        assert_eq!(
            pool.take(),
            Some(third),
            "a stack would have answered these three exactly backwards, and a \
             board that reuses one channel is a board that never exercises the \
             others"
        );
    }
}
