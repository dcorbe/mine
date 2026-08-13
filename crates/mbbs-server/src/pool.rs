//! The fixed set of channels a connection borrows for its lifetime.
//!
//! `nterms` is fixed at `Host::new` -- there is no channel this host can mint
//! that was not counted into every per-channel table at construction. So the
//! pool is exactly that many [`Chan`]s, handed out one per connection and
//! given back on disconnect. A connection arriving when the pool is empty is
//! refused rather than queued: the honest telnet translation of a modem that
//! did not answer.
//!
//! **One `Pool` per machine, never shared.** `crates/mbbs-server/src/host.rs`'s
//! `life` builds a fresh `Pool` every life, on the one thread that owns that
//! life's `A::Cpu` -- see `crates/mbbs-server/src/conn.rs`'s module doc,
//! "One `serve` call is one machine". A `Chan`'s value alone is therefore
//! only meaningful *within* the machine that handed it out: two machines
//! both number their channels from zero, and this module has no way to tell
//! one machine's channel zero from another's -- that is a fact about
//! whichever `Pool` a caller is holding, not something a `Chan` carries.

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
    /// Whether channel `i` (by [`Chan::index`]) is currently out with a
    /// connection. The only thing [`Pool::give_back`] consults to decide
    /// whether a free is real or a no-op -- see its doc.
    taken: Vec<bool>,
}

impl Pool {
    /// Every channel of `terms`, all free, lowest first.
    #[must_use]
    pub fn new(terms: Terms) -> Self {
        Self {
            free: terms.all().collect(),
            taken: vec![false; terms.count().into()],
        }
    }

    /// A free channel, or `None` if every line is busy.
    pub fn take(&mut self) -> Option<Chan> {
        let chan = self.free.pop_front()?;
        self.taken[chan.index()] = true;
        Some(chan)
    }

    /// Return a channel a connection is done with, behind everything already
    /// free.
    ///
    /// **Idempotent.** Freeing a channel that is not currently taken is a
    /// no-op -- not a panic, and not a second copy of `chan` in the free
    /// list. That is a real possibility, not a defensive nicety for a case
    /// that cannot arise: `crates/mbbs-server/src/host.rs` has two call
    /// sites that can both reach the *same* channel for the *same*
    /// disconnect. `flush` hangs a channel up when sending its queued output
    /// fails (the connection's `Sender<Out>` is closed or full); `apply`'s
    /// `In::Disconnect` arm hangs the same channel up when the connection's
    /// own EOF message is drained. A dropped sender and a queued
    /// `Disconnect` are two independent signals of one event, and nothing
    /// orders them against each other -- so whichever runs second, absent a
    /// guard, would free a channel the other had already freed, and the
    /// *next* `take` would then hand that one channel to two different
    /// connections at once.
    ///
    /// A panic would also stop this at the source, and this project's
    /// default is "runtime crashes are better than undefined behaviour" --
    /// but a panic here runs on the host thread, and the host thread has
    /// exactly one of itself: unwinding it ends the whole board, which is
    /// the very outage `crates/mbbs-server/src/host.rs`'s restart supervisor
    /// exists to survive. Trading a silently doubled free for a certainly
    /// crashed board is not the safer failure mode, so this stays a no-op
    /// instead: cheap to check, and it makes "the same channel handed to two
    /// connections" structurally unreachable through this method rather than
    /// merely unlikely in practice.
    ///
    /// Returns whether this call actually freed the channel (`true`) or
    /// found it already free and did nothing (`false`). No caller reads this
    /// today, which is fine -- the guarantee holds either way -- but the
    /// signature says honestly that calling `give_back` no longer promises
    /// unconditionally to grow `free` by one.
    pub fn give_back(&mut self, chan: Chan) -> bool {
        let idx = chan.index();
        if !self.taken[idx] {
            return false;
        }
        self.taken[idx] = false;
        self.free.push_back(chan);
        true
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

    /// Every test above shares one shape: it gives a channel back exactly
    /// once, and only ever a channel it actually took. That shape is
    /// precisely what let the double-free bug this module now guards
    /// against ship in the first place -- see `give_back`'s doc for the two
    /// real call sites that can both reach the same channel for the same
    /// disconnect. The two tests below violate that shape on purpose: one
    /// frees a channel nobody took, the other frees the same channel twice.
    ///
    /// A channel nobody took is free already -- `Pool::new` starts every
    /// channel free -- so `give_back` on it must be a no-op: `false`, and no
    /// second copy in `free`. A duplicate copy would show up here as the
    /// pool answering `take()` more times than it has channels.
    #[test]
    fn give_back_on_a_channel_that_was_never_taken_is_a_no_op() {
        let terms = Terms::new(2);
        let mut pool = Pool::new(terms);
        let stray = terms.chan(0).expect("channel 0");

        assert!(
            !pool.give_back(stray),
            "a channel nobody took was not freed by this call"
        );

        // Still exactly two channels obtainable, not three.
        let a = pool.take().expect("first");
        let b = pool.take().expect("second");
        assert_ne!(a, b);
        assert!(
            pool.take().is_none(),
            "give_back on an untaken channel must not have manufactured a third"
        );
    }

    /// The exact shape of Path 1 in the defect this guards against: one
    /// connection's channel gets freed twice in the same life (`flush`'s
    /// send-failure path and `apply`'s `In::Disconnect` arm can both reach
    /// it for the one disconnect). The second `give_back` must be a no-op,
    /// not a second entry in `free` -- otherwise `take` would hand the one
    /// real channel to two different connections.
    #[test]
    fn give_back_twice_after_one_take_frees_it_only_once() {
        let terms = Terms::new(1);
        let mut pool = Pool::new(terms);
        let a = pool.take().expect("the only channel");

        assert!(pool.give_back(a), "the first give_back genuinely frees it");
        assert!(
            !pool.give_back(a),
            "the second give_back finds it already free and does nothing"
        );

        // Exactly one channel is obtainable, not two.
        assert_eq!(pool.take(), Some(a));
        assert!(
            pool.take().is_none(),
            "the duplicate give_back must not have doubled the free list -- \
             this is the exact mechanism by which two clients would end up \
             sharing one channel"
        );
    }
}
