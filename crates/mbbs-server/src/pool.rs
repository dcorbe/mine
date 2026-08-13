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
//! one machine's channel zero from another's just by looking at a `Chan` --
//! that is a fact about whichever `Pool` a caller is holding, not something
//! a `Chan` carries.
//!
//! **[`MachineId`] and [`Routed`] are that fact, made a value.** Task 20 of
//! `docs/plans/2026-08-12-abi-border-implementation.md` built the pairing
//! the paragraph above only used to describe: `main.rs` assigns one
//! `MachineId` per `serve` call it makes (`crate::host::Boot::machine`), and
//! [`Pool::take`] hands back a `Routed` -- the id plus the `Chan` -- rather
//! than a bare `Chan`. That is the actual process-wide key wherever a
//! connection gets mapped to a host: `crate::msg::In::Connect`'s reply and
//! `In::Input`/`In::Disconnect`'s `chan` field all carry `Routed`, and
//! `crate::conn`'s per-connection state holds one for the connection's whole
//! life. Only one machine boots today (`main.rs` calls `conn::serve` once),
//! so every `Routed` in a running process currently shares the same
//! `MachineId` -- the type does not depend on that changing, and nothing
//! here builds a registry or a selector across machines; see Task 22 for
//! that, not yet designed.

use std::collections::VecDeque;

use mbbs::{Chan, Terms};

/// Which machine's `serve` call a [`Chan`] belongs to, process-wide.
///
/// Assigned once by whoever calls `crate::conn::serve` -- `main.rs` today,
/// always the same id, since only one machine boots -- never invented by a
/// `Pool` itself. See the module doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MachineId(pub u16);

/// A connection's identity, process-wide: which machine's [`Pool`] handed
/// `chan` out, plus the `chan` itself.
///
/// A bare [`Chan`] is only unique *within* the `Pool` that issued it (see the
/// module doc) -- this is the actual key everywhere a connection is mapped
/// to a host: [`Pool::take`]'s answer, `crate::msg::In::Connect`'s reply, and
/// `In::Input`/`In::Disconnect`'s `chan` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Routed {
    pub machine: MachineId,
    pub chan: Chan,
}

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
    /// The id every [`Chan`] this pool hands out gets tagged with -- see
    /// [`Routed`] and the module doc.
    machine: MachineId,
    free: VecDeque<Chan>,
    /// Whether channel `i` (by [`Chan::index`]) is currently out with a
    /// connection. The only thing [`Pool::give_back`] consults to decide
    /// whether a free is real or a no-op -- see its doc.
    taken: Vec<bool>,
}

impl Pool {
    /// Every channel of `terms`, all free, lowest first, all belonging to
    /// `machine`.
    #[must_use]
    pub fn new(machine: MachineId, terms: Terms) -> Self {
        Self {
            machine,
            free: terms.all().collect(),
            taken: vec![false; terms.count().into()],
        }
    }

    /// A free channel, tagged with this pool's [`MachineId`], or `None` if
    /// every line is busy.
    pub fn take(&mut self) -> Option<Routed> {
        let chan = self.free.pop_front()?;
        self.taken[chan.index()] = true;
        Some(Routed { machine: self.machine, chan })
    }

    /// Pair a [`Chan`] this pool already knows is its own with this pool's
    /// [`MachineId`].
    ///
    /// For a caller inside this crate that only ever has a bare `Chan` in
    /// hand because it is walking *this* pool's own channels (`host.rs`'s
    /// `flush`, sweeping `Terms::all()`) rather than answering an
    /// externally-sourced [`Routed`] message -- unlike [`Pool::give_back`],
    /// which is the guarded entry point for a `Routed` a caller received
    /// from somewhere else and must not simply trust.
    #[must_use]
    pub fn key(&self, chan: Chan) -> Routed {
        Routed { machine: self.machine, chan }
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
    ///
    /// **Also a no-op for the wrong [`MachineId`].** `routed.machine !=
    /// self.machine` means this `Routed` was never this pool's to free in
    /// the first place -- a caller can only construct one from
    /// `Pool::take`/`Pool::key`, so the only way to reach this arm is a
    /// message misrouted to the wrong machine's `apply`, and today nothing
    /// in this crate can do that (`main.rs` calls `conn::serve` once). This
    /// guard is what makes that true by construction, the same way the
    /// index guard above makes a double free structurally unreachable
    /// through this method rather than merely unlikely in practice -- see
    /// the module doc for why a `Chan`'s value alone cannot tell two
    /// machines' channel zeros apart.
    pub fn give_back(&mut self, routed: Routed) -> bool {
        if routed.machine != self.machine {
            return false;
        }
        let idx = routed.chan.index();
        if !self.taken[idx] {
            return false;
        }
        self.taken[idx] = false;
        self.free.push_back(routed.chan);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{MachineId, Pool};
    use mbbs::Terms;

    #[test]
    fn a_pool_hands_out_every_channel_once_and_then_refuses() {
        let terms = Terms::new(2);
        let mut pool = Pool::new(MachineId(0), terms);
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
        let mut pool = Pool::new(MachineId(0), terms);

        let first = pool.take().expect("a free channel");
        assert_eq!(
            first.chan,
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
        let mut pool = Pool::new(MachineId(0), terms);
        let stray = pool.key(terms.chan(0).expect("channel 0"));

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
        let mut pool = Pool::new(MachineId(0), terms);
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

    /// Task 20's whole point: two machines' `Pool`s both number their
    /// channels from zero, and the `Chan` values `take` hands back are
    /// therefore equal -- but the `Routed` values are not, because they
    /// carry different `MachineId`s. A `HashSet<Routed>` holding one key
    /// from each pool has two entries, not one; a `HashSet<mbbs::Chan>`
    /// built by stripping `.machine` off the same two values would have
    /// only one -- that collision is exactly the bug a bare `Chan` cannot
    /// see, see the module doc.
    #[test]
    fn two_machines_sharing_a_chan_value_are_routed_distinctly() {
        use std::collections::HashSet;

        let mut pool_a = Pool::new(MachineId(0), Terms::new(1));
        let mut pool_b = Pool::new(MachineId(1), Terms::new(1));

        let routed_a = pool_a.take().expect("pool a's only channel");
        let routed_b = pool_b.take().expect("pool b's only channel");

        assert_eq!(
            routed_a.chan, routed_b.chan,
            "both pools number their channels from zero -- the bare Chan really \
             does collide"
        );
        assert_ne!(
            routed_a, routed_b,
            "but the Routed keys must not -- they carry different MachineIds"
        );

        let mut seen = HashSet::new();
        seen.insert(routed_a);
        seen.insert(routed_b);
        assert_eq!(
            seen.len(),
            2,
            "two connections on two different machines' channel zero must occupy \
             two distinct slots in anything keyed on Routed, not collapse into one"
        );
    }

    /// A `Routed` naming the right `Chan` but the wrong `MachineId` must not
    /// free anything -- the same "no-op, not a crash" contract
    /// `give_back_on_a_channel_that_was_never_taken_is_a_no_op` pins for an
    /// untaken channel, but for the other way a `Routed` can be wrong: it
    /// names a channel that really is taken, just not by this pool.
    #[test]
    fn give_back_for_the_wrong_machine_is_a_no_op() {
        let mut pool_a = Pool::new(MachineId(0), Terms::new(1));
        let mut pool_b = Pool::new(MachineId(1), Terms::new(1));

        let routed_a = pool_a.take().expect("pool a's only channel");
        let _routed_b = pool_b.take().expect("pool b's only channel");

        assert!(
            !pool_b.give_back(routed_a),
            "pool b must refuse a Routed stamped with pool a's MachineId, even \
             though the Chan inside it (channel 0) is one pool b also handed out"
        );
        assert!(
            pool_b.take().is_none(),
            "pool b's channel 0 must still be out -- the wrong-machine give_back \
             must not have freed it"
        );

        assert!(
            pool_a.give_back(routed_a),
            "pool a must still accept the very same Routed value back -- it is \
             genuinely pool a's"
        );
    }
}
