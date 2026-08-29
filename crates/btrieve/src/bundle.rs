//! System transactions: how many writes a block has staged since its
//! last commit, and whether that is enough to commit now.
//!
//! Btrieve 6.15's MKDE gathered ops outside an explicit transaction into a
//! *system transaction* and committed it on the first of two limits --
//! `Systrans Bundle Limit` (100 ops) and `Systrans Time Limit` (1000 ms)
//! in a period Worldgroup deployment's registry
//! (`docs/mirrors/wiki.mud.fyi/.../worldgroup/setup.html`). Pure state,
//! no I/O: the block owning it decides what a commit is.

use std::time::{Duration, Instant};

/// When a bundle commits: at `ops` staged writes, or `age` after its first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub ops: u32,
    pub age: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self { ops: 100, age: Duration::from_millis(1000) }
    }
}

/// What the block should do after the write it just staged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum After {
    Hold,
    Commit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Open {
    since: Instant,
    ops: u32,
}

/// One block's staged-but-uncommitted writes, counted, not held: the
/// pages themselves live in the block's cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Bundle {
    limits: Limits,
    open: Option<Open>,
}

impl Default for Bundle {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

impl Bundle {
    pub(crate) fn new(limits: Limits) -> Self {
        Self { limits, open: None }
    }

    pub(crate) fn limits(&self) -> Limits {
        self.limits
    }

    /// Takes effect at the next `note_write`/`expired`, open bundle included.
    pub(crate) fn set_limits(&mut self, limits: Limits) {
        self.limits = limits;
    }

    pub(crate) fn is_open(&self) -> bool {
        self.open.is_some()
    }

    pub(crate) fn ops(&self) -> u32 {
        self.open.map_or(0, |o| o.ops)
    }

    /// One more staged write at `now`, opening the bundle if none is open.
    pub(crate) fn note_write(&mut self, now: Instant) -> After {
        let open = self.open.get_or_insert(Open { since: now, ops: 0 });
        open.ops += 1;
        if open.ops >= self.limits.ops || now.duration_since(open.since) >= self.limits.age {
            After::Commit
        } else {
            After::Hold
        }
    }

    /// Whether an open bundle has reached its age limit at `now`.
    pub(crate) fn expired(&self, now: Instant) -> bool {
        self.open.is_some_and(|o| now.duration_since(o.since) >= self.limits.age)
    }

    /// The block committed (or discarded) everything this counted.
    pub(crate) fn clear(&mut self) {
        self.open = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(ops: u32, age_ms: u64) -> Limits {
        Limits { ops, age: Duration::from_millis(age_ms) }
    }

    #[test]
    fn the_defaults_are_the_vendors() {
        let l = Limits::default();
        assert_eq!((l.ops, l.age), (100, Duration::from_millis(1000)));
    }

    #[test]
    fn the_hundredth_write_commits_and_the_next_opens_a_new_bundle() {
        let t0 = Instant::now();
        let mut b = Bundle::new(limits(100, 1000));
        assert!(!b.is_open());
        for n in 1..100 {
            assert_eq!(b.note_write(t0), After::Hold, "write {n} holds");
            assert_eq!(b.ops(), n);
        }
        assert_eq!(b.note_write(t0), After::Commit, "the 100th commits");
        b.clear();
        assert!(!b.is_open());
        assert_eq!(b.note_write(t0), After::Hold, "the 101st starts over");
        assert_eq!(b.ops(), 1);
    }

    #[test]
    fn a_write_at_or_past_the_age_limit_commits() {
        let t0 = Instant::now();
        let mut b = Bundle::new(limits(100, 1000));
        assert_eq!(b.note_write(t0), After::Hold);
        assert_eq!(b.note_write(t0 + Duration::from_millis(999)), After::Hold);
        assert_eq!(b.note_write(t0 + Duration::from_millis(1000)), After::Commit);
    }

    #[test]
    fn the_age_counts_from_the_first_write_not_the_last() {
        let t0 = Instant::now();
        let mut b = Bundle::new(limits(100, 1000));
        b.note_write(t0);
        b.note_write(t0 + Duration::from_millis(900));
        assert_eq!(b.note_write(t0 + Duration::from_millis(1000)), After::Commit);
    }

    #[test]
    fn expired_asks_the_same_question_without_a_write() {
        let t0 = Instant::now();
        let mut b = Bundle::new(limits(100, 1000));
        assert!(!b.expired(t0 + Duration::from_secs(5)), "nothing open, nothing expires");
        b.note_write(t0);
        assert!(!b.expired(t0 + Duration::from_millis(999)));
        assert!(b.expired(t0 + Duration::from_millis(1000)));
    }

    #[test]
    fn a_zero_age_or_a_one_op_limit_is_per_op_commit() {
        let t0 = Instant::now();
        assert_eq!(Bundle::new(limits(100, 0)).note_write(t0), After::Commit);
        assert_eq!(Bundle::new(limits(1, 1000)).note_write(t0), After::Commit);
    }

    #[test]
    fn new_limits_apply_to_the_open_bundle() {
        let t0 = Instant::now();
        let mut b = Bundle::new(limits(100, 1000));
        b.note_write(t0);
        b.set_limits(limits(2, 1000));
        assert_eq!(b.note_write(t0), After::Commit);
    }
}
