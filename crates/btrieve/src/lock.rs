//! Cross-channel lock ownership for the `dfa*` surface.
//!
//! # Why this is a second table, not a field added to `ops::LockTable`
//!
//! `ops::LockTable`'s own doc comment already worked out what an owner would
//! mean for it: `Held` gains an `owner` field, every method gains an owner
//! parameter, and the single/multiple/mode-mixing rules keep working, now
//! scoped per owner. This module does exactly that reasoning -- but as a
//! separate type, not an edit to `LockTable` itself, for two reasons:
//!
//! 1. `LockTable` is session-wide by design ("this session's Btrieve locks
//!    -- one table, shared by every open `Block`") and is exercised by both
//!    the `btv*` family (`shims/btrieve.rs`, under its own commit freeze)
//!    and the four `dfa*` calls this module serves. Reworking its signature
//!    would either touch that frozen file's own `take_lock`/`locate`/
//!    `absolute` call sites, or leave `btv*`'s calls passing a placeholder
//!    owner nobody asked for. Neither is this task's job: the brief scopes
//!    owner-awareness to `dfaAcqLock`/`dfaAcqAbsLock`/`dfaGetAbsLock`/
//!    `dfaStepLock`, and `LockTable`'s ~50 existing tests describe the
//!    unowned, single-client shape correctly for the caller that still has
//!    only one of those (`btv*`, no surveyed nonzero `loktyp` at all).
//! 2. `Btrieve` already keeps the `dfa*` family's own session state
//!    (`dfa_current`, `dfa_stack`, `dfa_mode`, `dfa_last_len`) genuinely
//!    independent of `btv*`'s (`stack`, `mode`) for the identical reason --
//!    see `shims/dfa.rs`'s own module doc comment, "`dfa`/`dfastk` are never
//!    `bb`/`bbstk`". This is that same split applied to locking specifically,
//!    which today is the one piece of session state the two families still
//!    share (both flow through `Btrieve::take_lock`/`ops::LockTable`).
//!
//! Both tables still run for a `dfa*` lock: `Btrieve::take_lock`'s existing
//! session-wide mode-mixing check (`ops::LockTable`, unowned) runs first,
//! inside the frozen `locate`/`absolute`/`stpbtvl`-equivalent call sequence,
//! exactly as it does for `btv*` today -- unchanged, and out of this task's
//! scope to rescope. Only once that has already succeeded (positioning and
//! delivery both already done -- see `shims/dfa.rs`'s own call sites) does
//! [`Locks::acquire`] run, adding the one check `LockTable` cannot make: is
//! this exact record already held by a *different* owner.
//!
//! # The status this refuses with
//!
//! Measured directly against genuine Pervasive Btrieve 6.15 under Wine, two
//! concurrent `wine btrvprobe.exe serve` clients against one shared
//! `W32MKDE.EXE` (`docs/lock-oracle-answer.md`): "client 2 Get the same key,
//! single + no-wait -> status **84**", and the same 84 for an Update or a
//! Delete against a record client 1 holds. `DFAAPI.C`'s own `dfaWasLocked()`
//! (`:853-855`) checks `status == 84 || status == 85` for exactly this --
//! 84 is the one of the two this project has actually measured live; 85
//! (named in `dfaOpen`'s own retry loop, `:161-163`, as "locked by another
//! process") is not, and is not needed here since nothing in this table
//! answers it. See [`LOCK_CONFLICT_STATUS`].
//!
//! # Single/multiple and auto-release, scoped per owner
//!
//! `docs/lock-oracle-answer.md`'s single-client measurements --
//! auto-release ("a single-record lock auto-releases when the same session
//! takes another single-record lock"), multiple accumulating, and
//! re-locking a record you already hold being a harmless no-op -- are
//! reproduced here exactly as `ops::LockTable::acquire` already reproduces
//! them, with one substitution throughout: everywhere the oracle's
//! "session" meant the one Btrieve client it measured, this reads "owner".
//! **Mode-mixing (status 93) is deliberately not reproduced a second time
//! here** -- it is `ops::LockTable`'s own check, already run (session-wide,
//! unowned) before this table is ever consulted, per this module's own
//! top-of-file reasoning above.

use crate::ops::BlockId;

/// Real Btrieve's status for "this record is locked by someone else" --
/// see this module's own top-of-file doc comment for the measurement.
/// Cited in doc comments and test failure messages; nothing computes with
/// it today because nothing on the `dfa*` shim edge threads a numeric
/// status back to the module for this family (see `dfaWasLocked`'s own doc
/// comment, `crates/mbbs/src/shims/dfa.rs`) -- a real number belongs here
/// regardless of whether today's one caller can read it back.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const LOCK_CONFLICT_STATUS: i16 = 84;

/// `raw < 300` is `SLWTBV`/`SLNWBV` (100/200, single); `raw >= 300` is
/// `MLWTBV`/`MLNWBV` (300/400, multiple) -- `DFAAPI.H:40-43`, the identical
/// threshold [`crate::ops::LockMode::of`] already reproduces. Restated
/// rather than reused so this module has no dependency on `ops::LockMode`
/// beyond the one already-public `BlockId` -- see this file's own doc
/// comment for why the two tables are independent.
fn is_single(raw: i16) -> bool {
    raw < 300
}

/// One dfa*-acquired lock: which block, which record (by physical
/// position -- the same identity `Block::get_position`/`dfaAbs` report),
/// which owner, and the raw `loktyp` -- kept verbatim rather than only
/// "single or multiple" for the same reason `ops::Held` keeps it: a caller
/// inspecting a held lock sees exactly what was asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Held {
    block: BlockId,
    position: u32,
    owner: u32,
    raw: i16,
}

/// Cross-channel lock ownership for the `dfa*` surface -- see this module's
/// own top-of-file doc comment for why this is a second table rather than
/// an owner field added to [`crate::ops::LockTable`].
#[derive(Debug, Default)]
pub(crate) struct Locks {
    held: Vec<Held>,
}

impl Locks {
    /// Take `raw` at `block`'s `position` on `owner`'s behalf, once a
    /// caller has already positioned there (the same "an operation that
    /// fails takes no lock" precondition [`crate::ops::Block::take_lock`]
    /// documents). `raw == 0` -- no lock asked for -- is always granted and
    /// changes nothing.
    ///
    /// In order, each the owner-scoped restatement of a
    /// `docs/lock-oracle-answer.md` measurement:
    ///
    /// 1. **Already held by `owner` itself is a no-op** (harmless
    ///    re-lock, status 0) -- **including when `raw` names a different
    ///    mode than the one already stored.** The stored `raw`/mode is not
    ///    updated in that case (mirrors [`crate::ops::LockTable::acquire`]'s
    ///    identical rule 1, which the same way returns before ever looking
    ///    at the new `raw`'s mode); see
    ///    `a_same_owner_re_lock_does_not_change_the_stored_mode` below.
    /// 2. **Already held by a *different* owner refuses** -- status 84,
    ///    see [`LOCK_CONFLICT_STATUS`].
    /// 3. **A single lock (`raw < 300`) replaces whatever single lock this
    ///    owner already held** -- auto-release, scoped to `owner`'s own
    ///    entries only; a different owner's locks are never touched.
    /// 4. **A multiple lock (`raw >= 300`) is added** without disturbing
    ///    anything already held, by `owner` or anyone else.
    ///
    /// Returns whether the lock was granted.
    pub(crate) fn acquire(&mut self, block: BlockId, position: u32, raw: i16, owner: u32) -> bool {
        if raw == 0 {
            return true;
        }

        if let Some(held) = self
            .held
            .iter()
            .find(|h| h.block == block && h.position == position)
        {
            return held.owner == owner;
        }

        if is_single(raw) {
            self.held
                .retain(|h| !(h.block == block && h.owner == owner && is_single(h.raw)));
        }
        self.held.push(Held {
            block,
            position,
            owner,
            raw,
        });
        true
    }

    /// Release `owner`'s lock at `block`'s `position`, if any -- Btrieve op
    /// 27, `dfaUnlock`. Never refuses: releasing a position `owner` does
    /// not hold there is a no-op, the same "status 0 even when nothing is
    /// locked" `ops::LockTable::release_at` already documents.
    ///
    /// **Not wired to any shim.** `dfaUnlock` is absent from the 32-bit
    /// `WCCMMUD.DLL` import list this crate's own doc comment
    /// (`Btrieve::dfa_current`'s, `crates/btrieve/src/lib.rs`) records --
    /// the seventeen `dfa*` symbols that module imports do not include it.
    /// Implemented anyway, on the standing instruction
    /// [`crate::ops::Block::take_lock`]'s own doc comment states: a routine
    /// that exists and is merely unexercised by the one module under test
    /// gets a real implementation, not an empty slot.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn release_at(&mut self, block: BlockId, position: u32, owner: u32) {
        self.held
            .retain(|h| !(h.block == block && h.position == position && h.owner == owner));
    }

    /// Release every owner's lock on `block` -- measured
    /// (`docs/lock-oracle-answer.md`: "closing a file releases every lock
    /// it held, immediately"). [`crate::Btrieve::close_file`] calls this
    /// alongside its existing `ops::LockTable::release_all_for` sweep, on
    /// the same block.
    pub(crate) fn release_all_for_block(&mut self, block: BlockId) {
        self.held.retain(|h| h.block != block);
    }

    /// Whose lock -- if any -- currently sits on `block` at `position`.
    /// Test/inspection surface, the "check" this module's own callers
    /// otherwise only exercise through [`Self::acquire`]'s return value.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn holder(&self, block: BlockId, position: u32) -> Option<u32> {
        self.held
            .iter()
            .find(|h| h.block == block && h.position == position)
            .map(|h| h.owner)
    }

    /// The raw `loktyp` stored for whoever holds `block` at `position`, if
    /// anyone. Test/inspection surface, the same as [`Self::holder`] --
    /// exists specifically to observe that a same-owner re-lock
    /// ([`Self::acquire`]'s rule 1) does not update this even when the new
    /// `raw` names a different mode.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn raw_at(&self, block: BlockId, position: u32) -> Option<i16> {
        self.held
            .iter()
            .find(|h| h.block == block && h.position == position)
            .map(|h| h.raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block() -> BlockId {
        BlockId::fresh()
    }

    #[test]
    fn a_lock_nobody_holds_is_granted() {
        let mut locks = Locks::default();
        let b = block();
        assert!(locks.acquire(b, 10, 100, 1), "nothing held it yet");
        assert_eq!(locks.holder(b, 10), Some(1));
    }

    #[test]
    fn a_lock_held_by_a_different_owner_is_refused() {
        let mut locks = Locks::default();
        let b = block();
        assert!(locks.acquire(b, 10, 100, 1), "owner 1 takes it first");
        assert!(
            !locks.acquire(b, 10, 200, 2),
            "owner 2 must be refused -- status {LOCK_CONFLICT_STATUS}, owner 1 still holds it"
        );
        assert_eq!(locks.holder(b, 10), Some(1), "still owner 1's, unchanged by the refusal");
    }

    #[test]
    fn re_locking_your_own_record_is_a_harmless_no_op() {
        let mut locks = Locks::default();
        let b = block();
        assert!(locks.acquire(b, 10, 100, 1));
        assert!(locks.acquire(b, 10, 100, 1), "re-locking your own record: status 0");
        assert_eq!(locks.holder(b, 10), Some(1));
    }

    /// Acquire's rule 1 (already held by `owner` itself) returns before
    /// ever comparing modes -- so a same-owner re-lock that asks for a
    /// *different* mode than the one already stored is still granted
    /// (matching `ops::LockTable::acquire`'s identical rule 1), and the
    /// stored `raw` is left exactly as it was, not updated to the new
    /// mode. Checked the hard way: if `acquire` updated `raw` on this
    /// path, `raw_at` would answer 300 here, not 100.
    #[test]
    fn a_same_owner_re_lock_does_not_change_the_stored_mode() {
        let mut locks = Locks::default();
        let b = block();
        assert!(locks.acquire(b, 10, 100, 1), "single lock first");
        assert!(
            locks.acquire(b, 10, 300, 1),
            "same owner, same record, now asking for multiple -- still a no-op grant"
        );
        assert_eq!(
            locks.raw_at(b, 10),
            Some(100),
            "the stored mode is still the original single lock, not updated to 300"
        );
    }

    #[test]
    fn releasing_lets_a_different_owner_acquire() {
        let mut locks = Locks::default();
        let b = block();
        assert!(locks.acquire(b, 10, 100, 1));
        assert!(!locks.acquire(b, 10, 100, 2), "still refused before release");
        locks.release_at(b, 10, 1);
        assert!(locks.acquire(b, 10, 100, 2), "granted once owner 1 released it");
        assert_eq!(locks.holder(b, 10), Some(2));
    }

    #[test]
    fn a_single_lock_auto_releases_only_the_same_owners_prior_single_lock() {
        let mut locks = Locks::default();
        let b = block();
        assert!(locks.acquire(b, 10, 100, 1), "owner 1's first single lock");
        assert!(locks.acquire(b, 20, 200, 2), "owner 2's own single lock, unrelated position");
        assert!(
            locks.acquire(b, 30, 100, 1),
            "owner 1 takes a second single lock -- auto-releases owner 1's own prior one"
        );
        assert_eq!(locks.holder(b, 10), None, "owner 1's prior single lock is gone");
        assert_eq!(
            locks.holder(b, 20),
            Some(2),
            "owner 2's own single lock is untouched by owner 1's auto-release"
        );
        assert_eq!(locks.holder(b, 30), Some(1));
    }

    #[test]
    fn a_multiple_lock_accumulates_without_disturbing_anything_held() {
        let mut locks = Locks::default();
        let b = block();
        assert!(locks.acquire(b, 10, 300, 1));
        assert!(locks.acquire(b, 20, 300, 1), "second multiple lock, same owner");
        assert_eq!(locks.holder(b, 10), Some(1), "the first multiple lock is still held");
        assert_eq!(locks.holder(b, 20), Some(1));
    }

    #[test]
    fn a_zero_lock_is_always_granted_and_records_nothing() {
        let mut locks = Locks::default();
        let b = block();
        assert!(locks.acquire(b, 10, 0, 1), "raw == 0 -- no lock asked for");
        assert_eq!(locks.holder(b, 10), None, "nothing recorded for a no-op acquire");
    }

    #[test]
    fn releasing_a_block_releases_every_owners_lock_on_it() {
        let mut locks = Locks::default();
        let b = block();
        let other = block();
        assert!(locks.acquire(b, 10, 100, 1));
        assert!(locks.acquire(b, 20, 300, 2));
        assert!(locks.acquire(other, 10, 100, 1), "same position, a different block");
        locks.release_all_for_block(b);
        assert_eq!(locks.holder(b, 10), None);
        assert_eq!(locks.holder(b, 20), None);
        assert_eq!(
            locks.holder(other, 10),
            Some(1),
            "a different block's lock is untouched by closing block b"
        );
    }

    #[test]
    fn releasing_a_position_you_do_not_hold_is_a_harmless_no_op() {
        let mut locks = Locks::default();
        let b = block();
        locks.release_at(b, 10, 1);
        assert_eq!(locks.holder(b, 10), None);
    }
}
