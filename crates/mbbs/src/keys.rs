//! What a channel is allowed to do, and the expression a module asks it with.
//!
//! MajorBBS called these locks and keys: a *lock* is a name a sysop configures
//! on a feature, a *key* is a name a user holds, and `haskey`
//! (`LOCKNKEY.C:254`) asks whether the current user holds the key to a lock.
//! `WCCMMUD.DLL` imports that one routine at 61 sites and none of the other
//! twenty-nine in the subsystem -- it asks, never grants, and never asks about
//! anyone but the current user.
//!
//! # A set of names, not the bitset the original allocated
//!
//! `LOCKNKEY.C` interned every lock name into a sorted array (`lockbit`,
//! `:439`) and gave each user a bitset indexed by position in it. That machinery
//! exists to make the test one AND instruction, and it is not reproduced here,
//! because nothing can observe it: `WCCMMUD.DLL` imports neither `usrptr`'s
//! keys field nor any of the bit routines. Its two failure branches --
//! "this lock was never interned" (`lockbit` returns -1) and "this user lacks
//! the key" (the bit is clear) -- are separate code over a bitset but one
//! answer over a set, and the answer is the same 0.
//!
//! # Names are uppercased once, on the way in
//!
//! `lockbit` opens with `strupr(lock)` and `fndkey` (`:313`) compares with
//! `sameas`, so lock and key names match case-insensitively. Doing the fold at
//! construction makes [`KeySet::evaluate`] a set lookup rather than a scan.
//! **ASCII only**: `strupr` on a CP437 box folded ASCII and nothing else, and a
//! Unicode casefold would map bytes the original never touched.
//!
//! # No truncation to `KEYSIZ`
//!
//! `LOCKNKEY.H:79` makes a key name 16 bytes because `stzcpy` wrote it into a
//! 16-byte field in `bbsk.dat`. Nothing in this host writes that record, and
//! silently shortening a key name changes an identity rather than rejecting
//! one. The limit is documented here and enforced nowhere. A `bbsk.dat` reader,
//! if one is ever written, enforces it at its own boundary, where the field
//! actually exists.

use std::collections::BTreeSet;

/// The keys one channel holds -- `LOCKNKEY.C`'s `usrptr->keys`.
///
/// Built by whoever authenticated the user, carried in on
/// [`crate::Connection`], and stored per channel by
/// [`crate::Users::set_keys`]. This host resolves keys once, at connect, which
/// is what the original did: `loadkeys()` (`LOCKNKEY.C:88`) read `bbsk.dat` at
/// logon and `low_haskey` never touched disk again.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeySet {
    /// Uppercased key names.
    keys: BTreeSet<String>,
    /// `MASTER`, `MAJORBBS.H:206` -- bit `0x40` of `user.flags`.
    ///
    /// **Read the warning on [`KeySet::master`] before setting this.**
    master: bool,
}

impl KeySet {
    /// A channel holding these keys and nothing else.
    pub fn new(keys: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        Self {
            keys: keys
                .into_iter()
                .map(|key| key.as_ref().to_ascii_uppercase())
                .collect(),
            master: false,
        }
    }

    /// Give this channel the master flag, which grants **every** lock.
    ///
    /// `low_haskey` returns 1 on `flags&MASTER` before it ever looks at the
    /// key set, so a master-flagged user holds every key that exists. That is
    /// a trap in this module's namespace rather than a convenience, because
    /// MajorMUD's locks include *negative* ones -- `NOPLAYKY {idiot}` bans you
    /// from the game, `GOSSKEY {gidiot}` disables gossip, `NOKICKEY` and
    /// `AUCTKEY` likewise. A master-flagged user therefore holds `idiot` and
    /// is banned from the game they are sysop of.
    ///
    /// Nothing in this tree sets it. It exists because the bit is real and a
    /// login backend may have a reason to; the consequence above is the one
    /// the original handed out too.
    pub fn master(mut self, yes: bool) -> Self {
        self.master = yes;
        self
    }

    /// Does this channel hold the key to one lock name?
    ///
    /// `low_haskey`, `LOCKNKEY.C:187`, minus the two branches that cannot
    /// arise here -- see [`KeySet::evaluate`] for those and for the expression
    /// grammar that calls this.
    fn holds(&self, lock: &str) -> bool {
        // `low_haskey`'s second check: an empty lock is no lock at all and
        // everyone passes it. Reached before the key set is consulted, which
        // is why an empty name is true even for a channel holding nothing.
        if lock.is_empty() {
            return true;
        }
        // `flags&MASTER` -- checked before the set, so it grants unknown locks
        // too. See `KeySet::master`.
        if self.master {
            return true;
        }
        self.keys.contains(&lock.to_ascii_uppercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_channel_holds_the_keys_it_was_given() {
        let keys = KeySet::new(["USER", "WCCSYSOP"]);
        assert!(keys.holds("USER"));
        assert!(keys.holds("WCCSYSOP"));
    }

    #[test]
    fn a_lock_nobody_holds_the_key_to_is_refused() {
        // `lockbit(lock,0) == -1` and "the bit is clear" are two branches in
        // `LOCKNKEY.C:206-209` and one answer here. Both are 0.
        let keys = KeySet::new(["USER"]);
        assert!(!keys.holds("WCCSYSOP"));
        assert!(!keys.holds("NEVERINTERNED"));
    }

    #[test]
    fn names_match_case_insensitively_in_both_directions() {
        // `lockbit` opens with `strupr(lock)` and `fndkey` compares with
        // `sameas`, so neither side's case is meaningful. Folding at
        // construction has to leave the stored side folded too -- a test that
        // only varied the lock's case would pass against a `holds` that folded
        // the argument and stored the key verbatim.
        let keys = KeySet::new(["user", "WccSysop"]);
        assert!(keys.holds("USER"));
        assert!(keys.holds("uSeR"));
        assert!(keys.holds("wccsysop"));
    }

    #[test]
    fn an_empty_lock_is_no_lock_and_everyone_passes_it() {
        // `LOCKNKEY.C:197` -- `if (lock[0] == '\0') return(1);`, checked
        // before the key set.
        assert!(KeySet::default().holds(""));
        assert!(KeySet::new(["USER"]).holds(""));
    }

    #[test]
    fn master_grants_every_lock_including_the_ones_that_ban_you() {
        // `flags&MASTER` returns 1 for *every* lock, and MajorMUD's namespace
        // has negative locks: NOPLAYKY {idiot} bans a user from the game. So a
        // master-flagged sysop holds `idiot`. Asserted rather than described,
        // because it is the reason nothing in this tree sets the flag.
        let sysop = KeySet::default().master(true);
        assert!(sysop.holds("WCCSYSOP"));
        assert!(sysop.holds("idiot"), "the trap: master holds the ban key too");
        assert!(sysop.holds("ANYTHINGATALL"));
    }

    #[test]
    fn a_channel_holding_nothing_refuses_every_named_lock() {
        let none = KeySet::default();
        assert!(!none.holds("USER"));
        assert!(!none.holds("WCCSYSOP"));
    }
}
