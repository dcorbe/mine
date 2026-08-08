//! How many channels this host has, and what it takes to name one.
//!
//! The host keys three separate things by channel. [`Users`](crate::Users)
//! holds four per-channel tables -- `user`, `extusr`, `uablok` and the keyring
//! -- sized as `MAJORBBS.C:735-736` and `ACCOUNT.C:109` sized theirs.
//! [`Gsbl`](crate::gsbl::Gsbl) holds one `Channel` per terminal. And the module
//! itself bounds its own loops by the `nterms` global this host writes into its
//! memory.
//!
//! Before this module those three agreed *by convention*: `Host::new` handed
//! the same constant to each of them and nothing checked the result. The
//! convention held, and it was invisible. Two call sites depended on it without
//! saying so -- `begin_polling` and `Host::dopoll` each resolve a channel
//! through `Users` and then inject a status into `Gsbl`, which is only the same
//! channel if the two tables are the same length.
//!
//! It was measured rather than argued. Building `Gsbl` one channel *shorter*
//! than `Users` failed 22 unit tests. Building it one channel *longer* passed
//! all 684, while `Gsbl::scan` handed `Host::poll` a channel that
//! `point_curusr` then refused -- so the host's own construction error arrived
//! dressed as a module stop, at a call site with nothing wrong with it. Silent
//! in exactly the direction that matters.
//!
//! [`Terms`] is that count, made a value instead of a convention, and [`Chan`]
//! is a channel number that has been checked against one. A table is built from
//! a `Terms`; a `Chan` minted by that same `Terms` is in range for it by
//! construction. So `Gsbl::inject` has no failure to return and no caller can
//! discard one.
//!
//! # What this does not do, and what had to be added because of it
//!
//! **A type alone did not close the silent direction, and the mutation that
//! proved it is worth keeping.** With `Chan` in place and nothing else, building
//! `Gsbl` a channel longer than `Users` *still* passed all 688 tests. The reason
//! is dull: at `nterms == 1` no code ever mints the channel-1 handle that would
//! index a table that does not have it, so the mismatched bound is never
//! exercised. What `Chan` guarantees is that such a handle cannot silently
//! index the wrong table -- it panics. It does not guarantee that anyone makes
//! one.
//!
//! So `Host::new` also asserts the three authorities against each other, and
//! reads `nterms` back out of module memory rather than trusting the value it
//! meant to write. Re-run under that assert, the same mutation fails 398 tests.
//! The type moves a silent wrong answer to a loud one; the assert is what makes
//! the construction error visible on the day it is made.
//!
//! `Terms::new` is public, so two of them holding different numbers is still
//! expressible. What it is not is *distributed*: `Host::new` binds one and uses
//! it three times, in three adjacent lines, and there is no longer a constant
//! reached for independently in each of them.

/// How many channels there are -- `nterms`, as a value.
///
/// `MAJORBBS.H:339` declares it `int nterms`, and `MAJORBBS.C:80` starts it at
/// one. Every table this host keys by channel is sized from one of these, and
/// [`Terms::chan`] is the only thing that turns a number the module supplied
/// into a [`Chan`] that may index them.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Terms(u16);

impl Terms {
    /// A host with `count` channels.
    ///
    /// # Panics
    ///
    /// If `count` is zero, or above `i16::MAX`. Neither is reachable from
    /// `MAJORBBS.C`: `:80` starts `nterms` at one, `:557` accumulates it per
    /// channel group as `numopt(msg+NUMBR1,1,256)` -- a floor of one, not zero
    /// -- and `:569` catastros above 256, so there is no path to a board with
    /// no channels. A zero here would make every `Chan` unmintable and every
    /// per-channel table empty, which is not a configuration -- it is a host
    /// that cannot do anything, discovered one confusing `None` at a time.
    #[must_use]
    pub fn new(count: u16) -> Self {
        assert!(count > 0, "a host with no channels cannot serve anyone");
        assert!(
            count <= i16::MAX as u16,
            "nterms is an int to the module; {count} channels cannot be named by one"
        );
        Self(count)
    }

    /// The count itself, for the module's `nterms` and for sizing a table.
    #[must_use]
    pub fn count(self) -> u16 {
        self.0
    }

    /// `n` as a channel of this host, or `None` if there is no such channel.
    ///
    /// This is `MAJORBBS.C:4293`'s `if (0 <= uno && uno < nterms)`, which
    /// `curusr` guards itself with and which `users.rs` used to restate. It is
    /// stated once now, and a `Chan` is the proof that it was asked.
    ///
    /// `i16` rather than `u16` because that is what the module pushes: a
    /// channel is an `int` in every prototype that takes one, and a module
    /// passing `-1` is passing a number this has to be able to refuse.
    #[must_use]
    pub fn chan(self, n: i16) -> Option<Chan> {
        (n >= 0 && (n as u16) < self.0).then_some(Chan(n as u16))
    }

    /// Every channel, in order.
    ///
    /// The replacement for `(0..host.users().terms() as i16)` and its several
    /// spellings, each of which had to get the cast and the bound right on its
    /// own.
    pub fn all(self) -> impl Iterator<Item = Chan> + Clone {
        (0..self.0).map(Chan)
    }
}

/// A channel number that names a channel of some [`Terms`].
///
/// Holding one is the whole guarantee: it was checked against a count, so the
/// tables built from that same count have a slot for it. Nothing here can be
/// constructed from a bare number -- [`Terms::chan`] and [`Terms::all`] are the
/// only two ways to get one, and both had to consult the bound to do it.
///
/// The original calls this `chan` in every GSBL prototype and `unum` or `uno`
/// in every MAJORBBS one. They are the same number; this crate keeps whichever
/// name the routine being reproduced used, and they all carry this type.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Chan(u16);

impl Chan {
    /// The channel number, as the module writes it -- for `usrnum`, for a
    /// message, and for anything that has to hand it back.
    #[must_use]
    pub fn number(self) -> i16 {
        self.0 as i16
    }

    /// The channel number as a table index.
    ///
    /// Separate from [`Chan::number`] so that `as usize` never has to appear at
    /// a call site, where it is one keystroke from `as u16` and both compile.
    #[must_use]
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

impl std::fmt::Display for Chan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_channel_number_is_checked_against_the_count_that_sized_the_tables() {
        let terms = Terms::new(4);
        for n in 0..4 {
            assert_eq!(
                terms.chan(n).expect("in range").number(),
                n,
                "channel {n} of four"
            );
        }
        assert!(terms.chan(4).is_none(), "one past the end");
        assert!(terms.chan(i16::MAX).is_none(), "far past the end");
    }

    #[test]
    fn a_negative_channel_is_refused_rather_than_wrapped() {
        // The reason `chan` takes `i16` and not `u16`. A module pushes an
        // `int`; `-1` reaching a `u16` parameter would arrive as 65,535 and be
        // refused for the wrong reason, which is fine at `nterms` 1 and is not
        // fine at `nterms` 65,535. Refusing the sign is refusing it for the
        // reason the original does: `MAJORBBS.C:4293` tests `0 <= uno` first.
        let terms = Terms::new(1);
        assert!(terms.chan(-1).is_none());
        assert!(terms.chan(i16::MIN).is_none());
    }

    #[test]
    fn every_channel_is_named_once_and_in_order() {
        let terms = Terms::new(3);
        let all: Vec<i16> = terms.all().map(Chan::number).collect();
        assert_eq!(all, vec![0, 1, 2]);
    }

    #[test]
    fn the_local_console_is_channel_zero_of_any_host() {
        // `MAJORBBS.C` reserves channel 0 for the operator console, so a host
        // with one channel has exactly that one and no other.
        let terms = Terms::new(1);
        assert_eq!(terms.chan(0).expect("channel zero").index(), 0);
        assert!(terms.chan(1).is_none());
    }

    #[test]
    #[should_panic(expected = "a host with no channels")]
    fn a_host_with_no_channels_is_refused_at_the_source() {
        let _ = Terms::new(0);
    }
}
