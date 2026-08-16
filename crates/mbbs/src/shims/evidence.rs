//! What backs a registered routine's behaviour.
//!
//! The 2026-08-15 scope rule says a symbol whose semantics cannot be confirmed
//! gets "an implementation plus a recorded uncertainty, not an
//! `Unimplemented` entry". Until now that recording was prose: the phrase
//! appeared in exactly one doc comment in the whole crate (`crt.rs:1037`) and
//! nothing enumerated it, so a guessed body was indistinguishable from a
//! confirmed one at the call site, in the test suite, and in any report.
//!
//! This makes the claim structural. It rides on the registration tuple rather
//! than a side table so that it is **compile-forced** -- a new routine cannot
//! land without someone deciding what backs it.
//!
//! Citations are checked against committed manifests (`re/vendor-bodies.tsv`,
//! `re/host-exports.tsv`) and never against the source trees, which are
//! gitignored and would make the check soft-skip on a fresh clone.

/// What backs a registered routine's behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {
    /// Ported from Galacticomm's own C. The path is relative to
    /// `re/wg33src` and must appear in `re/vendor-bodies.tsv`.
    VendorBody(&'static str),
    /// Written to a vendor prototype; the behaviour is reasoned from the
    /// signature and call sites, not copied from an implementation.
    VendorProto(&'static str),
    /// Behaviour matched against the genuine `MAJORBBS.EXE`. The symbol must
    /// appear in `re/host-exports.tsv` for the build the oracle runs.
    Oracle,
    /// ISO C, or documented Borland runtime semantics.
    Standard,
    /// Another project's implementation is the primary witness. The string
    /// names it, e.g. `"MBBSEmu Int21h.cs"`.
    Foreign(&'static str),
    /// Neither source nor oracle. The string is the argument for the guess,
    /// and exists so a reader can disagree with it.
    Guessed(&'static str),
    /// Nobody has checked. Honest, and a burn-down number.
    Unclassified,
}

impl Evidence {
    /// Does this claim rest on something outside Galacticomm's own material?
    ///
    /// These are the two variants [`crate::tests`] pins as a set, so that a
    /// guess can never land silently.
    pub fn is_unconfirmed(self) -> bool {
        matches!(self, Evidence::Foreign(_) | Evidence::Guessed(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foreign_and_guessed_are_the_unconfirmed_pair() {
        assert!(Evidence::Foreign("MBBSEmu Int21h.cs").is_unconfirmed());
        assert!(Evidence::Guessed("no witness survives").is_unconfirmed());
        assert!(!Evidence::VendorBody("SRC/x.C").is_unconfirmed());
        assert!(!Evidence::Oracle.is_unconfirmed());
        assert!(!Evidence::Standard.is_unconfirmed());
        // Unclassified is NOT unconfirmed: it is "not yet checked", which is a
        // different claim from "checked, and the witness is weak". Conflating
        // them would let the burn-down hide behind the guess pin.
        assert!(!Evidence::Unclassified.is_unconfirmed());
    }
}
