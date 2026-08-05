//! DOS filenames: the eleven bytes DOS matched on, and what a spec matches.
//!
//! `Host::dos_name` answers a different question -- which *directory* a module
//! is allowed to name -- and stays where it is. This is about the name itself.
//!
//! # The eleven bytes
//!
//! DOS did not match filenames as strings. It expanded both the spec and the
//! name into a fixed **eight bytes of stem and three of extension**, both
//! space-padded, and compared them byte for byte with `?` matching anything.
//! Two things follow that a shell-style glob gets wrong, and both are tested:
//!
//! - **`*` fills the rest of its own field with `?` and stops reading.**
//!   `AB*CD.DAT` is `AB??????DAT`.
//! - **`?` matches the padding**, so `A?.TXT` matches `A.TXT`.
//!
//! # What is deliberately refused
//!
//! A spec with a wildcard and no `.` -- `*`, `WCC*`, `??`. The FCB rule makes
//! `*` mean "no extension"; `COMMAND.COM` rewrote it to `*.*` before DOS ever
//! saw it. The two disagree, nothing in the call says which was meant, and no
//! call site in `WCCMMUD.DLL` sends one.

/// Bytes in the stem field of an FCB name.
const STEM: usize = 8;

/// Bytes in the extension field.
const EXT: usize = 3;

/// Bytes in the whole thing.
const FCB: usize = STEM + EXT;

/// Characters MS-DOS would not put in a filename, beyond the control codes and
/// the space.
///
/// `.` is here because it is the field separator and has already been consumed
/// by the time a field is being read; `\`, `/` and `:` because they are path
/// punctuation, which [`crate::Host::dos_name`] has refused before this is
/// reached. The rest are DOS's own reserved set.
const FORBIDDEN: &str = "\\/:.\"<>|+,;=[]";

/// A filename in the eleven bytes DOS matched on: an upper-cased stem and
/// extension, space-padded, with `?` standing for anything in a spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Name([u8; FCB]);

impl Name {
    /// The eleven bytes of a filename, or `None` for a name DOS could not have
    /// had.
    ///
    /// **`None` is not an error.** The question this answers is whether a
    /// `fnd1st`/`fndnxt` loop could ever have returned this entry, and for a
    /// Linux directory holding `slumpos.json` or `control_run.out` the answer is
    /// no. A scan skips those rather than refusing, because they are not files
    /// the module put there.
    pub fn parse(name: &str) -> Option<Self> {
        Self::fields(name, false)
    }

    /// The eleven bytes of a *spec*, in which `*` and `?` are wildcards.
    ///
    /// # Errors
    ///
    /// If it is not a spec DOS could have parsed, or if it is a wildcard with no
    /// extension -- see the module comment for why that one is refused rather
    /// than answered.
    pub fn spec(spec: &str) -> Result<Self, String> {
        if !spec.contains('.') && spec.contains(['*', '?']) {
            return Err(format!(
                "{spec} is a wildcard with no extension, and the two readings of \
                 one disagree: DOS's own match takes it as files with no \
                 extension at all, COMMAND.COM rewrote it to {spec}.*"
            ));
        }
        Self::fields(spec, true).ok_or_else(|| format!("{spec} is not a DOS file spec"))
    }

    /// Whether this, read as a template, matches `name`.
    ///
    /// `?` in the template matches any byte, including the space a short name
    /// pads with. Everything else is byte equality, both having been upper-cased
    /// on the way in.
    pub fn matches(&self, name: &Self) -> bool {
        self.0
            .iter()
            .zip(&name.0)
            .all(|(template, byte)| *template == b'?' || template == byte)
    }

    /// Split at the one dot DOS allowed and pack both fields.
    fn fields(text: &str, wild: bool) -> Option<Self> {
        let (stem, ext) = match text.split_once('.') {
            // A second dot is not a DOS name. `TWO.DOTS.C` never existed.
            Some((_, ext)) if ext.contains('.') => return None,
            Some(split) => split,
            None => (text, ""),
        };

        // A file with no stem is not a file. `.HIDDEN` is a Unix convention DOS
        // had no way to write down.
        if stem.is_empty() {
            return None;
        }

        let mut packed = [b' '; FCB];
        packed[..STEM].copy_from_slice(&field::<STEM>(stem, wild)?);
        packed[STEM..].copy_from_slice(&field::<EXT>(ext, wild)?);
        Some(Self(packed))
    }
}

/// Pack one field to exactly `N` bytes, or `None` if it is not one.
fn field<const N: usize>(text: &str, wild: bool) -> Option<[u8; N]> {
    let mut out = [b' '; N];
    for (at, c) in text.chars().enumerate() {
        match c {
            // The rest of the field, and the rest of the text is not read:
            // `AB*CD` is `AB??????`, which is DOS's expansion and not a
            // simplification of it.
            '*' if wild => {
                out[at..].fill(b'?');
                return Some(out);
            }
            '?' if wild => {}
            '*' | '?' => return None,
            c if !c.is_ascii_graphic() || FORBIDDEN.contains(c) => return None,
            _ => {}
        }
        // Checked after the `*` arm, because a `*` in the last position has
        // nothing left to fill and is still legal.
        if at == N {
            return None;
        }
        out[at] = c.to_ascii_uppercase() as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Match a spec against a name, the way [`crate::shims::stream::cntdir`]
    /// does: parse both, then compare.
    fn hits(spec: &str, name: &str) -> bool {
        let spec = Name::spec(spec).expect("a spec");
        Name::parse(name).is_some_and(|name| spec.matches(&name))
    }

    #[test]
    fn a_literal_spec_matches_only_that_name_in_any_case() {
        assert!(hits("wccupdat.dat", "WCCUPDAT.DAT"));
        assert!(hits("WCCUPDAT.DAT", "wccupdat.dat"));
        assert!(!hits("WCCUPDAT.DAT", "WCCUPDAT.VIR"));
        assert!(!hits("WCCUPDAT.DAT", "WCCUPDA.DAT"));
    }

    #[test]
    fn star_fills_its_own_field_and_no_other() {
        assert!(hits("*.DAT", "SAMPLE.DAT"));
        assert!(!hits("*.DAT", "SAMPLE.MSG"));
        assert!(hits("SAMPLE.*", "SAMPLE.MSG"));
        assert!(!hits("SAMPLE.*", "OTHER.MSG"));
        assert!(hits("*.*", "SAMPLE.DAT"));
        // `*.*` reaches a file with no extension too: its extension field pads
        // to three spaces, and `?` matches a space.
        assert!(hits("*.*", "README"));
    }

    #[test]
    fn star_stops_reading_its_field() {
        // DOS expands `*` to as many `?` as the field has room for and ignores
        // the rest, so `AB*CD` is `AB??????` -- `ABZZ.DAT` matches even though
        // it has no `CD` in it. A shell-style matcher would say no.
        assert!(hits("AB*CD.DAT", "ABZZ.DAT"));
    }

    #[test]
    fn question_matches_the_padding() {
        // `A?.TXT` is `A?      TXT`, and `A.TXT` pads to `A       TXT`.
        assert!(hits("A?.TXT", "A.TXT"));
        assert!(hits("A?.TXT", "AB.TXT"));
        assert!(!hits("A?.TXT", "ABC.TXT"));
    }

    #[test]
    fn a_wildcard_with_no_extension_is_refused_rather_than_guessed() {
        // The FCB rule makes `*` mean "no extension"; COMMAND.COM rewrote it to
        // `*.*` before DOS saw it. Two answers, and nothing in the call says
        // which was meant.
        for spec in ["*", "??", "WCC*"] {
            assert!(Name::spec(spec).is_err(), "{spec}");
        }
        // With the dot there is no ambiguity, and `*.` is a real spec meaning
        // "no extension".
        assert!(Name::spec("*.").is_ok());
    }

    #[test]
    fn a_name_that_dos_could_not_have_had_is_not_a_name() {
        // Not that these are refusals -- they are names no `fnd1st` loop could
        // ever have returned, so a scan skips them. Nine characters of stem,
        // four of extension, two dots, a character DOS forbids, and the two
        // wildcards, which are illegal in a name however legal in a spec.
        for name in [
            "TOOLONGNM.TXT",
            "NAME.JSON",
            "TWO.DOTS.C",
            "A+B.TXT",
            "WHAT?.TXT",
            ".HIDDEN",
        ] {
            assert!(Name::parse(name).is_none(), "{name}");
        }
        assert!(Name::parse("README").is_some());
        assert!(Name::parse("SAMPLE.DAT").is_some());
    }

    #[test]
    fn a_spec_is_not_a_name_and_a_name_is_not_a_spec() {
        // `parse` refuses the wildcards `spec` accepts, so a host file that
        // happens to be called `*.DAT` cannot match everything.
        assert!(Name::parse("*.DAT").is_none());
        assert!(Name::spec("SAMPLE.DAT").is_ok());
    }
}
