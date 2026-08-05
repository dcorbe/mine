//! Full-Screen Data Entry: what a form costs before anyone fills it in.
//!
//! A module describes a data-entry screen with two strings. The **template** is
//! a message out of its `.MCV` -- literal text with runs of `?`, `$` and `#`
//! standing where answers go. The **field specification** is a list of field
//! names with options: `TOT_STR(MIN=10, MAX=250)`. `fsdroom` reads the pair and
//! answers one question: how many bytes a session over them will need.
//!
//! # Why this is a compiler and not a formula
//!
//! The answer is `mbleng + numfld*sizeof(struct fsdfld) + maxans + 1`, and two
//! of those three terms can only be had by scanning both strings: `maxans` is
//! the sum of every field's name length and every field's width, and `mbleng`
//! is the length of the embedded-punctuation templates built for the fields
//! that have any. There is no shortcut, which is why this file exists.
//!
//! # Ported from source, not inferred
//!
//! `FSD.C` and `FSDBBS.C` both survive in `archive/`, so unlike `rtkick` this
//! is a port rather than a reconstruction. The four passes below are
//! `fspscn()`, `chkops()`, `tmpscn()` and `embscn()` -- `FSD.C:175`, `:230`,
//! `:299` and `:433` -- run in that order by `fsdppc()` at `FSD.C:463`.
//!
//! # Only the non-ANSI half is here
//!
//! `fsdppc(templt, ascn)` takes `ascn=1` when an ANSI entry session is coming,
//! and that path drives a full curses layer: `setwin`, `locate`, `curcury`,
//! `curatr`, and a `printf` of the template into a virtual screen so that each
//! field's cursor-goto string can be read back off it. This host has none of
//! that, and MajorMUD does not ask for it -- both of its calls are `amode=0`.
//! At `ascn=0` every one of those branches is skipped and the whole of
//! `fsdppc` is a pure function of two byte strings, which is what this is.
//!
//! # Two overflows of the original are not reproduced
//!
//! `tmpfld()` takes its `width` as a `char` and `xwidth` is a `char`, so in the
//! original a field run longer than 127 characters wraps *before* being clamped
//! to `ANSLEN` -- a 200-character run becomes -56, sails past `> ANSLEN`, and
//! is then added to `maxans` as a subtraction. This clamps instead. No template
//! in evidence comes near it: the longest run in either of MajorMUD's is 61,
//! and a field wider than a screen is not a thing a form can mean.

use std::fmt;

/// Maximum length of any one answer. `FSD.H:238`.
const ANSLEN: u16 = 80;

/// Maximum length of a field name. `FSD.H:240`.
const FLDNAM: u16 = 12;

/// Maximum length of the help field. `FSD.H:243`.
const MAXHLP: u16 = 80;

/// Maximum size of the embedded-punctuation array. `FSDBBS.H:208`.
pub const MBPMAX: u16 = 200;

/// `sizeof(struct fsdfld)`.
///
/// **A constant, not `size_of::<Field>()`.** The number is part of the answer
/// `fsdroom` returns, so it is the 16-bit compiler's layout of the C struct
/// that matters and not this crate's layout of the Rust one -- which omits the
/// two members `fsdans()` fills in and would be a different size. `FSD.H:262`
/// states it outright: `/* (23 bytes long) */`.
pub const FSDFLD: u16 = 23;

/// What a template character means. `FSD.C:44`'s `tmpspc[]` table.
///
/// The table has **256 entries** and its top half is entirely zero, which is
/// how it is known to be indexed by the unsigned byte: half of it would be dead
/// if only ASCII were expected. That is not academic here -- MajorMUD's ANSI
/// template carries 194 bytes with the high bit set, all of it box-drawing
/// decoration, and reading them as anything but [`Kind::Junk`] would invent
/// fields out of the borders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Ordinary text: copied, counted, and otherwise ignored.
    Junk,
    /// White space, which is also what ends a run of subfields.
    White,
    /// `=`. Named by the table, treated as [`Kind::Junk`] by every reader.
    Equ,
    /// `/`, which makes a `Y/N` field out of the characters either side.
    Slash,
    /// `!`, the help field.
    Exc,
    /// `$`, a numeric field.
    Dol,
    /// `#`, a field that may carry embedded punctuation.
    Pnd,
    /// `?`, a text field, which may also carry embedded punctuation.
    Qst,
}

impl Kind {
    /// Whether a second run of this character can extend the field before it.
    ///
    /// `FSD.C:64`'s `TMPSFD`, which is `#define`d to `TMPPND` and compared with
    /// `tmpidx >= TMPSFD` -- so `#` and `?` qualify and `$` and `!` do not.
    /// Written as a set rather than an ordering because the ordering is an
    /// accident of the numbering.
    fn joins(self) -> bool {
        matches!(self, Self::Pnd | Self::Qst)
    }

    /// What `tmpspc[]` says about one byte.
    fn of(b: u8) -> Self {
        match b {
            // Note that `\v` is absent, deliberately: the table marks 9, 10, 12
            // and 13, and `\v` is 11. `isspace` disagrees, and both are used.
            b'\t' | b'\n' | 0x0c | b'\r' | b' ' => Self::White,
            b'!' => Self::Exc,
            b'#' => Self::Pnd,
            b'$' => Self::Dol,
            b'/' => Self::Slash,
            b'=' => Self::Equ,
            b'?' => Self::Qst,
            _ => Self::Junk,
        }
    }
}

/// C's `isspace` in the C locale, which is **not** [`Kind::White`].
///
/// The two differ by the vertical tab, and the difference is real: `fspscn`
/// splits field names on `isspace` while `tmpscn` ends a subfield run on
/// `tmpspc`. Collapsing them would be a plausible-looking simplification that
/// changes what a template means.
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | 0x09..=0x0d)
}

/// One field of a form, as `fsdppc` computes it.
///
/// The two members the C struct has that this does not -- `ansoff` and `anslen`
/// -- belong to `fsdans()`, which installs an answer string. Nothing here has
/// an answer. See [`FSDFLD`] for why leaving them out costs nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    /// How many characters of answer fit, punctuation excluded.
    pub width: u8,

    /// How many characters the field occupies in the template, punctuation
    /// included. Equal to `width` unless subfields joined.
    pub xwidth: u8,

    /// The display attribute. Always `0x07` off the ANSI path.
    pub attr: u8,

    /// `FFF*` bits, from the field's options. See [`flags`].
    pub flags: u8,

    /// The template character that made it: `?`, `$`, `#` or `Y`.
    pub kind: u8,

    /// Where the field's name starts in the field specification.
    pub spec_at: u16,

    /// Where the field starts in the template.
    pub template_at: u16,

    /// Where this field's punctuation template starts in
    /// [`Form::punctuation`], or `None` if it has none.
    pub punctuation_at: Option<u16>,
}

/// The `FFF*` field flags. `FSD.H:265-273`.
pub mod flags {
    /// Multiple choice field.
    pub const MULTICHOICE: u8 = 0x01;
    /// Has at least some alternate values.
    pub const ALTERNATES: u8 = 0x02;
    /// Has a minimum and/or maximum.
    pub const MINMAX: u8 = 0x04;
    /// Does not accept spaces.
    pub const NOSPACES: u8 = 0x08;
    /// No negative numbers allowed.
    pub const NONNEGATIVE: u8 = 0x20;
    /// Entry needs to be secret.
    pub const SECRET: u8 = 0x40;
}

/// A compiled form: what a data-entry session over one template will need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Form {
    /// Every field the specification names, in order.
    pub fields: Vec<Field>,

    /// How many of them the template actually has room for.
    ///
    /// `numtpl`, and never more than `fields.len()`: a template with more field
    /// runs than the specification has names ignores the extra runs, which is
    /// not an error and is what MajorMUD's ASCII screen does with its trailing
    /// `CP Available: $$$$`.
    pub in_template: usize,

    /// The embedded-punctuation templates, NUL-separated. `mbpunc`.
    pub punctuation: Vec<u8>,

    /// The longest answer string the session could produce, NUL excluded.
    pub answer_max: u16,

    /// The help field's length, or `0` if the template has no `!` run.
    pub help_len: u8,

    /// Where the help field starts in the template.
    pub help_at: u16,

    /// Everything wrong with the pair, in the order found.
    ///
    /// The real host counts these and hands the first to `catastro`, which is
    /// why the count and the first message are both kept.
    pub errors: Vec<String>,
}

impl Form {
    /// How many bytes a session over this form needs. `FSDBBS.C:152`.
    ///
    /// # Errors
    ///
    /// If the total will not fit in the `int` the module reads it back as. The
    /// real host would have wrapped silently and returned a negative, which
    /// `dclvda` would then have ignored -- a form too big to size, sized wrong,
    /// with nothing said.
    pub fn size(&self) -> Result<u16, FormError> {
        let total = self.punctuation.len() as u32
            + self.fields.len() as u32 * u32::from(FSDFLD)
            + u32::from(self.answer_max)
            + 1;
        u16::try_from(total).map_err(|_| FormError::TooBig(total))
    }
}

/// Why a form could not be sized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormError {
    /// The session would need more bytes than an `int` can report.
    TooBig(u32),
}

impl fmt::Display for FormError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooBig(n) => write!(f, "a session needing {n} bytes does not fit in an int"),
        }
    }
}

impl std::error::Error for FormError {}

/// Compile a template and a field specification. `fsdppc()`, `FSD.C:463`.
///
/// `max_fields` is the host's `maxfld`: how many `struct fsdfld` fit in the
/// output buffer beside the punctuation array. Scanning stops there rather than
/// running off the end of a buffer the caller has not got.
pub fn compile(template: &[u8], spec: &[u8], max_fields: u16) -> Form {
    let mut form = Form {
        fields: Vec::new(),
        in_template: 0,
        punctuation: Vec::new(),
        answer_max: 0,
        help_len: 0,
        help_at: 0,
        errors: Vec::new(),
    };
    spec_scan(&mut form, spec, max_fields);
    options(&mut form, spec);
    form
}

/// `fspscn()`, `FSD.C:175`: split the specification into named fields.
fn spec_scan(form: &mut Form, spec: &[u8], max_fields: u16) {
    let end = spec.iter().position(|b| *b == 0).unwrap_or(spec.len());
    let spec = &spec[..end];

    let mut at = 0usize;
    while form.fields.len() < usize::from(max_fields) && at < spec.len() {
        while at < spec.len() && is_space(spec[at]) {
            at += 1;
        }
        if at >= spec.len() {
            break;
        }

        let name_at = at;
        while at < spec.len() && !is_space(spec[at]) && spec[at] != b'(' {
            at += 1;
            form.answer_max = form.answer_max.saturating_add(1);
        }
        // Room for '=', a NUL and one extra, per field, always.
        form.answer_max = form.answer_max.saturating_add(3);

        let name_len = at - name_at;
        if name_len > usize::from(FLDNAM) {
            form.errors.push(format!(
                "Field name \"{}\" too long",
                String::from_utf8_lossy(&spec[name_at..at])
            ));
        }

        if at < spec.len() && spec[at] == b'(' {
            while at < spec.len() && spec[at] != b')' {
                at += 1;
            }
            if at < spec.len() {
                at += 1;
            } else {
                form.errors.push(format!(
                    "Field spec \"{}\" missing ')'",
                    String::from_utf8_lossy(&spec[name_at..])
                ));
            }
        }

        form.fields.push(Field {
            width: 0,
            xwidth: 0,
            attr: 0,
            flags: 0,
            kind: 0,
            spec_at: name_at as u16,
            template_at: 0,
            punctuation_at: None,
        });
    }
}

/// `nxttkn()`, `FSD.C:103`: find `token` in an option list.
///
/// Returns where the option's value begins. The first byte is compared exactly
/// and the rest through `sameto`, which ignores case -- so `MIN=` matches
/// `MIN=` and `MiN=` but not `min=`. That asymmetry is in the original
/// (`c == t && sameto(token,cp)`) and is kept, because a field spec written in
/// lower case would then set no flags and the difference would show up as a
/// missing minimum rather than as an error.
fn next_token(list: &[u8], from: usize, token: &[u8], word: bool) -> Option<usize> {
    let mut at = from;
    let mut i = 0usize;
    while at < list.len() && list[at] != 0 && list[at] != b')' {
        let matches = list[at] == token[0]
            && list.len() - at >= token.len()
            && list[at..at + token.len()].eq_ignore_ascii_case(token)
            && (i == 0 || is_space(list[at - 1]))
            && (!word
                || match list.get(at + token.len()) {
                    None => true,
                    Some(&e) => e == 0 || is_space(e) || e == b')',
                });
        if matches {
            return Some(at + token.len());
        }
        at += 1;
        i += 1;
    }
    None
}

/// `foptkn()`, `FSD.C:127`: find `token` among one field's options.
///
/// The `fldtyp == 'Y'` branch of the original substitutes a synthetic
/// `(ALT=NO ALT=YES)` list. It cannot fire from here: `chkops` clears `fldtyp`
/// on the line above its first call, and only `embscn` ever sets it. It exists
/// for the entry-session callers this host does not have.
fn field_token(spec: &[u8], field: &Field, token: &[u8], word: bool) -> Option<usize> {
    let mut at = usize::from(field.spec_at);
    while at < spec.len() && spec[at] != b'(' {
        if spec[at] == 0 || is_space(spec[at]) {
            return None;
        }
        at += 1;
    }
    if at >= spec.len() {
        return None;
    }
    next_token(spec, at + 1, token, word)
}

/// `chkops()`, `FSD.C:230`: read each field's options into its flags.
///
/// None of this changes the size. It is here because [`Form`] is something a
/// caller can read, and a `flags` that was always zero would be a stored answer
/// that happened to be wrong rather than an answer this host declined to give.
fn options(form: &mut Form, spec: &[u8]) {
    for field in &mut form.fields {
        field.flags = 0;
        field.kind = 0;
        if let Some(at) = field_token(spec, field, b"MIN=", false) {
            field.flags |= flags::MINMAX;
            if spec.get(at) != Some(&b'-') {
                field.flags |= flags::NONNEGATIVE;
            }
        }
        if field_token(spec, field, b"MAX=", false).is_some() {
            field.flags |= flags::MINMAX;
        }
        if field_token(spec, field, b"MULTICHOICE", true).is_some() {
            field.flags |= flags::MULTICHOICE;
        }
        if field_token(spec, field, b"ALT=", false).is_some() {
            field.flags |= flags::ALTERNATES;
        }
        if field_token(spec, field, b"NOSPACES", true).is_some() {
            field.flags |= flags::NOSPACES;
        }
        if field_token(spec, field, b"SECRET", true).is_some() {
            field.flags |= flags::SECRET;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The maximum this host's 4,096-byte output buffer allows. See the
    /// `fsdroom` shim for where it comes from; a unit test just needs a number
    /// big enough not to be the thing under test.
    const MANY: u16 = 169;

    #[test]
    fn a_field_spec_is_a_list_of_names() {
        let form = compile(b"", b"ONE TWO THREE", MANY);
        assert_eq!(form.fields.len(), 3);
        assert_eq!(form.errors, Vec::<String>::new());

        // Each name costs its own length plus three: an '=', a NUL, and one
        // spare, which `fspscn` adds per field whatever else happens.
        assert_eq!(form.answer_max, (3 + 3) + (3 + 3) + (5 + 3));
    }

    #[test]
    fn options_are_read_into_flags() {
        let form = compile(b"", b"A(MIN=10, MAX=250) B(MULTICHOICE) C(SECRET)", MANY);
        assert_eq!(form.fields.len(), 3);
        assert_eq!(form.fields[0].flags, flags::MINMAX | flags::NONNEGATIVE);
        assert_eq!(form.fields[1].flags, flags::MULTICHOICE);
        assert_eq!(form.fields[2].flags, flags::SECRET);
    }

    #[test]
    fn a_negative_minimum_is_what_clears_the_non_negative_flag() {
        // `chkops` sets FFFNNG unless the character after `MIN=` is '-'. It is
        // the only thing that reads the option's *value*, so it is the only
        // place a wrong pointer into the spec would show.
        let form = compile(b"", b"A(MIN=-10)", MANY);
        assert_eq!(form.fields[0].flags, flags::MINMAX);
    }

    #[test]
    fn an_option_list_that_never_closes_is_an_error_and_not_a_panic() {
        let form = compile(b"", b"A(MIN=1", MANY);
        assert_eq!(form.fields.len(), 1);
        assert_eq!(form.errors.len(), 1);
        assert!(form.errors[0].contains("missing ')'"), "{:?}", form.errors);
    }

    #[test]
    fn a_name_longer_than_fldnam_is_named() {
        let form = compile(b"", b"A_VERY_LONG_NAME_INDEED", MANY);
        assert_eq!(form.errors.len(), 1);
        assert!(form.errors[0].contains("too long"), "{:?}", form.errors);
    }

    #[test]
    fn scanning_stops_at_the_field_limit() {
        let form = compile(b"", b"A B C D E", 3);
        assert_eq!(form.fields.len(), 3);
    }
}
