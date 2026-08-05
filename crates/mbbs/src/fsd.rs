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

use mbbs16::FarPtr;

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

/// `sizeof(struct fsdscb)`, `FSD.H:275`.
///
/// The host allocates this many bytes, and the `fsdscb` global points at them,
/// so the number is load-bearing the same way [`FSDFLD`] is: the module reaches
/// into the structure with offsets its compiler baked in.
pub const FSDSCB: u16 = 166;

/// Where each member of `struct fsdscb` sits. `FSD.H:275`.
///
/// **Byte alignment, not word.** Borland's default (`-a-`), and not an
/// assumption: `FSD.H:262` documents `struct fsdfld` as 23 bytes, and word
/// alignment would pad it to 24. Two of the offsets below are settled a second
/// time by `WCCMMUD.DLL` itself, which reaches `flddat` as `[fsdscb+4]` at
/// `seg 3:0x4340` and pushes `newans` from `[fsdscb+12]` at `seg 3:0x2d46`.
///
/// Only the members this host sets or reads are named. The rest -- `ansbuf`,
/// `typahd`, `state` and the other entry-session working storage -- are
/// deliberately absent and deliberately preserved: [`Scb`] keeps the bytes it
/// does not model rather than zeroing them.
pub mod scb {
    /// `char *fldspc` -- the field specification, in the module's memory.
    pub const FLDSPC: u16 = 0;
    /// `struct fsdfld *flddat` -- the field array, in the session buffer.
    pub const FLDDAT: u16 = 4;
    /// `char *mbpunc` -- the embedded-punctuation templates.
    pub const MBPUNC: u16 = 8;
    /// `char *newans` -- the answer string this session is building.
    pub const NEWANS: u16 = 12;
    /// `char crsatr` -- the attribute of the field the cursor is on.
    pub const CRSATR: u16 = 20;
    /// `int numfld` -- how many fields the specification names.
    pub const NUMFLD: u16 = 21;
    /// `int numtpl` -- how many of them the template has room for.
    pub const NUMTPL: u16 = 23;
    /// `int mbleng` -- bytes of punctuation template.
    pub const MBLENG: u16 = 25;
    /// `int maxans` -- the longest answer string this form can produce.
    pub const MAXANS: u16 = 27;
    /// `char hlplen` -- the help field's width, or 0.
    pub const HLPLEN: u16 = 29;
    /// `int hlpoff` -- where the help field starts in the template.
    pub const HLPOFF: u16 = 40;
    /// `int allans` -- the answer string's current length.
    pub const ALLANS: u16 = 42;
}

/// Where each member of `struct fsdfld` sits. `FSD.H:247`.
///
/// `FLAGS` at 12 is not read off the header alone: fourteen sites in
/// `WCCMMUD.DLL` do `or byte [flddat + 23*i + 12], 0x80`, marking the fields a
/// player may see but not type into.
pub mod fld {
    /// `char ansgto[GTOLEN+1]` -- the ANSI cursor-goto command.
    pub const ANSGTO: usize = 0;
    /// `char width`.
    pub const WIDTH: usize = 9;
    /// `char xwidth`.
    pub const XWIDTH: usize = 10;
    /// `char attr`.
    pub const ATTR: usize = 11;
    /// `char flags`.
    pub const FLAGS: usize = 12;
    /// `char fldtyp`.
    pub const FLDTYP: usize = 13;
    /// `int fspoff`.
    pub const FSPOFF: usize = 14;
    /// `int tmpoff`.
    pub const TMPOFF: usize = 16;
    /// `int mbpoff`.
    pub const MBPOFF: usize = 18;
    /// `int ansoff`.
    pub const ANSOFF: usize = 20;
    /// `char anslen`.
    pub const ANSLEN: usize = 22;
}

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

impl Field {
    /// This field as the 23 bytes `struct fsdfld` occupies in module memory.
    ///
    /// `ansoff` and `anslen` are arguments rather than members for the reason
    /// [`FSDFLD`] gives: they are not this field's to know. `fsdans()` computes
    /// them when an answer string is installed, and a [`Form`] describes a form
    /// nobody has answered.
    ///
    /// `ansgto` is left zero. The original never writes it off the ANSI path --
    /// `fsdppc(templt, 0)` skips every branch that would -- so the real host
    /// left whatever `alczer` or the stack had put there. Zero is that, and it
    /// is the same zero every run.
    pub fn record(&self, ansoff: u16, anslen: u8) -> [u8; FSDFLD as usize] {
        let mut out = [0u8; FSDFLD as usize];
        out[fld::ANSGTO] = 0;
        out[fld::WIDTH] = self.width;
        out[fld::XWIDTH] = self.xwidth;
        out[fld::ATTR] = self.attr;
        out[fld::FLAGS] = self.flags;
        out[fld::FLDTYP] = self.kind;
        out[fld::FSPOFF..fld::FSPOFF + 2].copy_from_slice(&self.spec_at.to_le_bytes());
        out[fld::TMPOFF..fld::TMPOFF + 2].copy_from_slice(&self.template_at.to_le_bytes());
        // `-1`, not `0`: `tmpfld()` writes -1 for a field with no embedded
        // punctuation and `embscn()` overwrites only the ones that joined, so a
        // zero here would name the first punctuation template rather than none.
        let mbpoff = self.punctuation_at.map_or(-1i16, |at| at as i16);
        out[fld::MBPOFF..fld::MBPOFF + 2].copy_from_slice(&mbpoff.to_le_bytes());
        out[fld::ANSOFF..fld::ANSOFF + 2].copy_from_slice(&ansoff.to_le_bytes());
        out[fld::ANSLEN] = anslen;
        out
    }
}

/// `struct fsdscb`, as a block of bytes with named members.
///
/// The bytes are kept whole rather than parsed into a Rust struct, for the
/// reason `globals.rs` opens with: this is the *module's* view of the session,
/// and the module writes through it. Round-tripping every byte -- including the
/// entry session's `ansbuf`, `typahd` and `state`, which this host never sets
/// -- means a member nobody modelled cannot be quietly zeroed by a member
/// somebody did.
///
/// No `Machine` here on purpose. Reading and writing module memory belongs to
/// the shims; this is the layout and nothing else, which is what keeps this
/// module testable with no machine present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scb {
    bytes: [u8; FSDSCB as usize],
}

impl Scb {
    /// Read a control block out of exactly [`FSDSCB`] bytes.
    ///
    /// # Errors
    ///
    /// If `bytes` is not that long. A caller resolving a far pointer has asked
    /// for the length already, so this is the second half of one check rather
    /// than a new one.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FormError> {
        let bytes: [u8; FSDSCB as usize] = bytes
            .try_into()
            .map_err(|_| FormError::ShortBlock(bytes.len()))?;
        Ok(Self { bytes })
    }

    /// The block, for writing back where it came from.
    pub fn as_bytes(&self) -> &[u8; FSDSCB as usize] {
        &self.bytes
    }

    fn ptr(&self, at: u16) -> FarPtr {
        let at = usize::from(at);
        FarPtr::from_bytes([
            self.bytes[at],
            self.bytes[at + 1],
            self.bytes[at + 2],
            self.bytes[at + 3],
        ])
    }

    fn set_ptr(&mut self, at: u16, value: FarPtr) {
        let at = usize::from(at);
        self.bytes[at..at + 4].copy_from_slice(&value.to_bytes());
    }

    fn word(&self, at: u16) -> u16 {
        let at = usize::from(at);
        u16::from_le_bytes([self.bytes[at], self.bytes[at + 1]])
    }

    fn set_word(&mut self, at: u16, value: u16) {
        let at = usize::from(at);
        self.bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn byte(&self, at: u16) -> u8 {
        self.bytes[usize::from(at)]
    }

    fn set_byte(&mut self, at: u16, value: u8) {
        self.bytes[usize::from(at)] = value;
    }

    /// `fldspc`: the field specification, in the module's memory.
    pub fn fldspc(&self) -> FarPtr {
        self.ptr(scb::FLDSPC)
    }
    /// Set [`Scb::fldspc`].
    pub fn set_fldspc(&mut self, value: FarPtr) {
        self.set_ptr(scb::FLDSPC, value);
    }

    /// `flddat`: the array of [`Field::record`]s, in the session buffer.
    pub fn flddat(&self) -> FarPtr {
        self.ptr(scb::FLDDAT)
    }
    /// Set [`Scb::flddat`].
    pub fn set_flddat(&mut self, value: FarPtr) {
        self.set_ptr(scb::FLDDAT, value);
    }

    /// `mbpunc`: the embedded-punctuation templates.
    pub fn mbpunc(&self) -> FarPtr {
        self.ptr(scb::MBPUNC)
    }
    /// Set [`Scb::mbpunc`].
    pub fn set_mbpunc(&mut self, value: FarPtr) {
        self.set_ptr(scb::MBPUNC, value);
    }

    /// `newans`: the answer string this session is building.
    pub fn newans(&self) -> FarPtr {
        self.ptr(scb::NEWANS)
    }
    /// Set [`Scb::newans`].
    pub fn set_newans(&mut self, value: FarPtr) {
        self.set_ptr(scb::NEWANS, value);
    }

    /// `crsatr`: the attribute of the field the cursor is on.
    pub fn crsatr(&self) -> u8 {
        self.byte(scb::CRSATR)
    }
    /// Set [`Scb::crsatr`].
    pub fn set_crsatr(&mut self, value: u8) {
        self.set_byte(scb::CRSATR, value);
    }

    /// `numfld`: how many fields the specification names.
    pub fn numfld(&self) -> u16 {
        self.word(scb::NUMFLD)
    }
    /// Set [`Scb::numfld`].
    pub fn set_numfld(&mut self, value: u16) {
        self.set_word(scb::NUMFLD, value);
    }

    /// `numtpl`: how many of them the template has room for.
    pub fn numtpl(&self) -> u16 {
        self.word(scb::NUMTPL)
    }
    /// Set [`Scb::numtpl`].
    pub fn set_numtpl(&mut self, value: u16) {
        self.set_word(scb::NUMTPL, value);
    }

    /// `mbleng`: bytes of punctuation template.
    pub fn mbleng(&self) -> u16 {
        self.word(scb::MBLENG)
    }
    /// Set [`Scb::mbleng`].
    pub fn set_mbleng(&mut self, value: u16) {
        self.set_word(scb::MBLENG, value);
    }

    /// `maxans`: the longest answer string this form can produce.
    pub fn maxans(&self) -> u16 {
        self.word(scb::MAXANS)
    }
    /// Set [`Scb::maxans`].
    pub fn set_maxans(&mut self, value: u16) {
        self.set_word(scb::MAXANS, value);
    }

    /// `hlplen`: the help field's width, or 0.
    pub fn hlplen(&self) -> u8 {
        self.byte(scb::HLPLEN)
    }
    /// Set [`Scb::hlplen`].
    pub fn set_hlplen(&mut self, value: u8) {
        self.set_byte(scb::HLPLEN, value);
    }

    /// `hlpoff`: where the help field starts in the template.
    pub fn hlpoff(&self) -> u16 {
        self.word(scb::HLPOFF)
    }
    /// Set [`Scb::hlpoff`].
    pub fn set_hlpoff(&mut self, value: u16) {
        self.set_word(scb::HLPOFF, value);
    }

    /// `allans`: the answer string's current length, final NUL included.
    pub fn allans(&self) -> u16 {
        self.word(scb::ALLANS)
    }
    /// Set [`Scb::allans`].
    pub fn set_allans(&mut self, value: u16) {
        self.set_word(scb::ALLANS, value);
    }
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

    /// A session control block was read from fewer bytes than one is.
    ShortBlock(usize),
}

impl fmt::Display for FormError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooBig(n) => write!(f, "a session needing {n} bytes does not fit in an int"),
            Self::ShortBlock(n) => {
                write!(f, "a session control block is {FSDSCB} bytes, not {n}")
            }
        }
    }
}

impl std::error::Error for FormError {}

/// A field's name in the specification, whole. What `fsdans()` writes out.
///
/// The specification text from the field's `fspoff` up to the first NUL, white
/// space or `(`, and **not** clamped to [`FLDNAM`] -- `fsdans()`'s copy loop
/// (`FSD.C:514`) has no such clamp, and `maxans` was counted the same way, so
/// truncating here would put fewer bytes in the answer string than `fsdroom`
/// reserved room for. A name longer than `FLDNAM` is an error `fsdppc` reports
/// and `fsdroom` refuses on, so the difference is unreachable in practice and
/// kept anyway because the two C routines really do differ.
fn spec_name<'a>(spec: &'a [u8], field: &Field) -> &'a [u8] {
    let from = usize::from(field.spec_at).min(spec.len());
    let rest = &spec[from..];
    let end = rest
        .iter()
        .position(|&c| c == 0 || is_space(c) || c == b'(')
        .unwrap_or(rest.len());
    &rest[..end]
}

/// A field's name, as `fldnmi()` reports it. `FSD.C:2155`.
///
/// [`spec_name`] clamped to [`FLDNAM`], because the original copies into a
/// `char[FLDNAM+1]` and stops at `i++ < FLDNAM`.
pub fn name_of<'a>(spec: &'a [u8], field: &Field) -> &'a [u8] {
    let name = spec_name(spec, field);
    &name[..name.len().min(usize::from(FLDNAM))]
}

/// Where a field's value begins in an answer string. `fsdxan()`, `FSD.C:2073`.
///
/// An answer string is a run of NUL-terminated `NAME=value` entries ended by an
/// empty one, so this walks entries rather than scanning bytes.
///
/// `None` when the name is not there. The original says the same thing by
/// returning a pointer to the string's final `'\0'`, which reads as `""` --
/// the caller cannot tell the two apart, and `""` is what a missing answer
/// means. Kept as an [`Option`] so that a caller who needs the difference has
/// it; [`answers`] does not.
///
/// Matching is `sameto` -- case-insensitive -- **and then** a check that the
/// next byte is `'='`. That second half is what stops the field `NAME` from
/// matching the answer `NAMEX=1`.
pub fn extract(answers: &[u8], name: &[u8]) -> Option<usize> {
    let mut at = 0usize;
    while at < answers.len() && answers[at] != 0 {
        let end = answers[at..]
            .iter()
            .position(|&c| c == 0)
            .map_or(answers.len(), |n| at + n);
        let entry = &answers[at..end];
        if entry.len() > name.len()
            && entry[..name.len()].eq_ignore_ascii_case(name)
            && entry[name.len()] == b'='
        {
            return Some(at + name.len() + 1);
        }
        at = end + 1;
    }
    None
}

/// The value at `at` in an answer string: up to the next NUL.
fn value_at(answers: &[u8], at: usize) -> &[u8] {
    let end = answers[at..]
        .iter()
        .position(|&c| c == 0)
        .map_or(answers.len(), |n| at + n);
    &answers[at..end]
}

/// An answer string, installed over a form. What `fsdans()` leaves behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answers {
    /// The string itself: `NAME=value\0NAME=value\0...\0`, final NUL included.
    pub text: Vec<u8>,

    /// Each field's `(ansoff, anslen)`, in field order. `ansoff` is the offset
    /// of the *value* within [`Answers::text`], one past the `=`.
    pub offsets: Vec<(u16, u8)>,

    /// `allans`: the whole string's length, the final NUL included.
    pub allans: u16,
}

/// Install an answer string over a form. `fsdans()`, `FSD.C:493`.
///
/// `old` is the caller's default answers, in the same format, and may be a lone
/// NUL for all blank. Each field's value is looked up in `old` **by the name
/// the specification gives it**, truncated to that field's width, and written
/// out under that name -- so the result is keyed by the form and not by
/// whatever the caller happened to send, and a field `old` never mentions comes
/// out blank rather than missing.
///
/// A field the template had no room for has width 0 and therefore an empty
/// answer, which is `FSD.H`'s Note 1 falling out of the arithmetic rather than
/// being a case anyone had to write.
///
/// The original does all of this in one pass over the output buffer, using the
/// name it has just written as the key to look up and overwriting that name's
/// terminator with `=` afterwards. The result is the same string.
pub fn answers(form: &Form, spec: &[u8], old: &[u8]) -> Answers {
    let mut text: Vec<u8> = Vec::new();
    let mut offsets = Vec::with_capacity(form.fields.len());

    for field in &form.fields {
        let name = spec_name(spec, field);
        text.extend_from_slice(name);
        text.push(b'=');
        let ansoff = text.len() as u16;

        // `stzcpy(cp+1, fsdxan(oldans,np), width+1)`: at most `width`
        // characters of the value, and a NUL after them whatever happens.
        let value = extract(old, name).map_or(&[][..], |at| value_at(old, at));
        let kept = value.len().min(usize::from(field.width));
        text.extend_from_slice(&value[..kept]);
        text.push(0);
        offsets.push((ansoff, kept as u8));
    }

    // The extra NUL that ends the whole string. `allans` counts it.
    text.push(0);
    let allans = text.len() as u16;
    Answers {
        text,
        offsets,
        allans,
    }
}

/// The synthetic option list a `Y/N` field gets. `foptkn()`, `FSD.C:135`.
///
/// A `Y/N` field may not carry options of its own -- `tmpscn` calls that an
/// error -- so its alternates come from here, and its ordinals are `NO=0` and
/// `YES=1` from a string that appears nowhere in the module's specification.
/// The substitution is keyed on `fldtyp == 'Y'`, which `embscn` sets, so it
/// fires for every caller after `fsdppc` and for none before.
const YES_NO: &[u8] = b"(ALT=NO ALT=YES)";

/// Every `ALT=` value of one field, in the order the specification lists them.
///
/// A value ends at white space, `)` or the terminator, and never runs past
/// [`ANSLEN`] characters -- `endtkn()`, `FSD.C:148`.
fn alternates<'a>(spec: &'a [u8], field: &Field) -> Vec<&'a [u8]> {
    let (list, mut at) = if field.kind == b'Y' {
        (YES_NO, 1usize)
    } else {
        match option_list(spec, field) {
            Some(at) => (spec, at),
            None => return Vec::new(),
        }
    };

    let mut out = Vec::new();
    while let Some(start) = next_token(list, at, b"ALT=", false) {
        let end = list[start..]
            .iter()
            .take(usize::from(ANSLEN))
            .position(|&c| c == 0 || c == b')' || is_space(c))
            .map_or(list.len(), |n| start + n);
        out.push(&list[start..end]);
        // `nxttkn(ep, ...)` resumes at the value's terminator, so a value that
        // ran to the end of the list must not restart the scan where it began.
        at = end.max(start + 1);
    }
    out
}

/// Which alternate value an answer is. `chkalt(0)` then `fsdord()`,
/// `FSD.C:965` and `FSD.C:2244`.
///
/// Returns the ordinal **and the alternate's own spelling**, because the
/// original does not merely report: on an unequivocal match it copies the full
/// alternate back over the answer, which is what `FSD.H:656` means by "in that
/// case, answer is available via `fsdnan(fldi)`". A caller that drops the
/// second half of the pair has not finished doing what `fsdord` does.
///
/// `None` when the field has no alternates, when nothing matches, **and when
/// more than one does**. Ambiguity is not a near miss here: `"B"` against
/// `ALT=Black ALT=Brown` picks neither, and a host that took the first would be
/// choosing on the player's behalf. `FSD.H:655` -- "only returns 0..N-1 if
/// unequivocal match".
///
/// The answer is matched as a *prefix*, after every white-space character in it
/// has been removed -- `rmvwht`, which is not a trim. So `" b l "` finds
/// `Black`.
pub fn ordinal(spec: &[u8], field: &Field, answer: &[u8]) -> Option<(u16, Vec<u8>)> {
    // `if (!(fldptr->flags&FFFALT) || foptkn("ALT=",0) == NULL) return 0;`
    if field.flags & flags::ALTERNATES == 0 {
        return None;
    }
    let wanted = crate::strings::rmvwht(answer);
    // `bc=toupper(bufptr[0])`. An empty answer has no first character, and the
    // original would compare against the terminator -- which no alternate
    // starts with, since a zero-length `ALT=` is the one exception FSD.H:214
    // calls out and it never reaches here with FFFALT set by a name.
    let first = wanted.first()?.to_ascii_uppercase();

    let mut found: Option<(u16, Vec<u8>)> = None;
    let mut matches = 0usize;
    for (i, alt) in alternates(spec, field).into_iter().enumerate() {
        // `sameto(bufptr,tp)` -- the alternate begins with the answer -- and
        // then `bc == toupper(*tp)`, which the first is already sufficient for
        // and which the original checks anyway.
        let same = alt.len() >= wanted.len()
            && alt[..wanted.len()].eq_ignore_ascii_case(&wanted)
            && alt.first().is_some_and(|c| c.to_ascii_uppercase() == first);
        if same {
            if matches == 0 {
                found = Some((i as u16, alt.to_vec()));
            }
            matches += 1;
        }
    }
    if matches == 1 { found } else { None }
}

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
    template_scan(&mut form, template);
    punctuation(&mut form, template);
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

/// Where a field's option list begins: one past its `(`. `foptkn()`'s scan.
///
/// `None` when the field has no options at all, which is a name followed by
/// white space or the end of the specification rather than by `(`.
fn option_list(spec: &[u8], field: &Field) -> Option<usize> {
    let mut at = usize::from(field.spec_at);
    while at < spec.len() && spec[at] != b'(' {
        if spec[at] == 0 || is_space(spec[at]) {
            return None;
        }
        at += 1;
    }
    if at >= spec.len() { None } else { Some(at + 1) }
}

/// `foptkn()`, `FSD.C:127`: find `token` among one field's options.
///
/// The `fldtyp == 'Y'` branch of the original substitutes a synthetic
/// `(ALT=NO ALT=YES)` list. It cannot fire from here: `chkops` clears `fldtyp`
/// on the line above its first call, and only `embscn` ever sets it. Where it
/// *does* fire is [`alternates`], which runs after `fsdppc` has finished.
fn field_token(spec: &[u8], field: &Field, token: &[u8], word: bool) -> Option<usize> {
    next_token(spec, option_list(spec, field)?, token, word)
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

/// `tmpfld()`, `FSD.C:265`: record where a field landed in the template.
fn place(form: &mut Form, index: usize, at: u16, width: u16) {
    let width = u8::try_from(width.min(ANSLEN)).expect("ANSLEN fits in a byte");
    let field = &mut form.fields[index];
    field.attr = 0x07;
    field.template_at = at;
    field.xwidth = width;
    field.width = width;
    field.punctuation_at = None;
    form.answer_max = form.answer_max.saturating_add(u16::from(width));
}

/// `tmpscn()`, `FSD.C:299`: find the field runs in the template.
fn template_scan(form: &mut Form, template: &[u8]) {
    let end = template
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(template.len());
    let template = &template[..end];

    let mut placed = 0usize;
    let mut last = 0u8;
    let mut joining = false;
    let mut at = 0usize;
    let mut off = 0u16;

    while at < template.len() {
        let c = template[at];
        let kind = Kind::of(c);
        match kind {
            Kind::White => {
                joining = false;
                at += 1;
                off += 1;
            }
            Kind::Dol | Kind::Exc | Kind::Pnd | Kind::Qst => {
                // A lone field character is literal text. Two or more make a
                // field, which is why a one-character answer is not spellable.
                if template.get(at + 1) != Some(&c) {
                    at += 1;
                    off += 1;
                    continue;
                }
                let mut run = 0u16;
                while at < template.len() && template[at] == c {
                    at += 1;
                    run += 1;
                }

                if placed > 0 && kind.joins() && joining && last == c {
                    // The run before this one was the same character with only
                    // punctuation between: `###-####` is one field, not two.
                    let field = &mut form.fields[placed - 1];
                    let xwidth = off + run - field.template_at;
                    let clamped = u8::try_from(xwidth.min(ANSLEN)).expect("ANSLEN is a byte");
                    field.punctuation_at = Some(0);
                    field.width = field
                        .width
                        .saturating_add(u8::try_from(run).unwrap_or(u8::MAX));
                    field.xwidth = clamped;
                    if xwidth > ANSLEN {
                        field.width = clamped;
                    }
                    form.answer_max = form.answer_max.saturating_add(run);
                } else if kind == Kind::Exc {
                    form.help_len = u8::try_from(run.min(MAXHLP)).expect("fits");
                    form.help_at = off;
                } else if placed < form.fields.len() {
                    place(form, placed, off, run);
                    placed += 1;
                    joining = true;
                }
                off += run;
                last = c;
            }
            Kind::Slash => {
                let before = at > 0 && template[at - 1].eq_ignore_ascii_case(&b'Y');
                let after = template
                    .get(at + 1)
                    .is_some_and(|b| b.eq_ignore_ascii_case(&b'N'));
                if off > 0 && before && after && placed < form.fields.len() {
                    place(form, placed, off - 1, 3);
                    last = c;
                    let field = &mut form.fields[placed];
                    if field.flags
                        & (flags::MULTICHOICE
                            | flags::ALTERNATES
                            | flags::MINMAX
                            | flags::NONNEGATIVE
                            | flags::NOSPACES
                            | flags::SECRET)
                        != 0
                    {
                        let flags = field.flags;
                        form.errors.push(format!(
                            "Field {placed}, Y/N field cannot have options ({flags:02X})"
                        ));
                    }
                    form.fields[placed].flags |= flags::MULTICHOICE | flags::ALTERNATES;
                    placed += 1;
                }
                at += 1;
                off += 1;
            }
            Kind::Junk | Kind::Equ => {
                at += 1;
                off += 1;
            }
        }
    }
    form.in_template = placed;
}

/// `embscn()`, `FSD.C:433`: build the punctuation template of each field.
fn punctuation(form: &mut Form, template: &[u8]) {
    let mut out: Vec<u8> = Vec::new();
    for field in form.fields.iter_mut().take(form.in_template) {
        let at = usize::from(field.template_at);
        let Some(&c) = template.get(at) else { continue };
        field.kind = c;
        if field.punctuation_at.is_some() {
            field.punctuation_at = Some(out.len() as u16);
            for k in 0..usize::from(field.xwidth) {
                let b = template.get(at + k).copied().unwrap_or(b' ');
                out.push(if b == c || c == b'Y' { b' ' } else { b });
            }
            out.push(0);
        }
    }
    form.punctuation = out;
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

    #[test]
    fn a_run_of_field_characters_is_a_field_and_a_single_one_is_not() {
        // Two or more, which is why a one-character answer cannot be spelled.
        let form = compile(b"a ? b ?? c", b"ONE TWO", MANY);
        assert_eq!(form.fields.len(), 2, "the spec names two");
        assert_eq!(form.in_template, 1, "the template has room for one");
        assert_eq!(form.fields[0].template_at, 6);
        assert_eq!(form.fields[0].width, 2);
        assert_eq!(form.fields[0].kind, b'?');
    }

    #[test]
    fn white_space_separates_fields_and_punctuation_joins_them() {
        let apart = compile(b"?? ??", b"A B", MANY);
        assert_eq!(apart.in_template, 2);
        assert!(apart.punctuation.is_empty());

        // `###-####` is one field of seven characters spanning eight, and the
        // punctuation template is what a session prints between the halves.
        let joined = compile(b"Phone ###-####", b"PHONE", MANY);
        assert_eq!(joined.in_template, 1);
        assert_eq!(joined.fields[0].width, 7);
        assert_eq!(joined.fields[0].xwidth, 8);
        assert_eq!(joined.fields[0].punctuation_at, Some(0));
        assert_eq!(joined.punctuation, b"   -    \0");
        assert_eq!(joined.size(), Ok(48));
    }

    #[test]
    fn dollar_runs_do_not_join_because_only_hash_and_question_are_subfields() {
        // `TMPSFD` is `TMPPND`, so `$` is below it. Two `$$` runs with a dash
        // between are two fields, not one -- unlike the `###-####` above.
        let form = compile(b"$$-$$", b"A B", MANY);
        assert_eq!(form.in_template, 2);
        assert!(form.punctuation.is_empty());
    }

    #[test]
    fn a_slash_between_y_and_n_makes_a_three_character_choice() {
        let form = compile(b"Ok Y/N", b"OK", MANY);
        assert_eq!(form.in_template, 1);
        assert_eq!(form.fields[0].template_at, 3, "it starts at the Y");
        assert_eq!(form.fields[0].width, 3);
        assert_eq!(form.fields[0].kind, b'Y');
        assert_eq!(
            form.fields[0].flags,
            flags::MULTICHOICE | flags::ALTERNATES,
            "a Y/N field is a two-choice field by construction"
        );
    }

    #[test]
    fn a_yes_no_field_may_not_also_carry_options() {
        let form = compile(b"Ok Y/N", b"OK(MULTICHOICE)", MANY);
        assert_eq!(form.errors.len(), 1);
        assert!(form.errors[0].contains("Y/N"), "{:?}", form.errors);
    }

    #[test]
    fn a_bang_run_is_the_help_field_and_not_a_field() {
        let form = compile(b"?? !!!!!", b"F", MANY);
        assert_eq!(form.in_template, 1, "the help field is not one of them");
        assert_eq!(form.help_len, 5);
        assert_eq!(form.help_at, 3);
    }

    #[test]
    fn high_bit_bytes_are_decoration() {
        // MajorMUD's ANSI template is 194 bytes of box drawing, in runs. If
        // `tmpspc[]` were indexed as a signed char those runs would read as
        // field characters and invent fields out of the borders.
        let form = compile("\u{c4}\u{c4}\u{c4}\u{c4} ??".as_bytes(), b"A B", MANY);
        assert_eq!(form.in_template, 1);
    }

    #[test]
    fn an_answer_matching_one_alternate_gives_its_position() {
        let spec = b"C(ALT=Black ALT=Brown ALT=Red MULTICHOICE)";
        let form = compile(b"??????", spec, MANY);
        assert_eq!(
            ordinal(spec, &form.fields[0], b"Brown"),
            Some((1, b"Brown".to_vec()))
        );
        assert_eq!(
            ordinal(spec, &form.fields[0], b"Red"),
            Some((2, b"Red".to_vec()))
        );
    }

    #[test]
    fn a_prefix_is_enough_and_the_canonical_spelling_comes_back() {
        // `sameto(bufptr,tp)`: the alternate must *begin* with the answer, and
        // when exactly one does, `chkalt` copies the full alternate back over
        // it. That is why FSD.H:656 can say "answer is available via
        // fsdnan(fldi)" -- it has rewritten it.
        let spec = b"C(ALT=Black ALT=Brown ALT=Red)";
        let form = compile(b"??????", spec, MANY);
        assert_eq!(
            ordinal(spec, &form.fields[0], b"br"),
            Some((1, b"Brown".to_vec()))
        );
    }

    #[test]
    fn an_ambiguous_answer_matches_nothing() {
        // "Black" and "Brown" both begin with "B". Two matches is not an
        // answer, and returning the first would pick a hair colour for the
        // player.
        let spec = b"C(ALT=Black ALT=Brown ALT=Red)";
        let form = compile(b"??????", spec, MANY);
        assert_eq!(ordinal(spec, &form.fields[0], b"B"), None);
    }

    #[test]
    fn white_space_inside_the_answer_is_removed_before_matching() {
        // `rmvwht(bufptr)` -- every space, not merely the outer ones.
        let spec = b"C(ALT=Black ALT=Red)";
        let form = compile(b"??????", spec, MANY);
        assert_eq!(
            ordinal(spec, &form.fields[0], b" R e d "),
            Some((1, b"Red".to_vec()))
        );
    }

    #[test]
    fn the_ordinal_counts_every_alternate_and_not_just_the_matching_ones() {
        // `i++` runs on every iteration of chkalt's loop, so the ordinal is a
        // position in the option list. Counting only candidates would number
        // the last of five as 0.
        let spec = b"C(ALT=Aa ALT=Bb ALT=Cc ALT=Dd ALT=Ee)";
        let form = compile(b"??????", spec, MANY);
        assert_eq!(
            ordinal(spec, &form.fields[0], b"Ee"),
            Some((4, b"Ee".to_vec()))
        );
    }

    #[test]
    fn a_field_with_no_alternates_has_no_ordinal() {
        let spec = b"C(MIN=1 MAX=9)";
        let form = compile(b"??????", spec, MANY);
        assert_eq!(ordinal(spec, &form.fields[0], b"5"), None);

        let bare = b"C";
        let form = compile(b"??????", bare, MANY);
        assert_eq!(ordinal(bare, &form.fields[0], b"5"), None);
    }

    #[test]
    fn a_yes_no_field_uses_the_synthetic_option_list() {
        // `foptkn()`, FSD.C:135: `fldtyp == 'Y'` substitutes
        // "(ALT=NO ALT=YES)" for the field's own options, which a Y/N field
        // does not have and may not have. So NO is 0 and YES is 1, from a
        // string that appears nowhere in the module's field specification.
        let spec = b"OK";
        let form = compile(b"Ok Y/N", spec, MANY);
        assert_eq!(form.fields[0].kind, b'Y');
        assert_eq!(
            ordinal(spec, &form.fields[0], b"YES"),
            Some((1, b"YES".to_vec()))
        );
        assert_eq!(
            ordinal(spec, &form.fields[0], b"n"),
            Some((0, b"NO".to_vec()))
        );
    }

    #[test]
    fn an_empty_answer_matches_no_alternate() {
        let spec = b"C(ALT=Black ALT=Red)";
        let form = compile(b"??????", spec, MANY);
        assert_eq!(ordinal(spec, &form.fields[0], b""), None);
        assert_eq!(ordinal(spec, &form.fields[0], b"   "), None);
    }

    #[test]
    fn an_answer_string_is_named_values_separated_by_nuls() {
        // The example at FSDBBS.H:202, built by hand and read back.
        let old = b"RANK=MAJOR\0NAME=Fred\0\0";
        assert_eq!(extract(old, b"NAME"), Some(16));
        assert_eq!(&old[16..20], b"Fred");
        assert_eq!(extract(old, b"RANK"), Some(5));
    }

    #[test]
    fn a_name_is_matched_whole_and_not_as_a_prefix() {
        // `fsdxan` takes a match only when the byte after the name is '=',
        // which is what stops "NAME" from matching "NAMEX=1".
        assert_eq!(extract(b"NAMEX=1\0\0", b"NAME"), None);
        assert_eq!(extract(b"NAM=1\0\0", b"NAME"), None);
        assert_eq!(extract(b"\0", b"NAME"), None);
    }

    #[test]
    fn a_name_is_matched_without_regard_to_case() {
        // `sameto` ignores case, so FSD.H:592's "all caps required" is advice.
        assert_eq!(extract(b"name=Fred\0\0", b"NAME"), Some(5));
    }

    #[test]
    fn installing_answers_writes_name_equals_value_per_field() {
        let form = compile(b"?????? ??????", b"NAME RANK", MANY);
        let a = answers(&form, b"NAME RANK", b"RANK=MAJOR\0\0");

        assert_eq!(a.text, b"NAME=\0RANK=MAJOR\0\0");
        // `ansoff` is the offset of the *value*, one past the '='.
        assert_eq!(a.offsets, vec![(5u16, 0u8), (11, 5)]);
        // `allans` counts the whole thing, final NUL included.
        assert_eq!(a.allans, a.text.len() as u16);
    }

    #[test]
    fn an_answer_longer_than_the_field_is_truncated_to_its_width() {
        // `stzcpy(cp+1, ..., width+1)`. A default that came through whole
        // would overrun the buffer `fsdroom` sized.
        let form = compile(b"??", b"A", MANY);
        assert_eq!(form.fields[0].width, 2);
        assert_eq!(answers(&form, b"A", b"A=abcdef\0\0").text, b"A=ab\0\0");
    }

    #[test]
    fn a_field_the_template_has_no_room_for_gets_an_empty_answer() {
        // FSD.H Note 1: fields in the spec but not in the template always have
        // zero-length answers, because their width is zero.
        let form = compile(b"??", b"A B", MANY);
        assert_eq!(form.in_template, 1);
        assert_eq!(
            answers(&form, b"A B", b"A=xy\0B=zz\0\0").text,
            b"A=xy\0B=\0\0"
        );
    }

    #[test]
    fn the_answer_string_never_exceeds_what_fsdroom_reserved() {
        // `maxans` is why `fsdroom` returns what it does. If `fsdans` could
        // produce more, every session would overrun the buffer the module
        // allocated from the number this crate gave it.
        let spec = b"NAME(MIN=1) RANK SERIALNO";
        let form = compile(b"?????????? ?????? ####", spec, MANY);
        let a = answers(
            &form,
            spec,
            b"NAME=abcdefghijkl\0RANK=MAJOR\0SERIALNO=1234\0\0",
        );
        assert!(
            a.allans <= form.answer_max + 1,
            "{} answer bytes against a reserved {}",
            a.allans,
            form.answer_max + 1
        );
    }

    #[test]
    fn a_field_name_stops_at_white_space_or_an_open_paren() {
        // `fldnmi()`, FSD.C:2155 -- the name is the spec text up to the first
        // space or '(', and it is what both the answer string and `fsdxan` are
        // keyed by.
        let spec = b"A(MIN=1) BB";
        let form = compile(b"?? ??", spec, MANY);
        assert_eq!(name_of(spec, &form.fields[0]), b"A");
        assert_eq!(name_of(spec, &form.fields[1]), b"BB");
    }

    #[test]
    fn fldnmi_clamps_a_name_to_fldnam_and_fsdans_does_not() {
        // The two C routines really do differ: `fldnmi` copies into a
        // `char[FLDNAM+1]`, `fsdans` copies until white space. Only an
        // over-long name shows it, and `fsdroom` refuses those -- so this
        // records the difference rather than relying on it.
        let spec = b"A_VERY_LONG_NAME_INDEED";
        let form = compile(b"??", spec, MANY);
        assert_eq!(name_of(spec, &form.fields[0]), b"A_VERY_LONG_");
        assert_eq!(
            answers(&form, spec, b"\0").text,
            b"A_VERY_LONG_NAME_INDEED=\0\0"
        );
    }

    #[test]
    fn the_session_control_block_is_the_size_the_header_declares() {
        // Byte-packed, every member of `FSD.H:275` in declaration order. Laid
        // out as a running total rather than one sum, because the first
        // spelling of this test said 167 and the mistake -- five trailing
        // `char`s counted as six -- was invisible in an expression.
        let members: u16 = [
            4,  // char *fldspc
            4,  // struct fsdfld *flddat
            4,  // char *mbpunc
            4,  // char *newans
            4,  // int (*fldvfy)()
            1,  // char crsatr
            2,  // int numfld
            2,  // int numtpl
            2,  // int mbleng
            2,  // int maxans
            1,  // char hlplen
            9,  // char hlpgto[GTOLEN+1]
            1,  // char hlpatr
            2,  // int hlpoff
            2,  // int allans
            1,  // char state
            81, /* char ansbuf[ANSLEN+1] */
            1,  // char anslen
            1,  // char ansptr
            20, /* char typahd[EXTHED] */
            1,  // char ahdptr
            1,  // char hdlahd
            1,  // char entfld
            1,  // char crsfld
            1,  // char shffld
            4,  // char *ftmptr
            1,  // char flags
            4,  // char *altptr
            2,  // int xitkey
            1,  // char chgcnt
            1,  // char maxy
        ]
        .iter()
        .sum();
        assert_eq!(FSDSCB, members);
        assert_eq!(FSDSCB, 166);

        // And the offsets are that same running total, so a member inserted
        // above one of them without moving it would show here.
        assert_eq!(scb::CRSATR, 20);
        assert_eq!(scb::NUMFLD, 21);
        assert_eq!(scb::HLPOFF, 40);
        assert_eq!(scb::ALLANS, 42);
    }

    #[test]
    fn the_module_finds_flddat_and_newans_where_this_puts_them() {
        // Not from the header -- from `WCCMMUD.DLL`. `seg 3:0x4340` is
        // `les bx,[es:bx+0x4]` on `fsdscb` to reach `flddat`, and
        // `seg 3:0x2d46` pushes `[es:bx+0xe]:[es:bx+0xc]` as `newans`. If these
        // two numbers were wrong the module would read two other pointers and
        // nothing would say so.
        assert_eq!(scb::FLDDAT, 4);
        assert_eq!(scb::NEWANS, 12);
    }

    #[test]
    fn a_field_record_is_twenty_three_bytes_with_the_flags_at_twelve() {
        // The module's fourteen `or byte [es:bx+n],0x80` sites are every one
        // `23*i+12` -- `seg 3:0x4344` is field 2 at 58 and `seg 3:0x4444` is
        // field 20 at 472.
        let form = compile(b"Ok Y/N", b"OK", MANY);
        let record = form.fields[0].record(7, 3);
        assert_eq!(record.len(), usize::from(FSDFLD));
        assert_eq!(record[fld::FLAGS], flags::MULTICHOICE | flags::ALTERNATES);
        assert_eq!(record[fld::WIDTH], 3);
        assert_eq!(record[fld::FLDTYP], b'Y');
        assert_eq!(
            i16::from_le_bytes([record[fld::ANSOFF], record[fld::ANSOFF + 1]]),
            7
        );
        assert_eq!(record[fld::ANSLEN], 3);
    }

    #[test]
    fn a_field_with_no_punctuation_records_mbpoff_as_minus_one() {
        // `tmpfld()` sets `mbpoff = -1` and `embscn()` overwrites it only for
        // the fields that joined. Zero would name the first punctuation
        // template rather than none.
        let plain = compile(b"?? ??", b"A B", MANY);
        let record = plain.fields[0].record(0, 0);
        assert_eq!(
            i16::from_le_bytes([record[fld::MBPOFF], record[fld::MBPOFF + 1]]),
            -1
        );

        let joined = compile(b"###-####", b"P", MANY);
        let record = joined.fields[0].record(0, 0);
        assert_eq!(
            i16::from_le_bytes([record[fld::MBPOFF], record[fld::MBPOFF + 1]]),
            0
        );
    }

    #[test]
    fn a_control_block_keeps_the_members_nobody_modelled() {
        // The entry session's `ansbuf`, `typahd` and `state` are FSD's working
        // storage and this host sets none of them. A round trip that zeroed
        // them would be a reset dressed as a write.
        let mut bytes = [0u8; FSDSCB as usize];
        bytes[45] = b'x'; // ansbuf[0]
        bytes[128] = b'y'; // typahd[0]
        let mut block = Scb::from_bytes(&bytes).expect("the right length");
        block.set_numfld(9);
        assert_eq!(block.numfld(), 9);
        assert_eq!(block.as_bytes()[45], b'x');
        assert_eq!(block.as_bytes()[128], b'y');
    }

    #[test]
    fn a_control_block_read_from_the_wrong_number_of_bytes_is_refused() {
        assert!(Scb::from_bytes(&[0u8; 165]).is_err());
        assert!(Scb::from_bytes(&[0u8; 167]).is_err());
    }

    #[test]
    fn the_size_is_the_three_terms_and_the_nul() {
        let form = compile(b"?? ??", b"A B", MANY);
        let expected = form.punctuation.len()
            + form.fields.len() * usize::from(FSDFLD)
            + usize::from(form.answer_max)
            + 1;
        assert_eq!(form.size(), Ok(expected as u16));
        assert_eq!(form.size(), Ok(59));
    }
}
