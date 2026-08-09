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

    /// A field read back out of the 23 bytes it occupies in module memory.
    ///
    /// The inverse of [`Field::record`], and the reason it exists is that the
    /// array in the session buffer is the module's: `WCCMMUD.DLL` sets
    /// `FFFAVD` on fourteen of its fields, so a routine that consulted the
    /// host's own [`Form`] instead would be reading flags the module had since
    /// changed.
    ///
    /// `ansoff` and `anslen` are not returned. They belong to the answer string
    /// rather than to the field, and a caller that needs them has the record.
    pub fn from_record(record: &[u8; FSDFLD as usize]) -> Self {
        let mbpoff = i16::from_le_bytes([record[fld::MBPOFF], record[fld::MBPOFF + 1]]);
        Self {
            width: record[fld::WIDTH],
            xwidth: record[fld::XWIDTH],
            attr: record[fld::ATTR],
            flags: record[fld::FLAGS],
            kind: record[fld::FLDTYP],
            spec_at: u16::from_le_bytes([record[fld::FSPOFF], record[fld::FSPOFF + 1]]),
            template_at: u16::from_le_bytes([record[fld::TMPOFF], record[fld::TMPOFF + 1]]),
            punctuation_at: (mbpoff >= 0).then_some(mbpoff as u16),
        }
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

/// The option list `foptkn()` searches for one field, and where it starts.
///
/// The whole of `foptkn()` (`FSD.C:127`) bar its final `nxttkn` call, including
/// the substitution the `fldtyp == 'Y'` branch makes: a `Y/N` field's options
/// come from [`YES_NO`] and not from the specification, so `MIN=` and `MAX=`
/// are unfindable on one however its name was written. That is not a corner --
/// `chkops` sets `FFFMMX` from the *specification*, before `embscn` has made
/// the field a `Y`, so a `Y/N` field really can arrive at [`min_ok`] with the
/// flag set and no minimum to be found.
///
/// `None` when the field has no option list at all. The offset is into the
/// returned list, which is [`YES_NO`] rather than `spec` for a `Y/N` field.
fn option_list_of<'a>(spec: &'a [u8], field: &Field) -> Option<(&'a [u8], usize)> {
    if field.kind == b'Y' {
        Some((YES_NO, 1))
    } else {
        option_list(spec, field).map(|at| (spec, at))
    }
}

/// One option's value: from `start` to its terminator. `endtkn(tp,0)`,
/// `FSD.C:148`.
///
/// A value ends at white space, `)` or the terminator, and never runs past
/// [`ANSLEN`] characters. The clamp is the *default* as well as the bound on
/// the search -- `endtkn` returns `token+ANSLEN` when it ran out of characters
/// before it ran out of value -- so falling through to the end of the list
/// instead would hand back a value as long as the rest of the specification.
fn token_value(list: &[u8], start: usize) -> &[u8] {
    let end = list[start..]
        .iter()
        .take(usize::from(ANSLEN))
        .position(|&c| c == 0 || c == b')' || is_space(c))
        .map_or((start + usize::from(ANSLEN)).min(list.len()), |n| start + n);
    &list[start..end]
}

/// `foptkn()` then `endtkn(tp,0)`: what one option of one field is set to.
///
/// `None` when the field has no options, or has options but not this one --
/// the two cases the C spells `foptkn(...) == NULL`, which is what both
/// [`min_ok`] and [`max_ok`] test.
fn option_value<'a>(spec: &'a [u8], field: &Field, token: &[u8], word: bool) -> Option<&'a [u8]> {
    let (list, at) = option_list_of(spec, field)?;
    let start = next_token(list, at, token, word)?;
    Some(token_value(list, start))
}

/// Every `ALT=` value of one field, in the order the specification lists them.
fn alternates<'a>(spec: &'a [u8], field: &Field) -> Vec<&'a [u8]> {
    let Some((list, mut at)) = option_list_of(spec, field) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    while let Some(start) = next_token(list, at, b"ALT=", false) {
        let value = token_value(list, start);
        out.push(value);
        // `nxttkn(ep, ...)` resumes exactly at the value's terminator, and its
        // own loop guard stops it on `)`. Stepping even one byte past that --
        // which an empty `ALT=` right before the `)` would do -- carries the
        // scan on into the *next* field's option list, and the ordinals after
        // it are then counted over somebody else's alternates.
        //
        // No progress guard is needed: `next_token` returns the offset one past
        // the token it matched, so `start` is at least `at + 4` every time round.
        at = start + value.len();
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
    // `bc=toupper(bufptr[0])`, over a NUL-terminated buffer -- so an *empty*
    // answer reads the terminator and `bc` is 0. That is not a degenerate case
    // to be refused: `sameto("",tp)` is true of every alternate, so the first
    // character is the whole of the test, and the only alternate whose first
    // character is also 0 is a zero-length one. A blank `ALT=` is exactly how
    // FSD.H:214 says to spell "no answer", and this is how it gets chosen.
    let upper = |s: &[u8]| s.first().map_or(0, u8::to_ascii_uppercase);
    let first = upper(&wanted);

    let mut found: Option<(u16, Vec<u8>)> = None;
    let mut matches = 0usize;
    for (i, alt) in alternates(spec, field).into_iter().enumerate() {
        // `sameto(bufptr,tp)` -- the alternate begins with the answer -- and
        // then `bc == toupper(*tp)`, which for a non-empty answer the first
        // test already implies and which the original checks anyway.
        let same = alt.len() >= wanted.len()
            && alt[..wanted.len()].eq_ignore_ascii_case(&wanted)
            && upper(alt) == first;
        if same {
            if matches == 0 {
                found = Some((i as u16, alt.to_vec()));
            }
            matches += 1;
        }
    }
    if matches == 1 { found } else { None }
}

/// Is this answer consistent with the field's type? `chktyp()`, `FSD.C:861`.
///
/// One of the four checks a candidate answer has to pass, and the only one that
/// looks at `fldtyp` at all -- `chkmin`, `chkmax` and `chkalt` are separate
/// passes over the same buffer. So a `false` here is not "the answer is
/// invalid", it is "the answer is not of this field's *shape*".
///
/// # A multiple-choice field says no to everything
///
/// `FFFMCH` makes the `?`/`Y` arm answer `false` whatever the answer is,
/// including an empty one. That is deliberate and it is the normal case: the
/// answer to a multiple-choice field is supposed to arrive from its `ALT=`
/// list, which is [`ordinal`]'s job, and `chkalt` is what installs it. Every
/// `Y/N` field is multiple-choice by construction -- `tmpfld` sets `FFFMCH` on
/// the field the `/` makes -- so `type_ok` is `false` for every typed answer to
/// every `Y/N` field on this host, `YES` included.
///
/// # The arms disagree about what they ignore
///
/// `FFFNSP` is read only by the `?`/`Y` arm, so a space in a `#` or `$` field
/// is refused by the digit test rather than by `FFFNSP`, and setting `NOSPACES`
/// on a numeric field changes nothing. `FFFMCH` is likewise read only there, so
/// a multiple-choice `$` field accepts a typed number. Neither is an asymmetry
/// worth tidying: the C reads each flag in exactly one arm.
///
/// # The answer is a C string
///
/// `bufptr` is one, and `strchr` and `alldgs` both stop at its terminator, so
/// an embedded NUL ends the answer as far as this check is concerned rather
/// than being a byte in it. Measured, not assumed: the genuine host's `chktyp`
/// accepts `"12\0ab"` in a `#` field and accepts `"ab\0 c"` in a `NOSPACES`
/// one.
///
/// # A field the template had no room for passes
///
/// The C's `switch` has no `default` and `rc` is initialised to 1, so a
/// `fldtyp` that is none of `Y ? # $` is consistent with everything. That arm
/// is reachable: `chkops` zeroes every field's `fldtyp` and only `embscn` fills
/// it in, and `embscn` stops at `numtpl` -- so a field the specification names
/// and the template has no run for keeps `fldtyp == 0` and answers `true` here.
pub fn type_ok(field: &Field, answer: &[u8]) -> bool {
    let answer = c_str(answer);
    match field.kind {
        b'Y' | b'?' => {
            field.flags & flags::MULTICHOICE == 0
                && (field.flags & flags::NOSPACES == 0 || !answer.contains(&b' '))
        }
        b'#' => crate::strings::all_digits(answer),
        b'$' => {
            // `cp=bufptr; if (*cp == '-') cp++;` -- one sign, and only at the
            // front. `strlen(cp) > 0` is then what stops a lone `-`, and it is
            // the whole of the difference between `$` and `#`.
            let digits = answer.strip_prefix(b"-").unwrap_or(answer);
            !digits.is_empty() && crate::strings::all_digits(digits)
        }
        _ => true,
    }
}

/// A candidate answer as the C sees it: up to its first NUL.
///
/// `bufptr` is a `char *` and every routine that reads it -- `strchr`,
/// `alldgs`, `strlen`, `strcmpi`, `sscanf` -- stops at the terminator. A Rust
/// slice does not, so the truncation has to be written down. Measured rather
/// than assumed: the genuine host's `chktyp` accepts `"12\0ab"` in a `#` field,
/// and its `chkmin` reads `"ab\0cd"` as two characters long.
fn c_str(s: &[u8]) -> &[u8] {
    match s.iter().position(|&c| c == 0) {
        Some(nul) => &s[..nul],
        None => s,
    }
}

/// `sscanf(s,"%ld",&n)`, as far as [`min_ok`] and [`max_ok`] need it.
///
/// A C `long` here is 32 bits, so this one is too. Two of `sscanf`'s edges are
/// deliberately not reproduced, because both are undefined behaviour rather
/// than behaviour:
///
/// * **Nothing to convert.** C leaves the target untouched, so the original
///   compares against whatever the stack held. This answers zero.
/// * **Overflow.** This saturates. A `MIN=` beyond a 32-bit `long` is outside
///   what either side can be said to mean.
fn as_long(s: &[u8]) -> i32 {
    let mut at = 0usize;
    while at < s.len() && is_space(s[at]) {
        at += 1;
    }
    let negative = s.get(at) == Some(&b'-');
    if negative || s.get(at) == Some(&b'+') {
        at += 1;
    }
    let magnitude = s[at..]
        .iter()
        .take_while(|c| c.is_ascii_digit())
        .fold(0i32, |n, &c| {
            n.saturating_mul(10).saturating_add(i32::from(c - b'0'))
        });
    if negative { -magnitude } else { magnitude }
}

/// `MIN=` read as a minimum **length**, or `None` if it cannot be one.
///
/// `FSD.C:903-905`: all digits, at most two of them, and no greater than the
/// field's width. Each of the three is load-bearing and the third is the one
/// that surprises -- `MIN=99` on a two-wide field is a *value*, not a length.
///
/// The result fits a `u8` because two digits cannot exceed 99.
fn as_length(min: &[u8], width: u8) -> Option<u8> {
    if !crate::strings::all_digits(min) || min.len() > 2 {
        return None;
    }
    // `atoi(tp)` over at most two digits. An empty `MIN=` reaches here -- both
    // `alldgs("")` and `atoi("")` are happy with it -- and asks for a minimum
    // length of zero, which every answer meets.
    let ml = min.iter().fold(0u8, |n, &c| n * 10 + (c - b'0'));
    (ml <= width).then_some(ml)
}

/// Is the answer at or above the field's `MIN=`? `chkmin()`, `FSD.C:887`.
///
/// # The `?` arm falls through, and that is the whole of this routine
///
/// A `?` field's `MIN=` is a minimum **length** when [`as_length`] can read it
/// as one, and a minimum **value** otherwise: `FSD.C:911-912` is a `case '?'`
/// that runs off the end of its block into `case '#'`, deliberately and
/// unmarked. A port that made the `?` arm complete in itself is right on every
/// input anyone would think to try and wrong on `MIN=100` for a four-wide
/// field, where the C compares `"100"` against the answer as text.
///
/// # Only `$` is arithmetic
///
/// `?` and `#` go through `strcmpi`, which compares *strings*: for a `#` field
/// `"9"` is greater than `"10"`, and a `MIN=9` therefore refuses `10`. Only a
/// `$` field reaches `sscanf("%ld")`. That is not a bug being preserved for its
/// own sake -- it is what makes `MIN=` usable on an alphabetic field at all.
///
/// # `Err` carries the message, because the message is the behaviour
///
/// The C writes it into `chkemg` (`FSD.C:29`) and the entry engine displays it,
/// so the wording, the quoting and the truncation are all observable. The
/// truncation is `%0.*s` with a precision of `MAXHLP-17`, and the genuine
/// host's `sprintf` overruns `chkemg` by exactly the terminating NUL when it
/// bites -- 15 characters of prose, two quotes and 63 of value is 80, and
/// `chkemg` is 80 bytes. Not reproduced: a `String` has no such edge.
///
/// # A `Y/N` field has no minimum whatever its flags say
///
/// `foptkn` substitutes `(ALT=NO ALT=YES)` for a `Y` field's option list, so
/// the `MIN=` its specification carried is unfindable. See [`option_list_of`].
pub fn min_ok(spec: &[u8], field: &Field, answer: &[u8]) -> Result<(), String> {
    if field.flags & flags::MINMAX == 0 {
        return Ok(());
    }
    let Some(min) = option_value(spec, field, b"MIN=", false) else {
        return Ok(());
    };
    let answer = c_str(answer);

    if field.kind == b'?'
        && let Some(ml) = as_length(min, field.width)
    {
        return if answer.len() >= usize::from(ml) {
            Ok(())
        } else {
            Err(format!("Enter at least {ml} character(s)"))
        };
    }

    match field.kind {
        // The fallthrough: `?` arrives here when its `MIN=` was not a length.
        b'?' | b'#' => {
            if crate::strings::strcmpi(min, answer).is_le() {
                Ok(())
            } else {
                Err(format!(
                    "Enter at least \"{}\"",
                    String::from_utf8_lossy(&min[..min.len().min(usize::from(MAXHLP) - 17)])
                ))
            }
        }
        b'$' => {
            let (want, got) = (as_long(min), as_long(answer));
            if want <= got {
                Ok(())
            } else {
                Err(format!("Enter at least {want}"))
            }
        }
        // `Y`, and a field the template had no run for. The C's `switch` has no
        // `default` and `rc` starts at 1, so neither has a minimum.
        _ => Ok(()),
    }
}

/// Is the answer at or below the field's `MAX=`? `chkmax()`, `FSD.C:931`.
///
/// Everything [`min_ok`] says about `strcmpi` versus `sscanf`, about `Err`
/// carrying the message, and about `Y/N`, holds here too. The one difference is
/// the one worth naming: **there is no fallthrough**. `case '?'` and `case '#'`
/// share a single arm outright (`FSD.C:944-945`), so a `MAX=` is never read as
/// a maximum length and `MAX=3` on a `?` field refuses every answer that sorts
/// after `"3"` however short it is.
///
/// Its message truncates at `MAXHLP-23` rather than `MAXHLP-17`, the prose
/// being six characters longer.
pub fn max_ok(spec: &[u8], field: &Field, answer: &[u8]) -> Result<(), String> {
    if field.flags & flags::MINMAX == 0 {
        return Ok(());
    }
    let Some(max) = option_value(spec, field, b"MAX=", false) else {
        return Ok(());
    };
    let answer = c_str(answer);

    match field.kind {
        b'?' | b'#' => {
            if crate::strings::strcmpi(max, answer).is_ge() {
                Ok(())
            } else {
                Err(format!(
                    "Enter no higher than \"{}\"",
                    String::from_utf8_lossy(&max[..max.len().min(usize::from(MAXHLP) - 23)])
                ))
            }
        }
        b'$' => {
            let (want, got) = (as_long(max), as_long(answer));
            if got <= want {
                Ok(())
            } else {
                Err(format!("Enter no higher than {want}"))
            }
        }
        _ => Ok(()),
    }
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
    fn an_empty_answer_matches_only_a_blank_alternate() {
        // `bc = toupper(bufptr[0])` over a NUL-terminated buffer is 0 for an
        // empty answer, and `sameto("",tp)` is true of everything -- so the
        // first-character test is the whole of it, and only a zero-length
        // alternate has a zero first character.
        let spec = b"C(ALT=Black ALT=Red)";
        let form = compile(b"??????", spec, MANY);
        assert_eq!(ordinal(spec, &form.fields[0], b""), None);
        assert_eq!(ordinal(spec, &form.fields[0], b"   "), None);

        // FSD.H:214: `ALT=` is how a blank answer is spelled, and it is the one
        // alternate allowed to be a substring of every other.
        let blank = b"C(ALT=Black ALT= ALT=Red)";
        let form = compile(b"??????", blank, MANY);
        assert_eq!(ordinal(blank, &form.fields[0], b""), Some((1, Vec::new())));
    }

    #[test]
    fn an_alternate_value_stops_at_anslen_characters() {
        // `endtkn()` bounds the value at ANSLEN and *returns* `token+ANSLEN`
        // when it gets there. Running on to the end of the list instead would
        // hand back an alternate as long as the rest of the specification --
        // and `fsdord` stores its length in a `char`.
        let long = "A".repeat(200);
        let spec = format!("C(ALT={long}").into_bytes();
        let form = compile(b"??????", &spec, MANY);
        let alts = alternates(&spec, &form.fields[0]);
        assert_eq!(alts.len(), 1);
        assert_eq!(alts[0].len(), usize::from(ANSLEN));
    }

    #[test]
    fn a_blank_alternate_before_the_paren_does_not_leak_into_the_next_field() {
        // `nxttkn` resumes at the value's terminator and its loop guard stops
        // it on `)`. Stepping even one byte past that carries the scan into the
        // next field's options, and every ordinal after it is counted over
        // somebody else's alternates.
        let spec = b"C(ALT=Red ALT=) D(ALT=Blue ALT=Green)";
        let form = compile(b"?????? ??????", spec, MANY);

        let c = alternates(spec, &form.fields[0]);
        assert_eq!(c, vec![&b"Red"[..], &b""[..]], "C has two, not three");
        let d = alternates(spec, &form.fields[1]);
        assert_eq!(d, vec![&b"Blue"[..], &b"Green"[..]]);

        // And so the ordinals are the field's own.
        assert_eq!(
            ordinal(spec, &form.fields[1], b"Green"),
            Some((1, b"Green".to_vec()))
        );
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
    fn a_field_survives_a_round_trip_through_its_record() {
        // `from_record` is what `fsdord` reads the module's own field array
        // with, so it has to give back what `record` put in -- flags and all,
        // since the module edits those.
        for form in [
            compile(b"Ok Y/N", b"OK", MANY),
            compile(b"###-####", b"P", MANY),
            compile(b"?? ??", b"A(SECRET) B(MULTICHOICE ALT=x)", MANY),
        ] {
            for field in &form.fields {
                assert_eq!(&Field::from_record(&field.record(41, 7)), field);
            }
        }
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

    /// `chktyp()`, `FSD.C:861`. A multiple-choice field rejects *any* typed
    /// answer -- the answer has to have come from the `ALT=` list, and getting
    /// there is `chkalt`'s job, not this one's.
    #[test]
    fn a_multiple_choice_field_rejects_a_typed_answer_outright() {
        let form = compile(b"??????", b"COLOUR(MULTICHOICE ALT=RED ALT=BLUE)", MANY);
        assert_eq!(form.fields[0].flags & flags::MULTICHOICE, flags::MULTICHOICE);
        assert!(!type_ok(&form.fields[0], b"RED"), "not even a listed one");
        assert!(!type_ok(&form.fields[0], b""), "not even an empty one");
    }

    /// Every `Y/N` field is one, which is what makes the arm's `false` normal
    /// rather than exceptional.
    #[test]
    fn a_yes_no_field_rejects_a_typed_answer_because_it_is_multiple_choice() {
        let form = compile(b"Ok Y/N", b"OK", MANY);
        assert_eq!(form.fields[0].kind, b'Y');
        assert!(!type_ok(&form.fields[0], b"YES"));

        // The rest of the arm, reached by clearing the flag `tmpfld` set. `Y`
        // is grouped with `?` in the C, and this is the whole of that grouping:
        // no sign is stripped and no digit is looked for.
        let mut typed = form.fields[0];
        typed.flags = 0;
        assert!(type_ok(&typed, b"YES"));
        assert!(type_ok(&typed, b"-"));
        typed.flags = flags::NOSPACES;
        assert!(!type_ok(&typed, b"Y N"));
    }

    /// `FFFNSP` is the only other thing a `?` field checks.
    #[test]
    fn a_no_spaces_field_rejects_a_space_and_nothing_else_does() {
        let spaced = compile(b"??????", b"NAME(NOSPACES)", MANY);
        assert_eq!(spaced.fields[0].flags, flags::NOSPACES);
        assert!(!type_ok(&spaced.fields[0], b"van Gogh"));
        assert!(type_ok(&spaced.fields[0], b"vanGogh"));
        // `strchr(bufptr,' ')` is the literal blank, not `isspace`.
        assert!(type_ok(&spaced.fields[0], b"van\tGogh"));

        let plain = compile(b"??????", b"NAME", MANY);
        assert_eq!(plain.fields[0].flags, 0);
        assert!(type_ok(&plain.fields[0], b"van Gogh"));
    }

    /// A `#` field is digits only, and an empty answer passes -- `alldgs("")`
    /// is true, measured from the genuine host.
    #[test]
    fn a_hash_field_takes_digits_and_an_empty_answer() {
        let form = compile(b"####", b"AGE", MANY);
        assert!(type_ok(&form.fields[0], b"42"));
        assert!(type_ok(&form.fields[0], b""));
        assert!(!type_ok(&form.fields[0], b"-1"), "no sign on a # field");
        assert!(!type_ok(&form.fields[0], b"4a"));
        assert!(!type_ok(&form.fields[0], b"4 2"));
        // Borland's `isdigit` indexes `_ctype` with a signed char, so the high
        // half is the half worth asserting.
        assert!(!type_ok(&form.fields[0], b"\xb2"), "superscript two is not 2");
        assert!(!type_ok(&form.fields[0], b"4\xff"));
    }

    /// A `$` field takes one leading minus and then insists on at least one
    /// digit -- `FSD.C:878-881`. This is the whole difference from `#`.
    #[test]
    fn a_dollar_field_takes_a_leading_minus_but_not_an_empty_answer() {
        let form = compile(b"$$$$", b"BALANCE", MANY);
        assert!(type_ok(&form.fields[0], b"-1"));
        assert!(type_ok(&form.fields[0], b"1"));
        assert!(!type_ok(&form.fields[0], b""), "unlike a # field");
        assert!(!type_ok(&form.fields[0], b"-"), "a sign alone is not a number");
        assert!(!type_ok(&form.fields[0], b"--1"), "one minus, not two");
        assert!(!type_ok(&form.fields[0], b"1-"), "and only at the front");
        assert!(!type_ok(&form.fields[0], b"-\xb2"));
    }

    /// Neither numeric arm reads a flag, so setting one changes nothing. The
    /// C reads `FFFMCH` and `FFFNSP` in the `?`/`Y` arm and nowhere else.
    #[test]
    fn the_numeric_field_types_ignore_the_flags_the_text_ones_read() {
        let hashes = compile(b"####", b"AGE(MULTICHOICE NOSPACES)", MANY);
        assert_eq!(
            hashes.fields[0].flags,
            flags::MULTICHOICE | flags::NOSPACES,
            "the options did compile"
        );
        assert!(type_ok(&hashes.fields[0], b"42"));

        let dollars = compile(b"$$$$", b"AMT(MULTICHOICE NOSPACES)", MANY);
        assert!(type_ok(&dollars.fields[0], b"-12"));
    }

    /// The `switch` has no `default` and `rc` starts at 1, and the arm is
    /// reachable: a field the specification names and the template has no run
    /// for never gets a `fldtyp`.
    #[test]
    fn a_field_the_template_had_no_room_for_is_consistent_with_anything() {
        let form = compile(b"", b"A", MANY);
        assert_eq!(form.in_template, 0);
        assert_eq!(form.fields[0].kind, 0, "embscn never reached it");
        assert!(type_ok(&form.fields[0], b"anything at all"));
        assert!(type_ok(&form.fields[0], b""));
        assert!(type_ok(&form.fields[0], b"-"));
    }

    /// `bufptr` is a C string, and `strchr` and `alldgs` both stop at its
    /// terminator. Measured against the genuine host in `tests/fsd_statics.rs`,
    /// which is the only reason this is the behaviour rather than the other
    /// plausible one.
    #[test]
    fn an_embedded_nul_ends_the_answer() {
        let hashes = compile(b"####", b"AGE", MANY);
        assert!(type_ok(&hashes.fields[0], b"12\x00ab"));

        let dollars = compile(b"$$$$", b"AMT", MANY);
        assert!(type_ok(&dollars.fields[0], b"-1\x00a"));
        assert!(!type_ok(&dollars.fields[0], b"\x009"), "an empty answer");

        let spaced = compile(b"??????", b"NAME(NOSPACES)", MANY);
        assert!(type_ok(&spaced.fields[0], b"ab\x00 c"));
    }

    /// `chkmin`'s `?` arm reads `MIN=` as a minimum **length**, but only when
    /// it is all digits, at most two of them, and no wider than the field.
    ///
    /// The specification is `NAME(MIN=3)` and not `NAME (MIN=3)`: `fspscn` ends
    /// a field name at white space, so a space before the `(` makes the option
    /// list a second, nameless field and the first one carries no flags at all.
    #[test]
    fn a_text_minimum_that_looks_like_a_length_is_a_length() {
        let spec = b"NAME(MIN=3)";
        let form = compile(b"??????", spec, MANY);
        let field = &form.fields[0];
        assert_eq!(field.flags & flags::MINMAX, flags::MINMAX, "MIN= was read");

        assert!(min_ok(spec, field, b"abc").is_ok());
        assert_eq!(
            min_ok(spec, field, b"ab").unwrap_err(),
            "Enter at least 3 character(s)"
        );
    }

    /// ...and otherwise **falls through** to the string comparison.
    /// `FSD.C:911-912` is a `case '?'` that runs into `case '#'`, and these are
    /// the two ways to reach it: three digits, and two digits wider than the
    /// field.
    #[test]
    fn a_text_minimum_too_long_to_be_a_length_falls_through_to_a_value() {
        let spec = b"CODE(MIN=100)";
        let form = compile(b"????", spec, MANY);
        let field = &form.fields[0];
        // "099" sorts before "100", so this is refused on value, and the
        // message is the value message rather than the length one.
        assert_eq!(
            min_ok(spec, field, b"099").unwrap_err(),
            "Enter at least \"100\""
        );
        assert!(min_ok(spec, field, b"100").is_ok(), "equal is at least");
        assert!(min_ok(spec, field, b"99").is_ok(), "text order, not numeric");

        // Two digits, but 99 does not fit a two-wide field.
        let spec = b"X(MIN=99)";
        let form = compile(b"??", spec, MANY);
        assert_eq!(
            min_ok(spec, &form.fields[0], b"1").unwrap_err(),
            "Enter at least \"99\""
        );

        // Three digits that would have fitted: the digit count alone stops it.
        let spec = b"NAME(MIN=003)";
        let form = compile(b"??????", spec, MANY);
        assert!(min_ok(spec, &form.fields[0], b"ab").is_ok());
    }

    /// A `$` field compares numerically, which is the only place a number is
    /// read as a number.
    #[test]
    fn a_dollar_minimum_compares_numerically_where_a_hash_compares_as_text() {
        let dollars = b"AMT(MIN=9)";
        let form = compile(b"$$$$", dollars, MANY);
        assert!(min_ok(dollars, &form.fields[0], b"10").is_ok(), "10 >= 9");
        assert!(min_ok(dollars, &form.fields[0], b"9").is_ok(), "9 >= 9");
        assert_eq!(
            min_ok(dollars, &form.fields[0], b"8").unwrap_err(),
            "Enter at least 9"
        );

        let hashes = b"AGE(MIN=9)";
        let form = compile(b"####", hashes, MANY);
        assert_eq!(
            min_ok(hashes, &form.fields[0], b"10").unwrap_err(),
            "Enter at least \"9\"",
            "as text, \"10\" sorts before \"9\""
        );
    }

    /// `chkmax` has no fallthrough: `?` and `#` share one arm, so a `MAX=` is
    /// never a maximum length.
    #[test]
    fn a_maximum_is_never_read_as_a_length() {
        let spec = b"CODE(MAX=3)";
        let form = compile(b"????", spec, MANY);
        let field = &form.fields[0];
        assert_eq!(
            max_ok(spec, field, b"abcd").unwrap_err(),
            "Enter no higher than \"3\"",
            "four characters is not what MAX=3 is about"
        );
        assert!(max_ok(spec, field, b"2").is_ok());

        let spec = b"AMT(MAX=9)";
        let form = compile(b"$$$$", spec, MANY);
        assert!(max_ok(spec, &form.fields[0], b"9").is_ok(), "9 <= 9");
        assert_eq!(
            max_ok(spec, &form.fields[0], b"10").unwrap_err(),
            "Enter no higher than 9"
        );
    }

    /// No `MIN=`/`MAX=` at all is a pass, and so is a field type the C's
    /// `switch` does not name.
    #[test]
    fn a_field_with_no_minimum_passes_everything() {
        let form = compile(b"??????", b"NAME", MANY);
        assert_eq!(form.fields[0].flags, 0, "no options, no flags");
        assert!(min_ok(b"NAME", &form.fields[0], b"").is_ok());
        assert!(max_ok(b"NAME", &form.fields[0], b"zzzzzz").is_ok());

        // A field the template had no run for keeps `fldtyp == 0`, and the C's
        // `switch` has no `default`.
        let spec = b"A(MIN=3)";
        let form = compile(b"", spec, MANY);
        assert_eq!(form.fields[0].kind, 0);
        assert!(min_ok(spec, &form.fields[0], b"").is_ok());
    }

    /// An answer is a C string wherever these two look at it.
    #[test]
    fn an_embedded_nul_ends_the_answer_a_minimum_is_measured_against() {
        let spec = b"NAME(MIN=3)";
        let form = compile(b"??????", spec, MANY);
        assert_eq!(
            min_ok(spec, &form.fields[0], b"ab\x00cd").unwrap_err(),
            "Enter at least 3 character(s)",
            "two characters long, not four"
        );

        let spec = b"NAME(MAX=M)";
        let form = compile(b"??????", spec, MANY);
        assert!(max_ok(spec, &form.fields[0], b"M\x00Z").is_ok());
    }
}
