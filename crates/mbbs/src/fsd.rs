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
//! # Overflows of the original are not reproduced
//!
//! `tmpfld()` takes its `width` as a `char` and `xwidth` is a `char`, so in the
//! original a field run longer than 127 characters wraps *before* being clamped
//! to `ANSLEN` -- a 200-character run becomes -56, sails past `> ANSLEN`, and
//! is then added to `maxans` as a subtraction. This clamps instead. No template
//! in evidence comes near it: the longest run in either of MajorMUD's is 61,
//! and a field wider than a screen is not a thing a form can mean.
//!
//! The third is `stranslen`'s `int`, which [`put_answer`] refuses rather than
//! wraps. That one has been watched happen -- `tests/fsd_oracle.rs` calls the
//! genuine `_FSDPAN` on either side of the boundary and the far side really
//! does write the new value over the tail it should have moved.

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
    /// `int (*fldvfy)(int fldno, char *answer)` -- the field verify routine,
    /// or NULL. A far function pointer, four bytes, the same as the data
    /// pointers ahead of it -- confirmed by [`CRSATR`] landing at 20, which
    /// only holds if this is 16 through 19.
    pub const FLDVFY: u16 = 16;
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
    /// `char flags` -- the entry session's own flags, `FSD.H:397-403`.
    ///
    /// The one piece of entry-session working storage named here, and named
    /// because [`super::move_field`]'s `wrap` argument is where its `FSDANS`
    /// (0x10) bit ends up: a caller with a live session reads it from this
    /// offset. Everything else between `state` at 44 and `maxy` at 165 is
    /// deliberately absent -- see the note above.
    ///
    /// 157 is not read off the header alone. `fsdent()` and `fsdlin()` are the
    /// two routines whose first act is to set it (`FSD.C:828`, `:838`), and in
    /// `MAJORBBS-mbbstd.EXE` they are `mov byte [es:bx+0x9d],0x10` at
    /// `28:0x12e1` and `mov byte [es:bx+0x9d],0x0` at `28:0x132c`.
    pub const FLAGS: u16 = 157;

    /// `char state` -- the entry engine's own state code, see [`state`].
    /// `fsdlin()` sets it last (`FSD.C:847`), which is how [`FLAGS`]'s own
    /// doc comment above pins offset 157 -- 44 is the running total that
    /// gets there one member earlier, cross-checked against
    /// `the_session_control_block_is_the_size_the_header_declares`'s own
    /// tally.
    pub const STATE: u16 = 44;

    /// `char ansbuf[ANSLEN+1]` -- the answer being typed, as a NUL-terminated
    /// C string. 81 bytes (`ANSLEN`, 80, plus the terminator), `FSD.H:307`.
    pub const ANSBUF: u16 = 45;

    /// `char entfld` -- which field `fsdinc()` most recently finished typing
    /// into: [`super::xitfld`] sets this the moment it moves the cursor off
    /// a field and before the session enters [`state::FSDBUF`], so
    /// `fsdprc`'s `FSDBUF` arm (Task 10, not yet ported) has a fixed record
    /// of which field to validate even after `crsfld` has already moved on
    /// to the next one. `FSD.H:313`. The running total lands here, one byte
    /// ahead of [`CRSFLD`]: 45 (`ANSBUF`) plus 81 plus 1 (`anslen`, not
    /// modeled) plus 1 (`ansptr`, not modeled) plus 20 (`typahd[EXTHED]`,
    /// not modeled -- dropped per the design doc) plus 1 (`ahdptr`, not
    /// modeled) plus 1 (`hdlahd`, not modeled) -- cross-checked against
    /// `the_session_control_block_is_the_size_the_header_declares`'s own
    /// running total.
    pub const ENTFLD: u16 = 150;

    /// `char crsfld` -- `fsdinc()`'s idea of the current cursor field.
    /// `FSD.H:314`.
    pub const CRSFLD: u16 = 151;

    /// `char *ftmptr` -- pointer into the current field's embedded-
    /// punctuation template, `FSD.H:316`. Computed from `CRSFLD` (151, 1
    /// byte) + `SHFFLD` (1 byte, not otherwise modeled) landing at 153,
    /// with `FLAGS` at 157 (`FSD.H:275`'s running total, cross-checked
    /// against the header's own member order) confirming the 4 bytes a
    /// real far pointer needs fit exactly in between. See
    /// [`Scb::ftmptr`] for why this port keeps only 2 of those 4 bytes.
    pub const FTMPTR: u16 = 153;

    /// `char *altptr` -- which of the current field's `ALT=` values
    /// [`super::hdlalt`]/[`super::altntr`] currently have selected, or
    /// `NULL`. `FSD.H:318`. Sits between `FLAGS` (157, 1 byte) and `XITKEY`
    /// (162), so the real 4-byte far pointer's own 4 bytes are 158-161 --
    /// cross-checked the same way [`FTMPTR`]'s own comment is, against
    /// `the_session_control_block_is_the_size_the_header_declares`'s running
    /// total. See [`Scb::altptr`] for why this port keeps only 2 of those 4
    /// bytes, the same substitution [`FTMPTR`] already makes.
    pub const ALTPTR: u16 = 158;

    /// `int xitkey` -- the keystroke that initiated exit of the field.
    /// `FSD.H:319`.
    pub const XITKEY: u16 = 162;

    /// `char chgcnt` -- count of changes during the session. `FSD.H:320`.
    pub const CHGCNT: u16 = 164;
}

/// FSD entry-engine state codes, `FSD.H:326-334`. `fsdscb->state` drives
/// `fsdinc()`'s outer switch (Task 6-9's scope); named here rather than as
/// magic numbers, because [`fsdlin`] already writes one of them.
pub mod state {
    /// Beginning, ANSI point mode. Stage 5 -- `fsdent`, not built by this
    /// host.
    pub const FSDAPT: u8 = 0;
    /// Entering stuff, ANSI mode. Stage 5.
    pub const FSDAEN: u8 = 1;
    /// Non-ANSI point mode -- what [`fsdlin`] leaves a fresh session in
    /// (`FSD.C:847`).
    pub const FSDNPT: u8 = 2;
    /// Non-ANSI entry mode: a field is being typed into.
    pub const FSDNEN: u8 = 3;
    /// Entry ready, buffering new keystrokes for `fsdprc`.
    pub const FSDBUF: u8 = 4;
    /// Entry processed, but still buffering keystrokes.
    pub const FSDSTB: u8 = 5;
    /// Need to wipe out the help message. ANSI only.
    pub const FSDKHP: u8 = 6;
    /// Exit the session, saving the answers.
    pub const FSDSAV: u8 = 7;
    /// Exit the session, discarding the answers.
    pub const FSDQIT: u8 = 8;
}

/// `fsdscb->flags`, `FSD.H:397-403`. The entry engine's own session flags --
/// distinct from a *field*'s `FFF*` flags in [`flags`], which live on each
/// [`Field`] instead.
pub mod entry_flags {
    /// Major `fsdinc()`-induced output has taken place and we're not yet
    /// sure it all went out.
    pub const FSDQOT: u8 = 0x01;
    /// Cursor shuffle NOT sent, need to shuffle cursor.
    pub const FSDSHN: u8 = 0x02;
    /// Alternate value entry has begun.
    pub const FSDANT: u8 = 0x04;
    /// Alternate value entered.
    pub const FSDALT: u8 = 0x08;
    /// ANSI supported this session? [`move_field`]'s `wrap` argument is
    /// `udwrap && fsdscb->flags&FSDANS` -- see its own doc comment.
    pub const FSDANS: u8 = 0x10;
    /// Ignore answer, just move cursor.
    pub const FSDIGA: u8 = 0x20;
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

    /// `fldvfy`: the field verify routine the module gave `fsdego`, or
    /// [`FarPtr::NULL`] if it passed none.
    pub fn fldvfy(&self) -> FarPtr {
        self.ptr(scb::FLDVFY)
    }
    /// Set [`Scb::fldvfy`].
    pub fn set_fldvfy(&mut self, value: FarPtr) {
        self.set_ptr(scb::FLDVFY, value);
    }

    /// `state`: the entry engine's own state code. See [`state`].
    pub fn state(&self) -> u8 {
        self.byte(scb::STATE)
    }
    /// Set [`Scb::state`].
    pub fn set_state(&mut self, value: u8) {
        self.set_byte(scb::STATE, value);
    }

    /// `ansbuf`: the answer currently being typed, up to its NUL terminator.
    /// `strcpy(fsdscb->ansbuf, ...)` is how the original writes it, so the
    /// bytes after the terminator -- if any survive from an earlier,
    /// shorter answer -- are not part of the string and are not returned.
    pub fn ansbuf(&self) -> &[u8] {
        let at = usize::from(scb::ANSBUF);
        let len = usize::from(ANSLEN) + 1;
        let raw = &self.bytes[at..at + len];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        &raw[..end]
    }
    /// Set [`Scb::ansbuf`], NUL-terminated, the way `strcpy` leaves it.
    ///
    /// # Panics
    ///
    /// If `value` does not fit in `ANSLEN+1` bytes with its terminator. The
    /// original's `strcpy` has no such check -- every real caller's answer
    /// is already bounded by `fldptr->width <= ANSLEN`, so this is `fsdroom`'s
    /// refusal-over-corruption discipline applied to a member `fsdroom`
    /// itself never touches.
    pub fn set_ansbuf(&mut self, value: &[u8]) {
        let cap = usize::from(ANSLEN) + 1;
        assert!(
            value.len() < cap,
            "ansbuf is ANSLEN+1 ({cap}) bytes and a {}-byte answer plus its \
             terminator does not fit",
            value.len()
        );
        let at = usize::from(scb::ANSBUF);
        self.bytes[at..at + value.len()].copy_from_slice(value);
        self.bytes[at + value.len()] = 0;
    }

    /// `entfld`: which field was just left, recorded by [`xitfld`] the
    /// instant it moves the cursor off it. See [`scb::ENTFLD`] for why this
    /// is a separate member from [`Scb::crsfld`] rather than a duplicate of
    /// it.
    pub fn entfld(&self) -> u8 {
        self.byte(scb::ENTFLD)
    }
    /// Set [`Scb::entfld`].
    pub fn set_entfld(&mut self, value: u8) {
        self.set_byte(scb::ENTFLD, value);
    }

    /// `crsfld`: `fsdinc()`'s idea of the current cursor field.
    pub fn crsfld(&self) -> u8 {
        self.byte(scb::CRSFLD)
    }
    /// Set [`Scb::crsfld`].
    pub fn set_crsfld(&mut self, value: u8) {
        self.set_byte(scb::CRSFLD, value);
    }

    /// `ftmptr`: how far [`skppnc`]/[`addprt`]/[`unentr`] have echoed into
    /// the current field's embedded-punctuation template.
    ///
    /// The real member (`FSD.H:316`) is a 4-byte far pointer,
    /// `mbpunc + position`. This stores only `position` -- an offset into
    /// [`Form::punctuation`] -- the same substitution
    /// [`Field::punctuation_at`] already makes for `fldptr->mbpoff`, and
    /// for the same reason: every reader of this port's `ftmptr` already
    /// has `form.punctuation` in hand and none of them resolve a `mbpunc`
    /// base through `Machine` (Task 6 is pure `fsd.rs`, no shim). The other
    /// two bytes the real pointer would occupy are left in the
    /// "deliberately absent" bucket like every other untouched byte in
    /// this struct -- nothing reads them back.
    ///
    /// `0` is the value an `alczer`'d block starts with, same as the real
    /// pointer's `NULL`. [`unentr`]'s own doc comment explains why that
    /// collision -- `ftmptr==0` meaning either "never positioned" or
    /// "positioned at the very start of a field whose own `mbpoff` happens
    /// to be 0" -- never has to be told apart: both mean "nothing to
    /// erase yet", and the clamp there produces that answer either way.
    pub fn ftmptr(&self) -> u16 {
        self.word(scb::FTMPTR)
    }
    /// Set [`Scb::ftmptr`].
    pub fn set_ftmptr(&mut self, value: u16) {
        self.set_word(scb::FTMPTR, value);
    }

    /// `flags`: the entry session's own flags. See [`entry_flags`].
    pub fn flags(&self) -> u8 {
        self.byte(scb::FLAGS)
    }
    /// Set [`Scb::flags`].
    pub fn set_flags(&mut self, value: u8) {
        self.set_byte(scb::FLAGS, value);
    }

    /// `altptr`: the ordinal (within [`alternates`]'s own listing order) of
    /// the alternate [`hdlalt`]/[`altntr`] currently have selected, or
    /// `None` for the real member's `NULL`.
    ///
    /// The real member (`FSD.H:318`) is a 4-byte far pointer into the field
    /// specification text, sitting right after the matched entry's own
    /// `ALT=`. This port keeps an ordinal instead -- the same substitution
    /// [`Scb::ftmptr`]'s own doc comment explains for its pointer: every
    /// reader of this port's `altptr` already has `spec`/[`alternates`] in
    /// hand, and none of them dereference a `fldspc`-relative address
    /// through `Machine`.
    ///
    /// Stored as `ordinal + 1`, with `0` standing for `NULL` -- the reverse
    /// of [`Scb::ftmptr`]'s own `0`-means-"never positioned" choice, and
    /// deliberately so: unlike an echo position, `0` is a *legitimate*
    /// ordinal (the very first alternate), so it cannot double as the
    /// sentinel the way `ftmptr`'s own zero does. An `alczer`'d block's raw
    /// zero bytes must decode to `None` -- nothing initializes this member
    /// on purpose, the same way nothing initializes any other entry-session
    /// field -- so the offset-by-one falls on the *occupied* side, not the
    /// empty one.
    pub fn altptr(&self) -> Option<u16> {
        match self.word(scb::ALTPTR) {
            0 => None,
            n => Some(n - 1),
        }
    }
    /// Set [`Scb::altptr`].
    ///
    /// # Panics
    ///
    /// If `value` is `Some(u16::MAX)`. No field specification in evidence
    /// carries anywhere near 65535 alternates, and refusing the one ordinal
    /// the `+1` encoding cannot represent is cheaper than silently storing a
    /// wrapped `0` (`NULL`) instead.
    pub fn set_altptr(&mut self, value: Option<u16>) {
        let stored = match value {
            None => 0,
            Some(n) => {
                assert!(n != u16::MAX, "altptr ordinal {n} has no room left for the +1 encoding");
                n + 1
            }
        };
        self.set_word(scb::ALTPTR, stored);
    }

    /// `xitkey`: the keystroke that initiated exit of the field.
    pub fn xitkey(&self) -> u16 {
        self.word(scb::XITKEY)
    }
    /// Set [`Scb::xitkey`].
    pub fn set_xitkey(&mut self, value: u16) {
        self.set_word(scb::XITKEY, value);
    }

    /// `chgcnt`: count of changes during the session.
    pub fn chgcnt(&self) -> u8 {
        self.byte(scb::CHGCNT)
    }
    /// Set [`Scb::chgcnt`].
    pub fn set_chgcnt(&mut self, value: u8) {
        self.set_byte(scb::CHGCNT, value);
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
    /// `FFFCHG` -- the field has changed this session. `FSD.H:270`.
    ///
    /// Written by the entry session rather than by `fsdppc`, which is why
    /// nothing in this module sets it: `fsdent()` and friends raise it when
    /// `stfans` reports a change, and `fsdprc()`'s caller reads it back to find
    /// out which answers to save.
    pub const CHANGED: u8 = 0x10;
    /// No negative numbers allowed.
    pub const NONNEGATIVE: u8 = 0x20;
    /// Entry needs to be secret.
    pub const SECRET: u8 = 0x40;
    /// `FFFAVD` -- avoid this field when moving or displaying. `FSD.H:273`.
    ///
    /// The one flag on this list that the **module** sets rather than the
    /// specification: fourteen sites in `WCCMMUD.DLL` do
    /// `or byte [flddat + 23*i + 12], 0x80` on its own character sheet, which
    /// is how a field is shown but not typed into. [`move_field`] is what acts
    /// on it, and `fsddsp` (`FSD.C:770`) blanks such a field rather than
    /// displaying its answer.
    pub const AVOID: u8 = 0x80;
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

/// The length of an answer string, its final double NUL included.
/// `stranslen()`, `FSD.C:2061`.
///
/// Entries are walked, not bytes: each one costs `strlen+1`, and the empty
/// entry that ends the string costs the 1 added at the end. So `b"A=1\0\0"`
/// measures 5 and the empty answer string -- `fsdans`'s own `""`, `FSD.H:475`
/// -- measures 1.
///
/// **A zero-length entry *is* the terminator**, wherever it appears. The C's
/// loop condition is `*anstg != '\0'` and nothing else, so `b"\0A=1\0\0"`
/// measures 1 and everything after that first NUL is unreachable. Measured: the
/// genuine host's `_STRANSLEN` answers 1. The same fact read the other way is
/// that a trailing byte does not have to be there -- `b"\0\0"` also measures 1,
/// so the "double NUL" of the comment is the *entry's* terminator followed by
/// the *string's*, not a pair this has to find.
///
/// **The C returns an `int`.** `stranslen` accumulates into `si` and returns
/// `si+1` (`28:0x36a2`), so an answer string of 32768 bytes or more comes back
/// negative -- and `fsdpan` tests that result with a signed `jng`. This returns
/// the true length; [`put_answer`] is where the difference has to be dealt
/// with, and says what it does about it.
///
/// # Panics
///
/// If the string does not terminate inside the slice. The C reads on until it
/// finds a NUL somewhere in the segment, so there is no length here that would
/// be the right answer, and a made-up one is worse than a stop.
pub fn answer_len(answers: &[u8]) -> usize {
    let mut at = 0usize;
    loop {
        let end = answers[at..]
            .iter()
            .position(|&c| c == 0)
            .unwrap_or_else(|| {
                panic!(
                    "an answer string ends with an empty entry, and from \
                     offset {at} these {} bytes hold no NUL at all: {:02x?}",
                    answers.len() - at,
                    &answers[at..]
                )
            });
        if end == 0 {
            return at + 1;
        }
        at += end + 1;
    }
}

/// Put a value into an answer string, replacing whatever was there.
/// `fsdpan()`, `FSD.C:2092`.
///
/// Two branches, and `fsdxan` picks between them. A name already in the string
/// has its value replaced where it stands, every later entry sliding along by
/// the difference in length; a name that is not there gets a whole
/// `NAME=value` entry appended at the end, over the terminator, with a fresh
/// terminator after it.
///
/// The name is written **as given** in that second case. Matching folds case
/// and writing does not, so `put_answer(a, b"eye_col", b"Violet")` on a string
/// with no such name leaves a lower-case entry that the next lookup still
/// finds. `sameto` is where the fold happens (`FSD.C:2085`): the genuine host's
/// is at `104:0` and folds each pair of bytes through `tolower` (`1:0x2a38`),
/// which is a `ctype` table lookup whose upper-case set is exactly `A`-`Z`. So
/// [`extract`]'s `eq_ignore_ascii_case` is the same function, and `A[C` does
/// not match `A{C` however tempting the 0x20 between them looks.
///
/// # The C is a buffer and this is a `Vec`
///
/// `FSD.C:2094` says the answer string "must have room for the new value" and
/// leaves the room to the caller. Growing a `Vec` is this port's answer to that
/// requirement, and the price is the assertion below: the `Vec` has to *be* the
/// answer string. The C's `movmem` moves `stranslen(vp+nold+1)` bytes, which
/// stops at the string's own terminator, where a splice moves everything to the
/// end of the `Vec` -- and those are the same bytes only when nothing follows
/// the terminator.
///
/// # `name` and `value` are C strings
///
/// `strlen`, `strcpy` and `sprintf`'s `%s` all stop at the first NUL, so
/// `put_answer(a, b"A", b"xy\0zw")` stores `xy`, and a `name` with a NUL in it
/// is the part before it. Measured against the genuine host rather than
/// assumed, as in [`store`].
///
/// # Panics
///
/// If `answers` is not a well-formed answer string, or if the part of it that
/// follows the entry being replaced is longer than an `int` can count. The
/// second is the C's own limit and not this port's: `nstr=stranslen(vp+nold+1)`
/// is an `int` and `if (nstr > 0 ...)` is a **signed** test -- `or dx,dx / jng`
/// at `28:0x37b6` -- so past 32767 the genuine host stops moving the tail and
/// `strcpy` writes the new value over whatever happened to follow it. That is a
/// corruption rather than a behaviour, so it is refused here the way the module
/// doc's two `tmpfld` overflows are. `tests/fsd_oracle.rs` holds the
/// measurement that says the host really does it.
pub fn put_answer(answers: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    assert_eq!(
        answer_len(answers),
        answers.len(),
        "a {}-byte buffer holding a {}-byte answer string: the C splices with \
         `movmem(vp+nold+1,vp+nnew+1,stranslen(vp+nold+1))`, which moves the \
         string and stops, and a splice here moves the whole `Vec`. The two \
         are the same edit only while nothing follows the terminator",
        answers.len(),
        answer_len(answers)
    );
    // `n=strlen(name)` in `fsdxan`, `nnew=strlen(value)` in `fsdpan`.
    let name = c_str(name);
    let value = c_str(value);

    match extract(answers, name) {
        // `nold=strlen(vp)`; the tail from `vp+nold+1` to the terminator slides
        // by `nnew-nold`, and `strcpy(vp,value)` puts the value in. One splice
        // is both `movmem`s.
        Some(at) => {
            let old = value_at(answers, at).len();
            let tail = answer_len(&answers[at + old + 1..]);
            assert!(
                tail <= i16::MAX as usize,
                "{tail} bytes follow the {:?} entry, and `nstr` is an `int` the \
                 genuine host tests with `jng`: past {} it stops moving the \
                 tail and writes the new value over the head of it instead",
                String::from_utf8_lossy(name),
                i16::MAX
            );
            answers.splice(at..at + old, value.iter().copied());
        }
        // `sprintf(xannam,"%s=%s%c",name,value,'\0')`, where `xannam` is the
        // string's final NUL: the entry lands on top of it, and the `%c` is the
        // terminator that ends the string again. `sprintf`'s own NUL is the
        // entry's.
        None => {
            answers.truncate(answers.len() - 1);
            answers.extend_from_slice(name);
            answers.push(b'=');
            answers.extend_from_slice(value);
            answers.push(0);
            answers.push(0);
        }
    }
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

/// Splice one field's answer into the answer string. `stfans()`, `FSD.C:1036`.
///
/// Returns whether the answer differs from the one that was there. That is what
/// the entry session counts as a change, and it is why the comparison happens
/// **before** anything is written: after the splice the old answer is gone and
/// the question can no longer be asked.
///
/// # Changing one answer's length moves every later one
///
/// The answers all live end to end in one string, so a longer answer pushes
/// every later `ansoff` along and a shorter one pulls them back. The C walks
/// backwards from `flddat[numfld-1]` to `fldptr` adding `anslen-m` to each
/// (`FSD.C:1054-1058`), which is a `while (efptr != fldptr)` and therefore
/// leaves the stored field itself alone -- its answer starts where it always
/// did, only its length changed. Storing into the **last** field runs the loop
/// zero times, and that is the boundary worth naming rather than a special
/// case.
///
/// `allans` moves by the same delta, because the tail the C's first `movmem`
/// shifts is `allans-nl-m` bytes -- the rest of the string, terminators
/// included.
///
/// # The answer is a C string and the stored length is a byte
///
/// `anslen=strlen(bufptr)`, so an embedded NUL ends the answer: storing
/// `"DA\0N"` stores `"DA"`, and storing `"DA\0N"` over an existing `"DA"`
/// reports **no** change. `strcmp` decides the rest, so the comparison is
/// case-sensitive.
///
/// `fldptr->anslen` is one byte (`FSD.H:262`) and the genuine host reads it
/// back zero-extended -- `mov al,es:[bx+0x16] / mov ah,0` at `28:0x19bd`, so
/// that build's `char` is unsigned. A 256-byte answer therefore stores a length
/// of 0 while the offsets move by the full 256. Reproduced rather than
/// corrected: the arithmetic is the C's, in the C's 16-bit `int`.
///
/// # Panics
///
/// If `field` is not one of `answers.offsets`, or if `allans` and the string's
/// own length have come apart. The C has no such check -- `stfans` would walk
/// `flddat` past `fldptr` and never find it, adding the delta to whatever
/// follows the array until it faulted -- which is exactly why this one does.
pub fn store(answers: &mut Answers, field: usize, answer: &[u8]) -> bool {
    assert_eq!(
        usize::from(answers.allans),
        answers.text.len(),
        "an answer string of {} bytes with allans={}: the two are the same \
         number in the C, where `newans` is the buffer and `allans` its used \
         length, and the splice arithmetic below is `allans-nl-m` in one place \
         and the string's own tail in another",
        answers.text.len(),
        answers.allans
    );
    // `anslen=strlen(bufptr)`, once, and everything downstream is over that.
    let answer = c_str(answer);
    let (at, was) = answers.offsets[field];
    let (at, was) = (usize::from(at), usize::from(was));

    // `rc=(anslen != fldptr->anslen || strcmp(bufptr,fsdscb->newans+nl) != 0)`.
    // The second half reads the old answer as a C string rather than as
    // `anslen` bytes, and the two are the same only while the stored length and
    // the string agree.
    let changed = answer.len() != was || c_str(&answers.text[at..]) != answer;

    // The two `movmem`s: shift the tail to make room (or close the gap), then
    // copy the answer in. A splice is both.
    answers.text.splice(at..at + was, answer.iter().copied());

    // `fldptr->anslen=anslen`, a byte store from an `int`.
    answers.offsets[field].1 = answer.len() as u8;
    // `anslen-m` in a 16-bit `int`.
    let delta = (answer.len() as i32 - was as i32) as i16;
    for later in &mut answers.offsets[field + 1..] {
        later.0 = later.0.wrapping_add_signed(delta);
    }
    answers.allans = answers.allans.wrapping_add_signed(delta);
    changed
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

/// Every alternate that could still be `answer`, in listing order --
/// `chkalt()`'s own matching loop, `FSD.C:966-1000`, factored out because
/// [`ordinal`] and [`hdlalt`] both need it and need different things from
/// its *count*: `ordinal` only cares whether there was exactly one,
/// `hdlalt`'s own typed-character branch has to tell "nothing matched" (stop
/// entirely) apart from "more than one still could" (keep typing) -- two
/// outcomes `chkalt`'s own `int` return already distinguishes and `ordinal`
/// alone collapsed into a single `None`.
///
/// The answer is matched as a *prefix*, after every white-space character in
/// it has been removed -- `rmvwht`, which is not a trim. So `" b l "` finds
/// `Black`.
fn matching_alternates(spec: &[u8], field: &Field, answer: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let wanted = crate::strings::rmvwht(answer);
    // `bc=toupper(bufptr[0])`, over a NUL-terminated buffer -- so an *empty*
    // answer reads the terminator and `bc` is 0. That is not a degenerate case
    // to be refused: `sameto("",tp)` is true of every alternate, so the first
    // character is the whole of the test, and the only alternate whose first
    // character is also 0 is a zero-length one. A blank `ALT=` is exactly how
    // FSD.H:214 says to spell "no answer", and this is how it gets chosen.
    let upper = |s: &[u8]| s.first().map_or(0, u8::to_ascii_uppercase);
    let first = upper(&wanted);

    alternates(spec, field)
        .into_iter()
        .enumerate()
        .filter_map(|(i, alt)| {
            // `sameto(bufptr,tp)` -- the alternate begins with the answer --
            // and then `bc == toupper(*tp)`, which for a non-empty answer the
            // first test already implies and which the original checks
            // anyway.
            let same = alt.len() >= wanted.len()
                && alt[..wanted.len()].eq_ignore_ascii_case(&wanted)
                && upper(alt) == first;
            same.then(|| (i as u16, alt.to_vec()))
        })
        .collect()
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
pub fn ordinal(spec: &[u8], field: &Field, answer: &[u8]) -> Option<(u16, Vec<u8>)> {
    // `if (!(fldptr->flags&FFFALT) || foptkn("ALT=",0) == NULL) return 0;`
    if field.flags & flags::ALTERNATES == 0 {
        return None;
    }
    let mut matches = matching_alternates(spec, field, answer);
    (matches.len() == 1).then(|| matches.pop().unwrap())
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

/// `vldfld()` -- bring a proposed field number into range, or refuse.
/// `FSD.C:662`.
///
/// `wrap` is the C's `udwrap && fsdscb->flags&FSDANS`, which is two pieces of
/// state neither of them this routine's argument: `udwrap` is a file-scope
/// `int` initialised to 1 (`FSD.C:36`) that the host exposes for a sysop to
/// turn off, and `FSDANS` (0x10, `FSD.H:402`) is set by `fsdent()` and cleared
/// by `fsdlin()`. Both terms matter and both are parameters here rather than
/// globals, because a global would make this untestable and would put session
/// state in a module that has none.
///
/// # The refusal and the last field are the same number in the C
///
/// `vldfld` says "no" by returning -1, and its wrapping arm computes
/// `numtpl-1`. On a form with no fields in the template at all those are the
/// same value, so a below-zero field number on such a form is refused **even
/// with wrapping on** -- not because anything tests for it, but because the
/// arithmetic collides with the sentinel. [`None`] here is that collision kept
/// rather than tidied away.
///
/// The other end does not collide: `fldn >= numtpl` on an empty template wraps
/// to field 0, which is a field the template has no room for and which
/// [`move_field`] will then read the flags of. That is the original's
/// behaviour and not an oversight of this port.
fn valid_field(form: &Form, field: i32, wrap: bool) -> Option<usize> {
    let last = form.in_template as i32;
    if field < 0 {
        // `numtpl-1`, and `-1` is the refusal. An empty template makes them one
        // and the same, so this is not `wrap.then(...)` on its own.
        wrap.then_some(last - 1).filter(|n| *n >= 0).map(|n| n as usize)
    } else if field >= last {
        wrap.then_some(0usize)
    } else {
        Some(field as usize)
    }
}

/// `movfld()` -- the first usable field at or beyond `field`, stepping by
/// `inc`. `FSD.C:675`.
///
/// "Usable" means not flagged [`flags::AVOID`]. `resort` is what comes back
/// when there is nowhere to go: off the end of a form that does not wrap, or a
/// walk that came back to where it started.
///
/// # `resort` is an `Option`, and the C is why
///
/// The original's `resort` is an `int`, and three of its six call sites pass
/// **-1** as one (`FSD.C:1344`, `:1363`, `:1906`) and test the answer against
/// -1 afterwards: "move there, and tell me if there is no there". The other
/// three pass a real field number (`:829`, `:840`, `:1199`) and use it
/// unconditionally. A `usize` cannot say the first thing and a bare `i32`
/// makes every caller re-check the range before indexing, so the two are one
/// [`Option`] here: [`None`] is the -1, and it comes back only when the caller
/// put it in.
///
/// `inc` may be 0. `hopfld` (`FSD.C:1363`) passes it to mean "that field or
/// nothing", and it works because a zero step lands on `flast` immediately.
///
/// # Why it terminates
///
/// Only because of the two comparisons at `FSD.C:689-690`. Stepping by ±1 with
/// `wrap` on visits every field forever, so the loop is bounded by noticing
/// that it has returned to the field it was asked about (`fldi == fldn`) or
/// that the step did not move (`fldi == flast`). Drop either and a form whose
/// fields are all avoided does not answer `resort`, it does not answer at all.
///
/// Note which numbers those are. `fldi == fldn` compares against the **raw
/// argument**, which may be the -1 or the past-the-end value that was wrapped
/// on the way in and therefore may match nothing; `fldi == flast` compares
/// against the previous position, which is what catches a single-field form.
///
/// # Panics
///
/// If the walk reaches a field index `form.fields` does not have. That is
/// reachable only through the `numtpl > fields.len()` inconsistency the C reads
/// past the end of the array on, and a panic is the better of the two.
pub fn move_field(
    form: &Form,
    field: i32,
    inc: i32,
    resort: Option<usize>,
    wrap: bool,
) -> Option<usize> {
    let Some(mut at) = valid_field(form, field, wrap) else {
        return resort;
    };
    let mut last = at;
    while form.fields[at].flags & flags::AVOID != 0 {
        match valid_field(form, at as i32 + inc, wrap) {
            Some(next) if next as i32 != field && next != last => {
                last = next;
                at = next;
            }
            _ => return resort,
        }
    }
    Some(at)
}

/// The character `dspans()` echoes for a `SECRET` field's answer, in place of
/// the answer itself. `char secchr='*'`, `FSD.C:37`.
///
/// The real host's `inifsd()` (`FSDBBS.C:82`) can override this from a
/// message (`SECCHR`, `BBSFSD.MCV`) -- not modeled, because `inifsd()`
/// itself is not ported: this crate registers the FSD's `state` slot
/// directly in [`crate::Host::finish_init`] rather than by walking
/// `inifsd()`'s own body, and MajorMUD's character sheet has no `SECRET`
/// field to expose the difference. Fixed at the compiled-in default rather
/// than silently assumed to be `'*'` for other reasons.
const SECCHR: u8 = b'*';

/// `dspans()`, `FSD.C:556-630`, wrapped by [`shoabf`]. Format `answer` for
/// display against one field's width and (if it has one) embedded
/// punctuation, and return the bytes it would have sent to the channel,
/// paired with `fmtend` -- the offset, within the field's `xwidth`, of the
/// first byte the answer did not reach.
///
/// `justfy`: `0` = show the minimum of the field (stop as soon as the answer
/// given so far has been shown, no trailing padding), `1` = justify --
/// right for embedded punctuation, and per [`Field::kind`] otherwise -- `-1`
/// = left-justify unconditionally. [`fsdlin`] only ever asks for `0`; `1`
/// and `-1` exist for `shofld`/`cursat` (ANSI, Stage 5), not yet ported.
///
/// `fmtbeg`, the C's other file-scope output, is not returned: nothing this
/// crate ports yet reads it (`shofld`, Stage 5, is the one caller).
///
/// # Panics
///
/// If `field`'s `xwidth` describes more embedded-punctuation bytes than
/// `punctuation` has from `field.punctuation_at` on. Unreachable through
/// [`fsdlin`], because both come from the same compiled [`Form`]; reachable
/// only if a caller hands `dspans` a field and a punctuation array that did
/// not come from one `compile()` call together.
fn dspans(field: &Field, punctuation: &[u8], answer: &[u8], justfy: i16) -> (Vec<u8>, i16) {
    let answer = c_str(answer);
    let anslen = answer.len() as i16;
    let npad = (i16::from(field.width) - anslen).max(0);
    let n = field.xwidth;
    let secret = field.flags & flags::SECRET != 0;

    let secreted = |answer: &[u8], out: &mut Vec<u8>| {
        if secret {
            out.extend(std::iter::repeat_n(SECCHR, answer.len()));
        } else {
            out.extend_from_slice(answer);
        }
    };

    if let Some(mbpoff) = field.punctuation_at {
        let tp = &punctuation[usize::from(mbpoff)..];
        let mut out = Vec::new();
        let mut fmtend: i16 = -1;
        let mut j = 0usize;
        for (i, &c) in tp.iter().take(usize::from(n)).enumerate() {
            if c == b' ' {
                if j >= answer.len() {
                    if fmtend == -1 {
                        fmtend = i as i16;
                    }
                    if justfy == 0 {
                        break;
                    }
                    out.push(b' ');
                } else {
                    secreted(&answer[j..j + 1], &mut out);
                }
                j += 1;
            } else {
                out.push(c);
            }
        }
        if fmtend == -1 {
            fmtend = i16::from(n);
        }
        (out, fmtend)
    } else {
        let mut out = Vec::new();
        let fmtend;
        if justfy == 0 || npad == 0 {
            secreted(answer, &mut out);
            fmtend = anslen;
        } else if field.kind == b'$' && justfy != -1 {
            out.extend(std::iter::repeat_n(b' ', npad as usize));
            secreted(answer, &mut out);
            fmtend = i16::from(n);
        } else {
            secreted(answer, &mut out);
            fmtend = anslen;
            out.extend(std::iter::repeat_n(b' ', npad as usize));
        }
        (out, fmtend)
    }
}

/// `shoabf()`, `FSD.C:652-660`. [`dspans`] over `scb.ansbuf()` -- the buffer
/// [`defntr`] just seeded -- for the field at `scb.crsfld()`.
///
/// The original's second half -- `if (fldptr->mbpoff >= 0) fsdscb->ftmptr =
/// fsdscb->mbpunc+fldptr->mbpoff+fmtend;` -- sets the entry session's
/// embedded-punctuation cursor. Not modeled: nothing this crate ports before
/// Task 6 ever reads `ftmptr`, the way [`defntr`]'s own doc comment explains
/// `altptr`'s identical gap.
pub fn shoabf(form: &Form, scb: &Scb, justfy: i16) -> Vec<u8> {
    let field = &form.fields[usize::from(scb.crsfld())];
    dspans(field, &form.punctuation, scb.ansbuf(), justfy).0
}

/// `pmtfld()`, `FSD.C:795-813`. The non-ANSI prompt for the field at
/// `scb.crsfld()`: the template text between the end of the previous
/// field's run and the start of this one -- or, for the very first field,
/// a leading `"\r\n"` and the template's own text up to that field's start.
///
/// `fldptr > fsdscb->flddat` in the original is a pointer comparison; since
/// `fldptr == flddat + crsfld`, it is true exactly when `crsfld > 0`, which
/// is the test this uses.
pub fn pmtfld(form: &Form, template: &[u8], scb: &Scb) -> Vec<u8> {
    let crsfld = usize::from(scb.crsfld());
    let field = &form.fields[crsfld];
    let mut out = Vec::new();
    let ti = if crsfld > 0 {
        let prev = &form.fields[crsfld - 1];
        usize::from(prev.template_at) + usize::from(prev.xwidth)
    } else {
        out.extend_from_slice(b"\r\n");
        0
    };
    let tn = usize::from(field.template_at);
    out.extend_from_slice(&template[ti..tn]);
    out
}

/// `defntr()`, `FSD.C:786-793`. Seed `ansbuf` from the field at
/// `scb.crsfld()`'s current answer, verbatim; seed `altptr` from whichever
/// alternate (if any) that answer exactly is; clear `FSDANT`.
///
/// # `ck4alt(1)`, ported as [`exact_alternate`]
///
/// The original's third line, `fsdscb->altptr=ck4alt(1);`, is not a
/// normalization -- it does not touch `ansbuf` or `answers` at all.
/// `ck4alt` (`FSD.C:716-729`) only *looks up* whether the answer already
/// matches one of the field's `ALT=` values exactly (`tokend=1`) and, if
/// so, hands back a pointer to it; the result feeds `altptr`, the
/// cursor-tracking state [`hdlalt`]/[`altntr`] (Task 7) consume while the
/// player is mid-edit of an `ALT=` field -- most concretely, [`hdlalt`]'s
/// own space-cycling branch, which cycles *from* whatever `altptr` already
/// names rather than re-deriving a starting point when a field that already
/// has an exact-match answer is re-entered. The routine that *rewrites* an
/// answer to its canonical `ALT=` spelling is `fsdord()`, already ported as
/// [`ordinal`], and it acts on `newans` directly -- so by the time `defntr`
/// runs, `answers` already carries whatever spelling the module's own
/// `fsdord` calls left there, and `ansbuf` copies it as-is.
///
/// The scb-level `anslen` (distinct from a *field's* `anslen` byte -- see
/// [`Field`]'s own doc comment) is not modeled: nothing this crate ports
/// reads it.
///
/// # Finding "the field's current answer"
///
/// The original reads `fsdscb->newans+fldptr->ansoff`, an offset computed
/// once by `fsdans()`/`fsdord()` and stored in the field's own record. This
/// port has no access to per-field storage outside `answers` itself, so it
/// finds the same bytes the way [`answers`] built them in the first place:
/// by the field's name. The two are the same value for the same reason
/// [`fsdnan`](crate::shims::fsd::fsdnan)'s own doc comment gives for reading
/// `flddat` fresh rather than trusting a host-side copy -- `fsdord` never
/// changes a `NAME=`, only what follows it, so a name lookup finds
/// whatever `fsdord` most recently put there.
pub fn defntr(form: &Form, spec: &[u8], scb: &mut Scb, answers: &[u8]) {
    let crsfld = usize::from(scb.crsfld());
    let field = &form.fields[crsfld];
    let name = name_of(spec, field);
    let value = extract(answers, name).map_or(&[][..], |at| value_at(answers, at));
    scb.set_ansbuf(value);
    scb.set_altptr(exact_alternate(spec, field, value));
    scb.set_flags(scb.flags() & !entry_flags::FSDANT);
}

/// `fsdlin()`, `FSD.C:836-848`. Begin data entry for a non-ANSI (line-mode)
/// session: unconditional, no branches at all in the original, so this
/// calls [`pmtfld`], [`defntr`] and [`shoabf`] in that fixed order every
/// time. Returns the bytes the original would have sent with `fsdous`.
///
/// `fsdscb->ansptr=fsdscb->anslen`, between `defntr()` and `shoabf(0)` in
/// the original, is not reproduced -- both are the scb-level fields
/// [`defntr`]'s own doc comment already declines to model.
pub fn fsdlin(form: &Form, spec: &[u8], template: &[u8], scb: &mut Scb, answers: &[u8]) -> Vec<u8> {
    scb.set_flags(0);
    // `movfld(0,1,0)`: a real field number as the last-resort, not the `-1`
    // sentinel -- see `move_field`'s own doc comment for which of its six
    // call sites do which. `wrap` is `udwrap && fsdscb->flags&FSDANS`
    // (`valid_field`'s doc comment); `flags` was just zeroed above, so
    // `FSDANS` is unset and `wrap` is `false` regardless of `udwrap`.
    let crsfld = move_field(form, 0, 1, Some(0), false).unwrap_or(0);
    scb.set_crsfld(crsfld as u8);

    let mut out = pmtfld(form, template, scb);
    defntr(form, spec, scb, answers);
    out.extend(shoabf(form, scb, 0));

    scb.set_state(state::FSDNPT);
    scb.set_chgcnt(0);
    out
}

/// `entprp()`, `FSD.C:776-784`.
///
/// **Not** `FSD.C:1776-1784` -- the file has exactly one `entprp`, and this
/// plan's own citation for it was wrong; re-derived from the source rather
/// than trusted, per this repo's house rule about citing the file and not a
/// prior summary of it.
///
/// Prepare for entry mode: blank `ansbuf`, clear `FSDANT`, and null
/// `altptr`.
///
/// `anslen` and `ansptr` are not modeled. Both are this module's standing
/// substitution -- [`bgnter`] and [`fsdlin`] both derive them from
/// `ansbuf`'s own length rather than storing them separately, and blanking
/// `ansbuf` here has the same effect `anslen=ansptr=0` would.
///
/// `altptr` **is** modeled, as of Task 7, and this is the routine the
/// original clears it in (`fsdscb->altptr=NULL;`, `FSD.C:781`) -- not an
/// afterthought: without this line, a value [`hdlalt`]/[`altntr`] committed
/// on one field would survive into the next field's fresh entry, and
/// [`hdlalt`]'s own space-cycling branch reads `altptr` before anything else
/// this port ports has a chance to reset it.
pub fn entprp(scb: &mut Scb) {
    scb.set_ansbuf(b"");
    scb.set_flags(scb.flags() & !entry_flags::FSDANT);
    scb.set_altptr(None);
}

/// `skppnc()`, `FSD.C:1287-1299`. Position [`Scb::ftmptr`] at the start of
/// the current field's embedded-punctuation template, echoing every literal
/// character up to (not including) the first blank slot or the template's
/// own terminator.
///
/// # Provably dead code against this engine's own [`compile`]
///
/// Every field this engine (real or ported) produces has its punctuation
/// template start with a blank, never a literal: `embscn`/[`punctuation`]
/// both build the template starting at `fldptr->tmpoff`/`field.template_at`,
/// which is always the position of the field's *own* leading `#`/`?`/`Y`
/// character -- the very thing every entry of `tmpspc[]` compares against
/// to decide "blank or literal" in the first place, so position 0 is always
/// "matches its own kind" and therefore always a space. `skppnc`'s echo loop
/// can only ever run zero times against a `Form` this crate's own
/// `compile()` built. It is ported anyway, faithfully, because that is what
/// `FSD.C` does and because the loop is not dead against a `Form` built by
/// hand -- which is exactly how this file's own tests exercise it.
pub fn skppnc(form: &Form, scb: &mut Scb) -> Vec<u8> {
    let field = &form.fields[usize::from(scb.crsfld())];
    let mut out = Vec::new();
    if let Some(mbpoff) = field.punctuation_at {
        let mut at = usize::from(mbpoff);
        while form.punctuation[at] != b' ' && form.punctuation[at] != 0 {
            out.push(form.punctuation[at]);
            at += 1;
        }
        scb.set_ftmptr(at as u16);
    }
    out
}

/// `unentr()`, `FSD.C:699-713`. Undo the on-screen display of a field's
/// previous answer in ASCII mode: one destructive backspace (`"\b \b"`) per
/// character currently showing.
///
/// # Pulled forward from Task 8
///
/// `unentr` is named in Task 8's scope (`hdlcbs`/`unentr`/`xitfld`), not
/// Task 6's. It is ported here anyway, in full rather than stubbed, because
/// [`bgnter`]'s else-branch calls it directly and unconditionally in line
/// mode -- a stub would make every `bgnter` test either untestable or
/// trivially true. `unentr` itself is eight lines of C over state Task 6
/// already models (`ftmptr`, `ansbuf`, `punctuation_at`), so porting it
/// costs nothing `hdlcbs`/`xitfld` would need. Those two are **not** ported
/// here and remain Task 8's.
///
/// # How many characters are "currently showing"
///
/// With no embedded punctuation, it is simply `anslen` -- this port's
/// `scb.ansbuf().len()`. With punctuation, the original computes
/// `ftmptr - (mbpunc+mbpoff)`, a pointer difference; this port's `ftmptr`
/// is already an offset into the same array `mbpoff` indexes, so the
/// subtraction is direct.
///
/// # The subtraction can go negative, and that is not a bug
///
/// The very first time a field is ever entered, nothing has called
/// [`skppnc`] for it yet, so `ftmptr` is still its `alczer`'d zero. In the
/// original, `ftmptr` is a real pointer and `0` is `NULL` -- always less
/// than the real heap address `mbpunc+mbpoff` -- so the pointer-difference
/// `n` comes out strongly negative, and `while (n-- > 0)` never runs: the
/// C's own signed arithmetic already produces "erase nothing" for a field
/// that has never been shown. This port's `ftmptr` is an offset rather than
/// an address, so `0` does not sit below every real `mbpoff` the way `NULL`
/// sits below every real heap address -- the subtraction is done as `i32`
/// and clamped at zero to reproduce the same "erase nothing" outcome by
/// construction rather than by coincidence of address space.
pub fn unentr(form: &Form, scb: &Scb) -> Vec<u8> {
    let field = &form.fields[usize::from(scb.crsfld())];
    let n = if let Some(mbpoff) = field.punctuation_at {
        (i32::from(scb.ftmptr()) - i32::from(mbpoff)).max(0) as usize
    } else {
        scb.ansbuf().len()
    };
    let mut out = Vec::new();
    for _ in 0..n {
        out.extend_from_slice(b"\x08 \x08");
    }
    out
}

/// `bgnter()`, `FSD.C:1383-1407`. Begin entry/edit of the field at
/// `scb.crsfld()`: undo whatever was previously shown for it, then position
/// [`Scb::ftmptr`] at the field's own punctuation start via [`skppnc`].
///
/// # Only the ASCII (else) branch is ported
///
/// The original's `if (fsdscb->flags&FSDANS)` branch is ANSI cursor-goto
/// output (`ibm2ans`, `spaces`) -- Stage 5, not built by this host. It is
/// unreachable through every line-mode path this crate builds: [`fsdlin`]
/// zeroes `flags` outright, and nothing this crate ports before Stage 5
/// ever sets `FSDANS`. Rather than silently take the else-branch
/// regardless of what `scb.flags()` says, this checks and refuses loudly if
/// the flag is somehow set, matching this crate's refusal-over-fallback
/// discipline for a seam that is not yet built.
///
/// `fsdscb->ansptr=fsdscb->anslen=strlen(fsdscb->ansbuf)`, between the
/// `if`/`else` and the `skppnc()` call in the original, is not reproduced:
/// both are the scb-level fields this module derives from `ansbuf` itself
/// rather than storing (see [`entprp`]'s doc comment).
///
/// # Panics
///
/// If `scb.flags() & FSDANS != 0` -- see above.
pub fn bgnter(form: &Form, scb: &mut Scb) -> Vec<u8> {
    assert!(
        scb.flags() & entry_flags::FSDANS == 0,
        "bgnter: ANSI mode (FSDANS) is not ported -- Stage 5"
    );
    let mut out = unentr(form, scb);
    out.extend(skppnc(form, scb));
    out
}

/// Try to add a printable character to the end of the current field's entry
/// buffer. `addprt()`, `FSD.C:1520-1538`.
///
/// Refuses silently (no output, `ansbuf` unchanged) when the field is
/// already at `width` or the character is a space on a [`flags::NOSPACES`]
/// field -- the original's whole body is one `if`, and there is no `else`.
///
/// # Where "the cursor position" comes from
///
/// The original indexes `ansbuf[fsdscb->ansptr++]`. This port has no
/// separate `ansptr` (see [`entprp`]'s doc comment): every caller of
/// `addprt` in this crate's scope only ever appends at the end of the field
/// currently being typed, so `scb.ansbuf().len()` is `ansptr`, and the
/// append below both plays `ansptr`'s role and re-terminates the string the
/// way `ansbuf[anslen=n]='\0'` does.
pub fn addprt(form: &Form, scb: &mut Scb, c: u8) -> Vec<u8> {
    let field = &form.fields[usize::from(scb.crsfld())];
    let mut out = Vec::new();
    let ansptr = scb.ansbuf().len();
    if usize::from(field.width) > ansptr && (field.flags & flags::NOSPACES == 0 || c != b' ') {
        let mut answer = scb.ansbuf().to_vec();
        answer.push(c);
        scb.set_ansbuf(&answer);

        out.push(if field.flags & flags::SECRET != 0 {
            SECCHR
        } else {
            c
        });

        // `while ((c=*++fsdscb->ftmptr) != ' ' && c != '\0') fsdouc(c);` --
        // pre-increment, so this always steps at least one byte past
        // wherever `skppnc`/the previous `addprt` left `ftmptr`, then
        // echoes every literal character up to the next blank slot or
        // terminator. Unlike `skppnc`'s own leading-punctuation loop, this
        // one is very much reachable: typing the last digit before a
        // literal separator (`"###-####"`'s dash) is exactly the case that
        // exercises it.
        if field.punctuation_at.is_some() {
            let mut at = usize::from(scb.ftmptr()) + 1;
            while form.punctuation[at] != b' ' && form.punctuation[at] != 0 {
                out.push(form.punctuation[at]);
                at += 1;
            }
            scb.set_ftmptr(at as u16);
        }
    }
    out
}

/// What [`hdlprt`] decided about one printable character, mirroring the
/// original's `int` return: `0`/`1`/`-1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hdlprt {
    /// `0`: the field says no to this character outright -- it is neither
    /// entered nor handled.
    Ignore,
    /// `1`: the caller should append it, with [`addprt`] (or, on the very
    /// first character of a fresh field, `fsdinc`'s own `bgnter()` +
    /// [`addprt`] sequence -- Task 9's wiring, not built here).
    Enter,
    /// `-1`: already handled -- an `ALT=` match completed and `altntr()`
    /// echoed it itself, so the caller does nothing further. Never
    /// produced by this port: only Task 7's `hdlalt`/`altntr` produce it,
    /// and [`hdlprt`] refuses loudly rather than guess at their behaviour.
    /// Named here so [`Hdlprt`] states the whole contract `hdlprt()`
    /// promises its caller, not just the part this task builds.
    Handled,
}

/// `bstalt()`, `FSD.C:1558-1569`. Can an ordinary backspace "bust through" a
/// committed alternate value? Task 8's `hdlcbs` is the only intended caller
/// -- ported here, ahead of Task 8, because this is the task that starts
/// setting [`Scb::altptr`] in the first place, and a routine that reads a
/// member nothing else writes yet would be untestable.
///
/// `true` means backspace may proceed: either nothing is committed
/// (`altptr` is `None`), or the field is a plain `?` field that is not
/// itself [`flags::MULTICHOICE`] -- an ALT= list offered as a shortcut
/// alongside ordinary typing, where starting over is safe -- in which case
/// [`Scb::altptr`] is cleared as a side effect (`fsdscb->altptr=NULL;`,
/// `FSD.C:1566`). `false` means a MULTICHOICE field's own committed choice,
/// or a `#`/`$` field's, is not undone by a bare backspace; `altptr` is left
/// alone.
pub fn bstalt(field: &Field, scb: &mut Scb) -> bool {
    if scb.altptr().is_some() {
        if field.flags & flags::MULTICHOICE != 0 || field.kind != b'?' {
            return false;
        }
        scb.set_altptr(None);
    }
    true
}

/// `hdlcbs()`, `FSD.C:1571-1585`. Handle a backspace in ASCII (line) mode:
/// move the cursor destructively, one `"\b \b"` per character erased.
///
/// # `ansptr > 0`, ported as "`ansbuf` is not empty"
///
/// The same substitution [`addprt`]'s own doc comment already makes: every
/// caller in this crate's scope only ever edits at the end of the field
/// currently being typed, so `scb.ansbuf().len()` plays `ansptr`'s role.
/// `&&` short-circuits in both the original and here, so [`bstalt`] is
/// never even called on an empty field -- it has nothing to bust through
/// yet, and calling it anyway would risk clearing an `altptr` a genuinely
/// empty field never had reason to hold.
///
/// # The embedded-punctuation walk
///
/// `while (*--fsdscb->ftmptr != ' ')` pre-decrements before testing, so it
/// steps back over every literal punctuation byte [`addprt`]'s own forward
/// walk most recently echoed -- the dash in `"###-####"`, for one -- each
/// one costing its own `"\b \b"`, and stops the instant it lands back on a
/// blank slot: the value slot the character itself occupied. That slot's
/// own erase is the unconditional `fsdous("\b \b")` right after the loop,
/// not part of it, which is why the loop's own body never fires for a field
/// with no embedded punctuation at all (`fldptr->mbpoff < 0` skips the
/// whole block).
///
/// Terminates for the reason [`unentr`]'s own doc comment gives [`skppnc`]'s
/// leading walk: [`compile`] never places a value slot anywhere but on a
/// blank, so stepping back from wherever [`addprt`] last left `ftmptr`
/// always finds one -- at the very latest, the current field's own leading
/// slot.
///
/// `fsdscb->ansptr--; fsdscb->anslen--; ...ansbuf[anslen]='\0';` -- three
/// statements that all say the same thing this port's `ansbuf`-is-the-
/// source-of-truth substitution already says once: drop the answer's last
/// byte and re-terminate. [`Scb::set_ansbuf`] does both.
pub fn hdlcbs(form: &Form, scb: &mut Scb) -> Vec<u8> {
    let field = form.fields[usize::from(scb.crsfld())];
    let mut out = Vec::new();
    if !scb.ansbuf().is_empty() && bstalt(&field, scb) {
        let mut answer = scb.ansbuf().to_vec();
        answer.pop();
        scb.set_ansbuf(&answer);

        if field.punctuation_at.is_some() {
            let mut at = usize::from(scb.ftmptr());
            loop {
                at -= 1;
                if form.punctuation[at] == b' ' {
                    break;
                }
                out.extend_from_slice(b"\x08 \x08");
            }
            scb.set_ftmptr(at as u16);
        }
        out.extend_from_slice(b"\x08 \x08");
    }
    out
}

/// Every alternate whose value case-insensitively *starts with* `answer`,
/// first-in-list first. `ck4alt(0)`'s own search (`foptkn(bufptr,0)` over
/// `"ALT="+answer`), used by [`hdlalt`]'s space-cycling branch to seed a
/// cycle from whatever has already been typed, when nothing is selected yet.
///
/// `None` if `answer` is empty -- `ck4alt`'s own `anslen==0` guard,
/// `FSD.C:723-725`: an empty answer would match every alternate via `sameto`
/// and "everything" is not a seed.
fn first_alternate_starting_with(spec: &[u8], field: &Field, answer: &[u8]) -> Option<u16> {
    if answer.is_empty() {
        return None;
    }
    alternates(spec, field)
        .into_iter()
        .position(|alt| alt.len() >= answer.len() && alt[..answer.len()].eq_ignore_ascii_case(answer))
        .map(|i| i as u16)
}

/// The alternate whose value case-insensitively *equals* `answer` exactly,
/// if there is one. `ck4alt(1)`'s own search (`tokend=1`, an exact-boundary
/// match rather than [`first_alternate_starting_with`]'s prefix one),
/// `FSD.C:715-729`. Used by [`defntr`] to seed [`Scb::altptr`] from a
/// field's pre-existing answer when a session starts on an already-answered
/// field.
fn exact_alternate(spec: &[u8], field: &Field, answer: &[u8]) -> Option<u16> {
    if answer.is_empty() {
        return None;
    }
    alternates(spec, field)
        .into_iter()
        .position(|alt| alt.eq_ignore_ascii_case(answer))
        .map(|i| i as u16)
}

/// The alternate right after `at`, in [`alternates`]'s own listing order, or
/// `None` if `at` was the last one. `nxttkn(altptr,"ALT=",0)`, `FSD.C:1437`
/// -- a second scan of the specification text starting just past the
/// current match, stopping at the option list's own `)`. Since
/// [`alternates`] already enumerates every entry that scan could find, "the
/// next index, if the list reaches that far" is the same answer.
fn next_alternate(spec: &[u8], field: &Field, at: u16) -> Option<u16> {
    let next = at + 1;
    (usize::from(next) < alternates(spec, field).len()).then_some(next)
}

/// `altntr()`, `FSD.C:1409-1425`. Commit `spelling` -- the alternate at
/// ordinal `at` -- as the field's answer: record `at` in [`Scb::altptr`],
/// erase whatever was showing ([`bgnter`]), overwrite `ansbuf` with the
/// canonical spelling and redisplay it ([`shoabf`]), clear `FSDANT`, and set
/// `FSDQOT`.
///
/// # `bgnter` runs before `ansbuf` is overwritten, not after
///
/// The original's own order is `strcpy(fsdscb->ansbuf,bufptr); bgnter();` --
/// ansbuf already holds the *new* value by the time `bgnter()` (and the
/// `unentr()` inside it) runs. That is not a bug there: `unentr()` erases
/// based on `fsdscb->anslen`, a separately-tracked field that still holds
/// the *old* length at that point (its own update, `anslen=strlen(ansbuf)`,
/// happens inside `bgnter()` itself, one line after `unentr()` already used
/// the old value). This port has no such separate field -- `entprp`'s own
/// doc comment names `scb.ansbuf().len()` as the standing substitution for
/// `anslen` -- so it has to get the same answer a different way: by calling
/// [`bgnter`] (whose [`unentr`] erases what's *currently* in `ansbuf`)
/// before overwriting it, rather than after. `hdlprt`'s own two reset
/// branches hit the identical trap; see either of their doc comments for a
/// second instance of the same fix.
///
/// # Only the non-ANSI half runs
///
/// The original's `if (fsdscb->flags&FSDANS) { shoabf(-1); ansmov(...); }`
/// branch is unreachable here for the same reason [`bgnter`]'s own ANSI
/// branch is: [`bgnter`] (called first) already asserts `FSDANS` is unset,
/// so by the time this function would test it, the answer is already known.
/// Calling [`shoabf`] with `justfy=0` unconditionally is that assertion's
/// consequence made explicit rather than a second, redundant check.
fn altntr(form: &Form, scb: &mut Scb, at: u16, spelling: &[u8]) -> Vec<u8> {
    scb.set_altptr(Some(at));
    let mut out = bgnter(form, scb);
    scb.set_ansbuf(spelling);
    out.extend(shoabf(form, scb, 0));
    scb.set_flags((scb.flags() & !entry_flags::FSDANT) | entry_flags::FSDQOT);
    out
}

/// `hdlalt(c)`, `FSD.C:1427-1484`. Handle one character typed into a field
/// that carries an `ALT=` list.
///
/// # The two branches
///
/// A space, on a [`flags::MULTICHOICE`] field, with `FSDQOT` not already set
/// (i.e. nothing from a previous commit is still pending display): an
/// if/else-if, not independent fallbacks (`FSD.C:1437-1442`) --
/// - something is already selected: the next alternate after it, in list
///   order, and *only* that; a selection that already sits on the last
///   alternate finds no next one here and falls through empty-handed rather
///   than trying to match `ansbuf` (which, being that same selection's own
///   spelling, would just match itself).
/// - nothing is selected: the first alternate that matches whatever has
///   already been typed.
///
/// Either way, landing empty-handed wraps: the very first alternate in the
/// list is used instead (`FSD.C:1443-1445`). This is what makes repeated
/// spaces actually cycle -- last alternate, one more space, back to the
/// first -- rather than getting stuck once the end is reached. If the
/// landed-on alternate is the one already selected (a one-alternate list,
/// most commonly, where "next" and "wrap to first" are the same answer),
/// nothing happens ([`Hdlprt::Ignore`]). Otherwise it is committed via
/// [`altntr`] and the character is [`Hdlprt::Handled`].
///
/// Any other character: builds a candidate out of whatever has already been
/// typed this attempt (`ansbuf`, but only if `FSDANT` says an ambiguous
/// match is already underway -- otherwise a fresh one-character candidate,
/// matching [`hdlprt`]'s own already-established substitution for `bufptr`)
/// plus `c`, then asks [`matching_alternates`]:
/// - no matches: [`Hdlprt::Ignore`], the character is rejected outright.
/// - exactly one: committed via [`altntr`], [`Hdlprt::Handled`].
/// - more than one: [`Hdlprt::Enter`] -- the caller's own [`addprt`] appends
///   it -- and, the *first* time this field becomes ambiguous, `FSDANT` is
///   set and (if anything was already showing) the field is blanked and
///   redrawn via [`bgnter`].
///
/// A space that is neither (not MULTICHOICE, or `FSDQOT` already set) falls
/// through both branches to [`Hdlprt::Ignore`], matching the original's own
/// fall-through to its final `return(0);`.
pub fn hdlalt(form: &Form, spec: &[u8], scb: &mut Scb, c: u8) -> (Hdlprt, Vec<u8>) {
    let field = form.fields[usize::from(scb.crsfld())];
    if field.flags & flags::ALTERNATES == 0 {
        return (Hdlprt::Ignore, Vec::new());
    }

    if c == b' ' && field.flags & flags::MULTICHOICE != 0 && scb.flags() & entry_flags::FSDQOT == 0 {
        let old = scb.altptr();
        // `if ((altptr=fsdscb->altptr) != NULL) { nxttkn } else if (anslen>0)
        // { ck4alt }`, `FSD.C:1437-1442` -- an if/else-if, not two
        // independent fallbacks. When something is already selected
        // (`old.is_some()`), only `next_alternate` may produce a candidate;
        // `ansbuf` at that point holds the *current* selection's own
        // spelling (set by the previous `altntr()`), so seeding from it here
        // would just match the alternate already selected and get stuck
        // instead of falling through to the wrap-to-first step below.
        let mut candidate = if let Some(at) = old {
            next_alternate(spec, &field, at)
        } else if !scb.ansbuf().is_empty() {
            first_alternate_starting_with(spec, &field, scb.ansbuf())
        } else {
            None
        };
        // `if (altptr == NULL) { altptr=foptkn("ALT=",0); }`, `FSD.C:1443-1445`
        // -- unconditional once the branch above didn't land anywhere: this
        // is the wrap, landing back on the first alternate in the list.
        if candidate.is_none() && !alternates(spec, &field).is_empty() {
            candidate = Some(0);
        }
        match candidate {
            None => (Hdlprt::Ignore, Vec::new()),
            Some(at) if Some(at) == old => (Hdlprt::Ignore, Vec::new()),
            Some(at) => {
                let spelling = alternates(spec, &field)[usize::from(at)].to_vec();
                (Hdlprt::Handled, altntr(form, scb, at, &spelling))
            }
        }
    } else if c != b' ' {
        let mut candidate = Vec::new();
        if scb.flags() & entry_flags::FSDANT != 0 {
            candidate.extend_from_slice(scb.ansbuf());
        }
        candidate.push(c);

        let mut matches = matching_alternates(spec, &field, &candidate);
        match matches.len() {
            0 => (Hdlprt::Ignore, Vec::new()),
            1 => {
                let (at, spelling) = matches.pop().unwrap();
                (Hdlprt::Handled, altntr(form, scb, at, &spelling))
            }
            _ => {
                let mut out = Vec::new();
                if scb.flags() & entry_flags::FSDANT == 0 {
                    scb.set_flags(scb.flags() | entry_flags::FSDANT);
                    scb.set_altptr(None);
                    if !scb.ansbuf().is_empty() {
                        // `bgnter()` (via `unentr()`) has to run *before*
                        // `ansbuf` is blanked on an unpunctuated field: this
                        // port's `unentr` reads its erase count off
                        // `scb.ansbuf().len()`, the standing substitution
                        // for the original's separately-tracked `anslen`
                        // (see `entprp`'s own doc comment) -- and that
                        // substitution only holds if the blank hasn't
                        // already happened. The original gets away with
                        // blanking first because `anslen` is a real,
                        // independent field that still holds the old count
                        // at the moment `unentr()` reads it; this port has
                        // no such field to lag behind the string.
                        out.extend(bgnter(form, scb));
                        scb.set_ansbuf(b"");
                    }
                }
                (Hdlprt::Enter, out)
            }
        }
    } else {
        (Hdlprt::Ignore, Vec::new())
    }
}

/// `hdlprt(c)`, `FSD.C:1486-1518`. Decide what a printable character means
/// for the field at `scb.crsfld()`.
///
/// # The two field-type arms
///
/// A `Y`/`?` field with [`flags::MULTICHOICE`] set routes to [`hdlalt`]
/// unconditionally; without it, every character is accepted (`return(1)`
/// regardless of what `c` is -- [`addprt`] is where width and
/// [`flags::NOSPACES`] actually get enforced).
///
/// A `#`/`$` field accepts a digit (or, on a non-[`flags::NONNEGATIVE`] `$`
/// field with nothing typed yet, a leading `-`) *unless* alternate-value
/// entry is already underway and there is something typed to lose
/// (`!FSDANT || ansbuf is empty`) -- otherwise it falls through to
/// [`hdlalt`] the same as an unrecognised character on any other field
/// would. Accepting a digit resets any alternate-matching in progress --
/// blanks `ansbuf`, re-runs [`bgnter`], clears `FSDANT` and nulls `altptr`
/// -- which is why this returns output bytes: it is the one branch of
/// `hdlprt` with a side effect beyond its own verdict.
///
/// # Why the reset checks `altptr`, not just `FSDANT`
///
/// The original's guard is `fsdscb->flags&FSDANT || fsdscb->altptr != NULL`
/// (`FSD.C:1508`) -- both halves, not one. Task 6 ported only the `FSDANT`
/// half, on the reasoning that nothing before Task 7 ever made `altptr`
/// non-`NULL`, so the two conditions could not yet come apart. Task 7 is
/// exactly what breaks that: [`hdlalt`]'s typed-character branch clears
/// `FSDANT` in the very same call that [`altntr`] sets `altptr` (a
/// completed, unambiguous match), so a `#`/`$` field that also carries an
/// `ALT=` list (legal per `FSD.H`, even though it is not
/// [`flags::MULTICHOICE`]) can be typed into: `AGE(ALT=UNKNOWN)`, type
/// "UNKNOWN" to commit it (`altptr=Some(0)`, `FSDANT` cleared by that same
/// commit), then type a digit -- `FSDANT` alone now reads `false` and the
/// stale "UNKNOWN" would neither be erased on screen nor cleared from
/// `ansbuf`, so `addprt` would append the digit onto the end of it
/// (`"UNKNOWN5"`) instead of starting fresh. Checking `scb.altptr().is_some()`
/// alongside `FSDANT` closes that gap and matches the original exactly.
/// (MajorMUD's own three `ALT=` fields -- `HAIR_COL`, `EYE_COL`, the
/// terminal `SAVE` field -- are all `?`/[`flags::MULTICHOICE`], which never
/// reaches this arm at all, so this fix is not observable through this
/// crate's acceptance test; it is real regardless, reachable through this
/// port's own `hdlalt`/`hdlprt` on any `#`/`$` ALT= field a specification
/// could name.)
pub fn hdlprt(form: &Form, spec: &[u8], scb: &mut Scb, c: u8) -> (Hdlprt, Vec<u8>) {
    let field = form.fields[usize::from(scb.crsfld())];
    match field.kind {
        b'Y' | b'?' => {
            if field.flags & flags::MULTICHOICE != 0 {
                hdlalt(form, spec, scb, c)
            } else {
                (Hdlprt::Enter, Vec::new())
            }
        }
        b'#' | b'$' => {
            let fsdant = scb.flags() & entry_flags::FSDANT != 0;
            let empty = scb.ansbuf().is_empty();
            let is_minus = c == b'-'
                && field.kind == b'$'
                && empty // `fsdscb->ansptr == 0`, this port's ansbuf-is-empty
                && field.flags & flags::NONNEGATIVE == 0;

            if (!fsdant || empty) && (c.is_ascii_digit() || is_minus) {
                let mut out = Vec::new();
                if fsdant || scb.altptr().is_some() {
                    // `bgnter()` before the blank, not after -- see
                    // `hdlalt`'s own identical reset for why this port's
                    // `unentr` needs `ansbuf` still holding its old value
                    // when it computes how much to erase.
                    out.extend(bgnter(form, scb));
                    scb.set_ansbuf(b"");
                    scb.set_flags(scb.flags() & !entry_flags::FSDANT);
                    scb.set_altptr(None);
                }
                (Hdlprt::Enter, out)
            } else {
                hdlalt(form, spec, scb, c)
            }
        }
        _ => (Hdlprt::Enter, Vec::new()),
    }
}

/// `xitfld(finc)`, `FSD.C:1336-1353`. Exit entry of the current field and
/// move the cursor: `finc` is `+1`/`-1`/`0` for higher/lower/stay, the same
/// convention [`move_field`]'s own doc comment already documents for its
/// `inc` argument -- `xitfld` is one of [`move_field`]'s six call sites.
///
/// # What is ported, and what is not
///
/// Four of the original's six statements are mode-neutral and are all that
/// is here:
/// - `fsdscb->ansbuf[fsdscb->anslen]='\0'` is not reproduced. It is not
///   dropped, either -- [`Scb::set_ansbuf`] already keeps `ansbuf`
///   NUL-terminated on every write, the same standing invariant
///   [`defntr`]/[`entprp`]'s own doc comments rely on, so the byte this
///   statement writes is already correct before `xitfld` ever runs.
/// - `fsdscb->entfld=fsdscb->crsfld` **is** ported, as [`Scb::set_entfld`]:
///   see [`scb::ENTFLD`]'s own doc comment for why this needed a new
///   accessor rather than reusing `crsfld`.
/// - `movfld(fsdscb->crsfld+finc,finc,-1)` is ported as [`move_field`] with
///   `resort: None` (this port's `-1`) and `wrap: false`. `wrap` is
///   `udwrap && fsdscb->flags&FSDANS` (`valid_field`'s own doc comment,
///   already established by [`fsdlin`]'s identical call) -- and `FSDANS` is
///   never set anywhere in this port's line-mode path, the same fact
///   [`bgnter`]'s own assertion polices, so `wrap` is `false` regardless of
///   `udwrap` for exactly the reason [`fsdlin`]'s own call already is.
/// - `fsdscb->state=FSDBUF` **is** ported.
///
/// Two are not:
/// - `if (fsdscb->flags&FSDANS) { fsdous(fsdscb->flddat[fldn].ansgto); }` --
///   the one line Task 8 was scoped to treat as dead code in line mode
///   rather than silently drop. Guarded here the same way [`bgnter`] already
///   guards its own ANSI branch: an assertion that fires loudly if `FSDANS`
///   is ever set, rather than a branch nothing can reach yet. (There would
///   be nothing faithful to send even if it fired -- [`Field::record`]'s own
///   doc comment explains why every `ansgto` this port ever produces is
///   zeroed.)
/// - `fsdscb->ahdptr=0` and `fsdnfy()` -- both entirely outside what this
///   crate's `fsd.rs` models. `ahdptr` belongs to `typahd`, dropped in full
///   per the design doc's "Dropped" list (see [`scb::ENTFLD`]'s own doc
///   comment, which explains the same gap for its neighbours). `fsdnfy()`
///   is the host-level `CYCLE` re-arm ([`crate::shims::fsd`]'s `Machine`
///   territory, wired up by Task 9's `fsdinc` dispatcher) -- not a thing a
///   pure `&Form`/`&mut Scb` function can do at all.
///
/// # Panics
///
/// If `scb.flags() & FSDANS != 0` -- see above.
pub fn xitfld(form: &Form, scb: &mut Scb, finc: i32) {
    assert!(
        scb.flags() & entry_flags::FSDANS == 0,
        "xitfld: ANSI mode (FSDANS) is not ported -- Stage 5's cursor-goto \
         echo (`fsdous(fldptr->ansgto)`) is dead code without it"
    );
    scb.set_entfld(scb.crsfld());
    if let Some(fldn) = move_field(form, i32::from(scb.crsfld()) + finc, finc, None, false) {
        scb.set_crsfld(fldn as u8);
    }
    scb.set_state(state::FSDBUF);
}

/// `fsdinc(c)`'s `FSDNPT`/`FSDNEN` cases -- the non-ANSI (line-mode)
/// keystroke dispatch. `FSD.C:1877-1888` (`FSDNPT`) and `:1889-1940`
/// (`FSDNEN`), re-derived directly from the file rather than trusted from
/// this plan's own transcription, per this repo's house rule.
///
/// # Why `byte: u8`, and what that already refuses for free
///
/// The original's `c` is an `int`. Values `0..255` are real keystrokes;
/// values that are exact multiples of 256 (`CRSRUP`, `CRSRDN`, `BAKTAB`,
/// `CRSRLF`, `CRSRRT`, `HOME`, `END`, `DEL`, `CTRLHOME`, `CTRLEND`,
/// `CTRLPGUP`, `CTRLPGDN` -- `GCOMM.H:169-185`) are two-byte special codes
/// `getchc()` assembles out of a BIOS scan code when it recognizes a cursor
/// key. This host's line-mode input never scans for those -- that is
/// exactly the ANSI cursor-key handling Stage 5 would add -- so a `u8`
/// parameter excludes every one of them at the type level, with no runtime
/// guard needed: there is no `u8` value equal to `72*256`. `TAB` (9) and
/// `ESC` (27, `GCOMM.H:180-181`) are ordinary bytes and stay reachable;
/// `'U'-64`, `'L'-64`, `'O'-64`, `'G'-64` (0x15, 0x0c, 0x0f, 0x07) are the
/// literal control characters those expressions evaluate to and are
/// reachable the same way.
///
/// # `'L'-64` (`fsdqdp()`) is refused, not silently dropped
///
/// `fsdqdp()` (`FSDBBS.C:407-411`) sets a host-side redisplay flag
/// (`fsdusr->flags|=FBRDSP`) and re-arms `CYCLE` via `fsdnfy()` so a later
/// poll pass redraws the whole screen -- machinery this crate's `Host` does
/// not have (no `FBRDSP` equivalent, no `fsdnfy` port), and it is not
/// ANSI-specific, so it falls under neither Tasks 6-8's ports nor this
/// plan's Stage 5 deferral list. Silently doing nothing on Ctrl-L would
/// look identical to a correct implementation in every test that never
/// presses it, so this refuses loudly instead, the same
/// refusal-over-fallback discipline [`bgnter`]/[`xitfld`] already apply to
/// their own out-of-scope ANSI branches.
///
/// # `fsdnfy()` and `ahdptr=0`, inside `xitfld`'s own original body
///
/// Not called here either, for the reason [`xitfld`]'s own doc comment
/// gives: both are `Machine`/`Host` territory a pure `&Form`/`&mut Scb`
/// function cannot reach. Whatever eventually wraps this `fsdinc` in
/// `Machine` I/O is where they belong; this function stays pure like every
/// function it calls.
///
/// # The subtlety `FSDNPT`'s missing `break` preserves
///
/// The original's `case FSDNPT:` body only runs -- and only sets
/// `state=FSDNEN` -- when `c` is a genuine printable byte (`'!' <= c`); for
/// every byte below that (backspace, `\r`, Ctrl-U, ESC, ...) control falls
/// straight through the missing `break` into `case FSDNEN:`'s own
/// `switch(c)`, with `fsdscb->state` **untouched**. That is not cosmetic:
/// the `'U'-64` branch below reads `fsdscb->state` mid-switch to decide
/// whether to erase what is on screen before backing out of the field, and
/// the answer differs depending on whether this call arrived via a direct
/// `FSDNEN` dispatch (state already `FSDNEN`, something was mid-typed,
/// erase it) or via `FSDNPT`'s fallthrough (state still `FSDNPT`, nothing
/// has been typed into this field this session, nothing to erase). This
/// port reproduces the fallthrough by testing `scb.state()` once, up
/// front, only to decide whether the point-mode arm's own body should run
/// at all -- it never writes `FSDNEN` back for a byte that took the
/// fallthrough path, so the read further down still sees the truth.
///
/// # The "double `bgnter`" `FSDNPT`'s own body produces, and why it is not a bug
///
/// `case FSDNPT`'s body runs `ansbuf[0]='\0'; bgnter(); addprt(c);`
/// unconditionally whenever `hdlprt(c)==1`, with no regard for whether
/// [`hdlprt`] already performed its own reset-and-erase internally -- its
/// `#`/`$` branch does, exactly when a digit follows an aborted or
/// committed `ALT=` match (see [`hdlprt`]'s own doc comment). A field can
/// reach `FSDNPT` with a non-empty, `ALT=`-matching answer already seeded
/// by [`defntr`] (returning to an already-answered numeric field, say), so
/// both erasures really can fire back to back on the very same keystroke.
/// That is what `FSD.C:1881-1885` says to do, and this port does it too.
///
/// # `bgnter` before the blank, not after
///
/// The C's own statement order is `ansbuf[0]='\0'; bgnter();` -- blank
/// first. This port runs [`bgnter`] first and blanks second, the same
/// reordering [`altntr`]'s own doc comment already explains and
/// [`hdlprt`]'s two reset branches already apply: [`unentr`] (called
/// inside `bgnter`) measures how much to erase off `scb.ansbuf().len()`,
/// this port's standing substitution for the C's separately-tracked
/// `anslen` -- and that substitution only gives the right answer while
/// `ansbuf` still holds what was actually on screen, i.e. before the blank
/// the C's own `anslen` would not see either.
///
/// # Panics
///
/// If `scb.state()` is not [`state::FSDNPT`] or [`state::FSDNEN`] --
/// `FSDAPT`/`FSDAEN` (ANSI) are Stage 5, and `FSDBUF`/`FSDSTB` (typeahead
/// accumulation between an `fsdinc` call and `fsdprc` catching up) are
/// dropped per the design doc's "Dropped" list, neither built by this
/// crate. Or if `byte` is Ctrl-L -- see above.
pub fn fsdinc(form: &Form, spec: &[u8], scb: &mut Scb, byte: u8) -> Vec<u8> {
    assert!(
        matches!(scb.state(), state::FSDNPT | state::FSDNEN),
        "fsdinc: state {} is neither FSDNPT nor FSDNEN -- FSDAPT/FSDAEN \
         (ANSI) are Stage 5 and FSDBUF/FSDSTB (typeahead accumulation) are \
         not this function's cases",
        scb.state()
    );

    let mut out = Vec::new();

    // Falls through to FSDNEN's own switch below, with `state` left at
    // FSDNPT, when this is false -- see this function's own doc comment.
    if scb.state() == state::FSDNPT && byte >= b'!' {
        scb.set_state(state::FSDNEN);
        // `fsdscb->ansptr=0` / the matching `...=fsdscb->anslen` that
        // bracket this whole arm in the original are not modeled -- see
        // `addprt`'s own doc comment for ansptr's standing substitution.
        let (verdict, prt_out) = hdlprt(form, spec, scb, byte);
        out.extend(prt_out);
        if verdict == Hdlprt::Enter {
            out.extend(bgnter(form, scb));
            scb.set_ansbuf(b"");
            out.extend(addprt(form, scb, byte));
        }
        return out;
    }

    match byte {
        b'\r' | b'\t' => {
            // CRSRDN is a special code, already excluded by `byte: u8`.
            scb.set_xitkey(u16::from(byte));
            if usize::from(scb.crsfld()) + 1 < form.in_template {
                xitfld(form, scb, 1);
            } else {
                // The last field: stay put but still commit it, then step
                // crsfld one past the end by hand (not through move_field)
                // -- the out-of-range sentinel fsdprc's own FSDBUF arm
                // (Task 10, not built here) reads to know the form is
                // complete.
                xitfld(form, scb, 0);
                scb.set_crsfld(scb.crsfld() + 1);
            }
        }
        0x15 => {
            // 'U'-64: CRSRUP/BAKTAB's ASCII alias, move to the previous
            // field. `movfld` is called first only to test whether one
            // exists -- it has no side effect of its own, matching how the
            // C uses its return value purely as an is-there-a-target check
            // before anything else runs.
            if move_field(form, i32::from(scb.crsfld()) - 1, -1, None, false).is_some() {
                if scb.state() == state::FSDNEN {
                    out.extend(unentr(form, scb));
                }
                scb.set_xitkey(u16::from(byte));
                xitfld(form, scb, -1);
                scb.set_flags(scb.flags() | entry_flags::FSDIGA);
            }
        }
        0x0c => {
            // 'L'-64: fsdqdp() -- refused, see this function's own doc
            // comment.
            panic!("fsdinc: Ctrl-L (fsdqdp, full-screen redisplay) is not built");
        }
        0x08 | 0x7f => {
            // '\b', literal DEL (0x7F). The special-code `DEL` (83*256) is
            // already excluded by `byte: u8`.
            scb.set_state(state::FSDNEN);
            out.extend(hdlcbs(form, scb));
        }
        0x0f | 0x07 | 0x1b => {
            // 'O'-64, 'G'-64, ESC: abandon the field.
            scb.set_xitkey(u16::from(byte));
            xitfld(form, scb, 0);
        }
        _ if byte >= b' ' => {
            scb.set_state(state::FSDNEN);
            let (verdict, prt_out) = hdlprt(form, spec, scb, byte);
            out.extend(prt_out);
            if verdict == Hdlprt::Enter {
                out.extend(addprt(form, scb, byte));
            }
        }
        _ => {}
    }
    out
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

    /// `stfans()`, `FSD.C:1036`. A longer answer pushes every later answer
    /// along, and `allans` grows by the same delta.
    #[test]
    fn storing_a_longer_answer_moves_every_later_offset() {
        let form = compile(b"?????? ??????", b"NAME RANK", MANY);
        let mut a = answers(&form, b"NAME RANK", b"\0");
        assert_eq!(a.offsets, vec![(5u16, 0u8), (11, 0)]);

        assert!(store(&mut a, 0, b"DAN"), "the answer changed");

        assert_eq!(a.text, b"NAME=DAN\0RANK=\0\0");
        assert_eq!(a.offsets, vec![(5, 3), (14, 0)]);
        assert_eq!(a.allans, a.text.len() as u16);
    }

    /// Shorter works the same way in the other direction.
    #[test]
    fn storing_a_shorter_answer_pulls_every_later_offset_back() {
        let form = compile(b"?????? ??????", b"NAME RANK", MANY);
        let mut a = answers(&form, b"NAME RANK", b"NAME=DANIEL\0\0");
        assert_eq!(a.offsets, vec![(5u16, 6u8), (17, 0)]);

        assert!(store(&mut a, 0, b"DAN"));

        assert_eq!(a.text, b"NAME=DAN\0RANK=\0\0");
        assert_eq!(a.offsets, vec![(5, 3), (14, 0)]);
        assert_eq!(a.allans, a.text.len() as u16);
    }

    /// The return value is "did it change", and it is the whole reason the
    /// engine can count changes (`chgcnt`) without diffing the string itself.
    #[test]
    fn storing_the_same_answer_reports_no_change() {
        let form = compile(b"??????", b"NAME", MANY);
        let mut a = answers(&form, b"NAME", b"NAME=DAN\0\0");
        assert!(!store(&mut a, 0, b"DAN"));
        assert_eq!(a.text, b"NAME=DAN\0\0", "and nothing moved");
    }

    /// An answer of the same length and different content is still a change,
    /// and it is the only shape that says so *only* through the `strcmp` half
    /// of `FSD.C:1049`.
    #[test]
    fn a_same_length_answer_is_compared_byte_by_byte() {
        let form = compile(b"??????", b"NAME", MANY);
        let mut a = answers(&form, b"NAME", b"NAME=DAN\0\0");
        assert!(store(&mut a, 0, b"dan"), "strcmp is case-sensitive");
        assert_eq!(a.text, b"NAME=dan\0\0");
    }

    /// The backwards walk's boundary: `efptr` starts at the last field, so
    /// storing into that field runs the loop zero times. `allans` still moves.
    #[test]
    fn storing_into_the_last_field_moves_nothing_after_it() {
        let form = compile(b"?? ?? ??", b"A B C", MANY);
        let mut a = answers(&form, b"A B C", b"\0");
        assert_eq!(a.offsets, vec![(2u16, 0u8), (5, 0), (8, 0)]);

        assert!(store(&mut a, 2, b"zz"));

        assert_eq!(a.text, b"A=\0B=\0C=zz\0\0");
        assert_eq!(a.offsets, vec![(2, 0), (5, 0), (8, 2)]);
        assert_eq!(a.allans, a.text.len() as u16);
    }

    /// The fields *before* the stored one do not move either -- the walk stops
    /// at `fldptr` rather than running to the front of the array.
    #[test]
    fn storing_into_a_middle_field_leaves_the_earlier_ones_alone() {
        let form = compile(b"?? ?? ??", b"A B C", MANY);
        let mut a = answers(&form, b"A B C", b"A=xx\0C=yy\0\0");
        assert_eq!(a.offsets, vec![(2u16, 2u8), (7, 0), (10, 2)]);

        assert!(store(&mut a, 1, b"q"));

        assert_eq!(a.text, b"A=xx\0B=q\0C=yy\0\0");
        assert_eq!(a.offsets, vec![(2, 2), (7, 1), (11, 2)]);
    }

    /// `anslen=strlen(bufptr)`: an embedded NUL ends the answer, so what is
    /// stored is the prefix and an answer whose prefix is already there is not
    /// a change.
    #[test]
    fn an_embedded_nul_ends_the_answer_being_stored() {
        let form = compile(b"??????", b"NAME", MANY);
        let mut a = answers(&form, b"NAME", b"NAME=DA\0\0");
        assert!(!store(&mut a, 0, b"DA\0NIEL"), "strlen stops at the NUL");
        assert_eq!(a.text, b"NAME=DA\0\0");

        assert!(store(&mut a, 0, b"\0DA"), "an answer that begins with one");
        assert_eq!(a.text, b"NAME=\0\0");
        assert_eq!(a.offsets, vec![(5, 0)]);
    }

    /// `stranslen` walks entries, so its answer is a count of entries and
    /// their terminators plus the string's own.
    #[test]
    fn an_answer_strings_length_counts_every_terminator() {
        assert_eq!(answer_len(b"\0"), 1, "the empty answer string, fsdans's \"\"");
        assert_eq!(answer_len(b"A=1\0\0"), 5, "one entry");
        assert_eq!(answer_len(b"A=1\0B=22\0C=\0\0"), 13, "three");
        assert_eq!(answer_len(b"NOEQUALS\0\0"), 10, "an entry need not have '='");
    }

    /// The loop condition is `*anstg != '\0'` and nothing else, so the first
    /// empty entry ends the string wherever it is -- and a byte after the
    /// terminator is not part of it.
    #[test]
    fn a_zero_length_entry_is_the_terminator() {
        assert_eq!(answer_len(b"\0A=1\0\0"), 1, "unreachable entries are not counted");
        assert_eq!(answer_len(b"\0\0"), 1, "and neither is a spare NUL");
        assert_eq!(answer_len(b"A=1\0\0B=2\0\0"), 5);
    }

    /// The C reads on past the slice; there is no length here that would be
    /// right, so this stops instead of inventing one.
    #[test]
    #[should_panic(expected = "hold no NUL at all")]
    fn an_answer_string_that_does_not_terminate_is_a_panic() {
        answer_len(b"A=1");
    }

    #[test]
    #[should_panic(expected = "hold no NUL at all")]
    fn an_answer_string_missing_only_its_terminator_is_a_panic() {
        answer_len(b"A=1\0");
    }

    /// The replace branch: the value goes in where it stood and everything
    /// after it slides, in both directions.
    #[test]
    fn putting_a_value_over_one_that_is_there_moves_the_rest() {
        let mut a = b"A=1234\0B=22\0C=3\0\0".to_vec();
        put_answer(&mut a, b"A", b"9");
        assert_eq!(a, b"A=9\0B=22\0C=3\0\0", "shorter");

        put_answer(&mut a, b"B", b"abcde");
        assert_eq!(a, b"A=9\0B=abcde\0C=3\0\0", "longer");

        put_answer(&mut a, b"C", b"7");
        assert_eq!(a, b"A=9\0B=abcde\0C=7\0\0", "the last one, same length");

        put_answer(&mut a, b"B", b"");
        assert_eq!(a, b"A=9\0B=\0C=7\0\0", "emptied");
    }

    /// The append branch: `sprintf` writes over the terminator and puts a new
    /// one after the entry, so the string grows by `strlen(name)+strlen(value)+2`.
    #[test]
    fn putting_a_value_no_name_carries_appends_an_entry() {
        let mut a = b"\0".to_vec();
        put_answer(&mut a, b"A", b"1");
        assert_eq!(a, b"A=1\0\0", "onto the empty answer string");

        put_answer(&mut a, b"B", b"");
        assert_eq!(a, b"A=1\0B=\0\0", "an empty value is still an entry");

        put_answer(&mut a, b"eye_col", b"Violet");
        assert_eq!(a, b"A=1\0B=\0eye_col=Violet\0\0", "the name as it was given");
        put_answer(&mut a, b"EYE_COL", b"Green");
        assert_eq!(
            a, b"A=1\0B=\0eye_col=Green\0\0",
            "and found again whichever way it is spelled, `sameto` folding case"
        );
    }

    /// `xannam[n] == '='` is the second half of the match, and it is what stops
    /// a name from matching an entry it is merely a prefix of.
    #[test]
    fn a_name_that_is_a_prefix_of_another_matches_neither() {
        let mut a = b"NAMEX=1\0NAME=2\0\0".to_vec();
        put_answer(&mut a, b"NAME", b"9");
        assert_eq!(a, b"NAMEX=1\0NAME=9\0\0");

        let mut a = b"NAMEX=1\0\0".to_vec();
        put_answer(&mut a, b"NAME", b"9");
        assert_eq!(a, b"NAMEX=1\0NAME=9\0\0", "so the name is not there at all");
    }

    /// `fsdxan` returns on its first hit, which is the same rule `fsdans`
    /// follows: of a duplicate name the earlier answer prevails.
    #[test]
    fn putting_a_value_replaces_the_first_of_two_entries_of_a_name() {
        let mut a = b"CLASS=Warrior\0CLASS=Thief\0\0".to_vec();
        put_answer(&mut a, b"CLASS", b"Mage");
        assert_eq!(a, b"CLASS=Mage\0CLASS=Thief\0\0");
    }

    /// `strlen`, `strcpy` and `%s` all stop at the first NUL.
    #[test]
    fn an_embedded_nul_ends_the_name_and_the_value_being_put() {
        let mut a = b"A=1\0B=2\0\0".to_vec();
        put_answer(&mut a, b"A", b"xy\0zw");
        assert_eq!(a, b"A=xy\0B=2\0\0", "the value is what precedes the NUL");

        let mut a = b"AB=1\0\0".to_vec();
        put_answer(&mut a, b"A\0B", b"9");
        assert_eq!(a, b"AB=1\0A=9\0\0", "and the name is `A`, which is not `AB`");
    }

    /// Past 32767 bytes of tail the genuine host stops moving it and splices
    /// over it instead, because `nstr` is an `int` and the guard is signed.
    /// That is a corruption rather than a behaviour: this refuses. The
    /// measurement that says the host really does it is in
    /// `tests/fsd_oracle.rs`, which is where the number comes from.
    #[test]
    #[should_panic(expected = "stops moving the tail")]
    fn a_tail_no_int_can_count_is_refused() {
        let mut a = with_tail(i16::MAX as usize + 1);
        put_answer(&mut a, b"A", b"22");
    }

    /// One byte less is inside what an `int` can count, and then the two agree.
    #[test]
    fn a_tail_an_int_can_still_count_is_spliced() {
        let mut a = with_tail(i16::MAX as usize);
        let tail = a[4..].to_vec();

        put_answer(&mut a, b"A", b"22");

        assert_eq!(&a[..5], b"A=22\0");
        assert_eq!(&a[5..], &tail[..], "the whole of it moved up one byte");
    }

    /// `A=1` and then one entry big enough that `stranslen` of everything after
    /// the first is exactly `tail`.
    fn with_tail(tail: usize) -> Vec<u8> {
        let mut a = b"A=1\0".to_vec();
        a.extend_from_slice(b"B=");
        a.resize(4 + tail - 2, b'x');
        a.push(0);
        a.push(0);
        assert_eq!(answer_len(&a[4..]), tail, "the tail this was built for");
        a
    }

    /// A `Vec` that is not exactly the answer string would splice bytes the C's
    /// `movmem` never touches, so it is refused rather than guessed at.
    #[test]
    #[should_panic(expected = "the same edit only while nothing follows")]
    fn putting_a_value_into_a_buffer_that_is_not_an_answer_string_is_a_panic() {
        let mut a = b"A=1\0\0spare room".to_vec();
        put_answer(&mut a, b"A", b"9");
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
        assert_eq!(scb::FLDVFY, 16, "the four pointers ahead of crsatr");
        assert_eq!(scb::STATE, 44, "the byte right after allans");
        assert_eq!(scb::ANSBUF, 45, "state's own one byte later");
        assert_eq!(
            scb::ENTFLD,
            150,
            "45 (ansbuf) + 81 + 1 (anslen) + 1 (ansptr) + 20 (typahd) + 1 \
             (ahdptr) + 1 (hdlahd)"
        );
        assert_eq!(scb::CRSFLD, 151, "entfld(150) + 1");
        assert_eq!(
            scb::FLAGS,
            157,
            "crsfld(151) + 1 (crsfld itself) + 1 (shffld) + 4 (ftmptr)"
        );
        assert_eq!(scb::ALTPTR, 158, "flags(157) + 1");
        assert_eq!(scb::XITKEY, 162, "flags(157) + 1 + 4 (altptr)");
        assert_eq!(scb::CHGCNT, 164, "xitkey(162) + 2");
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

    /// A fresh, zeroed control block, the way `alczer` leaves one.
    fn zeroed_scb() -> Scb {
        Scb::from_bytes(&[0u8; FSDSCB as usize]).expect("exactly FSDSCB bytes")
    }

    #[test]
    fn scb_fldvfy_reads_and_writes_only_its_own_offset() {
        let mut scb = zeroed_scb();
        let rou = FarPtr {
            offset: 0x1234,
            selector: 0x5678,
        };
        scb.set_fldvfy(rou);
        assert_eq!(scb.fldvfy(), rou);
        // Isolated: the neighbour on either side is untouched.
        assert_eq!(scb.crsatr(), 0, "crsatr, right after fldvfy");
        assert_eq!(scb.newans(), FarPtr::NULL, "newans, right before fldvfy");
    }

    #[test]
    fn scb_state_reads_and_writes_its_own_offset() {
        let mut scb = zeroed_scb();
        scb.set_state(state::FSDNPT);
        assert_eq!(scb.state(), state::FSDNPT);
        assert_eq!(scb.allans(), 0, "allans, right before state");
        assert_eq!(scb.ansbuf(), b"", "ansbuf, right after state, still empty");
    }

    #[test]
    fn scb_ansbuf_round_trips_a_c_string_and_leaves_its_neighbours_alone() {
        let mut scb = zeroed_scb();
        scb.set_state(state::FSDNPT);
        scb.set_crsfld(3);

        scb.set_ansbuf(b"Kaimon");
        assert_eq!(scb.ansbuf(), b"Kaimon");

        // Bytes past the terminator are not part of the string, even if a
        // previous, longer answer left them non-zero.
        scb.set_ansbuf(b"Verylongname");
        scb.set_ansbuf(b"Hi");
        assert_eq!(scb.ansbuf(), b"Hi");

        // Neither neighbour moved.
        assert_eq!(scb.state(), state::FSDNPT);
        assert_eq!(scb.crsfld(), 3);
    }

    #[test]
    #[should_panic(expected = "does not fit")]
    fn scb_ansbuf_refuses_an_answer_that_does_not_fit() {
        let mut scb = zeroed_scb();
        scb.set_ansbuf(&[b'x'; 81]);
    }

    #[test]
    fn scb_entfld_reads_and_writes_its_own_offset() {
        let mut scb = zeroed_scb();
        scb.set_entfld(4);
        assert_eq!(scb.entfld(), 4);
        assert_eq!(scb.crsfld(), 0, "crsfld, right after entfld");
    }

    #[test]
    fn scb_crsfld_reads_and_writes_its_own_offset() {
        let mut scb = zeroed_scb();
        scb.set_crsfld(9);
        assert_eq!(scb.crsfld(), 9);
        assert_eq!(scb.entfld(), 0, "entfld, right before crsfld");
        assert_eq!(scb.flags(), 0, "flags, a handful of bytes after crsfld");
    }

    #[test]
    fn scb_flags_reads_and_writes_its_own_offset() {
        let mut scb = zeroed_scb();
        scb.set_flags(entry_flags::FSDANS | entry_flags::FSDANT);
        assert_eq!(scb.flags(), entry_flags::FSDANS | entry_flags::FSDANT);
        assert_eq!(scb.crsfld(), 0, "crsfld, right before flags");
        assert_eq!(scb.xitkey(), 0, "xitkey, right after flags");
    }

    #[test]
    fn scb_xitkey_reads_and_writes_its_own_offset() {
        let mut scb = zeroed_scb();
        scb.set_xitkey(0x1b);
        assert_eq!(scb.xitkey(), 0x1b);
        assert_eq!(scb.chgcnt(), 0, "chgcnt, right after xitkey");
    }

    #[test]
    fn scb_chgcnt_reads_and_writes_its_own_offset() {
        let mut scb = zeroed_scb();
        scb.set_chgcnt(5);
        assert_eq!(scb.chgcnt(), 5);
        assert_eq!(scb.xitkey(), 0, "xitkey, right before chgcnt");
    }

    #[test]
    fn pmtfld_prints_the_leading_template_text_for_the_first_field() {
        // "Name: " is six characters of literal text before the field's own
        // `??` run starts.
        let template = b"Name: ??\r\n";
        let form = compile(template, b"NAME", MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);

        assert_eq!(pmtfld(&form, template, &scb), b"\r\nName: ");
    }

    #[test]
    fn pmtfld_on_a_later_field_starts_after_the_previous_fields_template_run() {
        // FSD.C:795-813's `ti` computation: crsfld > 0, so `ti` comes from
        // the PREVIOUS field's `tmpoff+xwidth`, not the template's start --
        // and no leading "\r\n" this time.
        let template = b"A: ?? B: ??";
        let form = compile(template, b"A B", MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(1);

        assert_eq!(pmtfld(&form, template, &scb), b" B: ");
    }

    #[test]
    fn defntr_seeds_ansbuf_from_the_fields_current_answer_verbatim() {
        // Not normalized to the ALT= value's canonical spelling -- that is
        // fsdord's job (already ported as `ordinal`), which rewrites
        // `answers` itself before defntr ever runs. "br" is not an exact
        // match for any alternate, so ck4alt(1)'s own effect (feeding
        // altptr) is not observable in *this* test; see the sibling test
        // below for that.
        let spec = b"C(ALT=Black ALT=Brown ALT=Red)";
        let form = compile(b"??????", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        scb.set_flags(entry_flags::FSDANT | entry_flags::FSDANS);

        defntr(&form, spec, &mut scb, b"C=br\0\0");

        assert_eq!(scb.ansbuf(), b"br", "verbatim, not \"Brown\"");
        assert_eq!(
            scb.flags(),
            entry_flags::FSDANS,
            "FSDANT cleared, FSDANS (unrelated) left alone"
        );
        assert_eq!(scb.altptr(), None, "\"br\" is not an exact match for anything");
    }

    #[test]
    fn defntr_seeds_altptr_when_the_current_answer_is_an_exact_alternate() {
        // `fsdscb->altptr=ck4alt(1);` (FSD.C:791) -- an exact-boundary
        // match, not the prefix match `hdlalt`'s own space-cycling branch
        // uses to seed a cycle from scratch. Matters when a session starts
        // (or a field is re-entered) on a field that already has one of its
        // own ALT= values as its answer, e.g. re-editing a previously
        // answered MULTICHOICE field: without this, the first space press
        // would treat nothing as selected and re-derive from ansbuf instead
        // of cycling on from what's already chosen.
        let spec = b"C(ALT=Black ALT=Brown ALT=Red)";
        let form = compile(b"??????", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);

        defntr(&form, spec, &mut scb, b"C=Brown\0\0");

        assert_eq!(scb.ansbuf(), b"Brown");
        assert_eq!(scb.altptr(), Some(1), "Brown is ordinal 1");
    }

    #[test]
    fn defntr_blanks_ansbuf_when_the_field_has_no_answer_yet() {
        let spec = b"NAME";
        let form = compile(b"??", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);

        defntr(&form, spec, &mut scb, b"NAME=\0\0");

        assert_eq!(scb.ansbuf(), b"");
        assert_eq!(scb.altptr(), None);
    }

    #[test]
    fn shoabf_echoes_the_answer_buffer_for_the_current_field() {
        let spec = b"NAME";
        let form = compile(b"????", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        scb.set_ansbuf(b"Kaimon");

        // justfy=0 with no embedded punctuation: dspans's first branch,
        // `secreted(answer)` and nothing else -- no padding out to width.
        assert_eq!(shoabf(&form, &scb, 0), b"Kaimon");
    }

    #[test]
    fn shoabf_masks_a_secret_fields_answer() {
        let spec = b"PASS(SECRET)";
        let form = compile(b"????", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        scb.set_ansbuf(b"xy");

        assert_eq!(shoabf(&form, &scb, 0), b"**");
    }

    #[test]
    fn shoabf_stops_at_the_answer_but_a_literal_character_right_after_it_still_shows() {
        // "Phone: ###-####" -- the one field joins across the "-", so it has
        // embedded punctuation: "   -    " is its own template, three blanks
        // (one per digit of "###"), the literal "-", then four more blanks.
        //
        // justfy=0 breaks out of dspans's loop the moment it reaches a BLANK
        // slot the answer does not reach -- but FSD.C:583's `else { *bp++=
        // *tp; }` arm, which handles a literal character, has no such break
        // at all. With answer "555" the loop consumes the three leading
        // blanks, then reaches the literal "-" *before* the next blank
        // (where it would stop), and echoes it unconditionally. So the
        // output is "555-", not "555" -- the dash survives, the trailing
        // "####" blanks do not. Measured against the C line by line, not
        // assumed: an earlier version of this test asserted "555" and was
        // wrong.
        let template = b"Phone: ###-####";
        let form = compile(template, b"PHONE", MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        scb.set_ansbuf(b"555");

        assert_eq!(shoabf(&form, &scb, 0), b"555-");
    }

    #[test]
    fn shoabf_stops_before_any_blank_the_answer_does_not_reach() {
        // The companion to the test above: with NO answer at all, the very
        // first slot (i=0, a blank) already has `j(0) >= anslen(0)`, so the
        // loop breaks before emitting anything -- not even the leading
        // blanks let alone the dash.
        let template = b"Phone: ###-####";
        let form = compile(template, b"PHONE", MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        scb.set_ansbuf(b"");

        assert_eq!(shoabf(&form, &scb, 0), b"");
    }

    #[test]
    fn fsdlin_calls_pmtfld_defntr_and_shoabf_in_that_fixed_order_and_sets_fsdnpt() {
        let template = b"Name: ??\r\n";
        let spec = b"NAME";
        let form = compile(template, spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_state(0xff); // anything but FSDNPT, so the assertion below is real
        scb.set_flags(entry_flags::FSDANT);
        scb.set_chgcnt(9);

        let out = fsdlin(&form, spec, template, &mut scb, b"NAME=Kaimon\0\0");

        // pmtfld's text, then shoabf's echo of the default answer -- in that
        // order, with nothing in between (defntr produces no output at all).
        assert_eq!(out, b"\r\nName: Kaimon");
        assert_eq!(scb.state(), state::FSDNPT);
        assert_eq!(scb.chgcnt(), 0);
        assert_eq!(scb.crsfld(), 0);
        assert_eq!(scb.ansbuf(), b"Kaimon", "defntr ran, seeding ansbuf");
    }

    #[test]
    fn fsdlin_skips_an_avoided_first_field_by_way_of_move_field() {
        // `movfld(0,1,0)` walks forward over FFFAVD fields -- this is the
        // seam that matters when a caller (fsdego, in the shim) has to
        // supply flags as the module left them, not as fsdroom compiled
        // them: proven here by simply marking field 0 avoided directly in
        // the Form this pure function is handed.
        let template = b"A: ?? B: ??";
        let spec = b"A B";
        let mut form = compile(template, spec, MANY);
        form.fields[0].flags |= flags::AVOID;

        let mut scb = zeroed_scb();
        let out = fsdlin(&form, spec, template, &mut scb, b"A=1\0B=2\0\0");

        assert_eq!(scb.crsfld(), 1, "field 0 was avoided, so field 1 is current");
        assert_eq!(out, b" B: 2");
    }

    #[test]
    fn scb_ftmptr_reads_and_writes_its_own_offset() {
        let mut scb = zeroed_scb();
        scb.set_ftmptr(42);
        assert_eq!(scb.ftmptr(), 42);
        assert_eq!(scb.crsfld(), 0, "crsfld, right before ftmptr");
        assert_eq!(scb.flags(), 0, "flags, right after ftmptr");
    }

    #[test]
    fn scb_altptr_reads_and_writes_its_own_offset() {
        let mut scb = zeroed_scb();
        assert_eq!(scb.altptr(), None, "an alczer'd block's altptr is NULL");

        scb.set_altptr(Some(0));
        assert_eq!(scb.altptr(), Some(0), "ordinal 0 does not collide with NULL");
        assert_eq!(scb.flags(), 0, "flags, right before altptr");
        assert_eq!(scb.xitkey(), 0, "xitkey, right after altptr");

        scb.set_altptr(Some(4));
        assert_eq!(scb.altptr(), Some(4));

        scb.set_altptr(None);
        assert_eq!(scb.altptr(), None, "set_altptr(None) round-trips back to NULL");
    }

    #[test]
    fn entprp_blanks_ansbuf_clears_fsdant_and_nulls_altptr() {
        // `FSD.C:776-784`: `fsdscb->altptr=NULL;` is the entry's third
        // statement, not an afterthought -- a stale `altptr` surviving into
        // a fresh field's entry is exactly the cross-field leak Task 7's own
        // `hdlalt` would otherwise be able to observe.
        let mut scb = zeroed_scb();
        scb.set_ansbuf(b"stale");
        scb.set_flags(entry_flags::FSDANT | entry_flags::FSDANS);
        scb.set_altptr(Some(2));

        entprp(&mut scb);

        assert_eq!(scb.ansbuf(), b"");
        assert_eq!(
            scb.flags(),
            entry_flags::FSDANS,
            "FSDANT cleared, FSDANS (unrelated) left alone"
        );
        assert_eq!(scb.altptr(), None);
    }

    #[test]
    fn skppnc_positions_ftmptr_but_echoes_nothing_on_a_form_this_engine_compiled() {
        // The "provably dead" case: `compile()` never puts anything but a
        // blank in position 0 of a field's own punctuation template. Proven
        // directly rather than merely asserted in the doc comment.
        let template = b"Phone: ###-####";
        let form = compile(template, b"PHONE", MANY);
        let mbpoff = form.fields[0].punctuation_at.expect("this field joins");
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);

        assert_eq!(skppnc(&form, &mut scb), b"", "position 0 is always blank");
        assert_eq!(scb.ftmptr(), mbpoff, "positioned at the field's own start");
    }

    #[test]
    fn skppnc_echoes_a_literal_prefix_on_a_hand_built_form() {
        // `compile()` cannot produce this shape -- see the doc comment on
        // `skppnc` -- but the function does not know that, and a hand-built
        // `Form` exercises the loop `compile()`'s own output never can.
        let mut form = compile(b"??", b"A", MANY);
        form.fields[0].punctuation_at = Some(0);
        form.punctuation = b"(-) \0".to_vec();
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);

        assert_eq!(skppnc(&form, &mut scb), b"(-)", "up to the first blank");
        assert_eq!(scb.ftmptr(), 3, "left pointing AT the blank, not past it");
    }

    #[test]
    fn unentr_on_a_never_shown_field_erases_nothing() {
        // The first-ever `bgnter()` for a field: `ftmptr` is still its
        // zeroed default, and the C's own pointer arithmetic (NULL is
        // always "less than" a real heap address) already means "erase
        // nothing" here -- this port's clamp reproduces that by
        // construction. `mbpoff` deliberately nonzero, so a naive
        // `ftmptr - mbpoff` without the clamp would underflow.
        let mut form = compile(b"??", b"A", MANY);
        form.fields[0].punctuation_at = Some(5);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        assert_eq!(scb.ftmptr(), 0, "never positioned");

        assert_eq!(unentr(&form, &scb), b"");
    }

    #[test]
    fn unentr_backspaces_once_per_character_shown() {
        let mut form = compile(b"??", b"A", MANY);
        form.fields[0].punctuation_at = Some(5);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        scb.set_ftmptr(9); // 4 characters in from mbpoff=5

        assert_eq!(unentr(&form, &scb), b"\x08 \x08\x08 \x08\x08 \x08\x08 \x08");
    }

    #[test]
    fn unentr_with_no_punctuation_erases_the_whole_answer() {
        let form = compile(b"??", b"A", MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        scb.set_ansbuf(b"Al");

        assert_eq!(unentr(&form, &scb), b"\x08 \x08\x08 \x08");
    }

    #[test]
    fn bgnter_erases_the_old_answer_then_positions_for_the_new_one() {
        let spec = b"NAME";
        let form = compile(b"??", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        scb.set_ansbuf(b"Al"); // what was showing before this bgnter() call

        let out = bgnter(&form, &mut scb);

        assert_eq!(out, b"\x08 \x08\x08 \x08", "unentr's erasure; skppnc echoes nothing (no punctuation)");
    }

    #[test]
    #[should_panic(expected = "FSDANS")]
    fn bgnter_refuses_the_ansi_branch_it_does_not_port() {
        let form = compile(b"??", b"A", MANY);
        let mut scb = zeroed_scb();
        scb.set_flags(entry_flags::FSDANS);
        bgnter(&form, &mut scb);
    }

    #[test]
    fn addprt_refuses_a_character_past_the_fields_width() {
        let form = compile(b"??", b"A", MANY); // width 2
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        scb.set_ansbuf(b"Al");

        assert_eq!(addprt(&form, &mut scb, b'x'), b"", "already at width");
        assert_eq!(scb.ansbuf(), b"Al", "unchanged");
    }

    #[test]
    fn addprt_refuses_a_space_on_a_nospaces_field() {
        let form = compile(b"????", b"A(NOSPACES)", MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);

        assert_eq!(addprt(&form, &mut scb, b' '), b"");
        assert_eq!(scb.ansbuf(), b"");
    }

    #[test]
    fn addprt_masks_a_secret_fields_echo_but_not_its_storage() {
        let form = compile(b"????", b"PASS(SECRET)", MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);

        assert_eq!(addprt(&form, &mut scb, b'x'), b"*");
        assert_eq!(scb.ansbuf(), b"x", "the real character is what's stored");
    }

    #[test]
    fn addprt_types_a_phone_number_and_skips_the_dash_after_the_third_digit() {
        // "Phone: ###-####": three addprt() calls type the digits before
        // the dash; the third one's own echo carries the dash along with
        // it, exactly as `shoabf`'s own test of this same fixture shows
        // the finished display doing ("555-", not "555").
        let template = b"Phone: ###-####";
        let form = compile(template, b"PHONE", MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        skppnc(&form, &mut scb); // bgnter's own precondition: ftmptr positioned

        assert_eq!(addprt(&form, &mut scb, b'5'), b"5");
        assert_eq!(addprt(&form, &mut scb, b'5'), b"5");
        assert_eq!(
            addprt(&form, &mut scb, b'5'),
            b"5-",
            "the third digit's own call carries the literal dash with it"
        );
        assert_eq!(scb.ansbuf(), b"555");
    }

    #[test]
    fn hdlprt_enters_any_character_on_a_plain_text_field() {
        let spec = b"NAME";
        let form = compile(b"??", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);

        let (verdict, out) = hdlprt(&form, spec, &mut scb, b'!');
        assert_eq!(verdict, Hdlprt::Enter);
        assert_eq!(out, b"");
    }

    #[test]
    fn hdlprt_ignores_a_multichoice_field_with_no_alternates() {
        // Exercises hdlalt's own first line against a field that really is
        // MULTICHOICE but has no ALT= list to match against.
        let spec = b"F(MULTICHOICE)";
        let form = compile(b"??", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        assert_eq!(form.fields[0].flags, flags::MULTICHOICE);

        let (verdict, out) = hdlprt(&form, spec, &mut scb, b'x');
        assert_eq!(verdict, Hdlprt::Ignore);
        assert_eq!(out, b"");
    }

    #[test]
    fn hdlprt_starts_an_ambiguous_alternate_match_and_sets_fsdant() {
        // "b" matches both Black and Brown -- ambiguous, so the character is
        // still entered (the caller's own addprt appends it) but FSDANT
        // gets set to mark that a match is now in progress.
        let spec = b"C(ALT=Black ALT=Brown ALT=Red MULTICHOICE)";
        let form = compile(b"??????", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);

        let (verdict, out) = hdlprt(&form, spec, &mut scb, b'b');

        assert_eq!(verdict, Hdlprt::Enter);
        assert_eq!(out, b"", "nothing was showing yet, so no erase/redraw");
        assert_eq!(scb.flags(), entry_flags::FSDANT);
        assert_eq!(scb.altptr(), None);
    }

    #[test]
    fn hdlprt_enters_a_digit_on_a_numeric_field() {
        let spec = b"AGE";
        let form = compile(b"###", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);

        let (verdict, out) = hdlprt(&form, spec, &mut scb, b'5');
        assert_eq!(verdict, Hdlprt::Enter);
        assert_eq!(out, b"");
    }

    #[test]
    fn hdlprt_ignores_a_non_digit_on_a_numeric_field_with_no_alternates() {
        let spec = b"AGE";
        let form = compile(b"###", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);

        let (verdict, out) = hdlprt(&form, spec, &mut scb, b'x');
        assert_eq!(verdict, Hdlprt::Ignore);
        assert_eq!(out, b"");
    }

    #[test]
    fn hdlprt_enters_a_leading_minus_on_a_signed_dollar_field() {
        let spec = b"BAL";
        let form = compile(b"$$$", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        assert_eq!(scb.ansbuf(), b"", "nothing typed yet");

        let (verdict, _) = hdlprt(&form, spec, &mut scb, b'-');
        assert_eq!(verdict, Hdlprt::Enter);
    }

    #[test]
    fn hdlprt_refuses_a_minus_on_a_nonnegative_dollar_field() {
        let spec = b"BAL(MIN=0)";
        let form = compile(b"$$$", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        assert!(form.fields[0].flags & flags::NONNEGATIVE != 0);

        let (verdict, _) = hdlprt(&form, spec, &mut scb, b'-');
        assert_eq!(verdict, Hdlprt::Ignore, "no ALT= list either, so hdlalt refuses too");
    }

    #[test]
    fn hdlprt_resets_a_committed_alternate_on_a_numeric_field_when_a_digit_follows() {
        // A `#`/`$` field carrying its own ALT= list (legal, and not
        // MULTICHOICE) whose alternate has already been committed --
        // altptr set, FSDANT cleared, exactly the state altntr leaves
        // behind. This is the state hdlprt's own reset guard has to catch
        // by testing altptr, not just FSDANT: see hdlprt's own doc comment.
        let spec = b"AGE(ALT=UNK)";
        let form = compile(b"###", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        scb.set_ansbuf(b"UNK");
        scb.set_altptr(Some(0));
        assert_eq!(scb.flags(), 0, "FSDANT already clear, as altntr leaves it");

        let (verdict, out) = hdlprt(&form, spec, &mut scb, b'5');

        assert_eq!(verdict, Hdlprt::Enter);
        assert_eq!(
            out,
            b"\x08 \x08\x08 \x08\x08 \x08",
            "the stale \"UNK\" is erased, not left on screen"
        );
        assert_eq!(scb.altptr(), None, "the committed alternate is discarded");
        assert_eq!(scb.ansbuf(), b"", "ready for the caller's own addprt to append the digit");
    }

    #[test]
    fn hdlprt_reruns_bgnter_and_clears_fsdant_when_a_digit_follows_an_aborted_alternate() {
        // The C's own outer guard, `!FSDANT || anslen==0`, means the
        // reset-and-restart sub-branch is reachable only once `ansbuf` is
        // ALREADY empty -- a non-empty `ansbuf` alongside `FSDANT` routes
        // to `hdlalt` instead (below). So the only way to observe the
        // restart's own erasure is through `ftmptr`, which -- on a
        // punctuated field -- `unentr` reads independently of `ansbuf`'s
        // length: exactly the state Task 7's `hdlalt` would leave behind
        // after an aborted partial match against a punctuated field's
        // alternates.
        let template = b"Code: ###-###";
        let spec = b"CODE";
        let form = compile(template, spec, MANY);
        let mbpoff = form.fields[0].punctuation_at.expect("this field joins");
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        scb.set_ftmptr(mbpoff + 4); // as if echoing had advanced this far
        scb.set_flags(entry_flags::FSDANT);
        assert_eq!(scb.ansbuf(), b"", "the guard's other half: nothing typed");

        let (verdict, out) = hdlprt(&form, spec, &mut scb, b'3');

        assert_eq!(verdict, Hdlprt::Enter);
        assert_eq!(
            out,
            b"\x08 \x08\x08 \x08\x08 \x08\x08 \x08",
            "unentr erased the 4 characters ftmptr had advanced past; skppnc's \
             own re-echo is empty, per skppnc's own \"provably dead\" doc comment"
        );
        assert_eq!(scb.ftmptr(), mbpoff, "skppnc repositioned it to the field's own start");
        assert_eq!(scb.flags(), 0, "FSDANT cleared");
    }

    #[test]
    fn hdlprt_falls_through_to_hdlalt_when_fsdant_is_set_and_something_is_typed() {
        // The C's outer guard again, from the other side: FSDANT set AND
        // ansbuf non-empty means the digit-accept branch never runs at
        // all, whatever the character is -- it always falls to hdlalt.
        let spec = b"AGE";
        let form = compile(b"###", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        scb.set_ansbuf(b"1");
        scb.set_flags(entry_flags::FSDANT);

        let (verdict, out) = hdlprt(&form, spec, &mut scb, b'3');

        assert_eq!(verdict, Hdlprt::Ignore, "AGE has no ALT= list, so hdlalt refuses too");
        assert_eq!(out, b"");
        assert_eq!(scb.ansbuf(), b"1", "hdlprt's own branch never ran");
    }

    #[test]
    fn hdlalt_types_a_full_alternate_value_and_commits_when_unambiguous() {
        // The seam Task 7 exists for: a whole field's worth of typing, not
        // one call in isolation -- "b" is ambiguous (Black, Brown both
        // match), "bl" is not. Drives hdlprt+addprt together the way
        // fsdinc's own dispatcher (Task 9) will, since Hdlprt::Enter's own
        // contract is "the caller appends it".
        let spec = b"C(ALT=Black ALT=Brown ALT=Red MULTICHOICE)";
        let form = compile(b"??????", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);

        let (verdict, out) = hdlprt(&form, spec, &mut scb, b'B');
        assert_eq!(verdict, Hdlprt::Enter, "ambiguous: Black and Brown both start with B");
        assert_eq!(out, b"", "nothing was showing yet to erase");
        addprt(&form, &mut scb, b'B');
        assert_eq!(scb.ansbuf(), b"B");
        assert_eq!(scb.flags(), entry_flags::FSDANT, "now tracking an ambiguous match");
        assert_eq!(scb.altptr(), None);

        let (verdict, out) = hdlprt(&form, spec, &mut scb, b'l');
        assert_eq!(verdict, Hdlprt::Handled, "\"Bl\" matches only Black");
        assert_eq!(scb.ansbuf(), b"Black", "the canonical spelling, not \"Bl\"");
        assert_eq!(scb.altptr(), Some(0));
        assert_eq!(scb.flags(), entry_flags::FSDQOT, "FSDANT cleared, FSDQOT set");
        assert_eq!(
            out,
            b"\x08 \x08Black",
            "bgnter erases the one \"B\" that was showing, then shoabf shows \
             \"Black\" in full"
        );
    }

    #[test]
    fn hdlalt_rejects_a_character_that_matches_no_alternate_at_all() {
        let spec = b"C(ALT=Black ALT=Brown ALT=Red MULTICHOICE)";
        let form = compile(b"??????", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);

        let (verdict, out) = hdlprt(&form, spec, &mut scb, b'Z');

        assert_eq!(verdict, Hdlprt::Ignore, "no alternate starts with Z");
        assert_eq!(out, b"");
        assert_eq!(scb.ansbuf(), b"", "rejected outright, nothing to append");
        assert_eq!(scb.flags(), 0, "FSDANT never set for an outright rejection");
    }

    #[test]
    fn hdlalt_rejects_a_typo_partway_through_an_otherwise_good_match() {
        // "Bl" narrows to Black alone; a further character that Black
        // itself does not continue with is rejected, not accepted as a new
        // ambiguous start -- matching chkalt(0)'s own "0 matches" case,
        // which is unconditional once FSDANT is already set (the typed
        // candidate is always ansbuf+c while FSDANT holds).
        let spec = b"C(ALT=Black ALT=Brown ALT=Red MULTICHOICE)";
        let form = compile(b"??????", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        scb.set_ansbuf(b"Bl");
        scb.set_flags(entry_flags::FSDANT);

        let (verdict, out) = hdlprt(&form, spec, &mut scb, b'x');

        assert_eq!(verdict, Hdlprt::Ignore, "\"Blx\" matches nothing");
        assert_eq!(out, b"");
        assert_eq!(scb.ansbuf(), b"Bl", "the typo is not appended");
        assert_eq!(scb.flags(), entry_flags::FSDANT, "still mid-match, unchanged");
    }

    #[test]
    fn hdlalt_space_cycles_to_the_first_alternate_from_a_fresh_field() {
        let spec = b"C(ALT=Black ALT=Brown ALT=Red MULTICHOICE)";
        let form = compile(b"??????", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);

        let (verdict, out) = hdlprt(&form, spec, &mut scb, b' ');

        assert_eq!(verdict, Hdlprt::Handled);
        assert_eq!(scb.ansbuf(), b"Black", "the first alternate in the list");
        assert_eq!(scb.altptr(), Some(0));
        assert!(!out.is_empty());
    }

    #[test]
    fn hdlalt_space_cycles_forward_through_the_list_and_wraps_to_the_first_alternate() {
        // FSD.C:1437-1445: reaching the end of the list is not a dead end --
        // the next space after the last alternate wraps back to the first
        // one, exactly the mechanism MajorMUD's own HAIR_COL/EYE_COL fields
        // and the terminal SAVE(ALT=SAVE ALT=EDIT ALT=QUIT MULTICHOICE)
        // field rely on to let a player cycle a 2-3 item list with space.
        let spec = b"C(ALT=Black ALT=Brown ALT=Red MULTICHOICE)";
        let form = compile(b"??????", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);

        let (v1, _) = hdlprt(&form, spec, &mut scb, b' ');
        assert_eq!(v1, Hdlprt::Handled);
        assert_eq!(scb.ansbuf(), b"Black");

        // FSDQOT is now set (altntr's own last act), so a second space in
        // the same "hasn't been flushed yet" window does nothing -- exactly
        // the gate the real host clears between keystrokes in fsdinc's own
        // dispatcher (Task 9, not built here). Clear it by hand to drive
        // the cycle a second time, the way that dispatcher eventually will.
        scb.set_flags(scb.flags() & !entry_flags::FSDQOT);
        let (v2, _) = hdlprt(&form, spec, &mut scb, b' ');
        assert_eq!(v2, Hdlprt::Handled);
        assert_eq!(scb.ansbuf(), b"Brown", "cycled to the next alternate");

        scb.set_flags(scb.flags() & !entry_flags::FSDQOT);
        let (v3, _) = hdlprt(&form, spec, &mut scb, b' ');
        assert_eq!(v3, Hdlprt::Handled);
        assert_eq!(scb.ansbuf(), b"Red", "cycled to the last alternate");

        // The fourth space is the one that matters: one more past the last
        // alternate must wrap back to the first, not get stuck on "Red".
        scb.set_flags(scb.flags() & !entry_flags::FSDQOT);
        let (v4, out4) = hdlprt(&form, spec, &mut scb, b' ');
        assert_eq!(v4, Hdlprt::Handled, "wraps around instead of ignoring the space");
        assert_eq!(scb.ansbuf(), b"Black", "back to the first alternate");
        assert_eq!(scb.altptr(), Some(0));
        assert!(!out4.is_empty(), "the wrap is committed and echoed, like any other cycle step");
    }

    #[test]
    fn hdlalt_space_wraps_from_the_last_alternate_straight_to_the_first() {
        // A tighter, single-step proof of the wrap itself: seed `altptr` at
        // the last alternate directly (rather than cycling there one space
        // at a time, as the test above does) and confirm one more space
        // lands on the first, not on nothing. This is the exact case the
        // buggy version got wrong: `next_alternate` finds no next entry, and
        // the old code then tried to seed a candidate from `ansbuf` -- which
        // at this point holds the last alternate's own spelling, so it
        // matched itself and returned `Ignore` instead of wrapping.
        let spec = b"C(ALT=Black ALT=Brown ALT=Red MULTICHOICE)";
        let form = compile(b"??????", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        scb.set_altptr(Some(2));
        scb.set_ansbuf(b"Red");

        let (verdict, out) = hdlprt(&form, spec, &mut scb, b' ');

        assert_eq!(verdict, Hdlprt::Handled, "wraps instead of getting stuck on the last alternate");
        assert_eq!(scb.ansbuf(), b"Black", "wrapped to the first alternate");
        assert_eq!(scb.altptr(), Some(0));
        assert!(!out.is_empty());
    }

    #[test]
    fn hdlalt_space_does_nothing_on_a_field_that_is_not_multichoice() {
        // ALTERNATES without MULTICHOICE -- a numeric field with an ALT=
        // shortcut alongside ordinary digit entry -- never takes the
        // space-cycling branch. A `?`/`Y` field can't even reach `hdlalt`
        // with a space unless it is MULTICHOICE (hdlprt's own `?`/`Y` arm
        // short-circuits to Enter otherwise), so this needs a `#`/`$` field,
        // whose arm falls through to `hdlalt` for any character that is not
        // a digit -- a space included.
        let spec = b"C(ALT=Black ALT=Brown)";
        let form = compile(b"######", spec, MANY);
        assert_eq!(form.fields[0].kind, b'#');
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);

        let (verdict, out) = hdlprt(&form, spec, &mut scb, b' ');

        assert_eq!(verdict, Hdlprt::Ignore);
        assert_eq!(out, b"");
        assert_eq!(scb.altptr(), None);
    }

    #[test]
    fn bstalt_with_no_committed_alternate_always_allows_backspace() {
        let field = Field {
            width: 5,
            xwidth: 5,
            attr: 0,
            flags: flags::MULTICHOICE,
            kind: b'?',
            spec_at: 0,
            template_at: 0,
            punctuation_at: None,
        };
        let mut scb = zeroed_scb();
        assert_eq!(scb.altptr(), None);

        assert!(bstalt(&field, &mut scb));
        assert_eq!(scb.altptr(), None, "nothing to clear");
    }

    #[test]
    fn bstalt_refuses_to_bust_a_multichoice_fields_committed_choice() {
        let field = Field {
            width: 5,
            xwidth: 5,
            attr: 0,
            flags: flags::MULTICHOICE,
            kind: b'?',
            spec_at: 0,
            template_at: 0,
            punctuation_at: None,
        };
        let mut scb = zeroed_scb();
        scb.set_altptr(Some(1));

        assert!(!bstalt(&field, &mut scb));
        assert_eq!(scb.altptr(), Some(1), "not busted through");
    }

    #[test]
    fn bstalt_refuses_to_bust_a_numeric_fields_committed_choice() {
        // `fldptr->fldtyp != '?'` -- a `#`/`$` field with an ALT= list of its
        // own (not MULTICHOICE) still refuses, because busting through would
        // leave a numeric field's own digit-entry state inconsistent.
        let field = Field {
            width: 5,
            xwidth: 5,
            attr: 0,
            flags: flags::ALTERNATES,
            kind: b'#',
            spec_at: 0,
            template_at: 0,
            punctuation_at: None,
        };
        let mut scb = zeroed_scb();
        scb.set_altptr(Some(0));

        assert!(!bstalt(&field, &mut scb));
        assert_eq!(scb.altptr(), Some(0));
    }

    #[test]
    fn bstalt_busts_through_a_plain_text_fields_committed_choice() {
        // Not MULTICHOICE, and fldtyp == '?': the one combination that is
        // allowed to start over.
        let field = Field {
            width: 5,
            xwidth: 5,
            attr: 0,
            flags: flags::ALTERNATES,
            kind: b'?',
            spec_at: 0,
            template_at: 0,
            punctuation_at: None,
        };
        let mut scb = zeroed_scb();
        scb.set_altptr(Some(2));

        assert!(bstalt(&field, &mut scb));
        assert_eq!(scb.altptr(), None, "starting over");
    }

    #[test]
    fn hdlcbs_does_nothing_on_an_empty_field() {
        let form = compile(b"??", b"A", MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);

        assert_eq!(hdlcbs(&form, &mut scb), b"", "ansptr==0 short-circuits before bstalt is even called");
        assert_eq!(scb.ansbuf(), b"");
    }

    #[test]
    fn hdlcbs_erases_one_character_with_no_punctuation() {
        let form = compile(b"??", b"A", MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        scb.set_ansbuf(b"Al");

        assert_eq!(hdlcbs(&form, &mut scb), b"\x08 \x08");
        assert_eq!(scb.ansbuf(), b"A");
    }

    #[test]
    fn hdlcbs_erases_a_literal_separator_along_with_the_digit_before_it() {
        // "Phone: ###-####", the same fixture as addprt's own phone-number
        // test: the third digit's own addprt() call echoed "5-" (the digit
        // plus the literal dash that immediately follows it in the
        // template), so backspacing it must erase both -- and leave
        // `ftmptr` exactly where the second digit's own addprt() call left
        // it, not one slot off in either direction. This is the "off-by-one
        // in cursor tracking" case a single isolated call cannot catch.
        let template = b"Phone: ###-####";
        let form = compile(template, b"PHONE", MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        skppnc(&form, &mut scb);
        addprt(&form, &mut scb, b'5');
        addprt(&form, &mut scb, b'5');
        let ftmptr_after_two_digits = scb.ftmptr();
        addprt(&form, &mut scb, b'5');
        assert_eq!(scb.ansbuf(), b"555");

        let out = hdlcbs(&form, &mut scb);

        assert_eq!(out, b"\x08 \x08\x08 \x08", "the dash, then the digit itself");
        assert_eq!(scb.ansbuf(), b"55");
        assert_eq!(
            scb.ftmptr(),
            ftmptr_after_two_digits,
            "back to exactly where the second digit's own addprt() left it"
        );
    }

    #[test]
    fn hdlcbs_refuses_to_erase_a_committed_multichoice_alternate() {
        let spec = b"C(ALT=Black ALT=Brown ALT=Red MULTICHOICE)";
        let form = compile(b"??????", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        scb.set_ansbuf(b"Black");
        scb.set_altptr(Some(0));

        assert_eq!(hdlcbs(&form, &mut scb), b"", "bstalt refuses -- the committed choice stands");
        assert_eq!(scb.ansbuf(), b"Black", "unchanged");
        assert_eq!(scb.altptr(), Some(0), "not busted through");
    }

    #[test]
    fn hdlcbs_busts_through_a_non_multichoice_alternates_field_and_erases_normally() {
        // ALTERNATES without MULTICHOICE on a plain '?' field: bstalt() says
        // yes, clearing altptr as a side effect, and hdlcbs proceeds exactly
        // as it would with no ALT= list at all.
        let spec = b"C(ALT=Black ALT=Brown)";
        let form = compile(b"??????", spec, MANY);
        assert_eq!(form.fields[0].flags, flags::ALTERNATES);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        scb.set_ansbuf(b"Black");
        scb.set_altptr(Some(0));

        let out = hdlcbs(&form, &mut scb);

        assert_eq!(scb.altptr(), None, "bstalt cleared it as a side effect");
        assert_eq!(scb.ansbuf(), b"Blac", "one character erased, same as any other field");
        assert_eq!(out, b"\x08 \x08");
    }

    #[test]
    fn hdlcbs_and_addprt_together_correct_a_typo_across_a_sequence_of_keystrokes() {
        // A whole field's worth of input, not one call in isolation --
        // "Kaimoon", two backspaces to drop the extra "o", then "n" to
        // finish "Kaimon". The same fixture Task 9's own planned
        // `fsdinc`-level test names, driven directly through addprt/hdlcbs
        // here since `fsdinc` itself is not built yet.
        let spec = b"NAME";
        let form = compile(b"????????", spec, MANY); // width 8
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);

        let mut out = Vec::new();
        for c in b"Kaimoon" {
            out.extend(addprt(&form, &mut scb, *c));
        }
        assert_eq!(scb.ansbuf(), b"Kaimoon");
        assert_eq!(out, b"Kaimoon");

        out.clear();
        out.extend(hdlcbs(&form, &mut scb));
        out.extend(hdlcbs(&form, &mut scb));
        assert_eq!(scb.ansbuf(), b"Kaimo", "both trailing o's backspaced off");
        assert_eq!(out, b"\x08 \x08\x08 \x08");

        out.clear();
        out.extend(addprt(&form, &mut scb, b'n'));
        assert_eq!(scb.ansbuf(), b"Kaimon");
        assert_eq!(out, b"n");
    }

    #[test]
    fn xitfld_advances_crsfld_to_the_next_field_and_enters_fsdbuf() {
        let spec = b"A B C";
        let form = compile(b"?? ?? ??", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        scb.set_ansbuf(b"Hi");

        xitfld(&form, &mut scb, 1);

        assert_eq!(scb.crsfld(), 1, "the cursor genuinely moved to the next field's index");
        assert_eq!(scb.entfld(), 0, "entfld records which field was just left");
        assert_eq!(scb.state(), state::FSDBUF);
    }

    #[test]
    fn xitfld_steps_backward_when_finc_is_negative() {
        let spec = b"A B C";
        let form = compile(b"?? ?? ??", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(2);

        xitfld(&form, &mut scb, -1);

        assert_eq!(scb.crsfld(), 1);
        assert_eq!(scb.entfld(), 2);
        assert_eq!(scb.state(), state::FSDBUF);
    }

    #[test]
    fn xitfld_skips_an_avoided_field_on_the_way_to_the_next_one() {
        // Proves xitfld actually calls move_field rather than a hand-rolled
        // crsfld+finc: field 1 is flagged AVOID (the module's own FFFAVD,
        // e.g. a "you may see but not type into" field), so moving forward
        // from field 0 must land on field 2, not field 1.
        let spec = b"A B C";
        let mut form = compile(b"?? ?? ??", spec, MANY);
        form.fields[1].flags |= flags::AVOID;
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);

        xitfld(&form, &mut scb, 1);

        assert_eq!(scb.crsfld(), 2, "field 1 is AVOID -- skipped over");
    }

    #[test]
    fn xitfld_at_the_last_field_leaves_crsfld_in_place_when_there_is_nowhere_to_go() {
        // No wrap in line mode (FSDANS unset): movfld's resort (-1, this
        // port's None) means crsfld is simply not written.
        let spec = b"A B";
        let form = compile(b"?? ??", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(1); // the last field

        xitfld(&form, &mut scb, 1);

        assert_eq!(scb.crsfld(), 1, "no next field to move to -- left alone");
        assert_eq!(scb.entfld(), 1, "still records which field was entered");
        assert_eq!(scb.state(), state::FSDBUF);
    }

    #[test]
    #[should_panic(expected = "FSDANS")]
    fn xitfld_refuses_the_ansi_branch_it_does_not_port() {
        let form = compile(b"?? ??", b"A B", MANY);
        let mut scb = zeroed_scb();
        scb.set_flags(entry_flags::FSDANS);
        xitfld(&form, &mut scb, 1);
    }

    #[test]
    fn fsdinc_types_a_whole_field_then_exits_on_enter() {
        // A whole field's worth of typing, byte by byte, through fsdinc
        // itself -- not one call per test. Three fields so the middle one
        // (crsfld=1) isn't the boundary case a last-field Enter is.
        let spec = b"A NAME B";
        let form = compile(b"?? ????????? ??", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(1);
        scb.set_state(state::FSDNPT); // what fsdlin() itself leaves a session in

        let mut out = Vec::new();
        for &c in b"Kaimon" {
            out.extend(fsdinc(&form, spec, &mut scb, c));
        }
        assert_eq!(out, b"Kaimon", "each character echoed as it was typed");
        assert_eq!(scb.ansbuf(), b"Kaimon");
        assert_eq!(scb.state(), state::FSDNEN, "still entering until Enter");

        fsdinc(&form, spec, &mut scb, b'\r');

        assert_eq!(scb.state(), state::FSDBUF, "xitfld committed the field");
        assert_eq!(scb.crsfld(), 2, "the cursor genuinely moved to the next field");
        assert_eq!(scb.entfld(), 1, "entfld records which field was just exited");
    }

    #[test]
    fn fsdinc_handles_a_typo_correction_mid_field() {
        // "Kaimoon" + backspace + backspace + "n" + Enter -> "Kaimon". The
        // same fixture hdlcbs_and_addprt_together_correct_a_typo_across_a_
        // sequence_of_keystrokes already proves at the addprt/hdlcbs level;
        // driven here through fsdinc's own byte dispatch instead, which is
        // the interaction a single-function test can't catch (state has to
        // survive FSDNPT->FSDNEN and every backspace correctly, not just
        // the answer buffer).
        let spec = b"NAME";
        let form = compile(b"????????", spec, MANY); // width 8
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        scb.set_state(state::FSDNPT);

        for &c in b"Kaimoon" {
            fsdinc(&form, spec, &mut scb, c);
        }
        assert_eq!(scb.ansbuf(), b"Kaimoon");
        assert_eq!(scb.state(), state::FSDNEN);

        let bs1 = fsdinc(&form, spec, &mut scb, 0x08);
        let bs2 = fsdinc(&form, spec, &mut scb, 0x08);
        assert_eq!(bs1, b"\x08 \x08");
        assert_eq!(bs2, b"\x08 \x08");
        assert_eq!(scb.ansbuf(), b"Kaimo", "both trailing o's backspaced off");
        assert_eq!(scb.state(), state::FSDNEN, "backspace re-asserts FSDNEN");

        let out = fsdinc(&form, spec, &mut scb, b'n');
        assert_eq!(out, b"n");
        assert_eq!(scb.ansbuf(), b"Kaimon");

        fsdinc(&form, spec, &mut scb, b'\r');
        assert_eq!(scb.state(), state::FSDBUF);
        assert_eq!(scb.ansbuf(), b"Kaimon", "the committed answer");
    }

    #[test]
    fn fsdinc_cycles_an_alt_field_with_space_and_commits_it_with_enter() {
        // MajorMUD's real HAIR_COL/EYE_COL/terminal SAVE fields are all
        // MULTICHOICE ALT= fields cycled with space -- this is the seam
        // Task 7 built and Task 9 has to actually dispatch to.
        let spec = b"C(ALT=Black ALT=Brown ALT=Red MULTICHOICE)";
        let form = compile(b"??????", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        scb.set_state(state::FSDNPT);

        // The first space arrives via FSDNPT's own fallthrough (' ' < '!'),
        // reaching FSDNEN's default arm with state still FSDNPT at the
        // moment hdlprt/hdlalt run -- and commits the first alternate.
        let out1 = fsdinc(&form, spec, &mut scb, b' ');
        assert_eq!(scb.ansbuf(), b"Black");
        assert_eq!(scb.state(), state::FSDNEN, "the default arm sets it even via fallthrough");
        assert!(!out1.is_empty());

        // FSDQOT (set by altntr's own commit) gates repeat spaces until
        // fsdqoe() -- the genuine output-drain callback, Machine-level and
        // out of this task's scope -- clears it. Driven by hand here, the
        // same workaround hdlalt_space_cycles_forward_through_the_list_
        // and_wraps_to_the_first_alternate already uses for the identical
        // reason.
        scb.set_flags(scb.flags() & !entry_flags::FSDQOT);
        fsdinc(&form, spec, &mut scb, b' ');
        assert_eq!(scb.ansbuf(), b"Brown", "cycled to the next alternate");

        scb.set_flags(scb.flags() & !entry_flags::FSDQOT);
        fsdinc(&form, spec, &mut scb, b' ');
        assert_eq!(scb.ansbuf(), b"Red", "cycled to the last alternate");

        fsdinc(&form, spec, &mut scb, b'\r');
        assert_eq!(scb.state(), state::FSDBUF, "Enter committed the field");
        assert_eq!(scb.ansbuf(), b"Red", "the last-cycled alternate is what got saved");
        assert_eq!(
            scb.crsfld(), 1,
            "the single-field form's last field: xitfld(0) leaves crsfld at 0, \
             then fsdinc steps it one past the end by hand as the \
             form-is-complete sentinel -- not xitfld(1)'s own move_field, \
             which would find no field 1 and leave crsfld unmoved at 0"
        );
    }

    #[test]
    fn fsdinc_backing_out_with_ctrl_u_only_erases_a_field_that_was_actually_typed_into() {
        // The subtlety FSDNPT's own missing `break` preserves: `'U'-64`'s
        // branch reads `fsdscb->state` to decide whether to unentr() before
        // backing out, and that read has to see FSDNPT (not FSDNEN) when
        // Ctrl-U itself is what triggered the fallthrough -- FSDNPT's own
        // body only ever runs for `c >= '!'`, and Ctrl-U (0x15) never is.
        let spec = b"A B";
        let form = compile(b"?? ??", spec, MANY);

        // Scenario 1: field B (crsfld=1) has never been typed into this
        // session -- state is still FSDNPT when Ctrl-U arrives, even though
        // ansbuf is non-empty (defntr() seeded it from an existing answer,
        // and shoabf() already painted it on screen before this fsdinc call
        // ever ran). A pre-seeded, non-empty ansbuf is deliberate: with an
        // empty one, an erroneous unentr() call and a correctly-skipped one
        // produce the same (empty) output, so that version of this test
        // could not tell "state was read as FSDNEN when it should have
        // stayed FSDNPT" apart from "state was read correctly" -- exactly
        // the sequence-only bug a naive always-set-FSDNEN implementation
        // would pass unnoticed.
        let mut scb = zeroed_scb();
        scb.set_crsfld(1);
        scb.set_state(state::FSDNPT);
        scb.set_ansbuf(b"Al");

        let out = fsdinc(&form, spec, &mut scb, 0x15);

        assert_eq!(
            out, b"",
            "state is still FSDNPT (never entered), so unentr must not fire \
             even though ansbuf holds defntr's pre-seeded \"Al\""
        );
        assert_eq!(scb.crsfld(), 0, "moved back to field A");
        assert_eq!(scb.entfld(), 1);
        assert_eq!(scb.state(), state::FSDBUF);
        assert_eq!(scb.flags() & entry_flags::FSDIGA, entry_flags::FSDIGA);

        // Scenario 2: field B was typed into first (FSDNPT -> FSDNEN via a
        // real character), so backing out with Ctrl-U now has something on
        // screen to erase.
        let mut scb = zeroed_scb();
        scb.set_crsfld(1);
        scb.set_state(state::FSDNPT);
        fsdinc(&form, spec, &mut scb, b'x');
        assert_eq!(scb.state(), state::FSDNEN, "typing moved it out of FSDNPT");

        let out = fsdinc(&form, spec, &mut scb, 0x15);

        assert_eq!(out, b"\x08 \x08", "the one typed character is erased before backing out");
        assert_eq!(scb.crsfld(), 0);
    }

    #[test]
    fn fsdinc_erases_a_pre_seeded_default_before_typing_a_fresh_first_character() {
        // A field defntr() seeded with an existing answer (returning to an
        // already-answered field): the very first fresh character must
        // erase the OLD value's on-screen characters before echoing the
        // new one. This only comes out right if bgnter() -- whose unentr()
        // reads this port's ansbuf-is-anslen substitution -- runs BEFORE
        // ansbuf is blanked, not after; see altntr's/hdlprt's own doc
        // comments for the same reordering and why the plain C statement
        // order (`ansbuf[0]='\0'; bgnter();`) does not port literally.
        let spec = b"NAME";
        let form = compile(b"????????", spec, MANY); // width 8
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        scb.set_state(state::FSDNPT);
        scb.set_ansbuf(b"Al"); // defntr()'s seed; shoabf() already showed it

        let out = fsdinc(&form, spec, &mut scb, b'K');

        assert_eq!(
            out,
            b"\x08 \x08\x08 \x08K",
            "unentr erases the two characters of the OLD default (\"Al\"), then K is echoed"
        );
        assert_eq!(scb.ansbuf(), b"K", "the old default is gone, not \"AlK\"");
    }

    #[test]
    #[should_panic(expected = "FSDNPT")]
    fn fsdinc_refuses_a_state_outside_fsdnpt_fsdnen() {
        let form = compile(b"?? ??", b"A B", MANY);
        let mut scb = zeroed_scb();
        scb.set_state(state::FSDAPT);
        fsdinc(&form, b"A B", &mut scb, b'x');
    }

    #[test]
    #[should_panic(expected = "fsdqdp")]
    fn fsdinc_refuses_ctrl_l_the_redisplay_request_it_does_not_build() {
        let spec = b"A B";
        let form = compile(b"?? ??", spec, MANY);
        let mut scb = zeroed_scb();
        scb.set_crsfld(0);
        scb.set_state(state::FSDNEN);
        fsdinc(&form, spec, &mut scb, 0x0c);
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

    /// `movfld()`, `FSD.C:675`: step past every field flagged "avoid".
    #[test]
    fn moving_skips_avoided_fields() {
        let mut form = compile(b"?? ?? ??", b"A B C", MANY);
        assert_eq!(form.in_template, 3, "three fields in the template");
        form.fields[1].flags |= flags::AVOID;
        assert_eq!(move_field(&form, 1, 1, Some(99), false), Some(2), "skipped B");
        assert_eq!(move_field(&form, 1, -1, Some(99), false), Some(0), "skipped B downwards");
        assert_eq!(move_field(&form, 0, 1, Some(99), false), Some(0), "already usable");
    }

    /// `vldfld()`, `FSD.C:662`: out of range is a refusal unless the session
    /// wraps, and only an ANSI session with `udwrap` set wraps.
    #[test]
    fn only_a_wrapping_session_wraps_around_the_ends() {
        let form = compile(b"?? ?? ??", b"A B C", MANY);
        assert_eq!(move_field(&form, 3, 1, Some(99), true), Some(0), "to the top");
        assert_eq!(move_field(&form, 3, 1, Some(99), false), Some(99), "the last resort");
        assert_eq!(move_field(&form, -1, -1, Some(99), true), Some(2), "to the bottom");
        assert_eq!(move_field(&form, -1, -1, Some(99), false), Some(99), "either way");
        // The -1 the real call sites pass, which is what the `Option` is for.
        assert_eq!(move_field(&form, 3, 1, None, false), None, "no there there");
    }

    /// Every field avoided means there is nowhere to go, and the answer is the
    /// caller's last resort rather than a loop.
    ///
    /// This is the test the `fldi == fldn || fldi == flast` guard exists for.
    /// A port that dropped it does not fail here, it hangs.
    #[test]
    fn a_form_of_avoided_fields_gives_up_instead_of_spinning() {
        let mut form = compile(b"?? ?? ??", b"A B C", MANY);
        for f in form.fields.iter_mut() {
            f.flags |= flags::AVOID;
        }
        assert_eq!(move_field(&form, 0, 1, Some(99), true), Some(99), "upwards");
        assert_eq!(move_field(&form, 0, -1, Some(99), true), Some(99), "downwards");
        assert_eq!(move_field(&form, 1, 1, Some(99), false), Some(99), "off the end");

        // One field, avoided. Asked about *that* field, `fldi == fldn` is what
        // ends the walk -- but asked about the one past it, `fldn` is 1 and the
        // walk stands on 0, so nothing it ever reaches equals `fldn` and
        // `flast` is the only guard left. Dropping `flast` does not fail the
        // first of these; it hangs on the second.
        let mut one = compile(b"??", b"A", MANY);
        one.fields[0].flags |= flags::AVOID;
        assert_eq!(move_field(&one, 0, 1, Some(7), true), Some(7), "fldn ends it");
        assert_eq!(move_field(&one, 1, 1, Some(7), true), Some(7), "flast ends it");
        assert_eq!(move_field(&one, -1, -1, Some(7), true), Some(7), "downwards");
    }

    /// `hopfld`'s zero step (`FSD.C:1363`): that field, or nothing.
    ///
    /// A step of 0 lands on `flast` on the first try, so the walk gives up
    /// after one look rather than examining any neighbour.
    #[test]
    fn a_zero_step_considers_one_field_and_no_other() {
        let mut form = compile(b"?? ?? ??", b"A B C", MANY);
        assert_eq!(move_field(&form, 1, 0, None, true), Some(1), "it is usable");
        form.fields[1].flags |= flags::AVOID;
        assert_eq!(move_field(&form, 1, 0, None, true), None, "and B's neighbours");
        assert_eq!(move_field(&form, 2, 0, None, true), Some(2), "are not looked at");
    }

    /// A template with no fields in it at all, where `numtpl-1` and the
    /// refusal are the same number.
    #[test]
    fn an_empty_template_wraps_forwards_but_not_backwards() {
        let form = compile(b"", b"A", MANY);
        assert_eq!(form.in_template, 0, "the spec named it, the template did not");
        assert_eq!(form.fields.len(), 1, "and it is still a field");

        // Backwards: `numtpl-1` is -1, which is `vldfld`'s own "can't use".
        assert_eq!(move_field(&form, -1, -1, Some(99), true), Some(99));
        // Forwards: wrapping to 0 is a field number the template has no room
        // for, and the C hands it back regardless.
        assert_eq!(move_field(&form, 0, 1, Some(99), true), Some(0));
        assert_eq!(move_field(&form, 0, 1, Some(99), false), Some(99), "or nowhere");
    }
}
