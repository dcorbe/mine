//! Key definitions, and the order they put records in.
//!
//! A Btrieve file is indexed by up to 24 keys, each of which is one or more
//! *segments* of the record compared in turn. The definitions live in the file
//! control record at `0x110`, thirty bytes each, and they are what
//! `PLBTVSTF.C`'s `clckln()` reads out of Btrieve's `STAT` reply to size
//! `bb->key` and fill `bb->keylns[]`.
//!
//! # The order is derived from the records, not from the index pages
//!
//! A Btrieve file carries its own B-tree index pages, and this does not read
//! them. It reads the *records* and sorts them by each key, which produces the
//! same order by construction -- an index is a sorted view of the data, and the
//! data is right here.
//!
//! That is a real trade: it costs a sort at open time and it means the file's
//! own index pages are never checked against. What it buys is that the only
//! format this has to understand is the record, and a misread index page would
//! otherwise hand the module records in a plausible wrong order with nothing
//! anywhere saying so. MBBSEmu reaches the same conclusion by a different route,
//! sorting into SQLite indexes rather than walking the B-tree.

use std::cmp::Ordering;
use std::sync::Arc;

use super::BtvError;
use crate::acs;
use crate::acs::{Acs, Table};

/// Where the key definitions start in the file control record.
pub(crate) const BASE: usize = 0x110;

/// Bytes of one key definition.
pub(crate) const WIDTH: usize = 0x1e;

/// `BTVSTF.H:13` -- the most segments a file may have.
pub const SEGMAX: usize = 24;

/// Where each field of a key definition sits.
pub(crate) mod at {
    /// Attribute flags.
    pub const ATTRIBUTES: usize = 0x08;
    /// Where a duplicate-permitting key's in-record `[prev][next]` chain pair
    /// lives, as a byte offset into the record's **physical** slot.
    ///
    /// Measured against two files the real engine wrote: `WCCUSERS.DAT` key 2
    /// reads 1998 here, its own `reclen` exactly, with no records to say
    /// whether that is `reclen` or `physical - 8` (`physical` is `reclen + 8`
    /// there, so the two coincide). `DUPKEY30.DAT` -- the first file measured
    /// with actual duplicate records in it -- reads 14, which is **not**
    /// `reclen` (12) but is exactly `physical - 8` (`physical` is 22: 12 of
    /// record, 2 unaccounted for, 8 of chain). `physical - 8` is therefore the
    /// general rule; `reclen` only looked right because `WCCUSERS` happens to
    /// have no gap between its record and its chain. See
    /// `docs/plans/2026-08-08-fsd-subsystem-design.md`.
    pub const CHAIN: usize = 0x12;
    /// Offset of this segment within the record.
    pub const OFFSET: usize = 0x14;
    /// Length of this segment, in bytes.
    pub const LENGTH: usize = 0x16;
    /// The extended data type, when the attributes say to use it.
    pub const EXTENDED: usize = 0x1c;
    /// The byte value this key treats as *null*, when either null attribute
    /// bit is set.
    ///
    /// Located by creating the same file twice through genuine Btrieve 6.15
    /// and changing nothing but this: `tools/btrieve-oracle/floatprobe.c`'s
    /// `createf` with null `0x00` and `0xaa`, and the only meaningful byte
    /// that moved was file offset `0x12d` -- which is
    /// [`BASE`](super::BASE) + `0x1d`, one past [`EXTENDED`]. (The other byte
    /// that moved was the control record's own write counter at `0x68`.)
    pub const NULL_VALUE: usize = 0x1d;
}

/// The attribute bits this reader understands.
pub(crate) mod flag {
    /// More than one record may carry this key value.
    pub const DUPLICATES: u16 = 1 << 0;
    /// An update may change this key's value.
    ///
    /// Without it, genuine Btrieve 6.15 answers **status 10** to any update
    /// that changes the key -- and writes nothing. Measured directly by
    /// creating the same file twice, once with attributes `0x0100` and once
    /// with `0x0102`, and running the same key-changing update against both
    /// (`tools/btrieve-oracle/delprobe.c`, `create` vs `create_mod`).
    pub const MODIFIABLE: u16 = 1 << 1;
    /// The key is compared as a plain unsigned binary field.
    pub const OLD_BINARY: u16 = 1 << 2;
    /// **Another segment of the same key follows this one.** `BTVSTF.H:59`
    /// names this one: `#define ANOSEG 0x10`.
    pub const ANOSEG: u16 = 1 << 4;
    /// The key collates through a numbered alternate character sequence.
    ///
    /// Named here rather than written as a bare `1 << 5` in [`UNSUPPORTED`]
    /// because [`crate::census`] reports this bit for definitions this module
    /// *refuses*, and a second literal in a second file is one edit away from
    /// disagreeing with this one.
    pub const ALT_COLLATING: u16 = 1 << 5;
    /// The segment sorts backwards.
    pub const DESCENDING: u16 = 1 << 6;
    /// The type is in [`at::EXTENDED`] rather than implied by the flags.
    pub const EXTENDED: u16 = 1 << 8;
    /// A record is left OUT of this key's index when **every** segment of it
    /// is entirely [`at::NULL_VALUE`].
    pub const NULL_ALL_SEGMENTS: u16 = 1 << 3;
    /// A record is left OUT of this key's index when **any** segment of it is
    /// entirely [`at::NULL_VALUE`].
    pub const NULL_ANY_SEGMENT: u16 = 1 << 9;
    /// Duplicate values repeat the key in the index instead of chaining the
    /// records together, so the record carries **no** `[prev][next]` pair.
    ///
    /// Measured against genuine 6.15 by creating the same file twice and
    /// changing only this bit: with it the engine chose `physical` 18 for a
    /// `reclen` of 16 -- two bytes of v6 slot marker and nothing else -- and
    /// wrote `0` into [`at::CHAIN`]; without it, `physical` 26 and a chain
    /// offset of 18. Eight bytes of record, and the whole mechanism, gone.
    ///
    /// The **order is identical either way**, which is why this crate can read
    /// such a file: it derives order by sorting the records and never reads
    /// the chain. Writing one is a different matter -- see [`Key::chain`].
    pub const REPEATING_DUPLICATES: u16 = 1 << 7;
}

/// Attribute bits that change what an index *contains* or how it collates, and
/// which this host does not reproduce.
///
/// Each of them would make the order derived from the records differ from the
/// order the file's own index pages hold, silently:
///
/// - `NULL_ALL_SEGMENTS` and `NULL_ANY_SEGMENT` **leave records out of the
///   index** when the key field is entirely the null value. Sorting every
///   record would then offer the module a record Btrieve would have skipped.
/// - `NUMBERED_ACS` collates through an alternate character sequence, so `a`
///   and `A` may be one letter, or the alphabet may not be the alphabet.
/// - `REPEATING_DUPLICATES` stores duplicate keys differently again.
///
/// **None of them is set on any key of any file MajorMUD ships**, which is
/// checked by `crates/mbbs/tests/btrieve.rs` -- so this refuses on nothing that
/// exists here, and refuses rather than guesses on a file that used one.
const UNSUPPORTED: [(u16, &str); 1] =
    [(flag::ALT_COLLATING, "a numbered alternate collating sequence")];

/// When a key leaves a record out of its index altogether.
///
/// Both bits were measured against genuine Pervasive Btrieve 6.15 with
/// `tools/btrieve-oracle/floatprobe.c`, over **one key of two two-byte
/// segments** -- a single-segment key cannot tell them apart, and the
/// single-segment run showed both omitting the same one record.
///
/// Four records, keys `AB CD`, `-- CD`, `AB --` and `-- --` where `--` is the
/// null value, walked through the engine's own index:
///
/// | attribute | in the index |
/// |---|---|
/// | neither bit | all four |
/// | [`flag::NULL_ALL_SEGMENTS`] | three -- only `-- --` is dropped |
/// | [`flag::NULL_ANY_SEGMENT`] | one -- only `AB CD` survives |
///
/// Every record was inserted with status 0 in all three cases, so the omitted
/// ones are **in the file and absent from the index**. That is why this
/// matters here at all: this crate derives key order by sorting the records
/// (see the module comment), so without reproducing the omission it would
/// hand a module a record the genuine engine skips, with nothing anywhere
/// reporting an error.
///
/// The value itself is the key definition's own byte at [`at::NULL_VALUE`],
/// not a hardcoded zero -- measured by declaring `0x20` and watching the
/// all-spaces record vanish while the all-zeroes record stayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Null {
    /// Omit the record when every segment is entirely this byte.
    All(u8),
    /// Omit the record when any segment is entirely this byte.
    Any(u8),
}

/// How a key segment's bytes are to be compared.
///
/// Btrieve defines twenty-odd data types and MajorMUD's eighteen files use
/// four of them: `Zstring` (0x0b), `Integer` (0x01), `UnsignedBinary` (0x0e)
/// and `AutoInc` (0x0f), which collapse to three orderings. Two more --
/// `Float` (0x02) and `Bfloat` (0x09) -- were added once the engine's own
/// order for each had been measured, the first because `MULTIACS.DAT` needs
/// it and the second because measuring it turned out to be as cheap.
///
/// **Anything else is refused rather than guessed at.** A `Date`, a `Time` or
/// a `Decimal` sorted as though it were bytes would put records in an order
/// that is wrong only sometimes, which is the worst way for it to be wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `String`, `Lstring`, `Zstring`, `OldAscii`: the bytes up to the first
    /// NUL, compared as text.
    Text,

    /// `Integer`, `AutoInc`: a signed little-endian number.
    Signed,

    /// `Unsigned`, `UnsignedBinary`, `OldBinary`: an unsigned little-endian
    /// number, of whatever width the segment is.
    Unsigned,

    /// `Float`: an IEEE binary float, of whatever width the segment is --
    /// eight bytes is an `f64`, four an `f32`. Both measured; see [`float`].
    Float,

    /// `Bfloat`: Borland's binary float, which is **not** IEEE -- the
    /// exponent is the last byte and the sign is a bit in the one before it.
    /// Measured at four and eight bytes; see [`bfloat`].
    Bfloat,
}

impl Kind {
    /// The ordering a Btrieve data type implies, or `None` for one this host
    /// has no ordering for.
    ///
    /// `pub(crate)` rather than private: [`create`](super::create) calls this
    /// to refuse writing a key of a type this reader could not make sense of
    /// afterward. Writing a value `parse` cannot read back is exactly the
    /// silent-corruption shape this module's own doc comment warns against,
    /// so the writer and the reader share one answer to "is this type
    /// readable" rather than keeping two lists that could drift apart.
    pub(crate) fn of(code: u8) -> Option<Self> {
        match code {
            0x00 | 0x0a | 0x0b | 0x20 => Some(Self::Text),
            0x01 | 0x0f => Some(Self::Signed),
            0x0d | 0x0e | 0x21 => Some(Self::Unsigned),
            0x02 => Some(Self::Float),
            0x09 => Some(Self::Bfloat),
            _ => None,
        }
    }

    /// What the type is called, for a refusal.
    fn name(code: u8) -> &'static str {
        match code {
            0x02 => "float",
            0x03 => "date",
            0x04 => "time",
            0x05 => "decimal",
            0x06 => "money",
            0x07 => "logical",
            0x08 => "numeric",
            0x09 => "bfloat",
            _ => "an unknown type",
        }
    }
}

/// One segment of a key: a field of the record, and how to compare it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    pub offset: u16,
    pub length: u16,
    pub kind: Kind,
    pub descending: bool,
}

impl Segment {
    /// This segment's bytes of a record.
    fn of<'a>(&self, record: &'a [u8]) -> &'a [u8] {
        let start = usize::from(self.offset);
        let end = start + usize::from(self.length);
        record.get(start..end).unwrap_or(&[])
    }

    /// Compare this segment of two records.
    fn compare(&self, a: &[u8], b: &[u8], acs: Option<&Acs>) -> Ordering {
        self.order(self.of(a), self.of(b), acs)
    }

    /// Compare two of this segment's fields, honouring its direction.
    ///
    /// Every key comparison in this crate funnels through here, which is why
    /// an alternate collating sequence is applied at this one point rather
    /// than anywhere nearer the callers.
    fn order(&self, a: &[u8], b: &[u8], acs: Option<&Acs>) -> Ordering {
        let order = match self.kind {
            // The `None` arm is deliberately the bare `cmp` and not a shared
            // iterator over both cases. `records.rs:239` measures this
            // function at 18.5% of a live board's CPU and the `memcmp` this
            // compiles to at roughly 23% more; folding both operands through
            // an iterator unconditionally would charge all 470 files in the
            // corpus for a feature 45 of them use.
            Kind::Text => match acs {
                None => text(a).cmp(text(b)),
                Some(acs) => text(a)
                    .iter()
                    .map(|b| acs.fold(*b))
                    .cmp(text(b).iter().map(|b| acs.fold(*b))),
            },
            // A table applies to text and nothing else. Folding a byte inside
            // an integer would corrupt the number rather than reorder it.
            Kind::Signed => signed(a, b),
            Kind::Unsigned => unsigned(a, b),
            Kind::Float => float(a, b),
            Kind::Bfloat => bfloat(a, b),
        };
        if self.descending { order.reverse() } else { order }
    }
}

/// A text key's bytes: everything before the first NUL.
///
/// A `Zstring` is NUL-terminated inside a fixed-width field, so the padding
/// after the terminator is not part of the value and two names differing only
/// in what follows their NUL are the same key.
fn text(field: &[u8]) -> &[u8] {
    match field.iter().position(|b| *b == 0) {
        Some(end) => &field[..end],
        None => field,
    }
}

/// Compare two little-endian unsigned fields of any width.
///
/// Byte by byte from the most significant end, which for little-endian is the
/// *last* byte. Deliberately not "read it into an integer and compare those":
/// the widths in these files are 1, 2, 4, 8, 18 and 20 bytes, and any fixed
/// accumulator wide enough for most of them silently drops the high bytes of
/// `WCCTEXT`'s eighteen. This has no width to be too narrow.
fn unsigned(a: &[u8], b: &[u8]) -> Ordering {
    for i in (0..a.len().max(b.len())).rev() {
        let (x, y) = (byte(a, i), byte(b, i));
        if x != y {
            return x.cmp(&y);
        }
    }
    Ordering::Equal
}

/// Compare two little-endian signed fields of any width.
///
/// The sign is the top bit of the field's own last byte, and once two
/// two's-complement numbers have the same sign their bytes compare the same way
/// unsigned ones do.
fn signed(a: &[u8], b: &[u8]) -> Ordering {
    let negative = |field: &[u8]| field.last().is_some_and(|b| b & 0x80 != 0);
    match (negative(a), negative(b)) {
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        _ => unsigned(a, b),
    }
}

/// Compare two IEEE binary floats -- `f64` at eight bytes, `f32` at four.
///
/// **IEEE totalOrder, which is `total_cmp` and not `partial_cmp`.** Measured
/// against genuine Pervasive Btrieve 6.15 with
/// `tools/btrieve-oracle/floatprobe.c`, which inserted seven values and
/// stepped the key: the engine answers
///
/// ```text
/// -1e308  <  -1.0  <  -0.0  <  +0.0  <  1.0  <  1e308  <  NaN
/// ```
///
/// Two of those would be wrong under the obvious implementation, and both
/// are the "wrong only sometimes" failure this module refuses on principle:
///
/// - **`-0.0` sorts strictly before `+0.0`.** They were inserted `+0.0`
///   first and came back the other way round, so the engine is ordering them
///   rather than calling them one key. `partial_cmp` reports them equal.
/// - **NaN sorts after every number.** `partial_cmp` reports `None`, and any
///   `unwrap_or` of that invents an answer.
///
/// A four-byte segment is an `f32`, measured the same way and not assumed
/// from the eight-byte case.
///
/// A width this host has no float for compares `Equal` rather than panicking:
/// [`parse`] has already refused any *key* of an unreadable width long before
/// a comparison can reach here, so this arm is unreachable rather than
/// lenient.
fn float(a: &[u8], b: &[u8]) -> Ordering {
    match (a.len(), b.len()) {
        (8, 8) => {
            let read = |f: &[u8]| {
                f64::from_le_bytes(f[..8].try_into().expect("eight bytes"))
            };
            read(a).total_cmp(&read(b))
        }
        (4, 4) => {
            let read = |f: &[u8]| {
                f32::from_le_bytes(f[..4].try_into().expect("four bytes"))
            };
            read(a).total_cmp(&read(b))
        }
        _ => Ordering::Equal,
    }
}

/// Compare two Borland binary floats (`bfloat`, type `0x09`).
///
/// **Not IEEE**, and the difference is structural rather than cosmetic: the
/// **last** byte is the exponent, biased by 128, and the sign is bit 7 of the
/// byte *before* it. Everything else is mantissa. IEEE puts the sign in the
/// top bit of the last byte and the exponent below it, so reading one as the
/// other misorders almost everything.
///
/// Measured against genuine Pervasive Btrieve 6.15 by inserting chosen bit
/// patterns -- not C floats, which would have assumed the encoding -- and
/// stepping the key. At four bytes the engine answers
///
/// ```text
/// ffffffff < 00008081 < ffffff7f < 00000001 < 00000080 < 00000081 < 00000082
/// ```
///
/// which under the layout above reads
/// `-huge < -1.0 < -0.5 < +tiny < +0.5 < +1.0 < +2.0`. Eight bytes agrees, and
/// adds the case four bytes could not show: an all-zero key sorts **between**
/// the negatives and the positives, which is what sign-magnitude requires and
/// what a plain byte comparison would get wrong.
///
/// See `docs/2026-08-17-float-key-oracle.md`.
fn bfloat(a: &[u8], b: &[u8]) -> Ordering {
    /// The sign, and the magnitude most significant byte first: exponent,
    /// then the sign's own byte with that bit cleared, then the rest.
    fn split(field: &[u8]) -> (bool, Vec<u8>) {
        let n = field.len();
        if n < 2 {
            return (false, field.to_vec());
        }
        let negative = field[n - 2] & 0x80 != 0;
        let mut magnitude = Vec::with_capacity(n);
        magnitude.push(field[n - 1]);
        // Masking the sign off cannot change an ordering -- the match below
        // has already split on it, so both operands of every comparison
        // carry it identically -- and no test can pin it. It is here because
        // a magnitude with a sign bit in it is not a magnitude.
        magnitude.push(field[n - 2] & 0x7f);
        magnitude.extend(field[..n - 2].iter().rev());
        (negative, magnitude)
    }

    let (a_negative, a_magnitude) = split(a);
    let (b_negative, b_magnitude) = split(b);
    match (a_negative, b_negative) {
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        // Two negatives sort by *descending* magnitude, the same inversion a
        // sign-magnitude representation always has.
        (true, true) => b_magnitude.cmp(&a_magnitude),
        (false, false) => a_magnitude.cmp(&b_magnitude),
    }
}

/// Byte `i` of a field, or zero past its end.
fn byte(field: &[u8], i: usize) -> u8 {
    field.get(i).copied().unwrap_or(0)
}

/// One key: the segments to compare, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    /// The key's ordinal among the file's keys, `0..count` -- what `qrybtv`
    /// and the acquire family name a key by, and what indexes
    /// [`Records::order`](super::records::Records)/`rank`.
    pub number: u16,

    /// Which key *definition* this key's first segment starts at, `0..`
    /// however many definitions the file has -- **not the same number as
    /// [`Self::number`] once any earlier key has more than one segment**.
    /// `WCCBANKS.DAT` is one key over two definitions and `WCCITOWN.DAT` is
    /// two keys over three, and both happen to put their multi-segment key
    /// last, which is the only reason `number` and `definition` agree for
    /// every file MajorMUD ships. This is where a key's root page and
    /// per-key record count live in the file control record --
    /// `fcr::KEYS + definition * fcr::KEY_WIDTH` -- because only the first
    /// definition of a multi-segment key carries them; a continuation
    /// definition's own root field is not meaningful.
    pub definition: u16,

    pub segments: Vec<Segment>,
    /// Whether two records may carry the same value.
    pub duplicates: bool,

    /// Whether an update may change this key's value.
    ///
    /// `false` makes genuine Btrieve refuse such an update with status 10 and
    /// write nothing -- see [`Block::update`](super::Block::update), which is
    /// where that refusal lives, and [`flag::MODIFIABLE`] for the
    /// measurement. Forty-three of the seventy-six key definitions in this
    /// repository's real files are `false`, including `WCCUSERS.DAT` key 0 and
    /// `WCCCLASS.DAT` key 0, so this is the common case rather than the
    /// exotic one.
    pub modifiable: bool,
    /// Where the in-record `[prev][next]` duplicate-chain pair lives, as a
    /// byte offset into a record's **physical** slot -- `None` when
    /// [`Self::duplicates`] is false, since a unique key has no chain to
    /// offset. See [`at::CHAIN`].
    pub chain: Option<u16>,
    /// The alternate collating sequence this key is ordered through, if it
    /// declares one.
    ///
    /// **Per key, not per file** -- the format expresses exactly that, and
    /// `MULTIACS.DAT` is the proof: it holds *two* tables, `ALLCAPS` on
    /// physical page 4 and `LOWER` on 5, one for each of its two ACS-flagged
    /// keys, and for v6 the engine stores the pointer per key segment
    /// (`W32MKDE_decompiled.c:15364-15375`).
    ///
    /// It lives on [`Key`] rather than on [`Segment`] because `Segment` is
    /// `Copy` and an `Arc` field would end that, and because [`Key::compare`]
    /// and [`Key::compare_value`] are the only comparison entry points
    /// [`records`](super::records) uses -- so the table reaches every
    /// comparison without that module changing.
    ///
    /// An `Arc` because every ACS-flagged key of a file usually shares one
    /// table, and a 256-byte array per key would be copied for nothing.
    pub acs: Option<Arc<Acs>>,

    /// When this key leaves a record out of its index altogether, and on
    /// which byte. `None` unless the definition sets one of the two null
    /// attribute bits. See [`Null`].
    pub null: Option<Null>,
}

impl Key {
    /// How many bytes the key is, all segments together.
    ///
    /// This is what `clckln()` puts in `bb->keylns[n]`, and what `qrybtv` and
    /// the acquire family copy out of the module's key buffer.
    pub fn length(&self) -> u16 {
        self.segments.iter().map(|s| s.length).sum()
    }

    /// This key, as an index page needs to measure it.
    ///
    /// [`Self::length`] alone is not enough to size an index entry -- a key that
    /// permits duplicates carries four more bytes per entry -- and passing a
    /// bare length is what let four separate places in
    /// [`pages`](super::pages) each get that wrong in the same way. This is the
    /// only way to build a [`Shape`](super::pages::Shape) from a key, so the
    /// duplicates term travels with the length rather than beside it.
    pub fn shape(&self) -> super::pages::Shape {
        super::pages::Shape {
            length: usize::from(self.length()),
            duplicates: self.duplicates,
        }
    }

    /// The key bytes of a record, segments concatenated.
    pub fn extract(&self, record: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(usize::from(self.length()));
        for segment in &self.segments {
            let field = segment.of(record);
            out.extend_from_slice(field);
            // A record too short for the segment still contributes its width,
            // or the concatenation would not line up with what the module hands
            // back in its key buffer.
            out.resize(out.len() + usize::from(segment.length) - field.len(), 0);
        }
        out
    }

    /// Whether this key leaves `record` out of its index entirely.
    ///
    /// See [`Null`] for the measurement. A segment counts as null when
    /// **every** byte of it is the declared value; a record shorter than a
    /// segment contributes the zero bytes [`Self::extract`] pads with, so the
    /// two agree about what a truncated record's segment holds.
    pub fn excluded(&self, record: &[u8]) -> bool {
        let Some(null) = self.null else {
            return false;
        };
        let byte = match null {
            Null::All(byte) | Null::Any(byte) => byte,
        };
        let segment_is_null = |segment: &Segment| {
            let field = segment.of(record);
            let width = usize::from(segment.length);
            field.iter().all(|b| *b == byte)
                && (field.len() == width || byte == 0)
        };
        match null {
            Null::All(_) => self.segments.iter().all(segment_is_null),
            Null::Any(_) => self.segments.iter().any(segment_is_null),
        }
    }

    /// Compare two records by this key.
    ///
    /// **Segment by segment, each with its own type and direction**, which is
    /// what the per-segment type is for. MBBSEmu compares a multi-segment key
    /// as one blob of bytes instead; the two agree for a key whose segments are
    /// all text and disagree for `WCCBANKS`, whose key is a 30-byte name
    /// followed by a 4-byte integer that a bytewise compare would order by its
    /// low byte first. Both of MajorMUD's segmented files hold no records, so
    /// nothing here can tell the readings apart -- this is the one the segment
    /// types imply.
    pub fn compare(&self, a: &[u8], b: &[u8]) -> Ordering {
        for segment in &self.segments {
            match segment.compare(a, b, self.acs.as_deref()) {
                Ordering::Equal => continue,
                other => return other,
            }
        }
        Ordering::Equal
    }

    /// Compare a record against a key value the module supplied.
    ///
    /// The module's buffer is the segments concatenated, so it is compared as
    /// though it were a record whose fields happen to be laid out that way.
    pub fn compare_value(&self, record: &[u8], value: &[u8]) -> Ordering {
        let mut at = 0u16;
        for segment in &self.segments {
            let laid_out = Segment {
                offset: at,
                ..*segment
            };
            match segment.order(segment.of(record), laid_out.of(value), self.acs.as_deref()) {
                Ordering::Equal => at += segment.length,
                other => return other,
            }
        }
        Ordering::Equal
    }
}

/// Read a file's key definitions out of its file control record.
///
/// `count` is the number of *keys*, from `0x14`. A key with more segments
/// consumes more than one definition, so the definitions are walked until
/// `count` keys have been assembled rather than for `count` iterations --
/// `WCCBANKS` has one key of two segments and `WCCITOWN` has two keys and three
/// segments between them.
///
/// Whether any key of this file collates through an alternate sequence.
///
/// The gate a caller uses to decide whether locating the file's tables is
/// worth any I/O at all -- and the *only* sound gate, because the control
/// record's own pointer at `FCR+0x10a` is a v6 field: `CLASSADS.DAT` and
/// `EMAIL.DAT` read zero there while genuinely holding a block. See
/// [`crate::acs`] for that measurement.
///
/// Follows `ANOSEG` exactly as [`parse`] does rather than scanning every
/// definition slot, because slots past the file's last key hold bytes that
/// belong to no key and may have anything in them.
#[must_use]
pub fn declares_alt_collating(fcr: &[u8], count: u16) -> bool {
    let mut keys = 0usize;
    let mut definitions = 0usize;
    while keys < usize::from(count) && definitions < SEGMAX {
        let start = BASE + definitions * WIDTH;
        let Some(definition) = fcr.get(start..start + WIDTH) else {
            return false;
        };
        definitions += 1;
        let attributes =
            u16::from_le_bytes([definition[at::ATTRIBUTES], definition[at::ATTRIBUTES + 1]]);
        if attributes & flag::ALT_COLLATING != 0 {
            return true;
        }
        if attributes & flag::ANOSEG == 0 {
            keys += 1;
        }
    }
    false
}

/// `tables` is every alternate collating sequence the file carries, in page
/// order, and empty when it has none. A key flagged as collating through one
/// is bound to it here; see the binding rule below for why more than one is
/// refused rather than guessed at.
///
/// # Errors
///
/// If a definition runs past the end of the file control record, uses a data
/// type this host has no ordering for, leaves a key with no segments, is
/// declared with an unsupported attribute, or collates through an alternate
/// sequence that `tables` cannot unambiguously supply.
pub fn parse(
    name: &str,
    fcr: &[u8],
    count: u16,
    tables: &[Table],
) -> Result<Vec<Key>, BtvError> {
    let fail = |why: String| BtvError {
        file: name.to_owned(),
        why,
    };

    // The binding rule. A key's attribute word says *that* it collates through
    // an alternate sequence; **which** one is the logical page in its own key
    // definition, read by [`acs::page_in_key`] -- a page number, not an index
    // into the file's blocks, which that function's doc comment shows matters.
    // So a key binds the located table sitting on the page it names, and a key
    // naming a page no table was found on is refused rather than given whatever
    // table happens to be to hand.
    //
    // v5 leaves that field zero and carries exactly one table, which
    // `acs_tables` registers under page zero -- so one rule serves both
    // versions rather than two.
    let bound = |page: u32| {
        tables
            .iter()
            .find(|table| table.page == page)
            .map(|table| Arc::clone(&table.acs))
    };

    let mut keys: Vec<Key> = Vec::with_capacity(usize::from(count));
    let mut segments = Vec::new();
    let mut definitions = 0usize;
    // Where the key currently being assembled started -- its first
    // segment's definition index, which is where its root page and record
    // count live (see [`Key::definition`]). Set fresh each time `segments`
    // is empty, i.e. at the start of a new key.
    let mut start_definition = 0usize;
    // Whether *any* segment of the key currently being assembled declared an
    // alternate sequence. Read across the whole key rather than off its last
    // definition: for v6 the pointer is stored per segment, so a segmented key
    // could flag it anywhere, and a key ordered through a table for one segment
    // is a key whose order this host cannot reproduce without that table.
    let mut alt_collating = false;
    // The logical page the key currently being assembled names its table by.
    let mut alt_page: Option<u32> = None;

    while keys.len() < usize::from(count) {
        if definitions >= SEGMAX {
            return Err(fail(format!(
                "more than {SEGMAX} key segments, which is more than a file has"
            )));
        }
        if segments.is_empty() {
            start_definition = definitions;
            alt_collating = false;
            alt_page = None;
        }
        let start = BASE + definitions * WIDTH;
        let definition = fcr.get(start..start + WIDTH).ok_or_else(|| {
            fail(format!(
                "key definition {definitions} runs past the end of the file control record"
            ))
        })?;
        definitions += 1;

        let word = |offset: usize| {
            u16::from_le_bytes([definition[offset], definition[offset + 1]])
        };
        let attributes = word(at::ATTRIBUTES);
        if attributes & flag::ALT_COLLATING != 0 {
            let page = acs::page_in_key(definition);
            match alt_page {
                // Read per *segment*, the way the engine reads it (`:15362`),
                // but bound per key -- so a segmented key whose segments name
                // two different tables is a shape `Key` cannot represent and
                // this refuses rather than picking one. No corpus file does it:
                // GALTELA's segmented key names page 1 from both segments.
                Some(first) if first != page => {
                    return Err(fail(format!(
                        "key {}'s segments collate through two different alternate \
                         sequences, on logical pages {first} and {page}, and this \
                         host binds one table per key",
                        keys.len()
                    )));
                }
                _ => alt_page = Some(page),
            }
            alt_collating = true;
        }
        for (bit, what) in UNSUPPORTED {
            if attributes & bit == 0 {
                continue;
            }
            // The one refusal a located table lifts. The other three --
            // null-all, null-any, repeating duplicates -- have no measured
            // behaviour here and stay unconditional.
            if bit == flag::ALT_COLLATING {
                let page = acs::page_in_key(definition);
                if bound(page).is_some() {
                    continue;
                }
                // A table was located, just not the one this key names. That is
                // a different fault from carrying none at all, and worth saying
                // so rather than reporting the generic refusal below.
                if !tables.is_empty() {
                    let found: Vec<u32> = tables.iter().map(|table| table.page).collect();
                    return Err(fail(format!(
                        "key {} collates through the alternate sequence on logical \
                         page {page}, and this file's tables were found on {found:?}",
                        keys.len()
                    )));
                }
            }
            return Err(fail(format!(
                "key {} is declared with {what}, which changes what its index \
                 holds and is not reproduced by sorting the records",
                keys.len()
            )));
        }

        let length = word(at::LENGTH);
        if length == 0 {
            return Err(fail(format!(
                "key {} has a zero-length segment, so the file claims {count} keys \
                 and describes fewer",
                keys.len()
            )));
        }

        // The type is the extended one when the attributes say so, and
        // otherwise is implied: binary if the old-style-binary bit is set and
        // text if it is not.
        let code = if attributes & flag::EXTENDED != 0 {
            definition[at::EXTENDED]
        } else if attributes & flag::OLD_BINARY != 0 {
            0x21
        } else {
            0x20
        };
        let kind = Kind::of(code).ok_or_else(|| {
            fail(format!(
                "key {} is {} ({code:#04x}), which this host has no ordering for",
                keys.len(),
                Kind::name(code)
            ))
        })?;

        segments.push(Segment {
            offset: word(at::OFFSET),
            length,
            kind,
            descending: attributes & flag::DESCENDING != 0,
        });

        // `ANOSEG` says another segment of *this* key follows. Without it, the
        // key is complete.
        if attributes & flag::ANOSEG == 0 {
            let duplicates = attributes & flag::DUPLICATES != 0;
            keys.push(Key {
                number: keys.len() as u16,
                definition: start_definition as u16,
                segments: std::mem::take(&mut segments),
                duplicates,
                // Read from this definition -- the key's *last* segment -- and
                // that is safe for a segmented key rather than merely
                // convenient: genuine Btrieve 6.15 refuses to CREATE a key
                // whose segments disagree about this bit, answering status 45
                // ("invalid key flags") at create time. Measured over the full
                // two-by-two matrix (`delprobe modseg`, 2026-08-16): both
                // segments modifiable creates and updates; neither creates and
                // refuses the update with status 10; one of each does not
                // produce a file at all. All four multi-segment keys in this
                // repository's real files agree across their segments, checked.
                modifiable: attributes & flag::MODIFIABLE != 0,
                // Read from the key's **first** definition, at
                // `start_definition` -- the same coordinate [`Key::definition`]
                // already uses, and for the same reason. A segmented duplicate
                // key carries its chain offset only in its first segment; its
                // later segments read 0 there.
                //
                // This used to read *this* definition, the key's last, on the
                // grounds that "none of the four [duplicate-permitting keys]
                // MajorMUD ships is segmented". `WGSGEN2.DAT` is: two keys in
                // three definitions, the first of them segmented, with chain
                // offsets 61 and 69 sitting in definitions 0 and 2 while
                // definition 1 -- key 0's last -- reads 0. That zero is not a
                // chain, it is the front of the slot, and eight bytes written
                // there overwrite the two-byte marker `records::walk_v6` reads
                // to decide whether the slot holds a record at all. See
                // `a_segmented_duplicate_key_reads_its_chain_offset_from_its_first_segment`
                // for what that cost.
                //
                // `None` when the key repeats its duplicates in the index
                // rather than chaining the records: such a key has no pair to
                // point at, and its definition duly reads 0 here. Writing
                // eight bytes at offset 0 would land on the front of the
                // record -- which is why the write paths ask for this and
                // refuse when it is absent, rather than defaulting.
                chain: (duplicates && attributes & flag::REPEATING_DUPLICATES == 0).then(|| {
                    let at = BASE + start_definition * WIDTH + at::CHAIN;
                    u16::from_le_bytes([fcr[at], fcr[at + 1]])
                }),
                // Which bit wins if a definition somehow set both is not
                // measured, and no file here sets either; `Any` is the
                // stricter of the two and omitting more than the engine does
                // shows up as a missing record rather than a phantom one.
                null: if attributes & flag::NULL_ANY_SEGMENT != 0 {
                    Some(Null::Any(definition[at::NULL_VALUE]))
                } else if attributes & flag::NULL_ALL_SEGMENTS != 0 {
                    Some(Null::All(definition[at::NULL_VALUE]))
                } else {
                    None
                },
                // Bound only for a key that actually declared one. A file may
                // carry a table that no key uses, and folding an unflagged
                // key's bytes through it would reorder an index that genuine
                // Btrieve leaves in raw byte order.
                acs: alt_collating.then(|| alt_page.and_then(bound)).flatten(),
            });
        }
    }

    if !segments.is_empty() {
        return Err(fail(format!(
            "the last key is left open by its ANOSEG bit after {count} keys"
        )));
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key definition, as thirty bytes of a file control record.
    fn definition(attributes: u16, offset: u16, length: u16, extended: u8) -> Vec<u8> {
        let mut out = vec![0u8; WIDTH];
        out[at::ATTRIBUTES..at::ATTRIBUTES + 2].copy_from_slice(&attributes.to_le_bytes());
        out[at::OFFSET..at::OFFSET + 2].copy_from_slice(&offset.to_le_bytes());
        out[at::LENGTH..at::LENGTH + 2].copy_from_slice(&length.to_le_bytes());
        out[at::EXTENDED] = extended;
        out
    }

    /// A key definition like [`definition`], with a chain offset at
    /// [`at::CHAIN`] -- what a duplicate-permitting key's descriptor carries
    /// and a unique one leaves zero.
    fn definition_with_chain(attributes: u16, offset: u16, length: u16, extended: u8, chain: u16) -> Vec<u8> {
        let mut out = definition(attributes, offset, length, extended);
        out[at::CHAIN..at::CHAIN + 2].copy_from_slice(&chain.to_le_bytes());
        out
    }

    /// A file control record holding these definitions.
    fn fcr(definitions: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![0u8; BASE + SEGMAX * WIDTH];
        for (n, definition) in definitions.iter().enumerate() {
            let at = BASE + n * WIDTH;
            out[at..at + WIDTH].copy_from_slice(definition);
        }
        out
    }

    #[test]
    fn a_key_is_one_segment_unless_anoseg_says_otherwise() {
        // `WCCUSERS`: three keys, one segment each -- the character's name, the
        // name of whoever it belongs to, and a four-byte number.
        let keys = parse(
            "WCCUSERS.DAT",
            &fcr(&[
                definition(flag::EXTENDED, 0, 30, 0x0b),
                definition(flag::EXTENDED, 30, 30, 0x0b),
                definition(flag::EXTENDED | flag::DUPLICATES, 60, 4, 0x0e),
            ]),
            3,
            &[],
        )
        .expect("parses");

        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].segments.len(), 1);
        assert_eq!(keys[0].length(), 30);
        assert_eq!(keys[0].segments[0].kind, Kind::Text);
        assert_eq!(keys[2].segments[0].kind, Kind::Unsigned);
        assert!(keys[2].duplicates);
        assert!(!keys[0].duplicates);
    }

    /// The in-record chain offset, measured against `DUPKEY30.DAT`'s own key
    /// descriptor: a 4-byte descending duplicate key over a 12-byte record
    /// reads 14 at [`at::CHAIN`] -- `physical - 8` (22 - 8), **not** `reclen`
    /// (12), which is what a first reading of `WCCUSERS.DAT` (a file with no
    /// duplicate records to disprove it) suggested. A key that forbids
    /// duplicates has nothing to read there at all.
    #[test]
    fn a_duplicate_keys_chain_offset_is_read_from_its_own_definition() {
        let keys = parse(
            "DUPKEY30.DAT",
            &fcr(&[definition_with_chain(
                flag::EXTENDED | flag::DUPLICATES,
                0,
                4,
                0x0e,
                14,
            )]),
            1,
            &[],
        )
        .expect("parses");
        assert_eq!(keys[0].chain, Some(14));

        let unique = parse("WCCRACE.DAT", &fcr(&[definition(flag::EXTENDED, 0, 2, 0x0e)]), 1, &[])
            .expect("parses");
        assert_eq!(unique[0].chain, None, "a unique key has no chain to offset");
    }

    /// A **segmented** duplicate key carries its chain offset in its *first*
    /// definition, and its later segments read zero there.
    ///
    /// Measured off `WGSGEN2.VIR`'s own file control record, the virgin
    /// generator file MajorMUD-NT's boot writes to. It declares two keys in
    /// three definitions, `reclen` 55 and `physical` 77:
    ///
    /// ```text
    /// def0  attrs 0x0133 (DUPLICATES|ANOSEG|...)  chain 61  offset  2  len 30
    /// def1  attrs 0x0123 (DUPLICATES, no ANOSEG)  chain  0  offset 32  len 25
    /// def2  attrs 0x0123 (DUPLICATES, no ANOSEG)  chain 69  offset 32  len 25
    /// ```
    ///
    /// def0 and def1 are one segmented key; def2 is the second key. The two
    /// chain offsets that are actually there -- 61 and 69 -- are exactly the
    /// eight-byte pairs a 77-byte slot has room for once its two-byte marker,
    /// 55-byte fixed part and four-byte variable pointer are counted
    /// (2 + 55 + 4 = 61, then 69). Reading the offset off the key's *last*
    /// definition gives key 0 a chain offset of **0**, which is not a chain at
    /// all: it is the front of the slot, and eight bytes written there land on
    /// the two-byte slot marker `records::walk_v6` reads to decide whether the
    /// slot holds a record.
    ///
    /// This is what broke MajorMUD-NT's boot. `Block::insert_v6` wrote each
    /// duplicate chain at `slot + 0`, and because `pages::to_long` stores a
    /// long word-swapped, a `prev` of position 16390 (`0x4006`) laid down
    /// `00 00 06 40` -- clearing the marker of the slot it was meant to
    /// describe. The third insert into `WGSGEN2.DAT` therefore left markers
    /// reading `[ffff, 0000, ffff]`, the walk found two records where the
    /// header said three, and `dfaacqlock` refused the file.
    ///
    /// The comment this replaces said a segmented duplicate key "would need
    /// this read at `start_definition` instead ... none exists to measure
    /// that against". One does, and it ships in every MajorMUD-NT install.
    ///
    /// # The corpus agrees, ten shapes out of ten
    ///
    /// Every Btrieve file in `archive/`, `peepeebbs/` and this crate's own
    /// fixtures was scanned for a segmented duplicate key. Ten distinct shapes
    /// exist, across three unrelated module families and **both** file
    /// versions, and all ten carry the offset in the first segment and zero in
    /// the later one -- there is no counterexample:
    ///
    /// ```text
    /// WGSGEN2.VIR   v6  key 0  chains [61, 0]  reclen   55  physical   77
    /// WCCBANK2.VIR  v6  key 0  chains [78, 0]  reclen   76  physical   86
    /// WCCITOW2.VIR  v6  key 1  chains [70, 0]  reclen   68  physical   78
    /// WCCITOW2.DAT  v6  key 1  chains [74, 0]  reclen   72  physical   82
    /// ELWGEMAL.DAT  v6  key 1  chains [1466,0] reclen 1456  physical 1474
    /// MBMGEMAL.DAT  v5  key 1  chains [1008,0] reclen 1000  physical 1016
    /// MBMG2MAL.DAT  v5  key 1  chains [246, 0] reclen  238  physical  254
    /// SAVGEMAL.DAT  v5  key 1  chains [246, 0] reclen  238  physical  254
    /// ```
    ///
    /// Independently corroborated by arithmetic: [`at::CHAIN`]'s own rule is
    /// that a file's last duplicate key chains at `physical - 8`, and every
    /// row above satisfies it from the **first** segment's number and none
    /// from the second. `WGSGEN2` is the only file here with *two* duplicate
    /// keys, and it is key 1 that reads 69 (= 77 - 8) while key 0 reads 61,
    /// the eight bytes before it.
    ///
    /// So this was never a `WGSGEN2` quirk. `WCCBANK2.DAT` -- every player's
    /// bank balance -- and `WCCITOW2.DAT` carry the same shape, and any insert
    /// into either would have written eight bytes over a slot marker the same
    /// way.
    #[test]
    fn a_segmented_duplicate_key_reads_its_chain_offset_from_its_first_segment() {
        let keys = parse(
            "WGSGEN2.DAT",
            &fcr(&[
                definition_with_chain(
                    flag::EXTENDED | flag::DUPLICATES | flag::ANOSEG | flag::MODIFIABLE,
                    2,
                    30,
                    0x0e,
                    61,
                ),
                definition_with_chain(
                    flag::EXTENDED | flag::DUPLICATES | flag::MODIFIABLE,
                    32,
                    25,
                    0x0e,
                    0,
                ),
                definition_with_chain(
                    flag::EXTENDED | flag::DUPLICATES | flag::MODIFIABLE,
                    32,
                    25,
                    0x0e,
                    69,
                ),
            ]),
            2,
            &[],
        )
        .expect("parses");

        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].segments.len(), 2, "def0 and def1 are one key");
        assert_eq!(
            keys[0].chain,
            Some(61),
            "the chain offset comes from the key's first definition, not its last"
        );
        assert_eq!(keys[1].chain, Some(69), "an unsegmented key is unaffected");
    }

    #[test]
    fn anoseg_joins_two_definitions_into_one_key() {
        // `WCCBANKS`: one key, thirty bytes of name and then four of number.
        // Counting definitions instead of keys would make this two keys and
        // every lookup by key 1 would be a lookup of something that is not a
        // key.
        let keys = parse(
            "WCCBANKS.DAT",
            &fcr(&[
                definition(flag::EXTENDED | flag::ANOSEG | flag::DUPLICATES, 0, 30, 0x0b),
                definition(flag::EXTENDED | flag::DUPLICATES, 30, 4, 0x01),
            ]),
            1,
            &[],
        )
        .expect("parses");

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].segments.len(), 2);
        assert_eq!(keys[0].length(), 34, "which is what clckln() computes");
        assert_eq!(keys[0].segments[1].kind, Kind::Signed);
    }

    /// I7: `Key::number` is the key's ordinal; `Key::definition` is where its
    /// first segment lives among the file's *definitions*. `WCCBANKS.DAT` and
    /// `WCCITOWN.DAT` both put their one multi-segment key last, which is the
    /// only reason `number` and `definition` happen to agree for every file
    /// MajorMUD ships. This puts the segmented key **first** instead --
    /// definitions 0 and 1 are key 0's two segments, definition 2 is key 1 --
    /// so `keys[1].definition` (2) has to disagree with `keys[1].number` (1)
    /// for the fix to be doing anything.
    #[test]
    fn a_keys_definition_is_where_its_first_segment_starts_even_after_a_segmented_key() {
        let keys = parse(
            "REORDERED.DAT",
            &fcr(&[
                definition(flag::EXTENDED | flag::ANOSEG, 0, 30, 0x0b),
                definition(flag::EXTENDED, 30, 4, 0x01),
                definition(flag::EXTENDED, 34, 2, 0x0e),
            ]),
            2,
            &[],
        )
        .expect("parses");

        assert_eq!(keys.len(), 2);
        assert_eq!((keys[0].number, keys[0].definition), (0, 0));
        assert_eq!(
            (keys[1].number, keys[1].definition),
            (1, 2),
            "key 1's own definition is index 2, not its key number 1"
        );
    }

    #[test]
    fn a_type_this_host_cannot_order_is_refused_by_name() {
        // A `date` key sorted as though it were text would be in the right
        // order for some pairs of records and not others.
        let e = parse("SOMETHING.DAT", &fcr(&[definition(flag::EXTENDED, 0, 4, 0x03)]), 1, &[])
            .expect_err("no ordering for a date");
        assert!(e.why.contains("date"), "{e}");
    }

    #[test]
    fn a_type_is_implied_when_the_extended_bit_is_clear() {
        let keys = parse("OLD.DAT", &fcr(&[definition(0, 0, 8, 0)]), 1, &[]).expect("parses");
        assert_eq!(keys[0].segments[0].kind, Kind::Text, "old-style ascii");

        let keys = parse("OLD.DAT", &fcr(&[definition(flag::OLD_BINARY, 0, 8, 0)]), 1, &[])
            .expect("parses");
        assert_eq!(keys[0].segments[0].kind, Kind::Unsigned, "old-style binary");
    }

    #[test]
    fn a_file_claiming_more_keys_than_it_describes_is_refused() {
        let e = parse("SHORT.DAT", &fcr(&[definition(flag::EXTENDED, 0, 30, 0x0b)]), 2, &[])
            .expect_err("the second definition is all zeros");
        assert!(e.why.contains("zero-length"), "{e}");
    }

    /// A key over one text segment, for the ordering tests.
    fn named(kind: Kind, length: u16) -> Key {
        Key {
            number: 0,
            definition: 0,
            segments: vec![Segment {
                offset: 0,
                length,
                kind,
                descending: false,
            }],
            duplicates: false,
            modifiable: true,
            chain: None,
                    acs: None,
                    null: None,
}
    }

    #[test]
    fn text_compares_up_to_the_terminator_and_not_past_it() {
        // Two names in a thirty-byte field, with different rubbish after the
        // NUL. A comparison over the whole field would order them by the
        // rubbish.
        let key = named(Kind::Text, 8);
        let a = b"Human\0\0\0";
        let b = b"Human\0zz";
        assert_eq!(key.compare(a, b), Ordering::Equal);
        assert_eq!(key.compare(b"Dwarf\0\0\0", a), Ordering::Less);
    }

    #[test]
    fn a_number_compares_as_a_number_and_not_as_its_bytes() {
        // 256 and 1, little-endian, are `00 01` and `01 00`. Bytewise, 256
        // sorts first; numerically it does not. Every `AutoInc` key in
        // MajorMUD's files is two or four bytes of exactly this shape.
        let key = named(Kind::Signed, 2);
        assert_eq!(key.compare(&[0, 1], &[1, 0]), Ordering::Greater);
        assert_eq!(key.compare(&[13, 0], &[1, 0]), Ordering::Greater);
    }

    /// The order genuine Pervasive Btrieve 6.15 puts float keys in, taken
    /// straight off the engine: seven values inserted, the key stepped, and
    /// this is what came back.
    ///
    /// `tools/btrieve-oracle/floatprobe.c`, and
    /// `docs/2026-08-17-float-key-oracle.md` for the transcript. A rig of
    /// only positive values would pass under a bytewise comparison and prove
    /// nothing, so every value here is one some wrong reading gets right.
    #[test]
    fn a_float_key_is_ordered_the_way_the_engine_orders_it() {
        let key = named(Kind::Float, 8);
        let engines_order: [f64; 7] = [
            -1e308,
            -1.0,
            -0.0,
            0.0,
            1.0,
            1e308,
            f64::NAN,
        ];
        for pair in engines_order.windows(2) {
            let (lower, higher) = (pair[0], pair[1]);
            assert_eq!(
                key.compare(&lower.to_le_bytes(), &higher.to_le_bytes()),
                Ordering::Less,
                "{lower} sorts before {higher} in the engine's own walk"
            );
        }
    }

    /// The two findings that make this `total_cmp` rather than `partial_cmp`.
    ///
    /// Both were measured, not reasoned about: `+0.0` was inserted before
    /// `-0.0` and the engine's walk returned them the other way round, which
    /// it could not do if it thought them equal; and NaN came back after
    /// `1e308` rather than being refused or dropped.
    #[test]
    fn negative_zero_sorts_below_positive_zero_and_nan_sorts_above_everything() {
        let key = named(Kind::Float, 8);

        assert_eq!(
            key.compare(&(-0.0f64).to_le_bytes(), &0.0f64.to_le_bytes()),
            Ordering::Less,
            "partial_cmp calls these equal; the engine does not"
        );
        assert_eq!(
            key.compare(&f64::NAN.to_le_bytes(), &1e308f64.to_le_bytes()),
            Ordering::Greater,
            "partial_cmp answers None here, and any default for it is invented"
        );
    }

    /// Four bytes is an `f32`, measured separately rather than assumed from
    /// the eight-byte case -- `MULTIACS.DAT`'s own segment is eight, so
    /// nothing in the corpus would have caught this being wrong.
    #[test]
    fn a_four_byte_float_segment_is_an_f32() {
        let key = named(Kind::Float, 4);
        assert_eq!(
            key.compare(&(-3.4e38f32).to_le_bytes(), &(-1.0f32).to_le_bytes()),
            Ordering::Less,
        );
        assert_eq!(
            key.compare(&(-0.0f32).to_le_bytes(), &0.0f32.to_le_bytes()),
            Ordering::Less,
        );

        // The same four bytes read as an f64 would be a different number
        // entirely, and this is what says they are not.
        assert_eq!(
            key.compare(&1.0f32.to_le_bytes(), &(-1.0f32).to_le_bytes()),
            Ordering::Greater,
        );
    }

    /// The engine's own order for a `bfloat` key, as raw bytes.
    ///
    /// These are the exact patterns `floatprobe insertraw` fed genuine 6.15
    /// and the exact order it walked them back in. Written as bytes rather
    /// than as numbers on purpose: naming them `-1.0` and so on would be
    /// asserting the encoding this test exists to pin.
    #[test]
    fn a_bfloat_key_is_ordered_the_way_the_engine_orders_it() {
        let key = named(Kind::Bfloat, 4);
        let engines_order: [[u8; 4]; 7] = [
            [0xff, 0xff, 0xff, 0xff], // -huge
            [0x00, 0x00, 0x80, 0x81], // -1.0
            [0xff, 0xff, 0xff, 0x7f], // -0.5
            [0x00, 0x00, 0x00, 0x01], // +tiny
            [0x00, 0x00, 0x00, 0x80], // +0.5
            [0x00, 0x00, 0x00, 0x81], // +1.0
            [0x00, 0x00, 0x00, 0x82], // +2.0
        ];
        for pair in engines_order.windows(2) {
            assert_eq!(
                key.compare(&pair[0], &pair[1]),
                Ordering::Less,
                "{:02x?} sorts before {:02x?} in the engine's own walk",
                pair[0],
                pair[1]
            );
        }
    }

    /// Eight bytes, and the case four could not show: zero sits between the
    /// negatives and the positives.
    #[test]
    fn a_bfloat_zero_sorts_between_the_negatives_and_the_positives() {
        let key = named(Kind::Bfloat, 8);
        let negative = [0, 0, 0, 0, 0, 0, 0x80, 0x81];
        let zero = [0u8; 8];
        let positive = [0, 0, 0, 0, 0, 0, 0, 0x01];

        assert_eq!(key.compare(&negative, &zero), Ordering::Less);
        assert_eq!(key.compare(&zero, &positive), Ordering::Less);
    }

    /// A `bfloat` is not an IEEE float, and the two disagree on these bytes.
    ///
    /// `00 00 80 41` is negative to Borland -- the sign is bit 7 of byte 2,
    /// which is set -- and `+16.0` to IEEE, which reads its sign from the top
    /// bit of byte 3, which is clear. Routing one type through the other's
    /// comparator is the silent misordering this pins against.
    #[test]
    fn a_bfloat_and_a_float_disagree_about_the_same_bytes() {
        let borland = named(Kind::Bfloat, 4);
        let ieee = named(Kind::Float, 4);
        let negative_to_borland = [0x00, 0x00, 0x80, 0x41];
        let zero = [0x00, 0x00, 0x00, 0x00];

        assert_eq!(borland.compare(&negative_to_borland, &zero), Ordering::Less);
        assert_eq!(
            ieee.compare(&negative_to_borland, &zero),
            Ordering::Greater,
            "IEEE reads these bytes as positive, which is why the types cannot share \
             a comparator"
        );
    }

    /// One key over two two-byte segments, and the four records the oracle
    /// walked through the genuine engine's own index.
    ///
    /// A single-segment key cannot tell these two bits apart -- both omit the
    /// same one record -- which is why the rig, and this test, use two.
    #[test]
    fn the_two_null_bits_omit_different_records() {
        let two_segments = |null| Key {
            number: 0,
            definition: 0,
            segments: vec![
                Segment { offset: 0, length: 2, kind: Kind::Text, descending: false },
                Segment { offset: 2, length: 2, kind: Kind::Text, descending: false },
            ],
            duplicates: false,
            modifiable: true,
            chain: None,
            acs: None,
            null,
        };

        let both = b"ABCD";      // neither segment null
        let first = b"\0\0CD";   // first segment null
        let second = b"AB\0\0";  // second segment null
        let neither = b"\0\0\0\0"; // both segments null

        let plain = two_segments(None);
        for record in [both, first, second, neither] {
            assert!(!plain.excluded(record), "a key with no null bit omits nothing");
        }

        // Measured: three of the four survive, and only the wholly-null one
        // is dropped.
        let all = two_segments(Some(Null::All(0)));
        assert!(!all.excluded(both));
        assert!(!all.excluded(first));
        assert!(!all.excluded(second));
        assert!(all.excluded(neither), "every segment null -- the only one dropped");

        // Measured: only the record with no null segment at all survives.
        let any = two_segments(Some(Null::Any(0)));
        assert!(!any.excluded(both), "the only one kept");
        assert!(any.excluded(first));
        assert!(any.excluded(second));
        assert!(any.excluded(neither));
    }

    /// The null value is the key definition\'s own byte, not a hardcoded zero.
    ///
    /// Measured by declaring `0x20` and watching the all-spaces record vanish
    /// from the engine\'s index while the all-zeroes record stayed in it.
    #[test]
    fn the_null_value_is_the_one_the_definition_declares() {
        let key = |null| Key {
            number: 0,
            definition: 0,
            segments: vec![Segment { offset: 0, length: 4, kind: Kind::Text, descending: false }],
            duplicates: false,
            modifiable: true,
            chain: None,
            acs: None,
            null,
        };

        let spaces = key(Some(Null::All(b' ')));
        assert!(spaces.excluded(b"    "), "all spaces is null when 0x20 is declared");
        assert!(!spaces.excluded(b"\0\0\0\0"), "and all zeroes is not");

        let zeroes = key(Some(Null::All(0)));
        assert!(zeroes.excluded(b"\0\0\0\0"));
        assert!(!zeroes.excluded(b"    "));
    }

    /// A key that repeats its duplicates in the index has no in-record chain,
    /// and must not claim one.
    ///
    /// Measured: the same file created twice, differing only in this bit, got
    /// `physical` 18 with it and 26 without -- eight bytes of `[prev][next]`
    /// that simply are not there -- and the definition's chain offset reads 0
    /// rather than a real offset. `Some(0)` would send the write path to the
    /// front of the record.
    #[test]
    fn a_repeating_duplicate_key_names_no_chain_at_all() {
        let definition = |attributes: u16| {
            let mut bytes = vec![0u8; WIDTH];
            bytes[at::ATTRIBUTES..at::ATTRIBUTES + 2]
                .copy_from_slice(&attributes.to_le_bytes());
            bytes[at::LENGTH..at::LENGTH + 2].copy_from_slice(&4u16.to_le_bytes());
            bytes[at::EXTENDED] = 0x0b;
            // A real chain offset, so `None` below cannot come from the bytes
            // happening to be zero.
            bytes[at::CHAIN..at::CHAIN + 2].copy_from_slice(&18u16.to_le_bytes());
            bytes
        };

        let plain = parse("D.DAT", &fcr(&[definition(flag::DUPLICATES | flag::EXTENDED)]), 1, &[])
            .expect("a plain duplicate key parses");
        assert_eq!(plain[0].chain, Some(18), "a chained duplicate key names its pair");

        let repeating = parse(
            "R.DAT",
            &fcr(&[definition(
                flag::DUPLICATES | flag::EXTENDED | flag::REPEATING_DUPLICATES,
            )]),
            1,
            &[],
        )
        .expect("a repeating duplicate key parses rather than being refused");
        assert_eq!(
            repeating[0].chain, None,
            "there is no in-record pair, whatever the definition's bytes say"
        );
        assert!(repeating[0].duplicates, "it still permits duplicates");
    }

    #[test]
    fn a_signed_key_reads_its_sign_from_its_own_width() {
        let key = named(Kind::Signed, 2);
        assert_eq!(key.compare(&[0xff, 0xff], &[1, 0]), Ordering::Less, "-1 < 1");

        // The same bytes as an unsigned key are 65,535 and sort the other way.
        let key = named(Kind::Unsigned, 2);
        assert_eq!(key.compare(&[0xff, 0xff], &[1, 0]), Ordering::Greater);
    }

    #[test]
    fn a_binary_key_wider_than_a_machine_integer_still_orders() {
        // `WCCTEXT`'s key is eighteen bytes of unsigned binary and `WCCMP001`'s
        // is eight. Neither fits the two-four-eight shape a width-by-width
        // reader would handle.
        let key = named(Kind::Unsigned, 18);
        let mut a = vec![0u8; 18];
        let mut b = vec![0u8; 18];
        a[0] = 1;
        b[1] = 1;
        assert_eq!(key.compare(&a, &b), Ordering::Less, "1 < 256");
    }

    #[test]
    fn a_descending_segment_sorts_backwards() {
        let mut key = named(Kind::Signed, 2);
        key.segments[0].descending = true;
        assert_eq!(key.compare(&[13, 0], &[1, 0]), Ordering::Less);
    }

    #[test]
    fn segments_are_compared_in_turn() {
        let key = Key {
            number: 0,
            definition: 0,
            segments: vec![
                Segment {
                    offset: 0,
                    length: 4,
                    kind: Kind::Text,
                    descending: false,
                },
                Segment {
                    offset: 4,
                    length: 2,
                    kind: Kind::Signed,
                    descending: false,
                },
            ],
            duplicates: true,
            modifiable: true,
            chain: Some(6),
                    acs: None,
                    null: None,
};
        assert_eq!(key.length(), 6);
        assert_eq!(key.extract(b"abc\0\x02\x00"), b"abc\0\x02\x00");

        // Same name, different number: the second segment decides, and decides
        // numerically.
        assert_eq!(key.compare(b"abc\0\x02\x00", b"abc\0\x0a\x00"), Ordering::Less);
        // Different name: the first segment decides and the second is not read.
        assert_eq!(key.compare(b"abc\0\x0a\x00", b"abd\0\x02\x00"), Ordering::Less);
    }

    #[test]
    fn a_key_value_the_module_supplies_is_laid_out_as_the_segments_are() {
        // The module hands over the segments concatenated, not a record. A
        // comparison that read the value at the *record's* offsets would read
        // the second segment out of the first one's bytes.
        let key = Key {
            number: 0,
            definition: 0,
            segments: vec![
                Segment {
                    offset: 10,
                    length: 4,
                    kind: Kind::Text,
                    descending: false,
                },
                Segment {
                    offset: 20,
                    length: 2,
                    kind: Kind::Signed,
                    descending: false,
                },
            ],
            duplicates: true,
            modifiable: true,
            chain: Some(6),
                    acs: None,
                    null: None,
};

        let mut record = vec![0u8; 32];
        record[10..14].copy_from_slice(b"abc\0");
        record[20..22].copy_from_slice(&7u16.to_le_bytes());

        assert_eq!(key.compare_value(&record, b"abc\0\x07\x00"), Ordering::Equal);
        assert_eq!(key.compare_value(&record, b"abc\0\x08\x00"), Ordering::Less);
        assert_eq!(key.compare_value(&record, b"abb\0\x07\x00"), Ordering::Greater);
    }

    fn case_fold_acs() -> Arc<Acs> {
        let mut table = [0u8; 256];
        for (i, slot) in table.iter_mut().enumerate() {
            *slot = i as u8;
        }
        for c in b'a'..=b'z' {
            table[c as usize] = c - 32;
        }
        Arc::new(Acs {
            name: *b"GALCAPS ",
            table,
        })
    }

    fn text_key(acs: Option<Arc<Acs>>) -> Key {
        Key {
            number: 0,
            definition: 0,
            segments: vec![Segment {
                offset: 0,
                length: 8,
                kind: Kind::Text,
                descending: false,
            }],
            duplicates: false,
            modifiable: true,
            chain: None,
            acs,
            null: None,
        }
    }

    /// The gap this closes: a case-mismatched lookup that genuine Btrieve
    /// satisfies answers "not found" without an ACS.
    #[test]
    fn an_alternate_sequence_folds_case_for_an_equality_lookup() {
        let plain = text_key(None);
        let folded = text_key(Some(case_fold_acs()));
        assert_ne!(
            plain.compare_value(b"smith\0\0\0", b"SMITH\0\0\0"),
            Ordering::Equal,
            "without an ACS these are different keys"
        );
        assert_eq!(
            folded.compare_value(b"smith\0\0\0", b"SMITH\0\0\0"),
            Ordering::Equal,
            "with a case-folding ACS they are one key"
        );
    }

    /// The worse failure the design names: an ordered walk returns a different
    /// order forever, silently. Raw bytes cluster all uppercase before all
    /// lowercase; the folded order interleaves them.
    #[test]
    fn an_alternate_sequence_changes_the_order_of_a_walk() {
        let plain = text_key(None);
        let folded = text_key(Some(case_fold_acs()));
        // 'B' (0x42) sorts before 'a' (0x61) by raw byte, after it when folded.
        assert_eq!(plain.compare(b"Bravo\0\0\0", b"alpha\0\0\0"), Ordering::Less);
        assert_eq!(
            folded.compare(b"Bravo\0\0\0", b"alpha\0\0\0"),
            Ordering::Greater
        );
    }

    /// The table applies only to text. A folded byte inside an integer key
    /// would corrupt the number.
    #[test]
    fn an_alternate_sequence_does_not_touch_a_numeric_key() {
        let mut key = text_key(Some(case_fold_acs()));
        key.segments[0].kind = Kind::Signed;
        key.segments[0].length = 2;
        // 0x61 'a' would fold to 0x41 'A' if this were text.
        assert_eq!(key.compare(b"\x61\x00", b"\x41\x00"), Ordering::Greater);
    }

    /// `extract` hands a module its raw key buffer. An ACS is a
    /// comparison-time transform; folding here would corrupt what the module
    /// reads back.
    #[test]
    fn extract_returns_raw_bytes_even_with_an_alternate_sequence() {
        let key = text_key(Some(case_fold_acs()));
        assert_eq!(&key.extract(b"smith\0\0\0")[..5], b"smith");
    }

    #[test]
    fn a_descending_alternate_key_still_reverses_after_folding() {
        let mut key = text_key(Some(case_fold_acs()));
        key.segments[0].descending = true;
        assert_eq!(key.compare(b"Bravo\0\0\0", b"alpha\0\0\0"), Ordering::Less);
    }

    /// A control record declaring one text key that collates through an
    /// alternate sequence.
    fn acs_fcr() -> Vec<u8> {
        let mut fcr = vec![0u8; 512];
        let key = definition(flag::ALT_COLLATING, 0, 8, 0);
        fcr[BASE..BASE + WIDTH].copy_from_slice(&key);
        fcr
    }

    /// A control record whose keys each collate through the table on the logical
    /// page named, one key per entry.
    fn acs_fcr_naming(pages: &[u32]) -> Vec<u8> {
        let mut fcr = vec![0u8; 512];
        for (slot, &page) in pages.iter().enumerate() {
            let at = BASE + slot * WIDTH;
            fcr[at..at + WIDTH].copy_from_slice(&definition(flag::ALT_COLLATING, 0, 8, 0));
            fcr[at + crate::acs::PAGE_LOW_IN_KEY] = page as u8;
            fcr[at + crate::acs::PAGE_MID_IN_KEY] = (page >> 8) as u8;
            fcr[at + crate::acs::PAGE_HIGH_IN_KEY] = (page >> 16) as u8;
        }
        fcr
    }

    fn table_at(page: u32, acs: Arc<Acs>) -> Table {
        Table { page, acs }
    }

    /// With no table located, the refusal must stand. Lifting it
    /// unconditionally would collate the file by raw bytes and return a
    /// different order forever, silently.
    #[test]
    fn parse_refuses_an_alternate_key_when_no_table_was_supplied() {
        let e = parse("NOTABLE.DAT", &acs_fcr(), 1, &[]).expect_err("no table to bind");
        assert!(e.why.contains("alternate collating"), "{}", e.why);
    }

    /// A v5 file leaves the per-key page unset and carries exactly one table,
    /// which `acs_tables` registers under page zero -- so the same matching rule
    /// binds it without a version special case.
    #[test]
    fn parse_binds_a_v5_files_unnumbered_table() {
        let table = case_fold_acs();
        let keys = parse("V5.DAT", &acs_fcr(), 1, &[table_at(0, Arc::clone(&table))])
            .expect("page zero is what a v5 key names");
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0].acs.as_deref(),
            Some(&*table),
            "the table must reach the key, not merely be read"
        );
    }

    /// **The gap this closes.** Two tables, two keys, and each key gets the one
    /// it names by logical page -- `MULTIACS.DAT`'s exact shape, and the only
    /// file in the corpus that was refused after everything else was fixed.
    #[test]
    fn parse_binds_each_key_to_the_table_on_the_page_it_names() {
        let upper = case_fold_acs();
        let mut lower_table = [0u8; 256];
        for (i, slot) in lower_table.iter_mut().enumerate() {
            *slot = i as u8;
        }
        for c in b'A'..=b'Z' {
            lower_table[c as usize] = c + 32;
        }
        let lower = Arc::new(Acs {
            name: *b"LOWER\0\0\0",
            table: lower_table,
        });

        let keys = parse(
            "MULTIACS.DAT",
            &acs_fcr_naming(&[1, 2]),
            2,
            &[table_at(1, Arc::clone(&upper)), table_at(2, Arc::clone(&lower))],
        )
        .expect("each key names its own table");

        assert_eq!(keys[0].acs.as_deref(), Some(&*upper), "key 0 named page 1");
        assert_eq!(keys[1].acs.as_deref(), Some(&*lower), "key 1 named page 2");
        // And the binding is by page, not by position: swapping which page each
        // table sits on must swap which key gets it.
        let swapped = parse(
            "SWAPPED.DAT",
            &acs_fcr_naming(&[1, 2]),
            2,
            &[table_at(2, Arc::clone(&upper)), table_at(1, Arc::clone(&lower))],
        )
        .expect("still unambiguous");
        assert_eq!(swapped[0].acs.as_deref(), Some(&*lower));
        assert_eq!(swapped[1].acs.as_deref(), Some(&*upper));
    }

    /// A key naming a page no table was found on is refused rather than handed
    /// whichever table is to hand -- the wrong sequence would order that key
    /// wrongly, silently, for as long as the file lives.
    #[test]
    fn parse_refuses_a_key_naming_a_page_that_holds_no_table() {
        let e = parse(
            "ELSEWHERE.DAT",
            &acs_fcr_naming(&[7]),
            1,
            &[table_at(1, case_fold_acs())],
        )
        .expect_err("no table on page 7");
        assert!(e.why.contains("page 7"), "{}", e.why);
        assert!(e.why.contains('1'), "it should say where tables were found: {}", e.why);
    }

    /// A key that does *not* declare a sequence must not be folded through a
    /// table the file happens to carry -- that would reorder an index genuine
    /// Btrieve leaves in raw byte order.
    #[test]
    fn parse_leaves_an_unflagged_key_unbound_even_when_a_table_exists() {
        let mut fcr = vec![0u8; 512];
        fcr[BASE..BASE + WIDTH].copy_from_slice(&definition(0, 0, 8, 0));
        let keys =
            parse("PLAIN.DAT", &fcr, 1, &[table_at(0, case_fold_acs())]).expect("a plain text key");
        assert!(
            keys[0].acs.is_none(),
            "an unflagged key collates by raw bytes even when a table is present"
        );
    }
}
