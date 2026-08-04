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

use super::BtvError;

/// Where the key definitions start in the file control record.
const BASE: usize = 0x110;

/// Bytes of one key definition.
const WIDTH: usize = 0x1e;

/// `BTVSTF.H:13` -- the most segments a file may have.
pub const SEGMAX: usize = 24;

/// Where each field of a key definition sits.
mod at {
    /// Attribute flags.
    pub const ATTRIBUTES: usize = 0x08;
    /// Offset of this segment within the record.
    pub const OFFSET: usize = 0x14;
    /// Length of this segment, in bytes.
    pub const LENGTH: usize = 0x16;
    /// The extended data type, when the attributes say to use it.
    pub const EXTENDED: usize = 0x1c;
}

/// The attribute bits this reader understands.
mod flag {
    /// More than one record may carry this key value.
    pub const DUPLICATES: u16 = 1 << 0;
    /// The key is compared as a plain unsigned binary field.
    pub const OLD_BINARY: u16 = 1 << 2;
    /// **Another segment of the same key follows this one.** `BTVSTF.H:59`
    /// names this one: `#define ANOSEG 0x10`.
    pub const ANOSEG: u16 = 1 << 4;
    /// The segment sorts backwards.
    pub const DESCENDING: u16 = 1 << 6;
    /// The type is in [`at::EXTENDED`] rather than implied by the flags.
    pub const EXTENDED: u16 = 1 << 8;
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
const UNSUPPORTED: [(u16, &str); 4] = [
    (1 << 3, "null-all-segments"),
    (1 << 9, "null-any-segment"),
    (1 << 5, "a numbered alternate collating sequence"),
    (1 << 7, "repeating duplicates"),
];

/// How a key segment's bytes are to be compared.
///
/// Btrieve defines twenty-odd data types and MajorMUD's eighteen files use
/// four of them: `Zstring` (0x0b), `Integer` (0x01), `UnsignedBinary` (0x0e)
/// and `AutoInc` (0x0f). They collapse to three orderings, and **anything else
/// is refused rather than guessed at** -- a `Date`, a `Decimal` or a `Bfloat`
/// sorted as though it were bytes would put records in an order that is wrong
/// only sometimes, which is the worst way for it to be wrong.
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
}

impl Kind {
    /// The ordering a Btrieve data type implies, or `None` for one this host
    /// has no ordering for.
    fn of(code: u8) -> Option<Self> {
        match code {
            0x00 | 0x0a | 0x0b | 0x20 => Some(Self::Text),
            0x01 | 0x0f => Some(Self::Signed),
            0x0d | 0x0e | 0x21 => Some(Self::Unsigned),
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
    fn compare(&self, a: &[u8], b: &[u8]) -> Ordering {
        self.order(self.of(a), self.of(b))
    }

    /// Compare two of this segment's fields, honouring its direction.
    fn order(&self, a: &[u8], b: &[u8]) -> Ordering {
        let order = match self.kind {
            Kind::Text => text(a).cmp(text(b)),
            Kind::Signed => signed(a, b),
            Kind::Unsigned => unsigned(a, b),
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

/// Byte `i` of a field, or zero past its end.
fn byte(field: &[u8], i: usize) -> u8 {
    field.get(i).copied().unwrap_or(0)
}

/// One key: the segments to compare, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub number: u16,
    pub segments: Vec<Segment>,
    /// Whether two records may carry the same value.
    pub duplicates: bool,
}

impl Key {
    /// How many bytes the key is, all segments together.
    ///
    /// This is what `clckln()` puts in `bb->keylns[n]`, and what `qrybtv` and
    /// the acquire family copy out of the module's key buffer.
    pub fn length(&self) -> u16 {
        self.segments.iter().map(|s| s.length).sum()
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
            match segment.compare(a, b) {
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
            match segment.order(segment.of(record), laid_out.of(value)) {
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
/// # Errors
///
/// If a definition runs past the end of the file control record, uses a data
/// type this host has no ordering for, or leaves a key with no segments.
pub fn parse(name: &str, fcr: &[u8], count: u16) -> Result<Vec<Key>, BtvError> {
    let fail = |why: String| BtvError {
        file: name.to_owned(),
        why,
    };

    let mut keys: Vec<Key> = Vec::with_capacity(usize::from(count));
    let mut segments = Vec::new();
    let mut definitions = 0usize;

    while keys.len() < usize::from(count) {
        if definitions >= SEGMAX {
            return Err(fail(format!(
                "more than {SEGMAX} key segments, which is more than a file has"
            )));
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
        for (bit, what) in UNSUPPORTED {
            if attributes & bit != 0 {
                return Err(fail(format!(
                    "key {} is declared with {what}, which changes what its index \
                     holds and is not reproduced by sorting the records",
                    keys.len()
                )));
            }
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
            keys.push(Key {
                number: keys.len() as u16,
                segments: std::mem::take(&mut segments),
                duplicates: attributes & flag::DUPLICATES != 0,
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
        )
        .expect("parses");

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].segments.len(), 2);
        assert_eq!(keys[0].length(), 34, "which is what clckln() computes");
        assert_eq!(keys[0].segments[1].kind, Kind::Signed);
    }

    #[test]
    fn a_type_this_host_cannot_order_is_refused_by_name() {
        // A `date` key sorted as though it were text would be in the right
        // order for some pairs of records and not others.
        let e = parse("SOMETHING.DAT", &fcr(&[definition(flag::EXTENDED, 0, 4, 0x03)]), 1)
            .expect_err("no ordering for a date");
        assert!(e.why.contains("date"), "{e}");
    }

    #[test]
    fn a_type_is_implied_when_the_extended_bit_is_clear() {
        let keys = parse("OLD.DAT", &fcr(&[definition(0, 0, 8, 0)]), 1).expect("parses");
        assert_eq!(keys[0].segments[0].kind, Kind::Text, "old-style ascii");

        let keys = parse("OLD.DAT", &fcr(&[definition(flag::OLD_BINARY, 0, 8, 0)]), 1)
            .expect("parses");
        assert_eq!(keys[0].segments[0].kind, Kind::Unsigned, "old-style binary");
    }

    #[test]
    fn a_file_claiming_more_keys_than_it_describes_is_refused() {
        let e = parse("SHORT.DAT", &fcr(&[definition(flag::EXTENDED, 0, 30, 0x0b)]), 2)
            .expect_err("the second definition is all zeros");
        assert!(e.why.contains("zero-length"), "{e}");
    }

    /// A key over one text segment, for the ordering tests.
    fn named(kind: Kind, length: u16) -> Key {
        Key {
            number: 0,
            segments: vec![Segment {
                offset: 0,
                length,
                kind,
                descending: false,
            }],
            duplicates: false,
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
        };

        let mut record = vec![0u8; 32];
        record[10..14].copy_from_slice(b"abc\0");
        record[20..22].copy_from_slice(&7u16.to_le_bytes());

        assert_eq!(key.compare_value(&record, b"abc\0\x07\x00"), Ordering::Equal);
        assert_eq!(key.compare_value(&record, b"abc\0\x08\x00"), Ordering::Less);
        assert_eq!(key.compare_value(&record, b"abb\0\x07\x00"), Ordering::Greater);
    }
}
