//! Model to bytes, with every byte accounted for.
//!
//! # Why emit does not write into a zeroed buffer
//!
//! Emitting into `vec![0; len]` lets an undescribed range emit zeroes, which
//! is a plausible wrong answer -- it would accidentally match any sparse file
//! and quietly satisfy the criterion this crate exists to enforce. A canvas
//! has no default byte: a byte nobody wrote is a reported fault.
//!
//! # Why both endianness conventions live here
//!
//! The format stores 4-byte page numbers, record counts and record positions
//! as two little-endian halves with the high half first, while ordinary u16s
//! are plain little-endian. Reading a long as a plain LE u32 produces a
//! plausible wrong number with no error, and has done so three times in this
//! project's history -- most recently in a measurement script that inflated a
//! distribution count from 18 to 37 before a plausibility check caught it.
//! Nothing outside this module converts bytes to integers.
//!
//! # Why coverage is a bitmap and provenance is a placement list
//!
//! The largest corpus file is 55,734,272 bytes. An owner-per-byte side table
//! over that would be hundreds of megabytes; a one-bit-per-byte coverage
//! bitmap is 6.6 MB, and provenance costs one placement record per `put`
//! call (sorted once in [`Canvas::finish`], then binary-searched by
//! [`Emitted::owner_of`]) rather than one owner per byte.

use std::fmt;

/// Who wrote a range of bytes, for fault messages and provenance.
///
/// Mirrors [`crate::format::Field`]'s `field` + `index` pair deliberately, so
/// a later task can render an owner's name the same way a field's is
/// rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owner {
    /// Which structure this byte belongs to -- `"fcr"`, `"key_descriptor"`,
    /// a record's structure, and so on.
    pub structure: &'static str,
    /// The field within that structure, in the vendor's vocabulary where one
    /// exists.
    pub field: &'static str,
    /// Which repetition this is, for a field that repeats. `None` for a
    /// field that occurs once.
    pub index: Option<usize>,
}

impl Owner {
    /// How this owner is named in a message. A repeated field says which
    /// repetition, so `key_descriptor[3]` cannot be mistaken for
    /// `key_descriptor[0]`.
    #[must_use]
    pub fn label(&self) -> String {
        match self.index {
            Some(index) => format!("{}.{}[{index}]", self.structure, self.field),
            None => format!("{}.{}", self.structure, self.field),
        }
    }
}

impl fmt::Display for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// A canvas operation that could not be satisfied.
#[derive(Debug)]
pub struct Fault(String);

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Fault {}

/// A byte buffer being assembled, with per-byte coverage tracked so that an
/// unwritten byte is a fault rather than a silent zero, and a doubly-written
/// byte is a fault rather than a silent overwrite.
pub struct Canvas {
    bytes: Vec<u8>,
    /// One bit per byte of `bytes`: set once that byte has been written.
    written: Vec<u64>,
    /// One entry per `put` call: `(start, end, owner)`, `end` exclusive.
    /// Unsorted until [`Canvas::finish`].
    placements: Vec<(usize, usize, Owner)>,
}

impl Canvas {
    /// A canvas `len` bytes long, entirely unwritten.
    #[must_use]
    pub fn new(len: usize) -> Self {
        Self {
            bytes: vec![0u8; len],
            written: vec![0u64; len.div_ceil(64)],
            placements: Vec::new(),
        }
    }

    fn is_written(&self, at: usize) -> bool {
        self.written[at / 64] & (1 << (at % 64)) != 0
    }

    fn mark_written(&mut self, at: usize) {
        self.written[at / 64] |= 1 << (at % 64);
    }

    /// Owner of an already-written byte, for a collision message. Panics if
    /// `at` is not actually covered by a recorded placement, which would
    /// mean the bitmap and the placement list have drifted apart.
    fn owner_covering(&self, at: usize) -> &Owner {
        self.placements
            .iter()
            .find(|(start, end, _)| *start <= at && at < *end)
            .map(|(_, _, owner)| owner)
            .unwrap_or_else(|| {
                panic!(
                    "byte {at} is marked written but no placement covers it -- \
                     the coverage bitmap and the placement list have drifted apart"
                )
            })
    }

    /// Write `src` at `at`, attributing it to `owner`.
    ///
    /// # Errors
    ///
    /// If the write runs past the end of the canvas, or any byte in the
    /// range has already been written by an earlier `put`.
    pub fn put(&mut self, at: usize, src: &[u8], owner: Owner) -> Result<(), Fault> {
        let end = at.checked_add(src.len()).ok_or_else(|| {
            Fault(format!(
                "{} at {at}, {} bytes: offset overflows, which is past the end \
                 of a {}-byte canvas",
                owner.label(),
                src.len(),
                self.bytes.len()
            ))
        })?;
        if end > self.bytes.len() {
            return Err(Fault(format!(
                "{} at {at}..{end}: runs past the end of a {}-byte canvas",
                owner.label(),
                self.bytes.len()
            )));
        }
        for i in at..end {
            if self.is_written(i) {
                let existing = self.owner_covering(i);
                return Err(Fault(format!(
                    "byte {i} already belongs to {existing} -- {} claims it too",
                    owner.label()
                )));
            }
        }
        self.bytes[at..end].copy_from_slice(src);
        for i in at..end {
            self.mark_written(i);
        }
        self.placements.push((at, end, owner));
        Ok(())
    }

    /// Write a plain little-endian `u16`.
    ///
    /// # Errors
    ///
    /// See [`Canvas::put`].
    pub fn put_u16(&mut self, at: usize, v: u16, owner: Owner) -> Result<(), Fault> {
        self.put(at, &v.to_le_bytes(), owner)
    }

    /// Write a 4-byte "long": two little-endian halves, high half first.
    /// This is not a plain little-endian `u32` -- see the module
    /// documentation for why that distinction is load-bearing.
    ///
    /// # Errors
    ///
    /// See [`Canvas::put`].
    pub fn put_long(&mut self, at: usize, v: u32, owner: Owner) -> Result<(), Fault> {
        let high = (v >> 16) as u16;
        let low = v as u16;
        let mut bytes = [0u8; 4];
        bytes[0..2].copy_from_slice(&high.to_le_bytes());
        bytes[2..4].copy_from_slice(&low.to_le_bytes());
        self.put(at, &bytes, owner)
    }

    /// Finish the canvas: every byte must have been written exactly once.
    ///
    /// # Errors
    ///
    /// If any byte was never written, naming the first contiguous run of
    /// unwritten bytes.
    pub fn finish(self) -> Result<Emitted, Fault> {
        let len = self.bytes.len();
        let mut i = 0;
        while i < len {
            if !self.is_written(i) {
                let start = i;
                while i < len && !self.is_written(i) {
                    i += 1;
                }
                return Err(Fault(format!(
                    "bytes {start}..{i} of {len} were never written -- no \
                     field describes them"
                )));
            }
            i += 1;
        }
        let mut placements = self.placements;
        placements.sort_unstable_by_key(|(start, _, _)| *start);
        Ok(Emitted { bytes: self.bytes, placements })
    }
}

/// A finished, fully-accounted-for byte buffer, plus who wrote each byte.
#[derive(Debug)]
pub struct Emitted {
    bytes: Vec<u8>,
    /// Sorted by `start`, non-overlapping -- [`Canvas::finish`] guarantees
    /// both.
    placements: Vec<(usize, usize, Owner)>,
}

impl Emitted {
    /// The finished bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Which owner wrote the byte at `at`, or `None` if `at` is outside the
    /// buffer.
    #[must_use]
    pub fn owner_of(&self, at: usize) -> Option<Owner> {
        self.placements
            .binary_search_by(|(start, end, _)| {
                if at < *start {
                    std::cmp::Ordering::Greater
                } else if at >= *end {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .ok()
            .map(|idx| self.placements[idx].2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(field: &'static str) -> Owner {
        Owner { structure: "sample", field, index: None }
    }

    /// The whole point: a byte nobody wrote is a fault, not a zero.
    #[test]
    fn an_unwritten_byte_is_a_fault_that_names_the_range() {
        let mut canvas = Canvas::new(8);
        canvas.put(0, &[1, 2, 3, 4], owner("lead")).expect("in range");
        let fault = canvas.finish().expect_err("four bytes are unwritten");
        let said = fault.to_string();
        assert!(said.contains("4..8"), "the fault names the range: {said}");
    }

    /// Two fields claiming one byte means one of them is wrong and nothing
    /// says which -- so the write is refused rather than silently resolved.
    #[test]
    fn writing_a_byte_twice_is_refused_and_names_both_owners() {
        let mut canvas = Canvas::new(8);
        canvas.put(0, &[1, 2, 3, 4], owner("lead")).expect("in range");
        let fault = canvas
            .put(3, &[9, 9], owner("version"))
            .expect_err("byte 3 already belongs to lead");
        let said = fault.to_string();
        assert!(said.contains("lead"), "names the existing owner: {said}");
        assert!(said.contains("version"), "and the incoming one: {said}");
    }

    /// The two conventions live here and nowhere else. A "long" is two
    /// little-endian halves, high half first -- reading one as a plain LE
    /// u32 gives a plausible wrong number, which has cost this project three
    /// separate defects.
    #[test]
    fn a_long_is_two_little_endian_halves_high_half_first() {
        let mut canvas = Canvas::new(4);
        canvas.put_long(0, 2, owner("highest")).expect("in range");
        let emitted = canvas.finish().expect("every byte written");
        assert_eq!(
            emitted.bytes(),
            &[0x00, 0x00, 0x02, 0x00],
            "USRACC.DAT carries exactly these bytes at 0x1e for a 3-page file"
        );
    }

    /// Plain u16s are ordinary little-endian, and must not be confused with
    /// the halves of a long.
    #[test]
    fn a_u16_is_plain_little_endian() {
        let mut canvas = Canvas::new(2);
        canvas.put_u16(0, 0x0200, owner("page_size")).expect("in range");
        let emitted = canvas.finish().expect("every byte written");
        assert_eq!(emitted.bytes(), &[0x00, 0x02]);
    }

    /// A write past the end is a fault, not a resize.
    #[test]
    fn writing_past_the_end_is_a_fault() {
        let mut canvas = Canvas::new(4);
        let fault = canvas.put(2, &[1, 2, 3], owner("tail")).expect_err("runs past 4");
        assert!(fault.to_string().contains("past the end"));
    }

    /// The provenance is what lets the round trip say which field owns a
    /// mismatched byte instead of announcing that two buffers differ.
    #[test]
    fn the_emitted_bytes_remember_who_wrote_each_one() {
        let mut canvas = Canvas::new(4);
        canvas.put(0, &[1, 2], owner("lead")).expect("in range");
        canvas.put(2, &[3, 4], owner("version")).expect("in range");
        let emitted = canvas.finish().expect("every byte written");
        assert_eq!(emitted.owner_of(0).map(|o| o.field), Some("lead"));
        assert_eq!(emitted.owner_of(3).map(|o| o.field), Some("version"));
        assert_eq!(emitted.owner_of(4), None, "past the end nobody owns");
    }

    /// The coverage bitmap is one `u64` per 64 bytes. Every other test in
    /// this module fits inside 8 bytes, so `at / 64` is always `0` and the
    /// word-selection arithmetic is never actually exercised -- a bug that
    /// only breaks word 1 or later would sail through them. 200 is
    /// deliberately not a multiple of 64: it needs four words, and its last
    /// word is only partly occupied (bytes 192..200).
    #[test]
    fn a_write_across_a_word_boundary_reads_back_correctly() {
        let mut canvas = Canvas::new(200);
        canvas.put(0, &[0u8; 60], owner("head")).expect("in range");
        // Bytes 60..70 straddle the boundary between word 0 (bits 0..64)
        // and word 1 (bits 64..128).
        let crossing: Vec<u8> = (60..70).collect();
        canvas.put(60, &crossing, owner("cross")).expect("in range");
        canvas.put(70, &[0u8; 130], owner("tail")).expect("in range");
        let emitted = canvas.finish().expect("all 200 bytes written");
        assert_eq!(&emitted.bytes()[60..70], crossing.as_slice());
        assert_eq!(
            emitted.owner_of(64).map(|o| o.field),
            Some("cross"),
            "byte 64 is the first bit of word 1, and still belongs to the field that wrote it"
        );
    }

    /// An unwritten byte living in word 1 or later (not word 0, which every
    /// other test in this file exercises) must still be found and named.
    #[test]
    fn an_unwritten_byte_in_a_later_word_is_a_fault_that_names_its_range() {
        let mut canvas = Canvas::new(200);
        canvas.put(0, &[0u8; 100], owner("head")).expect("in range");
        // Byte 100 (word 100 / 64 == 1) is deliberately skipped.
        canvas.put(101, &[0u8; 99], owner("tail")).expect("in range");
        let fault = canvas.finish().expect_err("byte 100 was never written");
        let said = fault.to_string();
        assert!(said.contains("100..101"), "names exactly the one missing byte, in word 1: {said}");
    }

    /// The last word of a 200-byte canvas covers bits 192..256, but the
    /// canvas itself ends at byte 200. If the missing-range scan walked to
    /// the end of the word instead of the end of the canvas, leaving only
    /// byte 199 unwritten would be misreported as `199..256` (or panic
    /// indexing bytes that do not exist). It must report exactly `199..200`.
    #[test]
    fn the_last_byte_of_a_non_word_aligned_canvas_is_reported_exactly() {
        let mut canvas = Canvas::new(200);
        canvas.put(0, &[0u8; 199], owner("body")).expect("in range");
        // Byte 199, the canvas's last byte, is deliberately left unwritten.
        let fault = canvas.finish().expect_err("byte 199 was never written");
        let said = fault.to_string();
        assert!(
            said.contains("199..200"),
            "names exactly the last byte, not the word it happens to live in: {said}"
        );
    }
}
