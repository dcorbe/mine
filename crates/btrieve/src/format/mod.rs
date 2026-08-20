//! The on-disk format, described as data rather than as parsing code.
//!
//! A [`Layout`] is a list of named byte ranges, each carrying the citation
//! that establishes it -- a decompile line, an oracle measurement, or a corpus
//! observation. Nothing here does I/O and nothing here parses; `read` and
//! `emit` both work from these descriptions, which is what keeps them from
//! drifting apart.
//!
//! # Why the tiling invariant exists
//!
//! The crate this replaces could read a file it understood only in part,
//! because nothing ever asked it to produce the bytes back. [`Layout`] closes
//! that: a structure's fields must account for every byte of it, so a range
//! nobody has described is a reported fault instead of a silent omission.

pub mod generation;

/// One described range of bytes.
pub struct Field {
    /// What this range is, in the vendor's vocabulary where one exists.
    pub name: &'static str,
    /// Byte offset from the start of the structure.
    pub at: usize,
    /// Length in bytes.
    pub len: usize,
    /// What establishes this -- a decompile line, a document, a measurement.
    /// A field nobody can cite is visible as such, which is the point.
    pub cite: &'static str,
}

/// A structure, described completely.
pub struct Layout {
    /// What this describes, for messages.
    pub what: &'static str,
    /// The structure's total length in bytes.
    pub len: usize,
    /// Its fields, which must tile `len` exactly. Order is not significant;
    /// [`Layout::tiling_fault`] sorts.
    pub fields: &'static [Field],
}

impl Layout {
    /// `None` when the fields cover every byte of `len` exactly once,
    /// otherwise the first fault, named.
    ///
    /// Checked as a separate assertion from the round trip, deliberately: a
    /// layout can tile and still be wrong, but a layout that does not tile is
    /// wrong whether or not a corpus file happens to catch it.
    #[must_use]
    pub fn tiling_fault(&self) -> Option<String> {
        let mut ranges: Vec<(usize, usize, &'static str)> =
            self.fields.iter().map(|f| (f.at, f.len, f.name)).collect();
        ranges.sort_unstable();

        let mut next = 0usize;
        for (at, len, name) in ranges {
            let end = match at.checked_add(len) {
                Some(end) => end,
                None => {
                    return Some(format!(
                        "{}: field {name} at {at} with length {len} overflows",
                        self.what
                    ));
                }
            };
            if at < next {
                return Some(format!(
                    "{}: field {name} starts at {at}, overlapping the range \
                     already described up to {next}",
                    self.what
                ));
            }
            if at > next {
                return Some(format!(
                    "{}: bytes {next}..{at} are described by no field, and an \
                     undescribed range is a fault rather than a blob to \
                     preserve",
                    self.what
                ));
            }
            if end > self.len {
                return Some(format!(
                    "{}: field {name} ends at {end}, past the end of a \
                     {}-byte structure",
                    self.what, self.len
                ));
            }
            next = end;
        }

        if next != self.len {
            return Some(format!(
                "{}: bytes {next}..{} are described by no field, and an \
                 undescribed range is a fault rather than a blob to preserve",
                self.what, self.len
            ));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A layout whose fields cover every byte exactly once is sound.
    #[test]
    fn a_complete_layout_has_no_tiling_fault() {
        static FIELDS: &[Field] = &[
            Field { name: "lead", at: 0, len: 4, cite: "test" },
            Field { name: "rest", at: 4, len: 4, cite: "test" },
        ];
        static LAYOUT: Layout = Layout { what: "sample", len: 8, fields: FIELDS };
        assert_eq!(LAYOUT.tiling_fault(), None);
    }

    /// The whole point: an undescribed range is a fault, not a preserved blob.
    #[test]
    fn a_gap_is_a_fault_and_the_message_names_the_range() {
        static FIELDS: &[Field] = &[
            Field { name: "lead", at: 0, len: 4, cite: "test" },
            Field { name: "rest", at: 6, len: 2, cite: "test" },
        ];
        static LAYOUT: Layout = Layout { what: "sample", len: 8, fields: FIELDS };
        let fault = LAYOUT.tiling_fault().expect("a gap is a fault");
        assert!(fault.contains("4..6"), "the message names the gap: {fault}");
        assert!(fault.contains("sample"), "and the structure: {fault}");
    }

    /// Two fields claiming one byte is equally a fault -- it means one of them
    /// is wrong and nothing says which.
    #[test]
    fn an_overlap_is_a_fault() {
        static FIELDS: &[Field] = &[
            Field { name: "lead", at: 0, len: 5, cite: "test" },
            Field { name: "rest", at: 4, len: 4, cite: "test" },
        ];
        static LAYOUT: Layout = Layout { what: "sample", len: 8, fields: FIELDS };
        let fault = LAYOUT.tiling_fault().expect("an overlap is a fault");
        assert!(fault.contains("overlap"), "the message says so: {fault}");
    }

    /// A field running past the end is a fault even if everything tiles below
    /// it -- the structure's length is part of the description.
    #[test]
    fn a_field_past_the_end_is_a_fault() {
        static FIELDS: &[Field] = &[
            Field { name: "lead", at: 0, len: 4, cite: "test" },
            Field { name: "rest", at: 4, len: 8, cite: "test" },
        ];
        static LAYOUT: Layout = Layout { what: "sample", len: 8, fields: FIELDS };
        let fault = LAYOUT.tiling_fault().expect("running past the end is a fault");
        assert!(fault.contains("past the end"), "the message says so: {fault}");
    }

    /// Fields that tile everything up to some point short of `len`, and then
    /// stop, are equally a fault -- the trailing bytes are undescribed too.
    #[test]
    fn a_layout_that_stops_short_of_len_is_a_fault() {
        static FIELDS: &[Field] = &[Field { name: "lead", at: 0, len: 4, cite: "test" }];
        static LAYOUT: Layout = Layout { what: "sample", len: 8, fields: FIELDS };
        let fault = LAYOUT.tiling_fault().expect("stopping short of len is a fault");
        assert!(fault.contains("4..8"), "the message names the trailing gap: {fault}");
    }
}
