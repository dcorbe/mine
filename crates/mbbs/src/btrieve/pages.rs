//! The bytes under a Btrieve file: pages, slots, and the file control record.
//!
//! [`records`](super::records) reads a file into memory and knows nothing about
//! where the bytes were. This is the layer that knows: which page a record
//! position lives on, which slot in it, where the next free slot is, and which
//! six fields of the file control record change when a record is written.
//!
//! Everything here is measured off the eighteen files MajorMUD ships rather than
//! taken from a specification, because no specification for the v5 on-disk
//! format survives. Where a field's meaning was settled by comparing several
//! files, the comparison is in the doc comment.
//!
//! # High word first, five times
//!
//! Record pointers, the free-list head, the record count, the total page count,
//! a page's own number and a key's root page are all four-byte quantities stored
//! as two little-endian words with the **high** word first. Reading one as a
//! plain little-endian `u32` yields a plausible wrong number and no error. See
//! [`long`].

/// Bytes of header at the start of every page.
///
/// Six: four of page number and two that carry the data-page flag and a
/// modification counter.
pub const HEADER: u16 = 6;

/// The record pointer, and free-list link, that means "nothing follows".
pub const NOWHERE: u32 = 0xffff_ffff;

/// Where each field this host writes lives in the file control record.
pub mod fcr {
    /// Free-list head. A [`long`](super::long).
    pub const FREE: usize = 0x10;
    /// Record count, high half. The low half is two bytes later.
    pub const RECORDS_HIGH: usize = 0x1a;
    /// Record count, low half.
    pub const RECORDS_LOW: usize = 0x1c;
    /// Highest page number in use, `u16` little-endian.
    ///
    /// Not the same as the page count: `WCCTEXT.DAT` is 3,602 pages and reads
    /// 3,565 here, because it is the variable-length file and its overflow
    /// pages are counted differently. For every other file it is the page count
    /// minus one.
    pub const HIGHEST: usize = 0x1e;
    /// Total pages in the file. A [`long`](super::long).
    ///
    /// Verified to equal `size / page` for all sixteen files the module opens.
    pub const PAGES: usize = 0x26;
    /// Where the key definitions start.
    pub const KEYS: usize = 0x110;
    /// Bytes of one key definition.
    pub const KEY_WIDTH: usize = 0x1e;
    /// Within a key definition: the root index page. A [`long`](super::long).
    pub const KEY_ROOT: usize = 0x00;
    /// Within a key definition: how many records this key indexes. A
    /// [`long`](super::long).
    pub const KEY_RECORDS: usize = 0x04;
}

/// Decode a four-byte quantity stored high word first.
pub fn long(bytes: &[u8]) -> u32 {
    (u32::from(u16::from_le_bytes([bytes[0], bytes[1]])) << 16)
        | u32::from(u16::from_le_bytes([bytes[2], bytes[3]]))
}

/// Encode a four-byte quantity high word first.
pub fn to_long(value: u32) -> [u8; 4] {
    let high = ((value >> 16) as u16).to_le_bytes();
    let low = (value as u16).to_le_bytes();
    [high[0], high[1], low[0], low[1]]
}

/// A page's six-byte header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The page's own number, which is its offset divided by the page length.
    pub number: u32,

    /// Whether the page holds records. Bit 15 of the second field.
    pub data: bool,

    /// Btrieve's modification counter, in the low fifteen bits. Preserved rather
    /// than interpreted -- see the module documentation.
    pub stamp: u16,
}

impl Header {
    /// Read a header from the first six bytes of a page.
    ///
    /// # Panics
    ///
    /// If `bytes` is shorter than [`HEADER`].
    pub fn decode(bytes: &[u8]) -> Self {
        let flags = u16::from_le_bytes([bytes[4], bytes[5]]);
        Self {
            number: long(bytes),
            data: flags & 0x8000 != 0,
            stamp: flags & 0x7fff,
        }
    }

    /// The six bytes this header is.
    pub fn encode(self) -> [u8; 6] {
        let flags = (u16::from(self.data) << 15) | (self.stamp & 0x7fff);
        let number = to_long(self.number);
        let flags = flags.to_le_bytes();
        [number[0], number[1], number[2], number[3], flags[0], flags[1]]
    }
}

/// Where the next record is going.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// A slot the free list gave back. Its first four bytes are the next link
    /// and the caller has to move the head along before overwriting them.
    Free(u32),

    /// An unused slot in a page that already holds records.
    Existing(u32),

    /// A page that does not exist yet, and the first slot of it.
    NewPage { number: u32, position: u32 },
}

impl Slot {
    /// Where the record goes, whichever kind of slot it is.
    pub fn position(self) -> u32 {
        match self {
            Self::Free(at) | Self::Existing(at) => at,
            Self::NewPage { position, .. } => position,
        }
    }
}

/// A file's page geometry: enough to turn a record position into a page and a
/// slot, and back.
///
/// A narrower thing than [`Geometry`](super::Geometry) on purpose. This layer
/// has no business knowing a file's record count or version, and a function that
/// takes only what it needs cannot be given a stale copy of what it does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    /// Bytes per page.
    pub page: u16,
    /// Bytes per record slot -- the physical length, not the logical one.
    pub physical: u16,
    /// How many pages the file currently is.
    pub pages: u32,
}

impl Layout {
    /// How many records fit in one page.
    pub fn per_page(self) -> u32 {
        u32::from((self.page - HEADER) / self.physical)
    }

    /// The file position of a slot.
    pub fn position(self, page: u32, slot: u32) -> u32 {
        u32::from(self.page) * page + u32::from(HEADER) + u32::from(self.physical) * slot
    }

    /// Which page and slot a file position is, or `None` if it is not on a slot
    /// boundary.
    ///
    /// A position that is not a slot is a module handing back a record pointer
    /// it invented, and it must not be silently rounded to a nearby record.
    pub fn slot_of(self, position: u32) -> Option<(u32, u32)> {
        let page = position / u32::from(self.page);
        let within = position % u32::from(self.page);
        let offset = within.checked_sub(u32::from(HEADER))?;
        if offset % u32::from(self.physical) != 0 {
            return None;
        }
        let slot = offset / u32::from(self.physical);
        (slot < self.per_page()).then_some((page, slot))
    }

    /// Where the next inserted record goes.
    ///
    /// `taken` is every position currently holding a live record, `free` is the
    /// head of the free list if there is one, and `data` is the number of every
    /// page that holds records, lowest first.
    ///
    /// The order -- free list, then a gap in an existing page, then a new page
    /// -- is the original's. Slots are filled from the front of a page because
    /// [`records::walk`](super::records) stops reading a page at the first slot
    /// that is neither live nor free, so a gap would hide every record behind
    /// it.
    pub fn next_slot(self, taken: &[u32], free: Option<u32>, data: &[u32]) -> Slot {
        if let Some(at) = free {
            return Slot::Free(at);
        }
        for page in data {
            for slot in 0..self.per_page() {
                let at = self.position(*page, slot);
                if !taken.contains(&at) {
                    return Slot::Existing(at);
                }
            }
        }
        Slot::NewPage {
            number: self.pages,
            position: self.position(self.pages, 0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The five places this format writes a `u32` high half first.
    ///
    /// Record pointers, the free-list head, the record count, the page count and
    /// a page's own number all use it. Read as a plain little-endian `u32`,
    /// `WCCITEMS`'s free-list head of `0x325806` becomes `0x06580032` and points
    /// past the end of the file -- a wrong number rather than an error, which is
    /// why this is pinned separately from anything that uses it.
    #[test]
    fn a_long_in_this_format_is_two_words_high_first() {
        assert_eq!(long(&[0x32, 0x00, 0x06, 0x58]), 0x0032_5806);
        assert_eq!(to_long(0x0032_5806), [0x32, 0x00, 0x06, 0x58]);
    }

    /// Round-tripping is not enough on its own: a decoder and an encoder that
    /// are wrong the same way agree with each other. This pins the encoder
    /// against a byte string measured out of `tmp/WCCUSERS.DAT` page 4.
    #[test]
    fn a_page_header_is_a_number_and_a_flag_measured_from_wccusers() {
        // `000004000080` -- page 4, bit 15 set, modification counter 0.
        let measured = [0x00, 0x00, 0x04, 0x00, 0x00, 0x80];
        let header = Header::decode(&measured);
        assert_eq!(header.number, 4);
        assert!(header.data, "bit 15 marks a page that holds records");
        assert_eq!(header.stamp, 0);
        assert_eq!(header.encode(), measured);
    }

    /// The low fifteen bits are a modification counter, **not** a count of used
    /// slots. `WCCRACE.DAT`'s four data pages read 141, 145, 127 and 133 while
    /// holding thirteen records between them. Nothing this host reads uses it;
    /// it is decoded so that writing a page can leave it alone rather than
    /// clobber it.
    #[test]
    fn the_low_fifteen_bits_are_a_stamp_and_not_a_population() {
        let header = Header::decode(&[0x00, 0x00, 0x02, 0x00, 0x8d, 0x80]);
        assert_eq!(header.number, 2);
        assert!(header.data);
        assert_eq!(header.stamp, 141);
    }

    /// An index page is a page with the bit clear, and must stay one.
    #[test]
    fn an_index_page_is_not_a_data_page() {
        let header = Header::decode(&[0x00, 0x00, 0x01, 0x00, 0x0d, 0x00]);
        assert!(!header.data);
        assert_eq!(header.stamp, 13);
    }

    /// `tmp/WCCUSERS.DAT` as shipped, which is this plan's subject: 2,048-byte
    /// pages holding one 2,006-byte record each, five pages of which exactly one
    /// (page 4) holds records.
    fn wccusers() -> Layout {
        Layout {
            page: 2048,
            physical: 2006,
            pages: 5,
        }
    }

    #[test]
    fn a_slot_is_a_page_a_header_and_a_stride() {
        let layout = wccusers();
        assert_eq!(layout.per_page(), 1, "2048 less six bytes holds one 2006");
        // Page 4, slot 0.
        assert_eq!(layout.position(4, 0), 4 * 2048 + 6);
        assert_eq!(layout.slot_of(4 * 2048 + 6), Some((4, 0)));
    }

    /// Four records to a 512-byte page, which is `WCCRACE.DAT`'s shape.
    #[test]
    fn several_slots_to_a_page_are_spaced_by_the_physical_length() {
        let layout = Layout {
            page: 512,
            physical: 126,
            pages: 6,
        };
        assert_eq!(layout.per_page(), 4);
        assert_eq!(layout.position(2, 0), 2 * 512 + 6);
        assert_eq!(layout.position(2, 3), 2 * 512 + 6 + 126 * 3);
        assert_eq!(layout.slot_of(2 * 512 + 6 + 126 * 3), Some((2, 3)));
        // A position that is not on a slot boundary is not a slot.
        assert_eq!(layout.slot_of(2 * 512 + 7), None);
    }

    /// The free list wins, because that is what the original did -- and the live
    /// board's `WCCUSERS.DB` proves it, with `id` gaps at 3, 5, 7 and 8 where
    /// deleted characters' slots were handed out again.
    #[test]
    fn a_free_slot_is_used_before_a_fresh_one() {
        let layout = wccusers();
        let free = 4 * 2048 + 6;
        assert_eq!(
            layout.next_slot(&[], Some(free), &[4]),
            Slot::Free(free),
            "a free slot is taken before anything else"
        );
    }

    /// Virgin `WCCUSERS.DAT`: nothing free, one data page, no records in it.
    #[test]
    fn the_first_record_of_an_empty_file_goes_in_the_one_data_page() {
        let layout = wccusers();
        assert_eq!(
            layout.next_slot(&[], None, &[4]),
            Slot::Existing(4 * 2048 + 6)
        );
    }

    /// One record in, one slot per page, no page has room -- so the file grows.
    /// This is the case nine characters hits eight times.
    #[test]
    fn a_full_file_grows_by_a_page() {
        let layout = wccusers();
        let taken = [4 * 2048 + 6];
        assert_eq!(
            layout.next_slot(&taken, None, &[4]),
            Slot::NewPage {
                number: 5,
                position: 5 * 2048 + 6,
            },
            "page 5 is one past the end of a five-page file"
        );
    }

    /// Slots must be filled from the front of a page, because `walk` stops at the
    /// first slot that is neither live nor free -- so a gap hides every record
    /// behind it. With slot 0 of a four-slot page taken, the answer is slot 1.
    #[test]
    fn slots_are_filled_from_the_front_of_a_page() {
        let layout = Layout {
            page: 512,
            physical: 126,
            pages: 6,
        };
        let taken = [2 * 512 + 6];
        assert_eq!(
            layout.next_slot(&taken, None, &[2, 3, 4, 5]),
            Slot::Existing(2 * 512 + 6 + 126)
        );
    }
}
