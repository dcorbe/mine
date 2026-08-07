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

/// Write one record into a slot, and update every header field that changes.
///
/// `records` is the file's record count **after** this write; the caller knows
/// it because the caller owns the in-memory model. Passing it in rather than
/// incrementing what is on disk means a write cannot drift from the model it is
/// supposed to be persisting.
///
/// The record is padded to the physical length with zeros. Btrieve's padding is
/// not specified anywhere that survives, and zero is what every unused tail byte
/// in the shipped files holds.
///
/// # Errors
///
/// If the file cannot be opened, sought or written.
pub fn write_record(
    path: &std::path::Path,
    layout: Layout,
    slot: Slot,
    bytes: &[u8],
    records: u32,
) -> Result<(), String> {
    use std::io::{Read, Seek, SeekFrom, Write};

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;

    let fail = |what: &str, e: std::io::Error| format!("{}: {what}: {e}", path.display());

    // A reused slot's first four bytes are the free list's next link, and they
    // have to be read before the record overwrites them.
    let mut head = None;
    if let Slot::Free(at) = slot {
        let mut link = [0u8; 4];
        file.seek(SeekFrom::Start(u64::from(at)))
            .and_then(|_| file.read_exact(&mut link))
            .map_err(|e| fail("reading a free slot's link", e))?;
        head = Some(long(&link));
    }

    // A new page is written whole -- header, then the record, then zeros --
    // because the file has to grow to reach it at all.
    if let Slot::NewPage { number, .. } = slot {
        let mut page = vec![0u8; usize::from(layout.page)];
        page[..usize::from(HEADER)].copy_from_slice(
            &Header {
                number,
                data: true,
                stamp: 0,
            }
            .encode(),
        );
        file.seek(SeekFrom::Start(u64::from(number) * u64::from(layout.page)))
            .and_then(|_| file.write_all(&page))
            .map_err(|e| fail("appending a page", e))?;
    }

    let mut slack = vec![0u8; usize::from(layout.physical)];
    slack[..bytes.len()].copy_from_slice(bytes);
    file.seek(SeekFrom::Start(u64::from(slot.position())))
        .and_then(|_| file.write_all(&slack))
        .map_err(|e| fail("writing a record", e))?;

    // Page 0 -- the file control record -- rather than a hard-coded 512: a real
    // Btrieve file's page is always at least 512 bytes (see `btrieve.rs`'s
    // `FCR` constant), but the field offsets used below are all well inside a
    // page of any size this format uses, including the 64-byte pages the tests
    // below use to keep the fixture readable.
    let mut fcr = vec![0u8; usize::from(layout.page)];
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.read_exact(&mut fcr))
        .map_err(|e| fail("reading the file control record", e))?;

    // The record count is stored as two separate u16 fields, `RECORDS_HIGH` at
    // 0x1a and `RECORDS_LOW` at 0x1c, and `to_long` writing all four bytes at
    // `RECORDS_HIGH` only reaches `RECORDS_LOW` because the two fields happen to
    // sit adjacent in the FCR. That is a coincidence of this layout, not a
    // guarantee -- do not "simplify" this into a plain little-endian `u32`
    // store, and do not assume any other field is secretly two halves like this
    // one is. `FREE` and `PAGES` are each already a single four-byte quantity,
    // high word first (see [`long`]).
    fcr[fcr::RECORDS_HIGH..fcr::RECORDS_HIGH + 4].copy_from_slice(&to_long(records));
    if let Some(next) = head {
        fcr[fcr::FREE..fcr::FREE + 4].copy_from_slice(&to_long(next));
    }
    if let Slot::NewPage { number, .. } = slot {
        fcr[fcr::PAGES..fcr::PAGES + 4].copy_from_slice(&to_long(number + 1));
        let highest = u16::from_le_bytes([fcr[fcr::HIGHEST], fcr[fcr::HIGHEST + 1]]);
        let grown = u16::try_from(number).map_err(|_| "a file of more than 65,535 pages".to_owned())?;
        if grown > highest {
            fcr[fcr::HIGHEST..fcr::HIGHEST + 2].copy_from_slice(&grown.to_le_bytes());
        }
    }

    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.write_all(&fcr))
        .and_then(|_| file.flush())
        .map_err(|e| fail("writing the file control record", e))
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

    /// A file laid out like virgin `WCCUSERS.DAT` but small enough to read at a
    /// glance: 64-byte pages holding one 20-byte record each, five pages, one of
    /// which (page 4) is a data page.
    fn seed(dir: &std::path::Path) -> std::path::PathBuf {
        let (page, physical, pages) = (64usize, 20usize, 5usize);
        let mut bytes = vec![0u8; page * pages];
        bytes[0x08..0x0a].copy_from_slice(&(page as u16).to_le_bytes());
        bytes[0x10..0x14].copy_from_slice(&to_long(NOWHERE));
        bytes[0x14..0x16].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x16..0x18].copy_from_slice(&16u16.to_le_bytes());
        bytes[0x18..0x1a].copy_from_slice(&(physical as u16).to_le_bytes());
        bytes[0x1e..0x20].copy_from_slice(&4u16.to_le_bytes());
        bytes[0x26..0x2a].copy_from_slice(&to_long(pages as u32));
        // Page 4 is the data page; 1..4 are index pages.
        for number in 1..pages {
            let header = Header {
                number: number as u32,
                data: number == 4,
                stamp: 0,
            };
            bytes[number * page..number * page + 6].copy_from_slice(&header.encode());
        }
        let path = dir.join("SCRATCH.DAT");
        std::fs::write(&path, &bytes).expect("scratch file");
        path
    }

    #[test]
    fn a_record_written_into_the_only_data_page_reads_back() {
        let dir = crate::testing::scratch("pages-write-existing-slot");
        let path = seed(&dir);
        let layout = Layout {
            page: 64,
            physical: 20,
            pages: 5,
        };
        let at = layout.position(4, 0);

        write_record(&path, layout, Slot::Existing(at), &[0xab; 16], 1).expect("write");

        let bytes = std::fs::read(&path).expect("read back");
        assert_eq!(&bytes[at as usize..at as usize + 16], &[0xab; 16]);
        assert_eq!(long(&bytes[0x1a..0x1e]), 1, "the header counts the record");
        assert_eq!(bytes.len(), 64 * 5, "no page was added");
    }

    /// The eight-times case: the file has no room and grows.
    #[test]
    fn a_record_that_does_not_fit_grows_the_file_by_a_page() {
        let dir = crate::testing::scratch("pages-write-grows-a-page");
        let path = seed(&dir);
        let layout = Layout {
            page: 64,
            physical: 20,
            pages: 5,
        };
        write_record(&path, layout, Slot::Existing(layout.position(4, 0)), &[1; 16], 1)
            .expect("first");

        let grown = Layout { pages: 5, ..layout };
        write_record(
            &path,
            grown,
            Slot::NewPage {
                number: 5,
                position: grown.position(5, 0),
            },
            &[2; 16],
            2,
        )
        .expect("second");

        let bytes = std::fs::read(&path).expect("read back");
        assert_eq!(bytes.len(), 64 * 6, "the file grew by exactly one page");
        let header = Header::decode(&bytes[5 * 64..5 * 64 + 6]);
        assert_eq!(header.number, 5);
        assert!(header.data, "a page holding records has bit 15 set");
        assert_eq!(long(&bytes[0x26..0x2a]), 6, "the page count grew");
        assert_eq!(
            u16::from_le_bytes([bytes[0x1e], bytes[0x1f]]),
            5,
            "the highest page in use grew"
        );
        assert_eq!(long(&bytes[0x1a..0x1e]), 2);
    }

    /// Reusing a free slot moves the head along to whatever the slot pointed at.
    #[test]
    fn taking_a_free_slot_moves_the_head_to_its_link() {
        let dir = crate::testing::scratch("pages-write-reuses-free-slot");
        let path = seed(&dir);
        let layout = Layout {
            page: 64,
            physical: 20,
            pages: 5,
        };
        let first = layout.position(4, 0);
        // Put one slot on the free list, chaining to nothing.
        let mut bytes = std::fs::read(&path).expect("read");
        bytes[0x10..0x14].copy_from_slice(&to_long(first));
        bytes[first as usize..first as usize + 4].copy_from_slice(&to_long(NOWHERE));
        std::fs::write(&path, &bytes).expect("seed the free list");

        write_record(&path, layout, Slot::Free(first), &[9; 16], 1).expect("write");

        let bytes = std::fs::read(&path).expect("read back");
        assert_eq!(long(&bytes[0x10..0x14]), NOWHERE, "the free list is empty now");
        assert_eq!(&bytes[first as usize..first as usize + 16], &[9; 16]);
    }
}
