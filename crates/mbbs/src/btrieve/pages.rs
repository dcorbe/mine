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
/// If `bytes` is longer than the slot it would go in, if the file cannot be
/// opened, sought or written, or if the record would read back as an empty
/// slot (see [`records::looks_empty`](super::records::looks_empty)).
pub fn write_record(
    path: &std::path::Path,
    layout: Layout,
    slot: Slot,
    bytes: &[u8],
    records: u32,
) -> Result<(), String> {
    use std::io::{Read, Seek, SeekFrom, Write};

    // Checked before anything is opened: `slack[..bytes.len()]` below would
    // panic on a buffer longer than the slot, and this crate's rule is that a
    // routine which cannot act honestly stops rather than proceeding --
    // including by panicking. `Block::update` and `Block::insert` normalise
    // to the file's own `reclen` before calling this, so an oversized buffer
    // reaching here is a bug in a caller, not a module input; naming both
    // lengths is what makes that caller findable.
    if bytes.len() > usize::from(layout.physical) {
        return Err(format!(
            "{}: a {}-byte record does not fit a {}-byte physical slot",
            path.display(),
            bytes.len(),
            layout.physical
        ));
    }

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;

    let fail = |what: &str, e: std::io::Error| format!("{}: {what}: {e}", path.display());

    let mut slack = vec![0u8; usize::from(layout.physical)];
    slack[..bytes.len()].copy_from_slice(bytes);

    // The file's size once this write lands -- one page larger for a slot on
    // a page that does not exist yet, unchanged otherwise -- which is the
    // same `size` a later `records::walk` would compute when it decides
    // whether this slot is empty. Checked, and refused, before any byte of
    // it is written: a record that would be unreadable the moment it landed
    // must not land at all, and everything behind it in the page would be
    // unreadable too.
    let current = file
        .metadata()
        .map_err(|e| fail("reading the file's size", e))?
        .len();
    let prospective = match slot {
        Slot::NewPage { number, .. } => u64::from(number + 1) * u64::from(layout.page),
        Slot::Free(_) | Slot::Existing(_) => current,
    };
    let size = u32::try_from(prospective)
        .map_err(|_| format!("{}: a file larger than four gigabytes", path.display()))?;
    if super::records::looks_empty(&slack, size) {
        return Err(format!(
            "{}: a record padded to {} bytes would read back as an empty slot -- its \
             bytes past the first four are all zero and its first four, read as a \
             record pointer, land inside a {size}-byte file -- so it and every record \
             behind it in the page would be unreadable",
            path.display(),
            layout.physical
        ));
    }

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

/// The free list's head, or `None` if it is empty.
///
/// Reads only the four bytes at [`fcr::FREE`]. `Block::insert` calls this
/// itself rather than trusting a copy of the geometry it might be holding,
/// because the free list is exactly the kind of thing an earlier write in the
/// same session already changed.
///
/// # Errors
///
/// If the file cannot be opened or read.
pub fn free_head(path: &std::path::Path) -> Result<Option<u32>, String> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut bytes = [0u8; 4];
    file.seek(SeekFrom::Start(fcr::FREE as u64))
        .and_then(|_| file.read_exact(&mut bytes))
        .map_err(|e| format!("{}: reading the free-list head: {e}", path.display()))?;

    let head = long(&bytes);
    Ok((head != NOWHERE).then_some(head))
}

/// The number of every page that holds records, lowest first.
///
/// Reads just the six-byte header of each page rather than the whole file:
/// [`Layout::next_slot`] only needs to know which pages are data pages, not
/// what is in them.
///
/// # Errors
///
/// If the file cannot be opened, or a page's header cannot be read.
pub fn data_pages(path: &std::path::Path, layout: Layout) -> Result<Vec<u32>, String> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut header = [0u8; HEADER as usize];
    let mut out = Vec::new();
    for number in 1..layout.pages {
        file.seek(SeekFrom::Start(u64::from(number) * u64::from(layout.page)))
            .and_then(|_| file.read_exact(&mut header))
            .map_err(|e| format!("{}: page {number}: {e}", path.display()))?;
        if Header::decode(&header).data {
            out.push(number);
        }
    }
    Ok(out)
}

/// Bytes of header at the start of a leaf index page, before its first entry.
///
/// Measured off `WCCRACE.DAT` and `WCCCLASS.DAT`, the only two shipped files
/// whose index fits one leaf page end to end (thirteen and fifteen records,
/// both a two-byte key): four bytes of the same [`Header`] a data page opens
/// with -- number, then flags with the data bit clear -- then two bytes that
/// equalled the entry count in both measurements, then eight bytes of
/// `0xffffffff` that a leaf with no siblings should hold. `docs/plans/
/// 2026-08-07-btrieve-writes.md`, Task 6, has the raw bytes.
pub const INDEX_HEADER: usize = 16;

/// Bytes of one index entry past its key: a record pointer, then a second
/// four-byte field.
///
/// Not a child pointer in the sense the name would suggest elsewhere in this
/// format -- a leaf has no children -- and not [`NOWHERE`] on every entry
/// either. Measured off both `WCCRACE.DAT` (13 entries) and `WCCCLASS.DAT`
/// (15 entries): every entry but the page's **last** carries `0xffffffff`
/// there, and the last carries zero instead. Two of two measurements agree,
/// and [`index_pages`] matches the pattern rather than the simpler one this
/// constant's name implies.
pub const INDEX_ENTRY_TAIL: usize = 8;

/// Emit the leaf pages for one key, from records already in that key's order.
///
/// `entries` is `(key bytes, record position)` pairs, already sorted --
/// [`Records`](super::Records) has already done that, and this does not
/// re-sort them.
///
/// Returns one page image per leaf, [`layout.page`](Layout::page) bytes each,
/// with the page number left zero: the caller allocates page numbers -- in
/// this crate, always the key's existing root -- and patches
/// [`Header::encode`] over the first six bytes before writing.
///
/// # Errors
///
/// If the entries do not fit in a single page. **That is a stop, not a
/// fallback.** Splitting into interior pages needs a fill-factor policy
/// nothing in the surviving record specifies, and inventing one would produce
/// a file that looks valid and orders wrongly -- see `docs/plans/
/// 2026-08-07-btrieve-writes.md`, Task 6, for the measurement this boundary
/// is drawn from: nine of the eleven files MajorMUD ships with records need
/// more than one leaf page, and this refuses every one of them rather than
/// guess at how Btrieve would have split them.
pub fn index_pages(layout: Layout, entries: &[(Vec<u8>, u32)]) -> Result<Vec<Vec<u8>>, String> {
    let width = entries.first().map_or(0, |(key, _)| key.len() + INDEX_ENTRY_TAIL);
    let used = INDEX_HEADER + width * entries.len();
    if used > usize::from(layout.page) {
        return Err(format!(
            "{} entries of {width} bytes need {used} bytes of index, and a page \
             holds only {}: an interior page would be needed and this host does \
             not build one",
            entries.len(),
            layout.page,
        ));
    }

    let mut page = vec![0u8; usize::from(layout.page)];
    page[..usize::from(HEADER)].copy_from_slice(
        &Header {
            number: 0,
            data: false,
            stamp: 0,
        }
        .encode(),
    );
    let count = u16::try_from(entries.len())
        .map_err(|_| format!("{} entries, more than a u16 counts", entries.len()))?;
    page[6..8].copy_from_slice(&count.to_le_bytes());
    page[8..12].copy_from_slice(&to_long(NOWHERE));
    page[12..16].copy_from_slice(&to_long(NOWHERE));

    let mut offset = INDEX_HEADER;
    for (index, (key, position)) in entries.iter().enumerate() {
        page[offset..offset + key.len()].copy_from_slice(key);
        let tail = offset + key.len();
        page[tail..tail + 4].copy_from_slice(&to_long(*position));
        // Every entry but the page's last carries NOWHERE in its second
        // four bytes; the last carries zero instead. See
        // [`INDEX_ENTRY_TAIL`]'s doc comment for the measurement this comes
        // from.
        let last = index + 1 == entries.len();
        page[tail + 4..tail + 8].copy_from_slice(&to_long(if last { 0 } else { NOWHERE }));
        offset += key.len() + INDEX_ENTRY_TAIL;
    }

    Ok(vec![page])
}

/// Overwrite an existing page's bytes in place.
///
/// Unlike [`write_record`], which may extend the file for a new data page,
/// this only ever writes into a page already inside the file. Every key's
/// root page exists from the moment the file is created -- virgin
/// `WCCUSERS.DAT` roots its three keys at pages 1, 2 and 3, exactly its three
/// non-data pages -- so [`Block::reindex`](super::Block::reindex) never has
/// to allocate one.
///
/// # Errors
///
/// If `bytes` is not exactly one page, or the file cannot be opened, sought
/// or written.
pub fn write_page(
    path: &std::path::Path,
    layout: Layout,
    number: u32,
    bytes: &[u8],
) -> Result<(), String> {
    if bytes.len() != usize::from(layout.page) {
        return Err(format!(
            "{} bytes for a page of {}",
            bytes.len(),
            layout.page
        ));
    }

    use std::io::{Seek, SeekFrom, Write};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    file.seek(SeekFrom::Start(u64::from(number) * u64::from(layout.page)))
        .and_then(|_| file.write_all(bytes))
        .map_err(|e| format!("{}: page {number}: {e}", path.display()))
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

    /// I5: `slack[..bytes.len()].copy_from_slice(bytes)` used to panic when
    /// `bytes` was longer than the slot. This crate's rule is that a routine
    /// which cannot act honestly stops rather than proceeding -- including by
    /// panicking -- and `write_record` already returns `Result`, so there was
    /// no reason for this one case to be a crash instead of an `Err`.
    #[test]
    fn a_record_longer_than_its_slot_is_an_error_not_a_panic() {
        let dir = crate::testing::scratch("pages-write-refuses-oversized-record");
        let path = seed(&dir);
        let layout = Layout {
            page: 64,
            physical: 20,
            pages: 5,
        };
        let at = layout.position(4, 0);

        let e = write_record(&path, layout, Slot::Existing(at), &[7u8; 21], 1)
            .expect_err("21 bytes do not fit a 20-byte physical slot");
        assert!(e.contains("21") && e.contains("20"), "{e}");

        let bytes = std::fs::read(&path).expect("read back");
        assert_eq!(
            &bytes[at as usize..at as usize + 4],
            &[0, 0, 0, 0],
            "the refused write touched nothing"
        );
    }

    /// C1: a record that, once padded to the physical length, would read back
    /// as an empty slot must be refused before it is written -- not written
    /// and then discovered corrupt the next time `records::walk` runs. An
    /// all-zero 16-byte record is the simplest instance: `record[4..]` is all
    /// zero and its first four bytes, read as a pointer, are `0`, which is
    /// less than any file this format can produce.
    #[test]
    fn a_record_that_would_read_back_as_empty_is_refused() {
        let dir = crate::testing::scratch("pages-write-refuses-empty-lookalike");
        let path = seed(&dir);
        let layout = Layout {
            page: 64,
            physical: 20,
            pages: 5,
        };
        let at = layout.position(4, 0);

        let e = write_record(&path, layout, Slot::Existing(at), &[0u8; 16], 1)
            .expect_err("an all-zero record decodes as an empty slot");
        assert!(e.contains("empty"), "{e}");

        let bytes = std::fs::read(&path).expect("read back");
        assert_eq!(
            &bytes[at as usize..at as usize + 4],
            &[0, 0, 0, 0],
            "the refused write touched nothing -- it was already zero"
        );
        assert_eq!(long(&bytes[0x1a..0x1e]), 0, "the record count was not bumped either");
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

    /// `Block::insert` needs the free-list head before it can call
    /// [`Layout::next_slot`], and the seed file starts with none.
    #[test]
    fn free_head_reads_none_from_a_virgin_file() {
        let dir = crate::testing::scratch("pages-free-head-empty");
        let path = seed(&dir);
        assert_eq!(free_head(&path).expect("reads"), None);
    }

    /// Once something is on the free list, its position is the head.
    #[test]
    fn free_head_reads_the_position_the_fcr_names() {
        let dir = crate::testing::scratch("pages-free-head-set");
        let path = seed(&dir);
        let at = 4 * 64 + 6; // page 4, slot 0.

        let mut bytes = std::fs::read(&path).expect("read");
        bytes[0x10..0x14].copy_from_slice(&to_long(at));
        std::fs::write(&path, &bytes).expect("seed a free list");

        assert_eq!(free_head(&path).expect("reads"), Some(at));
    }

    /// `Block::insert` needs to know which pages already hold records, and the
    /// seed file has exactly one -- page 4, the others are index pages.
    #[test]
    fn data_pages_lists_only_pages_with_the_data_bit_set() {
        let dir = crate::testing::scratch("pages-data-pages");
        let path = seed(&dir);
        let layout = Layout {
            page: 64,
            physical: 20,
            pages: 5,
        };

        assert_eq!(data_pages(&path, layout).expect("reads"), vec![4]);
    }

    /// A page appended by `write_record` is picked up the next time
    /// `data_pages` is asked, because `Block::insert` re-derives it fresh on
    /// every call rather than caching it.
    #[test]
    fn data_pages_sees_a_page_appended_since_it_was_last_asked() {
        let dir = crate::testing::scratch("pages-data-pages-grown");
        let path = seed(&dir);
        let layout = Layout {
            page: 64,
            physical: 20,
            pages: 5,
        };
        write_record(
            &path,
            layout,
            Slot::NewPage {
                number: 5,
                position: layout.position(5, 0),
            },
            &[1; 16],
            1,
        )
        .expect("grow the file by a page");

        let grown = Layout { pages: 6, ..layout };
        assert_eq!(data_pages(&path, grown).expect("reads"), vec![4, 5]);
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

    /// A 64-byte page, the same size the write tests above use: sixteen bytes
    /// of leaf header leave 48 for entries, and a 2-byte key entry is ten
    /// bytes wide, so four fit and a fifth does not.
    fn index_layout() -> Layout {
        Layout {
            page: 64,
            physical: 20,
            pages: 5,
        }
    }

    #[test]
    fn entries_that_fit_one_page_produce_a_single_leaf_that_decodes_back() {
        let layout = index_layout();
        let entries = vec![(vec![1u8, 0], 100u32), (vec![2u8, 0], 200u32)];

        let built = index_pages(layout, &entries).expect("two entries fit easily");

        assert_eq!(built.len(), 1);
        let page = &built[0];
        assert_eq!(page.len(), 64);

        let header = Header::decode(&page[..6]);
        assert!(!header.data, "an index page is not a data page");
        assert_eq!(
            u16::from_le_bytes([page[6], page[7]]),
            2,
            "the entry count"
        );
        assert_eq!(long(&page[8..12]), NOWHERE, "no sibling leaf before this one");
        assert_eq!(long(&page[12..16]), NOWHERE, "no sibling leaf after it");

        // First entry: key, then record pointer, then a leaf's NOWHERE child.
        assert_eq!(&page[16..18], &[1, 0]);
        assert_eq!(long(&page[18..22]), 100);
        assert_eq!(long(&page[22..26]), NOWHERE, "a leaf's child pointer");

        // Second entry follows immediately, ten bytes later -- and being the
        // page's last, its tail is zero rather than NOWHERE. C2: measured off
        // both WCCRACE.DAT and WCCCLASS.DAT, and the field this decoder never
        // checked before, so a wrong encoder here had nothing to catch it.
        assert_eq!(&page[26..28], &[2, 0]);
        assert_eq!(long(&page[28..32]), 200);
        assert_eq!(long(&page[32..36]), 0, "the page's last entry's tail, unlike every other entry's");
    }

    /// C2, pinned against the actual bytes measured out of `WCCRACE.DAT`
    /// page 1 (see `docs/plans/2026-08-07-btrieve-writes.md`'s C2 write-up):
    /// entry 11 (second to last of 13) reads `0c 00 | 00 00 80 09 | ff ff ff
    /// ff` and entry 12 (the last) reads `0d 00 | 00 00 06 0a | 00 00 00
    /// 00` -- the same key and record-pointer shape, but a **zero** tail
    /// instead of [`NOWHERE`]. This builds the same 13-entry, 2-byte-key
    /// leaf `WCCRACE.DAT` holds, with those two entries' real measured key
    /// and record pointer, and checks both byte-for-byte -- independent of
    /// `tmp/`'s presence, so it runs even where the shipped files do not.
    #[test]
    fn index_pages_matches_wccrace_dats_measured_last_two_entries() {
        let layout = wccrace_index_layout();
        let mut entries: Vec<(Vec<u8>, u32)> =
            (0u16..11).map(|n| (n.to_le_bytes().to_vec(), u32::from(n))).collect();
        entries.push((0x000cu16.to_le_bytes().to_vec(), 0x0000_0980));
        entries.push((0x000du16.to_le_bytes().to_vec(), 0x0000_0a06));
        assert_eq!(entries.len(), 13);

        let built = index_pages(layout, &entries).expect("13 entries fit one leaf");
        let page = &built[0];

        let second_to_last = INDEX_HEADER + 11 * (2 + INDEX_ENTRY_TAIL);
        assert_eq!(&page[second_to_last..second_to_last + 2], &[0x0c, 0x00], "entry 11's key");
        assert_eq!(long(&page[second_to_last + 2..second_to_last + 6]), 0x0000_0980);
        assert_eq!(
            &page[second_to_last + 6..second_to_last + 10],
            &[0xff, 0xff, 0xff, 0xff],
            "entry 11's tail, measured as NOWHERE"
        );

        let last = INDEX_HEADER + 12 * (2 + INDEX_ENTRY_TAIL);
        assert_eq!(&page[last..last + 2], &[0x0d, 0x00], "entry 12's key");
        assert_eq!(long(&page[last + 2..last + 6]), 0x0000_0a06);
        assert_eq!(
            &page[last + 6..last + 10],
            &[0x00, 0x00, 0x00, 0x00],
            "entry 12's tail, measured as zero -- only the page's last entry differs"
        );
    }

    /// `WCCRACE.DAT`'s own shape: 512-byte pages, 13 entries of a 2-byte key
    /// fit `INDEX_HEADER` (16) plus `13 * 10 = 130` bytes, 146 of 512.
    fn wccrace_index_layout() -> Layout {
        Layout {
            page: 512,
            physical: 126,
            pages: 6,
        }
    }

    #[test]
    fn no_entries_is_a_valid_empty_leaf() {
        let layout = index_layout();
        let built = index_pages(layout, &[]).expect("an empty key still has a root page");
        assert_eq!(built.len(), 1);
        assert_eq!(u16::from_le_bytes([built[0][6], built[0][7]]), 0);
    }

    /// The boundary Task 6 draws: an interior page is refused rather than
    /// built. Four ten-byte entries fit in this page's 48 bytes of room; a
    /// fifth does not.
    #[test]
    fn entries_that_do_not_fit_one_page_are_refused() {
        let layout = index_layout();
        let entries: Vec<(Vec<u8>, u32)> =
            (0..5u32).map(|n| (n.to_le_bytes()[..2].to_vec(), n)).collect();

        let e = index_pages(layout, &entries).expect_err("five ten-byte entries need 66 bytes");
        assert!(e.contains("interior"), "{e}");
    }

    #[test]
    fn a_page_at_the_boundary_still_fits() {
        let layout = index_layout();
        let entries: Vec<(Vec<u8>, u32)> =
            (0..4u32).map(|n| (n.to_le_bytes()[..2].to_vec(), n)).collect();

        let built = index_pages(layout, &entries).expect("four ten-byte entries need exactly 56");
        assert_eq!(built.len(), 1);
    }

    #[test]
    fn write_page_overwrites_an_existing_page_without_touching_the_rest() {
        let dir = crate::testing::scratch("pages-write-page");
        let path = seed(&dir);
        let layout = index_layout();

        let mut image = vec![0xabu8; usize::from(layout.page)];
        write_page(&path, layout, 2, &image).expect("page 2 already exists");

        let bytes = std::fs::read(&path).expect("read back");
        assert_eq!(&bytes[2 * 64..3 * 64], image.as_slice());
        assert_ne!(
            &bytes[1 * 64..2 * 64],
            image.as_slice(),
            "only the targeted page changed"
        );

        image[0] = 0xff;
        let e = write_page(&path, layout, 2, &image[..63]).expect_err("short by one byte");
        assert!(e.contains("63"), "{e}");
    }
}
