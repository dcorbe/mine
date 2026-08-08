//! The bytes under a Btrieve file: pages, slots, and the file control record.
//!
//! [`records`](super::records) reads a file into memory and knows nothing about
//! where the bytes were. This is the layer that knows: which page a record
//! position lives on, which slot in it, where the next free slot is, and which
//! four fields of the file control record change when a record is written --
//! [`fcr::FREE`], the record count ([`fcr::RECORDS_HIGH`]/[`fcr::RECORDS_LOW`]),
//! [`fcr::HIGHEST`] and [`fcr::PAGES`].
//!
//! Everything here is measured off the eighteen files MajorMUD ships rather than
//! taken from a specification, because no specification for the v5 on-disk
//! format survives. Where a field's meaning was settled by comparing several
//! files, the comparison is in the doc comment.
//!
//! # High word first, six times
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
    ///
    /// Zero rather than a panic if `physical` is zero -- a length no real
    /// file has, but nothing upstream of here refuses one before it reaches
    /// this division. Zero slots per page is also the right answer for it:
    /// no record fits, so [`next_slot`](Self::next_slot) moves straight past
    /// every existing page to a new one instead of looping forever trying to
    /// find room that was never there.
    pub fn per_page(self) -> u32 {
        if self.physical == 0 {
            return 0;
        }
        u32::from(self.page.saturating_sub(HEADER) / self.physical)
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
    ///
    /// `physical` guarded the same way [`Self::per_page`] is: zero is not a
    /// length any real file has, but nothing upstream refuses one before it
    /// would reach this division, and no position is on a slot boundary of a
    /// layout with no slots.
    pub fn slot_of(self, position: u32) -> Option<(u32, u32)> {
        if self.physical == 0 {
            return None;
        }
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
    ///
    /// I2: `taken` is sorted once here rather than probed with `.contains` on
    /// every slot of every data page -- for a file the shape of `WCCUPDAT.DAT`
    /// (38,754 records, one slot per page) the unsorted version was a linear
    /// scan of up to 38,754 positions inside a loop over up to 39,211 pages,
    /// roughly 1.5 billion comparisons for a single insert. Sorting once and
    /// binary-searching is `O(records log records + pages)` instead, and the
    /// caller sees no difference: same inputs, same [`Slot`] out.
    pub fn next_slot(self, taken: &[u32], free: Option<u32>, data: &[u32]) -> Slot {
        if let Some(at) = free {
            return Slot::Free(at);
        }
        let mut sorted = taken.to_vec();
        sorted.sort_unstable();
        for page in data {
            for slot in 0..self.per_page() {
                let at = self.position(*page, slot);
                if sorted.binary_search(&at).is_err() {
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
        let grown = u16::try_from(number)
            .map_err(|_| "a file of more than 65,535 pages".to_owned())?;
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

/// Bytes of header at the start of an index page, before its first entry.
///
/// Six bytes of the same [`Header`] a data page opens with — number, then flags
/// with the data bit clear — then two bytes of entry count, then two child page
/// numbers: the **rightmost** child at offset 8 and the **leftmost** at offset
/// 12. 6 + 2 + 4 + 4 = 16.
///
/// Both child slots are [`NOWHERE`] on a leaf, which is why the two files whose
/// whole index fits one page — `WCCRACE.DAT` and `WCCCLASS.DAT` — read
/// `0xffffffff` there and an earlier reading of this constant called them
/// sibling pointers. They are not. `WCCITEMS.VIR` page 131 holds 2045 and 130,
/// and walking from them reaches every one of that file's 1,950 records exactly
/// once. See `docs/plans/2026-08-07-btrieve-interior-pages-design.md`.
pub const INDEX_HEADER: usize = 16;

/// Bytes of one index entry past its key: a record pointer, then a child page.
///
/// The record pointer names a live record — **an interior entry indexes a
/// record just as a leaf entry does**, which is why a traversal of the whole
/// tree visits every record exactly once, and why the eleven shipped files that
/// hold records yield exactly as many index entries as they have records.
///
/// The child page holds keys **greater** than this entry's, and is [`NOWHERE`]
/// on a leaf. The **last** entry of any page carries zero there instead: a node
/// with `n` keys has `n+1` children, and the last of them lives in the page
/// header at offset 8 rather than in an entry. That zero is a placeholder, not
/// a pointer to page 0.
pub const INDEX_ENTRY_TAIL: usize = 8;

/// Emit the leaf page for one key, from records already in that key's order.
///
/// `entries` is `(key bytes, record position)` pairs, already sorted --
/// [`Records`](super::Records) has already done that, and this does not
/// re-sort them.
///
/// Returns one page image, [`layout.page`](Layout::page) bytes, with the page
/// number left zero: the caller allocates page numbers -- in this crate,
/// always the key's existing root -- and patches [`Header::encode`] over the
/// first six bytes before writing.
///
/// **One page, not a `Vec` of them.** `Err` is the only other outcome -- see
/// below -- so there is no shape in which this returns anything but exactly
/// one page, and every caller immediately un-wraps a one-element `Vec` to get
/// at it.
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
pub fn index_pages(layout: Layout, entries: &[(Vec<u8>, u32)]) -> Result<Vec<u8>, String> {
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

    Ok(page)
}

/// One index page, decoded.
///
/// The same shape whether the page is a leaf or an interior node — the format
/// does not mark which it is, and [`Self::leaf`] is the test. See
/// `docs/plans/2026-08-07-btrieve-interior-pages-design.md`, "The format, as
/// measured", for where every field came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexPage {
    /// The page's own number, from its [`Header`].
    pub number: u32,
    /// Btrieve's modification counter, preserved rather than interpreted.
    pub stamp: u16,
    /// The child holding keys greater than the last entry's, or [`NOWHERE`].
    ///
    /// A node with `n` keys has `n+1` children. This is the last of them, and
    /// it lives here rather than in the last entry because the last entry's own
    /// child slot is a zero placeholder.
    pub rightmost: u32,
    /// The child holding keys less than the first entry's, or [`NOWHERE`].
    pub leftmost: u32,
    /// `(key bytes, record position, child page)`, in key order.
    ///
    /// The child is [`NOWHERE`] on a leaf, and zero on the last entry of any
    /// page. **The key is a real record's key** — an interior entry names a
    /// record just as a leaf entry does, which is why a traversal visits every
    /// record exactly once.
    pub entries: Vec<(Vec<u8>, u32, u32)>,
}

impl IndexPage {
    /// Whether this page has no children.
    ///
    /// Byte 5 is **not** a discriminator: `WCCITEMS.VIR`'s root (page 131) and
    /// its leaf page 2045 both carry `0x12` there. The absence of a leftmost
    /// child is what distinguishes them.
    ///
    /// **Zero counts as absent, not as page 0.** Page 0 is the file control
    /// record and can never be a tree node, so a zero in a child slot means the
    /// same thing [`NOWHERE`] does. The format uses both: a *virgin* root page
    /// -- `WCCUSERS.VIR` pages 1, 2 and 3, and `WCCGANGS.VIR` pages 1 and 2 --
    /// reads `ffffffff` at offset 8 and `00000000` at offset 12. Reading that
    /// zero as a page number sends a walk into the file control record, and
    /// every file this host has ever written starts out in exactly that shape.
    #[must_use]
    pub fn leaf(&self) -> bool {
        self.leftmost == NOWHERE || self.leftmost == 0
    }
}

/// Decode one index page.
///
/// `key_length` is the key's total width in bytes — [`Key::length`](super::keys::Key::length).
/// It cannot be recovered from the page, which is why it is a parameter.
///
/// # Errors
///
/// If `page` is shorter than [`INDEX_HEADER`], or the entry count would run
/// past the end of the page. Both mean the caller is looking at something that
/// is not an index page for this key, and neither is worth panicking over
/// during a walk of a file another program wrote.
pub fn decode_index_page(page: &[u8], key_length: usize) -> Result<IndexPage, String> {
    if page.len() < INDEX_HEADER {
        return Err(format!("{} bytes is not an index page", page.len()));
    }
    let header = Header::decode(&page[..usize::from(HEADER)]);
    let count = usize::from(u16::from_le_bytes([page[6], page[7]]));
    let width = key_length + INDEX_ENTRY_TAIL;
    let used = INDEX_HEADER + count * width;
    if used > page.len() {
        return Err(format!(
            "a count of {count} entries of {width} bytes needs {used} bytes, and \
             the page is {}",
            page.len()
        ));
    }

    let mut entries = Vec::with_capacity(count);
    for n in 0..count {
        let at = INDEX_HEADER + n * width;
        let key = page[at..at + key_length].to_vec();
        let tail = at + key_length;
        entries.push((
            key,
            long(&page[tail..tail + 4]),
            long(&page[tail + 4..tail + 8]),
        ));
    }

    Ok(IndexPage {
        number: header.number,
        stamp: header.stamp,
        rightmost: long(&page[8..12]),
        leftmost: long(&page[12..16]),
        entries,
    })
}

/// The most levels a tree may have before a walk gives up.
///
/// Not a property of the format. A backstop: the deepest shipped file is three
/// levels (`docs/plans/2026-08-07-btrieve-interior-pages-design.md`), and a
/// file claiming more than this is corrupt in a way that would otherwise cost
/// the box its memory before it cost anyone an error message.
const MAX_DEPTH: usize = 32;

/// What walking a key's tree found.
#[derive(Debug)]
pub struct Walk {
    /// Every `(key bytes, record position)` in the tree, in key order.
    pub entries: Vec<(Vec<u8>, u32)>,
    /// The page numbers the tree occupies, **root first**.
    ///
    /// `Block::reindex` rebuilds into exactly these numbers, which is what
    /// keeps a rebuild from growing the file every time it runs.
    pub pages: Vec<u32>,
}

/// Walk one key's tree from its root.
///
/// In-order: the leftmost child's subtree, then for each entry the entry itself
/// followed by the subtree of the child that entry names — except the last
/// entry, whose subtree is the one the page header's rightmost slot names.
///
/// # Errors
///
/// If the file cannot be read, a page number is outside the file or zero (page
/// 0 is the file control record and never part of a tree), a page appears
/// twice, the tree is deeper than [`MAX_DEPTH`], or a page does not decode.
pub fn walk(
    path: &std::path::Path,
    layout: Layout,
    root: u32,
    key_length: usize,
) -> Result<Walk, String> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = Walk {
        entries: Vec::new(),
        pages: Vec::new(),
    };
    let mut seen = std::collections::HashSet::new();

    // An explicit stack rather than recursion: `MAX_DEPTH` bounds the tree, but
    // a page holds hundreds of entries and each one pushes a frame, so the
    // recursive shape is bounded by the *file* rather than by the depth.
    //
    // Each frame is a page and how far through its entries the walk has got.
    struct Frame {
        page: IndexPage,
        at: usize,
    }
    let mut stack: Vec<Frame> = Vec::new();
    let mut next = Some(root);

    loop {
        // Descend as far left as this subtree goes.
        while let Some(number) = next.take() {
            if number == 0 || number >= layout.pages {
                return Err(format!(
                    "page {number} is not inside a {}-page file",
                    layout.pages
                ));
            }
            if !seen.insert(number) {
                return Err(format!("page {number} appears twice in the tree"));
            }
            if stack.len() >= MAX_DEPTH {
                return Err(format!("the tree is more than {MAX_DEPTH} levels deep"));
            }
            out.pages.push(number);

            let mut bytes = vec![0u8; usize::from(layout.page)];
            file.seek(SeekFrom::Start(u64::from(number) * u64::from(layout.page)))
                .and_then(|_| file.read_exact(&mut bytes))
                .map_err(|e| format!("{}: page {number}: {e}", path.display()))?;
            let page = decode_index_page(&bytes, key_length)
                .map_err(|e| format!("page {number}: {e}"))?;

            let leftmost = (!page.leaf()).then_some(page.leftmost);
            stack.push(Frame { page, at: 0 });
            next = leftmost;
        }

        // Take the next entry off the deepest unfinished page.
        let Some(frame) = stack.last_mut() else {
            return Ok(out);
        };
        if frame.at == frame.page.entries.len() {
            stack.pop();
            continue;
        }
        let (key, position, child) = &frame.page.entries[frame.at];
        out.entries.push((key.clone(), *position));
        frame.at += 1;
        if !frame.page.leaf() {
            next = Some(if frame.at == frame.page.entries.len() {
                frame.page.rightmost
            } else {
                *child
            });
        }
    }
}

/// The six-byte header of a page already in the file, read on its own rather
/// than as part of the page it heads.
///
/// [`Block::reindex`](super::Block::reindex) calls this on a key's root page
/// before it overwrites that page: [`Header::stamp`]'s doc comment says the
/// stamp is preserved rather than interpreted, and the only way to preserve
/// it across a rebuild is to read what is there before writing over it.
///
/// # Errors
///
/// If the file cannot be opened, or the page cannot be read.
pub fn page_header(path: &std::path::Path, layout: Layout, number: u32) -> Result<Header, String> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut header = [0u8; HEADER as usize];
    file.seek(SeekFrom::Start(u64::from(number) * u64::from(layout.page)))
        .and_then(|_| file.read_exact(&mut header))
        .map_err(|e| format!("{}: page {number}: {e}", path.display()))?;
    Ok(Header::decode(&header))
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

    /// The six places this format writes a `u32` high half first.
    ///
    /// Record pointers, the free-list head, the record count, the total page
    /// count, a page's own number and a key's root page all use it. Read as a
    /// plain little-endian `u32`, `WCCITEMS`'s free-list head of `0x325806`
    /// becomes `0x06580032` and points past the end of the file -- a wrong
    /// number rather than an error, which is why this is pinned separately
    /// from anything that uses it.
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

    /// `next_slot` sorts its own copy of `taken` (I2); a naive `sort` followed
    /// by `binary_search` would give the right answer only if the caller
    /// already handed it a sorted slice. Nothing about the signature says
    /// that, `Records::positions` does not sort, and this hands `taken` in
    /// descending order -- the opposite of the file's own page order -- to
    /// make sure the answer does not depend on the order the caller happened
    /// to build it in.
    #[test]
    fn next_slot_does_not_care_what_order_taken_arrives_in() {
        let layout = Layout {
            page: 512,
            physical: 126,
            pages: 6,
        };
        assert_eq!(layout.per_page(), 4, "four 126-byte records fit a 512-byte page");

        // Every slot of pages 2 and 3 taken -- eight positions -- handed over
        // highest-first, the opposite of the order a sorted scan would want.
        let mut taken: Vec<u32> = [2u32, 3]
            .iter()
            .flat_map(|&page| (0..4).map(move |slot| layout.position(page, slot)))
            .collect();
        taken.reverse();

        assert_eq!(
            layout.next_slot(&taken, None, &[2, 3, 4, 5]),
            Slot::Existing(4 * 512 + 6),
            "pages 2 and 3 are full regardless of the order taken lists them in"
        );
    }

    /// I2: the cost this exists to bound. 100,000 data pages, one slot each,
    /// all but the last taken -- close to the shape of `WCCUPDAT.DAT`
    /// (38,754 records, 39,211 pages, one slot per page). Confirmed against
    /// the pre-fix `.contains` scan by reverting this method and rerunning
    /// this test: 36.5 seconds in the same `cargo test` debug build that
    /// runs the fixed version in 0.03 seconds. A half-second budget leaves
    /// three orders of magnitude of room on the pass side while still
    /// catching a regression back to the linear scan.
    #[test]
    fn next_slot_stays_fast_at_wccupdats_scale() {
        let layout = Layout {
            page: 2048,
            physical: 2015,
            pages: 100_001,
        };
        // Pages 1..=100,000 all exist and hold records; every one but the
        // last (100,000) has its one slot taken.
        let data: Vec<u32> = (1..=100_000).collect();
        let taken: Vec<u32> = (1..100_000).map(|page| layout.position(page, 0)).collect();

        let start = std::time::Instant::now();
        let slot = layout.next_slot(&taken, None, &data);
        let elapsed = start.elapsed();

        assert_eq!(slot, Slot::Existing(layout.position(100_000, 0)));
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "next_slot took {elapsed:?} over 100,000 pages -- the O(records^2) \
             scan is back"
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

        let page = index_pages(layout, &entries).expect("two entries fit easily");

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
        assert_eq!(
            long(&page[32..36]),
            0,
            "the page's last entry's tail, unlike every other entry's"
        );
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

        let page = index_pages(layout, &entries).expect("13 entries fit one leaf");

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
        let page = index_pages(layout, &[]).expect("an empty key still has a root page");
        assert_eq!(u16::from_le_bytes([page[6], page[7]]), 0);
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

        let page = index_pages(layout, &entries).expect("four ten-byte entries need exactly 56");
        assert_eq!(page.len(), usize::from(layout.page));
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

    /// **The interior page, from the bytes `WCCITEMS.VIR` page 131 holds.**
    ///
    /// Measured, not constructed: the first two entries of that file's root,
    /// which is an interior page with 29 entries. `0x0083` is the page's own
    /// number, 131. `0x07fd` and `0x0082` at offsets 8 and 12 are the rightmost
    /// and leftmost child, pages 2045 and 130. The first entry is key `81`, the
    /// record at file position 101,382, and child page 197.
    ///
    /// This is the fixture the whole plan rests on, so it is a literal rather
    /// than a read of `tmp/` — a test that needs the data files is a test that
    /// silently passes without them.
    ///
    /// All sixteen header bytes are the real page's, including its count of 29.
    /// Only the first two entries carry measured bytes; the other 27 are left
    /// zero. That is deliberate — **the count field is what drives the decode**,
    /// not how much data looks meaningful, and asserting 29 here is what pins
    /// that. A decoder that stopped at the first zero-filled entry would be
    /// wrong on any page Btrieve had deleted from.
    #[test]
    fn an_interior_page_decodes_to_its_children() {
        let mut page = vec![0u8; 1536];
        page[..16].copy_from_slice(&[
            0x00, 0x00, 0x83, 0x00, // number 131, high word first
            0x29, 0x12, //             stamp 0x1229, data bit clear
            0x1d, 0x00, //             29 entries
            0x00, 0x00, 0xfd, 0x07, // rightmost child, page 2045
            0x00, 0x00, 0x82, 0x00, // leftmost child, page 130
        ]);
        page[16..40].copy_from_slice(&[
            0x51, 0x00, 0x00, 0x00, // key 81
            0x01, 0x00, 0x06, 0x8c, // record at 101,382
            0x00, 0x00, 0xc5, 0x00, // child page 197
            0x9c, 0x00, 0x00, 0x00, // key 156
            0x03, 0x00, 0x06, 0x1e, // record at 204,294
            0x00, 0x00, 0x07, 0x01, // child page 263
        ]);

        let decoded = decode_index_page(&page, 4).expect("a well-formed page");
        assert_eq!(decoded.number, 131);
        assert_eq!(decoded.stamp, 0x1229);
        assert_eq!(decoded.leftmost, 130);
        assert_eq!(decoded.rightmost, 2045);
        assert!(!decoded.leaf(), "a page with children is not a leaf");
        assert_eq!(
            decoded.entries.len(),
            29,
            "the header's count drives the decode, not how many entries carry \
             measured bytes"
        );
        assert_eq!(decoded.entries[0], (vec![0x51, 0, 0, 0], 101_382, 197));
        assert_eq!(decoded.entries[1], (vec![0x9c, 0, 0, 0], 204_294, 263));
    }

    /// A leaf says so by having no children, and the format says that three
    /// times over: both header slots and every entry tail are `NOWHERE`.
    ///
    /// The one exception is the **last** entry, whose tail is zero rather than
    /// `NOWHERE` — a node with `n` keys has `n+1` children and the last of them
    /// lives in the header at offset 8, so the last entry's own slot is unused.
    /// Measured on `WCCITEMS.VIR` page 130 and page 197, and on the two files
    /// whose whole index is one leaf.
    #[test]
    fn a_leaf_page_has_no_children_anywhere() {
        let mut page = vec![0u8; 512];
        page[..16].copy_from_slice(&[
            0x00, 0x00, 0x05, 0x00, // page 5
            0x00, 0x00, //             no stamp
            0x02, 0x00, //             2 entries
            0xff, 0xff, 0xff, 0xff, // no rightmost child
            0xff, 0xff, 0xff, 0xff, // no leftmost child
        ]);
        page[16..36].copy_from_slice(&[
            0x07, 0x00, //             key 7
            0x00, 0x00, 0x02, 0x06, // record at 518
            0xff, 0xff, 0xff, 0xff, // no child
            0x09, 0x00, //             key 9
            0x00, 0x00, 0x02, 0x1a, // record at 538
            0x00, 0x00, 0x00, 0x00, // the last entry's slot is unused, not NOWHERE
        ]);

        let decoded = decode_index_page(&page, 2).expect("a well-formed page");
        assert!(decoded.leaf(), "no leftmost child means a leaf");
        assert_eq!(decoded.entries[0].2, NOWHERE);
        assert_eq!(decoded.entries[1].2, 0, "the last entry's child slot is a placeholder");
    }

    /// **A virgin root is a leaf, and it does not say so the same way.**
    ///
    /// Measured off `WCCUSERS.VIR` page 1, byte for byte: `NOWHERE` at offset 8
    /// and **zero** at offset 12. Page 0 is the file control record and can
    /// never be a child, so both mean "no child" -- but a `leaf()` that tests
    /// only for `NOWHERE` calls this an interior page and sends a walk into the
    /// file control record.
    ///
    /// This is the shape every file this host writes starts in, `WCCUSERS.DAT`
    /// included, so getting it wrong breaks the populated meter and not some
    /// edge case.
    #[test]
    fn a_virgin_root_reads_as_a_leaf_even_though_its_slots_disagree() {
        let mut page = vec![0u8; 2048];
        page[..16].copy_from_slice(&[
            0x00, 0x00, 0x01, 0x00, // page 1
            0x00, 0x00, //             no stamp
            0x00, 0x00, //             no entries
            0xff, 0xff, 0xff, 0xff, // no rightmost child
            0x00, 0x00, 0x00, 0x00, // no leftmost child -- as zero, not NOWHERE
        ]);

        let decoded = decode_index_page(&page, 4).expect("a well-formed page");
        assert!(decoded.leaf(), "page 0 can never be a child, so zero means none");
        assert!(decoded.entries.is_empty());
    }

    /// A count that runs off the end of the page is a refusal, not a panic.
    /// This is the guard that stops a corrupt or misidentified page from
    /// indexing out of bounds during a walk.
    #[test]
    fn a_count_that_does_not_fit_the_page_is_refused() {
        let mut page = vec![0u8; 512];
        page[6..8].copy_from_slice(&500u16.to_le_bytes());
        let e = decode_index_page(&page, 2).expect_err("500 entries do not fit 512 bytes");
        assert!(e.contains("500"), "{e}");
    }

    /// A two-level tree, built by hand and walked.
    ///
    /// Three pages: root 1 with one entry, leaves 2 and 3. In-order that is
    /// leaf 2's keys, then the root's own key, then leaf 3's — because the
    /// root's entry is itself a record, sorting between its two children.
    ///
    /// Built by hand rather than by `build_index` on purpose: a walker tested
    /// only against the builder's output agrees with the builder about any
    /// mistake they share.
    #[test]
    fn a_walk_returns_the_tree_in_key_order() {
        let dir = crate::testing::scratch("pages-walk-two-levels");
        let path = dir.join("TREE.DAT");
        let layout = Layout { page: 512, physical: 16, pages: 4 };

        let mut file = vec![0u8; 512 * 4];
        // Root, page 1: one entry (key 20), leftmost child 2, rightmost 3.
        let root = 512;
        file[root..root + 16].copy_from_slice(&[
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x03, 0x00, // rightmost, page 3
            0x00, 0x00, 0x02, 0x00, // leftmost, page 2
        ]);
        // Built with `to_long` rather than a hand-written literal. This fixture
        // is scaffolding for the *traversal order*, not an oracle for the byte
        // encoding -- that is already pinned by
        // `a_long_in_this_format_is_two_words_high_first` and by
        // `an_interior_page_decodes_to_its_children`, whose bytes came off a
        // real file. A hand-transposed pointer here would fail this test for a
        // reason that has nothing to do with what it is checking.
        file[root + 16..root + 18].copy_from_slice(&20u16.to_le_bytes());
        file[root + 18..root + 22].copy_from_slice(&to_long(3000));
        file[root + 22..root + 26].copy_from_slice(&to_long(0)); // last entry, placeholder
        // Leaves, pages 2 and 3.
        for (number, keys) in [(2u32, [10u16, 15]), (3, [25, 30])] {
            let at = 512 * number as usize;
            file[at..at + 16].copy_from_slice(&[
                0x00, 0x00, number as u8, 0x00, 0x00, 0x00, 0x02, 0x00,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ]);
            for (n, key) in keys.iter().enumerate() {
                let e = at + 16 + n * 10;
                file[e..e + 2].copy_from_slice(&key.to_le_bytes());
                file[e + 2..e + 6].copy_from_slice(&to_long(u32::from(*key) * 100));
                file[e + 6..e + 10]
                    .copy_from_slice(&to_long(if n == 1 { 0 } else { NOWHERE }));
            }
        }
        std::fs::write(&path, &file).expect("writes");

        let walk = walk(&path, layout, 1, 2).expect("walks");
        assert_eq!(
            walk.entries,
            vec![
                (vec![10, 0], 1000),
                (vec![15, 0], 1500),
                (vec![20, 0], 3000),
                (vec![25, 0], 2500),
                (vec![30, 0], 3000),
            ],
            "the root's own entry sorts between its two children"
        );
        assert_eq!(walk.pages, vec![1, 2, 3], "root first, then in walk order");
    }

    /// A tree that points at itself is refused rather than walked forever.
    ///
    /// This is the guard that keeps a corrupt file from becoming an unbounded
    /// allocation. It is cheap and it has a real failure mode behind it.
    #[test]
    fn a_cycle_in_the_tree_is_refused() {
        let dir = crate::testing::scratch("pages-walk-cycle");
        let path = dir.join("LOOP.DAT");
        let layout = Layout { page: 512, physical: 16, pages: 2 };

        let mut file = vec![0u8; 512 * 2];
        file[512..512 + 16].copy_from_slice(&[
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x01, 0x00, // rightmost child is itself
            0x00, 0x00, 0x01, 0x00, // leftmost child is itself
        ]);
        std::fs::write(&path, &file).expect("writes");

        let e = walk(&path, layout, 1, 2).expect_err("a self-referential root");
        assert!(e.contains("twice"), "{e}");
    }

    /// A key with no records still has a root page, and walking it is empty
    /// rather than an error. `Block::reindex` hits this on every virgin file.
    #[test]
    fn a_walk_of_an_empty_root_is_empty() {
        let dir = crate::testing::scratch("pages-walk-empty");
        let path = dir.join("EMPTY.DAT");
        let layout = Layout { page: 512, physical: 16, pages: 2 };

        let mut file = vec![0u8; 512 * 2];
        file[512..512 + 16].copy_from_slice(&[
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ]);
        std::fs::write(&path, &file).expect("writes");

        let walk = walk(&path, layout, 1, 2).expect("walks");
        assert!(walk.entries.is_empty());
        assert_eq!(walk.pages, vec![1], "the root itself is still owned");
    }
}
