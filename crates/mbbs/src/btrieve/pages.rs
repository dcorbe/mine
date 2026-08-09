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

/// Write one duplicate chain's `[prev][next]` pair into a record on disk.
///
/// Eight bytes at `position + offset`, and nothing else: no record count, no
/// free list, no page header. That is the whole difference from
/// [`write_record`], and the reason this is a separate function rather than an
/// argument to that one -- a chain write changes no field the file control
/// record holds, so re-reading and rewriting a whole page of it per record
/// would be both slow and an opportunity to write a stale count back.
///
/// `offset` is [`Key::chain`](super::keys::Key::chain): measured from the start
/// of the physical slot, not from the logical record. `chain` is
/// `[prev, next]`, each a record position or [`NOWHERE`] at that end of the
/// chain.
///
/// # Errors
///
/// If `position` is not a slot boundary of this layout, if the pair would not
/// fit inside the slot, or if the file cannot be opened, sought or written.
pub fn write_chain(
    path: &std::path::Path,
    layout: Layout,
    position: u32,
    offset: usize,
    chain: [u32; 2],
) -> Result<(), String> {
    use std::io::{Seek, SeekFrom, Write};

    // A position that is not a slot would put the pair inside a neighbouring
    // record -- the same reason `Layout::slot_of` refuses to round.
    let Some((_, slot)) = layout.slot_of(position) else {
        return Err(format!(
            "{}: {position} is not a record slot of a {}-byte page holding \
             {}-byte records",
            path.display(),
            layout.page,
            layout.physical
        ));
    };

    // Past `physical` is only safe when nothing else shares this page: for
    // any slot but the page's last, those bytes are the next record's, so
    // the bound stays at `physical`. The last slot has no neighbour to
    // spill into -- only the page's own end, `page - HEADER`, offset by
    // whatever precedes this slot -- and the real engine writes exactly
    // there for a key descriptor like `WCCUSERS.VIR`'s (offset 2034 on a
    // 2006-byte physical record, one record per 2048-byte page).
    let limit = if slot + 1 == layout.per_page() {
        usize::from(layout.page)
            - usize::from(HEADER)
            - slot as usize * usize::from(layout.physical)
    } else {
        usize::from(layout.physical)
    };
    if offset + 8 > limit {
        return Err(format!(
            "{}: a chain at offset {offset} does not fit a {}-byte physical slot",
            path.display(),
            layout.physical
        ));
    }

    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&to_long(chain[0]));
    bytes[4..].copy_from_slice(&to_long(chain[1]));

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    file.seek(SeekFrom::Start(u64::from(position) + offset as u64))
        .and_then(|_| file.write_all(&bytes))
        .and_then(|_| file.flush())
        .map_err(|e| format!("{}: writing a duplicate chain: {e}", path.display()))
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
/// record just as a leaf entry does**, which is why a traversal of a
/// **unique** key's whole tree visits every record exactly once, and why the
/// eleven shipped files that hold records yield exactly as many index entries
/// as they have records. **Not so for a duplicate-permitting key**: its entry
/// count is the number of distinct values, and the record pointer is the
/// *first* of possibly several -- see [`IndexPage::tails`] for the rest.
///
/// The child page holds keys **greater** than this entry's, and is [`NOWHERE`]
/// on a leaf. The **last** entry of any page carries zero there instead: a node
/// with `n` keys has `n+1` children, and the last of them lives in the page
/// header at offset 8 rather than in an entry. That zero is a placeholder, not
/// a pointer to page 0.
///
/// When a leaf fills its page exactly, those four placeholder bytes are not
/// written at all -- `WCCSPELS.VIR` page 1 declares fifty ten-byte entries in a
/// 512-byte page, which is four bytes more than fits, and the last entry ends
/// after its record pointer. A reader must tolerate it; this host's own
/// [`build_index`] does not produce it, because packing one extra entry per
/// page buys nothing it needs.
pub const INDEX_ENTRY_TAIL: usize = 8;

/// Bytes of index page header the *engine* counts before the first entry.
///
/// The engine frames a page as twelve bytes of header followed by entries of
/// `[child page][key][record pointer]`; this module folds that leading child
/// pointer into [`INDEX_HEADER`] and puts the trailing one on the entry
/// instead. **The two framings describe the same bytes** — `count` entries
/// occupy `12 + count * (key + 8)` either way — but only this one divides a
/// page correctly, because the leading child of the first entry is real
/// capacity and [`INDEX_HEADER`] spends it on the header.
///
/// `W32MKDE.EXE`, decompiled at `re/btrieve_ghidra/exports/W32MKDE_decompiled.c`
/// :18412, sizes a page as `(pageSize - 0xc) / entrySize`.
pub const INDEX_PAGE_HEADER: usize = 12;

/// A key, as much of it as sizing an index page needs.
///
/// This exists so that the width of an index entry has **one** spelling. It had
/// four — `decode_index_page`, `build_index`, `push_node` and `number_pages`
/// each wrote `key_length + INDEX_ENTRY_TAIL` out by hand — and a fifth in
/// `crates/mbbs/tests/btrieve.rs`. Every one of them was missing the same term,
/// and a bare `key_length: usize` parameter is what let them be: the caller had
/// nothing to pass that could have carried the rest of the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    /// The key's total width in bytes, summed over its segments —
    /// [`Key::length`](super::keys::Key::length).
    pub length: usize,

    /// Whether more than one record may carry this key value.
    ///
    /// **A duplicate-permitting key's index entries are four bytes wider**, and
    /// this is the whole reason a bare length is not enough to size a page.
    pub duplicates: bool,
}

impl Shape {
    /// Bytes of one index entry: the key, its record pointer, and a child page.
    ///
    /// Four more when the key permits duplicates. Measured against the stored
    /// entry size at key descriptor `+0x0c` in all 40 keys of the 32 shipped
    /// files, and derived independently from `W32MKDE_decompiled.c`:18398-18410,
    /// where the engine computes `keyLen + 8` and then `keyLen + 0xc` if the
    /// key's attribute bit 0 is set.
    #[must_use]
    pub fn entry_size(&self) -> usize {
        self.length + if self.duplicates { 12 } else { 8 }
    }

    /// How many entries of this key fit one page.
    ///
    /// Matches the engine's own `maxEntries`, stored at key descriptor `+0x0e`,
    /// on all 40 shipped keys.
    #[must_use]
    pub fn capacity(&self, page: u16) -> usize {
        usize::from(page).saturating_sub(INDEX_PAGE_HEADER) / self.entry_size().max(1)
    }
}

/// How a duplicate-permitting key's index differs from a unique one's.
///
/// Kept as documentation rather than deleted with the refusal it used to carry
/// -- Stage D2 of `docs/plans/2026-08-08-fsd-subsystem-design.md` says this
/// comment "gets rewritten, not deleted" -- because the two consequences below
/// are what [`build_index`] and [`Block::reindex`](super::Block::reindex) are
/// now built around rather than reasons to stop.
///
/// A duplicate-permitting key's index entry is four bytes wider, and those four
/// bytes are **not** slack at the end of the entry. The engine lays a *linked
/// duplicates* entry out as
///
/// ```text
///     [child page][key bytes][head of chain][tail of chain]
/// ```
///
/// where the last slot -- the one a unique key uses as its record pointer -- is
/// the *last* record carrying this key value, and the inserted slot is the
/// *first*. For a unique key the two collapse onto one field, which is why the
/// engine's own walkers need no special case and why this host's decoder used
/// to read dup entries as though they were unique ones without noticing.
/// Decompiled at `re/btrieve_ghidra/exports/W32MKDE_decompiled.c`: the entry is
/// built at :16457-16462, strided at :11788-11800, and the two ends are picked
/// apart by Get-First and Get-Last at :11895-11903. Confirmed against a file
/// the real engine actually populated,
/// `tools/btrieve-oracle/fixtures/DUPKEY30.DAT`: its one populated leaf decodes
/// to exactly 10 entries -- one per distinct value, not one per its 30 records
/// -- each with a `head` that is measurably the first-inserted record of its
/// group of three and a `tail` that is measurably the last. See
/// `docs/plans/2026-08-08-fsd-subsystem-design.md`, Stage D1.
///
/// **Two consequences make this a feature rather than an offset fix, and they
/// are what the two halves of writing one are:**
///
/// 1. A linked-duplicates index holds **one entry per distinct key value**, not
///    one per record. The invariant [`build_index`] and [`push_node`] used to
///    be written against -- that a tree's entry count equals the file's record
///    count -- does not hold for one. So [`build_index`] takes [`Entry`]
///    values rather than records, and
///    [`Block::reindex`](super::Block::reindex) collapses each group into one
///    before calling it, using the same comparator that put the records in
///    order so the two cannot disagree about what "the same value" means.
/// 2. The chain itself lives **inside the records**, as a `[prev][next]` pair
///    of record positions at the offset the key descriptor stores at `+0x12`
///    ([`super::keys::Key::chain`]), measured from the physical slot. That is
///    why such a file's physical record is longer than its logical one by the
///    width of the pair -- `WCCUSERS` 1998 -> 2006, `WCCBANKS` 72 -> 80, all
///    eight. (`DUPKEY30.DAT`'s 12 -> 22 is that eight plus two more, which are
///    the version 6 per-slot in-use marker every page in that file carries
///    whether or not its key permits duplicates, and not part of the chain;
///    see [`chain_pair`].) Writing the index therefore means writing the chain
///    into the records too, which [`build_index`] does not do and should not:
///    `Block::reindex` owns it, because only it knows where the records are.
///
/// The failure being avoided has not changed, only the way of avoiding it: a
/// wrong guess writes an index Btrieve reads as a plausible wrong order, which
/// is what this module exists to prevent -- see the note on
/// [`Kind`](super::keys::Kind). What used to be a refusal is now measured
/// against the engine itself, which is a better answer than either refusing or
/// guessing.

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
    /// record just as a leaf entry does, which is why a traversal of a
    /// **unique** key's tree visits every record exactly once.
    ///
    /// For a key that permits duplicates, `entries` holds one row per
    /// **distinct key value**, not one per record — see [`Self::tails`] — and
    /// `entries[n].1` is the **head** of that value's chain (the first record
    /// this value was ever inserted for), not "the" record the way it is for
    /// a unique key.
    pub entries: Vec<(Vec<u8>, u32, u32)>,

    /// The **tail** of each entry's duplicate chain — the last record
    /// inserted with that entry's key value — parallel to [`Self::entries`]
    /// and the same length as it whenever the key permits duplicates, empty
    /// otherwise.
    ///
    /// A duplicate-permitting key's index entry is four bytes wider than a
    /// unique one ([`Shape::entry_size`]), and this is where the extra four
    /// bytes go: `[child page][key bytes][head of chain][tail of chain]`,
    /// confirmed against `tools/btrieve-oracle/fixtures/DUPKEY30.DAT` --
    /// built by the genuine engine with 30 records colliding in groups of
    /// three over 10 distinct values. That file's root page decodes to
    /// exactly 10 entries, each carrying a `tails[n]` that is measurably the
    /// **last-inserted** record of the group and an `entries[n].1` that is
    /// measurably the **first-inserted** one — see
    /// `a_duplicate_leafs_head_and_tail_are_the_first_and_last_inserted_record`
    /// in this module's tests, which cross-checks both against the in-record
    /// `[prev][next]` chain ([`chain_pair`]) rather than trusting the index
    /// page alone.
    pub tails: Vec<u32>,
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
pub fn decode_index_page(page: &[u8], shape: Shape) -> Result<IndexPage, String> {
    if page.len() < INDEX_HEADER {
        return Err(format!("{} bytes is not an index page", page.len()));
    }
    let header = Header::decode(&page[..usize::from(HEADER)]);
    let count = usize::from(u16::from_le_bytes([page[6], page[7]]));
    let key_length = shape.length;
    let width = shape.entry_size();
    // The **last** entry may be four bytes short. Its child field is a
    // placeholder nothing reads (see `INDEX_ENTRY_TAIL`), and when a leaf fills
    // a page exactly Btrieve does not write it -- `WCCSPELS.VIR` page 1 is the
    // one page in all eleven shipped files that does, and it is four bytes
    // shy of the full width. So only `key + position` -- or, for a duplicate
    // key, `key + head + tail` -- is required of the last entry: `width - 4`
    // either way, since `width` already carries the duplicates term.
    let used = if count == 0 {
        INDEX_HEADER
    } else {
        INDEX_HEADER + (count - 1) * width + (width - 4)
    };
    if used > page.len() {
        return Err(format!(
            "a count of {count} entries of {width} bytes needs {used} bytes, and \
             the page is {}",
            page.len()
        ));
    }

    let mut entries = Vec::with_capacity(count);
    let mut tails = Vec::with_capacity(if shape.duplicates { count } else { 0 });
    for n in 0..count {
        let at = INDEX_HEADER + n * width;
        let key = page[at..at + key_length].to_vec();
        let head_at = at + key_length;
        let head = long(&page[head_at..head_at + 4]);
        // A duplicate entry carries a second four-byte field -- the chain's
        // tail -- between the head and the child; a unique entry does not.
        // Either way the child sits in the entry's last four bytes.
        let child_at = if shape.duplicates {
            let tail_at = head_at + 4;
            tails.push(long(&page[tail_at..tail_at + 4]));
            tail_at + 4
        } else {
            head_at + 4
        };
        // Zero rather than a read when the child field was never written: that
        // is the value the last entry's slot carries when it *is* written, so
        // the two spellings of "no child here" decode alike.
        let child = if child_at + 4 <= page.len() {
            long(&page[child_at..child_at + 4])
        } else {
            0
        };
        entries.push((key, head, child));
    }

    Ok(IndexPage {
        number: header.number,
        stamp: header.stamp,
        rightmost: long(&page[8..12]),
        leftmost: long(&page[12..16]),
        entries,
        tails,
    })
}

/// The `[prev][next]` pair inside one physical record of a
/// duplicate-permitting key, at the offset the key's own descriptor names.
///
/// `slot` is the record's **whole physical slot**, from its first byte, not
/// just its logical `reclen` bytes and not the logical record's own start --
/// `offset` is measured from the slot ([`Key::chain`](super::keys::Key::chain),
/// the descriptor's `+0x12`), and in a version 6 file the two are two bytes
/// apart. Both halves are ordinary [`long`]s: a record position, or
/// [`NOWHERE`] at the end of the chain.
///
/// **Both are [`Layout::position`]s**, in the same encoding a unique key's
/// index entry uses for its record pointer -- there is no second pointer
/// format in this file layout. Every one of `DUPKEY30.DAT`'s 30 records agrees:
/// `prev` is `NOWHERE` on the first record of a group and otherwise the
/// previous record's own position, `next` is `NOWHERE` on the last and
/// otherwise the following record's, and the two ends are exactly the `head`
/// and `tail` [`decode_index_page`] reads out of that value's index entry.
/// Asserted over the whole file rather than over a hand-picked group in
/// `a_records_own_chain_agrees_with_its_neighbours_and_with_the_index`.
///
/// **The position is against the file's *logical* page numbering**, which is
/// only worth saying because `DUPKEY30.DAT` is a **version 6** file and so
/// distinguishes it from the physical one: physical pages 0 and 1 are two
/// shadowed copies of the file control record, 2 and 3 are page allocation
/// tables, and every remaining page carries the logical page it currently
/// holds in the second word of its own header -- physical page 10 says
/// logical 2, physical 8 says logical 5. Feed those logical numbers to
/// `Layout::position` and the chain resolves exactly. **Every file MajorMUD
/// ships is version 5**, where the two numberings are the same thing and this
/// distinction disappears; it is recorded here only so that the next reading
/// of this fixture does not rediscover the offset as an unexplained constant.
///
/// An earlier reading of this function did exactly that. It returned each half
/// as `(value, tag)` and reported that the values were *not* positions,
/// because it was handed a window starting at the logical record rather than
/// at the slot -- two bytes late, which splits a word-swapped [`long`] down
/// the middle. In a file this small every position's high word is zero, so the
/// misaligned low half still read as the right number and every internal
/// cross-check passed; the "tag" was the *following* slot's two-byte
/// in-use marker, which is why it read 1 everywhere except at the end of a
/// page. All six of that test's sample records were shifted the same way, so
/// no comparison *between* them could see it -- which is why the test below
/// derives its records from the fixture instead of quoting them.
///
/// `None` if `offset + 8` runs past the end of `slot`.
pub fn chain_pair(slot: &[u8], offset: usize) -> Option<[u32; 2]> {
    let half = |at: usize| -> Option<u32> { slot.get(at..at + 4).map(long) };
    Some([half(offset)?, half(offset + 4)?])
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
    /// Every entry in the tree, in key order.
    ///
    /// **One row per distinct key value**, which for a unique key is one row
    /// per record and for a duplicate-permitting key is not -- the restated
    /// invariant `docs/plans/2026-08-08-fsd-subsystem-design.md`'s Stage D1
    /// calls "the actual refactor". [`Entry::head`] and [`Entry::tail`] are
    /// the ends of the group's chain, and are the same record when the value
    /// is unique to it; the records between them are reachable only through
    /// the chain itself ([`chain_pair`]), which a tree walk does not follow.
    pub entries: Vec<Entry>,
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
    shape: Shape,
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
            let page = decode_index_page(&bytes, shape)
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
        let (key, head, child) = &frame.page.entries[frame.at];
        out.entries.push(Entry {
            key: key.clone(),
            head: *head,
            // A unique key's entry has no tail field, and its one record is
            // both ends of a chain of one.
            tail: frame.page.tails.get(frame.at).copied().unwrap_or(*head),
        });
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

/// One index entry: a key value, and the record or records that carry it.
///
/// **One entry is one key value, not one record.** For a key that forbids
/// duplicates those are the same thing and [`Self::head`] and [`Self::tail`]
/// are both simply the record. For one that permits them, an entry stands for
/// every record sharing the value, and the two ends of that group's chain are
/// what the page stores -- see [`chain_pair`] for the links between them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The key value, [`Shape::length`] bytes.
    pub key: Vec<u8>,
    /// The first record carrying it.
    pub head: u32,
    /// The last record carrying it, equal to [`Self::head`] when only one
    /// does. **Written to the page only when the key permits duplicates**; a
    /// unique key's entry has no slot for it, which is the four bytes
    /// [`Shape::entry_size`] differs by.
    pub tail: u32,
}

impl Entry {
    /// The entry for a record whose key value no other record shares.
    #[must_use]
    pub fn unique(key: Vec<u8>, position: u32) -> Self {
        Self {
            key,
            head: position,
            tail: position,
        }
    }
}

/// One node of a tree under construction.
#[derive(Debug)]
pub struct Node {
    /// The node's entries, in key order.
    pub entries: Vec<Entry>,
    /// Indices into [`Built::nodes`]. Empty for a leaf; otherwise one more than
    /// `entries.len()`.
    pub children: Vec<usize>,
    /// The page image, with **every child slot left empty**.
    ///
    /// [`number_pages`] fills them in from [`Self::children`] once the caller
    /// has decided which page each node lives on. Header and entries are built
    /// here rather than there so the shape and the bytes cannot drift apart.
    ///
    /// The child slots are deliberately *not* filled with node indices standing
    /// in for page numbers. Zero means "no child" — page 0 is the file control
    /// record, see [`IndexPage::leaf`] — so node index 0 would be
    /// indistinguishable from an absent child, and the first node pushed always
    /// *is* index 0. An unnumbered interior node would then decode as a leaf.
    pub image: Vec<u8>,
}

/// A tree, built but not yet placed in a file.
#[derive(Debug)]
pub struct Built {
    pub nodes: Vec<Node>,
    /// Index into [`Self::nodes`] of the root.
    pub root: usize,
    /// The key these pages index.
    ///
    /// Carried rather than re-derived: [`number_pages`] used to recover the
    /// entry width from the *first entry's* key length, which is a different
    /// quantity that merely happens to agree for a fixed-width key, and which
    /// could not have carried the duplicates term at all.
    pub shape: Shape,
}

/// Build a key's whole tree from entries already in that key's order.
///
/// `entries` is already sorted — [`Records`](super::Records) has done that, and
/// this does not re-sort them. **One entry per key value**, which for a
/// duplicate-permitting key is fewer than the file has records:
/// [`Block::reindex`](super::Block::reindex) collapses each group of records
/// sharing a value into a single [`Entry`] before calling this, and writes the
/// chain that joins them into the records themselves.
///
/// Bottom-up and evenly filled: a level too big for one page splits into the
/// fewest nodes that will hold it, with the entries that fall between them
/// promoted to the level above. **A promoted entry is a real entry**, indexing
/// its records exactly as it would in a leaf, which is what the format does and
/// why the total entry count across every node equals the number of distinct
/// key values.
///
/// The fill factor is this host's to choose — see
/// `docs/plans/2026-08-07-btrieve-interior-pages-design.md`, "The fidelity
/// bar". Btrieve's own runs 50–77%; this packs evenly and as full as the
/// splitting allows, which uses fewer pages than Btrieve did on the same data.
///
/// # Errors
///
/// If no entry fits a page.
pub fn build_index(layout: Layout, entries: &[Entry], shape: Shape) -> Result<Built, String> {
    let width = shape.entry_size();
    let cap = shape.capacity(layout.page);
    if cap == 0 {
        return Err(format!(
            "an entry of {width} bytes does not fit a page of {} with a \
             {INDEX_PAGE_HEADER}-byte header",
            layout.page
        ));
    }

    let mut nodes: Vec<Node> = Vec::new();
    let mut items: Vec<Entry> = entries.to_vec();
    let mut children: Vec<usize> = Vec::new();

    let root = loop {
        if items.len() <= cap {
            break push_node(&mut nodes, layout, shape, items, children);
        }

        // The fewest nodes that hold `items` with one separator between each
        // adjacent pair: `count * cap + (count - 1) >= items.len()`.
        let count = (items.len() + 1).div_ceil(cap + 1);
        let held = items.len() - (count - 1);
        let base = held / count;
        let extra = held % count;

        let mut promoted: Vec<Entry> = Vec::with_capacity(count - 1);
        let mut level: Vec<usize> = Vec::with_capacity(count);
        let mut taken = 0usize;
        let mut consumed = 0usize;
        for n in 0..count {
            let size = base + usize::from(n < extra);
            let mine: Vec<Entry> = items[taken..taken + size].to_vec();
            taken += size;
            let theirs = if children.is_empty() {
                Vec::new()
            } else {
                let slice = children[consumed..consumed + size + 1].to_vec();
                consumed += size + 1;
                slice
            };
            level.push(push_node(&mut nodes, layout, shape, mine, theirs));
            if n + 1 < count {
                promoted.push(items[taken].clone());
                taken += 1;
            }
        }

        items = promoted;
        children = level;
    };

    Ok(Built { nodes, root, shape })
}

/// Serialise one node and add it to the arena, returning its index.
///
/// Child *page numbers* are not known yet, so every child slot is left empty;
/// [`number_pages`] fills them in once the caller has decided which page each
/// node lives on.
fn push_node(
    nodes: &mut Vec<Node>,
    layout: Layout,
    shape: Shape,
    entries: Vec<Entry>,
    children: Vec<usize>,
) -> usize {
    let mut image = vec![0u8; usize::from(layout.page)];
    image[..usize::from(HEADER)].copy_from_slice(
        &Header {
            number: 0,
            data: false,
            stamp: 0,
        }
        .encode(),
    );
    let count = u16::try_from(entries.len()).expect("a page holds far fewer than 65,535 entries");
    image[6..8].copy_from_slice(&count.to_le_bytes());
    // Both child slots are left empty here, whether or not this node has
    // children -- `number_pages` fills them from `Node::children`, and writing
    // node indices in the meantime would make node 0 read as "no child". A leaf
    // is finished as it stands.
    image[8..12].copy_from_slice(&to_long(NOWHERE));
    image[12..16].copy_from_slice(&to_long(NOWHERE));

    let mut at = INDEX_HEADER;
    for (n, entry) in entries.iter().enumerate() {
        image[at..at + entry.key.len()].copy_from_slice(&entry.key);
        let mut field = at + entry.key.len();
        image[field..field + 4].copy_from_slice(&to_long(entry.head));
        // The chain's other end, for a key that permits duplicates: the four
        // bytes `Shape::entry_size` is wider by, between the head and the
        // child. A unique key has no slot here at all -- writing one would
        // push its child four bytes late and every entry after it with it.
        if shape.duplicates {
            field += 4;
            image[field..field + 4].copy_from_slice(&to_long(entry.tail));
        }
        let tail = field;
        // The last entry's child slot is a placeholder -- a node with `n` keys
        // has `n+1` children and the last of them lives in the header at offset
        // 8, so this slot is never a pointer. Every other slot is left empty
        // for `number_pages`, which is also exactly what a leaf keeps.
        //
        // AND IT MAY NOT FIT. A page packed to the engine's own capacity ends
        // `INDEX_HEADER + cap * entry` bytes in, which is up to four past the
        // page, because `INDEX_HEADER` folds in a leading child pointer the
        // engine counts as capacity. Btrieve writes exactly this shape --
        // `WCCSPELS.VIR` page 1 declares fifty ten-byte entries in a 512-byte
        // page and its last entry ends after its record pointer. This host
        // never produced it while it packed one entry short of capacity;
        // `decode_index_page` has tolerated it on the read side all along.
        if tail + 8 <= image.len() {
            let child = if n + 1 == entries.len() { 0 } else { NOWHERE };
            image[tail + 4..tail + 8].copy_from_slice(&to_long(child));
        }
        at += shape.entry_size();
    }

    nodes.push(Node {
        entries,
        children,
        image,
    });
    nodes.len() - 1
}

/// Place a built tree on real pages.
///
/// `numbers[0]` becomes the root — in this crate always the key's existing
/// root, so that the file control record's `KEY_ROOT` never has to be
/// rewritten. The rest are handed out in the order [`walk`] would visit the
/// nodes, so that rebuilding an unchanged file twice produces the same bytes
/// both times.
///
/// Returns `(page number, image)` pairs, root first.
///
/// # Errors
///
/// If there are fewer numbers than nodes.
pub fn number_pages(built: &Built, numbers: &[u32]) -> Result<Vec<(u32, Vec<u8>)>, String> {
    if numbers.len() < built.nodes.len() {
        return Err(format!(
            "{} nodes need {} page numbers and only {} were given",
            built.nodes.len(),
            built.nodes.len(),
            numbers.len()
        ));
    }

    // Node index -> page number, assigned in walk order so the assignment is
    // stable across rebuilds of the same data.
    let mut placed = vec![0u32; built.nodes.len()];
    let mut order = Vec::with_capacity(built.nodes.len());
    let mut stack = vec![built.root];
    while let Some(at) = stack.pop() {
        order.push(at);
        // Reversed so the leftmost child is visited first -- a stack pops in
        // reverse order, so this is what makes the walk leftmost-first rather
        // than rightmost-first.
        //
        // **Not cosmetic.** This order must match the order [`walk`] pushes
        // into `Walk::pages`, because `Block::reindex` feeds `walk`'s output
        // straight back in here as the numbers to reuse. If the two disagree,
        // node *k* is handed a different page than it occupied, and reindexing
        // an unchanged file rewrites it into a different shape instead of being
        // a no-op. `reindexing_twice_over_the_same_records_writes_the_same_bytes`
        // catches it, and dropping this `.rev()` alone is enough to make that
        // test fail -- measured, not assumed.
        for child in built.nodes[at].children.iter().rev() {
            stack.push(*child);
        }
    }
    for (n, at) in order.iter().enumerate() {
        placed[*at] = numbers[n];
    }

    let mut out = Vec::with_capacity(built.nodes.len());
    for at in &order {
        let node = &built.nodes[*at];
        let mut image = node.image.clone();
        let mut header = Header::decode(&image[..usize::from(HEADER)]);
        header.number = placed[*at];
        image[..usize::from(HEADER)].copy_from_slice(&header.encode());

        if !node.children.is_empty() {
            let width = built.shape.entry_size();
            image[8..12].copy_from_slice(&to_long(placed[node.children[node.entries.len()]]));
            image[12..16].copy_from_slice(&to_long(placed[node.children[0]]));
            for n in 0..node.entries.len().saturating_sub(1) {
                // The child is the entry's **last** four bytes, whatever the
                // entry holds before them. Spelling that as `length + 4` was
                // right only for a unique key, and put an interior node's
                // children in a duplicate key's `tail` fields -- unreachable
                // while `build_index` refused the shape, and wrong the moment
                // it stopped.
                let tail = INDEX_HEADER + n * width + (width - 4);
                image[tail..tail + 4].copy_from_slice(&to_long(placed[node.children[n + 1]]));
            }
        }
        out.push((placed[*at], image));
    }
    Ok(out)
}

/// Append one zeroed page to a file and return its number.
///
/// Does **not** update the file control record's page count. The caller holds
/// that page and writes it once; see [`Block::reindex`](super::Block::reindex).
///
/// # Errors
///
/// If the file cannot be opened or written.
pub fn append_page(path: &std::path::Path, layout: Layout) -> Result<u32, String> {
    use std::io::{Seek, SeekFrom, Write};

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let number = layout.pages;
    file.seek(SeekFrom::Start(u64::from(number) * u64::from(layout.page)))
        .and_then(|_| file.write_all(&vec![0u8; usize::from(layout.page)]))
        .and_then(|_| file.flush())
        .map_err(|e| format!("{}: appending page {number}: {e}", path.display()))?;
    Ok(number)
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

    /// A key of `length` bytes that forbids duplicates.
    ///
    /// Every index fixture in this module is one, and that is the gap this
    /// module's tests still have rather than a convenience: every shipped file
    /// that holds records has a unique key, so there is no measured sample of a
    /// populated duplicate index anywhere to build a fixture from. See
    /// [`unplaced_duplicate_bytes`].
    fn unique(length: usize) -> Shape {
        Shape {
            length,
            duplicates: false,
        }
    }

    /// Every distinct key shape the shipped files hold, and what Btrieve itself
    /// says an index entry and a page of them measure.
    ///
    /// `(page, key length, duplicates, entry size, entries per page)`. The last
    /// two columns are **not** this host's arithmetic: they are read straight
    /// out of the file, from the key descriptor's `+0x0c` and `+0x0e`, which is
    /// where the engine stores the answers it computed when it built the file.
    /// Sixteen distinct shapes, reduced from the 40 keys of the 32 files in
    /// `tmp/`, spanning all five page lengths in use and both settings of the
    /// duplicates bit.
    ///
    /// This is the whole point of the table: the numbers have an author other
    /// than the code under test. A capacity this host computes for itself can
    /// only be checked against a formula, and the formula was wrong.
    const SHIPPED_KEY_SHAPES: &[(u16, usize, bool, usize, usize)] = &[
        (4096, 8, false, 16, 255),  // NEWMP001.VIR key 0
        (1536, 4, false, 12, 127),  // WCCACMSR.DAT key 0
        (1024, 30, false, 38, 26),  // WCCACTS.DAT  key 0
        (512, 34, true, 46, 10),    // WCCBANKS.DAT key 0, two segments
        (1536, 2, false, 10, 152),  // WCCCLASS.DAT key 0
        (512, 20, false, 28, 17),   // WCCGANGS.DAT key 0
        (512, 4, true, 16, 31),     // WCCGANGS.DAT key 1
        (1536, 5, true, 17, 89),    // WCCITOWN.DAT key 1, two segments
        (1536, 8, false, 16, 95),   // WCCMP001.DAT key 0
        (512, 4, false, 12, 41),    // WCCMSG.DAT   key 0
        (512, 2, false, 10, 50),    // WCCRACE.DAT  key 0
        (2048, 18, false, 26, 78),  // WCCTEXT.DAT  key 0, the variable file
        (2048, 4, false, 12, 169),  // WCCUPDAT.DAT key 0
        (2048, 30, false, 38, 53),  // WCCUSERS.DAT key 0
        (2048, 4, true, 16, 127),   // WCCUSERS.DAT key 2, the character file
        (2048, 11, false, 19, 107), // WCCUSERS.VIR key 1
    ];

    /// A built duplicate leaf lays its entries out the way the real engine's
    /// does, and decodes back to what went in.
    ///
    /// The bytes are checked against the layout `decode_index_page` reads and
    /// against the engine's own `DUPKEY30.DAT` leaf next to it -- head where a
    /// unique key's record pointer goes, tail in the four bytes
    /// [`Shape::entry_size`] adds, child last -- rather than only round-
    /// tripped through this module's own decoder, which would agree with a
    /// builder that put the tail and the child the wrong way round.
    ///
    /// An empty duplicate index still builds, and that is not a technicality:
    /// all four shipped duplicate-key files hold zero records, so
    /// `Block::reindex` runs over them on every close.
    #[test]
    fn a_built_duplicate_leaf_holds_a_head_a_tail_and_a_child_in_that_order() {
        let layout = index_layout();
        let duplicate = Shape {
            length: 2,
            duplicates: true,
        };

        let empty = build_index(layout, &[], duplicate).expect("an empty duplicate index");
        assert_eq!(empty.nodes.len(), 1, "one empty leaf, as a virgin file has");

        let entries = vec![
            Entry {
                key: vec![1u8, 0],
                head: 100,
                tail: 300,
            },
            Entry {
                key: vec![2u8, 0],
                head: 200,
                tail: 200,
            },
        ];
        let built = build_index(layout, &entries, duplicate).expect("two values fit one leaf");
        assert_eq!(built.nodes.len(), 1);

        let image = &built.nodes[built.root].image;
        assert_eq!(
            &image[INDEX_HEADER..INDEX_HEADER + 14],
            [
                &[1u8, 0][..],       // the key
                &to_long(100)[..],   // its chain's head
                &to_long(300)[..],   // its chain's tail
                &to_long(NOWHERE)[..], // no child: this is a leaf
            ]
            .concat()
            .as_slice(),
            "a duplicate entry is [key][head][tail][child]"
        );

        let decoded = decode_index_page(image, duplicate).expect("decodes");
        assert_eq!(decoded.entries.len(), 2);
        assert_eq!(decoded.entries[0].1, 100, "head");
        assert_eq!(decoded.tails, vec![300, 200], "both tails");
        assert_eq!(
            decoded.entries[1].2, 0,
            "the last entry's child is the zero placeholder, not the tail"
        );
    }

    /// **Reading** the same shape `build_index` above refuses to *write*: a
    /// duplicate-permitting key's populated leaf decodes rather than errors,
    /// with the extra four bytes read as a chain tail rather than mistaken for
    /// a child page.
    ///
    /// One entry, hand-built rather than drawn from a real file (the
    /// DUPKEY30-shaped tests below cover that): key `[1, 0]`, head 100, tail
    /// 200, and -- because it is also the page's last entry -- a zero
    /// placeholder where a child page would go.
    #[test]
    fn a_populated_duplicate_leaf_decodes_its_head_and_tail_rather_than_erroring() {
        let layout = index_layout();
        let duplicate = Shape {
            length: 2,
            duplicates: true,
        };
        let mut page = vec![0u8; usize::from(layout.page)];
        page[6..8].copy_from_slice(&1u16.to_le_bytes());
        page[16..18].copy_from_slice(&[1, 0]); // key
        page[18..22].copy_from_slice(&to_long(100)); // head
        page[22..26].copy_from_slice(&to_long(200)); // tail
        page[26..30].copy_from_slice(&to_long(0)); // the last entry's placeholder child

        let decoded = decode_index_page(&page, duplicate).expect("a populated duplicate leaf");
        assert_eq!(decoded.entries, vec![(vec![1, 0], 100, 0)], "head, as the record pointer");
        assert_eq!(decoded.tails, vec![200], "tail, in the field a unique entry does not have");
    }

    /// `(key bytes, position)` rows as entries of a key no two records share.
    ///
    /// Most of these tests build a unique key, where an entry and a record are
    /// the same thing; this keeps them reading as the rows they are rather
    /// than as `Entry::unique` repeated.
    fn rows(of: &[(Vec<u8>, u32)]) -> Vec<Entry> {
        of.iter()
            .map(|(key, at)| Entry::unique(key.clone(), *at))
            .collect()
    }

    /// `tools/btrieve-oracle/fixtures/DUPKEY30.DAT` -- built by the genuine
    /// Pervasive Btrieve 6.15 engine, not this crate: 12-byte records, one
    /// 4-byte descending duplicate-permitting key, 30 records whose values
    /// collide in groups of three. Committed to the repository (unlike
    /// `tmp/`), so this reads it directly rather than skipping when it is
    /// absent. See `tools/btrieve-oracle/fixtures/DUPKEY30.txt`.
    fn dupkey30() -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tools/btrieve-oracle/fixtures/DUPKEY30.DAT"),
        )
        .expect("DUPKEY30.DAT is committed to the repository")
    }

    /// The real engine's own duplicate-key leaf, decoded: 10 entries for 30
    /// records -- one per distinct value, not one per record -- each with the
    /// head and tail measured straight off the index page's bytes.
    ///
    /// Page 9 (`9 * 512` into the file) is this key's whole tree: a single
    /// leaf, both child slots `NOWHERE`, ten entries in descending order, the
    /// last one carrying the zero placeholder every format's last entry does
    /// instead of a child page -- the same convention a unique key's leaf
    /// uses, confirming the duplicates term does not disturb it.
    #[test]
    fn a_duplicate_leafs_head_and_tail_are_the_first_and_last_inserted_record() {
        let file = dupkey30();
        let page = &file[9 * 512..10 * 512];
        let shape = Shape {
            length: 4,
            duplicates: true,
        };

        let decoded = decode_index_page(page, shape).expect("the real engine's own leaf");
        assert!(decoded.leaf(), "one page holds all ten entries");
        assert_eq!(decoded.entries.len(), 10, "one entry per distinct value, not per record");
        assert_eq!(decoded.tails.len(), 10);
        assert_eq!(decoded.leftmost, NOWHERE);
        assert_eq!(decoded.rightmost, NOWHERE);

        // Descending: key 9 first, key 0 last. `(value, head, tail)`, read
        // independently off the page's raw bytes.
        let expected: [(u32, u32, u32); 10] = [
            (9, 2654, 2698),
            (8, 2588, 2632),
            (7, 1492, 2566),
            (6, 1426, 1470),
            (5, 1360, 1404),
            (4, 1294, 1338),
            (3, 1228, 1272),
            (2, 1162, 1206),
            (1, 1096, 1140),
            (0, 1030, 1074),
        ];
        for (n, (value, head, tail)) in expected.into_iter().enumerate() {
            assert_eq!(decoded.entries[n].0, value.to_le_bytes().to_vec(), "entry {n}'s key");
            assert_eq!(decoded.entries[n].1, head, "entry {n} (value {value})'s head");
            assert_eq!(decoded.tails[n], tail, "entry {n} (value {value})'s tail");
        }
        for n in 0..9 {
            assert_eq!(decoded.entries[n].2, NOWHERE, "entry {n}'s child -- a leaf has none");
        }
        assert_eq!(decoded.entries[9].2, 0, "the last entry's placeholder, not NOWHERE");
    }

    /// Where `DUPKEY30.DAT` keeps each of its 30 records, and what position
    /// the engine calls it by.
    ///
    /// Returns `(slot offset in the file, the record's position)` indexed by
    /// **insertion order** -- which this fixture makes recoverable, because
    /// its second field is the insertion index and its key is that index over
    /// three (see `tools/btrieve-oracle/fixtures/DUPKEY30.txt`).
    ///
    /// The position is [`Layout::position`] against the page's **logical**
    /// number, read out of the page's own header rather than assumed from
    /// where the page sits: this is a version 6 file and the two differ. See
    /// [`chain_pair`]. A version 6 slot also opens with two bytes of in-use
    /// marker before the logical record, which is why the slot starts two
    /// bytes before the record content this searches for -- and why
    /// [`Key::chain`](super::super::btrieve::keys::Key::chain) reads 14 here
    /// on a file whose `reclen` is 12.
    fn dupkey30_records(file: &[u8]) -> Vec<(usize, u32)> {
        const PAGE: usize = 512;
        const PHYSICAL: usize = 22;
        const DATA_PAGE: u16 = 0x4400;

        let layout = Layout {
            page: PAGE as u16,
            physical: PHYSICAL as u16,
            pages: (file.len() / PAGE) as u32,
        };

        // Every slot in the file, by where it starts, with the position the
        // engine would name it by.
        let mut slots: std::collections::HashMap<usize, u32> = std::collections::HashMap::new();
        for physical in 0..file.len() / PAGE {
            let base = physical * PAGE;
            let flags = u16::from_le_bytes([file[base], file[base + 1]]);
            let logical = u32::from(u16::from_le_bytes([file[base + 2], file[base + 3]]));
            if flags != DATA_PAGE {
                continue;
            }
            for slot in 0..layout.per_page() {
                let at = base + usize::from(HEADER) + PHYSICAL * slot as usize;
                slots.insert(at, layout.position(logical, slot));
            }
        }

        (0..30)
            .map(|n: u32| {
                // Key value, insertion index, and the record's third field.
                let mut content = Vec::new();
                content.extend_from_slice(&(n / 3).to_le_bytes());
                content.extend_from_slice(&n.to_le_bytes());
                content.extend_from_slice(&0u32.to_le_bytes());
                let found: Vec<usize> = slots
                    .keys()
                    .copied()
                    .filter(|slot| file[slot + 2..slot + 14] == content[..])
                    .collect();
                assert_eq!(found.len(), 1, "record {n} sits in exactly one slot");
                let slot = found[0];
                (slot, slots[&slot])
            })
            .collect()
    }

    /// The in-record `[prev][next]` chain, over **every record in the file**.
    ///
    /// Read at the offset `DUPKEY30.DAT`'s own key descriptor names --
    /// `a_duplicate_keys_chain_offset_is_read_from_its_own_definition` in
    /// `keys.rs` measures it as 14, which is `physical - 8` -- and decoded as
    /// two ordinary [`long`]s, which is what they are: positions, in the one
    /// pointer encoding this format has.
    ///
    /// **The chain is in insertion order, and the index's `head` and `tail`
    /// are its two ends.** That is the claim, and it is checked here against
    /// all 30 records and all 10 groups rather than against a hand-picked
    /// one: for each group, `prev` is [`NOWHERE`] at the head and otherwise
    /// the previous record's position, `next` is `NOWHERE` at the tail and
    /// otherwise the following record's. Group 7 crosses a data-page boundary
    /// -- its third record was written onto a different page than its first
    /// two -- so the walk is not merely following adjacent slots.
    ///
    /// Deriving the records from the fixture rather than quoting their bytes
    /// is deliberate. The version of this test that quoted six of them read
    /// each one two bytes late, and could not see it, because *all six* were
    /// shifted the same way and every assertion compared one against another.
    #[test]
    fn a_records_own_chain_agrees_with_its_neighbours_and_with_the_index() {
        const CHAIN_OFFSET: usize = 14;

        let file = dupkey30();
        let records = dupkey30_records(&file);

        for (n, (slot, _)) in records.iter().enumerate() {
            let bytes = &file[*slot..*slot + 22];
            let group = n / 3;
            let within = n % 3;
            let expected = [
                if within == 0 { NOWHERE } else { records[n - 1].1 },
                if within == 2 { NOWHERE } else { records[n + 1].1 },
            ];
            assert_eq!(
                chain_pair(bytes, CHAIN_OFFSET),
                Some(expected),
                "record {n} (value {group}, {} of its group)",
                within + 1
            );
        }

        // And the index's ends are the chain's ends. Read off the same leaf
        // `a_duplicate_leafs_head_and_tail_are_the_first_and_last_inserted_record`
        // decodes, so the two halves of the format are checked against each
        // other rather than each against its own reading.
        let leaf = decode_index_page(
            &file[9 * 512..10 * 512],
            Shape {
                length: 4,
                duplicates: true,
            },
        )
        .expect("the real engine's own leaf");
        for (at, (key, head, _)) in leaf.entries.iter().enumerate() {
            let value = u32::from_le_bytes(key.clone().try_into().expect("4-byte key"));
            let group = value as usize;
            assert_eq!(*head, records[group * 3].1, "value {value}'s head");
            assert_eq!(leaf.tails[at], records[group * 3 + 2].1, "value {value}'s tail");
        }

        // `None` past the end of a short buffer -- the guard that stops this
        // from panicking on a record whose declared physical length turns
        // out to be too short to hold the chain a duplicate key's descriptor
        // promises.
        let short = &file[records[0].0..records[0].0 + 20];
        assert_eq!(chain_pair(short, CHAIN_OFFSET), None);
    }

    /// The count invariant, restated, exercised through the actual production
    /// entry point rather than `decode_index_page` alone: [`walk`] over
    /// `DUPKEY30.DAT`'s real root returns **10** entries for a file of **30**
    /// records, because it is one entry per distinct value. Before this
    /// stage, [`walk`] could not even reach this page -- `decode_index_page`
    /// refused any populated duplicate page outright.
    #[test]
    fn walking_the_real_engines_duplicate_tree_yields_ten_entries_not_thirty() {
        let file = dupkey30();
        let dir = crate::testing::scratch("pages-walk-dupkey30");
        let path = dir.join("DUPKEY30.DAT");
        std::fs::write(&path, &file).expect("copy the fixture into scratch");

        let layout = Layout {
            page: 512,
            physical: 22,
            pages: (file.len() / 512) as u32,
        };
        let shape = Shape {
            length: 4,
            duplicates: true,
        };

        let walked = walk(&path, layout, 9, shape).expect("the real engine's own tree");
        assert_eq!(walked.pages, vec![9], "one leaf, and it owns itself");
        assert_eq!(
            walked.entries.len(),
            10,
            "ten distinct values, not the file's thirty records"
        );
        let values: Vec<u32> = walked
            .entries
            .iter()
            .map(|e| u32::from_le_bytes(e.key.clone().try_into().expect("4-byte key")))
            .collect();
        assert_eq!(values, (0..10).rev().collect::<Vec<_>>(), "descending, 9 down to 0");
    }

    /// Interior duplicate entries, and a chain that spans two leaves.
    ///
    /// `DUPKEY30.DAT` is one shape every test above shares and this one does
    /// not: ten distinct values fit a single leaf, so every child slot in it
    /// is either `NOWHERE` or the zero placeholder -- never a **real** child
    /// page sitting right next to a `[head][tail]` pair, which is what an
    /// interior node of a bigger duplicate-keyed file (`WCCUSERS` at scale)
    /// would actually hold. Built by hand, the way
    /// `a_walk_returns_the_tree_in_key_order` is, rather than through
    /// `build_index` -- which still refuses this shape outright -- so a
    /// walker and a builder that happened to agree with each other could not
    /// both be wrong here in the same way.
    ///
    /// Root: one duplicate entry (key 20, head 3000, tail 3050), a real
    /// leftmost child (page 2) and rightmost child (page 3). Two leaves of
    /// two duplicate entries each.
    #[test]
    fn a_walk_over_a_multi_page_duplicate_tree_visits_every_entry_once_in_order() {
        let dir = crate::testing::scratch("pages-walk-duplicate-two-levels");
        let path = dir.join("DUPTREE.DAT");
        let layout = Layout {
            page: 512,
            physical: 16,
            pages: 4,
        };
        let shape = Shape {
            length: 2,
            duplicates: true,
        };
        let width = shape.entry_size();
        assert_eq!(width, 14, "a 2-byte duplicate key's entry width");

        let mut file = vec![0u8; 512 * 4];

        // Root, page 1: one entry (key 20, head 3000, tail 3050), leftmost
        // child 2, rightmost child 3.
        let root = 512;
        file[root..root + 6].copy_from_slice(&[0, 0, 1, 0, 0, 0]);
        file[root + 6..root + 8].copy_from_slice(&1u16.to_le_bytes());
        file[root + 8..root + 12].copy_from_slice(&to_long(3));
        file[root + 12..root + 16].copy_from_slice(&to_long(2));
        file[root + 16..root + 18].copy_from_slice(&20u16.to_le_bytes());
        file[root + 18..root + 22].copy_from_slice(&to_long(3000));
        file[root + 22..root + 26].copy_from_slice(&to_long(3050));
        file[root + 26..root + 30].copy_from_slice(&to_long(0)); // last entry, placeholder

        // Leaves, pages 2 and 3: two duplicate entries each.
        let leaves = [
            (2u32, [(10u16, 1000u32, 1005u32), (15, 1500, 1505)]),
            (3u32, [(25, 2500, 2505), (30, 3500, 3505)]),
        ];
        for (number, entries) in leaves {
            let at = 512 * number as usize;
            file[at..at + 6].copy_from_slice(&[0, 0, number as u8, 0, 0, 0]);
            file[at + 6..at + 8].copy_from_slice(&2u16.to_le_bytes());
            file[at + 8..at + 16].copy_from_slice(&[0xff; 8]); // a leaf: no children
            for (n, (key, head, tail)) in entries.iter().enumerate() {
                let e = at + 16 + n * width;
                file[e..e + 2].copy_from_slice(&key.to_le_bytes());
                file[e + 2..e + 6].copy_from_slice(&to_long(*head));
                file[e + 6..e + 10].copy_from_slice(&to_long(*tail));
                let child = if n + 1 == entries.len() { 0 } else { NOWHERE };
                file[e + 10..e + 14].copy_from_slice(&to_long(child));
            }
        }
        std::fs::write(&path, &file).expect("writes");

        let walked = walk(&path, layout, 1, shape).expect("walks a duplicate tree");
        assert_eq!(
            walked.entries,
            [
                (vec![10u8, 0], 1000u32, 1005u32),
                (vec![15, 0], 1500, 1505),
                (vec![20, 0], 3000, 3050),
                (vec![25, 0], 2500, 2505),
                (vec![30, 0], 3500, 3505),
            ]
            .map(|(key, head, tail)| Entry { key, head, tail }),
            "the root's own entry -- head 3000 -- sorts between its two \
             children, and every entry carries its own chain's far end"
        );
        assert_eq!(walked.pages, vec![1, 2, 3]);
    }

    /// An index entry is as wide as Btrieve says it is, duplicates included.
    ///
    /// The four duplicate-permitting keys are what this pins that nothing else
    /// did. All four files hold **zero records**, so every index fixture in this
    /// crate was drawn from a key that forbids duplicates, and a builder that
    /// never added the four bytes agreed with a decoder that never expected
    /// them. The first character written to `WCCUSERS` is where that stops
    /// being free.
    #[test]
    fn an_index_entry_is_as_wide_as_the_shipped_files_say() {
        for (page, length, duplicates, entry_size, _) in SHIPPED_KEY_SHAPES {
            let shape = Shape {
                length: *length,
                duplicates: *duplicates,
            };
            assert_eq!(
                shape.entry_size(),
                *entry_size,
                "a {length}-byte {} key in a {page}-byte page",
                if *duplicates { "duplicate" } else { "unique" }
            );
        }
    }

    /// A page holds as many entries as Btrieve says it does.
    ///
    /// Two independent errors used to live here and they pull in opposite
    /// directions, so a table with only one kind of key in it could have caught
    /// neither: dividing `page - 16` rather than `page - 12` under-counts by one
    /// on six of these shapes, and omitting the duplicate term over-counts by up
    /// to a third on the other four.
    #[test]
    fn a_page_holds_as_many_entries_as_the_shipped_files_say() {
        for (page, length, duplicates, _, per_page) in SHIPPED_KEY_SHAPES {
            let shape = Shape {
                length: *length,
                duplicates: *duplicates,
            };
            assert_eq!(
                shape.capacity(*page),
                *per_page,
                "a {length}-byte {} key in a {page}-byte page",
                if *duplicates { "duplicate" } else { "unique" }
            );
        }
    }

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

    /// `write_chain`'s bound against a page holding exactly one record --
    /// `WCCUSERS.VIR`'s own shape, measured in
    /// `crates/btrieve-engine/tests/engine.rs`'s
    /// `wccusers_vir_chain_offset_measurement`. Its key 2 names a chain
    /// offset of 2034, past `physical` (2006) but inside the page's real
    /// usable end (`page - HEADER` = 2042): nothing else shares this page,
    /// so the real engine writes there and this host must accept it too.
    #[test]
    fn a_chain_fits_the_pages_usable_end_when_it_is_the_only_record_on_the_page() {
        let dir = crate::testing::scratch("pages-write-chain-last-slot");
        let path = dir.join("SCRATCH.DAT");
        std::fs::write(&path, [0u8; 8]).expect("placeholder file");
        let layout = Layout {
            page: 2048,
            physical: 2006,
            pages: 1,
        };
        assert_eq!(layout.per_page(), 1, "one 2006-byte record fits a 2048-byte page");
        let position = layout.position(0, 0);

        write_chain(&path, layout, position, 2034, [7, 9]).expect(
            "offset 2034 exceeds physical (2006) but fits this page's usable \
             end (2042) -- WCCUSERS.VIR's own shape",
        );

        let bytes = std::fs::read(&path).expect("read back");
        assert_eq!(
            chain_pair(&bytes[position as usize..], 2034),
            Some([7, 9]),
            "the chain landed at the declared offset"
        );
    }

    /// The bound above must not relax for a page that genuinely holds more
    /// than one record: writing past `physical` there spills into the next
    /// slot's own bytes, which is exactly the corruption `write_chain`
    /// exists to refuse.
    #[test]
    fn a_chain_past_physical_is_still_refused_when_a_neighbour_shares_the_page() {
        let dir = crate::testing::scratch("pages-write-chain-not-last-slot");
        let path = seed(&dir);
        let layout = Layout {
            page: 64,
            physical: 20,
            pages: 5,
        };
        assert_eq!(layout.per_page(), 2, "two 20-byte records fit a 58-byte usable page");
        let position = layout.position(4, 0); // slot 0 of 2 -- not the last slot

        let e = write_chain(&path, layout, position, 15, [7, 9])
            .expect_err("offset 15 + 8 = 23 spills 3 bytes into slot 1");
        assert!(e.contains("15") && e.contains("20"), "{e}");
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

        let built = build_index(layout, &rows(&entries), unique(2)).expect("two entries fit easily");
        assert_eq!(built.nodes.len(), 1, "these entries fit one page");
        let page = &built.nodes[built.root].image;

        assert_eq!(page.len(), 64);

        let header = Header::decode(&page[..6]);
        assert!(!header.data, "an index page is not a data page");
        assert_eq!(
            u16::from_le_bytes([page[6], page[7]]),
            2,
            "the entry count"
        );
        assert_eq!(long(&page[8..12]), NOWHERE, "no rightmost child -- a leaf has none");
        assert_eq!(long(&page[12..16]), NOWHERE, "no leftmost child -- a leaf has none");

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
    ///
    /// **The load-bearing one.** Pinned against bytes measured off a real
    /// file rather than derived from this crate's own encoder, so a decoder
    /// and encoder that agree with each other but are wrong the same way
    /// still cannot pass this.
    #[test]
    fn a_built_leaf_matches_wccrace_dats_measured_last_two_entries() {
        let layout = wccrace_index_layout();
        let mut entries: Vec<(Vec<u8>, u32)> =
            (0u16..11).map(|n| (n.to_le_bytes().to_vec(), u32::from(n))).collect();
        entries.push((0x000cu16.to_le_bytes().to_vec(), 0x0000_0980));
        entries.push((0x000du16.to_le_bytes().to_vec(), 0x0000_0a06));
        assert_eq!(entries.len(), 13);

        let built = build_index(layout, &rows(&entries), unique(2)).expect("13 entries fit one leaf");
        assert_eq!(built.nodes.len(), 1, "these entries fit one page");
        let page = &built.nodes[built.root].image;

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
        let built =
            build_index(layout, &[], unique(2)).expect("an empty key still has a root page");
        assert_eq!(built.nodes.len(), 1, "these entries fit one page");
        let page = &built.nodes[built.root].image;
        assert_eq!(u16::from_le_bytes([page[6], page[7]]), 0);
    }

    /// **What this host used to refuse, it now builds.**
    ///
    /// A 64-byte page holds `(64 - 12) / 10 = 5` ten-byte entries, so six of
    /// them split into two leaves with the entry between them promoted -- three
    /// nodes, and all six entries still present exactly once.
    ///
    /// This test is the retired refusal, kept pointing the other way, and it
    /// pairs with `a_page_at_the_boundary_still_fits` on either side of the
    /// capacity boundary. **Both moved by one when the capacity was corrected**
    /// from `page - 16` to the engine's `page - 12`; a pair that straddles a
    /// boundary is only worth having if it straddles the real one.
    #[test]
    fn entries_that_do_not_fit_one_page_become_a_tree() {
        let layout = index_layout();
        let entries: Vec<(Vec<u8>, u32)> =
            (0..6u32).map(|n| (n.to_le_bytes()[..2].to_vec(), n)).collect();

        let built = build_index(layout, &rows(&entries), unique(2)).expect("what index_pages refused");

        assert_eq!(built.nodes.len(), 3, "two leaves and a root");
        assert_eq!(
            built.nodes[built.root].entries.len(),
            1,
            "one separator between two leaves"
        );
        let total: usize = built.nodes.iter().map(|n| n.entries.len()).sum();
        assert_eq!(total, 6, "every entry is in exactly one node");
    }

    /// The full side of the boundary, and the full-leaf shape with it.
    ///
    /// Five ten-byte entries are exactly a 64-byte page's capacity, and the
    /// fifth one's child slot would end at byte 66. Btrieve omits it and so
    /// does this host -- the same shape as `WCCSPELS.VIR` page 1, which is the
    /// shipped sample of a leaf filled exactly. Before the capacity was
    /// corrected this host packed one entry short and could never produce it,
    /// so the tolerance `decode_index_page` has always had for it was never
    /// exercised against anything this host wrote.
    #[test]
    fn a_page_at_the_boundary_still_fits() {
        let layout = index_layout();
        let entries: Vec<(Vec<u8>, u32)> =
            (0..5u32).map(|n| (n.to_le_bytes()[..2].to_vec(), n)).collect();

        let built =
            build_index(layout, &rows(&entries), unique(2)).expect("five entries need exactly 62");
        assert_eq!(built.nodes.len(), 1, "these entries fit one page");
        let page = &built.nodes[built.root].image;
        assert_eq!(page.len(), usize::from(layout.page));

        // The page decodes back to all five, which is what makes the omitted
        // trailing child a shape rather than a truncation.
        let decoded = decode_index_page(page, unique(2)).expect("a full leaf is not a corrupt one");
        assert_eq!(decoded.entries.len(), 5);
        assert_eq!(decoded.entries[4].0, vec![4u8, 0], "the last entry survives");
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

        let decoded = decode_index_page(&page, unique(4)).expect("a well-formed page");
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

        let decoded = decode_index_page(&page, unique(2)).expect("a well-formed page");
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

        let decoded = decode_index_page(&page, unique(4)).expect("a well-formed page");
        assert!(decoded.leaf(), "page 0 can never be a child, so zero means none");
        assert!(decoded.entries.is_empty());
    }

    /// The same virgin shape, but for a duplicate-permitting key: an empty
    /// leaf decodes the same regardless of `Shape::duplicates`, because there
    /// are no entries to put the four extra bytes in. This is the read-side
    /// half of what `a_duplicate_key_is_refused_only_once_it_has_something_to_index`
    /// pins for `build_index` -- all four shipped duplicate-key files are
    /// exactly this page, so a decoder that could not read it would have
    /// broken `Block::reindex` for `WCCUSERS`, `WCCGANGS`, `WCCITOWN` and
    /// `WCCBANKS` the moment this stage's duplicate handling landed, not just
    /// once one of them gained a record.
    #[test]
    fn an_empty_duplicate_leaf_decodes_with_no_tails_at_all() {
        let mut page = vec![0u8; 2048];
        page[..16].copy_from_slice(&[
            0x00, 0x00, 0x01, 0x00, // page 1
            0x00, 0x00, //             no stamp
            0x00, 0x00, //             no entries
            0xff, 0xff, 0xff, 0xff, // no rightmost child
            0x00, 0x00, 0x00, 0x00, // no leftmost child -- as zero, not NOWHERE
        ]);
        let duplicate = Shape {
            length: 4,
            duplicates: true,
        };

        let decoded = decode_index_page(&page, duplicate).expect("an empty duplicate leaf");
        assert!(decoded.leaf());
        assert!(decoded.entries.is_empty());
        assert!(decoded.tails.is_empty(), "nothing to carry a tail for");
    }

    /// A count that runs off the end of the page is a refusal, not a panic.
    /// This is the guard that stops a corrupt or misidentified page from
    /// indexing out of bounds during a walk.
    #[test]
    fn a_count_that_does_not_fit_the_page_is_refused() {
        let mut page = vec![0u8; 512];
        page[6..8].copy_from_slice(&500u16.to_le_bytes());
        let e = decode_index_page(&page, unique(2)).expect_err("500 entries do not fit 512 bytes");
        assert!(e.contains("500"), "{e}");
    }

    /// The same guard, sized for a **duplicate** key's wider entry: this is
    /// the boundary a formula that forgot the tail field would get past.
    ///
    /// One duplicate entry of a 2-byte key needs `INDEX_HEADER + (width - 4)`
    /// = `16 + 10` = 26 bytes -- the last entry may omit its child, but not
    /// its tail. A page of 24 bytes is short by exactly the tail field's
    /// contribution a formula copied from the unique case (`key_length + 4`
    /// = 6, needing only 22) would not have noticed. Refused here means the
    /// reader stops before it would have sliced `page[22..26]` on a
    /// 24-byte buffer and panicked instead.
    #[test]
    fn a_duplicate_entrys_missing_tail_is_refused_not_read_past_the_page() {
        let duplicate = Shape {
            length: 2,
            duplicates: true,
        };
        assert_eq!(duplicate.entry_size(), 14);

        let mut page = vec![0u8; 24];
        page[6..8].copy_from_slice(&1u16.to_le_bytes());
        let e = decode_index_page(&page, duplicate)
            .expect_err("26 bytes needed for one duplicate entry's key, head and tail; 24 given");
        assert!(e.contains("26") && e.contains("24"), "{e}");
    }

    /// **A leaf that fills its page exactly is four bytes short, and legal.**
    ///
    /// Measured off `WCCSPELS.VIR` page 1, the only page in all eleven shipped
    /// files that does this. Fifty entries of ten bytes declared in a 512-byte
    /// page needs 516 — but the last entry's child field is a placeholder
    /// nothing reads, so Btrieve does not write it, and `16 + 49 * 10 + 6`
    /// is 512 on the nose.
    ///
    /// A decoder that demands the full width for the last entry refuses a file
    /// Btrieve itself wrote.
    #[test]
    fn a_leaf_that_fills_its_page_exactly_may_omit_the_last_child() {
        let mut page = vec![0u8; 512];
        page[..16].copy_from_slice(&[
            0x00, 0x00, 0x01, 0x00, // page 1
            0x30, 0x05, //             stamp 0x0530, data bit clear
            0x32, 0x00, //             50 entries -- 16 + 50*10 = 516 > 512
            0xff, 0xff, 0xff, 0xff, //
            0xff, 0xff, 0xff, 0xff, // a leaf
        ]);
        // The last entry, at offset 506, has six bytes and no more.
        page[506..508].copy_from_slice(&710u16.to_le_bytes());
        page[508..512].copy_from_slice(&to_long(193_542));

        let decoded =
            decode_index_page(&page, unique(2)).expect("a full leaf is not a corrupt one");
        assert!(decoded.leaf());
        assert_eq!(decoded.entries.len(), 50);
        assert_eq!(
            decoded.entries[49],
            (vec![0xc6, 0x02], 193_542, 0),
            "the absent child reads as the placeholder it would have held"
        );
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

        let walk = walk(&path, layout, 1, unique(2)).expect("walks");
        assert_eq!(
            walk.entries,
            rows(&[
                (vec![10, 0], 1000),
                (vec![15, 0], 1500),
                (vec![20, 0], 3000),
                (vec![25, 0], 2500),
                (vec![30, 0], 3000),
            ]),
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

        let e = walk(&path, layout, 1, unique(2)).expect_err("a self-referential root");
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

        let walk = walk(&path, layout, 1, unique(2)).expect("walks");
        assert!(walk.entries.is_empty());
        assert_eq!(walk.pages, vec![1], "the root itself is still owned");
    }

    /// Entries that fit one page still build one page, byte for byte the leaf
    /// `index_pages` built before there was a tree -- `index_pages` is gone
    /// (Task 9), so the comparison is against a literal instead.
    ///
    /// This is the regression guard for `WCCRACE.DAT` and `WCCCLASS.DAT`, whose
    /// rebuilt root pages are byte-identical to the shipped ones
    /// (`a_rebuilt_index_holds_what_the_files_own_index_holds`). A builder that
    /// changed the degenerate case would break that silently.
    #[test]
    fn a_tree_that_fits_one_page_is_the_page_index_pages_built() {
        let layout = Layout { page: 512, physical: 16, pages: 8 };
        let entries: Vec<(Vec<u8>, u32)> =
            (1u16..=4).map(|k| (k.to_le_bytes().to_vec(), u32::from(k) * 100)).collect();

        let built = build_index(layout, &rows(&entries), unique(2)).expect("four entries fit");
        assert_eq!(built.nodes.len(), 1, "one page, so one node");
        assert_eq!(built.root, 0, "the root is the only node");

        // A leaf's own shape: six bytes of header, then a count of 4, then
        // both child slots NOWHERE (a leaf has none), then the four entries --
        // key, position high-word-first, and NOWHERE except the last entry's
        // tail, which is the zero placeholder every node's last entry carries.
        let mut expected = vec![0u8; 512];
        expected[6..8].copy_from_slice(&4u16.to_le_bytes());
        expected[8..12].copy_from_slice(&to_long(NOWHERE));
        expected[12..16].copy_from_slice(&to_long(NOWHERE));
        for (n, (key, position)) in entries.iter().enumerate() {
            let at = INDEX_HEADER + n * 10;
            expected[at..at + 2].copy_from_slice(key);
            expected[at + 2..at + 6].copy_from_slice(&to_long(*position));
            let last = n + 1 == entries.len();
            expected[at + 6..at + 10].copy_from_slice(&to_long(if last { 0 } else { NOWHERE }));
        }

        assert_eq!(built.nodes[0].image, expected, "the one-page case must not have moved");
    }

    /// A duplicate key's tree, built across more than one page, and walked
    /// back entry for entry -- **tails included**.
    ///
    /// The one-leaf case above cannot see where an interior node puts its
    /// children, because a one-leaf tree has none. A duplicate entry is
    /// `[key][head][tail][child]`, so the child is twelve bytes past the key
    /// rather than four, and [`number_pages`] spelled that offset as
    /// `length + 4` -- which for this shape writes each child page into the
    /// entry's `tail` and leaves the real child slot empty. Nothing could
    /// reach it while `build_index` refused the shape.
    ///
    /// Round-tripped through a real file rather than through
    /// [`decode_index_page`] alone: [`walk`] descends children the way the
    /// engine does, so a tree whose children landed in the wrong field does
    /// not walk at all.
    #[test]
    fn a_duplicate_tree_across_pages_walks_back_with_every_head_and_tail() {
        let shape = Shape {
            length: 2,
            duplicates: true,
        };
        // (64 - 12) / (2 + 12) = 3 entries per page.
        assert_eq!(shape.capacity(64), 3);
        let layout = Layout {
            page: 64,
            physical: 16,
            pages: 16,
        };

        // Eleven values, each carried by two records a hundred apart, which
        // makes every head and tail distinct and distinguishable from the key.
        let entries: Vec<Entry> = (1u16..=11)
            .map(|k| Entry {
                key: k.to_le_bytes().to_vec(),
                head: u32::from(k) * 1000,
                tail: u32::from(k) * 1000 + 100,
            })
            .collect();

        let built = build_index(layout, &entries, shape).expect("eleven values, several pages");
        assert!(built.nodes.len() > 1, "eleven entries do not fit a page of three");

        let dir = crate::testing::scratch("pages-duplicate-tree-round-trip");
        let path = dir.join("DUPTREE.DAT");
        let numbers: Vec<u32> = (1..=built.nodes.len() as u32).collect();
        let mut file = vec![0u8; usize::from(layout.page) * (built.nodes.len() + 1)];
        for (number, image) in number_pages(&built, &numbers).expect("numbered") {
            let at = number as usize * usize::from(layout.page);
            file[at..at + usize::from(layout.page)].copy_from_slice(&image);
        }
        std::fs::write(&path, &file).expect("writes");

        let layout = Layout {
            pages: (built.nodes.len() + 1) as u32,
            ..layout
        };
        let walked = walk(&path, layout, 1, shape).expect("walks the tree it just wrote");
        assert_eq!(
            walked.entries, entries,
            "every value, in order, with both ends of its chain"
        );
        assert_eq!(walked.pages.len(), built.nodes.len(), "every node reached once");
    }

    /// Two levels, and the shape is the one the format uses.
    ///
    /// Nine entries into pages holding four. The split needs
    /// `ceil((9 + 1) / (4 + 1)) = 2` leaves, which leaves `9 - 1 = 8` entries to
    /// spread over them — four each — and promotes the one that falls between,
    /// key 5. Three nodes: two leaves and a root holding the single separator.
    #[test]
    fn a_tree_too_big_for_one_page_promotes_separators() {
        let layout = Layout { page: 64, physical: 16, pages: 16 };
        // (64 - 16) / (2 + 8) = 4 entries per page.
        let entries: Vec<(Vec<u8>, u32)> =
            (1u16..=9).map(|k| (k.to_le_bytes().to_vec(), u32::from(k) * 100)).collect();

        let built = build_index(layout, &rows(&entries), unique(2)).expect("nine entries, three pages");
        assert_eq!(built.nodes.len(), 3, "two leaves and a root");

        let root = &built.nodes[built.root];
        assert_eq!(root.entries.len(), 1, "one separator between two leaves");
        assert_eq!(root.children.len(), 2);
        assert_eq!(root.entries[0].key, 5u16.to_le_bytes().to_vec(), "the middle key");

        let left = &built.nodes[root.children[0]];
        let right = &built.nodes[root.children[1]];
        assert_eq!(left.entries.len(), 4);
        assert_eq!(right.entries.len(), 4);
        assert!(left.children.is_empty(), "a leaf has no children");

        // The root's children come from the **structure**, not from its bytes.
        // `build_index` leaves every child slot empty and `number_pages` fills
        // them, so this image is not yet a page and `IndexPage::leaf()` is not
        // a question it can answer -- that predicate is about a page in a file.
        // `numbering_puts_the_root_first_and_resolves_every_child` asks it at
        // the stage where it means something.
        assert_eq!(root.children, vec![0, 1], "the two leaves, in push order");

        let decoded = decode_index_page(&root.image, unique(2)).expect("decodes");
        assert_eq!(decoded.entries.len(), 1);
        assert_eq!(decoded.leftmost, NOWHERE, "empty until number_pages fills it");
        assert_eq!(decoded.rightmost, NOWHERE, "empty until number_pages fills it");
        assert_eq!(decoded.entries[0].2, 0, "the last entry's slot is a placeholder");
    }

    /// Three levels, because two of the files the update applier writes are
    /// three levels deep in the shipped data.
    #[test]
    fn a_tree_recurses_past_two_levels() {
        let layout = Layout { page: 64, physical: 16, pages: 64 };
        let entries: Vec<(Vec<u8>, u32)> =
            (1u16..=200).map(|k| (k.to_le_bytes().to_vec(), u32::from(k) * 100)).collect();

        let built = build_index(layout, &rows(&entries), unique(2)).expect("200 entries");
        let mut depth = 0usize;
        let mut at = built.root;
        while !built.nodes[at].children.is_empty() {
            depth += 1;
            at = built.nodes[at].children[0];
        }
        // 200 entries into pages of four: 41 leaves holding 160, then 9 nodes
        // holding 32, then 2 holding 7, then a root holding 1 -- four levels,
        // three edges from root to leaf. The assertion is `>= 2` because what
        // this test is for is that the builder recurses at all, not that it
        // lands on one particular shape.
        assert!(
            depth >= 2,
            "200 entries into pages of 5 needs more than two levels, got {}",
            depth + 1
        );

        let total: usize = built.nodes.iter().map(|n| n.entries.len()).sum();
        assert_eq!(total, 200, "every entry is in exactly one node");
    }

    /// A key so wide that no entry fits a page is a refusal, not a divide by
    /// zero.
    #[test]
    fn a_key_too_wide_for_a_page_is_refused() {
        let layout = Layout { page: 32, physical: 16, pages: 4 };
        let e = build_index(layout, &rows(&[(vec![0u8; 40], 1)]), unique(40))
            .expect_err("40 + 8 > 32 - 12");
        assert!(e.contains("does not fit"), "{e}");
    }

    /// Numbering keeps the root where it was, and rewrites every child slot
    /// from a node index to a page number.
    ///
    /// The root keeping its number is what lets `Block::reindex` leave the file
    /// control record's `KEY_ROOT` alone: one fewer shared field written, on a
    /// format where every extra written field is another way to corrupt a file
    /// a real Btrieve will open.
    #[test]
    fn numbering_puts_the_root_first_and_resolves_every_child() {
        let layout = Layout { page: 64, physical: 16, pages: 16 };
        let entries: Vec<(Vec<u8>, u32)> =
            (1u16..=9).map(|k| (k.to_le_bytes().to_vec(), u32::from(k) * 100)).collect();
        let built = build_index(layout, &rows(&entries), unique(2)).expect("three nodes");

        let placed = number_pages(&built, &[7, 3, 5]).expect("three numbers for three nodes");
        assert_eq!(placed[0].0, 7, "the root takes the first number given");

        let root = decode_index_page(&placed[0].1, unique(2)).expect("decodes");
        assert_eq!(root.number, 7, "and the header says so");
        assert!(
            !root.leaf(),
            "numbering is what turns a built node into a page, and only now is \
             leaf() a question worth asking of it"
        );
        let kids = std::collections::HashSet::from([root.leftmost, root.rightmost]);
        assert_eq!(
            kids,
            std::collections::HashSet::from([3, 5]),
            "both children resolved to real pages"
        );
        assert!(!kids.contains(&0), "no node index survived numbering");
    }

    /// Fewer numbers than nodes is a refusal. `Block::reindex` allocates the
    /// shortfall before calling; this is the guard that stops a miscount from
    /// writing a tree with a dangling child.
    #[test]
    fn numbering_refuses_to_place_more_nodes_than_it_has_pages_for() {
        let layout = Layout { page: 64, physical: 16, pages: 16 };
        let entries: Vec<(Vec<u8>, u32)> =
            (1u16..=9).map(|k| (k.to_le_bytes().to_vec(), u32::from(k) * 100)).collect();
        let built = build_index(layout, &rows(&entries), unique(2)).expect("three nodes");

        let e = number_pages(&built, &[7, 3]).expect_err("three nodes, two pages");
        assert!(e.contains('3') && e.contains('2'), "{e}");
    }

    /// Growth appends a zeroed page and says which number it got.
    ///
    /// The file control record is **not** touched here -- `Block::reindex`
    /// already holds the first page in memory and writes it once at the end,
    /// and two writers of the same bytes is how a file control record gets
    /// half-updated.
    #[test]
    fn appending_a_page_grows_the_file_by_exactly_one() {
        let dir = crate::testing::scratch("pages-append");
        let path = dir.join("GROW.DAT");
        std::fs::write(&path, vec![0u8; 512 * 3]).expect("writes");
        let layout = Layout { page: 512, physical: 16, pages: 3 };

        let number = append_page(&path, layout).expect("appends");
        assert_eq!(number, 3, "the next page after 0, 1 and 2");
        assert_eq!(
            std::fs::metadata(&path).expect("stat").len(),
            512 * 4,
            "exactly one page longer"
        );
    }
}
