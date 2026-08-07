//! Btrieve files: the geometry in a file's first page, and the blocks a module
//! names them by.
//!
//! A MajorBBS module keeps everything that is not text in Btrieve: MajorMUD's
//! items, spells, monsters, rooms, shops and characters are eighteen files
//! shipped beside the module. `BTVSTF.H` is the interface it reaches them
//! through and `PLBTVSTF.C` is Galacticomm's own implementation of it, which
//! settles most of what this file has to reproduce.
//!
//! The on-disk format is not Galacticomm's -- it is Btrieve's, and the real
//! host reached it through `INT 0x7B` into a TSR nobody has. So the format is
//! read here directly, and only as far as a step needs.
//!
//! # Read directly, not converted
//!
//! MBBSEmu converts each file into a SQLite database on first open. That is a
//! reasonable choice for a long-running emulator and the wrong one here: it
//! writes a second file that has to be kept in step with the first, and it
//! makes "give me the next record in key order" go through a query planner to
//! answer what a B-tree already knows. The largest file MajorMUD ships is 77 MB
//! and opening one reads its first page.
//!
//! # What is read, and what is not
//!
//! Initialisation opens sixteen files, counts the records in one, and never
//! reads a record -- so this reads the file control record and stops. No key
//! definitions, no page walking, no records. Everything below is a field of the
//! FCR, verified against all eighteen files MajorMUD ships by
//! `crates/mbbs/tests/btrieve.rs`.

pub mod keys;
pub mod pages;
pub mod records;

use std::fmt;
use std::path::{Path, PathBuf};

use mbbs16::{FarPtr, Machine};

pub use keys::Key;
pub use records::{Record, Records};

/// How much of the first page this host reads.
///
/// The file control record *is* the first page, and the smallest page a Btrieve
/// file has is 512 bytes -- so every field read here is inside the first 512 of
/// any file, whatever its page length.
const FCR: usize = 512;

/// Where each field of the file control record lives.
///
/// Byte offsets rather than a `#[repr(C)]` struct: the record has hundreds of
/// bytes this host has no reading for, and a struct would have to name them all
/// to reach the eight that matter.
mod at {
    /// Page length, in bytes.
    pub const PAGE: usize = 0x08;
    /// How many keys the file is indexed by.
    pub const KEYS: usize = 0x14;
    /// Logical record length -- the bytes a module sees.
    pub const RECLEN: usize = 0x16;
    /// Physical record length -- the logical length plus Btrieve's own padding.
    pub const PHYSICAL: usize = 0x18;
    /// Record count, **high half**.
    pub const RECORDS_HIGH: usize = 0x1a;
    /// Record count, **low half**.
    pub const RECORDS_LOW: usize = 0x1c;
    /// `0xff` when the file holds variable-length records.
    pub const VARIABLE_MARK: usize = 0x38;
    /// User flags. Bit 0 is variable-length records.
    pub const USRFLGS: usize = 0x106;
}

/// Which Btrieve wrote the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// Btrieve 5.x: the first four bytes are zero and byte 7 is the version.
    /// Seventeen of the eighteen files MajorMUD ships.
    V5,

    /// Btrieve 6.x: the first two bytes are `FC`. Exactly one file --
    /// `NEWMP001.VIR`, the virgin map template, which the module never opens.
    ///
    /// Its file control record reads correctly at the v5 offsets, which is why
    /// it is accepted rather than refused. **That is only established for the
    /// fields below**; a v6 file's *pages* are not laid out like a v5 file's,
    /// so whatever walks pages later must not assume they are.
    V6,
}

/// A Btrieve file's shape, out of its file control record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    pub version: Version,

    /// Bytes per page. Always a multiple of 512.
    pub page: u16,

    /// How many keys the file is indexed by. The definitions themselves are not
    /// read yet -- see [`Block::key`].
    pub keys: u16,

    /// Logical record length: what a module's `struct` is meant to match.
    pub reclen: u16,

    /// Physical record length: the logical length plus Btrieve's padding, and
    /// what a page's records are actually spaced by.
    pub physical: u16,

    /// How many records the file holds.
    pub records: u32,

    /// How many pages the file is, which is its size divided by [`page`](Self::page).
    pub pages: u32,

    /// Whether records are variable-length. `WCCTEXT` is; the other seventeen
    /// are not.
    pub variable: bool,
}

/// A file the host will not read as Btrieve, and the reason.
///
/// One shape rather than a variant per check, because what a caller does with
/// it is the same in every case -- stop the module and say this sentence. The
/// file is named separately from the reason so that the name cannot be left out
/// of the message by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtvError {
    pub file: String,
    pub why: String,
}

impl fmt::Display for BtvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.file, self.why)
    }
}

impl std::error::Error for BtvError {}

impl Geometry {
    /// Read a file's geometry from its first page.
    ///
    /// `name` is what the module called the file, and is what any refusal is
    /// named by.
    ///
    /// # Errors
    ///
    /// If the file cannot be read, is not Btrieve, or describes a shape that
    /// contradicts itself. A file whose header is wrong is refused here rather
    /// than read: every field below sizes something, and a wrong page length
    /// silently turns record 400 into whatever bytes are at the wrong offset.
    pub fn read(name: &str, path: &Path) -> Result<Self, BtvError> {
        let fail = |why: String| BtvError {
            file: name.to_owned(),
            why,
        };

        let size = std::fs::metadata(path)
            .map_err(|e| fail(format!("{}: {e}", path.display())))?
            .len();
        let bytes = read_head(path, FCR).map_err(|e| fail(format!("{}: {e}", path.display())))?;
        if bytes.len() < FCR {
            return Err(fail(format!(
                "{size} bytes, and a Btrieve file's first page is at least {FCR}"
            )));
        }

        let version = version(&bytes).ok_or_else(|| {
            fail(format!(
                "starts {:02x?}, which is neither a v5 file control record \
                 (four zero bytes) nor a v6 one (\"FC\")",
                &bytes[..4]
            ))
        })?;

        let word = |offset: usize| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let page = word(at::PAGE);
        let reclen = word(at::RECLEN);
        let physical = word(at::PHYSICAL);

        // Every check below is a *self*-consistency one: a number the file gives
        // twice, or gives once and can be checked against its own size. Nothing
        // is refused for being unusual, because a file none of the eighteen
        // resembles is not necessarily one this cannot read.
        if page < 512 || page % 512 != 0 {
            return Err(fail(format!(
                "a page length of {page}, which is not a multiple of 512"
            )));
        }
        if size % u64::from(page) != 0 {
            return Err(fail(format!(
                "{size} bytes, which is not a whole number of {page}-byte pages"
            )));
        }
        if reclen == 0 {
            return Err(fail("a record length of zero".to_owned()));
        }
        if physical < reclen {
            return Err(fail(format!(
                "a physical record length of {physical}, shorter than the \
                 {reclen}-byte record it holds"
            )));
        }
        if u32::from(physical) > u32::from(page) {
            return Err(fail(format!(
                "a {physical}-byte record in a {page}-byte page"
            )));
        }

        // Two independent witnesses to the same fact, and they are checked
        // against each other because either alone could be something else: bit
        // 0 of the user flags, and the `0xff` marker. All eighteen files agree,
        // and `WCCTEXT` is the one where both say yes.
        let variable = word(at::USRFLGS) & 1 != 0;
        if variable != (bytes[at::VARIABLE_MARK] == 0xff) {
            return Err(fail(format!(
                "user flags say variable-length records is {variable}, and the \
                 marker at {:#x} says {}",
                at::VARIABLE_MARK,
                !variable
            )));
        }

        Ok(Self {
            version,
            page,
            keys: word(at::KEYS),
            reclen,
            physical,
            // RECORDS_HIGH and RECORDS_LOW are two separate fields (see
            // `pages::write_record`'s doc comment on why `to_long` cannot
            // write them in one store), but they sit adjacent, so the range
            // between them is the same four-byte, high-word-first quantity
            // `pages::long` decodes everywhere else.
            records: pages::long(&bytes[at::RECORDS_HIGH..at::RECORDS_LOW + 2]),
            pages: (size / u64::from(page)) as u32,
            variable,
        })
    }
}

/// Which Btrieve wrote this, or `None` if nothing did.
fn version(bytes: &[u8]) -> Option<Version> {
    if &bytes[..2] == b"FC" {
        return Some(Version::V6);
    }
    // A v5 file control record opens with four zero bytes and carries its
    // version in byte 7 -- 4 in every file MajorMUD ships. 3, 4 and 5 are the
    // codes MBBSEmu accepts, which is the only independent transcription there
    // is; a file outside them is refused rather than read on the assumption
    // that the fields did not move.
    if bytes[..4] == [0, 0, 0, 0] && bytes[6] == 0 && (3..=5).contains(&bytes[7]) {
        return Some(Version::V5);
    }
    None
}

/// The first `len` bytes of a file, or fewer if it is shorter.
///
/// `WCCUPDAT.DAT` is 77 MB and `WCCMP001.VIR` 43. Reading a header is reading a
/// header.
fn read_head(path: &Path, len: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;

    let mut out = vec![0u8; len];
    let mut file = std::fs::File::open(path)?;
    let mut got = 0;
    while got < len {
        match file.read(&mut out[got..])? {
            0 => break,
            n => got += n,
        }
    }
    out.truncate(got);
    Ok(out)
}

/// Bytes of `struct btvblk`, and where each field of it sits.
///
/// `BTVSTF.H:17`, with the `PHARLAP` fields -- which `WCCMMUD.DLL` is built
/// for, because a server module targets the 286|DOS-Extender rather than DOS:
///
/// Each field is written as the one before it plus that one's width, so the
/// struct's total size cannot drift from the offsets inside it. The absolute
/// numbers are pinned by [`tests::the_block_is_laid_out_the_way_btvstf_h_declares_it`].
mod field {
    use super::SEGMAX;

    /// Btrieve's own 128-byte position block. Opaque to everybody, including
    /// the real host, which only ever handed its address to the TSR.
    pub const POSBLK: u16 = 0;
    pub const FILNAM: u16 = POSBLK + 128;
    pub const RECLEN: u16 = FILNAM + 4;
    pub const KEY: u16 = RECLEN + 2;
    pub const DATA: u16 = KEY + 4;
    pub const LASTKN: u16 = DATA + 4;
    pub const KEYLNS: u16 = LASTKN + 2;
    /// Real-mode segment of the block, for the DOS extender. Nothing here has a
    /// real mode to have a segment in, so it stays zero.
    pub const REALSEG: u16 = KEYLNS + SEGMAX * 2;
    /// Real-mode segment of the key buffer. Zero, for the same reason.
    pub const KEYSEG: u16 = REALSEG + 2;
    /// The whole struct.
    pub const SIZE: u16 = KEYSEG + 2;
}

/// `BTVSTF.H:13` -- key segments per file, which sizes `keylns`.
const SEGMAX: u16 = 24;

/// `BTVSTF.H:14` -- how deep `setbtv`'s stack is.
const BBSTSZ: usize = 10;

/// Where a file is positioned: the cursor Btrieve keeps in its position block.
///
/// Not in the module's memory. Btrieve kept it in `posblk`, which is 128 opaque
/// bytes the real host only ever handed back to the TSR -- so a module cannot
/// read it, cannot corrupt it, and has no way to notice that this host keeps it
/// somewhere else entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cursor {
    /// Nothing has positioned the file yet, and `absbtv` has nothing to report.
    Nowhere,

    /// At a place in a key's order: what the query and acquire families leave
    /// behind, and what `qnxbtv` steps along.
    Ordered { key: u16, at: usize },

    /// At a place in physical order: what the step family leaves behind.
    Physical { at: usize },
}

/// One open Btrieve file.
pub struct Block {
    /// What the module named it, for error messages.
    name: String,

    /// Where it is on disk, so records can be read without opening it again.
    path: PathBuf,

    /// The file's own shape.
    geometry: Geometry,

    /// What the file is indexed by.
    keys: Vec<Key>,

    /// The `struct btvblk` the module was handed. Also this block's identity:
    /// `setbtv`, `cntrbtv` and `clsbtv` name it and nothing else does.
    block: FarPtr,

    /// What the module said its records are -- `opnbtv`'s `maxlen`, which sizes
    /// `data` and is what `bb->reclen` holds. **Not** the file's record length:
    /// `PLBTVSTF.C:150` stores the module's number, and the two disagreeing is
    /// a thing worth being able to see rather than to silence.
    maxlen: u16,

    /// The record buffer, `maxlen` bytes of the module's heap.
    data: FarPtr,

    /// The key buffer, `clckln()` bytes of the module's heap. What a search
    /// value is copied into, and what a `Get Key` operation leaves the found
    /// key in.
    key: FarPtr,

    /// The records, read the first time something asks for one.
    ///
    /// **Lazily**, because `opnbtv` is not a read: initialisation opens fifteen
    /// files totalling 55 MB and then queries one of them. Loading at open time
    /// would make every module pay for every file it merely holds a handle to.
    records: Option<Records>,

    /// Where the file is positioned.
    cursor: Cursor,

    /// Whether a write has happened since the index pages last agreed with the
    /// data. Set by [`Self::insert`] and [`Self::update`], cleared by
    /// [`Self::reindex`].
    ///
    /// The host never reads an index page -- `records()` page-walks and sorts
    /// -- so nothing *needs* this flag to answer a module correctly. It exists
    /// for the file itself: a real Btrieve or MBBSEmu could open it later, and
    /// `clsbtv` calls `reindex` exactly when this is true so that a file
    /// leaving this host's reach never leaves with a stale index behind it.
    dirty: bool,
}

/// Make `bytes` exactly `reclen` long: padded with zero if shorter, cut off
/// if longer.
///
/// `records::walk` always stores exactly `geometry.reclen` bytes for a
/// record, because that is all it reads out of a slot. A model that kept a
/// caller's buffer at whatever length the caller handed over -- `dinsbtv`
/// passes `bb->reclen`, [`Block::maxlen`], the *module's* own idea of the
/// record length, which is allowed to differ from the file's -- would hold a
/// record of a different length than a re-read of the same file produces,
/// and `Key::extract`/`Key::compare` would then see different bytes before
/// and after the cache is dropped. [`Block::insert`] calls this on its way
/// into both the write and the model, which is the one place both have to
/// agree.
fn normalized(bytes: &[u8], reclen: u16) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out.resize(usize::from(reclen), 0);
    out
}

impl Block {
    /// What the module named this file.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The file's shape.
    pub fn geometry(&self) -> &Geometry {
        &self.geometry
    }

    /// What the file is indexed by.
    pub fn keys(&self) -> &[Key] {
        &self.keys
    }

    /// The `struct btvblk` the module holds.
    pub fn block(&self) -> FarPtr {
        self.block
    }

    /// The record length the module declared.
    pub fn maxlen(&self) -> u16 {
        self.maxlen
    }

    /// The record buffer the module may read into.
    pub fn data(&self) -> FarPtr {
        self.data
    }

    /// The key buffer a search value is copied into.
    ///
    /// `PLBTVSTF.C:166` sizes it with `clckln()`, which is the longest key plus
    /// one. The buffer exists whether or not the module ever searches by key,
    /// because the real host allocated it in `opnbtv` and a module is entitled
    /// to find a pointer there.
    pub fn key(&self) -> FarPtr {
        self.key
    }

    /// Where the file is positioned.
    pub fn cursor(&self) -> Cursor {
        self.cursor
    }

    /// Move the file to a new position.
    pub fn seek_to(&mut self, cursor: Cursor) {
        self.cursor = cursor;
    }

    /// The file's records, reading them if this is the first time.
    ///
    /// # Errors
    ///
    /// If the file cannot be read, or holds a different number of records from
    /// the number its header claims.
    pub fn records(&mut self) -> Result<&Records, BtvError> {
        if self.records.is_none() {
            self.records = Some(Records::read(
                &self.name,
                &self.path,
                &self.geometry,
                &self.keys,
            )?);
        }
        Ok(self.records.as_ref().expect("just read"))
    }

    /// The file's records, if they have been read.
    pub fn loaded(&self) -> Option<&Records> {
        self.records.as_ref()
    }

    /// Whether a write has happened since the index pages were last rebuilt.
    pub fn dirty(&self) -> bool {
        self.dirty
    }

    /// The record the cursor names, if it names one.
    pub fn current(&self) -> Option<&Record> {
        let records = self.records.as_ref()?;
        match self.cursor {
            Cursor::Nowhere => None,
            Cursor::Ordered { key, at } => records.ordered(key, at),
            Cursor::Physical { at } => records.physical(at),
        }
    }

    /// Add a record, choosing its slot and writing it.
    ///
    /// Returns the file position it went to, which is what `absbtv` would
    /// answer for it.
    ///
    /// In order: load the model, choose a slot from the model's own positions
    /// plus what is on disk, write the record to disk with the record count
    /// **after** the insert, then -- only once the write has succeeded -- add
    /// it to the model. A write that fails partway leaves the model agreeing
    /// with whatever is actually on disk, never with a slot nothing wrote.
    ///
    /// `bytes` is normalised to `self.geometry.reclen` before either of those
    /// happens -- see [`normalized`]. `dinsbtv` passes `bb->reclen`
    /// (`Self::maxlen`), the *module's* number, which is allowed to differ
    /// from the file's own `reclen`; without this, the model would hold the
    /// caller's buffer verbatim while `records::walk` always stores exactly
    /// `geometry.reclen` bytes, and the two would disagree the moment the
    /// cache is dropped and the file is read again.
    ///
    /// **Variable-length files refuse instead.** Normalising is right when
    /// `reclen` really is the length of every record; on a variable-length
    /// file it is not, and cutting a real record down to it is the same
    /// silent truncation [`Self::update`] already refuses for exactly this
    /// reason. See [`Self::update`]'s doc comment.
    ///
    /// `self.geometry` is updated last: `records` always grows by one, and
    /// `pages` grows by one only when the slot was a new page. Both fields are
    /// `Copy` and are what the next `Records::read` bounds its walk by, so
    /// leaving either stale here would make a later re-read of this same file
    /// -- after the cache is dropped -- silently wrong rather than merely
    /// inconvenient. See `a_block_that_writes_is_readable_after_its_cache_is_dropped`.
    ///
    /// # Errors
    ///
    /// If the records cannot be read, the file holds variable-length
    /// records, or the file cannot be written.
    pub fn insert(&mut self, bytes: &[u8]) -> Result<u32, BtvError> {
        self.records()?;
        let name = self.name.clone();

        if self.geometry.variable {
            return Err(BtvError {
                file: name,
                why: format!(
                    "holds variable-length records up to {} bytes, and this host does \
                     not write them -- inserting this {}-byte buffer would silently \
                     truncate it to fit the file's own reclen, the same wrong answer \
                     update already refuses to give",
                    self.geometry.reclen,
                    bytes.len()
                ),
            });
        }

        let bytes = normalized(bytes, self.geometry.reclen);

        let layout = pages::Layout {
            page: self.geometry.page,
            physical: self.geometry.physical,
            pages: self.geometry.pages,
        };

        let (positions, count) = {
            let records = self.records.as_ref().expect("just loaded");
            (records.positions(), records.len() as u32 + 1)
        };
        let free = pages::free_head(&self.path).map_err(|why| BtvError {
            file: name.clone(),
            why,
        })?;
        let data = pages::data_pages(&self.path, layout).map_err(|why| BtvError {
            file: name.clone(),
            why,
        })?;
        let slot = layout.next_slot(&positions, free, &data);

        pages::write_record(&self.path, layout, slot, &bytes, count).map_err(|why| BtvError {
            file: name.clone(),
            why,
        })?;

        let position = slot.position();
        self.records
            .as_mut()
            .expect("just loaded")
            .insert(&self.keys, position, bytes)
            .map_err(|why| BtvError {
                file: name.clone(),
                why,
            })?;

        self.geometry.records = count;
        if matches!(slot, pages::Slot::NewPage { .. }) {
            self.geometry.pages += 1;
        }
        self.dirty = true;

        Ok(position)
    }

    /// Replace the record at `position`.
    ///
    /// An update is in place: it neither adds a slot nor a page, so
    /// `self.geometry` is untouched. Existence is checked against the model
    /// **before** anything is written, because `position` is a module's word
    /// for a file offset and not a slot this layer chose -- writing to it
    /// unconditionally would let a module scribble over whatever bytes happen
    /// to be there, free-list link or otherwise.
    ///
    /// `bytes` must be exactly `self.geometry.reclen` long, refused rather
    /// than padded. [`Self::insert`] pads a short buffer with zero because
    /// there is nothing at a fresh slot to lose; an update writes over a
    /// record that already exists, and `pages::write_record` pads to
    /// `physical` unconditionally, so a short buffer here would silently
    /// zero-fill the tail of whatever was there. That is a live data-loss
    /// path once `dupdbtv` calls this.
    ///
    /// # Errors
    ///
    /// If `bytes` is not exactly `reclen` long, the records cannot be read,
    /// `position` holds no record, or the file cannot be written.
    pub fn update(&mut self, position: u32, bytes: &[u8]) -> Result<(), BtvError> {
        self.records()?;
        let name = self.name.clone();

        if bytes.len() != usize::from(self.geometry.reclen) {
            let why = if self.geometry.variable {
                format!(
                    "holds variable-length records up to {} bytes, and this host does \
                     not write them -- the {}-byte buffer the module opened it with is \
                     what a variable-length read needs (see opnbtv's doc comment), not \
                     something opcode 3 can write back as one fixed-length slot",
                    self.geometry.reclen,
                    bytes.len()
                )
            } else {
                format!(
                    "a {}-byte record for a {}-byte slot -- update refuses rather than \
                     zero-fill the tail of whatever was there",
                    bytes.len(),
                    self.geometry.reclen
                )
            };
            return Err(BtvError { file: name, why });
        }

        let records = self.records.as_ref().expect("just loaded");
        if records.find_physical(position).is_none() {
            return Err(BtvError {
                file: name,
                why: format!("position {position} holds no record"),
            });
        }
        let count = records.len() as u32;

        let layout = pages::Layout {
            page: self.geometry.page,
            physical: self.geometry.physical,
            pages: self.geometry.pages,
        };
        pages::write_record(&self.path, layout, pages::Slot::Existing(position), bytes, count)
            .map_err(|why| BtvError {
                file: name.clone(),
                why,
            })?;

        self.records
            .as_mut()
            .expect("just loaded")
            .update(&self.keys, position, bytes.to_vec())
            .map_err(|why| BtvError { file: name, why })?;

        self.dirty = true;

        Ok(())
    }

    /// Rebuild every key's leaf index page from the records already in memory,
    /// in that key's order, and update the file control record's per-key
    /// record count to match.
    ///
    /// The host never reads these pages back -- `records()` page-walks and
    /// sorts, which is [`keys`]'s whole design. But a file this host wrote is
    /// a file a real Btrieve, or MBBSEmu, could later open, and an index that
    /// disagrees with the data behind it is exactly the silent corruption this
    /// crate refuses to produce anywhere else. `clsbtv` calls this when
    /// [`Self::dirty`] is set, which is the flush point the design names.
    ///
    /// # Errors
    ///
    /// If the records have never been loaded, a key's entries do not fit in a
    /// single leaf page (see [`pages::index_pages`]), a key's root page is `0`
    /// or outside the file (see [`Key::definition`]), or the file cannot be
    /// written.
    pub fn reindex(&mut self) -> Result<(), BtvError> {
        let name = self.name.clone();
        let fail = |why: String| BtvError {
            file: name.clone(),
            why,
        };

        let records = self.records.as_ref().ok_or_else(|| {
            fail("reindex called before the records were loaded".to_owned())
        })?;

        let layout = pages::Layout {
            page: self.geometry.page,
            physical: self.geometry.physical,
            pages: self.geometry.pages,
        };

        // Just the first page: every field this touches -- the key
        // definitions and their record counts -- lives well inside it (see
        // `fcr::KEYS`), and reading the whole file to reindex an 80 MB one
        // would defeat the point of writing one page at a time.
        let mut fcr = read_head(&self.path, usize::from(self.geometry.page)).map_err(|e| {
            fail(format!("{}: {e}", self.path.display()))
        })?;

        for key in &self.keys {
            // `unwrap_or(0)` would treat a key number `Records` was never
            // built with the same as a key with no records, and write an
            // empty leaf over its root instead of saying it does not know
            // the key. This crate refuses to guess; refuse here too.
            let len = records.ordered_len(key.number).ok_or_else(|| {
                fail(format!(
                    "key {}: not among the keys the loaded records were ordered by",
                    key.number
                ))
            })?;
            let entries: Vec<(Vec<u8>, u32)> = (0..len)
                .map(|n| {
                    let record = records.ordered(key.number, n).expect("in range");
                    (key.extract(&record.bytes), record.position)
                })
                .collect();

            let mut page = pages::index_pages(layout, &entries)
                .map_err(|why| fail(format!("key {}: {why}", key.number)))?;

            // `key.definition`, not `key.number`: a multi-segment key's root
            // and record count live at its *first* definition, and the two
            // indices only coincide when no earlier key has more than one
            // segment. See [`Key::definition`].
            let definition = pages::fcr::KEYS + usize::from(key.definition) * pages::fcr::KEY_WIDTH;
            let root_at = definition + pages::fcr::KEY_ROOT;
            let root = pages::long(&fcr[root_at..root_at + 4]);

            // Page 0 is the file control record, never a key's root, and a
            // root has to name a page the file actually has. Refused
            // regardless of whether `key.definition` above is right: this is
            // the guard that stands even if it is subtly wrong, and it is
            // what stops a continuation definition's meaningless root field
            // (measured as `0` off the shipped files) from writing a leaf
            // over the file control record.
            if root == 0 || root >= self.geometry.pages {
                return Err(fail(format!(
                    "key {}: root page {root} is not inside a {}-page file",
                    key.number, self.geometry.pages
                )));
            }

            // `index_pages` leaves the page number zero; this is the
            // allocation `index_pages`'s own doc comment says the caller
            // does, and in this crate it is always the key's existing root.
            //
            // The stamp comes from the page this overwrites, not from
            // `index_pages`, which always emits zero there: `Header::stamp`'s
            // doc comment says it is preserved rather than interpreted, and
            // preserving it means reading it before it is gone. C3: measured
            // as 13 on `WCCRACE.DAT` page 1 and 42 on `WCCCLASS.DAT` page 1 --
            // neither zero, so writing zero unconditionally was a loss this
            // host could see in its own fixtures once it checked.
            let existing = pages::page_header(&self.path, layout, root)
                .map_err(|why| fail(format!("key {}: {why}", key.number)))?;
            let mut header = pages::Header::decode(&page[..6]);
            header.number = root;
            header.stamp = existing.stamp;
            page[..6].copy_from_slice(&header.encode());

            pages::write_page(&self.path, layout, root, &page)
                .map_err(|why| fail(format!("key {}: {why}", key.number)))?;

            let count = u32::try_from(entries.len())
                .map_err(|_| fail(format!("key {}: more than four billion entries", key.number)))?;
            let records_at = definition + pages::fcr::KEY_RECORDS;
            fcr[records_at..records_at + 4].copy_from_slice(&pages::to_long(count));
        }

        use std::io::{Seek, SeekFrom, Write};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&self.path)
            .map_err(|e| fail(format!("{}: {e}", self.path.display())))?;
        file.seek(SeekFrom::Start(0))
            .and_then(|_| file.write_all(&fcr))
            .map_err(|e| {
                fail(format!(
                    "{}: writing the file control record: {e}",
                    self.path.display()
                ))
            })?;

        self.dirty = false;
        Ok(())
    }
}

/// Every Btrieve file the host has open, and the stack of which is current.
///
/// The current file is **not** here. It is `bb`, a host global living in module
/// memory (`BTVSTF.H:36`), read back out of there every time -- the same rule
/// `curmbk` and `prfptr` are under. What is here is the stack behind it, which
/// `PLBTVSTF.C` keeps in a `static` the module cannot see either.
pub struct Btrieve {
    open: Vec<Block>,

    /// `bbstk`: what `rstbtv` will restore, nearest first. Fixed at ten and
    /// **shifting**, which is not an implementation detail -- see [`Self::set`].
    stack: [FarPtr; BBSTSZ],

    /// `bbomode`: the mode the next `opnbtv` opens in. `PRIMBV`, which is zero,
    /// until `omdbtv` says otherwise.
    mode: i16,
}

impl Default for Btrieve {
    /// Nothing open, nothing stacked, and `PRIMBV`.
    ///
    /// Ten null pointers rather than an empty vector, because that is what
    /// `static struct btvblk *bbstk[BBSTSZ]` is and what makes `rstbtv` past
    /// the bottom yield null instead of nothing.
    fn default() -> Self {
        Self {
            open: Vec::new(),
            stack: [FarPtr::NULL; BBSTSZ],
            mode: 0,
        }
    }
}

impl Btrieve {
    /// Open a file, and give the module a `struct btvblk` to name it by.
    ///
    /// The block is real memory from the module's own heap, laid out as
    /// `BTVSTF.H` declares it, with the fields the host knows filled in and the
    /// rest -- Btrieve's position block above all -- zeroed. A module that reads
    /// `bb->reclen` gets its record length; one that reads the position block
    /// gets zeros rather than a fault.
    ///
    /// This does **not** make the file current. `opnbtv` does that, separately
    /// and for a reason that is worth reading in
    /// [`shims::btrieve::opnbtv`](crate::shims::btrieve::opnbtv).
    ///
    /// # Errors
    ///
    /// If the file's key definitions cannot be read, or the heap has no room
    /// for the block, its name, its record buffer or its key buffer.
    pub fn open(
        &mut self,
        machine: &mut Machine,
        heap: &mut crate::Heap,
        name: &str,
        path: &Path,
        geometry: Geometry,
        maxlen: u16,
    ) -> Result<FarPtr, String> {
        // The key definitions come out of the same first page the geometry did,
        // and they are read at open time rather than with the records because
        // `clckln()` -- which sizes the key buffer below -- is part of what
        // `opnbtv` does. A file whose keys cannot be read is refused here, not
        // at whatever much later moment something first searches by one.
        let fcr = read_head(path, FCR).map_err(|e| format!("{}: {e}", path.display()))?;
        let parsed = keys::parse(name, &fcr, geometry.keys).map_err(|e| e.why)?;

        // `PLBTVSTF.C:148` -- `bb->filnam=alcmem(strlen(filnam)+1)`. The
        // module's, not the host's: `clsbtv` frees it.
        let bytes = name.as_bytes();
        let filnam = heap.alloc(machine, bytes.len() as u16 + 1)?;
        let mut terminated = bytes.to_vec();
        terminated.push(0);
        machine
            .write(filnam, &terminated)
            .map_err(|e| e.to_string())?;

        let data = heap.alloc(machine, maxlen)?;
        machine
            .write(data, &vec![0u8; usize::from(maxlen)])
            .map_err(|e| e.to_string())?;

        // `clckln()` returns the longest key plus one, and that is what the
        // real host allocated. Plus one because a Btrieve key buffer for a
        // string key holds a terminator the key length does not count.
        let longest = parsed.iter().map(Key::length).max().unwrap_or(0);
        let key = heap.alloc(machine, longest + 1)?;
        machine
            .write(key, &vec![0u8; usize::from(longest) + 1])
            .map_err(|e| e.to_string())?;

        let block = heap.alloc(machine, field::SIZE)?;
        let mut image = vec![0u8; usize::from(field::SIZE)];
        let put = |image: &mut Vec<u8>, offset: u16, bytes: &[u8]| {
            let at = usize::from(offset);
            image[at..at + bytes.len()].copy_from_slice(bytes);
        };
        put(&mut image, field::FILNAM, &filnam.to_bytes());
        put(&mut image, field::RECLEN, &maxlen.to_le_bytes());
        put(&mut image, field::DATA, &data.to_bytes());
        put(&mut image, field::KEY, &key.to_bytes());

        // `bb->keylns[n]`, which `clckln()` fills in and which `qrybtv` and the
        // acquire family read to know how many bytes of the module's buffer are
        // the key. Every one this host knows is written; the rest stay zero.
        for definition in &parsed {
            let at = field::KEYLNS + definition.number * 2;
            if at + 2 <= field::REALSEG {
                put(&mut image, at, &definition.length().to_le_bytes());
            }
        }
        machine.write(block, &image).map_err(|e| e.to_string())?;

        self.open.push(Block {
            name: name.to_owned(),
            path: path.to_owned(),
            geometry,
            keys: parsed,
            block,
            maxlen,
            data,
            key,
            records: None,
            cursor: Cursor::Nowhere,
            dirty: false,
        });
        Ok(block)
    }

    /// Push what is current and make `block` current, as `setbtv` does.
    ///
    /// `PLBTVSTF.C:227`, and every word of it is load-bearing:
    ///
    ///
    /// A **shifting** stack ten deep, not an indexed one. So an eleventh nested
    /// `setbtv` does not overflow -- it silently drops the *oldest* entry, and
    /// the module never finds out. That is reproduced here rather than refused,
    /// because the real host's behaviour is defined and modules were built
    /// against it; `rstbtv` has 176 call sites in `WCCMMUD.DLL` against
    /// `setbtv`'s 148, and a host that refused where the original did not would
    /// stop a module that was working as designed.
    ///
    /// What is different is that the dropped entry is *reported*. Returns the
    /// name of the file that fell off the bottom, if one did.
    ///
    /// Only the stack is touched. `bb` itself is written by the caller, because
    /// `bb` is in module memory and this type deliberately keeps no copy of it.
    pub fn set(&mut self, current: FarPtr) -> Option<String> {
        let dropped = self.stack[BBSTSZ - 1];
        self.stack.copy_within(0..BBSTSZ - 1, 1);
        self.stack[0] = current;
        if dropped == FarPtr::NULL {
            return None;
        }
        Some(match self.find(dropped) {
            Ok(at) => self.open[at].name.clone(),
            Err(_) => format!("{dropped:?}"),
        })
    }

    /// What was current before the last `setbtv`, as `rstbtv` restores it.
    ///
    /// `PLBTVSTF.C:236`:
    ///
    ///
    /// **An empty stack is not an error.** It restores `bbstk[0]`, which starts
    /// null, and every routine in `PLBTVSTF.C` opens by checking `bb == NULL`
    /// and returning quietly -- so a module that unbalances its `rstbtv` calls
    /// was designed to get null, not a refusal. `rstmbk` refuses on underflow
    /// and the module never hit it; here the gap between the call-site counts
    /// is 28 and the original's answer is documented, so the original's answer
    /// is what this gives.
    ///
    /// Returns what to put in `bb`, and whether the stack was empty.
    pub fn restore(&mut self) -> (FarPtr, bool) {
        let restored = self.stack[0];
        self.stack.copy_within(1..BBSTSZ, 0);
        (restored, restored == FarPtr::NULL)
    }

    /// The null `struct btvblk *`.
    pub fn null() -> FarPtr {
        FarPtr::NULL
    }

    /// The mode the next `opnbtv` will use.
    pub fn mode(&self) -> i16 {
        self.mode
    }

    /// Set the mode the next `opnbtv` will use, as `omdbtv` does.
    pub fn set_mode(&mut self, mode: i16) {
        self.mode = mode;
    }

    /// The block a module's pointer names.
    ///
    /// # Errors
    ///
    /// If it names no open file.
    pub fn block(&self, at: FarPtr) -> Result<&Block, String> {
        Ok(&self.open[self.find(at)?])
    }

    /// The block a module's pointer names, to be read from or positioned.
    ///
    /// # Errors
    ///
    /// If it names no open file.
    pub fn block_mut(&mut self, at: FarPtr) -> Result<&mut Block, String> {
        let index = self.find(at)?;
        Ok(&mut self.open[index])
    }

    /// How many files are open.
    pub fn len(&self) -> usize {
        self.open.len()
    }

    /// Whether no file is open.
    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }

    /// Every open file, in the order they were opened.
    pub fn files(&self) -> &[Block] {
        &self.open
    }

    /// Close `at`, as everything in `PLBTVSTF.C:632` *after* `bb=bbp` does.
    ///
    ///
    /// `bb=bbp` is [`shims::btrieve::clsbtv`](crate::shims::btrieve::clsbtv)'s
    /// job, not this one's -- `bb` is a module global this type does not
    /// touch, and it has to be written whether or not anything below finds a
    /// file to close. What is here is the guard and everything behind it.
    ///
    /// Returns whether `at` named an open file. `false` is not an error: it
    /// is what a second `clsbtv` of the same block answers, and what a
    /// pointer that was never opened answers too -- `PLBTVSTF.C` could not
    /// tell those two apart either.
    ///
    /// # The guard is `at` in [`Self::open`], not `bb->filnam` in module memory
    ///
    /// `PLBTVSTF.C` measures `bb->filnam != NULL`, and an earlier version of
    /// this measured it the same way: four bytes at `at`'s own
    /// `field::FILNAM`, on the theory that the first close nulls them before
    /// it frees anything and a second read of the same address would still
    /// find them null. That theory holds only until something else
    /// allocates over the span -- [`Heap::free`](crate::Heap::free) never
    /// clears what it frees (see its own doc comment), so those four bytes
    /// are only reliably null until a later, unrelated `alcmem` reuses that
    /// memory for something with a non-null value in the same position, at
    /// which point a *second* close of an already-closed block reads
    /// garbage that looks like an open file and fails looking it up in
    /// [`Self::open`] -- a module bug in disguise, not a refusal this crate
    /// intends. `self.open` is the authoritative record of what is actually
    /// open, and asking it directly cannot be fooled by whatever the heap
    /// has done with the memory since. `PLBTVSTF.C` could not tell a closed
    /// block from one never opened either way, so this is at least as
    /// faithful as reading `bb->filnam` was, and it does not share that
    /// method's failure mode.
    ///
    /// # Errors
    ///
    /// If the block is dirty and [`Block::reindex`] fails: this is the flush
    /// point the whole design rests on, and a file going out of this host's
    /// reach with an index that disagrees with its data is exactly what
    /// `reindex` exists to prevent. Or if any of the four allocations cannot
    /// be freed.
    pub fn close(
        &mut self,
        machine: &mut Machine,
        heap: &mut crate::Heap,
        at: FarPtr,
    ) -> Result<bool, BtvError> {
        if at == FarPtr::NULL {
            // `goodptr(bb=bbp)` is false for a null `bbp`.
            return Ok(false);
        }

        // Either a second close of a block already closed, or a pointer
        // that never named one. `self.open` cannot tell those two apart
        // either, and does not need to -- both answer `false` here, exactly
        // as `bb->filnam != NULL` being false answered for both in
        // `PLBTVSTF.C`.
        let Ok(index) = self.find(at) else {
            return Ok(false);
        };
        let name = self.open[index].name.clone();
        let fail = |why: String| BtvError {
            file: name.clone(),
            why,
        };

        let filnam_at = FarPtr {
            offset: at.offset + field::FILNAM,
            selector: at.selector,
        };
        let bytes = machine.resolve(filnam_at, 4).map_err(|e| fail(e.to_string()))?;
        let filnam = FarPtr::from_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

        // `bb->filnam=NULL` -- still written, and still before anything is
        // freed, exactly where `PLBTVSTF.C:639` writes it. A module that
        // reads its own `bb->filnam` after this call sees what the original
        // left there; this host just no longer *relies* on reading it back
        // to decide whether there was a file to close.
        machine
            .write(filnam_at, &FarPtr::NULL.to_bytes())
            .map_err(|e| fail(e.to_string()))?;

        // The flush point. A block that was never written is never
        // reindexed -- which is not merely tidy, it is load-bearing:
        // `pages::index_pages` refuses any key needing more than one leaf
        // page, and nine of MajorMUD's eleven files with records need one.
        // Reindexing every close rather than only a dirty one would stop the
        // module on the first `WCCITEMS` or `WCCTEXT` it closed.
        if self.open[index].dirty {
            self.open[index].reindex()?;
        }

        let block = self.open.remove(index);
        heap.free(block.key).map_err(fail)?;
        heap.free(block.data).map_err(fail)?;
        heap.free(filnam).map_err(fail)?;
        heap.free(block.block).map_err(fail)?;

        Ok(true)
    }

    fn find(&self, at: FarPtr) -> Result<usize, String> {
        self.open
            .iter()
            .position(|b| b.block == at)
            .ok_or_else(|| format!("{at:?} is not an open Btrieve file"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file control record with a page length, a record length and a count,
    /// and enough pages behind it to match.
    fn file(page: u16, reclen: u16, physical: u16, records: u32, pages: u32) -> Vec<u8> {
        let mut out = vec![0u8; (usize::from(page)) * pages as usize];
        out[at::PAGE..at::PAGE + 2].copy_from_slice(&page.to_le_bytes());
        out[6] = 0;
        out[7] = 4;
        out[at::KEYS..at::KEYS + 2].copy_from_slice(&1u16.to_le_bytes());
        out[at::RECLEN..at::RECLEN + 2].copy_from_slice(&reclen.to_le_bytes());
        out[at::PHYSICAL..at::PHYSICAL + 2].copy_from_slice(&physical.to_le_bytes());
        out[at::RECORDS_HIGH..at::RECORDS_HIGH + 2]
            .copy_from_slice(&((records >> 16) as u16).to_le_bytes());
        out[at::RECORDS_LOW..at::RECORDS_LOW + 2].copy_from_slice(&(records as u16).to_le_bytes());
        out
    }

    /// Read a header out of bytes, by way of a real file.
    ///
    /// A directory per file rather than one shared: tests run in parallel, and
    /// a scratch directory is emptied when it is asked for.
    fn read(name: &str, bytes: &[u8]) -> Result<Geometry, BtvError> {
        let dir = crate::testing::scratch(&format!("btv-{name}"));
        let path = dir.join(name);
        std::fs::write(&path, bytes).expect("written");
        Geometry::read(name, &path)
    }

    #[test]
    fn the_block_is_laid_out_the_way_btvstf_h_declares_it() {
        // A 16-bit compiler pads none of this -- every field is two or four
        // bytes and every offset is even -- so these are the byte offsets a
        // module's own `bb->reclen` compiles to, and a host that placed them
        // anywhere else would be handing back a struct of the right size with
        // everything in the wrong place.
        assert_eq!(field::POSBLK, 0);
        assert_eq!(field::FILNAM, 128);
        assert_eq!(field::RECLEN, 132);
        assert_eq!(field::KEY, 134);
        assert_eq!(field::DATA, 138);
        assert_eq!(field::LASTKN, 142);
        assert_eq!(field::KEYLNS, 144);
        assert_eq!(field::REALSEG, 192, "the first of the two PHARLAP fields");
        assert_eq!(field::KEYSEG, 194);
        assert_eq!(field::SIZE, 196);
    }

    #[test]
    fn a_file_control_record_gives_the_files_shape() {
        let geometry = read("SHAPE.DAT", &file(512, 100, 104, 7, 3)).expect("reads");
        assert_eq!(geometry.version, Version::V5);
        assert_eq!(geometry.page, 512);
        assert_eq!(geometry.keys, 1);
        assert_eq!(geometry.reclen, 100);
        assert_eq!(geometry.physical, 104);
        assert_eq!(geometry.records, 7);
        assert_eq!(geometry.pages, 3);
        assert!(!geometry.variable);
    }

    #[test]
    fn the_record_count_is_two_halves_and_the_high_one_comes_first() {
        // The one field in the record that is not simply little-endian: the
        // count is a `long` stored as two words, high word first. Every file
        // MajorMUD ships has a zero high word, so nothing in the corpus can
        // tell the two readings apart -- which is exactly why it is pinned
        // here, where a file with more than 65,535 records can be made.
        let geometry = read("BIG.DAT", &file(512, 100, 100, 70_000, 2)).expect("reads");
        assert_eq!(geometry.records, 70_000);

        let bytes = file(512, 100, 100, 70_000, 2);
        assert_eq!(&bytes[at::RECORDS_HIGH..at::RECORDS_HIGH + 2], &[1, 0]);
        assert_eq!(&bytes[at::RECORDS_LOW..at::RECORDS_LOW + 2], &[0x70, 0x11]);
    }

    #[test]
    fn a_v6_file_is_read_at_the_same_offsets() {
        let mut bytes = file(4096, 1544, 1546, 0, 6);
        bytes[..2].copy_from_slice(b"FC");
        bytes[7] = 0;
        let geometry = read("NEWMP001.VIR", &bytes).expect("reads");
        assert_eq!(geometry.version, Version::V6);
        assert_eq!(geometry.reclen, 1544);
    }

    #[test]
    fn something_that_is_not_btrieve_is_refused_by_name() {
        let mut bytes = vec![0u8; FCR];
        bytes[..4].copy_from_slice(b"MZ\x90\x00");
        let e = read("PKUNZIP.EXE", &bytes).expect_err("not a Btrieve file");
        assert_eq!(e.file, "PKUNZIP.EXE");
        assert!(e.to_string().contains("PKUNZIP.EXE"), "{e}");
    }

    #[test]
    fn a_v5_record_with_a_version_nobody_wrote_is_refused() {
        // The four zero bytes alone are not enough: a file of zeros has them.
        let mut bytes = file(512, 100, 100, 0, 2);
        bytes[7] = 9;
        assert!(read("FUTURE.DAT", &bytes).is_err());
    }

    #[test]
    fn a_page_length_that_is_not_a_multiple_of_512_is_refused() {
        let bytes = file(1000, 100, 100, 0, 2);
        let e = read("ODD.DAT", &bytes).expect_err("1000 is not a page length");
        assert!(e.why.contains("1000"), "{e}");
    }

    #[test]
    fn a_page_length_of_zero_is_refused_rather_than_dividing_by_it() {
        let mut bytes = file(512, 100, 100, 0, 2);
        bytes[at::PAGE..at::PAGE + 2].copy_from_slice(&0u16.to_le_bytes());
        assert!(read("ZERO.DAT", &bytes).is_err());
    }

    #[test]
    fn a_file_that_is_not_a_whole_number_of_pages_is_refused() {
        let mut bytes = file(512, 100, 100, 0, 2);
        bytes.truncate(900);
        let e = read("RAGGED.DAT", &bytes).expect_err("900 is not two pages");
        assert!(e.why.contains("900"), "{e}");
    }

    #[test]
    fn a_record_longer_than_a_page_is_refused() {
        let bytes = file(512, 600, 600, 0, 2);
        assert!(read("FAT.DAT", &bytes).is_err());
    }

    #[test]
    fn a_physical_record_shorter_than_the_logical_one_is_refused() {
        // Padding cannot be negative, and the two fields swapped would size
        // every read wrongly.
        let bytes = file(512, 104, 100, 0, 2);
        assert!(read("SWAPPED.DAT", &bytes).is_err());
    }

    #[test]
    fn a_file_shorter_than_one_page_is_refused_rather_than_read_past() {
        assert!(read("STUB.DAT", &[0u8; 64]).is_err());
    }

    /// A file laid out like virgin `WCCUSERS.DAT` but small enough to read at a
    /// glance: 64-byte pages holding two 20-byte records each, five pages, one
    /// of which (page 4) is a data page. Mirrors `pages::tests::seed`.
    fn seed(dir: &Path) -> PathBuf {
        let (page, physical, pages) = (64usize, 20usize, 5usize);
        let mut bytes = vec![0u8; page * pages];
        bytes[0x08..0x0a].copy_from_slice(&(page as u16).to_le_bytes());
        bytes[0x10..0x14].copy_from_slice(&pages::to_long(pages::NOWHERE));
        bytes[0x14..0x16].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x16..0x18].copy_from_slice(&16u16.to_le_bytes());
        bytes[0x18..0x1a].copy_from_slice(&(physical as u16).to_le_bytes());
        bytes[0x1e..0x20].copy_from_slice(&4u16.to_le_bytes());
        bytes[0x26..0x2a].copy_from_slice(&pages::to_long(pages as u32));
        // Page 4 is the data page; 1..4 are index pages.
        for number in 1..pages {
            let header = pages::Header {
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

    /// A `Block` over `seed`'s file, built directly rather than through
    /// `Btrieve::open` -- this test has no module and no heap, only the file
    /// and the geometry a real `opnbtv` would have read out of it.
    fn block(path: PathBuf) -> Block {
        let geometry = Geometry {
            version: Version::V5,
            page: 64,
            keys: 1,
            reclen: 16,
            physical: 20,
            records: 0,
            pages: 5,
            variable: false,
        };
        let keys = vec![Key {
            number: 0,
            definition: 0,
            segments: vec![keys::Segment {
                offset: 0,
                length: 2,
                kind: keys::Kind::Signed,
                descending: false,
            }],
            duplicates: false,
        }];
        Block {
            name: "SCRATCH.DAT".to_owned(),
            path,
            geometry,
            keys,
            block: FarPtr::NULL,
            maxlen: 16,
            data: FarPtr::NULL,
            key: FarPtr::NULL,
            records: None,
            cursor: Cursor::Nowhere,
            dirty: false,
        }
    }

    /// A 16-byte record whose two-byte key is `n`.
    fn record(n: u16) -> Vec<u8> {
        let mut bytes = vec![0u8; 16];
        bytes[..2].copy_from_slice(&n.to_le_bytes());
        bytes
    }

    /// The trap the plan names: `geometry` is a `Copy` struct held by value on
    /// `Block`, and `walk()` reads `geometry.records` and `geometry.pages` on
    /// the next `Records::read`. A `Block` that writes without updating its own
    /// copy would re-read the file wrongly the moment something drops the
    /// cache -- so this drops the cache and reads again, rather than trusting
    /// the in-memory model to agree with itself.
    ///
    /// Three inserts rather than one: page 4 holds two slots, so the third has
    /// nowhere to go but a fresh page, which is the other half of the trap --
    /// `geometry.pages` has to grow too, or the re-read never looks at page 5
    /// at all.
    #[test]
    fn a_block_that_writes_is_readable_after_its_cache_is_dropped() {
        let dir = crate::testing::scratch("block-write-persists");
        let path = seed(&dir);
        let mut block = block(path);

        let first = block.insert(&record(1)).expect("first insert");
        let second = block.insert(&record(2)).expect("second insert");
        let third = block.insert(&record(3)).expect("third insert");

        assert_eq!(block.geometry.records, 3, "the model's count is not stale");
        assert_eq!(block.geometry.pages, 6, "the third insert grew the file by a page");

        block.records = None;
        let reread = block.records().expect("a fresh read from disk");
        assert_eq!(reread.len(), 3, "all three records survive a fresh read");
        for position in [first, second, third] {
            assert!(reread.find_physical(position).is_some());
        }
    }

    /// I2: variable-length files must refuse `insert`, not truncate into it.
    /// `normalized` (below) exists for the fixed-length case -- see
    /// [`insert_normalizes_to_the_files_own_reclen_not_the_callers_buffer`] --
    /// where `reclen` really is every record's length and padding or cutting
    /// to it is correct. On a variable-length file `reclen` is not that; it
    /// is the same number `Block::update` already refuses to write over for
    /// exactly this reason (see its doc comment). Before this fix,
    /// `dinsbtv` on `WCCTEXT.DAT` would silently cut a 2,022-byte buffer down
    /// to a 22-byte `reclen` and answer 1, success -- the next task writes
    /// `WCCTEXT`, and that is not a plausible answer to give it.
    #[test]
    fn insert_refuses_a_variable_length_file_rather_than_truncate() {
        let dir = crate::testing::scratch("block-insert-refuses-variable-length");
        let path = seed(&dir);
        let mut block = block(path);
        block.geometry.variable = true;

        let long = vec![7u8; 2022];
        let e = block
            .insert(&long)
            .expect_err("a variable-length file refuses insert, the same as update");
        assert!(e.why.contains("variable-length"), "{e}");

        // The refusal did not touch the model, the count, or the file.
        assert_eq!(block.geometry.records, 0, "the refused insert did not count");
        block.records = None;
        let reread = block.records().expect("a fresh read from disk");
        assert_eq!(reread.len(), 0, "nothing was written");
    }

    /// I3: `dinsbtv` passes `bb->reclen` -- `Block::maxlen`, the module's own
    /// idea of the record length -- which the plan says is allowed to differ
    /// from the file's own `reclen`. `Block::insert` used to store the
    /// caller's buffer verbatim while `records::walk` always stores exactly
    /// `geometry.reclen` bytes, so the in-memory record and the on-disk one
    /// would have different lengths and `Key::extract`/`Key::compare` would
    /// see different bytes before and after the cache is dropped.
    ///
    /// This is the fixed-length case -- see
    /// [`insert_refuses_a_variable_length_file_rather_than_truncate`] for why
    /// the same normalising is wrong on a variable-length file.
    #[test]
    fn insert_normalizes_to_the_files_own_reclen_not_the_callers_buffer() {
        let dir = crate::testing::scratch("block-insert-normalizes-to-reclen");
        let path = seed(&dir);
        let mut block = block(path);

        // 20 bytes: the slot's physical length, standing in for a module
        // whose own `bb->reclen` is wider than the file's 16-byte `reclen`.
        // Bytes 16..20 are past the file's own record and must not survive
        // into the model.
        let mut bytes = vec![0u8; 20];
        bytes[..2].copy_from_slice(&7u16.to_le_bytes());
        bytes[16..20].copy_from_slice(&[0xaa; 4]);

        let position = block.insert(&bytes).expect("inserts");

        let stored = block
            .loaded()
            .and_then(|records| records.physical(0))
            .expect("in memory")
            .bytes
            .clone();
        assert_eq!(stored.len(), 16, "normalized to the file's reclen, not the caller's 20");

        block.records = None;
        let reread = block.records().expect("a fresh read from disk");
        let reread_record = reread
            .find_physical(position)
            .and_then(|at| reread.physical(at))
            .expect("still there");
        assert_eq!(
            reread_record.bytes, stored,
            "the model matches exactly what a re-read produces"
        );
    }

    /// C1: reproduces the reviewer's probe. Two records written into a
    /// scratch file, the second one all zero, used to leave
    /// `Records::read` answering `"the header says 2 records and walking
    /// the pages found 0"` -- `walk` reads the all-zero record as an empty
    /// slot, `break`s the page, and both records vanish, because a slot on
    /// a real free list is skipped rather than ending the page and a
    /// live-but-empty-looking slot is not on the free list. `Block::insert`
    /// must refuse the second record outright rather than write a file its
    /// own reader then refuses to read.
    #[test]
    fn insert_refuses_a_record_that_would_make_its_own_reader_fail() {
        let dir = crate::testing::scratch("block-insert-refuses-empty-lookalike");
        let path = seed(&dir);
        let mut block = block(path);

        let first = block.insert(&record(1)).expect("a live record");

        let e = block
            .insert(&[0u8; 16])
            .expect_err("an all-zero record decodes as an empty slot");
        assert!(e.why.contains("empty"), "{e}");

        // The refusal did not touch the model or the count.
        assert_eq!(block.geometry.records, 1, "the refused insert did not count");

        // And the file itself is still exactly what the reviewer's probe
        // checked: `Records::read` finds the one live record, not zero.
        block.records = None;
        let reread = block.records().expect("a fresh read from disk");
        assert_eq!(reread.len(), 1, "the file was never corrupted");
        assert!(reread.find_physical(first).is_some());
    }

    #[test]
    fn an_update_keeps_the_position_and_the_records_count() {
        let dir = crate::testing::scratch("block-update-persists");
        let path = seed(&dir);
        let mut block = block(path);
        let position = block.insert(&record(1)).expect("insert");

        block.update(position, &record(9)).expect("update");
        assert_eq!(block.geometry.records, 1, "an update changes no count");
        assert_eq!(block.geometry.pages, 5, "and grows no page");

        block.records = None;
        let reread = block.records().expect("a fresh read from disk");
        assert_eq!(reread.len(), 1);
        assert_eq!(
            reread
                .find_physical(position)
                .and_then(|at| reread.physical(at))
                .expect("still there")
                .bytes[0],
            9,
            "the new bytes, not the old, come back off disk"
        );
    }

    #[test]
    fn updating_a_position_that_holds_no_record_is_refused_by_the_block() {
        let dir = crate::testing::scratch("block-update-refused");
        let path = seed(&dir);
        let mut block = block(path);

        let e = block.update(999, &record(1)).expect_err("nothing is there");
        assert_eq!(e.file, "SCRATCH.DAT");
        assert!(e.why.contains("999"), "{e}");
    }

    /// I4: `write_record` pads to `physical` unconditionally, so an update
    /// with fewer bytes than the file's own `reclen` used to zero-fill the
    /// tail of whatever record was already there, silently. `dupdbtv` always
    /// calls `Block::update` with a fixed-length buffer, but the refusal
    /// belongs at this boundary rather than trusted to every future caller.
    #[test]
    fn an_update_shorter_than_reclen_is_refused_rather_than_zero_filling_the_tail() {
        let dir = crate::testing::scratch("block-update-refuses-short-buffer");
        let path = seed(&dir);
        let mut block = block(path);
        let position = block.insert(&record(1)).expect("insert");

        // `record` is 16 bytes, the file's own reclen; 10 is short.
        let short = vec![9u8; 10];
        let e = block
            .update(position, &short)
            .expect_err("10 bytes for a 16-byte record");
        assert!(e.why.contains("10") && e.why.contains("16"), "{e}");

        // Refusing left the original record intact, on disk as well as in
        // the model.
        block.records = None;
        let reread = block.records().expect("a fresh read from disk");
        let record = reread
            .find_physical(position)
            .and_then(|at| reread.physical(at))
            .expect("still there");
        assert_eq!(record.bytes[0], 1, "not overwritten by the refused update");
    }

    /// A file shaped like `seed`'s but at a real page size -- 512 bytes, the
    /// minimum an actual Btrieve file uses (`Geometry::read` refuses smaller).
    /// `seed`'s 64-byte pages are for the write tests above, which never touch
    /// a key definition; `reindex` does, and a key definition at `0x110`
    /// needs a page with room for one. Key 0 is given a root: page 1, one of
    /// the three index pages below the one data page.
    fn seed_indexed(dir: &Path) -> PathBuf {
        let (page, physical, pages) = (512usize, 20usize, 5usize);
        let mut bytes = vec![0u8; page * pages];
        bytes[0x08..0x0a].copy_from_slice(&(page as u16).to_le_bytes());
        bytes[0x10..0x14].copy_from_slice(&pages::to_long(pages::NOWHERE));
        bytes[0x14..0x16].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x16..0x18].copy_from_slice(&16u16.to_le_bytes());
        bytes[0x18..0x1a].copy_from_slice(&(physical as u16).to_le_bytes());
        bytes[0x1e..0x20].copy_from_slice(&4u16.to_le_bytes());
        bytes[0x26..0x2a].copy_from_slice(&pages::to_long(pages as u32));
        for number in 1..pages {
            let header = pages::Header {
                number: number as u32,
                data: number == 4,
                stamp: 0,
            };
            bytes[number * page..number * page + 6].copy_from_slice(&header.encode());
        }
        bytes[0x110..0x114].copy_from_slice(&pages::to_long(1));
        let path = dir.join("INDEXED.DAT");
        std::fs::write(&path, &bytes).expect("scratch file");
        path
    }

    /// A `Block` over `seed_indexed`'s file.
    fn block_indexed(path: PathBuf) -> Block {
        let geometry = Geometry {
            version: Version::V5,
            page: 512,
            keys: 1,
            reclen: 16,
            physical: 20,
            records: 0,
            pages: 5,
            variable: false,
        };
        let keys = vec![Key {
            number: 0,
            definition: 0,
            segments: vec![keys::Segment {
                offset: 0,
                length: 2,
                kind: keys::Kind::Signed,
                descending: false,
            }],
            duplicates: false,
        }];
        Block {
            name: "INDEXED.DAT".to_owned(),
            path,
            geometry,
            keys,
            block: FarPtr::NULL,
            maxlen: 16,
            data: FarPtr::NULL,
            key: FarPtr::NULL,
            records: None,
            cursor: Cursor::Nowhere,
            dirty: false,
        }
    }

    /// Bytes this process has read at the syscall level, from `/proc/self/io`'s
    /// `rchar` -- counted whether or not the bytes came off disk, which is
    /// exactly what distinguishes "read the first page" from "read the whole
    /// file and throw most of it away".
    fn bytes_read_by_this_process() -> u64 {
        let stat = std::fs::read_to_string("/proc/self/io").expect("/proc/self/io");
        stat.lines()
            .find_map(|line| line.strip_prefix("rchar:"))
            .expect("an rchar line")
            .trim()
            .parse()
            .expect("rchar is a number")
    }

    /// I1: `reindex` touches only the file control record, and must cost the
    /// same whether the file behind it is 2.5 KB or 80 MB -- `WCCUPDAT.DAT`
    /// is real at 80 MB, and a `reindex` that read the whole thing before
    /// truncating to one page would defeat the point of writing one page at
    /// a time.
    ///
    /// Grows `seed_indexed`'s file to a **sparse** 64 MiB with `set_len` --
    /// free on any filesystem that supports holes, since nothing is written
    /// to the new range -- then measures how many bytes `reindex` itself
    /// reads via `/proc/self/io`, which counts a sparse hole's zeroed bytes
    /// the same as any other: a whole-file read shows up as tens of millions
    /// of bytes; reading a handful of pages does not. A wall-clock budget
    /// would have worked too, but on this host reading a sparse gigabyte
    /// measured at barely half a second either way -- not a reliable
    /// tripwire under a parallel test run -- while the byte count is exact.
    #[test]
    fn reindex_does_not_read_the_whole_file_to_rebuild_one_page() {
        let dir = crate::testing::scratch("block-reindex-sparse-file");
        let path = seed_indexed(&dir);
        let mut block = block_indexed(path.clone());
        block.insert(&record(1)).expect("insert");

        let grown = 64 * 1024 * 1024;
        let big = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open to grow");
        big.set_len(grown).expect("grow the file sparsely");
        drop(big);

        let before = bytes_read_by_this_process();
        block.reindex().expect("reindexes without reading the sparse tail");
        let read = bytes_read_by_this_process().saturating_sub(before);

        assert!(
            read < 1024 * 1024,
            "reindex read {read} bytes off a {grown}-byte file -- it read more \
             than the first page"
        );
    }

    #[test]
    fn an_insert_leaves_the_block_dirty_and_reindex_clears_it() {
        let dir = crate::testing::scratch("block-reindex-dirty-flag");
        let path = seed_indexed(&dir);
        let mut block = block_indexed(path);
        assert!(!block.dirty(), "nothing written yet");

        block.insert(&record(1)).expect("insert");
        assert!(block.dirty(), "an insert leaves the index stale");

        block.reindex().expect("reindexes");
        assert!(!block.dirty(), "reindex brings the index back in step");
    }

    #[test]
    fn reindex_before_the_records_are_loaded_is_refused() {
        let dir = crate::testing::scratch("block-reindex-unloaded");
        let path = seed_indexed(&dir);
        let mut block = block_indexed(path);

        let e = block.reindex().expect_err("nothing has been read yet");
        assert!(e.why.contains("loaded"), "{e}");
    }

    /// The rebuild survives a fresh read of the *file*, not just the
    /// in-memory model -- reindex's whole point is that the bytes on disk
    /// agree with the records, and only reading them back proves that.
    #[test]
    fn reindex_writes_a_leaf_page_that_decodes_to_the_records_key_order() {
        let dir = crate::testing::scratch("block-reindex-leaf-page");
        let path = seed_indexed(&dir);
        let mut block = block_indexed(path.clone());

        // Out of key order on purpose: 3, 1, 2. Key order is 1, 2, 3.
        let first = block.insert(&record(3)).expect("insert");
        let second = block.insert(&record(1)).expect("insert");
        let third = block.insert(&record(2)).expect("insert");

        block.reindex().expect("reindexes");

        let bytes = std::fs::read(&path).expect("read back");

        // The file control record's key-0 record count, at `fcr::KEY_RECORDS`
        // within the key-0 definition.
        let definition = pages::fcr::KEYS;
        let count_at = definition + pages::fcr::KEY_RECORDS;
        assert_eq!(
            pages::long(&bytes[count_at..count_at + 4]),
            3,
            "the key's record count follows the rebuild, not the file's old one"
        );

        // Page 1 is a 512-byte leaf: 16 bytes of header, then three 10-byte
        // entries (a 2-byte key plus 8 bytes of pointers) in key order.
        let page = &bytes[512..1024];
        assert!(!pages::Header::decode(&page[..6]).data, "still an index page");
        assert_eq!(u16::from_le_bytes([page[6], page[7]]), 3, "three entries");

        let entry = |n: usize| {
            let at = 16 + n * 10;
            let key = u16::from_le_bytes([page[at], page[at + 1]]);
            let position = pages::long(&page[at + 2..at + 6]);
            (key, position)
        };
        assert_eq!(entry(0), (1, second), "1 sorts first");
        assert_eq!(entry(1), (2, third), "2 sorts second");
        assert_eq!(entry(2), (3, first), "3 sorts last");
    }

    /// C3: `Header::stamp`'s doc comment says the stamp is preserved rather
    /// than interpreted, and `seed_indexed` gives every page a stamp of
    /// zero -- which a bug that always writes zero cannot be told apart
    /// from the right answer. This seeds key 0's root with a nonzero stamp
    /// first, so a rebuild that clobbers it has something to be caught by.
    #[test]
    fn reindex_carries_the_roots_stamp_forward_rather_than_zeroing_it() {
        let dir = crate::testing::scratch("block-reindex-preserves-stamp");
        let path = seed_indexed(&dir);

        let mut bytes = std::fs::read(&path).expect("read");
        let mut header = pages::Header::decode(&bytes[512..518]);
        header.stamp = 141;
        bytes[512..518].copy_from_slice(&header.encode());
        std::fs::write(&path, &bytes).expect("seed a nonzero stamp on key 0's root");

        let mut block = block_indexed(path.clone());
        block.insert(&record(1)).expect("insert");
        block.reindex().expect("reindexes");

        let after = std::fs::read(&path).expect("read back");
        let header = pages::Header::decode(&after[512..518]);
        assert_eq!(header.stamp, 141, "the root's stamp must survive a rebuild");
        assert_eq!(header.number, 1, "and still names itself page 1");
        assert!(!header.data, "still an index page");
    }

    /// I7, part 1: a file like `seed_indexed`'s but with **two** keys, where
    /// key 0 has two segments (`ANOSEG`, definitions 0 and 1) and key 1 is a
    /// single segment -- `WCCITOWN.DAT`'s shape with the segmented key moved
    /// **first** instead of last, which is the order no shipped file uses and
    /// the one `reindex` got wrong.
    ///
    /// Definition 0 is key 0's real root, page 1. Definition 1 is key 0's
    /// continuation segment; measured off the shipped files, a continuation
    /// definition's own root field is `0`, so that is what this puts there.
    /// Definition 2 is key 1's real root, page 2 -- **not** page 1, which is
    /// `key.number * KEY_WIDTH` (`1 * 30`) would have landed on by reading
    /// definition 1 instead.
    fn seed_two_keys_segmented_first(dir: &Path) -> PathBuf {
        let (page, physical, pages) = (512usize, 20usize, 5usize);
        let mut bytes = vec![0u8; page * pages];
        bytes[0x08..0x0a].copy_from_slice(&(page as u16).to_le_bytes());
        bytes[0x10..0x14].copy_from_slice(&pages::to_long(pages::NOWHERE));
        bytes[0x14..0x16].copy_from_slice(&2u16.to_le_bytes());
        bytes[0x16..0x18].copy_from_slice(&16u16.to_le_bytes());
        bytes[0x18..0x1a].copy_from_slice(&(physical as u16).to_le_bytes());
        bytes[0x1e..0x20].copy_from_slice(&4u16.to_le_bytes());
        bytes[0x26..0x2a].copy_from_slice(&pages::to_long(pages as u32));
        for number in 1..pages {
            let header = pages::Header {
                number: number as u32,
                data: number == 4,
                stamp: 0,
            };
            bytes[number * page..number * page + 6].copy_from_slice(&header.encode());
        }
        bytes[0x110..0x114].copy_from_slice(&pages::to_long(1));
        let def1 = 0x110 + pages::fcr::KEY_WIDTH;
        bytes[def1..def1 + 4].copy_from_slice(&pages::to_long(0));
        let def2 = 0x110 + 2 * pages::fcr::KEY_WIDTH;
        bytes[def2..def2 + 4].copy_from_slice(&pages::to_long(2));
        let path = dir.join("TWOKEY.DAT");
        std::fs::write(&path, &bytes).expect("scratch file");
        path
    }

    /// A `Block` over `seed_two_keys_segmented_first`'s file: key 0 has two
    /// segments and `definition: 0`; key 1 has one segment, `number: 1` but
    /// `definition: 2`.
    fn block_two_keys(path: PathBuf) -> Block {
        let geometry = Geometry {
            version: Version::V5,
            page: 512,
            keys: 2,
            reclen: 16,
            physical: 20,
            records: 0,
            pages: 5,
            variable: false,
        };
        let segment = |offset| keys::Segment {
            offset,
            length: 2,
            kind: keys::Kind::Signed,
            descending: false,
        };
        let keys = vec![
            Key {
                number: 0,
                definition: 0,
                segments: vec![segment(0), segment(2)],
                duplicates: false,
            },
            Key {
                number: 1,
                definition: 2,
                segments: vec![segment(4)],
                duplicates: false,
            },
        ];
        Block {
            name: "TWOKEY.DAT".to_owned(),
            path,
            geometry,
            keys,
            block: FarPtr::NULL,
            maxlen: 16,
            data: FarPtr::NULL,
            key: FarPtr::NULL,
            records: None,
            cursor: Cursor::Nowhere,
            dirty: false,
        }
    }

    #[test]
    fn reindex_uses_a_keys_own_definition_not_its_number_for_the_root() {
        let dir = crate::testing::scratch("block-reindex-definition-not-number");
        let path = seed_two_keys_segmented_first(&dir);
        let mut block = block_two_keys(path.clone());

        block.records().expect("reads -- no records yet");
        block.reindex().expect("reindexes both keys at their own roots");

        let bytes = std::fs::read(&path).expect("read back");

        // Key 1's leaf landed on its own root, page 2 -- not page 1, which
        // reading `key.number` (1) instead of `key.definition` (2) would
        // have targeted, clobbering key 0's own root.
        let page2 = &bytes[2 * 512..3 * 512];
        let header2 = pages::Header::decode(&page2[..6]);
        assert_eq!(header2.number, 2);
        assert!(!header2.data, "still an index page");

        // And key 0's own root, page 1, is untouched by key 1's rebuild.
        let page1 = &bytes[512..1024];
        let header1 = pages::Header::decode(&page1[..6]);
        assert_eq!(header1.number, 1);

        // The file control record itself was not clobbered.
        assert_eq!(&bytes[..4], &[0, 0, 0, 0], "still a v5 marker, not a page header");
        assert_eq!(u16::from_le_bytes([bytes[0x16], bytes[0x17]]), 16, "reclen untouched");
    }

    /// I7, part 2: the guard that holds even if `key.definition` were
    /// somehow still wrong. A root of `0` names the file control record
    /// itself, and `reindex` must refuse it outright rather than write a
    /// leaf over it.
    #[test]
    fn reindex_refuses_a_root_of_zero_rather_than_write_over_the_file_control_record() {
        let dir = crate::testing::scratch("block-reindex-root-zero");
        let path = seed_indexed(&dir);
        let mut bytes = std::fs::read(&path).expect("read");
        bytes[0x110..0x114].copy_from_slice(&pages::to_long(0));
        std::fs::write(&path, &bytes).expect("corrupt the root to page 0");

        let mut block = block_indexed(path.clone());
        block.records().expect("reads");
        let e = block.reindex().expect_err("a root of page 0 is refused");
        assert!(e.why.contains("0"), "{e}");

        let after = std::fs::read(&path).expect("read back");
        assert_eq!(after, bytes, "a refused reindex touches nothing");
    }

    /// The other half of the same guard: a root naming a page the file does
    /// not have at all.
    #[test]
    fn reindex_refuses_a_root_past_the_end_of_the_file() {
        let dir = crate::testing::scratch("block-reindex-root-out-of-range");
        let path = seed_indexed(&dir);
        let mut bytes = std::fs::read(&path).expect("read");
        bytes[0x110..0x114].copy_from_slice(&pages::to_long(99));
        std::fs::write(&path, &bytes).expect("corrupt the root past the end");

        let mut block = block_indexed(path.clone());
        block.records().expect("reads");
        let e = block.reindex().expect_err("page 99 does not exist in a 5-page file");
        assert!(e.why.contains("99"), "{e}");
    }

    /// The record count stored in key 0's own definition -- `fcr::KEY_RECORDS`
    /// at `0x110 + 0x04`. Only [`Block::reindex`] ever writes it; an ordinary
    /// insert or update does not, which is what makes it a witness to whether
    /// a close actually rebuilt the index rather than merely not erroring.
    fn key_records(path: &Path) -> u32 {
        let bytes = std::fs::read(path).expect("read the file back");
        pages::long(&bytes[0x114..0x118])
    }

    /// Register `seed_indexed`'s block as a real open file: allocate its four
    /// module-memory pieces on a real heap and write `field::FILNAM` the way
    /// [`Btrieve::open`] does, then push it directly rather than going
    /// through `keys::parse` -- `seed_indexed`'s key definition has no real
    /// attributes, only a root, and `block_indexed`'s hand-built [`Key`]
    /// already describes it correctly. Returns the pointer a module's `bb`
    /// would hold.
    fn open_indexed(
        machine: &mut Machine,
        heap: &mut crate::Heap,
        btrieve: &mut Btrieve,
        path: PathBuf,
    ) -> FarPtr {
        let mut block = block_indexed(path);

        let filnam = heap.alloc(machine, 12).expect("alloc filnam");
        machine.write(filnam, b"INDEXED.DAT\0").expect("write filnam");

        let data = heap.alloc(machine, block.maxlen).expect("alloc data");
        machine
            .write(data, &vec![0u8; usize::from(block.maxlen)])
            .expect("write data");

        let key = heap.alloc(machine, 3).expect("alloc key");
        machine.write(key, &[0u8; 3]).expect("write key");

        let at = heap.alloc(machine, field::SIZE).expect("alloc block");
        let mut image = vec![0u8; usize::from(field::SIZE)];
        let put = |image: &mut Vec<u8>, offset: u16, bytes: &[u8]| {
            let start = usize::from(offset);
            image[start..start + bytes.len()].copy_from_slice(bytes);
        };
        put(&mut image, field::FILNAM, &filnam.to_bytes());
        put(&mut image, field::DATA, &data.to_bytes());
        put(&mut image, field::KEY, &key.to_bytes());
        machine.write(at, &image).expect("write block");

        block.block = at;
        block.data = data;
        block.key = key;
        btrieve.open.push(block);
        at
    }

    /// I4: `close` must call `reindex` exactly when the block is dirty, and
    /// not otherwise -- `pages::index_pages` refuses any key needing more
    /// than one leaf page, which is nine of MajorMUD's eleven files with
    /// records, and the `dirty` flag is the only thing standing between a
    /// clean close of one of those and that refusal.
    #[test]
    fn close_reindexes_a_dirty_block_but_never_a_clean_one() {
        let mut machine = Machine::new().expect("a 16-bit machine");
        let mut heap = crate::Heap::new(crate::Config::default());
        let mut btrieve = Btrieve::default();

        // Dirty: an insert alone never touches a key's own record count --
        // only `reindex` does. That field moving from 0 to 1 is proof the
        // rebuild ran, not merely that the close did not error.
        let dirty_path = seed_indexed(&crate::testing::scratch("btrieve-close-reindex-dirty"));
        let dirty = open_indexed(&mut machine, &mut heap, &mut btrieve, dirty_path.clone());
        btrieve
            .block_mut(dirty)
            .expect("open")
            .insert(&record(1))
            .expect("insert");
        assert_eq!(
            key_records(&dirty_path),
            0,
            "an insert alone leaves the key's own count alone"
        );

        btrieve
            .close(&mut machine, &mut heap, dirty)
            .expect("closes, and reindexes on the way");
        assert_eq!(
            key_records(&dirty_path),
            1,
            "closing a dirty block rebuilds the index"
        );

        // Clean: a second file with the same shape and the same real index
        // root, never written to. If `close` reindexed regardless of
        // `dirty`, this would still succeed -- the fixture's one entry fits
        // on one leaf page -- but its bytes would change, because
        // `index_pages` does not promise to reproduce Btrieve's own byte
        // layout (see `pages::index_pages`'s doc comment). Byte-for-byte
        // identical is only possible if `reindex` was never called.
        let clean_path = seed_indexed(&crate::testing::scratch("btrieve-close-reindex-clean"));
        let before = std::fs::read(&clean_path).expect("read before");
        let clean = open_indexed(&mut machine, &mut heap, &mut btrieve, clean_path.clone());
        btrieve
            .close(&mut machine, &mut heap, clean)
            .expect("closes without ever asking to reindex");
        let after = std::fs::read(&clean_path).expect("read after");
        assert_eq!(before, after, "a clean close never touches the file");
    }

    /// C5: the re-entrancy guard used to be `bb->filnam != NULL`, read out of
    /// module memory the first close already freed. [`crate::Heap::free`]
    /// never clears what it frees (see its own doc comment), so that read
    /// stayed reliably null only until something else allocated over the
    /// same span -- reproduced here with eight `Heap::alloc(256)` calls, the
    /// same shape `alcmem` makes, run after the first close. Before the fix
    /// the second close found garbage where `bb->filnam` used to be null,
    /// tried to look up a block already removed from [`Self::open`], and
    /// stopped the module with "is not an open Btrieve file" -- a module
    /// bug in disguise -- instead of the quiet no-op a real double close is.
    #[test]
    fn close_is_a_quiet_no_op_the_second_time_even_after_the_heap_reuses_its_span() {
        let mut machine = Machine::new().expect("a 16-bit machine");
        let mut heap = crate::Heap::new(crate::Config::default());
        let mut btrieve = Btrieve::default();

        let path = seed_indexed(&crate::testing::scratch(
            "btrieve-close-reentrancy-heap-reuse",
        ));
        let at = open_indexed(&mut machine, &mut heap, &mut btrieve, path);

        assert!(
            btrieve.close(&mut machine, &mut heap, at).expect("closes"),
            "the first close finds an open file"
        );

        // The same shape of traffic `alcmem` makes, and enough of it to land
        // on the span the closed block's own `struct btvblk` used to occupy
        // -- and, critically, written into, the way a module actually uses
        // memory it was just handed. `Heap::alloc` alone only reserves
        // address space; it is the write that leaves non-null garbage where
        // `bb->filnam` used to read as null.
        for _ in 0..8 {
            let block = heap.alloc(&mut machine, 256).expect("alcmem-shaped traffic");
            machine
                .write(block, &[0xaau8; 256])
                .expect("a module writes into what it was just given");
        }

        let second = btrieve
            .close(&mut machine, &mut heap, at)
            .expect("a second close of the same pointer must be a quiet no-op");
        assert!(!second, "nothing was open the second time");
    }

    #[test]
    fn the_two_witnesses_to_variable_length_records_must_agree() {
        let mut bytes = file(512, 100, 100, 0, 2);
        bytes[at::USRFLGS] = 1;
        assert!(read("HALF.DAT", &bytes).is_err(), "flag set, marker not");

        bytes[at::VARIABLE_MARK] = 0xff;
        assert!(read("BOTH.DAT", &bytes).expect("reads").variable);
    }
}
