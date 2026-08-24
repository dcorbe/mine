//! Resolve a version 6 file's logical page numbers to physical pages.
//!
//! v5 has no distinction: a page's number in a pointer is where it lives. v6
//! breaks that -- a page can move (Evidence 5: something relocates it, though
//! what triggers that is not established), and the only record of where a
//! logical id currently lives is the `"PP"` allocation table, itself shadowed
//! the same way the file control record is.
//!
//! [`Map`] resolves this **once, at open time**, into a plain lookup, rather
//! than threading a version tag through the page-arithmetic layer
//! ([`super::pages::Layout`]) that has no business holding state -- see the
//! plan's Task 3, "The design decision, made here rather than left open".
//!
//! # The shape of the data, measured against genuine Btrieve 6.15 output
//!
//! Every page opens with a six-byte header: a `u16` type tag at `[0x00]`
//! (`0x4400` for record/index content, `0x8000` for an empty/template page,
//! `0x5600` for a variable/fragment page -- `'V'` in the low byte read little-
//! endian), the page's own **logical id** at `[0x02]`, and a modification
//! stamp at `[0x04]`. An allocation-table page's header instead carries the
//! `"PP"` magic at `[0x00]`, a 1-based **block index** at `[0x02]` shared by
//! both shadow copies of that block, and a **generation** at `[0x04]` --
//! file-global, not per-block, so comparing it *across* blocks means nothing;
//! only the higher generation *within* a pair says which copy is live.
//! Entries start at `0x08`, `(page_size - 8) / 4` of them, each a
//! plain (not word-swapped) little-endian `[u16 marker][u16 page]` pair. The
//! marker's **high byte is the page type** the engine checks, and equals the
//! claimed page's own type tag; a marker whose high byte is zero is a slot that
//! was never allocated.
//!
//! # A slot's position is the logical id -- nothing else is
//!
//! **This is the whole of how resolution works, and it runs the opposite way
//! round from how this module used to read it.** The engine takes the logical id
//! it wants, computes `n = logical - 1`, and fetches block `n / entries + 1`,
//! slot `n % entries`; the 4-byte entry stored there *is* the answer
//! (`W32MKDE_decompiled.c:14276-14286`). It never reads a page's own header to
//! learn what logical id that page holds.
//!
//! This module used to do exactly that inverse: scan every page, read the
//! logical id out of its header, and group. Two things follow from the
//! correction. A page's self-stamped logical id is **decorative** as far as
//! resolution goes -- freed twins and never-written templates keep stale ids,
//! and nothing reads them. And "two pages claim one logical id" is not a
//! contradiction to refuse but a question the format does not pose; six real
//! files were refused for it, and genuine Btrieve reads all six.
//!
//! # Physical pages 0 and 1 are never ordinary pages
//!
//! They are the file control record's own shadow pair. An allocation table
//! that claims one of them contradicts the format, so this refuses rather
//! than mapping it: measured across all ten v6 files this repository has,
//! including the shipped `NEWMP001.VIR`, no live table entry ever names
//! physical page 0 or 1. Skipping them by their `"FC"` magic alone would not
//! do -- a file whose page 0 lost that tag would have its control record
//! handed back as an ordinary claimed page, which is exactly the plausible
//! wrong answer the plan's Trap 2 exists to forbid.
//!
//! # Where allocation-table blocks live, and why scanning for them was wrong
//!
//! Block `k`'s shadow **pair** -- exactly two copies, never more -- sits at
//! physical `2 + (k - 1) * (entries_per_page + 2)` and the page after it. Each
//! block governs `entries_per_page` logical pages plus its own two copies, so
//! the blocks repeat on that stride. Measured across every multi-block file in
//! `archive/modules/majormud-nt` at three page sizes with no exceptions:
//! 4096-byte pages put blocks 1 to 14 at 2, 1026, 2050 ... 13314
//! (`wccnt8pj/wccmp002.vir`); 2048-byte at 2, 514 ... 3586
//! (`wccnt8pj/wcctext2.vir`); 1536-byte at 2 and 386
//! (`wccnt8pj/wccknms2.vir`); `PP2BLOCK.DAT`'s 512-byte pages at 2 and 130.
//!
//! Finding blocks by scanning for the `"PP"` magic was not a slower way to the
//! same answer, it was a wrong one, and it is what made the "shadow pair is
//! really two *or more*" reading look true. Real files carry **abandoned** pages
//! that still hold the magic, a block index of 1, and a *higher* generation than
//! the live table: `wccnt7pq/wccrace2.vir` has them at physical 8 and 9 with
//! generations 1 and 3, against the real pair's 1 and 2. A scan chose physical 9
//! and read an entry array claiming pages 26 and 10 to 14 of a ten-page file.
//! Thirteen files in that tree have the shape -- `wccnt7po/wccshop2.vir` at
//! 20/21, `wccnt7pv/wccmp002.vir` at 10056/10057 -- always near the end of the
//! file and never at a position the formula names. The engine fetches a block by
//! page number and so cannot see them; neither can this.

use std::collections::HashMap;

#[cfg(test)]
thread_local! {
    /// How many times [`Map::read`] has walked a file's allocation table.
    ///
    /// Test-only, and it exists because the cost it counts is invisible to
    /// every other kind of check. Reading the map walks every
    /// allocation-table block in the file; `Block::v6_reindex` used to ask
    /// for one per index node, which on a 13,713-page `WCCMP002.DAT` was 109
    /// walks for a single-record update. Nothing about the file that results
    /// is different, so no correctness test can tell 2 walks from 109 -- only
    /// a counter can.
    ///
    /// Thread-local, not a `static`: the suite runs in parallel, and a
    /// process-wide counter reported 113 walks for the one update this
    /// measures because eight other tests were walking maps at the time.
    pub(crate) static READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Magic bytes opening an allocation-table page.
const MAGIC: &[u8; 2] = b"PP";

/// Byte offset, within a page, of the allocation table's 1-based block
/// index (`u16` little-endian). Shared by both shadow copies of one block.
const BLOCK: usize = 0x02;

/// Byte offset, within a page, of the generation counter (`u16` little-
/// endian). File-global -- only meaningful compared *within* one block's
/// shadow copies, never across blocks. The same field, at the same offset,
/// as the file control record's `at::GENERATION` in `btrieve.rs` -- but this
/// module reads raw bytes rather than a parsed `Geometry`, so it names its
/// own copy of the offset rather than depending on that module's internals.
const GENERATION: usize = 0x04;

/// Byte offset, within an allocation-table page, of its first entry.
///
/// **`0x08`, read off the engine.** It fetches entry `slot` of a block at
/// `page + 8 + slot * 4` (`W32MKDE_decompiled.c:14282`), and this module read
/// `0x0c` for months -- one whole entry too far in, so every slot it saw was
/// the engine's slot *N+1* and slot 0 was invisible.
///
/// That off-by-one entry is the whole of what an earlier reading of this format
/// called an `OVERFLOW` field at `0x0a`, "a second, markerless claim ... at a
/// fixed offset". An entry is a `u16` marker then a `u16` physical page, so
/// slot 0 occupies `0x08`-`0x0b` and its *physical-page half* lands exactly on
/// `0x0a`. Measured on `PP2BLOCK.DAT`: physical page 2's slot 0 reads
/// `{marker 0x8000, page 4}` and the old `OVERFLOW` word read 4; block 2's copy
/// at physical 130 reads `{0x0000, 128}` and `OVERFLOW` read 128.
///
/// Two independent confirmations that `0x0c` was wrong rather than merely
/// different. First, this module's own measured entry counts -- "509, or 381,
/// or 1021 live entries" -- are each exactly one less than `(page_size - 8) / 4`
/// for their page sizes, the count that a base of `0x08` gives. Second, the
/// anomaly those counts were recorded to explain ("block *N+1*'s array always
/// starts one logical id past where block *N*'s would have continued", and the
/// skipped id being "a real page ... not in *any* block's regular array")
/// disappears entirely: the skipped id was slot 0.
const ENTRIES: usize = 0x08;

/// Bytes per allocation-table entry: a `u16` marker and a `u16` physical
/// page number, both plain little-endian -- not the high-word-first
/// convention `pages::long` uses for record positions.
const ENTRY: usize = 4;

/// Byte offset, within an ordinary page, of its own logical id (`u16`
/// little-endian).
const LOGICAL: usize = 0x02;

/// How many leading bytes of a page carry everything a *resolving* scan ever
/// asks about: the two-byte tag/magic at `0x00`, the two-byte logical id or
/// allocation-table block index at `0x02` (the same offset serves both,
/// [`LOGICAL`] and [`BLOCK`]), and the two-byte generation at `0x04`. Two
/// bytes of padding round it to a `usize`-friendly width; nothing reads them.
///
/// This is the whole of what turns [`Map::relocate`]'s twin search from a
/// per-operation full-file read into one bounded by page *count*, not page
/// *size*: a candidate that is not the twin costs 8 bytes to rule out, not
/// 4,096.
const HEADER_LEN: usize = 8;

/// One page's content as [`Store`] holds it while a v6 write is in
/// progress: the bytes as they stood when this page was first read (`None`
/// if the page did not exist yet -- it was appended during this operation),
/// the bytes as they stand now, and whether the two differ.
///
/// `dirty` is kept as its own bit rather than computed by comparing
/// `original` and `current` on demand, because [`Store::page_mut`] cannot
/// know in advance whether its caller's edit will end up a no-op -- v6's own
/// write paths routinely copy a page over unchanged fields, see whether it
/// still reads the same, and skip the disk write if it does. That decision
/// belongs to the caller, not to this type; `dirty` just remembers that
/// mutable access was requested at all, and [`Store::write_page`] can still
/// leave a page marked dirty over bytes that end up identical to
/// `original` -- [`super::lib::write_changed_pages`]'s own before/after
/// comparison is what filters those back out before anything is written.
struct Entry {
    original: Option<Vec<u8>>,
    current: Vec<u8>,
    dirty: bool,
}

/// A v6 file's pages, read from disk one at a time and cached only for the
/// duration of a single write.
///
/// # What this replaces
///
/// Every v6 write used to open with `std::fs::read(&self.path)` -- the
/// *entire* file, unconditionally, because [`Map::read`], [`Map::claim`],
/// [`Map::relocate`] and [`super::lib::Block::v6_reindex`] all indexed a
/// shared `Vec<u8>` by absolute physical offset and had no other way to ask
/// for "physical page N". On `WCCMP002.DAT` (13,607 pages) that was 55.7 MB
/// read for a one-record, one-byte update, and the peak heap paid for it
/// twice over: `insert_v6`/`update_v6`/`delete_v6` each cloned that buffer
/// again before touching it, to have something to diff the finished write
/// against.
///
/// Every one of those call sites, measured, touches a *bounded* set of
/// pages -- the allocation table's own blocks (found by formula, never a
/// scan, see [`Map::read`]'s doc comment), the record's own data page, and
/// whichever index nodes a key's rebuilt tree actually relocates. None of
/// them needed the *whole* file resident; they needed `file[a..b]` to be
/// answerable for the handful of pages they actually touch, and a `Vec<u8>`
/// eagerly loaded to the file's full length was the only way this crate
/// had to answer that.
///
/// # What did not shrink, and had to be fixed a different way
///
/// [`Map::relocate`]'s twin search is a genuine `4..pages` scan -- it has to
/// rule out every physical page that is not this logical id's abandoned
/// twin, and the format gives no index to shortcut that with. Caching whole
/// pages would have made this store degenerate into loading the entire file
/// on the *first* relocation of any write that touches a never-before-moved
/// page (measured: on a fresh `WCCMP002.DAT`, 107 of 108 relocations in one
/// update find no twin and scan every candidate). [`Self::header`] is the
/// fix that measurement demanded: a twin search only ever needs to read
/// [`HEADER_LEN`] bytes of a candidate to rule it out, not the 4,096-byte
/// page a naive per-page cache would have fetched. The scan is still
/// O(pages), and said so plainly rather than mis-sold as bounded -- see
/// [`Map::relocate`]'s own doc comment -- but its *constant* dropped from
/// one page to eight bytes, and every relocation after the first within one
/// operation answers from this cache rather than touching disk again.
///
/// # Dirty tracking, replacing whole-buffer diffing
///
/// [`super::lib::Block::write_changed_pages`] used to diff an entire
/// `before: Vec<u8>` against an entire `after: Vec<u8>` to work out which
/// pages actually changed. This store already knows, because every write
/// went through [`Self::page_mut`], [`Self::write_page`] or
/// [`Self::append_page`] -- [`Self::dirty_pages`] is that list, already
/// known rather than rediscovered, and [`Self::original`] is the one
/// pre-image `write_changed_pages` needs per dirty page, not the whole
/// file's.
pub(crate) struct Store {
    path: std::path::PathBuf,
    page_size: usize,
    original_pages: usize,
    total_pages: usize,
    pages: HashMap<usize, Entry>,
    headers: HashMap<usize, [u8; HEADER_LEN]>,
    structural_pairs: std::collections::BTreeSet<(usize, usize)>,
}

impl Store {
    /// Open `path` for a page-at-a-time write. Nothing is read yet -- only
    /// the file's length, to know how many pages it starts with.
    ///
    /// # Errors
    ///
    /// If the file's metadata cannot be read, or its length is not a whole
    /// number of `page_size`-byte pages.
    pub(crate) fn open(path: &std::path::Path, page_size: u16) -> Result<Self, String> {
        let page_size_usize = usize::from(page_size);
        if page_size_usize == 0 {
            return Err("a v6 file's page size cannot be zero".to_owned());
        }
        let len = std::fs::metadata(path)
            .map_err(|e| format!("{}: {e}", path.display()))?
            .len();
        let len = usize::try_from(len)
            .map_err(|_| format!("{}: {len} bytes does not fit this host's usize", path.display()))?;
        if !len.is_multiple_of(page_size_usize) {
            return Err(format!(
                "{} bytes is not a whole number of {page_size}-byte pages",
                len
            ));
        }
        let pages = len / page_size_usize;
        Ok(Self {
            path: path.to_path_buf(),
            page_size: page_size_usize,
            original_pages: pages,
            total_pages: pages,
            pages: HashMap::new(),
            headers: HashMap::new(),
            structural_pairs: std::collections::BTreeSet::new(),
        })
    }

    /// Wrap bytes already in memory as a `Store`, instead of opening a file.
    ///
    /// For the handful of callers that legitimately have (or need) the whole
    /// file already -- [`super::records::walk_v6`], which must visit nearly
    /// every claimed page to enumerate a fixed-length file's records, and
    /// this crate's own tests, which build small synthetic fixtures by hand
    /// -- so they can still reach [`Map::read`]/[`Map::claim`]/etc. without
    /// this module keeping a second, byte-slice-based copy of that logic.
    ///
    /// Every page is pre-loaded and marked clean, so [`Self::ensure_loaded`]
    /// never falls back to disk for a `Store` built this way; `path` is a
    /// placeholder never read for that reason.
    ///
    /// # Errors
    ///
    /// If `bytes` is not a whole number of `page_size`-byte pages.
    pub(crate) fn from_bytes(bytes: &[u8], page_size: u16) -> Result<Self, String> {
        let page_size_usize = usize::from(page_size);
        if page_size_usize == 0 {
            return Err("a v6 file's page size cannot be zero".to_owned());
        }
        if !bytes.len().is_multiple_of(page_size_usize) {
            return Err(format!(
                "{} bytes is not a whole number of {page_size}-byte pages",
                bytes.len()
            ));
        }
        let total = bytes.len() / page_size_usize;
        let mut pages = HashMap::with_capacity(total);
        for n in 0..total {
            let content = bytes[n * page_size_usize..][..page_size_usize].to_vec();
            pages.insert(
                n,
                Entry {
                    original: Some(content.clone()),
                    current: content,
                    dirty: false,
                },
            );
        }
        Ok(Self {
            path: std::path::PathBuf::new(),
            page_size: page_size_usize,
            original_pages: total,
            total_pages: total,
            pages,
            headers: HashMap::new(),
            structural_pairs: std::collections::BTreeSet::new(),
        })
    }

    /// Reassemble every page, in order, into one contiguous buffer -- the
    /// inverse of [`Self::from_bytes`], for tests and inspection code that
    /// still want to assert against raw file bytes.
    ///
    /// Panics if any page from `0` to [`Self::total_pages`] was never read
    /// or written this operation -- the same "never guess" rule every other
    /// accessor here follows; a caller wanting the whole image back has to
    /// have touched the whole image.
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.total_pages * self.page_size);
        for n in 0..self.total_pages {
            let entry = self
                .pages
                .get(&n)
                .unwrap_or_else(|| panic!("physical page {n} was never read or written this operation"));
            out.extend_from_slice(&entry.current);
        }
        out
    }

    /// How many pages this file has *now*, original plus every page
    /// appended during this write.
    pub(crate) fn total_pages(&self) -> usize {
        self.total_pages
    }

    /// How many pages this file had when [`Self::open`] was called. A page
    /// numbered at or past this existed nowhere before this write and so has
    /// no `before` image -- see [`Self::original`].
    pub(crate) fn original_pages(&self) -> usize {
        self.original_pages
    }

    fn read_disk(&self, page: usize, len: usize) -> Result<Vec<u8>, String> {
        let bytes = super::read_at(&self.path, page * self.page_size, len)
            .map_err(|e| format!("{}: {e}", self.path.display()))?;
        if bytes.len() != len {
            return Err(format!(
                "physical page {page} is only {} of {len} bytes -- past the end \
                 of the file",
                bytes.len()
            ));
        }
        Ok(bytes)
    }

    /// The first [`HEADER_LEN`] bytes of a page -- tag, logical/block id,
    /// generation -- without paying to read the rest of it.
    ///
    /// Answered from whichever cache already has this page, full or
    /// header-only; a page neither cache has yet costs [`HEADER_LEN`] bytes
    /// of disk, not [`Self::page_size`].
    ///
    /// # Errors
    ///
    /// If `n` is at or past [`Self::total_pages`], or the file is shorter
    /// than this page claims.
    pub(crate) fn header(&mut self, n: usize) -> Result<[u8; HEADER_LEN], String> {
        if let Some(entry) = self.pages.get(&n) {
            let mut out = [0u8; HEADER_LEN];
            out.copy_from_slice(&entry.current[..HEADER_LEN]);
            return Ok(out);
        }
        if let Some(&out) = self.headers.get(&n) {
            return Ok(out);
        }
        if n >= self.total_pages {
            return Err(format!("physical page {n}, and the file is {} pages", self.total_pages));
        }
        let bytes = self.read_disk(n, HEADER_LEN)?;
        let mut out = [0u8; HEADER_LEN];
        out.copy_from_slice(&bytes);
        self.headers.insert(n, out);
        Ok(out)
    }

    fn ensure_loaded(&mut self, n: usize) -> Result<(), String> {
        if self.pages.contains_key(&n) {
            return Ok(());
        }
        if n >= self.total_pages {
            return Err(format!("physical page {n}, and the file is {} pages", self.total_pages));
        }
        let bytes = self.read_disk(n, self.page_size)?;
        self.pages.insert(
            n,
            Entry {
                original: Some(bytes.clone()),
                current: bytes,
                dirty: false,
            },
        );
        Ok(())
    }

    /// A page's whole current content -- its original bytes if nothing has
    /// written to it yet this operation, or whatever the last write left.
    ///
    /// # Errors
    ///
    /// If `n` is at or past [`Self::total_pages`], or the file is shorter
    /// than this page claims.
    pub(crate) fn page(&mut self, n: usize) -> Result<&[u8], String> {
        self.ensure_loaded(n)?;
        Ok(&self.pages[&n].current)
    }

    /// A page's whole current content, mutably -- read-through the same as
    /// [`Self::page`], then marked dirty because a caller asking for `&mut`
    /// means to change it.
    ///
    /// # Errors
    ///
    /// Same as [`Self::page`].
    pub(crate) fn page_mut(&mut self, n: usize) -> Result<&mut [u8], String> {
        self.ensure_loaded(n)?;
        let entry = self.pages.get_mut(&n).expect("just loaded");
        entry.dirty = true;
        self.headers.remove(&n);
        Ok(&mut entry.current)
    }

    /// Replace a page's entire content in one call, the shape every
    /// copy-on-write flip in this module already wants: "this page's stale
    /// half becomes the live half's bytes, then a few fields change."
    ///
    /// # Errors
    ///
    /// If `content` is not exactly [`Self::page_size`] bytes, or `n` is at
    /// or past [`Self::total_pages`].
    pub(crate) fn write_page(&mut self, n: usize, content: &[u8]) -> Result<(), String> {
        if content.len() != self.page_size {
            return Err(format!(
                "a {}-byte page for a {}-byte page slot",
                content.len(),
                self.page_size
            ));
        }
        self.ensure_loaded(n)?;
        let entry = self.pages.get_mut(&n).expect("just loaded");
        entry.current.copy_from_slice(content);
        entry.dirty = true;
        self.headers.remove(&n);
        Ok(())
    }

    /// Bring a brand-new page into the file, numbered one past whatever
    /// [`Self::total_pages`] answered before this call. Has no `before`
    /// image -- see [`Self::original`] -- because nothing was there.
    ///
    /// # Errors
    ///
    /// If `content` is not exactly [`Self::page_size`] bytes.
    pub(crate) fn append_page(&mut self, content: &[u8]) -> Result<usize, String> {
        if content.len() != self.page_size {
            return Err(format!(
                "a {}-byte page for a {}-byte page slot",
                content.len(),
                self.page_size
            ));
        }
        let n = self.total_pages;
        self.pages.insert(
            n,
            Entry {
                original: None,
                current: content.to_vec(),
                dirty: true,
            },
        );
        self.total_pages += 1;
        Ok(n)
    }

    /// Record that physical pages `first` and `second` are one shadow pair
    /// of structure -- the file control record or one allocation-table
    /// block -- so [`super::lib::Block::write_changed_pages`] knows to run
    /// its flip-canonicalisation over them instead of treating either half
    /// as ordinary content.
    ///
    /// Called by every function in this module that writes to a shadow
    /// pair ([`Map::claim`], [`Map::relocate`], [`Map::unclaim`],
    /// [`write_fcr`]), naming the exact pair it just touched -- never
    /// inferred after the fact by scanning for `"PP"` magic, for the same
    /// reason [`Map::read`] no longer scans for it either.
    pub(crate) fn note_structural_pair(&mut self, first: usize, second: usize) {
        self.structural_pairs.insert((first.min(second), first.max(second)));
    }

    /// Every shadow pair a write touched this operation, ascending.
    pub(crate) fn structural_pairs(&self) -> Vec<(usize, usize)> {
        self.structural_pairs.iter().copied().collect()
    }

    /// Every page number a write actually changed, ascending -- the whole
    /// answer to "what does this commit have to put down", without diffing
    /// anything.
    pub(crate) fn dirty_pages(&self) -> Vec<usize> {
        let mut out: Vec<usize> =
            self.pages.iter().filter(|(_, entry)| entry.dirty).map(|(&n, _)| n).collect();
        out.sort_unstable();
        out
    }

    /// A dirty page's pre-image, or `None` if it was appended during this
    /// operation and so never had one.
    ///
    /// Panics if `n` was never touched this operation -- a caller asking
    /// for a page's `before` state has to have gone through [`Self::page`]
    /// or a write method first, the same way every other accessor here
    /// refuses rather than guesses.
    pub(crate) fn original(&self, n: usize) -> Option<&[u8]> {
        self.pages
            .get(&n)
            .unwrap_or_else(|| panic!("physical page {n} was never read or written this operation"))
            .original
            .as_deref()
    }

    /// A page's current content, without the `&mut self` [`Self::page`]
    /// needs for its read-through cache -- for commit-time code that only
    /// ever asks about pages already known to be resident.
    ///
    /// Panics if `n` was never touched this operation, same as
    /// [`Self::original`].
    pub(crate) fn current(&self, n: usize) -> &[u8] {
        &self
            .pages
            .get(&n)
            .unwrap_or_else(|| panic!("physical page {n} was never read or written this operation"))
            .current
    }
}

/// A v6 file's logical page numbers, resolved to the physical pages that
/// currently hold them.
#[derive(Debug, Clone, Default)]
pub struct Map {
    physical: HashMap<u32, u32>,
}

impl Map {
    /// The physical page currently holding `logical`, or `None` if nothing
    /// live claims it.
    ///
    /// Absence is not this type's error to raise -- Evidence 3a: most
    /// duplicate logical ids the allocation table shows have no live
    /// claimant at all, and that is the ordinary case, not a fault. A
    /// caller that actually needed `logical` and got `None` back is the one
    /// with something to refuse.
    #[must_use]
    pub fn physical(&self, logical: u32) -> Option<u32> {
        self.physical.get(&logical).copied()
    }

    /// Every logical id this map resolves, paired with the physical page
    /// that currently holds it.
    ///
    /// [`Self::physical`] serves a caller that already knows which logical
    /// id it wants; `records::walk` (Task 5 of the plan) does not -- it has
    /// to visit every claimed page there is, so it needs the whole
    /// resolution rather than one lookup at a time. Order is unspecified;
    /// callers that need a particular one (`walk` sorts by logical id, to
    /// match the record ordering Evidence 1c measures) do it themselves.
    pub fn entries(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        self.physical.iter().map(|(&logical, &physical)| (logical, physical))
    }

    /// Build the map from a v6 file already read whole into memory.
    ///
    /// `page_size` is [`super::Geometry`]'s already-established `page` field
    /// -- read once by the caller from whichever control-record shadow copy
    /// is live, never re-derived here.
    ///
    /// # Errors
    ///
    /// Refuses rather than guesses, per the plan's Trap 2:
    ///
    /// - `page_size` cannot divide the file evenly, or is too small to hold
    ///   even one allocation-table entry.
    /// - Neither physical page 2 nor 3 carries the `"PP"` magic -- there is
    ///   no allocation-table block 1 where one is always expected.
    /// - Two shadow copies of one allocation-table block claim the same
    ///   generation -- nothing says which is live.
    /// - After the marker filter, two claimed pages still resolve to the
    ///   same logical id -- a shape this design says cannot happen (Evidence
    ///   3a measured zero of these across all eight committed fixtures), so
    ///   a wrong pick would be worse than stopping.
    pub fn read(store: &mut Store, page_size: u16) -> Result<Self, String> {
        #[cfg(test)]
        READS.with(|reads| reads.set(reads.get() + 1));
        let page_size_usize = usize::from(page_size);
        // `ENTRIES + ENTRY`, not `ENTRIES`: a page long enough to reach the
        // entry array but too short to hold one whole entry would divide out
        // to zero entries and return an empty map, reporting success for a
        // file nothing was read from.
        if page_size_usize < ENTRIES + ENTRY {
            return Err(format!(
                "{page_size_usize}-byte pages have no room for an allocation-table \
                 entry: the array starts at {ENTRIES:#x} and an entry is \
                 {ENTRY} bytes"
            ));
        }
        let pages = store.total_pages();

        // Header-only reads: every question this loop asks (magic, block
        // index, generation) lives in a page's first `HEADER_LEN` bytes, so
        // resolving the table never costs more than `HEADER_LEN` bytes per
        // page it actually looks at -- see [`Store`]'s own doc comment.
        let word = |store: &mut Store, page: usize, offset: usize| -> Result<u16, String> {
            let header = store.header(page)?;
            Ok(u16::from_le_bytes([header[offset], header[offset + 1]]))
        };
        let magic = |store: &mut Store, page: usize| -> Result<bool, String> {
            Ok(store.header(page)?[..2] == *MAGIC)
        };

        // Block 1's allocation table is always shadowed across physical
        // pages 2 and 3 -- an established fact (module doc comment), not
        // something this scans for. Checked directly, ahead of the general
        // scan below, so this exact refusal fires even if some other page
        // elsewhere happens to carry a stray "PP" tagged block 1.
        if pages < 4 || !(magic(store, 2)? || magic(store, 3)?) {
            return Err(
                "neither physical page 2 nor 3 carries the \"PP\" allocation-\
                 table magic -- there is no block 1 where one is always \
                 expected"
                    .to_owned(),
            );
        }

        // And whichever of them carries the magic must say it is block 1.
        // The doc comment above claims that position identifies block 1;
        // checking it is what keeps that a fact rather than an assumption,
        // and it costs nothing -- all ten v6 files here carry block index 1
        // on both copies at physical 2 and 3. Without this, a "PP" page at
        // physical 2 mislabelled block 7 becomes a lone unpaired copy that
        // is automatically live, since a single copy never reaches the
        // generation-tie check.

        // Where each allocation-table block lives is a *formula*, not something
        // to scan for -- the engine fetches block `k` by page number
        // (`FUN_00416fb0(param_1, table, ...)`, `:14279`) and never looks for
        // the magic anywhere. Block `k`'s shadow pair sits at physical
        // `2 + (k - 1) * (entries_per_page + 2)` and the page after it: each
        // block governs `entries_per_page` logical pages and its own pair of
        // copies, so the blocks repeat on that stride.
        //
        // Measured across every multi-block file in `archive/modules/majormud-nt`
        // at three page sizes, with no exceptions: 4096-byte pages put blocks 1
        // to 14 at 2, 1026, 2050 ... 13314 (`wccnt8pj/wccmp002.vir`);
        // 2048-byte at 2, 514 ... 3586 (`wccnt8pj/wcctext2.vir`); 1536-byte at
        // 2 and 386 (`wccnt8pj/wccknms2.vir`); and `PP2BLOCK.DAT`'s 512-byte
        // pages at 2 and 130.
        //
        // **Scanning for the magic was wrong, not merely slower.** Files carry
        // abandoned pages that still hold `"PP"`, a block index of 1 and a
        // *higher* generation than the real table -- `wccnt7pq/wccrace2.vir` has
        // them at physical 8 and 9 with generations 1 and 3, against the real
        // pair's 1 and 2. A scan picked physical 9 as live and read an entry
        // array claiming pages 26 and 10 to 14 in a ten-page file. Twelve other
        // files in that tree have the same shape (`wccnt7po/wccshop2.vir` at
        // 20/21, `wccnt7pv/wccmp002.vir` at 10056/10057, and so on), always
        // near the end of the file and never at a position this formula names.
        // The engine cannot see them, and neither can this now.
        let entries_per_page = Self::entries_per_block(page_size_usize);
        let mut blocks: HashMap<u16, Vec<(usize, u16)>> = HashMap::new();
        for index in 1u16.. {
            let (first, second) = Self::pair_position(page_size_usize, usize::from(index));
            if second >= pages {
                break;
            }
            let mut copies: Vec<(usize, u16)> = Vec::new();
            for page in [first, second] {
                if magic(store, page)? {
                    copies.push((page, word(store, page, GENERATION)?));
                }
            }
            if copies.is_empty() {
                break;
            }
            // Position is what identifies a block, so the index stored there has
            // to agree -- the same check physical 2 and 3 already get below.
            for &(page, _) in &copies {
                let stored = word(store, page, BLOCK)?;
                if stored != index {
                    return Err(format!(
                        "physical page {page} is where allocation-table block \
                         {index} lives, but it calls itself block {stored}"
                    ));
                }
            }
            blocks.insert(index, copies);
        }

        // The live copy of each block: highest generation wins. A tie is a
        // shape nothing has observed and this refuses rather than guesses
        // between two equally-current copies -- the same rule Task 1 applies
        // to the file control record's own shadow pair.
        let mut physical: HashMap<u32, u32> = HashMap::new();
        let mut block_indices: Vec<u16> = blocks.keys().copied().collect();
        block_indices.sort_unstable();
        for block in block_indices {
            let copies = &blocks[&block];
            let generation = copies.iter().map(|&(_, g)| g).max().unwrap_or(0);
            let live: Vec<usize> = copies
                .iter()
                .filter(|&&(_, g)| g == generation)
                .map(|&(page, _)| page)
                .collect();
            if live.len() > 1 {
                return Err(format!(
                    "allocation-table block {block} has {} copies all claiming \
                     generation {generation} ({live:?}), and there is no rule \
                     measured for choosing between them",
                    live.len()
                ));
            }
            let live = live[0];
            // Which logical ids this block answers for. `block` is at least 1 --
            // the position loop above numbers from 1 and refuses a page whose
            // stored index disagrees -- so this subtraction cannot wrap.
            // The engine derives the
            // block and slot *from* the logical id it wants -- block
            // `n / entries + 1` and slot `n % entries` for `n = logical - 1`
            // (`W32MKDE_decompiled.c:14276-14278`) -- so inverting it gives the
            // id a given slot answers for, and that is the only place a logical
            // id comes from.
            let first = u32::from(block - 1) * entries_per_page as u32;
            // The entry array starts at `ENTRIES` (0x08), past `HEADER_LEN`
            // -- this is the one place `Self::read` needs a page's *whole*
            // content rather than just its header, so it costs one full
            // page per block's live copy (bounded, at most one block per
            // stride of logical ids -- fourteen for `WCCMP002.DAT`).
            let page_bytes = store.page(live)?;
            for entry in 0..entries_per_page {
                let at = ENTRIES + entry * ENTRY;
                let marker = u16::from_le_bytes([page_bytes[at], page_bytes[at + 1]]);
                let claimed_page = u16::from_le_bytes([page_bytes[at + 2], page_bytes[at + 3]]);
                // The engine's own "was this ever allocated" test is the entry's
                // *type* byte -- `(entry >> 8) & 0xff` over the whole 4-byte
                // entry read little-endian (`:14283`, `:14286`), which is the
                // marker's high byte. `0x44` is a data page, `0x80` a template.
                // A marker with only its low byte set has never been allocated,
                // which `marker != 0` would have called claimed.
                if marker >> 8 != 0 {
                    // Physical 0 and 1 are the file control record's shadow
                    // pair. A table claiming one of them contradicts the
                    // format; refused rather than mapped, because the
                    // alternative is handing a caller the control record as
                    // an ordinary page. Skipping such pages by their "FC"
                    // magic instead would let a file whose page 0 lost that
                    // tag through silently.
                    if claimed_page <= 1 {
                        return Err(format!(
                            "allocation-table block {block} claims physical \
                             page {claimed_page}, which is the file control \
                             record's own shadow pair and cannot hold a \
                             logical page"
                        ));
                    }
                    // Now that a physical page comes from a table entry rather
                    // than from having been found in the file, one past the end
                    // is reachable and would hand a caller a read past EOF.
                    if usize::from(claimed_page) >= pages {
                        return Err(format!(
                            "allocation-table block {block} claims physical page \
                             {claimed_page}, and the file has only {pages} pages"
                        ));
                    }
                    physical.insert(first + entry as u32 + 1, u32::from(claimed_page));
                }
            }

        }

        Ok(Self { physical })
    }

    /// Claim a new logical page in block 1's allocation table, appending a
    /// fresh physical page to hold it.
    ///
    /// Task 13 of `docs/plans/2026-08-15-host-api-surface-track-b.md`, Step 1
    /// (allocation-table maintenance) folded together with enough of Steps 2
    /// and 3 (shadow-copy flipping, generation bumping) to make Step 1
    /// testable at all: block 1's own two copies are shadowed exactly like
    /// the file control record's, so even the *first* entry this adds has
    /// nowhere honest to land except "write the stale copy, then make it
    /// live" -- there is no unshadowed place to put it.
    ///
    /// `content` is a whole `page_size`-byte page, header included; the
    /// first six bytes ([`super::pages::HEADER`]) are overwritten with the
    /// new page's own tag and logical id before anything is written, so a
    /// caller only has to prepare the record bytes that follow.
    ///
    /// Returns the new page's logical id.
    ///
    /// # Scope, stated rather than silently assumed
    ///
    /// **Single block only.** A file with more than one `"PP"` block is
    /// refused: growing a *second* block is a distinct, harder mechanism
    /// (Evidence 5 -- where a new block's physical pages live is not
    /// established even for reading) and this claims none of that ground.
    /// A block whose regular entry array is already full (every one of
    /// `(page_size - 0x0c) / 4` entries claimed) is refused for the same
    /// reason -- growing past one block's capacity is exactly that
    /// mechanism.
    ///
    /// **Always appends; never reuses a freed page.** v6's free-list
    /// representation is not established (Evidence 5, `records::walk_v6`'s
    /// own doc comment) -- reusing a page this code cannot prove is
    /// genuinely free would be inventing an answer, which the plan's Global
    /// Constraints forbid. Appending costs space a real engine might not
    /// spend, and nothing here claims otherwise.
    ///
    /// **The new logical id is the first free slot's own position**,
    /// because a slot's position within its block *is* the id it answers for
    /// (`W32MKDE_decompiled.c:14276-14278`). There is no id to pick: filling
    /// slot `n` claims logical `n + 1` and nothing else can.
    ///
    /// # Errors
    ///
    /// If more than one `"PP"` block exists, if block 1's two copies are not
    /// at physical 2 and 3, if their generations tie, if the regular entry
    /// array is already full, or if `content` is not exactly `page_size`
    /// bytes.
    /// How many regular entries one allocation-table block holds.
    ///
    /// One number, one place. Both write paths and [`Self::read`] agree on it
    /// because a block's capacity is what turns a logical id into a
    /// (block, slot) pair, and two of those arithmetics that disagreed
    /// anywhere would put an entry in a slot the other could not find.
    fn entries_per_block(page_size: usize) -> usize {
        (page_size - ENTRIES) / ENTRY
    }

    /// The (block, slot) an already-claimed or about-to-be-claimed logical id
    /// belongs to, both 1-based and 0-based respectively.
    ///
    /// The engine's own arithmetic: `n = logical - 1`, block
    /// `n / entries + 1`, slot `n % entries`
    /// (`W32MKDE_decompiled.c:14276-14278`). Stated once here rather than
    /// open-coded at each call site.
    fn block_of(logical: u32, page_size: usize) -> Result<(usize, usize), String> {
        if logical == 0 {
            return Err("logical ids are numbered from 1".to_owned());
        }
        let entries = Self::entries_per_block(page_size);
        let n = (logical - 1) as usize;
        Ok((n / entries + 1, n % entries))
    }

    /// Which of allocation-table block `index`'s two shadow copies is stale
    /// and which is live, as `(stale, live)` physical page numbers.
    ///
    /// **Where a block lives is a formula, never a scan.** Block `k`'s pair
    /// sits at physical `2 + (k - 1) * (entries_per_block + 2)` and the page
    /// after it -- the same arithmetic [`Self::read`] already resolves every
    /// block by, and for the same reason: real files carry abandoned pages
    /// that still hold the `"PP"` magic and a *higher* generation than the
    /// live table, so a scan finds them and the engine never can. See this
    /// module's own doc comment for the measurement across three page sizes.
    ///
    /// The generation comparison is bounded to **this block's own two
    /// copies**. The counter is file-global, so comparing it across blocks
    /// means nothing; within a pair, the higher one is current.
    ///
    /// # Errors
    ///
    /// If the block's pair would fall outside the file, if neither copy
    /// carries the magic, if a copy calls itself some other block, or if the
    /// two generations tie -- the same refusals [`Self::read`] makes, so a
    /// file this can write is a file that can be read back.
    /// Where allocation-table block `index` (1-based) keeps its shadow pair,
    /// as physical page numbers -- position only, with no claim that a block
    /// is actually there.
    ///
    /// The formula this module's doc comment establishes, in one place: three
    /// callers need it ([`Self::read`] to walk the blocks, [`Self::pair_of`]
    /// to resolve one, and [`Self::table_pages`] to say which pages of a file are
    /// table rather than content), and three copies of an arithmetic that
    /// decides where a file's structure lives is three chances to disagree.
    fn pair_position(page_size: usize, index: usize) -> (usize, usize) {
        let stride = Self::entries_per_block(page_size) + 2;
        let first = 2 + (index - 1) * stride;
        (first, first + 1)
    }

    /// Every physical page this file's allocation table occupies.
    ///
    /// Both halves of every block's shadow pair, in ascending order. A page
    /// in this set is *structure*: it is what decides which physical page a
    /// logical one currently means, so a writer that puts pages down in
    /// crash-safe order has to write it after the content it comes to
    /// describe, never before.
    ///
    /// Position **and** magic, not either alone. Position alone would call a
    /// data page that happens to sit at a formula position part of the table;
    /// magic alone would sweep up the abandoned `"PP"` pages this module's
    /// doc comment measures in thirteen real files, which carry the magic, a
    /// block index and a higher generation than the live table, at positions
    /// no block ever lives at.
    ///
    /// Walking stops at the first position where neither copy carries the
    /// magic -- the rule [`Self::read`] already stops by, so the two agree on
    /// how many blocks a file has.
    ///
    /// # Test-only since Plan 3 Task 5
    ///
    /// `Block::write_changed_pages` used to call this against a whole-file
    /// `after: &[u8]` image to work out which pages were structure, before
    /// diffing every other page to find content. It no longer needs to:
    /// [`Store::structural_pairs`] already knows, named directly by every
    /// write that touches a pair, so nothing in the production write path
    /// calls this any more. Kept, still byte-slice based rather than
    /// `Store`-based, because tests want a cheap way to inspect a small
    /// synthetic fixture's table layout without opening a `Store` for it.
    pub(crate) fn table_pages(file: &[u8], page_size: u16) -> Vec<usize> {
        let page_size = usize::from(page_size);
        if page_size == 0 || file.len() < page_size {
            return Vec::new();
        }
        let pages = file.len() / page_size;
        let magic = |page: usize| file[page * page_size..][..2] == *MAGIC;

        let mut found = Vec::new();
        for index in 1usize.. {
            let (first, second) = Self::pair_position(page_size, index);
            if second >= pages {
                break;
            }
            if !magic(first) && !magic(second) {
                break;
            }
            found.push(first);
            found.push(second);
        }
        found
    }

    /// Header-only version of [`Self::pair_of`] -- `HEADER_LEN` bytes per
    /// candidate page instead of a whole one, for the same reason
    /// [`Self::read`] reads headers rather than pages.
    fn pair_of(store: &mut Store, page_size: usize, index: usize) -> Result<(usize, usize), String> {
        let pages = store.total_pages();
        let (first, _) = Self::pair_position(page_size, index);
        if first + 1 >= pages {
            return Err(format!(
                "allocation-table block {index} would have its shadow pair at \
                 physical {first} and {}, past the end of a {pages}-page file",
                first + 1
            ));
        }
        let word = |store: &mut Store, page: usize, offset: usize| -> Result<u16, String> {
            let header = store.header(page)?;
            Ok(u16::from_le_bytes([header[offset], header[offset + 1]]))
        };
        let magic = |store: &mut Store, page: usize| -> Result<bool, String> {
            Ok(store.header(page)?[..2] == *MAGIC)
        };

        if !(magic(store, first)? || magic(store, first + 1)?) {
            return Err(format!(
                "neither physical page {first} nor {} carries the \"PP\" \
                 allocation-table magic -- there is no block {index} there",
                first + 1
            ));
        }
        for page in [first, first + 1] {
            if magic(store, page)? {
                let stored = word(store, page, BLOCK)?;
                if usize::from(stored) != index {
                    return Err(format!(
                        "physical page {page} is where allocation-table block \
                         {index} lives, but it calls itself block {stored}"
                    ));
                }
            }
        }
        match word(store, first, GENERATION)?.cmp(&word(store, first + 1, GENERATION)?) {
            std::cmp::Ordering::Greater => Ok((first + 1, first)),
            std::cmp::Ordering::Less => Ok((first, first + 1)),
            std::cmp::Ordering::Equal => Err(format!(
                "both copies of block {index} claim generation {}, and there is \
                 no rule measured for choosing between them",
                word(store, first, GENERATION)?
            )),
        }
    }

    pub(crate) fn claim(
        store: &mut Store,
        page_size: u16,
        content: &[u8],
        tag: [u8; 2],
    ) -> Result<u32, String> {
        let page_size_usize = usize::from(page_size);
        if content.len() != page_size_usize {
            return Err(format!(
                "a new page must be exactly {page_size} bytes, and this one is {}",
                content.len()
            ));
        }
        let pages = store.total_pages();

        let magic = |store: &mut Store, page: usize| -> Result<bool, String> {
            Ok(store.header(page)?[..2] == *MAGIC)
        };

        if pages < 4 || !(magic(store, 2)? || magic(store, 3)?) {
            return Err(
                "neither physical page 2 nor 3 carries the \"PP\" allocation-\
                 table magic -- there is no block 1 to claim a page in"
                    .to_owned(),
            );
        }

        let entries_per_page = Self::entries_per_block(page_size_usize);

        // The first free slot, and that is the whole answer: a slot's position
        // within block 1 *is* the logical id it answers for, so the new page's
        // id is not chosen, it is wherever the entry goes (`:14276-14278`).
        //
        // This used to read each claimed page's own `LOGICAL` header, take the
        // highest, and add one. That is the inverted resolution `Self::read` no
        // longer performs, and it could hand back an id whose slot already held
        // something -- or, on a block whose claims were not contiguous, an id
        // belonging to a slot several places along. The special case for "a
        // block that claims nothing to number the new page after" goes with it:
        // an empty block's first free slot is slot 0, which is logical 1.
        // Blocks in order, and within a block, slots in order: the first free
        // slot anywhere is the id this claim takes. Scanning past block 1 is
        // what lets a file that has outgrown one block keep claiming --
        // `WCCMP002.DAT` ships with fourteen.
        //
        // The scan stops at the first block whose pair is not there, rather
        // than at block 1: `pair_of` refuses a block past the end of the file,
        // and that refusal is the end of the table, not an error. Each
        // candidate block costs one whole-page read of its live copy (the
        // entry array starts past `HEADER_LEN`) -- bounded by how many
        // blocks the file has, not by its page count.
        let mut found: Option<(usize, usize, usize, usize)> = None;
        for block in 1usize.. {
            let Ok((stale, live)) = Self::pair_of(store, page_size_usize, block) else {
                break;
            };
            let live_bytes = store.page(live)?;
            let free = (0..entries_per_page).find(|&entry| {
                let at = ENTRIES + entry * ENTRY;
                u16::from_le_bytes([live_bytes[at], live_bytes[at + 1]]) >> 8 == 0
            });
            if let Some(entry) = free {
                found = Some((block, entry, stale, live));
                break;
            }
        }
        let Some((block, free_entry, stale, live)) = found else {
            return Err(format!(
                "every allocation-table block in this file already claims all \
                 {entries_per_page} of its entries -- growing a new block is \
                 not implemented"
            ));
        };
        let new_logical = ((block - 1) * entries_per_page + free_entry) as u32 + 1;
        let new_logical16 = u16::try_from(new_logical)
            .map_err(|_| format!("logical id {new_logical} does not fit in this format's u16"))?;

        let generation_at = |store: &mut Store, page: usize| -> Result<u16, String> {
            let header = store.header(page)?;
            Ok(u16::from_le_bytes([header[GENERATION], header[GENERATION + 1]]))
        };
        let new_generation = generation_at(store, live)?.wrapping_add(1);

        // Append the new physical page whole -- header, then the caller's
        // content -- before the allocation table is touched, so a failure
        // past this point (none exist below, but the order still matters if
        // this function ever grows one) never leaves a claim pointing at a
        // page that was never written.
        let new_physical16 = u16::try_from(pages)
            .map_err(|_| format!("physical page {pages} does not fit in this format's u16"))?;
        let mut page = content.to_vec();
        page[..2].copy_from_slice(&tag);
        page[LOGICAL..LOGICAL + 2].copy_from_slice(&new_logical16.to_le_bytes());
        store.append_page(&page)?;

        // Copy-on-write, the same shape the file control record's own shadow
        // pair already uses (Task 1): the stale copy becomes a full copy of
        // the live one, plus this one new entry, plus a higher generation --
        // never a partial edit of whichever copy happened to be live.
        store.note_structural_pair(stale, live);
        let live_page = store.page(live)?.to_vec();
        store.write_page(stale, &live_page)?;

        let stale_bytes = store.page_mut(stale)?;
        let entry_at_new = ENTRIES + free_entry * ENTRY;
        let marker = u16::from_le_bytes([tag[0], tag[1]]);
        stale_bytes[entry_at_new..entry_at_new + 2].copy_from_slice(&marker.to_le_bytes());
        stale_bytes[entry_at_new + 2..entry_at_new + 4].copy_from_slice(&new_physical16.to_le_bytes());
        stale_bytes[GENERATION..GENERATION + 2].copy_from_slice(&new_generation.to_le_bytes());

        Ok(new_logical)
    }

    /// Release an already-claimed logical id back to the allocation table's
    /// free pool, [`Self::claim`]'s inverse.
    ///
    /// Only the allocation-table *entry* is touched -- both halves zeroed,
    /// so the slot reads exactly as an entry that was never allocated
    /// (`entry`'s own doc comment: "a marker whose high byte is zero is a
    /// slot that was never allocated"). The physical page `logical` used to
    /// name is left as it stands, untouched and unzeroed: this module's own
    /// doc comment already establishes that an abandoned physical page's
    /// bytes are decorative once nothing claims it (`Self::read` never
    /// consults a page's self-stamped header to resolve it), and
    /// [`Self::relocate`] already leaves an old physical home exactly this
    /// way on every move. Releasing the claim is what turns the page into
    /// that same ordinary litter, one call earlier than relocate reaches it.
    ///
    /// # Why this exists
    ///
    /// `Block::v6_reindex`'s bulk rebuild can need *fewer* index nodes than
    /// a key's tree currently occupies -- this crate packs a fresh rebuild
    /// as full as the format allows, genuine Btrieve 6.15 does not (measured
    /// 50-77% full, this module's own doc comment) -- and the nodes it no
    /// longer needs must stop being claimed, or the allocation table still
    /// names a page no key's walk reaches, which `read::file` refuses as
    /// "claimed but attributed to no key's B-tree". This is the mechanism
    /// that turns "the tree shrank" into a file this crate can still read
    /// back, the same way an ordinary v5 rebuild's surplus pages were never
    /// a problem: v5 has no allocation table to leave a stale claim in.
    ///
    /// # Errors
    ///
    /// If the file is not a whole number of `page_size`-byte pages, if the
    /// block `logical` belongs to has no live pair, or if `logical`'s own
    /// slot is not claimed in that block's live copy -- there is nothing to
    /// release.
    pub(crate) fn unclaim(store: &mut Store, page_size: u16, logical: u32) -> Result<(), String> {
        let page_size_usize = usize::from(page_size);

        let (block, entry) = Self::block_of(logical, page_size_usize)?;
        let (stale, live) = Self::pair_of(store, page_size_usize, block)?;

        let at = ENTRIES + entry * ENTRY;
        let live_bytes = store.page(live)?;
        let marker = u16::from_le_bytes([live_bytes[at], live_bytes[at + 1]]);
        if marker >> 8 == 0 {
            return Err(format!(
                "logical id {logical} is not claimed in block {block}'s live copy -- \
                 there is nothing to release"
            ));
        }
        let header = store.header(live)?;
        let new_generation = u16::from_le_bytes([header[GENERATION], header[GENERATION + 1]]).wrapping_add(1);

        // Copy-on-write into the stale copy, the same shape `Self::claim`
        // and `Self::relocate` both use: the live copy's own bytes, plus
        // this one change, plus a higher generation.
        store.note_structural_pair(stale, live);
        let live_page = store.page(live)?.to_vec();
        store.write_page(stale, &live_page)?;

        let stale_bytes = store.page_mut(stale)?;
        let repoint = ENTRIES + entry * ENTRY;
        stale_bytes[repoint..repoint + ENTRY].fill(0);
        stale_bytes[GENERATION..GENERATION + 2].copy_from_slice(&new_generation.to_le_bytes());

        Ok(())
    }

    /// Change what physical page an **already-claimed** logical id resolves
    /// to, writing `content` fresh and repointing the existing
    /// allocation-table claim at it -- [`Self::claim`]'s sibling for a page
    /// that already has an identity, rather than one that needs a new one.
    ///
    /// Measured directly against genuine Btrieve 6.15 (`crtprobe.exe`,
    /// 2026-08-15): inserting a record into a fresh one-key v6 file did not
    /// leave that key's index root where it was and edit it in place. The
    /// root's *logical* id (read from the file control record's `KEY_ROOT`
    /// field, Evidence below) never changed, but the *physical* page backing
    /// it moved -- physical 5 before the insert, physical 6 after, both
    /// claimed as logical 2, with the allocation table's own entry rewritten
    /// to match and its shadow pair flipped and its generation bumped
    /// exactly the way [`Self::claim`] adds a brand-new entry. A second
    /// insert moved it again, back to physical 5. **Every write relocates
    /// the page it touches**, not only the file control record and the
    /// allocation table themselves (Evidence 5's open question, now
    /// answered for the one case measured): an ordinary claimed page is
    /// shadow-copied on write too, just without a second dedicated slot of
    /// its own -- the old physical page is abandoned rather than reused in
    /// place, and a fresh one is claimed to hold the new content, the same
    /// as [`Self::claim`] always does for pages it has never seen before.
    ///
    /// This is what makes maintaining a v6 key's index possible without
    /// establishing the free-list representation records.rs's own
    /// `walk_v6` doc comment says is still open: relocating never edits a
    /// live page in place, so a reader mid-walk of the *old* copy is never
    /// looking at a page this call is simultaneously changing.
    ///
    /// `content` is a whole `page_size`-byte page; as with [`Self::claim`],
    /// only its first four bytes (tag, then logical id) are overwritten by
    /// this call -- everything from byte four on, flags included, is the
    /// caller's to have already set correctly. Passing `logical` again
    /// rather than leaving this to rediscover it is deliberate: the caller
    /// found it by reading `KEY_ROOT` (or another already-known claim), and
    /// re-deriving it from `content` would be trusting the very value this
    /// function's caller is responsible for getting right.
    ///
    /// # Scope, the same boundary [`Self::claim`] states
    ///
    /// **Single block only**, for the identical reason: relocating into a
    /// second block is not established. `logical`'s own slot -- `logical - 1`
    /// of block 1 -- must already be claimed in the live copy; a `logical`
    /// nothing claims is refused rather than
    /// silently claimed fresh, because that is [`Self::claim`]'s job, and a
    /// caller that meant to call it should not be quietly redirected here.
    ///
    /// # Errors
    ///
    /// If more than one `"PP"` block exists, if block 1's two copies are not
    /// at physical 2 and 3, if their generations tie, if `content` is not
    /// exactly `page_size` bytes, or if `logical`'s own slot is not claimed
    /// in block 1's live copy.
    pub(crate) fn relocate(
        store: &mut Store,
        page_size: u16,
        logical: u32,
        content: &[u8],
        tag: [u8; 2],
    ) -> Result<u32, String> {
        let page_size_usize = usize::from(page_size);
        if content.len() != page_size_usize {
            return Err(format!(
                "a relocated page must be exactly {page_size} bytes, and this one is {}",
                content.len()
            ));
        }
        let pages = store.total_pages();

        // Which block answers for this logical id, and which half of that
        // block's pair is live. Both by formula -- see [`Self::pair_of`].
        let (block, entry) = Self::block_of(logical, page_size_usize)?;
        let (stale, live) = Self::pair_of(store, page_size_usize, block)?;

        let logical16 = u16::try_from(logical)
            .map_err(|_| format!("logical id {logical} does not fit in this format's u16"))?;

        // Where `logical` is claimed is not something to search for. The engine
        // derives the slot *from* the id -- slot `(logical - 1) % entries` of
        // block `(logical - 1) / entries + 1` (`:14276-14278`) -- and this
        // function handles only single-block files, so the slot is `logical - 1`
        // outright. The old search read each claimed page's own header looking
        // for a match, which is the inverted resolution `Self::read` no longer
        // performs either.
        let at = ENTRIES + entry * ENTRY;
        let live_bytes = store.page(live)?;
        let marker = u16::from_le_bytes([live_bytes[at], live_bytes[at + 1]]);
        if marker >> 8 == 0 {
            return Err(format!(
                "logical id {logical} is not claimed in block 1's live copy -- \
                 there is nothing to relocate"
            ));
        }
        let claimed_physical = usize::from(u16::from_le_bytes([live_bytes[at + 2], live_bytes[at + 3]]));

        let header = store.header(live)?;
        let new_generation = u16::from_le_bytes([header[GENERATION], header[GENERATION + 1]]).wrapping_add(1);

        // Where the new copy goes: this logical page's **own stale twin** if
        // it has one, and a page appended to the file if it does not.
        //
        // A logical page that has been written more than once has two
        // physical homes and the engine alternates between them -- measured
        // across a create/insert/insert/insert/update/delete/insert sequence
        // on genuine 6.15, where the data page ran 6, 5, 6, 5, 6, 5 and its
        // index ran 7, 4, 7, 4 (`docs/2026-08-16-v6-update-delete-oracle.md`).
        // A page that has only ever been claimed has no twin yet, and gets
        // one here, on its first rewrite.
        //
        // **Appending unconditionally was the earlier behaviour and it grew
        // the file by a page on every write of every page** -- two pages per
        // record inserted, once records started packing, forever. The old
        // copy is not lost by reusing the twin: it is precisely the copy this
        // call is superseding, and the one still live until the allocation
        // table below is flipped.
        //
        // The candidate must carry this same logical id *and* be claimed by
        // nothing. Any other unclaimed page is some other logical id's stale
        // twin, and overwriting one of those would throw away a shadow copy
        // that is not this call's to spend.
        //
        // Claimed by **any** block, not just this one. Read through
        // [`Self::read`], which resolves every block's live copy by the same
        // formula [`Self::pair_of`] uses -- one authority for "what does this
        // file currently claim", rather than a second walk here that would
        // only ever see the block this call happens to be writing. On a
        // multi-block file the difference is a live page belonging to another
        // block being picked as this id's twin and written over.
        let mut claimed = vec![false; pages];
        for (_, page) in Self::read(store, page_size)?.entries() {
            let page = page as usize;
            if page < pages {
                claimed[page] = true;
            }
        }
        // **Still an O(pages) scan** -- the format gives no index from a
        // logical id to its abandoned twin, so ruling out every candidate is
        // the only way to answer "does one exist". What changed is the
        // *cost per candidate*: [`Store::header`] reads [`HEADER_LEN`] bytes,
        // not a whole page, and every page this scan touches stays cached in
        // `store` for the rest of the operation -- so a write that relocates
        // many pages (`WCCMP002.DAT`'s first touch relocates 107) pays this
        // scan's full cost once, on its first relocation, and every
        // relocation after that answers from cache. Measured: 13,603
        // candidates at 8 bytes each is 109 KB, against the 55.7 MB a
        // whole-page scan (let alone a whole-file read) would have cost --
        // and that 109 KB is paid at most once per `Block::update()` call,
        // not once per relocation within it.
        let mut twin = None;
        for page in 4..pages {
            if page == claimed_physical || claimed[page] {
                continue;
            }
            let header = store.header(page)?;
            if header[..2] == *MAGIC {
                continue;
            }
            if u16::from_le_bytes([header[LOGICAL], header[LOGICAL + 1]]) == logical16 {
                twin = Some(page);
                break;
            }
        }

        let new_physical16 = u16::try_from(twin.unwrap_or(pages))
            .map_err(|_| format!("physical page {pages} does not fit in this format's u16"))?;
        let mut page = content.to_vec();
        page[..2].copy_from_slice(&tag);
        page[LOGICAL..LOGICAL + 2].copy_from_slice(&logical16.to_le_bytes());
        match twin {
            Some(at) => store.write_page(at, &page)?,
            None => {
                store.append_page(&page)?;
            }
        }

        // Copy-on-write into the stale copy, exactly `Self::claim`'s shape:
        // the live copy's own bytes, plus this one change, plus a higher
        // generation.
        store.note_structural_pair(stale, live);
        let live_page = store.page(live)?.to_vec();
        store.write_page(stale, &live_page)?;

        let stale_bytes = store.page_mut(stale)?;
        let repoint = ENTRIES + entry * ENTRY;
        stale_bytes[repoint + 2..repoint + 4].copy_from_slice(&new_physical16.to_le_bytes());
        stale_bytes[GENERATION..GENERATION + 2].copy_from_slice(&new_generation.to_le_bytes());

        Ok(u32::from(new_physical16))
    }
}

/// Write a v6 file's shadowed file control record (physical pages 0 and 1)
/// with a new record count and each key's own approximate-count field, using
/// the identical copy-on-write-plus-generation-bump shape [`Map::claim`] and
/// [`Map::relocate`] already use for the allocation table and an ordinary
/// claimed page respectively -- Task 13's mechanisms 2 and 3 (shadow-copy
/// flipping, generation bumping), applied to the third shadow pair the
/// format has.
///
/// Measured against genuine Btrieve 6.15 (`crtprobe.exe`, 2026-08-15):
/// `records` lands at the same `RECORDS_HIGH`/`RECORDS_LOW` offsets
/// [`super::pages::fcr`] already names for v5 -- unchanged from the v5
/// layout the read path already trusts for these fields (`Version::V6`'s own
/// doc comment: "reads correctly at the v5 offsets"). Each key's own
/// approximate count -- what `crtprobe.exe stat`'s `approx` field reports --
/// lives at [`super::pages::fcr::KEY_RECORDS`] within that key's own
/// definition, same offset too. `super::pages::fcr::PAGES`, by contrast, is
/// **not** touched here: measured on the same fixture, it read `3` both
/// before and after a record landed on an already-claimed logical page, and
/// only [`Map::claim`]'s own new logical id -- not a page count -- moves it,
/// so a caller that added one keeps it in step by writing `new_logical + 1`
/// itself rather than this function guessing at the relationship.
///
/// `key_record_counts` is `(byte offset of that key's own `KEY_RECORDS`
/// field, new count)` pairs -- the caller's job to compute, since only it
/// knows which keys changed and which definition each lives at
/// (`super::keys::Key::definition`).
///
/// # Errors
///
/// If the file is not at least two whole `page_size`-byte pages, if the
/// shadow pair's two generations tie, or if a `key_record_counts` offset
/// does not leave room for its four bytes.
pub(crate) fn write_fcr(
    store: &mut Store,
    page_size: u16,
    records: u32,
    key_record_counts: &[(usize, u32)],
    free_head: Option<u32>,
    variable_head: Option<Option<u32>>,
) -> Result<(), String> {
    let page_size_usize = usize::from(page_size);
    if store.total_pages() < 2 {
        return Err(format!(
            "{} bytes does not hold two whole {page_size}-byte pages for the \
             file control record's shadow pair",
            store.total_pages() * page_size_usize
        ));
    }

    let generation_of = |store: &mut Store, page: usize| -> Result<u16, String> {
        let header = store.header(page)?;
        Ok(u16::from_le_bytes([header[GENERATION], header[GENERATION + 1]]))
    };

    let (stale, live) = match generation_of(store, 0)?.cmp(&generation_of(store, 1)?) {
        std::cmp::Ordering::Greater => (1usize, 0usize),
        std::cmp::Ordering::Less => (0usize, 1usize),
        std::cmp::Ordering::Equal => {
            return Err(format!(
                "both control-record copies claim generation {}, and there is \
                 no rule measured for choosing between them",
                generation_of(store, 0)?
            ));
        }
    };
    let new_generation = generation_of(store, live)?.wrapping_add(1);

    store.note_structural_pair(0, 1);
    let live_page = store.page(live)?.to_vec();
    store.write_page(stale, &live_page)?;

    let stale_bytes = store.page_mut(stale)?;
    let records_at = super::pages::fcr::RECORDS_HIGH;
    stale_bytes[records_at..records_at + 4].copy_from_slice(&super::pages::to_long(records));

    // `None` leaves whatever the live copy had, which is right for every
    // caller that did not move a slot on or off the free list -- the whole
    // live page was copied over the stale one above, so "leave it alone"
    // costs nothing and says nothing.
    if let Some(free) = free_head {
        let free_at = super::pages::fcr::FREE_V6;
        stale_bytes[free_at..free_at + 4].copy_from_slice(&super::pages::to_long(free));
    }

    // The *variable* free-space chain's head, which is a different list from
    // the one above: that threads free record slots, this threads variable
    // pages with room left. Doubly optional on purpose -- the outer `None`
    // means "this caller did not touch the chain", and `Some(None)` means
    // "the chain is now empty", which are different instructions and would be
    // indistinguishable through one layer.
    if let Some(head) = variable_head {
        let at = super::pages::fcr::VARIABLE_HEAD;
        let value = head.unwrap_or(super::pages::fcr::NO_VARIABLE_HEAD);
        stale_bytes[at..at + 4].copy_from_slice(&super::pages::to_long(value));
    }

    for &(offset, count) in key_record_counts {
        if offset + 4 > page_size_usize {
            return Err(format!(
                "a key-records offset of {offset} does not leave room for its \
                 four bytes in a {page_size}-byte page"
            ));
        }
        stale_bytes[offset..offset + 4].copy_from_slice(&super::pages::to_long(count));
    }

    stale_bytes[GENERATION..GENERATION + 2].copy_from_slice(&new_generation.to_le_bytes());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as Map16;

    /// `CARGO_MANIFEST_DIR`-relative, not workspace-root-relative -- the
    /// convention `btrieve.rs`'s v6 tests and `pages.rs`'s `dupkey30()`
    /// already use, because a test binary's working directory is the crate
    /// root, not wherever `cargo test` was invoked from.
    fn fixture(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/btrieve-oracle/fixtures")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    /// Round-trip a synthetic `Vec<u8>` fixture through a [`Store`] for one
    /// call, and write the result back into `file` -- test-only sugar so a
    /// fixture built as a flat buffer (every test above and below this one
    /// predates `Store`) does not have to be restructured around holding a
    /// `Store` for its whole body just to call the production API, which now
    /// takes one. `Store::from_bytes`/`Self::into_bytes` never touch disk, so
    /// this costs nothing beyond the copy the old in-place `&mut Vec<u8>`
    /// calls never needed -- acceptable here because it is test weight, not
    /// the write path Stage B measures.
    fn via_store<T>(
        file: &mut Vec<u8>,
        page_size: u16,
        f: impl FnOnce(&mut Store) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut store = Store::from_bytes(file, page_size).expect("a whole number of pages");
        let result = f(&mut store);
        *file = store.into_bytes();
        result
    }

    /// Eight 512-byte pages: an allocation-table pair at 2/3 whose live copy
    /// (3) claims physical 4 as logical 1 **and** physical 5 as logical 2, with
    /// three pages -- 4, 5 and 6 -- all stamping themselves logical 1.
    ///
    /// The claims sit in slots 0 and 1 because a slot's position within the
    /// block *is* the logical id it answers for. An earlier version of this
    /// fixture claimed the same two pages but stamped all three headers logical
    /// 7, which only worked while resolution ran backwards off those headers.
    ///
    /// Malformed on purpose. One logical id with two live claims is not
    /// something a well-formed file has, which is exactly why the shape is
    /// built by hand here: [`Map::relocate`] picks the page it writes over by
    /// scanning for this logical id's own unclaimed twin, and the "unclaimed"
    /// half of that rule cannot be exercised by any file where the rule's
    /// other half already excludes every claimed candidate.
    fn two_live_claims_on_one_logical_id() -> Vec<u8> {
        const PAGE: usize = 512;
        let mut out = vec![0u8; PAGE * 8];
        let word = |out: &mut [u8], at: usize, value: u16| {
            out[at..at + 2].copy_from_slice(&value.to_le_bytes());
        };

        for (page, generation) in [(2usize, 1u16), (3, 2)] {
            let at = page * PAGE;
            out[at..at + 2].copy_from_slice(MAGIC);
            word(&mut out, at + BLOCK, 1);
            word(&mut out, at + GENERATION, generation);
        }
        // The live copy's two claims.
        let live = 3 * PAGE;
        word(&mut out, live + ENTRIES, 0x4400);
        word(&mut out, live + ENTRIES + 2, 4);
        word(&mut out, live + ENTRIES + ENTRY, 0x4400);
        word(&mut out, live + ENTRIES + ENTRY + 2, 5);

        // Three pages stamped logical 1, of which 4 and 5 are claimed.
        for page in [4usize, 5, 6] {
            let at = page * PAGE;
            word(&mut out, at, 0x4400);
            word(&mut out, at + LOGICAL, 1);
            // Something recognisable in the body, so an overwrite shows.
            out[at + 16..at + 24].fill(0xB0 + page as u8);
        }

        out
    }

    /// `PP2BLOCK.DAT` keeps two allocation-table blocks, at the two positions
    /// the formula names for 512-byte pages, and [`Map::table_pages`] finds
    /// both pairs and nothing else.
    #[test]
    fn table_pages_finds_every_block_pair_and_stops_after_the_last() {
        let file = fixture("PP2BLOCK.DAT");
        assert_eq!(Map::table_pages(&file, 512), vec![2, 3, 130, 131]);
    }

    /// The walk stops where the blocks stop, not where the file does.
    ///
    /// `PP2BLOCK.DAT` is 156 pages and block 3 would live at physical 258, so
    /// the real fixture never reaches the magic check -- the bounds check ends
    /// the walk first, and a version of this that dropped the magic rule
    /// entirely passed against it. Growing the file past 258 is what makes the
    /// rule load-bearing: those pages are blank, and without the check they
    /// would be reported as an allocation-table block.
    #[test]
    fn table_pages_stops_where_the_blocks_stop_not_where_the_file_does() {
        const PAGE: usize = 512;
        let mut file = fixture("PP2BLOCK.DAT");
        assert_eq!(file.len() / PAGE, 156, "the fixture is 156 pages");
        file.resize(PAGE * 300, 0);
        assert_eq!(Map::table_pages(&file, 512), vec![2, 3, 130, 131]);
    }

    /// An abandoned page carrying the `"PP"` magic is not part of the table.
    ///
    /// Thirteen real files in `archive/modules/majormud-nt` have them -- magic,
    /// a block index, and a *higher* generation than the live table, at
    /// positions no block lives at. A writer that treated one as structure
    /// would order a content page into the wrong phase; one that missed a real
    /// block would flip the table before the pages it describes are durable.
    /// Position and magic together are what separate the two.
    #[test]
    fn table_pages_ignores_an_abandoned_page_that_still_carries_the_magic() {
        const PAGE: usize = 512;
        let mut file = fixture("PP2BLOCK.DAT");
        let stray = 6;
        assert!(
            file.len() > (stray + 1) * PAGE,
            "the fixture is long enough to hold a stray page at {stray}"
        );
        file[stray * PAGE..stray * PAGE + 2].copy_from_slice(MAGIC);
        file[stray * PAGE + BLOCK..][..2].copy_from_slice(&1u16.to_le_bytes());
        file[stray * PAGE + GENERATION..][..2].copy_from_slice(&0xffffu16.to_le_bytes());

        assert_eq!(
            Map::table_pages(&file, 512),
            vec![2, 3, 130, 131],
            "physical {stray} carries the magic but is not where a block lives"
        );
    }

    /// Relocating never writes over a page the allocation table still claims.
    ///
    /// With physical 5 claimed and carrying the same logical id as the page
    /// being relocated, the only legitimate destination is the unclaimed 6.
    /// Dropping the "and claimed by nothing" half of that rule sends the
    /// write to 5 -- destroying a live page -- and every other test in this
    /// crate stays green, which is why this one exists.
    #[test]
    fn relocating_skips_a_same_logical_page_that_is_still_claimed() {
        const PAGE: usize = 512;
        let mut file = two_live_claims_on_one_logical_id();
        let claimed_twin = file[5 * PAGE..6 * PAGE].to_vec();

        let mut content = vec![0u8; PAGE];
        content[32..40].fill(0xCC);
        let to = via_store(&mut file, PAGE as u16, |s| Map::relocate(s, PAGE as u16, 1, &content, [0x00, 0x44]))
            .expect("logical 1 is claimed, so it can be relocated");

        assert_eq!(to, 6, "the unclaimed twin is the only legitimate destination");
        assert_eq!(
            file[5 * PAGE..6 * PAGE],
            claimed_twin[..],
            "a page the table still claims must not be written over"
        );
        assert_eq!(file.len(), PAGE * 8, "and nothing needed appending");
        assert_eq!(
            &file[6 * PAGE + 32..6 * PAGE + 40],
            &[0xCC; 8],
            "the new content landed on 6"
        );
    }

    /// Claiming a page in a file that *has* a second block works, even when
    /// the free slot itself is in block 1.
    ///
    /// [`Map::claim`] used to scan every page for the `"PP"` magic and refuse
    /// the whole file if any of them called itself something other than block
    /// 1. That refused `PP2BLOCK.DAT` outright -- not because the claim needed
    /// block 2, but because block 2 existed at all.
    #[test]
    fn claiming_works_on_a_file_that_has_a_second_block() {
        const PAGE: usize = 512;
        let mut file = fixture("PP2BLOCK.DAT");
        let before = Map::read(&mut Store::from_bytes(&file, PAGE as u16).expect("test fixture"), PAGE as u16).expect("resolves");
        let was = file.len() / PAGE;

        let mut content = vec![0u8; PAGE];
        content[32..40].fill(0xDD);
        let logical = via_store(&mut file, PAGE as u16, |s| Map::claim(s, PAGE as u16, &content, [0x00, 0x44]))
            .expect("a two-block file can still be claimed in");

        assert_eq!(before.physical(logical), None, "the id claimed was free before");
        let after = Map::read(&mut Store::from_bytes(&file, PAGE as u16).expect("test fixture"), PAGE as u16).expect("still resolves");
        assert_eq!(
            after.physical(logical),
            Some(was as u32),
            "the new page was appended and the table points at it"
        );
        assert_eq!(
            &file[was * PAGE + 32..was * PAGE + 40],
            &[0xDD; 8],
            "the caller's content reached the new page"
        );

        // Nothing that already resolved may move.
        for (id, physical) in before.entries() {
            assert_eq!(after.physical(id), Some(physical), "logical {id} moved");
        }
    }

    /// Relocating a block-2 id must not pick a twin that **block 1** claims.
    ///
    /// [`Map::relocate`] chooses where to write by scanning for a page that
    /// carries this logical id and that nothing claims. "Nothing claims" has
    /// to mean nothing in the *whole file*: the entry arrays are per block,
    /// and a walk of only the block being written sees none of the other
    /// blocks' live pages, so any of them is a candidate to be overwritten.
    ///
    /// Built to discriminate, because the obvious version of this test cannot.
    /// Twelve-byte pages give one entry a block, so block 1 answers logical 1
    /// and block 2 answers logical 2. Physical 4 is **claimed by block 1** and
    /// stamps itself logical 2 -- a stale self-stamp, which this format's own
    /// doc comment establishes is decorative and outlives the claim that put
    /// it there. Physical 8 is unclaimed and stamps itself logical 2 as well.
    /// Relocating logical 2 must land on 8; a claimed-set gathered from block 2
    /// alone finds 4 first and destroys a live page.
    #[test]
    fn relocating_never_takes_a_twin_another_block_still_claims() {
        let page_size: usize = ENTRIES + ENTRY;
        let mut file = vec![0u8; page_size * 9];
        let at = |page: usize| page * page_size;

        for (first, index) in [(2usize, 1u16), (5, 2)] {
            for page in [first, first + 1] {
                file[at(page)..at(page) + 2].copy_from_slice(MAGIC);
                file[at(page) + BLOCK..at(page) + BLOCK + 2]
                    .copy_from_slice(&index.to_le_bytes());
            }
            file[at(first) + GENERATION..at(first) + GENERATION + 2]
                .copy_from_slice(&1u16.to_le_bytes());
            file[at(first + 1) + GENERATION..at(first + 1) + GENERATION + 2]
                .copy_from_slice(&2u16.to_le_bytes());
        }

        // Block 1's live copy (physical 3) claims logical 1 at physical 4.
        let entry = at(3) + ENTRIES;
        file[entry..entry + 2].copy_from_slice(&0x4400u16.to_le_bytes());
        file[entry + 2..entry + 4].copy_from_slice(&4u16.to_le_bytes());
        // Block 2's live copy (physical 6) claims logical 2 at physical 7.
        let entry = at(6) + ENTRIES;
        file[entry..entry + 2].copy_from_slice(&0x4400u16.to_le_bytes());
        file[entry + 2..entry + 4].copy_from_slice(&7u16.to_le_bytes());

        // Physical 4 (block 1's live page), 7 (block 2's) and 8 (unclaimed)
        // all stamp themselves logical 2.
        for page in [4usize, 7, 8] {
            file[at(page)..at(page) + 2].copy_from_slice(&[0x00, 0x44]);
            file[at(page) + LOGICAL..at(page) + LOGICAL + 2]
                .copy_from_slice(&2u16.to_le_bytes());
        }
        file[at(4) + 8..at(4) + 12].fill(0xB1);
        let block1_page = file[at(4)..at(4) + page_size].to_vec();

        let mut content = vec![0u8; page_size];
        content[8..12].fill(0xCC);
        let to = via_store(&mut file, page_size as u16, |s| Map::relocate(s, page_size as u16, 2, &content, [0x00, 0x44]))
            .expect("logical 2 is claimed in block 2");

        assert_eq!(to, 8, "the only twin no block claims");
        assert_eq!(
            file[at(4)..at(4) + page_size],
            block1_page[..],
            "physical 4 is block 1's live page and must not be written over"
        );
        let map = Map::read(&mut Store::from_bytes(&file, page_size as u16).expect("test fixture"), page_size as u16).expect("resolves");
        assert_eq!(map.physical(1), Some(4), "block 1 still resolves to its page");
        assert_eq!(map.physical(2), Some(8), "logical 2 moved to the free twin");
    }

    /// With block 1 full and a block 2 present, a claim lands in block 2 and
    /// the new logical id is numbered from block 2's own base.
    ///
    /// This is the capability, as opposed to
    /// [`claiming_works_on_a_file_that_has_a_second_block`], which only shows
    /// the blanket refusal is gone. A slot's position within its block is the
    /// id it answers for, so block 2 slot 0 is logical
    /// `entries_per_block + 1` -- getting that arithmetic wrong writes a real
    /// entry under an id nothing will ever resolve to.
    ///
    /// Twelve-byte pages: one entry a block, stride three, so block 1's pair
    /// is at physical 2/3 and block 2's at 5/6.
    #[test]
    fn a_claim_lands_in_the_second_block_once_the_first_is_full() {
        let page_size: usize = ENTRIES + ENTRY;
        assert_eq!(Map::entries_per_block(page_size), 1, "one entry a block");
        let mut file = vec![0u8; page_size * 8];
        let at = |page: usize| page * page_size;

        // Block 1 at 2/3, copy 3 live, its single entry already claimed.
        // Block 2 at 5/6, copy 6 live, claiming nothing.
        for (first, index) in [(2usize, 1u16), (5, 2)] {
            for page in [first, first + 1] {
                file[at(page)..at(page) + 2].copy_from_slice(MAGIC);
                file[at(page) + BLOCK..at(page) + BLOCK + 2]
                    .copy_from_slice(&index.to_le_bytes());
            }
            file[at(first) + GENERATION..at(first) + GENERATION + 2]
                .copy_from_slice(&1u16.to_le_bytes());
            file[at(first + 1) + GENERATION..at(first + 1) + GENERATION + 2]
                .copy_from_slice(&2u16.to_le_bytes());
        }
        let entry = at(3) + ENTRIES;
        file[entry..entry + 2].copy_from_slice(&0x4400u16.to_le_bytes());
        file[entry + 2..entry + 4].copy_from_slice(&4u16.to_le_bytes());
        file[at(4) + LOGICAL..at(4) + LOGICAL + 2].copy_from_slice(&1u16.to_le_bytes());

        let content = vec![0u8; page_size];
        let logical = via_store(&mut file, page_size as u16, |s| Map::claim(s, page_size as u16, &content, [0x00, 0x44]))
            .expect("block 1 is full, so the claim belongs to block 2");

        assert_eq!(logical, 2, "block 2 slot 0 is logical entries_per_block + 1");
        let map = Map::read(&mut Store::from_bytes(&file, page_size as u16).expect("test fixture"), page_size as u16).expect("resolves");
        assert_eq!(map.physical(2), Some(8), "the appended page, claimed by block 2");
        assert_eq!(map.physical(1), Some(4), "block 1's claim is untouched");
    }

    /// A logical id whose slot lives in allocation-table block **2** relocates
    /// through block 2's own shadow pair.
    ///
    /// `PP2BLOCK.DAT`'s 512-byte pages give `(512 - 8) / 4 == 126` entries a
    /// block, so block 1 answers logical 1 to 126 and block 2 answers 127
    /// onward from its pair at physical 130/131. [`Map::read`] has resolved
    /// both blocks by formula since the page-addressing plan's Task 3; the
    /// write paths did not, and refused any file with a second block outright
    /// -- which is the wall MajorMUD-NT's boot hits on `WCCMP002.DAT`:
    ///
    /// ```text
    /// WGSERVER.EXE.dfaupdatedup refused: WCCMP002.DAT: relocating the
    /// record's page: physical page 1026 is allocation-table block 2, and
    /// relocating a page only handles a single-block file
    /// ```
    ///
    /// Logical 127 is block 2's slot 0, claimed at physical 128. Relocating it
    /// must rewrite **block 2's** stale copy and bump **block 2's** generation,
    /// leaving block 1's pair untouched -- a generation counter is only ever
    /// compared within one block's own two copies.
    #[test]
    fn a_logical_id_in_the_second_block_relocates_through_that_blocks_pair() {
        const PAGE: usize = 512;
        let mut file = fixture("PP2BLOCK.DAT");
        let before = Map::read(&mut Store::from_bytes(&file, PAGE as u16).expect("test fixture"), PAGE as u16).expect("resolves");
        assert_eq!(
            before.physical(127),
            Some(128),
            "logical 127 is block 2's slot 0, claimed at physical 128"
        );
        let block1 = file[2 * PAGE..4 * PAGE].to_vec();

        let mut content = vec![0u8; PAGE];
        content[32..40].fill(0xCC);
        let to = via_store(&mut file, PAGE as u16, |s| Map::relocate(s, PAGE as u16, 127, &content, [0x00, 0x44]))
            .expect("logical 127 is claimed in block 2, so it can be relocated");

        assert_ne!(to, 128, "a relocation never writes the page it supersedes");
        assert_eq!(
            &file[to as usize * PAGE + 32..to as usize * PAGE + 40],
            &[0xCC; 8],
            "the new content landed on the page the call named"
        );

        let after = Map::read(&mut Store::from_bytes(&file, PAGE as u16).expect("test fixture"), PAGE as u16).expect("still resolves");
        assert_eq!(
            after.physical(127),
            Some(to),
            "block 2's table now points logical 127 at its new home"
        );
        assert_eq!(
            file[2 * PAGE..4 * PAGE],
            block1[..],
            "block 1's pair is untouched -- the write belonged to block 2"
        );

        // Every other id still resolves exactly where it did. A block-2 write
        // that clobbered block 1, or renumbered slots across the boundary,
        // shows up here and nowhere else.
        for (logical, physical) in before.entries() {
            if logical == 127 {
                continue;
            }
            assert_eq!(
                after.physical(logical),
                Some(physical),
                "logical {logical} moved, and only 127 was relocated"
            );
        }
    }

    /// Ten 512-byte pages with an allocation-table pair at 2/3, copy 3 live
    /// and claiming nothing yet.
    ///
    /// Entries are addressed by **slot**, because under the engine's own
    /// resolution a slot's position within the block *is* the logical id it
    /// answers for -- there is nothing else to read it from.
    fn indexed_fixture() -> Vec<u8> {
        const PAGE: usize = 512;
        let mut out = vec![0u8; PAGE * 10];
        for (page, generation) in [(2usize, 1u16), (3, 2)] {
            let at = page * PAGE;
            out[at..at + 2].copy_from_slice(MAGIC);
            out[at + BLOCK..at + BLOCK + 2].copy_from_slice(&1u16.to_le_bytes());
            out[at + GENERATION..at + GENERATION + 2]
                .copy_from_slice(&generation.to_le_bytes());
        }
        out
    }

    /// Point block 1's entry for `logical` at `physical`, marked as a live
    /// data page.
    fn set_entry(file: &mut [u8], logical: u32, physical: u16) {
        set_entry_raw(file, logical, 0x4400, physical);
    }

    /// The same, with the marker spelled out -- the marker's **high** byte is
    /// the page type the engine tests for, so `0x0050` is an unallocated slot
    /// and `0x4400` is a live one.
    fn set_entry_raw(file: &mut [u8], logical: u32, marker: u16, physical: u16) {
        const PAGE: usize = 512;
        let slot = (logical - 1) as usize;
        let at = 3 * PAGE + ENTRIES + slot * ENTRY;
        file[at..at + 2].copy_from_slice(&marker.to_le_bytes());
        file[at + 2..at + 4].copy_from_slice(&physical.to_le_bytes());
    }

    /// Stamp a page's own header with a logical id and a type tag -- the bytes
    /// the engine never consults when resolving.
    fn set_header(file: &mut [u8], page: usize, tag: u16, logical: u16) {
        const PAGE: usize = 512;
        let at = page * PAGE;
        file[at..at + 2].copy_from_slice(&tag.to_le_bytes());
        file[at + LOGICAL..at + LOGICAL + 2].copy_from_slice(&logical.to_le_bytes());
    }

    /// The engine indexes the allocation table; it never groups pages by the
    /// logical id in their own headers. So a page carrying a stale header id is
    /// not a competing claim -- it is bytes nothing reads.
    #[test]
    fn a_stale_header_logical_id_is_never_consulted() {
        let mut file = indexed_fixture();
        // The table answers logical 1 with physical 6 and logical 4 with 7.
        set_entry(&mut file, 1, 6);
        set_entry(&mut file, 4, 7);
        // Both pages nonetheless stamp themselves logical 1 in their own
        // headers -- and both are claimed, so no marker filter can separate
        // them. Only the table's *position* can.
        set_header(&mut file, 6, 0x4400, 1);
        set_header(&mut file, 7, 0x4400, 1);

        let map = Map::read(&mut Store::from_bytes(&file, 512).expect("test fixture"), 512).expect("no collision exists to find");
        assert_eq!(map.physical(1), Some(6), "the table decides, not the header");
        assert_eq!(
            map.physical(4),
            Some(7),
            "page 7 answers for the slot that names it, not for what it says"
        );
    }

    /// Two *written* pages both claiming one logical id in their headers is
    /// likewise not a collision -- `wccnt7po`'s logical 2 (physical 5 and 8)
    /// has exactly this shape, and the engine reads that file without
    /// difficulty.
    #[test]
    fn two_written_pages_claiming_one_logical_id_are_not_a_collision() {
        let mut file = indexed_fixture();
        set_entry(&mut file, 2, 5);
        set_entry(&mut file, 6, 8);
        // Both are live, both are claimed, and both say logical 2.
        for page in [5usize, 8] {
            set_header(&mut file, page, 0x4400, 2);
        }
        let map = Map::read(&mut Store::from_bytes(&file, 512).expect("test fixture"), 512).expect("the table names exactly one");
        assert_eq!(map.physical(2), Some(5));
        assert_eq!(map.physical(6), Some(8));
    }

    /// A logical page whose entry carries a zero type byte was never
    /// allocated, and must not resolve to anything -- even when the entry's
    /// low byte is set and its page number looks plausible.
    #[test]
    fn an_unallocated_logical_page_resolves_to_nothing() {
        let mut file = indexed_fixture();
        set_entry_raw(&mut file, 3, 0x0050, 9);
        set_header(&mut file, 9, 0x4400, 3);
        let map = Map::read(&mut Store::from_bytes(&file, 512).expect("test fixture"), 512).expect("an unallocated slot is not an error");
        assert_eq!(
            map.physical(3),
            None,
            "the type byte is the marker's high byte, and it is zero here"
        );
    }

    /// A slot's position within its block *is* the logical id, so the very
    /// first slot answers for logical 1 -- the claim an earlier reading of this
    /// format treated as a special "overflow" field at `0x0a`, which is really
    /// just this entry's own physical-page half.
    #[test]
    fn the_first_slot_answers_for_logical_one() {
        let mut file = indexed_fixture();
        set_entry(&mut file, 1, 4);
        let map = Map::read(&mut Store::from_bytes(&file, 512).expect("test fixture"), 512).expect("resolves");
        assert_eq!(map.physical(1), Some(4));
        // And that physical half sits exactly where `OVERFLOW` used to be read.
        assert_eq!(
            u16::from_le_bytes([file[3 * 512 + 0x0a], file[3 * 512 + 0x0b]]),
            4,
            "0x0a is entry slot 0's physical page, not a field of its own"
        );
    }

    fn assert_map(map: &Map, expected: &[(u32, u32)]) {
        let want: Map16<u32, u32> = expected.iter().copied().collect();
        assert_eq!(map.physical.len(), want.len(), "map size differs");
        for (&logical, &physical) in &want {
            assert_eq!(
                map.physical(logical),
                Some(physical),
                "logical {logical}: expected physical {physical}"
            );
        }
    }

    /// The pair that makes this necessary. `NONMONO2.DAT` was produced by
    /// deleting a record and reinserting a longer one, and three logical ids
    /// each have two physical claimants -- the live page and a freed one
    /// that kept its stale self-stamp. Scanning page headers alone cannot
    /// tell them apart; the allocation table's marker can, and does:
    /// non-zero means claimed.
    ///
    /// Logical 26 resolves to the **higher** physical page while 11 and 14
    /// resolve to the lower -- asserting only the first two would still pass
    /// an implementation that always picked the lower physical page, so all
    /// three are asserted.
    #[test]
    fn a_freed_page_keeps_its_logical_id_and_the_allocation_table_settles_it() {
        let file = fixture("NONMONO2.DAT");
        let map = Map::read(&mut Store::from_bytes(&file, 512).expect("test fixture"), 512).expect("resolves");
        assert_eq!(map.physical(11), Some(7));
        assert_eq!(map.physical(14), Some(17));
        assert_eq!(map.physical(26), Some(36));
        // 24 slots allocated in block 1, logical 1 among them -- an empty
        // `0x8000` template, exactly as in every other fixture here. Harmless
        // (an empty template holds no records `records::walk_v6` would read) but
        // real: slot 0 is where this file's allocation table puts logical 1.
        // Slot 0 is the entry an earlier reading of this format mistook for a
        // separate `OVERFLOW` field at `0x0a`.
        assert_eq!(map.physical(1), Some(13));
        assert_eq!(map.physical.len(), 24, "24 allocated slots, slot 0 included");
    }

    /// The control for the pair above: the same file immediately *before*
    /// the delete-and-reinsert, with no duplicate logical ids at all. A scan
    /// -only implementation passes this one and fails `NONMONO2` -- this is
    /// the regression signal that the marker filter, not just page
    /// resolution in general, is doing the work.
    #[test]
    fn nonmono1_the_control_before_the_delete_has_no_duplicates() {
        let file = fixture("NONMONO1.DAT");
        let map = Map::read(&mut Store::from_bytes(&file, 512).expect("test fixture"), 512).expect("resolves");
        assert_map(
            &map,
            &[
                // Logical 1: block 1's slot 0, an empty `0x8000` template.
                (1, 13),
                (2, 12), (5, 8), (6, 9), (7, 10), (8, 14), (9, 6), (10, 7),
                (11, 17), (12, 15), (13, 16), (14, 20), (15, 18), (16, 19),
                (17, 23), (18, 21), (19, 22), (20, 26), (24, 27), (25, 28),
                (26, 29),
            ],
        );
    }

    /// `DUPKEY30.DAT` is the one real file the engine built and this repo
    /// owns. Physical 5 is a stale twin of logical 2, tagged `0x4400` just
    /// like the live physical 10 is, but carries a zero marker -- absent
    /// from the map, not a conflict. Every other logical id in the file
    /// (0, 1, ...) has no live claimant at all and is likewise absent.
    #[test]
    fn dupkey30_only_two_logical_ids_have_a_live_claimant() {
        let file = fixture("DUPKEY30.DAT");
        let map = Map::read(&mut Store::from_bytes(&file, 512).expect("test fixture"), 512).expect("resolves");
        // Logical 1 resolves too, from block 1's slot 0 -- physical 9, an
        // empty `0x8000` template. It reads no differently than any other
        // logical id: `records::walk_v6` skips it by its tag, same as it always
        // has. Slot 0 is the entry an earlier reading of this format mistook
        // for a separate field at `0x0a`, which is why block 1 resolves it
        // to something harmless like this one.
        assert_map(&map, &[(1, 9), (2, 10), (5, 8)]);
        assert_eq!(map.physical(0), None);
    }

    /// Catches a 125-entry-per-page capacity hard-coded for a 512-byte page:
    /// `PP2048.DAT`'s pages are 2048 bytes, `(2048 - 0x0c) / 4 == 509`
    /// entries, and its one live id sits at entry index far past 125.
    #[test]
    fn pp2048_a_2048_byte_page_still_finds_its_one_live_id() {
        let file = fixture("PP2048.DAT");
        let map = Map::read(&mut Store::from_bytes(&file, 2048).expect("test fixture"), 2048).expect("resolves");
        // Logical 1 -> physical 9: block 1's slot 0, same as every other
        // fixture in this file, at whatever page size.
        assert_map(&map, &[(1, 9), (2, 8)]);
    }

    /// Catches locating a second allocation-table block by formula rather
    /// than by scanning: `PP2BLOCK.DAT` has a second block at physical
    /// 130/131, discovered nowhere near a fixed offset from the first pair.
    /// 136 logical ids have a live claimant in the regular entry arrays, and
    /// this asserts every one of them against the reference implementation's
    /// own output (`.scratch-v6-exec/expected_map.py`, `expected_maps.txt`)
    /// rather than a handful of spot checks -- plus each block's slot 0
    /// (logical 1 and logical 127), which that reference implementation and
    /// this module both used to read as a separate field, for 138 total.
    #[test]
    fn pp2block_a_second_allocation_table_block_is_found_by_scanning() {
        let file = fixture("PP2BLOCK.DAT");
        let map = Map::read(&mut Store::from_bytes(&file, 512).expect("test fixture"), 512).expect("resolves");
        assert_map(
            &map,
            &[
                // Each block's slot 0: block 1's is logical 1
                // at physical 147, block 2's is logical 127 at physical 128
                // -- the exact page the page-addressing plan's own Evidence
                // catalogue named as "unclaimed" (`128 and 147... is
                // unclaimed, exactly as if its marker were zero"). Both are
                // empty `0x8000` templates; the correction is that they are
                // in the allocation table after all, just not in either
                // block's regular entry array -- not that they hold records.
                (1, 147), (127, 128),
                (2, 6), (3, 5), (4, 4), (5, 8), (6, 7), (7, 10), (8, 11),
                (9, 149), (10, 9), (11, 13), (12, 14), (13, 15), (14, 18),
                (15, 12), (16, 19), (17, 33), (18, 21), (19, 20), (20, 23),
                (21, 27), (22, 16), (23, 22), (24, 26), (25, 17), (26, 29),
                (27, 28), (28, 31), (29, 34), (30, 24), (31, 37), (32, 30),
                (33, 25), (34, 38), (35, 35), (36, 36), (37, 41), (38, 32),
                (39, 43), (40, 42), (41, 45), (42, 44), (43, 40), (44, 47),
                (45, 46), (46, 50), (47, 39), (48, 54), (49, 48), (50, 49),
                (51, 55), (52, 51), (53, 53), (54, 58), (55, 52), (56, 56),
                (57, 59), (58, 57), (59, 61), (60, 64), (61, 60), (62, 62),
                (63, 63), (64, 66), (65, 65), (66, 73), (67, 67), (68, 70),
                (69, 86), (70, 69), (71, 68), (72, 74), (73, 75), (74, 76),
                (75, 72), (76, 77), (77, 80), (78, 71), (79, 78), (80, 81),
                (81, 84), (82, 87), (83, 79), (84, 85), (85, 88), (86, 90),
                (87, 89), (88, 82), (89, 92), (90, 91), (91, 101), (92, 95),
                (93, 143), (94, 98), (95, 97), (96, 94), (97, 93), (98, 83),
                (99, 99), (100, 102), (101, 100), (102, 104), (103, 105),
                (104, 107), (105, 111), (106, 108), (107, 106), (108, 112),
                (109, 103), (110, 110), (111, 113), (112, 109), (113, 115),
                (114, 116), (115, 119), (116, 114), (117, 117), (118, 135),
                (119, 121), (120, 120), (121, 127), (122, 123), (123, 125),
                (124, 126), (125, 118), (126, 129), (128, 133), (129, 136),
                (130, 122), (131, 138), (132, 137), (135, 141), (136, 134),
                (139, 144), (140, 146), (141, 139), (142, 142),
            ],
        );
    }

    /// A file with no `"PP"` magic at physical page 2 or 3 at all -- Trap 2's
    /// first named refusal, exercised directly rather than only through the
    /// shape of a real fixture: two ordinary-looking pages, no allocation
    /// table anywhere the design trusts a fixed position for.
    #[test]
    fn a_file_with_no_pp_table_at_physical_two_or_three_is_refused() {
        let file = vec![0u8; 512 * 4];
        let e = Map::read(&mut Store::from_bytes(&file, 512).expect("test fixture"), 512).unwrap_err();
        assert!(e.contains("physical page 2 nor 3"), "{e}");
    }

    /// Trap 2's second named refusal: two shadow copies of the same
    /// allocation-table block claiming the same generation. Built by hand
    /// because no fixture in the corpus has this shape -- Evidence 3a says
    /// none of the eight committed files ever produced a tie.
    #[test]
    fn a_tied_generation_within_an_allocation_table_block_is_refused() {
        let mut file = vec![0u8; 512 * 4];
        for page in [2usize, 3] {
            let at = page * 512;
            file[at..at + 2].copy_from_slice(MAGIC);
            file[at + BLOCK..at + BLOCK + 2].copy_from_slice(&1u16.to_le_bytes());
            file[at + GENERATION..at + GENERATION + 2].copy_from_slice(&5u16.to_le_bytes());
        }
        let e = Map::read(&mut Store::from_bytes(&file, 512).expect("test fixture"), 512).unwrap_err();
        assert!(e.contains("generation 5"), "{e}");
    }

    /// What used to be "Trap 2's third named refusal": two *claimed* pages
    /// holding the same logical id in their own headers, refused as a
    /// contradiction.
    ///
    /// It is not one. The engine resolves a logical id by indexing the
    /// allocation table and never reads a page's self-stamp, so two pages
    /// agreeing on a stale id are two pages nothing asks about -- and the six
    /// real files this refusal was rejecting are files genuine Btrieve reads
    /// without difficulty. The refusal is gone; this test now pins the shape it
    /// used to reject, and the two entries claim *different* slots because that
    /// is the only thing that decides a logical id.
    #[test]
    fn two_claimed_pages_stamped_with_one_logical_id_are_read_not_refused() {
        let mut file = vec![0u8; 512 * 6];
        let at = |page: usize| page * 512;

        file[at(2)..at(2) + 2].copy_from_slice(MAGIC);
        file[at(2) + BLOCK..at(2) + BLOCK + 2].copy_from_slice(&1u16.to_le_bytes());
        file[at(2) + GENERATION..at(2) + GENERATION + 2].copy_from_slice(&5u16.to_le_bytes());
        let entry = |n: usize| at(2) + ENTRIES + n * ENTRY;
        file[entry(0)..entry(0) + 2].copy_from_slice(&0x4400u16.to_le_bytes());
        file[entry(0) + 2..entry(0) + 4].copy_from_slice(&4u16.to_le_bytes());
        file[entry(1)..entry(1) + 2].copy_from_slice(&0x4400u16.to_le_bytes());
        file[entry(1) + 2..entry(1) + 4].copy_from_slice(&5u16.to_le_bytes());

        // Both claimed pages stamp themselves logical 7. Bytes nothing reads.
        file[at(4) + LOGICAL..at(4) + LOGICAL + 2].copy_from_slice(&7u16.to_le_bytes());
        file[at(5) + LOGICAL..at(5) + LOGICAL + 2].copy_from_slice(&7u16.to_le_bytes());

        let map = Map::read(&mut Store::from_bytes(&file, 512).expect("test fixture"), 512).expect("no contradiction exists here");
        assert_eq!(map.physical(1), Some(4), "slot 0 answers for logical 1");
        assert_eq!(map.physical(2), Some(5), "slot 1 answers for logical 2");
        assert_eq!(map.physical(7), None, "nothing claims logical 7 at all");
    }

    /// Physical page 0 is the file control record. Nothing in the corpus ever
    /// claims it -- verified across all ten v6 files this repository has,
    /// including the shipped `NEWMP001.VIR` -- so a table that does is a
    /// contradiction rather than an unusual file.
    ///
    /// The page's `"FC"` magic is deliberately *not* what excludes it here:
    /// this fixture leaves page 0 all zero, so a version that skipped the
    /// control record by its tag alone would map logical 0 to physical 0 and
    /// hand a caller the control record as an ordinary page.
    #[test]
    fn an_allocation_table_that_claims_the_control_record_is_refused() {
        let mut file = vec![0u8; 512 * 6];
        let at = |page: usize| page * 512;

        file[at(2)..at(2) + 2].copy_from_slice(MAGIC);
        file[at(2) + BLOCK..at(2) + BLOCK + 2].copy_from_slice(&1u16.to_le_bytes());
        file[at(2) + GENERATION..at(2) + GENERATION + 2].copy_from_slice(&5u16.to_le_bytes());

        // `0x4400`, a live data page: the marker's HIGH byte is the page type
        // the engine tests, so a marker of 1 would be an unallocated slot and
        // this fixture would assert nothing.
        let entry = at(2) + ENTRIES;
        file[entry..entry + 2].copy_from_slice(&0x4400u16.to_le_bytes()); // marker
        file[entry + 2..entry + 4].copy_from_slice(&0u16.to_le_bytes()); // physical page 0

        let e = Map::read(&mut Store::from_bytes(&file, 512).expect("test fixture"), 512).unwrap_err();
        assert!(e.contains("physical page 0"), "{e}");
        assert!(e.contains("control record"), "{e}");
    }

    /// A page long enough to reach the entry array but too short to hold one
    /// whole entry divided out to zero entries and returned an empty map --
    /// success, for a file nothing had been read from. No real Btrieve page
    /// is this small; the refusal exists so the answer is never "an empty
    /// map, and no reason".
    #[test]
    fn a_page_too_short_for_one_whole_entry_is_refused_not_answered_empty() {
        // One page, sized to whatever `size` is this iteration -- `Store`
        // itself only asks for a whole number of pages, so the point being
        // tested (`Map::read`'s own too-small-for-an-entry refusal) has to
        // reach it via a buffer that clears that unrelated bar.
        for size in [ENTRIES + 1, ENTRIES + ENTRY - 1] {
            let file = vec![0u8; size];
            let e = Map::read(&mut Store::from_bytes(&file, size as u16).expect("test fixture"), size as u16).unwrap_err();
            assert!(e.contains("no room for an allocation-table entry"), "{e}");
        }
    }

    /// Position is what identifies block 1, so the block index found there
    /// has to agree. A `"PP"` page at physical 2 calling itself block 7 would
    /// otherwise become a lone unpaired copy -- and a single copy is
    /// automatically live, never reaching the generation-tie check.
    #[test]
    fn a_pp_page_at_physical_two_that_is_not_block_one_is_refused() {
        let mut file = vec![0u8; 512 * 6];
        let at = |page: usize| page * 512;

        file[at(2)..at(2) + 2].copy_from_slice(MAGIC);
        file[at(2) + BLOCK..at(2) + BLOCK + 2].copy_from_slice(&7u16.to_le_bytes());
        file[at(2) + GENERATION..at(2) + GENERATION + 2].copy_from_slice(&5u16.to_le_bytes());

        let e = Map::read(&mut Store::from_bytes(&file, 512).expect("test fixture"), 512).unwrap_err();
        assert!(e.contains("block 7"), "{e}");
    }

    /// `Map::claim`, Task 13 Step 1 of the plan (allocation-table
    /// maintenance) -- see the function's own doc comment for scope. Not yet
    /// wired into `Block::insert` or the oracle: this is the mechanism in
    /// isolation, checked against this module's own reader.
    #[test]
    fn claim_adds_a_new_logical_page_and_disturbs_nothing_else() {
        let mut file = fixture("DUPKEY30.DAT");
        let before = Map::read(&mut Store::from_bytes(&file, 512).expect("test fixture"), 512).expect("resolves before");

        let mut content = vec![0u8; 512];
        content[6..10].copy_from_slice(b"NEW!");
        let logical = via_store(&mut file, 512, |s| Map::claim(s, 512, &content, [0x00, 0x44])).expect("claims");

        // A slot's position within block 1 *is* the logical id it answers for,
        // so the new page's id is the first free slot rather than one past the
        // highest claimed. Measured on this fixture's live copy (physical 3):
        // slot 0 is allocated (type 0x80, physical 9), slot 1 is allocated
        // (0x44, physical 10), slot 2 is free -- so the answer is logical 3.
        //
        // The old answer was 6, from taking the highest logical id claimed and
        // adding one. That read each claimed page's own header to learn its id,
        // and it would skip every hole in the array: here it left logical 3 and
        // 4 permanently unreachable while numbering a fourth page 6.
        assert_eq!(logical, 3);

        let after = Map::read(&mut Store::from_bytes(&file, 512).expect("test fixture"), 512).expect("resolves after");
        for (l, p) in before.entries() {
            assert_eq!(after.physical(l), Some(p), "logical {l} moved");
        }
        let new_physical = after.physical(logical).expect("the new id resolves");
        let at = new_physical as usize * 512;
        assert_eq!(&file[at..at + 2], [0x00, 0x44], "the new page's own tag");
        assert_eq!(&file[at + LOGICAL..at + LOGICAL + 2], 3u16.to_le_bytes());
        assert_eq!(&file[at + 6..at + 10], b"NEW!", "the caller's content landed");
    }

    /// Two claims in a row exercise the shadow flip both ways: the first
    /// claim's stale copy becomes live, so the second claim has to find
    /// *that* one stale and flip it back -- not repeat writing physical 2 (or
    /// 3) forever because it cached which was which.
    #[test]
    fn claiming_twice_flips_the_shadow_pair_both_ways() {
        let mut file = fixture("DUPKEY30.DAT");
        let content = vec![0u8; 512];

        let first = via_store(&mut file, 512, |s| Map::claim(s, 512, &content, [0x00, 0x44])).expect("first claim");
        let gen_after_first = u16::from_le_bytes([
            file[2 * 512 + GENERATION],
            file[2 * 512 + GENERATION + 1],
        ])
        .max(u16::from_le_bytes([
            file[3 * 512 + GENERATION],
            file[3 * 512 + GENERATION + 1],
        ]));

        let second = via_store(&mut file, 512, |s| Map::claim(s, 512, &content, [0x00, 0x44])).expect("second claim");
        assert_eq!(second, first + 1);

        let map = Map::read(&mut Store::from_bytes(&file, 512).expect("test fixture"), 512).expect("resolves");
        assert!(map.physical(first).is_some());
        assert!(map.physical(second).is_some());
        assert_ne!(
            map.physical(first),
            map.physical(second),
            "two different claims must not land on the same physical page"
        );

        let gen_after_second = u16::from_le_bytes([
            file[2 * 512 + GENERATION],
            file[2 * 512 + GENERATION + 1],
        ])
        .max(u16::from_le_bytes([
            file[3 * 512 + GENERATION],
            file[3 * 512 + GENERATION + 1],
        ]));
        assert!(
            gen_after_second > gen_after_first,
            "the second claim must bump the generation again, not repeat the first's"
        );
    }

    /// Mutation: revert the generation bump `claim` just made, leaving the
    /// new entry's bytes physically present but on the copy the generation
    /// comparison no longer picks. If this test failed to fail, the
    /// generation field would not be load-bearing -- exactly Trap 2's shape.
    #[test]
    fn without_the_generation_bump_the_new_claim_is_invisible() {
        let mut file = fixture("DUPKEY30.DAT");
        let content = vec![0u8; 512];
        let logical = via_store(&mut file, 512, |s| Map::claim(s, 512, &content, [0x00, 0x44])).expect("claims");

        // Whichever of 2/3 is now live, roll its generation down below the
        // *other* copy's -- undoing only the bump, leaving the new entry's
        // bytes in place. Not a plain `- 1`: a single claim always leaves
        // the two copies exactly one generation apart, so the copy that was
        // live before this claim already holds `new - 1` -- subtracting one
        // would tie them rather than un-bump anything.
        let live = if u16::from_le_bytes([file[2 * 512 + GENERATION], file[2 * 512 + GENERATION + 1]])
            > u16::from_le_bytes([file[3 * 512 + GENERATION], file[3 * 512 + GENERATION + 1]])
        {
            2
        } else {
            3
        };
        let at = live * 512 + GENERATION;
        file[at..at + 2].copy_from_slice(&0u16.to_le_bytes());

        let map = Map::read(&mut Store::from_bytes(&file, 512).expect("test fixture"), 512).expect("resolves");
        assert_eq!(
            map.physical(logical),
            None,
            "with the bump undone the new claim must not be visible -- the \
             bytes alone are not what makes it live"
        );
    }

    /// A file whose blocks are all full is refused rather than silently
    /// growing a *new* block -- still the stated scope boundary, now that
    /// claiming scans every block that already exists.
    ///
    /// Twelve-byte pages give one entry a block and a stride of three, so
    /// block 2's pair would sit at physical 5 and 6 of a five-page file:
    /// past the end, which [`Map::pair_of`] refuses and the scan reads as
    /// the end of the table. Block 1 is full and there is no block 2, so
    /// there is nowhere left to put a claim.
    #[test]
    fn claim_refuses_a_block_with_no_free_entry_left() {
        // A tiny page (the smallest this format allows an entry array on)
        // gives block 1 exactly one entry of capacity, already claimed.
        let page_size: usize = ENTRIES + ENTRY;
        let mut file = vec![0u8; page_size * 5];
        let at = |page: usize| page * page_size;

        for (page, generation) in [(2usize, 1u16), (3, 1)] {
            file[at(page)..at(page) + 2].copy_from_slice(MAGIC);
            file[at(page) + BLOCK..at(page) + BLOCK + 2].copy_from_slice(&1u16.to_le_bytes());
            file[at(page) + GENERATION..at(page) + GENERATION + 2]
                .copy_from_slice(&generation.to_le_bytes());
        }
        // Page 3 is live (equal generations would refuse); make it strictly
        // higher and give it the one claimed entry, naming physical page 4.
        file[at(3) + GENERATION..at(3) + GENERATION + 2].copy_from_slice(&2u16.to_le_bytes());
        let entry = at(3) + ENTRIES;
        file[entry..entry + 2].copy_from_slice(&0x4400u16.to_le_bytes());
        file[entry + 2..entry + 4].copy_from_slice(&4u16.to_le_bytes());
        file[at(4) + LOGICAL..at(4) + LOGICAL + 2].copy_from_slice(&2u16.to_le_bytes());

        let content = vec![0u8; page_size];
        let e = via_store(&mut file, page_size as u16, |s| Map::claim(s, page_size as u16, &content, [0x00, 0x44])).unwrap_err();
        assert!(e.contains("already claims all"), "{e}");
    }

    /// Mutation: claim a physical page (write its content, header included)
    /// but do not record the entry -- reproduced deliberately rather than
    /// found by accident. A page's own header is never what proves it live (Evidence
    /// 3/3a, this module's own top doc comment); only an allocation-table
    /// entry naming it is. If this test failed to fail, that whole design
    /// would be false.
    #[test]
    fn without_the_pp_table_entry_the_new_page_is_an_orphan() {
        let mut file = fixture("DUPKEY30.DAT");
        let mut content = vec![0u8; 512];
        content[6..10].copy_from_slice(b"LOST");
        let logical = via_store(&mut file, 512, |s| Map::claim(s, 512, &content, [0x00, 0x44])).expect("claims");

        // Undo only the entry this claim wrote, leaving the new page's own
        // bytes -- header and content both -- exactly as `claim` left them.
        let physical = Map::read(&mut Store::from_bytes(&file, 512).expect("test fixture"), 512)
            .expect("resolves")
            .physical(logical)
            .expect("the claim resolved a moment ago");
        let live = if u16::from_le_bytes([file[2 * 512 + GENERATION], file[2 * 512 + GENERATION + 1]])
            > u16::from_le_bytes([file[3 * 512 + GENERATION], file[3 * 512 + GENERATION + 1]])
        {
            2
        } else {
            3
        };
        let entries_per_page = (512 - ENTRIES) / ENTRY;
        let mut cleared = false;
        for entry in 0..entries_per_page {
            let at = live * 512 + ENTRIES + entry * ENTRY;
            let marker = u16::from_le_bytes([file[at], file[at + 1]]);
            let claimed_page = u16::from_le_bytes([file[at + 2], file[at + 3]]);
            if marker != 0 && u32::from(claimed_page) == physical {
                file[at..at + 2].copy_from_slice(&0u16.to_le_bytes());
                cleared = true;
                break;
            }
        }
        assert!(cleared, "the entry `claim` wrote has to exist to clear it");

        let map = Map::read(&mut Store::from_bytes(&file, 512).expect("test fixture"), 512).expect("resolves");
        assert_eq!(
            map.physical(logical),
            None,
            "a page's own header content must not be enough on its own -- \
             only the allocation-table entry makes a claim real"
        );
    }

    /// `Map::unclaim`, `claim`'s inverse -- Task 3b's fix for `v6_reindex`
    /// leaving a shrunk tree's surplus pages claimed. Mirrors `claim`'s own
    /// four tests (fresh-add, double-flip, refuse, second-block) rather than
    /// only being exercised indirectly through `lib.rs`'s two integration
    /// scenarios -- an inverse operation with no direct test of its own
    /// refusals is exactly the shape this project keeps finding.
    ///
    /// `DUPKEY30.DAT`'s live copy (physical 3) claims logical 1 at physical 9
    /// and logical 2 at physical 10 -- measured in
    /// `claim_adds_a_new_logical_page_and_disturbs_nothing_else`'s own
    /// comment. Releasing logical 2 must clear only its own entry, leave
    /// logical 1 and every other page byte-for-byte alone, and bump the
    /// generation the same way `claim` does.
    #[test]
    fn unclaim_releases_a_claimed_entry_and_disturbs_nothing_else() {
        let mut file = fixture("DUPKEY30.DAT");
        let before = Map::read(&mut Store::from_bytes(&file, 512).expect("test fixture"), 512).expect("resolves before");
        assert_eq!(before.physical(2), Some(10), "measured baseline");
        let physical10_before = file[10 * 512..11 * 512].to_vec();

        via_store(&mut file, 512, |s| Map::unclaim(s, 512, 2)).expect("logical 2 is claimed");

        let after = Map::read(&mut Store::from_bytes(&file, 512).expect("test fixture"), 512).expect("resolves after");
        assert_eq!(after.physical(2), None, "logical 2 is no longer claimed");
        assert_eq!(after.physical(1), Some(9), "logical 1 untouched");
        assert_eq!(
            file[10 * 512..11 * 512],
            physical10_before[..],
            "unclaim never touches the abandoned page's own bytes -- only \
             the allocation-table entry"
        );
    }

    /// Releasing a logical id nothing claims is refused, not a silent no-op
    /// -- the same discipline `claim`'s own refusals hold to. Logical 3 is
    /// `DUPKEY30.DAT`'s first free slot (the same fact
    /// `claim_adds_a_new_logical_page_and_disturbs_nothing_else` claims into).
    #[test]
    fn unclaim_refuses_a_logical_id_nothing_claims() {
        let mut file = fixture("DUPKEY30.DAT");
        let e = via_store(&mut file, 512, |s| Map::unclaim(s, 512, 3)).unwrap_err();
        assert!(e.contains("there is nothing to release"), "{e}");
    }

    /// Unclaiming and reclaiming exercise the shadow flip both ways, the
    /// same way `claiming_twice_flips_the_shadow_pair_both_ways` does for
    /// two claims in a row -- and prove the freed slot is genuinely back in
    /// the free pool, not merely reported empty by `Map::read`.
    #[test]
    fn unclaiming_then_claiming_reuses_the_freed_slot() {
        let mut file = fixture("DUPKEY30.DAT");

        via_store(&mut file, 512, |s| Map::unclaim(s, 512, 2)).expect("logical 2 is claimed");

        let mut content = vec![0u8; 512];
        content[6..10].copy_from_slice(b"NEW!");
        let logical = via_store(&mut file, 512, |s| Map::claim(s, 512, &content, [0x00, 0x44])).expect("claims");
        assert_eq!(
            logical, 2,
            "the lowest free slot is logical 2's, now that unclaim freed it -- \
             not logical 3, which was already free before either call"
        );

        let map = Map::read(&mut Store::from_bytes(&file, 512).expect("test fixture"), 512).expect("resolves");
        assert_eq!(map.physical(1), Some(9), "logical 1 was never touched");
        assert_eq!(map.physical(3), None, "logical 3 is still free, as it always was");
        let physical = map.physical(2).expect("the reclaim resolved");
        let at = physical as usize * 512;
        assert_eq!(&file[at + 6..at + 10], b"NEW!", "the reclaim's own content landed");
    }

    /// A logical id in allocation-table **block 2** releases through block
    /// 2's own shadow pair alone -- the multi-block correctness
    /// `relocate`'s own doc comment claims for itself but `unclaim` had no
    /// direct test of. `PP2BLOCK.DAT`'s logical 127 is block 2's slot 0,
    /// claimed at physical 128 -- the same fact
    /// `a_logical_id_in_the_second_block_relocates_through_that_blocks_pair`
    /// measures.
    #[test]
    fn unclaim_in_the_second_block_touches_only_that_blocks_pair() {
        const PAGE: usize = 512;
        let mut file = fixture("PP2BLOCK.DAT");
        let before = Map::read(&mut Store::from_bytes(&file, PAGE as u16).expect("test fixture"), PAGE as u16).expect("resolves");
        assert_eq!(before.physical(127), Some(128), "measured baseline");
        let block1 = file[2 * PAGE..4 * PAGE].to_vec();

        via_store(&mut file, PAGE as u16, |s| Map::unclaim(s, PAGE as u16, 127)).expect("logical 127 is claimed in block 2");

        assert_eq!(
            file[2 * PAGE..4 * PAGE],
            block1[..],
            "block 1's pair is untouched -- the release belonged to block 2"
        );
        let after = Map::read(&mut Store::from_bytes(&file, PAGE as u16).expect("test fixture"), PAGE as u16).expect("still resolves");
        assert_eq!(after.physical(127), None, "logical 127 is released");

        // Every other id still resolves exactly where it did. A block-2
        // release that clobbered block 1, or the wrong slot within block 2,
        // shows up here and nowhere else.
        for (logical, physical) in before.entries() {
            if logical == 127 {
                continue;
            }
            assert_eq!(after.physical(logical), Some(physical), "logical {logical} moved");
        }
    }
}
