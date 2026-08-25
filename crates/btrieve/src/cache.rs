//! A page-at-a-time cache over one Btrieve file, with dirty tracking.
//!
//! [`super::PAGE_FETCHES`] plays the same role for this cache that
//! [`super::FILE_OPENS`] plays for file opens: a choke-point count this crate
//! keeps of its own, because nothing outside the process can see "how many
//! times did a cache actually go to disk for a page" the way `/proc/self/io`
//! sees `open(2)`/`read(2)` traffic. A caller proving its own read path is
//! bounded resets it, does the read, and checks the count -- the same
//! pattern `write_cost.rs` already uses for [`super::FILE_OPENS`].
//!
//! [`v6::Store`](super::v6::Store) already caches pages this way for the v6
//! write path, with v6-specific concerns (header-only reads, shadow pairs,
//! before-images for `verify_writes`) mixed in. Nothing in this crate builds
//! a [`PageCache`] yet -- this module is the cache and its own tests only; a
//! later task routes a read path through it.

use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};

/// One resident page: the bytes as last read from disk or written into
/// memory, and whether those bytes have diverged from what disk holds.
struct CachedPage {
    bytes: Vec<u8>,
    dirty: bool,
}

/// A page-at-a-time cache over one open Btrieve file, scoped to one block's
/// working lifetime rather than the process's.
///
/// A caller reads and writes pages through it, then asks it what changed
/// when it is time to flush: [`Self::dirty_pages`] names exactly what to
/// write, [`Self::mark_clean`] says a flush succeeded, and
/// [`Self::drop_dirty`] is the abort path -- it throws every unflushed
/// change away so a caller that gives up mid-operation leaves disk exactly
/// as it found it.
pub(crate) struct PageCache {
    path: PathBuf,
    file: File,
    page_size: usize,
    pages: HashMap<u32, CachedPage>,
    total_pages: u32,
}

impl PageCache {
    /// Open `path` for page-at-a-time access. Nothing is read yet beyond the
    /// file's length, to learn how many pages it starts with -- the handle
    /// itself is opened once here and kept for every later page fetch, so a
    /// caller that touches many pages this operation still opens the file
    /// once, the same discipline [`super::FILE_OPENS`]'s doc comment
    /// describes for [`v6::Store`](super::v6::Store).
    ///
    /// # Errors
    ///
    /// If `page_size` is zero, the file cannot be opened or its metadata
    /// read, or its length is not a whole number of `page_size`-byte pages.
    pub(crate) fn open(path: &Path, page_size: u16) -> Result<Self, String> {
        let page_size = usize::from(page_size);
        if page_size == 0 {
            return Err("a page cache's page size cannot be zero".to_owned());
        }
        let file = super::open_for_read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let len = file
            .metadata()
            .map_err(|e| format!("{}: {e}", path.display()))?
            .len();
        let len = usize::try_from(len)
            .map_err(|_| format!("{}: {len} bytes does not fit this host's usize", path.display()))?;
        if !len.is_multiple_of(page_size) {
            return Err(format!(
                "{}: {len} bytes is not a whole number of {page_size}-byte pages",
                path.display()
            ));
        }
        let total_pages = u32::try_from(len / page_size)
            .map_err(|_| format!("{}: more pages than fit in a u32", path.display()))?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            page_size,
            pages: HashMap::new(),
            total_pages,
        })
    }

    /// Bring `physical` into memory if it is not resident already. The one
    /// place [`super::PAGE_FETCHES`] is incremented, and only on the branch
    /// that actually touches disk -- a cache hit costs nothing.
    ///
    /// # Errors
    ///
    /// If `physical` is at or past [`Self::total_pages`], or the file turns
    /// out to be shorter than that page claims.
    fn ensure_loaded(&mut self, physical: u32) -> Result<(), String> {
        if self.pages.contains_key(&physical) {
            return Ok(());
        }
        if physical >= self.total_pages {
            return Err(format!(
                "{}: physical page {physical}, and the file is {} pages",
                self.path.display(),
                self.total_pages
            ));
        }
        let offset = physical as usize * self.page_size;
        let bytes = super::read_at_open(&mut self.file, offset, self.page_size)
            .map_err(|e| format!("{}: {e}", self.path.display()))?;
        if bytes.len() != self.page_size {
            return Err(format!(
                "{}: physical page {physical} is only {} of {} bytes -- past the end of the file",
                self.path.display(),
                bytes.len(),
                self.page_size
            ));
        }
        super::PAGE_FETCHES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.pages.insert(physical, CachedPage { bytes, dirty: false });
        Ok(())
    }

    /// A page's whole content -- fetched from disk the first time this
    /// operation asks for it, served from memory every time after.
    ///
    /// # Errors
    ///
    /// Same as [`Self::ensure_loaded`].
    pub(crate) fn page(&mut self, physical: u32) -> Result<&[u8], String> {
        self.ensure_loaded(physical)?;
        Ok(&self.pages[&physical].bytes)
    }

    /// A page's whole content, mutably -- fetch-through the same as
    /// [`Self::page`], then marked dirty because a caller only reaches for
    /// `&mut` to change it.
    ///
    /// # Errors
    ///
    /// Same as [`Self::page`].
    pub(crate) fn page_mut(&mut self, physical: u32) -> Result<&mut Vec<u8>, String> {
        self.ensure_loaded(physical)?;
        let entry = self.pages.get_mut(&physical).expect("just loaded");
        entry.dirty = true;
        Ok(&mut entry.bytes)
    }

    /// Replace `physical`'s content outright and mark it dirty, without
    /// reading whatever was there first -- for a caller that already has
    /// the full new bytes of a page (a fresh allocation, a rebuilt index
    /// node) and would only throw away a disk read it never needed. Extends
    /// [`Self::total_pages`] when `physical` is at or past it, so appending
    /// a page is one call.
    pub(crate) fn put(&mut self, physical: u32, bytes: Vec<u8>) {
        if physical >= self.total_pages {
            self.total_pages = physical + 1;
        }
        self.pages.insert(physical, CachedPage { bytes, dirty: true });
    }

    /// Every dirty page's physical number, ascending -- exactly what a flush
    /// has to write, without diffing anything against disk.
    pub(crate) fn dirty_pages(&self) -> Vec<u32> {
        let mut out: Vec<u32> = self.pages.iter().filter(|(_, p)| p.dirty).map(|(&n, _)| n).collect();
        out.sort_unstable();
        out
    }

    /// Mark every resident page clean. Call this once a flush has actually
    /// written [`Self::dirty_pages`] to disk -- the pages stay resident,
    /// still answering [`Self::page`] from memory, but nothing is left for
    /// the next flush to redo.
    pub(crate) fn mark_clean(&mut self) {
        for page in self.pages.values_mut() {
            page.dirty = false;
        }
    }

    /// The abort path: throw away every dirty page, keeping clean ones
    /// resident. A page evicted this way has no in-memory bytes left at
    /// all, so the next [`Self::page`]/[`Self::page_mut`] on it re-reads
    /// disk from scratch -- correct because disk was never written to for a
    /// page this cache never flushed.
    ///
    /// Returns how many pages were dropped.
    pub(crate) fn drop_dirty(&mut self) -> usize {
        let dirty: Vec<u32> = self.pages.iter().filter(|(_, p)| p.dirty).map(|(&n, _)| n).collect();
        for physical in &dirty {
            self.pages.remove(physical);
        }
        dirty.len()
    }

    /// How many pages this cache currently holds in memory -- instrumentation,
    /// not a bound anything enforces.
    pub(crate) fn resident(&self) -> usize {
        self.pages.len()
    }

    /// How many pages the file has *now*, original plus anything
    /// [`Self::put`] appended past the end this operation.
    pub(crate) fn total_pages(&self) -> usize {
        self.total_pages as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises every test in this module that reads
    /// [`crate::testing::page_fetches`] -- [`super::super::PAGE_FETCHES`] is
    /// one process-global counter and the default test harness runs
    /// `#[test]`s in parallel threads, so two windows open at once would
    /// each see the other's fetches. Same reasoning, same shape, as
    /// `tests/write_cost.rs`'s own `MEASURE_LOCK`.
    static MEASURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A 3-page, 512-byte-per-page scratch file with a distinct fill byte
    /// per page -- 0xAA/0xBB/0xCC -- so a test can tell which page it read
    /// back from one byte.
    fn three_page_file(name: &str) -> std::path::PathBuf {
        let dir = crate::testing::scratch(name);
        let path = dir.join("PAGECACHE.DAT");
        let mut bytes = vec![0u8; 512 * 3];
        bytes[..512].fill(0xAA);
        bytes[512..1024].fill(0xBB);
        bytes[1024..].fill(0xCC);
        std::fs::write(&path, &bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        path
    }

    #[test]
    fn a_page_is_fetched_from_disk_once_and_served_from_memory_after() {
        let _guard = MEASURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // 3-page scratch file, distinct fill bytes per page.
        let path = three_page_file("cache-fetch-once");
        crate::testing::reset_page_fetches();
        let mut c = PageCache::open(&path, 512).expect("opens");
        assert_eq!(c.page(1).expect("reads")[0], 0xBB);
        assert_eq!(crate::testing::page_fetches(), 1);
        assert_eq!(c.page(1).expect("cached")[0], 0xBB);
        assert_eq!(crate::testing::page_fetches(), 1, "second access must not touch disk");
    }

    #[test]
    fn a_dirty_page_survives_drop_dirty_only_on_disk() {
        let _guard = MEASURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = three_page_file("cache-drop-dirty");
        let mut c = PageCache::open(&path, 512).expect("opens");

        let page = c.page_mut(2).expect("fetches then hands out a mutable page");
        assert_eq!(page[0], 0xCC, "page 2's original content, before the scribble");
        page[0] = 0x11;
        page[1] = 0x22;

        assert_eq!(c.dirty_pages(), vec![2]);
        assert_eq!(c.drop_dirty(), 1);
        assert_eq!(c.dirty_pages(), Vec::<u32>::new(), "nothing left dirty after the drop");

        let fetches_before = crate::testing::page_fetches();
        assert_eq!(
            c.page(2).expect("refetches")[0],
            0xCC,
            "drop_dirty must not leave the scribble behind -- disk was never written to"
        );
        assert_eq!(
            crate::testing::page_fetches(),
            fetches_before + 1,
            "the evicted page must come back from disk, not from memory"
        );
    }

    #[test]
    fn put_past_the_end_extends_total_pages() {
        let path = three_page_file("cache-put-extend");
        let mut c = PageCache::open(&path, 512).expect("opens");
        assert_eq!(c.total_pages(), 3);

        c.put(3, vec![0u8; 512]);

        assert_eq!(c.total_pages(), 4);
        assert_eq!(c.dirty_pages(), vec![3]);
    }

    /// [`PageCache::mark_clean`] is the flush-succeeded half of the contract
    /// [`a_dirty_page_survives_drop_dirty_only_on_disk`] exercises the
    /// abort half of: the write stays in memory and stays readable, but the
    /// page is no longer reported dirty, and it stays resident rather than
    /// being evicted.
    #[test]
    fn mark_clean_keeps_the_write_and_clears_dirty() {
        let path = three_page_file("cache-mark-clean");
        let mut c = PageCache::open(&path, 512).expect("opens");

        c.page_mut(0).expect("fetches then hands out a mutable page")[0] = 0x99;
        assert_eq!(c.dirty_pages(), vec![0]);
        assert_eq!(c.resident(), 1);

        c.mark_clean();

        assert_eq!(c.dirty_pages(), Vec::<u32>::new(), "mark_clean must clear every dirty flag");
        assert_eq!(c.resident(), 1, "mark_clean keeps the page resident, unlike drop_dirty");
        assert_eq!(c.page(0).expect("still resident")[0], 0x99, "mark_clean must not discard the write");
    }
}
