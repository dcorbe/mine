//! Reading a Btrieve file's records, and putting them in key order.
//!
//! Records live in *data pages*, packed at the physical record length and never
//! crossing a page boundary. Which pages are data pages, which slots inside
//! them are live, and which are on the free list are all things the file says;
//! this reads all three and then checks its own work against the record count
//! in the file control record.
//!
//! # The count is the acceptance check
//!
//! The header says how many records the file holds. Walking the pages produces
//! a number too, and **the two agreeing is what makes this a reading rather
//! than a guess**. They agree for every one of the eighteen files MajorMUD
//! ships and the seventeen virgin copies beside them -- 1,950 items, 1,379
//! spells, 26,720 map rooms, 38,754 update records -- and a file where they
//! disagree is refused, because the alternative is handing the module a
//! plausible subset of its own world.

use std::cmp::Ordering;
use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use super::keys::Key;
use super::variable::{Chain, Pages, Pointer};
use super::{BtvError, Geometry, Version};

/// Bytes of marker a v6 record slot opens with, before the record body.
///
/// Evidence 1b of `docs/plans/2026-08-11-btrieve-v6-page-addressing.md`,
/// measured against 1,580 oracle-dumped records: a v6 page's header is six
/// bytes exactly as v5's, and slots are `physical` bytes apart from there --
/// only the body's offset *within* the slot moves. Every slot observed holds
/// `01 00`; what the two bytes mean is not established, so this reads past
/// them rather than interpreting them.
///
/// Named because three places depend on it and a bare `2` in any of them is
/// unsearchable.
const V6_SLOT_MARKER: usize = 2;

/// Where the free list starts, in the file control record.
const FREE_LIST: usize = 0x10;

/// The record pointer that ends a chain.
const NOWHERE: u32 = 0xffff_ffff;

/// One record, and where in the file it lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The record's byte offset in the file.
    ///
    /// This is what `absbtv` returns and what `gabbtv` takes back, so it is the
    /// record's identity as far as the module is concerned -- not its index in
    /// any order.
    pub position: u32,

    /// The record itself.
    ///
    /// Exactly `geometry.reclen` bytes for a fixed-length file. For a
    /// variable-length one it is the logical record **and** everything its
    /// fragment chain holds, concatenated -- which is what Btrieve itself
    /// hands back and what the module's buffer is sized for. `WCCTEXT`'s
    /// records are 22 bytes of fixed part and 2,000 of fragment, and MajorMUD
    /// opens the file for 2,022.
    ///
    /// Every key of every file MajorMUD ships lies inside the fixed part, so
    /// [`Key::extract`] and [`Key::compare`] see the same bytes either way.
    pub bytes: Vec<u8>,
}

/// Every record in a file, in physical order, with an index per key.
///
/// `Clone`: Task 6's transaction journal keeps a whole copy of this as a
/// pre-image, taken the first time a write inside a transaction reaches a
/// block and restored verbatim on abort -- see `btrieve.rs`'s `PreImage`.
/// Every field here is itself `Clone` (two levels of `Vec`, at most), so this
/// is a derive, not new logic to get wrong.
#[derive(Debug, Clone)]
pub struct Records {
    /// Physical order: the order `stpbtvl` walks.
    records: Vec<Record>,

    /// For each key, the record indices in that key's order.
    order: Vec<Vec<usize>>,

    /// For each key, where each record sits in [`Self::order`]. The inverse,
    /// kept rather than searched for, because `gabbtv` positions by file
    /// offset and the next `qnxbtv` after it has to carry on in key order from
    /// there.
    rank: Vec<Vec<usize>>,

    /// For each key, how many adjacent pairs in its order carry the same key
    /// value. See [`Self::ties`].
    ties: Vec<usize>,

    /// How many leading bytes a key's own `offset` field is measured past
    /// [`Record::bytes`]'s own start -- zero for v5, two for v6.
    ///
    /// A key definition's `offset` is read straight off the file control
    /// record (`keys.rs`'s `at::OFFSET`, applied with no version-specific
    /// adjustment -- Evidence 5's "keys.rs is already correct for v6" is
    /// true of *parsing*, not of what coordinate system the number it reads
    /// is in). Measured against `DUPKEY30.DAT`: its one key reads `offset:
    /// 2`, and `keys.rs`'s `at::CHAIN` reads a duplicate-chain offset of 14
    /// on the same file, which is `physical - 8`, not `reclen - 8` -- both
    /// numbers are relative to the **physical slot**, the coordinate system
    /// `at::CHAIN`'s own doc comment already established. But
    /// [`Record::bytes`] is `reclen` bytes with Evidence 1b's two-byte v6
    /// slot marker already read past and discarded (`walk_v6`), so applying
    /// the FCR's own offset to it unmodified reads two bytes into the next
    /// field. [`Self::keyed`] pads it back on, only for the span of one
    /// comparison, so this is a coordinate fix confined to how a key is
    /// *applied* -- `keys.rs` itself stays exactly as version-independent as
    /// Evidence 5 says it is.
    key_shift: usize,
}

impl Records {
    /// Read every record of a file and sort them by each of its keys.
    ///
    /// **The single point every record read passes through.** `Block::records`
    /// calls this; so does half the test suite, directly, which is what makes
    /// this the entry point to guard rather than `Block::records` -- a check
    /// placed there would not have covered the callers that never go through
    /// a `Block` at all.
    ///
    /// Both versions are read here: [`walk`] dispatches on `geometry.version`
    /// and resolves a v6 file's logical page numbers through [`super::v6::Map`]
    /// rather than applying v5's `page * number` arithmetic to them
    /// (`docs/plans/2026-08-11-btrieve-v6-page-addressing.md`, Task 5 --
    /// Task 2 refused every v6 file outright, and this is what replaces that
    /// refusal with the real path it promised).
    ///
    /// # Errors
    ///
    /// If the file cannot be read, its free list leaves the file (v5 only --
    /// see [`walk`]'s v6 doc comment for why a v6 walk does not consult one),
    /// the v6 allocation table cannot be resolved (any of [`super::v6::Map::read`]'s
    /// own refusals), or the number of records found is not the number the
    /// header claims.
    pub fn read(
        name: &str,
        path: &Path,
        geometry: &Geometry,
        keys: &[Key],
    ) -> Result<Self, BtvError> {
        let fail = |why: String| BtvError {
            file: name.to_owned(),
            why,
        };

        let records = walk(geometry, path).map_err(fail)?;

        if records.len() as u32 != geometry.records {
            return Err(fail(format!(
                "the header says {} records and walking the pages found {}",
                geometry.records,
                records.len()
            )));
        }

        let key_shift = if geometry.version == Version::V6 { 2 } else { 0 };

        let mut me = Self {
            records,
            order: Vec::new(),
            rank: Vec::new(),
            ties: Vec::new(),
            key_shift,
        };
        me.reindex(keys);
        Ok(me)
    }

    /// A record's bytes, padded so a key's own `offset` field lands where it
    /// was measured from. See [`Self::key_shift`] for why this is needed at
    /// all and why it is confined to here rather than to `keys.rs`.
    ///
    /// Zero-cost for v5 (`key_shift` is `0`, so this borrows `bytes`
    /// unchanged) -- `WCCUPDAT.DAT`'s 38,754-record sort must not pay for a
    /// fix a v5 file never needs.
    pub(crate) fn keyed<'a>(&self, bytes: &'a [u8]) -> std::borrow::Cow<'a, [u8]> {
        keyed(self.key_shift, bytes)
    }

    /// How far a key's `offset` field is ahead of [`Record::bytes`].
    ///
    /// Exposed because three call sites outside this type read key bytes off
    /// a record and cannot reach [`Self::keyed`] through a `&mut self`
    /// borrow: [`answer_with_key`](crate::shims::btrieve) and the two in
    /// `Block::reindex`. They were all missed when `key_shift` was
    /// introduced, and a key read without it sorts and answers on the wrong
    /// bytes.
    pub(crate) fn key_shift(&self) -> usize {
        self.key_shift
    }

    /// Where `a` sits relative to `b` under `key`, as the sort orders them.
    ///
    /// The tie-break on `position` is what makes the order *total*, and it has
    /// to match [`Self::reindex`]'s comparator exactly -- the incremental
    /// paths below binary-search with this against an order that was built
    /// with that, and two comparators that disagree anywhere put a record in a
    /// place a later search will not find it.
    fn cmp_under(&self, key: &Key, a: usize, b: usize) -> Ordering {
        match key.compare(
            &self.keyed(&self.records[a].bytes),
            &self.keyed(&self.records[b].bytes),
        ) {
            Ordering::Equal => self.records[a].position.cmp(&self.records[b].position),
            other => other,
        }
    }

    /// Whether `a` and `b` hold the same value under `key`, ignoring the
    /// position tie-break -- which is what [`Self::ties`] counts.
    fn same_value(&self, key: &Key, a: usize, b: usize) -> bool {
        key.compare(
            &self.keyed(&self.records[a].bytes),
            &self.keyed(&self.records[b].bytes),
        ) == Ordering::Equal
    }

    /// Put `index` into every key's order, and fix `rank` and `ties`.
    ///
    /// `records` must already hold the record at `index`, and every order must
    /// already be numbered for it -- see [`Self::renumber`]. This only finds
    /// the place and links it in.
    ///
    /// **This is the whole point of the incremental paths.** Re-sorting cost
    /// `n log n` *comparisons* per key per write, and a comparison is a key
    /// extraction plus a `memcmp`; a binary search costs `log n` of them. On
    /// `WCCUPDAT.DAT`'s 38,754 records that is about 590,000 comparisons
    /// against about 16. The `O(n)` renumber and `rank` rebuild stay, but they
    /// are `memmove` and integer stores -- no key bytes are read at all --
    /// which is the difference between the two costs.
    ///
    /// Worth doing because the sort was measured rather than guessed at: a
    /// profile of the live board put `keys::Segment::order` at 18.5% of all
    /// CPU and the `memcmp` it calls at roughly 23% more. See `BUGS.md`.
    fn link(&mut self, keys: &[Key], index: usize) {
        for k in 0..keys.len() {
            let key = &keys[k];
            let mut ord = std::mem::take(&mut self.order[k]);

            let place = ord.partition_point(|&e| self.cmp_under(key, e, index) == Ordering::Less);

            // `ties` changes only at the seam: the pair that used to straddle
            // `place` is replaced by the two the new record makes.
            let before = place.checked_sub(1).map(|p| ord[p]);
            let after = ord.get(place).copied();
            if let (Some(b), Some(a)) = (before, after)
                && self.same_value(key, b, a)
            {
                self.ties[k] -= 1;
            }
            if let Some(b) = before
                && self.same_value(key, b, index)
            {
                self.ties[k] += 1;
            }
            if let Some(a) = after
                && self.same_value(key, index, a)
            {
                self.ties[k] += 1;
            }

            ord.insert(place, index);
            self.rerank(k, &ord);
            self.order[k] = ord;
        }
    }

    /// Take `index` out of every key's order, and fix `rank` and `ties`.
    ///
    /// The record must still be in `records` with the bytes it was linked
    /// under: the seam is repaired by comparing against it, and `rank` is what
    /// says where it sits without searching for it.
    ///
    /// Renumbering is deliberately **not** done here. A delete needs it and an
    /// update must not have it -- an updated record keeps its place in
    /// `records` and only moves within the key orders -- and folding the two
    /// together is how the update path silently corrupts every index above
    /// the one it touched. See [`Self::renumber`].
    fn unlink(&mut self, keys: &[Key], index: usize) {
        for k in 0..keys.len() {
            let key = &keys[k];
            let mut ord = std::mem::take(&mut self.order[k]);
            let place = self.rank[k][index];

            let before = place.checked_sub(1).map(|p| ord[p]);
            let after = ord.get(place + 1).copied();
            if let Some(b) = before
                && self.same_value(key, b, index)
            {
                self.ties[k] -= 1;
            }
            if let Some(a) = after
                && self.same_value(key, index, a)
            {
                self.ties[k] -= 1;
            }
            if let (Some(b), Some(a)) = (before, after)
                && self.same_value(key, b, a)
            {
                self.ties[k] += 1;
            }

            ord.remove(place);
            self.rerank(k, &ord);
            self.order[k] = ord;
        }
    }

    /// Renumber every order after `records` grew or shrank at `at`.
    ///
    /// `order` names records by their index in `records`, so a `Vec::insert`
    /// or `Vec::remove` moves every record above `at` and every entry naming
    /// one has to follow. Integer compares and stores; no key bytes are read.
    ///
    /// `grew` is which way: `true` after an insert, `false` after a remove.
    fn renumber(&mut self, at: usize, grew: bool) {
        let total = self.records.len();
        for (k, ord) in self.order.iter_mut().enumerate() {
            for entry in ord.iter_mut() {
                if grew {
                    if *entry >= at {
                        *entry += 1;
                    }
                } else if *entry > at {
                    *entry -= 1;
                }
            }
            let places = &mut self.rank[k];
            places.clear();
            places.resize(total, 0);
            for (place, &record) in ord.iter().enumerate() {
                places[record] = place;
            }
        }
    }

    /// Rebuild `rank[k]` from `ord`.
    ///
    /// `rank` is indexed by record, `order` by place; one is the other
    /// inverted, and there is no way to update a prefix of it when a splice
    /// moves everything after the seam. `O(n)` integer stores, no comparisons.
    fn rerank(&mut self, k: usize, ord: &[usize]) {
        // Sized by `records`, not by `ord`: `rank` is indexed by record and
        // `order` by place, and the two lengths differ for exactly as long as
        // a record is unlinked but not yet removed -- which is the window
        // `unlink` hands back to its caller.
        let total = self.records.len();
        let places = &mut self.rank[k];
        places.clear();
        places.resize(total, 0);
        for (place, &record) in ord.iter().enumerate() {
            places[record] = place;
        }
    }

    /// Re-derive `order`, `rank` and `ties` from `records`, for the given keys.
    ///
    /// **Once, when the file is read.** It used to run again after every
    /// `insert`, `update` and `delete` -- the comment here said "at these
    /// record counts a sort is cheap, and a splice is the kind of thing that
    /// is right for a year and then is not", and that year is up: on
    /// `WCCUPDAT.DAT`'s 38,754 records it is a full `n log n` sort per key per
    /// write, and a live profile put the comparator and its `memcmp` at over
    /// 40% of the board's CPU. [`Self::splice_in`] and [`Self::splice_out`]
    /// maintain the same three tables incrementally now.
    ///
    /// It stays because it is the definition of what those tables mean, and
    /// the incremental paths are checked against it rather than against a
    /// restatement of themselves --
    /// `splicing_matches_a_full_reindex_over_a_long_run_of_writes` runs both
    /// and compares.
    fn reindex(&mut self, keys: &[Key]) {
        let mut order = Vec::with_capacity(keys.len());
        let mut rank = Vec::with_capacity(keys.len());
        let mut ties = Vec::with_capacity(keys.len());
        for key in keys {
            let mut sorted: Vec<usize> = (0..self.records.len()).collect();
            // Ties broken by physical position, so the order is total: two
            // records with the same duplicate key must still come out in the
            // same sequence every run, or `qnxbtv` would step somewhere else on
            // a second pass over the same file. See [`Self::ties`] for what
            // that tie-break is and is not.
            sorted.sort_by(|a, b| {
                match key.compare(
                    &self.keyed(&self.records[*a].bytes),
                    &self.keyed(&self.records[*b].bytes),
                ) {
                    Ordering::Equal => self.records[*a].position.cmp(&self.records[*b].position),
                    other => other,
                }
            });
            let mut places = vec![0usize; self.records.len()];
            for (place, record) in sorted.iter().enumerate() {
                places[*record] = place;
            }
            let tied = sorted
                .windows(2)
                .filter(|pair| {
                    key.compare(
                        &self.keyed(&self.records[pair[0]].bytes),
                        &self.keyed(&self.records[pair[1]].bytes),
                    ) == Ordering::Equal
                })
                .count();
            order.push(sorted);
            rank.push(places);
            ties.push(tied);
        }
        self.order = order;
        self.rank = rank;
        self.ties = ties;
    }

    /// How many records share a key value with the record before them, per key.
    ///
    /// **This is the one place the derived order can differ from the file's own
    /// index, and it is not checkable against these files.**
    ///
    /// Every other part of the ordering is verified against the B-tree pages
    /// themselves -- 1,219 index pages and 77,505 entries agree with the
    /// comparator exactly. But two records with the *same* key value are in
    /// whatever order Btrieve's duplicate chain put them, which is the order
    /// they were inserted; here they come out in file-position order, and a
    /// record inserted into a slot freed by a deletion has a low position and a
    /// late insertion.
    ///
    /// It cannot be measured **against MajorMUD's own shipped data**, because
    /// all four keys in MajorMUD's files that permit duplicates -- `WCCUSERS`
    /// key 2, `WCCGANGS` key 1, `WCCBANKS` key 0, `WCCITOWN` key 1 -- are in
    /// files that hold no records at all. So this counts the pairs where it
    /// *could* matter, and the host reports the number rather than letting
    /// the difference be silent. On a board nobody has played on, every one
    /// of them is zero.
    ///
    /// **The assumption itself has since been measured, against a file that
    /// isn't MajorMUD's.**
    /// `crates/mbbs/tests/engine_diff.rs`'s `duplicate_insertion_order_the_real_engine_uses`
    /// (`docs/plans/2026-08-09-btrieve-engine-in-the-loop.md`, Task 8) inserts
    /// five colliding records through the genuine Btrieve engine and reads
    /// its chain-walk order back: it is insertion order, agreeing with what
    /// this module assumes. One collision group of five is not every shape a
    /// duplicate chain can take, but it is the first time this ever had an
    /// engine-measured answer rather than an assumption stated as one.
    ///
    /// **For a file this host itself indexed the difference is gone**, and
    /// this still counts: [`Block::reindex`](super::Block::reindex) writes the
    /// duplicate chain in exactly this order, so the file's own index agrees
    /// with the order here by construction. What remains is a count of the
    /// records whose place in a *Btrieve-written* file could have come from an
    /// insertion sequence this host cannot see -- which is what it always
    /// measured, and is now the narrower thing it says.
    pub fn ties(&self) -> &[usize] {
        &self.ties
    }

    /// How many records there are.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the file holds no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The record at a place in physical order.
    pub fn physical(&self, at: usize) -> Option<&Record> {
        self.records.get(at)
    }

    /// The record at a place in a key's order.
    pub fn ordered(&self, key: u16, at: usize) -> Option<&Record> {
        let order = self.order.get(usize::from(key))?;
        self.records.get(*order.get(at)?)
    }

    /// How many records a key orders, which is all of them.
    pub fn ordered_len(&self, key: u16) -> Option<usize> {
        Some(self.order.get(usize::from(key))?.len())
    }

    /// Where a record sits in physical order, by its position in the file.
    pub fn find_physical(&self, position: u32) -> Option<usize> {
        self.records.iter().position(|r| r.position == position)
    }

    /// Where the record at a place in physical order sits in a key's order.
    pub fn place_in(&self, key: u16, physical: usize) -> Option<usize> {
        self.rank.get(usize::from(key))?.get(physical).copied()
    }

    /// The first place in `key`'s order whose record is not before `value`.
    ///
    /// A binary search over the sorted order, which is what makes a lookup by
    /// key a lookup rather than a scan of 26,720 rooms.
    pub fn seek(&self, keys: &[Key], key: u16, value: &[u8]) -> usize {
        let Some(order) = self.order.get(usize::from(key)) else {
            return 0;
        };
        let definition = &keys[usize::from(key)];
        order.partition_point(|record| {
            definition.compare_value(&self.keyed(&self.records[*record].bytes), value)
                == Ordering::Less
        })
    }

    /// Whether the record at a place in `key`'s order has exactly `value`.
    pub fn matches(&self, keys: &[Key], key: u16, at: usize, value: &[u8]) -> bool {
        let Some(record) = self.ordered(key, at) else {
            return false;
        };
        keys[usize::from(key)].compare_value(&self.keyed(&record.bytes), value) == Ordering::Equal
    }

    /// Add a record at a position nothing else occupies.
    ///
    /// Inserted in position order, not appended. [`Self::records`] is file
    /// order -- what `walk` produces and what a fresh read always agrees
    /// with -- and the two are the same thing only while every insert lands
    /// after every existing record. [`pages::Layout::next_slot`]'s free
    /// list is checked first, ahead of a gap or a new page, so a position
    /// *lower* than records already in the file is not a hypothetical: it
    /// is what any insert into a file with a non-empty free list does. This
    /// keeps `records` sorted by position unconditionally, which `delete`
    /// and `update` already preserve by construction (`remove` keeps the
    /// order of what is left; `update` mutates a record in place), so the
    /// invariant holds for the whole lifetime of a `Records`.
    ///
    /// [`pages::Layout::next_slot`]: super::pages::Layout::next_slot
    ///
    /// # Errors
    ///
    /// If `position` already holds a record.
    pub fn insert(&mut self, keys: &[Key], position: u32, bytes: Vec<u8>) -> Result<(), String> {
        if self.records.iter().any(|r| r.position == position) {
            return Err(format!("position {position} already holds a record"));
        }
        let at = self.records.partition_point(|r| r.position < position);
        self.records.insert(at, Record { position, bytes });
        // Renumber first, so every existing entry names the record it did
        // before the shift, then link the new one into the gap that leaves.
        self.renumber(at, true);
        for places in &mut self.rank {
            places.resize(self.records.len(), 0);
        }
        self.link(keys, at);
        Ok(())
    }

    /// Replace the bytes of the record at `position`, leaving it where it is.
    ///
    /// An update is in place: Btrieve's opcode 3 rewrites the record the file
    /// is positioned on, so `absbtv` answers the same before and after. Only
    /// the key orders move.
    ///
    /// # Errors
    ///
    /// If `position` holds no record.
    pub fn update(&mut self, keys: &[Key], position: u32, bytes: Vec<u8>) -> Result<(), String> {
        let index = self
            .records
            .iter()
            .position(|r| r.position == position)
            .ok_or_else(|| format!("position {position} holds no record"))?;
        // The record stays where it is in `records` -- an update is in place,
        // so nothing is renumbered -- but its key value may have changed, so
        // it leaves and re-enters every order. `unlink` runs first, while the
        // old bytes are still there for it to repair the seam against.
        self.unlink(keys, index);
        self.records[index].bytes = bytes;
        self.link(keys, index);
        Ok(())
    }

    /// Remove the record at `position`.
    ///
    /// `pub(crate)` rather than `pub`, and it stays that way: this only
    /// removes `position` from the in-memory model, never the on-disk slot
    /// or the free list. `Block::delete` (`crate::btrieve`, the same crate,
    /// so `pub(crate)` already reaches it) is the only caller and always
    /// pairs this with `pages::delete_record` -- disk first, then this --
    /// so the two never drift apart. Calling this alone, from outside that
    /// pairing, would take `position` out of [`Self::positions`] while the
    /// slot on disk is still live: `Layout::next_slot`'s
    /// free-list-then-existing-gap search does not consult the free list on
    /// disk either, so nothing would stop `next_slot` handing that same
    /// still-live position back as `Slot::Existing` and a later insert
    /// overwriting it.
    ///
    /// # Errors
    ///
    /// If `position` holds no record.
    pub(crate) fn delete(&mut self, keys: &[Key], position: u32) -> Result<(), String> {
        let index = self
            .records
            .iter()
            .position(|r| r.position == position)
            .ok_or_else(|| format!("position {position} holds no record"))?;
        // Before the removal: the key bytes have to still be there to
        // compare the seam against.
        self.unlink(keys, index);
        self.records.remove(index);
        self.renumber(index, false);
        Ok(())
    }

    /// Every position currently holding a record, for
    /// [`Layout::next_slot`](super::pages::Layout::next_slot).
    pub fn positions(&self) -> Vec<u32> {
        self.records.iter().map(|r| r.position).collect()
    }
}

/// Walk the data pages and collect every live record.
///
/// Dispatches on the file's version: [`walk_v5`] and [`walk_v6`] share the
/// same arithmetic ([`super::pages::Layout`], [`super::pages::Header::decode`])
/// but differ in what a page's number means and where the free-standing
/// slot content starts -- see [`walk_v6`]'s doc comment for the differences
/// and why each is what it is.
fn walk(geometry: &Geometry, path: &Path) -> Result<Vec<Record>, String> {
    match geometry.version {
        Version::V5 => walk_v5(geometry, path),
        Version::V6 => walk_v6(geometry, path),
    }
}

/// Walk a version 5 file's data pages, in physical order.
///
/// A page's own number *is* its physical position for v5, so this is a
/// linear scan of `1..geometry.pages` -- no allocation table, no logical ids.
fn walk_v5(geometry: &Geometry, path: &Path) -> Result<Vec<Record>, String> {
    let mut file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let size = u32::try_from(
        file.metadata()
            .map_err(|e| e.to_string())?
            .len(),
    )
    .map_err(|_| "a Btrieve file larger than four gigabytes".to_owned())?;

    let dead = free_list(&mut file, size)?;

    // The one place this file's page arithmetic lives -- see
    // `pages::Layout::position` and `pages::Header::decode` below. Trap 1 in
    // `docs/plans/2026-08-11-btrieve-v6-page-addressing.md` was this
    // function reimplementing both instead of calling them.
    let layout = super::pages::Layout {
        page: geometry.page,
        physical: geometry.physical,
        pages: geometry.pages,
    };
    let per_page = layout.per_page();

    let mut records = Vec::with_capacity(geometry.records as usize);
    let mut buffer = vec![0u8; geometry.page as usize];

    // A second page-sized buffer, for the fragment pages a variable-length
    // record's chain jumps to. Separate from `buffer` because the walk is
    // still standing on the data page it found the record in.
    let mut fragment = vec![0u8; geometry.page as usize];

    // Page 0 is the file control record, so records start at page 1.
    for number in 1..geometry.pages {
        let at = layout.page_start(number);
        file.seek(SeekFrom::Start(u64::from(at)))
            .and_then(|_| file.read_exact(&mut buffer))
            .map_err(|e| format!("page {number}: {e}"))?;

        // The high bit of the usage count marks a page that holds records. The
        // rest are index pages, and reading one as data would produce records
        // out of B-tree nodes.
        if !super::pages::Header::decode(&buffer).data {
            continue;
        }

        for slot in 0..per_page {
            if records.len() as u32 == geometry.records {
                break;
            }
            let position = layout.position(number, slot);
            if dead.contains(&position) {
                continue;
            }

            let start = (position - at) as usize;
            let record = &buffer[start..start + geometry.physical as usize];

            // Slots are filled from the front -- so the first empty one ends
            // the page rather than being skipped. See [`looks_empty`].
            if looks_empty(record, size) {
                break;
            }

            let mut bytes = record[..geometry.reclen as usize].to_vec();

            // A variable-length record is its fixed part and then whatever the
            // four bytes after it point at. The pointer is copied out before
            // the chain is followed, because following it reads other pages
            // into a buffer of its own and `record` is a slice of this one.
            let pointer = geometry.variable.then(|| {
                let at = usize::from(geometry.reclen);
                Pointer::decode([record[at], record[at + 1], record[at + 2], record[at + 3]])
            });
            if let Some(pointer) = pointer {
                let mut source = Chained {
                    file: &mut file,
                    buffer: &mut fragment,
                    pages: geometry.pages,
                };
                Chain::follow(&mut source, geometry.version, pointer, &mut bytes)
                    .map_err(|why| format!("the record at {position}: {why}"))?;
            }

            records.push(Record { position, bytes });
        }
    }

    Ok(records)
}

/// Walk a version 6 file's claimed data pages, resolving every page number
/// through [`super::v6::Map`] rather than treating it as a physical position
/// (Evidence 2 of `docs/plans/2026-08-11-btrieve-v6-page-addressing.md`).
///
/// **Variable-length records are read too, as of Task 6.** A v6 record's
/// fixed part is followed by the same four-byte fragment pointer v5 uses
/// (`variable::Pointer`), but every page number the chain names is a
/// *logical* id, resolved through the same `map` this function already built
/// to place the record's own fixed part -- [`MappedPages`] is that
/// resolution, done once per fragment read rather than reimplemented.
///
/// # Design decisions made here, and why
///
/// **The whole file is read into memory, once.** [`super::v6::Map::read`]
/// already requires a whole-file slice -- that is Task 3's established
/// signature, tested against eight fixtures -- so a v6 walk cannot avoid
/// that read, and this reuses the same buffer to read every claimed page
/// too rather than opening the file a second time. Every v6 file this
/// repository has measured is under 100 KB, and the one v6 file MajorMUD
/// ships that might not be tiny -- `NEWMP001.VIR` -- is the map template
/// the module never opens (see this plan's "Why this is a separate plan").
/// So this cost is not paid by anything that runs today. A v6 file large
/// enough to make slurping it a real problem would need `Map::read` itself
/// to stream, which is out of scope here -- v5's `walk_v5` keeps streaming,
/// unchanged, because it is what `WCCUPDAT.DAT`'s 77 MB needs.
///
/// **No free list is consulted.** `records::free_list` seeks from byte
/// offset [`FREE_LIST`] unconditionally -- physical page 0, always -- which
/// is the identical shadow-copy bug Task 1 fixed for the control record: on
/// a v6 file whose live copy is page 1, it reads the stale one. Measured on
/// both fixtures below, the candidate fields at `0x20`/`0x24` happen to
/// agree between the two copies but `0x28` does not (`03000000` on
/// `DUPKEY30.DAT`'s stale page 0, `06000000` on its live page 1), so "the
/// copies agree anyway" is not a defence available here even if this
/// wanted to reuse `free_list` against the live copy. More fundamentally,
/// whether a v6 free list even uses the same on-disk representation as
/// v5's is simply not established (Evidence 5) -- so rather than guess,
/// this reads no free list at all for v6, and relies on the same
/// empty-slot test v5 uses to find the tail of a page's live records
/// ([`looks_empty`], applied to the two bytes past the slot's marker --
/// verified to correctly end both `DUPKEY30.DAT`'s 7-record page and
/// `PP2048.DAT`'s 50-record one). A record deleted from the *middle* of a
/// v6 page -- a shape neither committed fixture exercises, and Evidence 5
/// leaves open ("what triggers copy-on-write relocation... is not
/// established") -- would not be skipped by this the way a v5 free list
/// entry is.
///
/// **What that costs, stated exactly, because an earlier version of this
/// comment overstated it.** It claimed [`Records::read`]'s count check turns
/// the case into a refusal, "a stop, not a plausible wrong answer". That is
/// the likely outcome and it is not a guarantee, and the difference is the
/// whole of Trap 2. Two ways it goes:
///
/// - The deleted slot's leftover bytes satisfy [`looks_empty`]: this stops
///   there and misses every live record behind it on that page, the count
///   falls short, and `Records::read` refuses. Loud, correct.
/// - They do **not** satisfy it -- Evidence 3a establishes that a stale v6
///   page can hold real leftover content -- and the slot is read as a live
///   record that is not one. The count is then inflated by a ghost and
///   deflated by whatever the walk stopped short of, and if those cancel,
///   the count matches the header exactly and nothing refuses. That is a
///   wrong answer that counts correctly, which is precisely the shape the
///   Task 2 correction in the plan documents.
///
/// No fixture has an interior deletion, so neither branch is exercised and
/// the second is a structural argument rather than a demonstrated failure.
/// It is written down instead of being asserted away because "very probably
/// refuses" is not what this crate promises elsewhere. Closing it properly
/// means establishing the v6 free-list representation and consulting it;
/// until then this is a known hole with a known shape.
///
/// **A record's position embeds the page's LOGICAL id, not its physical
/// one.** Measured directly against `DUPKEY30.DAT`: physical page 8
/// (logical 5) holds the file's last seven inserted records and physical
/// page 10 (logical 2) holds the first twenty-three, but logical 2 is less
/// than logical 5 while physical 10 is greater than physical 8 -- the
/// allocator did not hand out physical pages in insertion order, but the
/// logical id it assigned each one preserves it. The duplicate-key group
/// for value 7 (insertion indices 21-23) spans both pages, and it only
/// comes back in the real engine's own insertion order -- what
/// `Records::reindex`'s tie-break assumes duplicates are in -- when
/// positions sort by logical page: sorting by physical page would put
/// index 23 (physical 8) ahead of indices 21-22 (physical 10) and fail the
/// byte-for-byte comparison this task's tests make. `pages.rs`'s own
/// `dupkey30_records` test helper independently reaches the same
/// conclusion, from the in-record `[prev][next]` duplicate chain rather
/// than from insertion order -- see its doc comment.
fn walk_v6(geometry: &Geometry, path: &Path) -> Result<Vec<Record>, String> {
    if usize::from(geometry.physical) < V6_SLOT_MARKER {
        return Err(format!(
            "a {}-byte physical record, too short to hold the two-byte v6 slot \
             marker every record body follows two bytes past (Evidence 1b)",
            geometry.physical
        ));
    }

    let file = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let size = u32::try_from(file.len())
        .map_err(|_| "a Btrieve file larger than four gigabytes".to_owned())?;

    let map = super::v6::Map::read(&file, geometry.page)?;

    let layout = super::pages::Layout {
        page: geometry.page,
        physical: geometry.physical,
        pages: geometry.pages,
    };
    let per_page = layout.per_page();

    // Ascending by logical id -- the tie-break this walk's doc comment
    // measures, and what keeps `records` sorted by `position` the way a v5
    // walk's ascending physical scan always has.
    let mut claimed: Vec<(u32, u32)> = map.entries().collect();
    claimed.sort_unstable_by_key(|&(logical, _)| logical);

    let mut records = Vec::with_capacity(geometry.records as usize);

    for (logical, physical_page) in claimed {
        if records.len() as u32 == geometry.records {
            break;
        }

        let at = layout.page_start(physical_page);
        let end = at
            .checked_add(u32::from(geometry.page))
            .filter(|&end| end <= size)
            .ok_or_else(|| {
                format!(
                    "the allocation table names physical page {physical_page} for \
                     logical page {logical}, past the end of a {size}-byte file"
                )
            })?;
        let buffer = &file[at as usize..end as usize];

        // Evidence 3/3a: claimed alone is not enough to mean "read this as
        // records" -- the tag's high byte has to say "data" (`0x44`; this
        // module's own doc comment notes the same tag also covers index
        // content), and within that, the header's own data bit -- the same
        // field `Header::decode` reads for v5, at the same offset either
        // version -- is what tells a leaf of records from a B-tree node.
        if buffer[1] != 0x44 || !super::pages::Header::decode(buffer).data {
            continue;
        }

        for slot in 0..per_page {
            if records.len() as u32 == geometry.records {
                break;
            }
            let position = layout.position(logical, slot);

            // Evidence 1b: the record body starts two bytes into the slot,
            // past a marker this reads past rather than interprets.
            //
            // `position(0, slot)` rather than a restated `HEADER + physical *
            // slot`, so the formula lives only in `Layout::position` -- Trap 1
            // in miniature otherwise. Page **0**, not this page: `position`
            // above is deliberately keyed by the *logical* id (Evidence 1c)
            // while `at` is the *physical* page's byte offset, so the two do
            // not subtract into an in-page offset the way `walk_v5`'s do. The
            // offset of a slot within its page is the same for every page, and
            // page 0 starts at byte 0, so asking for page 0 asks exactly that
            // question. This subtlety cost a broken refactor: `position - at`
            // compiles, reads plausibly, and is wrong.
            let start = layout.position(0, slot) as usize + V6_SLOT_MARKER;
            let content_len = usize::from(geometry.physical) - V6_SLOT_MARKER;
            let record = &buffer[start..start + content_len];

            // Slots fill from the front of a page here too -- see v5's
            // identical comment in `walk_v5` -- so the first one that looks
            // unwritten ends this page's live records.
            if looks_empty(record, size) {
                break;
            }

            let mut bytes = record[..geometry.reclen as usize].to_vec();

            // A variable-length record's fixed part is followed by four
            // bytes naming its first fragment -- v5's own encoding
            // (`variable::Pointer::decode`), read from the same offset --
            // but every page number inside it is a logical id (Evidence 2)
            // and has to go through `map`, not be read as a physical
            // position. Copied out before `bytes` grows, same as `walk_v5`.
            if geometry.variable {
                let at = usize::from(geometry.reclen);
                let pointer = Pointer::decode([
                    record[at],
                    record[at + 1],
                    record[at + 2],
                    record[at + 3],
                ]);
                let mut source = MappedPages {
                    file: &file,
                    layout,
                    map: &map,
                };
                Chain::follow(&mut source, geometry.version, pointer, &mut bytes)
                    .map_err(|why| format!("the record at {position}: {why}"))?;
            }

            records.push(Record { position, bytes });
        }
    }

    Ok(records)
}

/// Whole pages of a v6 file already read into memory, addressed by
/// **logical** id and resolved through [`super::v6::Map`] -- the fragment-
/// chain counterpart to [`walk_v6`]'s own resolution of a record's own page.
/// A v6 fragment pointer names a logical page exactly the way an ordinary
/// record position does (Evidence 1c and 2), so this is not a second
/// implementation of that resolution: it is [`Chained`]'s file-backed shape,
/// reused, with the one extra indirection the map adds -- and the mutation
/// this exists to make impossible is resolving a fragment pointer as though
/// it already named a physical page (plan Task 6, mandatory mutation (c)).
struct MappedPages<'a> {
    file: &'a [u8],
    /// Carried whole rather than as a bare page size so that where a page
    /// starts is [`Layout::page_start`]'s answer here too. This held the page
    /// size and multiplied it out by hand until the branch's final review
    /// counted the implementations of that one fact and found this a third.
    layout: super::pages::Layout,
    map: &'a super::v6::Map,
}

impl Pages for MappedPages<'_> {
    fn page(&mut self, number: u32) -> Result<&[u8], String> {
        let physical = self.map.physical(number).ok_or_else(|| {
            format!(
                "logical page {number}, and the allocation table names no live physical \
                 page for it"
            )
        })?;
        let at = self.layout.page_start(physical) as usize;
        let end = at + usize::from(self.layout.page);
        self.file.get(at..end).ok_or_else(|| {
            format!(
                "logical page {number} resolves to physical {physical}, past the end of a \
                 {}-byte file",
                self.file.len()
            )
        })
    }
}

/// Whole pages of an open file, for [`Chain::follow`].
///
/// Built per record and borrowing both the file and one reusable page buffer,
/// so following 3,467 chains allocates nothing: the buffer belongs to
/// [`walk`], which is also the reason this cannot simply own its own.
struct Chained<'a> {
    file: &'a mut std::fs::File,
    buffer: &'a mut Vec<u8>,
    pages: u32,
}

impl Pages for Chained<'_> {
    fn page(&mut self, number: u32) -> Result<&[u8], String> {
        // Page 0 is the file control record and never holds fragments;
        // checking the bound here names the file's own shape in the error
        // rather than letting a seek past the end come back as "unexpected end
        // of file".
        if number == 0 || number >= self.pages {
            return Err(format!(
                "a fragment on page {number}, and the file is {} pages",
                self.pages
            ));
        }
        let at = u64::from(number) * self.buffer.len() as u64;
        self.file
            .seek(SeekFrom::Start(at))
            .and_then(|_| self.file.read_exact(self.buffer))
            .map_err(|e| format!("page {number}: {e}"))?;
        Ok(self.buffer)
    }
}

/// Every record slot on the free list.
///
/// A chain of file offsets, each holding the next. Following it is what keeps
/// deleted records out of the count -- a file that has been played on and had
/// characters removed has live records after dead ones in the same page.
fn free_list(file: &mut std::fs::File, size: u32) -> Result<HashSet<u32>, String> {
    let mut dead = HashSet::new();
    let mut head = [0u8; 4];
    file.seek(SeekFrom::Start(FREE_LIST as u64))
        .and_then(|_| file.read_exact(&mut head))
        .map_err(|e| format!("reading the free list: {e}"))?;

    let mut next = super::pages::long(&head);
    while next != NOWHERE {
        if next + 4 > size {
            return Err(format!(
                "the free list points at {next}, past the end of a {size}-byte file"
            ));
        }
        // A cycle would spin here forever, and a file whose free list re-enters
        // itself is corrupt rather than merely long.
        if !dead.insert(next) {
            return Err(format!("the free list loops back to {next}"));
        }
        let mut link = [0u8; 4];
        file.seek(SeekFrom::Start(u64::from(next)))
            .and_then(|_| file.read_exact(&mut link))
            .map_err(|e| format!("following the free list: {e}"))?;
        next = super::pages::long(&link);
    }
    Ok(dead)
}

/// Pad a record's bytes so a key's own `offset` field lands where it was
/// measured from.
///
/// A key definition's `offset` is relative to the **physical slot**, and a
/// v6 slot opens with a two-byte marker that [`Record::bytes`] does not carry
/// (Evidence 1b) -- so on a v6 file every key is two bytes further along than
/// the body it is read out of. `keys.rs`'s own `at::CHAIN` is measured the
/// same way, from the slot.
///
/// Free rather than a method so the three call sites that hold a `&mut
/// Records`, or no `Records` at all, can use the one implementation instead
/// of open-coding the shift a fourth time.
///
/// Zero-cost for v5, where `shift` is `0` and this borrows `bytes` unchanged:
/// `WCCUPDAT.DAT`'s 38,754-record sort must not pay for a fix a v5 file never
/// needs.
pub(crate) fn keyed(shift: usize, bytes: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    if shift == 0 {
        return std::borrow::Cow::Borrowed(bytes);
    }
    let mut padded = vec![0u8; shift];
    padded.extend_from_slice(bytes);
    std::borrow::Cow::Owned(padded)
}

/// Whether a slot's bytes would be read as unused rather than as a record.
///
/// An unused slot is all zero except for four bytes of free-list pointer, and
/// a record too short to hold one has no pointer to check, so being all zero
/// is the whole of the evidence for it. `size` is the file's size in bytes,
/// which bounds what a plausible pointer looks like.
///
/// [`pages::write_record`](super::pages::write_record) calls this too, on the
/// bytes it is about to write padded to the physical length -- the same test
/// [`walk`] applies when it later decides whether that slot holds a record.
/// A write that satisfied this predicate would be unreadable the moment it
/// landed, and everything after it in the page with it, so it is refused
/// before it is written rather than accepted and discovered corrupt on the
/// next read. See C1 in `docs/plans/2026-08-07-btrieve-writes.md`.
pub(crate) fn looks_empty(record: &[u8], size: u32) -> bool {
    match record.len() {
        0..4 => record.iter().all(|b| *b == 0),
        _ => record[4..].iter().all(|b| *b == 0) && super::pages::long(record) < size,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btrieve::keys;

    /// Bytes of a record in these fixtures.
    ///
    /// Eight rather than two, because a free slot holds a four-byte pointer to
    /// the next one and a record shorter than that cannot be on a free list at
    /// all. Every file MajorMUD ships has records of 22 bytes or more.
    const RECLEN: u16 = 8;

    /// A record whose key -- two bytes at offset 0 -- is `n`.
    fn record(n: u16) -> Vec<u8> {
        let mut out = vec![0xee; RECLEN as usize];
        out[..2].copy_from_slice(&n.to_le_bytes());
        out
    }

    /// A file of one page of control record and enough data pages for
    /// `records`, each identified by its two-byte key.
    fn of(keys: &[u16]) -> Vec<u8> {
        let records: Vec<Vec<u8>> = keys.iter().map(|n| record(*n)).collect();
        let borrowed: Vec<&[u8]> = records.iter().map(Vec::as_slice).collect();
        file(512, RECLEN, &borrowed, &[])
    }

    /// Where the `n`th record slot of the first data page is.
    fn slot(n: u32) -> u32 {
        512 + u32::from(crate::btrieve::pages::HEADER) + u32::from(RECLEN) * n
    }

    /// A page of B-tree index, appended where a walk will meet it.
    ///
    /// Its usage count has no high bit, which is the only thing that
    /// distinguishes it from a page of records -- and reading it as records
    /// would produce eight-byte slices of index node. `WCCTEXT` is 3,601 pages
    /// of which 45 hold records, so this is the ordinary case and not the odd
    /// one.
    fn with_index_page(mut bytes: Vec<u8>) -> Vec<u8> {
        bytes.extend(std::iter::repeat_n(0x5au8, 512));
        let at = bytes.len() - 512;
        bytes[at + 5] &= !0x80;
        bytes
    }

    /// A file of one page of control record and `pages` data pages.
    fn file(page: u16, reclen: u16, records: &[&[u8]], free: &[u32]) -> Vec<u8> {
        let physical = reclen;
        let per_page = (page - crate::btrieve::pages::HEADER) / physical;
        let pages = 1 + records.len().div_ceil(usize::from(per_page)).max(1);
        let mut out = vec![0u8; usize::from(page) * pages];

        out[0x08..0x0a].copy_from_slice(&page.to_le_bytes());
        out[6] = 0;
        out[7] = 4;
        out[0x14..0x16].copy_from_slice(&1u16.to_le_bytes());
        out[0x16..0x18].copy_from_slice(&reclen.to_le_bytes());
        out[0x18..0x1a].copy_from_slice(&physical.to_le_bytes());
        let count = records.len() as u32;
        out[0x1a..0x1c].copy_from_slice(&((count >> 16) as u16).to_le_bytes());
        out[0x1c..0x1e].copy_from_slice(&(count as u16).to_le_bytes());

        // One key: two bytes of signed number at offset 0.
        let key = 0x110;
        out[key + 0x08..key + 0x0a].copy_from_slice(&(1u16 << 8).to_le_bytes());
        out[key + 0x16..key + 0x18].copy_from_slice(&2u16.to_le_bytes());
        out[key + 0x1c] = 0x0f;

        // The free list, as a chain through the slots it names.
        let head = free.first().copied().unwrap_or(NOWHERE);
        out[FREE_LIST..FREE_LIST + 2].copy_from_slice(&((head >> 16) as u16).to_le_bytes());
        out[FREE_LIST + 2..FREE_LIST + 4].copy_from_slice(&(head as u16).to_le_bytes());
        for (n, slot) in free.iter().enumerate() {
            let next = free.get(n + 1).copied().unwrap_or(NOWHERE);
            let at = *slot as usize;
            out[at..at + 2].copy_from_slice(&((next >> 16) as u16).to_le_bytes());
            out[at + 2..at + 4].copy_from_slice(&(next as u16).to_le_bytes());
        }

        // Records, packed into data pages. Every slot the free list names is
        // stepped over, so the caller's records land where a real file's would.
        let mut slots = Vec::new();
        for number in 1..pages {
            let base = u32::try_from(usize::from(page) * number).expect("small");
            out[usize::try_from(base).unwrap() + 5] |= 0x80;
            for slot in 0..u32::from(per_page) {
                slots.push(base + u32::from(crate::btrieve::pages::HEADER) + u32::from(physical) * slot);
            }
        }
        let mut live = slots.iter().filter(|s| !free.contains(s));
        for record in records {
            let at = *live.next().expect("a slot for every record") as usize;
            out[at..at + record.len()].copy_from_slice(record);
        }
        out
    }

    /// Read a file's records, by way of a real file.
    fn read(name: &str, bytes: &[u8]) -> Result<Records, BtvError> {
        let dir = crate::testing::scratch(&format!("btv-rec-{name}"));
        let path = dir.join(name);
        std::fs::write(&path, bytes).expect("written");
        let geometry = Geometry::read(name, &path)?;
        let fcr = std::fs::read(&path).expect("read");
        let parsed = keys::parse(name, &fcr, geometry.keys)?;
        Records::read(name, &path, &geometry, &parsed)
    }

    #[test]
    fn every_record_is_found_and_kept_in_the_order_the_pages_hold_them() {
        let records = read("THREE.DAT", &of(&[3, 1, 2])).expect("reads");
        assert_eq!(records.len(), 3);
        assert_eq!(records.physical(0).expect("first").bytes[0], 3);
        assert_eq!(records.physical(2).expect("third").bytes[0], 2);
    }

    #[test]
    fn the_key_order_is_not_the_physical_order() {
        // `WCCRACE` is exactly this: thirteen races whose first record is
        // number 10. A host that handed back physical order for a keyed read
        // would give the module the wrong race and nothing would say so.
        let records = read("ORDER.DAT", &of(&[3, 1, 2])).expect("reads");
        let ordered: Vec<u8> = (0..3)
            .map(|n| records.ordered(0, n).expect("in order").bytes[0])
            .collect();
        assert_eq!(ordered, [1, 2, 3]);
    }

    #[test]
    fn a_record_on_the_free_list_is_not_a_record() {
        // The second slot of the first data page, deleted. `WCCITEMS` has 165
        // of these and `WCCMP001` has 1,915; counting them would make every
        // file report more records than it has.
        let records = read(
            "FREED.DAT",
            &file(512, RECLEN, &[&record(1), &record(2)], &[slot(1)]),
        )
        .expect("reads");
        assert_eq!(records.len(), 2);
        assert!(records.find_physical(slot(1)).is_none(), "and not that one");
        assert_eq!(records.physical(1).expect("second").position, slot(2));
    }

    #[test]
    fn a_free_list_that_leaves_the_file_is_refused() {
        let mut bytes = of(&[1]);
        bytes[FREE_LIST..FREE_LIST + 2].copy_from_slice(&0xffu16.to_le_bytes());
        bytes[FREE_LIST + 2..FREE_LIST + 4].copy_from_slice(&0u16.to_le_bytes());
        let e = read("ESCAPE.DAT", &bytes).expect_err("that is past the end");
        assert!(e.why.contains("past the end"), "{e}");
    }

    #[test]
    fn a_free_list_that_loops_is_refused_rather_than_followed_forever() {
        let mut bytes = of(&[1]);
        for at in [FREE_LIST, slot(1) as usize] {
            bytes[at..at + 2].copy_from_slice(&((slot(1) >> 16) as u16).to_le_bytes());
            bytes[at + 2..at + 4].copy_from_slice(&(slot(1) as u16).to_le_bytes());
        }
        assert!(read("LOOP.DAT", &bytes).is_err());
    }

    #[test]
    fn a_file_holding_fewer_records_than_its_header_claims_is_refused() {
        // The check that makes this a reading rather than a guess. A page
        // format misread by one byte finds a different number of records, and
        // without this the module would get a plausible subset of its world.
        let mut bytes = of(&[1, 2]);
        bytes[0x1c..0x1e].copy_from_slice(&9u16.to_le_bytes());
        let e = read("SHORT.DAT", &bytes).expect_err("nine is not two");
        assert!(e.why.contains('9') && e.why.contains('2'), "{e}");
    }

    #[test]
    fn an_index_page_is_not_read_as_records() {
        let records = read("INDEX.DAT", &with_index_page(of(&[1, 2]))).expect("reads");
        assert_eq!(records.len(), 2);
        assert!(
            records.physical(0).expect("first").bytes.iter().all(|b| *b != 0x5a),
            "no byte of an index page reached a record"
        );
    }

    #[test]
    fn a_place_in_physical_order_maps_to_its_place_in_key_order() {
        // What `gabbtv` needs: the module names a record by its file offset and
        // the next `qnxbtv` has to carry on from there in key order.
        let records = read("RANK.DAT", &of(&[3, 1, 2])).expect("reads");
        assert_eq!(records.place_in(0, 0), Some(2), "record 3 sorts last");
        assert_eq!(records.place_in(0, 1), Some(0), "record 1 sorts first");
    }

    #[test]
    fn a_key_lookup_finds_the_first_record_not_before_the_value() {
        let bytes = of(&[3, 1, 5]);
        let records = read("SEEK.DAT", &bytes).expect("reads");
        let parsed = keys::parse("SEEK.DAT", &bytes, 1).expect("keys");

        assert_eq!(records.seek(&parsed, 0, &[1, 0]), 0);
        assert_eq!(records.seek(&parsed, 0, &[3, 0]), 1);
        assert_eq!(records.seek(&parsed, 0, &[4, 0]), 2, "the first one above 4");
        assert_eq!(records.seek(&parsed, 0, &[9, 0]), 3, "past the end");

        assert!(records.matches(&parsed, 0, 1, &[3, 0]));
        assert!(!records.matches(&parsed, 0, 1, &[4, 0]));
    }

    #[test]
    /// Splicing has to agree with a full re-derivation, for every table, after
    /// every write -- not just on the first one.
    ///
    /// This is the guard that makes the incremental paths safe to have at all.
    /// `reindex` is the definition of what `order`, `rank` and `ties` mean;
    /// `link`/`unlink`/`renumber` are an optimisation of it, and an
    /// optimisation is only correct if it is indistinguishable. So this runs a
    /// long mixed sequence of inserts, updates and deletes and compares all
    /// three tables against a freshly sorted copy after *each* one -- a
    /// divergence that only appears on the ninth write is exactly the kind
    /// this replaces a sort with.
    ///
    /// The values are chosen to collide: duplicate keys are what make `ties`
    /// non-zero and what put the position tie-break to work, and a comparator
    /// that is subtly wrong about equal values is invisible against distinct
    /// ones. `9` recurs for that reason.
    ///
    /// Deterministic rather than random: a property test that fails once in a
    /// hundred runs on someone else's machine is worse than one that either
    /// always fails or always passes.
    #[test]
    fn splicing_matches_a_full_reindex_over_a_long_run_of_writes() {
        let bytes = of(&[5, 9, 1, 9]);
        let parsed = keys::parse("SPLICE.DAT", &bytes, 1).expect("keys");
        let mut records = read("SPLICE.DAT", &bytes).expect("reads");

        // (what to do, which slot, which key value)
        let script: &[(&str, u32, u16)] = &[
            ("insert", 4, 7),
            ("insert", 5, 9),   // ties with two existing records
            ("update", 0, 9),   // a distinct value becomes a duplicate
            ("delete", 2, 0),   // remove from the middle, renumbering the rest
            ("insert", 2, 0),   // reuse a freed slot: a low position, inserted late
            ("update", 5, 1),   // a duplicate stops being one
            ("delete", 0, 0),   // remove the first record in physical order
            ("insert", 6, 9),
            ("update", 4, 9),
            ("delete", 5, 0),
        ];

        for (step, (what, n, value)) in script.iter().enumerate() {
            let position = slot(*n);
            match *what {
                "insert" => records.insert(&parsed, position, record(*value)).expect("inserts"),
                "update" => records.update(&parsed, position, record(*value)).expect("updates"),
                "delete" => records.delete(&parsed, position).expect("deletes"),
                other => panic!("unknown step {other}"),
            }

            let mut oracle = records.clone();
            oracle.reindex(&parsed);
            assert_eq!(
                records.order, oracle.order,
                "step {step} ({what} {n}): key order diverged from a full reindex"
            );
            assert_eq!(
                records.rank, oracle.rank,
                "step {step} ({what} {n}): rank diverged -- rank is order inverted, so \
                 this fails when a renumber missed an entry"
            );
            assert_eq!(
                records.ties, oracle.ties,
                "step {step} ({what} {n}): tie count diverged -- the seam repair is wrong"
            );
        }
    }

    fn an_inserted_record_appears_in_physical_and_in_key_order() {
        let bytes = of(&[1, 3]);
        let mut records = read("INSERT.DAT", &bytes).expect("reads");
        let parsed = keys::parse("INSERT.DAT", &bytes, 1).expect("keys");
        let position = slot(2); // the third slot of the page, unused by [1, 3]

        records.insert(&parsed, position, record(2)).expect("inserts");

        assert_eq!(records.len(), 3);
        assert_eq!(
            records.physical(2).expect("appended at the end").bytes[0],
            2,
            "physical order is file order, and an insert is the newest thing in the file"
        );
        assert_eq!(
            records.ordered(0, 1).expect("the middle of the key order").bytes[0],
            2,
            "2 sorts between 1 and 3"
        );
        assert_eq!(records.find_physical(position), Some(2));
    }

    /// I3: `insert` used to `push`, so physical order was insertion order.
    /// The two agree only while every insert appends -- which is all
    /// `WCCUSERS`'s empty free list ever exercises. `WCCITEMS`'s free-list
    /// head is `0x325806`, a position *lower* than records already in the
    /// file, so its inserts do not append: they land in a low slot a
    /// deletion freed. This reproduces that shape without needing
    /// `WCCITEMS` itself -- a free slot before both live records -- and
    /// checks both halves: the in-memory model right after the insert, and
    /// a completely independent fresh read of the same write from disk.
    #[test]
    fn an_insert_through_a_free_slot_at_a_low_position_agrees_with_a_fresh_read() {
        let bytes = file(512, RECLEN, &[&record(1), &record(3)], &[slot(0)]);
        let dir = crate::testing::scratch("btv-rec-freeslot");
        let path = dir.join("FREESLOT.DAT");
        std::fs::write(&path, &bytes).expect("written");

        let geometry = Geometry::read("FREESLOT.DAT", &path).expect("geometry");
        let fcr = std::fs::read(&path).expect("read");
        let parsed = keys::parse("FREESLOT.DAT", &fcr, geometry.keys).expect("keys");
        let mut records =
            Records::read("FREESLOT.DAT", &path, &geometry, &parsed).expect("reads");

        // Baseline: the two live records, in file order.
        assert_eq!(records.physical(0).expect("first").position, slot(1));
        assert_eq!(records.physical(1).expect("second").position, slot(2));

        // The model, in isolation: insert at `slot(0)`, below both.
        records.insert(&parsed, slot(0), record(9)).expect("inserts");
        assert_eq!(
            records.physical(0).expect("lowest position sorts first").position,
            slot(0),
            "the model is in file order, not insertion order"
        );
        assert_eq!(records.physical(0).expect("first").bytes[0], 9);
        assert_eq!(records.physical(1).expect("second").position, slot(1));
        assert_eq!(records.physical(2).expect("third").position, slot(2));

        // The same write, actually made -- through the free slot the
        // fixture built, whose link already terminates the list at
        // `NOWHERE` -- and read back completely fresh, independent of the
        // `records` model above.
        let layout = crate::btrieve::pages::Layout {
            page: geometry.page,
            physical: geometry.physical,
            pages: geometry.pages,
        };
        crate::btrieve::pages::write_record(
            &path,
            layout,
            crate::btrieve::pages::Slot::Free(slot(0)),
            &record(9),
            3,
        )
        .expect("writes");

        let geometry = Geometry::read("FREESLOT.DAT", &path).expect("geometry after the write");
        let fcr = std::fs::read(&path).expect("read again");
        let parsed = keys::parse("FREESLOT.DAT", &fcr, geometry.keys).expect("keys");
        let reread =
            Records::read("FREESLOT.DAT", &path, &geometry, &parsed).expect("a fresh read");

        assert_eq!(reread.len(), 3);
        assert_eq!(
            reread.physical(0).expect("first").position,
            slot(0),
            "a fresh read is always file order"
        );
        assert_eq!(reread.physical(0).expect("first").bytes[0], 9);
        assert_eq!(reread.physical(1).expect("second").position, slot(1));
        assert_eq!(reread.physical(2).expect("third").position, slot(2));
    }

    #[test]
    fn inserting_into_a_position_that_already_holds_a_record_is_refused() {
        let bytes = of(&[1]);
        let mut records = read("OCCUPIED.DAT", &bytes).expect("reads");
        let parsed = keys::parse("OCCUPIED.DAT", &bytes, 1).expect("keys");
        let position = records.physical(0).expect("first").position;

        assert!(records.insert(&parsed, position, record(2)).is_err());
    }

    #[test]
    fn an_updated_record_keeps_its_position_and_moves_in_key_order() {
        let bytes = of(&[1, 2, 3]);
        let mut records = read("UPDATE.DAT", &bytes).expect("reads");
        let parsed = keys::parse("UPDATE.DAT", &bytes, 1).expect("keys");
        let position = records.physical(0).expect("first, holding key 1").position;

        records.update(&parsed, position, record(9)).expect("updates");

        assert_eq!(
            records.physical(0).expect("still first physically").position,
            position,
            "an update rewrites the record the file is positioned on -- absbtv must \
             answer the same before and after"
        );
        assert_eq!(records.physical(0).expect("same slot").bytes[0], 9);
        assert_eq!(
            records.ordered(0, 2).expect("now sorts last").bytes[0],
            9,
            "9 is greater than 2 and 3"
        );
    }

    #[test]
    fn updating_a_position_that_holds_no_record_is_refused() {
        let bytes = of(&[1]);
        let mut records = read("MISSING.DAT", &bytes).expect("reads");
        let parsed = keys::parse("MISSING.DAT", &bytes, 1).expect("keys");

        // The module is entitled to be wrong; the host is not entitled to
        // invent a record.
        assert!(records.update(&parsed, slot(5), record(2)).is_err());
    }

    #[test]
    fn a_deleted_record_leaves_physical_order_and_every_key_order() {
        let bytes = of(&[1, 2, 3]);
        let mut records = read("DELETE.DAT", &bytes).expect("reads");
        let parsed = keys::parse("DELETE.DAT", &bytes, 1).expect("keys");
        let position = records.physical(1).expect("the middle record, key 2").position;

        records.delete(&parsed, position).expect("deletes");

        assert_eq!(records.len(), 2);
        assert!(records.find_physical(position).is_none());
        for n in 0..records.len() {
            assert_ne!(
                records.ordered(0, n).expect("in order").bytes[0],
                2,
                "the deleted record is gone from key order too"
            );
        }
    }

    #[test]
    fn deleting_a_position_that_holds_no_record_is_refused() {
        let bytes = of(&[1]);
        let mut records = read("GONE.DAT", &bytes).expect("reads");
        let parsed = keys::parse("GONE.DAT", &bytes, 1).expect("keys");

        assert!(records.delete(&parsed, slot(5)).is_err());
    }

    /// I8: why `delete` is `pub(crate)` rather than `pub`. It only ever
    /// touches the in-memory model -- there is no `Block::delete` yet to
    /// free the slot on disk or add it to the free list -- so a caller with
    /// access to this alone could take `position` out of
    /// [`Records::positions`] while the slot behind it is still live on
    /// disk, and a later `Layout::next_slot` would hand that same position
    /// back as `Slot::Existing` for a write to overwrite. This demonstrates
    /// the gap directly: deleting from the model leaves the underlying bytes
    /// completely untouched, so a fresh read of them still finds the record
    /// the model just forgot.
    #[test]
    fn deleting_from_the_model_alone_does_not_touch_the_file() {
        let bytes = of(&[1, 2, 3]);
        let mut records = read("MODEL-ONLY.DAT", &bytes).expect("reads");
        let parsed = keys::parse("MODEL-ONLY.DAT", &bytes, 1).expect("keys");
        let position = records.physical(1).expect("the middle record").position;

        records.delete(&parsed, position).expect("deletes from the model");
        assert!(
            records.positions().iter().all(|p| *p != position),
            "the model has forgotten it"
        );

        // The bytes this came from were never written to -- a fresh read of
        // exactly the same file content still finds all three records,
        // including the one the model just forgot.
        let reread = read("MODEL-ONLY.DAT", &bytes).expect("reads again");
        assert_eq!(reread.len(), 3, "the file itself was never touched");
        assert!(reread.find_physical(position).is_some());
    }

    /// `ties` is how this host reports the one Btrieve divergence it cannot
    /// check: duplicates come out in file-position order here and in
    /// insertion order in Btrieve. Inserting two records with the same key
    /// value must make the count say so rather than let the difference be
    /// silent.
    #[test]
    fn inserting_a_duplicate_key_is_counted_as_a_tie() {
        let bytes = of(&[1]);
        let mut records = read("TIES.DAT", &bytes).expect("reads");
        let parsed = keys::parse("TIES.DAT", &bytes, 1).expect("keys");
        assert_eq!(records.ties()[0], 0);

        records.insert(&parsed, slot(1), record(1)).expect("inserts");

        assert_eq!(records.ties()[0], 1);
    }

    #[test]
    fn positions_lists_every_record_currently_held() {
        let bytes = of(&[1, 2, 3]);
        let mut records = read("POSITIONS.DAT", &bytes).expect("reads");
        let parsed = keys::parse("POSITIONS.DAT", &bytes, 1).expect("keys");
        let doomed = records.physical(1).expect("middle").position;

        records.delete(&parsed, doomed).expect("deletes");

        let positions = records.positions();
        assert_eq!(positions.len(), 2);
        assert!(!positions.contains(&doomed));
    }

    /// A v6 page's own six-byte header: a tag at `[0x00]`, its logical id at
    /// `[0x02]`, and a flags word at `[0x04]` whose bit 15 is the same
    /// "holds records" bit `Header::decode` reads for v5, at the same
    /// offset either version.
    fn v6_page_header(tag: u16, logical: u16, data: bool) -> [u8; 6] {
        let mut out = [0u8; 6];
        out[0..2].copy_from_slice(&tag.to_le_bytes());
        out[2..4].copy_from_slice(&logical.to_le_bytes());
        let flags: u16 = if data { 0x8000 } else { 0 };
        out[4..6].copy_from_slice(&flags.to_le_bytes());
        out
    }

    /// A hand-built v6 file, six 512-byte pages: a shadow FCR pair (0/1), a
    /// shadow allocation-table pair (2/3) claiming exactly one data page
    /// (physical 4), and a *second* data page (physical 5) that carries the
    /// same `0x44` data tag and a header shaped just like page 4's, but that
    /// the allocation table never names.
    ///
    /// `PHYSICAL = 6` is a two-byte v6 slot marker plus a four-byte record
    /// body and nothing else (Evidence 1b, minus the duplicate-chain
    /// overhead `DUPKEY30.DAT` also carries) -- the minimum shape that can
    /// tell "read the body at slot + 2" apart from "at slot + 0", and
    /// "visited because claimed" apart from "visited because it merely
    /// carries the data tag".
    ///
    /// Page 4 (claimed, logical 2) holds two live records, `b"AAAA"` and
    /// `b"BBBB"`. Page 5 (unclaimed, logical 1 -- lower, so a scan that
    /// ignores the allocation table and sorts by logical id visits it
    /// *first*) holds two records of its own, `b"XXXX"` and `b"YYYY"`, that
    /// no correct reading of this file should ever return. `keys` is left
    /// at zero: this fixture is about which *pages* a walk visits, not about
    /// key parsing, so the test below hands `Records::read` an empty key
    /// slice directly rather than exercising `keys::parse`.
    fn v6_stale_twin_fixture() -> Vec<u8> {
        const PAGE: usize = 512;
        const RECLEN: u16 = 4;
        const PHYSICAL: u16 = 6;

        let mut out = vec![0u8; PAGE * 6];
        let word = |out: &mut [u8], at: usize, value: u16| {
            out[at..at + 2].copy_from_slice(&value.to_le_bytes());
        };

        // Page 0: the stale FCR shadow copy -- generation 1. `Geometry::read`
        // derives `page_size` from *this* half before it knows which copy is
        // live (Evidence 1a), so the page length has to be here too, not
        // only on page 1.
        out[0..2].copy_from_slice(b"FC");
        word(&mut out, 0x04, 1);
        word(&mut out, 0x08, PAGE as u16);

        // Page 1: the live FCR shadow copy (generation 2), carrying every
        // field a fixed-length v6 file needs.
        let p1 = PAGE;
        out[p1..p1 + 2].copy_from_slice(b"FC");
        word(&mut out, p1 + 0x04, 2);
        word(&mut out, p1 + 0x08, PAGE as u16);
        word(&mut out, p1 + 0x14, 0); // key count
        word(&mut out, p1 + 0x16, RECLEN);
        word(&mut out, p1 + 0x18, PHYSICAL);
        word(&mut out, p1 + 0x1a, 0); // record count, high
        word(&mut out, p1 + 0x1c, 2); // record count, low -- two live records

        // Page 2: the stale allocation-table shadow copy -- magic, block
        // index and a lower generation, no entries needed.
        let p2 = PAGE * 2;
        out[p2..p2 + 2].copy_from_slice(b"PP");
        word(&mut out, p2 + 0x02, 1);
        word(&mut out, p2 + 0x04, 1);

        // Page 3: the live allocation-table shadow copy, claiming exactly
        // one page -- physical 4, marker `0x4400` (this format's own data
        // tag, which is what every marker observed in the real corpus is).
        let p3 = PAGE * 3;
        out[p3..p3 + 2].copy_from_slice(b"PP");
        word(&mut out, p3 + 0x02, 1);
        word(&mut out, p3 + 0x04, 2);
        word(&mut out, p3 + 0x0c, 0x4400); // entry 0's marker
        word(&mut out, p3 + 0x0e, 4); // entry 0's physical page

        // Page 4: the one page the allocation table actually claims.
        // Logical 2, two live records front-packed, the rest zero -- so
        // `looks_empty` stops the scan there, same as the real corpus.
        let p4 = PAGE * 4;
        out[p4..p4 + 6].copy_from_slice(&v6_page_header(0x4400, 2, true));
        out[p4 + 6..p4 + 8].copy_from_slice(&1u16.to_le_bytes());
        out[p4 + 8..p4 + 12].copy_from_slice(b"AAAA");
        out[p4 + 12..p4 + 14].copy_from_slice(&1u16.to_le_bytes());
        out[p4 + 14..p4 + 18].copy_from_slice(b"BBBB");

        // Page 5: the stale-twin shape (Evidence 3/3a) -- except *not*
        // empty, so a reading that visits it anyway produces bytes no real
        // Btrieve ever returned for this file.
        let p5 = PAGE * 5;
        out[p5..p5 + 6].copy_from_slice(&v6_page_header(0x4400, 1, true));
        out[p5 + 6..p5 + 8].copy_from_slice(&1u16.to_le_bytes());
        out[p5 + 8..p5 + 12].copy_from_slice(b"XXXX");
        out[p5 + 12..p5 + 14].copy_from_slice(&1u16.to_le_bytes());
        out[p5 + 14..p5 + 18].copy_from_slice(b"YYYY");

        out
    }

    /// The claimed-page filter, exercised directly. Dropping it -- Task 5's
    /// mandatory mutation (b) -- makes this fail: `v6_stale_twin_fixture`
    /// carries a second `0x44`-tagged page the allocation table never
    /// claims, holding bytes no correct reading of the file should surface.
    ///
    /// **Neither committed oracle fixture catches this mutation on its
    /// own.** Measured directly: `DUPKEY30.DAT`'s and `PP2048.DAT`'s own
    /// stale twins (physical 5 in both) happen to `looks_empty` regardless
    /// of whether the claimed-page filter runs at all, because their first
    /// four content bytes decode as a small `long` with an all-zero tail --
    /// the same shape a genuinely unused slot has. That is a real, measured
    /// property of those two files, not something this design is entitled
    /// to rely on in general: Evidence 3a is explicit that a stale twin can
    /// hold real leftover content (`NONMONO2.DAT`'s three duplicate logical
    /// ids all disagree in their *bodies*, not just their headers). This
    /// fixture is built to say so where the real corpus happens not to.
    #[test]
    fn a_stale_page_sharing_the_data_tag_but_not_claimed_is_never_visited() {
        let bytes = v6_stale_twin_fixture();
        let dir = crate::testing::scratch("btv-rec-v6-stale-twin");
        let path = dir.join("STALETWIN.DAT");
        std::fs::write(&path, &bytes).expect("written");

        let geometry = Geometry::read("STALETWIN.DAT", &path).expect("a v6 shape");
        assert_eq!(geometry.version, Version::V6);

        let records = Records::read("STALETWIN.DAT", &path, &geometry, &[]).expect("reads");
        assert_eq!(records.len(), 2);
        assert_eq!(records.physical(0).expect("first").bytes, b"AAAA");
        assert_eq!(records.physical(1).expect("second").bytes, b"BBBB");
    }

    /// A second implementation of [`walk`]'s page arithmetic, built once as
    /// the safety net for the Task 4 refactor
    /// (`docs/plans/2026-08-11-btrieve-v6-page-addressing.md`) that routes
    /// `walk` itself through [`super::pages::Layout`]. Until that refactor
    /// lands, this and `walk` are two independent implementations of the same
    /// assumption -- Trap 1 in that plan -- so
    /// [`walk_and_a_layout_based_walk_agree_on_every_shipped_file`] exists to
    /// prove they agree while that is still true.
    fn layout_walk(geometry: &Geometry, path: &Path) -> Result<Vec<Record>, String> {
        let mut file =
            std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let size = u32::try_from(file.metadata().map_err(|e| e.to_string())?.len())
            .map_err(|_| "a Btrieve file larger than four gigabytes".to_owned())?;

        let dead = free_list(&mut file, size)?;
        let layout = crate::btrieve::pages::Layout {
            page: geometry.page,
            physical: geometry.physical,
            pages: geometry.pages,
        };
        let per_page = layout.per_page();

        let mut records = Vec::with_capacity(geometry.records as usize);
        let mut buffer = vec![0u8; geometry.page as usize];
        let mut fragment = vec![0u8; geometry.page as usize];

        for number in 1..geometry.pages {
            // The page's own start, derived from `Layout` rather than
            // reimplementing its multiplication: a slot-0 position is always
            // `HEADER` bytes past the page start.
            let at = layout.position(number, 0) - u32::from(crate::btrieve::pages::HEADER);
            file.seek(SeekFrom::Start(u64::from(at)))
                .and_then(|_| file.read_exact(&mut buffer))
                .map_err(|e| format!("page {number}: {e}"))?;

            if !crate::btrieve::pages::Header::decode(&buffer).data {
                continue;
            }

            for slot in 0..per_page {
                if records.len() as u32 == geometry.records {
                    break;
                }
                let position = layout.position(number, slot);
                if dead.contains(&position) {
                    continue;
                }

                let start = (position - at) as usize;
                let record = &buffer[start..start + geometry.physical as usize];

                if looks_empty(record, size) {
                    break;
                }

                let mut bytes = record[..geometry.reclen as usize].to_vec();

                let pointer = geometry.variable.then(|| {
                    let at = usize::from(geometry.reclen);
                    Pointer::decode([record[at], record[at + 1], record[at + 2], record[at + 3]])
                });
                if let Some(pointer) = pointer {
                    let mut source = Chained {
                        file: &mut file,
                        buffer: &mut fragment,
                        pages: geometry.pages,
                    };
                    Chain::follow(&mut source, geometry.version, pointer, &mut bytes)
                        .map_err(|why| format!("the record at {position}: {why}"))?;
                }

                records.push(Record { position, bytes });
            }
        }

        Ok(records)
    }

    /// Every file MajorMUD ships, by name only -- the shape census belongs to
    /// `crates/mbbs/tests/btrieve.rs`'s `FILES`, this just needs to open each.
    const SHIPPED_FILES: &[&str] = &[
        "NEWMP001.VIR",
        "WCCACMSR.VIR",
        "WCCACTS.VIR",
        "WCCBANKS.VIR",
        "WCCCLASS.VIR",
        "WCCGANGS.VIR",
        "WCCITEMS.VIR",
        "WCCITOWN.VIR",
        "WCCKNMSR.VIR",
        "WCCMP001.VIR",
        "WCCMSG.VIR",
        "WCCRACE.VIR",
        "WCCSHOPS.VIR",
        "WCCSPELS.VIR",
        "WCCTEXT.VIR",
        "WCCUSERS.VIR",
        "WCCUPDAT.DAT",
        "WCCUSERS.DAT",
    ];

    /// `records::walk` and a `Layout`-based walk must agree on every file
    /// MajorMUD ships, since both implement the same page-arithmetic
    /// assumption -- Trap 1 in
    /// `docs/plans/2026-08-11-btrieve-v6-page-addressing.md`. This is the
    /// safety net for the refactor that collapses them into one: it must pass
    /// *before* `walk` is touched, and it must keep passing (trivially, once
    /// `walk` and `layout_walk` share an implementation) after.
    #[test]
    #[ignore = "needs MajorMUD's data files in tmp/"]
    fn walk_and_a_layout_based_walk_agree_on_every_shipped_file() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tmp");
        if !dir.join("WCCITEMS.VIR").is_file() {
            eprintln!("skipped: no MajorMUD data files in tmp/");
            return;
        }

        for name in SHIPPED_FILES {
            let path = dir.join(name);
            let geometry = Geometry::read(name, &path).unwrap_or_else(|e| panic!("{name}: {e}"));
            let want = walk(&geometry, &path).unwrap_or_else(|e| panic!("{name} walk: {e}"));
            let got =
                layout_walk(&geometry, &path).unwrap_or_else(|e| panic!("{name} layout_walk: {e}"));
            assert_eq!(want, got, "{name}: walk and layout_walk disagree");
        }
    }
}
