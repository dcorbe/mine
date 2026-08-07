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
use super::{BtvError, Geometry};

/// Bytes of header at the start of a data page, before the first record.
///
/// Six: four of page number and two of usage count. The high bit of byte 5 is
/// what marks a page as holding records at all.
const PAGE_HEADER: u16 = 6;

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

    /// The record itself, logical length.
    pub bytes: Vec<u8>,
}

/// Every record in a file, in physical order, with an index per key.
#[derive(Debug)]
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
}

impl Records {
    /// Read every record of a file and sort them by each of its keys.
    ///
    /// # Errors
    ///
    /// If the file cannot be read, its free list leaves the file, or the number
    /// of records found is not the number the header claims.
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

        let mut me = Self {
            records,
            order: Vec::new(),
            rank: Vec::new(),
            ties: Vec::new(),
        };
        me.reindex(keys);
        Ok(me)
    }

    /// Re-derive `order`, `rank` and `ties` from `records`, for the given keys.
    ///
    /// Re-sorted rather than spliced: at these record counts a sort is cheap,
    /// and a splice is the kind of thing that is right for a year and then is
    /// not. `read` calls this once after walking the pages, and `insert`,
    /// `update` and `delete` each call it again after touching `records` --
    /// one derivation, so the two cannot drift.
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
                match key.compare(&self.records[*a].bytes, &self.records[*b].bytes) {
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
                    key.compare(&self.records[pair[0]].bytes, &self.records[pair[1]].bytes)
                        == Ordering::Equal
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
    /// It cannot be measured because all four keys in MajorMUD's files that
    /// permit duplicates -- `WCCUSERS` key 2, `WCCGANGS` key 1, `WCCBANKS`
    /// key 0, `WCCITOWN` key 1 -- are in files that hold no records at all.
    /// So this counts the pairs where it *could* matter, and the host reports
    /// the number rather than letting the difference be silent. On a board
    /// nobody has played on, every one of them is zero.
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
            definition.compare_value(&self.records[*record].bytes, value) == Ordering::Less
        })
    }

    /// Whether the record at a place in `key`'s order has exactly `value`.
    pub fn matches(&self, keys: &[Key], key: u16, at: usize, value: &[u8]) -> bool {
        let Some(record) = self.ordered(key, at) else {
            return false;
        };
        keys[usize::from(key)].compare_value(&record.bytes, value) == Ordering::Equal
    }

    /// Add a record at a position nothing else occupies.
    ///
    /// # Errors
    ///
    /// If `position` already holds a record.
    pub fn insert(&mut self, keys: &[Key], position: u32, bytes: Vec<u8>) -> Result<(), String> {
        if self.records.iter().any(|r| r.position == position) {
            return Err(format!("position {position} already holds a record"));
        }
        self.records.push(Record { position, bytes });
        self.reindex(keys);
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
        let record = self
            .records
            .iter_mut()
            .find(|r| r.position == position)
            .ok_or_else(|| format!("position {position} holds no record"))?;
        record.bytes = bytes;
        self.reindex(keys);
        Ok(())
    }

    /// Remove the record at `position`.
    ///
    /// # Errors
    ///
    /// If `position` holds no record.
    pub fn delete(&mut self, keys: &[Key], position: u32) -> Result<(), String> {
        let index = self
            .records
            .iter()
            .position(|r| r.position == position)
            .ok_or_else(|| format!("position {position} holds no record"))?;
        self.records.remove(index);
        self.reindex(keys);
        Ok(())
    }

    /// Every position currently holding a record, for
    /// [`Layout::next_slot`](super::pages::Layout::next_slot).
    pub fn positions(&self) -> Vec<u32> {
        self.records.iter().map(|r| r.position).collect()
    }
}

/// Walk the data pages and collect every live record.
fn walk(geometry: &Geometry, path: &Path) -> Result<Vec<Record>, String> {
    let mut file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let size = u32::try_from(
        file.metadata()
            .map_err(|e| e.to_string())?
            .len(),
    )
    .map_err(|_| "a Btrieve file larger than four gigabytes".to_owned())?;

    let dead = free_list(&mut file, size)?;
    let page = u32::from(geometry.page);
    let physical = u32::from(geometry.physical);
    let per_page = u32::from((geometry.page - PAGE_HEADER) / geometry.physical);

    let mut records = Vec::with_capacity(geometry.records as usize);
    let mut buffer = vec![0u8; geometry.page as usize];

    // Page 0 is the file control record, so records start at page 1.
    for number in 1..geometry.pages {
        let at = page * number;
        file.seek(SeekFrom::Start(u64::from(at)))
            .and_then(|_| file.read_exact(&mut buffer))
            .map_err(|e| format!("page {number}: {e}"))?;

        // The high bit of the usage count marks a page that holds records. The
        // rest are index pages, and reading one as data would produce records
        // out of B-tree nodes.
        if buffer[5] & 0x80 == 0 {
            continue;
        }

        for slot in 0..per_page {
            if records.len() as u32 == geometry.records {
                break;
            }
            let position = at + u32::from(PAGE_HEADER) + physical * slot;
            if dead.contains(&position) {
                continue;
            }

            let start = (u32::from(PAGE_HEADER) + physical * slot) as usize;
            let record = &buffer[start..start + geometry.physical as usize];

            // An unused slot is all zero except for four bytes of free-list
            // pointer, and slots are filled from the front -- so the first one
            // ends the page rather than being skipped. A record too short to
            // hold a pointer has no pointer to check, and being all zero is the
            // whole of the evidence.
            let empty = match record.len() {
                0..4 => record.iter().all(|b| *b == 0),
                _ => record[4..].iter().all(|b| *b == 0) && pointer(record) < size,
            };
            if empty {
                break;
            }
            records.push(Record {
                position,
                bytes: record[..geometry.reclen as usize].to_vec(),
            });
        }
    }

    Ok(records)
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

    let mut next = pointer(&head);
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
        next = pointer(&link);
    }
    Ok(dead)
}

/// A record pointer: four bytes, **high word first**, the same shape the record
/// count in the file control record is.
fn pointer(bytes: &[u8]) -> u32 {
    (u32::from(u16::from_le_bytes([bytes[0], bytes[1]])) << 16)
        | u32::from(u16::from_le_bytes([bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btrieve::keys;

    #[test]
    fn a_record_pointer_is_two_words_high_first() {
        // The same encoding as the record count, and the same trap: read as a
        // little-endian `u32`, `WCCITEMS`'s free list head of 0x325806 becomes
        // 0x06580032 and points past the end of the file.
        assert_eq!(pointer(&[0x32, 0x00, 0x06, 0x58]), 0x0032_5806);
    }

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
        512 + u32::from(PAGE_HEADER) + u32::from(RECLEN) * n
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
        let per_page = (page - PAGE_HEADER) / physical;
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
                slots.push(base + u32::from(PAGE_HEADER) + u32::from(physical) * slot);
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
}
