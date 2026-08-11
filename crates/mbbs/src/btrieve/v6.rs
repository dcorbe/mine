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
//! Entries start at `[0x0c]`, `(page_size - 0x0c) / 4` of them, each a plain
//! (not word-swapped) little-endian `[u16 marker][u16 page]` pair. A non-zero
//! marker means the named physical page is currently claimed; the marker's
//! value is observed to equal that page's own type tag.
//!
//! **A page absent from the table, or present with a zero marker, is
//! unclaimed** -- freed pages and pages that were never written both keep
//! stale or all-zero headers, and both collide on logical id 0 or on
//! whatever they held before being freed. Filtering by the marker *before*
//! grouping by logical id is what tells a freed twin from the live page
//! (Evidence 3, 3a); every one of the eight fixtures this module is tested
//! against has zero unresolved logical ids left after that filter.
//!
//! # Where further allocation-table blocks live
//!
//! Block 1 is always shadowed across physical pages 2 and 3 -- measured on
//! every fixture this module has ever seen, and treated as an established
//! fact rather than discovered. A file that outgrows one block's capacity
//! gets a second (`PP2BLOCK.DAT` has one at physical 130/131), but **where**
//! is not established (Evidence 5), so this module finds every block -- 1
//! included -- by scanning every page for the magic, and refuses only if
//! neither physical page 2 nor 3 is one of them: that specific refusal is
//! the one shape this module trusts a fixed position for.

use std::collections::HashMap;

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
const ENTRIES: usize = 0x0c;

/// Bytes per allocation-table entry: a `u16` marker and a `u16` physical
/// page number, both plain little-endian -- not the high-word-first
/// convention `pages::long` uses for record positions.
const ENTRY: usize = 4;

/// Byte offset, within an ordinary page, of its own logical id (`u16`
/// little-endian).
const LOGICAL: usize = 0x02;

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
    pub fn read(file: &[u8], page_size: u16) -> Result<Self, String> {
        let page_size = usize::from(page_size);
        if page_size <= ENTRIES {
            return Err(format!(
                "{page_size}-byte pages have no room for an allocation-table \
                 entry, which starts at {ENTRIES:#x}"
            ));
        }
        if file.is_empty() || !file.len().is_multiple_of(page_size) {
            return Err(format!(
                "{} bytes is not a whole number of {page_size}-byte pages",
                file.len()
            ));
        }
        let pages = file.len() / page_size;

        let word = |page: usize, offset: usize| -> u16 {
            let at = page * page_size + offset;
            u16::from_le_bytes([file[at], file[at + 1]])
        };
        let magic = |page: usize| -> bool {
            let at = page * page_size;
            &file[at..at + 2] == MAGIC
        };

        // Block 1's allocation table is always shadowed across physical
        // pages 2 and 3 -- an established fact (module doc comment), not
        // something this scans for. Checked directly, ahead of the general
        // scan below, so this exact refusal fires even if some other page
        // elsewhere happens to carry a stray "PP" tagged block 1.
        if pages < 4 || !(magic(2) || magic(3)) {
            return Err(
                "neither physical page 2 nor 3 carries the \"PP\" allocation-\
                 table magic -- there is no block 1 where one is always \
                 expected"
                    .to_owned(),
            );
        }

        // Every allocation-table page in the file, however many blocks that
        // is -- a second block's placement is not established (Evidence 5),
        // so this is a scan for the magic, not a formula off the first pair.
        let mut blocks: HashMap<u16, Vec<(usize, u16)>> = HashMap::new();
        for page in 0..pages {
            if magic(page) {
                let block = word(page, BLOCK);
                let generation = word(page, GENERATION);
                blocks.entry(block).or_default().push((page, generation));
            }
        }

        // The live copy of each block: highest generation wins. A tie is a
        // shape nothing has observed and this refuses rather than guesses
        // between two equally-current copies -- the same rule Task 1 applies
        // to the file control record's own shadow pair.
        let mut claimed: HashMap<u32, u16> = HashMap::new();
        let entries_per_page = (page_size - ENTRIES) / ENTRY;
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
            for entry in 0..entries_per_page {
                let at = live * page_size + ENTRIES + entry * ENTRY;
                let marker = u16::from_le_bytes([file[at], file[at + 1]]);
                let claimed_page = u16::from_le_bytes([file[at + 2], file[at + 3]]);
                if marker != 0 {
                    claimed.insert(u32::from(claimed_page), marker);
                }
            }
        }

        // Every remaining page, filtered to the ones the allocation table
        // marks claimed (Evidence 3, 3a) -- a page absent from `claimed`, or
        // present with a zero marker, is unclaimed regardless of what its
        // own stale header still says.
        let mut by_logical: HashMap<u32, Vec<u32>> = HashMap::new();
        for page in 0..pages {
            if magic(page) {
                continue;
            }
            let at = page * page_size;
            if &file[at..at + 2] == b"FC" {
                continue;
            }
            let page = page as u32;
            if !claimed.contains_key(&page) {
                continue;
            }
            let logical = u32::from(word(page as usize, LOGICAL));
            by_logical.entry(logical).or_default().push(page);
        }

        let mut physical = HashMap::with_capacity(by_logical.len());
        for (logical, mut holders) in by_logical {
            if holders.len() > 1 {
                holders.sort_unstable();
                return Err(format!(
                    "logical page {logical} is claimed by {} physical pages \
                     {holders:?} after the allocation-table marker filter -- \
                     this design says that cannot happen",
                    holders.len()
                ));
            }
            physical.insert(logical, holders[0]);
        }

        Ok(Self { physical })
    }
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
        let map = Map::read(&file, 512).expect("resolves");
        assert_eq!(map.physical(11), Some(7));
        assert_eq!(map.physical(14), Some(17));
        assert_eq!(map.physical(26), Some(36));
        assert_eq!(map.physical.len(), 23, "23 logical ids have a live claimant");
    }

    /// The control for the pair above: the same file immediately *before*
    /// the delete-and-reinsert, with no duplicate logical ids at all. A scan
    /// -only implementation passes this one and fails `NONMONO2` -- this is
    /// the regression signal that the marker filter, not just page
    /// resolution in general, is doing the work.
    #[test]
    fn nonmono1_the_control_before_the_delete_has_no_duplicates() {
        let file = fixture("NONMONO1.DAT");
        let map = Map::read(&file, 512).expect("resolves");
        assert_map(
            &map,
            &[
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
        let map = Map::read(&file, 512).expect("resolves");
        assert_map(&map, &[(2, 10), (5, 8)]);
        assert_eq!(map.physical(0), None);
        assert_eq!(map.physical(1), None);
    }

    /// Catches a 125-entry-per-page capacity hard-coded for a 512-byte page:
    /// `PP2048.DAT`'s pages are 2048 bytes, `(2048 - 0x0c) / 4 == 509`
    /// entries, and its one live id sits at entry index far past 125.
    #[test]
    fn pp2048_a_2048_byte_page_still_finds_its_one_live_id() {
        let file = fixture("PP2048.DAT");
        let map = Map::read(&file, 2048).expect("resolves");
        assert_map(&map, &[(2, 8)]);
    }

    /// Catches locating a second allocation-table block by formula rather
    /// than by scanning: `PP2BLOCK.DAT` has a second block at physical
    /// 130/131, discovered nowhere near a fixed offset from the first pair.
    /// 136 logical ids have a live claimant, and this asserts every one of
    /// them against the reference implementation's own output
    /// (`.scratch-v6-exec/expected_map.py`, `expected_maps.txt`) rather than
    /// a handful of spot checks.
    #[test]
    fn pp2block_a_second_allocation_table_block_is_found_by_scanning() {
        let file = fixture("PP2BLOCK.DAT");
        let map = Map::read(&file, 512).expect("resolves");
        assert_map(
            &map,
            &[
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
        let e = Map::read(&file, 512).unwrap_err();
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
        let e = Map::read(&file, 512).unwrap_err();
        assert!(e.contains("generation 5"), "{e}");
    }

    /// Trap 2's third named refusal: two *claimed* pages holding the same
    /// logical id. Built by hand, like the tie above -- Evidence 3a measured
    /// zero of these on the real corpus after the marker filter, which is
    /// exactly why this design treats it as a refusal rather than a case to
    /// handle: nothing here has ever seen one, so nothing gets to guess.
    #[test]
    fn a_conflict_between_two_claimed_pages_is_refused() {
        let mut file = vec![0u8; 512 * 6];
        let at = |page: usize| page * 512;

        file[at(2)..at(2) + 2].copy_from_slice(MAGIC);
        file[at(2) + BLOCK..at(2) + BLOCK + 2].copy_from_slice(&1u16.to_le_bytes());
        file[at(2) + GENERATION..at(2) + GENERATION + 2].copy_from_slice(&5u16.to_le_bytes());
        // Two entries, each claiming a different physical page (4 and 5)
        // with a non-zero marker.
        let entry = |n: usize| at(2) + ENTRIES + n * ENTRY;
        file[entry(0)..entry(0) + 2].copy_from_slice(&1u16.to_le_bytes()); // marker
        file[entry(0) + 2..entry(0) + 4].copy_from_slice(&4u16.to_le_bytes()); // page 4
        file[entry(1)..entry(1) + 2].copy_from_slice(&1u16.to_le_bytes()); // marker
        file[entry(1) + 2..entry(1) + 4].copy_from_slice(&5u16.to_le_bytes()); // page 5

        // Both claimed pages carry the same logical id.
        file[at(4) + LOGICAL..at(4) + LOGICAL + 2].copy_from_slice(&7u16.to_le_bytes());
        file[at(5) + LOGICAL..at(5) + LOGICAL + 2].copy_from_slice(&7u16.to_le_bytes());

        let e = Map::read(&file, 512).unwrap_err();
        assert!(e.contains("logical page 7"), "{e}");
        assert!(e.contains('4') && e.contains('5'), "{e}");
    }
}
