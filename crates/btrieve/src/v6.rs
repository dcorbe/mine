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
    pub fn read(file: &[u8], page_size: u16) -> Result<Self, String> {
        let page_size = usize::from(page_size);
        // `ENTRIES + ENTRY`, not `ENTRIES`: a page long enough to reach the
        // entry array but too short to hold one whole entry would divide out
        // to zero entries and return an empty map, reporting success for a
        // file nothing was read from.
        if page_size < ENTRIES + ENTRY {
            return Err(format!(
                "{page_size}-byte pages have no room for an allocation-table \
                 entry: the array starts at {ENTRIES:#x} and an entry is \
                 {ENTRY} bytes"
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

        // And whichever of them carries the magic must say it is block 1.
        // The doc comment above claims that position identifies block 1;
        // checking it is what keeps that a fact rather than an assumption,
        // and it costs nothing -- all ten v6 files here carry block index 1
        // on both copies at physical 2 and 3. Without this, a "PP" page at
        // physical 2 mislabelled block 7 becomes a lone unpaired copy that
        // is automatically live, since a single copy never reaches the
        // generation-tie check.
        let entries_per_page = (page_size - ENTRIES) / ENTRY;

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
        let stride = entries_per_page + 2;
        let mut blocks: HashMap<u16, Vec<(usize, u16)>> = HashMap::new();
        for index in 1u16.. {
            let first = 2 + (usize::from(index) - 1) * stride;
            if first + 1 >= pages {
                break;
            }
            let copies: Vec<(usize, u16)> = [first, first + 1]
                .into_iter()
                .filter(|&page| magic(page))
                .map(|page| (page, word(page, GENERATION)))
                .collect();
            if copies.is_empty() {
                break;
            }
            // Position is what identifies a block, so the index stored there has
            // to agree -- the same check physical 2 and 3 already get below.
            for &(page, _) in &copies {
                if word(page, BLOCK) != index {
                    return Err(format!(
                        "physical page {page} is where allocation-table block \
                         {index} lives, but it calls itself block {}",
                        word(page, BLOCK)
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
            for entry in 0..entries_per_page {
                let at = live * page_size + ENTRIES + entry * ENTRY;
                let marker = u16::from_le_bytes([file[at], file[at + 1]]);
                let claimed_page = u16::from_le_bytes([file[at + 2], file[at + 3]]);
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
    pub(crate) fn claim(
        file: &mut Vec<u8>,
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
        if file.is_empty() || !file.len().is_multiple_of(page_size_usize) {
            return Err(format!(
                "{} bytes is not a whole number of {page_size}-byte pages",
                file.len()
            ));
        }
        let pages = file.len() / page_size_usize;

        let word = |page: usize, offset: usize| -> u16 {
            let at = page * page_size_usize + offset;
            u16::from_le_bytes([file[at], file[at + 1]])
        };
        let magic =
            |page: usize| -> bool { file[page * page_size_usize..][..2] == *MAGIC };

        // Single block only -- see the doc comment above. A scan, the same
        // shape `read` already trusts, rather than assuming physical 2/3 are
        // the only "PP" pages without checking.
        for page in 0..pages {
            if magic(page) && word(page, BLOCK) != 1 {
                return Err(format!(
                    "physical page {page} is allocation-table block {}, and \
                     claiming a page only handles a single-block file",
                    word(page, BLOCK)
                ));
            }
        }
        if pages < 4 || !(magic(2) || magic(3)) {
            return Err(
                "neither physical page 2 nor 3 carries the \"PP\" allocation-\
                 table magic -- there is no block 1 to claim a page in"
                    .to_owned(),
            );
        }

        let (stale, live) = match word(2, GENERATION).cmp(&word(3, GENERATION)) {
            std::cmp::Ordering::Greater => (3usize, 2usize),
            std::cmp::Ordering::Less => (2usize, 3usize),
            std::cmp::Ordering::Equal => {
                return Err(format!(
                    "both copies of block 1 claim generation {}, and there is \
                     no rule measured for choosing between them",
                    word(2, GENERATION)
                ));
            }
        };

        let entries_per_page = (page_size_usize - ENTRIES) / ENTRY;
        let entry_at = |page: usize, entry: usize| page * page_size_usize + ENTRIES + entry * ENTRY;

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
        let mut free_entry: Option<usize> = None;
        for entry in 0..entries_per_page {
            let at = entry_at(live, entry);
            let marker = u16::from_le_bytes([file[at], file[at + 1]]);
            if marker >> 8 == 0 {
                free_entry = free_entry.or(Some(entry));
                break;
            }
        }
        let Some(free_entry) = free_entry else {
            return Err(format!(
                "block 1's regular array already claims every one of its \
                 {entries_per_page} entries -- growing to a second block is \
                 not implemented"
            ));
        };
        let new_logical = free_entry as u32 + 1;
        let new_logical16 = u16::try_from(new_logical)
            .map_err(|_| format!("logical id {new_logical} does not fit in this format's u16"))?;

        // Read before any mutation below: `word` borrows `file` immutably,
        // and every write past this point needs it mutably.
        let new_generation = word(live, GENERATION).wrapping_add(1);

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
        file.extend_from_slice(&page);

        // Copy-on-write, the same shape the file control record's own shadow
        // pair already uses (Task 1): the stale copy becomes a full copy of
        // the live one, plus this one new entry, plus a higher generation --
        // never a partial edit of whichever copy happened to be live.
        let live_page = file[live * page_size_usize..][..page_size_usize].to_vec();
        let stale_at = stale * page_size_usize;
        file[stale_at..stale_at + page_size_usize].copy_from_slice(&live_page);

        let entry_at_new = stale_at + ENTRIES + free_entry * ENTRY;
        let marker = u16::from_le_bytes([tag[0], tag[1]]);
        file[entry_at_new..entry_at_new + 2].copy_from_slice(&marker.to_le_bytes());
        file[entry_at_new + 2..entry_at_new + 4].copy_from_slice(&new_physical16.to_le_bytes());

        file[stale_at + GENERATION..stale_at + GENERATION + 2]
            .copy_from_slice(&new_generation.to_le_bytes());

        Ok(new_logical)
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
        file: &mut Vec<u8>,
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
        if file.is_empty() || !file.len().is_multiple_of(page_size_usize) {
            return Err(format!(
                "{} bytes is not a whole number of {page_size}-byte pages",
                file.len()
            ));
        }
        let pages = file.len() / page_size_usize;

        let word = |page: usize, offset: usize| -> u16 {
            let at = page * page_size_usize + offset;
            u16::from_le_bytes([file[at], file[at + 1]])
        };
        let magic =
            |page: usize| -> bool { file[page * page_size_usize..][..2] == *MAGIC };

        for page in 0..pages {
            if magic(page) && word(page, BLOCK) != 1 {
                return Err(format!(
                    "physical page {page} is allocation-table block {}, and \
                     relocating a page only handles a single-block file",
                    word(page, BLOCK)
                ));
            }
        }
        if pages < 4 || !(magic(2) || magic(3)) {
            return Err(
                "neither physical page 2 nor 3 carries the \"PP\" allocation-\
                 table magic -- there is no block 1 to relocate a page in"
                    .to_owned(),
            );
        }

        let (stale, live) = match word(2, GENERATION).cmp(&word(3, GENERATION)) {
            std::cmp::Ordering::Greater => (3usize, 2usize),
            std::cmp::Ordering::Less => (2usize, 3usize),
            std::cmp::Ordering::Equal => {
                return Err(format!(
                    "both copies of block 1 claim generation {}, and there is \
                     no rule measured for choosing between them",
                    word(2, GENERATION)
                ));
            }
        };

        let entries_per_page = (page_size_usize - ENTRIES) / ENTRY;
        let entry_at = |page: usize, entry: usize| page * page_size_usize + ENTRIES + entry * ENTRY;
        let logical16 = u16::try_from(logical)
            .map_err(|_| format!("logical id {logical} does not fit in this format's u16"))?;

        // Where `logical` is claimed is not something to search for. The engine
        // derives the slot *from* the id -- slot `(logical - 1) % entries` of
        // block `(logical - 1) / entries + 1` (`:14276-14278`) -- and this
        // function handles only single-block files, so the slot is `logical - 1`
        // outright. The old search read each claimed page's own header looking
        // for a match, which is the inverted resolution `Self::read` no longer
        // performs either.
        if logical == 0 {
            return Err("logical ids are numbered from 1".to_owned());
        }
        let entry = (logical - 1) as usize;
        if entry >= entries_per_page {
            return Err(format!(
                "logical id {logical} belongs to allocation-table block \
                 {}, and relocating only handles a single-block file",
                entry / entries_per_page + 1
            ));
        }
        let at = entry_at(live, entry);
        let marker = u16::from_le_bytes([file[at], file[at + 1]]);
        if marker >> 8 == 0 {
            return Err(format!(
                "logical id {logical} is not claimed in block 1's live copy -- \
                 there is nothing to relocate"
            ));
        }

        // Read before any mutation: `word` borrows `file` immutably.
        let new_generation = word(live, GENERATION).wrapping_add(1);

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
        let claimed_physical = usize::from(u16::from_le_bytes([file[at + 2], file[at + 3]]));
        let mut claimed = vec![false; pages];
        for entry in 0..entries_per_page {
            let at = entry_at(live, entry);
            if u16::from_le_bytes([file[at], file[at + 1]]) >> 8 == 0 {
                continue;
            }
            let page = usize::from(u16::from_le_bytes([file[at + 2], file[at + 3]]));
            if page < pages {
                claimed[page] = true;
            }
        }
        let twin = (4..pages).find(|&page| {
            page != claimed_physical
                && !claimed[page]
                && !magic(page)
                && word(page, LOGICAL) == logical16
        });

        let new_physical16 = u16::try_from(twin.unwrap_or(pages))
            .map_err(|_| format!("physical page {pages} does not fit in this format's u16"))?;
        let mut page = content.to_vec();
        page[..2].copy_from_slice(&tag);
        page[LOGICAL..LOGICAL + 2].copy_from_slice(&logical16.to_le_bytes());
        match twin {
            Some(at) => {
                let at = at * page_size_usize;
                file[at..at + page_size_usize].copy_from_slice(&page);
            }
            None => file.extend_from_slice(&page),
        }

        // Copy-on-write into the stale copy, exactly `Self::claim`'s shape:
        // the live copy's own bytes, plus this one change, plus a higher
        // generation.
        let live_page = file[live * page_size_usize..][..page_size_usize].to_vec();
        let stale_at = stale * page_size_usize;
        file[stale_at..stale_at + page_size_usize].copy_from_slice(&live_page);

        let repoint = stale_at + ENTRIES + entry * ENTRY;
        file[repoint + 2..repoint + 4].copy_from_slice(&new_physical16.to_le_bytes());

        file[stale_at + GENERATION..stale_at + GENERATION + 2]
            .copy_from_slice(&new_generation.to_le_bytes());

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
    file: &mut Vec<u8>,
    page_size: u16,
    records: u32,
    key_record_counts: &[(usize, u32)],
    free_head: Option<u32>,
    variable_head: Option<Option<u32>>,
) -> Result<(), String> {
    let page_size_usize = usize::from(page_size);
    if file.len() < 2 * page_size_usize || !file.len().is_multiple_of(page_size_usize) {
        return Err(format!(
            "{} bytes does not hold two whole {page_size}-byte pages for the \
             file control record's shadow pair",
            file.len()
        ));
    }

    let word = |page: usize, offset: usize| -> u16 {
        let at = page * page_size_usize + offset;
        u16::from_le_bytes([file[at], file[at + 1]])
    };

    let (stale, live) = match word(0, GENERATION).cmp(&word(1, GENERATION)) {
        std::cmp::Ordering::Greater => (1usize, 0usize),
        std::cmp::Ordering::Less => (0usize, 1usize),
        std::cmp::Ordering::Equal => {
            return Err(format!(
                "both control-record copies claim generation {}, and there is \
                 no rule measured for choosing between them",
                word(0, GENERATION)
            ));
        }
    };
    let new_generation = word(live, GENERATION).wrapping_add(1);

    let live_page = file[live * page_size_usize..][..page_size_usize].to_vec();
    let stale_at = stale * page_size_usize;
    file[stale_at..stale_at + page_size_usize].copy_from_slice(&live_page);

    let records_at = stale_at + super::pages::fcr::RECORDS_HIGH;
    file[records_at..records_at + 4].copy_from_slice(&super::pages::to_long(records));

    // `None` leaves whatever the live copy had, which is right for every
    // caller that did not move a slot on or off the free list -- the whole
    // live page was copied over the stale one above, so "leave it alone"
    // costs nothing and says nothing.
    if let Some(free) = free_head {
        let free_at = stale_at + super::pages::fcr::FREE_V6;
        file[free_at..free_at + 4].copy_from_slice(&super::pages::to_long(free));
    }

    // The *variable* free-space chain's head, which is a different list from
    // the one above: that threads free record slots, this threads variable
    // pages with room left. Doubly optional on purpose -- the outer `None`
    // means "this caller did not touch the chain", and `Some(None)` means
    // "the chain is now empty", which are different instructions and would be
    // indistinguishable through one layer.
    if let Some(head) = variable_head {
        let at = stale_at + super::pages::fcr::VARIABLE_HEAD;
        let value = head.unwrap_or(super::pages::fcr::NO_VARIABLE_HEAD);
        file[at..at + 4].copy_from_slice(&super::pages::to_long(value));
    }

    for &(offset, count) in key_record_counts {
        let at = stale_at + offset;
        if at + 4 > stale_at + page_size_usize {
            return Err(format!(
                "a key-records offset of {offset} does not leave room for its \
                 four bytes in a {page_size}-byte page"
            ));
        }
        file[at..at + 4].copy_from_slice(&super::pages::to_long(count));
    }

    file[stale_at + GENERATION..stale_at + GENERATION + 2]
        .copy_from_slice(&new_generation.to_le_bytes());

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
        let to = Map::relocate(&mut file, PAGE as u16, 1, &content, [0x00, 0x44])
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

        let map = Map::read(&file, 512).expect("no collision exists to find");
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
        let map = Map::read(&file, 512).expect("the table names exactly one");
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
        let map = Map::read(&file, 512).expect("an unallocated slot is not an error");
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
        let map = Map::read(&file, 512).expect("resolves");
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
        let map = Map::read(&file, 512).expect("resolves");
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
        let map = Map::read(&file, 512).expect("resolves");
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
        let map = Map::read(&file, 512).expect("resolves");
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
        let map = Map::read(&file, 2048).expect("resolves");
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
        let map = Map::read(&file, 512).expect("resolves");
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

        let map = Map::read(&file, 512).expect("no contradiction exists here");
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

        let e = Map::read(&file, 512).unwrap_err();
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
        let file = vec![0u8; 14 * 4];
        for size in [ENTRIES + 1, ENTRIES + ENTRY - 1] {
            let e = Map::read(&file, size as u16).unwrap_err();
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

        let e = Map::read(&file, 512).unwrap_err();
        assert!(e.contains("block 7"), "{e}");
    }

    /// `Map::claim`, Task 13 Step 1 of the plan (allocation-table
    /// maintenance) -- see the function's own doc comment for scope. Not yet
    /// wired into `Block::insert` or the oracle: this is the mechanism in
    /// isolation, checked against this module's own reader.
    #[test]
    fn claim_adds_a_new_logical_page_and_disturbs_nothing_else() {
        let mut file = fixture("DUPKEY30.DAT");
        let before = Map::read(&file, 512).expect("resolves before");

        let mut content = vec![0u8; 512];
        content[6..10].copy_from_slice(b"NEW!");
        let logical = Map::claim(&mut file, 512, &content, [0x00, 0x44]).expect("claims");

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

        let after = Map::read(&file, 512).expect("resolves after");
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

        let first = Map::claim(&mut file, 512, &content, [0x00, 0x44]).expect("first claim");
        let gen_after_first = u16::from_le_bytes([
            file[2 * 512 + GENERATION],
            file[2 * 512 + GENERATION + 1],
        ])
        .max(u16::from_le_bytes([
            file[3 * 512 + GENERATION],
            file[3 * 512 + GENERATION + 1],
        ]));

        let second = Map::claim(&mut file, 512, &content, [0x00, 0x44]).expect("second claim");
        assert_eq!(second, first + 1);

        let map = Map::read(&file, 512).expect("resolves");
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
        let logical = Map::claim(&mut file, 512, &content, [0x00, 0x44]).expect("claims");

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

        let map = Map::read(&file, 512).expect("resolves");
        assert_eq!(
            map.physical(logical),
            None,
            "with the bump undone the new claim must not be visible -- the \
             bytes alone are not what makes it live"
        );
    }

    /// A multi-block file is refused outright rather than silently claiming
    /// into block 1 and leaving block 2 unrelated to the new page.
    #[test]
    fn claim_refuses_a_file_that_already_has_a_second_block() {
        let mut file = fixture("PP2BLOCK.DAT");
        let content = vec![0u8; 512];
        let e = Map::claim(&mut file, 512, &content, [0x00, 0x44]).unwrap_err();
        assert!(e.contains("single-block"), "{e}");
    }

    /// A block with no free entry left is refused rather than silently
    /// growing a second block -- Step 1's own stated scope boundary.
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
        let e = Map::claim(&mut file, page_size as u16, &content, [0x00, 0x44]).unwrap_err();
        assert!(e.contains("already claims every one of its"), "{e}");
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
        let logical = Map::claim(&mut file, 512, &content, [0x00, 0x44]).expect("claims");

        // Undo only the entry this claim wrote, leaving the new page's own
        // bytes -- header and content both -- exactly as `claim` left them.
        let physical = Map::read(&file, 512)
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

        let map = Map::read(&file, 512).expect("resolves");
        assert_eq!(
            map.physical(logical),
            None,
            "a page's own header content must not be enough on its own -- \
             only the allocation-table entry makes a claim real"
        );
    }
}
