//! Bytes to model.
//!
//! Total, or a refusal: this never returns a model with holes in it. A file
//! whose bytes are not yet fully described is refused with the reason, and the
//! round-trip pin does not count it.

use std::collections::{HashMap, HashSet};

use crate::format::acs;
use crate::format::alloc;
use crate::format::fcr;
use crate::format::fcr::key_descriptor;
use crate::format::free_slot;
use crate::format::generation::{identify, NotBtrieve};
use crate::format::index;
use crate::format::page;
use crate::format::variable;
use crate::model::{
    AcsBlock, Control, ControlRecord, DataPage, File, FragmentPage, FragmentSlot, IndexEntry,
    IndexPage, KeyDescriptor, Page, PageKind, RecordSlot, V6AllocationBlock, V6AllocationBlockCopy,
    V6AllocationEntry, V6ControlRecord, V6PageTail,
};

/// Read a plain little-endian `u16` at `at`.
fn get_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

/// Read a 4-byte "long": two little-endian halves, high half first -- the
/// read-side mirror of `Canvas::put_long`. See harvest 1's "Endianness
/// convention" section: reading one as a plain LE `u32` gives a plausible
/// wrong number with no error, which has cost this project three separate
/// defects.
fn get_long(bytes: &[u8], at: usize) -> u32 {
    let high = u16::from_le_bytes([bytes[at], bytes[at + 1]]);
    let low = u16::from_le_bytes([bytes[at + 2], bytes[at + 3]]);
    (u32::from(high) << 16) | u32::from(low)
}

fn get_array<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    bytes[at..at + N].try_into().expect("slice of the requested width")
}

/// Read a plain little-endian `u32` at `at` -- distinct from [`get_long`]:
/// this is for a field harvest 2 does *not* name among the "high word first"
/// family (`RECORDS`, `PAGES`, `FREE`, `FREE_V6`, `VARIABLE_HEAD`, `ROOT`),
/// where reading it the other way would be an unevidenced assumption rather
/// than a transcription.
fn get_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(get_array(bytes, at))
}

/// Read one control record's fixed portion (`0x00..0x110`) out of `bytes`,
/// which must be at least that long. `bytes` is expected to start at that
/// copy's own page: absolute page 0 for a v5 file (there is only one copy),
/// or the start of whichever physical page (0 or 1) is being read for a v6
/// file's shadow pair -- see [`resolve_shadow`].
fn control_record(bytes: &[u8]) -> ControlRecord {
    ControlRecord {
        page_gen: get_u16(bytes, fcr::at::PAGE_GEN),
        companion_selector: bytes[fcr::at::COMPANION_SELECTOR],
        lock_flag: bytes[fcr::at::LOCK_FLAG],
        unknown_0c: get_long(bytes, fcr::at::UNKNOWN_0C),
        free: get_long(bytes, fcr::at::FREE),
        keys: get_u16(bytes, fcr::at::KEYS),
        reclen: get_u16(bytes, fcr::at::RECLEN),
        physical: get_u16(bytes, fcr::at::PHYSICAL),
        records: get_long(bytes, fcr::at::RECORDS),
        highest: get_long(bytes, fcr::at::HIGHEST),
        data_page_count: get_long(bytes, fcr::at::DATA_PAGE_COUNT),
        pages: get_long(bytes, fcr::at::PAGES),
        page_usable: get_u16(bytes, fcr::at::PAGE_USABLE),
        lock_transaction: get_u16(bytes, fcr::at::LOCK_TRANSACTION),
        negative_version_a: get_long(bytes, fcr::at::NEGATIVE_VERSION_A),
        negative_version_b: get_long(bytes, fcr::at::NEGATIVE_VERSION_B),
        negative_version_c: bytes[fcr::at::NEGATIVE_VERSION_C],
        negative_version_d: bytes[fcr::at::NEGATIVE_VERSION_D],
        variable_tag: bytes[fcr::at::VARIABLE_TAG],
        variable_subflag: bytes[fcr::at::VARIABLE_SUBFLAG],
        variable_highest: get_u16(bytes, fcr::at::VARIABLE_HIGHEST),
        acs_name: get_array(bytes, fcr::at::ACS_NAME),
        reserved_44: get_array(bytes, fcr::at::RESERVED_44),
        write_counter_68: get_u16(bytes, fcr::at::WRITE_COUNTER_68),
        reserved_6a: get_array(bytes, fcr::at::RESERVED_6A),
        usrflgs: get_u16(bytes, fcr::at::USRFLGS),
        variable_page_capacity: bytes[fcr::at::VARIABLE_PAGE_CAPACITY],
        reserved_109: bytes[fcr::at::RESERVED_109],
        acs_page_pointer: get_long(bytes, fcr::at::ACS_PAGE_POINTER),
        reserved_10e: get_array(bytes, fcr::at::RESERVED_10E),
    }
}

/// Read one v6 control record's fixed portion (`0x00..0x110`) out of
/// `bytes`, which must be at least that long. `bytes` starts at that copy's
/// own physical page (0 or 1) -- see [`resolve_shadow`]. Task 15's
/// transcription of harvest 2's field table (`format::fcr::v6_fixed`); every
/// offset here is `fcr::v6::*`, not `fcr::at::*` -- the two families'
/// fixed-portion layouts genuinely diverge past `0x20` (see
/// `model::V6ControlRecord`'s own doc comment), so this is not
/// [`control_record`] with different constants plugged in, it is a
/// different structure.
fn v6_control_record(bytes: &[u8]) -> V6ControlRecord {
    V6ControlRecord {
        generation: get_u16(bytes, fcr::v6::GENERATION),
        reserved_06: get_array(bytes, fcr::v6::RESERVED_06),
        reserved_0a: get_array(bytes, fcr::v6::RESERVED_0A),
        reserved_0c: get_u32(bytes, fcr::v6::RESERVED_0C),
        free: get_long(bytes, fcr::v6::FREE),
        keys: get_u16(bytes, fcr::v6::KEYS),
        reclen: get_u16(bytes, fcr::v6::RECLEN),
        physical: get_u16(bytes, fcr::v6::PHYSICAL),
        records: get_long(bytes, fcr::v6::RECORDS),
        highest: get_u16(bytes, fcr::v6::HIGHEST),
        reserved_20: get_u16(bytes, fcr::v6::RESERVED_20),
        sentinel_22: get_u16(bytes, fcr::v6::SENTINEL_22),
        sentinel_24: get_u16(bytes, fcr::v6::SENTINEL_24),
        pages: get_long(bytes, fcr::v6::PAGES),
        reserved_2a: get_u16(bytes, fcr::v6::RESERVED_2A),
        reserved_2c: get_array(bytes, fcr::v6::RESERVED_2C),
        variable_mark: get_u32(bytes, fcr::v6::VARIABLE_MARK),
        acs_name: get_array(bytes, fcr::v6::ACS_NAME),
        reserved_44: get_array(bytes, fcr::v6::RESERVED_44),
        usage_4c: get_u16(bytes, fcr::v6::USAGE_4C),
        index_alloc_4e: get_u16(bytes, fcr::v6::INDEX_ALLOC_4E),
        mirror_50: get_u16(bytes, fcr::v6::MIRROR_50),
        usage_52: get_u16(bytes, fcr::v6::USAGE_52),
        reserved_54: get_u16(bytes, fcr::v6::RESERVED_54),
        stamp_56: get_array(bytes, fcr::v6::STAMP_56),
        reserved_5a: get_array(bytes, fcr::v6::RESERVED_5A),
        reserved_60: get_array(bytes, fcr::v6::RESERVED_60),
        write_counter: get_u16(bytes, fcr::v6::WRITE_COUNTER),
        reserved_6a: get_array(bytes, fcr::v6::RESERVED_6A),
        reserved_72: get_array(bytes, fcr::v6::RESERVED_72),
        reserved_7c: get_array(bytes, fcr::v6::RESERVED_7C),
        reserved_90: get_array(bytes, fcr::v6::RESERVED_90),
        free_v6: get_long(bytes, fcr::v6::FREE_V6),
        variable_head: get_long(bytes, fcr::v6::VARIABLE_HEAD),
        reserved_a4: get_array(bytes, fcr::v6::RESERVED_A4),
        reserved_d4: get_array(bytes, fcr::v6::RESERVED_D4),
        reserved_100: get_array(bytes, fcr::v6::RESERVED_100),
        reserved_106: get_array(bytes, fcr::v6::RESERVED_106),
        acs_page: get_long(bytes, fcr::v6::ACS_PAGE),
        reserved_10e: get_array(bytes, fcr::v6::RESERVED_10E),
    }
}

/// Resolve a v6 file's shadowed control record -- Ruling 7 (harvest 0
/// ruling 7; harvest 2 "FCR shadowing"): physical pages 0 and 1 are each a
/// complete `page_size`-byte control record, and the `u16` generation
/// counter at page-relative `0x04` (`V6ControlRecord::generation`) says
/// which one is live -- higher wins. This is the *first* thing this crate
/// does with a v6 file's bytes, before any other field of either copy is
/// treated as meaningful: reading physical page 0 unconditionally (the bug
/// this ruling exists to close) is silently wrong on 157 of 507 corpus
/// files, because it is not corrupt, just stale, and parses perfectly
/// either way.
///
/// `bytes` must already be at least `2 * page_size` long -- the caller
/// checks this before calling, so the two slices below never panic.
///
/// # Errors
///
/// If both copies carry the same generation counter. No corpus file has
/// ever tied (0 of 507), so this rejects a shape never observed rather than
/// one observed and merely inconvenient.
fn resolve_shadow(bytes: &[u8], page_size: usize) -> Result<Control, NotBtrieve> {
    let page0 = v6_control_record(&bytes[0..page_size]);
    let page1 = v6_control_record(&bytes[page_size..2 * page_size]);

    match page0.generation.cmp(&page1.generation) {
        std::cmp::Ordering::Greater => {
            Ok(Control::Shadowed { live: page0, stale: page1, live_is_page: 0 })
        }
        std::cmp::Ordering::Less => {
            Ok(Control::Shadowed { live: page1, stale: page0, live_is_page: 1 })
        }
        std::cmp::Ordering::Equal => Err(NotBtrieve {
            why: format!(
                "physical pages 0 and 1 both carry generation {} at \
                 page-relative 0x04 -- a tie between the two control-record \
                 shadow copies has no answer, and no corpus file has ever \
                 produced one, so this is refused rather than resolved \
                 (harvest 0 ruling 7)",
                page0.generation
            ),
        }),
    }
}

/// Walk the key/segment definition array starting at `fcr::at::FIXED_LEN`,
/// consuming definitions until `keys` keys have been assembled -- each
/// `ANOSEG`-terminated run of definitions counts as one key, so a segmented
/// key consumes more than one definition before the count advances. See
/// harvest 4 SS1/SS3 and `format::fcr::key_descriptor`'s module doc for why
/// the count cannot be `keys` itself.
///
/// `start_definition` (the index the currently-open key's chain began at) is
/// tracked purely so a refusal can name it: a chain that never terminates or
/// runs past the page is reported in terms of the `key_descriptor[n]` that
/// opened it, not just the one where the walk gave up.
///
/// # Errors
///
/// If a definition would run past the `page_size`-byte control record, or an
/// `ANOSEG` chain has not terminated after `key_descriptor::SEGMAX`
/// definitions -- more segments in one key than the format allows
/// (`BTVSTF.H:13`).
fn key_descriptors(
    bytes: &[u8],
    page_size: usize,
    keys: u16,
) -> Result<Vec<KeyDescriptor>, NotBtrieve> {
    let mut out = Vec::new();
    let mut assembled = 0usize;
    let mut n = 0usize;
    let mut start_definition = 0usize;
    let mut new_key = true;

    while assembled < usize::from(keys) {
        if new_key {
            // Starting a fresh key's chain at this definition.
            start_definition = n;
            new_key = false;
        }

        if n >= key_descriptor::SEGMAX {
            return Err(NotBtrieve {
                why: format!(
                    "key_descriptor[{start_definition}] opens a segment chain \
                     (ANOSEG) that has not terminated after \
                     {} definitions -- {assembled} of {keys} keys assembled, \
                     more segments in one key than the format allows \
                     (BTVSTF.H:13, SEGMAX={})",
                    key_descriptor::SEGMAX,
                    key_descriptor::SEGMAX
                ),
            });
        }

        let start = key_descriptor::base(n);
        let end = start + key_descriptor::WIDTH;
        if end > page_size {
            return Err(NotBtrieve {
                why: format!(
                    "key_descriptor[{n}] (continuing key_descriptor[{start_definition}]) \
                     would occupy {start:#x}..{end:#x}, past the {page_size}-byte \
                     control record -- the key/segment definition array is malformed"
                ),
            });
        }

        let d = &bytes[start..end];
        let root_long = get_long(d, key_descriptor::at::ROOT);
        let attributes = get_u16(d, key_descriptor::at::ATTRIBUTES);
        out.push(KeyDescriptor {
            key_number: (root_long >> 24) as u8,
            root_page: root_long & 0x00ff_ffff,
            records: get_long(d, key_descriptor::at::RECORDS),
            attributes,
            key_length: get_u16(d, key_descriptor::at::KEY_LENGTH),
            entry_size: get_u16(d, key_descriptor::at::ENTRY_SIZE),
            max_entries: get_u16(d, key_descriptor::at::MAX_ENTRIES),
            half_entries: get_u16(d, key_descriptor::at::HALF_ENTRIES),
            chain: get_u16(d, key_descriptor::at::CHAIN),
            offset: get_u16(d, key_descriptor::at::OFFSET),
            length: get_u16(d, key_descriptor::at::LENGTH),
            self_tag: d[key_descriptor::at::SELF_TAG],
            acs_page_high: d[key_descriptor::at::ACS_PAGE_HIGH],
            acs_page_low: d[key_descriptor::at::ACS_PAGE_LOW],
            acs_page_mid: d[key_descriptor::at::ACS_PAGE_MID],
            extended: d[key_descriptor::at::EXTENDED],
            null_value: d[key_descriptor::at::NULL_VALUE],
        });
        n += 1;
        if attributes & key_descriptor::ANOSEG == 0 {
            assembled += 1;
            new_key = true;
        }
    }
    Ok(out)
}

/// Read and validate a v6 physical page's definition-offset trailer (Task
/// 16), plus the padding on either side of it -- `descriptors` is that same
/// page's own key/segment definition array, already walked by
/// [`key_descriptors`].
///
/// `bytes` starts at the physical page itself (offset `0` is this page's own
/// `LEAD`), the same convention [`v6_control_record`] and [`key_descriptors`]
/// use.
///
/// # Errors
///
/// If `descriptors` run past `format::fcr::trailer::position(page_size)`
/// (never observed -- max 4 definitions in the corpus, every measured
/// trailer position leaves room for far more), or any trailer slot's value
/// disagrees with `format::fcr::trailer::expected_entries` -- a disagreement
/// this crate's own census found in 0 of 493 corpus files.
fn v6_page_tail(
    bytes: &[u8],
    page_size: usize,
    descriptors: &[KeyDescriptor],
) -> Result<V6PageTail, NotBtrieve> {
    let after_definitions = key_descriptor::base(descriptors.len());

    let Some(trailer_pos) = fcr::trailer::position(page_size as u16) else {
        // No trailer at this page size (512, or one this corpus has never
        // used) -- everything past the definitions is a plain tail, the
        // same shape page_zero_tail describes for v5, carried verbatim.
        let gap = if page_size > after_definitions {
            bytes[after_definitions..page_size].to_vec()
        } else {
            Vec::new()
        };
        return Ok(V6PageTail { gap, padding: Vec::new() });
    };

    if after_definitions > trailer_pos {
        return Err(NotBtrieve {
            why: format!(
                "{} key/segment definitions run to byte {after_definitions:#x}, \
                 past the definition-offset trailer's own fixed position \
                 {trailer_pos:#x} for a {page_size}-byte page -- more \
                 definitions than this file's trailer has room for, never \
                 observed in the corpus (max 4)",
                descriptors.len()
            ),
        });
    }
    let gap = bytes[after_definitions..trailer_pos].to_vec();

    // The compacted rule (`format::fcr::trailer::expected_entries`'s own
    // doc): a slot's expected value is NOT a function of its own index, so
    // this compares the whole array at once rather than one definition's
    // SELF_TAG against one slot.
    let self_tags: Vec<u8> = descriptors.iter().map(|d| d.self_tag).collect();
    let expected = fcr::trailer::expected_entries(&self_tags);
    for (n, exp) in expected.iter().enumerate() {
        let at = trailer_pos + n * 2;
        let actual = get_u16(bytes, at);
        if actual != *exp {
            return Err(NotBtrieve {
                why: format!(
                    "definition-offset trailer slot {n} at byte {at:#x} reads \
                     {actual:#06x}, but this crate's own compacted \
                     derivation (harvest 2 'Definition-offset trailer, \
                     worked', corrected by this task's census of 493 \
                     corpus files: each independent segment's own offset \
                     packed into the next free slot, in definition order, \
                     zero-padded thereafter -- not one slot per definition \
                     index) expects {exp:#06x} here given SELF_TAGs {:?}",
                    self_tags
                ),
            });
        }
    }

    let after_trailer = trailer_pos + descriptors.len() * 2;
    let padding = if page_size > after_trailer {
        bytes[after_trailer..page_size].to_vec()
    } else {
        Vec::new()
    };

    Ok(V6PageTail { gap, padding })
}

/// Read one allocation-table page's content, whole -- caller has already
/// checked the `"PP"` magic; `bytes` starts at that copy's own physical
/// page.
fn v6_allocation_copy(bytes: &[u8], page_size: usize) -> V6AllocationBlockCopy {
    let entries = alloc::entries_per_block(page_size);
    let mut out = Vec::with_capacity(entries);
    for n in 0..entries {
        let at = alloc::at::ENTRIES + n * alloc::ENTRY_WIDTH;
        out.push(V6AllocationEntry {
            marker: get_u16(bytes, at),
            physical_page: get_u16(bytes, at + 2),
        });
    }
    V6AllocationBlockCopy {
        block: get_u16(bytes, alloc::at::BLOCK),
        generation: get_u16(bytes, alloc::at::GENERATION),
        reserved_06: get_array(bytes, alloc::at::RESERVED_06),
        entries: out,
    }
}

/// Resolve one allocation-table block's shadow pair -- the identical rule
/// [`resolve_shadow`] already enforces for the file control record's own
/// pair (harvest 3 "Generation counters and shadow-copy resolution"): a
/// `u16` generation at page-relative `0x04`, higher wins, a tie is refused
/// rather than guessed.
///
/// `first` and `second` are physical page numbers, already computed by
/// [`alloc::pair_position`] -- this function only resolves what is *at*
/// them, it does not compute where they are.
///
/// # Errors
///
/// If either physical page does not carry the `"PP"` magic, if either
/// claims a different block index than `block_index` names, or if the two
/// generations tie.
fn resolve_allocation_block(
    bytes: &[u8],
    page_size: usize,
    block_index: u16,
    first: usize,
    second: usize,
) -> Result<V6AllocationBlock, NotBtrieve> {
    let page_bytes = |page: usize| &bytes[page * page_size..(page + 1) * page_size];

    for &page in &[first, second] {
        if &page_bytes(page)[0..2] != alloc::MAGIC {
            return Err(NotBtrieve {
                why: format!(
                    "allocation-table block {block_index}'s shadow pair is \
                     physical pages {first} and {second} (harvest 3's own \
                     formula), but physical page {page} does not carry the \
                     \"PP\" magic"
                ),
            });
        }
    }

    let first_copy = v6_allocation_copy(page_bytes(first), page_size);
    let second_copy = v6_allocation_copy(page_bytes(second), page_size);

    for (page, copy) in [(first, &first_copy), (second, &second_copy)] {
        if copy.block != block_index {
            return Err(NotBtrieve {
                why: format!(
                    "physical page {page} is where allocation-table block \
                     {block_index} lives (harvest 3's own formula), but it \
                     calls itself block {}",
                    copy.block
                ),
            });
        }
    }

    match first_copy.generation.cmp(&second_copy.generation) {
        std::cmp::Ordering::Greater => {
            Ok(V6AllocationBlock { live: first_copy, stale: second_copy, live_is_first: true })
        }
        std::cmp::Ordering::Less => {
            Ok(V6AllocationBlock { live: second_copy, stale: first_copy, live_is_first: false })
        }
        std::cmp::Ordering::Equal => Err(NotBtrieve {
            why: format!(
                "allocation-table block {block_index}'s shadow pair \
                 (physical {first}/{second}) both carry generation \
                 {} at page-relative 0x04 -- a tie between the two shadow \
                 copies has no answer, and no corpus file has ever \
                 produced one (harvest 3 'Generation counters and \
                 shadow-copy resolution'), so this is refused rather than \
                 resolved",
                first_copy.generation
            ),
        }),
    }
}

/// Walk every allocation-table block a v6 file has, resolving each block's
/// shadow pair and building the logical-to-physical map every later v6
/// structure needs.
///
/// Blocks are found by formula, never by scanning for the `"PP"` magic --
/// see `format::alloc`'s own module doc for why a scan is actively wrong
/// (real files carry abandoned pages that still carry the magic, a stale
/// block index and a higher generation than the live table, at positions
/// no block ever lives at). The walk stops at the first formula position
/// where *neither* physical page carries the magic -- the same stopping
/// rule the engine's own block-by-number lookup implies, since it never
/// looks past the blocks a file actually has.
///
/// # Errors
///
/// If any block's shadow pair fails to resolve (see
/// [`resolve_allocation_block`]), or if a live entry claims physical page 0
/// or 1 (the file control record's own shadow pair, which cannot hold a
/// logical page) or a physical page past the file's own `total_pages`.
fn v6_allocation_table(
    bytes: &[u8],
    page_size: usize,
    total_pages: usize,
) -> Result<(Vec<V6AllocationBlock>, HashMap<u32, u32>), NotBtrieve> {
    let mut blocks = Vec::new();
    let mut physical: HashMap<u32, u32> = HashMap::new();
    let entries_per_block = alloc::entries_per_block(page_size);

    let mut index: usize = 1;
    loop {
        let (first, second) = alloc::pair_position(page_size, index);
        if second >= total_pages {
            break;
        }
        let magic = |page: usize| bytes[page * page_size..page * page_size + 2] == *alloc::MAGIC;
        if !magic(first) && !magic(second) {
            break;
        }

        let block_index = u16::try_from(index).map_err(|_| NotBtrieve {
            why: format!(
                "allocation-table block index {index} does not fit in the \
                 format's own 16-bit block-index field -- no corpus file \
                 has ever had more than 14 blocks"
            ),
        })?;
        let block = resolve_allocation_block(bytes, page_size, block_index, first, second)?;

        let base = u32::from(block_index - 1) * entries_per_block as u32;
        for (slot, entry) in block.live.entries.iter().enumerate() {
            // The engine's own "was this ever allocated" test is the
            // entry's marker high byte -- 0 means this slot has never been
            // claimed, and there is nothing to resolve.
            if entry.marker >> 8 == 0 {
                continue;
            }
            let logical = base + slot as u32 + 1;
            let claimed = u32::from(entry.physical_page);
            if claimed <= 1 {
                return Err(NotBtrieve {
                    why: format!(
                        "allocation-table block {block_index} resolves \
                         logical page {logical} to physical page {claimed}, \
                         which is the file control record's own shadow pair \
                         and cannot hold a logical page"
                    ),
                });
            }
            if claimed as usize >= total_pages {
                return Err(NotBtrieve {
                    why: format!(
                        "allocation-table block {block_index} resolves \
                         logical page {logical} to physical page {claimed}, \
                         past this file's own {total_pages} physical pages"
                    ),
                });
            }
            physical.insert(logical, claimed);
        }

        blocks.push(block);
        index += 1;
    }

    Ok((blocks, physical))
}

/// Read a fixed-length-record data page's content: every slot in order,
/// then whatever is left between the last slot and the end of the page.
///
/// `physical` must be nonzero -- the caller only calls this when it is (see
/// `resolve_pages`'s guard). `free_slots` is the set `resolve_pages`'s own
/// free-chain walk built: every freed slot's absolute file position
/// (harvest 5 SS2.1) -- a slot whose start appears there is
/// [`RecordSlot::Free`], its own forwarding link decoded independently here
/// (`format::free_slot::decode_link`) rather than reused from the walk;
/// every other slot is [`RecordSlot::Live`], unchanged from before this
/// task.
///
/// # Slack is measured, not assumed
///
/// Every v5 corpus file this crate can currently read (143 files) was walked
/// this way for this task: 42,571 data/free pages whose geometry leaves a
/// nonzero-length trailing region. 42,566 of those are all zero. The
/// remaining 5 -- 2 pages apiece in `archive/modules/majormud-nt/wccnt7pz/`
/// `out/wccitem2.vir` (byte-identical to `wccITEM2.nu1` in the same
/// directory) and 1 in `wccnt7py/out/wccupda2.dat` -- carry genuine leftover
/// bytes: readable item-description text past the last live slot, matching
/// no live record. This is why `slack` is stored verbatim rather than
/// asserted zero -- the general case is zero, but it is not a rule the
/// format enforces, and 5 real pages disagree with it.
///
/// # Errors
///
/// If the free chain names a slot on this page whose `physical` width is
/// too short to hold the 4-byte forwarding link a free slot must carry
/// (`format::free_slot::at::LINK_LEN`) -- harvest 5 SS2.1 does not describe
/// what a free list even means for a record that short, so this crate
/// refuses rather than guessing.
fn read_data_page(
    bytes: &[u8],
    page_start: usize,
    page_size: usize,
    physical: usize,
    free_slots: &HashSet<u32>,
) -> Result<DataPage, NotBtrieve> {
    let per_page = (page_size - page::LEN) / physical;
    let mut slots = Vec::with_capacity(per_page);
    for i in 0..per_page {
        let start = page_start + page::LEN + i * physical;
        let slot = if free_slots.contains(&(start as u32)) {
            if physical < free_slot::at::LINK_LEN {
                return Err(NotBtrieve {
                    why: format!(
                        "page {page_start:#x}: the free chain names slot {i} \
                         (position {start:#x}), but this file's \
                         {physical}-byte physical record is too short to \
                         hold the 4-byte forwarding link a free slot must \
                         carry"
                    ),
                });
            }
            let link: [u8; free_slot::at::LINK_LEN] =
                bytes[start..start + free_slot::at::LINK_LEN].try_into().expect("4 bytes");
            RecordSlot::Free {
                next: free_slot::decode_link(link),
                fill: bytes[start + free_slot::at::LINK_LEN..start + physical].to_vec(),
            }
        } else {
            RecordSlot::Live(bytes[start..start + physical].to_vec())
        };
        slots.push(slot);
    }
    let used = page::LEN + per_page * physical;
    Ok(DataPage { slots, slack: bytes[page_start + used..page_start + page_size].to_vec() })
}

/// Read an index page's content (harvest 4 SS4): the entry count and the
/// two boundary pointers, then every entry -- key, `head`, the
/// duplicate-only `tail`, and the possibly-omitted `child` -- and finally
/// whatever bytes remain to the end of the page.
///
/// `key_length` and `attributes` are the owning key descriptor's own
/// values -- they cannot be recovered from the page itself, which is why
/// they are parameters. `entry_size` is cross-checked against
/// `key_length`/`attributes` rather than trusted alone: harvest 4 SS4 says
/// it is `key_length + 8`, or `+12` when [`key_descriptor::DUPLICATES`] is
/// set, and a descriptor whose stored `entry_size` agrees with neither is a
/// genuine contradiction between two independently-stored fields, refused
/// by name rather than silently guessed at.
///
/// # The last entry's `child` field: written as a literal zero, or omitted
///
/// Every entry's `child` is read **verbatim**, never derived from "this is
/// a leaf so it must be NOWHERE" -- the last entry of a page reads literal
/// zero there (a placeholder, not a pointer to page 0), which this function
/// stores exactly as found. When the page has no room left at all for
/// those trailing 4 bytes (`WCCSPELS.VIR` page 1: fifty 10-byte entries in
/// a 512-byte page, four bytes more than fits), `child` is `None` and zero
/// bytes are consumed for it -- distinct from a *present* value of zero.
///
/// # Errors
///
/// If `entry_size` matches neither the unique- nor duplicate-key formula,
/// if any entry (even without its possibly-omitted `child` field) would
/// run past the page, or if a **non-last** entry would run past the page
/// only counting its trailing `child` field -- omission is a rule for the
/// last entry alone (harvest 4 SS4); a non-last entry that does not fully
/// fit is a malformed file, refused by name rather than read past this
/// page's own bounds.
fn read_index_page(
    bytes: &[u8],
    page_start: usize,
    page_size: usize,
    key_length: usize,
    entry_size: usize,
    attributes: u16,
) -> Result<IndexPage, NotBtrieve> {
    let duplicates = attributes & key_descriptor::DUPLICATES != 0;
    let expected = index::entry_width(key_length, duplicates);
    if entry_size != expected {
        return Err(NotBtrieve {
            why: format!(
                "page {page_start:#x}: entry_size {entry_size} disagrees \
                 with key_length {key_length} and duplicates={duplicates} \
                 -- harvest 4 SS4 says this should be {expected}"
            ),
        });
    }

    let count = usize::from(get_u16(bytes, page_start + index::at::COUNT));
    let rightmost = get_long(bytes, page_start + index::at::RIGHTMOST);
    let leftmost = get_long(bytes, page_start + index::at::LEFTMOST);

    let page_end = page_start + page_size;
    let mut entries = Vec::with_capacity(count);
    let mut offset = page_start + index::at::ENTRIES;
    for n in 0..count {
        let is_last = n + 1 == count;
        let without_child = entry_size - 4;
        if offset + without_child > page_end {
            return Err(NotBtrieve {
                why: format!(
                    "page {page_start:#x}: entry {n} of {count} (width \
                     {entry_size}) would run past the {page_size}-byte page \
                     even without its trailing child field"
                ),
            });
        }
        let full_end = offset + entry_size;
        // Only the LAST entry of a page may omit its trailing 4-byte
        // child field (harvest 4 SS4, WCCSPELS.VIR). A non-last entry
        // that does not fully fit is a malformed file -- refused by name
        // here, before any read would run past this page's own bounds
        // (and, for the last page of the file, past the buffer itself).
        if !is_last && full_end > page_end {
            return Err(NotBtrieve {
                why: format!(
                    "page {page_start:#x}: entry {n} of {count} (width \
                     {entry_size}) would run past the {page_size}-byte page, \
                     and only the last entry of a page may omit its \
                     trailing child field (harvest 4 SS4)"
                ),
            });
        }
        let key = bytes[offset..offset + key_length].to_vec();
        let mut at = offset + key_length;
        let head = get_long(bytes, at);
        at += 4;
        let tail = if duplicates {
            let t = get_long(bytes, at);
            at += 4;
            Some(t)
        } else {
            None
        };
        let (child, consumed) = if is_last && full_end > page_end {
            (None, at)
        } else {
            (Some(get_long(bytes, at)), full_end)
        };
        entries.push(IndexEntry { key, head, tail, child });
        offset = consumed;
    }

    let padding = bytes[offset..page_end].to_vec();
    Ok(IndexPage { rightmost, leftmost, entries, padding })
}

/// Read an ACS page's content (harvest 4 SS6): the tag byte, the 8-byte
/// name, and the 256-byte table, then whatever bytes remain to the end of
/// the page -- like `read_data_page`'s `slack` and `read_index_page`'s
/// `padding`, captured verbatim rather than assumed zero.
///
/// # Errors
///
/// If the page is too short to hold the 265-byte block at all, or the tag
/// byte is neither `0xac` nor `0xad` (`acs::TAGS`) -- the engine's own
/// predicate for "this is really an ACS block," refused by name rather than
/// decoded past a byte that fails it.
fn read_acs_block(bytes: &[u8], page_start: usize, page_size: usize) -> Result<AcsBlock, NotBtrieve> {
    let page_end = page_start + page_size;
    if page_start + acs::at::TABLE + acs::at::TABLE_LEN > page_end {
        return Err(NotBtrieve {
            why: format!(
                "page {page_start:#x}: a {page_size}-byte page cannot hold \
                 the {}-byte ACS block (harvest 4 SS6)",
                acs::LEN
            ),
        });
    }

    let tag = bytes[page_start + acs::at::TAG];
    if !acs::TAGS.contains(&tag) {
        return Err(NotBtrieve {
            why: format!(
                "page {page_start:#x}: ACS tag byte is {tag:#04x}, but the \
                 engine only accepts 0xac or 0xad (harvest 4 SS6)"
            ),
        });
    }

    let name = get_array(bytes, page_start + acs::at::NAME);
    let table = get_array(bytes, page_start + acs::at::TABLE);
    let padding = bytes[page_start + acs::at::TABLE + acs::at::TABLE_LEN..page_end].to_vec();
    Ok(AcsBlock { tag, name, table, padding })
}

/// Whether `page_start`'s own bytes match harvest 5 SS3.3's fragment-page
/// shape: fragment count (`0x0a`) in `1..=256`, and the first live
/// (non-`0xffff`) entry of the array names offset exactly `0x0c` -- the same
/// two checks `W32MKDE_decompiled.c:19029-19060` performs before treating a
/// page as this shape at all. Used only as evidence for classifying an
/// unclaimed, data-bit-clear page of a variable-length file; see
/// `PageKind::Variable`'s own doc for the corpus measurement backing this as
/// a real discriminator rather than a guess.
fn looks_like_fragment_page(bytes: &[u8], page_start: usize, page_size: usize) -> bool {
    if page_start + variable::at::FRAGMENTS > bytes.len() {
        return false;
    }
    let fragment_count = get_u16(bytes, page_start + variable::at::FRAGMENT_COUNT);
    if fragment_count == 0 || fragment_count > variable::MAX_FRAGMENTS {
        return false;
    }
    for i in 0..=usize::from(fragment_count) {
        let Some(rel) = variable::entry_at(page_size, i) else { return false };
        if page_start + rel + 2 > bytes.len() {
            return false;
        }
        let entry = get_u16(bytes, page_start + rel);
        if entry != variable::UNUSED_ENTRY {
            return usize::from(entry & variable::OFFSET_MASK) == variable::at::FRAGMENTS;
        }
    }
    false
}

/// Read a variable-length file's fragment/overflow page (harvest 5 SS3.3):
/// the write-side free-chain link, every fragment slot the page's own header
/// says it holds, the entry array's one extra boundary member, and whatever
/// bytes remain between the last live fragment's tiling and the entry array
/// itself.
///
/// Only called once `looks_like_fragment_page` has already confirmed the
/// page's shape, so the two checks it performs are re-derived here rather
/// than re-verified -- but every fragment's own tiling is still checked as
/// it is walked: harvest 5 SS3.3's "length is derived, never stored" means a
/// fragment's declared start must agree with where the fragments before it
/// actually end, and a file that disagrees is refused rather than read past
/// its own bounds.
///
/// # Errors
///
/// If a fragment's start offset disagrees with where the previous live
/// fragment's tiling says free space begins, a fragment has no live entry
/// after it to end it, a continued fragment is too short to hold its
/// 4-byte pointer, or the boundary entry's own offset disagrees with the
/// tiling of the fragments before it.
fn read_fragment_page(
    bytes: &[u8],
    page_start: usize,
    page_size: usize,
) -> Result<FragmentPage, NotBtrieve> {
    let free_chain = get_long(bytes, page_start + variable::at::FREE_CHAIN);
    let fragment_count = usize::from(get_u16(bytes, page_start + variable::at::FRAGMENT_COUNT));

    // Every fragment_count + 1 raw entries, verbatim, read once up front --
    // harvest 5 SS3.3: the array is one longer than the fragment count, the
    // extra (index `fragment_count`) member marking only where free space
    // starts.
    let mut raw_entries = Vec::with_capacity(fragment_count + 1);
    for i in 0..=fragment_count {
        let rel = variable::entry_at(page_size, i).ok_or_else(|| NotBtrieve {
            why: format!(
                "page {page_start:#x}: entry {i} of {fragment_count} fragments \
                 would start before byte 0 of a {page_size}-byte page"
            ),
        })?;
        raw_entries.push(get_u16(bytes, page_start + rel));
    }

    let mut fragments = Vec::with_capacity(fragment_count);
    let mut cursor = variable::at::FRAGMENTS;
    for i in 0..fragment_count {
        let entry = raw_entries[i];
        if entry == variable::UNUSED_ENTRY {
            fragments.push(FragmentSlot::Freed);
            continue;
        }
        let start = usize::from(entry & variable::OFFSET_MASK);
        let continued = entry & variable::CONTINUED_BIT != 0;
        if start != cursor {
            return Err(NotBtrieve {
                why: format!(
                    "page {page_start:#x}: fragment {i} names start offset \
                     {start}, but the fragments before it tile up to {cursor} \
                     -- harvest 5 SS3.3's fragments must tile with no gaps"
                ),
            });
        }

        let end = raw_entries[i + 1..=fragment_count]
            .iter()
            .find(|&&next| next != variable::UNUSED_ENTRY)
            .map(|&next| usize::from(next & variable::OFFSET_MASK));
        let Some(end) = end else {
            return Err(NotBtrieve {
                why: format!(
                    "page {page_start:#x}: fragment {i} of {fragment_count} has \
                     no live entry after it to end it"
                ),
            });
        };
        let Some(length) = end.checked_sub(start) else {
            return Err(NotBtrieve {
                why: format!(
                    "page {page_start:#x}: fragment {i} starts at {start}, past \
                     where the entry after it says free space begins ({end})"
                ),
            });
        };
        if page_start + end > page_start + page_size {
            return Err(NotBtrieve {
                why: format!(
                    "page {page_start:#x}: fragment {i} ends at {end}, past the \
                     {page_size}-byte page"
                ),
            });
        }
        let abs_start = page_start + start;

        let slot = if continued {
            if length < variable::POINTER_LEN {
                return Err(NotBtrieve {
                    why: format!(
                        "page {page_start:#x}: fragment {i} says it continues \
                         and is {length} bytes, too short for a \
                         {}-byte pointer",
                        variable::POINTER_LEN
                    ),
                });
            }
            let ptr_bytes: [u8; variable::POINTER_LEN] =
                get_array(bytes, abs_start);
            let next = variable::Pointer::decode(ptr_bytes);
            let body = bytes[abs_start + variable::POINTER_LEN..abs_start + length].to_vec();
            FragmentSlot::Live { next: Some(next), body }
        } else {
            let body = bytes[abs_start..abs_start + length].to_vec();
            FragmentSlot::Live { next: None, body }
        };
        fragments.push(slot);
        cursor = end;
    }

    // The boundary entry (index `fragment_count`): no fragment of its own,
    // but its offset must agree with where the live fragments before it
    // say free space actually starts.
    let free_space_entry = raw_entries[fragment_count];
    if free_space_entry != variable::UNUSED_ENTRY {
        let free_space_start = usize::from(free_space_entry & variable::OFFSET_MASK);
        if free_space_start != cursor {
            return Err(NotBtrieve {
                why: format!(
                    "page {page_start:#x}: the entry array's boundary member \
                     names free space starting at {free_space_start}, but the \
                     live fragments before it tile up to {cursor}"
                ),
            });
        }
    }
    let entry_array_start = variable::entry_at(page_size, fragment_count).ok_or_else(|| {
        NotBtrieve {
            why: format!(
                "page {page_start:#x}: the entry array's own boundary member \
                 would start before byte 0 of a {page_size}-byte page"
            ),
        }
    })?;
    if cursor > entry_array_start {
        return Err(NotBtrieve {
            why: format!(
                "page {page_start:#x}: the live fragments tile up to {cursor}, \
                 past where the entry array itself begins ({entry_array_start})"
            ),
        });
    }
    let trailing = bytes[page_start + cursor..page_start + entry_array_start].to_vec();

    Ok(FragmentPage { free_chain, fragments, free_space_entry, trailing })
}

/// Whether the raw header at `at` looks like what an abandoned page leaves
/// behind: either the engine zeroed the whole 6-byte header outright, or the
/// header survives and the page still reads as a genuine B-tree leaf
/// (`rightmost` `NOWHERE`, `leftmost` `NOWHERE` or literal `0` --
/// `model::IndexPage::leftmost`'s own doc already allows both). A pure
/// function of the page's own bytes, so it can check a page not yet
/// resolved -- see `resolve_pages`'s `None` arm, which uses it both on the
/// page being classified and, for the one shape neither self-corroborates,
/// on its physically adjacent neighbour.
fn orphan_header_shape(bytes: &[u8], at: usize) -> bool {
    let number = get_long(bytes, at + page::at::NUMBER);
    let counter = get_u16(bytes, at + page::at::COUNTER);
    if number == 0 && counter == 0 {
        return true;
    }
    let rightmost = get_long(bytes, at + index::at::RIGHTMOST);
    let leftmost = get_long(bytes, at + index::at::LEFTMOST);
    rightmost == crate::pages::NOWHERE && (leftmost == crate::pages::NOWHERE || leftmost == 0)
}

/// How `page_number` is already spoken for, for a conflict message.
fn describe_claim(kind: PageKind) -> String {
    match kind {
        PageKind::Index => "an index root".to_string(),
        PageKind::Acs => "the ACS block".to_string(),
        PageKind::Free => "on the free chain".to_string(),
        PageKind::IndexChild => "an index page (not a root)".to_string(),
        PageKind::Data => "a data page".to_string(),
        PageKind::Variable => "a variable-length fragment page".to_string(),
        PageKind::Orphan => "an orphaned page".to_string(),
    }
}

/// Whether an index page (identified by its own `leftmost` field alone) is a
/// leaf -- harvest 4's own rule, confirmed against `wccitem2.vir`'s root
/// (page 118, `leftmost` 117, genuinely interior) and its leaf (page 117,
/// `leftmost` `NOWHERE`): **zero counts as absent, not as page 0** -- a
/// virgin root page reads `NOWHERE` at `rightmost` and a literal `0` at
/// `leftmost`, and reading that zero as a real page sends a walk into the
/// file control record itself.
fn is_index_leaf(leftmost: u32) -> bool {
    leftmost == 0xffff_ffff || leftmost == 0
}

/// Validate one candidate child pointer and, if it is genuine, claim it for
/// `key_index`'s tree: bounds (not page 0, not past the file), not already
/// reached (by this same key's own walk -- a cycle -- or by a different
/// key's -- ambiguity), not already claimed by something else (the ACS
/// block, the free chain, or another key's root), and its own header's
/// `data_bit` clear (a B-tree node, not a page that holds records). Only
/// once all five hold does this insert the page into `claim` as
/// [`PageKind::IndexChild`] and into `owner`/`visited` for `key_index`.
///
/// # Errors
///
/// If any of the five checks above fails -- each arm names the page and the
/// specific predicate that failed, per Task 11b's own rule that ambiguity is
/// a refusal, never a guess.
fn enter_child(
    candidate: u32,
    key_index: usize,
    total_pages: usize,
    claim: &mut HashMap<u32, PageKind>,
    owner: &mut HashMap<u32, usize>,
    visited: &mut HashMap<u32, usize>,
    bytes: &[u8],
    page_size: usize,
) -> Result<u32, NotBtrieve> {
    if candidate == 0 {
        return Err(NotBtrieve {
            why: format!(
                "key_descriptor[{key_index}]'s B-tree names child page 0 -- \
                 the control record, never a real B-tree node"
            ),
        });
    }
    if candidate as usize >= total_pages {
        return Err(NotBtrieve {
            why: format!(
                "key_descriptor[{key_index}]'s B-tree names child page \
                 {candidate}, but the file has only {total_pages} pages"
            ),
        });
    }
    if let Some(&existing_key) = visited.get(&candidate) {
        return if existing_key == key_index {
            Err(NotBtrieve {
                why: format!(
                    "key_descriptor[{key_index}]'s B-tree revisits page \
                     {candidate} -- the tree does not terminate cleanly (a \
                     cycle)"
                ),
            })
        } else {
            Err(NotBtrieve {
                why: format!(
                    "page {candidate} is reached by both \
                     key_descriptor[{existing_key}]'s and \
                     key_descriptor[{key_index}]'s B-tree walk -- a page \
                     cannot belong to two keys' trees"
                ),
            })
        };
    }
    if let Some(existing) = claim.get(&candidate).copied() {
        return Err(NotBtrieve {
            why: format!(
                "key_descriptor[{key_index}]'s B-tree names page \
                 {candidate}, which is already {} -- a B-tree node cannot \
                 also be that",
                describe_claim(existing)
            ),
        });
    }
    let child_at = candidate as usize * page_size;
    let counter = get_u16(bytes, child_at + page::at::COUNTER);
    if counter & page::DATA_BIT != 0 {
        return Err(NotBtrieve {
            why: format!(
                "key_descriptor[{key_index}]'s B-tree names page {candidate} \
                 as a child, but its own header's data_bit is set -- the \
                 tree claims a B-tree node, but the page itself says it \
                 holds records"
            ),
        });
    }
    visited.insert(candidate, key_index);
    claim.insert(candidate, PageKind::IndexChild);
    owner.insert(candidate, key_index);
    Ok(candidate)
}

/// Walk one key's B-tree from its own root down through every genuine child
/// pointer, attributing each page it reaches to `key_index` (via `claim`/
/// `owner`) -- an explicit stack rather than recursion, leftmost-first, the
/// same shape `pages::walk_with` uses for the same problem on the live
/// engine's own page format: descend as far left as a subtree goes, then for
/// each entry in turn follow the entry itself and (on an interior page) the
/// child between it and the next, with the very last entry's gap filled by
/// the page header's own `rightmost` slot rather than the entry's own
/// (placeholder) `child` field.
///
/// The root's own bounds and `data_bit` are checked directly here, before
/// anything is decoded, using the identical wording `resolve_pages`'s own
/// per-page loop uses for the same contradiction on an ordinary forward
/// scan -- so a bogus root cannot be walked into as though its bytes were a
/// real B-tree node before either check has fired.
///
/// # Errors
///
/// If the root is out of range or its own `data_bit` is set, if the tree
/// runs deeper than a generous bound (corruption, not a real B-tree -- no
/// v5 corpus file this task measured exceeds a handful of levels), if a
/// non-last entry of an interior page has no stored `child` field at all
/// (only the last entry of a page may omit it, and only because the page is
/// full), or if [`enter_child`] refuses any child pointer along the way.
fn walk_one_key(
    bytes: &[u8],
    page_size: usize,
    total_pages: usize,
    key_index: usize,
    d: &KeyDescriptor,
    claim: &mut HashMap<u32, PageKind>,
    owner: &mut HashMap<u32, usize>,
    visited: &mut HashMap<u32, usize>,
) -> Result<(), NotBtrieve> {
    const MAX_DEPTH: usize = 64;

    let root = d.root_page;
    if root == 0 || root as usize >= total_pages {
        return Err(NotBtrieve {
            why: format!(
                "key_descriptor[{key_index}]'s root names page {root}, but \
                 the file has only {total_pages} pages (page 0 is the \
                 control record) -- not a real page to walk"
            ),
        });
    }
    let root_at = root as usize * page_size;
    if get_u16(bytes, root_at + page::at::COUNTER) & page::DATA_BIT != 0 {
        return Err(NotBtrieve {
            why: format!(
                "page {root} is an index root, but its own header's \
                 data_bit is set -- a key's root claims it as a B-tree \
                 node, but the page itself says it holds records"
            ),
        });
    }

    struct Frame {
        number: u32,
        page: IndexPage,
        at: usize,
    }
    let mut stack: Vec<Frame> = Vec::new();
    let mut next = Some(root);

    loop {
        while let Some(number) = next.take() {
            if stack.len() >= MAX_DEPTH {
                return Err(NotBtrieve {
                    why: format!(
                        "key_descriptor[{key_index}]'s B-tree from root \
                         {root} is more than {MAX_DEPTH} levels deep -- not \
                         a real B-tree"
                    ),
                });
            }
            let child_at = number as usize * page_size;
            let page = read_index_page(
                bytes,
                child_at,
                page_size,
                d.key_length as usize,
                d.entry_size as usize,
                d.attributes,
            )?;
            let leftmost = page.leftmost;
            stack.push(Frame { number, page, at: 0 });
            next = if is_index_leaf(leftmost) {
                None
            } else {
                Some(enter_child(
                    leftmost, key_index, total_pages, claim, owner, visited, bytes, page_size,
                )?)
            };
        }

        let Some(frame) = stack.last_mut() else { return Ok(()) };
        if frame.at == frame.page.entries.len() {
            stack.pop();
            continue;
        }
        let is_last = frame.at + 1 == frame.page.entries.len();
        let entry_child = frame.page.entries[frame.at].child;
        let leaf = is_index_leaf(frame.page.leftmost);
        let rightmost = frame.page.rightmost;
        let frame_number = frame.number;
        let entry_index = frame.at;
        frame.at += 1;
        if !leaf {
            let candidate = if is_last {
                rightmost
            } else {
                entry_child.ok_or_else(|| NotBtrieve {
                    why: format!(
                        "key_descriptor[{key_index}]'s B-tree: page \
                         {frame_number}'s entry {entry_index} has no stored \
                         child field at all, but it is not the page's last \
                         entry -- only the last entry of a page may omit it"
                    ),
                })?
            };
            next = Some(enter_child(
                candidate, key_index, total_pages, claim, owner, visited, bytes, page_size,
            )?);
        }
    }
}

/// Walk every key's own B-tree from its root, attributing each genuine
/// interior or leaf child page it reaches to that key -- see this task's
/// (11b) own brief: "every `IndexChild` page is attributed to exactly one
/// key's B-tree, by walking child pointers from that key's root."
///
/// `visited` is seeded with every key's own root page before any walk
/// starts, so a walk that loops back to its own root, or strays into a
/// different key's root, is refused the same way straying into a genuine
/// sibling child is -- there is exactly one predicate (`enter_child`'s
/// "already reached" check) for every one of these cases, not a separate
/// special case per source of ambiguity.
///
/// Each page is decoded exactly once per key whose tree reaches it (the
/// `visited` map guarantees no page is ever entered twice, by any key), so
/// this walk is linear in the number of pages the trees actually occupy,
/// never quadratic in the file's total page count.
///
/// # Errors
///
/// See [`walk_one_key`] and [`enter_child`].
fn walk_index_trees(
    bytes: &[u8],
    page_size: usize,
    total_pages: usize,
    key_descriptors: &[KeyDescriptor],
    claim: &mut HashMap<u32, PageKind>,
    owner: &mut HashMap<u32, usize>,
) -> Result<(), NotBtrieve> {
    let mut visited: HashMap<u32, usize> = HashMap::new();
    for (i, d) in key_descriptors.iter().enumerate() {
        if d.root_page != 0 {
            visited.insert(d.root_page, i);
        }
    }
    for (i, d) in key_descriptors.iter().enumerate() {
        if d.root_page == 0 {
            continue;
        }
        walk_one_key(bytes, page_size, total_pages, i, d, claim, owner, &mut visited)?;
    }
    Ok(())
}

/// Resolve the v5 page graph: what every physical page from 1 to
/// `total_pages - 1` *is*, derived from **two** independent sources -- the
/// control record's own pointers, and each page's own header bit -- neither
/// trusted alone.
///
/// v5 has no page-*kind* tag (no byte anywhere says "this is an index page"
/// versus "this is the ACS block" versus "this is free"), but it is not
/// true that a page's own header carries no signal at all: bit 15 of the
/// counter word is set iff the page holds records rather than a B-tree node
/// (harvest 3 SS2). An earlier version of this function treated the
/// pointers as the *only* signal and let a page with no pointer claim it
/// default to `Data` -- a controller-run measurement caught this: across
/// the 145 v5 corpus files, 9,058 pages in 39 files hold a B-tree node no
/// key root names, and their own `data_bit` said so the whole time. This
/// function now classifies from both sources and requires them to agree
/// wherever a pointer speaks.
///
/// A page named by a key descriptor's `root_page` is an index root -- and
/// its `data_bit` must be clear (a B-tree node, not records), or the file is
/// refused. A page is the ACS block when some key descriptor sets
/// `ALT_COLLATING`: harvest 4 SS6a measured this as always physical page 1
/// on every v5 corpus file that declares a sequence, with no exceptions, so
/// that is the rule this function trusts; its `data_bit` must also be clear.
/// FCR `0x10a` is read only as corroboration -- harvest 4 SS6a's own caution
/// is that it is unreliable on v5 (`CLASSADS.DAT` and `EMAIL.DAT` both read
/// zero there while genuinely holding a block on page 1), so a zero `0x10a`
/// alongside a declared sequence is accepted rather than refused, while a
/// **nonzero** `0x10a` that disagrees with what the key descriptors say is a
/// genuine contradiction and is refused, naming both. A page reachable by
/// walking the record-slot free chain from FCR `0x10` (a byte position, not
/// a page number -- harvest 3 SS4) is free, and its `data_bit` must be set
/// (a freed record slot lives on a page that otherwise holds records); v5
/// has no page-level free list, so this only records "at least one freed
/// record slot lives here," never displacing an Index or Acs claim.
///
/// A page no pointer claims is decided by `data_bit` first: set means
/// `Data`. Clear means a B-tree node no key's root names -- `IndexChild` if
/// some key's own walk (`walk_index_trees`) reaches it, or, failing that (on
/// a variable-length file) `Variable` if its content matches that shape, or
/// else [`PageKind::Orphan`] (Task 13): a page abandoned by every key's
/// tree, which v5's total absence of a page-level free list (harvest 3 SS4)
/// makes an expected outcome rather than evidence this crate failed to
/// attribute it. Measured 281/281 index roots, 15/15 ACS pages, and 22/22
/// free pages agree with their own `data_bit` across the whole v5 corpus,
/// so the checks below have never yet fired on real data -- but they are
/// real checks, not formalities, and a corpus file that ever disagrees is
/// refused rather than silently reclassified.
///
/// # Errors
///
/// If two keys claim the same root page, an index root and the ACS page
/// coincide, FCR `0x10a` names an ACS page that contradicts what the key
/// descriptors themselves declare (in either direction), the free chain
/// does not terminate cleanly -- a position repeats, a link runs past the
/// end of the file, or a link names a position inside the control record
/// itself, or reaches a page an index root or the ACS block already claims
/// -- or a page's own `data_bit` disagrees with what a pointer claims it is.
fn resolve_pages(
    bytes: &[u8],
    page_size: usize,
    total_pages: usize,
    control: &ControlRecord,
    key_descriptors: &[KeyDescriptor],
) -> Result<Vec<Page>, NotBtrieve> {
    let mut claim: HashMap<u32, PageKind> = HashMap::new();
    // Which key descriptor a page (root **or**, once `walk_index_trees` has
    // run, a genuine descendant) belongs to -- needed once a page is known
    // to be `Index`/`IndexChild`, so its entries can be decoded with the
    // right `key_length`/`entry_size`/`attributes` (none of which the page
    // itself carries).
    let mut owner: HashMap<u32, usize> = HashMap::new();

    // Index: every key descriptor's own root page (0 means "no root" --
    // either a continuation definition or an as-yet-empty key).
    for (i, d) in key_descriptors.iter().enumerate() {
        if d.root_page == 0 {
            continue;
        }
        if let Some(existing) = claim.get(&d.root_page).copied() {
            return Err(NotBtrieve {
                why: format!(
                    "key_descriptor[{i}]'s root names page {}, which is \
                     already {} -- two keys cannot share one root page",
                    d.root_page,
                    describe_claim(existing)
                ),
            });
        }
        claim.insert(d.root_page, PageKind::Index);
        owner.insert(d.root_page, i);
    }

    // ACS: gated on content (harvest 4 SS6a), not on FCR 0x10a alone.
    let v5_acs_page = acs::V5_PAGE;
    let acs_declared =
        key_descriptors.iter().any(|d| d.attributes & key_descriptor::ALT_COLLATING != 0);
    if acs_declared {
        if let Some(existing) = claim.get(&v5_acs_page).copied() {
            return Err(NotBtrieve {
                why: format!(
                    "a key descriptor declares an alternate collating \
                     sequence, which harvest 4 SS6a places at physical page \
                     {v5_acs_page} on every v5 corpus file measured, but \
                     page {v5_acs_page} is already {} -- the ACS block and \
                     an index root cannot be the same page",
                    describe_claim(existing)
                ),
            });
        }
        claim.insert(v5_acs_page, PageKind::Acs);
        if control.acs_page_pointer != 0 && control.acs_page_pointer != v5_acs_page {
            return Err(NotBtrieve {
                why: format!(
                    "FCR 0x10a names page {} as the ACS block, but a key \
                     descriptor's ALT_COLLATING bit places it at physical \
                     page {v5_acs_page} instead (harvest 4 SS6a) -- the two \
                     disagree",
                    control.acs_page_pointer
                ),
            });
        }
    } else if control.acs_page_pointer != 0 {
        return Err(NotBtrieve {
            why: format!(
                "FCR 0x10a names page {} as the ACS block, but no key \
                 descriptor declares ALT_COLLATING -- harvest 4 SS6a's \
                 content-based rule finds nothing to corroborate it",
                control.acs_page_pointer
            ),
        });
    }

    // IndexChild: walk every key's own tree from its root, down through
    // every genuine child pointer, attributing each page it reaches to that
    // key -- see `walk_index_trees`'s own doc. Ordered before the free-chain
    // walk below so a free-chain link that reaches a genuine B-tree child is
    // caught as the same kind of contradiction as one reaching a root or the
    // ACS page.
    walk_index_trees(bytes, page_size, total_pages, key_descriptors, &mut claim, &mut owner)?;

    // Free: walk the record-slot free chain from FCR 0x10, both to claim
    // the pages it touches (as before) and to remember every freed
    // position itself (harvest 5 SS2.1) -- `free_slots` is what lets
    // `read_data_page` tell a free slot from a live one instead of storing
    // every slot as an opaque blob. `read_data_page` decodes each free
    // slot's own forwarding link independently
    // (`format::free_slot::decode_link`), rather than reusing the `next`
    // this walk computes below to keep walking -- deliberately: this walk's
    // own `get_long` exists to find every freed *position*, a wholly
    // different job from the model's own claim about what a free slot's
    // bytes *mean*, and conflating the two would leave no isolated place
    // for this task's own decode to be wrong.
    const NOWHERE: u32 = 0xffff_ffff;
    let mut cur = control.free;
    let mut visited: HashSet<u32> = HashSet::new();
    let mut free_slots: HashSet<u32> = HashSet::new();
    while cur != NOWHERE {
        if !visited.insert(cur) {
            return Err(NotBtrieve {
                why: format!(
                    "the free chain from FCR 0x10 revisits position \
                     {cur:#x} -- it does not terminate cleanly"
                ),
            });
        }
        let at = cur as usize;
        if at < page_size {
            return Err(NotBtrieve {
                why: format!(
                    "the free chain from FCR 0x10 names position {cur:#x}, \
                     inside the control record itself -- not a record \
                     position on any real page"
                ),
            });
        }
        if at + 4 > bytes.len() {
            return Err(NotBtrieve {
                why: format!(
                    "the free chain from FCR 0x10 names position {cur:#x}, \
                     past the end of the {}-byte file", bytes.len()
                ),
            });
        }
        let page_number = (at / page_size) as u32;
        if let Some(existing) = claim.get(&page_number).copied() {
            if matches!(existing, PageKind::Index | PageKind::Acs | PageKind::IndexChild) {
                return Err(NotBtrieve {
                    why: format!(
                        "the free chain from FCR 0x10 reaches page \
                         {page_number}, which is already {} -- a B-tree or \
                         ACS page cannot also hold a freed record slot",
                        describe_claim(existing)
                    ),
                });
            }
        } else {
            claim.insert(page_number, PageKind::Free);
        }
        free_slots.insert(cur);
        cur = get_long(bytes, at);
    }

    // Every page's own header carries a second signal past the pointers
    // above: bit 15 of the counter word, set iff the page holds records
    // rather than a B-tree node (harvest 3 SS2). This crate's brief once
    // said v5 has no page-type tag at all -- wrong, and a controller-run
    // corpus measurement caught it: 9,058 pages across 39 v5 files hold a
    // B-tree node no key root names, and their own `data_bit` says so. A
    // page's kind is therefore never a residual "whatever the pointers
    // didn't claim" -- every page is classified from *both* sources, and
    // where a pointer claims a role, the bit must agree or the file is
    // refused, naming the page, what the pointer claimed, and what the bit
    // said. Measured across all 145 v5 corpus files: 281/281 index roots
    // agree (`data_bit` clear), 15/15 ACS pages agree (`data_bit` clear),
    // 22/22 free-chain pages agree (`data_bit` set) -- zero contradictions,
    // so this check has never yet fired on real data, but it is a real
    // check, not a formality.
    let mut pages = Vec::with_capacity(total_pages.saturating_sub(1));
    for page_number in 1..total_pages {
        let at = page_number * page_size;
        let number = get_long(bytes, at + page::at::NUMBER);
        let counter = get_u16(bytes, at + page::at::COUNTER);
        let data_bit = counter & page::DATA_BIT != 0;
        let stamp = counter & !page::DATA_BIT;

        // Harvest 5 SS3.1's whole-file flag: only a variable-length file's
        // unclaimed, data-bit-clear pages are ever candidates for
        // `PageKind::Variable` -- see that variant's own doc for why
        // gating on this (rather than trying the shape on every file) costs
        // nothing and avoids even a theoretical false positive on the 143
        // non-variable v5 corpus files this crate already reads correctly.
        let variable = control.usrflgs & fcr::usrflgs::VARIABLE != 0;

        let kind = match claim.get(&(page_number as u32)).copied() {
            Some(PageKind::Index) if data_bit => {
                return Err(NotBtrieve {
                    why: format!(
                        "page {page_number} is an index root, but its own \
                         header's data_bit is set -- a key's root claims it \
                         as a B-tree node, but the page itself says it \
                         holds records"
                    ),
                });
            }
            Some(existing @ PageKind::Acs) if data_bit => {
                return Err(NotBtrieve {
                    why: format!(
                        "page {page_number} is {}, but its own header's \
                         data_bit is set -- FCR/key evidence claims a \
                         B-tree-shaped page, but the page itself says it \
                         holds records",
                        describe_claim(existing)
                    ),
                });
            }
            Some(existing @ PageKind::Free) if !data_bit => {
                return Err(NotBtrieve {
                    why: format!(
                        "page {page_number} is {}, but its own header's \
                         data_bit is clear -- the free chain claims a \
                         record slot lives here, but the page itself says \
                         it holds a B-tree node, not records",
                        describe_claim(existing)
                    ),
                });
            }
            Some(kind @ (PageKind::Index | PageKind::Acs | PageKind::Free | PageKind::IndexChild)) => {
                kind
            }
            Some(other) => {
                unreachable!(
                    "claim only ever stores Index, Acs, Free, or IndexChild -- got {other:?}"
                )
            }
            None if data_bit => PageKind::Data,
            None if variable && looks_like_fragment_page(bytes, at, page_size) => {
                PageKind::Variable
            }
            None => {
                // Not named by any root, not the ACS block, not on the free
                // chain, its own header says "not records", not reached by
                // any key's own B-tree walk (`walk_index_trees`, above --
                // every genuine child of a real tree is already `claim`ed
                // by the time this loop runs), and (on a variable-length
                // file) its own bytes do not match this format's
                // fragment-page shape either. Task 11b's own rule still
                // holds: this crate never guesses a *structure* for such a
                // page (this used to fall through to `PageKind::IndexChild`
                // residually, mislabelling 9,058 pages). Task 13 adds the
                // one thing it is safe to say instead of refusing: v5 has no
                // page-level free list (harvest 3 SS4), so a page no walk
                // reaches is the format's own expected abandoned-page
                // outcome, not evidence of a parsing gap -- `PageKind::Orphan`
                // asserts exactly that and nothing more; see its own
                // documentation for the corpus evidence.
                //
                // But that is only safe if this page's own bytes actually
                // corroborate abandonment -- a review of Task 13 pointed out
                // that `Orphan` had no in-crate check of its own, so a future
                // bug that silently under-visits a live subtree (rather than
                // erroring, which every real `?` in `walk_index_trees` would)
                // would deposit a real, reachable page here, carried
                // byte-identical and undetectable by the round trip alone.
                //
                // `orphan_header_shape` (below) names the two shapes this
                // crate can verify on a page's own bytes alone: the engine
                // zeroed the whole 6-byte header outright (`wccitem2.vir`
                // page 593 under `wccnt7pz`, `wccupda2.dat`'s own two
                // orphans -- `number == 0 && counter == 0`), or the header
                // survives and the page still looks like a genuine B-tree
                // leaf (`TTIHORSS.DAT`/`.VIR` page 251, `wccitem2.vir` page
                // 592 under `wccnt7py` -- `rightmost` reads `NOWHERE` and
                // `leftmost` reads `NOWHERE` or literal `0`, the same two
                // leaf shapes `IndexPage::leftmost`'s own doc already
                // allows).
                //
                // Enforcing that check against every corpus file turned up a
                // *third* shape: physical page 594 of
                // `wccitem2.vir`/`wccITEM2.nu1` under `wccnt7pz`, and page
                // 17565 of `wccupda2.dat` under `wccnt7py`, are each
                // unclaimed, `data_bit` clear, and hold *nothing but*
                // leftover monster/item-description prose -- starting right
                // at byte 0, so it overwrites what would be the header too.
                // Neither zeroed nor leaf-shaped; `data_bit` reads clear only
                // because printable ASCII text never sets a byte's high bit,
                // a coincidence of the encoding, not a structural signal.
                //
                // A second review caught the first fix for this shape being
                // weaker than its own comment claimed: it accepted a page as
                // `Orphan` if EITHER neighbour looked right, checked "is the
                // neighbour already `Orphan`" rather than "does the neighbour
                // self-corroborate," and never actually verified a live
                // `Data` page bounded the run at all. That combination lets
                // one self-corroborating page bootstrap an unbounded chain:
                // page N self-corroborates, page N+1 is accepted because N
                // is `Orphan` (not because N+1 itself proves anything), page
                // N+2 is then accepted because N+1 is now `Orphan` too,
                // forever -- every page in the chain carried verbatim, every
                // test green, and not one byte of it examined. That is
                // exactly the wrong-but-lossless classification this whole
                // check exists to catch.
                //
                // The rule actually enforced now, matching the only two
                // witnesses this crate has ever measured (both a chain of
                // exactly one such page): a page whose own shape does not
                // self-corroborate is `Orphan` only when BOTH neighbours
                // independently prove it -- the *immediately preceding* page
                // is itself unclaimed, `data_bit` clear, and passes
                // `orphan_header_shape` **on its own raw bytes** (never "is
                // already `Orphan`," which is exactly the transitive trust
                // that bootstraps), and the *immediately following* page's
                // own `data_bit` is set, so it is by construction a genuine
                // record-holding page (`Data` or `Free`, never another
                // candidate for this same rule) -- the live `Data` page this
                // crate actually measured resuming at 595 and 17566. Because
                // only a page that self-corroborates on its own bytes can
                // ever serve as the preceding anchor, this page itself can
                // never in turn anchor a third -- the chain this rule
                // accepts is always exactly one page long, not because of an
                // explicit counter but as a structural consequence of never
                // trusting a neighbour's *classification*, only its bytes.
                let this_shape = orphan_header_shape(bytes, at);
                let extends_a_corroborated_anchor = page_number > 1
                    && page_number + 1 < total_pages
                    && claim.get(&((page_number - 1) as u32)).is_none()
                    && {
                        let prev_at = at - page_size;
                        let prev_data_bit =
                            get_u16(bytes, prev_at + page::at::COUNTER) & page::DATA_BIT != 0;
                        !prev_data_bit && orphan_header_shape(bytes, prev_at)
                    }
                    && {
                        let next_at = at + page_size;
                        get_u16(bytes, next_at + page::at::COUNTER) & page::DATA_BIT != 0
                    };
                if !this_shape && !extends_a_corroborated_anchor {
                    let rightmost = get_long(bytes, at + index::at::RIGHTMOST);
                    let leftmost = get_long(bytes, at + index::at::LEFTMOST);
                    return Err(NotBtrieve {
                        why: format!(
                            "page {page_number} is not named by any key's root, \
                             not the ACS block, not on the free chain, its own \
                             header says it holds a B-tree node rather than \
                             records, and no key's B-tree walk ever reached it \
                             -- but its header is not the zero an abandoned page \
                             leaves (number {number:#x}, counter {counter:#x}), its \
                             own rightmost/leftmost ({rightmost:#x}/{leftmost:#x}) do \
                             not look like an abandoned leaf's either, and it does \
                             not extend a corroborated anchor either (the immediately \
                             preceding page must itself self-corroborate and the \
                             immediately following page must be a genuine \
                             record-holding page) -- so this crate refuses rather \
                             than assuming it is orphaned"
                        ),
                    });
                }
                PageKind::Orphan
            }
        };

        // A fixed-length-record data page's content -- slots plus trailing
        // slack -- is described whenever the page actually holds records
        // (`data_bit` set: `Data` or `Free`, never `Index`/`IndexChild`/
        // `Acs`/`Variable` -- the last three are never `data_bit` set, see
        // `PageKind::Variable`'s own doc) and `physical` is a sound slot
        // width to divide by. A variable-length file's `Data`/`Free` pages
        // get this the same as any other file's: harvest 5 SS1.1's slot
        // layout does not change shape when a record's tail holds a
        // fragment pointer instead of zero padding, and `DataPage::slots`
        // already stores each slot whole and verbatim, so nothing here
        // needs to know a pointer is inside one.
        let content = if data_bit && control.physical != 0 {
            Some(read_data_page(bytes, at, page_size, control.physical as usize, &free_slots)?)
        } else {
            None
        };

        // An index page's entries, described whenever this page is a key's
        // own root **or** a genuine descendant `walk_index_trees` reached:
        // either way its owning key descriptor is known directly (via
        // `owner`), so `key_length`/`entry_size`/`attributes` need no
        // re-deriving here -- they are read a second time from the same key
        // descriptor the walk itself used, which is what Task 11b's
        // mutation targets (see `read`'s own
        // `attributing_every_index_child_to_key_zero_...` test).
        let index_content = if kind == PageKind::Index || kind == PageKind::IndexChild {
            let &n = owner
                .get(&(page_number as u32))
                .unwrap_or_else(|| panic!("page {page_number} is {kind:?} but claims no owner"));
            let d = &key_descriptors[n];
            Some(read_index_page(
                bytes,
                at,
                page_size,
                d.key_length as usize,
                d.entry_size as usize,
                d.attributes,
            )?)
        } else {
            None
        };

        // The ACS block's content, described whenever this page is the
        // file's collating-sequence page (`kind == Acs`, harvest 4 SS6a
        // gates its very presence on a key's own `ALT_COLLATING` bit, above
        // -- never on FCR 0x10a alone).
        let acs_content =
            if kind == PageKind::Acs { Some(read_acs_block(bytes, at, page_size)?) } else { None };

        // A fragment page's content (harvest 5 SS3.3), described whenever
        // this page is `PageKind::Variable` -- established above by content
        // evidence, not by residue.
        let fragment_content = if kind == PageKind::Variable {
            Some(read_fragment_page(bytes, at, page_size)?)
        } else {
            None
        };

        // An orphan's entire body (Task 13): stored whole and verbatim,
        // past the 6-byte header, with no attempt to decode it as any other
        // page shape -- see `PageKind::Orphan`'s own documentation.
        let orphan_content = if kind == PageKind::Orphan {
            Some(bytes[at + page::LEN..at + page_size].to_vec())
        } else {
            None
        };

        pages.push(Page {
            number,
            data_bit,
            stamp,
            kind,
            content,
            index: index_content,
            acs: acs_content,
            fragments: fragment_content,
            orphan: orphan_content,
        });
    }
    Ok(pages)
}

/// Read a whole Btrieve file into a model.
///
/// # Errors
///
/// If [`identify`] refuses the control record, the file is shorter than its
/// own declared page size, the file is not a whole number of pages, the
/// key/segment definition array is malformed (runs past the page, or an
/// `ANOSEG` chain never terminates), or [`resolve_pages`] cannot classify
/// every page -- see that function's own documentation for the specific
/// contradictions it checks for. Page 0's tail past the last key/segment
/// definition is never a refusal reason -- see `model::File::page_zero_tail`.
///
/// A v6 file is always refused today, but not until after page 0 *and* the
/// allocation table have been read and validated: the live control-record
/// copy (harvest 0 ruling 7, harvest 2 "FCR shadowing") is resolved first,
/// then its key/segment definitions (Task 15), then its definition-offset
/// trailer (Task 16, [`v6_page_tail`]), then every "PP" allocation-table
/// block's own shadow pair and the logical-to-physical map its entries
/// encode (Task 17, [`v6_allocation_table`]) -- and the refusal names all of
/// it (which physical page is live, at what generation, KEYS realized as how
/// many definitions, how many allocation-table blocks and logical pages
/// resolved), because ordinary v6 page headers, records and index pages
/// past addressing are later work -- see [`resolve_shadow`].
pub fn file(bytes: &[u8]) -> Result<File, NotBtrieve> {
    let id = identify(bytes)?;
    let page_size = id.page_size as usize;

    if id.generation.is_v6() {
        // Ruling 7, part 1: resolve the live copy before interpreting any
        // other field. The control record is shadowed across physical pages
        // 0 and 1, each `page_size` bytes, so both must actually be present
        // before anything past `identify`'s own page-0-only check can be
        // asked at all.
        if bytes.len() < 2 * page_size {
            return Err(NotBtrieve {
                why: format!(
                    "identified as {:?} with {page_size}-byte pages, but \
                     this v6 file is only {} bytes -- shorter than the two \
                     full pages its own shadowed control record requires",
                    id.generation,
                    bytes.len()
                ),
            });
        }

        let control = resolve_shadow(bytes, page_size)?;
        let Control::Shadowed { live, live_is_page, .. } = &control else {
            unreachable!("resolve_shadow only ever returns Control::Shadowed")
        };

        // Task 15: the live copy's own key/segment definitions are the same
        // 30-byte, ANOSEG-chained structure v5 uses (harvest 2's field
        // table transcribes to identical offsets), so the same walk applies
        // -- just against the live copy's own physical page, not physical
        // page 0 unconditionally. A malformed array (a chain that runs past
        // the page, or never terminates) is refused by that walk's own,
        // more specific message; a well-formed one still cannot produce a
        // `File` today, since the allocation table and page addressing past
        // the control record are later work.
        let live_page_start = live_is_page * page_size;
        let live_descriptors = key_descriptors(&bytes[live_page_start..], page_size, live.keys)?;

        // Task 16: the live copy's own definition-offset trailer -- past
        // the key/segment definitions above -- is read and validated too,
        // moving the frontier past all of page 0, not just its fixed
        // portion and key array. A malformed trailer (a slot disagreeing
        // with what this crate's own census-derived formula expects) is
        // refused by that function's own, more specific message.
        let _live_page_tail =
            v6_page_tail(&bytes[live_page_start..], page_size, &live_descriptors)?;

        // Task 17: the allocation table is the mechanism that makes v6
        // pages addressable at all, and it needs a whole-number-of-pages
        // file to walk (harvest 3 SS7 measured this on all 612 corpus
        // files with no exceptions) -- the same check the v5 path below
        // makes, just needed here first since the table walk indexes by
        // physical page number.
        if bytes.len() % page_size != 0 {
            return Err(NotBtrieve {
                why: format!(
                    "identified as {:?} with {page_size}-byte pages, but \
                     the file is {} bytes -- not a whole number of pages",
                    id.generation,
                    bytes.len()
                ),
            });
        }
        let total_pages = bytes.len() / page_size;

        // Task 17: resolve the allocation table -- every "PP" block's own
        // shadow pair (the identical generation rule Ruling 7 already
        // applies to the control record itself), and the logical-to-
        // physical map its entries encode. A malformed table (a bad
        // shadow pair, a block claiming the control record's own pages, a
        // claim past the end of the file) is refused by that function's
        // own, more specific message; a well-formed one still cannot
        // produce a `File` today, since ordinary v6 page headers, records
        // and index pages past the addressing layer are later work.
        let (allocation_blocks, physical_map) =
            v6_allocation_table(bytes, page_size, total_pages)?;

        // Ruling 7, part 3: identification stays on page 0 -- already true,
        // `identify` never moves. What must not come from page 0 is
        // geometry, and page 0 plus the allocation table (Task 17) is now
        // everything this crate can resolve without ordinary v6 page
        // content: the refusal moves here, past addressing, not just past
        // the control record and its key/segment definitions.
        return Err(NotBtrieve {
            why: format!(
                "identified as {:?} with {page_size}-byte pages; the live \
                 control record is physical page {live_is_page} (generation \
                 {}), KEYS={} realized as {} key/segment definitions plus a \
                 validated definition-offset trailer (page 0 is fully \
                 described), RECLEN={}, PHYSICAL={}, RECORDS={}, PAGES={} \
                 (logical, not physical); the allocation table has {} \
                 block(s) resolving {} logical page(s) to physical pages \
                 out of {total_pages} physical pages total, but this crate \
                 does not yet describe ordinary v6 page headers, records \
                 or index pages, so it cannot resolve page content past \
                 addressing",
                id.generation,
                live.generation,
                live.keys,
                live_descriptors.len(),
                live.reclen,
                live.physical,
                live.records,
                live.pages,
                allocation_blocks.len(),
                physical_map.len(),
            ),
        });
    }

    if bytes.len() < page_size {
        return Err(NotBtrieve {
            why: format!(
                "identified as {:?} with {page_size}-byte pages, but the \
                 file is only {} bytes -- shorter than its own first page",
                id.generation,
                bytes.len()
            ),
        });
    }

    let control = control_record(bytes);
    let key_descriptors = key_descriptors(bytes, page_size, control.keys)?;

    // Whatever bytes remain after the last actual key/segment definition, up
    // to page_size, are carried verbatim rather than asserted zero -- see
    // `model::File::page_zero_tail`'s own documentation. Harvest 1's
    // tail_check.py measured this zero on 112 of 112 v5 corpus files,
    // re-measured for Task 13 on 143 of the 145 v5 corpus files currently
    // identified; the 2 exceptions (wccitems.nu1 and its sibling) hold
    // genuine leftover record prose here, not corruption, so this crate
    // stores what the file actually says instead of refusing it.
    let after_definitions = key_descriptor::base(key_descriptors.len());
    let page_zero_tail = if page_size > after_definitions {
        bytes[after_definitions..page_size].to_vec()
    } else {
        Vec::new()
    };

    // The file must be a whole number of pages -- harvest 3 SS7 measured
    // this on all 612 corpus files this crate has identified, with no
    // exceptions, so a file that disagrees is refused rather than silently
    // truncated to whatever whole pages fit.
    if bytes.len() % page_size != 0 {
        return Err(NotBtrieve {
            why: format!(
                "identified as {:?} with {page_size}-byte pages, but the \
                 file is {} bytes -- not a whole number of pages",
                id.generation,
                bytes.len()
            ),
        });
    }
    let total_pages = bytes.len() / page_size;
    let pages = resolve_pages(bytes, page_size, total_pages, &control, &key_descriptors)?;

    Ok(File {
        id,
        control: Control::Single(control),
        key_descriptors,
        page_zero_tail,
        pages,
        len: bytes.len() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::generation::Generation;
    use crate::model::fixtures::{
        full_index_page_with_an_omitted_last_child, two_key_fixed_portion, usracc_dat,
        usracc_first_page, usracc_fixed_portion, variable_length_file_with_a_real_fragment_page,
    };
    use crate::model::FragmentSlot;

    /// The exact values the controller measured independently off
    /// `archive/galacticomm/hosts/majorbbs/USRACC.DAT`'s raw bytes before
    /// this task was dispatched.
    #[test]
    fn usracc_dat_fixed_portion_reads_its_measured_values() {
        let buf = usracc_fixed_portion();
        let file = file(&buf).expect("a valid v5 control record");
        assert_eq!(file.id.generation, Generation::V5R3);
        assert_eq!(file.id.page_size, 512);
        assert_eq!(file.live_control().keys, 1, "KEYS");
        assert_eq!(file.live_control().reclen, 0xfc, "RECLEN");
        assert_eq!(file.live_control().physical, 0xfc, "PHYSICAL");
        assert_eq!(file.live_control().records, 2, "RECORDS");
        assert_eq!(file.live_control().highest, 2, "HIGHEST");
        assert_eq!(file.live_control().pages, 3, "PAGES");
        assert_eq!(file.live_control().usrflgs, 0, "USRFLGS");
        assert_eq!(file.len, 512);
    }

    /// A v6 file one page long is refused before Ruling 7's shadow
    /// resolution can even run: a v6 control record is *two* full-page
    /// copies, so a file that is only one page cannot possibly hold both,
    /// and this is caught before generation counters are ever compared.
    #[test]
    fn a_one_page_v6_file_is_refused_before_the_shadow_pair_can_be_resolved() {
        let mut b = vec![0u8; 512];
        b[..4].copy_from_slice(&[b'F', b'C', 0, 0]);
        b[0x4a..0x4c].copy_from_slice(&0x600u16.to_le_bytes());
        b[8..10].copy_from_slice(&512u16.to_le_bytes());
        let e = file(&b).expect_err("one page cannot hold a shadow pair");
        assert!(e.why.contains("v6"), "{}", e.why);
        assert!(e.why.contains("512"), "{}", e.why);
    }

    /// The workspace's `archive/`-relative path, joined onto the workspace
    /// root the same way `corpus::root()` finds `archive/` itself --
    /// `path` already includes the `archive/` prefix, so this is a plain
    /// join, not a second copy of that lookup.
    fn corpus_path(path: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("crates/btrieve is two directories under the workspace root")
            .join(path)
    }

    /// A synthetic two-page v6 buffer whose only interesting content is the
    /// generation counter at page-relative `0x04` in each copy -- everything
    /// else is just enough for `identify` to accept it as v6.
    fn two_copies_with_generations(gen0: u16, gen1: u16) -> Vec<u8> {
        const PAGE_SIZE: usize = 512;
        let mut b = vec![0u8; 2 * PAGE_SIZE];
        for page in [0usize, 1] {
            let base = page * PAGE_SIZE;
            b[base..base + 4].copy_from_slice(&[b'F', b'C', 0, 0]);
            b[base + 0x4a..base + 0x4c].copy_from_slice(&0x600u16.to_le_bytes());
            b[base + 8..base + 10].copy_from_slice(&(PAGE_SIZE as u16).to_le_bytes());
        }
        b[0x04..0x06].copy_from_slice(&gen0.to_le_bytes());
        b[PAGE_SIZE + 0x04..PAGE_SIZE + 0x06].copy_from_slice(&gen1.to_le_bytes());
        b
    }

    /// Physical page 0 of this file describes an empty three-page database.
    /// The file is 55,734,272 bytes. Nothing about page 0 is malformed --
    /// it is simply not the current copy, which is why reading it has never
    /// been refused and has always been wrong.
    ///
    /// This tests [`resolve_shadow`] directly rather than the full [`file`]
    /// pipeline. `file` itself still refuses every v6 file (the allocation
    /// table, page addressing, and the rest of v6's own pages are later
    /// work), so it cannot return `Ok` for a real v6 file yet -- but the
    /// shadow resolution Ruling 7 requires happens unconditionally, before
    /// that later refusal, and is independently correct and testable here.
    /// `the_refusal_names_the_live_copy_it_resolved` below is the companion
    /// check: that `file`'s own refusal for this same file changed shape.
    #[test]
    fn the_live_control_record_is_the_one_with_the_higher_generation() {
        let path = "archive/modules/majormud-nt/wccnt8pj/out/wccmp002.vir";
        let Ok(bytes) = std::fs::read(corpus_path(path)) else {
            eprintln!("no archive/ on this box, nothing verified");
            return;
        };
        let id = identify(&bytes).expect("a v6 file with two control records");
        let control = resolve_shadow(&bytes, id.page_size as usize)
            .expect("two control records, generations must differ");
        let Control::Shadowed { live, stale, live_is_page } = &control else {
            panic!("a v6 file has two control records")
        };
        assert_eq!(*live_is_page, 1);
        assert_eq!(live.records, 26_720);
        assert_eq!(stale.records, 0);
    }

    /// Task 15's own failing-test-first: the live control record of a named
    /// v6 file reads its full measured geometry, not just `records` and
    /// `live_is_page` -- `WCCBANK2.VIR` (24,576 bytes, page_size 4096, a
    /// single un-flipped generation) independently re-measured by this
    /// task's own controller directly off the raw bytes (`xxd`/a small
    /// Python script), before `V6ControlRecord` existed to hold most of
    /// these fields. Before Task 15 this would not compile: `free_v6`,
    /// `variable_head`, `acs_page`, `sentinel_22`/`sentinel_24` and the
    /// logical/physical `pages` distinction had no field to assert against.
    #[test]
    fn wccbank2_vir_live_control_record_reads_its_full_measured_geometry() {
        let path = "archive/modules/majormud-nt/wccnt8pj/out/WCCBANK2.VIR";
        let Ok(bytes) = std::fs::read(corpus_path(path)) else {
            eprintln!("no archive/ on this box, nothing verified");
            return;
        };
        let id = identify(&bytes).expect("a v6 file with two control records");
        let control = resolve_shadow(&bytes, id.page_size as usize)
            .expect("two control records, generations must differ");
        let Control::Shadowed { live, live_is_page, .. } = &control else {
            panic!("a v6 file has two control records")
        };
        assert_eq!(*live_is_page, 0, "gen0=1, gen1=0 -- page 0 is live");
        assert_eq!(live.keys, 1, "KEYS");
        assert_eq!(live.reclen, 76, "RECLEN");
        assert_eq!(live.physical, 86, "PHYSICAL");
        assert_eq!(live.records, 0, "a virgin file");
        assert_eq!(live.pages, 3, "PAGES is LOGICAL: 3, not the 6 physical pages a 24,576-byte, 4096-byte-page file actually has");
        assert_eq!(live.sentinel_22, 0xffff);
        assert_eq!(live.sentinel_24, 1, "raw bytes 01 00, read little-endian: 0x0001, not the harvest prose's own 0x0100 gloss");
        assert_eq!(live.free_v6, 8198);
        assert_eq!(live.variable_head, 0xff00_ffff, "NO_VARIABLE_HEAD: a fixed-length-record file");
        assert_eq!(live.acs_page, 0, "no ACS declared");
        assert_eq!(live.acs_name, [0u8; 8]);
    }

    /// MULTIACS.DAT (harvest 2's own worked example): `KEYS` at `0x14`
    /// counts 3 *keys*, but the key/segment definition array actually holds
    /// 4 definitions, because the second key has two segments chained by
    /// `ANOSEG`. Reusing `key_descriptors` -- the same walk v5 uses,
    /// unmodified -- against the live copy's own bytes produces exactly
    /// that: proof the two families' key/segment shapes genuinely match, not
    /// just superficially.
    ///
    /// This also exercises `SELF_TAG` (relative `0x18`), harvest 2's other
    /// new finding: `0x80|keynum` on an independent segment, `0x00` on an
    /// `ANOSEG` continuation.
    #[test]
    fn multiacs_dat_keys_counts_keys_not_definitions_and_self_tag_matches_harvest_2() {
        let path = "archive/tooling/wbtrv32/assets/MULTIACS.DAT";
        let Ok(bytes) = std::fs::read(corpus_path(path)) else {
            eprintln!("no archive/ on this box, nothing verified");
            return;
        };
        let id = identify(&bytes).expect("a v6.10 file");
        assert_eq!(id.generation, crate::format::generation::Generation::V610);
        let control = resolve_shadow(&bytes, id.page_size as usize).expect("resolves");
        let Control::Shadowed { live, live_is_page, .. } = &control else {
            panic!("a v6 file has two control records")
        };
        assert_eq!(live.keys, 3, "KEYS counts 3 keys");

        let live_start = live_is_page * id.page_size as usize;
        let descriptors = key_descriptors(&bytes[live_start..], id.page_size as usize, live.keys)
            .expect("a well-formed ANOSEG chain");
        assert_eq!(descriptors.len(), 4, "3 keys realized as 4 definitions -- one key has 2 segments");

        let self_tags: Vec<u8> = descriptors.iter().map(|d| d.self_tag).collect();
        assert_eq!(
            self_tags,
            vec![0x80, 0x81, 0x00, 0x82],
            "def0/def1/def3 are independent segments (0x80|keynum); def2 is \
             def1's ANOSEG continuation (0x00)"
        );
        assert_eq!(descriptors[2].root_page, 0, "a continuation's root is 0");
    }

    /// `wccmp002.vir`'s live control record's fixed portion (`0x00..0x110`)
    /// round-trips through `V6ControlRecord` and
    /// `emit::write_v6_fixed_portion` byte for byte -- including `PAGES`
    /// (13,572, logical), the field this task's own required mutation
    /// targets. This is the site that mutation must turn red: if `emit`
    /// wrote the file's *physical* page count (13,607) instead of the
    /// model's own stored (logical) value, this assertion is what would
    /// catch it.
    #[test]
    fn wccmp002_virs_live_fixed_portion_round_trips_including_the_logical_pages_field() {
        let path = "archive/modules/majormud-nt/wccnt8pj/out/wccmp002.vir";
        let Ok(bytes) = std::fs::read(corpus_path(path)) else {
            eprintln!("no archive/ on this box, nothing verified");
            return;
        };
        let id = identify(&bytes).expect("a v6 file");
        let page_size = id.page_size as usize;
        assert_eq!(bytes.len() % page_size, 0, "13,607 physical pages, no partial page");
        let physical_pages = bytes.len() / page_size;
        assert_eq!(physical_pages, 13_607, "the measured physical page count");

        let control = resolve_shadow(&bytes, page_size).expect("resolves");
        let Control::Shadowed { live, live_is_page, .. } = &control else {
            panic!("a v6 file has two control records")
        };
        assert_eq!(live.pages, 13_572, "PAGES is logical, not the 13,607 physical pages above");

        let mut canvas = crate::canvas::Canvas::new(fcr::v6::FIXED_LEN);
        crate::emit::write_v6_fixed_portion(&mut canvas, id.generation, id.page_size, live, 0)
            .expect("the fixed portion is fully described");
        let emitted = canvas.finish().expect("every byte written exactly once");

        let live_start = live_is_page * page_size;
        assert_eq!(
            emitted.bytes(),
            &bytes[live_start..live_start + fcr::v6::FIXED_LEN],
            "the live copy's fixed portion must reproduce byte for byte"
        );
    }

    /// Task 17's own failing-test-first: `wccmp002.vir` (already this
    /// crate's own named fixture for the logical/physical `PAGES`
    /// distinction) has 14 allocation-table blocks -- one of 29 corpus
    /// files (measured directly with `format::alloc::pair_position`
    /// against every identified v6 file, not reimplemented as a separate
    /// count) with more than one. Before this task's implementation,
    /// `v6_allocation_table` does not exist and this fails to compile;
    /// after, it resolves all 14 blocks, both shadow copies of each, and
    /// the logical ids they claim -- measured directly off the raw bytes
    /// with a standalone Python script before this test was written:
    /// block 1's shadow pair is physical 2/3 with generations 1/285 (live
    /// at physical 3), block 14's is physical 13314/13315 with generations
    /// 279/285 (live at physical 13315); 13,568 of the 13,571 possible
    /// logical ids (`PAGES - 1`) are actually claimed; logical 1 resolves
    /// to physical 13603, logical 2 to physical 8, logical 3 to physical
    /// 112.
    #[test]
    fn wccmp002_virs_fourteen_allocation_table_blocks_resolve_every_live_claim() {
        let path = "archive/modules/majormud-nt/wccnt8pj/out/wccmp002.vir";
        let Ok(bytes) = std::fs::read(corpus_path(path)) else {
            eprintln!("no archive/ on this box, nothing verified");
            return;
        };
        let id = identify(&bytes).expect("a v6 file");
        let page_size = id.page_size as usize;
        assert_eq!(bytes.len() % page_size, 0);
        let total_pages = bytes.len() / page_size;
        assert_eq!(total_pages, 13_607);

        let (blocks, physical) =
            v6_allocation_table(&bytes, page_size, total_pages).expect("a well-formed table");
        assert_eq!(blocks.len(), 14, "wccmp002.vir has 14 allocation-table blocks");

        // Block 1 (index 0): shadow pair physical 2/3, live at physical 3
        // (generation 285 > 1) -- both copies carried, not just the live
        // one.
        assert_eq!(blocks[0].live.block, 1);
        assert_eq!(blocks[0].live.generation, 285);
        assert_eq!(blocks[0].stale.generation, 1);
        assert!(!blocks[0].live_is_first, "physical 3 (second) is live, not physical 2");

        // Block 14 (index 13): shadow pair physical 13314/13315, live at
        // physical 13315 (generation 285 > 279).
        assert_eq!(blocks[13].live.block, 14);
        assert_eq!(blocks[13].live.generation, 285);
        assert_eq!(blocks[13].stale.generation, 279);
        assert!(!blocks[13].live_is_first, "physical 13315 (second) is live, not 13314");

        assert_eq!(physical.len(), 13_568, "13,568 of 13,571 possible logical ids are claimed");
        assert_eq!(physical.get(&1), Some(&13_603));
        assert_eq!(physical.get(&2), Some(&8));
        assert_eq!(physical.get(&3), Some(&112));
        assert_eq!(
            physical.keys().copied().max(),
            Some(13_571),
            "the highest claimed logical id is 13,571 (PAGES - 1)"
        );
    }

    /// Every allocation-table entry [`v6_allocation_table`] resolves must
    /// round-trip through the canvas byte for byte -- both shadow copies of
    /// every block, not just the live one, the same discipline
    /// `resolve_shadow`'s own control-record pair already earns.
    #[test]
    fn wccmp002_virs_allocation_table_blocks_round_trip_both_shadow_copies() {
        let path = "archive/modules/majormud-nt/wccnt8pj/out/wccmp002.vir";
        let Ok(bytes) = std::fs::read(corpus_path(path)) else {
            eprintln!("no archive/ on this box, nothing verified");
            return;
        };
        let id = identify(&bytes).expect("a v6 file");
        let page_size = id.page_size as usize;
        let total_pages = bytes.len() / page_size;

        let (blocks, _physical) =
            v6_allocation_table(&bytes, page_size, total_pages).expect("a well-formed table");

        for (n, block) in blocks.iter().enumerate() {
            let index = n + 1;
            let (first, second) = alloc::pair_position(page_size, index);
            let (live_page, stale_page) =
                if block.live_is_first { (first, second) } else { (second, first) };

            let mut live_canvas = crate::canvas::Canvas::new(page_size);
            crate::emit::write_v6_allocation_copy(&mut live_canvas, &block.live, 0, page_size)
                .expect("the live copy is fully described");
            let live_emitted = live_canvas.finish().expect("every byte written exactly once");
            assert_eq!(
                live_emitted.bytes(),
                &bytes[live_page * page_size..(live_page + 1) * page_size],
                "block {index}'s live copy (physical {live_page}) must reproduce byte for byte"
            );

            let mut stale_canvas = crate::canvas::Canvas::new(page_size);
            crate::emit::write_v6_allocation_copy(&mut stale_canvas, &block.stale, 0, page_size)
                .expect("the stale copy is fully described");
            let stale_emitted = stale_canvas.finish().expect("every byte written exactly once");
            assert_eq!(
                stale_emitted.bytes(),
                &bytes[stale_page * page_size..(stale_page + 1) * page_size],
                "block {index}'s stale copy (physical {stale_page}) must reproduce byte for byte"
            );
        }
    }

    /// Required mutation: resolving a logical id as if it were a physical
    /// one. Every v6 file with more than three pages must go red -- the
    /// resolved physical page for logical 2 must *not* equal 2 itself
    /// (which is what "treat logical as physical" would produce), and must
    /// instead be whatever the table's own entry actually names.
    #[test]
    fn logical_ids_are_not_physical_page_numbers() {
        let path = "archive/modules/majormud-nt/wccnt8pj/out/wccmp002.vir";
        let Ok(bytes) = std::fs::read(corpus_path(path)) else {
            eprintln!("no archive/ on this box, nothing verified");
            return;
        };
        let id = identify(&bytes).expect("a v6 file");
        let page_size = id.page_size as usize;
        let total_pages = bytes.len() / page_size;
        let (_blocks, physical) =
            v6_allocation_table(&bytes, page_size, total_pages).expect("a well-formed table");

        // If resolution treated logical ids as physical page numbers, this
        // crate would never even build this map (there would be nothing to
        // resolve *through*) -- the mutation this guards against is a
        // caller substituting `logical` for `physical.get(&logical)`. Both
        // measured values disagree with their own logical id, which is
        // exactly what a "logical == physical" bug would get wrong.
        assert_ne!(physical.get(&1), Some(&1), "logical 1 must not resolve to physical 1");
        assert_eq!(physical.get(&1), Some(&13_603));
        assert_ne!(physical.get(&2), Some(&2), "logical 2 must not resolve to physical 2");
        assert_eq!(physical.get(&2), Some(&8));
    }

    /// Second required mutation: flip which shadow copy of an
    /// allocation-table block is treated as live. Block 1's own two copies
    /// carry different generations (1 and 285) and materially different
    /// entry arrays -- swapping them changes the resolved physical page for
    /// logical ids in that block's own range, so this is a real catch, not
    /// a vacuous one.
    #[test]
    fn swapping_a_blocks_live_and_stale_copy_changes_the_resolved_physical_page() {
        let path = "archive/modules/majormud-nt/wccnt8pj/out/wccmp002.vir";
        let Ok(bytes) = std::fs::read(corpus_path(path)) else {
            eprintln!("no archive/ on this box, nothing verified");
            return;
        };
        let id = identify(&bytes).expect("a v6 file");
        let page_size = id.page_size as usize;
        let total_pages = bytes.len() / page_size;
        let (blocks, physical) =
            v6_allocation_table(&bytes, page_size, total_pages).expect("a well-formed table");

        // Correct resolution: logical 1 (block 1, slot 0) is physical
        // 13,603, from block 1's *live* copy (generation 285, physical 3).
        assert_eq!(physical.get(&1), Some(&13_603));

        // The mutation: pretend the *stale* copy (generation 1, physical 2)
        // is live instead -- exactly what a shadow-pair selection bug
        // (picking the lower generation, or an unconditional "first
        // physical position wins") would do. Block 1's own stale entry for
        // slot 0 must disagree with the live one, or this mutation could
        // not be caught by anything -- it does, which is the point of this
        // test rather than an assumption.
        let stale_slot0 = blocks[0].stale.entries[0];
        let live_slot0 = blocks[0].live.entries[0];
        assert_ne!(
            stale_slot0.physical_page, live_slot0.physical_page,
            "block 1's two copies must genuinely disagree on slot 0, or a \
             swapped-copy bug could not be observed here"
        );
        assert_ne!(
            u32::from(stale_slot0.physical_page),
            *physical.get(&1).expect("logical 1 resolves"),
            "the stale copy's own claim for logical 1 must differ from the \
             correctly-resolved (live-copy) answer"
        );
    }

    /// Task 16's own failing-test-first: a named corpus file per page size
    /// this corpus's v6 family actually uses above 512 (1024, 1536, 2048,
    /// 3584, 4096) round-trips its *whole* physical page 0 -- fixed
    /// portion, key/segment definitions, and (Task 16) the
    /// definition-offset trailer plus its surrounding padding -- byte for
    /// byte. Before Task 16 this could not be attempted at all:
    /// `v6_page_tail` and `emit::write_v6_page_tail` did not exist, and
    /// nothing described the region past the key/segment definitions.
    fn assert_whole_page_zero_round_trips(path: &str, expected_page_size: u16) {
        let Ok(bytes) = std::fs::read(corpus_path(path)) else {
            eprintln!("no archive/ on this box, nothing verified: {path}");
            return;
        };
        let id = identify(&bytes).expect("a v6 file");
        assert_eq!(id.page_size, expected_page_size, "{path}");
        let page_size = id.page_size as usize;

        // Physical page 0 itself, live or stale -- both copies share the
        // same parsing rules, and this test is about page 0's own
        // description, not shadow resolution (Ruling 7 is exercised
        // elsewhere).
        let page0 = &bytes[0..page_size];
        let control = v6_control_record(page0);
        let descriptors =
            key_descriptors(page0, page_size, control.keys).expect("a well-formed key array");
        let tail = v6_page_tail(page0, page_size, &descriptors).expect("a well-formed trailer");

        let mut canvas = crate::canvas::Canvas::new(page_size);
        crate::emit::write_v6_fixed_portion(&mut canvas, id.generation, id.page_size, &control, 0)
            .expect("the fixed portion is fully described");
        crate::emit::write_v6_page_tail(&mut canvas, page_size, &descriptors, &tail)
            .expect("the key/segment definitions and trailer are fully described");
        let emitted = canvas.finish().expect("every byte of page 0 written exactly once");

        assert_eq!(emitted.bytes(), page0, "{path}: whole page 0 must reproduce byte for byte");
    }

    #[test]
    fn elwglobn_dat_page_size_1024_whole_page_zero_round_trips() {
        assert_whole_page_zero_round_trips(
            "archive/modules/elwynor/elwglob/Dist/ELWGLOBN.DAT",
            1024,
        );
    }

    #[test]
    fn wccacms2_nu1_page_size_1536_whole_page_zero_round_trips() {
        assert_whole_page_zero_round_trips(
            "archive/modules/majormud-nt/wccnt7py/out/wccacms2.nu1",
            1536,
        );
    }

    #[test]
    fn wcctext2_vir_page_size_2048_whole_page_zero_round_trips() {
        assert_whole_page_zero_round_trips(
            "archive/modules/majormud-nt/wccnt7py/out/gcvirdat/WCCTEXT2.VIR",
            2048,
        );
    }

    #[test]
    fn elwglobu_dat_page_size_3584_whole_page_zero_round_trips() {
        assert_whole_page_zero_round_trips(
            "archive/modules/elwynor/elwglob/Dist/ELWGLOBU.DAT",
            3584,
        );
    }

    /// `WCCBANK2.VIR` has `KEYS=1` realized as 2 key/segment definitions
    /// (harvest 2's own "PAGES, worked" file) -- its trailer exercises the
    /// zero-padded continuation slot this task's own census found (one real
    /// offset, one zero), not just the trivial single-definition case the
    /// other four files above give. Its continuation (`def1`) is the *last*
    /// definition in the file, so this alone cannot distinguish the
    /// compacted rule from the (wrong) positional one -- see
    /// `galtela_dat_page_size_4096_whole_page_zero_round_trips` below for
    /// the fixture that can.
    #[test]
    fn wccbank2_vir_page_size_4096_whole_page_zero_round_trips() {
        assert_whole_page_zero_round_trips(
            "archive/modules/majormud-nt/wccnt8pj/out/WCCBANK2.VIR",
            4096,
        );
    }

    /// `GALTELA.DAT` has `KEYS=3` realized as 4 definitions: `def0`
    /// independent, `def1` a continuation, then `def2`/`def3` independent
    /// -- a continuation that is *not* the last definition in the file.
    /// This is the shape a code review found missing from every other
    /// fixture in this file: the positional rule (slot `n` = `base(n)` when
    /// definition `n` is independent, `0` otherwise) and the true compacted
    /// rule (`format::fcr::trailer::expected_entries`: each independent
    /// segment's offset packed into the *next free slot*, in order) only
    /// disagree once an independent segment follows a continuation, and
    /// none of `ELWGLOBN.DAT`/`wccacms2.nu1`/`WCCTEXT2.VIR`/`ELWGLOBU.DAT`/
    /// `WCCBANK2.VIR` has that shape. `GALTELA.DAT`'s own measured trailer
    /// is `0x0110, 0x014c, 0x016a, 0x0000` -- `def3`'s offset (`0x016a`)
    /// compacted into slot 2, not sitting at slot 3 where its own
    /// definition index would place it.
    #[test]
    fn galtela_dat_page_size_4096_whole_page_zero_round_trips() {
        assert_whole_page_zero_round_trips(
            "archive/tooling/wbtrv32/assets/GALTELA.DAT",
            4096,
        );
    }

    /// `file`'s own refusal, for the same file, names the copy Ruling 7
    /// resolved rather than repeating the old blanket "v6 is not described"
    /// -- the shift this task exists to make: not just refused, but refused
    /// for a later, more specific reason than before.
    #[test]
    fn the_refusal_names_the_live_copy_it_resolved() {
        let path = "archive/modules/majormud-nt/wccnt8pj/out/wccmp002.vir";
        let Ok(bytes) = std::fs::read(corpus_path(path)) else {
            eprintln!("no archive/ on this box, nothing verified");
            return;
        };
        let e = file(&bytes).expect_err("v6 pages are not yet described");
        assert!(e.why.contains("page 1"), "{}", e.why);
        assert!(e.why.contains("285"), "{}", e.why);
        assert!(
            !e.why.contains("every byte of a v6 control record"),
            "the old blanket refusal text must be gone: {}",
            e.why
        );

        // Task 15: the refusal moved further along than Ruling 7's own
        // shadow-pair message -- it now names the live copy's own
        // fixed-portion geometry and how many key/segment definitions its
        // walk actually assembled, not just which physical page and
        // generation is live.
        assert!(e.why.contains("KEYS=1"), "names the key count: {}", e.why);
        assert!(
            e.why.contains("1 key/segment definitions"),
            "names the definition count the walk assembled: {}",
            e.why
        );
        assert!(e.why.contains("RECORDS=26720"), "names the live record count: {}", e.why);
        assert!(
            e.why.contains("PAGES=13572"),
            "names the LOGICAL page count (13,572), not the file's 13,607 \
             physical pages: {}",
            e.why
        );
        assert!(
            !e.why.contains("PAGES=13607") && !e.why.contains("PAGES=13,607"),
            "must not report the physical page count as PAGES: {}",
            e.why
        );

        // Task 17: the refusal moved past the allocation table too -- it
        // now names how many blocks this 14-block file has and how many of
        // its 13,571 possible logical ids the live table actually
        // resolves (13,568; the gap is unclaimed headroom, not a refusal),
        // against the file's 13,607 physical pages -- a *different*,
        // correctly-labeled use of the physical count than the PAGES
        // conflation the assertion above guards against.
        assert!(e.why.contains("14 block"), "names the block count: {}", e.why);
        assert!(e.why.contains("13568 logical"), "names the resolved logical count: {}", e.why);
        assert!(
            e.why.contains("out of 13607 physical pages"),
            "names the total physical page count, correctly labeled: {}",
            e.why
        );
        assert!(
            e.why.contains("cannot resolve page content past addressing"),
            "the refusal is now about content, not addressing: {}",
            e.why
        );
    }

    /// A tie is refused rather than resolved. No corpus file has ever tied,
    /// so this rejects a shape never observed -- not one observed and merely
    /// inconvenient.
    #[test]
    fn two_control_records_of_equal_generation_are_refused() {
        let bytes = two_copies_with_generations(7, 7);
        let refusal = file(&bytes).expect_err("a tie has no answer");
        assert!(refusal.why.contains("generation"), "names the test that failed: {}", refusal.why);
    }

    /// A file shorter than its own declared page size is refused, naming
    /// both numbers.
    #[test]
    fn a_file_shorter_than_its_own_page_is_refused() {
        let mut buf = usracc_fixed_portion();
        buf.truncate(256);
        let e = file(&buf).expect_err("shorter than page_size");
        assert!(e.why.contains("256"), "{}", e.why);
        assert!(e.why.contains("512"), "{}", e.why);
    }

    /// Task 13, Group A: a page-size-1024 file with a nonzero byte in page
    /// 0's tail (past the historical 512-byte control record) is accepted --
    /// not refused -- and the tail is captured verbatim in
    /// `File::page_zero_tail`. This replaces the old
    /// `nonzero_zero_padding_is_refused_and_names_the_offset`: the assertion
    /// it exercised named a property (page 0's tail is always zero) that two
    /// real corpus files (`wccitems.nu1` and its sibling) disprove, so this
    /// crate now carries the tail rather than refusing a file for disagreeing
    /// with a rule the format never actually enforced.
    #[test]
    fn nonzero_page_zero_tail_is_carried_verbatim_not_refused() {
        let mut buf = usracc_fixed_portion();
        buf[0x08..0x0a].copy_from_slice(&1024u16.to_le_bytes());
        buf.resize(1024, 0);
        buf[600] = 0xaa;
        let model = file(&buf).expect("a nonzero page-0 tail is not a refusal");
        let after_definitions = key_descriptor::base(model.key_descriptors.len());
        assert_eq!(after_definitions, 0x12e, "one key descriptor, tail starts right after it");
        let mut expected = vec![0u8; 1024 - after_definitions];
        expected[600 - after_definitions] = 0xaa;
        assert_eq!(model.page_zero_tail, expected, "the nonzero byte is carried, at its own offset");
    }

    /// USRACC.DAT's own single key/segment definition (measured directly off
    /// the real file when this task was dispatched): root 1, records 2,
    /// key_length 10, entry_size 18 (key_length + 8, no duplicates),
    /// max_entries 27, half_entries 13, chain/offset 0, length 10 -- and
    /// `root`'s top byte (`key_number`) is 0, unexercised on this file like
    /// every other v5 corpus file measured.
    #[test]
    fn usracc_dats_key_descriptor_decodes_root_and_records() {
        // Calls `key_descriptors` directly rather than going through
        // `file`: this test is about the key/segment definition array's own
        // decode, not the page graph, and `usracc_first_page` is
        // deliberately truncated to page 0 alone -- since Task 11b, `file`
        // itself refuses that (the descriptor's `root_page` names a page
        // the buffer does not contain), which is a different, correct
        // concern this test is not the place to exercise.
        let buf = usracc_first_page();
        let control = control_record(&buf);
        let descriptors =
            key_descriptors(&buf, 512, control.keys).expect("a valid descriptor array");
        assert_eq!(descriptors.len(), 1, "USRACC.DAT has exactly one definition");
        let d = &descriptors[0];
        assert_eq!(d.key_number, 0, "unexercised on v5 -- always 0 in the corpus");
        assert_eq!(d.root_page, 1, "root");
        assert_eq!(d.records, 2, "records");
        assert_eq!(d.attributes, 0, "attributes");
        assert_eq!(d.key_length, 10, "key_length");
        assert_eq!(d.entry_size, 18, "entry_size");
        assert_eq!(d.max_entries, 27, "max_entries");
        assert_eq!(d.half_entries, 13, "half_entries");
        assert_eq!(d.chain, 0, "chain");
        assert_eq!(d.offset, 0, "offset");
        assert_eq!(d.length, 10, "length");
        assert_eq!(d.self_tag, 0);
        assert_eq!(d.extended, 0);
        assert_eq!(d.null_value, 0);
    }

    /// The mask that matters: `ROOT`'s top byte is `key_number`, the low 24
    /// bits are `root_page`. No real v5 corpus file exercises a nonzero top
    /// byte (0 of 307 definitions measured for this task), so this fixture
    /// is synthetic, styled after `MULTIACS.DAT`'s own (v6) bytes -- see
    /// `two_key_fixed_portion`'s doc comment. This is the test the brief's
    /// mutation (masking 31 bits instead of 24) must turn red: with a
    /// 31-bit mask, key 1's `root_page` reads `0x01000004` instead of `4`.
    #[test]
    fn a_multi_key_files_root_pointers_decode_the_top_byte_and_low_24_bits() {
        // Calls `key_descriptors` directly, not `file` -- see
        // `usracc_dats_key_descriptor_decodes_root_and_records`'s own note.
        // `two_key_fixed_portion` names roots 3 and 4 in a 1-page buffer
        // purely to exercise the mask on the raw `ROOT` word; neither page
        // is meant to exist, so a walk (Task 11b) is not this test's
        // concern.
        let buf = two_key_fixed_portion();
        let control = control_record(&buf);
        let descriptors =
            key_descriptors(&buf, 512, control.keys).expect("a valid descriptor array");
        assert_eq!(descriptors.len(), 2);
        assert_eq!(descriptors[0].key_number, 0x80);
        assert_eq!(descriptors[0].root_page, 3);
        assert_eq!(descriptors[1].key_number, 0x81);
        assert_eq!(descriptors[1].root_page, 4, "not 0x01000004");
    }

    /// A segment chain that never closes (every definition sets ANOSEG) runs
    /// out of the format's own ceiling (SEGMAX = 24) before KEYS keys are
    /// assembled. The refusal names the key that opened the chain --
    /// `key_descriptor[0]` -- not just the definition where the walk gave up.
    #[test]
    fn a_segment_chain_that_never_terminates_is_refused_and_names_the_key_it_opened() {
        let mut buf = usracc_fixed_portion();
        buf[0x08..0x0a].copy_from_slice(&1024u16.to_le_bytes()); // page_size = 1024
        buf.resize(1024, 0);
        buf[0x14..0x16].copy_from_slice(&1u16.to_le_bytes()); // keys = 1
        for n in 0..24 {
            let attrs_at = 0x110 + n * 0x1e + 0x08;
            buf[attrs_at..attrs_at + 2].copy_from_slice(&0x10u16.to_le_bytes()); // ANOSEG
        }
        let e = file(&buf).expect_err("a chain that never closes is malformed");
        assert!(e.why.contains("key_descriptor[0]"), "names the key that opened the chain: {}", e.why);
        assert!(e.why.contains("SEGMAX"), "names the ceiling: {}", e.why);
    }

    /// A segment chain that runs past the end of the control record itself
    /// (rather than exhausting SEGMAX first) is refused too, naming both the
    /// definition that overran and the key it was continuing.
    #[test]
    fn a_segment_chain_that_runs_past_the_page_is_refused_and_names_both_definitions() {
        let mut buf = usracc_fixed_portion(); // page_size = 512
        buf[0x14..0x16].copy_from_slice(&1u16.to_le_bytes()); // keys = 1
        for n in 0..8 {
            let attrs_at = 0x110 + n * 0x1e + 0x08;
            buf[attrs_at..attrs_at + 2].copy_from_slice(&0x10u16.to_le_bytes()); // ANOSEG
        }
        let e = file(&buf).expect_err("definition 8 would run past the 512-byte page");
        assert!(e.why.contains("key_descriptor[8]"), "names the overrunning definition: {}", e.why);
        assert!(e.why.contains("key_descriptor[0]"), "names the key it continues: {}", e.why);
        assert!(e.why.contains("512-byte control record"), "{}", e.why);
    }

    /// `USRACC.DAT`'s three page headers, the exact case this task was
    /// dispatched to make pass: page 0's own header bytes are the control
    /// record's always-zero `lead` (already checked by
    /// `usracc_dat_fixed_portion_reads_its_measured_values` above -- nothing
    /// new to assert there), page 1 is the index page its one key's root
    /// names, and page 2 is everything else -- a data page.
    #[test]
    fn usracc_dats_three_page_headers_are_measured_correctly() {
        let buf = usracc_dat();
        let file = file(&buf).expect("a valid three-page v5 file");
        assert_eq!(file.pages.len(), 2, "physical pages 1 and 2");

        let page1 = &file.pages[0];
        assert_eq!(page1.number, 1, "page 1's own header number");
        assert_eq!(page1.stamp, 3, "page 1's stamp");
        assert!(!page1.data_bit, "page 1 holds a B-tree node, not records");
        assert_eq!(page1.kind, PageKind::Index, "named by key_descriptor[0]'s root");

        let page2 = &file.pages[1];
        assert_eq!(page2.number, 2, "page 2's own header number");
        assert_eq!(page2.stamp, 6, "page 2's stamp");
        assert!(page2.data_bit, "page 2 holds USRACC.DAT's two records");
        assert_eq!(page2.kind, PageKind::Data, "claimed by no root, ACS, or free chain");
    }

    /// Step 1 of this task: `USRACC.DAT` page 2 holds exactly two records at
    /// the measured offsets (`0x06` and `0x102`, `physical` 252 bytes
    /// apart), and the page's trailing 2 bytes (`512 - 6 - 2*252`, the same
    /// arithmetic `PAGE_USABLE` corroborates) are described rather than
    /// silently dropped -- they are zero in this real file, but the model
    /// must carry them explicitly, not assume it.
    #[test]
    fn usracc_dats_page_two_holds_exactly_two_records_at_the_measured_offsets() {
        let buf = usracc_dat();
        let file = file(&buf).expect("a valid three-page v5 file");
        let page2 = &file.pages[1];
        assert_eq!(page2.kind, PageKind::Data, "page 2 holds USRACC.DAT's two records");

        let content = page2.content.as_ref().expect("a data page's content is described");
        assert_eq!(content.slots.len(), 2, "two 252-byte slots fit in a 512-byte page");
        let RecordSlot::Live(slot0) = &content.slots[0] else {
            panic!("USRACC.DAT has no deletions -- slot 0 must be live")
        };
        let RecordSlot::Live(slot1) = &content.slots[1] else {
            panic!("USRACC.DAT has no deletions -- slot 1 must be live")
        };
        assert_eq!(slot0.len(), 252);
        assert_eq!(slot1.len(), 252);
        assert!(slot0.starts_with(b"Sysop"), "slot 0 at page offset 0x06 is the Sysop record");
        assert!(slot1.starts_with(b"Test"), "slot 1 at page offset 0x102 is the Test record");
        assert_eq!(content.slack, vec![0u8, 0], "the trailing 2 bytes, described and zero here");
    }

    /// Task 12, step 1: this crate's clean, unambiguous single-deletion
    /// witness (harvest 5 SS6.2) -- `wccnt7pz/out/wccitem2.vir` (and its
    /// byte-identical sibling under `wccnt7py`), 1,736 live records plus
    /// exactly one freed slot, physical page 591 slot 2 (file position
    /// `0x24f866`). The full corpus file currently refuses for an unrelated
    /// reason -- physical page 593 is an orphaned B-tree leaf no key's walk
    /// reaches (Task 11b) -- so this test isolates page 591 alone the same
    /// way `emit::tests::a_real_files_nonzero_slack_...` isolates page 592:
    /// a synthetic zero-key control record puts the real page directly
    /// after page 0, so nothing about the orphan elsewhere can interfere.
    ///
    /// This is the model-level claim a byte round trip cannot make on its
    /// own: not just that the bytes come back, but that this crate knows
    /// slot 2 is *free*, decodes its forwarding link as `NOWHERE` (this
    /// file's one deletion was also its first), and that the remaining
    /// 1,068 bytes are the zero fill the delete left -- structure, not
    /// bytes that merely happen to round-trip.
    #[test]
    fn wccitem2_vir_page_591_decodes_its_one_free_slot_as_free_with_a_nowhere_link() {
        let Some(root) = crate::corpus::root() else {
            eprintln!("read: no archive/ on this box, nothing verified");
            return;
        };
        let path = root.join("modules/majormud-nt/wccnt7pz/out/wccitem2.vir");
        let Ok(real) = std::fs::read(&path) else {
            eprintln!("read: wccitem2.vir not present, nothing verified");
            return;
        };

        const PAGE_SIZE: usize = 4096;
        const PHYSICAL: u16 = 1072;
        let page_591 = &real[591 * PAGE_SIZE..592 * PAGE_SIZE];

        // The free slot's new absolute position once page 591 becomes this
        // synthetic file's only page (page number 1): header (6) plus two
        // live slots ahead of it.
        let free_at: u32 = (PAGE_SIZE + page::LEN + 2 * PHYSICAL as usize) as u32;

        let mut original = vec![0u8; PAGE_SIZE];
        original[0x06..0x08].copy_from_slice(&[0, 4]); // version -> V5R4, this file's own generation
        original[0x08..0x0a].copy_from_slice(&(PAGE_SIZE as u16).to_le_bytes());
        original[0x0c..0x10].copy_from_slice(&0xffff_ffffu32.to_le_bytes()); // unknown_0c = NOWHERE
        original[0x10..0x14].copy_from_slice(&crate::pages::to_long(free_at)); // FREE: high-word-first long
        original[0x14..0x16].copy_from_slice(&0u16.to_le_bytes()); // keys = 0
        original[0x16..0x18].copy_from_slice(&PHYSICAL.to_le_bytes()); // reclen
        original[0x18..0x1a].copy_from_slice(&PHYSICAL.to_le_bytes()); // physical
        original.extend_from_slice(page_591);

        let model = file(&original).expect("reads: a synthetic zero-key file wrapping page 591");
        assert_eq!(model.pages.len(), 1);
        assert_eq!(model.pages[0].kind, PageKind::Free, "one freed slot lives on this page");
        let content = model.pages[0].content.as_ref().expect("a data page's content is described");
        assert_eq!(content.slots.len(), 3, "3 whole 1072-byte slots fit in 4096 - 6 bytes");

        assert!(
            matches!(content.slots[0], RecordSlot::Live(_)),
            "slot 0 is one of the file's 1,736 live records"
        );
        assert!(
            matches!(content.slots[1], RecordSlot::Live(_)),
            "slot 1 is one of the file's 1,736 live records"
        );
        let RecordSlot::Free { next, fill } = &content.slots[2] else {
            panic!("slot 2 is this file's one and only freed slot")
        };
        assert_eq!(
            *next, 0xffff_ffff,
            "harvest 5 SS6.2: this file's one deletion was also its first, so its \
             forwarding link is NOWHERE, not a real position"
        );
        assert_eq!(fill.len(), 1072 - 4);
        assert!(fill.iter().all(|&b| b == 0), "harvest 5 SS2.1: a fresh delete's zero fill");

        let emitted =
            crate::emit::file(&model).expect("zero keys leaves nothing undescribed but this page");
        assert_eq!(
            emitted.bytes(),
            original.as_slice(),
            "the forwarding link and zero fill must come back verbatim"
        );
    }

    /// Task 12's harder real-corpus witness: `TTIHORBT.DAT` (harvest 5 SS7's
    /// own "ambiguous history" file) -- zero live records, a free chain
    /// threading through every slot the file has, at least 8 hops deep.
    /// Unlike `wccitem2.vir`, this file's full form already reads and
    /// round-trips today (no orphaned page elsewhere), so this test reads
    /// the real file directly rather than isolating one synthetic page.
    ///
    /// The forwarding links this asserts (`0x1006 -> 0x147a -> 0x107a ->
    /// 0x14ee`, measured independently off the file's own raw bytes) are
    /// **not** byte-order-symmetric -- a plain little-endian misread of
    /// `0x1006`'s own slot bytes (`00 00 06 10`) would read `0x10060000`, a
    /// different, still-plausible position. This is the discriminator a
    /// byte-identical round trip cannot make on its own: decoding every
    /// link the wrong way, consistently, still reproduces the same bytes
    /// (see this task's own report for the mutation that proves it) --
    /// only a model-level assertion of the *decoded value* can tell the two
    /// apart.
    #[test]
    fn ttihorbt_dat_free_chain_decodes_to_the_measured_positions() {
        let Some(root) = crate::corpus::root() else {
            eprintln!("read: no archive/ on this box, nothing verified");
            return;
        };
        let path =
            root.join("modules/isv-file-libraries/ISVTTI - Tessier Technologies/temp/TTIHORBT.DAT");
        let Ok(original) = std::fs::read(&path) else {
            eprintln!("read: TTIHORBT.DAT not present, nothing verified");
            return;
        };

        let model = file(&original).expect("TTIHORBT.DAT reads: 0 records, a threaded free chain");
        assert_eq!(model.live_control().free, 0x1006, "FCR 0x10: the chain's own head, measured");
        assert_eq!(model.live_control().physical, 116);

        // Walk the model's own pages to find every free slot's decoded
        // link, keyed by this slot's own absolute file position -- so the
        // assertions below read as "position X's link is Y," independent of
        // which physical page X happens to land on.
        let mut links: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
        let page_size = model.id.page_size as usize;
        for (i, p) in model.pages.iter().enumerate() {
            let Some(content) = &p.content else { continue };
            let page_number = i + 1;
            let mut at = page_number * page_size + page::LEN;
            for slot in &content.slots {
                if let RecordSlot::Free { next, .. } = slot {
                    links.insert(at as u32, *next);
                }
                at += match slot {
                    RecordSlot::Live(b) => b.len(),
                    RecordSlot::Free { fill, .. } => 4 + fill.len(),
                };
            }
        }

        assert_eq!(links.len() >= 8, true, "at least 8 hops deep (harvest 5 SS7)");
        assert_eq!(links.get(&0x1006), Some(&0x147a), "the chain's first hop");
        assert_eq!(links.get(&0x147a), Some(&0x107a), "the chain's second hop");
        assert_eq!(links.get(&0x107a), Some(&0x14ee), "the chain's third hop");
        assert_eq!(links.get(&0x14ee), Some(&0x1162), "the chain's fourth hop");

        let emitted = crate::emit::file(&model).expect("TTIHORBT.DAT: nothing undescribed");
        assert_eq!(emitted.bytes(), original.as_slice(), "the whole threaded chain round-trips");
    }

    /// This task's own anchor case: `USRACC.DAT` page 1's index content,
    /// decoded byte by byte against the raw bytes the controller measured
    /// when this task was dispatched. `count` 2, `rightmost`/`leftmost`
    /// both `NOWHERE` (a leaf with no children). Entry 0's key is `Sysop`
    /// (NUL-padded to 10 bytes), `head` `0x406` (file byte 1030 -- page 2
    /// starts at 1024, and the `Sysop` slot sits at page offset `0x06`),
    /// no `tail` (this key permits no duplicates), `child` `Some(NOWHERE)`
    /// -- a leaf, not the last entry. Entry 1's key is `Test`, `head`
    /// `0x502` (file byte 1282 -- page offset `0x102`), `child`
    /// `Some(0)` -- the last entry's literal-zero placeholder, not
    /// `NOWHERE`, exactly as harvest 4 SS4 describes. The 460 bytes after
    /// the last entry (`512 - 0x34`) are zero in this real file.
    #[test]
    fn usracc_dats_index_page_decodes_its_two_entries() {
        let buf = usracc_dat();
        let file = file(&buf).expect("a valid three-page v5 file");
        let page1 = &file.pages[0];
        assert_eq!(page1.kind, PageKind::Index);

        let idx = page1.index.as_ref().expect("an Index page's content is described");
        assert_eq!(idx.rightmost, 0xffff_ffff, "a leaf: no rightmost child");
        assert_eq!(idx.leftmost, 0xffff_ffff, "a leaf: no leftmost child");
        assert_eq!(idx.entries.len(), 2, "USRACC.DAT has exactly 2 records");

        let sysop = &idx.entries[0];
        assert_eq!(sysop.key, b"Sysop\0\0\0\0\0");
        assert_eq!(sysop.head, 0x0406, "file byte 1030 -- page 2 offset 0x06");
        assert_eq!(sysop.tail, None, "this key permits no duplicates");
        assert_eq!(sysop.child, Some(0xffff_ffff), "not the last entry: a leaf's NOWHERE");

        let test = &idx.entries[1];
        assert_eq!(test.key, b"Test\0\0\0\0\0\0");
        assert_eq!(test.head, 0x0502, "file byte 1282 -- page 2 offset 0x102");
        assert_eq!(test.tail, None);
        assert_eq!(test.child, Some(0), "the last entry's literal-zero placeholder, not NOWHERE");

        assert_eq!(idx.padding, vec![0u8; 512 - 0x34], "460 zero bytes after the last entry");
    }

    /// The last-entry **omission** branch, unwitnessed by any of the 102
    /// corpus files this task's own measurement found passing (fullest
    /// real index root: 42% of its page) -- a synthetic fixture styled
    /// after `WCCSPELS.VIR` (harvest 4 SS4): 50 entries of a 10-byte key
    /// in one 512-byte page, four bytes more than fits. The last entry's
    /// `child` is `None` (no bytes at all for it, not a present zero --
    /// contrast `usracc_dats_index_page_decodes_its_two_entries` above,
    /// which is the *present*-zero case), and `padding` is empty: the
    /// crafted page tiles the 512 bytes exactly, with nothing left over.
    #[test]
    fn a_full_pages_last_entry_omits_its_child_field_entirely() {
        let buf = full_index_page_with_an_omitted_last_child();
        let file = file(&buf).expect("a valid two-page v5 file");
        let page1 = &file.pages[0];
        assert_eq!(page1.kind, PageKind::Index);

        let idx = page1.index.as_ref().expect("an Index page's content is described");
        assert_eq!(idx.entries.len(), 50);
        for (n, entry) in idx.entries.iter().enumerate().take(49) {
            assert_eq!(entry.child, Some(0xffff_ffff), "entry {n}: a leaf, not the last entry");
        }
        assert_eq!(
            idx.entries[49].child, None,
            "the last entry has no room at all for its trailing child field"
        );
        assert_eq!(idx.padding, Vec::<u8>::new(), "the page tiles exactly -- nothing left over");
    }

    /// Finding 2 of this task's review: a **non-last** entry that would
    /// run past the page even counting its trailing `child` field must be
    /// refused by name, not read past this page's own bounds (and, when
    /// the page is the file's last, past the buffer itself, which used to
    /// panic rather than refuse). Only the *last* entry of a page may omit
    /// its child field (harvest 4 SS4) -- calling `read_index_page`
    /// directly (a private function in this same module) rather than
    /// building a whole synthetic file, since the malformed shape this
    /// test needs has no other reason to exist.
    #[test]
    fn a_non_last_entry_that_lacks_room_for_its_child_is_refused_not_a_panic() {
        // A self-contained 24-byte page: count 2, key_length 1, entry_size
        // 9 (unique). Entry 0 (not the last of 2) needs key(1)+head(4)=5
        // bytes to start (offset 16..21, which fits), but its child would
        // need bytes 21..25 -- past this 24-byte page, and this buffer is
        // exactly 24 bytes long, so an unchecked read would index past the
        // end of the slice itself.
        let page_size = 24usize;
        let mut page = vec![0u8; page_size];
        page[6..8].copy_from_slice(&2u16.to_le_bytes()); // count = 2
        page[8..12].copy_from_slice(&[0xff; 4]); // rightmost = NOWHERE
        page[12..16].copy_from_slice(&[0xff; 4]); // leftmost = NOWHERE

        let e = read_index_page(&page, 0, page_size, 1, 9, 0)
            .expect_err("entry 0 is not the last entry but has no room for its child");
        assert!(e.why.contains("entry 0"), "{}", e.why);
        assert!(e.why.contains("only the last entry"), "{}", e.why);
    }

    /// A real corpus file with deletions on record: `TTIHORBT.DAT`, 12
    /// 512-byte pages, `records` 0 (every record ever inserted has since
    /// been deleted). Its two keys' roots claim pages 1 and 2; the free
    /// chain from FCR 0x10 (measured directly off this file when this task
    /// was dispatched) visits every one of the remaining 9 pages, 3 through
    /// 11. This is the real file the brief's mutation step asks for -- no
    /// synthetic fixture was needed because this one already exists in the
    /// corpus.
    #[test]
    fn a_real_files_emptied_data_pages_classify_as_free() {
        let Some(root) = crate::corpus::root() else {
            eprintln!("read: no archive/ on this box, nothing verified");
            return;
        };
        let path = root
            .join("modules/isv-file-libraries/ISVTTI - Tessier Technologies/temp/TTIHORBT.DAT");
        let Ok(buf) = std::fs::read(&path) else {
            eprintln!("read: TTIHORBT.DAT not present, nothing verified");
            return;
        };
        let file = file(&buf).expect("TTIHORBT.DAT is a valid v5 file");
        assert_eq!(file.live_control().records, 0, "every record has been deleted");
        assert_eq!(file.pages.len(), 11, "12 physical pages, less page 0");
        assert_eq!(file.pages[0].kind, PageKind::Index, "page 1, key 0's root");
        assert_eq!(file.pages[1].kind, PageKind::Index, "page 2, key 1's root");
        for (i, page) in file.pages.iter().enumerate().skip(2) {
            assert_eq!(
                page.kind,
                PageKind::Free,
                "page {} should be free -- every record has been deleted",
                i + 1
            );
        }
    }

    /// A real corpus file with B-tree nodes no key root names: `FW_QSQDB.DA_`
    /// (13 1024-byte pages, three keys rooted at pages 1, 2, 8; also a
    /// variable-length file, `usrflgs` bit 0 set, `reclen` 101 `physical`
    /// 113). Measured directly off the file when this task's review was
    /// addressed: pages 4, 6, and 10 hold records (`data_bit` set) and are
    /// `Data`; pages 3, 7, 11, and 12 are B-tree nodes no root names
    /// (`data_bit` clear, and their own bytes do not match the
    /// fragment-page shape) and are `IndexChild`.
    ///
    /// **Pages 5 and 9 are `Variable`, not `IndexChild`** -- a correction
    /// this task's own dispatch made: the task that first wrote this test
    /// (before fragment pages were described at all) classified every
    /// unclaimed, data-bit-clear page here as `IndexChild` residually, with
    /// no positive evidence either way. Direct measurement for this task
    /// shows both pages match the fragment-page shape (fragment count in
    /// range, first live entry at exactly `0x0c`) *and* are genuinely
    /// reachable: every record slot on pages 4, 6, and 10 decodes a
    /// fragment pointer landing on page 5 or page 9 (`variable_scan.py`,
    /// this task's own corpus walk) -- the same "which fragment is this"
    /// bit-3 `Pointer::decode` this task's mutation test exercises. Pages
    /// 3, 7, 11, and 12 remain genuine `IndexChild`: their own fragment
    /// count reads `0xffff`, out of the `1..=256` range the engine itself
    /// requires.
    #[test]
    fn a_real_files_unrooted_btree_nodes_classify_as_index_children() {
        let Some(root) = crate::corpus::root() else {
            eprintln!("read: no archive/ on this box, nothing verified");
            return;
        };
        let path = root.join(
            "modules/butt-care/DOS Software/BBS/MajorBBS/4EVER/Addons/Farwest Trivia v3.23a/COPY/FW_QSQDB.DA_",
        );
        let Ok(buf) = std::fs::read(&path) else {
            eprintln!("read: FW_QSQDB.DA_ not present, nothing verified");
            return;
        };
        let file = file(&buf).expect("FW_QSQDB.DA_ is a valid v5 file");
        assert_eq!(file.pages.len(), 12, "13 physical pages, less page 0");

        let kind_of = |page_number: usize| file.pages[page_number - 1].kind;
        for &root_page in &[1, 2, 8] {
            assert_eq!(kind_of(root_page), PageKind::Index, "page {root_page} is a key's root");
        }
        for &data_page in &[4, 6, 10] {
            assert_eq!(kind_of(data_page), PageKind::Data, "page {data_page} holds records");
        }
        for &fragment_page in &[5, 9] {
            assert_eq!(
                kind_of(fragment_page),
                PageKind::Variable,
                "page {fragment_page} is a fragment page real record pointers reach"
            );
        }
        for &child_page in &[3, 7, 11, 12] {
            assert_eq!(
                kind_of(child_page),
                PageKind::IndexChild,
                "page {child_page} is a B-tree node no root names"
            );
        }
    }

    /// Task 11b's own anchor: `FW_QSQDB.DAT` (the real, full-size file --
    /// 1,775 pages, three keys of three different widths: key 0 is 4 bytes,
    /// key 1 is 8, key 2 is 80 and permits duplicates) has a genuine
    /// multi-page tree under every one of its three keys (measured
    /// independently for this task: 123, 160, and 577 pages respectively).
    /// Page 734 is a real child reached only by key 1's own walk (its
    /// root's own `leftmost`); page 1057 only by key 2's. This is the test
    /// this task's required mutation (Step 6: attribute every `IndexChild`
    /// to key 0 instead of the key whose walk reached it) must turn red --
    /// and a byte-level round trip of the whole file cannot, on its own,
    /// prove that: `read_index_page`/`write_index_pages` are exact
    /// structural inverses of each other for *any* internally-consistent
    /// `(key_length, entry_size, duplicates)` triple that does not overrun
    /// the page, so misattributing page 734 to key 0's *narrower* 4-byte
    /// shape still reproduces the same bytes (a different partition of the
    /// identical byte range into "entries" versus "padding") without
    /// tripping any bounds check. Asserting the *decoded key width* here,
    /// rather than only the round trip, is what actually catches it.
    #[test]
    fn a_real_files_multi_key_btree_children_are_attributed_to_the_right_keys_width() {
        let Some(root) = crate::corpus::root() else {
            eprintln!("read: no archive/ on this box, nothing verified");
            return;
        };
        let path = root.join(
            "modules/butt-care/DOS Software/BBS/MajorBBS/4EVER/Addons/Farwest Trivia v3.23a/Addons/FW_QSQDB.DAT",
        );
        let Ok(buf) = std::fs::read(&path) else {
            eprintln!("read: FW_QSQDB.DAT not present, nothing verified");
            return;
        };
        let file = file(&buf).expect("FW_QSQDB.DAT is a valid v5 file");

        let page_734 = &file.pages[734 - 1];
        assert_eq!(page_734.kind, PageKind::IndexChild, "not a root itself");
        let idx_734 = page_734.index.as_ref().expect("attributed, so described");
        assert!(!idx_734.entries.is_empty(), "page 734 holds real entries");
        assert_eq!(
            idx_734.entries[0].key.len(),
            8,
            "page 734 is a child of key 1 (key_length 8), not key 0 (4)"
        );

        let page_1057 = &file.pages[1057 - 1];
        assert_eq!(page_1057.kind, PageKind::IndexChild, "not a root itself");
        let idx_1057 = page_1057.index.as_ref().expect("attributed, so described");
        assert!(!idx_1057.entries.is_empty(), "page 1057 holds real entries");
        assert_eq!(
            idx_1057.entries[0].key.len(),
            80,
            "page 1057 is a child of key 2 (key_length 80), not key 0 (4)"
        );
    }

    /// Two keys cannot share one root page -- if they did, this crate would
    /// have to guess which key's B-tree actually lives there. No corpus file
    /// does this (0 of 145 v5 files measured for this task), so the fixture
    /// is synthetic.
    #[test]
    fn two_keys_claiming_the_same_root_page_are_refused() {
        let mut buf = usracc_fixed_portion();
        buf.resize(1024, 0); // 2 pages, so page 1 is a real page
        buf[0x14..0x16].copy_from_slice(&2u16.to_le_bytes()); // keys = 2
        let def0 = 0x110;
        buf[def0..def0 + 4].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]); // root = 1
        let def1 = def0 + 0x1e;
        buf[def1..def1 + 4].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]); // root = 1 too
        let e = file(&buf).expect_err("both keys claim page 1");
        assert!(e.why.contains("key_descriptor[1]"), "{}", e.why);
        assert!(e.why.contains("page 1"), "{}", e.why);
    }

    /// A key cannot be both an index root and the ACS block at the same
    /// page -- if a key's root names page 1 and some key also declares
    /// `ALT_COLLATING` (which harvest 4 SS6a fixes at page 1), the file
    /// contradicts itself. Unmeasured in the corpus (0 of 145 v5 files); a
    /// synthetic fixture is the only way to exercise it.
    #[test]
    fn an_index_root_and_the_acs_block_on_the_same_page_are_refused() {
        let mut buf = usracc_fixed_portion();
        buf.resize(1024, 0);
        buf[0x14..0x16].copy_from_slice(&1u16.to_le_bytes()); // keys = 1
        let def0 = 0x110;
        buf[def0..def0 + 4].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]); // root = 1
        buf[def0 + 0x08..def0 + 0x0a].copy_from_slice(&0x20u16.to_le_bytes()); // ALT_COLLATING
        let e = file(&buf).expect_err("page 1 cannot be both an index root and the ACS block");
        assert!(e.why.contains("ACS"), "{}", e.why);
        assert!(e.why.contains("page 1"), "{}", e.why);
    }

    /// FCR `0x10a` naming an ACS page while no key declares `ALT_COLLATING`
    /// is the mirror of harvest 4 SS6a's known false negative (a declared
    /// sequence the pointer misses) -- a false *positive* the pointer alone
    /// cannot be trusted to invent. Unmeasured in the corpus; synthetic.
    #[test]
    fn an_acs_pointer_with_no_declaring_key_is_refused() {
        let mut buf = usracc_first_page(); // keys = 1, attributes = 0 (no ALT_COLLATING)
        buf[0x10a..0x10e].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]); // acs_page_pointer = 1
        let e = file(&buf).expect_err("no key corroborates the pointer");
        assert!(e.why.contains("0x10a"), "{}", e.why);
        assert!(e.why.contains("ALT_COLLATING"), "{}", e.why);
    }

    /// A free chain that revisits a position it has already visited does not
    /// terminate cleanly and is refused rather than looped forever.
    #[test]
    fn a_free_chain_that_cycles_is_refused() {
        let mut buf = usracc_fixed_portion();
        buf.resize(1536, 0); // 3 pages
        buf[0x10..0x14].copy_from_slice(&[0x00, 0x00, 0x06, 0x02]); // free = 518 (0x206)
        buf[0x206..0x20a].copy_from_slice(&[0x00, 0x00, 0x06, 0x02]); // next = 518 too
        let e = file(&buf).expect_err("the chain points back at itself");
        assert!(e.why.contains("revisits"), "{}", e.why);
    }

    /// The three page-kind *disagreement* refusal arms have no corpus
    /// fixture -- 281/281 index roots, 15/15 ACS pages, and 22/22
    /// free-chain pages agree with their own `data_bit` across the whole
    /// v5 corpus (`resolve_pages`'s own doc comment). Reachable but
    /// untested until now: three synthetic fixtures, one per arm.
    ///
    /// Arm 1: a key's root claims page 1 as an index root, but page 1's
    /// own header sets `data_bit` -- the page says it holds records, which
    /// contradicts the root claim.
    #[test]
    fn an_index_roots_own_data_bit_set_is_refused() {
        let mut buf = usracc_first_page(); // keys = 1, root = 1
        buf.resize(1024, 0); // page 0 plus page 1
        buf[512..516].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]); // page 1's own number = 1
        buf[516..518].copy_from_slice(&0x8003u16.to_le_bytes()); // data_bit set, stamp 3
        let e = file(&buf).expect_err("page 1 is an index root but data_bit is set");
        assert!(e.why.contains("index root"), "{}", e.why);
        assert!(e.why.contains("data_bit is set"), "{}", e.why);
    }

    /// Arm 2: a key declares `ALT_COLLATING`, which harvest 4 SS6a places
    /// the ACS block at physical page 1 -- but page 1's own header sets
    /// `data_bit`, contradicting the ACS claim.
    #[test]
    fn the_acs_pages_own_data_bit_set_is_refused() {
        let mut buf = usracc_first_page(); // keys = 1
        let def0 = 0x110;
        buf[def0 + 0x08..def0 + 0x0a].copy_from_slice(&0x20u16.to_le_bytes()); // ALT_COLLATING
        buf[0x14..0x16].copy_from_slice(&1u16.to_le_bytes()); // keys = 1
        // Point this key's own root elsewhere so it does not also claim
        // page 1 as an index root (that would hit arm 1's check first).
        buf[def0..def0 + 4].copy_from_slice(&[0x00, 0x00, 0x02, 0x00]); // root = 2
        buf.resize(1536, 0); // page 0, page 1 (ACS), page 2 (the root)
        buf[512..516].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]); // page 1's own number = 1
        buf[516..518].copy_from_slice(&0x8003u16.to_le_bytes()); // data_bit set, stamp 3
        buf[1024..1028].copy_from_slice(&[0x00, 0x00, 0x02, 0x00]); // page 2's own number = 2
        buf[1028..1030].copy_from_slice(&0x0003u16.to_le_bytes()); // data_bit clear
        let e = file(&buf).expect_err("page 1 is the ACS block but data_bit is set");
        assert!(e.why.contains("ACS"), "{}", e.why);
        assert!(e.why.contains("data_bit is set"), "{}", e.why);
    }

    /// Arm 3: the free chain from FCR `0x10` reaches page 1, but page 1's
    /// own header clears `data_bit` -- the page says it holds a B-tree
    /// node, contradicting the free-chain claim that a record slot lives
    /// there.
    #[test]
    fn a_free_pages_own_data_bit_clear_is_refused() {
        let mut buf = usracc_fixed_portion(); // no keys, so nothing else claims page 1
        buf.resize(1024, 0); // page 0 plus page 1
        buf[0x10..0x14].copy_from_slice(&[0x00, 0x00, 0x06, 0x02]); // free = 518 (page 1, offset 6)
        buf[512..516].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]); // page 1's own number = 1
        buf[516..518].copy_from_slice(&0x0003u16.to_le_bytes()); // data_bit clear, stamp 3
        buf[518..522].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]); // this slot's own [prev/next] terminates the chain
        let e = file(&buf).expect_err("the free chain reaches page 1 but data_bit is clear");
        assert!(e.why.contains("free chain"), "{}", e.why);
        assert!(e.why.contains("data_bit is clear"), "{}", e.why);
    }

    /// `enter_child`'s four refusal predicates (Task 11b review finding):
    /// a child pointer naming page 0, one running past the file, a cycle
    /// within one key's own tree, and two different keys' walks reaching
    /// the same page. Each fixture below drives exactly one of these --
    /// synthetic, since no corpus file happens to be malformed this way --
    /// built from minimal empty index pages (`count` 0 or 1, real
    /// `key_length`/`entry_size` so the walk actually decodes them rather
    /// than faulting on an unrelated mismatch first) so only the single
    /// targeted predicate can fire.

    /// A child pointer naming page 0 (the control record). The last
    /// entry's own `child` field is always a placeholder (harvest 4 SS4),
    /// so the walk never reads a descent target from it -- the page
    /// header's own `rightmost` slot is what stands in for the last
    /// entry's child, and this fixture sets *that* to 0: root (page 1) has
    /// one entry and a real `leftmost` child (page 2, a genuine empty
    /// leaf, descended into and exhausted first) so the walk is genuinely
    /// interior, then `rightmost` -- followed only after the root's one
    /// (and therefore last) entry -- is the literal value 0.
    #[test]
    fn a_child_pointer_naming_page_zero_is_refused() {
        let mut buf = usracc_fixed_portion();
        buf[0x14..0x16].copy_from_slice(&1u16.to_le_bytes()); // keys = 1
        let def0 = 0x110;
        buf[def0..def0 + 4].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]); // root = 1
        buf[def0 + 0x0a..def0 + 0x0c].copy_from_slice(&2u16.to_le_bytes()); // key_length
        buf[def0 + 0x0c..def0 + 0x0e].copy_from_slice(&10u16.to_le_bytes()); // entry_size
        buf.resize(1536, 0); // page 0, page 1 (root), page 2 (leftmost leaf)

        // Page 1: root, one entry, leftmost = 2 (real, interior), rightmost
        // = 0 (the control record -- not a real child, and this entry is
        // both the root's only and its last, so `rightmost` is what the
        // walk follows after it).
        buf[512..516].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]); // page 1 number = 1
        buf[512 + 6..512 + 8].copy_from_slice(&1u16.to_le_bytes()); // count = 1
        buf[512 + 8..512 + 12].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // rightmost = 0
        buf[512 + 12..512 + 16].copy_from_slice(&[0x00, 0x00, 0x02, 0x00]); // leftmost = 2
        // entry 0: key (2 bytes), head (4), child placeholder (4) -- values
        // do not matter, this entry is never used to name a child (it is
        // the last entry, so `rightmost` stands in for it).

        // Page 2: a genuine empty leaf -- the walk descends into it via
        // `leftmost` before it ever reaches the root's own entry/rightmost.
        buf[1024..1028].copy_from_slice(&[0x00, 0x00, 0x02, 0x00]); // page 2 number = 2
        buf[1024 + 8..1024 + 12].copy_from_slice(&[0xff; 4]); // rightmost = NOWHERE
        buf[1024 + 12..1024 + 16].copy_from_slice(&[0xff; 4]); // leftmost = NOWHERE

        let e = file(&buf).expect_err("the root's rightmost names page 0");
        assert!(e.why.contains("child page 0"), "{}", e.why);
        assert!(e.why.contains("control record"), "{}", e.why);
    }

    /// A child pointer naming a page past the end of the file -- the
    /// root's own `leftmost` names page 99 in a 2-page file.
    #[test]
    fn a_child_pointer_past_the_end_of_the_file_is_refused() {
        let mut buf = usracc_fixed_portion();
        buf[0x14..0x16].copy_from_slice(&1u16.to_le_bytes()); // keys = 1
        let def0 = 0x110;
        buf[def0..def0 + 4].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]); // root = 1
        buf[def0 + 0x0a..def0 + 0x0c].copy_from_slice(&2u16.to_le_bytes()); // key_length
        buf[def0 + 0x0c..def0 + 0x0e].copy_from_slice(&10u16.to_le_bytes()); // entry_size
        buf.resize(1024, 0); // page 0 plus page 1 only -- 2 pages total

        buf[512..516].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]); // page 1 number = 1
        buf[512 + 8..512 + 12].copy_from_slice(&[0xff; 4]); // rightmost = NOWHERE
        buf[512 + 12..512 + 16].copy_from_slice(&[0x00, 0x00, 99, 0x00]); // leftmost = 99

        let e = file(&buf).expect_err("leftmost names page 99 in a 2-page file");
        assert!(e.why.contains("page 99"), "{}", e.why);
        assert!(e.why.contains("has only 2 pages"), "{}", e.why);
    }

    /// A cycle within one key's own tree: root (1) -> page 2 -> page 3 ->
    /// back to page 2 (not the root itself, so the refusal can only come
    /// from the walk's own `visited` map, never from page 2 already being
    /// pre-claimed as some *other* kind before the walk starts).
    #[test]
    fn a_cycle_within_one_keys_own_tree_is_refused() {
        let mut buf = usracc_fixed_portion();
        buf[0x14..0x16].copy_from_slice(&1u16.to_le_bytes()); // keys = 1
        let def0 = 0x110;
        buf[def0..def0 + 4].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]); // root = 1
        buf[def0 + 0x0a..def0 + 0x0c].copy_from_slice(&2u16.to_le_bytes()); // key_length
        buf[def0 + 0x0c..def0 + 0x0e].copy_from_slice(&10u16.to_le_bytes()); // entry_size
        buf.resize(2048, 0); // page 0, pages 1-3

        // Page 1 (root): leftmost = 2, no entries needed to force descent.
        buf[512..516].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]);
        buf[512 + 8..512 + 12].copy_from_slice(&[0xff; 4]); // rightmost = NOWHERE
        buf[512 + 12..512 + 16].copy_from_slice(&[0x00, 0x00, 0x02, 0x00]); // leftmost = 2

        // Page 2: leftmost = 3.
        buf[1024..1028].copy_from_slice(&[0x00, 0x00, 0x02, 0x00]);
        buf[1024 + 8..1024 + 12].copy_from_slice(&[0xff; 4]);
        buf[1024 + 12..1024 + 16].copy_from_slice(&[0x00, 0x00, 0x03, 0x00]); // leftmost = 3

        // Page 3: leftmost = 2 -- back to page 2, already on this key's own
        // walk.
        buf[1536..1540].copy_from_slice(&[0x00, 0x00, 0x03, 0x00]);
        buf[1536 + 8..1536 + 12].copy_from_slice(&[0xff; 4]);
        buf[1536 + 12..1536 + 16].copy_from_slice(&[0x00, 0x00, 0x02, 0x00]); // leftmost = 2

        let e = file(&buf).expect_err("page 3's leftmost cycles back to page 2");
        assert!(e.why.contains("revisits page 2"), "{}", e.why);
        assert!(e.why.contains("cycle"), "{}", e.why);
    }

    /// Two different keys' walks reaching the same page: key 0's root
    /// (page 1) and key 1's root (page 2) both name page 3 as their own
    /// `leftmost`. Key 0's walk runs first (key descriptors are walked in
    /// order) and reaches page 3 cleanly; key 1's walk then reaches the
    /// same page and must refuse, naming both keys.
    #[test]
    fn two_different_keys_walks_reaching_the_same_page_is_refused() {
        let mut buf = usracc_fixed_portion();
        buf[0x14..0x16].copy_from_slice(&2u16.to_le_bytes()); // keys = 2
        let def0 = 0x110;
        buf[def0..def0 + 4].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]); // key 0 root = 1
        buf[def0 + 0x0a..def0 + 0x0c].copy_from_slice(&2u16.to_le_bytes());
        buf[def0 + 0x0c..def0 + 0x0e].copy_from_slice(&10u16.to_le_bytes());
        let def1 = def0 + 0x1e;
        buf[def1..def1 + 4].copy_from_slice(&[0x00, 0x00, 0x02, 0x00]); // key 1 root = 2
        buf[def1 + 0x0a..def1 + 0x0c].copy_from_slice(&2u16.to_le_bytes());
        buf[def1 + 0x0c..def1 + 0x0e].copy_from_slice(&10u16.to_le_bytes());
        buf.resize(2048, 0); // page 0, page 1 (key 0 root), page 2 (key 1 root), page 3 (shared)

        // Page 1 (key 0's root): leftmost = 3.
        buf[512..516].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]);
        buf[512 + 8..512 + 12].copy_from_slice(&[0xff; 4]);
        buf[512 + 12..512 + 16].copy_from_slice(&[0x00, 0x00, 0x03, 0x00]); // leftmost = 3

        // Page 2 (key 1's root): leftmost = 3 too.
        buf[1024..1028].copy_from_slice(&[0x00, 0x00, 0x02, 0x00]);
        buf[1024 + 8..1024 + 12].copy_from_slice(&[0xff; 4]);
        buf[1024 + 12..1024 + 16].copy_from_slice(&[0x00, 0x00, 0x03, 0x00]); // leftmost = 3

        // Page 3: a genuine empty leaf -- key 0's walk reaches it and
        // finishes cleanly before key 1's walk ever starts.
        buf[1536..1540].copy_from_slice(&[0x00, 0x00, 0x03, 0x00]);
        buf[1536 + 8..1536 + 12].copy_from_slice(&[0xff; 4]);
        buf[1536 + 12..1536 + 16].copy_from_slice(&[0xff; 4]);

        let e = file(&buf).expect_err("page 3 is reached by both keys' walks");
        assert!(e.why.contains("page 3"), "{}", e.why);
        assert!(e.why.contains("key_descriptor[0]"), "{}", e.why);
        assert!(e.why.contains("key_descriptor[1]"), "{}", e.why);
        assert!(e.why.contains("cannot belong to two keys"), "{}", e.why);
    }

    /// A free chain entry naming a position past the end of the file is
    /// refused, naming the file's own length.
    #[test]
    fn a_free_chain_past_the_end_of_the_file_is_refused() {
        let mut buf = usracc_fixed_portion();
        buf.resize(1536, 0); // 3 pages, 1536 bytes
        buf[0x10..0x14].copy_from_slice(&[0x00, 0x00, 0xfe, 0x05]); // free = 1534 (0x5fe)
        let e = file(&buf).expect_err("1534 + 4 runs past 1536 bytes");
        assert!(e.why.contains("past the end"), "{}", e.why);
    }

    /// A free chain entry naming a page an index root already claims is
    /// refused -- a B-tree page cannot also hold a freed record slot.
    #[test]
    fn a_free_chain_reaching_an_index_page_is_refused() {
        let mut buf = usracc_fixed_portion();
        buf.resize(1536, 0); // 3 pages
        buf[0x14..0x16].copy_from_slice(&1u16.to_le_bytes()); // keys = 1
        let def0 = 0x110;
        buf[def0..def0 + 4].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]); // root = 1
        // A real, walkable key -- Task 11b's own walk runs before the free
        // chain below, so the root must actually decode (key_length 2,
        // entry_size 10: the unique-key formula) rather than fault on its
        // own entry_size mismatch before the free-chain conflict this test
        // means to exercise ever gets a chance to fire.
        buf[def0 + 0x0a..def0 + 0x0c].copy_from_slice(&2u16.to_le_bytes()); // key_length
        buf[def0 + 0x0c..def0 + 0x0e].copy_from_slice(&10u16.to_le_bytes()); // entry_size
        // Page 1 itself: a genuine empty leaf (count 0, both child slots
        // NOWHERE) so the walk finds nothing further to descend into.
        buf[512 + 8..512 + 12].copy_from_slice(&[0xff; 4]); // rightmost = NOWHERE
        buf[512 + 12..512 + 16].copy_from_slice(&[0xff; 4]); // leftmost = NOWHERE
        buf[0x10..0x14].copy_from_slice(&[0x00, 0x00, 0x06, 0x02]); // free = 518 (page 1, offset 6)
        let e = file(&buf).expect_err("the free chain reaches page 1, an index root");
        assert!(e.why.contains("page 1"), "{}", e.why);
        assert!(e.why.contains("index root"), "{}", e.why);
    }

    /// Task 12 review finding: `read_data_page`'s guard against a free
    /// chain naming a slot too short to hold its own 4-byte forwarding
    /// link had no fixture driving it. Reachable by construction -- nothing
    /// upstream of `read_data_page` bounds `physical` below 4, so a
    /// synthetic zero-key file with `physical = 2` and the free chain
    /// pointing at its one data page reaches this arm directly. Without the
    /// guard, `fill: bytes[start + 4..start + physical]` would build a
    /// range whose start exceeds its end (`522..520`) and panic outright --
    /// this refusal is what stands between a malformed free chain and a
    /// crash, not decoration.
    #[test]
    fn a_free_slot_shorter_than_its_own_forwarding_link_is_refused() {
        let mut buf = usracc_fixed_portion(); // keys = 1, root = 0 -- claims nothing
        buf.resize(1024, 0); // page 0 plus page 1
        buf[0x16..0x18].copy_from_slice(&2u16.to_le_bytes()); // reclen = 2
        buf[0x18..0x1a].copy_from_slice(&2u16.to_le_bytes()); // physical = 2
        buf[0x10..0x14].copy_from_slice(&[0x00, 0x00, 0x06, 0x02]); // free = 518 (page 1, offset 6)
        buf[512..516].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]); // page 1 number = 1
        buf[516..518].copy_from_slice(&0x8003u16.to_le_bytes()); // data_bit set, stamp 3
        buf[518..522].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]); // this slot's own link: terminates the chain
        let e = file(&buf).expect_err("a 2-byte physical record cannot hold a 4-byte link");
        assert!(e.why.contains("too short to hold"), "{}", e.why);
        assert!(e.why.contains("2-byte physical record"), "{}", e.why);
        assert!(e.why.contains("slot 0"), "{}", e.why);
        assert!(e.why.contains("0x206"), "{}", e.why);
    }

    /// A real corpus file whose control record's own `0x10a` pointer agrees
    /// with the page graph: `WLDSLOTS.DAT` (V5R4, one key declaring
    /// `ALT_COLLATING`, table name `GALCAPS `). Its ACS block decodes at
    /// physical page 1, its tag is one of the two the engine accepts, its
    /// name matches the control record's own `acs_name` at `0x3c`, and its
    /// table is the corpus's uppercase fold (harvest 4 SS6b: `GALCAPS`
    /// names the same table as `UPPER`).
    #[test]
    fn a_real_files_acs_block_decodes_with_the_uppercase_fold() {
        let Some(root) = crate::corpus::root() else {
            eprintln!("read: no archive/ on this box, nothing verified");
            return;
        };
        let path = root.join(
            "modules/butt-care/DOS Software/BBS/MajorBBS/4EVER/Addons/\
             Wilderlands Slotto America v1.1R/COPY/WLDSLOTS.DAT",
        );
        let Ok(buf) = std::fs::read(&path) else {
            eprintln!("read: WLDSLOTS.DAT not present, nothing verified");
            return;
        };
        let model = file(&buf).expect("WLDSLOTS.DAT is a valid v5 file");
        assert_eq!(model.live_control().acs_page_pointer, 1, "0x10a agrees here");
        assert_eq!(&model.live_control().acs_name, b"GALCAPS ", "FCR 0x3c");

        assert_eq!(model.pages[0].kind, PageKind::Acs, "physical page 1");
        let block = model.pages[0].acs.as_ref().expect("an Acs page carries a block");
        assert!(acs::TAGS.contains(&block.tag), "tag is one the engine accepts");
        assert_eq!(&block.name, b"GALCAPS ", "the block's own name agrees with FCR 0x3c");
        assert_eq!(block.table[b'a' as usize], b'A', "the uppercase fold");
        assert_eq!(block.table[b'A' as usize], b'A', "idempotent on an already-upper byte");
        assert_eq!(block.table[b'0' as usize], b'0', "digits pass through unchanged");
    }

    /// The case harvest 4 SS6a exists to name: `CLASSADS.DAT` (V5R3) reads
    /// **zero** at FCR `0x10a` while genuinely holding a real ACS block on
    /// physical page 1 -- the pointer that lies. `read::resolve_pages`
    /// finds the page from a key's own `ALT_COLLATING` bit, not from
    /// `0x10a`, so this file's block must decode exactly the same as
    /// `WLDSLOTS.DAT`'s despite the pointer disagreeing.
    #[test]
    fn classads_dat_holds_a_real_acs_block_despite_a_zero_pointer() {
        let Some(root) = crate::corpus::root() else {
            eprintln!("read: no archive/ on this box, nothing verified");
            return;
        };
        let path = root.join("galacticomm/hosts/majorbbs/CLASSADS.DAT");
        let Ok(buf) = std::fs::read(&path) else {
            eprintln!("read: CLASSADS.DAT not present, nothing verified");
            return;
        };
        let model = file(&buf).expect("CLASSADS.DAT is a valid v5 file");
        assert_eq!(
            model.live_control().acs_page_pointer, 0,
            "the known-lying pointer -- CLASSADS.DAT reads zero here regardless"
        );
        assert_eq!(&model.live_control().acs_name, b"UPPER   ", "FCR 0x3c is still set correctly");

        assert_eq!(
            model.pages[0].kind,
            PageKind::Acs,
            "found by content (a key's own ALT_COLLATING bit), not by the lying pointer"
        );
        let block = model.pages[0].acs.as_ref().expect("a real block despite the zero pointer");
        assert_eq!(block.tag, 0xac);
        assert_eq!(&block.name, b"UPPER   ");
        assert_eq!(block.table[b'a' as usize], b'A', "the same uppercase fold");
    }

    /// This task's own anchor case: a real fragment page from
    /// `archive/tooling/wbtrv32/assets/VARIABLE.DAT` -- physical page 15,
    /// the harvest's own named best evidence for a multi-hop chain -- reads
    /// as `PageKind::Variable` with 8 fragments, the first of which
    /// continues onto page 13, fragment 8 (harvest 5 SS3.2/SS3.4).
    #[test]
    fn a_real_fragment_page_from_variable_dat_classifies_and_decodes() {
        let buf = variable_length_file_with_a_real_fragment_page();
        let model = file(&buf).expect("a valid v5 file with usrflgs bit 0 set");
        assert_eq!(model.pages.len(), 1, "page 1 only");
        let page = &model.pages[0];
        assert_eq!(
            page.kind,
            PageKind::Variable,
            "unclaimed, data_bit clear, and its own bytes match the fragment-page shape"
        );
        assert!(!page.data_bit, "harvest 5 SS3.3: a fragment page's data_bit reads clear");

        let fp = page.fragments.as_ref().expect("Variable pages carry fragment content");
        assert_eq!(fp.free_chain, 0xffff_ffff, "off the write-side free-space chain");
        assert_eq!(fp.fragments.len(), 8, "this page's own fragment_count");

        match &fp.fragments[0] {
            FragmentSlot::Live { next, body } => {
                assert_eq!(
                    *next,
                    Some(crate::format::variable::Pointer { page: 13, fragment: 8 }),
                    "fragment 0's own leading 4 bytes, 00 0d 00 08, decoded"
                );
                assert_eq!(body.len(), 33, "37-byte span less the 4-byte pointer");
                assert_eq!(body[0], 0x00, "this asset's own 0x00.. filler pattern");
            }
            other => panic!("fragment 0 is a live, continuing fragment: {other:?}"),
        }
        for (n, slot) in fp.fragments.iter().enumerate().skip(1) {
            match slot {
                FragmentSlot::Live { next, .. } => {
                    assert_eq!(*next, None, "fragment {n} ends its chain here");
                }
                other => panic!("fragment {n} is live, not freed: {other:?}"),
            }
        }
        assert!(fp.trailing.is_empty(), "the last fragment tiles right up to the entry array");
    }

    /// This task's required mutation, at the model layer rather than the
    /// full corpus round trip (every real variable-length v5 file this task
    /// found also has an unresolved `IndexChild` page elsewhere -- see this
    /// task's report -- so the corpus round trip cannot isolate this
    /// specific defect the way this fixture can): decoding the pointer with
    /// an unscrambled `[low][mid][high][fragment]` reading, rather than
    /// harvest 5 SS3.2's `[high][low][mid][fragment]`, must produce a
    /// *different* page number from fragment 0's real leading bytes.
    #[test]
    fn decoding_the_pointer_unscrambled_would_read_a_different_page() {
        let buf = variable_length_file_with_a_real_fragment_page();
        let model = file(&buf).expect("a valid v5 file with usrflgs bit 0 set");
        let fp = model.pages[0].fragments.as_ref().expect("Variable pages carry fragment content");
        let FragmentSlot::Live { next: Some(scrambled), .. } = &fp.fragments[0] else {
            panic!("fragment 0 continues");
        };
        assert_eq!(*scrambled, crate::format::variable::Pointer { page: 13, fragment: 8 });

        // The exact reading the harvest names as the one this crate does
        // not use: [low][mid][high][fragment] instead of
        // [high][low][mid][fragment].
        let bytes = [0x00u8, 0x0d, 0x00, 0x08];
        let unscrambled_page =
            u32::from(bytes[2]) << 16 | u32::from(bytes[0]) | u32::from(bytes[1]) << 8;
        assert_ne!(
            unscrambled_page, scrambled.page,
            "an unscrambled reading of these exact bytes must disagree with the \
             scrambled one this crate uses -- if it agreed, this bit pattern could \
             not distinguish the two and the mutation below would be vacuous"
        );
    }

    /// Task 13, Group A: `wccitems.nu1` is one of this crate's two witnesses
    /// that page 0's tail is not always zero. Controller-measured: 1,536-byte
    /// pages, one key descriptor (`after_definitions` `0x12e`), and 239
    /// non-zero bytes starting at page offset `0x400` (tail-relative `722`)
    /// running to the very last byte of the page -- readable MajorMUD prose
    /// ("er teeth like spears, and the ... intelligence"), leftover record
    /// text, not structure. Before this task, `read::file` refused this file
    /// outright; now it reads, `page_zero_tail` holds exactly these bytes,
    /// and the whole file round-trips byte for byte.
    #[test]
    fn wccitems_nu1s_nonzero_page_zero_tail_is_carried_verbatim_and_round_trips() {
        let Some(root) = crate::corpus::root() else {
            eprintln!("read: no archive/ on this box, nothing verified");
            return;
        };
        let path = root.join("modules/majormud-nt/wccnt7py/out/wccitems.nu1");
        let Ok(original) = std::fs::read(&path) else {
            eprintln!("read: wccitems.nu1 not present, nothing verified");
            return;
        };

        let model = file(&original).expect("a nonzero page-0 tail is no longer a refusal");
        assert_eq!(model.id.page_size, 1536);
        assert_eq!(model.key_descriptors.len(), 1, "one key/segment definition");

        let after_definitions = key_descriptor::base(1);
        assert_eq!(after_definitions, 0x12e);
        assert_eq!(model.page_zero_tail.len(), 1536 - after_definitions);

        let nonzero: Vec<usize> = model
            .page_zero_tail
            .iter()
            .enumerate()
            .filter(|&(_, &b)| b != 0)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(nonzero.len(), 239, "the controller's own measured count");
        assert_eq!(*nonzero.first().unwrap(), 722, "first non-zero byte, tail-relative");
        assert_eq!(*nonzero.last().unwrap(), model.page_zero_tail.len() - 1, "runs to the page's last byte");
        assert!(
            model.page_zero_tail[722..].starts_with(b"er teeth like spears"),
            "the tail is genuine leftover prose, not noise"
        );

        let emitted = crate::emit::file(&model).expect("wccitems.nu1: nothing undescribed");
        assert_eq!(emitted.bytes(), original.as_slice(), "the whole file round-trips, tail included");
    }

    /// Task 13, Group B: `TTIHORSS.DAT`'s one orphan, physical page 251 --
    /// not named by any key's root, not the ACS block, not on the free
    /// chain, its own header's `data_bit` clear, and unreached by every
    /// key's own B-tree walk. Before this task `read::file` refused this
    /// file by name; now it classifies the page `PageKind::Orphan`, carries
    /// its whole body (past the 6-byte header) verbatim without attempting
    /// to decode it, and the file round-trips completely.
    #[test]
    fn ttihorss_dats_orphan_page_251_is_carried_whole_and_round_trips() {
        let Some(root) = crate::corpus::root() else {
            eprintln!("read: no archive/ on this box, nothing verified");
            return;
        };
        let path =
            root.join("modules/isv-file-libraries/ISVTTI - Tessier Technologies/temp/TTIHORSS.DAT");
        let Ok(original) = std::fs::read(&path) else {
            eprintln!("read: TTIHORSS.DAT not present, nothing verified");
            return;
        };

        let model = file(&original).expect("an orphan page is no longer a refusal");
        assert_eq!(model.id.page_size, 1024);
        let orphan_page = &model.pages[251 - 1];
        assert_eq!(orphan_page.number, 251, "this page's own header.number field agrees with its position");
        assert!(!orphan_page.data_bit, "the orphan's own header says B-tree node, not records");
        assert_eq!(orphan_page.kind, PageKind::Orphan);
        let body = orphan_page.orphan.as_ref().expect("Orphan carries its whole body");
        assert_eq!(body.len(), 1024 - page::LEN);
        assert_eq!(
            &body[0..6],
            &[0x00, 0x00, 0xff, 0xff, 0xff, 0xff],
            "the body is carried verbatim, whatever it contains"
        );

        let emitted = crate::emit::file(&model).expect("TTIHORSS.DAT: nothing undescribed");
        assert_eq!(emitted.bytes(), original.as_slice(), "the orphan page round-trips, body included");
    }

    /// Task 13, Group B's other shape: `wccitem2.vir` under `wccnt7py` has
    /// its own orphan at physical page 592, and unlike `TTIHORSS.DAT`'s,
    /// this one's header and leading bytes are a *structurally
    /// self-consistent* index leaf (a controller review walked this file's
    /// keys from scratch in Python and confirmed no walk reaches it: real
    /// root 118, 11 pages visited, maximum 582). This crate does not
    /// special-case that -- it carries the same whole, undecoded body
    /// either way, because attributing these bytes to a specific key's
    /// entry shape without a walk's own evidence is exactly the guess Task
    /// 7/11b already ruled out.
    #[test]
    fn wccitem2_virs_structurally_index_shaped_orphan_is_still_carried_whole_not_decoded() {
        let Some(root) = crate::corpus::root() else {
            eprintln!("read: no archive/ on this box, nothing verified");
            return;
        };
        let path = root.join("modules/majormud-nt/wccnt7py/out/wccitem2.vir");
        let Ok(original) = std::fs::read(&path) else {
            eprintln!("read: wccitem2.vir not present, nothing verified");
            return;
        };

        let model = file(&original).expect("an orphan page is no longer a refusal");
        assert_eq!(model.id.page_size, 4096);
        let orphan_page = &model.pages[592 - 1];
        assert_eq!(orphan_page.kind, PageKind::Orphan);
        assert!(orphan_page.index.is_none(), "no key attribution exists, so no IndexPage is decoded");
        let body = orphan_page.orphan.as_ref().expect("Orphan carries its whole body");
        assert_eq!(body.len(), 4096 - page::LEN);

        let emitted = crate::emit::file(&model).expect("wccitem2.vir: nothing undescribed");
        assert_eq!(emitted.bytes(), original.as_slice(), "the orphan page round-trips, body included");
    }

    /// The follow-up review's whole point, proven directly: a genuinely
    /// unclaimed, `data_bit`-clear page whose header is neither zero nor
    /// leaf-shaped, and which sits next to no established orphan either,
    /// must be refused by name -- not silently accepted as `Orphan` just
    /// because no key's walk happened to visit it. This is the synthetic
    /// counterpart to `nonzero_page_zero_tail_is_carried_verbatim_not_refused`:
    /// a small, fully-controlled fixture rather than a real corpus file,
    /// so the corroborating check's own refusal path has direct coverage
    /// independent of which real files happen to exercise it.
    #[test]
    fn an_unclaimed_page_shaped_like_neither_zero_nor_a_leaf_nor_adjacent_to_one_is_refused() {
        let mut buf = usracc_fixed_portion();
        buf[0x14..0x16].copy_from_slice(&1u16.to_le_bytes()); // keys = 1
        let def0 = 0x110;
        buf[def0..def0 + 4].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]); // root = 1
        buf[def0 + 0x0a..def0 + 0x0c].copy_from_slice(&2u16.to_le_bytes()); // key_length
        buf[def0 + 0x0c..def0 + 0x0e].copy_from_slice(&10u16.to_le_bytes()); // entry_size
        buf.resize(1536, 0); // page 0, page 1 (key 0's root), page 2 (the page under test)

        // Page 1: key 0's root, a genuine empty leaf -- the walk visits
        // only this page and finishes cleanly.
        buf[512..516].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]);
        buf[512 + 8..512 + 12].copy_from_slice(&[0xff; 4]); // rightmost = NOWHERE
        buf[512 + 12..512 + 16].copy_from_slice(&[0xff; 4]); // leftmost = NOWHERE

        // Page 2: unclaimed, data_bit clear, but its header is not zero
        // (number = 2) and its rightmost/leftmost (5/7) are real, non-NOWHERE
        // values -- not a leaf's shape either. No other page is orphaned, so
        // adjacency cannot corroborate it.
        buf[1024..1028].copy_from_slice(&[0x00, 0x00, 0x02, 0x00]);
        buf[1024 + 8..1024 + 12].copy_from_slice(&[0x00, 0x00, 0x00, 0x05]); // rightmost = 5
        buf[1024 + 12..1024 + 16].copy_from_slice(&[0x00, 0x00, 0x00, 0x07]); // leftmost = 7

        let e = file(&buf).expect_err("page 2 corroborates nothing -- neither shape nor adjacency");
        assert!(e.why.contains("page 2"), "{}", e.why);
        assert!(e.why.contains("not the zero an abandoned page"), "{}", e.why);
        assert!(e.why.contains("do not look like an abandoned leaf's either"), "{}", e.why);
        assert!(e.why.contains("it does not extend a corroborated anchor either"), "{}", e.why);
    }

    /// A third review's exact concern, proven directly: a chain of TWO
    /// ambiguous pages must not bootstrap off a single corroborated seed.
    /// Page 2 self-corroborates (zeroed header). Page 3 is ambiguous
    /// (neither zero nor leaf-shaped) and sits immediately after page 2 --
    /// under the tightened rule this is not enough on its own, because
    /// page 3's own *following* page (4) must independently be a genuine
    /// record-holding page (`data_bit` set), and it is not: page 4 is
    /// itself ambiguous, the same shape as page 3. So page 3 is refused --
    /// and critically, it is refused even though its immediately preceding
    /// page (2) genuinely self-corroborates, because a real anchor is not
    /// enough by itself; the run must also actually terminate. Had the
    /// earlier (looser) rule still been in place, page 3 would have been
    /// wrongly accepted via "page 2 is Orphan" alone, and page 4 would then
    /// have been accepted via "page 3 is now Orphan" -- an unbounded,
    /// unexaminable chain, every page carried verbatim, every test green.
    /// This test is the fixture that catches exactly that regression.
    #[test]
    fn a_two_page_chain_of_ambiguous_pages_does_not_bootstrap_off_one_corroborated_seed() {
        let mut buf = usracc_fixed_portion();
        buf[0x14..0x16].copy_from_slice(&1u16.to_le_bytes()); // keys = 1
        let def0 = 0x110;
        buf[def0..def0 + 4].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]); // root = 1
        buf[def0 + 0x0a..def0 + 0x0c].copy_from_slice(&2u16.to_le_bytes()); // key_length
        buf[def0 + 0x0c..def0 + 0x0e].copy_from_slice(&10u16.to_le_bytes()); // entry_size
        // page 0 (control), page 1 (root), page 2 (anchor), page 3 (B,
        // ambiguous), page 4 (C, ambiguous) -- 5 pages of 512 bytes.
        buf.resize(2560, 0);

        // Page 1: key 0's root, a genuine empty leaf.
        buf[512..516].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]);
        buf[512 + 8..512 + 12].copy_from_slice(&[0xff; 4]); // rightmost = NOWHERE
        buf[512 + 12..512 + 16].copy_from_slice(&[0xff; 4]); // leftmost = NOWHERE

        // Page 2: the anchor -- header left entirely zero, self-corroborating.

        // Page 3 ("B"): unclaimed, data_bit clear, ambiguous shape (nonzero
        // header, rightmost/leftmost neither NOWHERE nor 0).
        buf[1536..1540].copy_from_slice(&[0x00, 0x00, 0x03, 0x00]);
        buf[1536 + 8..1536 + 12].copy_from_slice(&[0x00, 0x00, 0x00, 0x05]); // rightmost = 5
        buf[1536 + 12..1536 + 16].copy_from_slice(&[0x00, 0x00, 0x00, 0x07]); // leftmost = 7

        // Page 4 ("C"): the same ambiguous shape as B, deliberately NOT a
        // genuine data_bit-set page -- this is what must stop B's own
        // acceptance, and what a bootstrap-vulnerable rule would instead
        // wrongly accept off B.
        buf[2048..2052].copy_from_slice(&[0x00, 0x00, 0x04, 0x00]);
        buf[2048 + 8..2048 + 12].copy_from_slice(&[0x00, 0x00, 0x00, 0x09]); // rightmost = 9
        buf[2048 + 12..2048 + 16].copy_from_slice(&[0x00, 0x00, 0x00, 0x0b]); // leftmost = 11

        let e = file(&buf).expect_err("neither ambiguous page may bootstrap off the other");
        assert!(e.why.contains("page 3"), "must name the first page the chain fails at: {}", e.why);
        assert!(
            e.why.contains("it does not extend a corroborated anchor either"),
            "{}",
            e.why
        );
    }

    /// Task 13's follow-up review: enforcing `orphan_header_shape` against
    /// the whole corpus turned up a *third* orphan shape, previously
    /// undiscovered because it was silently accepted before the review's
    /// corroborating check existed. `wccitem2.vir` under `wccnt7pz` has TWO
    /// consecutive orphans, not one: physical page 593 (zeroed header,
    /// self-corroborating) and page 594 immediately after it (unclaimed,
    /// `data_bit` clear, but its own "header" bytes are literally leftover
    /// prose -- neither zero nor leaf-shaped). Page 594 is accepted only
    /// because it is physically adjacent to page 593's own corroborated
    /// orphan; a genuine live `Data` page (595) resumes right after.
    #[test]
    fn wccitem2_virs_second_consecutive_orphan_is_accepted_by_adjacency_not_its_own_shape() {
        let Some(root) = crate::corpus::root() else {
            eprintln!("read: no archive/ on this box, nothing verified");
            return;
        };
        let path = root.join("modules/majormud-nt/wccnt7pz/out/wccitem2.vir");
        let Ok(original) = std::fs::read(&path) else {
            eprintln!("read: wccitem2.vir not present, nothing verified");
            return;
        };

        let model = file(&original).expect("both consecutive orphans are accepted");
        assert_eq!(model.id.page_size, 4096);

        let anchor = &model.pages[593 - 1];
        assert_eq!(anchor.kind, PageKind::Orphan);
        assert_eq!(anchor.number, 0, "page 593's own header.number is literally zeroed");
        assert_eq!(anchor.stamp, 0, "page 593's own header.counter is literally zeroed");

        let second = &model.pages[594 - 1];
        assert_eq!(second.kind, PageKind::Orphan, "accepted via adjacency, not its own shape");
        assert!(!second.data_bit, "data_bit reads clear only because the leftover bytes are ASCII");
        let body = second.orphan.as_ref().expect("Orphan carries its whole body");
        assert!(body.starts_with(b" He wears soft leather"), "leftover prose, not structure");

        let resumed = &model.pages[595 - 1];
        assert_eq!(resumed.kind, PageKind::Data, "a genuine live data page resumes right after");

        let emitted = crate::emit::file(&model).expect("wccitem2.vir: nothing undescribed");
        assert_eq!(emitted.bytes(), original.as_slice(), "both orphans round-trip, bodies included");
    }
}
