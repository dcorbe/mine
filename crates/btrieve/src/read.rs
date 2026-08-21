//! Bytes to model.
//!
//! Total, or a refusal: this never returns a model with holes in it. A file
//! whose bytes are not yet fully described is refused with the reason, and the
//! round-trip pin does not count it.

use std::collections::{HashMap, HashSet};

use crate::format::acs;
use crate::format::fcr;
use crate::format::fcr::key_descriptor;
use crate::format::generation::{identify, NotBtrieve};
use crate::format::index;
use crate::format::page;
use crate::format::variable;
use crate::model::{
    AcsBlock, ControlRecord, DataPage, File, FragmentPage, FragmentSlot, IndexEntry, IndexPage,
    KeyDescriptor, Page, PageKind,
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

/// Read the v5 control record's fixed portion (`0x00..0x110`) out of `bytes`,
/// which must be at least that long.
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

/// Read a fixed-length-record data page's content: every slot in order,
/// then whatever is left between the last slot and the end of the page.
///
/// `physical` must be nonzero -- the caller only calls this when it is (see
/// `resolve_pages`'s guard).
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
fn read_data_page(bytes: &[u8], page_start: usize, page_size: usize, physical: usize) -> DataPage {
    let per_page = (page_size - page::LEN) / physical;
    let mut slots = Vec::with_capacity(per_page);
    for i in 0..per_page {
        let start = page_start + page::LEN + i * physical;
        slots.push(bytes[start..start + physical].to_vec());
    }
    let used = page::LEN + per_page * physical;
    DataPage { slots, slack: bytes[page_start + used..page_start + page_size].to_vec() }
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

/// How `page_number` is already spoken for, for a conflict message.
fn describe_claim(kind: PageKind) -> String {
    match kind {
        PageKind::Index => "an index root".to_string(),
        PageKind::Acs => "the ACS block".to_string(),
        PageKind::Free => "on the free chain".to_string(),
        PageKind::IndexChild => "an index page (not a root)".to_string(),
        PageKind::Data => "a data page".to_string(),
        PageKind::Variable => "a variable-length fragment page".to_string(),
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
/// A page no pointer claims is decided by `data_bit` alone: set means
/// `Data`, clear means [`PageKind::IndexChild`] -- a B-tree node no key's
/// root names. Measured 281/281 index roots, 15/15 ACS pages, and 22/22
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

    // Free: walk the record-slot free chain from FCR 0x10.
    const NOWHERE: u32 = 0xffff_ffff;
    let mut cur = control.free;
    let mut visited: HashSet<u32> = HashSet::new();
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
                // fragment-page shape either. Task 11b's own rule: a page
                // reached by no walk is a refusal, not a guess -- this used
                // to fall through to `PageKind::IndexChild` residually
                // (exactly the defect an earlier task's `unwrap_or` shipped
                // elsewhere, mislabelling 9,058 pages), which this crate no
                // longer does now that a real walk exists to attribute
                // every genuine child.
                return Err(NotBtrieve {
                    why: format!(
                        "page {page_number} is not named by any key's root, \
                         not the ACS block, not on the free chain, its own \
                         header says it holds a B-tree node rather than \
                         records, and no key's B-tree walk ever reached it \
                         either -- there is no positive evidence for what \
                         this page is, so this crate refuses rather than \
                         guessing"
                    ),
                });
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
            Some(read_data_page(bytes, at, page_size, control.physical as usize))
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

        pages.push(Page {
            number,
            data_bit,
            stamp,
            kind,
            content,
            index: index_content,
            acs: acs_content,
            fragments: fragment_content,
        });
    }
    Ok(pages)
}

/// Read a whole Btrieve file into a model.
///
/// # Errors
///
/// If [`identify`] refuses the control record, the file is shorter than its
/// own declared page size, the file is a v6 file (not yet described by this
/// crate), the key/segment definition array is malformed (runs past the
/// page, or an `ANOSEG` chain never terminates), the zero padding past the
/// last definition, up to `page_size`, is not actually zero, the file is not
/// a whole number of pages, or [`resolve_pages`] cannot classify every page
/// -- see that function's own documentation for the specific
/// contradictions it checks for.
pub fn file(bytes: &[u8]) -> Result<File, NotBtrieve> {
    let id = identify(bytes)?;

    if id.generation.is_v6() {
        return Err(NotBtrieve {
            why: format!(
                "identified as {:?} with {}-byte pages, but this crate does \
                 not yet describe every byte of a v6 control record",
                id.generation, id.page_size
            ),
        });
    }

    let page_size = id.page_size as usize;
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
    // to page_size, must be zero -- harvest 1's tail_check.py measured this
    // on 112 of 112 v5 corpus files, re-measured for this task on 143 of the
    // 145 v5 corpus files currently identified. The 2 exceptions
    // (wccitems.nu1 and its sibling) are refused here, by name, rather than
    // accepted as harmless padding -- a later task investigates them.
    let after_definitions = key_descriptor::base(key_descriptors.len());
    if page_size > after_definitions {
        let tail = &bytes[after_definitions..page_size];
        if let Some(offset) = tail.iter().position(|&b| b != 0) {
            return Err(NotBtrieve {
                why: format!(
                    "identified as {:?}, but byte {:#x} of the zero padding \
                     past the {} key/segment definition(s) (ending at {:#x}) \
                     is {:#04x}, not zero",
                    id.generation,
                    after_definitions + offset,
                    key_descriptors.len(),
                    after_definitions,
                    tail[offset]
                ),
            });
        }
    }

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
        control,
        key_descriptors,
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
        assert_eq!(file.control.keys, 1, "KEYS");
        assert_eq!(file.control.reclen, 0xfc, "RECLEN");
        assert_eq!(file.control.physical, 0xfc, "PHYSICAL");
        assert_eq!(file.control.records, 2, "RECORDS");
        assert_eq!(file.control.highest, 2, "HIGHEST");
        assert_eq!(file.control.pages, 3, "PAGES");
        assert_eq!(file.control.usrflgs, 0, "USRFLGS");
        assert_eq!(file.len, 512);
    }

    /// A v6 file is refused, naming the reason, not silently accepted with
    /// an empty control record.
    #[test]
    fn a_v6_file_is_refused() {
        let mut b = vec![0u8; 512];
        b[..4].copy_from_slice(&[b'F', b'C', 0, 0]);
        b[0x4a..0x4c].copy_from_slice(&0x600u16.to_le_bytes());
        b[8..10].copy_from_slice(&512u16.to_le_bytes());
        let e = file(&b).expect_err("v6 is not yet described");
        assert!(e.why.contains("v6"), "{}", e.why);
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

    /// A page-size-1024 file with a nonzero byte in the zero-padding region
    /// (past the historical 512-byte control record) is refused, naming the
    /// specific offset and byte -- not just "this file is corrupt".
    #[test]
    fn nonzero_zero_padding_is_refused_and_names_the_offset() {
        let mut buf = usracc_fixed_portion();
        buf[0x08..0x0a].copy_from_slice(&1024u16.to_le_bytes());
        buf.resize(1024, 0);
        buf[600] = 0xaa;
        let e = file(&buf).expect_err("nonzero zero padding");
        assert!(e.why.contains("0x258"), "names the offset: {}", e.why);
        assert!(e.why.contains("0xaa"), "names the byte: {}", e.why);
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
        assert_eq!(content.slots[0].len(), 252);
        assert_eq!(content.slots[1].len(), 252);
        assert!(
            content.slots[0].starts_with(b"Sysop"),
            "slot 0 at page offset 0x06 is the Sysop record"
        );
        assert!(
            content.slots[1].starts_with(b"Test"),
            "slot 1 at page offset 0x102 is the Test record"
        );
        assert_eq!(content.slack, vec![0u8, 0], "the trailing 2 bytes, described and zero here");
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
        assert_eq!(file.control.records, 0, "every record has been deleted");
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
        assert_eq!(model.control.acs_page_pointer, 1, "0x10a agrees here");
        assert_eq!(&model.control.acs_name, b"GALCAPS ", "FCR 0x3c");

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
            model.control.acs_page_pointer, 0,
            "the known-lying pointer -- CLASSADS.DAT reads zero here regardless"
        );
        assert_eq!(&model.control.acs_name, b"UPPER   ", "FCR 0x3c is still set correctly");

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
}
