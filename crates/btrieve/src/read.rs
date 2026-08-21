//! Bytes to model.
//!
//! Total, or a refusal: this never returns a model with holes in it. A file
//! whose bytes are not yet fully described is refused with the reason, and the
//! round-trip pin does not count it.

use std::collections::{HashMap, HashSet};

use crate::format::fcr;
use crate::format::fcr::key_descriptor;
use crate::format::generation::{identify, NotBtrieve};
use crate::format::index;
use crate::format::page;
use crate::model::{ControlRecord, DataPage, File, IndexEntry, IndexPage, KeyDescriptor, Page, PageKind};

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
/// or an entry (even without its possibly-omitted `child` field) would run
/// past the page.
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
        let full_end = offset + entry_size;
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

/// How `page_number` is already spoken for, for a conflict message.
fn describe_claim(kind: PageKind) -> String {
    match kind {
        PageKind::Index => "an index root".to_string(),
        PageKind::Acs => "the ACS block".to_string(),
        PageKind::Free => "on the free chain".to_string(),
        PageKind::IndexChild => "an index page (not a root)".to_string(),
        PageKind::Data => "a data page".to_string(),
    }
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
    // Which key descriptor a root page belongs to -- needed once a page is
    // known to be `Index`, so its entries can be decoded with the right
    // `key_length`/`entry_size`/`attributes` (none of which the page itself
    // carries).
    let mut root_owner: HashMap<u32, usize> = HashMap::new();

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
        root_owner.insert(d.root_page, i);
    }

    // ACS: gated on content (harvest 4 SS6a), not on FCR 0x10a alone.
    const V5_ACS_PAGE: u32 = 1;
    let acs_declared =
        key_descriptors.iter().any(|d| d.attributes & key_descriptor::ALT_COLLATING != 0);
    if acs_declared {
        if let Some(existing) = claim.get(&V5_ACS_PAGE).copied() {
            return Err(NotBtrieve {
                why: format!(
                    "a key descriptor declares an alternate collating \
                     sequence, which harvest 4 SS6a places at physical page \
                     {V5_ACS_PAGE} on every v5 corpus file measured, but \
                     page {V5_ACS_PAGE} is already {} -- the ACS block and \
                     an index root cannot be the same page",
                    describe_claim(existing)
                ),
            });
        }
        claim.insert(V5_ACS_PAGE, PageKind::Acs);
        if control.acs_page_pointer != 0 && control.acs_page_pointer != V5_ACS_PAGE {
            return Err(NotBtrieve {
                why: format!(
                    "FCR 0x10a names page {} as the ACS block, but a key \
                     descriptor's ALT_COLLATING bit places it at physical \
                     page {V5_ACS_PAGE} instead (harvest 4 SS6a) -- the two \
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
            if matches!(existing, PageKind::Index | PageKind::Acs) {
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
            Some(kind @ (PageKind::Index | PageKind::Acs | PageKind::Free)) => kind,
            Some(other) => {
                unreachable!("claim only ever stores Index, Acs, or Free -- got {other:?}")
            }
            None if data_bit => PageKind::Data,
            None => {
                // Not named by any root, not the ACS block, not on the free
                // chain, and its own header says "not records" -- a B-tree
                // node no key's root claims, i.e. a child of some tree.
                // Which tree is Task 9's business, once index entries are
                // parsed and child pointers can actually be walked; this
                // task only has to say honestly that the page is an index
                // page, not that it knows whose.
                PageKind::IndexChild
            }
        };

        // A fixed-length-record data page's content -- slots plus trailing
        // slack -- is described whenever the page actually holds records
        // (`data_bit` set: `Data` or `Free`, never `Index`/`IndexChild`/
        // `Acs`) and this task's scope actually covers it: `physical`
        // nonzero (a sound slot width to divide by) and the file is not
        // variable-length (harvest 5 SS3.1's `usrflgs` bit 0 -- a
        // variable-length file's data-bit-set pages are `'V'`-tagged
        // fragment pages, a different structure entirely, a later task's
        // job). `USRACC.DAT` itself is not variable and every corpus file
        // this task measured agrees: content is `None` only for a page kind
        // this task does not yet describe, never as a residual guess.
        let variable = control.usrflgs & fcr::usrflgs::VARIABLE != 0;
        let content = if data_bit && !variable && control.physical != 0 {
            Some(read_data_page(bytes, at, page_size, control.physical as usize))
        } else {
            None
        };

        // An index page's entries, described whenever this page is a key's
        // own root: its owning key descriptor is known directly (via
        // `root_owner`), so `key_length`/`entry_size`/`attributes` need no
        // walking to find. An `IndexChild` page's owning key is not yet
        // known -- that requires walking child pointers down from a root,
        // out of this task's scope -- so it stays `None` and `emit` faults
        // on it honestly, the same way it faults on a variable-length
        // fragment page today.
        let index_content = if kind == PageKind::Index {
            let &n = root_owner
                .get(&(page_number as u32))
                .unwrap_or_else(|| panic!("page {page_number} is Index but claims no owner"));
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

        pages.push(Page { number, data_bit, stamp, kind, content, index: index_content });
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
        two_key_fixed_portion, usracc_dat, usracc_first_page, usracc_fixed_portion,
    };

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
        let buf = usracc_first_page();
        let file = file(&buf).expect("a valid v5 control record");
        assert_eq!(file.key_descriptors.len(), 1, "USRACC.DAT has exactly one definition");
        let d = &file.key_descriptors[0];
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
        let buf = two_key_fixed_portion();
        let file = file(&buf).expect("a valid v5 control record");
        assert_eq!(file.key_descriptors.len(), 2);
        assert_eq!(file.key_descriptors[0].key_number, 0x80);
        assert_eq!(file.key_descriptors[0].root_page, 3);
        assert_eq!(file.key_descriptors[1].key_number, 0x81);
        assert_eq!(file.key_descriptors[1].root_page, 4, "not 0x01000004");
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
    /// (13 1024-byte pages, three keys rooted at pages 1, 2, 8). Measured
    /// directly off the file when this task's review was addressed: pages
    /// 4, 6, and 10 hold records (`data_bit` set) and are `Data`; pages 3,
    /// 5, 7, 9, 11, and 12 are B-tree nodes no root names (`data_bit`
    /// clear) and are `IndexChild`. This is the exact case the review's
    /// Critical finding caught -- the earlier `unwrap_or(PageKind::Data)`
    /// residual mislabelled all six of the latter as `Data`.
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
        for &child_page in &[3, 5, 7, 9, 11, 12] {
            assert_eq!(
                kind_of(child_page),
                PageKind::IndexChild,
                "page {child_page} is a B-tree node no root names"
            );
        }
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
        buf[0x10..0x14].copy_from_slice(&[0x00, 0x00, 0x06, 0x02]); // free = 518 (page 1, offset 6)
        let e = file(&buf).expect_err("the free chain reaches page 1, an index root");
        assert!(e.why.contains("page 1"), "{}", e.why);
        assert!(e.why.contains("index root"), "{}", e.why);
    }
}
