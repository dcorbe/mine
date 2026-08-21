//! Model to bytes.
//!
//! # The signature is the guarantee
//!
//! [`file`] takes a [`File`] and nothing else. It cannot see the bytes
//! [`crate::read::file`] was given, so a byte-identical round trip cannot be
//! achieved by copying the input -- the only way to reproduce a file is to
//! have described it. Any function added here that accepts the source bytes
//! defeats the crate's entire correctness argument.
//!
//! Bytes are produced through a [`Canvas`], never a `vec![0; len]` written
//! into directly: a byte the model does not describe is a reported fault,
//! not a silent zero. [`crate::model::File`] describes a v5 file's control
//! record fixed portion (`0x00..0x110`), its key/segment definition array,
//! every physical page's six-byte header (`format::page`) plus what the page
//! graph says it is, a `Data`/`Free` page of a non-variable-length file's
//! fixed-length-record content (every slot, verbatim, plus the trailing
//! slack -- `crate::model::DataPage`), an `Index` page's own entry array
//! too: the entry count, the two boundary pointers, every entry -- key,
//! `head`, the duplicate-only `tail`, and the possibly-omitted `child` --
//! plus trailing padding (`crate::model::IndexPage`), for **every** index
//! page a key's own root or its walked descendants resolve to (Task 11b --
//! an `IndexChild` page writes exactly the same way an `Index` root does,
//! since both carry the same `IndexPage` content once attributed to a key);
//! a v5 file's alternate collating sequence block
//! (`crate::model::AcsBlock`), found by the page graph on content -- a
//! key's own `ALT_COLLATING` bit -- rather than trusted from the control
//! record's own (on 2 corpus files, lying) `0x10a` pointer; and a
//! variable-length file's fragment/overflow pages
//! (`crate::model::FragmentPage`); and (Task 13) an abandoned page no key's
//! walk reaches and no other evidence names (`crate::model::PageKind::Orphan`),
//! whose whole body is carried back verbatim, undecoded. `USRACC.DAT`
//! round-trips completely as of an earlier task -- the first real corpus
//! file to do so; a genuine multi-page B-tree (`FW_QSQDB.DAT`,
//! `JABTTQST.DAT`, `VARIABLE.DAT`, `wcctext.nu1`, and 13 more v5 corpus
//! files) now does too; as of Task 13, all 145 v5 corpus files this crate
//! can identify do. If [`file`] still faults, the fault names the first byte
//! range this crate genuinely has no description for yet.

use crate::canvas::{Canvas, Emitted, Fault, Owner};
use crate::format::acs;
use crate::format::alloc;
use crate::format::fcr;
use crate::format::fcr::key_descriptor;
use crate::format::free_slot;
use crate::format::generation::Generation;
use crate::format::index;
use crate::format::page;
use crate::format::variable;
use crate::model::{
    Control, ControlRecord, File, FragmentPage, FragmentSlot, KeyDescriptor, RecordSlot,
    V6AllocationBlockCopy, V6ControlRecord, V6Page, V6PageTail,
};

fn owner(field: &'static str) -> Owner {
    Owner { structure: "fcr", field, index: None }
}

fn key_owner(field: &'static str, index: usize) -> Owner {
    Owner { structure: "fcr", field, index: Some(index) }
}

fn page_owner(field: &'static str, page_number: usize) -> Owner {
    Owner { structure: "page", field, index: Some(page_number) }
}

/// Write every physical page's six-byte header (`format::page`) into
/// `canvas`. Each page's content past the header -- records, index entries,
/// the ACS table -- is a later task's job, so this leaves the rest of every
/// page unwritten and `Canvas::finish` reports it.
///
/// # Errors
///
/// See [`Canvas::put`].
fn write_page_headers(canvas: &mut Canvas, model: &File) -> Result<(), Fault> {
    let page_size = model.id.page_size as usize;
    for (i, p) in model.pages.iter().enumerate() {
        let page_number = i + 1;
        let at = page_number * page_size;
        let data_bit = if p.data_bit { page::DATA_BIT } else { 0 };
        let counter = data_bit | (p.stamp & !page::DATA_BIT);
        canvas.put_long(at + page::at::NUMBER, p.number, page_owner("number", page_number))?;
        canvas.put_u16(at + page::at::COUNTER, counter, page_owner("counter", page_number))?;
    }
    Ok(())
}

/// Write every page's fixed-length-record content -- slots, then trailing
/// slack -- for every page whose model carries one (`Page::content`,
/// `Some` for a `Data`/`Free` page of a non-variable-length file; `None`
/// for an index/ACS page or a variable-length file's fragment page, both
/// still a later task, so those pages' bodies stay unwritten and
/// `Canvas::finish` reports them as before).
///
/// A live slot is written from its own stored bytes, whole. A free slot
/// (harvest 5 SS2.1) is written as its two decoded fields, `link` then
/// `fill` (`format::free_slot`) -- `fill` is the model's own stored bytes,
/// never re-zeroed, `DataPage::slack`'s discipline extended to a free
/// slot's own remainder. Slack past the last slot is written the same way
/// it always was, never re-derived as zero -- `read::read_data_page`'s doc
/// measures 5 real corpus pages where that would be wrong.
///
/// # Errors
///
/// See [`Canvas::put`].
fn write_page_content(canvas: &mut Canvas, model: &File) -> Result<(), Fault> {
    let page_size = model.id.page_size as usize;
    for (i, p) in model.pages.iter().enumerate() {
        let Some(content) = &p.content else { continue };
        let page_number = i + 1;
        let at = page_number * page_size;
        let mut offset = at + page::LEN;
        for slot in &content.slots {
            match slot {
                RecordSlot::Live(bytes) => {
                    canvas.put(offset, bytes, page_owner("record", page_number))?;
                    offset += bytes.len();
                }
                RecordSlot::Free { next, fill } => {
                    canvas.put(
                        offset + free_slot::at::LINK,
                        &free_slot::encode_link(*next),
                        page_owner("free_link", page_number),
                    )?;
                    canvas.put(
                        offset + free_slot::at::LINK_LEN,
                        fill,
                        page_owner("free_fill", page_number),
                    )?;
                    offset += free_slot::at::LINK_LEN + fill.len();
                }
            }
        }
        canvas.put(offset, &content.slack, page_owner("slack", page_number))?;
    }
    Ok(())
}

/// Write every index page's content -- entry count, the two boundary
/// pointers, every entry, then trailing padding -- for every page whose
/// model carries one (`Page::index`, `Some` for an `Index` page **and** for
/// an `IndexChild` page a key's own walk attributed, Task 11b; `None` only
/// for a `Data`/`Free`/`Acs` page, which never carries index content).
///
/// Every field is written from the model's own stored value, never
/// derived -- in particular the last entry's `child` field is written
/// exactly as `read::read_index_page` captured it (typically a literal
/// zero placeholder, not `NOWHERE`), and is not written at all when the
/// model says it was never on disk to begin with (`IndexEntry::child`
/// `None`, the `WCCSPELS.VIR`-style full-page omission).
///
/// # Errors
///
/// See [`Canvas::put`].
fn write_index_pages(canvas: &mut Canvas, model: &File) -> Result<(), Fault> {
    let page_size = model.id.page_size as usize;
    for (i, p) in model.pages.iter().enumerate() {
        let Some(idx) = &p.index else { continue };
        let page_number = i + 1;
        let at = page_number * page_size;

        // A page this small cannot physically hold anywhere near 65,536
        // entries (`read::read_index_page` would have refused first), so
        // this narrowing is sound rather than a silent truncation risk.
        let count = idx.entries.len() as u16;
        canvas.put_u16(at + index::at::COUNT, count, page_owner("index_count", page_number))?;
        canvas.put_long(
            at + index::at::RIGHTMOST,
            idx.rightmost,
            page_owner("index_rightmost", page_number),
        )?;
        canvas.put_long(
            at + index::at::LEFTMOST,
            idx.leftmost,
            page_owner("index_leftmost", page_number),
        )?;

        let mut offset = at + index::at::ENTRIES;
        for entry in &idx.entries {
            canvas.put(offset, &entry.key, page_owner("index_key", page_number))?;
            offset += entry.key.len();
            canvas.put_long(offset, entry.head, page_owner("index_head", page_number))?;
            offset += 4;
            if let Some(tail) = entry.tail {
                canvas.put_long(offset, tail, page_owner("index_tail", page_number))?;
                offset += 4;
            }
            if let Some(child) = entry.child {
                canvas.put_long(offset, child, page_owner("index_child", page_number))?;
                offset += 4;
            }
        }
        canvas.put(offset, &idx.padding, page_owner("index_padding", page_number))?;
    }
    Ok(())
}

/// Write every ACS page's content -- tag, name, table, then trailing
/// padding -- for every page whose model carries one (`Page::acs`, `Some`
/// only for an `Acs` page).
///
/// Every field is written from the model's own stored value, never
/// derived: the name is written exactly as read, never re-padded or
/// normalised, and `padding` is written verbatim the same way
/// `write_page_content`'s slack is -- see this task's mutation test for why
/// that matters.
///
/// # Errors
///
/// See [`Canvas::put`].
fn write_acs_blocks(canvas: &mut Canvas, model: &File) -> Result<(), Fault> {
    let page_size = model.id.page_size as usize;
    for (i, p) in model.pages.iter().enumerate() {
        let Some(block) = &p.acs else { continue };
        let page_number = i + 1;
        let at = page_number * page_size;
        canvas.put(at + acs::at::TAG, &[block.tag], page_owner("acs_tag", page_number))?;
        canvas.put(at + acs::at::NAME, &block.name, page_owner("acs_name", page_number))?;
        canvas.put(at + acs::at::TABLE, &block.table, page_owner("acs_table", page_number))?;
        canvas.put(
            at + acs::at::TABLE + acs::at::TABLE_LEN,
            &block.padding,
            page_owner("acs_padding", page_number),
        )?;
    }
    Ok(())
}

/// Write one fragment page's content -- the free-chain link, fragment
/// count, every fragment slot, the entry array's boundary member, and
/// trailing free space -- shared between v5's [`write_fragment_pages`] and
/// v6's [`write_v6_fragment_pages`] (Task 20): the shape is identical in
/// both families (harvest 3 SS4), and only how a live fragment's
/// continuation bit is written differs, gated by `is_v6` the same way
/// `read::read_fragment_page` gates how it is read.
///
/// Every field is written from the model's own stored value: a fragment's
/// placement is never re-read from a stored offset (there isn't one -- see
/// `model::FragmentPage`'s own doc) but replayed by advancing a cursor the
/// same way `read::read_fragment_page` derived it in the first place, which
/// is reproducing an already-fully-known tiling, not guessing a new one.
/// `next: Some(pointer)`'s four bytes are written through
/// `variable::Pointer::encode` -- harvest 5 SS3.2's scrambled byte order.
///
/// # The continuation bit, v5 versus v6
///
/// v5 sets `variable::CONTINUED_BIT` exactly when `next.is_some()` -- the
/// bit is real, load-bearing on-disk data there. v6's `next` is always
/// `Some` (`read_fragment_page`'s own doc comment), but this crate never
/// sets the bit for it regardless: every real v6 fragment this project has
/// ever produced leaves it clear (`variable.rs:340-353`, 165/165 entries
/// across four oracle-written fixtures), so writing it from `next.is_some()`
/// here would set a bit measured reality never sets. **No v6 file in this
/// project's corpus has ever exercised this choice** -- see
/// `model::FragmentPage`'s own doc comment.
///
/// # Errors
///
/// See [`Canvas::put`].
fn write_one_fragment_page(
    canvas: &mut Canvas,
    page_number: usize,
    page_size: usize,
    fp: &FragmentPage,
    is_v6: bool,
) -> Result<(), Fault> {
    let at = page_number * page_size;

    canvas.put_long(
        at + variable::at::FREE_CHAIN,
        fp.free_chain,
        page_owner("variable_free_chain", page_number),
    )?;
    // `fragments.len()` came from a fragment_count this crate already
    // validated fits `1..=256` when the page was read, so this cast
    // cannot silently truncate.
    let fragment_count = fp.fragments.len() as u16;
    canvas.put_u16(
        at + variable::at::FRAGMENT_COUNT,
        fragment_count,
        page_owner("variable_fragment_count", page_number),
    )?;

    let mut cursor = at + variable::at::FRAGMENTS;
    for (n, slot) in fp.fragments.iter().enumerate() {
        // `read_fragment_page` already computed this same offset
        // successfully for this exact (page_size, n) pair when this
        // model was built -- a page too small to hold it would have
        // been refused before a `FragmentPage` ever existed to emit.
        let entry_rel = variable::entry_at(page_size, n)
            .expect("read already validated every entry position fits");
        match slot {
            FragmentSlot::Freed => {
                canvas.put_u16(
                    at + entry_rel,
                    variable::UNUSED_ENTRY,
                    page_owner("variable_entry", page_number),
                )?;
            }
            FragmentSlot::Live { next, body } => {
                let start = cursor - at;
                let mut raw = start as u16;
                if next.is_some() && !is_v6 {
                    raw |= variable::CONTINUED_BIT;
                }
                canvas.put_u16(
                    at + entry_rel,
                    raw,
                    page_owner("variable_entry", page_number),
                )?;
                if let Some(pointer) = next {
                    canvas.put(
                        cursor,
                        &pointer.encode(),
                        page_owner("variable_continuation", page_number),
                    )?;
                    cursor += variable::POINTER_LEN;
                }
                canvas.put(cursor, body, page_owner("variable_fragment", page_number))?;
                cursor += body.len();
            }
        }
    }

    let boundary_rel = variable::entry_at(page_size, fp.fragments.len())
        .expect("read already validated the boundary entry position fits");
    canvas.put_u16(
        at + boundary_rel,
        fp.free_space_entry,
        page_owner("variable_free_space_entry", page_number),
    )?;

    canvas.put(cursor, &fp.trailing, page_owner("variable_trailing", page_number))?;
    Ok(())
}

/// Write every v5 fragment page's content, for every page whose model
/// carries one (`Page::fragments`, `Some` only for a `PageKind::Variable`
/// page). See [`write_one_fragment_page`] for the shared mechanics.
///
/// # Errors
///
/// See [`Canvas::put`].
fn write_fragment_pages(canvas: &mut Canvas, model: &File) -> Result<(), Fault> {
    let page_size = model.id.page_size as usize;
    for (i, p) in model.pages.iter().enumerate() {
        let Some(fp) = &p.fragments else { continue };
        write_one_fragment_page(canvas, i + 1, page_size, fp, false)?;
    }
    Ok(())
}

/// Write every v6 fragment/overflow page's content (Task 20), for every
/// page whose model carries one (`V6Page::fragment`, `Some` only for a page
/// tagged `TAG_VARIABLE`). See [`write_one_fragment_page`] for the shared
/// mechanics and what distinguishes the v6 write from v5's.
///
/// **No v6 file in this project's corpus has a `TAG_VARIABLE` page** -- see
/// `model::FragmentPage`'s own doc comment for what grounds this function
/// instead.
///
/// # Errors
///
/// See [`Canvas::put`].
fn write_v6_fragment_pages(canvas: &mut Canvas, model: &File) -> Result<(), Fault> {
    let page_size = model.id.page_size as usize;
    for p in &model.v6_pages {
        let Some(fp) = &p.fragment else { continue };
        write_one_fragment_page(canvas, p.physical_page as usize, page_size, fp, true)?;
    }
    Ok(())
}

/// Write every orphan page's whole body back verbatim (`Page::orphan`, Task
/// 13), for every page whose model carries one (`Some` only for
/// `PageKind::Orphan`). Written as one opaque block past the header, exactly
/// as `read::resolve_pages` captured it -- this crate makes no claim about
/// what, if anything, inside it is still meaningful; see `PageKind::Orphan`'s
/// own documentation for the evidence that this is abandoned content, not an
/// unparsed structure.
///
/// # Errors
///
/// See [`Canvas::put`].
fn write_orphan_pages(canvas: &mut Canvas, model: &File) -> Result<(), Fault> {
    let page_size = model.id.page_size as usize;
    for (i, p) in model.pages.iter().enumerate() {
        let Some(body) = &p.orphan else { continue };
        let page_number = i + 1;
        let at = page_number * page_size;
        canvas.put(at + page::LEN, body, page_owner("orphan_body", page_number))?;
    }
    Ok(())
}

/// Write every key/segment definition in `descriptors`, starting at
/// `base + key_descriptor::base(0)` -- the 30-byte, `ANOSEG`-chained
/// structure v5 and v6 share (harvest 2's field table transcribes to
/// identical offsets). `base` is `0` for v5 (page 0 is the only copy, at
/// absolute offset 0) or a v6 physical page's own absolute byte offset
/// (`physical_page * page_size`) -- v6 needs this because the identical
/// 30-byte structure repeats at whichever physical page holds the live or
/// the stale copy (Task 18), not only at offset 0.
///
/// Shared by v5's [`write_key_descriptors`] (which appends
/// `model.page_zero_tail`) and v6's [`write_v6_page_tail`] (which appends
/// the definition-offset trailer and its own surrounding padding, Task 16)
/// -- one write site for one 30-byte structure, not two copies of the same
/// eleven `canvas.put*` calls.
///
/// # Errors
///
/// See [`Canvas::put`].
fn write_key_descriptor_array(
    canvas: &mut Canvas,
    descriptors: &[KeyDescriptor],
    base: usize,
) -> Result<(), Fault> {
    for (n, d) in descriptors.iter().enumerate() {
        let start = base + key_descriptor::base(n);
        let root = (u32::from(d.key_number) << 24) | (d.root_page & 0x00ff_ffff);
        canvas.put_long(start + key_descriptor::at::ROOT, root, key_owner("root", n))?;
        canvas.put_long(start + key_descriptor::at::RECORDS, d.records, key_owner("records", n))?;
        canvas.put_u16(start + key_descriptor::at::ATTRIBUTES, d.attributes, key_owner("attributes", n))?;
        canvas.put_u16(start + key_descriptor::at::KEY_LENGTH, d.key_length, key_owner("key_length", n))?;
        canvas.put_u16(start + key_descriptor::at::ENTRY_SIZE, d.entry_size, key_owner("entry_size", n))?;
        canvas.put_u16(start + key_descriptor::at::MAX_ENTRIES, d.max_entries, key_owner("max_entries", n))?;
        canvas.put_u16(start + key_descriptor::at::HALF_ENTRIES, d.half_entries, key_owner("half_entries", n))?;
        canvas.put_u16(start + key_descriptor::at::CHAIN, d.chain, key_owner("chain", n))?;
        canvas.put_u16(start + key_descriptor::at::OFFSET, d.offset, key_owner("offset", n))?;
        canvas.put_u16(start + key_descriptor::at::LENGTH, d.length, key_owner("length", n))?;
        canvas.put(start + key_descriptor::at::SELF_TAG, &[d.self_tag], key_owner("self_tag", n))?;
        canvas.put(
            start + key_descriptor::at::ACS_PAGE_HIGH,
            &[d.acs_page_high],
            key_owner("acs_page_high", n),
        )?;
        canvas.put(
            start + key_descriptor::at::ACS_PAGE_LOW,
            &[d.acs_page_low],
            key_owner("acs_page_low", n),
        )?;
        canvas.put(
            start + key_descriptor::at::ACS_PAGE_MID,
            &[d.acs_page_mid],
            key_owner("acs_page_mid", n),
        )?;
        canvas.put(start + key_descriptor::at::EXTENDED, &[d.extended], key_owner("extended", n))?;
        canvas.put(start + key_descriptor::at::NULL_VALUE, &[d.null_value], key_owner("null_value", n))?;
    }
    Ok(())
}

/// Write the key/segment definition array (`0x110` onward) and page 0's own
/// tail (`model.page_zero_tail`) that follows it, out to `page_size`, into
/// `canvas`. The tail is written verbatim -- it is not always zero, see
/// `model::File::page_zero_tail`.
///
/// # Errors
///
/// See [`Canvas::put`].
fn write_key_descriptors(canvas: &mut Canvas, model: &File) -> Result<(), Fault> {
    write_key_descriptor_array(canvas, &model.key_descriptors, 0)?;

    let after_definitions = key_descriptor::base(model.key_descriptors.len());
    let page_size = model.id.page_size as usize;
    if page_size > after_definitions {
        canvas.put(after_definitions, &model.page_zero_tail, owner("page_zero_tail"))?;
    }
    Ok(())
}

/// Write a v6 physical page's key/segment definition array, then its
/// definition-offset trailer and surrounding padding (Task 16) -- the
/// write-side counterpart to `read::v6_page_tail`. `tail.gap` and
/// `tail.padding` are written verbatim; the trailer's own `u16` slots are
/// not stored in `tail` at all, since they are a pure function of
/// `descriptors` -- see `model::V6PageTail`'s own doc comment for why, and
/// `format::fcr::trailer::expected_entries` for the one formula both this and
/// `read::v6_page_tail` share.
///
/// `base` is this physical page's own absolute byte offset (`0` for a
/// caller writing a lone page-sized canvas, `physical_page * page_size`
/// when writing straight into a whole file's canvas -- Task 18 needs the
/// latter, since the live and stale copies sit at different physical
/// pages).
///
/// When `page_size` has no trailer at all (512), `tail.padding` is empty
/// and `tail.gap` holds the whole remaining region instead -- see
/// `read::v6_page_tail`.
///
/// # Errors
///
/// See [`Canvas::put`].
pub(crate) fn write_v6_page_tail(
    canvas: &mut Canvas,
    page_size: usize,
    descriptors: &[KeyDescriptor],
    tail: &V6PageTail,
    base: usize,
) -> Result<(), Fault> {
    write_key_descriptor_array(canvas, descriptors, base)?;

    let after_definitions = base + key_descriptor::base(descriptors.len());

    let Some(trailer_pos) = fcr::trailer::position(page_size as u16) else {
        return canvas.put(after_definitions, &tail.gap, owner("page_tail"));
    };

    canvas.put(after_definitions, &tail.gap, owner("trailer_gap"))?;
    let self_tags: Vec<u8> = descriptors.iter().map(|d| d.self_tag).collect();
    for (n, value) in fcr::trailer::expected_entries(&self_tags).into_iter().enumerate() {
        canvas.put_u16(base + trailer_pos + n * 2, value, key_owner("definition_offset", n))?;
    }
    let after_trailer = base + trailer_pos + descriptors.len() * 2;
    canvas.put(after_trailer, &tail.padding, owner("trailer_padding"))?;
    Ok(())
}

fn alloc_owner(field: &'static str) -> Owner {
    Owner { structure: "v6_allocation_block", field, index: None }
}

fn alloc_entry_owner(index: usize) -> Owner {
    Owner { structure: "v6_allocation_block", field: "entry", index: Some(index) }
}

/// Write one allocation-table page's whole content -- one shadow copy, at
/// `base` (an absolute byte offset into `canvas`) -- the write-side
/// counterpart to `read::v6_allocation_copy`. Every entry is written
/// verbatim, allocated or not: an unallocated slot's marker (high byte
/// zero) and whatever physical page number happens to sit in its low half
/// are stored facts, not values this crate recomputes.
///
/// # Errors
///
/// See [`Canvas::put`].
pub(crate) fn write_v6_allocation_copy(
    canvas: &mut Canvas,
    copy: &V6AllocationBlockCopy,
    base: usize,
    page_size: usize,
) -> Result<(), Fault> {
    debug_assert_eq!(
        copy.entries.len(),
        alloc::entries_per_block(page_size),
        "a copy read at one page_size must not be written back at another"
    );
    canvas.put(base + alloc::at::MAGIC, alloc::MAGIC, alloc_owner("magic"))?;
    canvas.put_u16(base + alloc::at::BLOCK, copy.block, alloc_owner("block"))?;
    canvas.put_u16(base + alloc::at::GENERATION, copy.generation, alloc_owner("generation"))?;
    canvas.put(base + alloc::at::RESERVED_06, &copy.reserved_06, alloc_owner("reserved_06"))?;
    for (n, entry) in copy.entries.iter().enumerate() {
        let at = base + alloc::at::ENTRIES + n * alloc::ENTRY_WIDTH;
        canvas.put_u16(at, entry.marker, alloc_entry_owner(n))?;
        canvas.put_u16(at + 2, entry.physical_page, alloc_entry_owner(n))?;
    }
    // No trailing padding write: every corpus page size leaves the entry
    // array tiling the page exactly (`format::alloc`'s own doc comment), so
    // there is no byte left to describe here. If `page_size` ever disagreed,
    // `Canvas::finish` would fault on the unwritten range on its own --
    // exactly the outcome wanted, not a fabricated zero fill.
    Ok(())
}

fn v6_page_owner(field: &'static str, physical_page: u32) -> Owner {
    Owner { structure: "v6_page", field, index: Some(physical_page as usize) }
}

/// Write one ordinary v6 page (Task 18): its six-byte header
/// (`format::page::v6`) plus, when the model describes one
/// (`V6Page::content`), its fixed-length-record content -- every slot's own
/// marker, live or free, then the trailing slack. The write-side
/// counterpart to `read::read_v6_data_page`.
///
/// A live slot's marker is written from the model's own stored value, never
/// re-derived (harvest 5 SS1.2: what a specific nonzero marker means beyond
/// "live" is not established, so nothing here invents one). A free slot's
/// marker is the literal `0` -- not stored in [`crate::model::V6RecordSlot::Free`]
/// at all, since `0` is what "free" means, never a fact that could
/// disagree -- followed by its forwarding link
/// (`format::free_slot::encode_link`) and the model's own stored fill,
/// never re-zeroed.
///
/// `content` is `None` for a page this function does not write content
/// for -- an index page (`V6Page::index`, written by
/// `write_v6_index_pages` instead), an ACS block (`V6Page::acs`, written by
/// `write_v6_acs_blocks`), or a fragment/overflow page (`V6Page::fragment`,
/// Task 20, written by `write_v6_fragment_pages`), all three called
/// separately by [`file`] right after this one. Only a page where **all
/// four** of `content`/`index`/`acs`/`fragment` are `None` -- which
/// `read::file` never actually produces, since it refuses rather than build
/// a `V6Page` it cannot fully classify (`V6Page`'s own doc comment) --
/// would leave its body unwritten here, `Canvas::finish` reporting it the
/// same way an undescribed v5 page's content once did.
///
/// # Errors
///
/// See [`Canvas::put`].
fn write_v6_page(canvas: &mut Canvas, page: &V6Page, page_size: usize) -> Result<(), Fault> {
    let at = page.physical_page as usize * page_size;
    canvas.put_u16(at + page::v6::at::TAG, page.tag, v6_page_owner("tag", page.physical_page))?;
    canvas.put_u16(
        at + page::v6::at::LOGICAL,
        page.logical,
        v6_page_owner("logical", page.physical_page),
    )?;
    canvas.put_u16(at + page::v6::at::STAMP, page.stamp, v6_page_owner("stamp", page.physical_page))?;

    let Some(content) = &page.content else { return Ok(()) };
    let mut offset = at + page::v6::LEN;
    for slot in &content.slots {
        match slot {
            crate::model::V6RecordSlot::Live { marker, body } => {
                canvas.put_u16(
                    offset + free_slot::v6::at::MARKER,
                    *marker,
                    v6_page_owner("marker", page.physical_page),
                )?;
                canvas.put(
                    offset + free_slot::v6::at::MARKER_LEN,
                    body,
                    v6_page_owner("record", page.physical_page),
                )?;
                offset += free_slot::v6::at::MARKER_LEN + body.len();
            }
            crate::model::V6RecordSlot::Free { next, fill } => {
                canvas.put_u16(
                    offset + free_slot::v6::at::MARKER,
                    0,
                    v6_page_owner("marker", page.physical_page),
                )?;
                let link_at = offset + free_slot::v6::at::LINK;
                canvas.put(
                    link_at,
                    &free_slot::encode_link(*next),
                    v6_page_owner("free_link", page.physical_page),
                )?;
                canvas.put(
                    link_at + free_slot::at::LINK_LEN,
                    fill,
                    v6_page_owner("free_fill", page.physical_page),
                )?;
                offset = link_at + free_slot::at::LINK_LEN + fill.len();
            }
        }
    }
    canvas.put(offset, &content.slack, v6_page_owner("slack", page.physical_page))?;
    Ok(())
}

/// Write every v6 index page's content -- entry count, the two boundary
/// pointers, every entry, then trailing padding -- for every page whose
/// model carries one (`V6Page::index`, Task 19: `Some` for a page some
/// key's own walk attributed to its tree, root or descendant alike).
///
/// The same field-by-field write [`write_index_pages`] does for v5, at each
/// page's own absolute physical offset -- the entry-array layout past the
/// 6-byte header is identical in both families (harvest 4 SS4's own
/// framing), so there is nothing v6-specific to this beyond where the page
/// itself lives. In particular each pointer (`rightmost`/`leftmost`/entry
/// `child`) is written exactly as `read::read_index_page` stored it --
/// including its top-byte key tag -- never re-masked or re-derived.
///
/// # Errors
///
/// See [`Canvas::put`].
fn write_v6_index_pages(canvas: &mut Canvas, model: &File) -> Result<(), Fault> {
    let page_size = model.id.page_size as usize;
    for page in &model.v6_pages {
        let Some(idx) = &page.index else { continue };
        let at = page.physical_page as usize * page_size;

        let count = idx.entries.len() as u16;
        canvas.put_u16(at + index::at::COUNT, count, v6_page_owner("index_count", page.physical_page))?;
        canvas.put_long(
            at + index::at::RIGHTMOST,
            idx.rightmost,
            v6_page_owner("index_rightmost", page.physical_page),
        )?;
        canvas.put_long(
            at + index::at::LEFTMOST,
            idx.leftmost,
            v6_page_owner("index_leftmost", page.physical_page),
        )?;

        let mut offset = at + index::at::ENTRIES;
        for entry in &idx.entries {
            canvas.put(offset, &entry.key, v6_page_owner("index_key", page.physical_page))?;
            offset += entry.key.len();
            canvas.put_long(offset, entry.head, v6_page_owner("index_head", page.physical_page))?;
            offset += 4;
            if let Some(tail) = entry.tail {
                canvas.put_long(offset, tail, v6_page_owner("index_tail", page.physical_page))?;
                offset += 4;
            }
            if let Some(child) = entry.child {
                canvas.put_long(offset, child, v6_page_owner("index_child", page.physical_page))?;
                offset += 4;
            }
        }
        canvas.put(offset, &idx.padding, v6_page_owner("index_padding", page.physical_page))?;
    }
    Ok(())
}

/// Write every v6 ACS page's content -- tag, name, table, then trailing
/// padding -- for every page whose model carries one (`V6Page::acs`, Task
/// 19: `Some` for a page tagged `TAG_ACS`). The same field-by-field write
/// [`write_acs_blocks`] does for v5's single, fixed-page block -- the
/// 265-byte block layout is identical in both families (harvest 4 SS6:
/// "same layout in both families"), so only the page this writes to differs.
///
/// # Errors
///
/// See [`Canvas::put`].
fn write_v6_acs_blocks(canvas: &mut Canvas, model: &File) -> Result<(), Fault> {
    let page_size = model.id.page_size as usize;
    for page in &model.v6_pages {
        let Some(block) = &page.acs else { continue };
        let at = page.physical_page as usize * page_size;
        canvas.put(at + acs::at::TAG, &[block.tag], v6_page_owner("acs_tag", page.physical_page))?;
        canvas.put(at + acs::at::NAME, &block.name, v6_page_owner("acs_name", page.physical_page))?;
        canvas.put(at + acs::at::TABLE, &block.table, v6_page_owner("acs_table", page.physical_page))?;
        canvas.put(
            at + acs::at::TABLE + acs::at::TABLE_LEN,
            &block.padding,
            v6_page_owner("acs_padding", page.physical_page),
        )?;
    }
    Ok(())
}

/// Write one control record's fixed portion (`0x00..0x110`) into `canvas` at
/// `base` -- absolute offset `0` for a v5 file (there is only one copy), or
/// `0` / `page_size` for a v6 file's shadow pair, once per copy. Shared by
/// [`file`] and this module's own tests, which check the fixed portion in
/// isolation from the pages this crate does not yet describe.
///
/// `control` is the specific copy being written -- `model.control`'s single
/// record for v5, or whichever of `live`/`stale` this call is writing for
/// v6 -- never `model.live_control()`, which would write the live copy
/// twice and lose the stale one (harvest 0 ruling 7, part 2: the model
/// holds both copies in full, and emit must reproduce both, not the live
/// copy plus a flag).
///
/// # Errors
///
/// See [`Canvas::put`].
fn write_fixed_portion(
    canvas: &mut Canvas,
    model: &File,
    control: &ControlRecord,
    base: usize,
) -> Result<(), Fault> {
    // lead + version: what `format::generation::identify` reads to decide
    // family and generation -- this is its exact inverse. Byte `0x06` is
    // always zero in this corpus for both families; v5 encodes the
    // generation as `byte7` there, while v6's own version word lives at
    // `0x4a` instead, inside `reserved_44` below, and is carried verbatim
    // by that field rather than recomputed here.
    let (lead, version): ([u8; 4], [u8; 2]) = match model.id.generation {
        Generation::V5R3 => ([0, 0, 0, 0], [0, 3]),
        Generation::V5R4 => ([0, 0, 0, 0], [0, 4]),
        Generation::V5R5 => ([0, 0, 0, 0], [0, 5]),
        Generation::V600 | Generation::V610 | Generation::V620 => {
            ([b'F', b'C', 0, 0], [0, 0])
        }
    };
    canvas.put(base + fcr::at::LEAD, &lead, owner("lead"))?;
    canvas.put_u16(base + fcr::at::PAGE_GEN, control.page_gen, owner("page_gen"))?;
    canvas.put(base + fcr::at::VERSION, &version, owner("version"))?;
    canvas.put_u16(base + fcr::at::PAGE_SIZE, model.id.page_size, owner("page_size"))?;
    canvas.put(
        base + fcr::at::COMPANION_SELECTOR,
        &[control.companion_selector],
        owner("companion_selector"),
    )?;
    canvas.put(base + fcr::at::LOCK_FLAG, &[control.lock_flag], owner("lock_flag"))?;
    canvas.put_long(base + fcr::at::UNKNOWN_0C, control.unknown_0c, owner("unknown_0c"))?;
    canvas.put_long(base + fcr::at::FREE, control.free, owner("free"))?;
    canvas.put_u16(base + fcr::at::KEYS, control.keys, owner("keys"))?;
    canvas.put_u16(base + fcr::at::RECLEN, control.reclen, owner("reclen"))?;
    canvas.put_u16(base + fcr::at::PHYSICAL, control.physical, owner("physical"))?;
    canvas.put_long(base + fcr::at::RECORDS, control.records, owner("records"))?;
    canvas.put_long(base + fcr::at::HIGHEST, control.highest, owner("highest"))?;
    canvas.put_long(
        base + fcr::at::DATA_PAGE_COUNT,
        control.data_page_count,
        owner("data_page_count"),
    )?;
    canvas.put_long(base + fcr::at::PAGES, control.pages, owner("pages"))?;
    canvas.put_u16(base + fcr::at::PAGE_USABLE, control.page_usable, owner("page_usable"))?;
    canvas.put_u16(
        base + fcr::at::LOCK_TRANSACTION,
        control.lock_transaction,
        owner("lock_transaction"),
    )?;
    canvas.put_long(
        base + fcr::at::NEGATIVE_VERSION_A,
        control.negative_version_a,
        owner("negative_version_a"),
    )?;
    canvas.put_long(
        base + fcr::at::NEGATIVE_VERSION_B,
        control.negative_version_b,
        owner("negative_version_b"),
    )?;
    canvas.put(
        base + fcr::at::NEGATIVE_VERSION_C,
        &[control.negative_version_c],
        owner("negative_version_c"),
    )?;
    canvas.put(
        base + fcr::at::NEGATIVE_VERSION_D,
        &[control.negative_version_d],
        owner("negative_version_d"),
    )?;
    canvas.put(base + fcr::at::VARIABLE_TAG, &[control.variable_tag], owner("variable_tag"))?;
    canvas.put(
        base + fcr::at::VARIABLE_SUBFLAG,
        &[control.variable_subflag],
        owner("variable_subflag"),
    )?;
    canvas.put_u16(
        base + fcr::at::VARIABLE_HIGHEST,
        control.variable_highest,
        owner("variable_highest"),
    )?;
    canvas.put(base + fcr::at::ACS_NAME, &control.acs_name, owner("acs_name"))?;
    canvas.put(base + fcr::at::RESERVED_44, &control.reserved_44, owner("reserved_44"))?;
    canvas.put_u16(
        base + fcr::at::WRITE_COUNTER_68,
        control.write_counter_68,
        owner("write_counter_68"),
    )?;
    canvas.put(base + fcr::at::RESERVED_6A, &control.reserved_6a, owner("reserved_6a"))?;
    canvas.put_u16(base + fcr::at::USRFLGS, control.usrflgs, owner("usrflgs"))?;
    canvas.put(
        base + fcr::at::VARIABLE_PAGE_CAPACITY,
        &[control.variable_page_capacity],
        owner("variable_page_capacity"),
    )?;
    canvas.put(base + fcr::at::RESERVED_109, &[control.reserved_109], owner("reserved_109"))?;
    canvas.put_long(
        base + fcr::at::ACS_PAGE_POINTER,
        control.acs_page_pointer,
        owner("acs_page_pointer"),
    )?;
    canvas.put(base + fcr::at::RESERVED_10E, &control.reserved_10e, owner("reserved_10e"))?;
    Ok(())
}

/// Write one v6 control record's fixed portion (`0x00..0x110`) into `canvas`
/// at `base` -- absolute offset `0` or `page_size`, once per shadow copy.
/// Task 15's write-side counterpart to `read::v6_control_record`; every
/// offset here is `fcr::v6::*`, a genuinely different structure from
/// [`write_fixed_portion`]'s v5 one past `0x20` (see
/// `model::V6ControlRecord`'s own doc comment), not the same function with
/// different constants.
///
/// `page_size` is not read off `control` -- like v5's `lead`/`page_size`, it
/// is `Identified`'s job, carried by the caller rather than duplicated into
/// `V6ControlRecord`. **`version` no longer is** (Task 20): it used to be
/// derived from the caller's own `Identified.generation` the same way, on
/// the assumption that both shadow copies always report the same version --
/// `MULTIACS.DAT`'s stale copy disproved that (`model::V6ControlRecord::
/// version`'s own doc comment), so this function now writes each copy's own
/// stored `version` verbatim instead of re-deriving one from a single
/// file-wide generation.
///
/// # Errors
///
/// See [`Canvas::put`].
pub(crate) fn write_v6_fixed_portion(
    canvas: &mut Canvas,
    page_size: u16,
    control: &V6ControlRecord,
    base: usize,
) -> Result<(), Fault> {
    let version = control.version.to_le_bytes();
    canvas.put(base + fcr::at::LEAD, &[b'F', b'C', 0, 0], owner("lead"))?;
    canvas.put_u16(base + fcr::v6::GENERATION, control.generation, owner("generation"))?;
    canvas.put(base + fcr::v6::RESERVED_06, &control.reserved_06, owner("reserved_06"))?;
    canvas.put_u16(base + fcr::v6::PAGE_SIZE, page_size, owner("page_size"))?;
    canvas.put(base + fcr::v6::RESERVED_0A, &control.reserved_0a, owner("reserved_0a"))?;
    canvas.put(base + fcr::v6::RESERVED_0C, &control.reserved_0c.to_le_bytes(), owner("reserved_0c"))?;
    canvas.put_long(base + fcr::v6::FREE, control.free, owner("free"))?;
    canvas.put_u16(base + fcr::v6::KEYS, control.keys, owner("keys"))?;
    canvas.put_u16(base + fcr::v6::RECLEN, control.reclen, owner("reclen"))?;
    canvas.put_u16(base + fcr::v6::PHYSICAL, control.physical, owner("physical"))?;
    canvas.put_long(base + fcr::v6::RECORDS, control.records, owner("records"))?;
    canvas.put_u16(base + fcr::v6::HIGHEST, control.highest, owner("highest"))?;
    canvas.put_u16(base + fcr::v6::RESERVED_20, control.reserved_20, owner("reserved_20"))?;
    canvas.put_u16(base + fcr::v6::SENTINEL_22, control.sentinel_22, owner("sentinel_22"))?;
    canvas.put_u16(base + fcr::v6::SENTINEL_24, control.sentinel_24, owner("sentinel_24"))?;
    canvas.put_long(base + fcr::v6::PAGES, control.pages, owner("pages"))?;
    canvas.put_u16(base + fcr::v6::RESERVED_2A, control.reserved_2a, owner("reserved_2a"))?;
    canvas.put(base + fcr::v6::RESERVED_2C, &control.reserved_2c, owner("reserved_2c"))?;
    canvas.put(
        base + fcr::v6::VARIABLE_MARK,
        &control.variable_mark.to_le_bytes(),
        owner("variable_mark"),
    )?;
    canvas.put(base + fcr::v6::ACS_NAME, &control.acs_name, owner("acs_name"))?;
    canvas.put(base + fcr::v6::RESERVED_44, &control.reserved_44, owner("reserved_44"))?;
    canvas.put(base + fcr::v6::VERSION, &version, owner("version"))?;
    canvas.put_u16(base + fcr::v6::USAGE_4C, control.usage_4c, owner("usage_4c"))?;
    canvas.put_u16(base + fcr::v6::INDEX_ALLOC_4E, control.index_alloc_4e, owner("index_alloc_4e"))?;
    canvas.put_u16(base + fcr::v6::MIRROR_50, control.mirror_50, owner("mirror_50"))?;
    canvas.put_u16(base + fcr::v6::USAGE_52, control.usage_52, owner("usage_52"))?;
    canvas.put_u16(base + fcr::v6::RESERVED_54, control.reserved_54, owner("reserved_54"))?;
    canvas.put(base + fcr::v6::STAMP_56, &control.stamp_56, owner("stamp_56"))?;
    canvas.put(base + fcr::v6::RESERVED_5A, &control.reserved_5a, owner("reserved_5a"))?;
    canvas.put(base + fcr::v6::RESERVED_60, &control.reserved_60, owner("reserved_60"))?;
    canvas.put_u16(base + fcr::v6::WRITE_COUNTER, control.write_counter, owner("write_counter"))?;
    canvas.put(base + fcr::v6::RESERVED_6A, &control.reserved_6a, owner("reserved_6a"))?;
    canvas.put(base + fcr::v6::RESERVED_72, &control.reserved_72, owner("reserved_72"))?;
    canvas.put(base + fcr::v6::RESERVED_7C, &control.reserved_7c, owner("reserved_7c"))?;
    canvas.put(base + fcr::v6::RESERVED_90, &control.reserved_90, owner("reserved_90"))?;
    canvas.put_long(base + fcr::v6::FREE_V6, control.free_v6, owner("free_v6"))?;
    canvas.put_long(base + fcr::v6::VARIABLE_HEAD, control.variable_head, owner("variable_head"))?;
    canvas.put(base + fcr::v6::RESERVED_A4, &control.reserved_a4, owner("reserved_a4"))?;
    canvas.put(base + fcr::v6::RESERVED_D4, &control.reserved_d4, owner("reserved_d4"))?;
    canvas.put(base + fcr::v6::RESERVED_100, &control.reserved_100, owner("reserved_100"))?;
    canvas.put(base + fcr::v6::RESERVED_106, &control.reserved_106, owner("reserved_106"))?;
    canvas.put_long(base + fcr::v6::ACS_PAGE, control.acs_page, owner("acs_page"))?;
    canvas.put(base + fcr::v6::RESERVED_10E, &control.reserved_10e, owner("reserved_10e"))?;
    Ok(())
}

/// Produce the bytes of the file this model describes.
///
/// # Errors
///
/// If the model does not yet describe every byte of the file. For
/// `Control::Shadowed` (v6): both control-record shadow copies are written
/// in full, each at its own physical page (harvest 0 ruling 7, part 2, never
/// the live copy plus a flag or the live copy written twice); each copy's
/// own key/segment definitions and definition-offset trailer (`model.
/// key_descriptors`/`v6_page_tail` for the live copy, `v6_stale_key_
/// descriptors`/`v6_stale_page_tail` for the stale one, both `None`/empty
/// when the model does not carry them); every "PP" allocation-table block's
/// both shadow copies (`model.v6_allocation_blocks`, Task 17); and every
/// ordinary v6 page the allocation table resolves (`model.v6_pages`) -- a
/// genuine data page's header, per-slot marker and record content
/// (`V6Page::content`, Task 18); an index page's own entry array, for a
/// page some key's own walk attributed to its tree, root or descendant
/// alike (`V6Page::index`, Task 19 -- `write_v6_index_pages`); and a v6
/// ACS block's tag, name, table and padding (`V6Page::acs`, Task 19 --
/// `write_v6_acs_blocks`), found by scanning for `TAG_ACS` rather than at a
/// fixed page the way v5's single block is; and a fragment/overflow page's
/// free-chain link, every fragment, and trailing free space (`V6Page::
/// fragment`, Task 20 -- `write_v6_fragment_pages`), found by its own
/// `TAG_VARIABLE` tag, whether or not the file also holds ordinary
/// `TAG_DATA` pages (Task 20 also removed the `variable_mark` gate that used
/// to keep a variable-length file's `TAG_DATA` pages unread). `read::file`
/// refuses a v6 file whose allocation table claims a page this crate cannot
/// classify this way -- a `TAG_TEMPLATE` page, or a tag it does not
/// recognize, that no key's walk claims -- so this function never has to
/// guess at one either. A v5 file's
/// page 0 (the control record plus its key/segment definitions) is fully
/// described and will round-trip on its own; every page's six-byte header
/// round-trips too; a `Data`/`Free` page's slots and slack described
/// (variable-length or not -- harvest 5 SS1.1's slot layout does not change
/// shape); every index page -- a key's own root **and** every genuine
/// descendant that key's own walk attributed it to (Task 11b) -- has its
/// entry array described; a v5 file's ACS block (`Page::acs`) has its tag,
/// name, table and trailing padding described; and a variable-length file's
/// fragment/overflow page (`Page::fragments`, harvest 5 SS3.3) has every
/// fragment, the entry array's boundary member, and trailing free space
/// described as well. An orphan page (`Page::orphan`, Task 13 -- a page no
/// root, ACS claim, free chain, or key's walk reaches) has its whole body
/// written back verbatim, unparsed. A file this crate could read at all now
/// round-trips completely, multi-page B-tree and abandoned pages included.
pub fn file(model: &File) -> Result<Emitted, Fault> {
    let mut canvas = Canvas::new(model.len as usize);

    let Control::Single(control) = &model.control else {
        // `Control::Shadowed`: write both copies, in full, each at its own
        // physical page. Not the live copy plus a flag and not the live
        // copy written twice -- that would silently lose the stale copy's
        // exact bytes, exactly the failure mode ruling 7 exists to
        // forbid.
        let Control::Shadowed { live, stale, live_is_page } = &model.control else {
            unreachable!("the Single arm above already matched")
        };
        let page_size = model.id.page_size as usize;
        let stale_is_page = 1 - live_is_page;
        write_v6_fixed_portion(&mut canvas, model.id.page_size, live, live_is_page * page_size)?;
        write_v6_fixed_portion(&mut canvas, model.id.page_size, stale, stale_is_page * page_size)?;

        if let Some(tail) = &model.v6_page_tail {
            write_v6_page_tail(
                &mut canvas,
                page_size,
                &model.key_descriptors,
                tail,
                live_is_page * page_size,
            )?;
        }
        if let Some(tail) = &model.v6_stale_page_tail {
            write_v6_page_tail(
                &mut canvas,
                page_size,
                &model.v6_stale_key_descriptors,
                tail,
                stale_is_page * page_size,
            )?;
        }

        for (index, block) in model.v6_allocation_blocks.iter().enumerate() {
            let (first, second) = alloc::pair_position(page_size, index + 1);
            let (live_pos, stale_pos) = if block.live_is_first { (first, second) } else { (second, first) };
            write_v6_allocation_copy(&mut canvas, &block.live, live_pos * page_size, page_size)?;
            write_v6_allocation_copy(&mut canvas, &block.stale, stale_pos * page_size, page_size)?;
        }

        for page in &model.v6_pages {
            write_v6_page(&mut canvas, page, page_size)?;
        }
        write_v6_index_pages(&mut canvas, model)?;
        write_v6_acs_blocks(&mut canvas, model)?;
        write_v6_fragment_pages(&mut canvas, model)?;

        return canvas.finish();
    };

    write_fixed_portion(&mut canvas, model, control, 0)?;
    write_key_descriptors(&mut canvas, model)?;
    write_page_headers(&mut canvas, model)?;
    write_page_content(&mut canvas, model)?;
    write_index_pages(&mut canvas, model)?;
    write_acs_blocks(&mut canvas, model)?;
    write_fragment_pages(&mut canvas, model)?;
    write_orphan_pages(&mut canvas, model)?;
    canvas.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::fixtures::{
        full_index_page_with_an_omitted_last_child, two_key_fixed_portion, usracc_dat,
        usracc_first_page, usracc_fixed_portion, variable_length_file_with_a_real_fragment_page,
    };
    use crate::read;

    /// A hand-built `V6ControlRecord`, real enough to round-trip through a
    /// canvas but not claiming to be any particular corpus file -- only
    /// `generation` and `records` vary between calls, which is all
    /// `a_v6_shadow_pair_writes_both_copies_not_the_live_one_twice` needs to
    /// tell the two shadow copies apart.
    fn sample_v6_control(generation: u16, records: u32) -> V6ControlRecord {
        V6ControlRecord {
            generation,
            reserved_06: [0, 0],
            reserved_0a: [0, 0],
            reserved_0c: 0xffff_ffff,
            free: 0xffff_ffff,
            keys: 1,
            reclen: 128,
            physical: 128,
            records,
            highest: 0,
            reserved_20: 0,
            sentinel_22: 0xffff,
            sentinel_24: 1,
            pages: 3,
            reserved_2a: 0,
            reserved_2c: [0; 12],
            variable_mark: 0,
            acs_name: [0; 8],
            reserved_44: [0; 6],
            version: 0x600,
            usage_4c: 1,
            index_alloc_4e: 16,
            mirror_50: 1,
            usage_52: 3,
            reserved_54: 0,
            stamp_56: [0; 4],
            reserved_5a: [0xff; 6],
            reserved_60: [0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00],
            write_counter: 0,
            reserved_6a: [0; 8],
            reserved_72: [0; 10],
            reserved_7c: [0; 20],
            reserved_90: [0; 12],
            free_v6: 0,
            variable_head: 0xff00_ffff,
            reserved_a4: [0; 48],
            reserved_d4: [0; 44],
            reserved_100: [0; 6],
            reserved_106: [0; 4],
            acs_page: 0,
            reserved_10e: [0; 2],
        }
    }

    /// The fixed portion round-trips byte for byte: read it, emit it back
    /// into a canvas sized to exactly `0x110`, and compare against the
    /// original bytes in that same range.
    #[test]
    fn the_v5_fixed_portion_round_trips() {
        let original = usracc_fixed_portion();
        let model = read::file(&original).expect("reads");

        let mut canvas = Canvas::new(fcr::at::FIXED_LEN);
        write_fixed_portion(&mut canvas, &model, model.live_control(), 0).expect("every field is in range");
        let emitted = canvas.finish().expect("the fixed portion is fully described");

        assert_eq!(emitted.bytes(), &original[..fcr::at::FIXED_LEN]);
    }

    /// Harvest 0 ruling 7, part 2: the model holds both shadow copies in
    /// full, and `emit` must reproduce both -- not the live copy plus a
    /// flag, and not the live copy written twice. Two real, independently
    /// measured control records (both derived from `usracc_fixed_portion`,
    /// one edited so it is genuinely a different record, not a hand-typed
    /// stand-in) are wrapped as `Control::Shadowed` with the live copy on
    /// physical page 1, and `emit::file` must place each copy's own bytes
    /// on its own physical page.
    ///
    /// `page_size` is deliberately `fcr::at::FIXED_LEN` (`0x110`) here, not
    /// a real v6 page size -- that leaves no trailing tail past the fixed
    /// portion for either copy to model, which is convenient here but is
    /// not a shape `read::file` would ever produce: `identify` itself
    /// requires a v6 page size to be a nonzero multiple of `0x200`
    /// (`fcr::v6_fixed`'s own `page_size` citation), and `0x110` is
    /// neither. This model is also otherwise empty (no key descriptors, no
    /// allocation blocks, no `v6_pages`) in a way no real read produces
    /// either. So this test constructs the model by hand -- not because
    /// `read::file` cannot yet produce a `Control::Shadowed` `File` (it can,
    /// as of Task 19, for real v6 files with a real page size) -- to
    /// exercise `emit`'s side of ruling 7 in isolation from everything else
    /// a real v6 file would also need described.
    #[test]
    fn a_v6_shadow_pair_writes_both_copies_not_the_live_one_twice() {
        use crate::format::generation::Identified;

        let stale = sample_v6_control(1, 0); // generation 1, records 0: stale
        let live = sample_v6_control(2, 26_720); // generation 2, records 26720: live
        assert_ne!(live, stale, "the two copies must actually differ, or this test proves nothing");

        let page_size = fcr::v6::FIXED_LEN;
        let model = File {
            id: Identified { generation: Generation::V600, page_size: page_size as u16 },
            control: Control::Shadowed { live: live.clone(), stale: stale.clone(), live_is_page: 1 },
            key_descriptors: Vec::new(),
            page_zero_tail: Vec::new(),
            pages: Vec::new(),
            v6_stale_key_descriptors: Vec::new(),
            v6_page_tail: None,
            v6_stale_page_tail: None,
            v6_allocation_blocks: Vec::new(),
            v6_pages: Vec::new(),
            len: (2 * page_size) as u64,
        };

        let emitted = file(&model).expect("both copies are fully described");
        let bytes = emitted.bytes();

        let mut want_page0 = Canvas::new(page_size);
        write_v6_fixed_portion(&mut want_page0, page_size as u16, &stale, 0)
            .expect("stale, alone");
        let want_page0 = want_page0.finish().expect("fully described");
        assert_eq!(
            &bytes[0..page_size],
            want_page0.bytes(),
            "physical page 0 (stale, live_is_page == 1) must carry the STALE record's own bytes"
        );

        let mut want_page1 = Canvas::new(page_size);
        write_v6_fixed_portion(&mut want_page1, page_size as u16, &live, 0)
            .expect("live, alone");
        let want_page1 = want_page1.finish().expect("fully described");
        assert_eq!(
            &bytes[page_size..2 * page_size],
            want_page1.bytes(),
            "physical page 1 (live) must carry the LIVE record's own bytes"
        );
    }

    /// Page 0 as a whole -- fixed portion, key/segment definition, and zero
    /// padding out to `page_size` -- round-trips byte for byte for a
    /// single-page model (`model.len == page_size`, the shape a virgin
    /// one-page file would have).
    #[test]
    fn a_single_page_v5_file_round_trips_completely() {
        // `usracc_first_page` carries the real USRACC.DAT key descriptor's
        // `root_page` (1) verbatim, but this fixture is deliberately
        // truncated to page 0 alone -- not a real page 1 for that root to
        // name. Since Task 11b, `read::file` walks every declared root, so
        // a genuinely single-page (virgin, no B-tree yet) file must say so
        // itself: zero the root word here, locally, rather than in the
        // shared fixture other tests still check against its real value.
        let mut original = usracc_first_page();
        original[0x110..0x114].copy_from_slice(&[0, 0, 0, 0]); // root = 0: no B-tree yet
        let model = read::file(&original).expect("reads");
        let emitted = file(&model).expect("page 0 is fully described -- fixed portion plus one key descriptor plus page_zero_tail");
        assert_eq!(emitted.bytes(), original.as_slice());
    }

    /// The same, with two key descriptors -- proving the writer handles more
    /// than one repetition, not just the single-definition USRACC.DAT case.
    #[test]
    fn a_single_page_v5_file_with_two_keys_round_trips_completely() {
        // Same adjustment as above: both keys' roots are zeroed locally so
        // this stays a genuine (if virgin) single-page file under Task
        // 11b's walk, rather than two dangling pointers into pages the
        // 512-byte buffer never contains.
        let mut original = two_key_fixed_portion();
        original[0x110..0x114].copy_from_slice(&[0, 0, 0, 0]); // key 0's root = 0
        original[0x12e..0x132].copy_from_slice(&[0, 0, 0, 0]); // key 1's root = 0
        let model = read::file(&original).expect("reads");
        let emitted = file(&model).expect("two key descriptors plus page_zero_tail tile page 0");
        assert_eq!(emitted.bytes(), original.as_slice());
    }

    /// Task 11b resolves exactly what this test used to prove `emit` could
    /// not yet do: `FW_QSQDB.DA_`'s pages 3, 7, 11, and 12 are `IndexChild`
    /// nodes no key's root names (`read`'s own
    /// `a_real_files_unrooted_btree_nodes_classify_as_index_children`
    /// measures this), and are now attributed to whichever of the file's
    /// three keys' walks actually reaches them -- so the whole file,
    /// multi-page B-tree included, round-trips byte for byte.
    #[test]
    fn a_real_files_multi_page_btree_round_trips_completely() {
        let Some(root) = crate::corpus::root() else {
            eprintln!("emit: no archive/ on this box, nothing verified");
            return;
        };
        let path = root.join(
            "modules/butt-care/DOS Software/BBS/MajorBBS/4EVER/Addons/Farwest Trivia v3.23a/COPY/FW_QSQDB.DA_",
        );
        let Ok(original) = std::fs::read(&path) else {
            eprintln!("emit: FW_QSQDB.DA_ not present, nothing verified");
            return;
        };
        let model = read::file(&original).expect("FW_QSQDB.DA_ is a valid v5 file");
        let emitted = file(&model).expect(
            "every page is now described -- data, ACS-free, fragment, and \
             every IndexChild page a key's own walk reached",
        );
        assert_eq!(emitted.bytes(), original.as_slice());
    }

    /// The three v5 corpus files that carry **both** a genuine multi-page
    /// B-tree and a continuing fragment chain -- this task's own
    /// highest-value targets (Task 11b's brief): each one that round-trips
    /// proves the walk here *and* gives the previous task's fragment-chain
    /// work its first real corpus witness, since every such file used to
    /// fault on an unresolved `IndexChild` page before either byte of a
    /// fragment was ever compared.
    #[test]
    fn the_three_multi_page_fragment_chain_files_round_trip_completely() {
        let Some(root) = crate::corpus::root() else {
            eprintln!("emit: no archive/ on this box, nothing verified");
            return;
        };
        for rel in [
            "modules/butt-care/DOS Software/BBS/MajorBBS/4EVER/Addons/Farwest Trivia v3.23a/Addons/FW_QSQDB.DAT",
            "modules/butt-care/DOS Software/BBS/MajorBBS/4EVER/Addons/Jabberwocky Teleconference Trivia v2.2/COPY/JABTTQST.DAT",
            "tooling/wbtrv32/assets/VARIABLE.DAT",
        ] {
            let path = root.join(rel);
            let Ok(original) = std::fs::read(&path) else {
                eprintln!("emit: {rel} not present, nothing verified");
                continue;
            };
            let model = read::file(&original).unwrap_or_else(|e| panic!("{rel}: {}", e.why));
            let emitted =
                file(&model).unwrap_or_else(|e| panic!("{rel}: emit faulted: {e}"));
            assert_eq!(emitted.bytes(), original.as_slice(), "{rel} round-trips byte for byte");
        }
    }

    /// `wcctext.nu1`: the largest variable-length file in the corpus (5.4
    /// MB, 2,639 pages, 2,541 records), present at all only because an
    /// earlier ruling deleted the filename filter that used to hide it
    /// (`corpus`'s own `the_walk_reaches_the_largest_variable_length_v5_file`
    /// test). Its one key's B-tree spans 64 pages (measured for this task)
    /// -- a genuine, if shallow, multi-page tree over the largest
    /// fragment-chain file this crate reads.
    #[test]
    fn wcctext_nu1_round_trips_completely() {
        let Some(root) = crate::corpus::root() else {
            eprintln!("emit: no archive/ on this box, nothing verified");
            return;
        };
        let path = root.join("modules/majormud-nt/wccnt7pz/out/wcctext.nu1");
        let Ok(original) = std::fs::read(&path) else {
            eprintln!("emit: wcctext.nu1 not present, nothing verified");
            return;
        };
        let model = read::file(&original).expect("wcctext.nu1 is a valid v5 file");
        let emitted = file(&model).expect("every page -- data, fragment, and every IndexChild page its key's walk reached -- is described");
        assert_eq!(emitted.bytes(), original.as_slice());
    }

    /// Page 1's own six-byte header round-trips byte for byte, checked in
    /// isolation the same way `the_v5_fixed_portion_round_trips` checks page
    /// 0's fixed portion alone: a two-page model (page 0 plus page 1, no
    /// page 2) writes exactly `page_size + 6` bytes with nothing left over,
    /// because page 1's content is the only thing past its header and this
    /// model is deliberately shaped to have none.
    #[test]
    fn a_pages_own_header_round_trips_in_isolation() {
        let mut original = usracc_first_page();
        original.resize(1024, 0); // page 0 plus page 1, page 1 otherwise empty
        original[512..518].copy_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x03, 0x00]);
        let model = read::file(&original).expect("reads");
        assert_eq!(model.pages.len(), 1, "page 1 only");

        let mut canvas = Canvas::new(512 + page::LEN);
        write_fixed_portion(&mut canvas, &model, model.live_control(), 0)
            .expect("page 0's fixed portion");
        write_key_descriptors(&mut canvas, &model).expect("page 0's key descriptor and padding");
        write_page_headers(&mut canvas, &model).expect("page 1's header");
        let emitted = canvas.finish().expect("512 + 6 bytes, all written");

        assert_eq!(emitted.bytes(), &original[..512 + page::LEN]);
    }

    /// Step 4/5 of this task, end to end: a file with no keys at all has no
    /// index page to leave undescribed, so its one data page -- carrying
    /// `USRACC.DAT`'s own real two records, reused from [`usracc_dat`] --
    /// is the *only* thing past page 0, and the whole file now round-trips
    /// completely. This is the concrete case the task brief's "EXPECTED
    /// OUTCOME" describes: data pages stop being the reason a file faults.
    #[test]
    fn a_data_page_with_no_preceding_index_page_round_trips_completely() {
        use crate::model::PageKind;

        let mut original = usracc_fixed_portion();
        original[0x14..0x16].copy_from_slice(&0u16.to_le_bytes()); // keys = 0
        original.resize(1024, 0);
        let real_page_two = &usracc_dat()[1024..1536];
        original[512..1024].copy_from_slice(real_page_two);

        let model = read::file(&original).expect("reads");
        assert_eq!(model.pages.len(), 1, "page 1 only, and nothing claims it");
        assert_eq!(model.pages[0].kind, PageKind::Data, "unclaimed, data_bit set");

        let emitted = file(&model)
            .expect("zero keys leaves nothing undescribed: page 0 plus one fully-described data page");
        assert_eq!(emitted.bytes(), original.as_slice());
    }

    /// Step 1/4 of this task, and the whole point of it: `USRACC.DAT`
    /// round-trips completely for the first time. Page 0 (fixed portion,
    /// key descriptor, page_zero_tail), page 1's header plus its index
    /// content (2 entries), and page 2's header plus its 2 data slots and
    /// slack are now *all* described -- nothing left for the canvas to
    /// fault on.
    #[test]
    fn usracc_dat_round_trips_byte_for_byte() {
        let original = usracc_dat();
        let model = read::file(&original).expect("reads");
        let emitted = file(&model).expect(
            "USRACC.DAT has one key, one index root page, and one data page -- \
             every byte of it is now described",
        );
        assert_eq!(emitted.bytes(), original.as_slice());
    }

    /// The last-entry **omission** branch round-trips too, not just the
    /// present-zero case `usracc_dat_round_trips_byte_for_byte` above
    /// covers: a synthetic page styled after `WCCSPELS.VIR` (harvest 4
    /// SS4) whose last entry's trailing 4-byte `child` field has no room
    /// at all. `write_index_pages` must write *nothing* for that field --
    /// the model says `None`, and the page is already exactly full.
    /// Unwitnessed by any of the 102 real corpus files that pass today
    /// (see `model::fixtures::full_index_page_with_an_omitted_last_child`'s
    /// own doc for the 42%-fullest measurement); this is the fixture the
    /// review asked for.
    #[test]
    fn a_full_index_pages_omitted_child_round_trips_completely() {
        let original = full_index_page_with_an_omitted_last_child();
        let model = read::file(&original).expect("reads");
        let emitted = file(&model)
            .expect("a full index root with no data page -- nothing left undescribed");
        assert_eq!(emitted.bytes(), original.as_slice());
    }

    /// This task's mutation case (brief Step 6), against a genuine corpus
    /// file rather than a contrived one: `wccnt7pz/out/wccitem2.vir`,
    /// page 592, is one of exactly 5 real data/free pages this task's own
    /// corpus measurement found with non-zero slack (874 bytes of leftover
    /// item-description text past the page's 3 live 1072-byte slots). A
    /// synthetic zero-key control record puts this real page directly after
    /// page 0, so the whole file is fully described and must round-trip
    /// byte for byte -- including those 874 bytes. If `write_page_content`
    /// were mutated to emit `vec![0; content.slack.len()]` instead of
    /// `content.slack` itself, this assertion is exactly what would catch
    /// it: the emitted bytes would differ from the real file at the slack
    /// range, this test would go red, and no other test in this module
    /// would notice (every other model here has all-zero slack).
    #[test]
    fn a_real_files_nonzero_slack_round_trips_and_would_catch_a_zeroing_mutation() {
        use crate::model::PageKind;

        let Some(root) = crate::corpus::root() else {
            eprintln!("emit: no archive/ on this box, nothing verified");
            return;
        };
        let path = root.join("modules/majormud-nt/wccnt7pz/out/wccitem2.vir");
        let Ok(real) = std::fs::read(&path) else {
            eprintln!("emit: wccitem2.vir not present, nothing verified");
            return;
        };

        const PAGE_SIZE: usize = 4096;
        const PHYSICAL: u16 = 1072;
        let page_592 = &real[592 * PAGE_SIZE..593 * PAGE_SIZE];

        let mut original = vec![0u8; PAGE_SIZE];
        original[0x06..0x08].copy_from_slice(&[0, 4]); // version -> V5R4, this file's own generation
        original[0x08..0x0a].copy_from_slice(&(PAGE_SIZE as u16).to_le_bytes());
        original[0x0c..0x10].copy_from_slice(&0xffff_ffffu32.to_le_bytes()); // unknown_0c = NOWHERE
        original[0x10..0x14].copy_from_slice(&0xffff_ffffu32.to_le_bytes()); // free = NOWHERE
        original[0x14..0x16].copy_from_slice(&0u16.to_le_bytes()); // keys = 0
        original[0x16..0x18].copy_from_slice(&PHYSICAL.to_le_bytes()); // reclen
        original[0x18..0x1a].copy_from_slice(&PHYSICAL.to_le_bytes()); // physical
        original.extend_from_slice(page_592);

        let model = read::file(&original).expect("reads: a synthetic zero-key file");
        assert_eq!(model.pages.len(), 1);
        assert_eq!(model.pages[0].kind, PageKind::Data);
        let content = model.pages[0].content.as_ref().expect("a data page's content is described");
        assert_eq!(content.slots.len(), 3, "3 whole 1072-byte slots fit in 4096 - 6 bytes");
        assert!(
            content.slack.iter().any(|&b| b != 0),
            "this is the real, measured non-zero-slack page -- if this assertion \
             ever fails, the fixture stopped pointing at the right page"
        );

        let emitted =
            file(&model).expect("zero keys leaves nothing undescribed but this one data page");
        assert_eq!(
            emitted.bytes(),
            original.as_slice(),
            "the 874 non-zero slack bytes must come back verbatim, not as zeroes"
        );
    }

    /// This task, end to end on a named ACS-bearing corpus file:
    /// `WLDSLOTS.DAT` (V5R4, `GALCAPS` table, a correct `0x10a` pointer)
    /// round-trips completely -- page 0, its one key's index root, its one
    /// data page, and now its ACS block are all described.
    #[test]
    fn wldslots_dat_round_trips_byte_for_byte() {
        let Some(root) = crate::corpus::root() else {
            eprintln!("emit: no archive/ on this box, nothing verified");
            return;
        };
        let path = root.join(
            "modules/butt-care/DOS Software/BBS/MajorBBS/4EVER/Addons/\
             Wilderlands Slotto America v1.1R/COPY/WLDSLOTS.DAT",
        );
        let Ok(original) = std::fs::read(&path) else {
            eprintln!("emit: WLDSLOTS.DAT not present, nothing verified");
            return;
        };
        let model = read::file(&original).expect("WLDSLOTS.DAT is a valid v5 file");
        assert!(
            model.pages.iter().any(|p| p.acs.is_some()),
            "WLDSLOTS.DAT carries a real ACS block"
        );
        let emitted = file(&model)
            .expect("WLDSLOTS.DAT's ACS block, index root, and data page are all described");
        assert_eq!(emitted.bytes(), original.as_slice());
    }

    /// The task brief's own target, and the harder of the two: `CLASSADS.DAT`
    /// reads **zero** at FCR `0x10a` while genuinely holding an ACS block on
    /// physical page 1 (harvest 4 SS6a). `read::resolve_pages` finds the page
    /// from a key's own `ALT_COLLATING` bit rather than trusting the lying
    /// pointer, and this test proves emit reproduces that page's real bytes
    /// -- not a page of zeroes matching the pointer's own claim of "no ACS
    /// here."
    #[test]
    fn classads_dat_round_trips_byte_for_byte_despite_the_lying_pointer() {
        let Some(root) = crate::corpus::root() else {
            eprintln!("emit: no archive/ on this box, nothing verified");
            return;
        };
        let path = root.join("galacticomm/hosts/majorbbs/CLASSADS.DAT");
        let Ok(original) = std::fs::read(&path) else {
            eprintln!("emit: CLASSADS.DAT not present, nothing verified");
            return;
        };
        let model = read::file(&original).expect("CLASSADS.DAT is a valid v5 file");
        assert_eq!(model.live_control().acs_page_pointer, 0, "the lying pointer");
        assert!(
            model.pages.iter().any(|p| p.acs.is_some()),
            "a real block is found by content despite the pointer"
        );
        let emitted = file(&model)
            .expect("CLASSADS.DAT's ACS block, index root, and data page are all described");
        assert_eq!(emitted.bytes(), original.as_slice());
    }

    /// An earlier task's own step 4/5 end to end: a synthetic v5 file
    /// wrapping a real `VARIABLE.DAT` page (physical page 15, harvest 5
    /// SS3.5's own named best evidence for a multi-hop chain -- fragment 0
    /// continues onto another page) round-trips completely. At the time
    /// every real corpus file carrying fragment pages also carried at least
    /// one unresolved `IndexChild` page, so this synthetic fixture -- zero
    /// keys, nothing else on the page -- was what proved the fragment-page
    /// writer byte for byte, independent of that then-unrelated gap. Task
    /// 11b closed that gap (`VARIABLE.DAT` itself now round-trips whole,
    /// see `the_three_multi_page_fragment_chain_files_round_trip_completely`
    /// above); this fixture stays, since it still isolates the fragment
    /// writer on its own.
    #[test]
    fn a_real_fragment_page_from_variable_dat_round_trips_byte_for_byte() {
        let original = variable_length_file_with_a_real_fragment_page();
        let model = read::file(&original).expect("reads");
        let emitted = file(&model).expect(
            "zero keys leaves nothing undescribed but this one fragment page, \
             fully described by this task",
        );
        assert_eq!(emitted.bytes(), original.as_slice());
    }

    /// This task's required mutation (brief step 6): emitting the fragment
    /// pointer through an **unscrambled** `[low][mid][high][fragment]`
    /// encoding instead of harvest 5 SS3.2's `[high][low][mid][fragment]`
    /// must produce different bytes for this fixture's own continuing
    /// fragment -- a real multi-hop chain from `VARIABLE.DAT`, the file
    /// harvest 5 SS3.5 measures at 72% multi-hop. Performed here by
    /// reproducing `write_fragment_pages`' own placement logic with the
    /// alternate byte order substituted for `Pointer::encode`, rather than
    /// editing the production function in place -- the manual mutation this
    /// task's report describes was run directly against
    /// `format::variable::Pointer::encode`, confirmed to turn this exact
    /// test (and `read`'s own decode-side mutation test) red, then reverted;
    /// this permanent test pins the same defect so a future change cannot
    /// silently reintroduce it.
    #[test]
    fn emitting_the_pointer_unscrambled_would_mismatch_the_real_chain() {
        let original = variable_length_file_with_a_real_fragment_page();
        let model = read::file(&original).expect("reads");
        let page = &model.pages[0];
        let fp = page.fragments.as_ref().expect("a fragment page");
        let crate::model::FragmentSlot::Live { next: Some(pointer), .. } = &fp.fragments[0] else {
            panic!("fragment 0 continues onto another page");
        };

        // The scrambled encoding this crate actually uses (and what the
        // real file's own bytes are, at fragment 0's leading four bytes,
        // page offset 0x0c).
        let scrambled = pointer.encode();
        let real_bytes = &original[512 + 0x0c..512 + 0x10];
        assert_eq!(&scrambled, real_bytes, "the scrambled encoding matches the real file");

        // The unscrambled reading harvest 5 SS3.2 names as the wrong one:
        // [low][mid][high][fragment] instead of [high][low][mid][fragment].
        let unscrambled = [
            pointer.page as u8,
            (pointer.page >> 8) as u8,
            (pointer.page >> 16) as u8,
            pointer.fragment,
        ];
        assert_ne!(
            &unscrambled, real_bytes,
            "an emitter that dropped the scramble would write different bytes here \
             than the real file has -- this is the mutation this task's Step 6 requires, \
             and it is not vacuous: it changes real, on-disk bytes"
        );
    }
}
