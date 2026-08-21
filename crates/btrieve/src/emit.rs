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
use crate::format::fcr;
use crate::format::fcr::key_descriptor;
use crate::format::free_slot;
use crate::format::generation::Generation;
use crate::format::index;
use crate::format::page;
use crate::format::variable;
use crate::model::{Control, ControlRecord, File, FragmentSlot, RecordSlot};

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

/// Write every fragment page's content -- the free-chain link, fragment
/// count, every fragment slot, the entry array's boundary member, and
/// trailing free space -- for every page whose model carries one
/// (`Page::fragments`, `Some` only for a `PageKind::Variable` page).
///
/// Every field is written from the model's own stored value: a fragment's
/// placement is never re-read from a stored offset (there isn't one -- see
/// `model::FragmentPage`'s own doc) but replayed by advancing a cursor the
/// same way `read::read_fragment_page` derived it in the first place, which
/// is reproducing an already-fully-known tiling, not guessing a new one.
/// `next: Some(pointer)`'s four bytes are written through
/// `variable::Pointer::encode` -- harvest 5 SS3.2's scrambled byte order --
/// which is exactly what this task's mutation test targets.
///
/// # Errors
///
/// See [`Canvas::put`].
fn write_fragment_pages(canvas: &mut Canvas, model: &File) -> Result<(), Fault> {
    let page_size = model.id.page_size as usize;
    for (i, p) in model.pages.iter().enumerate() {
        let Some(fp) = &p.fragments else { continue };
        let page_number = i + 1;
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
                    if next.is_some() {
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

/// Write the key/segment definition array (`0x110` onward) and page 0's own
/// tail (`model.page_zero_tail`) that follows it, out to `page_size`, into
/// `canvas`. The tail is written verbatim -- it is not always zero, see
/// `model::File::page_zero_tail`.
///
/// # Errors
///
/// See [`Canvas::put`].
fn write_key_descriptors(canvas: &mut Canvas, model: &File) -> Result<(), Fault> {
    for (n, d) in model.key_descriptors.iter().enumerate() {
        let start = key_descriptor::base(n);
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

    let after_definitions = key_descriptor::base(model.key_descriptors.len());
    let page_size = model.id.page_size as usize;
    if page_size > after_definitions {
        canvas.put(after_definitions, &model.page_zero_tail, owner("page_zero_tail"))?;
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

/// Produce the bytes of the file this model describes.
///
/// # Errors
///
/// If the model does not yet describe every byte of the file. A v6 file
/// today only ever reaches this function with `Control::Shadowed` through
/// this crate's own tests -- `read::file` refuses every real v6 file before
/// building one, since the allocation table, page addressing, and the rest
/// of v6's own pages are later work -- but when it is given one, both
/// control-record shadow copies are written in full, each through the
/// canvas, at physical pages 0 and 1 (harvest 0 ruling 7, part 2); nothing
/// past the shadow pair is written for v6 yet. A v5 file's page 0 (the
/// control record plus its key/segment definitions) is fully described and
/// will round-trip on its own; every page's six-byte header round-trips
/// too; a `Data`/`Free` page's slots and slack described (variable-length
/// or not -- harvest 5 SS1.1's slot layout does not change shape); every
/// index page -- a key's own root **and** every genuine descendant that
/// key's own walk attributed it to (Task 11b) -- has its entry array
/// described; a v5 file's ACS block (`Page::acs`) has its tag, name, table
/// and trailing padding described; and a variable-length file's
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
        // forbid. Nothing past the shadow pair is described yet, so this
        // is everything emit can do for v6 today.
        let Control::Shadowed { live, stale, live_is_page } = &model.control else {
            unreachable!("the Single arm above already matched")
        };
        let page_size = model.id.page_size as usize;
        let stale_is_page = 1 - live_is_page;
        write_fixed_portion(&mut canvas, model, live, live_is_page * page_size)?;
        write_fixed_portion(&mut canvas, model, stale, stale_is_page * page_size)?;
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
    /// portion for either copy to model, since a v6 file's own page trailer
    /// (harvest 2 "FCR size") is later work this task does not own. Nothing
    /// about `read::file` produces this shape today (it refuses every v6
    /// file before building one); this test constructs the model by hand to
    /// exercise `emit`'s side of ruling 7 in isolation.
    #[test]
    fn a_v6_shadow_pair_writes_both_copies_not_the_live_one_twice() {
        use crate::format::generation::Identified;

        let mut stale_bytes = usracc_fixed_portion();
        stale_bytes[0x04..0x06].copy_from_slice(&1u16.to_le_bytes()); // generation 1: stale
        stale_bytes[0x1a..0x1e].copy_from_slice(&[0, 0, 0, 0]); // records = 0

        let mut live_bytes = usracc_fixed_portion();
        live_bytes[0x04..0x06].copy_from_slice(&2u16.to_le_bytes()); // generation 2: live

        let stale = read::file(&stale_bytes).expect("a valid record").live_control().clone();
        let live = read::file(&live_bytes).expect("a valid record").live_control().clone();
        assert_ne!(live, stale, "the two copies must actually differ, or this test proves nothing");

        let page_size = fcr::at::FIXED_LEN;
        let model = File {
            id: Identified { generation: Generation::V600, page_size: page_size as u16 },
            control: Control::Shadowed { live: live.clone(), stale: stale.clone(), live_is_page: 1 },
            key_descriptors: Vec::new(),
            page_zero_tail: Vec::new(),
            pages: Vec::new(),
            len: (2 * page_size) as u64,
        };

        let emitted = file(&model).expect("both copies are fully described");
        let bytes = emitted.bytes();

        let mut want_page0 = Canvas::new(page_size);
        write_fixed_portion(&mut want_page0, &model, &stale, 0).expect("stale, alone");
        let want_page0 = want_page0.finish().expect("fully described");
        assert_eq!(
            &bytes[0..page_size],
            want_page0.bytes(),
            "physical page 0 (stale, live_is_page == 1) must carry the STALE record's own bytes"
        );

        let mut want_page1 = Canvas::new(page_size);
        write_fixed_portion(&mut want_page1, &model, &live, 0).expect("live, alone");
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
