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
//! slack -- `crate::model::DataPage`), and now an `Index` page's own entry
//! array too: the entry count, the two boundary pointers, every entry --
//! key, `head`, the duplicate-only `tail`, and the possibly-omitted `child`
//! -- plus trailing padding (`crate::model::IndexPage`). `USRACC.DAT`
//! round-trips completely as of this task -- the first real corpus file to
//! do so. An `IndexChild` page's content (a B-tree node no key's root
//! names, whose owning key this task does not resolve), the ACS block's
//! content, and a variable-length file's fragment-page content are all
//! still later tasks, so [`file`] still faults on any real corpus file that
//! has one of those -- but the fault names the first byte range *this*
//! crate still cannot describe, and 102 of 652 corpus files have none of
//! them.

use crate::canvas::{Canvas, Emitted, Fault, Owner};
use crate::format::fcr;
use crate::format::fcr::key_descriptor;
use crate::format::generation::Generation;
use crate::format::index;
use crate::format::page;
use crate::model::File;

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
/// Slack is written from the model's own stored bytes, never re-derived as
/// zero -- `read::read_data_page`'s doc measures 5 real corpus pages where
/// that would be wrong.
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
            canvas.put(offset, slot, page_owner("record", page_number))?;
            offset += slot.len();
        }
        canvas.put(offset, &content.slack, page_owner("slack", page_number))?;
    }
    Ok(())
}

/// Write every index page's content -- entry count, the two boundary
/// pointers, every entry, then trailing padding -- for every page whose
/// model carries one (`Page::index`, `Some` for an `Index` page; `None` for
/// a `Data`/`Free`/`Acs` page, or an `IndexChild` page whose owning key is
/// not yet resolved, both a later task, so those pages' bodies stay
/// unwritten and `Canvas::finish` reports them).
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

/// Write the key/segment definition array (`0x110` onward) and the zero
/// padding that follows it, out to `page_size`, into `canvas`.
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
        let zeros = vec![0u8; page_size - after_definitions];
        canvas.put(after_definitions, &zeros, owner("zero_padding"))?;
    }
    Ok(())
}

/// Write the v5 control record's fixed portion (`0x00..0x110`) into `canvas`.
/// Shared by [`file`] and this module's own tests, which check the fixed
/// portion in isolation from the pages this crate does not yet describe.
///
/// # Errors
///
/// See [`Canvas::put`].
fn write_fixed_portion(canvas: &mut Canvas, model: &File) -> Result<(), Fault> {
    let control = &model.control;

    // lead: 4 zero bytes -- what identifies the pre-v6 family.
    canvas.put(fcr::at::LEAD, &[0, 0, 0, 0], owner("lead"))?;
    canvas.put_u16(fcr::at::PAGE_GEN, control.page_gen, owner("page_gen"))?;

    // version: byte 6 is always zero in this corpus, byte 7 selects the
    // generation -- the exact inverse of format::generation::identify.
    let byte7 = match model.id.generation {
        Generation::V5R3 => 3u8,
        Generation::V5R4 => 4,
        Generation::V5R5 => 5,
        Generation::V600 | Generation::V610 | Generation::V620 => {
            unreachable!(
                "file() filters out v6 before calling write_fixed_portion"
            );
        }
    };
    canvas.put(fcr::at::VERSION, &[0, byte7], owner("version"))?;
    canvas.put_u16(fcr::at::PAGE_SIZE, model.id.page_size, owner("page_size"))?;
    canvas.put(
        fcr::at::COMPANION_SELECTOR,
        &[control.companion_selector],
        owner("companion_selector"),
    )?;
    canvas.put(fcr::at::LOCK_FLAG, &[control.lock_flag], owner("lock_flag"))?;
    canvas.put_long(fcr::at::UNKNOWN_0C, control.unknown_0c, owner("unknown_0c"))?;
    canvas.put_long(fcr::at::FREE, control.free, owner("free"))?;
    canvas.put_u16(fcr::at::KEYS, control.keys, owner("keys"))?;
    canvas.put_u16(fcr::at::RECLEN, control.reclen, owner("reclen"))?;
    canvas.put_u16(fcr::at::PHYSICAL, control.physical, owner("physical"))?;
    canvas.put_long(fcr::at::RECORDS, control.records, owner("records"))?;
    canvas.put_long(fcr::at::HIGHEST, control.highest, owner("highest"))?;
    canvas.put_long(fcr::at::DATA_PAGE_COUNT, control.data_page_count, owner("data_page_count"))?;
    canvas.put_long(fcr::at::PAGES, control.pages, owner("pages"))?;
    canvas.put_u16(fcr::at::PAGE_USABLE, control.page_usable, owner("page_usable"))?;
    canvas.put_u16(
        fcr::at::LOCK_TRANSACTION,
        control.lock_transaction,
        owner("lock_transaction"),
    )?;
    canvas.put_long(
        fcr::at::NEGATIVE_VERSION_A,
        control.negative_version_a,
        owner("negative_version_a"),
    )?;
    canvas.put_long(
        fcr::at::NEGATIVE_VERSION_B,
        control.negative_version_b,
        owner("negative_version_b"),
    )?;
    canvas.put(
        fcr::at::NEGATIVE_VERSION_C,
        &[control.negative_version_c],
        owner("negative_version_c"),
    )?;
    canvas.put(
        fcr::at::NEGATIVE_VERSION_D,
        &[control.negative_version_d],
        owner("negative_version_d"),
    )?;
    canvas.put(fcr::at::VARIABLE_TAG, &[control.variable_tag], owner("variable_tag"))?;
    canvas.put(fcr::at::VARIABLE_SUBFLAG, &[control.variable_subflag], owner("variable_subflag"))?;
    canvas.put_u16(fcr::at::VARIABLE_HIGHEST, control.variable_highest, owner("variable_highest"))?;
    canvas.put(fcr::at::ACS_NAME, &control.acs_name, owner("acs_name"))?;
    canvas.put(fcr::at::RESERVED_44, &control.reserved_44, owner("reserved_44"))?;
    canvas.put_u16(fcr::at::WRITE_COUNTER_68, control.write_counter_68, owner("write_counter_68"))?;
    canvas.put(fcr::at::RESERVED_6A, &control.reserved_6a, owner("reserved_6a"))?;
    canvas.put_u16(fcr::at::USRFLGS, control.usrflgs, owner("usrflgs"))?;
    canvas.put(
        fcr::at::VARIABLE_PAGE_CAPACITY,
        &[control.variable_page_capacity],
        owner("variable_page_capacity"),
    )?;
    canvas.put(fcr::at::RESERVED_109, &[control.reserved_109], owner("reserved_109"))?;
    canvas.put_long(fcr::at::ACS_PAGE_POINTER, control.acs_page_pointer, owner("acs_page_pointer"))?;
    canvas.put(fcr::at::RESERVED_10E, &control.reserved_10e, owner("reserved_10e"))?;
    Ok(())
}

/// Produce the bytes of the file this model describes.
///
/// # Errors
///
/// If the model does not yet describe every byte of the file. A v6 file's
/// control record is entirely undescribed. A v5 file's page 0 (the control
/// record plus its key/segment definitions) is fully described and will
/// round-trip on its own; every page's six-byte header round-trips too; a
/// `Data`/`Free` page of a non-variable-length file has its slots and slack
/// described; and now an `Index` page (a key's own root) has its entry
/// array described too. An `IndexChild` page's content, the ACS block's
/// content, and a variable-length file's fragment-page content are not, so
/// a real corpus file that has one of those still leaves the canvas with
/// unwritten bytes and `Canvas::finish` reports them -- but a file small
/// enough that every key's whole tree fits on its own root page (no
/// `IndexChild` pages at all) now round-trips completely.
pub fn file(model: &File) -> Result<Emitted, Fault> {
    let mut canvas = Canvas::new(model.len as usize);
    if model.id.generation.is_v6() {
        return canvas.finish();
    }
    write_fixed_portion(&mut canvas, model)?;
    write_key_descriptors(&mut canvas, model)?;
    write_page_headers(&mut canvas, model)?;
    write_page_content(&mut canvas, model)?;
    write_index_pages(&mut canvas, model)?;
    canvas.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::fixtures::{
        two_key_fixed_portion, usracc_dat, usracc_first_page, usracc_fixed_portion,
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
        write_fixed_portion(&mut canvas, &model).expect("every field is in range");
        let emitted = canvas.finish().expect("the fixed portion is fully described");

        assert_eq!(emitted.bytes(), &original[..fcr::at::FIXED_LEN]);
    }

    /// Page 0 as a whole -- fixed portion, key/segment definition, and zero
    /// padding out to `page_size` -- round-trips byte for byte for a
    /// single-page model (`model.len == page_size`, the shape a virgin
    /// one-page file would have).
    #[test]
    fn a_single_page_v5_file_round_trips_completely() {
        let original = usracc_first_page();
        let model = read::file(&original).expect("reads");
        let emitted = file(&model).expect("page 0 is fully described -- fixed portion plus one key descriptor plus zero_padding");
        assert_eq!(emitted.bytes(), original.as_slice());
    }

    /// The same, with two key descriptors -- proving the writer handles more
    /// than one repetition, not just the single-definition USRACC.DAT case.
    #[test]
    fn a_single_page_v5_file_with_two_keys_round_trips_completely() {
        let original = two_key_fixed_portion();
        let model = read::file(&original).expect("reads");
        let emitted = file(&model).expect("two key descriptors plus zero_padding tile page 0");
        assert_eq!(emitted.bytes(), original.as_slice());
    }

    /// `file` still faults on a real corpus file that has an `IndexChild`
    /// page -- a B-tree node no key's root names, whose owning key this
    /// task does not resolve (`model::Page::index`'s own doc): `USRACC.DAT`
    /// itself is now fully described (see
    /// `usracc_dat_round_trips_byte_for_byte` below), so this test uses
    /// `FW_QSQDB.DA_` instead, the same real file `read`'s own
    /// `a_real_files_unrooted_btree_nodes_classify_as_index_children` test
    /// measures: pages 3, 5, 7, 9, 11, 12 are `IndexChild`. Page 0, every
    /// page's own six-byte header, both `Index` roots' content (pages 1
    /// and 2), and every `Data` page's content (4, 6, 10) are all described
    /// now -- so the fault must name the earliest undescribed range, which
    /// is page 3's content, starting right after its own header.
    #[test]
    fn file_still_faults_on_a_real_files_unresolved_index_child_page() {
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

        let page_size = model.id.page_size as usize;
        let page_3_content_start = 3 * page_size + page::LEN;

        let fault = file(&model).expect_err("page 3's IndexChild content is not yet described");
        let said = fault.to_string();
        assert!(
            said.contains(&page_3_content_start.to_string()),
            "names the range starting right after page 3's header \
             ({page_3_content_start}): {said}"
        );
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
        write_fixed_portion(&mut canvas, &model).expect("page 0's fixed portion");
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
    /// key descriptor, zero padding), page 1's header plus its index
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
}
