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
//! record fixed portion (`0x00..0x110`) and its key/segment definition
//! array, so [`file`] now writes the whole of page 0 for a v5 file -- but
//! records and index pages (page 1 onward) are still later tasks, so
//! [`file`] still faults on every real (multi-page) corpus file, just
//! further along than it used to: page 0 round-trips, and the fault names
//! the pages this crate has no description for yet. That is why the
//! round-trip pin stays at zero.

use crate::canvas::{Canvas, Emitted, Fault, Owner};
use crate::format::fcr;
use crate::format::fcr::key_descriptor;
use crate::format::generation::Generation;
use crate::model::File;

fn owner(field: &'static str) -> Owner {
    Owner { structure: "fcr", field, index: None }
}

fn key_owner(field: &'static str, index: usize) -> Owner {
    Owner { structure: "fcr", field, index: Some(index) }
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
/// round-trip on its own, but records and index pages -- page 1 onward --
/// are not, so any real (multi-page) corpus file still leaves the canvas
/// with unwritten bytes and `Canvas::finish` reports them.
pub fn file(model: &File) -> Result<Emitted, Fault> {
    let mut canvas = Canvas::new(model.len as usize);
    if model.id.generation.is_v6() {
        return canvas.finish();
    }
    write_fixed_portion(&mut canvas, model)?;
    write_key_descriptors(&mut canvas, model)?;
    canvas.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::fixtures::{usracc_fixed_portion, usracc_first_page, two_key_fixed_portion};
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

    /// `file` faults rather than succeeding on a real (multi-page) corpus
    /// file: page 0 (fixed portion, key/segment definitions, zero padding)
    /// is now fully described and writes without a fault, but records and
    /// index pages -- page 1 onward -- are not, so the fault must name the
    /// range starting exactly at `page_size`, not at `0x110`.
    #[test]
    fn file_faults_on_bytes_past_page_zero_for_a_multi_page_file() {
        // USRACC.DAT itself: page_size 512, 3 pages, 1536 bytes total.
        let mut original = usracc_first_page();
        original.resize(1536, 0);
        let model = read::file(&original).expect("reads");
        assert_eq!(model.len, 1536);

        let fault = file(&model).expect_err("pages 1 and 2 are not yet described");
        let said = fault.to_string();
        assert!(
            said.contains("512") && said.contains("1536"),
            "names the range starting at page_size (512) up to the file's own length (1536): {said}"
        );
    }
}
