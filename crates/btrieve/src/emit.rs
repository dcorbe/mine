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
//! not a silent zero. Today [`crate::model::File`] describes a v5 file's
//! control record fixed portion (`0x00..0x110`) and nothing past it -- no
//! key/segment table, no records, no index pages -- so [`file`] faults on
//! every real corpus file, just further along than it used to: the fixed
//! portion round-trips, and the fault names the pages this crate has no
//! description for yet. That is why the round-trip pin stays at zero.

use crate::canvas::{Canvas, Emitted, Fault, Owner};
use crate::format::fcr;
use crate::format::generation::Generation;
use crate::model::File;

fn owner(field: &'static str) -> Owner {
    Owner { structure: "fcr", field, index: None }
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
/// If the model does not yet describe every byte of the file. Today that is
/// every real file: a v6 file's control record is entirely undescribed, and
/// a v5 file's key/segment table, records and index pages are all past what
/// [`crate::model::File`] carries, so the canvas is left with unwritten
/// bytes and `Canvas::finish` reports them.
pub fn file(model: &File) -> Result<Emitted, Fault> {
    let mut canvas = Canvas::new(model.len as usize);
    if model.id.generation.is_v6() {
        return canvas.finish();
    }
    write_fixed_portion(&mut canvas, model)?;
    canvas.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::fixtures::usracc_fixed_portion;
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

    /// `file` faults rather than succeeding on a real file, because the
    /// key/segment table, records and index pages past the fixed portion
    /// are not yet described -- this is the "faulted, not refused, not
    /// mismatched" outcome the round trip is expected to show for v5 files
    /// after this task.
    #[test]
    fn file_faults_on_bytes_past_the_fixed_portion() {
        let original = usracc_fixed_portion();
        let model = read::file(&original).expect("reads");
        let fault = file(&model).expect_err("bytes past 0x110 are not yet described");
        assert!(
            fault.to_string().contains("0x110") || fault.to_string().contains("272"),
            "names the range starting where the fixed portion ends: {fault}"
        );
    }
}
