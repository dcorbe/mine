//! Bytes to model.
//!
//! Total, or a refusal: this never returns a model with holes in it. A file
//! whose bytes are not yet fully described is refused with the reason, and the
//! round-trip pin does not count it.

use crate::format::fcr;
use crate::format::generation::{identify, NotBtrieve, FCR_MIN};
use crate::model::{ControlRecord, File};

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

/// Read a whole Btrieve file into a model.
///
/// # Errors
///
/// If [`identify`] refuses the control record, the file is shorter than its
/// own declared page size, the file is a v6 file (not yet described by this
/// crate), or the v5 zero-padding past the historical 512-byte control
/// record is not actually zero.
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

    // Bytes past the historical 512-byte control record, when page_size is
    // larger still, must be zero -- harvest 1's tail_check.py measured this
    // on 94 of 96 v5 corpus files with that much headroom. The 2
    // exceptions (wccitems.nu1 and its sibling) are refused here, by name,
    // rather than accepted as harmless padding -- a later task investigates
    // them. Bytes 0x110..512 (the key/segment definition table) are not
    // inspected at all: they are genuinely non-zero for a populated file,
    // and reading them is a later task's job.
    if page_size > FCR_MIN {
        let tail = &bytes[FCR_MIN..page_size];
        if let Some(offset) = tail.iter().position(|&b| b != 0) {
            return Err(NotBtrieve {
                why: format!(
                    "identified as {:?}, but byte {:#x} of the zero padding \
                     past the control record's historical 512-byte extent \
                     is {:#04x}, not zero",
                    id.generation,
                    FCR_MIN + offset,
                    tail[offset]
                ),
            });
        }
    }

    Ok(File {
        id,
        control: control_record(bytes),
        len: bytes.len() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::generation::Generation;
    use crate::model::fixtures::usracc_fixed_portion;

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
}
