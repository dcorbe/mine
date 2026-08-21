//! Bytes to model.
//!
//! Total, or a refusal: this never returns a model with holes in it. A file
//! whose bytes are not yet fully described is refused with the reason, and the
//! round-trip pin does not count it.

use crate::format::fcr;
use crate::format::fcr::key_descriptor;
use crate::format::generation::{identify, NotBtrieve};
use crate::model::{ControlRecord, File, KeyDescriptor};

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

/// Read a whole Btrieve file into a model.
///
/// # Errors
///
/// If [`identify`] refuses the control record, the file is shorter than its
/// own declared page size, the file is a v6 file (not yet described by this
/// crate), the key/segment definition array is malformed (runs past the
/// page, or an `ANOSEG` chain never terminates), or the zero padding past
/// the last definition, up to `page_size`, is not actually zero.
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

    Ok(File {
        id,
        control,
        key_descriptors,
        len: bytes.len() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::generation::Generation;
    use crate::model::fixtures::{usracc_fixed_portion, usracc_first_page, two_key_fixed_portion};

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
}
