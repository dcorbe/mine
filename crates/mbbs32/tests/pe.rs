//! Parsing, against images built here rather than against a real module.
//!
//! The real-module tests live in `tests/wccmmud.rs`. These exist because a real
//! file exercises exactly one path through each branch, and the error paths need
//! an input built to reach them.

use mbbs32::{PeError, PeImage, Relocation};

/// The smallest thing that parses: an MZ stub, a PE signature, a COFF header
/// saying i386, a PE32 optional header, and no sections.
///
/// **Every optional-header field carries a distinct, non-zero value**, and that
/// is load-bearing rather than tidy. Left at zero -- as this helper originally
/// had them -- a parser reading `entry_point` from `image_base`'s offset returns
/// zero for both and no test can tell. That exact transposition was mutated in
/// and the whole suite stayed green, which is why
/// `every_optional_header_field_comes_from_its_own_offset` exists. The values
/// are also pairwise unequal, so no two fields can be swapped without one of
/// them landing on a number that belongs to the other.
fn minimal() -> Vec<u8> {
    let mut v = vec![0u8; 0x200];
    v[0..2].copy_from_slice(b"MZ");
    v[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew
    v[0x80..0x84].copy_from_slice(b"PE\0\0");
    v[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes()); // machine = i386
    v[0x86..0x88].copy_from_slice(&0u16.to_le_bytes()); // 0 sections
    v[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes()); // SizeOfOptionalHeader
    v[0x96..0x98].copy_from_slice(&0x010eu16.to_le_bytes()); // characteristics
    v[0x98..0x9a].copy_from_slice(&0x010bu16.to_le_bytes()); // PE32 magic

    let opt = 0x98;
    v[opt + 16..opt + 20].copy_from_slice(&ENTRY_POINT.to_le_bytes());
    v[opt + 28..opt + 32].copy_from_slice(&IMAGE_BASE.to_le_bytes());
    v[opt + 32..opt + 36].copy_from_slice(&SECTION_ALIGNMENT.to_le_bytes());
    v[opt + 36..opt + 40].copy_from_slice(&FILE_ALIGNMENT.to_le_bytes());
    v[opt + 56..opt + 60].copy_from_slice(&SIZE_OF_IMAGE.to_le_bytes());
    v
}

/// The five optional-header values `minimal()` plants. Pairwise distinct, and
/// none of them zero -- see that function's note for why that matters.
const ENTRY_POINT: u32 = 0x0000_1111;
const IMAGE_BASE: u32 = 0x2222_0000;
const SECTION_ALIGNMENT: u32 = 0x0000_3000;
const FILE_ALIGNMENT: u32 = 0x0000_0400;
const SIZE_OF_IMAGE: u32 = 0x0005_5000;

#[test]
fn every_optional_header_field_comes_from_its_own_offset() {
    // The success path, which nothing else in this file reaches: every test
    // here but this one asserts on `unwrap_err()`, so before this existed the
    // parser could read all five of these fields from each other's offsets and
    // the suite stayed green.
    let image = PeImage::parse(&minimal()).unwrap();
    assert_eq!(image.entry_point, ENTRY_POINT, "entry point, opt+16");
    assert_eq!(image.image_base, IMAGE_BASE, "image base, opt+28");
    assert_eq!(
        image.section_alignment, SECTION_ALIGNMENT,
        "section alignment, opt+32"
    );
    assert_eq!(image.file_alignment, FILE_ALIGNMENT, "file alignment, opt+36");
    assert_eq!(image.size_of_image, SIZE_OF_IMAGE, "size of image, opt+56");

    // Characteristics 0x010e clears IMAGE_FILE_RELOCS_STRIPPED.
    assert!(image.rebasable(), "RELOCS_STRIPPED is clear in 0x010e");
}

#[test]
fn an_image_with_relocs_stripped_is_not_rebasable() {
    // The other side of `rebasable()`, which no test reached either. Task 12
    // refuses to load one of these anywhere but its own ImageBase, so this
    // predicate is about to become load-bearing.
    let mut v = minimal();
    let c = u16::from_le_bytes([v[0x96], v[0x97]]) | 0x0001;
    v[0x96..0x98].copy_from_slice(&c.to_le_bytes());
    assert!(!PeImage::parse(&v).unwrap().rebasable());
}

#[test]
fn a_truncated_file_is_an_error_rather_than_a_short_read() {
    let full = minimal();
    for cut in [0, 1, 0x3f, 0x80, 0x90, 0x9a] {
        let err = PeImage::parse(&full[..cut]).unwrap_err();
        assert!(
            matches!(err, PeError::NotPe | PeError::Truncated { .. }),
            "cut at {cut:#x} gave {err:?}"
        );
    }
}

#[test]
fn a_file_that_is_not_pe_is_an_error() {
    assert_eq!(PeImage::parse(b"").unwrap_err(), PeError::NotPe);
    assert_eq!(PeImage::parse(b"ZM\0\0").unwrap_err(), PeError::NotPe);
    let mut v = minimal();
    v[0x80..0x84].copy_from_slice(b"NE\0\0");
    assert_eq!(PeImage::parse(&v).unwrap_err(), PeError::NotPe);
}

#[test]
fn a_64_bit_image_is_refused_rather_than_misread() {
    let mut v = minimal();
    v[0x98..0x9a].copy_from_slice(&0x020bu16.to_le_bytes()); // PE32+
    assert_eq!(
        PeImage::parse(&v).unwrap_err(),
        PeError::NotPe32 { magic: 0x020b }
    );
}

#[test]
fn a_non_i386_image_is_refused() {
    let mut v = minimal();
    v[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    assert_eq!(
        PeImage::parse(&v).unwrap_err(),
        PeError::NotI386 { machine: 0x8664 }
    );
}

/// `minimal()` plus one section. The section table follows the optional
/// header, at `opt + SizeOfOptionalHeader` -- which is why the value that
/// field carries matters, not just whether it is present.
fn with_one_section() -> Vec<u8> {
    let mut v = minimal();
    v[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    let sec = 0x98 + 0xe0; // opt + SizeOfOptionalHeader
    v.resize(sec + 40 + 0x200, 0);
    v[sec..sec + 8].copy_from_slice(b"CODE\0\0\0\0");
    v[sec + 8..sec + 12].copy_from_slice(&0x100u32.to_le_bytes()); // VirtualSize
    v[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    v[sec + 16..sec + 20].copy_from_slice(&0x80u32.to_le_bytes()); // SizeOfRawData
    v[sec + 20..sec + 24].copy_from_slice(&((sec + 40) as u32).to_le_bytes()); // PointerToRawData
    v[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    v
}

#[test]
fn a_section_table_parses() {
    let image = PeImage::parse(&with_one_section()).unwrap();
    assert_eq!(image.sections.len(), 1);
    let s = &image.sections[0];
    assert_eq!(s.name, "CODE");
    assert_eq!(s.rva, 0x1000);
    assert_eq!(s.virtual_size, 0x100);
    assert_eq!(s.raw_size, 0x80);
}

#[test]
fn an_rva_resolves_to_a_file_offset_only_inside_a_section() {
    let image = PeImage::parse(&with_one_section()).unwrap();
    let base = image.sections[0].raw_offset;
    assert_eq!(image.rva_to_file(0x1000).unwrap(), base as usize);
    assert_eq!(image.rva_to_file(0x1040).unwrap(), base as usize + 0x40);

    // Below every section, and above the only one.
    assert_eq!(
        image.rva_to_file(0x0fff).unwrap_err(),
        PeError::UnmappedRva { rva: 0x0fff }
    );
    assert_eq!(
        image.rva_to_file(0x2000).unwrap_err(),
        PeError::UnmappedRva { rva: 0x2000 }
    );
}

#[test]
fn an_rva_in_the_bss_tail_has_no_file_offset() {
    // VirtualSize 0x100 but SizeOfRawData 0x80: the last 0x80 bytes are BSS and
    // exist only once the image is mapped. Asking for a file offset there is a
    // bug in the caller, not a valid translation.
    let image = PeImage::parse(&with_one_section()).unwrap();
    assert_eq!(
        image.rva_to_file(0x1080).unwrap_err(),
        PeError::UnmappedRva { rva: 0x1080 }
    );
}

/// Two sections, laid out on disk so that CODE's raw data ends exactly where
/// DATA's raw data begins. This is the shape that makes a `virtual_size`
/// vs. `raw_size` bug in `rva_to_file` observable as *wrong bytes* rather
/// than merely as a wrong boolean: if BSS-tail RVAs were resolved against
/// `virtual_size`, an address in CODE's tail would silently return an offset
/// that lands inside DATA's raw bytes on disk.
fn with_two_sections() -> Vec<u8> {
    let mut v = minimal();
    v[0x86..0x88].copy_from_slice(&2u16.to_le_bytes()); // 2 sections
    let sec0 = 0x98 + 0xe0;
    let sec1 = sec0 + 40;
    let raw0 = sec1 + 40;
    let raw1 = raw0 + 0x80;
    v.resize(raw1 + 0x80 + 0x200, 0);

    v[sec0..sec0 + 8].copy_from_slice(b"CODE\0\0\0\0");
    v[sec0 + 8..sec0 + 12].copy_from_slice(&0x100u32.to_le_bytes()); // VirtualSize
    v[sec0 + 12..sec0 + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    v[sec0 + 16..sec0 + 20].copy_from_slice(&0x80u32.to_le_bytes()); // SizeOfRawData
    v[sec0 + 20..sec0 + 24].copy_from_slice(&(raw0 as u32).to_le_bytes());
    v[sec0 + 36..sec0 + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    v[sec1..sec1 + 8].copy_from_slice(b"DATA\0\0\0\0");
    v[sec1 + 8..sec1 + 12].copy_from_slice(&0x80u32.to_le_bytes()); // VirtualSize
    v[sec1 + 12..sec1 + 16].copy_from_slice(&0x1100u32.to_le_bytes()); // VirtualAddress, right after CODE's virtual range
    v[sec1 + 16..sec1 + 20].copy_from_slice(&0x80u32.to_le_bytes()); // SizeOfRawData
    v[sec1 + 20..sec1 + 24].copy_from_slice(&(raw1 as u32).to_le_bytes());
    v[sec1 + 36..sec1 + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes());

    // A marker at the start of DATA's raw bytes: a buggy translation of
    // CODE's BSS tail would land here instead of erroring.
    v[raw1] = 0xaa;
    v
}

#[test]
fn a_second_sections_raw_bytes_are_never_returned_for_the_first_sections_bss_tail() {
    let image = PeImage::parse(&with_two_sections()).unwrap();
    assert_eq!(image.sections.len(), 2);
    assert_eq!(
        image.sections.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
        ["CODE", "DATA"]
    );

    // rva 0x1080 is inside CODE's VirtualSize (0x100) but past its
    // SizeOfRawData (0x80): BSS, not file bytes -- even though DATA's raw
    // bytes happen to sit immediately afterward on disk.
    assert_eq!(
        image.rva_to_file(0x1080).unwrap_err(),
        PeError::UnmappedRva { rva: 0x1080 }
    );

    // DATA's own rva resolves to DATA's own raw offset, independent of CODE.
    let data = &image.sections[1];
    assert_eq!(image.rva_to_file(0x1100).unwrap(), data.raw_offset as usize);
}

#[test]
fn a_too_small_size_of_optional_header_is_refused() {
    // SizeOfOptionalHeader locates the section table (`opt + optional_size`).
    // A value smaller than this parser's own reads reach (opt+56, 4 bytes --
    // i.e. up through opt+60) means "trust this field to place the section
    // table" is trusting a number that cannot even describe the header
    // fields already read out of it. 0x20 is such a value: real headers are
    // 0xe0 (this module) or occasionally smaller for older linkers, but never
    // this small.
    let mut v = minimal();
    v[0x94..0x96].copy_from_slice(&0x20u16.to_le_bytes());
    assert_eq!(
        PeImage::parse(&v).unwrap_err(),
        PeError::BadOptionalHeaderSize { size: 0x20 }
    );
}

/// `IMAGE_REL_BASED_HIGHLOW` (type 3) packed with `offset` the way
/// `IMAGE_BASE_RELOCATION` entries store it: type in the top 4 bits, the
/// 12-bit offset from the block's page in the low bits.
fn highlow(offset: u16) -> u16 {
    0x3000 | (offset & 0x0fff)
}

/// `IMAGE_REL_BASED_ABSOLUTE` (type 0): padding, dropped rather than applied.
fn absolute(offset: u16) -> u16 {
    offset & 0x0fff
}

/// Lays out one or more base-relocation blocks right after `with_one_section`'s
/// CODE section raw data, and points the base-relocation data directory
/// (index 5, at `opt + 96 + 5*8`) at them. Each block is `(page_rva, entries)`;
/// entries are pre-packed by `highlow`/`absolute`.
///
/// The directory RVA is always the section's own RVA (0x1000): the block data
/// is written starting at that section's raw offset, so the directory and the
/// first block always share a file position, independent of what "page" each
/// block's entries target.
fn write_relocation_blocks(v: &mut [u8], blocks: &[(u32, &[u16])]) {
    let sec = 0x98 + 0xe0;
    let raw = u32::from_le_bytes(v[sec + 20..sec + 24].try_into().unwrap()) as usize;
    let mut at = raw;
    for (page, entries) in blocks {
        let size = 8 + entries.len() * 2;
        v[at..at + 4].copy_from_slice(&page.to_le_bytes());
        v[at + 4..at + 8].copy_from_slice(&(size as u32).to_le_bytes());
        for (i, e) in entries.iter().enumerate() {
            v[at + 8 + i * 2..at + 10 + i * 2].copy_from_slice(&e.to_le_bytes());
        }
        at += size;
    }
    let total = (at - raw) as u32;
    let dir = 0x98 + 96 + 5 * 8;
    v[dir..dir + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    v[dir + 4..dir + 8].copy_from_slice(&total.to_le_bytes());
}

#[test]
fn base_relocations_parse_and_padding_is_dropped() {
    // One block covering page rva 0x1000: two HIGHLOW entries and one
    // ABSOLUTE pad. Block header is 8 bytes, each entry 2.
    let mut v = with_one_section();
    write_relocation_blocks(
        &mut v,
        &[(0x1000, &[highlow(0x004), highlow(0x008), absolute(0)])],
    );

    let image = PeImage::parse(&v).unwrap();
    assert_eq!(
        image.relocations,
        vec![Relocation { rva: 0x1004 }, Relocation { rva: 0x1008 }],
        "the ABSOLUTE entry is padding and must not survive parsing"
    );
}

#[test]
fn two_relocation_blocks_are_both_read_in_order() {
    // A single block makes `at += size` invisible: a parser that only ever
    // reads the first block, or that forgets to advance `at`, would still
    // pass a one-block test. Two blocks at two different pages catch both:
    // if the second block were skipped, the last two relocations here would
    // be missing; if `at` were miscomputed, the second block's header would
    // be read from the wrong offset and either error out or attribute its
    // entries to the wrong page.
    let mut v = with_one_section();
    write_relocation_blocks(
        &mut v,
        &[
            (0x1000, &[highlow(0x010)]),
            (0x2000, &[highlow(0x004), highlow(0xffc)]),
        ],
    );

    let image = PeImage::parse(&v).unwrap();
    assert_eq!(
        image.relocations,
        vec![
            Relocation { rva: 0x1010 },
            Relocation { rva: 0x2004 },
            Relocation { rva: 0x2ffc },
        ]
    );
}

#[test]
fn relocation_rva_is_page_plus_offset_not_page_or_offset() {
    // A block's `page` field is not guaranteed 4KiB-aligned by anything this
    // parser checks, and `page + offset` and `page | offset` only agree when
    // it is. 0x1800 is deliberately unaligned, and the two entries land in
    // two different 4KiB regions (0x1000..0x2000 and 0x2000..0x3000): a
    // one-block, one-page test cannot distinguish `+` from `|`, because every
    // page RVA in such a test is chosen aligned. This also exercises the
    // block's last entry (offset 0xffe, right at the edge of the 12-bit
    // range) to rule out an off-by-one that drops it.
    let mut v = with_one_section();
    write_relocation_blocks(&mut v, &[(0x1800, &[highlow(0x000), highlow(0xffe)])]);

    let image = PeImage::parse(&v).unwrap();
    assert_eq!(
        image.relocations,
        vec![Relocation { rva: 0x1800 }, Relocation { rva: 0x27fe }],
        "page 0x1800 + offset 0xffe is 0x27fe; page 0x1800 | offset 0xffe would be 0x1ffe"
    );
}

#[test]
fn an_unsupported_relocation_type_is_an_error() {
    // Type 3 (HIGHLOW) is the only type this image contains and the only one
    // implemented; anything else must be reported rather than silently
    // applied or silently dropped like ABSOLUTE padding is.
    let mut v = with_one_section();
    write_relocation_blocks(&mut v, &[(0x1000, &[0x1000 | 0x004])]); // type 1: HIGH

    assert_eq!(
        PeImage::parse(&v).unwrap_err(),
        PeError::UnsupportedRelocation { kind: 1 }
    );
}
