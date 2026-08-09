//! Parsing, against images built here rather than against a real module.
//!
//! The real-module tests live in `tests/wccmmud.rs`. These exist because a real
//! file exercises exactly one path through each branch, and the error paths need
//! an input built to reach them.

use mbbs32::{PeError, PeImage};

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
