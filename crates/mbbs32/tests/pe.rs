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
