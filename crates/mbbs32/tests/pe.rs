//! Parsing, against images built here rather than against a real module.
//!
//! The real-module tests live in `tests/wccmmud.rs`. These exist because a real
//! file exercises exactly one path through each branch, and the error paths need
//! an input built to reach them.

use mbbs32::{PeError, PeImage};

/// The smallest thing that parses: an MZ stub, a PE signature, a COFF header
/// saying i386, a PE32 optional header, and no sections.
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
    v
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
