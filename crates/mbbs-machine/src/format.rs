//! Which loader a module file belongs to, read from its header alone.
//!
//! `m16::ne::NeImage::parse` and `m32::pe::PeImage::parse` each check the
//! signature at `e_lfanew` before reading anything else; this is that check
//! hoisted so a caller can pick a loader without parsing.

use std::fmt;

/// `e_lfanew`: the DOS header word that says where the new-executable
/// header starts (`ne.rs:53`, `pe.rs:289`).
const E_LFANEW: usize = 0x3c;

/// Which loader a module file belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// 16-bit New Executable -- `m16`, `Wg16`.
    Ne,
    /// 32-bit Portable Executable -- `m32`, `Wg32`.
    Pe,
}

/// Why a file is not sniffable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatError {
    /// Too short to hold an MZ stub, `e_lfanew`, or the signature it points at.
    Short,
    /// A signature that is neither `NE` nor `PE\0\0`; for a file with no MZ
    /// stub at all, the first bytes of the file.
    Neither([u8; 4]),
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Short => f.write_str("file too short to carry an NE or PE header"),
            Self::Neither(sig) => write!(
                f,
                "neither an NE nor a PE file (signature [{:02x}, {:02x}, {:02x}, {:02x}])",
                sig[0], sig[1], sig[2], sig[3]
            ),
        }
    }
}

impl std::error::Error for FormatError {}

impl Format {
    /// Read `e_lfanew` and the signature there: `NE` or `PE\0\0`.
    ///
    /// `NE` is checked on two bytes and `PE` on four, exactly as the two
    /// parsers do; a file that fails either length check is `Short`, not
    /// `Neither`, so a truncated PE is never reported as "not a PE".
    ///
    /// # Errors
    ///
    /// [`FormatError::Short`] if the file cannot hold the bytes looked at;
    /// [`FormatError::Neither`] if it can and they name no known format.
    pub fn sniff(file: &[u8]) -> Result<Format, FormatError> {
        if file.len() < E_LFANEW + 4 {
            return Err(FormatError::Short);
        }
        if &file[0..2] != b"MZ" {
            let mut head = [0u8; 4];
            head.copy_from_slice(&file[0..4]);
            return Err(FormatError::Neither(head));
        }
        let at = u32::from_le_bytes(file[E_LFANEW..E_LFANEW + 4].try_into().expect("4 bytes")) as usize;
        let sig2 = file.get(at..at + 2).ok_or(FormatError::Short)?;
        if sig2 == b"NE" {
            return Ok(Format::Ne);
        }
        let sig4 = file.get(at..at + 4).ok_or(FormatError::Short)?;
        if sig4 == b"PE\0\0" {
            return Ok(Format::Pe);
        }
        let mut found = [0u8; 4];
        found.copy_from_slice(sig4);
        Err(FormatError::Neither(found))
    }
}

#[cfg(test)]
mod tests {
    use super::{Format, FormatError};

    /// An MZ stub whose `e_lfanew` points at `sig`.
    fn with_signature(sig: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 0x80 + sig.len()];
        v[0..2].copy_from_slice(b"MZ");
        v[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        v[0x80..0x80 + sig.len()].copy_from_slice(sig);
        v
    }

    #[test]
    fn ne_signature_is_ne() {
        assert_eq!(Format::sniff(&with_signature(b"NE\0\0")), Ok(Format::Ne));
    }

    #[test]
    fn pe_signature_is_pe() {
        assert_eq!(Format::sniff(&with_signature(b"PE\0\0")), Ok(Format::Pe));
    }

    #[test]
    fn ne_needs_only_two_signature_bytes() {
        assert_eq!(Format::sniff(&with_signature(b"NE")), Ok(Format::Ne));
    }

    #[test]
    fn pe_needs_all_four_signature_bytes() {
        assert_eq!(
            Format::sniff(&with_signature(b"PE")),
            Err(FormatError::Short),
            "PE\\0\\0 is four bytes; two is a truncated file, not a PE"
        );
    }

    #[test]
    fn a_file_too_short_for_e_lfanew_is_short() {
        assert_eq!(Format::sniff(b"MZ"), Err(FormatError::Short));
    }

    #[test]
    fn e_lfanew_past_the_end_is_short() {
        let mut v = with_signature(b"NE");
        v[0x3c..0x40].copy_from_slice(&0x1000u32.to_le_bytes());
        assert_eq!(Format::sniff(&v), Err(FormatError::Short));
    }

    #[test]
    fn no_mz_stub_is_neither() {
        let mut v = with_signature(b"NE");
        v[0..2].copy_from_slice(b"ZM");
        assert_eq!(Format::sniff(&v), Err(FormatError::Neither(*b"ZM\0\0")));
    }

    #[test]
    fn an_unknown_signature_names_what_it_found() {
        assert_eq!(
            Format::sniff(&with_signature(b"LE\0\0")),
            Err(FormatError::Neither(*b"LE\0\0"))
        );
    }

    #[test]
    fn errors_display_usefully() {
        assert_eq!(FormatError::Short.to_string(), "file too short to carry an NE or PE header");
        assert_eq!(
            FormatError::Neither(*b"LE\0\0").to_string(),
            "neither an NE nor a PE file (signature [4c, 45, 00, 00])"
        );
    }
}
