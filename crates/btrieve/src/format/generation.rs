//! Which format generation a file is, decided the way the engine decides it.
//!
//! Transcribed from `re/btrieve_ghidra/exports/W32MKDE_decompiled.c:33906-33934`
//! (`FUN_00435970`), the file-open control-record check, reached from three
//! call sites in the shipping 32-bit MicroKernel engine. Nothing here is
//! inferred: every accepted value is a literal comparison in that function.
//!
//! # One rule, and only one
//!
//! Everything in this crate that decides whether a file is Btrieve calls
//! [`identify`]. The crate this replaces had two rules that disagreed -- its
//! census accepted any file beginning with four zero bytes, while its engine
//! additionally required a known version byte, so a Turbo Pascal game file was
//! recorded as a Btrieve file with 20,046 keys by one and refused by the other.
//!
//! # Version is the only format axis
//!
//! Not word size. Settled 2026-08-20 on four independent lines: Novell's
//! `BTR61.DOC` frames every compatibility rule around version and never around
//! platform; a 32-bit Windows NT product ships v5 and v6 files side by side in
//! five directories; `FUN_00435970` branches only on file content, with no
//! platform flag anywhere near it; and the 16-bit `WBTR32.EXE` and 32-bit
//! `W32MKDE.EXE` both embed `\btrieve\common\engn620\fcrsubs.c`, differing only
//! in entry point.

/// The smallest buffer [`identify`] will look at, and the size of a control
/// record. The engine reads page 0 as `0x200` bytes before checking anything
/// (`W32MKDE_decompiled.c:33874`).
pub const FCR_MIN: usize = 512;

/// Which on-disk generation wrote a file.
///
/// Six are legitimate. The corpus exercises four: `V5R5` and `V620` are
/// accepted on the engine's authority and shipped by nobody, which is recorded
/// rather than smoothed over -- they cannot be round-trip tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Generation {
    /// Pre-v6, control-record byte 7 == 3.
    V5R3,
    /// Pre-v6, control-record byte 7 == 4.
    V5R4,
    /// Pre-v6, control-record byte 7 == 5. Engine-legitimate, none shipped.
    V5R5,
    /// v6.00. The default a 6.1 engine writes for a file using no 6.1 feature.
    V600,
    /// v6.10/6.15. Written only for a file using multiple alternate collating
    /// sequences, locale-specific ACSs, a variable-tail allocation table, or
    /// the index-balancing mark (`BTR61.DOC`).
    V610,
    /// v6.20. Engine-legitimate, none shipped.
    V620,
}

impl Generation {
    /// Whether this is the `"FC"` family.
    #[must_use]
    pub fn is_v6(self) -> bool {
        matches!(self, Self::V600 | Self::V610 | Self::V620)
    }
}

/// A file this is not going to read, and the specific test that refused it.
///
/// The message names the predicate that actually failed. The crate this
/// replaces reported "starts [00, 00, 00, 00], which is neither a v5 file
/// control record (four zero bytes) nor a v6 one" about a file that did start
/// with four zero bytes and was refused for its version byte -- sending the
/// reader to inspect the one thing that was fine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotBtrieve {
    /// The failing predicate, in terms of the field it tested.
    pub why: String,
}

/// What [`identify`] establishes before anything else is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identified {
    /// The generation that wrote the file.
    pub generation: Generation,
    /// Page size in bytes, from control-record offset 8.
    pub page_size: u16,
}

/// Decide whether `head` begins a Btrieve file, and which generation wrote it.
///
/// `head` is the first [`FCR_MIN`] bytes of the file, or more.
///
/// # Errors
///
/// If the buffer is short, the lead is neither family's, the version field is
/// outside the engine's accepted set, or the page size is not a non-zero
/// multiple of 512 up to 4096.
pub fn identify(head: &[u8]) -> Result<Identified, NotBtrieve> {
    if head.len() < FCR_MIN {
        return Err(NotBtrieve {
            why: format!(
                "{} bytes, and a control record is {FCR_MIN}",
                head.len()
            ),
        });
    }

    // `*param_1` -- the first four bytes as one word, which is what selects
    // the family. Note this is a *word* comparison, not a byte one: `"FC"`
    // followed by two zero bytes is `0x4346` little-endian.
    let lead = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);

    let generation = if lead == 0 {
        // The engine takes the absolute value of the *signed* 16-bit word at
        // offset 6 and compares against three literals. Since the word is
        // `byte6 | (byte7 << 8)`, those literals mean byte 6 is zero and
        // byte 7 is 3, 4 or 5.
        let word = i16::from_le_bytes([head[6], head[7]]).unsigned_abs();
        match word {
            0x300 => Generation::V5R3,
            0x400 => Generation::V5R4,
            0x500 => Generation::V5R5,
            other => {
                return Err(NotBtrieve {
                    why: format!(
                        "leads with four zero bytes, so this is the pre-v6 \
                         family, but the version word at offset 6 is \
                         {other:#06x} and the engine accepts only 0x300, \
                         0x400 or 0x500 (W32MKDE FUN_00435970)"
                    ),
                });
            }
        }
    } else if lead == 0x4346 {
        let word = i16::from_le_bytes([head[0x4a], head[0x4b]]).unsigned_abs();
        match word {
            0x600 => Generation::V600,
            0x610 => Generation::V610,
            0x620 => Generation::V620,
            other => {
                return Err(NotBtrieve {
                    why: format!(
                        "leads with \"FC\", so this is the v6 family, but the \
                         version word at offset 0x4a is {other:#06x} and the \
                         engine accepts only 0x600, 0x610 or 0x620 \
                         (W32MKDE FUN_00435970)"
                    ),
                });
            }
        }
    } else {
        return Err(NotBtrieve {
            why: format!(
                "leads with {:02x?}, which is neither four zero bytes (pre-v6) \
                 nor \"FC\" (v6)",
                &head[..4]
            ),
        });
    };

    // Checked after both branches by the engine, so it applies to every
    // generation: non-zero, at most 0x1000, a multiple of 0x200.
    let page_size = u16::from_le_bytes([head[8], head[9]]);
    if page_size == 0 || page_size > 0x1000 || page_size & 0x1ff != 0 {
        return Err(NotBtrieve {
            why: format!(
                "page size {page_size} at offset 8 is not a non-zero multiple \
                 of 512 up to 4096 (W32MKDE FUN_00435970)"
            ),
        });
    }

    Ok(Identified {
        generation,
        page_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 512-byte buffer shaped like a v5-family control record.
    fn v5(byte6: u8, byte7: u8, page: u16) -> Vec<u8> {
        let mut b = vec![0u8; FCR_MIN];
        b[6] = byte6;
        b[7] = byte7;
        b[8..10].copy_from_slice(&page.to_le_bytes());
        b
    }

    /// A 512-byte buffer shaped like a v6 control record.
    fn v6(version: u16, page: u16) -> Vec<u8> {
        let mut b = vec![0u8; FCR_MIN];
        b[..4].copy_from_slice(&[b'F', b'C', 0, 0]);
        b[0x4a..0x4c].copy_from_slice(&version.to_le_bytes());
        b[8..10].copy_from_slice(&page.to_le_bytes());
        b
    }

    #[test]
    fn the_three_v5_versions_the_engine_accepts() {
        for (byte7, want) in [(3u8, Generation::V5R3), (4, Generation::V5R4), (5, Generation::V5R5)] {
            let got = identify(&v5(0, byte7, 1024)).expect("the engine accepts this");
            assert_eq!(got.generation, want, "byte 7 == {byte7}");
            assert_eq!(got.page_size, 1024);
        }
    }

    #[test]
    fn the_three_v6_versions_the_engine_accepts() {
        for (word, want) in [(0x600u16, Generation::V600), (0x610, Generation::V610), (0x620, Generation::V620)] {
            let got = identify(&v6(word, 4096)).expect("the engine accepts this");
            assert_eq!(got.generation, want, "version word {word:#06x}");
            assert_eq!(got.page_size, 4096);
        }
    }

    /// The engine's set is exactly {3,4,5}; 2 and 6 are refused with status 30.
    #[test]
    fn a_v5_version_outside_the_engines_set_is_refused() {
        for byte7 in [0u8, 1, 2, 6, 7, 0xff] {
            let e = identify(&v5(0, byte7, 1024)).expect_err("outside the set");
            assert!(e.why.contains("offset 6"), "names the test that failed: {}", e.why);
        }
    }

    /// LORD.DAT's shape: four zero bytes, byte 7 == 0. The refusal must name
    /// the version word, NOT the leading bytes -- the old crate's message
    /// blamed the four zero bytes on a file that genuinely had them.
    #[test]
    fn the_refusal_names_the_version_word_not_the_leading_bytes() {
        let e = identify(&v5(0, 0, 1024)).expect_err("byte 7 == 0 is refused");
        assert!(
            e.why.contains("offset 6"),
            "the actual failing test is the version word: {}",
            e.why
        );
        assert!(
            !e.why.contains("neither"),
            "must not claim the file is neither v5 nor v6 -- it took the v5 \
             branch and failed inside it: {}",
            e.why
        );
    }

    #[test]
    fn a_v6_version_outside_the_engines_set_is_refused() {
        for word in [0u16, 0x500, 0x601, 0x630, 0x700] {
            let e = identify(&v6(word, 4096)).expect_err("outside the set");
            assert!(e.why.contains("0x4a"), "names the field: {}", e.why);
        }
    }

    /// byte6 must be zero: the engine compares the whole 16-bit word, so a
    /// non-zero low byte makes it something other than 0x300/0x400/0x500.
    #[test]
    fn a_nonzero_byte_six_is_refused() {
        let e = identify(&v5(1, 4, 1024)).expect_err("byte 6 must be zero");
        assert!(e.why.contains("offset 6"), "{}", e.why);
    }

    #[test]
    fn page_size_must_be_a_nonzero_multiple_of_512_up_to_4096() {
        for bad in [0u16, 100, 513, 1023, 4097, 8192] {
            let e = identify(&v5(0, 4, bad)).expect_err("a bad page size is refused");
            assert!(e.why.contains("page size"), "names the test: {}", e.why);
        }
        for good in [512u16, 1024, 1536, 2048, 4096] {
            identify(&v5(0, 4, good)).unwrap_or_else(|e| panic!("page {good}: {}", e.why));
        }
    }

    #[test]
    fn a_buffer_shorter_than_a_control_record_is_refused() {
        let e = identify(&[0u8; 64]).expect_err("too short");
        assert!(e.why.contains("64"), "names the actual length: {}", e.why);
    }

    #[test]
    fn a_lead_that_is_neither_shape_is_refused_and_says_so() {
        let mut b = vec![0u8; FCR_MIN];
        b[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let e = identify(&b).expect_err("neither shape");
        assert!(e.why.contains("neither"), "{}", e.why);
    }

    #[test]
    fn is_v6_splits_the_families() {
        assert!(!Generation::V5R3.is_v6());
        assert!(!Generation::V5R5.is_v6());
        assert!(Generation::V600.is_v6());
        assert!(Generation::V620.is_v6());
    }
}
