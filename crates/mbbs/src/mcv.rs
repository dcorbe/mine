//! Compiling a `.MSG` into the `.MCV` the real host produced from it.
//!
//! This host has never needed one: [`crate::msg`] reads `.MSG` directly, and a
//! module never sees either form because `opnmsg` hands back a `FILE *` it only
//! passes to `setmbk` and `clsmsg`. What needs a `.MCV` is a **DOS utility** run
//! outside the host — `WCCMMUTL.EXE` refuses to start without `WCCMMUD.MCV`, and
//! the distro does not ship one because the host compiled it at install time.
//! See `docs/2026-08-17-wccmmutl-incomplete-install.md`.
//!
//! # The format, from the engine that reads it
//!
//! `re/wg33src/SRC/api/gcommlib/MCVAPI.C`'s `opnmsg` and `msgseek`, plus the
//! `struct msgblk` comment in `re/wg33src/INC/MCVAPI.H` which spells out that
//! five fields are "always last 16 bytes of a .MCV file":
//!
//! ```text
//! 0                : the language list -- `lngcnt` NUL-terminated names
//! after them       : every message body in order, each NUL-terminated
//! loclist          : `msgcnt + 1` little-endian i32 file offsets
//! end - 16         : lnglist i32 | lenlist i32 | loclist i32 | lngcnt i16 | msgcnt i16
//! ```
//!
//! `opnmsg` seeks to `end - 16`, reads those five fields (`MCVEND` is 16,
//! `MCVAPI.C:23,85-87`), then seeks to `lnglist` and reads `lngcnt` names with
//! `fgetstg` (`:92-101`), then seeks to `loclist` and reads **`msgcnt + 1`**
//! longs (`:103-106`). The extra one is a sentinel: `msgseek` takes a
//! single-language message's size as `msgloc[n+1] - msgloc[n]` (`:143-146`), so
//! the size *includes* the terminating NUL and the last entry has to mark where
//! the bodies end.
//!
//! `lenlist` is read **only** when `lngcnt > 1` (`:109-122`), as
//! `msgcnt * lngcnt` `USHORT`s. Every `.MCV` in this repository's archive is
//! single-language, so this writer emits `lenlist = 0` and refuses to invent the
//! multilingual layout it has never measured.
//!
//! # Measured, not inferred
//!
//! All ten `.MSG`/`.MCV` pairs in the archive obey exactly one layout: `lnglist`
//! is 0, `lenlist` is 0, `lngcnt` is 1, the language is `English/ANSI`, the
//! location list's last entry equals `loclist`, and the file is exactly
//! `loclist + 4 * (msgcnt + 1) + 16` bytes. `crates/mbbs/tests/msgfile.rs`
//! compiles each `.MSG` and compares against the `.MCV` that shipped beside it,
//! byte for byte.

/// Bytes of the trailer every `.MCV` ends with (`MCVAPI.C:23`'s `MCVEND`).
const TRAILER: usize = 16;

/// The language every `.MCV` in the archive records, and what a `.MSG` with no
/// `LANGUAGE` line compiles to.
pub const DEFAULT_LANGUAGE: &[u8] = b"English/ANSI";

/// Compile `messages` into a single-language `.MCV`.
///
/// `messages` are the bodies **without** their terminating NUL, exactly as
/// [`crate::msg::MsgFile::messages`] yields them; this appends one to each,
/// because that is what the size arithmetic in `msgseek` counts.
///
/// `language` is the `.MSG`'s `LANGUAGE` value, or [`DEFAULT_LANGUAGE`] when it
/// declares none.
#[must_use]
pub fn compile(messages: &[Vec<u8>], language: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();

    // The language list first, at offset 0 -- which is why `lnglist` is 0 in
    // every measured file rather than by choice here.
    out.extend_from_slice(language);
    out.push(0);

    // Bodies in order. `offsets` collects where each one starts, and gains the
    // sentinel `msgseek` subtracts against.
    let mut offsets: Vec<i32> = Vec::with_capacity(messages.len() + 1);
    for message in messages {
        offsets.push(out.len() as i32);
        out.extend_from_slice(message);
        out.push(0);
    }
    let loclist = out.len() as i32;
    offsets.push(loclist);

    for offset in &offsets {
        out.extend_from_slice(&offset.to_le_bytes());
    }

    // lnglist, lenlist, loclist, lngcnt, msgcnt.
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&loclist.to_le_bytes());
    out.extend_from_slice(&1i16.to_le_bytes());
    out.extend_from_slice(&(messages.len() as i16).to_le_bytes());

    debug_assert_eq!(
        out.len(),
        loclist as usize + 4 * (messages.len() + 1) + TRAILER,
        "the trailer must land exactly at the end"
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape `opnmsg` reads back, asserted field by field rather than by
    /// round-tripping through our own reader -- a writer checked only against a
    /// reader we also wrote would agree with itself about a wrong format.
    #[test]
    fn the_trailer_is_the_last_sixteen_bytes_and_says_where_everything_is() {
        let messages = vec![b"first".to_vec(), b"".to_vec(), b"third".to_vec()];
        let out = compile(&messages, DEFAULT_LANGUAGE);

        let at = out.len() - TRAILER;
        let word = |o: usize| i32::from_le_bytes(out[at + o..at + o + 4].try_into().unwrap());
        let short = |o: usize| i16::from_le_bytes(out[at + o..at + o + 2].try_into().unwrap());

        assert_eq!(word(0), 0, "lnglist");
        assert_eq!(word(4), 0, "lenlist is unused for one language");
        assert_eq!(short(12), 1, "lngcnt");
        assert_eq!(short(14), 3, "msgcnt");

        let loclist = word(8) as usize;
        assert_eq!(
            loclist + 4 * 4 + TRAILER,
            out.len(),
            "loclist holds msgcnt+1 offsets and then the trailer ends the file"
        );
    }

    /// The language name is at offset 0 and NUL-terminated, because `opnmsg`
    /// seeks to `lnglist` and reads it with `fgetstg`.
    #[test]
    fn the_language_comes_first_and_is_nul_terminated() {
        let out = compile(&[b"x".to_vec()], b"English/ANSI");
        assert_eq!(&out[..12], b"English/ANSI");
        assert_eq!(out[12], 0);
    }

    /// `msgseek` computes a message's size as the gap between consecutive
    /// offsets, so each body must carry its NUL and the gap must include it.
    /// A writer that omitted the NUL would hand the host the next message's
    /// first bytes as part of this one.
    #[test]
    fn a_messages_size_is_the_gap_to_the_next_offset_and_includes_its_nul() {
        let messages = vec![b"alpha".to_vec(), b"beta".to_vec()];
        let out = compile(&messages, DEFAULT_LANGUAGE);
        let at = out.len() - TRAILER;
        let loclist = i32::from_le_bytes(out[at + 8..at + 12].try_into().unwrap()) as usize;
        let offset = |n: usize| {
            i32::from_le_bytes(out[loclist + n * 4..loclist + n * 4 + 4].try_into().unwrap())
                as usize
        };

        assert_eq!(offset(1) - offset(0), 6, "\"alpha\" plus its NUL");
        assert_eq!(offset(2) - offset(1), 5, "\"beta\" plus its NUL");
        assert_eq!(&out[offset(0)..offset(1)], b"alpha\0");
        assert_eq!(&out[offset(1)..offset(2)], b"beta\0");
    }

    /// An empty message is one byte -- just its NUL. `BSWANON.MCV` has one at
    /// message 0, whose offsets are 13 and 14.
    #[test]
    fn an_empty_message_still_occupies_its_nul() {
        let out = compile(&[b"".to_vec(), b"after".to_vec()], DEFAULT_LANGUAGE);
        let at = out.len() - TRAILER;
        let loclist = i32::from_le_bytes(out[at + 8..at + 12].try_into().unwrap()) as usize;
        let offset = |n: usize| {
            i32::from_le_bytes(out[loclist + n * 4..loclist + n * 4 + 4].try_into().unwrap())
                as usize
        };
        assert_eq!(offset(1) - offset(0), 1);
    }

    /// A file with no messages is still well-formed: one sentinel offset, and a
    /// trailer saying so.
    #[test]
    fn a_file_with_no_messages_is_still_readable() {
        let out = compile(&[], DEFAULT_LANGUAGE);
        let at = out.len() - TRAILER;
        assert_eq!(
            i16::from_le_bytes(out[at + 14..at + 16].try_into().unwrap()),
            0
        );
        let loclist = i32::from_le_bytes(out[at + 8..at + 12].try_into().unwrap()) as usize;
        assert_eq!(loclist + 4 + TRAILER, out.len(), "just the sentinel");
    }
}
