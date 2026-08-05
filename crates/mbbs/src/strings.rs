//! The MajorBBS string routines, transcribed from `MAJORBBS.EXE`.
//!
//! **These have no surviving C source.** `GCOMM.H` declares them and no `.C`
//! file in `archive/` defines them, so unlike `genrdn` -- which is a
//! translation of `BBSUTILS.C:49` -- every routine here was read off the
//! instructions of `MAJORBBS-wg200.EXE`, the Worldgroup host that matches
//! MajorMUD 1.11p. `python3 re/ne_exports.py re/hosts/MAJORBBS-wg200.EXE
//! rmvwht skpwht skpwrd depad` prints what they were transcribed from.
//!
//! # The one distinction the names hide
//!
//! [`rmvwht`] tests Borland's **ctype table**; [`skpwht`] tests a **literal
//! `0x20`**. They do not agree about tabs, and no amount of reasoning from
//! "remove whitespace" and "skip whitespace" would tell you which way round it
//! goes. This is the reason the binary had to be found before this file could
//! be written.
//!
//! # Why these are slices rather than pointers
//!
//! The shims in `crate::shims::text` do the reading and writing of module
//! memory; what is here is only the transformation. That is the split
//! [`random`](crate::random) established, and it is what lets the whitespace
//! set be checked over all 256 byte values in a unit test instead of through a
//! 16-bit machine.

/// Whether `rmvwht` and `depad` consider this character whitespace.
///
/// Bit 0 of Borland's ctype table, which lives at `DGROUP:0x1a09` in
/// `MAJORBBS.EXE` and was read out of it rather than assumed:
///
/// ```text
/// index:  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
/// value:  20 20 20 20 20 20 20 20 20 21 21 21 21 21 20 20
/// ```
///
/// Exactly six characters have it -- the C `isspace` set. Not `\0`, and nothing
/// with the high bit set, which matters because MajorMUD's text is full of both.
pub fn is_white(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// `void rmvwht(char *string)` -- remove **every** whitespace character.
///
/// Not a trim. The original keeps two cursors over the one buffer and compacts
/// in place, dropping any character with [`is_white`] set wherever it occurs,
/// then re-terminates. `"  a b  "` becomes `"ab"`.
pub fn rmvwht(s: &[u8]) -> Vec<u8> {
    s.iter().copied().filter(|&c| !is_white(c)).collect()
}

/// `char *skpwht(char *cp)` -- how far to the first character that is not a
/// space.
///
/// **A literal `0x20`, not [`is_white`].** The original is
/// `while (*cp == ' ') cp++;` and it stops at the terminator only because `\0`
/// is not `0x20`. A tab stops it too, which is not what the name suggests.
pub fn skpwht(s: &[u8]) -> usize {
    s.iter().take_while(|&&c| c == b' ').count()
}

/// `char *skpwrd(char *cp)` -- how far to the space that ends this word.
///
/// The original stops on `\0` *or* `0x20`; `s` here is already the string
/// without its terminator, so the terminator check is what bounds the slice.
/// Answers `s.len()` for a word with no space after it.
pub fn skpwrd(s: &[u8]) -> usize {
    s.iter().take_while(|&&c| c != b' ').count()
}

/// `int depad(char *cp)` -- strip trailing whitespace, answer how much went.
///
/// Returns `(kept, removed)`: the new length, and the routine's own return
/// value. The original is `strlen(cp) - strpln(cp)` after `cp[strpln(cp)] = 0`,
/// with `strpln` walking backward over the [`is_white`] set -- both calls
/// resolved from `seg 33`'s relocation records, as ordinals 578 and 583. The
/// module never imports `strpln`, so it is folded in here rather than shimmed.
///
/// **Leading whitespace is not padding** and is left alone.
pub fn depad(s: &[u8]) -> (usize, u16) {
    let kept = s.iter().rposition(|&c| !is_white(c)).map_or(0, |i| i + 1);
    (kept, (s.len() - kept) as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitespace_is_the_c_isspace_set_and_nothing_else() {
        // Bit 0 of Borland's ctype table, read out of MAJORBBS.EXE wg200 at
        // DGROUP:0x1a09. Exactly six characters have it, and they are listed
        // here in the ascending order the sweep produces them: the space is
        // 0x20 and sorts last, not first.
        let white: Vec<u8> = (0..=255u8).filter(|&c| is_white(c)).collect();
        assert_eq!(white, b"\t\n\x0b\x0c\r ".iter().copied().collect::<Vec<_>>());
    }

    #[test]
    fn rmvwht_removes_every_space_not_merely_the_outer_ones() {
        // The question the surviving material could not answer, and the reason
        // this routine had to be read off the binary. A leading-and-trailing
        // trim would answer "the quick brown fox" here.
        assert_eq!(rmvwht(b"  the quick brown fox  "), b"thequickbrownfox");
    }

    #[test]
    fn rmvwht_covers_the_whole_whitespace_set_not_just_the_space() {
        assert_eq!(rmvwht(b"a\tb\nc\x0bd\x0ce\rf g"), b"abcdefg");
    }

    #[test]
    fn rmvwht_leaves_a_string_with_no_whitespace_alone() {
        assert_eq!(rmvwht(b"unchanged"), b"unchanged");
        assert_eq!(rmvwht(b""), b"");
        assert_eq!(rmvwht(b"   "), b"");
    }

    #[test]
    fn skpwht_skips_the_literal_space_and_not_the_rest_of_the_set() {
        // The single most valuable thing the disassembly bought: `rmvwht` tests
        // the ctype table, `skpwht` tests a literal 0x20. Nothing in the names
        // says so, and a reader who assumed they agreed would skip tabs here.
        assert_eq!(skpwht(b"   abc"), 3);
        assert_eq!(skpwht(b"\t abc"), 0, "a tab is not a space to this routine");
        assert_eq!(skpwht(b"abc"), 0);
        assert_eq!(skpwht(b"   "), 3, "all spaces lands on the terminator");
        assert_eq!(skpwht(b""), 0);
    }

    #[test]
    fn skpwrd_advances_to_the_space_that_ends_the_word() {
        assert_eq!(skpwrd(b"word rest"), 4);
        assert_eq!(skpwrd(b"word"), 4, "no space: lands on the terminator");
        assert_eq!(skpwrd(b" word"), 0, "already on a space: goes nowhere");
        assert_eq!(skpwrd(b""), 0);
    }

    #[test]
    fn depad_strips_the_trailing_run_and_says_how_long_it_was() {
        assert_eq!(depad(b"text   "), (4, 3));
        assert_eq!(depad(b"text"), (4, 0));
        assert_eq!(depad(b"  text"), (6, 0), "leading padding is not padding");
        assert_eq!(depad(b"text \t\r\n"), (4, 4), "the whole whitespace set");
        assert_eq!(depad(b"   "), (0, 3), "all padding leaves nothing");
        assert_eq!(depad(b""), (0, 0));
    }

    #[test]
    fn depad_counts_what_it_removed_not_what_remains() {
        // It is `strlen - strpln`, and getting that backwards is the obvious
        // slip: both are plausible ints and neither faults.
        let (kept, removed) = depad(b"ab      ");
        assert_eq!((kept, removed), (2, 6));
    }
}
