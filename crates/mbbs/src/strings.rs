//! The MajorBBS string routines, transcribed from `MAJORBBS.EXE`.
//!
//! **These have no surviving C source.** `GCOMM.H` declares them and no `.C`
//! file in `archive/` defines them, so unlike `genrdn` -- which is a
//! translation of `BBSUTILS.C:49` -- every routine here was read off the
//! instructions of the Worldgroup host. `python3 re/ne_exports.py
//! re/hosts/MAJORBBS-wg101.EXE rmvwht skpwht skpwrd depad sameas sameto samein
//! lastwd sortstgs` prints what they were transcribed from.
//!
//! **Which host binary hardly matters.** Every routine transcribed here is
//! byte-for-byte identical in `MAJORBBS-wg101.EXE` and `MAJORBBS-wg200.EXE` --
//! checked by extracting each one's bytes from both files and comparing, not
//! assumed. The target is Worldgroup 1.01, so the citations below name wg101;
//! the four routines that predate this file were read from wg200 and are the
//! same instructions.
//!
//! # Two of them were called rather than read
//!
//! [`all_digits`] and [`strcmpi`] came in for the FSD's field checks, and both
//! are cheap leaves with one string argument, so they were measured instead of
//! disassembled: `cargo run -p mbbs-machine --example alldgs` and `--example
//! stricmp` call the genuine host's own copies over probe sets chosen to
//! separate every plausible implementation from every other one. The doc
//! comment on each says which probes decided what. A measurement is worth more
//! than a transcription only when the probes are adversarial, so those probe
//! lists are part of the evidence and not decoration.
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

/// Whether a character may appear in a user-ID --
/// `SRC/api/gcommlib/ISUIDC.C:18-30`'s whole body, as a byte test.
///
///
/// Here rather than in a shim because two registered routines answer with
/// it -- `crate::shims::cnc::isuidc`, which *is* this predicate, and
/// `crate::shims::text::issupc`, whose `default:` arm calls it
/// (`SIGNUP.C:1161`) -- and because it belongs beside [`is_white`] and
/// [`toupper`]: a byte classification, checkable over all 256 values without
/// a 16-bit machine.
///
/// **`' '` is a user-ID character.** MajorBBS user-IDs contain spaces, which
/// is why `cncuid` does not stop at the first blank.
///
/// The two high ranges are `0x80..=0xa5` and `0xe0..=0xef` **read as bytes**
/// out of `ISUIDC.C`, not from the character literals it spells them with:
/// the file is CP437 and those literals do not survive being read as UTF-8.
/// In CP437 they are the accented letters and the Greek block a European
/// user-ID needed.
pub fn is_uid_char(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(c, b'.' | b' ' | b',' | b'-' | b'_' | b'\'')
        || (0x80..=0xa5).contains(&c)
        || (0xe0..=0xef).contains(&c)
}

/// Whether a character may appear in a text-variable name --
/// `SRC/api/gcommlib/ISTXVC.C:19-30`'s whole body, as a byte test.
///
///
/// [`is_uid_char`]'s sibling, written by the same author on the same day, with
/// the same two CP437 ranges and a **different** punctuation set: `_` and `?`
/// here, against `. space , - _ '` there. Only `_` is in both. The difference
/// is the point -- `crate::shims::user::keynam` validates key names with this
/// one, so a key may be called `WHO?` and may not contain a space, while a
/// user-ID may contain a space and not a `?`.
pub fn is_text_var_char(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(c, b'_' | b'?')
        || (0x80..=0xa5).contains(&c)
        || (0xe0..=0xef).contains(&c)
}

/// `int toupper(int c)`, for the byte the host actually indexes with.
///
/// Ordinal 604, `seg 1:0x54a9`. The original tests **bit 3 of the ctype table**
/// -- `test byte [es:bx+0x1a09],0x8`, Borland's `_IS_LOW` -- and subtracts 32
/// when it is set. Nothing above 127 carries a flag in that table, so **only
/// the 26 ASCII lowercase letters fold** and MajorMUD's high-bit text passes
/// through untouched.
///
/// The `int`-level behaviour -- EOF, and the truncation of everything else to
/// a byte -- is [`crate::shims::text::toupper`]'s, because it is the `int` that
/// the argument arrives as and this is the byte the table is indexed with.
pub fn toupper(c: u8) -> u8 {
    if c.is_ascii_lowercase() { c - 32 } else { c }
}

/// `int tolower(int c)` -- ordinal 603, `seg 1:0x5473`, and [`toupper`]'s
/// mirror instruction for instruction: bit 2 (`_IS_UPP`), plus 32.
///
/// This is the routine `sameas`, `sameto` and `samein` fold with -- their
/// relocation records resolve to ordinal 603, not 604.
pub fn tolower(c: u8) -> u8 {
    if c.is_ascii_uppercase() { c + 32 } else { c }
}

/// `int sameas(char *stg1,char *stg2)` -- equal, ignoring case.
///
/// Ordinal 520, `seg 35:0x1da2`, and **the opposite sense from `strcmp`**: 1
/// means equal, 0 means different. The original walks both strings folding each
/// byte with [`tolower`] -- the relocation at `seg 35:0x1db9` resolves to
/// ordinal 603, not 604 -- and when `stg1` reaches its terminator it answers
/// whether `stg2` reached its own at the same moment.
pub fn sameas(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && folded_prefix(a, b)
}

/// `int sameto(char *shorts,char *longs)` -- does `longs` **begin with**
/// `shorts`, ignoring case.
///
/// Ordinal 522, `seg 35:0x1ec4`. [`sameas`]'s loop with one line removed: when
/// `shorts` runs out it answers 1 without looking at what is left of `longs`.
///
/// **The short one is the first argument.** `GCOMM.H:324` names them that way
/// and `CSREGIS.C:134` uses them that way -- `sameto("sau:inf ",dpkstg)`.
pub fn sameto(shorts: &[u8], longs: &[u8]) -> bool {
    shorts.len() <= longs.len() && folded_prefix(shorts, &longs[..shorts.len()])
}

/// `int samein(char *shorts,char *longs)` -- does `shorts` occur **anywhere in**
/// `longs`, ignoring case.
///
/// Ordinal 521, `seg 35:0x1dfb`, and built out of [`sameto`] rather than out of
/// a scan: it calls it at each of `strlen(longs) - strlen(shorts) + 1` offsets.
/// That count is held in a local and compared **signed** (`jl`), so a `shorts`
/// longer than `longs` answers 0 without reading a byte -- unsigned, it would
/// have wrapped and walked most of a segment.
pub fn samein(shorts: &[u8], longs: &[u8]) -> bool {
    longs.len() >= shorts.len()
        && (0..=longs.len() - shorts.len()).any(|i| sameto(shorts, &longs[i..]))
}

/// `int strcmp(char *s1,char *s2)`.
///
/// Ordinal 573, `seg 1:0x2714`. Borland's is `repe cmpsb` over `strlen(s2) + 1`
/// bytes -- the terminator included, which is what makes a prefix compare
/// against the byte that follows it -- and then `sub ax,bx` with **both high
/// bytes cleared**. So the answer is the *unsigned* byte difference at the
/// first mismatch, somewhere in -255..255, and not merely a sign.
///
/// `a` and `b` are the strings without their terminators, which is why the loop
/// runs one position past `b`.
pub fn strcmp(a: &[u8], b: &[u8]) -> i16 {
    for i in 0..=b.len() {
        // Past the end of either is its terminator, and the loop stops at the
        // first difference -- so at most one step past the shorter one.
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if x != y {
            return i16::from(x) - i16::from(y);
        }
    }
    0
}

/// `int strcmpi(char *s1,char *s2)` -- [`strcmp`] with the case folded away.
///
/// Borland's `strcmpi` is its `stricmp`, ordinal 576, `seg 1:0x47f1`. This one
/// was measured rather than disassembled: `cargo run -p mbbs-machine --example
/// stricmp` calls the genuine host's copy over the pairs that distinguish every
/// plausible implementation from every other one.
///
/// **It folds up.** The six bytes between `'Z'` and `'a'` -- `[ \ ] ^ _` and
/// the backquote -- are what make the direction observable, and every one of
/// them is typeable into an FSD field. `stricmp("_","A")` and `stricmp("_","a")`
/// both answer 30, which is `0x5f - 0x41` either way: the *letter* is being
/// raised. Folding down would have put `'_'` below `'a'` instead of above it,
/// and a `MIN=`/`MAX=` range spanning one of the six would order the wrong way.
///
/// The fold is [`toupper`]'s -- the 26 ASCII lowercase letters and nothing
/// else. `stricmp("\xe0","\xc0")` answers 32, the raw difference untouched, so
/// no high-bit byte is a letter here either.
///
/// # Why an `Ordering` where [`strcmp`] returns the byte difference
///
/// Not a style choice: the magnitude is **not** simply the folded byte
/// difference, and returning one would mean modelling an asymmetry that no
/// caller can see. When the left string runs out first the host compares the
/// right byte *unfolded* -- `stricmp("ab","abc")` is -99 (against `'c'`) while
/// `stricmp("ab","abC")` is -67 (against `'C'`) -- but when the right runs out
/// first the left byte *is* folded, `stricmp("abc","ab")` and
/// `stricmp("abC","ab")` both answering 67.
///
/// The sign is unaffected by that in every case, because a string that ran out
/// is smaller whichever byte it is measured against. `chkmin`/`chkmax`
/// (`FSD.C:913`, `:947`) use the sign and nothing else, so an `Ordering` is
/// exactly the part of the answer that is both meaningful and faithful.
///
/// It compares *strings*: for a `#` field `"9"` is greater than `"10"`. Only a
/// `$` field goes through `sscanf("%ld")` and compares numerically.
pub fn strcmpi(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    // Unsigned, byte for byte, shorter-is-smaller -- which is what comparing
    // against the terminator amounts to. No allocation: the fold is applied as
    // the two runs are walked in step.
    a.iter()
        .map(|&c| toupper(c))
        .cmp(b.iter().map(|&c| toupper(c)))
}

/// `int alldgs(char *string)` -- is every character a decimal digit?
///
/// `GCOMM.H:345` declares it and no recovered `.C` file defines it, so this is
/// measured from the genuine host at `46:0` by `cargo run -p mbbs-machine --example
/// alldgs` rather than inferred.
///
/// **The empty string answers true**, and that is the part that matters:
/// `chktyp` (`FSD.C:874`) tests a `#` field with a bare `alldgs(bufptr)` and a
/// `$` field with `strlen(cp) > 0 && alldgs(cp)`, an asymmetry that is only
/// coherent if an empty answer passes the first and fails the second.
///
/// Everything else is literal. A sign is not a digit -- which is why `chktyp`'s
/// `$` case strips the leading `-` itself -- and neither is leading or trailing
/// whitespace. `"/"` and `":"` bracket the range and both answer 0, and so do
/// `0x80`, `0xb2` and `0xff`, so Borland's signed-`char` `isdigit` table
/// indexing never comes into it and there is nothing here but the ASCII digits.
pub fn all_digits(s: &[u8]) -> bool {
    s.iter().all(u8::is_ascii_digit)
}

/// `char *lastwd(char *string)` -- how far to the start of the last word.
///
/// Ordinal 381, `seg 34:0x12fd`. Two backward walks from the last character:
/// over the trailing whitespace, then over the word itself. Each stops dead at
/// the start of the string and answers it, which is what makes an empty string,
/// an all-whitespace string and a single word all answer offset zero.
///
/// **Nothing is written.** The trailing whitespace is skipped over, not
/// removed -- `lastwd("go north  ")` answers `"north  "` -- and `depad` is the
/// routine that truncates.
///
/// The whitespace set is [`is_white`], `_ctype` bit 0, the same set `rmvwht`
/// and `depad` test and not the literal `0x20` that `skpwht` does.
pub fn lastwd(s: &[u8]) -> usize {
    let Some(mut p) = s.len().checked_sub(1) else {
        return 0;
    };
    while is_white(s[p]) {
        if p == 0 {
            return 0;
        }
        p -= 1;
    }
    while !is_white(s[p]) {
        if p == 0 {
            return 0;
        }
        p -= 1;
    }
    p + 1
}

/// `void sortstgs(char *stgs[],int num)` -- the shell sort itself.
///
/// Ordinal 558, `seg 36:0x096d`, transcribed rather than handed to
/// [`slice::sort_by`]: a shell sort is not stable, so which of two equal
/// strings ends up where is observable, and only the original's own gap
/// sequence answers that the same way.
///
/// The comparison is a far call whose relocation resolves to `seg 1:0x2714` =
/// [`strcmp`], so the order is **case-sensitive** and by unsigned byte.
///
/// A `num` below two makes `gap` zero and the original returns having read
/// nothing; the caller refuses those before it reads the array at all, so the
/// loop here is only what remains once `gap` is known positive.
pub fn sortstgs<T>(items: &mut [T], mut cmp: impl FnMut(&T, &T) -> i16) {
    let mut gap = items.len() / 2;
    while gap > 0 {
        for i in gap..items.len() {
            let mut j = i - gap;
            // The original breaks out of the whole `j` loop the moment a pair
            // is already in order -- `jng` past the swap -- rather than merely
            // stopping this comparison.
            while cmp(&items[j], &items[j + gap]) > 0 {
                items.swap(j, j + gap);
                match j.checked_sub(gap) {
                    Some(next) => j = next,
                    None => break,
                }
            }
        }
        gap /= 2;
    }
}

/// Whether two equal-length runs match once [`tolower`] has folded each byte.
///
/// The one loop `sameas` and `sameto` share; they differ only in what happens
/// when it runs out.
fn folded_prefix(a: &[u8], b: &[u8]) -> bool {
    a.iter().zip(b).all(|(&x, &y)| tolower(x) == tolower(y))
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
    fn case_folding_covers_the_ascii_letters_and_nothing_else() {
        // `_ctype` carries `_IS_LOW` and `_IS_UPP` on the 26 ASCII letters and
        // on nothing at all above 127. MajorMUD's text is full of high-bit
        // bytes and not one of them folds.
        let folded: Vec<u8> = (0..=255u8).filter(|&c| toupper(c) != c).collect();
        assert_eq!(folded, (b'a'..=b'z').collect::<Vec<u8>>());

        let folded: Vec<u8> = (0..=255u8).filter(|&c| tolower(c) != c).collect();
        assert_eq!(folded, (b'A'..=b'Z').collect::<Vec<u8>>());

        assert_eq!(toupper(b'a'), b'A');
        assert_eq!(tolower(b'A'), b'a');
        assert_eq!(toupper(0xe9), 0xe9, "an accented byte is not a letter here");
    }

    #[test]
    fn sameas_is_whole_string_and_case_blind() {
        assert!(sameas(b"LONG", b"long"));
        assert!(sameas(b"", b""));
        assert!(!sameas(b"long", b"longer"), "not a prefix test");
        assert!(!sameas(b"longer", b"long"));
        assert!(!sameas(b"", b"x"));
        assert!(!sameas(b"x", b""));
    }

    #[test]
    fn sameto_asks_whether_the_long_one_begins_with_the_short_one() {
        // `GCOMM.H:324` names the arguments `shorts` and `longs` in that
        // order, and `CSREGIS.C:134` -- `sameto("sau:inf ",dpkstg)` -- puts
        // the literal prefix on the left. Getting this round the wrong way is
        // the trap.
        assert!(sameto(b"sau:inf ", b"sau:inf 1234"));
        assert!(sameto(b"same", b"SAME"), "an exact match is a prefix");
        assert!(sameto(b"", b"anything"), "an empty prefix always matches");
        assert!(sameto(b"", b""));
        assert!(!sameto(b"sau:inf ", b"sau:"), "longs runs out first");
        assert!(!sameto(b"x", b""));
    }

    #[test]
    fn samein_is_a_substring_test_built_out_of_sameto() {
        assert!(samein(b"NORTH", b"go north now"));
        assert!(samein(b"go", b"go north"), "a prefix is a substring");
        assert!(samein(b"now", b"go north now"), "so is a suffix");
        assert!(samein(b"", b"anything"));
        assert!(!samein(b"south", b"go north"));

        // `strlen(longs) - strlen(shorts) + 1` is zero or less under a SIGNED
        // compare, so the loop never runs. Unsigned it would wrap and read
        // 65,000-odd offsets past the end.
        assert!(!samein(b"longer than", b"short"));
        assert!(!samein(b"x", b""));
    }

    #[test]
    fn strcmp_answers_the_byte_difference_and_not_merely_a_sign() {
        assert_eq!(strcmp(b"abc", b"abc"), 0);
        assert_eq!(strcmp(b"", b""), 0);
        assert_eq!(strcmp(b"abc", b"abd"), -1);
        assert_eq!(strcmp(b"abd", b"abc"), 1);
        assert_eq!(strcmp(b"ab", b"abc"), -99, "the terminator against 'c'");
        assert_eq!(strcmp(b"abc", b"ab"), 99);
        assert_eq!(strcmp(b"", b"a"), -97);
    }

    #[test]
    fn strcmp_compares_bytes_unsigned() {
        // `mov al,[si-1]` with `ah` and `bh` cleared before the `sub`. Read
        // signed, 0x80 would be negative and this would come out the other way.
        assert_eq!(strcmp(b"\x80", b"\x01"), 127);
        assert_eq!(strcmp(b"\x01", b"\x80"), -127);
        assert_eq!(strcmp(b"\xff", b"\x01"), 254, "the widest it can be");
    }

    /// `alldgs`, `GCOMM.H:345`. Measured from the genuine host, not inferred:
    /// `cargo run -p mbbs-machine --example alldgs` prints every line asserted here.
    ///
    /// The empty string is the one that matters. `chktyp` (`FSD.C:874`) tests a
    /// `#` field with a bare `alldgs(bufptr)` and a `$` field with
    /// `strlen(cp) > 0 && alldgs(cp)`, and that asymmetry is only coherent if
    /// an empty answer passes the first and fails the second. It does.
    #[test]
    fn all_digits_is_what_the_genuine_host_says_it_is() {
        assert!(all_digits(b""), "the empty string is all-digits");
        assert!(all_digits(b"0"));
        assert!(all_digits(b"9"));
        assert!(all_digits(b"007"));
        assert!(all_digits(b"12345678901234567890"), "no length limit, no overflow");

        // A sign is not a digit, which is exactly why `chktyp`'s `$` case
        // strips the minus itself before it asks.
        assert!(!all_digits(b"-1"));
        assert!(!all_digits(b"+1"));
        // Nor is whitespace, on either end. "All" means all, not "a prefix".
        assert!(!all_digits(b" "));
        assert!(!all_digits(b" 1"));
        assert!(!all_digits(b"1 "));
        assert!(!all_digits(b"\t"));
        assert!(!all_digits(b"1.0"));
        assert!(!all_digits(b"a"));
        assert!(!all_digits(b"1a"));
        assert!(!all_digits(b"a1"));
    }

    /// The four bytes a wrong `alldgs` would disagree on, all measured.
    ///
    /// `/` and `:` bracket `'0'..'9'` and catch a range check written with the
    /// wrong comparison. The high-bit three catch the other hazard: Borland's
    /// `isdigit` indexes `_ctype` with a *signed* `char`, so a byte above 0x7f
    /// reads before the start of that table and could answer anything. The
    /// host says 0 to all five, so "every byte is an ASCII digit" is the whole
    /// of it and no table has to be modelled.
    #[test]
    fn all_digits_stops_at_the_edges_of_the_ascii_digits() {
        assert!(!all_digits(b"/"), "'0' - 1");
        assert!(!all_digits(b":"), "'9' + 1");
        assert!(!all_digits(b"\x80"));
        assert!(!all_digits(b"\xb2"), "superscript two is not a digit here");
        assert!(!all_digits(b"\xff"));
    }

    /// `strcmpi` -- Borland's case-insensitive `strcmp`. `chkmin`/`chkmax` use
    /// it to order *strings*, including strings of digits, which is why "9" is
    /// greater than "10" for a `#` field and not for a `$` one.
    #[test]
    fn strcmpi_orders_without_regard_to_case() {
        use std::cmp::Ordering;
        assert_eq!(strcmpi(b"abc", b"ABC"), Ordering::Equal);
        assert_eq!(strcmpi(b"ABC", b"abd"), Ordering::Less);
        assert_eq!(strcmpi(b"b", b"A"), Ordering::Greater);
        assert_eq!(strcmpi(b"A", b"b"), Ordering::Less);
        assert_eq!(strcmpi(b"ab", b"abc"), Ordering::Less, "a prefix sorts first");
        assert_eq!(strcmpi(b"abc", b"ab"), Ordering::Greater);
        assert_eq!(strcmpi(b"", b""), Ordering::Equal);
        assert_eq!(strcmpi(b"", b"a"), Ordering::Less);
        assert_eq!(strcmpi(b"a", b""), Ordering::Greater);
        assert_eq!(strcmpi(b"9", b"10"), Ordering::Greater, "string order, not numeric");
    }

    /// **It folds up, not down**, and the six bytes between `'Z'` and `'a'` are
    /// what make that observable. Measured by
    /// `cargo run -p mbbs-machine --example stricmp`.
    ///
    /// `'_'` is 0x5f. Folding up, it is compared against `'A'` = 0x41 and is
    /// *greater*; folding down it would be compared against `'a'` = 0x61 and be
    /// *smaller*. The host answers 30 to both `stricmp("_","A")` and
    /// `stricmp("_","a")` -- 0x5f - 0x41 either way -- so the letter is being
    /// raised, not the underscore lowered. Every one of these six is typeable
    /// into an FSD field, so a `MIN=`/`MAX=` range spanning one orders
    /// differently under the wrong fold.
    #[test]
    fn strcmpi_folds_up_so_the_between_case_bytes_outrank_the_letters() {
        use std::cmp::Ordering;
        for &between in &[b"[", b"\\", b"]", b"^", b"_", b"`"] {
            assert_eq!(strcmpi(between, b"A"), Ordering::Greater, "{between:?} vs A");
            assert_eq!(
                strcmpi(between, b"a"),
                Ordering::Greater,
                "{between:?} vs a -- the same answer, which is what pins the direction"
            );
        }
    }

    /// The fold stops at ASCII, so the host's high-bit text orders by raw byte.
    ///
    /// `stricmp("\xe0","\xc0")` and `stricmp("\xe9","\xc9")` both answer 32 --
    /// the difference untouched -- so nothing above 0x7f is a letter to this
    /// routine, the same way nothing above 0x7f carries a `_ctype` flag for
    /// [`toupper`]. And the comparison is unsigned: 0x80 outranks 0x01.
    #[test]
    fn strcmpi_folds_only_the_ascii_letters_and_compares_unsigned() {
        use std::cmp::Ordering;
        assert_eq!(strcmpi(b"\xe0", b"\xc0"), Ordering::Greater);
        assert_eq!(strcmpi(b"\xe9", b"\xc9"), Ordering::Greater);
        assert_eq!(strcmpi(b"\x80", b"\x01"), Ordering::Greater);
        assert_eq!(strcmpi(b"\x01", b"\x80"), Ordering::Less);
    }

    #[test]
    fn lastwd_finds_the_start_of_the_last_word() {
        // `MAJORBBS.C:535` is `sameas(lastwd(getmsg(SHORTM)),"LONG")` -- the
        // last word of a configuration line.
        assert_eq!(lastwd(b"go north"), 3);
        assert_eq!(lastwd(b"SHORT MESSAGES LONG"), 15);
        assert_eq!(lastwd(b"word"), 0, "one word starts at the start");
        assert_eq!(lastwd(b""), 0);
        assert_eq!(lastwd(b"   "), 0, "nothing but whitespace");
    }

    #[test]
    fn lastwd_skips_the_trailing_whitespace_without_removing_it() {
        // It writes nothing at all. `depad` is the routine that truncates;
        // this one answers a pointer and leaves the padding behind it in place.
        assert_eq!(lastwd(b"go north  "), 3);
        assert_eq!(lastwd(b"go\tnorth\r\n"), 3, "the whole is_white set");
    }

    #[test]
    fn sortstgs_orders_by_strcmp_and_so_is_case_sensitive() {
        // The comparison is a far call whose relocation resolves to
        // `seg 1:0x2714` = `strcmp`, not `sameas`. Uppercase sorts first.
        let mut items: Vec<&[u8]> = vec![b"pear", b"Apple", b"apple"];
        sortstgs(&mut items, |a, b| strcmp(a, b));
        assert_eq!(items, vec![&b"Apple"[..], &b"apple"[..], &b"pear"[..]]);
    }

    #[test]
    fn sortstgs_moves_equal_strings_the_way_a_shell_sort_does() {
        // The property that justifies transcribing this instead of calling
        // `sort_by`, and the only test that can tell the two apart. Four
        // pointers, three of them to equal strings, so what is observable is
        // *which* pointer lands where.
        //
        // gap 2: cmp(items[1], items[3]) is "b" against "a", so they swap and
        // `b` travels two places at once -- and equal elements that a stable
        // sort would have left alone are reordered around it.
        let mut items = [
            Tagged(b"a", 'A'),
            Tagged(b"b", 'B'),
            Tagged(b"a", 'C'),
            Tagged(b"a", 'D'),
        ];
        sortstgs(&mut items, |x, y| strcmp(x.0, y.0));
        let order: String = items.iter().map(|t| t.1).collect();
        assert_eq!(order, "ADCB", "the shell sort's own permutation");

        let mut items = [
            Tagged(b"a", 'A'),
            Tagged(b"b", 'B'),
            Tagged(b"a", 'C'),
            Tagged(b"a", 'D'),
        ];
        items.sort_by(|x, y| strcmp(x.0, y.0).cmp(&0));
        let stable: String = items.iter().map(|t| t.1).collect();
        assert_eq!(stable, "ACDB", "which a stable sort does not agree with");
    }

    /// A string and a label, so a test can see which of two equal strings
    /// moved. Equality of the *strings* is what the sort compares; the label
    /// rides along and is never looked at.
    #[derive(Debug, PartialEq, Eq)]
    struct Tagged(&'static [u8], char);

    #[test]
    fn sortstgs_handles_every_size_its_gap_sequence_degenerates_on() {
        for n in 0..12usize {
            let reversed: Vec<Vec<u8>> = (0..n).rev().map(|i| vec![b'a' + i as u8]).collect();
            let mut items: Vec<&[u8]> = reversed.iter().map(Vec::as_slice).collect();
            sortstgs(&mut items, |a, b| strcmp(a, b));

            let want: Vec<Vec<u8>> = (0..n).map(|i| vec![b'a' + i as u8]).collect();
            let want: Vec<&[u8]> = want.iter().map(Vec::as_slice).collect();
            assert_eq!(items, want, "n = {n}");
        }
    }

    #[test]
    fn whitespace_is_the_c_isspace_set_and_nothing_else() {
        // Bit 0 of Borland's ctype table, read out of MAJORBBS.EXE wg200 at
        // DGROUP:0x1a09. Exactly six characters have it, and they are listed
        // here in the ascending order the sweep produces them: the space is
        // 0x20 and sorts last, not first.
        let white: Vec<u8> = (0..=255u8).filter(|&c| is_white(c)).collect();
        assert_eq!(white, b"\t\n\x0b\x0c\r ".to_vec());
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
