//! Task 22's actual payoff, enforced mechanically instead of by a trait.
//!
//! Task 22 measured the reconstruction stack (`format/`, `model.rs`,
//! `read.rs`, `emit.rs`, `canvas.rs`, `corpus.rs`) and found the spec's
//! `GenerationBehaviour` trait would wrap two implementations that never
//! meet at a shared call site -- ceremony, not structure (see the task
//! report). The controller's ruling: don't build the trait, but the spec's
//! real promise -- "adding a generation means the compiler names every
//! behaviour not yet written" -- still has to be true, and `Generation`
//! being a plain, exhaustively-matched enum is what already delivers it, or
//! would, if nothing quietly opts out of exhaustiveness checking.
//!
//! Two things opt out of it, and this test forbids both, over the *real*
//! source text of the *real* files in scope, not a description of the rule:
//!
//! 1. **`matches!(x, A | B)`** desugars to `match x { A | B => true, _ =>
//!    false }` -- the wildcard is inside the macro, invisible at the call
//!    site, so no scan for a literal `_` at the call site would ever catch
//!    it. `Generation::is_v6` was written this way before this task: a
//!    hypothetical seventh generation would have silently come back `false`
//!    from it forever, with no compile error anywhere. So any `matches!`
//!    call whose argument names a `Generation` variant is forbidden
//!    outright, full stop -- there is no wildcard-shaped text to look for
//!    inside it.
//! 2. **A bare catch-all arm** (`_ =>`, `other =>`, or any other single bare
//!    identifier pattern) inside a real `match` that does mention
//!    `Generation`/`Self` variants. A real `match` with no such arm is
//!    exhaustive by construction -- rustc itself refuses to compile it
//!    otherwise -- so finding zero of these is what makes the compiler's
//!    own exhaustiveness check load-bearing rather than bypassable.
//!
//! # What this scanner does and does not understand
//!
//! This crate is std-only, so this test has no Rust parser to call into --
//! it is a small, purpose-built lexer (`code_mask`) that marks which bytes
//! are live code versus inside a string, char, or comment, so a stray `{`,
//! `}`, or the word "match" inside an error message or a doc comment (both
//! are constant hazards in this crate's prose-heavy style) cannot desync
//! the brace count or produce a false hit. On top of that mask it finds
//! every `match` keyword, brace-balances to that match's own closing `}`,
//! and classifies the block as "concerns `Generation`" only if some arm's
//! own *pattern* (not its result expression, and not the word "generation"
//! in prose or in the unrelated page/allocation-block *counter* field of
//! the same name) names a `Generation::V*`/`Self::V*` variant path
//! explicitly. The pattern-versus-result distinction is load-bearing:
//! `format::generation::identify`'s word-decode matches (`match word {
//! 0x300 => Generation::V5R3, ..., other => Err(..) }`) construct
//! `Generation` values as their *results* while matching on a raw `u16`
//! *pattern* -- a first version of this scanner checked the whole body and
//! wrongly flagged `identify`'s own two deliberate, correct wildcards.
//!
//! It assumes -- because both real matches in scope are written this way,
//! and stay written this way -- that each arm's pattern and its `=>` share
//! one physical line. A pattern wrapped across multiple lines, or a guarded
//! arm (`pat if cond =>`), would defeat the bare-identifier check below; the
//! two matches this test currently finds do not do that, and the mutation
//! test (`a_wildcard_arm_is_caught`) proves the check fires on the shapes
//! that matter -- `_ =>` and a bare catch-all name -- rather than claiming
//! broader coverage than it has.
//!
//! # The mutation
//!
//! `a_wildcard_arm_is_caught` inserts a real wildcard arm into a copy of
//! `is_v6`'s source text (not the compiled crate -- this test only reads
//! text) and asserts the scanner used by the real check below flags it.
//! Confirmed by hand while writing this test: reverting
//! `Generation::is_v6` to its old `matches!` form, or adding a `_ =>` arm to
//! either real match, turns `no_match_on_generation_has_a_catch_all_arm` red.

use std::fs;
use std::path::{Path, PathBuf};

/// `Generation`'s own variant names, used only to recognise which `match`
/// blocks are about `Generation` at all -- not the mechanism that enforces
/// exhaustiveness (that's rustc, once the wildcard is gone).
const VARIANTS: [&str; 6] = ["V5R3", "V5R4", "V5R5", "V600", "V610", "V620"];

fn crate_src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// The six modules pre-flight ruling 3 and the Task 22 report scope this
/// to. `format/` is a directory; every `.rs` file inside it is in scope.
fn scoped_files() -> Vec<PathBuf> {
    let src = crate_src_dir();
    let mut files = vec![
        src.join("model.rs"),
        src.join("read.rs"),
        src.join("emit.rs"),
        src.join("canvas.rs"),
        src.join("corpus.rs"),
    ];
    let format_dir = src.join("format");
    let mut format_files: Vec<PathBuf> = fs::read_dir(&format_dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", format_dir.display()))
        .map(|entry| entry.expect("a readable directory entry").path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "rs"))
        .collect();
    format_files.sort();
    assert!(!format_files.is_empty(), "format/ walk found nothing -- the walker has gone blind");
    files.extend(format_files);

    for f in &files {
        assert!(f.is_file(), "{} does not exist -- the scope list is stale", f.display());
    }
    files
}

/// Byte-for-byte the same length as `source`: `true` where that byte is
/// live code, `false` where it is inside a `"string"`, a `'c'`har literal,
/// a `// line` comment, or a `/* block */` comment (block comments nest,
/// since Rust's do). A lifetime (`'a`) is distinguished from a char literal
/// by whether a closing `'` shows up within the next few bytes -- a
/// lifetime never has one there.
fn code_mask(source: &str) -> Vec<bool> {
    #[derive(Clone, Copy, PartialEq)]
    enum St {
        Normal,
        Str,
        StrEsc,
        Char,
        CharEsc,
        Line,
        Block(u32),
    }

    let bytes = source.as_bytes();
    let mut mask = vec![false; bytes.len()];
    let mut st = St::Normal;
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        match st {
            St::Normal => {
                if c == b'/' && bytes.get(i + 1) == Some(&b'/') {
                    st = St::Line;
                    i += 2;
                    continue;
                }
                if c == b'/' && bytes.get(i + 1) == Some(&b'*') {
                    st = St::Block(1);
                    i += 2;
                    continue;
                }
                if c == b'"' {
                    st = St::Str;
                    i += 1;
                    continue;
                }
                if c == b'\'' {
                    // Look ahead for a closing quote within a plausible char
                    // literal's width (`'\''`, `'\\'`, `'\0'` are the
                    // longest at 4 bytes including both quotes). No closing
                    // quote there means this is a lifetime, not a literal,
                    // and stays Normal.
                    let mut j = i + 1;
                    let mut escaped = false;
                    let mut closes = false;
                    while j < bytes.len() && j <= i + 4 {
                        if bytes[j] == b'\\' && !escaped {
                            escaped = true;
                            j += 1;
                            continue;
                        }
                        if bytes[j] == b'\'' && j > i + 1 {
                            closes = true;
                            break;
                        }
                        escaped = false;
                        j += 1;
                    }
                    mask[i] = true;
                    i += 1;
                    if closes {
                        st = St::Char;
                    }
                    continue;
                }
                mask[i] = true;
                i += 1;
            }
            St::Str => {
                if c == b'\\' {
                    st = St::StrEsc;
                } else if c == b'"' {
                    st = St::Normal;
                }
                i += 1;
            }
            St::StrEsc => {
                st = St::Str;
                i += 1;
            }
            St::Char => {
                if c == b'\\' {
                    st = St::CharEsc;
                } else if c == b'\'' {
                    st = St::Normal;
                }
                i += 1;
            }
            St::CharEsc => {
                st = St::Char;
                i += 1;
            }
            St::Line => {
                if c == b'\n' {
                    st = St::Normal;
                    mask[i] = true;
                }
                i += 1;
            }
            St::Block(depth) => {
                if c == b'/' && bytes.get(i + 1) == Some(&b'*') {
                    st = St::Block(depth + 1);
                    i += 2;
                    continue;
                }
                if c == b'*' && bytes.get(i + 1) == Some(&b'/') {
                    st = if depth == 1 { St::Normal } else { St::Block(depth - 1) };
                    i += 2;
                    continue;
                }
                i += 1;
            }
        }
    }
    mask
}

/// Whether `source[at..]` begins with `word` there, as a whole word: not
/// preceded or followed by an identifier character, and sitting on live
/// code per `mask`.
fn word_at(source: &str, mask: &[bool], at: usize, word: &str) -> bool {
    let bytes = source.as_bytes();
    if at + word.len() > bytes.len() {
        return false;
    }
    if &source[at..at + word.len()] != word {
        return false;
    }
    if mask[at..at + word.len()].iter().any(|&m| !m) {
        return false;
    }
    let before_ok = at == 0 || !is_ident_byte(bytes[at - 1]);
    let after_idx = at + word.len();
    let after_ok = after_idx >= bytes.len() || !is_ident_byte(bytes[after_idx]);
    before_ok && after_ok
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The byte index one past the `}` that closes the block opened by the `{`
/// at `open`, counting only braces on live code.
fn matching_brace(source: &str, mask: &[bool], open: usize) -> usize {
    let bytes = source.as_bytes();
    assert_eq!(bytes[open], b'{', "matching_brace must be called on a '{{'");
    let mut depth = 0i32;
    let mut i = open;
    while i < bytes.len() {
        if mask[i] {
            if bytes[i] == b'{' {
                depth += 1;
            } else if bytes[i] == b'}' {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
        }
        i += 1;
    }
    panic!("unbalanced braces starting at byte {open}");
}

/// Delete every `#[cfg(test)]`-attributed item (a `mod tests { ... }`, or --
/// `format/free_slot.rs` has one of each -- a single `#[cfg(test)] fn` inside
/// an otherwise-production module) from `source`, mask-aware. Test code
/// legitimately builds `Generation` values and matches on them for
/// assertions (`corpus.rs`'s census tests, for instance); that is not the
/// hazard this test polices, so it must not be scanned at all, or it would
/// either hide a real production catch-all inside noise or -- the wrong
/// direction of failure -- flag a perfectly normal test assertion as one.
///
/// Every occurrence of this attribute in the scoped files is the literal
/// text `#[cfg(test)]` (verified: no `#[cfg(unix)]`, `#[cfg_attr(...)]`, or
/// similar appears in `format/`, `model.rs`, `read.rs`, `emit.rs`,
/// `canvas.rs`, or `corpus.rs`), so this looks for that exact substring
/// rather than parsing attribute syntax generally.
fn strip_test_modules(source: &str) -> String {
    const ATTR: &str = "#[cfg(test)]";
    let mut text = source.to_string();
    loop {
        let mask = code_mask(&text);
        let Some(attr_at) = find_live_substring(&text, &mask, ATTR, 0) else {
            break;
        };
        let after_attr = attr_at + ATTR.len();
        let Some(brace_off) = text[after_attr..].find('{') else {
            break;
        };
        let brace_at = after_attr + brace_off;
        let mask2 = code_mask(&text);
        let end = matching_brace(&text, &mask2, brace_at);
        text.replace_range(attr_at..end, "");
    }
    text
}

/// First occurrence of the literal substring `needle` that lands entirely
/// on live code (`mask`), at or after `from`.
fn find_live_substring(source: &str, mask: &[bool], needle: &str, from: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let needle_bytes = needle.as_bytes();
    if needle_bytes.is_empty() || needle_bytes.len() > bytes.len() {
        return None;
    }
    let mut i = from;
    while i + needle_bytes.len() <= bytes.len() {
        if &bytes[i..i + needle_bytes.len()] == needle_bytes && mask[i..i + needle_bytes.len()].iter().all(|&m| m) {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// First occurrence of `word` as a whole word on live code at or after
/// `from`.
fn find_word(source: &str, mask: &[bool], word: &str, from: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut i = from;
    while i + word.len() <= bytes.len() {
        if word_at(source, mask, i, word) {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// One `match` block found in production source: the file it came from,
/// its scrutinee text, and its arm body (between the braces, exclusive).
struct MatchBlock {
    file: String,
    body: String,
}

/// Every `match` keyword in `source` (live code only), paired with its own
/// arm body. Deliberately does not special-case `matches!` -- the whole
/// point is that macro never shows up as a `match` keyword at all (it
/// expands at compile time, long after this text scan runs), which is
/// exactly why `forbidden_matches_bang_calls` has to exist as a *separate*
/// check.
fn match_blocks(file: &str, source: &str) -> Vec<MatchBlock> {
    let mask = code_mask(source);
    let mut out = Vec::new();
    let mut search_from = 0usize;
    while let Some(kw_at) = find_word(source, &mask, "match", search_from) {
        let after_kw = kw_at + "match".len();
        // `matches!` shares the prefix "match" but is never a whole word
        // "match" on its own -- `word_at` already required a non-identifier
        // byte right after "match", and `e` in "matches" is an identifier
        // byte, so `find_word` already skips every `matches!` call without
        // help. (Confirmed: `matches!(` never matches `word_at(.., "match",
        // ..)` because the byte after "match"'s 5 letters is `e`.)
        let Some(brace_off) = source[after_kw..].find('{') else {
            search_from = after_kw;
            continue;
        };
        let brace_at = after_kw + brace_off;
        let close = matching_brace(source, &mask, brace_at);
        out.push(MatchBlock {
            file: file.to_string(),
            body: source[brace_at + 1..close - 1].to_string(),
        });
        search_from = close;
    }
    out
}

/// Whether `body` matches *on* `Generation` -- a `Generation::V600` or
/// `Self::V5R3` variant path named in an arm's *pattern* (the text before
/// that line's own `=>`), not merely somewhere in the body.
///
/// The pattern side specifically, not "anywhere in the block", is what
/// distinguishes this from `format::generation::identify`'s two word-decode
/// matches: `match word { 0x300 => Generation::V5R3, ..., other => {
/// return Err(...) } }` matches on a raw `u16`/`i16` *word* read off the
/// file, and its arm *results* legitimately construct `Generation::V5R3` --
/// but its arm *patterns* are `0x300`, `0x400`, `other`, never a
/// `Generation`/`Self` path, so it is correctly not a match on `Generation`
/// and its `other` wildcard is exactly right (the word space is far larger
/// than six valid values, and unrecognised ones are refused, not silently
/// absorbed -- confirmed by hand: the first version of this scanner
/// checked the whole body and wrongly flagged `identify`'s own two
/// deliberate, correct wildcards as violations).
///
/// This also keeps `read.rs`'s `page0.generation.cmp(&page1.generation)` --
/// a `u16` shadow-copy *counter* field sharing the enum's name, compared as
/// an ordinary integer via `std::cmp::Ordering` -- out of scope: its arm
/// patterns are `Ordering::Greater`/`Less`/`Equal`, never a `Generation`/
/// `Self` path (`the_scanner_does_not_confuse_the_generation_counter_field_
/// with_the_enum` below proves this directly).
fn concerns_generation(body: &str) -> bool {
    for line in body.lines() {
        let Some(arrow_at) = line.find("=>") else { continue };
        let pattern = &line[..arrow_at];
        if VARIANTS.iter().any(|v| pattern.contains(&format!("Generation::{v}")) || pattern.contains(&format!("Self::{v}"))) {
            return true;
        }
    }
    false
}

/// Whether any arm in `body` is a bare catch-all: `_ =>` or a single plain
/// identifier (`other =>`, `unknown =>`, ...) immediately before `=>` on its
/// own line. A real variant path always contains `::`, so this cannot
/// mistake `Generation::V600 =>` or `Self::V5R3 | Self::V5R4 =>` for a
/// catch-all; it also cannot see a guarded arm's condition (`pat if cond
/// =>`) as anything other than "not bare" (the space defeats the identifier
/// check), which is a real, documented limitation, not silent unsoundness in
/// either direction: it needs no false positive to trip, and this test's
/// only two subjects use no guards.
fn has_bare_catch_all_arm(body: &str) -> bool {
    for line in body.lines() {
        let Some(arrow_at) = line.find("=>") else { continue };
        let pattern = line[..arrow_at].trim();
        if pattern.is_empty() {
            continue;
        }
        let bare = pattern.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if bare {
            return true;
        }
    }
    false
}

/// Every `matches!(...)` call in `source` whose argument list names a
/// `Generation` variant -- forbidden outright, since `matches!` bakes an
/// invisible `_ => false` into every call regardless of what the call site's
/// own text says.
fn forbidden_matches_bang_calls(file: &str, source: &str) -> Vec<String> {
    let mask = code_mask(source);
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(at) = find_word(source, &mask, "matches", from) {
        let bang_at = at + "matches".len();
        if source.as_bytes().get(bang_at) != Some(&b'!') {
            from = at + 1;
            continue;
        }
        let Some(paren_off) = source[bang_at..].find('(') else {
            from = bang_at;
            continue;
        };
        let paren_at = bang_at + paren_off;
        // Reuse the brace matcher's logic by temporarily treating this as a
        // brace scan is wrong (different delimiter); paren-balance directly,
        // mask-aware, the same way.
        let bytes = source.as_bytes();
        let mut depth = 0i32;
        let mut i = paren_at;
        let mut close = paren_at;
        while i < bytes.len() {
            if mask[i] {
                if bytes[i] == b'(' {
                    depth += 1;
                } else if bytes[i] == b')' {
                    depth -= 1;
                    if depth == 0 {
                        close = i + 1;
                        break;
                    }
                }
            }
            i += 1;
        }
        let call = &source[at..close];
        if VARIANTS.iter().any(|v| call.contains(&format!("Generation::{v}")) || call.contains(&format!("Self::{v}"))) {
            out.push(format!("{file}: {call}"));
        }
        from = close;
    }
    out
}

fn production_source(path: &Path) -> (String, String) {
    let raw = fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    let stripped = strip_test_modules(&raw);
    (raw, stripped)
}

#[test]
fn matches_bang_never_names_a_generation_variant() {
    let mut offences = Vec::new();
    for path in scoped_files() {
        let (_raw, production) = production_source(&path);
        offences.extend(forbidden_matches_bang_calls(&path.display().to_string(), &production));
    }
    assert!(
        offences.is_empty(),
        "matches!() bakes an implicit `_ => false` underneath, invisible at \
         the call site -- a Generation variant must be matched with a real \
         `match` instead, which the check below can verify is exhaustive-\
         by-construction. Offending calls:\n{}",
        offences.join("\n")
    );
}

#[test]
fn no_match_on_generation_has_a_catch_all_arm() {
    let mut blocks = Vec::new();
    for path in scoped_files() {
        let (_raw, production) = production_source(&path);
        blocks.extend(match_blocks(&path.display().to_string(), &production));
    }

    let concerning: Vec<&MatchBlock> = blocks.iter().filter(|b| concerns_generation(&b.body)).collect();

    // Non-vacuous: Task 22's own measurement found exactly two production
    // `match`es on `Generation` in this scope (`Generation::is_v6`,
    // `emit::write_fixed_portion`). If that ever drops to zero, this test
    // must fail loudly rather than pass by finding nothing to check.
    assert!(
        concerning.len() >= 2,
        "expected at least the two known Generation matches \
         (format/generation.rs's is_v6, emit.rs's write_fixed_portion); \
         found {} -- either the scanner regressed or the code's shape \
         changed enough that this test needs updating, not silently passing",
        concerning.len()
    );
    assert!(
        concerning.iter().any(|b| b.file.ends_with("generation.rs")),
        "expected to find Generation::is_v6's match in format/generation.rs"
    );
    assert!(
        concerning.iter().any(|b| b.file.ends_with("emit.rs")),
        "expected to find write_fixed_portion's match in emit.rs"
    );

    let mut offences = Vec::new();
    for block in concerning {
        if has_bare_catch_all_arm(&block.body) {
            offences.push(format!("{}: {}", block.file, block.body.trim()));
        }
    }
    assert!(
        offences.is_empty(),
        "a bare catch-all arm on a match over Generation defeats rustc's \
         own exhaustiveness check -- a seventh generation would compile \
         silently into whichever arm this one is, rather than naming a \
         behaviour not yet written. Offending matches:\n{}",
        offences.join("\n---\n")
    );
}

/// Proves `has_bare_catch_all_arm` (and therefore
/// `no_match_on_generation_has_a_catch_all_arm`) can actually fail: it is
/// run directly against a copy of `Generation::is_v6`'s pre-Task-22 body
/// (`matches!`-free but with an added wildcard, to isolate exactly the
/// property under test) and against the real, fixed body, and asserts they
/// disagree. This was also confirmed the harder way while writing this
/// test: reverting the real `Generation::is_v6` to `matches!(self, Self::V600
/// | Self::V610 | Self::V620)`, or adding a `_ => false` arm to it, was
/// observed turning `no_match_on_generation_has_a_catch_all_arm` red, then
/// reverted.
#[test]
fn a_wildcard_arm_is_caught() {
    let with_wildcard = "\
        Self::V600 | Self::V610 | Self::V620 => true,\n\
        _ => false,\n\
    ";
    assert!(
        has_bare_catch_all_arm(with_wildcard),
        "the detector must catch a bare `_` arm"
    );

    let with_named_catch_all = "\
        Self::V5R3 => false,\n\
        other => true,\n\
    ";
    assert!(
        has_bare_catch_all_arm(with_named_catch_all),
        "the detector must catch a bare named catch-all like `other =>`, \
         not just `_`"
    );

    let exhaustive = "\
        Self::V5R3 | Self::V5R4 | Self::V5R5 => false,\n\
        Self::V600 | Self::V610 | Self::V620 => true,\n\
    ";
    assert!(
        !has_bare_catch_all_arm(exhaustive),
        "the real, fixed body must NOT be flagged -- every arm names a \
         qualified variant path"
    );
}

#[test]
fn the_scanner_does_not_confuse_the_generation_counter_field_with_the_enum() {
    // `read.rs` compares two `u16` shadow-copy *generation counters* with
    // `.cmp()` -- `page0.generation.cmp(&page1.generation)` -- which has
    // nothing to do with the `Generation` enum this test polices (it is a
    // stored byte offset 0x04 value, compared as an ordinary integer). This
    // must not be misclassified as a Generation match.
    let source = "\
        fn resolve_shadow() {\n\
            match page0.generation.cmp(&page1.generation) {\n\
                std::cmp::Ordering::Greater => {}\n\
                std::cmp::Ordering::Less => {}\n\
                std::cmp::Ordering::Equal => {}\n\
            }\n\
        }\n\
    ";
    let blocks = match_blocks("synthetic", source);
    assert_eq!(blocks.len(), 1, "the scanner should find exactly the one match");
    assert!(
        !concerns_generation(&blocks[0].body),
        "an Ordering match over the generation *counter* must not be \
         classified as a match over the Generation *enum* -- it names no \
         Generation::/Self:: variant path"
    );
}
