//! `FILE_OPENS` (`src/lib.rs`) claims to count every file a Btrieve **read**
//! opens. That claim is only true if `open_for_read`/`read_whole` are the
//! only two places non-test code calls `std::fs::File::open`/`std::fs::read`
//! directly -- a claim `80f93140` made in prose and never checked, and which
//! was false: 13 read-serving sites across `lib.rs`, `pages.rs`, `records.rs`,
//! `variable.rs`, `verify.rs`, `census.rs` and `corpus.rs` opened files of
//! their own, uncounted. This is the mechanical check that keeps it true --
//! modelled on `independence.rs`'s own reasoning: a denylist checked by
//! nothing but a reviewer's memory is the entry nobody writes, and the entry
//! nobody writes is the one that lets a regression back in.
//!
//! # Why `src/` only
//!
//! `tests/` legitimately reads fixtures by hand -- over a hundred call sites,
//! by the same count that found the 13 real gaps -- and `independence.rs`
//! already governs what `tests/` may depend on. This guard's job is
//! `FILE_OPENS`'s own claim about the *library*, so it walks `src/` alone.
//!
//! # Why comments and strings are masked before anything else runs
//!
//! Several doc comments in `src/` -- `FILE_OPENS`'s own, `v6.rs`'s -- name
//! `std::fs::File::open` and `std::fs::read` in prose, explaining exactly
//! the thing this guard exists to enforce. A guard that pattern-matched raw
//! source text would fail on its own documentation. [`mask`] blanks every
//! comment and string/char literal to a same-length run of spaces (newlines
//! kept, so line numbers never shift) before either the brace counter or the
//! pattern search sees the text.
//!
//! # Why `#[cfg(test)]` is found by a brace counter, not a line range
//!
//! A `#[cfg(test)] mod tests { ... }` is not the only shape in this crate --
//! `lib.rs` and `v6.rs` also gate a bare `thread_local! { ... }` and, once,
//! a bare `fn` this way, and none of them are guaranteed to run to end of
//! file. Hardcoding "skip past line N" would silently stop working the next
//! time someone reorders a file. [`Scan`] instead watches for the attribute
//! line, then treats whatever brace-delimited item follows as the region to
//! skip, however deep it nests, however long it runs -- the same mechanism
//! also carves out `open_for_read`/`read_whole`'s own two bodies, which
//! legitimately call the raw functions this guard forbids everywhere else.
//!
//! # The self-check
//!
//! [`Scan`]'s depth must return to zero at end of file. If it does not, the
//! brace/string/comment tokenizer above has lost track of a file's
//! structure -- a raw string delimiter it does not understand, say -- and
//! the guard is no longer trustworthy for that file. That is asserted
//! loudly rather than left to silently report zero offences, because a
//! guard that goes blind and stays green is worse than no guard.

use std::path::{Path, PathBuf};

/// `testing.rs`'s own module doc: "Public rather than `#[cfg(test)]` because
/// two crates need it" -- `mbbs`'s own tests call [`crate::testing::scratch`]
/// and [`crate::testing::make_keys_modifiable`] across the crate boundary,
/// so it cannot be gated the way every other test module in this crate is.
/// Every function in it is fixture setup (a scratch directory, editing a
/// key's attribute byte for a test to write against, reading `FILE_OPENS`
/// back for a test to assert on) -- not a Btrieve read path -- so it is
/// exempted here by name, the same way `independence.rs` names its own one
/// exception rather than widening a pattern to cover it.
fn is_test_support_despite_not_being_gated(path: &Path) -> bool {
    path.file_name().is_some_and(|f| f == "testing.rs")
}

/// Every `.rs` file under this crate's `src/` that `FILE_OPENS`'s doc comment
/// makes a claim about: the library, minus [`is_test_support_despite_not_being_gated`]'s
/// one named exception, minus `src/bin/`.
///
/// `src/bin/*.rs` is out of scope on more than judgement -- it is structurally
/// impossible for it to be in scope. `independence.rs`'s own comment on
/// `ALLOWED_PREFIXES` says it plainly: a `src/bin/*.rs` file is its own
/// binary crate, whose `crate::` root is the *binary*, not this library, so
/// it cannot even name a `pub(crate)` item like [`open_for_read`] --
/// visibility alone rules it out of the choke point. `btrieve-census.rs`'s
/// own `std::fs::read` (line 182, at last count) is also a different kind of
/// read from what `FILE_OPENS` counts: a content digest over a census sweep's
/// candidate files for deduplication, not a file opened to serve one Btrieve
/// operation.
fn guarded_files() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        if dir.file_name().is_some_and(|f| f == "bin") {
            continue;
        }
        for entry in std::fs::read_dir(&dir).expect("a readable directory") {
            let path = entry.expect("a readable dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs")
                && !is_test_support_despite_not_being_gated(&path)
            {
                out.push(path);
            }
        }
    }
    out
}

/// `text` with every `//`/`/* */` comment and every string/char literal's
/// *contents* replaced by spaces -- delimiters included -- and every
/// newline preserved verbatim. Handles block comment nesting (Rust allows
/// it) and raw strings of any hash count (`r"..."`, `r#"..."#`, ...). A
/// lifetime (`'a`) is deliberately left untouched rather than mistaken for
/// an unterminated char literal: nothing downstream cares whether a `'`
/// that never closes is code or not, since it can carry no brace either way.
fn mask(text: &str) -> String {
    #[derive(Clone, Copy, PartialEq)]
    enum Mode {
        Code,
        Line,
        Block(u32),
        Str,
        Raw(usize),
    }

    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(chars.len());
    let mut mode = Mode::Code;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match mode {
            Mode::Code => {
                if c == '/' && chars.get(i + 1) == Some(&'/') {
                    mode = Mode::Line;
                    out.push_str("  ");
                    i += 2;
                    continue;
                }
                if c == '/' && chars.get(i + 1) == Some(&'*') {
                    mode = Mode::Block(1);
                    out.push_str("  ");
                    i += 2;
                    continue;
                }
                if c == '"' {
                    mode = Mode::Str;
                    out.push(' ');
                    i += 1;
                    continue;
                }
                if c == 'r' {
                    let mut j = i + 1;
                    let mut hashes = 0usize;
                    while chars.get(j) == Some(&'#') {
                        hashes += 1;
                        j += 1;
                    }
                    if chars.get(j) == Some(&'"') {
                        mode = Mode::Raw(hashes);
                        for _ in i..=j {
                            out.push(' ');
                        }
                        i = j + 1;
                        continue;
                    }
                }
                // A char literal (`'x'`, `'\n'`, `'\\''`) closes within a
                // few characters; a lifetime (`'a`, `'static`) never closes
                // this way at all. Only the closing forms are consumed here
                // -- an unmatched `'` falls through as plain code, which is
                // exactly right for a lifetime and carries no brace to miss.
                if c == '\'' {
                    if chars.get(i + 1) == Some(&'\\') {
                        let mut j = i + 2;
                        while j < chars.len() && chars[j] != '\'' && chars[j] != '\n' {
                            j += 1;
                        }
                        if chars.get(j) == Some(&'\'') {
                            for _ in i..=j {
                                out.push(' ');
                            }
                            i = j + 1;
                            continue;
                        }
                    } else if chars.get(i + 2) == Some(&'\'') {
                        out.push_str("   ");
                        i += 3;
                        continue;
                    }
                }
                out.push(c);
                i += 1;
            }
            Mode::Line => {
                out.push(if c == '\n' { '\n' } else { ' ' });
                if c == '\n' {
                    mode = Mode::Code;
                }
                i += 1;
            }
            Mode::Block(depth) => {
                if c == '/' && chars.get(i + 1) == Some(&'*') {
                    mode = Mode::Block(depth + 1);
                    out.push_str("  ");
                    i += 2;
                    continue;
                }
                if c == '*' && chars.get(i + 1) == Some(&'/') {
                    mode = if depth == 1 { Mode::Code } else { Mode::Block(depth - 1) };
                    out.push_str("  ");
                    i += 2;
                    continue;
                }
                out.push(if c == '\n' { '\n' } else { ' ' });
                i += 1;
            }
            Mode::Str => {
                // An escape swallows exactly one following character -- unless
                // that character is a literal newline (a string's own
                // line-continuation escape, `\` followed directly by `\n`, as
                // `btrieve-census.rs` uses spanning its "found N candidate
                // files" message). Swallowing the newline there would erase a
                // line from the masked text without erasing it from `text`,
                // and every line number reported from that point on in the
                // file would be off by one. Left for the ordinary branch
                // below to push instead, which always keeps a `\n` a `\n`.
                if c == '\\' && chars.get(i + 1).is_some() && chars.get(i + 1) != Some(&'\n') {
                    out.push_str("  ");
                    i += 2;
                    continue;
                }
                if c == '"' {
                    mode = Mode::Code;
                    out.push(' ');
                    i += 1;
                    continue;
                }
                out.push(if c == '\n' { '\n' } else { ' ' });
                i += 1;
            }
            Mode::Raw(hashes) => {
                if c == '"' {
                    let mut j = i + 1;
                    let mut n = 0;
                    while n < hashes && chars.get(j) == Some(&'#') {
                        n += 1;
                        j += 1;
                    }
                    if n == hashes {
                        mode = Mode::Code;
                        for _ in i..j {
                            out.push(' ');
                        }
                        i = j;
                        continue;
                    }
                }
                out.push(if c == '\n' { '\n' } else { ' ' });
                i += 1;
            }
        }
    }
    out
}

/// The two calls [`FILE_OPENS`][crate's own] exists to have counted every
/// instance of. `std::fs::OpenOptions` (a write open) is deliberately not
/// here -- see `FILE_OPENS`'s own doc comment in `src/lib.rs` for why the
/// counter's scope stops at reads.
const FORBIDDEN: &[&str] = &["std::fs::File::open(", "std::fs::read("];

/// Blanks every `#[cfg(test)]`-gated item's body and both of
/// `open_for_read`/`read_whole`'s own bodies out of `masked`, using a brace
/// counter so nesting depth and length never matter -- see this module's
/// own doc comment, "Why `#[cfg(test)]` is found by a brace counter". Also
/// returns whether the counter came back to zero, the self-check this
/// module's doc comment describes.
fn blank_excluded_regions(masked: &str) -> (String, bool) {
    let mut depth: i64 = 0;
    let mut in_skip: Option<i64> = None;
    let mut pending = false;
    let mut out = String::with_capacity(masked.len());

    for line in masked.split_inclusive('\n') {
        let trimmed = line.trim();
        if in_skip.is_none() {
            if trimmed == "#[cfg(test)]" {
                pending = true;
            } else if trimmed.contains("fn open_for_read(") || trimmed.contains("fn read_whole(") {
                pending = true;
            }
        }
        for c in line.chars() {
            let currently_skip = in_skip.is_some();
            match c {
                '{' => {
                    if in_skip.is_none() && pending {
                        in_skip = Some(depth);
                        pending = false;
                    }
                    depth += 1;
                }
                '}' => {
                    depth -= 1;
                    if in_skip == Some(depth) {
                        in_skip = None;
                    }
                }
                ';' => {
                    // A pending attribute/name with no brace at all (e.g. a
                    // hypothetical `#[cfg(test)] use x::y;`) -- nothing to
                    // skip past, just stop waiting for one.
                    if in_skip.is_none() && pending {
                        pending = false;
                    }
                }
                _ => {}
            }
            out.push(if currently_skip {
                if c == '\n' {
                    '\n'
                } else {
                    ' '
                }
            } else {
                c
            });
        }
    }
    (out, depth == 0 && in_skip.is_none())
}

/// Every `path:line: text` offence in `text` -- non-test code, outside
/// `open_for_read`/`read_whole`'s own bodies, that calls
/// `std::fs::File::open` or `std::fs::read` directly.
///
/// # Panics
///
/// If the brace counter does not return to depth zero by end of file --
/// this module's own doc comment, "The self-check".
fn offences_in(path: &Path, text: &str) -> Vec<String> {
    let masked = mask(text);
    let (filtered, balanced) = blank_excluded_regions(&masked);
    assert!(
        balanced,
        "{}: the guard's own brace counter did not return to top level -- it has lost track \
         of this file's structure (an unhandled string or comment form, most likely) and \
         cannot be trusted to scope cfg(test) correctly here",
        path.display()
    );

    let mut offences = Vec::new();
    for (line_no, (orig, filt)) in text.lines().zip(filtered.lines()).enumerate() {
        for pat in FORBIDDEN {
            if filt.contains(pat) {
                offences.push(format!("{}:{}: {}", path.display(), line_no + 1, orig.trim()));
            }
        }
    }
    offences
}

#[test]
fn every_read_open_in_non_test_source_goes_through_the_choke_point() {
    let files = guarded_files();
    assert!(!files.is_empty(), "the walker found no sources under src/ -- it has gone blind");

    let mut offences = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(&path).expect("a readable source file");
        offences.extend(offences_in(&path, &text));
    }

    assert!(
        offences.is_empty(),
        "non-test code opened a file to read without going through open_for_read/read_whole \
         (src/lib.rs) -- route it through one of them, or FILE_OPENS's doc comment is lying \
         again:\n{}",
        offences.join("\n")
    );
}

/// [`mask`] and [`blank_excluded_regions`] together, proved on synthetic
/// input rather than only ever exercised against whatever `src/` happens to
/// contain today.
#[test]
fn the_scanner_finds_a_real_offence_and_ignores_every_exempt_shape() {
    let sample = r##"
/// See `std::fs::File::open` for why this exists.
pub(crate) fn open_for_read(path: &Path) -> std::io::Result<std::fs::File> {
    let file = std::fs::File::open(path)?;
    Ok(file)
}

fn real_offence(path: &Path) -> std::io::Result<Vec<u8>> {
    let s = "a string mentioning std::fs::read( that must not count";
    std::fs::read(path)
}

#[cfg(test)]
mod tests {
    fn fixture_reader(path: &Path) {
        let _ = std::fs::File::open(path);
    }
}
"##;
    let path = Path::new("synthetic.rs");
    let offences = offences_in(path, sample);
    assert_eq!(
        offences.len(),
        1,
        "expected exactly the real_offence call, got {offences:?}"
    );
    assert!(
        offences[0].contains("std::fs::read(path)"),
        "the one offence should name the real_offence line, got {:?}",
        offences[0]
    );
}
