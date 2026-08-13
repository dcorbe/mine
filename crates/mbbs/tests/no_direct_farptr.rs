//! `FarPtr` is `m16`'s pointer representation, and the whole point of the
//! `Abi` trait (`crates/mbbs/src/abi.rs`) is to keep it out of code meant to
//! serve either width. Without a test, the next contributor reintroduces the
//! coupling one shim at a time and nothing objects.
//!
//! Built as a **named allowlist, not a count**, for the reason
//! `argument_order.rs`'s module comment already gives at length: a count
//! cannot tell a removal from an addition, and it goes vacuous by
//! construction as the number falls to zero. Granularity here is per FILE,
//! not per line or per function, because that is the unit a conversion
//! commit actually frees -- converting a file's last Wg16-concrete leaf
//! deletes that file's own entry from `ALLOWED` in the same diff that does
//! the conversion.
//!
//! Measured directly against the source below, not trusted from a prior run.
//!
//! # What is measured
//!
//! **Production code only.** Comment prose is stripped ([`code_only`]) and
//! `#[cfg(test)]` items are stripped ([`strip_test_modules`]); each of those
//! functions documents why at its own definition. Code inside a doctest fence
//! survives both, because it is compiled and run.
//!
//! # The list, as of 2026-08-12
//!
//! It went from 26 files to 8 in one pass. Most of that was not conversion
//! work at all -- it was this test learning to measure what it always said it
//! measured. Eight of the eighteen files that left had *zero* production
//! mentions and were on the list purely for their fixtures; two more were on
//! it for doc comments explaining a conversion that had already happened.
//! The genuine removals were `Streams`'/`Messages`'/`TextVars`'/`Users`' dead
//! `Wg16` facades (deleted -- every caller had already moved to the generic
//! `_mem` core), `Users::new`, and the Btrieve engine going `Btrieve<A>`.
//!
//! Three of those eight are permanent and are marked as such in `ALLOWED`:
//! `abi.rs` (where the type is declared), `shims/memory.rs` (segment tiling,
//! no flat-memory counterpart) and `testing.rs` (the fixture builder). A
//! fourth left in the very next commit: the seventeen `btv*` shims went
//! `fn foo<A: Abi>(...)` once `Host<A>::btrieve`'s own elided parameter (see
//! `lib.rs`'s history) stopped pinning the engine behind them to `Wg16`. So
//! the live conversion backlog is **four files**.
//!
//! # The one that is not like the others
//!
//! `lib.rs` is `impl Host<Wg16>`'s execution driver, and it is not blocked on
//! a facade or a leaf the way the other four are. It is blocked on the `Abi`
//! trait, which abstracts *memory and pointers* and has no notion of
//! *execution* -- there is no `resume`, no `call`. Every other entry here is
//! an afternoon's mechanical work. This one is a design question first.
//!
//! # Rules
//!
//! Do not add a file to `ALLOWED` to make a new production use pass, and do
//! not reword a signature to slip past the scanner -- deleting a `FarPtr`
//! type annotation and letting inference supply it removes the mention
//! without removing an ounce of the coupling. Convert the code, and delete
//! the file's entry in the same diff.

use std::fs;
use std::path::{Path, PathBuf};

/// Files under `crates/mbbs/src`, relative to that directory, whose
/// **production** code may still name `FarPtr`. Grouped by reason rather than
/// sorted -- the test sorts both sides before comparing, so the order here is
/// free to carry meaning. See this file's module comment before editing.
const ALLOWED: &[&str] = &[
    // Where the type is SUPPOSED to live: `Wg16::Ptr = mbbs_machine::m16::FarPtr` is
    // declared here. Not a leak, and this entry never leaves.
    "abi.rs",
    // Irreducibly 16-bit, and staying. `alctile`/`ptrtile` are LDT segment
    // tiling, which has no flat-memory counterpart at all -- the 32-bit
    // equivalents `alcblok`/`ptrblok` are different routines, among the 56
    // still unimplemented. Same for `Heap::alloc_tiled` behind them.
    "shims/memory.rs",
    // The test fixture builder. Every fixture in this crate constructs a real
    // `mbbs_machine::m16::Machine`, so this names `FarPtr` by construction. It is
    // Wg16-only on purpose and is not a conversion target.
    "testing.rs",
    // --- Genuinely still to convert, in rough order of difficulty ---
    //
    // `Heap::alloc` -- a `&mut Machine` facade over the generic
    // `Heap::reserve`. Unlike the four facades deleted alongside this commit,
    // it still has live callers, so it goes when they move.
    "heap.rs",
    // `Globals::new`/`pointer`/`long` (construction and MajorBBS-specific
    // readers) plus `selector`, which is 16-bit in SUBSTANCE rather than by
    // signature: it returns `base.selector`, and a flat pointer has none.
    // `selector` will still be here when the other three are gone.
    "globals.rs",
    // `fsdego`/`vfyadn`, each blocked on a dependency `shims::mod`'s
    // `ROUTINES` table documents beside its own entry.
    "shims/fsd.rs",
    // The big one, and the real remaining boundary: `impl Host<Wg16>`'s
    // execution driver -- `run`, `poll`, `cycle`, `load`, `stop` and the rest
    // of the 26 methods that take a `&mut Machine`. These are NOT blocked on
    // a facade or a leaf; they are blocked on the `Abi` trait itself, which
    // abstracts memory and pointers but has no notion of EXECUTION (no
    // `resume`, no `call`). Nothing here converts until that is designed.
    "lib.rs",
];

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// `{` and `}` counts for one line of code, ignoring any inside a string.
fn braces(line: &str) -> (isize, isize) {
    let (mut open, mut close) = (0, 0);
    let bytes = line.as_bytes();
    let mut i = 0;
    let mut in_str = false;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if in_str => i += 1,
            b'"' => in_str = !in_str,
            b'{' if !in_str => open += 1,
            b'}' if !in_str => close += 1,
            _ => {}
        }
        i += 1;
    }
    (open, close)
}

/// `code` with every `#[cfg(test)]` item removed.
///
/// # Why
///
/// This file's own module comment has always said test code is not what the
/// guard is for -- "it targets the shim layer's SHARED code, not the Wg16-only
/// fixtures that exercise it" -- because every fixture in this crate builds a
/// real `mbbs_machine::m16::Machine` and so names `FarPtr` by construction. But the
/// allowlist is per FILE, so a file whose production code is fully converted
/// stayed on the list anyway if its `#[cfg(test)]` module poked one address.
///
/// That made `ALLOWED` mean "has production coupling, **or** has a 16-bit
/// fixture", and the two were indistinguishable from the outside. Eight
/// files were on the list with zero production mentions between them:
/// `fmt.rs`, `shims/mod.rs`, `shims/msg.rs`, `shims/runtime.rs`,
/// `shims/screen.rs`, `shims/stream.rs`, `shims/text.rs`, `shims/user.rs`.
/// Reading the list, all eight looked like remaining work. None was.
///
/// **This removes no coupling.** It stops counting fixtures, so the list
/// says what it always claimed to. The production count is the number that
/// moves when a conversion lands, and it is unaffected by this function.
///
/// Brace-matched rather than truncated at the first `#[cfg(test)]`: an
/// earlier draft cut the file there, which is right only because the test
/// module conventionally comes last, and would silently drop production code
/// the day one did not.
fn strip_test_modules(code: &str) -> String {
    let mut out = String::new();
    let mut lines = code.lines();

    while let Some(line) = lines.next() {
        if !line.trim_start().starts_with("#[cfg(test)]") {
            out.push_str(line);
            out.push('\n');
            continue;
        }

        // Skip the annotated item: find its opening brace, then run to the
        // matching close. Anything before the first brace (a `mod tests`
        // line, attributes) belongs to the item too.
        let mut depth: isize = 0;
        let mut started = false;
        for l in lines.by_ref() {
            let (open, close) = braces(l);
            depth += open;
            if open > 0 {
                started = true;
            }
            depth -= close;
            if started && depth <= 0 {
                break;
            }
        }
    }

    out
}

/// `text` with comment prose removed, so only code is left to search.
///
/// # Why this exists
///
/// The first version of this test scanned the raw file. That counts a doc
/// comment *about* the conversion -- "`cookie` widened from `FarPtr` to
/// `A::Ptr`" -- exactly the same as a `FarPtr` in a signature, and the two
/// are opposites: the first documents that the coupling is gone, the second
/// is the coupling. Under a raw scan, the clearest possible explanation of a
/// finished conversion is what keeps its file on `ALLOWED` forever, so the
/// list stops meaning "still coupled" and starts meaning "still coupled, or
/// once was and said so". `stream.rs` and `msg.rs` hit this on the commit
/// that deleted their last `FarPtr`-typed function: zero code mentions left,
/// six prose ones.
///
/// The implementation plan's Task 7 anticipated this shape of problem and
/// gave the rule -- "fix the scanner rather than the allowlist when it
/// produces a false positive, which `72d6bfa` already had to do once". This
/// is that fix.
///
/// # What is deliberately still scanned
///
/// Code inside a doc-comment fence (```` ``` ````) is kept, because a
/// doctest is compiled and run -- it is code that happens to live in a
/// comment, and a `FarPtr` there is a real use. 86 fences exist in this
/// crate; none names `FarPtr` today, which is a fact worth keeping true
/// rather than a reason to stop looking.
///
/// String literals are kept too. A `FarPtr` inside one is not coupling, but
/// stripping strings would mean parsing them, and the conservative direction
/// for a guard is to over-report: a false positive here is a visible test
/// failure, a false negative is coupling nobody notices.
fn code_only(text: &str) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(text.len());
    let mut in_block = false;
    let mut in_fence = false;

    for line in text.lines() {
        let trimmed = line.trim_start();
        let doc = trimmed
            .strip_prefix("///")
            .or_else(|| trimmed.strip_prefix("//!"));

        if let Some(body) = doc {
            if body.trim_start().starts_with("```") {
                // The fence marker itself is not code; the toggle is the point.
                in_fence = !in_fence;
                out.push(b'\n');
                continue;
            }
            if in_fence {
                out.extend_from_slice(body.as_bytes());
                out.push(b'\n');
                continue;
            }
            // Ordinary doc prose.
            out.push(b'\n');
            continue;
        }

        let bytes = line.as_bytes();
        let mut i = 0;
        let mut in_str = false;
        while i < bytes.len() {
            if in_block {
                if bytes[i] == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                    in_block = false;
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            if in_str {
                match bytes[i] {
                    b'\\' => i += 2,
                    b'"' => {
                        in_str = false;
                        out.push(b'"');
                        i += 1;
                    }
                    b => {
                        out.push(b);
                        i += 1;
                    }
                }
                continue;
            }
            if bytes[i] == b'"' {
                in_str = true;
                out.push(b'"');
                i += 1;
            } else if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                break;
            } else if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
                in_block = true;
                i += 2;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        out.push(b'\n');
    }

    String::from_utf8_lossy(&out).into_owned()
}

/// Whether `text` names the bare identifier `FarPtr` -- not as a substring of
/// a longer identifier such as `FarPtrError` or a hypothetical
/// `ModuleFarPtr`. A plain substring search would count `FarPtrError`, which
/// names a different (and legitimately ABI-agnostic-adjacent) type, and would
/// silently inflate every file that only ever touches errors.
fn names_far_ptr(text: &str) -> bool {
    let bytes = text.as_bytes();
    let needle = b"FarPtr";
    let mut start = 0;
    while let Some(rel) = bytes[start..].windows(needle.len()).position(|w| w == needle) {
        let at = start + rel;
        let before_ok = at == 0 || !is_ident_byte(bytes[at - 1]);
        let after = at + needle.len();
        let after_ok = after >= bytes.len() || !is_ident_byte(bytes[after]);
        if before_ok && after_ok {
            return true;
        }
        start = at + 1;
    }
    false
}

/// Every `.rs` file under `dir`, recursively.
fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display())) {
        let path = entry.expect("readable dir entry").path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn far_ptr_is_named_only_where_the_allowlist_says() {
    let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
    let mut files = Vec::new();
    rs_files(root, &mut files);

    let mut found: Vec<String> = files
        .into_iter()
        .filter(|p| {
            let text = fs::read_to_string(p)
                .unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
            names_far_ptr(&strip_test_modules(&code_only(&text)))
        })
        .map(|p| {
            p.strip_prefix(root)
                .expect("walked under root")
                .to_str()
                .expect("utf8 path")
                .replace(std::path::MAIN_SEPARATOR, "/")
        })
        .collect();
    found.sort_unstable();

    let mut allowed: Vec<&str> = ALLOWED.to_vec();
    allowed.sort_unstable();

    assert_eq!(
        found, allowed,
        "FarPtr's footprint in crates/mbbs/src changed -- see this file's \
         module comment before editing ALLOWED. A path present in the left \
         side but not the right is a NEW mention outside the shim \
         conversion's declared boundary; one present on the right but not \
         the left means a conversion already freed that file and ALLOWED \
         should shrink to match, in the same commit that freed it."
    );
}

/// [`code_only`] is now the thing standing between a real `FarPtr` in a
/// signature and a green test, so it gets its own tests rather than being
/// trusted because the suite happened to stay green after it landed.
///
/// Checked by mutation, not by observing the suite stay green. Five defects
/// were introduced one at a time and every one was caught:
///
/// | mutation | caught by |
/// |---|---|
/// | fence branch disabled, so doctest code reads as prose | `code_inside_a_doctest_fence_is_still_code` |
/// | block comments never entered | `prose_in_a_block_comment_is_not_code`, `a_block_comment_spanning_lines_stays_stripped` |
/// | test module truncated at the first `#[cfg(test)]` rather than brace-matched | `production_code_after_a_test_module_still_counts` |
/// | `braces` ignores string literals | `a_brace_inside_a_string_does_not_end_the_test_module_early` |
/// | `code_only` never enters a string literal | `a_double_slash_inside_a_string_does_not_start_a_comment` |
///
/// One of those five appeared to survive on the first pass. The mutation was
/// at fault, not the test: it broke only the `{` arm of `braces` while the
/// fixture's string contains `}`, so nothing about the file's behaviour
/// actually changed. A survivor is a claim about a test, and it has to be
/// read as sceptically as the test itself -- the first question is whether
/// the mutation did anything.
#[cfg(test)]
mod scanner {
    use super::{code_only, names_far_ptr, strip_test_modules};

    #[test]
    fn prose_in_a_doc_comment_is_not_code() {
        let src = "/// `cookie` widened from `FarPtr` to `A::Ptr`.\npub fn f() {}\n";
        assert!(!names_far_ptr(&code_only(src)));
    }

    #[test]
    fn prose_in_a_line_comment_is_not_code() {
        assert!(!names_far_ptr(&code_only("let x = 1; // was a FarPtr once\n")));
    }

    #[test]
    fn prose_in_a_block_comment_is_not_code() {
        assert!(!names_far_ptr(&code_only("/* FarPtr lived here */\nlet x = 1;\n")));
    }

    #[test]
    fn a_block_comment_spanning_lines_stays_stripped() {
        // The `in_block` flag has to survive the line boundary, or the second
        // line is scanned as code and the whole file reports a false positive.
        let src = "/*\n * FarPtr\n */\nlet x = 1;\n";
        assert!(!names_far_ptr(&code_only(src)));
    }

    #[test]
    fn a_signature_is_code() {
        assert!(names_far_ptr(&code_only("pub fn f(at: FarPtr) -> u16 { 0 }\n")));
    }

    #[test]
    fn code_after_a_comment_on_the_same_line_survives() {
        // Stripping from the wrong end -- or stripping the whole line once a
        // `//` appears anywhere -- would lose this.
        let src = "let a = 1; // note\nlet b: FarPtr = q;\n";
        assert!(names_far_ptr(&code_only(src)));
    }

    #[test]
    fn code_inside_a_doctest_fence_is_still_code() {
        // The one case that distinguishes this stripper from "delete every
        // comment": a doctest is compiled and run.
        let src = "/// ```\n/// let at: FarPtr = q;\n/// ```\npub fn f() {}\n";
        assert!(names_far_ptr(&code_only(src)));
    }

    #[test]
    fn prose_after_a_closed_fence_is_prose_again() {
        // If the fence toggle never flips back, everything below the first
        // doctest in a file is scanned as code and prose starts counting.
        let src = "/// ```\n/// let x = 1;\n/// ```\n/// and `FarPtr` is gone now\npub fn f() {}\n";
        assert!(!names_far_ptr(&code_only(src)));
    }

    #[test]
    fn a_double_slash_inside_a_string_does_not_start_a_comment() {
        let src = "let s = \"http://x\"; let at: FarPtr = q;\n";
        assert!(names_far_ptr(&code_only(src)));
    }

    #[test]
    fn an_escaped_quote_does_not_end_a_string_early() {
        // Getting this wrong flips the in-string state for the rest of the
        // line, which silently swallows real code after it.
        let src = "let s = \"he said \\\"hi\\\"\"; let at: FarPtr = q;\n";
        assert!(names_far_ptr(&code_only(src)));
    }

    #[test]
    fn a_test_module_is_not_production_code() {
        let src = "pub fn f() {}\n#[cfg(test)]\nmod tests {\n    let at: FarPtr = q;\n}\n";
        assert!(!names_far_ptr(&strip_test_modules(&code_only(src))));
    }

    #[test]
    fn production_code_after_a_test_module_still_counts() {
        // The reason this is brace-matched and not truncated at the first
        // `#[cfg(test)]`. Truncation passes every other case here and loses
        // exactly this one.
        let src =
            "#[cfg(test)]\nmod tests {\n    let x = 1;\n}\npub fn g(at: FarPtr) -> u16 { 0 }\n";
        assert!(names_far_ptr(&strip_test_modules(&code_only(src))));
    }

    #[test]
    fn a_nested_brace_does_not_end_the_test_module_early() {
        let src = "#[cfg(test)]\nmod tests {\n    fn a() { let at: FarPtr = q; }\n    fn b() {}\n}\n";
        assert!(!names_far_ptr(&strip_test_modules(&code_only(src))));
    }

    #[test]
    fn a_brace_inside_a_string_does_not_end_the_test_module_early() {
        let src = "#[cfg(test)]\nmod tests {\n    let s = \"}\";\n    let at: FarPtr = q;\n}\n";
        assert!(!names_far_ptr(&strip_test_modules(&code_only(src))));
    }

    #[test]
    fn a_longer_identifier_is_not_a_match() {
        // `names_far_ptr`'s own boundary rule, re-checked through the
        // stripper so the two are known to compose.
        assert!(!names_far_ptr(&code_only("fn f(e: FarPtrError) {}\n")));
    }
}
