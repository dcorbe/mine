//! `FarPtr` is `mbbs16`'s pointer representation, and the whole point of the
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
//! As of this test's introduction (2026-08-12), three kinds of file account
//! for the whole list:
//!
//! - **`abi.rs` itself** -- the 16-bit `Abi` implementation, where
//!   `Wg16::Ptr = mbbs16::FarPtr` is declared. This is where the type is
//!   *supposed* to live, not a leak to guard against.
//! - **Facades not yet converted, or never going to be.** Tasks 4-6 moved
//!   most shim bodies and the subsystems behind them onto `A::Ptr`, but each
//!   left either a `_wg16`-suffixed dispatch-table bridge (the pattern
//!   `shims::mod`'s `call` doc comment names) or a Wg16-concrete method
//!   beside a generic core -- `Heap::alloc` beside `Heap::reserve`,
//!   `Users::polrou`, and `Messages`'/`Streams`'/`TextVars`' own Wg16-typed
//!   leaves -- plus routines the design says stay 16-bit forever:
//!   `shims::memory`'s `alctile`/`ptrtile` (segment tiling has no
//!   flat-memory counterpart), `shims::runtime`'s Borland helpers (the
//!   `Cleans::Callee` family, 16-bit-only by the design's Part 2),
//!   `shims::btrieve` and `crates/mbbs/src/btrieve.rs` (frozen for another
//!   session's Btrieve-engine work -- do not touch either file to shrink
//!   this list), and `shims::fsd`'s `fsdego`/`vfyadn`, `shims::user`'s
//!   `getin`, `shims::system`'s
//!   `register_module`/`register_agent`/`rtkick`, each blocked on a
//!   dependency `shims::mod`'s `ROUTINES` table documents beside its own
//!   entry.
//! - **Test code.** Every fixture in this crate builds a real
//!   `mbbs16::Machine` (`crates/mbbs/src/testing.rs`), so a `#[cfg(test)]`
//!   module that pokes a known address or reads back a `Ret::Far` names
//!   `FarPtr` directly even in a file whose production code no longer does.
//!   That is not a gap this test is meant to close -- it targets the shim
//!   layer's SHARED code, not the Wg16-only fixtures that exercise it.
//!
//! Do not add a file to `ALLOWED` to make a new production use pass; convert
//! that file's remaining concrete code, or -- if the mention is only in its
//! test module -- confirm that first before touching `ALLOWED` at all.

use std::fs;
use std::path::{Path, PathBuf};

/// Files under `crates/mbbs/src`, relative to that directory, that may still
/// name `FarPtr`. Sorted. See this file's module comment before editing.
const ALLOWED: &[&str] = &[
    "abi.rs",
    "btrieve.rs",
    // Arrived with the Btrieve locking work merged from `btrieve-finish`, and
    // caught by this test on the merge rather than noticed by hand -- which is
    // what it is for. They are engine files behind the seventeen `btv*` shims,
    // which are the last unconverted block in `ROUTINES`, so they leave this
    // list in the same commit those shims take a `Call<A>`.
    "btrieve/ops.rs",
    "fmt.rs",
    "fsd.rs",
    "globals.rs",
    "heap.rs",
    "lib.rs",
    "shims/btrieve.rs",
    "shims/fsd.rs",
    "shims/memory.rs",
    "shims/mod.rs",
    "shims/msg.rs",
    "shims/runtime.rs",
    "shims/screen.rs",
    "shims/stream.rs",
    "shims/system.rs",
    "shims/text.rs",
    "shims/user.rs",
    "testing.rs",
    "textvar.rs",
    "users.rs",
];

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
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
            names_far_ptr(&code_only(&text))
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
/// Each case below was checked by mutation: the stripper was broken in the
/// matching way (drop the fence branch, drop the block-comment branch, strip
/// strings, treat `//` inside a string as a comment) and the case named here
/// is the one that failed. A case no mutation can break is not a test, and
/// two early drafts of this list had exactly that problem.
#[cfg(test)]
mod scanner {
    use super::{code_only, names_far_ptr};

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
    fn a_longer_identifier_is_not_a_match() {
        // `names_far_ptr`'s own boundary rule, re-checked through the
        // stripper so the two are known to compose.
        assert!(!names_far_ptr(&code_only("fn f(e: FarPtrError) {}\n")));
    }
}
