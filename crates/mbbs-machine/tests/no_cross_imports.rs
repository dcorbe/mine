//! m16 and m32 lost their crate boundary in Task 1; this is the fence
//! that replaces it. `fault`, `ldt` and `module` are the only sanctioned
//! shared modules -- see the design's §1 ("What the merge costs, and the
//! guard for it") for `fault`/`ldt`, and Task 8 for `module` (the
//! format-neutral `Symbol`/`ImportSite` vocabulary, which joined them for
//! the identical reason: it sits beside `m16/` and `m32/`, not inside
//! either).
//!
//! # Recursion
//!
//! `m16/` and `m32/` are flat directories today (no subdirectories).
//! Walking the tree recursively is one way to stay correct if that
//! changes; this test takes the other option the task allows: it asserts
//! flatness first and panics loudly if either directory ever grows a
//! subdirectory. A guard that silently stopped scanning a new nested
//! module the day someone added `src/m16/sub/foo.rs` would be worse than
//! no guard at all, so the choice here is to force a human decision (go
//! recursive, or decide the new subdirectory doesn't need the fence)
//! rather than let coverage quietly shrink.
//!
//! # Spellings
//!
//! Covered: `crate::m32` / `crate::m16` (the plan's original needle) AND
//! `super::super::m32` / `super::super::m16`, which reach the same module
//! from a file one level inside `m16/`/`m32/` -- and would today, since
//! both directories are flat and every file in them sits exactly one
//! level below `src/`.
//!
//! Deliberately NOT covered: a braced multi-import such as
//! `use crate::{m16, m32};`. The bare substring needle `crate::m32` does
//! not match text that reads `crate::{m16, m32}`, so that spelling would
//! slip past a naive `contains` check. It is not covered here because (a)
//! no code anywhere in this crate uses a braced `crate::{...}` import
//! today (checked: zero hits), so covering it buys nothing yet, and (b)
//! a codebase-wide style of always writing full single-path `use`
//! statements makes a sudden braced multi-import exactly the kind of
//! change a human reviewer would notice and question on its own -- unlike
//! the bare `crate::m32`/`super::super::m32` spellings, which read as
//! completely ordinary code and are the ones that need a mechanical
//! fence instead of a human's attention. If that style changes, this
//! comment is the marker to come back and widen the needle.
//!
//! Also deliberately NOT covered: `crate :: m32` with stray whitespace
//! around the `::`. Nothing in this codebase is hand-formatted that way
//! (Rust tooling never emits it), so it is not a spelling anyone is
//! likely to type by accident, and covering it would mean normalizing
//! whitespace before every needle check for a case with no real-world
//! instance.
//!
//! One more known false-negative, in a different class from the spelling
//! ones above: the comment stripper cuts at the first `//` on the line
//! regardless of whether it sits inside a string literal, so
//! `let u = "http://x"; use crate::m32::Y;` would have its real `use`
//! silently dropped from the scanned text. No such line exists here (every
//! `://` in `m16`/`m32` is a URL in a doc comment, already invisible
//! because the line *starts* with `//`), and one statement per line is the
//! house style, so this is recorded rather than fixed. Block comments are
//! not stripped either; that direction can only produce false *positives*
//! (commented-out code tripping the guard), which fail loudly and safely.
//!
//! # The laundering hole, and why the shared modules are checked too
//!
//! The needles above only ever scan files *inside* `m16/` and `m32/`. That
//! is not sufficient, and the gap is not theoretical -- it was built and
//! demonstrated against the first version of this test:
//!
//! ```ignore
//! // src/ldt.rs
//! pub(crate) use crate::m32::Poison as LaunderedPoison;
//! // src/m16/mod.rs
//! pub(crate) fn probe(p: crate::ldt::LaunderedPoison) -> String { .. }
//! ```
//!
//! That compiles, gives `m16` a real dependency on an `m32` type, and the
//! directory scan reports green -- because `m16` never writes the string
//! `crate::m32` anywhere. `fault` and `ldt` are the two modules the design
//! originally sanctioned as shared (§1), which is exactly what makes a
//! re-export through them look legitimate to a reader *and* invisible to a
//! fence that only watches the machines. `module.rs` (Task 8, the
//! format-neutral `Symbol`/`ImportSite` vocabulary) joined them as a third
//! door: it sits beside `m16/` and `m32/` for the same reason `fault.rs`
//! and `ldt.rs` do, so it gets the same fence, not a pass.
//!
//! They are the only three doors between the machines, so the invariant
//! that closes the path is the strongest and simplest one available: **a
//! bridge that never names either side cannot carry anything across it.**
//! None of `fault.rs`, `ldt.rs`, or `module.rs` may mention `m16` or `m32`
//! in code at all -- not via `crate::`, not via `super::`, not braced, not
//! renamed. Today all three mention them only in prose (doc comments), so
//! the invariant holds as written.
//!
//! The needle there is the bare substring, not a path spelling, and that
//! is deliberate: it costs a loud, easily-diagnosed failure if someone
//! ever names an identifier containing `m16`/`m32` in one of these files,
//! and it buys immunity to every spelling -- including the braced and
//! whitespace forms the directory scan gives up on. Same trade as the
//! flatness assertion above: force a human decision rather than let
//! coverage quietly shrink.

use std::fs;
use std::path::Path;

/// Lines (with comments stripped) that mention `needle`, as
/// `path:line: text`. Panics if `dir` contains a subdirectory -- see the
/// module doc comment's "Recursion" section.
fn offending(dir: &Path, needles: &[&str]) -> Vec<String> {
    let mut hits = Vec::new();
    for entry in fs::read_dir(dir).expect("module dir exists") {
        let entry = entry.expect("dirent");
        let path = entry.path();
        let file_type = entry.file_type().expect("dirent file_type");
        assert!(
            !file_type.is_dir(),
            "{} grew a subdirectory ({}); this guard only scans the top \
             level of m16/m32 -- make it recursive (or confirm the new \
             subdirectory needs no fence) before adding nested modules",
            dir.display(),
            path.display()
        );
        if path.extension().map_or(false, |e| e == "rs") {
            let text = fs::read_to_string(&path).expect("source is UTF-8");
            for (i, line) in text.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                if needles.iter().any(|n| code.contains(n)) {
                    hits.push(format!("{}:{}: {}", path.display(), i + 1, line.trim()));
                }
            }
        }
    }
    hits
}

/// The same scan as [`offending`], over an explicit list of files rather
/// than a directory. Used for the shared modules, which sit beside `m16/`
/// and `m32/` rather than inside them -- pointing [`offending`] at `src/`
/// itself would trip its own flatness assertion on those two directories.
fn offending_in_files(files: &[std::path::PathBuf], needles: &[&str]) -> Vec<String> {
    let mut hits = Vec::new();
    for path in files {
        let text = fs::read_to_string(path).expect("source is UTF-8");
        for (i, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if needles.iter().any(|n| code.contains(n)) {
                hits.push(format!("{}:{}: {}", path.display(), i + 1, line.trim()));
            }
        }
    }
    hits
}

#[test]
fn the_two_machines_do_not_import_each_other() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    let m16_uses_m32 = offending(&root.join("m16"), &["crate::m32", "super::super::m32"]);
    let m32_uses_m16 = offending(&root.join("m32"), &["crate::m16", "super::super::m16"]);

    assert!(
        m16_uses_m32.is_empty(),
        "m16 reaches into m32:\n{}",
        m16_uses_m32.join("\n")
    );
    assert!(
        m32_uses_m16.is_empty(),
        "m32 reaches into m16:\n{}",
        m32_uses_m16.join("\n")
    );
}

/// The other half of the fence. See the module comment's "laundering hole"
/// section: watching only the machines leaves `fault`/`ldt`/`module` free to
/// re-export one machine's types for the other to pick up, which compiles,
/// reads as legitimate, and was demonstrated to pass the scan above.
#[test]
fn the_shared_modules_name_neither_machine() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let shared = [
        root.join("fault.rs"),
        root.join("ldt.rs"),
        root.join("module.rs"),
        root.join("library.rs"),
    ];

    let leaks = offending_in_files(&shared, &["m16", "m32"]);

    assert!(
        leaks.is_empty(),
        "a shared module names a machine in code, which is the laundering \
         path the module comment describes -- `fault`, `ldt` and `module` are \
         the only doors between m16 and m32, so they must not name either \
         side:\n{}",
        leaks.join("\n")
    );
}
