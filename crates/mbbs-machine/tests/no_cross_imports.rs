//! m16 and m32 lost their crate boundary in Task 1; this is the fence
//! that replaces it. `fault` and `ldt` are the only sanctioned shared
//! modules -- see the design's §1 ("What the merge costs, and the guard
//! for it").
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
