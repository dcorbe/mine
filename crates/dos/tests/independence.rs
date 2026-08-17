//! The `dos` crate must not learn about either edge.
//!
//! Prose in a doc comment does not prevent this: the ABI border shipped the
//! same guard as a test for the same reason, after a crate boundary was the
//! only thing that had been keeping two machines apart.

use std::path::{Path, PathBuf};

/// What a `use` in this crate is allowed to name.
///
/// An allowlist, not a list of forbidden words, for two reasons. The house
/// rule is that claims are positive -- "this is one of the things we permit",
/// never "this is not one of the things we happened to think of". And a
/// denylist was tried by hand during Task 4 and got the wrong answer: the grep
/// was case-sensitive and lowercase-only, so it missed four prose `KVM`
/// mentions and reported a clean result that was cleaner than the truth. A
/// denylist cannot fail safe, because the entry you did not write is the one
/// that lets a dependency in.
const ALLOWED_PREFIXES: &[&str] =
    &["use std::", "use core::", "use libc::", "use crate::", "use super::", "use self::"];

/// Collect every `.rs` file under `dir`, recursing into subdirectories.
///
/// There are no subdirectories under `src/` today, but a walker that only
/// reads the top level is a guard that goes blind, silently, the first time
/// someone adds one (e.g. splitting a module into `foo/mod.rs` plus
/// siblings). Recursing costs nothing while the tree is flat and keeps the
/// guard honest once it isn't.
fn rust_files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("directory is readable") {
        let path = entry.expect("a readable dir entry").path();
        if path.is_dir() {
            rust_files_under(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn the_dos_crate_names_no_execution_substrate() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files_under(&src, &mut files);
    assert!(!files.is_empty(), "the walker found no source files under {}", src.display());

    let mut offences = Vec::new();

    for path in &files {
        let text = std::fs::read_to_string(path).expect("a readable source file");
        for (n, line) in text.lines().enumerate() {
            // Only `use` statements. Substrate names are allowed in prose --
            // these files discuss both edges in their doc comments on purpose,
            // and `kernel.rs`'s `AH=25h` arm explains what a protected-mode
            // edge would have to do differently.
            let trimmed = line.trim_start();
            if !trimmed.starts_with("use ") {
                continue;
            }
            if !ALLOWED_PREFIXES.iter().any(|p| trimmed.starts_with(p)) {
                offences.push(format!("{}:{}: {}", path.display(), n + 1, trimmed));
            }
        }
    }

    assert!(
        offences.is_empty(),
        "the dos crate must depend on nothing but std and libc; these `use` \
         statements name something else:\n{}",
        offences.join("\n")
    );
}
