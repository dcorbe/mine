//! The `btrieve` crate must depend on nothing but `std`.
//!
//! An allowlist, not a list of forbidden words. A denylist cannot fail safe --
//! the entry nobody writes is the one that lets a dependency in -- and one was
//! tried by hand during the DOS border refactor and returned a result cleaner
//! than the truth, because its pattern was case-sensitive.
//!
//! This is the only thing standing between the crate and a slow return to
//! where it came from. The engine spent its whole life inside `mbbs`, so an
//! `mbbs` type is exactly what a future edit will reach for; the seam is
//! prose until something mechanical enforces it.

use std::path::{Path, PathBuf};

// `use btrieve::` is allowed alongside the crate-relative forms: a
// `src/bin/*.rs` file is its own binary crate whose `crate::` root is the
// *binary*, not the library, so the only way it can reach the library at
// all is by the package's own name. That is a self-reference within one
// Cargo package, not an external dependency -- the thing this guard exists
// to catch -- so it belongs on the allowlist rather than being read as a
// leak.
const ALLOWED_PREFIXES: &[&str] = &[
    "use std::",
    "use core::",
    "use crate::",
    "use super::",
    "use self::",
    "use btrieve::",
];

fn rust_files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("a readable directory") {
        let path = entry.expect("a readable dir entry").path();
        if path.is_dir() {
            out.extend(rust_files_under(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out
}

#[test]
fn the_btrieve_crate_depends_on_nothing_but_std() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let files = rust_files_under(&src);
    assert!(!files.is_empty(), "the walker found no sources -- it has gone blind");

    let mut offences = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(&path).expect("a readable source file");
        for (n, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            // Every form, not just a bare `use`. A `pub use mbbs::Thing;`
            // re-export leaks exactly as far as a private one, and the first
            // draft of this guard read only lines beginning `use ` -- which
            // the six `pub use` re-exports at this crate's root walked
            // straight through.
            let Some(rest) = trimmed
                .strip_prefix("pub(crate) use ")
                .or_else(|| trimmed.strip_prefix("pub use "))
                .or_else(|| trimmed.strip_prefix("use "))
            else {
                continue;
            };
            let normalised = format!("use {}", rest.trim_start_matches("::"));
            if !ALLOWED_PREFIXES.iter().any(|p| normalised.starts_with(p)) {
                offences.push(format!("{}:{}: {}", path.display(), n + 1, trimmed));
            }
        }
    }
    assert!(offences.is_empty(), "the seam has leaked:\n{}", offences.join("\n"));
}

#[test]
fn the_manifest_declares_no_dependencies() {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("readable manifest");
    let deps = manifest
        .split("[dependencies]")
        .nth(1)
        .map(|rest| rest.split("\n[").next().unwrap_or("").trim().to_string())
        .unwrap_or_default();
    assert!(
        deps.is_empty(),
        "btrieve must depend on nothing but std; found:\n{deps}"
    );
}

/// The use-line guard reads `use` lines and nothing else, so a dependency
/// reached by a fully-qualified path in the body of a function is invisible to
/// it. That is not hypothetical -- this crate's own `mem.rs` calls
/// `mbbs_machine::ptr::ModulePtr::resolve` nowhere, but the impl that does
/// live in `mbbs` writes exactly that, and moving it back here would compile
/// without ever adding a `use`.
///
/// Guarding the crate name directly is the cheap half of that, and it is a
/// denylist, which the module doc above says cannot fail safe. It is written
/// anyway because it costs nothing and the manifest guard is what actually
/// makes it airtight: a fully-qualified path to a crate that is not a
/// dependency does not compile at all. This test's job is to fail *first*,
/// with a message that says which line, rather than leaving someone reading a
/// resolver error.
#[test]
fn no_source_names_a_workspace_crate_by_path() {
    const FORBIDDEN: &[&str] = &["mbbs_machine::", "mbbs::", "btrieve_oracle::", "libc::"];

    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offences = Vec::new();
    for path in rust_files_under(&src) {
        let text = std::fs::read_to_string(&path).expect("a readable source file");
        for (n, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            // Doc comments name these crates on purpose: the seam's own
            // documentation explains what it replaced, and that explanation is
            // worth more than the uniformity of never writing the name.
            if trimmed.starts_with("//") {
                continue;
            }
            if let Some(named) = FORBIDDEN.iter().find(|c| line.contains(**c)) {
                offences.push(format!("{}:{}: names {named} -- {trimmed}", path.display(), n + 1));
            }
        }
    }
    assert!(
        offences.is_empty(),
        "the seam has leaked through a qualified path:\n{}",
        offences.join("\n")
    );
}
