//! The `dos` crate must not learn about either edge.
//!
//! Prose in a doc comment does not prevent this: the ABI border shipped the
//! same guard as a test for the same reason, after a crate boundary was the
//! only thing that had been keeping two machines apart.
//!
//! Accepted blind spots, recorded rather than closed: this is a line-based
//! text scan, not a parse. `extern crate other_thing;` and a bare
//! fully-qualified reference with no `use` at all (`dos_runtime::kvm::VmGuest::new()`)
//! are invisible to it, and a `use` statement split across multiple lines
//! would evade the prefix match on its first line. All three are inert under
//! `dos`'s current manifest (see `the_dos_crate_declares_no_dependency_but_libc`
//! below) -- there is nothing past `std`/`core`/`libc`/`crate`/`super`/`self`
//! to name yet -- but they are gaps in this guard's coverage, not cases it
//! has been shown to handle.

use std::path::{Path, PathBuf};

/// What a `use` in this crate is allowed to name, after a leading `::` (the
/// 2018+ "absolute path" spelling) has been stripped.
///
/// An allowlist, not a list of forbidden words, for two reasons. The house
/// rule is that claims are positive -- "this is one of the things we permit",
/// never "this is not one of the things we happened to think of". And a
/// denylist was tried by hand during Task 4 and got the wrong answer: the grep
/// was case-sensitive and lowercase-only, so it missed four prose `KVM`
/// mentions and reported a clean result that was cleaner than the truth. A
/// denylist cannot fail safe, because the entry you did not write is the one
/// that lets a dependency in.
///
/// These entries omit the `use ` keyword itself (matched separately, see
/// `offences_among`) and are matched against the path with any leading `::`
/// already stripped -- `use ::libc::c_void;` and `use libc::c_void;` name the
/// same dependency and must be judged identically. `crates/dos-runtime/src/lib.rs`
/// already writes re-exports the `::`-prefixed way (`pub use ::dos::kernel as
/// dos;`, forced by a module-name shadow), so this is not a hypothetical
/// style one hop from this crate.
const ALLOWED_PREFIXES: &[&str] = &["std::", "core::", "libc::", "crate::", "super::", "self::"];

/// Collect every `.rs` file under `dir`, recursing into subdirectories.
///
/// There are no subdirectories under `src/` today, but a walker that only
/// reads the top level is a guard that goes blind, silently, the first time
/// someone adds one (e.g. splitting a module into `foo/mod.rs` plus
/// siblings). Recursing costs nothing while the tree is flat and keeps the
/// guard honest once it isn't. `the_walker_recurses_into_subdirectories`
/// below proves this against a fixture rather than trusting inspection.
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

/// Scan `files` for `use` lines whose named path is not on `ALLOWED_PREFIXES`.
///
/// `pub use` re-exports are not scanned here: a line starting with `pub ` does
/// not start with `use `, so it never matches the first check below and is
/// silently out of scope for this function. That is deliberate, not an
/// oversight -- see `the_dos_crate_declares_no_dependency_but_libc`, which
/// pins the invariant that makes it safe: `dos`'s manifest permits nothing but
/// `libc`, so nothing reachable by a `pub use` is outside this same allowlist
/// anyway, and Cargo itself refuses to compile a `use` (plain or `pub`) of any
/// crate that isn't a declared dependency. If a second dependency is ever
/// added, that assertion fails first and this comment stops being true.
fn offences_among(files: &[PathBuf]) -> Vec<String> {
    let mut offences = Vec::new();

    for path in files {
        let text = std::fs::read_to_string(path).expect("a readable source file");
        for (n, line) in text.lines().enumerate() {
            // Only `use` statements. Substrate names are allowed in prose --
            // these files discuss both edges in their doc comments on purpose,
            // and `kernel.rs`'s `AH=25h` arm explains what a protected-mode
            // edge would have to do differently.
            let trimmed = line.trim_start();
            let Some(named) = trimmed.strip_prefix("use ") else {
                continue;
            };
            let named = named.trim_start();
            let named = named.strip_prefix("::").unwrap_or(named);
            if !ALLOWED_PREFIXES.iter().any(|p| named.starts_with(p)) {
                offences.push(format!("{}:{}: {}", path.display(), n + 1, trimmed));
            }
        }
    }

    offences
}

#[test]
fn the_dos_crate_names_no_execution_substrate() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files_under(&src, &mut files);
    assert!(!files.is_empty(), "the walker found no source files under {}", src.display());

    let offences = offences_among(&files);
    assert!(
        offences.is_empty(),
        "the dos crate must depend on nothing but std and libc; these `use` \
         statements name something else:\n{}",
        offences.join("\n")
    );
}

/// Proves recursion actually happens, rather than trusting that `src/`
/// happens to have no subdirectories today. A fixture tree under
/// `tests/fixtures/`, outside `src/`, holds a nested file with a disallowed
/// `use`; if the walker regresses to a flat, top-level-only scan, this test
/// fails while `the_dos_crate_names_no_execution_substrate` stays green
/// (`src/` has no subdirectories to miss) -- which is exactly the silent
/// blind spot recursion exists to close.
///
/// The fixture directory is never compiled: Cargo's test autodiscovery only
/// turns top-level files directly under `tests/` into test binaries, so
/// `tests/fixtures/nested_violation/sub/deep.rs` is inert source text, read
/// here the same way `src/*.rs` is read above, never fed to rustc as a
/// module.
#[test]
fn the_walker_recurses_into_subdirectories() {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/nested_violation");
    let mut files = Vec::new();
    rust_files_under(&fixture, &mut files);
    assert!(
        files.iter().any(|p| p.components().any(|c| c.as_os_str() == "sub")),
        "the walker did not descend into {}/sub -- recursion is broken",
        fixture.display()
    );

    let offences = offences_among(&files);
    assert!(
        !offences.is_empty(),
        "the walker found files under {}/sub but did not report the disallowed \
         `use` inside sub/deep.rs -- recursion into subdirectories is broken",
        fixture.display()
    );
}

/// Pins the invariant `offences_among`'s `pub use` skip depends on: `dos`
/// depends on nothing but `libc` (and the implicit `std`). Without this, "a
/// `pub use` re-export cannot smuggle in a disallowed crate because Cargo
/// enforces the same allowlist" is a claim this guard assumes rather than
/// checks -- and the day it stops being true is exactly the day the `pub use`
/// blind spot starts to matter.
#[test]
fn the_dos_crate_declares_no_dependency_but_libc() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let text = std::fs::read_to_string(&manifest).expect("Cargo.toml is readable");

    let mut in_dependencies = false;
    let mut names = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("[dependencies.") {
            if let Some(name) = rest.strip_suffix(']') {
                names.push(name.to_string());
            }
            in_dependencies = false;
            continue;
        }
        if trimmed.starts_with('[') {
            in_dependencies = trimmed == "[dependencies]";
            continue;
        }
        if in_dependencies && !trimmed.is_empty() && !trimmed.starts_with('#') {
            if let Some(name) = trimmed.split(['=', ' ']).next() {
                if !name.is_empty() {
                    names.push(name.to_string());
                }
            }
        }
    }

    assert_eq!(
        names,
        vec!["libc".to_string()],
        "the independence guard's handling of `pub use` (see `offences_among`) \
         assumes `dos` depends on nothing but libc; {} now lists {:?} -- widen \
         that handling deliberately before this dependency lands for real",
        manifest.display(),
        names
    );
}
