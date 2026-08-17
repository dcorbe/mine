//! The `btrieve` crate must depend on nothing but `std` at runtime, and
//! exactly one thing in its tests: `btrieve-oracle`, named once.
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
//!
//! # The one named exception
//!
//! Task 12's differential replay (`tests/differential.rs`) needs
//! `btrieve-oracle`'s `Fixture`/`Scenario`/`Request` types to read the
//! committed fixtures it diffs `btrcall` against -- a legitimate, Wine-free,
//! test-only dependency (`Cargo.toml`'s `[dev-dependencies]`). Until this
//! task, every guard below only ever looked at `src/` and only ever checked
//! `[dependencies]`, so a `[dev-dependencies]` addition -- this one included
//! -- was invisible to both: the manifest check split on the literal
//! `"[dependencies]"` and found nothing under a *different* header, and the
//! source scan never walked `tests/` at all. Both guards now see the whole
//! picture, and both stay allowlists: [`EXPECTED_DEV_DEPENDENCIES`] names
//! exactly what is permitted under `[dev-dependencies]`, and
//! [`is_the_one_file_allowed_to_name_btrieve_oracle`] names exactly which
//! file may say so in source. A second dev-dependency, or a second file
//! naming `btrieve_oracle`, fails both guards rather than sliding through
//! an empty split or an unwalked directory.

use std::collections::BTreeSet;
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

/// Additionally allowed in [`is_the_one_file_allowed_to_name_btrieve_oracle`]'s
/// one file alone -- see this module's own doc comment's "The one named
/// exception" section.
const DIFFERENTIAL_REPLAY_ALLOWED_PREFIXES: &[&str] = &["use btrieve_oracle::"];

/// Exactly what `[dev-dependencies]` may name. `btrieve-oracle` and nothing
/// else -- a second entry here must be a deliberate edit to this constant,
/// not a name this guard silently accepted.
fn expected_dev_dependencies() -> BTreeSet<String> {
    ["btrieve-oracle".to_owned()].into_iter().collect()
}

/// The one file allowed to name `btrieve_oracle` in source -- in a `use`
/// line (checked by
/// [`the_source_and_tests_use_only_the_allowed_dependencies`]) or a
/// fully-qualified path (checked by
/// [`no_source_names_a_workspace_crate_by_path`]). Both guards call this
/// rather than each hardcoding its own copy of the exception, so there is
/// exactly one place that says which file it is.
fn is_the_one_file_allowed_to_name_btrieve_oracle(path: &Path) -> bool {
    path.file_name().is_some_and(|f| f == "differential.rs")
}

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

/// Every `.rs` file this module's two source guards are responsible for:
/// this crate's own `src/` (must depend on nothing but `std`) and its
/// `tests/` (may additionally depend on `btrieve-oracle`, and only in
/// [`is_the_one_file_allowed_to_name_btrieve_oracle`]'s one file). Shared so
/// both guards below walk the same set rather than each collecting its own.
///
/// **Excludes this guard's own file.** `independence.rs` itself has to name
/// `mbbs_machine::`, `btrieve_oracle::` and friends as string data -- the
/// `FORBIDDEN`/`DIFFERENTIAL_REPLAY_ALLOWED_PREFIXES` constants above are the
/// whole point of this module -- and scanning `tests/` for the first time
/// (this task) means this file is now inside the walk it used to only run
/// *over*. Flagging its own constants would not be catching a leak; it would
/// be the guard tripping over its own configuration.
fn guarded_files() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = rust_files_under(&root.join("src"));
    files.extend(
        rust_files_under(&root.join("tests"))
            .into_iter()
            .filter(|p| p.file_name().is_some_and(|f| f != "independence.rs")),
    );
    files
}

#[test]
fn the_source_and_tests_use_only_the_allowed_dependencies() {
    let files = guarded_files();
    assert!(!files.is_empty(), "the walker found no sources -- it has gone blind");

    let mut offences = Vec::new();
    for path in files {
        let extra: &[&str] = if is_the_one_file_allowed_to_name_btrieve_oracle(&path) {
            DIFFERENTIAL_REPLAY_ALLOWED_PREFIXES
        } else {
            &[]
        };
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
            let allowed = ALLOWED_PREFIXES
                .iter()
                .chain(extra.iter())
                .any(|p| normalised.starts_with(p));
            if !allowed {
                offences.push(format!("{}:{}: {}", path.display(), n + 1, trimmed));
            }
        }
    }
    assert!(offences.is_empty(), "the seam has leaked:\n{}", offences.join("\n"));
}

/// Splits `manifest` on `header` (a literal section marker like
/// `"[dependencies]"`) and returns the trimmed text up to the next section
/// header, or an empty string if `header` never appears. `"[dev-
/// dependencies]"` never collides with a search for `"[dependencies]"`: the
/// former's `[` is immediately followed by `dev-`, not `dependencies]`, so
/// the two section markers do not overlap as substrings.
fn section(manifest: &str, header: &str) -> String {
    manifest
        .split(header)
        .nth(1)
        .map(|rest| rest.split("\n[").next().unwrap_or("").trim().to_owned())
        .unwrap_or_default()
}

/// The crate name on the left of each `name = ...` line in a dependencies
/// section, ignoring blank lines. Good enough for this manifest, which never
/// nests a table under `[dev-dependencies]`.
fn crate_names(section: &str) -> BTreeSet<String> {
    section
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            line.split('=').next().map(|n| n.trim().to_owned())
        })
        .collect()
}

#[test]
fn the_manifest_declares_no_runtime_dependencies_and_exactly_the_expected_dev_dependency() {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("readable manifest");

    let deps = section(&manifest, "[dependencies]");
    assert!(
        deps.is_empty(),
        "btrieve must depend on nothing but std at runtime; found under [dependencies]:\n{deps}"
    );

    let dev_deps = crate_names(&section(&manifest, "[dev-dependencies]"));
    let expected = expected_dev_dependencies();
    assert_eq!(
        dev_deps, expected,
        "btrieve's [dev-dependencies] must be exactly {expected:?} -- Task 12's differential \
         replay (crates/btrieve/tests/differential.rs) needs btrieve-oracle's fixture types; a \
         new dev-dependency must widen this allowlist deliberately (this constant, plus the \
         source guards' own exceptions), not slip past an empty split unnoticed"
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
///
/// Walks `tests/` as well as `src/` (via [`guarded_files`]) -- a qualified
/// path is exactly as invisible to a caller-code-only scan whether it sits
/// in the library or in a test, and `btrieve_oracle::` is now a legitimate
/// name for exactly one file to write, not merely a leak to catch. Every
/// other file, in `src/` or `tests/`, is still refused it.
#[test]
fn no_source_names_a_workspace_crate_by_path() {
    const FORBIDDEN: &[&str] = &["mbbs_machine::", "mbbs::", "btrieve_oracle::", "libc::"];

    let mut offences = Vec::new();
    for path in guarded_files() {
        let exempt_here = is_the_one_file_allowed_to_name_btrieve_oracle(&path);
        let text = std::fs::read_to_string(&path).expect("a readable source file");
        for (n, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            // Doc comments name these crates on purpose: the seam's own
            // documentation explains what it replaced, and that explanation is
            // worth more than the uniformity of never writing the name.
            if trimmed.starts_with("//") {
                continue;
            }
            let named = FORBIDDEN
                .iter()
                .filter(|c| !(exempt_here && **c == "btrieve_oracle::"))
                .find(|c| line.contains(**c));
            if let Some(named) = named {
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
