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
//! picture, and both stay allowlists: [`expected_dev_dependencies`] names
//! exactly what is permitted under `[dev-dependencies]`, and
//! [`is_the_one_file_allowed_to_name_btrieve_oracle`] names exactly which
//! file may say so in source. A second dev-dependency, or a second file
//! naming `btrieve_oracle`, fails both guards rather than sliding through
//! an empty split or an unwalked directory.
//!
//! # The empty split, closed
//!
//! That literal split stayed a hole even after the exception above was added,
//! and it was recorded as a follow-up rather than fixed as a rider
//! (`docs/2026-08-17-btrcall-facade-landed.md`, follow-up 1). It is closed
//! here. Searching a manifest for the *substring* `"[dependencies]"` finds
//! nothing in four ordinary Cargo spellings -- `[dependencies.libc]`,
//! `[build-dependencies]`, `[target.'cfg(unix)'.dependencies]` and
//! `[target.'cfg(unix)'.dependencies.libc]` -- and "no section found" and "the
//! section is empty" were the same answer, so each of those forms declared a
//! dependency the guard reported as an absence. [`declared_dependencies`]
//! reads the section *header's path* instead, so how the table is spelled
//! stops mattering. Each of those four forms was written into this crate's
//! real `Cargo.toml` in turn, and each now fails the guard -- a check that has
//! been watched failing, not merely watched passing.

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

/// Which dependency table a section header names. Read off the header's
/// *last* path segment rather than matched against one literal spelling --
/// the previous guard searched the manifest for the substring
/// `"[dependencies]"`, which four ordinary Cargo spellings do not contain:
/// `[dependencies.libc]`, `[target.'cfg(unix)'.dependencies]`,
/// `[target.'cfg(unix)'.dependencies.libc]` and `[build-dependencies]`. Each
/// read as an absent section, i.e. as an empty one, i.e. as "no dependency
/// here" -- the exact failure this guard exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DependencyKind {
    /// `[dependencies]` -- must be empty; this crate is `std`-only.
    Runtime,
    /// `[dev-dependencies]` -- exactly [`expected_dev_dependencies`].
    Dev,
    /// `[build-dependencies]` -- must be empty. This crate has no build
    /// script, so a build dependency is either dead weight or a dependency
    /// smuggled in through the one table nobody thinks to look at.
    Build,
}

impl DependencyKind {
    fn from_segment(segment: &str) -> Option<Self> {
        match segment {
            "dependencies" => Some(Self::Runtime),
            "dev-dependencies" => Some(Self::Dev),
            "build-dependencies" => Some(Self::Build),
            _ => None,
        }
    }
}

/// Splits a section header's path on `.`, honouring the quoting Cargo requires
/// for `[target.'cfg(any(unix, windows))'.dependencies]`. An unquoted split
/// would cut a `cfg(...)` predicate wherever it contains a dot -- and a
/// predicate that mentions a version, a path or a feature name routinely does.
/// The surrounding quotes are stripped so a segment compares equal to a plain
/// name.
fn header_segments(header: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for c in header.chars() {
        match (quote, c) {
            (Some(q), _) if c == q => quote = None,
            (Some(_), _) => current.push(c),
            (None, '\'' | '"') => quote = Some(c),
            (None, '.') => segments.push(std::mem::take(&mut current)),
            (None, _) => current.push(c),
        }
    }
    segments.push(current);
    segments.into_iter().map(|s| s.trim().to_owned()).collect()
}

/// What a section header means for the dependency census.
#[derive(Debug, PartialEq, Eq)]
enum Section {
    /// A dependency table proper (`[dependencies]`,
    /// `[target.'cfg(unix)'.dev-dependencies]`): every key in it names a
    /// dependency.
    KeysAreDependencies(DependencyKind),
    /// The sub-table form (`[dependencies.libc]`): the *header* names the one
    /// dependency and the keys inside it are that dependency's own fields --
    /// `version`, `path`, `features` -- which are not dependency names and
    /// must not be collected as if they were.
    Names(DependencyKind, String),
    /// `[package]`, `[lints]`, `[[bin]]`, anything else.
    Irrelevant,
}

fn classify(header: &str) -> Section {
    let segments = header_segments(header);
    let Some(at) = segments.iter().position(|s| DependencyKind::from_segment(s).is_some()) else {
        return Section::Irrelevant;
    };
    let kind = DependencyKind::from_segment(&segments[at]).expect("position found it");
    match segments.get(at + 1) {
        Some(name) => Section::Names(kind, name.clone()),
        None => Section::KeysAreDependencies(kind),
    }
}

/// Every dependency the manifest declares, paired with the table that declared
/// it. Comment lines and blank lines are skipped; a dotted key (`libc.workspace
/// = true`) contributes its first segment, and a quoted key its unquoted name.
///
/// Deliberately not a TOML parser. Where it cannot tell -- a value array split
/// across lines inside a `[dependencies]` table, say -- it reports the
/// continuation line as a dependency name rather than skipping it, so the
/// guard fails loudly and someone reads the manifest. An allowlist that errs
/// towards refusing is doing its job; one that errs towards accepting is the
/// bug this whole file exists to stop.
fn declared_dependencies(manifest: &str) -> BTreeSet<(DependencyKind, String)> {
    let mut declared = BTreeSet::new();
    let mut section = Section::Irrelevant;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // `[[bin]]` and friends are arrays of tables, never dependency
        // tables, and their inner text (`[bin]`) must not be classified.
        if trimmed.starts_with("[[") {
            section = Section::Irrelevant;
            continue;
        }
        if let Some(header) = trimmed.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            section = classify(header);
            if let Section::Names(kind, name) = &section {
                declared.insert((*kind, name.clone()));
            }
            continue;
        }
        if let Section::KeysAreDependencies(kind) = section {
            let key = trimmed.split('=').next().unwrap_or("").trim();
            let first = key.split('.').next().unwrap_or("").trim().trim_matches(['\'', '"']);
            if !first.is_empty() {
                declared.insert((kind, first.to_owned()));
            }
        }
    }
    declared
}

/// The names declared under one table, for the assertions below.
fn names_of(declared: &BTreeSet<(DependencyKind, String)>, kind: DependencyKind) -> BTreeSet<String> {
    declared.iter().filter(|(k, _)| *k == kind).map(|(_, n)| n.clone()).collect()
}

/// The four spellings the previous literal-substring guard read as an empty
/// section. Each is ordinary Cargo, not a contrivance: `cargo add` writes the
/// sub-table form whenever a dependency needs more than a version string.
#[test]
fn the_scanner_sees_a_dependency_however_the_manifest_spells_the_table() {
    let cases: &[(&str, DependencyKind, &str)] = &[
        ("[dependencies]\nlibc = \"0.2\"\n", DependencyKind::Runtime, "libc"),
        ("[dependencies.libc]\nversion = \"0.2\"\n", DependencyKind::Runtime, "libc"),
        ("[build-dependencies]\ncc = \"1\"\n", DependencyKind::Build, "cc"),
        ("[dev-dependencies.tempfile]\nversion = \"3\"\n", DependencyKind::Dev, "tempfile"),
        ("[target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n", DependencyKind::Runtime, "libc"),
        (
            "[target.'cfg(unix)'.dependencies.libc]\nversion = \"0.2\"\n",
            DependencyKind::Runtime,
            "libc",
        ),
        ("[dependencies]\nlibc.workspace = true\n", DependencyKind::Runtime, "libc"),
        ("[dependencies]\n\"libc\" = \"0.2\"\n", DependencyKind::Runtime, "libc"),
    ];
    for (manifest, kind, name) in cases {
        let declared = declared_dependencies(manifest);
        assert!(
            declared.contains(&(*kind, (*name).to_owned())),
            "the guard missed {name} in:\n{manifest}\nit saw {declared:?}"
        );
    }
}

/// The other half of the same guard: a dependency's own *fields* are not
/// dependencies. Without this, `[dependencies.libc]`'s `version`/`features`
/// keys would be collected as crate names and the guard would fail on a
/// manifest that is perfectly fine -- an allowlist that cries wolf gets
/// widened until it stops meaning anything.
#[test]
fn the_scanner_reads_no_dependency_where_there_is_none() {
    let manifest = "\
# a comment mentioning [dependencies] libc = \"0.2\"
[package]
name = \"btrieve\"

[dependencies.libc]
version = \"0.2\"
features = [\"std\"]

[[bin]]
name = \"btrvdump\"

[lints]
workspace = true
";
    let declared = declared_dependencies(manifest);
    assert_eq!(
        declared,
        [(DependencyKind::Runtime, "libc".to_owned())].into_iter().collect::<BTreeSet<_>>(),
        "only libc is a dependency here"
    );
}

#[test]
fn the_manifest_declares_no_runtime_dependencies_and_exactly_the_expected_dev_dependency() {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("readable manifest");
    let declared = declared_dependencies(&manifest);

    let mut not_dev: Vec<_> = declared.iter().filter(|(k, _)| *k != DependencyKind::Dev).collect();
    not_dev.sort();
    assert!(
        not_dev.is_empty(),
        "btrieve must depend on nothing but std to build and to run; found {not_dev:?}"
    );

    let dev_deps = names_of(&declared, DependencyKind::Dev);
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
