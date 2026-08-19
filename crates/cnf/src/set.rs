//! The set of files an editing session covers.
//!
//! The picker assembles the ordinary set: every `*.MSG` in the directory. A
//! `FILE0n` declaration is a hint on top of that -- measured across the 186
//! distinct corpus files, 17 declare one, 16 of those name the file they are
//! in, and exactly one (`ELWIC.MSG` -> `ELWICTXT.MSG`) names a sibling.
//!
//! `FILE0n` never carries a type letter in real data -- the tail is either
//! empty or free English prose (`FILE01 {ELWICTXT.MSG} Infinity Complex
//! Message File`), so it never parses as an [`crate::spec::OptionSpec`] and
//! never appears in `SpecFile::options()`. `siblings` reads
//! [`crate::spec::SpecFile::named`] instead, which records every `{value}`
//! construct regardless of whether it went on to parse as a typed option --
//! a deliberate departure from the original plan's suggested implementation
//! (iterate `options()`), which measurement showed cannot see a `FILE0n` at
//! all: none of the 62 `FILE0n` lines in the wider archive (not just the 186
//! distinct-by-content corpus) carry a type letter.

use std::io;
use std::path::{Path, PathBuf};

use crate::spec::{OptionSpec, SpecFile};

/// Every `*.MSG` in a directory, sorted, case-insensitive on the extension.
pub fn list_msg_files(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("msg")))
        .collect();
    out.sort();
    Ok(out)
}

/// `FILE` followed by one or more digits and nothing else -- not just a name
/// that happens to start with `FILE` (`FILEDESC` is a real option name in the
/// corpus and is not a `FILE0n` hint).
fn is_file0n(name: &[u8]) -> bool {
    name.strip_prefix(b"FILE").is_some_and(|rest| !rest.is_empty() && rest.iter().all(u8::is_ascii_digit))
}

/// Files this one declares that are not itself.
#[must_use]
pub fn siblings(file: &SpecFile) -> Vec<String> {
    let own = file.name().to_ascii_uppercase();
    let mut out = Vec::new();
    for n in file.named() {
        if !is_file0n(&n.name) {
            continue;
        }
        let declared = String::from_utf8_lossy(&file.source()[n.value.start..n.value.end])
            .trim()
            .to_ascii_uppercase();
        if !declared.is_empty() && declared != own {
            out.push(declared);
        }
    }
    out
}

/// Every option across a group of `.MSG` files, indexed as one flat list.
///
/// A hinge can name an option in another file in the same set (that is the
/// whole reason `FILE0n` pulls a sibling in), so `value_of` searches every
/// file rather than just one.
#[derive(Debug)]
pub struct OptionSet {
    files: Vec<SpecFile>,
}

impl OptionSet {
    /// Parse every path into a [`SpecFile`], in the order given.
    ///
    /// # Errors
    ///
    /// Any I/O failure reading a path, or a `.MSG` that does not parse --
    /// wrapped as [`io::ErrorKind::InvalidData`] since [`crate::spec::SpecError`]
    /// is not itself a [`std::error::Error`].
    pub fn open(paths: &[PathBuf]) -> io::Result<Self> {
        let mut files = Vec::with_capacity(paths.len());
        for path in paths {
            let source = std::fs::read(path)?;
            let name = path.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned());
            let file = SpecFile::parse(&name, &source)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e:?}", path.display())))?;
            files.push(file);
        }
        Ok(Self { files })
    }

    /// A one-file set from bytes already in memory, rather than a path on
    /// disk. For tests: real callers always go through [`Self::open`].
    ///
    /// # Errors
    ///
    /// If `source` does not parse as a `.MSG` -- see [`SpecFile::parse`].
    pub fn from_source(name: &str, source: &[u8]) -> Result<Self, io::Error> {
        let file = SpecFile::parse(name, source)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{name}: {e:?}")))?;
        Ok(Self { files: vec![file] })
    }

    #[must_use]
    pub fn files(&self) -> &[SpecFile] {
        &self.files
    }

    /// How many options the set holds in total, across every file.
    #[must_use]
    pub fn len(&self) -> usize {
        self.files.iter().map(|f| f.options().len()).sum()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The `n`th option in the set, and which file it came from.
    ///
    /// # Panics
    ///
    /// If `n >= self.len()`, the same contract as indexing a slice.
    #[must_use]
    pub fn at(&self, n: usize) -> (usize, &OptionSpec) {
        let mut remaining = n;
        for (file_index, file) in self.files.iter().enumerate() {
            let opts = file.options();
            if remaining < opts.len() {
                return (file_index, &opts[remaining]);
            }
            remaining -= opts.len();
        }
        panic!("option index {n} out of range for a set of {} options", self.len());
    }

    /// The current value of the option named `name`, wherever in the set it
    /// lives. `None` if no file in the set declares it.
    ///
    /// For [`crate::hinge::visible`]: a hinge's condition names an option by
    /// name, not by file, so evaluating it needs to search the whole set.
    #[must_use]
    pub fn value_of(&self, name: &[u8]) -> Option<Vec<u8>> {
        for file in &self.files {
            for opt in file.options() {
                if opt.name == name {
                    return file.messages().get(opt.index).map(<[u8]>::to_vec);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_self_naming_file0n_does_not_grow_the_set() {
        // The common case: 16 of the 17 corpus files that declare one. No
        // real FILE0n carries a type tail (measured), so this fixture
        // matches that shape rather than inventing one.
        let src = b"FILE01 {SELF.MSG}\r\nOPT {x} S 10 p\r\n";
        let f = SpecFile::parse("SELF.MSG", src).expect("parses");
        assert_eq!(siblings(&f), Vec::<String>::new());
    }

    #[test]
    fn a_file0n_naming_another_file_grows_the_set() {
        // ELWIC.MSG declares ELWICTXT.MSG -- the one corpus case.
        let src = b"FILE01 {ELWICTXT.MSG}\r\nOPT {x} S 10 p\r\n";
        let f = SpecFile::parse("ELWIC.MSG", src).expect("parses");
        assert_eq!(siblings(&f), vec!["ELWICTXT.MSG".to_string()]);
    }

    #[test]
    fn the_comparison_ignores_case() {
        let src = b"FILE01 {self.msg}\r\nOPT {x} S 10 p\r\n";
        let f = SpecFile::parse("SELF.MSG", src).expect("parses");
        assert_eq!(siblings(&f), Vec::<String>::new());
    }

    #[test]
    fn a_name_that_merely_starts_with_file_is_not_a_file0n_hint() {
        // FILEDESC is a real option name in the wider archive -- "FILE"
        // followed by letters, not digits. Treating it as a FILE0n hint
        // would pull its value in as a bogus sibling.
        let src = b"FILEDESC {NOT_A_SIBLING.MSG} S 20 p\r\n";
        let f = SpecFile::parse("SELF.MSG", src).expect("parses");
        assert_eq!(siblings(&f), Vec::<String>::new());
    }
}
