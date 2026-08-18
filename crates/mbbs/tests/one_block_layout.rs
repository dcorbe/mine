//! A module's Btrieve file block has exactly one layout authority:
//! `btrieve::Layout`. Nothing else may name a field's offset.
//!
//! # The defect this exists to prevent, measured
//!
//! `crates/mbbs/src/shims/btrieve.rs` used to carry its own
//! `pub(crate) const LASTKN: u16 = 142;` -- a second, independent copy of a
//! layout `crate::btrieve` already owned. That was correct for as long as
//! this host ran only 16-bit modules, and silently wrong the moment it ran a
//! 32-bit one: 142 is `lastkn` under the packed 16-bit layout and **the top
//! half of `data`** under `DFAAPI.H`'s `GCWINNT` layout (see
//! `btrieve::mem::BlockAbi`).
//!
//! So `key_number`, writing a key number through that constant, zeroed the
//! high two bytes of the record-buffer pointer MajorMUD-NT then dereferenced.
//! Measured on a real boot -- the same `dfaSetBlk`'d block, dumped either
//! side of one `dfaAcqLock(keynum: 0)`:
//!
//! ```text
//! before  ... 98 2f 01 42 | a8 27 01 42 | 00 00     data = 0x420127a8
//! after   ... 98 2f 01 42 | a8 27 00 00 | 00 00     data = 0x000027a8
//! ```
//!
//! and then `mov edx,[eax]` at `wccmmud.dll` RVA `0x5e688` took SIGSEGV.
//!
//! # Why a source scan and not a value assertion
//!
//! Because the bug was not a wrong *value*, it was a wrong *authority*. The
//! layout tests in `crates/btrieve/src/lib.rs` all passed while this was
//! broken -- they check what `Layout` says, and `Layout` was right. Nothing
//! checked that everyone asks it. This test does, and it is the only thing
//! in the suite that would have caught the constant.
//!
//! The rule is deliberately narrow: it governs the *file block*, the one
//! structure whose layout differs per ABI and whose fields a module reads
//! directly. It says nothing about `ptr_offset` in general -- `users.rs`,
//! `textvar.rs` and `stream.rs` all offset their own structures and are none
//! of this test's business.

use std::fs;
use std::path::{Path, PathBuf};

/// Every `.rs` file under `dir`.
fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("readable source directory") {
        let path = entry.expect("readable entry").path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Drop `//`-comments, so prose that *describes* the old constant -- this
/// file's own module comment does, and so does the replacement note left at
/// the deleted constant's site -- does not read as a reintroduction.
///
/// Crude on purpose: it does not understand strings or nested block
/// comments. A false negative here (a real offset hidden inside a string
/// literal) is not a failure mode anyone has, and a parser would be more
/// machinery than the rule is worth.
fn code_only(text: &str) -> String {
    text.lines()
        .map(|line| match line.find("//") {
            Some(at) => &line[..at],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The names a Btrieve file block is bound to in this crate. A call
/// offsetting one of these is offsetting a `struct btvblk`/`struct dfablk`.
const BLOCK_BINDINGS: &[&str] = &["block", "dfaptr", "bigptr"];

/// Every offset into a module's file block must come from `btrieve::Layout`.
///
/// Failing this means a second layout authority has appeared. The fix is not
/// to add the file to an allowlist -- it is to ask `Layout` instead, and to
/// teach `Layout` the field if it does not carry it yet.
#[test]
fn every_block_field_offset_comes_from_the_one_layout() {
    let mut files = Vec::new();
    for dir in ["src"] {
        rs_files(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(dir), &mut files);
    }
    files.sort();

    let mut offenders = Vec::new();
    let mut checked = 0usize;
    for path in &files {
        let text = code_only(&fs::read_to_string(path).expect("readable source"));
        for (n, line) in text.lines().enumerate() {
            for binding in BLOCK_BINDINGS {
                let needle = format!("ptr_offset({binding}");
                if !line.contains(&needle) {
                    continue;
                }
                checked += 1;
                if !line.contains("Layout") {
                    offenders.push(format!(
                        "{}:{}: {}",
                        path.display(),
                        n + 1,
                        line.trim()
                    ));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "these offset a Btrieve file block without asking btrieve::Layout, which is how \
         `LASTKN = 142` happened -- see this file's module comment:\n{}",
        offenders.join("\n")
    );

    // A scan that silently examines nothing passes forever. The `btv*`/`dfa*`
    // shims reach into a module's block for `lastkn`, and if that stops being
    // true this test has gone vacuous and should be deleted rather than left
    // to reassure people -- the same argument `no_direct_farptr.rs`'s module
    // comment makes about counts.
    assert!(
        checked > 0,
        "no block-field offset found anywhere -- this test is no longer measuring anything"
    );
}
