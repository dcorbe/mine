//! The FSD's per-field record has two layouts, and generic code may name
//! neither of them directly.
//!
//! `struct fsdfld` is 23 bytes in the 16-bit build and 36 in the 32-bit one,
//! because `INT` is `int` (`re/wg33src/INC/GCTYPDEF.H:88`). The host
//! *allocates* that array and the module writes into it without calling back
//! -- `WCCMMUD`'s `edit_character_stats` ORs `FFFAVD` into fourteen of the
//! records with a bare `or byte [flddat + n*sizeof + 12], 0x80` -- so the two
//! agree on which byte is which only if the host uses the same `sizeof` the
//! module's compiler did.
//!
//! For years it did not: `crates/mbbs/src/fsd.rs` had one `FSDFLD = 23` and
//! every ABI got it. Under `Wg32` that made the host read each field's flags
//! from `n*23+12` while the module had written them at `n*36+12`. Those
//! coincide only at `n == 0`, so the host saw no `FFFAVD` at all and
//! MajorMUD's character sheet let the player put the cursor into the
//! *minimum* and *maximum* columns of every stat -- fields the module had
//! explicitly marked unenterable.
//!
//! [`crate::fsd::FieldLayout`] is the fix and `Abi::FSD_FIELD` is how generic
//! code reaches it. This test is what stops the next contributor from
//! reaching past it: the five members whose offsets move between builds
//! (`fspoff`, `tmpoff`, `mbpoff`, `ansoff`, `anslen`) still exist under
//! `fsd::fld::` as **16-bit-only** aliases, because the 16-bit oracle files
//! pin real `MAJORBBS.EXE` instruction bytes against them. Naming one of
//! those from a function generic over `A: Abi` compiles, passes every
//! existing test, and is wrong under exactly one of the two ABIs -- which is
//! the failure mode that produced this bug in the first place.
//!
//! A prose warning on the constants was not enough; this repository has
//! already recorded a trap documented in prose for three days that did not
//! stop the bug it described. So it is a test.
//!
//! # What is measured
//!
//! Production code only, in the two files that implement the FSD. Comments
//! are not stripped (a doc comment naming `fld::ANSOFF` in a `[`link`]` is
//! rare and easy to spell around), but `#[cfg(test)]` modules are: the unit
//! tests in both files use a `Wg16` fixture throughout and *should* name the
//! 16-bit offsets, since 16-bit is what they exercise.

use std::fs;
use std::path::PathBuf;

/// The `fsd::fld::` members whose offset depends on `INT`'s width.
///
/// `ANSGTO`, `WIDTH`, `XWIDTH`, `ATTR`, `FLAGS` and `FLDTYP` are deliberately
/// absent: everything before `flags` is `CHAR`-sized, so those six are the
/// same number in both builds and generic code may name them freely.
const MOVED: &[&str] = &["FSPOFF", "TMPOFF", "MBPOFF", "ANSOFF", "ANSLEN"];

/// Where the FSD is implemented. Both files are generic over `A: Abi`.
const FILES: &[&str] = &["src/fsd.rs", "src/shims/fsd.rs"];

/// Drop `#[cfg(test)] mod tests { .. }` by brace balance.
///
/// Crude on purpose: it only has to handle the one shape both files use, a
/// single trailing test module introduced by `#[cfg(test)]`.
fn strip_test_modules(code: &str) -> String {
    let mut out = String::new();
    let mut lines = code.lines().peekable();
    while let Some(line) = lines.next() {
        if line.trim_start().starts_with("#[cfg(test)]") {
            // Skip forward to the module's opening brace, then past its close.
            let mut depth = 0isize;
            let mut started = false;
            for rest in lines.by_ref() {
                depth += rest.matches('{').count() as isize;
                depth -= rest.matches('}').count() as isize;
                if rest.contains('{') {
                    started = true;
                }
                if started && depth <= 0 {
                    break;
                }
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

#[test]
fn generic_fsd_code_reaches_the_layout_through_the_abi_not_the_16_bit_aliases() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for name in FILES {
        let path = root.join(name);
        let text = fs::read_to_string(&path).expect("the FSD source reads");
        let production = strip_test_modules(&text);
        for (n, line) in production.lines().enumerate() {
            if line.trim_start().starts_with("///") {
                continue;
            }
            // `fld::X` alone, since `fsd::fld::X` and `crate::fsd::fld::X`
            // all contain it -- matching each spelling separately would
            // report the same line more than once.
            if MOVED.iter().any(|m| line.contains(&format!("fld::{m}"))) {
                offenders.push(format!("{name}:{}: {}", n + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these lines name a `struct fsdfld` member whose offset differs between \
         the 16-bit (23-byte) and 32-bit (36-byte) layouts, from production code \
         that serves both ABIs. Use `A::FSD_FIELD` -- the `FieldLayout` for the \
         ABI actually in hand -- so the host reads the byte the module wrote:\n  {}",
        offenders.join("\n  ")
    );
}

/// The two layouts must not be silently the same.
///
/// If someone "simplifies" `FieldLayout::WG32` back onto the 16-bit numbers,
/// every other test in this file still passes -- it only checks that generic
/// code goes *through* the abstraction, not that the abstraction distinguishes
/// anything.
#[test]
fn the_two_layouts_actually_differ() {
    use mbbs::fsd::FieldLayout;
    assert_ne!(
        FieldLayout::WG16.size,
        FieldLayout::WG32.size,
        "a per-ABI layout whose two ABIs agree is an abstraction with nothing \
         behind it -- `struct fsdfld` is 23 bytes in the 16-bit build and 36 in \
         the 32-bit one"
    );
    assert_ne!(FieldLayout::WG16.int_width, FieldLayout::WG32.int_width);
    assert_ne!(FieldLayout::WG16.ansoff, FieldLayout::WG32.ansoff);
}
