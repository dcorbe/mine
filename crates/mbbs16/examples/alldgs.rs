//! Ask the genuine host what `alldgs` says, because the source does not survive.
//!
//! ```sh
//! cargo run -p mbbs16 --example alldgs
//! ```
//!
//! `GCOMM.H:345` declares `int alldgs(char *string)` and no `.C` file in the
//! recovered archive defines it. `chktyp` (`FSD.C:861`) guards the `$` case with
//! `strlen(cp) > 0 && alldgs(cp)` and the `#` case not at all, which reads like
//! an inference that the empty string is all-digits. An inference is not a
//! measurement, and this is the measurement.
//!
//! # Why this can be called cold
//!
//! `alldgs` is a leaf: one string argument, an `int` back, no `fsdscb`, no
//! channel, no screen library. It is exported outright at NE segment 46 offset
//! 0, so a freshly loaded image is all it needs. Every import is resolved to a
//! thunk so that a call out to `PHAPI`, `GALGSBL` or `DOSCALLS` arrives as
//! [`Exit::Call`] naming the symbol rather than as a far call into nothing --
//! if `alldgs` turns out not to be the leaf it looks like, this says so.
//!
//! # The export is `_ALLDGS`
//!
//! Uppercase, one leading underscore, as everything in this binary's name
//! tables is. `re/ne_exports.py` will not show you that -- it
//! `lstrip("_").lower()`s both sides of its lookup -- so the spelling comes
//! from the name table itself, the same way `_FSDPPC` and `_FSDANS` do.

use std::path::Path;

use mbbs16::{Exit, FarPtr, Import, Machine, Symbol};

/// Room for the longest probe plus its NUL, with slack. One segment, reused:
/// each probe is written over the last, so the run costs one LDT entry rather
/// than one per string.
const SCRATCH: usize = 64;

/// The probes, in the order the report prints them.
///
/// The first five are the ones that decide an implementation. `""` is what
/// makes `chktyp`'s asymmetry between `#` and `$` coherent -- or does not.
/// `" "`, `"-1"`, `"+1"` and `"1 "` say whether "all digits" means *every*
/// character or merely *some prefix*, and whether a sign or surrounding
/// whitespace is tolerated.
///
/// `"/"` and `":"` are `'0' - 1` and `'9' + 1`, the two bytes a range check
/// gets wrong when it is written with the wrong comparison. `"\x80"`, `"\xb2"`
/// and `"\xff"` are high-bit bytes: Borland's `isdigit` indexes a table with a
/// *signed* `char`, so a byte above 0x7f reads before the start of that table
/// and can answer anything at all. If any of them come back 1, then "every
/// byte is an ASCII digit" is the wrong port and the table has to be modelled.
const PROBES: &[&[u8]] = &[
    b"",
    b" ",
    b"-1",
    b"+1",
    b"1 ",
    b"0",
    b"7",
    b"9",
    b"42",
    b"007",
    b" 1",
    b"1.0",
    b"a",
    b"1a",
    b"a1",
    b"\t",
    b"/",
    b":",
    b"\x80",
    b"\xb2",
    b"\xff",
    b"12345678901234567890",
];

/// One probe, rendered byte for byte.
///
/// Not `String::from_utf8_lossy`: half the interesting probes are single bytes
/// above 0x7f, and lossy decoding collapses every one of them to the same
/// replacement character. A measurement whose inputs cannot be told apart in
/// its own output is not a measurement.
fn shown(probe: &[u8]) -> String {
    probe
        .iter()
        .map(|&b| match b {
            b'\\' => "\\\\".to_string(),
            b'"' => "\\\"".to_string(),
            0x20..=0x7e => (b as char).to_string(),
            _ => format!("\\x{b:02x}"),
        })
        .collect()
}

fn main() -> std::io::Result<()> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("re/hosts/MAJORBBS-mbbstd.EXE");
    let file = std::fs::read(&path)?;

    let mut machine = Machine::new()?;
    let module = machine.load_ne(&file, &|_: &str, _: &Symbol| Some(Import::Routine))?;

    let alldgs = module
        .entry_by_name("_ALLDGS")
        .expect("the host exports _ALLDGS");
    println!("_ALLDGS at {alldgs}");

    let scratch = machine.alloc_segment(SCRATCH)?;
    let at = FarPtr {
        offset: 0,
        selector: scratch,
    };

    for probe in PROBES {
        assert!(
            probe.len() < SCRATCH,
            "probe {probe:?} does not fit the scratch segment"
        );
        // Zero the whole segment, not just the terminator: a shorter probe must
        // not be able to read the tail of a longer one that came before it.
        machine.write(at, &[0u8; SCRATCH])?;
        machine.write(at, probe)?;

        let exit = machine.call(alldgs, &[at.offset, at.selector])?;
        let shown = shown(probe);
        match exit {
            Exit::Returned { ax, .. } => println!("alldgs(\"{shown}\") = {}", ax as i16),
            Exit::Call { index } => {
                let who = module
                    .import(index)
                    .map(|i| format!("{}.{:?}", i.module, i.symbol))
                    .unwrap_or_else(|| format!("thunk {index}, no import site"));
                println!("alldgs(\"{shown}\") -> called an import: {who}");
                return Ok(());
            }
            other => {
                println!("alldgs(\"{shown}\") -> {other:?}");
                return Ok(());
            }
        }
    }
    Ok(())
}
