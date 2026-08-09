//! Ask the genuine host which way `stricmp` folds, because the source does not
//! survive.
//!
//! ```sh
//! cargo run -p mbbs16 --example stricmp
//! ```
//!
//! Borland's `strcmpi` is `stricmp`, and the host exports it at NE segment 1
//! offset 18417. `chkmin`/`chkmax` (`FSD.C:913`, `:947`) order field answers
//! with it, so the port needs its *sign*, not merely its notion of equality.
//!
//! # The fold direction is observable, and it is not a style question
//!
//! Six bytes sit between `'Z'` (0x5a) and `'a'` (0x61): `[ \ ] ^ _` and the
//! backquote. Against a letter they land on opposite sides depending on which
//! way the comparison folds:
//!
//! - folding to upper: `'_'` (0x5f) against `'A'` (0x41) -- `'_'` is greater;
//! - folding to lower: `'_'` (0x5f) against `'a'` (0x61) -- `'_'` is smaller.
//!
//! Every one of those six is typeable into an FSD field, so a `MIN=`/`MAX=`
//! range containing one orders differently under the two folds. This measures
//! which it is instead of picking one.
//!
//! It also asks what the magnitude is. This crate's [`mbbs::strings::strcmp`]
//! is transcribed as the *unsigned byte difference* rather than as a sign,
//! because Borland's `strcmp` is `repe cmpsb` then `sub ax,bx` with both high
//! bytes cleared. Whether `stricmp` answers the same way is worth knowing
//! before a port throws the magnitude away.

use std::path::Path;

use mbbs16::{Exit, FarPtr, Import, Machine, Symbol};

/// Room for the longer of the two probe strings plus its NUL.
const SCRATCH: usize = 32;

/// The pairs, in the order the report prints them.
///
/// The first block is the fold direction: each pair puts one of the six
/// between-case bytes against a letter that differs in case from its partner,
/// so the answer cannot be explained by anything but the fold. The second is
/// ordinary ordering, equality and prefix behaviour.
const PAIRS: &[(&[u8], &[u8])] = &[
    (b"_", b"A"),
    (b"_", b"a"),
    (b"[", b"A"),
    (b"[", b"a"),
    (b"`", b"A"),
    (b"`", b"a"),
    (b"^", b"Z"),
    (b"^", b"z"),
    (b"abc", b"ABC"),
    (b"ABC", b"abd"),
    (b"b", b"A"),
    (b"A", b"b"),
    (b"ab", b"abc"),
    (b"abc", b"ab"),
    (b"ab", b"abC"),
    (b"abC", b"ab"),
    (b"", b""),
    (b"", b"a"),
    (b"a", b""),
    (b"9", b"10"),
    (b"\x80", b"\x01"),
    (b"\xe0", b"\xc0"),
    (b"\xe9", b"\xc9"),
];

/// One probe, rendered byte for byte rather than through `from_utf8_lossy`,
/// which collapses every high-bit probe to the same replacement glyph.
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

    let stricmp = module
        .entry_by_name("_STRICMP")
        .expect("the host exports _STRICMP");
    println!("_STRICMP at {stricmp}");

    let left = machine.alloc_segment(SCRATCH)?;
    let right = machine.alloc_segment(SCRATCH)?;
    let a = FarPtr {
        offset: 0,
        selector: left,
    };
    let b = FarPtr {
        offset: 0,
        selector: right,
    };

    for (x, y) in PAIRS {
        assert!(
            x.len() < SCRATCH && y.len() < SCRATCH,
            "probe does not fit the scratch segment"
        );
        // Zero both segments each time: a shorter probe must not be able to
        // read the tail of a longer one that came before it.
        machine.write(a, &[0u8; SCRATCH])?;
        machine.write(b, &[0u8; SCRATCH])?;
        machine.write(a, x)?;
        machine.write(b, y)?;

        let exit = machine.call(stricmp, &[a.offset, a.selector, b.offset, b.selector])?;
        let (sx, sy) = (shown(x), shown(y));
        match exit {
            Exit::Returned { ax, .. } => println!("stricmp(\"{sx}\", \"{sy}\") = {}", ax as i16),
            other => {
                println!("stricmp(\"{sx}\", \"{sy}\") -> {other:?}");
                return Ok(());
            }
        }
    }
    Ok(())
}
