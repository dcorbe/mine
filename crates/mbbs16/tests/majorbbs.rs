//! The loader against the *host* binary, not a module.
//!
//! `re/hosts/MAJORBBS-mbbstd.EXE` is the genuine 16-bit MajorBBS host. It is an
//! NE *executable* rather than a DLL -- there is no MAJORBBS.DLL -- and it
//! exports 838 symbols by ordinal (`re/ne_exports.py --list` reports 850
//! ordinals, 838 named) because that is how modules link against it. Loading it
//! here is not about running a BBS: its entry point never runs. It is about
//! being able to *call* the routines whose C source did not survive, and use
//! their answers as ground truth. See
//! `docs/plans/2026-08-08-fsd-subsystem-design.md`, "Stage 0".
//!
//! The binary is not in the repository, so every test here skips, loudly, when
//! it is absent.

use std::path::{Path, PathBuf};

use mbbs16::{Import, Machine, Module, NeImage, Symbol};

/// What the file is, measured from it before this test was written.
const SEGMENTS: usize = 210;
const AUTODATA: u16 = 209;

/// The three libraries the host itself imports from.
const IMPORTED_MODULES: [&str; 3] = ["PHAPI", "GALGSBL", "DOSCALLS"];

fn host_path() -> Option<PathBuf> {
    // The crate lives two directories below the repository root.
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("re/hosts/MAJORBBS-mbbstd.EXE");
    path.exists().then_some(path)
}

/// The file's bytes, or `None` with a message saying why the test did nothing.
pub fn host() -> Option<Vec<u8>> {
    match host_path() {
        Some(path) => Some(std::fs::read(path).expect("the host binary is readable")),
        None => {
            eprintln!("skipped: re/hosts/MAJORBBS-mbbstd.EXE is not present");
            None
        }
    }
}

/// Load it with every import resolved as a routine.
///
/// Wrong in principle for any data import, and it does not matter for the calls
/// this rig makes: a thunk address is a far pointer like any other, so the fixups
/// land in the same places. The host's own imports are PHAPI (the Phar Lap
/// extender), GALGSBL (the serial library) and DOSCALLS; a routine that reached
/// one would stop and name it, which is the answer we want.
pub fn load(machine: &mut Machine, file: &[u8]) -> Module {
    machine
        .load_ne(file, &|_: &str, _: &Symbol| Some(Import::Routine))
        .expect("the host binary loads")
}

#[test]
fn the_host_binary_parses() {
    let Some(file) = host() else { return };
    let image = NeImage::parse(&file).expect("an NE image");

    assert_eq!(image.segments.len(), SEGMENTS);
    assert_eq!(image.autodata, AUTODATA);
    for name in IMPORTED_MODULES {
        assert!(
            image.modules.iter().any(|m| m == name),
            "the host imports from {name}"
        );
    }
}

#[test]
fn the_host_binary_loads_into_a_machine() {
    let Some(file) = host() else { return };
    let mut machine = Machine::new().expect("a machine");
    let module = load(&mut machine, &file);

    assert_eq!(module.segment_count(), SEGMENTS);
}

/// The exports this rig exists to call, and where they live.
///
/// Ordinals and addresses cross-checked against `re/ne_exports.py --list` before
/// this test was written, so a change here is a change in the loader's reading of
/// the entry table rather than a test brought into line with it.
///
/// `entry_by_name` does not normalize -- it looks up exactly what
/// `collect_names` read out of the non-resident name table, same as
/// `wccmmud.rs`'s `INIT_NAME = "_INIT__WCCMMUD"`. `re/ne_exports.py` is a
/// friendlier reader: it `lstrip("_").lower()`s both the table and the query,
/// so `python3 re/ne_exports.py ... fsdppc` finds `_FSDPPC` without telling you
/// the file actually stores it uppercase with a leading underscore. Confirmed
/// by parsing the non-resident table's raw bytes directly (`nrestab`, ordinal
/// field per entry) rather than trusting the normalized `--list` output.
#[test]
fn the_fsd_and_screen_routines_are_reachable_by_name() {
    let Some(file) = host() else { return };
    let mut machine = Machine::new().expect("a machine");
    let module = load(&mut machine, &file);

    for name in [
        "_FSDPPC", "_FSDANS", "_FSDDSP", "_FSDENT", "_FSDLIN", "_FSDPRC",
        "_FSDINC", "_SETWIN", "_LOCATE", "_CURCURX", "_CURCURY", "_RSTWIN",
        "_RSTLOC", "_ANSION",
    ] {
        assert!(
            module.entry_by_name(name).is_some(),
            "the host exports {name}"
        );
    }
}
