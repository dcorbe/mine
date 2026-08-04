//! The loader against the module it exists to load.
//!
//! `tests/ne.rs` covers the format; this covers *this file*. Every number
//! asserted here was measured from `re/WCCMMUD.DLL` before the loader was
//! written and recorded in `docs/plans/2026-08-04-ne-loader.md`, so a change in
//! any of them is a change in the loader's reading of the file rather than a
//! test being brought into line with it.
//!
//! `re/WCCMMUD.DLL` is not in the repository -- it is a commercial binary --
//! so every test here skips, loudly, when it is absent.

use std::path::{Path, PathBuf};

use mbbs16::{Exit, Import, Machine, Module, NeImage, Symbol};

/// What the file is, measured rather than assumed.
const SEGMENTS: usize = 82;
const RELOCATIONS: usize = 22_371;
const AUTODATA: u16 = 81;
const INIT_ORDINAL: u16 = 1;
const INIT_NAME: &str = "_INIT__WCCMMUD";
const INIT_SEGMENT: u16 = 3;
const INIT_OFFSET: u16 = 0x0f5d;

/// Distinct imported symbols, which is how many thunks the module needs.
///
/// 207, not the 206 the design note quotes: that figure counts ordinals, and
/// `PHAPI.DOSCREATEDSALIAS` is imported by name. A thunk table sized to the
/// ordinal count alone would be one short.
const DISTINCT_IMPORTS: usize = 207;

/// Per-module call-site and symbol counts, agreeing with `re/nefmt.py` -- with
/// the same caveat: `nefmt` tallies ordinals and names into separate counters,
/// so its "PHAPI 0" is 0 ordinals beside 1 name.
const PER_MODULE: &[(&str, usize, usize)] = &[
    ("GALGSBL", 1173, 15),
    ("MAJORBBS", 13331, 188),
    ("DOSCALLS", 15, 2),
    ("GALME", 2, 1),
    ("PHAPI", 1, 1),
];

fn module_path() -> Option<PathBuf> {
    // The crate lives two directories below the repository root.
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("re/WCCMMUD.DLL");
    path.exists().then_some(path)
}

/// The file's bytes, or `None` with a message saying why the test did nothing.
fn wccmmud() -> Option<Vec<u8>> {
    match module_path() {
        Some(path) => Some(std::fs::read(path).expect("re/WCCMMUD.DLL is readable")),
        None => {
            eprintln!("skipped: re/WCCMMUD.DLL is not present in this checkout");
            None
        }
    }
}

/// Load it with every import resolved as a routine.
///
/// Deliberately the wrong answer for the 38 data imports, and it does not
/// matter here: a thunk address is a far pointer like any other, so the fixups
/// land in the same places either way. Which arm each import belongs in is
/// step 7's business.
fn load(machine: &mut Machine, file: &[u8]) -> Module {
    machine
        .load_ne(file, &|_: &str, _: &Symbol| Some(Import::Routine))
        .expect("WCCMMUD.DLL loads")
}

#[test]
fn the_real_module_parses_as_measured() {
    let Some(file) = wccmmud() else { return };
    let image = NeImage::parse(&file).expect("WCCMMUD.DLL parses");

    assert_eq!(image.segments.len(), SEGMENTS);
    assert_eq!(image.autodata, AUTODATA);
    assert_eq!(image.align, 9, "512-byte sectors");
    assert_eq!(image.flags, 0x8009, "library, single-data, protected-mode");
    assert_eq!(
        image.modules,
        ["GALGSBL", "DOSCALLS", "PHAPI", "MAJORBBS", "GALME"]
    );

    let code = image.segments.iter().filter(|s| !s.is_data()).count();
    assert_eq!((code, SEGMENTS - code), (34, 48), "code and data segments");

    let total: usize = image.segments.iter().map(|s| s.relocations.len()).sum();
    assert_eq!(total, RELOCATIONS);
}

#[test]
fn the_import_histogram_agrees_with_nefmt() {
    let Some(file) = wccmmud() else { return };
    let image = NeImage::parse(&file).expect("WCCMMUD.DLL parses");

    for (name, sites, ordinals) in PER_MODULE {
        let index = image
            .modules
            .iter()
            .position(|m| m == name)
            .expect("a named module") as u16
            + 1;

        let mut seen = std::collections::HashSet::new();
        let mut count = 0;
        for segment in &image.segments {
            for reloc in &segment.relocations {
                if let mbbs16::Target::Import { module, symbol } = &reloc.target
                    && *module == index
                {
                    count += 1;
                    seen.insert(symbol.clone());
                }
            }
        }
        assert_eq!(count, *sites, "{name} call sites");
        assert_eq!(seen.len(), *ordinals, "{name} distinct symbols");
    }
}

#[test]
fn the_real_module_loads_and_every_relocation_is_applied() {
    let Some(file) = wccmmud() else { return };
    let mut machine = Machine::new().expect("16-bit machine");
    let module = load(&mut machine, &file);

    assert_eq!(module.segment_count(), SEGMENTS);
    assert_eq!(module.relocations_applied(), RELOCATIONS, "none rejected");
    assert_eq!(module.imports().len(), DISTINCT_IMPORTS);
    assert_eq!(
        module.data_selector(),
        module.segment_selector(AUTODATA).expect("segment 81"),
        "DGROUP is the autodata segment"
    );
    assert_eq!(machine.data_selector(), module.data_selector());
}

#[test]
fn every_relocation_lands_inside_a_segment_this_loader_created() {
    let Some(file) = wccmmud() else { return };
    let image = NeImage::parse(&file).expect("WCCMMUD.DLL parses");
    let mut machine = Machine::new().expect("16-bit machine");
    let module = load(&mut machine, &file);

    for (i, segment) in image.segments.iter().enumerate() {
        let number = (i + 1) as u16;
        let selector = module.segment_selector(number).expect("a mapped segment");

        for reloc in &segment.relocations {
            // The source is inside the segment it belongs to.
            assert!(
                machine
                    .resolve(
                        mbbs16::FarPtr {
                            offset: reloc.offset,
                            selector
                        },
                        reloc.source.width(),
                    )
                    .is_ok(),
                "a {:?} fixup at {:#06x} is outside segment {number}",
                reloc.source,
                reloc.offset
            );

            // And an internal target names a segment that exists.
            if let mbbs16::Target::Internal { segment, .. } = reloc.target {
                assert!(
                    module.segment_selector(u16::from(segment)).is_some(),
                    "a fixup names segment {segment}, which was not created"
                );
            }
        }
    }
}

/// Every `mov ax, <segment>` site holds the selector of the segment it names.
///
/// 2,924 of them: 2,069 additive and 855 not. This is the check that a wrong
/// answer does not announce -- a `SEGMENT` fixup pointing at the wrong segment
/// does not fault, it hands the module a selector for someone else's memory and
/// every access through it reads or writes the wrong thing.
///
/// The design note guessed these were `mov ax, DGROUP` sites and expected them
/// all to name segment 81. They do not: they spread across the module's data
/// segments, 767 naming segment 36, 685 segment 43, and only six naming 81 at
/// all. The check is stronger this way -- 82 distinct right answers rather than
/// one -- so the guess is corrected rather than the test weakened.
#[test]
fn every_segment_fixup_resolves_to_the_segment_it_names() {
    let Some(file) = wccmmud() else { return };
    let image = NeImage::parse(&file).expect("WCCMMUD.DLL parses");
    let mut machine = Machine::new().expect("16-bit machine");
    let module = load(&mut machine, &file);

    let mut checked = 0;
    let mut naming_dgroup = 0;

    for (i, segment) in image.segments.iter().enumerate() {
        let selector = module.segment_selector((i + 1) as u16).expect("mapped");
        for reloc in &segment.relocations {
            let mbbs16::Target::Internal {
                segment: target, ..
            } = reloc.target
            else {
                continue;
            };
            if reloc.source != mbbs16::Source::Segment {
                continue;
            }

            let expected = module
                .segment_selector(u16::from(target))
                .expect("the target segment was created");
            let bytes = machine
                .resolve(
                    mbbs16::FarPtr {
                        offset: reloc.offset,
                        selector,
                    },
                    2,
                )
                .expect("inside the segment");
            assert_eq!(
                u16::from_le_bytes([bytes[0], bytes[1]]),
                expected,
                "a fixup at {:#06x} in segment {} should name segment {target}",
                reloc.offset,
                i + 1
            );

            checked += 1;
            if u16::from(target) == AUTODATA {
                naming_dgroup += 1;
            }
        }
    }

    assert_eq!(checked, 2_924, "SEGMENT fixups with an internal target");
    assert_eq!(naming_dgroup, 6, "and how few of them are DGROUP");
}

#[test]
fn the_host_entry_point_resolves_by_ordinal_and_by_name() {
    let Some(file) = wccmmud() else { return };
    let mut machine = Machine::new().expect("16-bit machine");
    let module = load(&mut machine, &file);

    let by_ordinal = module.entry(INIT_ORDINAL).expect("ordinal 1");
    let by_name = module.entry_by_name(INIT_NAME).expect(INIT_NAME);

    assert_eq!(by_ordinal, by_name, "the same entry point either way");
    assert_eq!(by_ordinal.offset, INIT_OFFSET);
    assert_eq!(
        by_ordinal.selector,
        module.segment_selector(INIT_SEGMENT).expect("segment 3"),
    );
}

/// The end-to-end statement: the image is coherent enough to execute.
///
/// `_INIT__WCCMMUD` is what the host calls to make a module register itself, so
/// the first thing it does is reach for the host. Getting an `Exit::Call` here
/// and not an `Exit::Fault` means the segments, the relocations, the entry
/// point and `DS` are all right enough to run real compiled code.
#[test]
fn entering_the_module_reaches_an_import_rather_than_a_fault() {
    let Some(file) = wccmmud() else { return };
    let mut machine = Machine::new().expect("16-bit machine");
    let module = load(&mut machine, &file);

    let init = module.entry(INIT_ORDINAL).expect("ordinal 1");
    // The library flag says AX holds the module handle on entry. Nothing here
    // implements handles, so the argument list is empty and AX is whatever
    // `call` sets -- which the first host call will make irrelevant.
    match machine.call(init, &[]).expect("entered _INIT__WCCMMUD") {
        Exit::Call { index } => {
            let site = module.import(index).expect("a thunk that names itself");
            eprintln!("_INIT__WCCMMUD's first host call is {site}");
        }
        other => panic!("expected a host call, got {other:?}"),
    }
}
