//! The real 32-bit MajorMUD module, parsed.
//!
//! Every number here was measured from this exact file before the parser was
//! written, and is recorded in `docs/plans/2026-08-08-mbbs32-design.md`. A test
//! that disagrees with one of them is reporting a real difference: change the
//! code, or re-measure and change both -- never quietly relax the assertion.

use std::path::{Path, PathBuf};

use mbbs32::{Exit, Image, Import32, Machine, PeImage, Symbol};

fn module_path() -> Option<PathBuf> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(|root| root.join("re/wg_nt_ref/WCCNT8PJ/out/wccmmud.dll"))?;
    if path.exists() {
        Some(path)
    } else {
        eprintln!("skipped: re/wg_nt_ref/WCCNT8PJ/out/wccmmud.dll is not present");
        None
    }
}

fn image() -> Option<(Vec<u8>, PeImage)> {
    let bytes = std::fs::read(module_path()?).unwrap();
    let image = PeImage::parse(&bytes).unwrap();
    Some((bytes, image))
}

#[test]
fn the_real_module_parses_as_measured() {
    let Some((bytes, image)) = image() else { return };
    assert_eq!(bytes.len(), 643_072);
    assert_eq!(image.image_base, 0x40_0000);
    assert_eq!(image.size_of_image, 0xac_000);
    assert_eq!(image.section_alignment, 0x1000);
    assert_eq!(image.file_alignment, 0x200);
    assert_eq!(image.entry_point, 0x1000);
    assert!(image.rebasable(), "RELOCS_STRIPPED must be clear");

    let names: Vec<&str> = image.sections.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["CODE", "DATA", ".idata", ".edata", ".reloc"]);

    let code = &image.sections[0];
    assert_eq!(code.rva, 0x1000);
    assert_eq!(code.virtual_size, 0x78000);
    assert_eq!(code.raw_size, 0x77e00);
    assert_eq!(code.raw_offset, 0x600);

    let data = &image.sections[1];
    assert_eq!(data.rva, 0x79_000);
    assert_eq!(data.virtual_size, 0x24_000);
    assert_eq!(data.raw_size, 0x17_c00);
    assert_eq!(data.raw_offset, 0x78400);
    assert_eq!(
        data.virtual_size - data.raw_size,
        0xc400,
        "DATA's BSS tail, which must arrive zeroed"
    );

    let idata = &image.sections[2];
    assert_eq!(idata.rva, 0x9d000);
    assert_eq!(idata.virtual_size, 0x2000);
    assert_eq!(idata.raw_size, 0x1200);
    assert_eq!(idata.raw_offset, 0x90000);

    let edata = &image.sections[3];
    assert_eq!(edata.rva, 0x9f000);
    assert_eq!(edata.virtual_size, 0x5000);
    assert_eq!(edata.raw_size, 0x4600);
    assert_eq!(edata.raw_offset, 0x91200);

    let reloc = &image.sections[4];
    assert_eq!(reloc.rva, 0xa4000);
    assert_eq!(reloc.virtual_size, 0x8000);
    assert_eq!(reloc.raw_size, 0x7400);
    assert_eq!(reloc.raw_offset, 0x95800);
}

#[test]
fn every_relocation_is_highlow_and_padding_is_gone() {
    let Some((_, image)) = image() else { return };
    assert_eq!(image.relocations.len(), 13_920);

    // 14,112 entries in the file, 192 of them ABSOLUTE padding.
    let inside = |rva: u32| {
        image
            .sections
            .iter()
            .any(|s| rva >= s.rva && rva + 4 <= s.rva + s.virtual_size)
    };
    assert!(
        image.relocations.iter().all(|r| inside(r.rva)),
        "every relocation site must be inside a section"
    );
}

#[test]
fn the_import_histogram_is_as_measured() {
    let Some((_, image)) = image() else { return };
    let mut per: std::collections::BTreeMap<&str, usize> = Default::default();
    for i in &image.imports {
        *per.entry(i.library.as_str()).or_default() += 1;
    }
    assert_eq!(
        per,
        [
            ("GALGSBL.dll", 17),
            ("GALME.dll", 1),
            ("KERNEL32.dll", 3),
            ("WGSERVER.EXE", 149),
            ("cw3220mt.DLL", 40),
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(image.imports.len(), 210);
    assert!(
        image
            .imports
            .iter()
            .all(|i| matches!(i.symbol, Symbol::Name(_))),
        "every import in this module is by name; not one is by ordinal"
    );
}

#[test]
fn the_export_table_is_as_measured() {
    let Some((_, image)) = image() else { return };
    assert_eq!(image.exports.len(), 592);
    assert!(
        image.exports.iter().all(|e| e.forwarder().is_none()),
        "this module forwards nothing"
    );

    // `_INIT__WCCMMUD` is the 16-bit module's registration entry point: host
    // ordinal 1, the routine the host calls to hand the module its tables.
    // This 32-bit build exports the identical identifier, spelled in this
    // toolchain's lowercase convention rather than the 16-bit build's
    // ALLCAPS one -- every export in this table is lowercase, so the case
    // difference is a toolchain fact, not a different symbol. It sits at
    // export ordinal 1 here too (`Base` 1 plus its zero-based index 0 in
    // `AddressOfFunctions`), which was confirmed independently by reading
    // the raw export directory with `python3` rather than trusted from the
    // name match alone. That is the 32-bit analogue this test was left
    // unfinished for.
    assert_eq!(
        image.export_rva("_init__wccmmud"),
        Some(0x1aaa),
        "the module's registration entry point, the 32-bit analogue of \
         _INIT__WCCMMUD, must be exported at the RVA measured from the file"
    );
}

/// `re/pefmt.py` reads the same import directory this crate does, written
/// before this crate existed, so it is the independent second opinion --
/// exactly what `crates/mbbs16/tests/wccmmud.rs`'s
/// `the_import_histogram_agrees_with_nefmt` is for the 16-bit loader. Unlike
/// that test, this one shells out for real rather than checking a
/// hand-transcribed table: `pefmt.py` has no `__main__`, so the invocation
/// below is a short driver script (mirroring `re/ne_imports.py`'s report over
/// `nefmt.parse`) that imports it, parses the module, and prints one
/// `library\tcount` line per imported library -- ordinals and names both
/// counted, though this module has none of the former (see
/// `the_import_histogram_is_as_measured`).
#[test]
fn the_import_table_agrees_with_pefmt_py() {
    let Some(module) = module_path() else { return };

    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/mbbs32 is two directories below the repo root");
    let pefmt = root.join("re/pefmt.py");
    if !pefmt.exists() {
        eprintln!("skipped: re/pefmt.py is not present");
        return;
    }

    const DRIVER: &str = "\
import sys
sys.path.insert(0, sys.argv[1])
import pefmt
from collections import Counter
imports = pefmt.parse(sys.argv[2])
per_library = Counter()
for (library, _ordinal), count in imports.ordinals.items():
    per_library[library] += count
for (library, _name), count in imports.names.items():
    per_library[library] += count
for library in sorted(per_library):
    print('%s\\t%d' % (library, per_library[library]))
";

    let output = match std::process::Command::new("python3")
        .arg("-c")
        .arg(DRIVER)
        .arg(root.join("re"))
        .arg(&module)
        .output()
    {
        Ok(output) => output,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipped: python3 is not present");
            return;
        }
        Err(e) => panic!("failed to run python3: {e}"),
    };
    assert!(
        output.status.success(),
        "re/pefmt.py failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut from_pefmt: std::collections::BTreeMap<String, usize> = Default::default();
    for line in String::from_utf8(output.stdout)
        .expect("pefmt's driver prints UTF-8")
        .lines()
    {
        let (library, count) = line.split_once('\t').expect("library\\tcount");
        from_pefmt.insert(
            library.to_string(),
            count.parse().expect("a decimal count"),
        );
    }

    let (_, image) = image().expect("module_path() already confirmed the file is present");
    let mut from_rust: std::collections::BTreeMap<String, usize> = Default::default();
    for i in &image.imports {
        *from_rust.entry(i.library.clone()).or_default() += 1;
    }

    assert_eq!(
        from_rust, from_pefmt,
        "PeImage and re/pefmt.py must agree on the per-library import counts"
    );
}

/// **The falsifying test this whole increment exists for.** A loader with no
/// execution proves nothing: "every relocation landed inside a section" and
/// "every import resolved" are satisfied just as well by a plausibly-wrong
/// image as by a correct one. Only running the module and watching it reach
/// a real host symbol -- rather than a fault, or a return with no calls made
/// at all -- tells the two apart.
///
/// Every import is bound to a thunk (`Import32::Routine`, never `Data`), so
/// whichever symbol `DllMain` reaches first comes back as [`Exit::Call`]
/// naming it, rather than silently succeeding through an address this crate
/// invented. If it instead comes back [`Exit::Fault`], that is still a
/// result: this test reports the linear `eip`, resolves it to a section and
/// an offset, and fails loudly rather than papering over it.
#[test]
fn entering_dllmain_reaches_an_import_rather_than_a_fault() {
    let Some((file, pe)) = image() else { return };

    let mut mapped = Image::load(&file, &pe).expect("the module maps");
    mapped.relocate(&pe).expect("the module relocates");

    let resolver =
        |_library: &str, _symbol: &Symbol| -> Option<Import32> { Some(Import32::Routine) };
    let thunks = mapped.bind_imports(&pe, &resolver);

    let mut machine = Machine::new().expect("a Machine");
    mapped.patch_thunk_addresses(&pe, &thunks, |index| {
        machine.thunk_addr(u16::try_from(index).expect("well under MAX_THUNKS"))
    });

    let entry = mapped.base() + pe.entry_point;
    let hinst_dll = mapped.base();
    // DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved).
    const DLL_PROCESS_ATTACH: u32 = 1;
    let exit = machine
        .call(entry, &[hinst_dll, DLL_PROCESS_ATTACH, 0])
        .expect("a fault is recovered as Exit::Fault, never fatal to this test process");

    match exit {
        Exit::Call { index } => {
            let site = &thunks[usize::from(index)];
            eprintln!(
                "DllMain's first host call: {}:{:?} (thunk {index} of {})",
                site.library,
                site.symbol,
                thunks.len()
            );

            // Printing it is not asserting it. This measurement is the whole
            // point of the increment -- it is what the host port needs and
            // what no amount of static parsing produces -- so it is pinned
            // here rather than left to a line of stderr nobody reads.
            //
            // It is also stable under the obvious next change. Servicing
            // `GetModuleHandleA` instead of stopping at it would let `DllMain`
            // continue to a *second* symbol; the first would still be this
            // one. A different answer here means the entry path changed --
            // relocation, binding, the TIB, or the module -- and that is
            // exactly the regression worth catching.
            assert_eq!(site.library, "KERNEL32.dll");
            assert_eq!(
                site.symbol,
                Symbol::Name("GetModuleHandleA".to_owned()),
                "DllMain's first host call"
            );
        }
        Exit::Fault { signo, eip } => {
            let rva = eip.checked_sub(mapped.base());
            let section = rva.and_then(|rva| {
                pe.sections
                    .iter()
                    .find(|s| rva >= s.rva && rva < s.rva + s.virtual_size)
                    .map(|s| (s.name.clone(), rva - s.rva))
            });
            panic!(
                "DllMain faulted instead of reaching an import: signal {signo} at linear \
                 eip {eip:#010x} (image base {:#010x}, rva {rva:?}, section {section:?})",
                mapped.base(),
            );
        }
        Exit::Returned { eax, edx } => {
            panic!(
                "DllMain returned ({eax:#x}, {edx:#x}) without calling any host import -- \
                 unexpected for a module whose entry point does real startup work"
            );
        }
    }
}
