//! The real 32-bit MajorMUD module, parsed.
//!
//! Every number here was measured from this exact file before the parser was
//! written, and is recorded in `docs/plans/2026-08-08-mbbs32-design.md`. A test
//! that disagrees with one of them is reporting a real difference: change the
//! code, or re-measure and change both -- never quietly relax the assertion.

use std::path::{Path, PathBuf};

use mbbs32::{PeImage, Symbol};

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
