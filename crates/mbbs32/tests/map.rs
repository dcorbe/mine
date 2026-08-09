//! Memory below 4 GiB, and (once `image.rs` exists) a real image mapped into
//! it.
//!
//! `tests/pe.rs` and `tests/wccmmud.rs` cover parsing -- plain data, no
//! `unsafe`. This covers Part B, where `unsafe` starts: a mapping is real
//! kernel state, so these tests check real kernel state back, not merely that
//! a `Result` came back `Ok`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use mbbs32::{Image, Mapping, PeError, PeImage};

#[test]
fn base_is_non_null_below_4gib_and_page_aligned() {
    let m = Mapping::new(0x1000).expect("a 4 KiB mapping should succeed");
    let base = m.base() as usize;
    assert_ne!(base, 0, "mmap must not hand back a null base");
    assert!(
        base + m.len() <= 0x1_0000_0000,
        "base {base:#x} + len {:#x} must stay below 4 GiB",
        m.len()
    );
    let page = 0x1000;
    assert_eq!(base % page, 0, "mmap always returns a page-aligned base");
}

#[test]
fn writes_read_back() {
    let mut m = Mapping::new(0x2000).expect("a mapping should succeed");
    m.as_mut_slice()[0] = 0xab;
    m.as_mut_slice()[0x1fff] = 0xcd;
    assert_eq!(m.as_slice()[0], 0xab);
    assert_eq!(m.as_slice()[0x1fff], 0xcd);
}

#[test]
fn drop_actually_unmaps() {
    let m = Mapping::new(0x3000).expect("a mapping should succeed");
    let base = m.base();
    let len = m.len();
    drop(m);

    // A second `Mapping::new` of the same size succeeding is not proof that
    // `drop` unmapped anything -- the allocator is free to hand back a
    // different address, or even the same one, for an unrelated reason. Ask
    // the kernel directly whether this exact range is still mapped instead.
    //
    // SAFETY: `base`/`len` name a range that was mapped a moment ago and has
    // just been dropped, so as far as this process is concerned it no longer
    // exists. `msync` only consults the kernel's VMA bookkeeping for the
    // range -- it never reads or writes through the pointer -- so calling it
    // on a range known to be unmapped is exactly the intended, sound use: it
    // is how one *asks* whether a range is mapped without touching the
    // memory behind it.
    let rc = unsafe { libc::msync(base.cast(), len, libc::MS_ASYNC) };
    assert_eq!(rc, -1, "msync must fail once the range is unmapped");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ENOMEM),
        "ENOMEM is msync's documented answer for an unmapped range"
    );
}

/// The real 32-bit MajorMUD module, the same fixture
/// `tests/wccmmud.rs` uses -- see that file for the measured layout these
/// tests depend on. Skips loudly rather than failing when the fixture is
/// absent, matching `crates/mbbs16/tests/wccmmud.rs`.
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

fn loaded() -> Option<(Vec<u8>, PeImage, Image)> {
    let file = std::fs::read(module_path()?).expect("the fixture is readable");
    let image = PeImage::parse(&file).expect("the fixture parses");
    let mapped = Image::load(&file, &image).expect("the fixture maps");
    Some((file, image, mapped))
}

#[test]
fn every_sections_raw_bytes_land_at_its_rva() {
    let Some((file, image, mapped)) = loaded() else {
        return;
    };
    for section in &image.sections {
        let rva = section.rva as usize;
        let raw_offset = section.raw_offset as usize;
        let raw_size = section.raw_size as usize;
        assert_eq!(
            &mapped.as_slice()[rva..rva + raw_size],
            &file[raw_offset..raw_offset + raw_size],
            "section {:?} did not land at its rva",
            section.name
        );
    }
}

#[test]
fn the_bss_tail_arrives_zeroed_and_is_not_the_next_sections_bytes() {
    let Some((file, image, mapped)) = loaded() else {
        return;
    };

    let data = image
        .sections
        .iter()
        .find(|s| s.name == "DATA")
        .expect("the module has a DATA section");
    let idata = image
        .sections
        .iter()
        .find(|s| s.name == ".idata")
        .expect("the module has an .idata section");

    let tail_start = (data.rva + data.raw_size) as usize;
    let tail_end = (data.rva + data.virtual_size) as usize;
    assert_eq!(
        tail_end - tail_start,
        0xc400,
        "DATA's measured BSS tail size"
    );

    let tail = &mapped.as_slice()[tail_start..tail_end];
    assert!(
        tail.iter().all(|&b| b == 0),
        "DATA's BSS tail must arrive zeroed, not carry whatever the file \
         happens to hold past DATA's own raw data"
    );

    // The other half of the same assertion: not merely "zero", but
    // specifically *not* .idata's raw bytes, which is what a `virtual_size`
    // copy would put there -- DATA's raw data on disk ends at exactly the
    // file offset .idata's raw data begins.
    let idata_raw_start = idata.raw_offset as usize;
    let idata_raw_len = (idata.raw_size as usize).min(tail.len());
    assert_ne!(
        &tail[..idata_raw_len],
        &file[idata_raw_start..idata_raw_start + idata_raw_len],
        ".idata's raw bytes must not have landed in DATA's BSS tail"
    );
}

/// The smallest thing that parses, with `IMAGE_FILE_RELOCS_STRIPPED` (0x0001)
/// set in the COFF characteristics and no relocation directory.
///
/// Mirrors `tests/pe.rs`'s `minimal()` byte-for-byte (same MZ/PE/COFF/optional
/// header offsets) but is not shared with it -- `tests/pe.rs` and
/// `tests/map.rs` are separate integration-test binaries with no common
/// module between them, so this is its own small copy rather than a `mod
/// common` neither file currently has a reason to grow.
fn stripped_minimal() -> Vec<u8> {
    let mut v = vec![0u8; 0x200];
    v[0..2].copy_from_slice(b"MZ");
    v[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew
    v[0x80..0x84].copy_from_slice(b"PE\0\0");
    v[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes()); // machine = i386
    v[0x86..0x88].copy_from_slice(&0u16.to_le_bytes()); // 0 sections
    v[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes()); // SizeOfOptionalHeader
    v[0x96..0x98].copy_from_slice(&0x0001u16.to_le_bytes()); // characteristics: RELOCS_STRIPPED
    v[0x98..0x9a].copy_from_slice(&0x010bu16.to_le_bytes()); // PE32 magic

    let opt = 0x98;
    v[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry point
    v[opt + 28..opt + 32].copy_from_slice(&0x4000_0000u32.to_le_bytes()); // image base
    v[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // section alignment
    v[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // file alignment
    v[opt + 56..opt + 60].copy_from_slice(&0x1000u32.to_le_bytes()); // size of image
    v
}

#[test]
fn an_image_that_cannot_be_rebased_is_refused_rather_than_loaded_wrong() {
    // With the image loaded at its own ImageBase, delta is zero and
    // RelocsStripped never has anything to refuse -- see the module doc
    // comment. Loading at its own ImageBase is (separately) still fine:
    // check that too, so this test cannot be satisfied by a `relocate` that
    // simply always errors.
    let stripped = stripped_minimal();
    let mut image = PeImage::parse(&stripped).expect("stripped_minimal parses");
    assert!(!image.rebasable(), "characteristics 0x0001 sets RELOCS_STRIPPED");

    let mut at_own_base = Image::load(&stripped, &image).expect("stripped_minimal maps");
    let mut same_base_image = image.clone();
    same_base_image.image_base = at_own_base.base();
    at_own_base
        .relocate(&same_base_image)
        .expect("delta zero must never be refused, rebasable or not");

    // Now force a base mismatch this test can prove, rather than hope the
    // kernel never hands back the one address `stripped_minimal` claims as
    // its ImageBase (`0x4000_0000`): retarget `image_base` to a value
    // guaranteed different from wherever this second mapping actually
    // landed, using the mapping's own reported base rather than a constant.
    let mut mapped = Image::load(&stripped, &image).expect("stripped_minimal maps");
    image.image_base = mapped.base().wrapping_add(0x1_0000);
    let err = mapped.relocate(&image).unwrap_err();
    assert_eq!(err, PeError::RelocsStripped);
}

#[test]
fn relocation_changes_exactly_the_sites_the_directory_names() {
    // Load the real module (which will not land at its own ImageBase --
    // Mapping::new never asks mmap for a specific address), snapshot the
    // mapped bytes before relocating, relocate, then check two things byte
    // by byte -- not 4-byte-aligned words. wccmmud.dll's relocation sites are
    // x86 instruction immediates, not aligned pointer slots: 9,999 of its
    // 13,920 relocations have an rva that is not a multiple of 4, so a scan
    // that only ever looks at aligned words would see two neighbouring
    // aligned words each change by *half* of one unaligned site's delta and
    // (wrongly) fail them both. The assertion with teeth is not "N bytes
    // changed" -- a loader that relocated the wrong N bytes would pass that
    // too -- it is two-sided: every named site's own word changed by exactly
    // delta (below), AND every byte NOT covered by any named site's 4-byte
    // window is bit-for-bit unchanged (further below). The second half is
    // deliberately not "every byte inside a window changed": adding `delta`
    // to a word is free to leave any of its 4 bytes unchanged (no carry in,
    // and delta's own byte there is 0), which is exactly what most of these
    // 13,920 real sites do.
    let Some((_file, image, mut mapped)) = loaded() else {
        return;
    };

    let mut rvas: Vec<u32> = image.relocations.iter().map(|r| r.rva).collect();
    rvas.sort_unstable();
    rvas.dedup_by(|a, b| {
        // Two relocation sites closer together than 4 bytes would overlap in
        // the mapping, and this test's per-site check below (each site's
        // *own* before/after words differ by exactly delta) assumes the
        // sites are independent -- an overlap would mean the order
        // `Image::relocate` happens to apply them in changes what an
        // "earlier" site's own before/after diff even measures. Confirmed
        // absent (13,920 unique, sorted rvas, zero adjacent pair closer than
        // 4 apart) by inspection; `dedup_by` marking any pair less than 4
        // apart as a duplicate turns that inspection into an assertion
        // instead of a silent assumption.
        b.abs_diff(*a) < 4
    });
    assert_eq!(
        rvas.len(),
        image.relocations.len(),
        "wccmmud.dll's relocation sites must be distinct and non-overlapping \
         for this test's per-site before/after check to mean anything"
    );

    let before = mapped.as_slice().to_vec();
    mapped.relocate(&image).expect("wccmmud.dll is rebasable");
    let after = mapped.as_slice();

    let delta = mapped.base().wrapping_sub(image.image_base);
    assert_ne!(
        delta, 0,
        "this fixture must load away from its own ImageBase for the rest of \
         this test to prove anything -- see the module doc's warning"
    );

    let mut expected_bytes = BTreeSet::new();
    for reloc in &image.relocations {
        let rva = reloc.rva as usize;
        let old = u32::from_le_bytes(before[rva..rva + 4].try_into().unwrap());
        let new = u32::from_le_bytes(after[rva..rva + 4].try_into().unwrap());
        assert_eq!(
            new,
            old.wrapping_add(delta),
            "word at relocation rva {rva:#x} changed by something other than delta"
        );
        expected_bytes.extend(rva as u32..rva as u32 + 4);
    }

    // The converse of the per-site check above: nothing OUTSIDE a named
    // window may have changed. This is deliberately not "every byte inside a
    // window changed" -- `word.wrapping_add(delta)` is free to leave any of
    // the 4 individual bytes unchanged (no carry into that byte, and delta's
    // own byte there is 0), which is exactly what the real module's data
    // does for most of its 13,920 sites. So the only sound byte-level claim
    // is on the complement: every byte NOT covered by any relocation window
    // must be bit-for-bit identical before and after.
    for i in 0..before.len() as u32 {
        if expected_bytes.contains(&i) {
            continue;
        }
        assert_eq!(
            before[i as usize], after[i as usize],
            "byte at rva {i:#x} changed even though no relocation names it"
        );
    }
    assert_eq!(
        image.relocations.len(),
        13_920,
        "wccmmud.dll's measured relocation count"
    );
}
