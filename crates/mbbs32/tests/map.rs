//! Memory below 4 GiB, and (once `image.rs` exists) a real image mapped into
//! it.
//!
//! `tests/pe.rs` and `tests/wccmmud.rs` cover parsing -- plain data, no
//! `unsafe`. This covers Part B, where `unsafe` starts: a mapping is real
//! kernel state, so these tests check real kernel state back, not merely that
//! a `Result` came back `Ok`.

use std::path::{Path, PathBuf};

use mbbs32::{Image, Mapping, PeImage};

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
