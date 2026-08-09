//! Memory below 4 GiB, and (once `image.rs` exists) a real image mapped into
//! it.
//!
//! `tests/pe.rs` and `tests/wccmmud.rs` cover parsing -- plain data, no
//! `unsafe`. This covers Part B, where `unsafe` starts: a mapping is real
//! kernel state, so these tests check real kernel state back, not merely that
//! a `Result` came back `Ok`.

use mbbs32::Mapping;

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
