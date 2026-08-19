//! runexe serves host libraries the guest asks the filesystem for.

/// Eight digits, validated rather than truncated: GETRNO reads exactly eight
/// bytes after the marker, so a short value would silently mean a different
/// serial than the operator typed.
#[test]
fn a_bturno_must_be_exactly_eight_digits() {
    assert!(dos_runtime::host_library::parse_bturno("00000000").is_ok());
    assert!(dos_runtime::host_library::parse_bturno("1234567").is_err(), "seven is not eight");
    assert!(dos_runtime::host_library::parse_bturno("123456789").is_err(), "nine is not eight");
    assert!(dos_runtime::host_library::parse_bturno("0000000x").is_err(), "not a digit");
}

/// The emitted GALGSBL carries the serial where a linear scan finds it, and
/// the anchor generation's export count.
#[test]
fn the_galgsbl_blob_carries_the_serial_and_the_anchor_table() {
    let bytes = dos_runtime::host_library::galgsbl(None, "00000000").expect("anchor builds");
    assert!(
        bytes.windows(4).any(|w| w == b"ReG#"),
        "GETRNO scans linearly for this marker"
    );
    // The plan's test text names `mbbs_machine::m16::ne::NeImage` but `ne` is
    // a private module (`mod ne;` in m16/mod.rs) -- only its types are
    // re-exported, at `m16::NeImage` directly. See the Task 3 report for
    // this mismatch.
    let image = mbbs_machine::m16::NeImage::parse(&bytes).expect("parses");
    let exported = image.entries.iter().filter(|e| e.as_ref().is_some_and(|x| x.exported)).count();
    assert_eq!(exported, 101, "wg101 is the anchor and exports 101 ordinals");
}

/// An unknown family refuses rather than falling back to the anchor.
#[test]
fn an_unknown_family_refuses() {
    assert!(dos_runtime::host_library::galgsbl(Some("nosuch"), "00000000").is_err());
}
