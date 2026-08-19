//! The measured relationships between GALGSBL's generations. These are the
//! properties the detection in Plan 2 rests on, so they are pinned here.

use mbbs_machine::library::{GALGSBL_TABLES, MAJORBBS_TABLES, OrdinalTable};

fn table(tables: &[&'static OrdinalTable], generation: &str) -> &'static OrdinalTable {
    tables
        .iter()
        .copied()
        .find(|t| t.generation == generation)
        .unwrap_or_else(|| panic!("no {generation} table"))
}

#[test]
fn every_table_is_the_size_the_source_exports() {
    assert_eq!(table(GALGSBL_TABLES, "mbbs625").len(), 100);
    assert_eq!(table(GALGSBL_TABLES, "wg101").len(), 101);
    assert_eq!(table(GALGSBL_TABLES, "wg2").len(), 102);
    assert_eq!(table(GALGSBL_TABLES, "wg3-16").len(), 102);
    assert_eq!(table(GALGSBL_TABLES, "layout-c").len(), 86);
    assert_eq!(table(MAJORBBS_TABLES, "mbbs625").len(), 992);
}

/// Layout A is purely additive: MBBS 6.x, WG 1.01 and WG 2.x never move an
/// ordinal. This is the property that makes an unobservable choice between
/// them safe, so it is asserted rather than assumed.
#[test]
fn layout_a_is_additive_and_moves_no_ordinal() {
    let a = table(GALGSBL_TABLES, "mbbs625").names();
    let b = table(GALGSBL_TABLES, "wg101").names();
    let c = table(GALGSBL_TABLES, "wg2").names();
    for (ord, name) in &a {
        assert_eq!(b.get(ord), Some(name), "wg101 moved ordinal {ord}");
    }
    for (ord, name) in &b {
        assert_eq!(c.get(ord), Some(name), "wg2 moved ordinal {ord}");
    }
    assert_eq!(b.len() - a.len(), 1, "wg101 adds exactly btuicx@101");
    assert_eq!(c.len() - b.len(), 1, "wg2 adds exactly cdixfn@102");
    assert_eq!(b.get(&101).map(AsRef::as_ref), Some("btuicx"));
    assert_eq!(c.get(&102).map(AsRef::as_ref), Some("cdixfn"));
}

/// WG 3.x renumbers 38 of 102 ordinals without changing a single name, and
/// ordinal 72 is the one that matters: `bturno` reads the board's registration
/// number, `btuhit` does not.
#[test]
fn wg3_renumbers_without_renaming_and_ordinal_72_changes_meaning() {
    let a = table(GALGSBL_TABLES, "wg2").names();
    let b = table(GALGSBL_TABLES, "wg3-16").names();
    let a_names: std::collections::BTreeSet<_> = a.values().cloned().collect();
    let b_names: std::collections::BTreeSet<_> = b.values().cloned().collect();
    assert_eq!(a_names, b_names, "WG 3.x renumbers, it does not rename");

    let moved = a.iter().filter(|(o, n)| b.get(o) != Some(n)).count();
    assert_eq!(moved, 38, "38 of 102 ordinals move");

    assert_eq!(a.get(&72).map(AsRef::as_ref), Some("bturno"));
    assert_eq!(b.get(&72).map(AsRef::as_ref), Some("btuhit"));
}

/// Layout C drops the hardware surface and converts two data exports into
/// functions. Ordinal 87 does not exist in it at all, which is what rules it
/// out for a board whose modules import 87.
#[test]
fn layout_c_drops_the_hardware_surface() {
    let c = table(GALGSBL_TABLES, "layout-c").names();
    for gone in ["x25udt", "x25heap", "x25ign", "lanrev", "lansop", "lansca", "ticker", "btuhrt"] {
        assert!(!c.values().any(|n| &**n == gone), "{gone} must not be in layout C");
    }
    assert!(c.values().any(|n| &**n == "btuticker"), "ticker became btuTicker()");
    assert!(c.values().any(|n| &**n == "hrtval"), "btuhrt became hrtval()");
    assert_eq!(c.get(&87), None, "ordinal 87 is absent, which is what excludes layout C");
}
