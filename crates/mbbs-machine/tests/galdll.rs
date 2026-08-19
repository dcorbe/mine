//! `galdll` writes the same synthesised NE image `runexe` serves in memory,
//! to a file for a consumer outside this process.

#[path = "../src/bin/galdll.rs"]
mod galdll;

/// The durable exit refuses on ambiguity, because the emitted table is a
/// SUPERSET of any demand: wg101 and wg2 agree on every ordinal this board's
/// modules import and still differ at @102 (`cdixfn`, wg2 only). A file
/// outlives the run and another consumer may read exactly that ordinal.
#[test]
fn ambiguous_detection_refuses_and_names_the_candidates() {
    let err = galdll::choose(&["wg101", "wg2"], None).expect_err("must refuse");
    assert!(err.contains("wg101") && err.contains("wg2"), "{err}");
    assert!(err.contains("--family"), "the refusal must say how to resolve it: {err}");
}

/// An explicit family settles it.
#[test]
fn an_explicit_family_overrides_ambiguity() {
    assert_eq!(galdll::choose(&["wg101", "wg2"], Some("wg2")).expect("resolves"), "wg2");
}

/// And an override that is not among the candidates is refused, not honoured.
#[test]
fn an_override_outside_the_candidates_refuses() {
    assert!(galdll::choose(&["wg101", "wg2"], Some("wg3-16")).is_err());
}
