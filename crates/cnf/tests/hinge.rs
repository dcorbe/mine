use cnf::hinge::{parse, visible, Hinge, HingeOp};

fn values<'a>(pairs: &'a [(&'a [u8], &'a [u8])]) -> impl Fn(&[u8]) -> Option<Vec<u8>> + 'a {
    move |name| pairs.iter().find(|(n, _)| *n == name).map(|(_, v)| v.to_vec())
}

#[test]
fn an_equals_hinge_parses_with_its_value_list() {
    let (h, rest) = parse(b"B (MODE=FULL,LITE)");
    assert_eq!(
        h,
        Some(Hinge {
            on: b"MODE".to_vec(),
            op: HingeOp::Eq,
            values: vec![b"FULL".to_vec(), b"LITE".to_vec()],
        })
    );
    assert_eq!(rest, b"B ", "the hinge is removed from the tail");
}

#[test]
fn a_not_equals_hinge_parses() {
    let (h, _) = parse(b"B (MODE#OFF)");
    assert_eq!(h.expect("hinge").op, HingeOp::Ne);
}

#[test]
fn the_exclude_always_hinge_parses() {
    // `(UNUSED*)` is how the corpus marks an option that is never shown.
    let (h, _) = parse(b"B (UNUSED*)");
    assert_eq!(h.expect("hinge").op, HingeOp::ExcludeAlways);
}

#[test]
fn no_hinge_leaves_the_tail_alone() {
    let (h, rest) = parse(b"N 0 32767");
    assert_eq!(h, None);
    assert_eq!(rest, b"N 0 32767");
}

#[test]
fn an_equals_hinge_shows_only_on_a_listed_value() {
    let h = Hinge { on: b"MODE".to_vec(), op: HingeOp::Eq, values: vec![b"FULL".to_vec()] };
    assert!(visible(Some(&h), &values(&[(b"MODE", b"FULL")])));
    assert!(!visible(Some(&h), &values(&[(b"MODE", b"LITE")])));
}

#[test]
fn a_not_equals_hinge_hides_only_on_a_listed_value() {
    let h = Hinge { on: b"MODE".to_vec(), op: HingeOp::Ne, values: vec![b"OFF".to_vec()] };
    assert!(!visible(Some(&h), &values(&[(b"MODE", b"OFF")])));
    assert!(visible(Some(&h), &values(&[(b"MODE", b"ON")])));
}

#[test]
fn exclude_always_is_never_visible_and_no_hinge_always_is() {
    let h = Hinge { on: b"UNUSED".to_vec(), op: HingeOp::ExcludeAlways, values: vec![] };
    assert!(!visible(Some(&h), &values(&[])));
    assert!(visible(None, &values(&[])));
}

#[test]
fn a_hinge_on_an_unknown_option_shows_rather_than_hides() {
    // Hiding an option the sysop cannot then find is worse than showing one
    // that does not apply: an invisible option cannot be diagnosed.
    let h = Hinge { on: b"NOSUCH".to_vec(), op: HingeOp::Eq, values: vec![b"X".to_vec()] };
    assert!(visible(Some(&h), &values(&[])));
}
