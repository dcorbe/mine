//! One export slot, two names: what the host may serve from two bodies.
//!
//! # The bug this exists for
//!
//! On 2026-08-19 a `getmsgblk` shim was written as a *new body* -- a third
//! transcription of something `msg::rawmsg` and `mlt::getmsg` already shared
//! byte for byte. Nothing objected, because it was registered under a name no
//! other registration claimed. `da891421` had already deleted twenty dead twins
//! from this crate and `6d8af77` a duplicate registration, so it is a recurring
//! failure, and every instrument in the tree was blind to it.
//!
//! The witness was sitting in the vendor tree unread. A real import library
//! numbers each export once, so two names at one ordinal in one ordinal space
//! are one export slot -- and the host cannot serve one slot two different ways
//! without the two answers being able to disagree.
//!
//! # The ordinal space, and the trap in it
//!
//! `re/ordinal-renames.tsv` holds two comparisons, both **within a single
//! numbering**. First, the MAJORBBS space as numbered by MAJORBBS (wg2) against
//! the same space as numbered by the wg2-era `WGSERVER` import library: those
//! two really are one numbering -- `__WRITE` is `@48` in both -- and 38 slots
//! differ. Second, the MAJORBBS generations against each other, where six more
//! do: `free`/`galfree` at `@230`, `malloc`/`galmalloc` at `@400`,
//! `bgnedt`/`oldbgnedt` at `@88` and three others.
//!
//! That second set is the same four ordinals `Host::load` reports as
//! `AmbiguousProfile` when two admissible generations disagree, plus two more.
//! The discriminator list and the rename list are one dataset seen from two
//! directions, and only one of them was being read.
//!
//! The committed `wgserver_wg300`/`wg312`/`wg33` tables are a **different**
//! space and must never be merged with these: `@48` is `_FFLUSH` there and
//! `@326` is `_CHOOWD`. An earlier draft of this file unioned
//! `WGSERVER_TABLES` into MAJORBBS on the assumption they shared a numbering
//! and reported nonsense -- `_write` and `fflush` as "the same export" -- which
//! is what `library.rs` already warns about for `GALETL`, whose `@36` is
//! `_TL2LST` in one build and `___TLCACT` in another. Same-ordinal means
//! same-export only *within* one numbering.
//!
//! # What the 38 turned out to be
//!
//! Thirty of them are the `btv*` family against the `dfa*` family at identical
//! ordinals: `delbtv`/`dfadelete` at `@162`, `qrybtv`/`dfaquery` at `@485`,
//! `stpbtvl`/`dfasteplock` at `@1101`, and so on. `qrybtv` and `delbtv` appear
//! in no wg33 header at all -- the vendor replaced the `btv*` export names with
//! `dfa*` ones in the same slots.
//!
//! This host implements both families separately (`shims::btrieve`,
//! `shims::dfa`), and `ce64fbbe` is what that costs: `dfaDelete` and `delbtv`
//! both delete the positioned record, and only one of them invalidated the
//! cursor afterwards. A second `dfaDelete` then acted on a freed position.
//!
//! # So this is a pin, not a prohibition
//!
//! Demanding one body per slot today would fail on thirty pairs and demand a
//! rewrite of two large modules. [`SPLIT_BODIES`] enumerates the pairs the host
//! currently serves from two bodies, so they are visible and countable instead
//! of invisible, and the list may only shrink. A new pair cannot be added
//! without saying so here, which is exactly what `getmsgblk` did silently.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use mbbs::abi::Wg16;
use mbbs::shims::{Entry, entry};

/// Ordinal slots the host serves from two different bodies today.
///
/// `(library, ordinal)`. **May only shrink.** Each entry is one export the
/// vendor numbered once and this host answers twice, so the two answers can
/// drift -- and `ce64fbbe` is the drift already found, at `@162`.
///
/// Thirty of these are the `btv*`/`dfa*` rename. Collapsing a pair means one
/// name registering against the other's body, the way `getmsgblk` now
/// registers against `mlt::getmsg`; where the two genuinely take different
/// arguments, it means both funnelling into one shared core, which
/// `shims::btrieve`'s `pub(crate)` helpers already do for part of the family.
const SPLIT_BODIES: &[(&str, u16)] = &[
    // `@51` (aabbtv/dfaacqabs) and `@313` (gabbtv/dfagetabs) are deliberately
    // absent: the host registers the `btv*` name but not the `dfa*` one at
    // those two slots, so there is only one body and nothing to disagree.
    // `dfaacqabslock` and `dfagetabslock` are different routines at `@1100`
    // and `@999`.
    ("MAJORBBS", 53),   // absbtv / dfaabs
    ("MAJORBBS", 117),  // clsbtv / dfaclose
    ("MAJORBBS", 133),  // cntrbtv / dfacountrec
    ("MAJORBBS", 144),  // crtbtv / dfacreate
    ("MAJORBBS", 162),  // delbtv / dfadelete -- the pair that drifted
    ("MAJORBBS", 170),  // dinsbtv / dfainsertdup
    ("MAJORBBS", 180),  // dupdbtv / dfaupdatedup
    ("MAJORBBS", 351),  // insbtv / dfainsert
    ("MAJORBBS", 357),  // invbtv / dfainsertv
    ("MAJORBBS", 388),  // llnbtv / dfalastlen
    ("MAJORBBS", 447),  // omdbtv / dfamode
    ("MAJORBBS", 455),  // opnbtv / dfaopen
    ("MAJORBBS", 484),  // qnpbtv / dfaquerynp
    ("MAJORBBS", 485),  // qrybtv / dfaquery
    ("MAJORBBS", 505),  // rstbtv / dfarstblk
    ("MAJORBBS", 534),  // setbtv / dfasetblk
    ("MAJORBBS", 588),  // sttbtv / dfastat
    ("MAJORBBS", 621),  // updbtv / dfaupdate
    ("MAJORBBS", 622),  // upvbtv / dfaupdatev
    ("MAJORBBS", 904),  // rlenbtv / dfareclen
    ("MAJORBBS", 996),  // getbtvl / dfagetlock
    ("MAJORBBS", 997),  // obtbtvl / dfaacqlock
    ("MAJORBBS", 998),  // anpbtvlk / dfaacqnplock
    ("MAJORBBS", 999),  // gabbtvl / dfagetabslock
    ("MAJORBBS", 1100), // aabbtvl / dfaacqabslock
    ("MAJORBBS", 1101), // stpbtvl / dfasteplock
    ("MAJORBBS", 1102), // unlbtv / dfaunlock
    ("MAJORBBS", 1103), // wslbtv / dfawaslocked
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `(library, ordinal, majorbbs_name, wgserver_name)` from the committed table.
fn renames() -> Vec<(String, u16, String, String)> {
    let path = repo_root().join("re/ordinal-renames.tsv");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{} is committed: {e}", path.display()));
    let mut out = Vec::new();
    for line in text.lines() {
        if line.starts_with('#') || line.is_empty() || line.starts_with("library\t") {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        assert_eq!(
            f.len(),
            5,
            "every row is library/ordinal/name/name/source: {line:?}"
        );
        out.push((
            f[0].to_owned(),
            f[1].parse().expect("ordinal is a number"),
            f[2].to_owned(),
            f[3].to_owned(),
        ));
    }
    assert!(
        out.len() > 30,
        "re/ordinal-renames.tsv parsed to {} rows, too few to be the derived \
         table -- did its format change?",
        out.len()
    );
    out
}

/// Every slot where the host registers both names, partitioned by whether the
/// two resolve to one body.
fn both_registered() -> (BTreeSet<(String, u16)>, Vec<String>) {
    let mut shared = BTreeSet::new();
    let mut split = Vec::new();
    for (lib, ordinal, a, b) in renames() {
        let (Entry::Routine(fa, _), Entry::Routine(fb, _)) =
            (entry::<Wg16>(&lib, &a), entry::<Wg16>(&lib, &b))
        else {
            continue; // only one side registered: nothing can disagree yet
        };
        if std::ptr::fn_addr_eq(fa, fb) {
            shared.insert((lib, ordinal));
        } else {
            split.push(format!("{lib} @{ordinal}: `{a}` and `{b}`"));
        }
    }
    (shared, split)
}

/// The pin: exactly the slots served from two bodies, and no new ones.
#[test]
fn no_new_export_slot_gains_a_second_body() {
    let (_, split) = both_registered();
    let actual: BTreeSet<(String, u16)> = split
        .iter()
        .map(|s| {
            let (lib, rest) = s.split_once(" @").expect("formatted above");
            let ordinal = rest.split(':').next().unwrap().parse().expect("ordinal");
            (lib.to_owned(), ordinal)
        })
        .collect();
    let expected: BTreeSet<(String, u16)> = SPLIT_BODIES
        .iter()
        .map(|(l, o)| ((*l).to_owned(), *o))
        .collect();

    let gained: Vec<_> = actual.difference(&expected).collect();
    assert!(
        gained.is_empty(),
        "an export slot the vendor numbered once is now served by two \
         different bodies in this host, and two bodies can drift -- `ce64fbbe` \
         is the drift already found. Register one name against the other's \
         body (see `getmsgblk` in shims::mod), or funnel both into one shared \
         core:\n{gained:#?}\nall split slots:\n{}",
        split.join("\n"),
    );

    let closed: Vec<_> = expected.difference(&actual).collect();
    assert!(
        closed.is_empty(),
        "these slots no longer have two bodies -- remove them from \
         SPLIT_BODIES, which may only shrink:\n{closed:#?}",
    );
}

/// The rename that started this, closed: `getmsg` and `getmsgblk` are `@326`
/// in the same numbering and now resolve to one function.
///
/// Named separately so the pin above cannot pass by comparing nothing, and
/// asserted by address rather than behaviour -- two bodies that agree today
/// pass a behavioural check and then drift.
#[test]
fn the_getmsg_rename_is_one_body() {
    let at = renames()
        .into_iter()
        .find(|(_, _, a, b)| a == "getmsg" && b == "getmsgblk")
        .expect("re/ordinal-renames.tsv carries the getmsg/getmsgblk slot");
    assert_eq!(at.1, 326, "GCOMM.H's renamed message routine is ordinal 326");

    let (Entry::Routine(a, _), Entry::Routine(b, _)) = (
        entry::<Wg16>("MAJORBBS", "getmsg"),
        entry::<Wg16>("MAJORBBS", "getmsgblk"),
    ) else {
        panic!("both names resolve");
    };
    assert!(std::ptr::fn_addr_eq(a, b), "one export slot, one body");
}
