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
//! `tests/data/api-renames.tsv` holds two comparisons, both **within a single
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
/// The name pair, as `tests/data/api-renames.tsv` spells it. **May only shrink.** Each entry is one export the
/// vendor numbered once and this host answers twice, so the two answers can
/// drift -- and `ce64fbbe` is the drift already found, at `@162`.
///
/// Thirty of these are the `btv*`/`dfa*` rename. Collapsing a pair means one
/// name registering against the other's body, the way `getmsgblk` now
/// registers against `mlt::getmsg`; where the two genuinely take different
/// arguments, it means both funnelling into one shared core, which
/// `shims::btrieve`'s `pub(crate)` helpers already do for part of the family.
const SPLIT_BODIES: &[(&str, &str)] = &[
    ("aabbtvl", "dfaacqabslock"),
    ("absbtv", "dfaabs"),
    ("anpbtvlk", "dfaacqnplock"),
    ("clsbtv", "dfaclose"),
    ("cntrbtv", "dfacountrec"),
    ("crtbtv", "dfacreate"),
    ("delbtv", "dfadelete"),
    ("dinsbtv", "dfainsertdup"),
    ("dupdbtv", "dfaupdatedup"),
    ("gabbtvl", "dfagetabslock"),
    ("getbtvl", "dfagetlock"),
    ("insbtv", "dfainsert"),
    ("invbtv", "dfainsertv"),
    ("llnbtv", "dfalastlen"),
    ("obtbtvl", "dfaacqlock"),
    ("omdbtv", "dfamode"),
    ("opnbtv", "dfaopen"),
    ("qnpbtv", "dfaquerynp"),
    ("qrybtv", "dfaquery"),
    ("rlenbtv", "dfareclen"),
    ("rstbtv", "dfarstblk"),
    ("setbtv", "dfasetblk"),
    ("stpbtvl", "dfasteplock"),
    ("sttbtv", "dfastat"),
    ("unlbtv", "dfaunlock"),
    ("updbtv", "dfaupdate"),
    ("upvbtv", "dfaupdatev"),
    ("wslbtv", "dfawaslocked"),
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `(library, name_a, name_b)` from the committed table.
///
/// The ordinal column is read past deliberately. Most of `GALPORT.C`'s pairs
/// have no slot of their own -- they are macros over the ordinal-exported
/// primitives -- so keying this on an ordinal would drop the majority of the
/// vendor's own map.
fn renames() -> Vec<(String, String, String)> {
    let path = repo_root().join("crates/mbbs/tests/data/api-renames.tsv");
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
            "every row is library/name_a/name_b/ordinal/source: {line:?}"
        );
        out.push((f[0].to_owned(), f[1].to_owned(), f[2].to_owned()));
    }
    assert!(
        out.len() > 60,
        "tests/data/api-renames.tsv parsed to {} rows, too few to be the vendor's own \
         map (67 GALPORT.C pairs alone) -- did its format change?",
        out.len()
    );
    out
}

/// Every slot where the host registers both names, partitioned by whether the
/// two resolve to one body.
fn both_registered() -> (BTreeSet<(String, String)>, BTreeSet<(String, String)>) {
    let mut shared = BTreeSet::new();
    let mut split = BTreeSet::new();
    for (lib, a, b) in renames() {
        let (Entry::Routine(fa, _), Entry::Routine(fb, _)) =
            (entry::<Wg16>(&lib, &a), entry::<Wg16>(&lib, &b))
        else {
            continue; // only one side registered: nothing can disagree yet
        };
        let _ = lib;
        if std::ptr::fn_addr_eq(fa, fb) {
            shared.insert((a, b));
        } else {
            split.insert((a, b));
        }
    }
    (shared, split)
}

/// The pin: exactly the pairs whose registered wrappers differ, and no new ones.
///
/// **What this measures, precisely.** Two *registered functions*, not two
/// implementations. A pair that shares a `pub(crate)` core and differs only in
/// how it finds its block still shows up here, and that is fine -- ten of the
/// 28 already reach a common core (`dfa.rs` calls `btv::locate` nine times,
/// `btv::update_variable` six, `btv::delbtv` five). Wrapper identity is a
/// proxy, and the property that actually matters is that neither name carries
/// its own copy of the decision.
///
/// So do not read a shrinking count as the goal. The goal is that every pair
/// with real logic funnels into one core, which is what `insert_record` and
/// `delete_record` did for the insert and delete families. What this pin
/// guarantees is narrower and still worth having: a NEW pair cannot appear
/// without somebody writing it down, and `getmsgblk` appeared silently.
#[test]
fn no_new_pair_gains_a_second_body() {
    let (_, actual) = both_registered();
    let expected: BTreeSet<(String, String)> = SPLIT_BODIES
        .iter()
        .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
        .collect();

    let gained: Vec<_> = actual.difference(&expected).collect();
    assert!(
        gained.is_empty(),
        "a routine the vendor renamed is now served by two different \
         registered bodies in this host, and two bodies can drift -- \
         `ce64fbbe` (dfaDelete's cursor) and `f0f40187` (invbtv's stale \
         refusal) are the two that already did. Give one name the other's \
         body, or funnel both into one `pub(crate)` core:\n{gained:#?}",
    );

    let closed: Vec<_> = expected.difference(&actual).collect();
    assert!(
        closed.is_empty(),
        "these pairs no longer have two registered bodies -- remove them from \
         SPLIT_BODIES, which may only shrink:\n{closed:#?}",
    );
}

/// The rename that started this, closed: `getmsg` and `getmsgblk` resolve to
/// one function.
///
/// Named separately so the pin above cannot pass by comparing nothing, and
/// asserted by address rather than behaviour -- two bodies that agree today
/// pass a behavioural check and then drift.
#[test]
fn the_getmsg_rename_is_one_body() {
    assert!(
        renames()
            .iter()
            .any(|(_, a, b)| a == "getmsg" && b == "getmsgblk"),
        "tests/data/api-renames.tsv carries the getmsg/getmsgblk pair"
    );

    let (Entry::Routine(a, _), Entry::Routine(b, _)) = (
        entry::<Wg16>("MAJORBBS", "getmsg"),
        entry::<Wg16>("MAJORBBS", "getmsgblk"),
    ) else {
        panic!("both names resolve");
    };
    assert!(std::ptr::fn_addr_eq(a, b), "one export, one body");
}
