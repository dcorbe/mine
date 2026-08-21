//! The criterion the rebuild is scored against.
//!
//! For every corpus file: read it into a model, emit bytes from that model
//! alone, and compare. The count that survives is pinned in
//! `tests/data/roundtrip-pin.txt` and may only go up.
//!
//! # Why a ratchet rather than "all files pass"
//!
//! All 652 passing is the finish line, not the starting line. A pin that only
//! grows turns a long build into a monotone measurement: every task either
//! raises it or does not, and a regression is a failure rather than a number
//! someone edits down.
//!
//! # Why this cannot be faked
//!
//! `emit::file` takes the model and nothing else -- it has no access to the
//! bytes `read::file` was given, so byte-identity cannot be reached by copying.
//! That is a property of the signature, not a convention.

use btrieve::canvas::Emitted;
use btrieve::{corpus, emit, read};

/// Describe a mismatch between emitted bytes and the original file: the
/// first differing byte, and which field owns it. Extracted from the round
/// trip's per-file loop so the rendering can be exercised directly, on a
/// deliberate mismatch, rather than waiting for the corpus to produce one --
/// see `a_mismatch_names_the_field_that_owns_the_differing_byte` below.
fn describe_mismatch(emitted: &Emitted, original: &[u8]) -> String {
    let produced = emitted.bytes();
    let at = produced
        .iter()
        .zip(original.iter())
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| produced.len().min(original.len()));
    let owner = match emitted.owner_of(at) {
        Some(owner) => format!("owned by {}", owner.label()),
        None => "but no field claims that byte".to_string(),
    };
    format!(
        "first difference at byte {at:#x}, {owner} \
         (produced {} bytes, original {})",
        produced.len(),
        original.len()
    )
}

/// The committed count. Raise it when a task makes more files round-trip;
/// never lower it.
fn pin() -> usize {
    include_str!("data/roundtrip-pin.txt")
        .trim()
        .parse()
        .expect("the pin is a decimal count")
}

#[test]
fn the_round_trip_count_only_grows() {
    let files = corpus::walk();
    if files.is_empty() {
        eprintln!(
            "roundtrip: no archive/ on this box, nothing verified -- this is \
             expected in a fresh checkout and proves nothing either way"
        );
        return;
    }

    // Four distinct failure classes, each reported under its own heading.
    // Collapsing an emit fault into a byte mismatch would print "first
    // difference at byte 0x0" for every corpus file and bury the real
    // diagnostic -- an emit fault is a new failure class the harness did not
    // previously have an arm for.
    let mut passing = 0usize;
    let mut unreadable = 0usize;
    let mut refused = 0usize;
    let mut mismatched = 0usize;
    let mut faulted = 0usize;
    let mut unreadable_faults: Vec<String> = Vec::new();
    let mut refused_faults: Vec<String> = Vec::new();
    let mut mismatched_faults: Vec<String> = Vec::new();
    let mut faulted_faults: Vec<String> = Vec::new();
    for entry in &files {
        let original = match std::fs::read(&entry.path) {
            Ok(original) => original,
            Err(e) => {
                unreadable += 1;
                if unreadable_faults.len() < 10 {
                    unreadable_faults.push(format!(
                        "  {} ({:?}): could not read the file at all: {}",
                        entry.path.display(),
                        entry.id.generation,
                        e
                    ));
                }
                continue;
            }
        };
        match read::file(&original) {
            Ok(model) => match emit::file(&model) {
                Ok(emitted) => {
                    let produced = emitted.bytes();
                    if produced == original.as_slice() {
                        passing += 1;
                    } else {
                        mismatched += 1;
                        if mismatched_faults.len() < 10 {
                            mismatched_faults.push(format!(
                                "  {} ({:?}): {}",
                                entry.path.display(),
                                entry.id.generation,
                                describe_mismatch(&emitted, &original)
                            ));
                        }
                    }
                }
                Err(e) => {
                    faulted += 1;
                    if faulted_faults.len() < 10 {
                        faulted_faults.push(format!(
                            "  {} ({:?}): emit faulted: {}",
                            entry.path.display(),
                            entry.id.generation,
                            e
                        ));
                    }
                }
            },
            Err(e) => {
                refused += 1;
                if refused_faults.len() < 10 {
                    refused_faults.push(format!(
                        "  {} ({:?}): read refused: {}",
                        entry.path.display(),
                        entry.id.generation,
                        e.why
                    ));
                }
            }
        }
    }

    println!(
        "round trip: {passing} of {} corpus files ({unreadable} unreadable, \
         {refused} refused, {mismatched} mismatched, {faulted} faulted)",
        files.len()
    );
    let pin = pin();
    assert!(
        passing >= pin,
        "round trip regressed: {passing} files now, pin says {pin}.\n\
         The pin may only grow.\n\
         Unreadable ({unreadable}):\n{}\n\
         Refused ({refused}):\n{}\n\
         Mismatched ({mismatched}):\n{}\n\
         Faulted ({faulted}):\n{}",
        unreadable_faults.join("\n"),
        refused_faults.join("\n"),
        mismatched_faults.join("\n"),
        faulted_faults.join("\n"),
    );
    if passing > pin {
        println!(
            "round trip improved: raise tests/data/roundtrip-pin.txt from \
             {pin} to {passing}"
        );
    }
}

/// A run that verified nothing must not look like success.
#[test]
fn the_harness_reports_whether_it_verified_anything() {
    let files = corpus::walk();
    if corpus::root().is_some() {
        assert!(
            !files.is_empty(),
            "archive/ is present but the walk found no Btrieve files, so this \
             suite would verify nothing while appearing to pass"
        );
    }
}

/// Task 20's own honest tripwire.
///
/// The v6 free list is established by the round trip (harvest 5 SS2.2's
/// per-slot shape is exercised by every one of the 337+ v6 corpus files that
/// pass). The v6 **variable-length/fragment path is not** -- harvest 5
/// SS4.3 measured zero of this corpus's 507 v6-family files combining
/// populated records with variable-length data, and a hole-walk over every
/// one found no genuine `TAG_VARIABLE` page either. So `read::
/// read_fragment_page`'s `is_v6` branch and `V6Page::fragment` are written
/// from `W32MKDE_decompiled.c` and from the oracle fixtures this project's
/// own `variable.rs` module cites (`variable.rs:340-353,493-501`), not from
/// anything this test could drive across the corpus and watch pass.
///
/// This asserts the two claims that grounded that choice stay true, driven
/// through the *shipped* `read::file` -- not a reimplementation of its own
/// rule (Trap 3 from earlier tasks in this plan): no v6 file combines
/// `variable_mark != 0` with `records > 0`, and no `V6Page` this crate has
/// ever decoded carries `fragment: Some(_)`. If this test ever fails, that
/// means a real v6 file finally showing the variable-length/fragment path
/// has turned up -- go re-open harvest 5 SS3/SS4 and re-check this crate's
/// only-fixture-tested assumptions against it (the entry continuation bit
/// always clear, on emit and on read; the page-level free list still
/// unestablished) before trusting the round trip's pass/fail verdict for
/// that file, or for this path in general.
#[test]
fn no_corpus_file_witnesses_the_v6_variable_path() {
    let files = corpus::walk();
    if files.is_empty() {
        eprintln!(
            "roundtrip: no archive/ on this box, nothing verified -- this is \
             expected in a fresh checkout and proves nothing either way"
        );
        return;
    }

    let mut populated_variable_v6: Vec<String> = Vec::new();
    let mut fragment_pages_found: Vec<String> = Vec::new();
    for entry in &files {
        let Ok(original) = std::fs::read(&entry.path) else { continue };
        let Ok(model) = read::file(&original) else { continue };
        let btrieve::model::Control::Shadowed { live, .. } = &model.control else { continue };
        if live.variable_mark != 0 && live.records > 0 {
            populated_variable_v6.push(entry.path.display().to_string());
        }
        for page in &model.v6_pages {
            if page.fragment.is_some() {
                fragment_pages_found.push(format!(
                    "{} physical page {}",
                    entry.path.display(),
                    page.physical_page
                ));
            }
        }
    }

    assert!(
        populated_variable_v6.is_empty(),
        "a v6 file combining variable-length records with actual data now \
         exists in the corpus -- Task 20's own report said this evidence did \
         not exist. Go re-derive the fragment/free-list rules against it \
         (harvest 5 SS2.2/SS3) before trusting anything this crate currently \
         assumes about the v6 variable-length path. Files: {populated_variable_v6:?}"
    );
    assert!(
        fragment_pages_found.is_empty(),
        "a genuine TAG_VARIABLE ('V') page now exists in a corpus file -- \
         this crate's v6 fragment-page code (`read::read_fragment_page`'s \
         `is_v6` branch, `write_v6_fragment_pages`) has never been run \
         against real data before now. Re-check the always-clear \
         continuation bit and the pointer scramble against it (harvest 5 \
         SS3.2/SS3.4) before trusting the round trip's verdict on this file. \
         Pages: {fragment_pages_found:?}"
    );
}

/// A diagnostic nobody has seen produce output is a diagnostic that does not
/// work -- the round trip cannot currently reach the mismatched class (every
/// corpus file is refused before it gets that far), so this test builds one
/// directly: a canvas emitted with known owners, then compared against bytes
/// altered at a byte one of those owners wrote. The message must name that
/// owner, not just announce that two buffers differ.
#[test]
fn a_mismatch_names_the_field_that_owns_the_differing_byte() {
    use btrieve::canvas::{Canvas, Owner};

    let mut canvas = Canvas::new(4);
    canvas
        .put(0, &[0xaa, 0xbb], Owner { structure: "fcr", field: "page_size", index: None })
        .expect("in range");
    canvas
        .put(
            2,
            &[0xcc, 0xdd],
            Owner { structure: "fcr", field: "key_descriptor", index: Some(3) },
        )
        .expect("in range");
    let emitted = canvas.finish().expect("every byte written");

    // Alter byte 2, the first byte "key_descriptor[3]" wrote, so it
    // disagrees with what the canvas actually produced.
    let mut original = emitted.bytes().to_vec();
    original[2] = 0xff;

    let message = describe_mismatch(&emitted, &original);
    assert!(
        message.contains("fcr.key_descriptor[3]"),
        "message names the owning field and its repetition: {message}"
    );
    assert!(message.contains("0x2"), "message names the byte offset: {message}");
}

/// The other branch of the same rendering: a byte outside every recorded
/// placement must say so explicitly, not print nothing and not panic.
#[test]
fn a_mismatch_past_every_placement_says_no_field_claims_it() {
    use btrieve::canvas::{Canvas, Owner};

    let mut canvas = Canvas::new(2);
    canvas
        .put(0, &[0x01, 0x02], Owner { structure: "fcr", field: "lead", index: None })
        .expect("in range");
    let emitted = canvas.finish().expect("every byte written");

    // A longer "original" that agrees with every byte the canvas actually
    // wrote finds no differing byte within the shared range, so
    // `describe_mismatch` falls back to the first index past the emitted
    // bytes -- a position no placement covers.
    let original: Vec<u8> = vec![0x01, 0x02, 0x03];

    let message = describe_mismatch(&emitted, &original);
    assert!(
        message.contains("but no field claims that byte"),
        "an unowned byte is named as such, in a sentence, not silently \
         omitted or stapled onto a fragment: {message}"
    );
}
