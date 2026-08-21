//! The criterion the rebuild is scored against.
//!
//! For every corpus file: read it into a model, emit bytes from that model
//! alone, and compare. The count that survives is pinned in
//! `tests/data/roundtrip-pin.txt` and may only go up.
//!
//! # Why a ratchet rather than "all files pass"
//!
//! All 612 passing is the finish line, not the starting line. A pin that only
//! grows turns a long build into a monotone measurement: every task either
//! raises it or does not, and a regression is a failure rather than a number
//! someone edits down.
//!
//! # Why this cannot be faked
//!
//! `emit::file` takes the model and nothing else -- it has no access to the
//! bytes `read::file` was given, so byte-identity cannot be reached by copying.
//! That is a property of the signature, not a convention.

use btrieve::{corpus, emit, read};

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
                            let at = produced
                                .iter()
                                .zip(original.iter())
                                .position(|(a, b)| a != b)
                                .unwrap_or_else(|| produced.len().min(original.len()));
                            mismatched_faults.push(format!(
                                "  {} ({:?}): first difference at byte {at:#x} \
                                 (produced {} bytes, original {})",
                                entry.path.display(),
                                entry.id.generation,
                                produced.len(),
                                original.len()
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
    assert!(
        passing <= files.len(),
        "more files passed than exist, which is impossible"
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
