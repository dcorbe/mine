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

    let mut passing = 0usize;
    let mut unreadable = 0usize;
    let mut first_faults: Vec<String> = Vec::new();
    for entry in &files {
        let original = match std::fs::read(&entry.path) {
            Ok(original) => original,
            Err(e) => {
                unreadable += 1;
                if first_faults.len() < 10 {
                    first_faults.push(format!(
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
            Ok(model) => {
                let produced = emit::file(&model);
                if produced == original {
                    passing += 1;
                } else if first_faults.len() < 10 {
                    let at = produced
                        .iter()
                        .zip(original.iter())
                        .position(|(a, b)| a != b)
                        .unwrap_or_else(|| produced.len().min(original.len()));
                    first_faults.push(format!(
                        "  {} ({:?}): first difference at byte {at:#x} \
                         (produced {} bytes, original {})",
                        entry.path.display(),
                        entry.id.generation,
                        produced.len(),
                        original.len()
                    ));
                }
            }
            Err(e) if first_faults.len() < 10 => {
                first_faults.push(format!(
                    "  {} ({:?}): read refused: {}",
                    entry.path.display(),
                    entry.id.generation,
                    e.why
                ));
            }
            Err(_) => {}
        }
    }

    if unreadable == 0 {
        println!("round trip: {passing} of {} corpus files", files.len());
    } else {
        println!(
            "round trip: {passing} of {} corpus files ({unreadable} unreadable)",
            files.len()
        );
    }
    let pin = pin();
    assert!(
        passing >= pin,
        "round trip regressed: {passing} files now, pin says {pin}.\n\
         The pin may only grow. First faults:\n{}",
        first_faults.join("\n")
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
