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

/// Superseded Task 20 tripwire, now a positive witness (Task 21).
///
/// Task 20 shipped `read::read_fragment_page`'s `is_v6` branch and
/// `V6Page::fragment` from `W32MKDE_decompiled.c` and from oracle fixtures
/// alone, because at the time every v6 file that combined populated
/// records with variable-length data, or carried a genuine `TAG_VARIABLE`
/// page, was refused before `read::file` ever reached that code -- by the
/// unrelated "unclaimed physical page" gate Task 21 closed
/// (`V6Page::orphan`). Removing that gate exposed the evidence directly:
/// this corpus has real fragment pages after all, just every one of them
/// sat behind a file that also happened to carry at least one physical
/// page Task 20's own round trip could not yet describe.
///
/// Measured once this task's fix landed, driven through the *shipped*
/// `read::file` -- not a reimplementation of its own rule (Trap 3 from
/// earlier tasks in this plan): 17 v6-family files combine
/// `variable_mark != 0` with `records > 0` (16 `wcctext2.vir`/`.nu1` copies
/// plus `WGSMENU2.DAT`, the same file this task's own brief named as the
/// flagship "unclaimed physical page" refusal); together they carry 19,231
/// genuine `TAG_VARIABLE` pages holding 35,442 live fragment entries, and
/// every one of the 652 corpus files still round-trips byte-identically
/// (`the_round_trip_count_only_grows`, same run). This asserts the exact
/// counts (a regression either way -- fewer real fragment pages found, or
/// more appearing without a re-check -- is worth noticing by name) and the
/// one invariant harvest 5 SS3.4 could previously only cite from four
/// oracle fixtures: every live entry's own continuation bit (`0x8000`,
/// `format::variable::CONTINUED_BIT`) reads clear, read directly off the
/// original file's raw bytes rather than through the model (the model
/// never consults this bit for v6 at all -- `read::read_fragment_page`'s
/// `is_v6` parameter skips it -- so a bug that silently flipped it on
/// write would not otherwise be caught by anything in this file).
#[test]
fn the_v6_fragment_path_is_now_corpus_witnessed() {
    let files = corpus::walk();
    if files.is_empty() {
        eprintln!(
            "roundtrip: no archive/ on this box, nothing verified -- this is \
             expected in a fresh checkout and proves nothing either way"
        );
        return;
    }

    let mut populated_variable_v6: Vec<String> = Vec::new();
    let mut fragment_pages_found: Vec<(String, u32)> = Vec::new();
    let mut live_entries = 0usize;
    let mut continuation_bit_set: Vec<String> = Vec::new();
    for entry in &files {
        let Ok(original) = std::fs::read(&entry.path) else { continue };
        let Ok(model) = read::file(&original) else { continue };
        let page_size = model.id.page_size as usize;
        if let btrieve::model::Control::Shadowed { live, .. } = &model.control {
            if live.variable_mark != 0 && live.records > 0 {
                populated_variable_v6.push(entry.path.display().to_string());
            }
        }
        for page in &model.v6_pages {
            let Some(fp) = &page.fragment else { continue };
            fragment_pages_found.push((entry.path.display().to_string(), page.physical_page));
            let page_start = page.physical_page as usize * page_size;
            for which in 0..fp.fragments.len() {
                let Some(entry_off) = btrieve::format::variable::entry_at(page_size, which)
                else {
                    continue;
                };
                let at = page_start + entry_off;
                let raw = u16::from_le_bytes([original[at], original[at + 1]]);
                if raw == btrieve::format::variable::UNUSED_ENTRY {
                    continue;
                }
                live_entries += 1;
                if raw & btrieve::format::variable::CONTINUED_BIT != 0 {
                    continuation_bit_set.push(format!(
                        "{} physical page {}, entry {which}",
                        entry.path.display(),
                        page.physical_page
                    ));
                }
            }
        }
    }

    assert_eq!(
        populated_variable_v6.len(),
        17,
        "populated variable-length v6 files: {populated_variable_v6:?}"
    );
    assert_eq!(
        fragment_pages_found.len(),
        19_231,
        "genuine TAG_VARIABLE pages found across those files"
    );
    assert_eq!(live_entries, 35_442, "live fragment entries across every one of those pages");
    assert!(
        continuation_bit_set.is_empty(),
        "harvest 5 SS3.4's 'every real v6 fragment leaves this bit clear' claim rested on \
         four oracle fixtures (165/165 entries); this corpus now has 35,442 real ones and \
         at least one disagrees -- re-open harvest 5 SS3.4 before trusting \
         `read::read_fragment_page`'s `is_v6` branch on it: {continuation_bit_set:?}"
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
