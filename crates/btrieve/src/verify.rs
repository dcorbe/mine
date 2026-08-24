//! Whether a write left behind a file this crate can still fully account for.
//!
//! Plan 2 built a total reader and a total writer -- [`crate::read::file`]
//! turns bytes into a model, [`crate::emit::file`] rebuilds bytes from that
//! model **alone** -- and proved, over 652 corpus files, that the round trip
//! is byte-identical. Nothing outside Plan 2's own tests ever called either
//! function on a file this crate had just written. [`written`] is that call:
//! it re-reads the file a write just produced, re-emits it, and compares the
//! result against the bytes actually on disk. A write that leaves the file
//! structurally sound passes silently; a write that does not is named down
//! to the offset and the field that owns it.
//!
//! # Why this checks more than a record count
//!
//! The only post-write check this crate had before this module is a record
//! count compared after a re-open (see the tests this module's own doc
//! references in `lib.rs`). That check cannot see a corrupted stale shadow
//! half, a fragment chain pointer written without its byte-order scramble,
//! an allocation-table entry that claims a page no key's tree reaches, or
//! any of the other shapes `read::file`'s own refusal messages exist to
//! name. [`written`] can, because it runs the same total reader and total
//! emitter the round-trip test does -- against the engine's real output
//! instead of a corpus fixture.
//!
//! # Why this is not unconditional -- two gates, not one
//!
//! A verification costs one full read of the file plus one full re-emit --
//! exactly the whole-file amplification `crates/btrieve`'s write path
//! already has and Plan 3's Stage B exists to remove (`v6_slot` and the v6
//! write path both currently read the entire file for one record; on
//! `WCCMP002.DAT`, 55 MB, per write). Wiring [`written`] into every write
//! unconditionally would make a debug-only safety net a permanent cost paid
//! in every build, including the release build a board actually runs.
//!
//! So the hook this module ships (`Block::verify_write` in `lib.rs`) is
//! gated twice, on two different questions:
//!
//! 1. **`#[cfg(debug_assertions)]`** -- is this a release build? In a
//!    `--release` build the check is compiled out entirely, not merely
//!    skipped at runtime, so the cost is paid in precisely zero of the
//!    builds a board actually runs. The same switch `debug_assert!` uses,
//!    chosen over a runtime flag for the same reason: this crate has no
//!    dependency on an argument-parsing or config crate to carry an opt-in
//!    flag through (`Cargo.toml`'s `[dependencies]` is empty and stays
//!    that way), and a compile-time gate cannot be forgotten at a call site
//!    the way a boolean parameter can.
//! 2. **`Block::verify_writes`, a per-block opt-in field** -- is this a
//!    `Block` a real module opened (`Block::open`), or one of this crate's
//!    own unit-test fixtures? This gate exists because the first version of
//!    this task used `#[cfg(debug_assertions)]` alone, wired unconditionally
//!    into every `Block`, and ran the suite: **37 previously-passing tests
//!    went red**, every one of them a `NotBtrieve` refusal. Those tests
//!    build a `Block` directly, bypassing `Block::open`, with synthetic
//!    geometries -- pages under [`crate::format::generation::FCR_MIN`],
//!    version words `read::file` does not accept -- built to exercise one
//!    piece of write-path logic in isolation, never meant to be a complete
//!    file [`read::file`] could parse. `Block::open` sets `verify_writes`
//!    to `cfg!(debug_assertions)`; every test-fixture constructor in this
//!    crate leaves it `false`. See `Block::verify_writes`'s own doc comment
//!    in `lib.rs`.
//!
//! The cost, when both gates are open, is real and is exactly the
//! read-plus-emit this doc comment describes above -- see
//! `docs/2026-08-24-btrieve-write-cost-baseline.md` (Plan 3 Task 2) for what
//! that costs in bytes and wall time on a real file, once that task has run.
//! **Task 2's measurement must be taken with one of the two gates closed**
//! (a `--release` build, or `verify_writes` left `false`), or the numbers
//! measured are this module, not the write.
//!
//! One consequence follows directly: **a release build ships with no
//! post-write structural check at all**, exactly as it did before this
//! module existed. That is the trade this task was asked to make, not an
//! oversight -- the alternative (verifying in release too) reintroduces the
//! full-file read Stage B is written specifically to remove.

use std::path::Path;

use crate::{emit, read};

/// Read the file at `path`, re-emit it, and confirm the result matches the
/// file's own bytes.
///
/// # Errors
///
/// Three distinct failure shapes, each named as such rather than folded into
/// one "verification failed":
///
/// - the file cannot even be opened or read (an I/O error, not this crate's
///   concern to diagnose further);
/// - [`read::file`] refuses it -- the write produced something this crate
///   cannot parse at all, which is the worse of the two structural failures
///   and is reported as a refusal, not a mismatch, so the two are never
///   confused;
/// - the file parses and re-emits, but the emitted bytes differ from the
///   file's own bytes -- reported at the first differing offset, together
///   with the field [`crate::canvas::Emitted::owner_of`] says owns that byte.
pub fn written(path: &Path) -> Result<(), String> {
    let on_disk = std::fs::read(path)
        .map_err(|e| format!("{}: reading the file this write just produced: {e}", path.display()))?;

    let model = read::file(&on_disk).map_err(|why| {
        format!(
            "{}: this write produced a file this crate cannot even parse back -- {} -- \
             which is worse than a byte mismatch: nothing downstream of this write can \
             read the file at all",
            path.display(),
            why.why
        )
    })?;

    let emitted = emit::file(&model).map_err(|fault| {
        format!(
            "{}: this write's file parses, but rebuilding it from that model faulted: {fault}",
            path.display()
        )
    })?;

    let produced = emitted.bytes();
    if produced.len() != on_disk.len() {
        return Err(format!(
            "{}: rebuilding the model produced {} bytes, but the file on disk is {} -- \
             lengths differ before any byte does",
            path.display(),
            produced.len(),
            on_disk.len()
        ));
    }

    let Some(at) = produced.iter().zip(on_disk.iter()).position(|(a, b)| a != b) else {
        return Ok(());
    };

    let owner = emitted
        .owner_of(at)
        .map(|owner| owner.label())
        .unwrap_or_else(|| "no field -- past every range this model describes".to_string());
    Err(format!(
        "{}: byte {at:#x} on disk is {:#04x}, but rebuilding the model this write's own \
         file reads back as produces {:#04x} there -- owned by {owner}",
        path.display(),
        on_disk[at],
        produced[at]
    ))
}

#[cfg(test)]
mod tests {
    use super::written;
    use std::path::Path;

    /// A committed, small, real Btrieve file that this crate already
    /// round-trips byte-identically (`roundtrip.rs`'s own corpus sweep
    /// covers it). `verify::written` on an unmodified copy must agree.
    ///
    /// Scratch, not the committed fixture itself: `crate::testing::scratch`
    /// gives each test its own directory under the workspace's (gitignored)
    /// `target/`, the same convention every other test in this crate that
    /// mutates a file already uses.
    fn scratch_copy_of_v6dup(test: &str) -> std::path::PathBuf {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates/")
            .parent()
            .expect("workspace root");
        let source = workspace.join("crates/btrieve/tests/data/variable/V6DUP.DAT");

        let dir = crate::testing::scratch(&format!("verify-written-{test}"));
        let dest = dir.join("V6DUP.DAT");
        std::fs::copy(&source, &dest).expect("copy the fixture to scratch");
        dest
    }

    /// An untouched copy of a file this crate already round-trips passes:
    /// this is the case Plan 2's own corpus sweep already covers, restated
    /// here as the baseline the corruption test below is contrasted against.
    #[test]
    fn an_unmodified_round_tripping_file_passes() {
        let path = scratch_copy_of_v6dup("passes");
        assert_eq!(written(&path), Ok(()));
    }

    /// Corrupt one byte inside a described field -- offset 512, the first
    /// byte of the second physical page's `fcr.lead` -- and confirm
    /// `verify::written` reports that offset and names the owning field,
    /// rather than announcing only that the bytes differ.
    ///
    /// This byte was chosen by direct measurement, not guessed: reading the
    /// live control record never re-derives the *other* shadow half's lead
    /// bytes from what is actually on disk there (`emit.rs`'s v6 control
    /// record write always emits the fixed four-byte v6 lead, `[b'F', b'C',
    /// 0, 0]`, rather than replaying whatever this copy's stale half
    /// happened to hold) -- so corrupting it changes what is on disk without
    /// changing what the model reads or what emit reproduces, which is
    /// exactly the "read succeeds, re-emit disagrees with disk" shape a
    /// record-count check cannot see and this function exists to catch.
    #[test]
    fn a_corrupted_byte_is_reported_by_offset_and_owning_field() {
        let path = scratch_copy_of_v6dup("corrupted-byte");
        let mut bytes = std::fs::read(&path).expect("just copied it");
        bytes[512] ^= 0xff;
        std::fs::write(&path, &bytes).expect("write the corrupted copy back");

        let err = written(&path).expect_err("a corrupted field must not pass silently");
        assert!(
            err.contains("0x200") || err.contains("512"),
            "the error names the offset: {err}"
        );
        assert!(err.contains("fcr.lead"), "the error names the owning field: {err}");
    }

    /// A file this crate cannot parse at all is a distinct failure from a
    /// byte mismatch, and must say so rather than reporting "0 bytes
    /// differ" or some other misleading comparison against nothing.
    #[test]
    fn a_file_read_refuses_is_reported_distinctly_from_a_mismatch() {
        let dir = crate::testing::scratch("verify-written-not-a-btrieve-file");
        let path = dir.join("garbage.dat");
        std::fs::write(&path, b"this is not a Btrieve file at all").expect("write garbage");

        let err = written(&path).expect_err("garbage bytes cannot parse");
        assert!(
            err.contains("cannot even parse"),
            "a refusal is named as a refusal, not a byte mismatch: {err}"
        );
    }
}
