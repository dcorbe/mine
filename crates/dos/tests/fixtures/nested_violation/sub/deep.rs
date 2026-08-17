//! Fixture for `the_walker_recurses_into_subdirectories` in
//! `crates/dos/tests/independence.rs`.
//!
//! This file lives under `tests/fixtures/`, not `src/`, so it is never
//! itself subject to the independence guard and never compiled -- Cargo's
//! test autodiscovery only turns top-level files directly under `tests/`
//! into test binaries. It exists purely as text for the walker to read.
//!
//! The `use` below is a deliberate, disallowed dependency. If the walker
//! ever regresses to a flat, top-level-only scan of its root directory, this
//! file stops being seen and the test that reads it fails.
//!
//! It is written with a leading `::` on purpose: it also stands as a
//! permanent check that stripping a leading `::` before matching (see
//! `offences_among` in `independence.rs`) does not accidentally widen the
//! allowlist -- `::dos_poc::...` must still be reported after the strip,
//! exactly as `dos_poc::...` would be.

use ::dos_poc::kvm::VmGuest;
