//! Serving GALGSBL out of the guest filesystem instead of off disk.
//!
//! `WCCMMUTL.EXE` opens `GALGSBL.DLL` and reads a `ReG#`-prefixed serial out
//! of it (`GETRNO`, per `docs/superpowers/specs/2026-08-19-host-library-
//! synthesis-design.md`). Nothing under `--root` has ever shipped that file
//! -- it is a host library, not board data -- so the open fails and
//! `WCCMMUTL` reports "Error opening GALGSBL.DLL for input" before it ever
//! reaches its menu. This module builds the bytes `runexe` hands `Files::
//! provide` so that open succeeds without anything touching disk.
//!
//! **Detection deliberately does not run here.** `mbbs_machine::library::
//! detect` exists to pick a generation from a module's own *import* table --
//! which ordinals it demands. `runexe`'s guest is a real-mode MZ program: it
//! has no import table at all, only DOS calls it makes at runtime, so there
//! is no demand to run detection against. The generation this file emits
//! comes from `--family`, or from `library::ANCHOR` when the operator does
//! not say -- a caller's choice, not an inference.

use mbbs_machine::library;

/// Exactly eight ASCII digits, or a reason it is not.
///
/// `GETRNO` reads exactly eight bytes after the `ReG#` marker (see
/// `re/wg33src` and the design spec), so a value that is not exactly eight
/// digits would silently read back as a different serial than the operator
/// typed -- shorter, and the read walks into whatever follows in the data
/// segment; longer, and the extra digits are silently dropped. Refusing
/// either is the only honest answer.
pub fn parse_bturno(s: &str) -> Result<&str, String> {
    if s.len() == 8 && s.bytes().all(|b| b.is_ascii_digit()) {
        Ok(s)
    } else {
        Err(format!(
            "--bturno must be exactly eight ASCII digits, got {:?} ({} chars)",
            s,
            s.len()
        ))
    }
}

/// Build the GALGSBL image `runexe` provides in place of a file on disk.
///
/// `family` names a [`library::Profile`] by its generation tag (`"wg101"`,
/// `"wg2"`, ...); `None` takes [`library::ANCHOR`]. An unknown family is
/// refused rather than silently falling back to the anchor -- a typo'd
/// `--family` should not quietly run a different generation than the
/// operator asked for.
pub fn galgsbl(family: Option<&str>, bturno: &str) -> Result<Vec<u8>, String> {
    let name = family.unwrap_or(library::ANCHOR);
    let profile = library::profile(name)
        .ok_or_else(|| format!("unknown --family {name:?}; known: wg101, mbbs625, wg2, wg3-16, layout-c"))?;
    let table = profile
        .table(library::GALGSBL)
        .ok_or_else(|| format!("profile {name:?} has no GALGSBL table"))?;

    let names = table.names();
    let mut exports: Vec<(u16, String)> = names.into_iter().map(|(ord, n)| (ord, n.into())).collect();
    exports.sort_by_key(|(ord, _)| *ord);
    let exports: Vec<(u16, &str)> = exports.iter().map(|(ord, n)| (*ord, n.as_str())).collect();

    let mut payload = Vec::with_capacity(4 + 8 + 1);
    payload.extend_from_slice(b"ReG#");
    payload.extend_from_slice(bturno.as_bytes());
    payload.push(0);

    Ok(mbbs_machine::m16::emit(library::GALGSBL, &exports, &payload))
}

// The plan's own Step 1 test lives in `tests/host_library.rs`, an
// integration test rather than an inline `#[cfg(test)] mod`, so this file
// carries none of its own -- an inline module here would add to the `dos-
// runtime` lib's baseline count (103 passed / 42 failed / 2 ignored) that
// Task 5's sweep checks against, for no coverage the integration test does
// not already give.
