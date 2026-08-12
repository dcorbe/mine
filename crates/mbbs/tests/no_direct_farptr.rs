//! `FarPtr` is `mbbs16`'s pointer representation, and the whole point of the
//! `Abi` trait (`crates/mbbs/src/abi.rs`) is to keep it out of code meant to
//! serve either width. Without a test, the next contributor reintroduces the
//! coupling one shim at a time and nothing objects.
//!
//! Built as a **named allowlist, not a count**, for the reason
//! `argument_order.rs`'s module comment already gives at length: a count
//! cannot tell a removal from an addition, and it goes vacuous by
//! construction as the number falls to zero. Granularity here is per FILE,
//! not per line or per function, because that is the unit a conversion
//! commit actually frees -- converting a file's last Wg16-concrete leaf
//! deletes that file's own entry from `ALLOWED` in the same diff that does
//! the conversion.
//!
//! Measured directly against the source below, not trusted from a prior run.
//! As of this test's introduction (2026-08-12), three kinds of file account
//! for the whole list:
//!
//! - **`abi.rs` itself** -- the 16-bit `Abi` implementation, where
//!   `Wg16::Ptr = mbbs16::FarPtr` is declared. This is where the type is
//!   *supposed* to live, not a leak to guard against.
//! - **Facades not yet converted, or never going to be.** Tasks 4-6 moved
//!   most shim bodies and the subsystems behind them onto `A::Ptr`, but each
//!   left either a `_wg16`-suffixed dispatch-table bridge (the pattern
//!   `shims::mod`'s `call` doc comment names) or a Wg16-concrete method
//!   beside a generic core -- `Heap::alloc` beside `Heap::reserve`,
//!   `Users::polrou`, and `Messages`'/`Streams`'/`TextVars`' own Wg16-typed
//!   leaves -- plus routines the design says stay 16-bit forever:
//!   `shims::memory`'s `alctile`/`ptrtile` (segment tiling has no
//!   flat-memory counterpart), `shims::runtime`'s Borland helpers (the
//!   `Cleans::Callee` family, 16-bit-only by the design's Part 2),
//!   `shims::btrieve` and `crates/mbbs/src/btrieve.rs` (frozen for another
//!   session's Btrieve-engine work -- do not touch either file to shrink
//!   this list), and `shims::fsd`'s `fsdego`/`vfyadn`, `shims::user`'s
//!   `getin`, `shims::system`'s
//!   `register_module`/`register_agent`/`rtkick`, each blocked on a
//!   dependency `shims::mod`'s `ROUTINES` table documents beside its own
//!   entry.
//! - **Test code.** Every fixture in this crate builds a real
//!   `mbbs16::Machine` (`crates/mbbs/src/testing.rs`), so a `#[cfg(test)]`
//!   module that pokes a known address or reads back a `Ret::Far` names
//!   `FarPtr` directly even in a file whose production code no longer does.
//!   That is not a gap this test is meant to close -- it targets the shim
//!   layer's SHARED code, not the Wg16-only fixtures that exercise it.
//!
//! Do not add a file to `ALLOWED` to make a new production use pass; convert
//! that file's remaining concrete code, or -- if the mention is only in its
//! test module -- confirm that first before touching `ALLOWED` at all.

use std::fs;
use std::path::{Path, PathBuf};

/// Files under `crates/mbbs/src`, relative to that directory, that may still
/// name `FarPtr`. Sorted. See this file's module comment before editing.
const ALLOWED: &[&str] = &[
    "abi.rs",
    "arena.rs",
    "btrieve.rs",
    "fmt.rs",
    "fsd.rs",
    "globals.rs",
    "heap.rs",
    "lib.rs",
    "msg.rs",
    "shims/btrieve.rs",
    "shims/fsd.rs",
    "shims/memory.rs",
    "shims/mod.rs",
    "shims/msg.rs",
    "shims/runtime.rs",
    "shims/screen.rs",
    "shims/stream.rs",
    "shims/system.rs",
    "shims/text.rs",
    "shims/user.rs",
    "stream.rs",
    "testing.rs",
    "textvar.rs",
    "users.rs",
];

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Whether `text` names the bare identifier `FarPtr` -- not as a substring of
/// a longer identifier such as `FarPtrError` or a hypothetical
/// `ModuleFarPtr`. A plain substring search would count `FarPtrError`, which
/// names a different (and legitimately ABI-agnostic-adjacent) type, and would
/// silently inflate every file that only ever touches errors.
fn names_far_ptr(text: &str) -> bool {
    let bytes = text.as_bytes();
    let needle = b"FarPtr";
    let mut start = 0;
    while let Some(rel) = bytes[start..].windows(needle.len()).position(|w| w == needle) {
        let at = start + rel;
        let before_ok = at == 0 || !is_ident_byte(bytes[at - 1]);
        let after = at + needle.len();
        let after_ok = after >= bytes.len() || !is_ident_byte(bytes[after]);
        if before_ok && after_ok {
            return true;
        }
        start = at + 1;
    }
    false
}

/// Every `.rs` file under `dir`, recursively.
fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display())) {
        let path = entry.expect("readable dir entry").path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn far_ptr_is_named_only_where_the_allowlist_says() {
    let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
    let mut files = Vec::new();
    rs_files(root, &mut files);

    let mut found: Vec<String> = files
        .into_iter()
        .filter(|p| {
            let text = fs::read_to_string(p)
                .unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
            names_far_ptr(&text)
        })
        .map(|p| {
            p.strip_prefix(root)
                .expect("walked under root")
                .to_str()
                .expect("utf8 path")
                .replace(std::path::MAIN_SEPARATOR, "/")
        })
        .collect();
    found.sort_unstable();

    let mut allowed: Vec<&str> = ALLOWED.to_vec();
    allowed.sort_unstable();

    assert_eq!(
        found, allowed,
        "FarPtr's footprint in crates/mbbs/src changed -- see this file's \
         module comment before editing ALLOWED. A path present in the left \
         side but not the right is a NEW mention outside the shim \
         conversion's declared boundary; one present on the right but not \
         the left means a conversion already freed that file and ALLOWED \
         should shrink to match, in the same commit that freed it."
    );
}
