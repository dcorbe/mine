//! Resolve a Btrieve `Open`'s DOS-syntax filename into a real path beneath a
//! sandbox root -- the one piece of containment every edge onto
//! `crates/btrieve` must supply for itself.
//!
//! **Why this exists.** `crates/btrieve` is deliberately dependency-free
//! (`crates/btrieve/tests/independence.rs` enforces that mechanically) and
//! reads and writes through plain `std::fs`: `btrcall::open` takes whatever
//! bytes sit in a guest's key buffer, decodes them, and hands the result
//! straight to a path join. It has no notion of a sandbox and cannot enforce
//! a root, so every edge that calls into it -- a Win32 process
//! ([`crate::win32::btrieve`]) sandboxed beneath `--root`, a real-mode DOS
//! guest ([`crate::btrieve`]), and whatever a third edge turns out to be --
//! has to impose containment itself before the engine ever sees a path. This
//! module is that containment, written once: a symlink already sitting
//! inside the sandboxed tree (planted before an edge's process ever started,
//! not something a guest's own DOS-syntax name could spell) would otherwise
//! let `Open` walk out of `root` even after the lexical checks below refuse
//! `..`, an absolute path, and a `C:\` drive prefix. A future edge should
//! find this and call it rather than reinvent it -- this was written down
//! twice, by hand, before it was written down once.
//!
//! **The algorithm.** [`dos::files::translate`] does the DOS-syntax decoding
//! -- drive letters, `..`, device names -- once, for every DOS file access
//! any edge makes; a candidate that survives it is tried against the root
//! (and, if that spelling does not exist, against an all-lowercase retry,
//! since DOS is case-insensitive but this host's directories are not); and
//! anything that exists is canonicalized -- resolving any symlink -- and
//! confirmed to still start with the canonicalized root before it is
//! trusted. That last check is what a lexical rejection of `..` alone cannot
//! do.

use std::path::{Path, PathBuf};

/// What resolving a Btrieve `Open`'s filename against `root` found.
#[derive(Debug)]
pub enum OpenResolution {
    /// A path safe to hand `crates/btrieve`: either verified, by
    /// canonicalizing it and checking the result still starts with the
    /// canonicalized root, to resolve beneath the sandbox -- or (a name that
    /// plainly does not exist under either spelling) an unresolved path
    /// `Geometry::read` will fail against exactly the way a genuinely
    /// missing file fails. The second case is safe to hand over unchecked
    /// precisely because nothing on disk answers to it, symlink or not.
    Path(PathBuf),
    /// The guest's own name is why this failed: [`dos::files::translate`]
    /// rejected it outright (`..`, empty, or a bare device name -- none of
    /// which is a Btrieve file), or it resolved to something real but only
    /// by following a symlink back out of `root`. Real Btrieve has no status
    /// for either distinction, and neither is a host misconfiguration, so
    /// both answer the same way a genuinely missing file does: status 12,
    /// never a `Gap`.
    Refused,
    /// `root` itself could not be canonicalized. Unlike [`Refused`], this is
    /// not something the guest's own name could cause -- it means this
    /// edge's own sandbox is misconfigured, which callers should treat as a
    /// `Gap`, not a status. A caller that additionally has no root
    /// *configured* at all (the Win32 edge's `Process` may or may not have
    /// one attached) checks that itself before ever calling this function --
    /// see [`crate::win32::btrieve::btrcall`]'s own call site.
    RootUnusable,
}

/// Resolve a Btrieve `Open`'s filename -- DOS syntax such as `.\WCCACMS2.DAT`,
/// or a guest's attempt at `\..\..\etc\passwd` -- into a real path beneath
/// `root`, or a refusal. See this module's own doc comment for the algorithm
/// and why it lives here rather than in `crates/btrieve` or in either edge.
pub fn resolve_open_path(root: &Path, keybuf: &[u8]) -> OpenResolution {
    // Canonicalized once per `Open` rather than cached by a caller: this
    // runs once per file a module opens (on the order of a dozen files for
    // the utilities measured against this host, never one per record), not
    // once per Btrieve call, so there is no hot loop here to optimise away.
    let Ok(canonical_root) = root.canonicalize() else {
        return OpenResolution::RootUnusable;
    };
    match dos::files::translate(keybuf) {
        dos::files::Target::File(rel) => {
            let candidate = root.join(&rel);
            if candidate.exists() {
                return contained(&candidate, &canonical_root);
            }
            // `dos::files::translate` upper-cases every byte -- DOS is
            // case-insensitive and a guest reliably writes upper case, but
            // this host's directories are not, and real board archives hold
            // both spellings for some extensions. One lower-case retry, the
            // same fallback `dos::files::Files` documents for the same
            // reason.
            let lower = root.join(rel.to_ascii_lowercase());
            if lower.exists() {
                return contained(&lower, &canonical_root);
            }
            // Neither spelling exists, so there is nothing a symlink could
            // have carried anywhere -- handing this back unresolved is safe,
            // and `Geometry::read` will fail on it exactly the way a
            // genuinely missing file fails.
            OpenResolution::Path(candidate)
        }
        // Neither is a Btrieve file: `translate` already refused `..` and
        // empty names outright, and a device name (`NUL`, `CON`, ...) is not
        // something Btrieve's own `Geometry::read` could open either way.
        // Both are the guest's own doing, not a host-configuration gap, so
        // both answer status 12 rather than a `Gap`.
        dos::files::Target::Device(_) | dos::files::Target::Rejected => OpenResolution::Refused,
    }
}

/// `candidate`, canonicalized and checked against `canonical_root` -- the one
/// check that catches a symlink already sitting inside `root` and pointing
/// back out of it, which no amount of lexical rejection of `..` can see.
fn contained(candidate: &Path, canonical_root: &Path) -> OpenResolution {
    match candidate.canonicalize() {
        Ok(real) if real.starts_with(canonical_root) => OpenResolution::Path(real),
        _ => OpenResolution::Refused,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A symlink already sitting inside the sandbox root, pointing outside
    /// it, must not let a Btrieve `Open` follow it out. Planted before
    /// anything runs, the way a symlink already present in real board data
    /// would be -- not something a DOS-syntax name in the key buffer could
    /// spell on its own (`dos::files::translate` already refuses `..`), so
    /// lexical rejection alone cannot catch this; only canonicalizing the
    /// candidate and checking it against the canonicalized root does.
    #[test]
    fn a_symlink_inside_the_root_cannot_walk_a_btrieve_open_out_of_it() {
        let base = std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tmp"))
            .join("btrieve-open-path-escape");
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).expect("root dir");
        std::fs::create_dir_all(&outside).expect("outside dir");

        std::fs::write(outside.join("SECRET.DAT"), b"not yours").expect("outside file");

        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.join("SECRET.DAT"), root.join("ESCAPE.DAT"))
            .expect("symlink");

        let resolved = resolve_open_path(&root, b"ESCAPE.DAT\0");
        assert!(
            matches!(resolved, OpenResolution::Refused),
            "expected the symlink to be refused, got {resolved:?}"
        );
    }

    /// A `..` traversal attempt must be refused the same way, and by the
    /// same status a genuinely missing file gets -- never treated as a
    /// host-configuration gap. This is the divergence the two edges had
    /// before this module existed: the Win32 copy folded a rejected name
    /// into its "no root at all" case, which became a `Gap`, not status 12.
    #[test]
    fn a_dot_dot_name_is_refused_not_rootunusable() {
        let base = std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tmp"))
            .join("btrieve-open-path-dotdot");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("root dir");

        let resolved = resolve_open_path(&base, b"..\\..\\etc\\passwd\0");
        assert!(
            matches!(resolved, OpenResolution::Refused),
            "expected a `..` name to be refused, got {resolved:?}"
        );
    }

    /// A device name (`PRN`, `NUL`, ...) is refused the same way -- not a
    /// Btrieve file, but the guest's own doing, not a host-configuration
    /// gap.
    #[test]
    fn a_device_name_is_refused_not_rootunusable() {
        let base = std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tmp"))
            .join("btrieve-open-path-device");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("root dir");

        let resolved = resolve_open_path(&base, b"PRN\0");
        assert!(
            matches!(resolved, OpenResolution::Refused),
            "expected a device name to be refused, got {resolved:?}"
        );
    }
}
