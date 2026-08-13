//! Vocabulary shared by every container format a module can be compiled
//! into, rather than owned by either `m16` or `m32`.
//!
//! Both NE (16-bit) and PE (32-bit) images name an import either by ordinal
//! or by name -- NE mostly by ordinal (`WCCMMUD.DLL` has 22,370 ordinal
//! imports against exactly one by name), PE mostly by name (its 32-bit
//! sibling imports all 210 of its symbols by name, zero by ordinal) -- and
//! both loaders resolve every import site down to the same three facts:
//! which DLL, which symbol, whether the host had an answer. `Abi::import`'s
//! dispatch must never learn which container format it is looking at (see
//! `docs/plans/2026-08-12-abi-border-design.md` §3), so that resolved shape
//! needs to be one type, not two that merely look alike. `Symbol` and
//! `ImportSite` are that type: until this module existed, `m16::ne::Symbol`
//! and `m32::pe::Symbol` were separately-defined enums with the same two
//! variants in the other order, and `m16::ne::ImportSite` and
//! `m32::image::ThunkSite` were the same struct under two names.
//!
//! # Naming: `module`, not `library`
//!
//! `m16::ne::ImportSite` called the field `module`; `m32::image::ThunkSite`
//! -- now merged into this type -- called the identical concept `library`.
//! `module` is the name that survives: it is the word the rest of the
//! shared vocabulary already uses for "the file a symbol comes from"
//! (`Abi::Module`, `LoadError`'s per-module accounting), where `library`
//! was m32's own local word and appears nowhere else in this crate's shared
//! surface.
//!
//! # Why this file, not `m16` or `m32`
//!
//! `fault` and `ldt` are the only other modules that sit beside `m16/` and
//! `m32/` rather than inside one of them (see this crate's `lib.rs`); this
//! one joins them for the same reason -- it is a door both machines walk
//! through -- and `tests/no_cross_imports.rs` fences it exactly as it
//! fences those two: this file may not name `m16` or `m32` in code. A
//! shared vocabulary module that quietly depended on one machine's address
//! type would stop being format-neutral, and dispatch code built on top of
//! it would inherit that dependency invisibly.

use std::fmt;

/// How an imported symbol is named.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Symbol {
    Ordinal(u16),
    Name(String),
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ordinal(n) => write!(f, "{n}"),
            Self::Name(s) => write!(f, "{s}"),
        }
    }
}

/// An imported symbol that was given a thunk, and what the host said about
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportSite {
    pub module: String,
    pub symbol: Symbol,
    /// False when the host had no answer. The thunk exists anyway, so that a
    /// module reaching an unimplemented import announces which one rather
    /// than calling into nothing.
    pub resolved: bool,
}

impl fmt::Display for ImportSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.module, self.symbol)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbol_display_matches_its_kind() {
        assert_eq!(Symbol::Ordinal(42).to_string(), "42");
        assert_eq!(Symbol::Name("foo".to_owned()).to_string(), "foo");
    }

    #[test]
    fn import_site_display_is_module_dot_symbol() {
        let site = ImportSite {
            module: "MAJORBBS".to_owned(),
            symbol: Symbol::Ordinal(474),
            resolved: true,
        };
        assert_eq!(site.to_string(), "MAJORBBS.474");
    }

    #[test]
    fn import_site_display_uses_a_name_symbol_too() {
        let site = ImportSite {
            module: "WGSERVER.EXE".to_owned(),
            symbol: Symbol::Name("_l2as".to_owned()),
            resolved: false,
        };
        assert_eq!(site.to_string(), "WGSERVER.EXE._l2as");
    }
}
