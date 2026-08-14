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

/// What a host answers "what is `<module>.<symbol>`?" with, in this format's
/// own address representation.
///
/// `Ptr` is a raw address type (`m16::FarPtr`, `m32::Flat32Ptr`'s inner
/// `u32`), not `crate` -- neither `m16` nor `m32` -- so this stays reachable
/// from both without either depending on the other (`tests/no_cross_imports.rs`
/// fences that). The host-level policy that decides *which* `Import` a
/// symbol resolves to is one level up, in `crates/mbbs`'s `Resolver<A>` --
/// this only names the shape the answer takes once decided.
///
/// **`Absolute` has no PE counterpart, and a PE resolver must refuse one
/// rather than silently drop it or bind it as data.** An NE fixup can patch
/// *part* of an address into an instruction's own immediate field
/// (`DOSCALLS.135`'s huge-shift constant, 13 fixup sites in `WCCMMUD.DLL` --
/// see `m16::ne`'s own module doc comment); a PE fixup always writes a
/// whole address-sized IAT slot and never an instruction's immediate (see
/// `m32::image::Image::bind_imports`'s own doc comment, "every import site
/// is a full-width IAT write"). So a PE-format resolver being asked to bind
/// an `Absolute` means either the resolver answered for the wrong ABI, or a
/// symbol the host's own table marks `Absolute` reached a PE import site at
/// all -- both are host bugs, not something a loader can route around, and
/// both deserve to stop the load rather than be coerced into something that
/// merely compiles.
///
/// This variant is carried in the one shared enum, rather than splitting
/// `Import` into a 3-variant NE version and a 2-variant PE version, because
/// the *decision* "what does this symbol mean" (`Entry::Absolute` in
/// `crates/mbbs`'s shim table) is host policy that does not know which
/// container format is asking -- see `Resolver<A>::resolve`'s own doc
/// comment. Splitting the enum would only move the same refusal one level
/// up, into policy code that has even less business knowing about PE fixup
/// mechanics than the PE loader itself does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Import<Ptr> {
    /// A host routine. It gets a thunk, and calling it is reported as a
    /// call to thunk `index` by whichever `Exit` this format's machine
    /// answers.
    Routine,

    /// An address the loader writes into the fixup site verbatim, no thunk
    /// involved -- a host global the module addresses directly, **or**,
    /// since cross-module import support landed, another already-loaded
    /// module's own export. The two are indistinguishable to the loader on
    /// purpose: an NE fixup does not know or care whether the instruction it
    /// is patching is a `mov` reading a variable or a `call far`/`jmp far`
    /// reaching a routine (see `m16::ne::apply`'s own doc comment, "the
    /// additive-OFFSET case is the one that matters"), so a routine another
    /// *module* exports is patched in exactly the way a datum the *host*
    /// owns always has been -- the caller writes straight into the target's
    /// own code, with no host-side thunk to mediate the call afterwards.
    /// `crates/mbbs`'s `Resolver::resolve` is what decides which of the two
    /// this is, once, at load time; this variant only says "here is the
    /// address, write it".
    Data(Ptr),

    /// A constant with no address at all -- see this enum's own doc
    /// comment for why only NE can ever produce or consume one.
    Absolute(u16),
}

/// How a host answers "what is `<module>.<symbol>`?", for either container
/// format -- the loader that calls this never learns which. `Ptr` matches
/// whichever `Import<Ptr>` the answer comes back as.
///
/// Implemented for any suitable closure, which is what tests and examples
/// want; a real host has a table, keyed by version (see `crates/mbbs`'s
/// `Resolver<A>`).
pub trait ImportResolver<Ptr> {
    /// `None` for a symbol the host does not implement. The loader still
    /// gives it a thunk, so that calling it is a diagnosable event rather
    /// than a call into nothing.
    fn resolve(&self, module: &str, symbol: &Symbol) -> Option<Import<Ptr>>;
}

impl<Ptr, F: Fn(&str, &Symbol) -> Option<Import<Ptr>>> ImportResolver<Ptr> for F {
    fn resolve(&self, module: &str, symbol: &Symbol) -> Option<Import<Ptr>> {
        self(module, symbol)
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
