//! Which external library a guest is asking for, and what is known about it.
//!
//! Sits beside `m16/` and `m32/` for the same reason `module.rs` does: it is a
//! door both machines walk through. `module.rs` answers "how is this symbol
//! named"; this answers "which library, and which generation of it".
//!
//! Fenced by `tests/no_cross_imports.rs` exactly as the other shared modules
//! are -- a shared module that named one machine would make every dispatcher
//! built on it inherit that dependency invisibly.

use std::collections::HashMap;

/// Where a table's numbering came from.
///
/// Recorded because the three do not carry equal weight. A shipped binary is
/// what a module was actually linked against; a vendor `.DEF` can be a
/// superset of what shipped (the WG 3.3 `WGSERVER.DEF` lists `_dfaStat @457`,
/// which the 3.12 binary does not export) or a subset (`GMEDEF.DEF` names 207
/// ordinals where `GALME.DLL` exports 208, the extra being `_INIT__GME`).
/// Where a binary survives it wins and the `.DEF` corroborates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// The shipped DLL's own export table.
    Binary,
    /// A vendor `.DEF` export definition.
    VendorDef,
    /// An import library's IMPDEF/`IMPORT_OBJECT` records.
    ImportLibrary,
}

/// One library's ordinal numbering for one generation.
pub struct OrdinalTable {
    /// Canonical library name, matching a [`Library::name`].
    pub library: &'static str,
    /// Generation tag: `"mbbs625"`, `"wg101"`, `"wg2"`, `"wg3-16"`, `"wgnt"`.
    pub generation: &'static str,
    /// `ordinal<TAB>linkage-name`, one per line. Committed rather than read
    /// from `archive/` at runtime: a host that loses these in a fresh
    /// checkout is a host whose refusals report bare ordinals.
    pub tsv: &'static str,
    /// The file this was extracted from, so the claim can be re-checked.
    pub source_path: &'static str,
    pub source_kind: SourceKind,
    /// How it was checked, in prose. Not decoration -- this is the reason the
    /// table is trustworthy.
    pub verified: &'static str,
}

impl OrdinalTable {
    /// Ordinal to C name. Built on demand; callers that resolve repeatedly
    /// should build once and keep it.
    pub fn names(&self) -> HashMap<u16, Box<str>> {
        self.tsv
            .lines()
            .filter_map(|line| {
                let (ordinal, name) = line.split_once('\t')?;
                Some((ordinal.trim().parse().ok()?, c_name(name.trim())))
            })
            .collect()
    }

    /// How many ordinals this table names.
    pub fn len(&self) -> usize {
        self.names().len()
    }

    /// Whether this table names no ordinals at all.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The C name behind a linkage name.
///
/// Borland's cdecl prefixes an underscore to every external, so the export
/// table holds `_PRF` for what `GCOMM.H` calls `prf` and `__CTYPE` for what
/// `ctype.h` calls `_ctype`. Exactly one underscore comes off, which is what
/// makes those two different names rather than the same one.
///
/// The compiler's own helper routines keep their shape: `F_LUMOD@` has no
/// leading underscore and is not given one. It is also the one symbol
/// `WCCMMUD.DLL` imports by name rather than by ordinal, so both spellings
/// have to arrive at the same entry.
///
/// `DOSCALLS` and `PHAPI` are far pascal, whose linkage name is the C
/// identifier upper-cased with no underscore at all. Case is lost there and
/// cannot be recovered mechanically, so this yields `dossetvec` for what
/// `BSEDOS.H` spells `DosSetVec`.
pub fn c_name(linkage: &str) -> Box<str> {
    let stripped = linkage.strip_prefix('_').unwrap_or(linkage);
    stripped.to_ascii_lowercase().into_boxed_str()
}

/// WG 1.01's GALGSBL numbering, from the `GSBLIMP.LIB` import library beside
/// the shipped DLL. Relocated from `crates/mbbs/src/exports.rs` unchanged.
pub static GALGSBL_WG101: OrdinalTable = OrdinalTable {
    library: GALGSBL,
    generation: "wg101",
    tsv: include_str!("../data/galgsbl_wg101.tsv"),
    source_path: "archive/galacticomm/extract/wg1/GALDSRC/DLIB/GSBLIMP.LIB",
    source_kind: SourceKind::ImportLibrary,
    verified: "101 ordinals; agrees with the shipped WG 1.01 GALGSBL.DLL name table on all 101.",
};

/// MajorBBS 6.x. **Two independent sources agree on all 100 shared ordinals
/// with zero disagreements and identical name sets** -- the 6.25 SDK's
/// `GSBLIMP.LIB` and the shipped 1992 `GALGSBL.DLL`.
///
/// The 93- and 96-export 1992 builds are recovered but not shipped: the
/// 93-build is a strict ordinal prefix of this one with zero disagreements on
/// all 93 shared entries, so it can add no discrimination this table does not
/// already provide.
pub static GALGSBL_MBBS625: OrdinalTable = OrdinalTable {
    library: GALGSBL,
    generation: "mbbs625",
    tsv: include_str!("../data/galgsbl_mbbs625.tsv"),
    source_path: "archive/galacticomm/extract/mbbs625sdk/MBBS_SDK/INSTALLB/GSBLIMP.LIB",
    source_kind: SourceKind::ImportLibrary,
    verified: "100 ordinals; agrees with the 1992 GALGSBL.DLL on all 100, identical name sets.",
};

/// Worldgroup 2.x. Adds `cdixfn@102` to WG 1.01 and moves nothing.
pub static GALGSBL_WG2: OrdinalTable = OrdinalTable {
    library: GALGSBL,
    generation: "wg2",
    tsv: include_str!("../data/galgsbl_wg2.tsv"),
    source_path: "re/wg33src/LIB/wg2/GALGSBL.DEF",
    source_kind: SourceKind::VendorDef,
    verified: "102 ordinals; agrees with the 1995-1996 GALGSBL.DLL binary.",
};

/// Worldgroup 3.x, 16-bit. **The same 102 names as WG 2.x with 38 of them
/// renumbered** -- the break that makes ordinal binding version-specific.
/// Ordinal 72 is `btuhit` here and `bturno` in every Layout A table.
pub static GALGSBL_WG3_16: OrdinalTable = OrdinalTable {
    library: GALGSBL,
    generation: "wg3-16",
    tsv: include_str!("../data/galgsbl_wg3_16.tsv"),
    source_path: "re/wg33src/LIB/GALGSBL.DEF (#ifdef GCDOS branch)",
    source_kind: SourceKind::VendorDef,
    verified: "102 ordinals; agrees with the 1996-1997 GALGSBL.DLL binary.",
};

/// Worldgroup NT, 32-bit. Named for the layout rather than a release because
/// MBBS 10's own import library carries the identical numbering -- 88 shared
/// ordinals, zero disagreements. Whether an MBBS 10 *module* binds by ordinal
/// at all is unresolved; see the spec's caveat. The table is established for
/// `wgnt` regardless.
pub static GALGSBL_LAYOUT_C: OrdinalTable = OrdinalTable {
    library: GALGSBL,
    generation: "layout-c",
    tsv: include_str!("../data/galgsbl_layout_c.tsv"),
    source_path: "re/wg33src/LIB/GALGSBL.DEF (#else branch)",
    source_kind: SourceKind::VendorDef,
    verified: "86 ordinals; the WG NT PE32 DLL exports these plus _btugri, _lanecb and a Borland __debuggerhookdata artifact.",
};

/// MajorBBS 6.25's MAJORBBS numbering. **Shipped first among the MAJORBBS
/// tables because it is what excludes the `mbbs625` profile for a Worldgroup
/// module**: the board's modules demand ordinals up to 1191 and this stops at
/// 1180, missing 16 of them.
///
/// 992 export lines, not the 996 `crates/mbbs/src/exports.rs` claims -- that
/// figure counts `@N` anywhere in the file, and four such strings sit outside
/// export lines.
pub static MAJORBBS_MBBS625: OrdinalTable = OrdinalTable {
    library: MAJORBBS,
    generation: "mbbs625",
    tsv: include_str!("../data/majorbbs_mbbs625.tsv"),
    source_path: "archive/galacticomm/extract/mbbs625sdk/MBBS_SDK/INSTALLB/MAJORBBS.DEF",
    source_kind: SourceKind::VendorDef,
    verified: "992 name@ordinal lines, zero duplicate ordinals, max 1180.",
};

/// Canonical library names.
pub const MAJORBBS: &str = "MAJORBBS";
pub const GALGSBL: &str = "GALGSBL";

pub const GALGSBL_TABLES: &[&OrdinalTable] = &[
    &GALGSBL_MBBS625,
    &GALGSBL_WG101,
    &GALGSBL_WG2,
    &GALGSBL_WG3_16,
    &GALGSBL_LAYOUT_C,
];

pub const MAJORBBS_TABLES: &[&OrdinalTable] = &[&MAJORBBS_MBBS625];

#[cfg(test)]
mod tests {
    use super::*;

    /// Borland's cdecl prefixes an underscore to every external, so the export
    /// table holds `_PRF` for what `GCOMM.H` calls `prf`. Exactly one
    /// underscore comes off, which is what makes `_PRF` and `__CTYPE`
    /// different names rather than the same one.
    #[test]
    fn c_name_strips_exactly_one_underscore_and_lowercases() {
        assert_eq!(&*c_name("_PRF"), "prf");
        assert_eq!(&*c_name("__CTYPE"), "_ctype");
        assert_eq!(&*c_name("DOSSETVEC"), "dossetvec");
    }

    /// A compiler helper has no leading underscore and must not be given one.
    /// `F_LUMOD@` is also the single symbol `WCCMMUD.DLL` imports by name
    /// rather than by ordinal, so both spellings must arrive at one entry.
    #[test]
    fn c_name_leaves_a_compiler_helper_its_shape() {
        assert_eq!(&*c_name("F_LUMOD@"), "f_lumod@");
    }

    #[test]
    fn a_table_parses_ordinal_tab_name_and_ignores_blank_lines() {
        const T: OrdinalTable = OrdinalTable {
            library: "GALGSBL",
            generation: "test",
            tsv: "1\t_BTUBSE\n2\t_BTUBSZ\n\n72\t_BTURNO\n",
            source_path: "(fixture)",
            source_kind: SourceKind::Binary,
            verified: "fixture",
        };
        let names = T.names();
        assert_eq!(T.len(), 3, "the blank line is not an entry");
        assert_eq!(names.get(&1).map(AsRef::as_ref), Some("btubse"));
        assert_eq!(names.get(&72).map(AsRef::as_ref), Some("bturno"));
        assert_eq!(names.get(&3), None, "an absent ordinal is None, never invented");
    }
}
