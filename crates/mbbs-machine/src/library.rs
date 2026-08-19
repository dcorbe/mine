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

/// WG 1.01's export tables, from `MAJORBBS.DEF` and `GSBLIMP.LIB`.
///
/// Committed rather than read from `archive/` at runtime. Twenty kilobytes of
/// derived names, and a host that loses them in a fresh checkout is a host
/// whose refusals report bare ordinals.
pub static MAJORBBS_WG101: OrdinalTable = OrdinalTable {
    library: MAJORBBS,
    generation: "wg101",
    tsv: include_str!("../data/majorbbs_wg101.tsv"),
    source_path: "archive/galacticomm/extract/wg1/GALDSRC/DLIB/MAJORBBS.DEF",
    source_kind: SourceKind::VendorDef,
    verified: "1,210 ordinals spread over 1..1323.",
};

/// `GALME.DLL`'s own name table, read out of the shipped WG 1.01 binary.
///
/// The one place a DEF and a binary disagree in this crate: `GMEDEF.DEF` in the
/// Worldgroup 1.01 source kit names 207 ordinals and the shipped DLL exports
/// 208, the extra being `_INIT__GME` at ordinal 1. They agree on the other 207,
/// and the binary is the thing the module is actually linked against.
pub static GALME_WG101: OrdinalTable = OrdinalTable {
    library: GALME,
    generation: "wg101",
    tsv: include_str!("../data/galme_wg101.tsv"),
    source_path: "archive/galacticomm/extract/wg101host/GALME.DLL",
    source_kind: SourceKind::Binary,
    verified: "208 ordinals; GMEDEF.DEF names 207 of them and agrees on every one, the extra being _INIT__GME at ordinal 1.",
};

/// Worldgroup 3.3's `GALME` numbering, from `re/wg33src/LIB/GALME.DEF` --
/// three byte-identical copies of that `.DEF` exist in the tree and agree.
/// 287 exports, ordinals 1-287 with no gaps (verified directly, not assumed).
///
/// Recovered while tracing `GALME.dll!simpsnd` (ordinal 113 here), a PE named
/// import in every 32-bit build surveyed and so never actually unnameable by
/// ordinal -- see `docs/2026-08-15-unnameable-imports.md`. Committed for
/// completeness; nothing in this crate consumes it yet.
pub static GALME_WG33: OrdinalTable = OrdinalTable {
    library: GALME,
    generation: "wg33",
    tsv: include_str!("../data/galme_wg33.tsv"),
    source_path: "re/wg33src/LIB/GALME.DEF",
    source_kind: SourceKind::VendorDef,
    verified: "287 name@ordinal lines, ordinals 1-287 with no gaps, verified directly.",
};

/// Recovered 2026-08-14 from the WG 1.01 `GALDLL.ZIP` binaries, the same zip
/// the `GALME`/`GALGSBL` tables came from, and verified ordinal-by-ordinal
/// against `GALMSG.DEF`/`GALFIL.DEF` (byte-identical in the wg1 and wg20
/// source kits). Each binary carries one entry its `.DEF` omits -- the
/// `_INIT__*` entry point -- the same pattern `GALME`'s table already shows.
pub static GALMSG_WG101: OrdinalTable = OrdinalTable {
    library: GALMSG,
    generation: "wg101",
    tsv: include_str!("../data/galmsg_wg101.tsv"),
    source_path: "archive/galacticomm/extract/wg101host/GALMSG.DLL",
    source_kind: SourceKind::Binary,
    verified: "10 ordinals; verified against GALMSG.DEF.",
};

/// Recovered 2026-08-14 from the WG 1.01 `GALDLL.ZIP` binaries, the same zip
/// the `GALME`/`GALGSBL` tables came from, and verified ordinal-by-ordinal
/// against `GALMSG.DEF`/`GALFIL.DEF` (byte-identical in the wg1 and wg20
/// source kits). Each binary carries one entry its `.DEF` omits -- the
/// `_INIT__*` entry point -- the same pattern `GALME`'s table already shows.
pub static GALFIL_WG101: OrdinalTable = OrdinalTable {
    library: GALFIL,
    generation: "wg101",
    tsv: include_str!("../data/galfil_wg101.tsv"),
    source_path: "archive/galacticomm/extract/wg101host/GALFIL.DLL",
    source_kind: SourceKind::Binary,
    verified: "104 ordinals; verified against GALFIL.DEF.",
};

/// **Weaker provenance than the tables above, and deliberately said out loud.**
/// No `GALETL.DEF` or import library survives anywhere in the archive, so this
/// has no independent numeric cross-check -- only that its routine names match
/// `GALETL.DOC`'s description of a teleconferencing engine. The NE header
/// version (6.01) matches the confirmed WG-1.01 binaries, but the copy came
/// from a third-party archive rather than the WG 1.01 CD.
///
/// Three GALETL builds exist and their ordinals genuinely DISAGREE (ordinal 36
/// is `_TL2LST` in one and `___TLCACT` in another), so they are kept as
/// separate files and must never be merged: a wrong ordinal map is worse than
/// none, because it makes this host confidently name the wrong routine. The
/// other two are `galetl_wg300.tsv` and `galetl_ne5.tsv`, recovered but not
/// wired -- nothing this host loads is a WG 3.x or Entertainment Pack module.
pub static GALETL_WG101: OrdinalTable = OrdinalTable {
    library: GALETL,
    generation: "wg101",
    tsv: include_str!("../data/galetl_wg101.tsv"),
    source_path: "archive/_acquire/pools/full (GALETL.DLL, third-party archive copy, NE header v6.01)",
    source_kind: SourceKind::Binary,
    verified: "59 ordinals; no independent numeric cross-check survives -- weakest provenance among these tables.",
};

/// **Weaker provenance than the tables above, and deliberately said out loud.**
/// No `GALETL.DEF` or import library survives anywhere in the archive, so this
/// has no independent numeric cross-check -- only that its routine names match
/// `GALETL.DOC`'s description of a teleconferencing engine. The NE header
/// version (6.01) matches the confirmed WG-1.01 binaries, but the copy came
/// from a third-party archive rather than the WG 1.01 CD.
///
/// Three GALETL builds exist and their ordinals genuinely DISAGREE (ordinal 36
/// is `_TL2LST` in one and `___TLCACT` in another), so they are kept as
/// separate files and must never be merged: a wrong ordinal map is worse than
/// none, because it makes this host confidently name the wrong routine. The
/// other two are `galetl_wg300.tsv` and `galetl_ne5.tsv`, recovered but not
/// wired -- nothing this host loads is a WG 3.x or Entertainment Pack module.
pub static GALETL_WG300: OrdinalTable = OrdinalTable {
    library: GALETL,
    generation: "wg300",
    tsv: include_str!("../data/galetl_wg300.tsv"),
    source_path: "archive/_acquire/pools/full (GALETL.DLL, WG 3.0 build, third-party archive copy)",
    source_kind: SourceKind::Binary,
    verified: "58 ordinals; ordinal 36 is ___TLCACT here, disagreeing with wg101's _TL2LST -- must never be merged with it.",
};

/// The third GALETL build, referenced but not wired by [`GALETL_WG101`]'s own
/// doc comment ("the other two are `galetl_wg300.tsv` and `galetl_ne5.tsv`,
/// recovered but not wired -- nothing this host loads is a WG 3.x or
/// Entertainment Pack module"). No dedicated writeup for this file exists
/// anywhere in the repo beyond that mention and its recovery in commit
/// `d5a1bca4`; the `ne5` generation tag and provenance below are carried
/// forward unverified rather than invented here.
pub static GALETL_NE5: OrdinalTable = OrdinalTable {
    library: GALETL,
    generation: "ne5",
    tsv: include_str!("../data/galetl_ne5.tsv"),
    source_path: "archive/_acquire/pools/full (GALETL.DLL, Entertainment Pack build, third-party archive copy)",
    source_kind: SourceKind::Binary,
    verified: "52 ordinals; ordinal 50 is ___TLCACT, matching wg300 and disagreeing with wg101's _TL2LST at 36 -- not independently re-verified here.",
};

/// The 32-bit host's own export table, recovered 2026-08-14 from the genuinely
/// NE-format `WGSERVER.EXE` copies under `archive/_acquire/pools/full` -- five
/// are there, and they are two distinct builds (three byte-identical 3.12/3.13
/// and two byte-identical 3.00), NOT the PE32 `WGSERVER.EXE` that 32-bit
/// modules import by name and needs no ordinal table at all.
///
/// **Verified against the vendor's own export definitions**, which do survive:
/// `re/wg33src/LIB/wg30/WGSERVER.DEF` and `re/wg33src/LIB/WGSERVER.DEF`, from
/// the Worldgroup 3.3 source kit. 1,227 of the 3.00 DEF's 1,234 names appear
/// in the 3.00 table (99.4%) and 1,494 of the 3.3 DEF's 1,508 in the 3.12
/// table (99.1%). Every name the DEFs have and the binaries do not is an
/// NT-only routine sitting behind an `#ifdef` -- `iswinnt`,
/// `isrunasservice`, `getlasterrortext`, `excpfilter`, `geterrortext` --
/// which a DOS-era build correctly lacks.
///
/// The 3.3 DEF goes further: 1,506 of its entries carry an explicit
/// `@ordinal`, so the 3.12 table is verified ORDINAL BY ORDINAL against it --
/// **1,494 of 1,494 shared ordinals agree on the name, zero mismatches.**
/// The 3.00 DEF lists names only, so that table rests on the name set plus
/// its own binary's export table for the numbering.
pub static WGSERVER_WG300: OrdinalTable = OrdinalTable {
    library: WGSERVER,
    generation: "wg300",
    tsv: include_str!("../data/wgserver_wg300.tsv"),
    source_path: "archive/_acquire/pools/full (WGSERVER.EXE, NE 3.00 build, one of two byte-identical copies)",
    source_kind: SourceKind::Binary,
    verified: "1,381 ordinals; name-set verified against re/wg33src/LIB/wg30/WGSERVER.DEF -- 1,227 of the DEF's 1,234 names appear (99.4%).",
};

/// The 32-bit host's own export table, recovered 2026-08-14 from the genuinely
/// NE-format `WGSERVER.EXE` copies under `archive/_acquire/pools/full` -- five
/// are there, and they are two distinct builds (three byte-identical 3.12/3.13
/// and two byte-identical 3.00), NOT the PE32 `WGSERVER.EXE` that 32-bit
/// modules import by name and needs no ordinal table at all.
///
/// **Verified against the vendor's own export definitions**, which do survive:
/// `re/wg33src/LIB/wg30/WGSERVER.DEF` and `re/wg33src/LIB/WGSERVER.DEF`, from
/// the Worldgroup 3.3 source kit. 1,227 of the 3.00 DEF's 1,234 names appear
/// in the 3.00 table (99.4%) and 1,494 of the 3.3 DEF's 1,508 in the 3.12
/// table (99.1%). Every name the DEFs have and the binaries do not is an
/// NT-only routine sitting behind an `#ifdef` -- `iswinnt`,
/// `isrunasservice`, `getlasterrortext`, `excpfilter`, `geterrortext` --
/// which a DOS-era build correctly lacks.
///
/// The 3.3 DEF goes further: 1,506 of its entries carry an explicit
/// `@ordinal`, so the 3.12 table is verified ORDINAL BY ORDINAL against it --
/// **1,494 of 1,494 shared ordinals agree on the name, zero mismatches.**
/// The 3.00 DEF lists names only, so that table rests on the name set plus
/// its own binary's export table for the numbering.
pub static WGSERVER_WG312: OrdinalTable = OrdinalTable {
    library: WGSERVER,
    generation: "wg312",
    tsv: include_str!("../data/wgserver_wg312.tsv"),
    source_path: "archive/_acquire/pools/full (WGSERVER.EXE, NE 3.12/3.13 build, one of three byte-identical copies)",
    source_kind: SourceKind::Binary,
    verified: "1,495 ordinals; verified ORDINAL BY ORDINAL against re/wg33src/LIB/WGSERVER.DEF -- 1,494 of 1,494 shared ordinals agree, zero mismatches.",
};

/// `DOSCALLS`, keyed to the extender release rather than the host release.
///
/// No Worldgroup disk ships a `DOSCALLS.DLL`. The 286|DOS-Extender bound into
/// `MAJORBBS.EXE` provides it, so the table comes from Phar Lap's own copy --
/// 206 ordinals out of the NE name table of `BIN/DOSCALLS.DLL`, a binary that
/// describes itself as "EFI FUNCTIONS - DOSCALLS EMULATION" -- plus the three
/// its entry table skips (`DosExit`, `DosChgFilePtr`, `DosWrite`) taken from
/// the IMPDEF records of `BC4/LIB/PHAPI.LIB`.
///
/// The two sources are independent and agree on all 79 ordinals they share.
/// They differ in wording on exactly two, and those are aliases rather than
/// conflicts: Borland's import library calls 135 and 136 `__AHSHIFT` and
/// `__AHINCR`, which is what its runtime wants huge-pointer arithmetic to link
/// against. What a DLL calls its own ordinal is what this records.
///
/// `pharlap31` is measured, not assumed. WG 1.01's `MAJORBBS.EXE` carries the
/// 286|DOS-Extender banner and the version literal `3.1`, and the 3.04 and 3.12
/// `DOSCALLS.DLL` files -- different binaries -- name every ordinal the same.
pub static DOSCALLS_PHARLAP31: OrdinalTable = OrdinalTable {
    library: DOSCALLS,
    generation: "pharlap31",
    tsv: include_str!("../data/doscalls_pharlap31.tsv"),
    source_path: "Phar Lap BIN/DOSCALLS.DLL name table + BC4/LIB/PHAPI.LIB IMPDEFs",
    source_kind: SourceKind::Binary,
    verified: "209 ordinals; two independent sources agree on all 79 they share.",
};

/// Canonical library names.
pub const MAJORBBS: &str = "MAJORBBS";
pub const GALGSBL: &str = "GALGSBL";
pub const GALMSG: &str = "GALMSG";
pub const GALFIL: &str = "GALFIL";
pub const GALETL: &str = "GALETL";
pub const WGSERVER: &str = "WGSERVER";

pub const GALGSBL_TABLES: &[&OrdinalTable] = &[
    &GALGSBL_MBBS625,
    &GALGSBL_WG101,
    &GALGSBL_WG2,
    &GALGSBL_WG3_16,
    &GALGSBL_LAYOUT_C,
];

pub const MAJORBBS_TABLES: &[&OrdinalTable] = &[&MAJORBBS_MBBS625, &MAJORBBS_WG101];
pub const GALME_TABLES: &[&OrdinalTable] = &[&GALME_WG101, &GALME_WG33];
pub const GALMSG_TABLES: &[&OrdinalTable] = &[&GALMSG_WG101];
pub const GALFIL_TABLES: &[&OrdinalTable] = &[&GALFIL_WG101];
/// **Three builds whose ordinals genuinely disagree** -- ordinal 36 is
/// `_TL2LST` in one and `___TLCACT` in another -- so these must never be
/// merged. A wrong ordinal map is worse than none.
pub const GALETL_TABLES: &[&OrdinalTable] = &[&GALETL_NE5, &GALETL_WG101, &GALETL_WG300];
pub const WGSERVER_TABLES: &[&OrdinalTable] = &[&WGSERVER_WG300, &WGSERVER_WG312];
pub const DOSCALLS_TABLES: &[&OrdinalTable] = &[&DOSCALLS_PHARLAP31];

/// How a library's symbols are named.
///
/// This describes whether the library *has* an ordinal space, not how a given
/// module chose to bind to it. GALGSBL has one, and is reached by name from a
/// 32-bit Worldgroup module and by ordinal from a 16-bit one. A by-name import
/// simply never consults a table.
pub enum Naming {
    /// The library has an ordinal space, and these tables number it.
    Ordinals(&'static [&'static OrdinalTable]),
    /// The library has no ordinal space at all. `PHAPI`: every entry in
    /// `PHAPI.LIB` is a by-name IMPDEF record and the shipped `PHAPI.DLL`
    /// exports nothing, so a linker had no ordinal to use.
    NamesOnly,
    /// Not reached by symbol at all. Btrieve's DOS edge is an interrupt.
    Interrupt {
        vector: u8,
        /// Where the trap stub must sit inside its segment, when a guest
        /// probes for it. Btrieve's presence check demands the `int 7Bh`
        /// handler's offset be `0x33`, which is the real TSR's signature.
        stub_offset: Option<u16>,
    },
}

/// Whether an authentic binary could ever serve this library here.
pub enum Eligibility {
    /// A plain NE or PE image this host can load.
    Loadable,
    /// Present as a file but not runnable here, and why.
    NotLoadable(&'static str),
}

/// One external library a guest can ask for.
pub struct Library {
    /// The canonical name every dispatcher keys on.
    pub name: &'static str,
    /// Other spellings that mean this library, matched case-insensitively.
    pub aliases: &'static [&'static str],
    pub naming: Naming,
    pub authentic: Eligibility,
}

pub const GALME: &str = "GALME";
pub const PHAPI: &str = "PHAPI";
pub const DOSCALLS: &str = "DOSCALLS";

pub const LIBRARIES: &[Library] = &[
    Library {
        name: MAJORBBS,
        // `WGSERVER.EXE` is the 32-bit host's own exports and `cw3220mt.DLL`
        // is the Borland C runtime. They are aliased here because that is
        // where the host registers their routines today; splitting them into
        // libraries of their own is a later change with its own measurement.
        aliases: &["WGSERVER.EXE", "cw3220mt.DLL"],
        naming: Naming::Ordinals(MAJORBBS_TABLES),
        authentic: Eligibility::NotLoadable(
            "MAJORBBS.EXE is NE plus a Phar Lap 286 extender; neither host can run it",
        ),
    },
    Library {
        name: GALGSBL,
        aliases: &["GALGSBL.dll"],
        naming: Naming::Ordinals(GALGSBL_TABLES),
        authentic: Eligibility::Loadable,
    },
    Library {
        name: GALME,
        // A 32-bit module spells it `GALME.dll` while this host registers
        // GALME's routines under the bare `GALME` an NE segment is named --
        // the same shape as `GALGSBL.dll` one library over. Without this
        // alias `simpsnd` misses a routine that exists.
        aliases: &["GALME.dll"],
        naming: Naming::Ordinals(GALME_TABLES),
        authentic: Eligibility::Loadable,
    },
    Library {
        name: PHAPI,
        aliases: &[],
        naming: Naming::NamesOnly,
        authentic: Eligibility::NotLoadable("the shipped PHAPI.DLL exports nothing"),
    },
    Library {
        name: DOSCALLS,
        aliases: &[],
        // Keyed to the extender release, not the host release.
        naming: Naming::Ordinals(DOSCALLS_TABLES),
        authentic: Eligibility::NotLoadable("provided by the extender bound into MAJORBBS.EXE"),
    },
    Library {
        name: GALMSG,
        aliases: &[],
        naming: Naming::Ordinals(GALMSG_TABLES),
        authentic: Eligibility::Loadable,
    },
    Library {
        name: GALFIL,
        aliases: &[],
        naming: Naming::Ordinals(GALFIL_TABLES),
        authentic: Eligibility::Loadable,
    },
    Library {
        name: GALETL,
        aliases: &[],
        naming: Naming::Ordinals(GALETL_TABLES),
        authentic: Eligibility::Loadable,
    },
    Library {
        name: WGSERVER,
        // `canonical_dll` aliases `WGSERVER.EXE -> MAJORBBS` in `crates/mbbs`,
        // so a `WGSERVER` library with this bare name does not collide with
        // that alias. Do NOT give this library the alias `"WGSERVER.EXE"`:
        // that spelling stays on `MAJORBBS`, where it resolves today, until
        // Plan 3 splits it deliberately and re-measures what depends on it.
        aliases: &[],
        naming: Naming::Ordinals(WGSERVER_TABLES),
        authentic: Eligibility::Loadable,
    },
];

/// The library a spelling names, canonical or aliased.
pub fn library(spelling: &str) -> Option<&'static Library> {
    LIBRARIES.iter().find(|lib| {
        lib.name.eq_ignore_ascii_case(spelling)
            || lib.aliases.iter().any(|a| a.eq_ignore_ascii_case(spelling))
    })
}

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

    /// `canonical_dll` in `crates/mbbs` folds `cw3220mt.DLL` and
    /// `WGSERVER.EXE` onto `MAJORBBS`, so the Borland C runtime, the 32-bit
    /// host's exports and the game API share one namespace. Aliases here keep
    /// the identity while still resolving.
    #[test]
    fn an_alias_finds_its_library_without_losing_its_own_name() {
        let found = library("GALGSBL.dll").expect("alias resolves");
        assert_eq!(found.name, GALGSBL);
        assert_eq!(library("GALGSBL").expect("canonical resolves").name, GALGSBL);
        assert!(library("NOSUCHLIB").is_none(), "an unknown spelling is None, not a guess");
    }

    /// PHAPI has no ordinal space at all: every entry in `PHAPI.LIB` is a
    /// by-name IMPDEF and the shipped DLL exports nothing. That is different
    /// from a library which has ordinals that a given module chose not to use.
    #[test]
    fn phapi_has_no_ordinal_space_but_galgsbl_does() {
        assert!(matches!(library("PHAPI").expect("phapi").naming, Naming::NamesOnly));
        assert!(matches!(library("GALGSBL").expect("galgsbl").naming, Naming::Ordinals(_)));
    }

    /// An authentic MAJORBBS.EXE cannot be loaded even when present: it is NE
    /// plus a Phar Lap 286 extender. Recording the reason is what stops the
    /// file being silently ignored.
    #[test]
    fn majorbbs_is_ineligible_for_authentic_loading_with_a_stated_reason() {
        match library("MAJORBBS").expect("majorbbs").authentic {
            Eligibility::NotLoadable(why) => assert!(why.contains("Phar Lap"), "{why}"),
            Eligibility::Loadable => panic!("MAJORBBS.EXE cannot be loaded by this host"),
        }
        assert!(matches!(library("GALGSBL").expect("galgsbl").authentic, Eligibility::Loadable));
    }

    /// Every table a library offers must belong to that library, or a lookup
    /// would answer with another library's ordinal space.
    #[test]
    fn no_library_offers_another_librarys_table() {
        for lib in LIBRARIES {
            if let Naming::Ordinals(tables) = lib.naming {
                for t in tables {
                    assert_eq!(t.library, lib.name, "{} offers {}'s table", lib.name, t.library);
                }
            }
        }
    }
}
