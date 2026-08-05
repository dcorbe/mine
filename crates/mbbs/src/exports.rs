//! The host's export tables: which ordinal of which DLL names which symbol.
//!
//! A module imports almost everything by ordinal -- `WCCMMUD.DLL` has 22,370
//! fixups naming an ordinal and exactly one naming a symbol. An ordinal on its
//! own says nothing, so without these tables a host that cannot service an
//! import can only report a number, and a number is not something anyone can
//! look up in `MAJORBBS.H`.
//!
//! # More than one DLL
//!
//! `WCCMMUD.DLL` links against five of the host's: `MAJORBBS`, `GALGSBL`,
//! `GALME`, and -- because a server module targets the Phar Lap 286|DOS-Extender
//! rather than DOS -- the OS/2-style `DOSCALLS` and `PHAPI`. Their ordinal
//! spaces are unrelated, so a table is per DLL and looking one up in another's
//! would produce a plausible wrong name rather than an error.
//!
//! Two are transcribed here. `MAJORBBS` comes from the host's own
//! `MAJORBBS.DEF`, and `GALGSBL` from the `GSBLIMP.LIB` import library that
//! shipped beside it. Nothing names `DOSCALLS`, `PHAPI` or `GALME` yet, so
//! their imports are reported by number -- which is honest, and is what a
//! refusal for one of them says.
//!
//! # Which version's table
//!
//! Ordinals move between host versions -- MBBS 6.25 exports 996 of them,
//! WG 1.01 1,210, WG 2.0 1,233 -- so resolving against the wrong one produces
//! plausible wrong bindings rather than errors. That makes the table a
//! per-host-version input and not a constant.
//!
//! Only WG 1.01 is built in so far, for a measured reason: `WCCMMUD.DLL`
//! imports up to ordinal 1191, which MBBS 6.25's table does not reach for 15 of
//! them, and WG 1.01 and WG 2.0 agree on the name of every ordinal this module
//! imports. So the choice is unobservable for MajorMUD, and would not be for
//! something else.

use std::collections::HashMap;
use std::sync::OnceLock;

/// The host DLLs whose ordinals are known.
pub const MAJORBBS: &str = "MAJORBBS";
pub const GALGSBL: &str = "GALGSBL";
pub const GALME: &str = "GALME";
pub const DOSCALLS: &str = "DOSCALLS";

/// WG 1.01's export tables, from `MAJORBBS.DEF` and `GSBLIMP.LIB`.
///
/// Committed rather than read from `archive/` at runtime. Twenty kilobytes of
/// derived names, and a host that loses them in a fresh checkout is a host
/// whose refusals report bare ordinals.
const MAJORBBS_WG101: &str = include_str!("../data/majorbbs_wg101.tsv");
const GALGSBL_WG101: &str = include_str!("../data/galgsbl_wg101.tsv");

/// `GALME.DLL`'s own name table, read out of the shipped WG 1.01 binary.
///
/// The one place a DEF and a binary disagree in this crate: `GMEDEF.DEF` in the
/// Worldgroup 1.01 source kit names 207 ordinals and the shipped DLL exports
/// 208, the extra being `_INIT__GME` at ordinal 1. They agree on the other 207,
/// and the binary is the thing the module is actually linked against.
const GALME_WG101: &str = include_str!("../data/galme_wg101.tsv");

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
const DOSCALLS_PHARLAP31: &str = include_str!("../data/doscalls_pharlap31.tsv");

/// One host version's exports, across every DLL it ships.
pub struct Exports {
    by_dll: HashMap<&'static str, HashMap<u16, Box<str>>>,
}

impl Exports {
    /// Worldgroup 1.01.
    pub fn wg101() -> &'static Self {
        static TABLE: OnceLock<Exports> = OnceLock::new();
        TABLE.get_or_init(|| Exports {
            by_dll: [
                (MAJORBBS, parse(MAJORBBS_WG101)),
                (GALGSBL, parse(GALGSBL_WG101)),
                (GALME, parse(GALME_WG101)),
                (DOSCALLS, parse(DOSCALLS_PHARLAP31)),
            ]
            .into_iter()
            .collect(),
        })
    }

    /// The C name of a DLL's ordinal, or `None` when the host has no name for
    /// it.
    ///
    /// A gap is not an error here. `MAJORBBS`'s 1,210 entries are spread over
    /// ordinals 1 to 1,323, and three of the DLLs have no table at all -- so a
    /// module naming one is a module the host can only report by number, which
    /// is what it then does.
    pub fn name(&self, dll: &str, ordinal: u16) -> Option<&str> {
        self.by_dll.get(dll)?.get(&ordinal).map(AsRef::as_ref)
    }

    /// How many ordinals a DLL exports.
    #[cfg(test)]
    fn len(&self, dll: &str) -> usize {
        self.by_dll.get(dll).map_or(0, HashMap::len)
    }
}

fn parse(tsv: &str) -> HashMap<u16, Box<str>> {
    tsv.lines()
        .filter_map(|line| {
            let (ordinal, name) = line.split_once('\t')?;
            Some((ordinal.trim().parse().ok()?, c_name(name.trim())))
        })
        .collect()
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
/// `WCCMMUD.DLL` imports by name rather than by ordinal, so both spellings have
/// to arrive at the same entry.
pub fn c_name(linkage: &str) -> Box<str> {
    let stripped = linkage.strip_prefix('_').unwrap_or(linkage);
    stripped.to_ascii_lowercase().into_boxed_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tables_are_the_size_the_host_exports() {
        assert_eq!(Exports::wg101().len(MAJORBBS), 1210);
        assert_eq!(Exports::wg101().len(GALGSBL), 101);
        assert_eq!(Exports::wg101().len(GALME), 208);
        assert_eq!(Exports::wg101().len(DOSCALLS), 209);
    }

    #[test]
    fn an_ordinal_names_the_symbol_majorbbs_h_declares() {
        let wg101 = Exports::wg101();
        assert_eq!(wg101.name(MAJORBBS, 474), Some("prf"));
        assert_eq!(wg101.name(MAJORBBS, 628), Some("usrnum"));
        assert_eq!(wg101.name(MAJORBBS, 403), Some("margv"));
        assert_eq!(wg101.name(MAJORBBS, 559), Some("spr"));
    }

    #[test]
    fn each_dll_has_its_own_ordinal_space() {
        // Ordinal 72 is `bturno` in GALGSBL and something else entirely in
        // MAJORBBS. Reading one table for the other would produce a plausible
        // wrong binding rather than an error, which is why there are two.
        let wg101 = Exports::wg101();
        assert_eq!(wg101.name(GALGSBL, 72), Some("bturno"));
        assert_ne!(wg101.name(MAJORBBS, 72), Some("bturno"));

        // And ordinal 135 is `doshugeshift` in DOSCALLS and something else
        // again in MAJORBBS.
        assert_eq!(wg101.name(DOSCALLS, 135), Some("doshugeshift"));
        assert_ne!(wg101.name(MAJORBBS, 135), Some("doshugeshift"));

        // PHAPI is the fifth DLL and has no table because it has no ordinals:
        // all 70 of its entries in `PHAPI.LIB` are by-name IMPDEF records, and
        // the shipped `PHAPI.DLL` -- "Empty DLL for various Debuggers" --
        // exports nothing at all. That is why the module's single by-name fixup
        // out of 22,371 is the one that names `DOSCREATEDSALIAS`.
        assert_eq!(wg101.name("PHAPI", 1), None, "PHAPI has no ordinal space");
    }

    #[test]
    fn doscalls_names_the_two_ordinals_the_module_imports() {
        let wg101 = Exports::wg101();
        // `DosSetVec(0, handler, &prev)`, far pascal, twice in segment 1 --
        // install a divide-by-zero handler and put the old one back.
        assert_eq!(wg101.name(DOSCALLS, 89), Some("dossetvec"));
        // Not a routine. An absolute-valued export, the selector shift for
        // huge-pointer arithmetic, which is why all 13 of the module's sites
        // are `mov cx,<it>` followed by `shl dx,cl` rather than a call.
        assert_eq!(wg101.name(DOSCALLS, 135), Some("doshugeshift"));
    }

    #[test]
    fn doscalls_ordinals_the_exporting_dll_skips_come_from_the_import_library() {
        // Phar Lap's `DOSCALLS.DLL` entry table has no entry for these three;
        // `PHAPI.LIB`'s IMPDEF records name them, and the two sources agree on
        // every one of the 79 ordinals they both cover.
        let wg101 = Exports::wg101();
        assert_eq!(wg101.name(DOSCALLS, 5), Some("dosexit"));
        assert_eq!(wg101.name(DOSCALLS, 58), Some("doschgfileptr"));
        assert_eq!(wg101.name(DOSCALLS, 138), Some("doswrite"));
    }

    #[test]
    fn galme_ordinal_30_is_the_messaging_engines_6x_compatibility_entry() {
        // `GME.H` declares `BOOL _oldsend(struct oldmsg *, char *)`, and both
        // of the module's sites clean 8 bytes -- cdecl with those two
        // arguments. Borland's underscore makes the export `__OLDSEND`, so
        // exactly one comes off.
        assert_eq!(Exports::wg101().name(GALME, 30), Some("_oldsend"));
    }

    #[test]
    fn one_underscore_comes_off_and_no_more() {
        // `_ctype` is exported as `__CTYPE`, and is a different symbol from
        // anything named `ctype`. Stripping greedily would merge them.
        assert_eq!(Exports::wg101().name(MAJORBBS, 11), Some("_ctype"));
    }

    #[test]
    fn a_compiler_helper_keeps_its_name() {
        // These are Borland's runtime -- long division, huge-pointer
        // arithmetic -- which MAJORBBS re-exports so a module can link against
        // the host's copy. They have no leading underscore to strip, and both
        // spellings of one have to reach the same entry.
        assert_eq!(Exports::wg101().name(MAJORBBS, 657), Some("f_lumod@"));
        assert_eq!(&*c_name("F_LUMOD@"), "f_lumod@");
        assert_eq!(Exports::wg101().name(MAJORBBS, 653), Some("dgroup@"));
    }

    #[test]
    fn an_ordinal_the_host_does_not_export_has_no_name() {
        // The gaps are real: 1,210 entries over ordinals 1 to 1,323.
        assert_eq!(Exports::wg101().name(MAJORBBS, 9999), None);
    }

    #[test]
    fn no_two_ordinals_share_a_c_name() {
        // Stripping and lowercasing could in principle merge two exports into
        // one, which would make a lookup by name ambiguous. It does not.
        for dll in [MAJORBBS, GALGSBL, GALME, DOSCALLS] {
            let mut names: Vec<&str> = Exports::wg101().by_dll[dll]
                .values()
                .map(AsRef::as_ref)
                .collect();
            names.sort_unstable();
            let before = names.len();
            names.dedup();
            assert_eq!(names.len(), before, "{dll} normalised two into one");
        }
    }
}
