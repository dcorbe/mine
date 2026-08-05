//! What sits behind each import, and what to do when nothing does.

pub mod btrieve;
pub mod fsd;
pub mod memory;
pub mod msg;
pub mod runtime;
pub mod stream;
pub mod system;
pub mod text;

use mbbs16::{Machine, Ret};

use crate::Host;
use crate::exports::MAJORBBS;
use crate::globals::GLOBALS;

/// -1, as a 16-bit `int`.
///
/// What a routine returns when absence or failure is the truth and the module is
/// entitled to be told: `access` on a file that is not there, `unlink` on one it
/// cannot remove. Everywhere else in this crate a host that cannot answer stops
/// the module instead -- these are the routines whose *purpose* includes
/// reporting that something is not there, and for them -1 is an answer.
pub(crate) const NO: u16 = -1i16 as u16;

/// One host routine.
///
/// `machine` is how it reads the module's arguments and writes into its
/// memory; the return value goes back in `AX` or `DX:AX`.
pub type Shim = fn(&mut Machine, &mut Host) -> Result<Ret, ShimError>;

/// Who removes a routine's arguments from the module's stack.
///
/// The MajorBBS API is cdecl -- the module pushes the arguments and the module
/// pops them -- and for a long time this crate had no reason to name that,
/// because everything it implemented was the same. Borland's 32-bit arithmetic
/// helpers are not: they are called with four words on the stack and no
/// `add sp` after the call.
///
/// Stated per routine rather than inferred, because the cost of inferring it
/// wrongly is not a crash. A callee-cleaned routine serviced as caller-cleaned
/// leaves its arguments behind and the module carries on with every subsequent
/// frame shifted -- the module's own stack, quietly wrong, which is precisely
/// the class of failure this crate refuses everywhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cleans {
    /// The module pops its own arguments after the call returns. cdecl, and
    /// what every MajorBBS routine does.
    Caller,

    /// The routine pops this many bytes of arguments before returning.
    Callee(u16),
}

/// Why a host routine could not do what it was asked.
///
/// Every variant is terminal. A shim that cannot answer has nothing safe to
/// return -- a plausible zero is the failure mode this whole design exists to
/// avoid -- so the module is stopped instead.
#[derive(Debug)]
pub enum ShimError {
    /// The module handed the host a pointer naming nothing, or a range leaving
    /// its segment.
    BadPointer(mbbs16::FarPtrError),

    /// The host could not do it: a file that would not open, a value that would
    /// not fit.
    Failed(String),
}

impl std::fmt::Display for ShimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadPointer(e) => write!(f, "{e}"),
            Self::Failed(why) => f.write_str(why),
        }
    }
}

impl From<mbbs16::FarPtrError> for ShimError {
    fn from(e: mbbs16::FarPtrError) -> Self {
        Self::BadPointer(e)
    }
}

/// What an imported symbol is.
pub enum Entry {
    /// A host routine, reached by far call, and who cleans up after it.
    Routine(Shim, Cleans),

    /// A host global the module addresses directly. Reached by no call at all,
    /// so there is nothing to dispatch -- the address goes into the fixup at
    /// load time and the host never hears about it again.
    Datum,

    /// A constant with no address, written into an instruction's immediate.
    Absolute(u16),

    /// Named, and not implemented. Calling it stops the module and says so.
    Unimplemented,
}

/// Every routine the host implements, by the DLL and the C name that exports it.
///
/// Keyed by name rather than by ordinal so that the export tables stay the one
/// place ordinals are written down. A different host version re-keys the whole
/// table by itself; a table of ordinals would have to be rewritten and would
/// look right while being wrong.
const ROUTINES: &[(&str, &str, Shim, Cleans)] = &[
    // Strings, numbers and the print buffer.
    (MAJORBBS, "spr", text::spr, Cleans::Caller),
    (MAJORBBS, "sprintf", text::sprintf, Cleans::Caller),
    (MAJORBBS, "vsprintf", text::vsprintf, Cleans::Caller),
    (MAJORBBS, "prf", text::prf, Cleans::Caller),
    (MAJORBBS, "clrprf", text::clrprf, Cleans::Caller),
    (MAJORBBS, "stzcpy", text::stzcpy, Cleans::Caller),
    (MAJORBBS, "strcpy", text::strcpy, Cleans::Caller),
    (MAJORBBS, "strlen", text::strlen, Cleans::Caller),
    (MAJORBBS, "rmvwht", text::rmvwht, Cleans::Caller),
    (MAJORBBS, "skpwht", text::skpwht, Cleans::Caller),
    (MAJORBBS, "skpwrd", text::skpwrd, Cleans::Caller),
    (MAJORBBS, "depad", text::depad, Cleans::Caller),
    (MAJORBBS, "rstrin", text::rstrin, Cleans::Caller),
    (MAJORBBS, "atol", text::atol, Cleans::Caller),
    // Message files, and the options in them.
    (MAJORBBS, "opnmsg", msg::opnmsg, Cleans::Caller),
    (MAJORBBS, "clsmsg", msg::clsmsg, Cleans::Caller),
    (MAJORBBS, "setmbk", msg::setmbk, Cleans::Caller),
    (MAJORBBS, "rstmbk", msg::rstmbk, Cleans::Caller),
    (MAJORBBS, "stgopt", msg::stgopt, Cleans::Caller),
    (MAJORBBS, "numopt", msg::numopt, Cleans::Caller),
    (MAJORBBS, "ynopt", msg::ynopt, Cleans::Caller),
    (MAJORBBS, "chropt", msg::chropt, Cleans::Caller),
    (MAJORBBS, "tokopt", msg::tokopt, Cleans::Caller),
    (MAJORBBS, "prfmsg", msg::prfmsg, Cleans::Caller),
    // Memory the module owns, and the leaves that move bytes about.
    (MAJORBBS, "alcmem", memory::alcmem, Cleans::Caller),
    (MAJORBBS, "alczer", memory::alczer, Cleans::Caller),
    (MAJORBBS, "galfree", memory::galfree, Cleans::Caller),
    (MAJORBBS, "farcoreleft", memory::farcoreleft, Cleans::Caller),
    (MAJORBBS, "alctile", memory::alctile, Cleans::Caller),
    (MAJORBBS, "ptrtile", memory::ptrtile, Cleans::Caller),
    (MAJORBBS, "setmem", memory::setmem, Cleans::Caller),
    (MAJORBBS, "movmem", memory::movmem, Cleans::Caller),
    (MAJORBBS, "memcpy", memory::memcpy, Cleans::Caller),
    (MAJORBBS, "memcmp", memory::memcmp, Cleans::Caller),
    // Btrieve: opening a module's data files, and which one is current.
    (MAJORBBS, "omdbtv", btrieve::omdbtv, Cleans::Caller),
    (MAJORBBS, "opnbtv", btrieve::opnbtv, Cleans::Caller),
    (MAJORBBS, "setbtv", btrieve::setbtv, Cleans::Caller),
    (MAJORBBS, "rstbtv", btrieve::rstbtv, Cleans::Caller),
    (MAJORBBS, "cntrbtv", btrieve::cntrbtv, Cleans::Caller),
    // Btrieve: reading records.
    (MAJORBBS, "qrybtv", btrieve::qrybtv, Cleans::Caller),
    (MAJORBBS, "qnpbtv", btrieve::qnpbtv, Cleans::Caller),
    (MAJORBBS, "obtbtvl", btrieve::obtbtvl, Cleans::Caller),
    (MAJORBBS, "stpbtvl", btrieve::stpbtvl, Cleans::Caller),
    (MAJORBBS, "absbtv", btrieve::absbtv, Cleans::Caller),
    (MAJORBBS, "aabbtv", btrieve::aabbtv, Cleans::Caller),
    (MAJORBBS, "gabbtvl", btrieve::gabbtvl, Cleans::Caller),
    // Btrieve: the write family's guards. Neither of these writes -- each
    // reproduces what `PLBTVSTF.C` did with no file current, and refuses when
    // there is one.
    (MAJORBBS, "invbtv", btrieve::invbtv, Cleans::Caller),
    (MAJORBBS, "delbtv", btrieve::delbtv, Cleans::Caller),
    // Streams: the module's own files, read and written.
    (MAJORBBS, "fopen", stream::fopen, Cleans::Caller),
    (MAJORBBS, "fclose", stream::fclose, Cleans::Caller),
    (MAJORBBS, "fgets", stream::fgets, Cleans::Caller),
    (MAJORBBS, "fread", stream::fread, Cleans::Caller),
    (MAJORBBS, "fprintf", stream::fprintf, Cleans::Caller),
    (MAJORBBS, "fflush", stream::fflush, Cleans::Caller),
    (MAJORBBS, "unlink", stream::unlink, Cleans::Caller),
    // The clock, the audit trail, and coming online.
    (MAJORBBS, "access", system::access, Cleans::Caller),
    (MAJORBBS, "now", system::now, Cleans::Caller),
    (MAJORBBS, "today", system::today, Cleans::Caller),
    (MAJORBBS, "time", system::time, Cleans::Caller),
    (MAJORBBS, "srand", system::srand, Cleans::Caller),
    (MAJORBBS, "genrdn", system::genrdn, Cleans::Caller),
    (MAJORBBS, "gmdnam", system::gmdnam, Cleans::Caller),
    (MAJORBBS, "shocst", system::shocst, Cleans::Caller),
    (MAJORBBS, "rtkick", system::rtkick, Cleans::Caller),
    (MAJORBBS, "fsdroom", fsd::fsdroom, Cleans::Caller),
    (MAJORBBS, "fsdapr", fsd::fsdapr, Cleans::Caller),
    (MAJORBBS, "fsdnan", fsd::fsdnan, Cleans::Caller),
    (MAJORBBS, "dclvda", system::dclvda, Cleans::Caller),
    (
        MAJORBBS,
        "register_module",
        system::register_module,
        Cleans::Caller,
    ),
    (
        MAJORBBS,
        "register_agent",
        system::register_agent,
        Cleans::Caller,
    ),
    (
        MAJORBBS,
        "register_textvar",
        system::register_textvar,
        Cleans::Caller,
    ),
    (MAJORBBS, "catastro", system::catastro, Cleans::Caller),
    // The compiler's own runtime, which this host exports because the real one
    // did. These four pop their own arguments -- see `runtime`.
    (
        MAJORBBS,
        "f_ldiv@",
        runtime::f_ldiv,
        Cleans::Callee(runtime::OPERANDS),
    ),
    (
        MAJORBBS,
        "f_lmod@",
        runtime::f_lmod,
        Cleans::Callee(runtime::OPERANDS),
    ),
    (
        MAJORBBS,
        "f_ludiv@",
        runtime::f_ludiv,
        Cleans::Callee(runtime::OPERANDS),
    ),
    (
        MAJORBBS,
        "f_lumod@",
        runtime::f_lumod,
        Cleans::Callee(runtime::OPERANDS),
    ),
];

/// Every constant the host exports.
///
/// Only one so far, and it is keyed by ordinal because nothing in the recovered
/// sources names it. `DOSCALLS.135` is the huge shift: how far to shift a count
/// of 64 KiB chunks to get the matching selector increment. Thirteen of
/// `WCCMMUD.DLL`'s fixups resolve it straight into the immediate of a
/// `mov $x, %cx` that is followed by a `shl`, which is Borland's huge-pointer
/// normalisation and is what identifies it.
///
/// [`SELECTOR_STEP`](mbbs16::SELECTOR_STEP) is the answer, expressed as the
/// shift the module wants: consecutive LDT entries are eight apart, so a count
/// of chunks becomes a selector delta by shifting left three.
///
/// **This is only true once a huge object's chunks occupy consecutive LDT
/// entries**, which was an open question when the constant went in and is no
/// longer: [`alloc_tiled`](mbbs16::Machine::alloc_tiled) reserves a region's
/// descriptors as one run, and `memory::ptrtile` is tested against exactly this
/// arithmetic. The module computes tile addresses both ways and they agree.
const ABSOLUTES: &[(&str, &str, u16)] =
    &[("DOSCALLS", "#135", mbbs16::SELECTOR_STEP.ilog2() as u16)];

/// What the host knows about a symbol.
///
/// `symbol` is the C name when the export tables have one and `#<ordinal>` when
/// they do not, which is how a DLL with no table of its own is still addressed
/// by something stable.
pub fn entry(dll: &str, symbol: &str) -> Entry {
    if let Some((_, _, shim, cleans)) = ROUTINES
        .iter()
        .find(|(d, n, _, _)| *d == dll && *n == symbol)
    {
        return Entry::Routine(*shim, *cleans);
    }
    if let Some((_, _, value)) = ABSOLUTES.iter().find(|(d, n, _)| *d == dll && *n == symbol) {
        return Entry::Absolute(*value);
    }
    if GLOBALS.iter().any(|g| g.dll == dll && g.name == symbol) {
        return Entry::Datum;
    }
    Entry::Unimplemented
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exports::GALGSBL;

    #[test]
    fn a_global_is_a_datum() {
        assert!(matches!(entry(MAJORBBS, "usrnum"), Entry::Datum));
        assert!(matches!(entry(MAJORBBS, "margv"), Entry::Datum));
        assert!(matches!(entry(GALGSBL, "bturno"), Entry::Datum));
    }

    #[test]
    fn a_global_belongs_to_the_dll_that_exports_it() {
        // `bturno` is GSBL's, not MAJORBBS's. Asking the wrong DLL for it must
        // not find it, or a name shared between two DLLs would bind one to the
        // other's memory.
        assert!(matches!(entry(MAJORBBS, "bturno"), Entry::Unimplemented));
        assert!(matches!(entry(GALGSBL, "usrnum"), Entry::Unimplemented));
    }

    #[test]
    fn an_unknown_symbol_is_unimplemented() {
        // `dinsbtv` is the insert that writing records needs, and is
        // deliberately absent: nothing in this host writes to a Btrieve file
        // yet, so a module that saves a character is stopped rather than
        // appearing to work.
        assert!(matches!(entry(MAJORBBS, "dinsbtv"), Entry::Unimplemented));
        assert!(matches!(entry(MAJORBBS, "nonesuch"), Entry::Unimplemented));
    }

    #[test]
    fn the_huge_shift_steps_one_ldt_entry() {
        let Entry::Absolute(shift) = entry("DOSCALLS", "#135") else {
            panic!("DOSCALLS.135 is a constant");
        };
        assert_eq!(
            1u16 << shift,
            mbbs16::SELECTOR_STEP,
            "shifting by this must land on the next selector"
        );
    }

    #[test]
    fn nothing_is_in_two_tables_at_once() {
        // They answer the same question, and a symbol in two would resolve to
        // whichever is consulted first -- a far call into globals memory, or a
        // variable at a code address. Neither fails loudly.
        for (dll, name, _, _) in ROUTINES {
            assert!(
                !GLOBALS.iter().any(|g| g.dll == *dll && g.name == *name),
                "{dll}.{name} is both a routine and a global"
            );
            assert!(
                !ABSOLUTES.iter().any(|(d, n, _)| d == dll && n == name),
                "{dll}.{name} is both a routine and a constant"
            );
        }
        for (dll, name, _) in ABSOLUTES {
            assert!(
                !GLOBALS.iter().any(|g| g.dll == *dll && g.name == *name),
                "{dll}.{name} is both a constant and a global"
            );
        }
    }
}

#[cfg(test)]
mod convention {
    use super::*;

    #[test]
    fn every_routine_but_the_borland_helpers_is_caller_cleaned() {
        // The MajorBBS API is cdecl throughout: the module pushes, the module
        // pops. Only the compiler's own runtime helpers differ, and there are
        // four of them.
        let callee: Vec<&str> = ROUTINES
            .iter()
            .filter(|(_, _, _, cleans)| !matches!(cleans, Cleans::Caller))
            .map(|(_, name, _, _)| *name)
            .collect();
        assert_eq!(callee, ["f_ldiv@", "f_lmod@", "f_ludiv@", "f_lumod@"]);
    }

    #[test]
    fn the_helpers_pop_two_longs() {
        for (_, name, _, cleans) in ROUTINES {
            if name.starts_with("f_l") {
                assert!(
                    matches!(cleans, Cleans::Callee(runtime::OPERANDS)),
                    "{name} pops {cleans:?}"
                );
            }
        }
    }
}
