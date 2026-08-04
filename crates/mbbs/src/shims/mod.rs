//! What sits behind each import, and what to do when nothing does.

pub mod btrieve;
pub mod memory;
pub mod msg;
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
    /// A host routine, reached by far call.
    Routine(Shim),

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
const ROUTINES: &[(&str, &str, Shim)] = &[
    // Strings, numbers and the print buffer.
    (MAJORBBS, "spr", text::spr),
    (MAJORBBS, "sprintf", text::sprintf),
    (MAJORBBS, "prf", text::prf),
    (MAJORBBS, "clrprf", text::clrprf),
    (MAJORBBS, "stzcpy", text::stzcpy),
    (MAJORBBS, "strcpy", text::strcpy),
    (MAJORBBS, "strlen", text::strlen),
    (MAJORBBS, "atol", text::atol),
    // Message files, and the options in them.
    (MAJORBBS, "opnmsg", msg::opnmsg),
    (MAJORBBS, "clsmsg", msg::clsmsg),
    (MAJORBBS, "setmbk", msg::setmbk),
    (MAJORBBS, "rstmbk", msg::rstmbk),
    (MAJORBBS, "stgopt", msg::stgopt),
    (MAJORBBS, "numopt", msg::numopt),
    (MAJORBBS, "ynopt", msg::ynopt),
    (MAJORBBS, "chropt", msg::chropt),
    (MAJORBBS, "tokopt", msg::tokopt),
    (MAJORBBS, "prfmsg", msg::prfmsg),
    // Memory the module owns, and the leaves that move bytes about.
    (MAJORBBS, "alcmem", memory::alcmem),
    (MAJORBBS, "alczer", memory::alczer),
    (MAJORBBS, "galfree", memory::galfree),
    (MAJORBBS, "farcoreleft", memory::farcoreleft),
    (MAJORBBS, "alctile", memory::alctile),
    (MAJORBBS, "ptrtile", memory::ptrtile),
    (MAJORBBS, "setmem", memory::setmem),
    (MAJORBBS, "movmem", memory::movmem),
    (MAJORBBS, "memcpy", memory::memcpy),
    (MAJORBBS, "memcmp", memory::memcmp),
    // Btrieve: opening a module's data files, and which one is current.
    (MAJORBBS, "omdbtv", btrieve::omdbtv),
    (MAJORBBS, "opnbtv", btrieve::opnbtv),
    (MAJORBBS, "setbtv", btrieve::setbtv),
    (MAJORBBS, "rstbtv", btrieve::rstbtv),
    (MAJORBBS, "cntrbtv", btrieve::cntrbtv),
    // Btrieve: reading records.
    (MAJORBBS, "qrybtv", btrieve::qrybtv),
    (MAJORBBS, "qnpbtv", btrieve::qnpbtv),
    (MAJORBBS, "obtbtvl", btrieve::obtbtvl),
    (MAJORBBS, "stpbtvl", btrieve::stpbtvl),
    (MAJORBBS, "absbtv", btrieve::absbtv),
    (MAJORBBS, "aabbtv", btrieve::aabbtv),
    (MAJORBBS, "gabbtvl", btrieve::gabbtvl),
    // Streams: the module's own files, read and written.
    (MAJORBBS, "fopen", stream::fopen),
    (MAJORBBS, "fclose", stream::fclose),
    (MAJORBBS, "fgets", stream::fgets),
    (MAJORBBS, "fread", stream::fread),
    (MAJORBBS, "fprintf", stream::fprintf),
    (MAJORBBS, "fflush", stream::fflush),
    (MAJORBBS, "unlink", stream::unlink),
    // The clock, the audit trail, and coming online.
    (MAJORBBS, "access", system::access),
    (MAJORBBS, "now", system::now),
    (MAJORBBS, "today", system::today),
    (MAJORBBS, "time", system::time),
    (MAJORBBS, "srand", system::srand),
    (MAJORBBS, "gmdnam", system::gmdnam),
    (MAJORBBS, "shocst", system::shocst),
    (MAJORBBS, "dclvda", system::dclvda),
    (MAJORBBS, "register_module", system::register_module),
    (MAJORBBS, "catastro", system::catastro),
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
    if let Some((_, _, shim)) = ROUTINES.iter().find(|(d, n, _)| *d == dll && *n == symbol) {
        return Entry::Routine(*shim);
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
        for (dll, name, _) in ROUTINES {
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
